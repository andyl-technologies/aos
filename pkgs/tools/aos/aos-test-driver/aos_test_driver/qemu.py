"""QemuMachine — virtio-serial transport (fleet/multi-VM mode).

argv is a 1:1 port of the bash driver this replaces; the load-bearing
workarounds (mcast localaddr pin, SCSI CD-ROM for the metadata ISO,
serial drain via socat) survive verbatim — see comments in start().
"""

import glob
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import IO, ClassVar, override

from .agent import Driver
from .machine import Machine


log: logging.Logger = logging.getLogger(__name__)


def _mcast_endpoint() -> tuple[str, int]:
    """Pick a per-driver-process multicast group + port for the fleet L2.

    Every machine in one ``aos-test-driver`` invocation joins the same
    group (so they form one virtual L2 segment); two driver processes on
    the same host cannot collide because their PIDs are distinct while
    both are live. Mirrors the per-PID CID derivation in
    ``firecracker.py`` — the codebase already does not rely on Nix
    sandbox netns isolation for harness-internal addresses.

    Even when the sandbox netns *does* isolate ``localaddr=127.0.0.1``
    mcast traffic, this keeps the interactive launcher (which runs
    outside the sandbox) and any future non-sandboxed call path correct
    by construction.

    239.0.0.0/8 is the IANA "organization-local scope" range (RFC 2365)
    — the right pool for an ephemeral, harness-internal multicast group.
    The last three octets carry 24 bits of PID; Linux's default
    PID_MAX_LIMIT is 2^22, so within the live PID range the group is
    unique. The port adds a second axis of separation in case the PID
    happens to share its low 24 bits with another live driver.
    """
    pid = os.getpid()
    group = f"239.{(pid >> 16) & 0xff}.{(pid >> 8) & 0xff}.{pid & 0xff}"
    port = 10000 + (pid % 50000)
    return group, port


MCAST_GROUP, MCAST_PORT = _mcast_endpoint()


class QemuMachine(Machine):
    """A fleet VM.

    Two boot shapes share the transport plumbing (agent virtio-serial
    port, serial drain, mcast L2 netdev):

    - ``boot="kernel"`` (default): direct kernel boot via
      ``-kernel``/``-initrd``/``-append`` with the ignition config on a
      metadata ISO (SCSI CD-ROM) — the original fleet path.
    - ``boot="image"``: boot a self-bootable raw disk image under OVMF
      (two pflash drives), with the ignition config delivered over
      ``-fw_cfg name=opt/com.coreos/config``. No metadata ISO is
      attached — its presence would force ``PLATFORM_ID=file`` in
      aos-platform-detect and ignition would never look at fw_cfg.
      The per-run disk copy is grown to ``disk_size_mib`` and its GPT
      backup header relocated (``sgdisk -e``) so ignition's disks
      stage can create partitions past the image's original boundary.
    """

    transport: ClassVar[Driver] = "qemu"

    boot: str
    kernel_pkg: str | None
    initrd_path: str | None
    disk_src: str
    metadata_src: str | None
    firmware_code: str | None
    firmware_vars_src: str | None
    fw_cfg_path: str | None
    disk_size_mib: int | None
    memory_mib: int
    vcpu_count: int
    mac: str
    ip: str
    tmpdir: Path
    serial_socket: str
    qemu_log: str
    disk_copy: str
    metadata_copy: str
    vars_copy: str
    qemu_proc: subprocess.Popen[bytes] | None
    drain_proc: subprocess.Popen[bytes] | None

    def __init__(
        self,
        *,
        name: str,
        disk: str,
        memory_mib: int,
        vcpu_count: int,
        mac: str,
        ip: str,
        tmpdir: str,
        boot: str = "kernel",
        kernel: str | None = None,
        initrd: str | None = None,
        metadata: str | None = None,
        firmware_code: str | None = None,
        firmware_vars: str | None = None,
        fw_cfg: str | None = None,
        disk_size_mib: int | None = None,
    ) -> None:
        self.boot = boot
        self.kernel_pkg = kernel
        self.initrd_path = initrd
        self.disk_src = disk
        self.metadata_src = metadata
        self.firmware_code = firmware_code
        self.firmware_vars_src = firmware_vars
        self.fw_cfg_path = fw_cfg
        self.disk_size_mib = disk_size_mib
        self.memory_mib = memory_mib
        self.vcpu_count = vcpu_count
        self.mac = mac
        self.ip = ip
        self.tmpdir = Path(tmpdir)

        agent_socket = str(self.tmpdir / f"{name}-agent.sock")
        serial_log = str(self.tmpdir / f"{name}-serial.log")
        super().__init__(name, agent_socket, serial_log)

        self.serial_socket = str(self.tmpdir / f"{name}-serial.sock")
        self.qemu_log = str(self.tmpdir / f"{name}-qemu.log")
        self.disk_copy = str(self.tmpdir / f"{name}-disk.img")
        self.metadata_copy = str(self.tmpdir / f"{name}-metadata.iso")
        self.vars_copy = str(self.tmpdir / f"{name}-OVMF_VARS.fd")

        self.qemu_proc = None
        self.drain_proc = None
        self._qemu_log_fd: IO[bytes] | None = None

    # ------------------------------------------------------------------
    def _find_kernel(self) -> str:
        # The fleet QEMU boots vmlinuz (compressed). Driver expands the
        # glob; fail fast on zero or multiple matches.
        if self.kernel_pkg is None:
            raise RuntimeError(f"[{self.name}] kernel boot requested without kernel")
        pattern = str(Path(self.kernel_pkg) / "boot" / "vmlinuz-*")
        candidates = sorted(glob.glob(pattern))
        if not candidates:
            raise RuntimeError(f"[{self.name}] no vmlinuz under {pattern}")
        if len(candidates) > 1:
            log.warning(
                "[%s] multiple vmlinuz candidates, picking first: %s",
                self.name,
                candidates,
            )
        return candidates[0]

    # ------------------------------------------------------------------
    @override
    def start(self) -> None:
        log.info(
            "==> Starting machine: %s (ip=%s mac=%s mcast=%s:%d)",
            self.name,
            self.ip,
            self.mac,
            MCAST_GROUP,
            MCAST_PORT,
        )

        # Per-machine writable copy. The disk is shared across machines of
        # this system variant (Nix dedups), but each VM needs a writable
        # copy because QEMU opens it rw. The metadata ISO is per-machine
        # already; the local copy isolates the run from any read-side
        # caching quirks with store files on certain filesystems.
        shutil.copyfile(self.disk_src, self.disk_copy)
        os.chmod(self.disk_copy, 0o644)

        if self.boot == "image":
            # Grow the per-run copy to the install target size (sparse —
            # os.truncate extends with holes, no real I/O) and relocate
            # the GPT backup header to the new end of disk. Without the
            # relocation ignition-disks cannot create or resize
            # partitions past the image's original boundary; ignition
            # treats the stale table as authoritative (its disks stage
            # is declarative and never repairs GPT itself).
            if self.disk_size_mib is not None:
                os.truncate(self.disk_copy, self.disk_size_mib * 1024 * 1024)
                subprocess.run(
                    ["sgdisk", "-e", self.disk_copy],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                )
            if self.firmware_vars_src is None:
                raise RuntimeError(
                    f"[{self.name}] image boot requires firmware_vars"
                )
            # Writable per-run NVRAM variable store, seeded from the
            # firmware package's template.
            shutil.copyfile(self.firmware_vars_src, self.vars_copy)
            os.chmod(self.vars_copy, 0o644)
            log.info("  Image:    %s (%s MiB)", self.disk_copy, self.disk_size_mib)
            log.info("  Firmware: %s", self.firmware_code)
            log.info("  fw_cfg:   %s", self.fw_cfg_path)
        else:
            if self.metadata_src is None:
                raise RuntimeError(
                    f"[{self.name}] kernel boot requires a metadata ISO"
                )
            shutil.copyfile(self.metadata_src, self.metadata_copy)
            os.chmod(self.metadata_copy, 0o644)
            log.info("  Disk:     %s", self.disk_copy)
            log.info("  Metadata: %s", self.metadata_copy)

        # Serial drain — unidirectional listener appending to
        # <name>-serial.log. Must be up before QEMU connects; the wait
        # loop guards against early-boot output being lost. -u +
        # OPEN-with-creat,append matches the bash driver this replaces.
        self.drain_proc = subprocess.Popen(
            [
                "socat",
                "-u",
                f"UNIX-LISTEN:{self.serial_socket},reuseaddr,fork",
                f"OPEN:{self.serial_log_path},creat,append",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5.0
        while not os.path.exists(self.serial_socket):
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"[{self.name}] serial drain socket did not appear within 5s"
                )
            time.sleep(0.05)

        # The metadata ISO rides on a SCSI CD-ROM so the guest sees
        # /dev/sr0 with ISO9660 volume label `aos-metadata` — exactly
        # what aos-platform-detect.service probes for.
        #
        # `localaddr=127.0.0.1` on the mcast netdev binds the multicast
        # socket to loopback. Without it QEMU asks the kernel to pick an
        # outbound interface for the group, and the Nix sandbox's network
        # namespace has only `lo` — which doesn't carry the
        # IFF_MULTICAST flag — so the kernel rejects IP_ADD_MEMBERSHIP
        # with "No such device". Pinning to 127.0.0.1 routes the mcast
        # traffic through lo explicitly and works around the missing flag
        # (no CAP_NET_ADMIN required). Cross-process delivery between
        # QEMU instances of the same fleet works as designed.
        #
        # The mcast group + port are derived from the driver PID at
        # import time (see _mcast_endpoint above), so two concurrent
        # driver processes — sandboxed or not — get distinct L2 segments
        # and cannot cross-talk even if a future change shares a netns.
        self._launch()

    # ------------------------------------------------------------------
    def _launch(self) -> None:
        """Start the QEMU process against the prepared per-run artifacts.

        Split out of start() so reboot() can relaunch against the same
        disk/NVRAM state without re-running the prep (copy/grow/sgdisk).
        """
        argv: list[str] = [
            "qemu-system-x86_64",
            "-machine", "q35,accel=kvm",
            "-cpu", "host",
            "-m", str(self.memory_mib),
            "-smp", str(self.vcpu_count),
            "-nographic",
        ]

        if self.boot == "image":
            # UEFI image boot: OVMF code (read-only) + per-run vars on
            # pflash; firmware loads sd-boot from the image's ESP. The
            # ignition config rides fw_cfg — aos-platform-detect sees
            # QEMU DMI (no metadata ISO attached) and classifies
            # PLATFORM_ID=qemu, which is exactly the platform whose
            # fetch stage reads opt/com.coreos/config.
            argv += [
                "-drive",
                f"if=pflash,format=raw,readonly=on,file={self.firmware_code}",
                "-drive", f"if=pflash,format=raw,file={self.vars_copy}",
                "-drive", f"file={self.disk_copy},format=raw,if=virtio",
            ]
            if self.fw_cfg_path is not None:
                argv += [
                    "-fw_cfg", f"name=opt/com.coreos/config,file={self.fw_cfg_path}",
                ]
        else:
            vmlinuz = self._find_kernel()
            initrd = str(Path(self.initrd_path or ""))
            log.info("  Kernel:   %s", vmlinuz)
            log.info("  Initrd:   %s", initrd)
            argv += [
                "-kernel", vmlinuz,
                "-initrd", initrd,
                "-append",
                (
                    "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro "
                    "systemd.unified_cgroup_hierarchy=1 systemd.gpt-auto=0 "
                    "systemd.journald.forward_to_console=1 enforcing=0 "
                    "net.ifnames=0"
                ),
                "-drive", f"file={self.disk_copy},format=raw,if=virtio",
                "-drive",
                f"id=metadata,file={self.metadata_copy},if=none,format=raw,readonly=on",
                "-device", "virtio-scsi-pci,id=scsi0",
                "-device", "scsi-cd,drive=metadata,bus=scsi0.0",
            ]

        argv += [
            "-device", "virtio-serial",
            "-device", "virtserialport,chardev=agent,name=aos.test.agent",
            "-chardev",
            f"socket,id=agent,path={self.agent.socket_path},server=on,wait=off",
            "-chardev",
            f"socket,id=ttyS0,path={self.serial_socket},server=off",
            "-serial", "chardev:ttyS0",
            "-netdev",
            f"socket,id=net0,mcast={MCAST_GROUP}:{MCAST_PORT},localaddr=127.0.0.1",
            "-device", f"virtio-net-pci,netdev=net0,mac={self.mac}",
            "-no-reboot",
        ]

        self._qemu_log_fd = open(self.qemu_log, "ab")
        self.qemu_proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=self._qemu_log_fd,
            stderr=self._qemu_log_fd,
        )

        time.sleep(0.2)
        if self.qemu_proc.poll() is not None:
            self._dump_qemu_log()
            raise RuntimeError(
                f"[{self.name}] QEMU exited immediately"
                f" (code {self.qemu_proc.returncode})"
            )

    # ------------------------------------------------------------------
    def reboot(self, timeout: float = 600.0) -> None:
        """Reboot the guest and wait for the agent to come back.

        ``-no-reboot`` makes a guest-initiated reboot exit the QEMU
        process, so a reboot is: ask the guest to reboot (detached, so
        the agent's framed reply gets out first), wait for QEMU to
        exit, relaunch against the same on-disk state — second boot,
        not first boot — and re-handshake with the agent.
        """
        # The trailing `&` detaches the reboot so the agent can frame
        # its reply before PID 1 tears the transport down.
        self.execute("(sleep 1; reboot -f) >/dev/null 2>&1 &", timeout=30)
        self.agent.close()

        if self.qemu_proc is None:
            raise RuntimeError(f"[{self.name}] reboot before start()")
        deadline = time.monotonic() + timeout
        try:
            self.qemu_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"[{self.name}] guest did not exit QEMU within 60s of reboot"
            ) from None
        if self._qemu_log_fd is not None:
            self._qemu_log_fd.close()
            self._qemu_log_fd = None

        log.info(
            "==> Rebooting machine: %s (QEMU exited %s)",
            self.name,
            self.qemu_proc.returncode,
        )
        self._launch()
        log.info(
            "[%s] relaunched QEMU (pid %s); waiting for agent",
            self.name,
            self.qemu_proc.pid if self.qemu_proc else "?",
        )
        self.agent.wait_ready(deadline)

    # ------------------------------------------------------------------
    @override
    def stop(self) -> None:
        # Release the persistent agent connection before tearing down
        # QEMU so the guest's virtio-serial read() sees a clean EOF.
        self.agent.close()
        if self.qemu_proc is not None and self.qemu_proc.poll() is None:
            self.qemu_proc.terminate()
            try:
                self.qemu_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.qemu_proc.kill()
                self.qemu_proc.wait()
        if self.drain_proc is not None and self.drain_proc.poll() is None:
            self.drain_proc.terminate()
            try:
                self.drain_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.drain_proc.kill()
                self.drain_proc.wait()
        if self._qemu_log_fd is not None:
            self._qemu_log_fd.close()
            self._qemu_log_fd = None

    def _dump_qemu_log(self) -> None:
        if self._qemu_log_fd is not None:
            self._qemu_log_fd.flush()
        try:
            with open(self.qemu_log, "r", errors="replace") as f:
                log.error("--- %s qemu log ---\n%s", self.name, f.read())
        except OSError:
            pass
