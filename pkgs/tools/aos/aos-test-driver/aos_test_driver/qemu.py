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
from .fs import clone_or_copy
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
      ``-kernel``/``-initrd``/``-append``.
    - ``boot="image"``: boot a self-bootable raw disk image under OVMF
      (two pflash drives).

    Either shape may attach an ``aos-metadata`` ISO as a SCSI CD-ROM. Image
    tests use that channel to exercise native first-boot provisioning before
    repartitioning. The per-run disk copy is grown to ``disk_size_mib`` and
    its GPT backup header relocated (``sgdisk -e``) so systemd-repart sees the
    complete target capacity.
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
    var_size_mib: int | None
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
    tpm: bool
    swtpm_bin: str | None
    tpm_socket: str | None
    tpm_state_dir: str | None
    qemu_proc: subprocess.Popen[bytes] | None
    drain_proc: subprocess.Popen[bytes] | None
    swtpm_proc: subprocess.Popen[bytes] | None

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
        var_size_mib: int | None = None,
        tpm: bool = False,
        swtpm_bin: str | None = None,
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
        self.var_size_mib = var_size_mib
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
        self.tpm = tpm
        self.swtpm_bin = swtpm_bin
        self.tpm_socket = str(self.tmpdir / f"{name}-tpm.sock") if tpm else None
        self.tpm_state_dir = str(self.tmpdir / f"{name}-tpm-state") if tpm else None
        self.swtpm_log = str(self.tmpdir / f"{name}-swtpm.log")

        self.qemu_proc = None
        self.drain_proc = None
        self.swtpm_proc = None
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
        # copy because QEMU opens it rw. clone_or_copy reflinks it on a
        # CoW filesystem (the common case: the Nix store and build scratch
        # are the same btrfs/XFS/ZFS volume), so the copy is near-instant and
        # free until the guest writes — it falls back to a full copy
        # otherwise. The metadata ISO is per-machine already; its local
        # copy isolates the run from any read-side caching quirks with
        # store files on certain filesystems.
        reflinked = clone_or_copy(self.disk_src, self.disk_copy)
        os.chmod(self.disk_copy, 0o644)
        copy_method = "reflink" if reflinked else "copy"
        if self.metadata_src is not None:
            shutil.copyfile(self.metadata_src, self.metadata_copy)
            os.chmod(self.metadata_copy, 0o644)

        if self.boot == "image":
            # Grow the per-run copy to the install target size (sparse —
            # os.truncate extends with holes, no real I/O) and relocate
            # the GPT backup header to the new end of disk. Without the
            # relocation systemd-repart cannot allocate partitions past the
            # image's original boundary.
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
            log.info(
                "  Image:    %s (%s MiB, %s)",
                self.disk_copy,
                self.disk_size_mib,
                copy_method,
            )
            log.info("  Firmware: %s", self.firmware_code)
            log.info("  fw_cfg:   %s", self.fw_cfg_path)
            if self.metadata_src is not None:
                log.info("  Metadata: %s", self.metadata_copy)
        else:
            # A metadata ISO is optional because fleet
            # identity is baked into the image's /etc (via extendModules), so a
            # kernel-boot machine may carry no metadata channel at all. When
            # absent, no SCSI CD-ROM is attached (see the argv block below) and
            # aos-metadata-detect falls through to the `metal` platform.
            # A repart-provisioned kernel disk ships no /var, so
            # grow the per-run copy by var_size_mib to open trailing free
            # space (sparse — os.truncate extends with holes) and relocate
            # the GPT backup header to the new end. systemd-repart then
            # creates and formats /var there on first boot. Growing the per-run
            # copy — not the shared base image — is what lets machines
            # differing only in /var size share one deduplicated base disk.
            if self.var_size_mib is not None:
                grown = os.path.getsize(self.disk_copy) + (
                    self.var_size_mib + 1
                ) * 1024 * 1024
                os.truncate(self.disk_copy, grown)
                subprocess.run(
                    ["sgdisk", "-e", self.disk_copy],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                )
                log.info(
                    "  Disk:     %s (%s, +%s MiB /var via systemd-repart)",
                    self.disk_copy,
                    copy_method,
                    self.var_size_mib,
                )
            else:
                log.info("  Disk:     %s (%s)", self.disk_copy, copy_method)
            if self.metadata_src is not None:
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
        # what the initrd metadata detector probes for.
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
    def _ensure_swtpm(self) -> None:
        """Ensure the per-machine swtpm is running before QEMU (re)launch.

        Idempotent: reuses a live swtpm (preserving its in-memory TPM), and
        otherwise (re)launches it against the persistent ``--tpmstate`` dir.
        QEMU tears its control connection down on the reboot leg and swtpm
        exits with it, so this is called from every ``_launch()`` — the
        relaunch reloads the persisted NV state and enrolled keys while PCRs
        reset at power-on, exactly matching real-hardware reboot semantics.

        # Raises

        ``RuntimeError`` if no ``swtpm_bin`` was supplied, or swtpm exits
        immediately / its control socket never appears.
        """
        if not self.tpm:
            return
        if self.swtpm_proc is not None and self.swtpm_proc.poll() is None:
            log.info("[%s] vTPM: reusing live swtpm (pid %s)",
                     self.name, self.swtpm_proc.pid)
            return  # still alive — reuse it
        if self.swtpm_bin is None:
            raise RuntimeError(
                f"[{self.name}] tpm requested but no swtpm_bin in manifest"
            )
        # If a previous swtpm died, surface why before relaunching.
        if self.swtpm_proc is not None:
            log.warning("[%s] vTPM: previous swtpm exited (code %s); relaunching",
                        self.name, self.swtpm_proc.returncode)
            self._dump_swtpm_log()
        assert self.tpm_state_dir is not None and self.tpm_socket is not None
        os.makedirs(self.tpm_state_dir, exist_ok=True)
        # A stale socket file from a dead swtpm would block bind.
        if os.path.exists(self.tpm_socket):
            os.unlink(self.tpm_socket)
        log.info("  vTPM:     swtpm @ %s", self.tpm_socket)
        swtpm_log_fd = open(self.swtpm_log, "ab")
        self.swtpm_proc = subprocess.Popen(
            [
                self.swtpm_bin,
                "socket",
                "--tpm2",
                f"--tpmstate=dir={self.tpm_state_dir}",
                f"--ctrl=type=unixio,path={self.tpm_socket}",
                "--flags=startup-clear",
                "--log=level=5",
            ],
            stdout=swtpm_log_fd,
            stderr=swtpm_log_fd,
        )
        deadline = time.monotonic() + 5.0
        while not os.path.exists(self.tpm_socket):
            if self.swtpm_proc.poll() is not None:
                raise RuntimeError(
                    f"[{self.name}] swtpm exited immediately"
                    f" (code {self.swtpm_proc.returncode})"
                )
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"[{self.name}] swtpm control socket did not appear within 5s"
                )
            time.sleep(0.05)

    # ------------------------------------------------------------------
    def _launch(self) -> None:
        """Start the QEMU process against the prepared per-run artifacts.

        Split out of start() so reboot() can relaunch against the same
        disk/NVRAM state without re-running the prep (copy/grow/sgdisk).
        """
        # vTPM must be up before QEMU connects to its socket — on the reboot
        # leg swtpm died with the previous QEMU, so (re)launch it here.
        self._ensure_swtpm()

        # Image boot uses the SB+SMM OVMF, which requires the q35 SMM
        # machine. Kernel boot keeps the plain machine.
        machine = (
            "q35,smm=on,accel=kvm" if self.boot == "image" else "q35,accel=kvm"
        )
        argv: list[str] = [
            "qemu-system-x86_64",
            "-machine", machine,
            "-cpu", "host",
            "-m", str(self.memory_mib),
            "-smp", str(self.vcpu_count),
            "-nographic",
        ]

        if self.boot == "image":
            # UEFI image boot: OVMF code (read-only) + per-run vars on
            # pflash; firmware loads sd-boot from the image's ESP.
            #
            # Secure Boot needs SMM: OVMF's authenticated variable store
            # lives in SMM, and the firmware flash is marked secure so
            # only SMM code can write it (cfi.pflash01 secure=on). The
            # OVMF_CODE pflash is unit 0 (the secured one), VARS unit 1.
            # disable_s3 avoids an S3-resume path OVMF+SMM doesn't support
            # here. Without these the SecureBoot/SetupMode variables never
            # appear and SB reports "unsupported".
            argv += [
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-global", "ICH9-LPC.disable_s3=1",
                "-drive",
                f"if=pflash,unit=0,format=raw,readonly=on,file={self.firmware_code}",
                "-drive", f"if=pflash,unit=1,format=raw,file={self.vars_copy}",
                "-drive", f"file={self.disk_copy},format=raw,if=virtio",
            ]
            if self.fw_cfg_path is not None:
                argv += [
                    "-fw_cfg", f"name=opt/org.andyl/provisioning,file={self.fw_cfg_path}",
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
            ]

        # Attach native provisioning input for either boot shape. The initrd
        # probes the `aos-metadata` filesystem label before cloud DMI routing.
        if self.metadata_src is not None:
            argv += [
                "-drive",
                f"id=metadata,file={self.metadata_copy},if=none,format=raw,readonly=on",
                "-device", "virtio-scsi-pci,id=scsi0",
                "-device", "scsi-cd,drive=metadata,bus=scsi0.0",
            ]

        # vTPM device — connects QEMU's emulated tpm-tis to the swtpm
        # control socket launched in start(). Present on every (re)launch
        # so the guest keeps its TPM across the reboot leg.
        if self.tpm:
            argv += [
                "-chardev", f"socket,id=chrtpm,path={self.tpm_socket}",
                "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                "-device", "tpm-tis,tpmdev=tpm0",
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
        ]
        # `-no-reboot` makes a guest reboot exit QEMU (the relaunch reboot
        # path, and the SB negative test's rejection signal). A vTPM
        # machine must instead reset in place so QEMU keeps its swtpm
        # connection alive — swtpm exits when QEMU disconnects, and a
        # relaunched swtpm loading the prior boot's state wedges the
        # measured-boot reboot. So omit -no-reboot when a TPM is attached.
        if not self.tpm:
            argv += ["-no-reboot"]

        log.info("[%s] qemu argv: %s", self.name, " ".join(argv))
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
        # its reply before PID 1 starts an orderly shutdown. Do not use
        # `reboot -f` here: it bypasses systemd, so journald and /var do
        # not get a clean stop before the next boot reads the journal.
        self.execute("(sleep 1; systemctl reboot) >/dev/null 2>&1 &", timeout=30)
        self.agent.close()

        if self.qemu_proc is None:
            raise RuntimeError(f"[{self.name}] reboot before start()")
        deadline = time.monotonic() + timeout

        # vTPM machines reset in place (no -no-reboot): QEMU keeps running
        # and stays connected to swtpm, so the emulated TPM's state is
        # continuous across the reboot (PCRs reset via the guest's
        # TPM2_Startup, NV/keys persist). Just wait for the agent to
        # answer again on the same QEMU agent socket — no QEMU relaunch.
        if self.tpm:
            log.info(
                "==> Rebooting machine: %s (in-VM reset, vTPM preserved)",
                self.name,
            )
            # Wait for the pre-reboot agent to go silent BEFORE waiting for
            # the new boot — otherwise a PONG from the old boot (the
            # `sleep 1; reboot` hasn't fired yet) is mistaken for the
            # reboot completing.
            self.agent.wait_down(time.monotonic() + 90)
            self.agent.wait_ready(deadline)
            return

        try:
            self.qemu_proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"[{self.name}] guest did not exit QEMU within 120s of reboot"
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
    def reboot_expect_rejected(
        self, settle: float = 90.0, markers: list[str] | None = None
    ) -> str:
        """Reboot and assert the firmware REFUSES to boot the image.

        For the Secure Boot negative test: after the on-disk UKI has been
        tampered (or is unsigned) under an enforcing firmware, a reboot
        must NOT come back. Triggers the reboot, relaunches QEMU, then
        waits ``settle`` seconds and asserts the guest agent never answers
        — and (best-effort) that the serial log shows a firmware
        rejection. Returns the tail of the serial log for the caller to
        assert on. Raises if the agent DOES come up (image booted —
        enforcement failed).

        ``markers`` defaults to the OVMF/UEFI access-denied signatures.
        """
        if markers is None:
            markers = [
                "Security Violation",
                "Access Denied",
                "failed to load",
                "verification failed",
            ]
        self.execute("(sleep 1; systemctl reboot) >/dev/null 2>&1 &", timeout=30)
        self.agent.close()

        if self.qemu_proc is None:
            raise RuntimeError(f"[{self.name}] reboot before start()")
        try:
            self.qemu_proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"[{self.name}] guest did not exit QEMU within 120s of reboot"
            ) from None
        if self._qemu_log_fd is not None:
            self._qemu_log_fd.close()
            self._qemu_log_fd = None

        log.info("==> Rebooting %s, expecting firmware rejection", self.name)
        self._launch()

        # Give the firmware time to reject and the (doomed) boot to NOT
        # produce an agent. wait_ready with a short deadline: if it
        # returns, the image booted — that's a test failure.
        deadline = time.monotonic() + settle
        try:
            self.agent.wait_ready(deadline)
        except RuntimeError:
            # Expected: no agent — the firmware rejected the image.
            tail = ""
            try:
                with open(self.serial_log_path, "r", errors="replace") as f:
                    tail = f.read()[-8000:]
            except OSError:
                pass
            hit = next((m for m in markers if m in tail), None)
            if hit:
                log.info("[%s] firmware rejection confirmed (%r)", self.name, hit)
            else:
                log.warning(
                    "[%s] agent never came up (good) but no rejection marker "
                    "found in serial; markers=%r",
                    self.name,
                    markers,
                )
            return tail
        raise RuntimeError(
            f"[{self.name}] image BOOTED after tampering — Secure Boot did not"
            " enforce (agent came up)"
        )

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
        if self.swtpm_proc is not None and self.swtpm_proc.poll() is None:
            self.swtpm_proc.terminate()
            try:
                self.swtpm_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.swtpm_proc.kill()
                self.swtpm_proc.wait()
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
        self._dump_swtpm_log()

    def _dump_swtpm_log(self) -> None:
        """Emit the swtpm log tail — its TPM-command trace and any crash."""
        if not self.tpm:
            return
        try:
            with open(self.swtpm_log, "r", errors="replace") as f:
                tail = f.read()[-4000:]
            log.error("--- %s swtpm log (tail) ---\n%s", self.name, tail)
        except OSError:
            pass
