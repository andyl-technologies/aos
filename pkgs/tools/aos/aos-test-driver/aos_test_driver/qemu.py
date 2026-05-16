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


class QemuMachine(Machine):
    transport: ClassVar[Driver] = "qemu"

    kernel_pkg: str
    initrd_path: str
    disk_src: str
    metadata_src: str
    memory_mib: int
    vcpu_count: int
    mac: str
    ip: str
    tmpdir: Path
    serial_socket: str
    qemu_log: str
    disk_copy: str
    metadata_copy: str
    qemu_proc: subprocess.Popen[bytes] | None
    drain_proc: subprocess.Popen[bytes] | None

    def __init__(
        self,
        *,
        name: str,
        kernel: str,
        initrd: str,
        disk: str,
        metadata: str,
        memory_mib: int,
        vcpu_count: int,
        mac: str,
        ip: str,
        tmpdir: str,
    ) -> None:
        self.kernel_pkg = kernel
        self.initrd_path = initrd
        self.disk_src = disk
        self.metadata_src = metadata
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

        self.qemu_proc = None
        self.drain_proc = None
        self._qemu_log_fd: IO[bytes] | None = None

    # ------------------------------------------------------------------
    def _find_kernel(self) -> str:
        # The fleet QEMU boots vmlinuz (compressed). Driver expands the
        # glob; fail fast on zero or multiple matches.
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
            "==> Starting machine: %s (ip=%s mac=%s)",
            self.name,
            self.ip,
            self.mac,
        )

        # Per-machine writable copy. The disk is shared across machines of
        # this system variant (Nix dedups), but each VM needs a writable
        # copy because QEMU opens it rw. The metadata ISO is per-machine
        # already; the local copy isolates the run from any read-side
        # caching quirks with store files on certain filesystems.
        shutil.copyfile(self.disk_src, self.disk_copy)
        os.chmod(self.disk_copy, 0o644)
        shutil.copyfile(self.metadata_src, self.metadata_copy)
        os.chmod(self.metadata_copy, 0o644)

        vmlinuz = self._find_kernel()
        initrd = str(Path(self.initrd_path))

        log.info("  Kernel:   %s", vmlinuz)
        log.info("  Initrd:   %s", initrd)
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
        # outbound interface for 230.0.0.1, and the Nix sandbox's network
        # namespace has only `lo` — which doesn't carry the
        # IFF_MULTICAST flag — so the kernel rejects IP_ADD_MEMBERSHIP
        # with "No such device". Pinning to 127.0.0.1 routes the mcast
        # traffic through lo explicitly and works around the missing flag
        # (no CAP_NET_ADMIN required). Cross-process delivery between
        # QEMU instances on the same host works as designed.
        argv: list[str] = [
            "qemu-system-x86_64",
            "-machine", "q35,accel=kvm",
            "-cpu", "host",
            "-m", str(self.memory_mib),
            "-smp", str(self.vcpu_count),
            "-nographic",
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
            "-device", "virtio-serial",
            "-device", "virtserialport,chardev=agent,name=aos.test.agent",
            "-chardev",
            f"socket,id=agent,path={self.agent.socket_path},server=on,wait=off",
            "-chardev",
            f"socket,id=ttyS0,path={self.serial_socket},server=off",
            "-serial", "chardev:ttyS0",
            "-netdev",
            "socket,id=net0,mcast=230.0.0.1:1234,localaddr=127.0.0.1",
            "-device", f"virtio-net-pci,netdev=net0,mac={self.mac}",
            "-no-reboot",
        ]

        self._qemu_log_fd = open(self.qemu_log, "wb")
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
