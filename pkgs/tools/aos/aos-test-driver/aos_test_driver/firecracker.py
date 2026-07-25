"""FirecrackerMachine — vsock transport (single-VM mode).

Ports the bash driver verbatim, including the stdin-FIFO writer trick
that keeps the guest's ttyS0 reads blocking instead of EOF-ing (so the
debug profile's autologin getty can coexist with the harness).
"""

import glob
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import IO, Any, ClassVar, override

from .agent import Driver
from .fs import clone_or_copy
from .machine import Machine


log: logging.Logger = logging.getLogger(__name__)


class FirecrackerMachine(Machine):
    transport: ClassVar[Driver] = "firecracker"

    kernel_pkg: str
    initrd_path: str
    disk_src: str
    metadata_src: str | None
    memory_mib: int
    vcpu_count: int
    tmpdir: Path
    fc_log: str
    disk_copy: str
    metadata_copy: str | None
    fc_cfg: str
    fc_stdin_fifo: str
    fc_proc: subprocess.Popen[bytes] | None
    stdin_proc: subprocess.Popen[bytes] | None

    def __init__(
        self,
        *,
        name: str,
        kernel: str,
        initrd: str,
        disk: str,
        metadata: str | None,
        memory_mib: int,
        vcpu_count: int,
        tmpdir: str,
    ) -> None:
        self.kernel_pkg = kernel
        self.initrd_path = initrd
        self.disk_src = disk
        self.metadata_src = metadata  # may be None
        self.memory_mib = memory_mib
        self.vcpu_count = vcpu_count
        self.tmpdir = Path(tmpdir)

        # Firecracker creates the vsock UDS at `uds_path`; the client
        # CONNECTs to it. From the host's perspective the vsock UDS *is*
        # the agent socket.
        agent_socket = str(self.tmpdir / f"{name}-vm.vsock")
        serial_log = str(self.tmpdir / f"{name}-serial.log")
        super().__init__(name, agent_socket, serial_log)

        self.fc_log = str(self.tmpdir / f"{name}-firecracker.log")
        self.disk_copy = str(self.tmpdir / f"{name}-disk.img")
        self.metadata_copy = (
            str(self.tmpdir / f"{name}-metadata.iso")
            if metadata is not None
            else None
        )
        self.fc_cfg = str(self.tmpdir / f"{name}-fc-config.json")
        self.fc_stdin_fifo = str(self.tmpdir / f"{name}-fc-stdin")

        self.fc_proc = None
        self.stdin_proc = None
        self._fc_stdin_fd: IO[bytes] | None = None
        self._serial_fd: IO[bytes] | None = None
        self._fc_err_fd: IO[bytes] | None = None

    # ------------------------------------------------------------------
    def _find_kernel(self) -> str:
        # Firecracker requires the uncompressed vmlinux image.
        pattern = str(Path(self.kernel_pkg) / "boot" / "vmlinux-*")
        candidates = sorted(glob.glob(pattern))
        if not candidates:
            raise RuntimeError(f"[{self.name}] no vmlinux under {pattern}")
        if len(candidates) > 1:
            log.warning(
                "[%s] multiple vmlinux candidates, picking first: %s",
                self.name,
                candidates,
            )
        return candidates[0]

    # ------------------------------------------------------------------
    @override
    def start(self) -> None:
        self._start(copy_disk=True)

    def _start(self, *, copy_disk: bool) -> None:
        log.info("==> Starting machine: %s (firecracker)", self.name)

        # Per-machine writable copy; reflinked on a CoW filesystem (free
        # until written), full copy otherwise. See clone_or_copy in fs.py.
        #
        # Only (re)create the copy on the initial boot. A reboot must reuse
        # the *same* per-VM disk so writes from the previous boot survive —
        # re-cloning from the pristine `disk_src` here would reset the disk
        # (including the /var partition) to its build-time baked state,
        # silently discarding everything the guest persisted. This mirrors
        # the QEMU driver, whose reboot() relaunches against the same disk
        # without re-running the copy, and matches real-hardware reboot
        # semantics. See _start(copy_disk=False) in reboot().
        if copy_disk:
            reflinked = clone_or_copy(self.disk_src, self.disk_copy)
            os.chmod(self.disk_copy, 0o644)
            copy_method = "reflink" if reflinked else "copy"
            if self.metadata_copy is not None and self.metadata_src is not None:
                shutil.copyfile(self.metadata_src, self.metadata_copy)
                os.chmod(self.metadata_copy, 0o644)
        else:
            copy_method = "reused"
        for stale in (self.agent.socket_path, self.fc_stdin_fifo):
            try:
                os.unlink(stale)
            except FileNotFoundError:
                pass

        vmlinux = self._find_kernel()
        initrd = str(Path(self.initrd_path))

        # Unique CID per builder PID (range 3..65535) keeps parallel
        # test runs on the same host from colliding.
        guest_cid = (os.getpid() % 65533) + 3

        drives: list[dict[str, Any]] = [
            {
                "drive_id": "rootfs",
                "path_on_host": self.disk_copy,
                "is_root_device": False,
                "is_read_only": False,
                "cache_type": "Unsafe",
                "io_engine": "Sync",
            }
        ]
        if self.metadata_copy is not None:
            # Firecracker has no CD-ROM support, so the ISO rides as a
            # read-only virtio-blk drive. blkid still probes the ISO9660
            # superblock and exposes /dev/disk/by-label/aos-metadata.
            drives.append(
                {
                    "drive_id": "metadata",
                    "path_on_host": self.metadata_copy,
                    "is_root_device": False,
                    "is_read_only": True,
                    "cache_type": "Unsafe",
                    "io_engine": "Sync",
                }
            )

        cfg: dict[str, Any] = {
            "boot-source": {
                "kernel_image_path": vmlinux,
                "initrd_path": initrd,
                "boot_args": (
                    "console=ttyS0 reboot=k panic=1 root=/dev/vda2 ro "
                    "systemd.unified_cgroup_hierarchy=1 "
                    "systemd.gpt-auto=0 "
                    "systemd.journald.forward_to_console=1 "
                    "enforcing=0"
                ),
            },
            "drives": drives,
            "machine-config": {
                "vcpu_count": self.vcpu_count,
                "mem_size_mib": self.memory_mib,
                "smt": False,
                "track_dirty_pages": False,
                "huge_pages": "None",
            },
            "vsock": {
                "guest_cid": guest_cid,
                "uds_path": self.agent.socket_path,
            },
            "network-interfaces": [],
        }
        with open(self.fc_cfg, "w") as f:
            json.dump(cfg, f, indent=2)

        log.info("  Driver: firecracker")
        log.info("  Kernel: %s", vmlinux)
        log.info("  Initrd: %s", initrd)
        log.info("  Disk:   %s (%s)", self.disk_copy, copy_method)
        log.info("  CID:    %d", guest_cid)
        log.info("  Vsock:  %s", self.agent.socket_path)

        # Firecracker wires the guest's ttyS0 to its own stdin/stdout.
        # Feed stdin from a FIFO held open r/w by a permanent silent
        # writer (`sleep infinity <>fifo`). Guest reads from ttyS0 then
        # block indefinitely — no EOF → no agetty respawn — so the debug
        # profile's autologin can coexist with the harness.
        os.mkfifo(self.fc_stdin_fifo)
        self.stdin_proc = subprocess.Popen(
            ["sh", "-c", f"exec sleep infinity <>{self.fc_stdin_fifo}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        self._fc_stdin_fd = open(self.fc_stdin_fifo, "rb")
        log_mode = "wb" if copy_disk else "ab"
        self._serial_fd = open(self.serial_log_path, log_mode)
        self._fc_err_fd = open(self.fc_log, log_mode)

        self.fc_proc = subprocess.Popen(
            ["firecracker", "--no-api", "--config-file", self.fc_cfg],
            stdin=self._fc_stdin_fd,
            stdout=self._serial_fd,
            stderr=self._fc_err_fd,
        )

        time.sleep(0.5)
        if self.fc_proc.poll() is not None:
            self._dump_logs()
            raise RuntimeError(
                f"[{self.name}] firecracker exited immediately"
                f" (code {self.fc_proc.returncode})"
            )

        # Firecracker creates the vsock UDS shortly after startup.
        deadline = time.monotonic() + 10.0
        while not os.path.exists(self.agent.socket_path):
            if time.monotonic() > deadline:
                self._dump_logs()
                raise RuntimeError(
                    f"[{self.name}] vsock UDS did not appear within 10s"
                )
            time.sleep(0.1)

    # ------------------------------------------------------------------
    @override
    def stop(self) -> None:
        for proc in (self.fc_proc, self.stdin_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for fd in (self._fc_stdin_fd, self._serial_fd, self._fc_err_fd):
            if fd is not None:
                try:
                    fd.close()
                except OSError:
                    pass
        self._fc_stdin_fd = self._serial_fd = self._fc_err_fd = None
        self.fc_proc = None
        self.stdin_proc = None

    def reboot(self, timeout: float = 600.0) -> None:
        """Reboot the guest and wait for the agent to return."""
        self.execute("(sleep 1; reboot -f) >/dev/null 2>&1 &", timeout=30)
        self.agent.close()

        if self.fc_proc is None:
            raise RuntimeError(f"[{self.name}] reboot before start()")
        deadline = time.monotonic() + timeout
        try:
            self.fc_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"[{self.name}] guest did not exit Firecracker within 60s of reboot"
            ) from None

        log.info(
            "==> Rebooting machine: %s (Firecracker exited %s)",
            self.name,
            self.fc_proc.returncode,
        )
        self.stop()
        self._start(copy_disk=False)
        log.info(
            "[%s] relaunched Firecracker (pid %s); waiting for agent",
            self.name,
            self.fc_proc.pid if self.fc_proc else "?",
        )
        self.agent.wait_ready(deadline)

    def _dump_logs(self) -> None:
        for fd in (self._serial_fd, self._fc_err_fd):
            if fd is not None:
                try:
                    fd.flush()
                except OSError:
                    pass
        for label, path in (("firecracker", self.fc_log), ("serial", self.serial_log_path)):
            try:
                with open(path, "r", errors="replace") as f:
                    log.error("--- %s %s log ---\n%s", self.name, label, f.read())
            except OSError:
                pass
