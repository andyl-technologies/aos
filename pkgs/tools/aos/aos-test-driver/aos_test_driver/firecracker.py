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

from .machine import Machine


log = logging.getLogger(__name__)


class FirecrackerMachine(Machine):
    transport = "firecracker"

    def __init__(
        self,
        *,
        name,
        kernel,
        initrd,
        disk,
        metadata,
        memory_mib,
        vcpu_count,
        tmpdir,
    ):
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
        self._fc_stdin_fd = None
        self._serial_fd = None
        self._fc_err_fd = None

    # ------------------------------------------------------------------
    def _find_kernel(self):
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
    def start(self):
        log.info("==> Starting machine: %s (firecracker)", self.name)

        shutil.copyfile(self.disk_src, self.disk_copy)
        os.chmod(self.disk_copy, 0o644)
        if self.metadata_copy is not None:
            shutil.copyfile(self.metadata_src, self.metadata_copy)
            os.chmod(self.metadata_copy, 0o644)

        vmlinux = self._find_kernel()
        initrd = str(Path(self.initrd_path))

        # Unique CID per builder PID (range 3..65535) keeps parallel
        # test runs on the same host from colliding.
        guest_cid = (os.getpid() % 65533) + 3

        drives = [
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

        cfg = {
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
        log.info("  Disk:   %s", self.disk_copy)
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
        self._serial_fd = open(self.serial_log_path, "wb")
        self._fc_err_fd = open(self.fc_log, "wb")

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
    def stop(self):
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

    def _dump_logs(self):
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
