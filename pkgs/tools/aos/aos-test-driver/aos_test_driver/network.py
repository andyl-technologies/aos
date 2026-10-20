"""Adjusts only an owned QEMU child's multicast socket buffers on Linux."""

import ctypes
import errno
import os
import socket
import time
from pathlib import Path


def configure_multicast_buffers(
    process_id: int, endpoint: tuple[str, int], requested_bytes: int = 4 * 1024 * 1024
) -> tuple[int, int]:
    """Returns the actual receive/send limits after configuring the child's socket.

    Linux enforces access to the owned process through ``pidfd_getfd``. The
    duplicate refers to QEMU's actual queue; no host-wide setting changes.
    The kernel may cap the request at its existing per-socket maximum.
    """
    duplicate = ctypes.CDLL(None, use_errno=True).pidfd_getfd
    duplicate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    duplicate.restype = ctypes.c_int
    process = os.pidfd_open(process_id)
    deadline = time.monotonic() + 5

    try:
        while time.monotonic() < deadline:
            for entry in (Path("/proc") / str(process_id) / "fd").iterdir():
                try:
                    if not str(entry.readlink()).startswith("socket:["):
                        continue
                except FileNotFoundError:
                    continue

                descriptor = duplicate(process, int(entry.name), 0)
                if descriptor < 0:
                    error = ctypes.get_errno()
                    if error == errno.EBADF:
                        continue
                    raise OSError(error, os.strerror(error))

                try:
                    with socket.fromfd(descriptor, socket.AF_INET, socket.SOCK_DGRAM) as network:
                        if network.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM:
                            continue
                        if network.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_INET:
                            continue
                        if network.getsockname() != endpoint:
                            continue

                        for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                            if network.getsockopt(socket.SOL_SOCKET, option) < requested_bytes:
                                network.setsockopt(socket.SOL_SOCKET, option, requested_bytes)
                        return (
                            network.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                            network.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                        )
                finally:
                    os.close(descriptor)

            time.sleep(0.01)
    finally:
        os.close(process)

    raise OSError(errno.ETIMEDOUT, "QEMU multicast socket was not ready")
