"""Configures only an owned QEMU child's multicast socket on Linux."""

import ctypes
import errno
import os
import re
import socket
import time
from pathlib import Path


class _SocketFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jump_true", ctypes.c_ubyte),
        ("jump_false", ctypes.c_ubyte),
        ("value", ctypes.c_uint),
    ]


class _SocketFilterProgram(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("instructions", ctypes.POINTER(_SocketFilter)),
    ]


def filter_unicast(network: socket.socket, destination_mac: str) -> None:
    """Keeps this NIC's frames and all Ethernet broadcast/multicast traffic.

    QEMU's multicast datagrams contain raw Ethernet frames. Filtering before
    queue admission prevents another VM's bulk transfer from filling this
    socket with unicast frames that this NIC would discard anyway. Tests that
    need promiscuous reception leave filtering disabled.

    Linux's socket drop counter includes intentional filter rejections; it no
    longer measures receive queue overflow alone once this filter is attached.
    """
    if re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", destination_mac) is None:
        raise ValueError("invalid fleet destination MAC")
    address = bytes.fromhex(destination_mac.replace(":", ""))
    if address[0] & 1:
        raise ValueError("fleet destination MAC must be unicast")

    # Linux presents the eight-byte UDP header to an AF_INET datagram filter.
    # Classic BPF loads are in network byte order. Accepted frames are returned
    # whole; no packet data or guest protocol is rewritten.
    load_length = 0x80
    load_byte = 0x30
    load_word = 0x20
    load_half = 0x28
    jump_at_least = 0x35
    jump_bits = 0x45
    jump_equal = 0x15
    return_constant = 0x06
    instructions = (_SocketFilter * 10)(
        _SocketFilter(load_length, 0, 0, 0),
        _SocketFilter(jump_at_least, 0, 7, 8 + 14),
        _SocketFilter(load_byte, 0, 0, 8),
        _SocketFilter(jump_bits, 4, 0, 1),
        _SocketFilter(load_word, 0, 0, 8),
        _SocketFilter(jump_equal, 0, 3, int.from_bytes(address[:4], "big")),
        _SocketFilter(load_half, 0, 0, 12),
        _SocketFilter(jump_equal, 0, 1, int.from_bytes(address[4:], "big")),
        _SocketFilter(return_constant, 0, 0, 0xFFFFFFFF),
        _SocketFilter(return_constant, 0, 0, 0),
    )
    program = _SocketFilterProgram(len(instructions), instructions)
    # SO_ATTACH_FILTER is part of Linux's socket ABI but is not exported by
    # every Python build. The kernel copies the instructions during setsockopt.
    attach_filter = getattr(socket, "SO_ATTACH_FILTER", 26)
    network.setsockopt(socket.SOL_SOCKET, attach_filter, bytes(program))


def configure_multicast_buffers(
    process_id: int,
    endpoint: tuple[str, int],
    requested_bytes: int = 4 * 1024 * 1024,
    *,
    destination_mac: str | None = None,
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

                        if destination_mac is not None:
                            filter_unicast(network, destination_mac)
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
