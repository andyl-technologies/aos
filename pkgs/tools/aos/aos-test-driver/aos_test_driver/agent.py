"""AgentClient — v2 wire-format RPC over a Unix domain socket.

Wire format (both directions):

    Frame:        <body_len>\\n<body bytes>
    Request body: <command bytes — bash blob, OR "PING" / "SHUTDOWN">
    Response body:
        <exit_code> <stdout_len> <stderr_len>\\n<stdout bytes><stderr bytes>

PING and SHUTDOWN replies are bare ``0 0 0\\n`` (6-byte body) with no
trailing payload — the agent's stdout/stderr from a bash run are zero
bytes in those cases.

Each call opens a fresh connection. For Firecracker we first negotiate
the vsock CONNECT handshake (``CONNECT 52\\n`` → ``OK <port>\\n``).
"""

import logging
import socket
import time
from typing import Literal

from .errors import AgentProtocolError, AgentTimeout

log: logging.Logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT: float = 30
# Same upper bound the agent enforces; mismatched limits would let the
# host send a request the agent silently rejects.
MAX_FRAME_BYTES: int = 16 * 1024 * 1024

Driver = Literal["qemu", "firecracker"]


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _read_n(sock: socket.socket, n: int, deadline: float) -> bytes:
    out = bytearray()
    while len(out) < n:
        sock.settimeout(max(_remaining(deadline), 0.001))
        try:
            chunk = sock.recv(n - len(out))
        except socket.timeout:
            raise TimeoutError("recv timed out")
        if not chunk:
            raise _ProtocolMidstream(
                f"socket closed after {len(out)} of {n} bytes"
            )
        out += chunk
    return bytes(out)


def _read_line(sock: socket.socket, deadline: float, max_bytes: int = 64) -> bytes:
    out = bytearray()
    while True:
        if len(out) >= max_bytes:
            raise _ProtocolMidstream(f"line exceeds {max_bytes} bytes")
        b = _read_n(sock, 1, deadline)
        if b == b"\n":
            return bytes(out)
        out += b


def _write_all(sock: socket.socket, data: bytes, deadline: float) -> None:
    pos = 0
    while pos < len(data):
        sock.settimeout(max(_remaining(deadline), 0.001))
        try:
            n = sock.send(data[pos:])
        except socket.timeout:
            raise TimeoutError("send timed out")
        if n == 0:
            raise _ProtocolMidstream("socket write returned 0")
        pos += n


class _ProtocolMidstream(Exception):
    """Internal: protocol violation discovered mid-request. Re-raised as
    AgentProtocolError once the machine name is in scope."""


class AgentClient:
    """One-shot RPC client. Each ``request()`` opens a fresh connection."""

    name: str
    socket_path: str
    driver: Driver

    def __init__(self, name: str, socket_path: str, driver: str) -> None:
        if driver not in ("qemu", "firecracker"):
            raise ValueError(
                f"driver must be 'qemu' or 'firecracker', got {driver!r}"
            )
        self.name = name
        self.socket_path = socket_path
        # narrowed by the check above
        self.driver = driver  # type: ignore[assignment]

    def request(
        self, payload: bytes, timeout: float = DEFAULT_TIMEOUT
    ) -> tuple[int, bytes, bytes]:
        """Send ``payload`` to the agent and return (exit_code, stdout, stderr).

        Raises ``AgentTimeout`` on the overall RPC deadline,
        ``AgentProtocolError`` on a malformed wire response.
        """
        if len(payload) > MAX_FRAME_BYTES:
            raise AgentProtocolError(
                self.name,
                f"request {len(payload)} bytes exceeds {MAX_FRAME_BYTES}",
            )

        deadline = time.monotonic() + timeout
        log.debug("[%s] request: %r (%d bytes)", self.name, payload[:60], len(payload))
        t0 = time.monotonic()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(max(_remaining(deadline), 0.001))
                s.connect(self.socket_path)
                log.debug("[%s] connected in %.3fs", self.name, time.monotonic() - t0)

                if self.driver == "firecracker":
                    _write_all(s, b"CONNECT 52\n", deadline)
                    handshake = _read_line(s, deadline, max_bytes=128)
                    if not handshake.startswith(b"OK"):
                        raise _ProtocolMidstream(
                            f"vsock handshake: expected 'OK …', got {handshake!r}"
                        )

                frame_prefix = f"{len(payload)}\n".encode("ascii")
                _write_all(s, frame_prefix, deadline)
                _write_all(s, payload, deadline)
                log.debug("[%s] wrote request in %.3fs, reading...", self.name, time.monotonic() - t0)

                body_len_line = _read_line(s, deadline)
                log.debug("[%s] got length line %r in %.3fs", self.name, body_len_line, time.monotonic() - t0)
                try:
                    body_len = int(body_len_line)
                except ValueError:
                    raise _ProtocolMidstream(
                        f"non-numeric body length: {body_len_line!r}"
                    )
                if body_len <= 0 or body_len > MAX_FRAME_BYTES:
                    raise _ProtocolMidstream(
                        f"body length {body_len} out of range"
                    )
                body = _read_n(s, body_len, deadline)
        except TimeoutError:
            preview = payload[:80].decode("utf-8", errors="replace")
            raise AgentTimeout(self.name, preview, timeout)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise AgentProtocolError(self.name, f"connect {self.socket_path!r}: {e}")
        except _ProtocolMidstream as e:
            raise AgentProtocolError(self.name, str(e))

        nl = body.find(b"\n")
        if nl < 0:
            raise AgentProtocolError(self.name, "response body missing header newline")
        header = body[:nl]
        parts = header.split()
        if len(parts) != 3:
            raise AgentProtocolError(
                self.name, f"malformed response header: {header!r}"
            )
        try:
            exit_code, stdout_len, stderr_len = (int(x) for x in parts)
        except ValueError:
            raise AgentProtocolError(
                self.name, f"non-numeric response header: {header!r}"
            )
        payload_start = nl + 1
        expected = payload_start + stdout_len + stderr_len
        if expected != len(body):
            raise AgentProtocolError(
                self.name,
                f"response body length {len(body)} != header {payload_start}"
                f"+{stdout_len}+{stderr_len}={expected}",
            )
        stdout = body[payload_start : payload_start + stdout_len]
        stderr = body[payload_start + stdout_len :]
        return exit_code, stdout, stderr

    def ping(self, timeout: float = 2.0) -> bool:
        """Send PING; return True if the agent responded with a valid frame."""
        exit_code, _, _ = self.request(b"PING", timeout=timeout)
        return exit_code == 0

    def shutdown(self, timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        """Send SHUTDOWN; the agent calls reboot/poweroff -f."""
        return self.request(b"SHUTDOWN", timeout=timeout)
