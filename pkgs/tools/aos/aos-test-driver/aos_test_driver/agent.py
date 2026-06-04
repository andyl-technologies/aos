"""AgentClient — v2 wire-format RPC.

Wire format (both directions):

    Frame:        <body_len>\\n<body bytes>
    Request body: <command bytes — bash blob, OR "PING" / "SHUTDOWN">
    Response body:
        <exit_code> <stdout_len> <stderr_len>\\n<stdout bytes><stderr bytes>

PING and SHUTDOWN replies are bare ``0 0 0\\n`` (6-byte body) with no
trailing payload — the agent's stdout/stderr from a bash run are zero
bytes in those cases.

Transport differs by driver:

  - firecracker (vsock): each ``request()`` opens a fresh connection and
    negotiates the ``CONNECT 52\\n`` → ``OK <port>\\n`` handshake. The
    guest side is ``socat VSOCK-LISTEN,fork EXEC:agent-handler`` — one
    fork+exec per connection — so one connection genuinely is one
    request.
  - qemu (virtio-serial): a single connection is opened once and reused
    for the whole run. virtio-serial is a persistent byte stream and the
    guest agent holds its port open across requests; reconnecting per
    request would make both ends close+reopen the link, which races
    QEMU's virtio-serial port state machine under KVM and wedges the
    agent mid-run. The self-delimiting frame format already lets any
    number of request/response pairs ride one connection.
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
    """RPC client. firecracker opens a fresh connection per request;
    qemu reuses one persistent connection (see module docstring)."""

    name: str
    socket_path: str
    driver: Driver
    # qemu only: the persistent connection, opened lazily and reused.
    # None means "not yet connected" or "torn down after an error" —
    # the next request reopens it.
    _conn: socket.socket | None

    def __init__(self, name: str, socket_path: str, driver: str) -> None:
        if driver not in ("qemu", "firecracker"):
            raise ValueError(
                f"driver must be 'qemu' or 'firecracker', got {driver!r}"
            )
        self.name = name
        self.socket_path = socket_path
        # narrowed by the check above
        self.driver = driver  # type: ignore[assignment]
        self._conn = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def _persistent_conn(self, deadline: float) -> socket.socket:
        """Return the qemu persistent connection, opening it if needed."""
        conn = self._conn
        if conn is None:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(max(_remaining(deadline), 0.001))
            conn.connect(self.socket_path)
            self._conn = conn
        return conn

    def _reset_conn(self) -> None:
        """Drop the persistent connection. The next request reopens it.

        Called after any error: once a request fails mid-stream the
        connection is desynced (a response may be half-read or still
        outstanding) so it cannot be reused.
        """
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    def close(self) -> None:
        """Release the persistent connection (no-op for firecracker)."""
        self._reset_conn()

    # ------------------------------------------------------------------
    # Wire framing
    # ------------------------------------------------------------------
    def _parse_body(self, body: bytes) -> tuple[int, bytes, bytes]:
        nl = body.find(b"\n")
        if nl < 0:
            raise AgentProtocolError(
                self.name, "response body missing header newline"
            )
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

    def _read_frame(
        self, sock: socket.socket, deadline: float
    ) -> tuple[int, bytes, bytes]:
        """Read one length-prefixed response frame and parse it."""
        body_len_line = _read_line(sock, deadline)
        try:
            body_len = int(body_len_line)
        except ValueError:
            raise _ProtocolMidstream(
                f"non-numeric body length: {body_len_line!r}"
            )
        if body_len <= 0 or body_len > MAX_FRAME_BYTES:
            raise _ProtocolMidstream(f"body length {body_len} out of range")
        body = _read_n(sock, body_len, deadline)
        return self._parse_body(body)

    def _exchange(
        self, sock: socket.socket, payload: bytes, deadline: float
    ) -> tuple[int, bytes, bytes]:
        """Write one request frame and read its response frame."""
        _write_all(sock, f"{len(payload)}\n".encode("ascii"), deadline)
        _write_all(sock, payload, deadline)
        return self._read_frame(sock, deadline)

    # ------------------------------------------------------------------
    # Request paths
    # ------------------------------------------------------------------
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
        log.debug(
            "[%s] request: %r (%d bytes)", self.name, payload[:60], len(payload)
        )
        if self.driver == "qemu":
            return self._request_persistent(payload, deadline, timeout)
        return self._request_oneshot(payload, deadline, timeout)

    def _request_persistent(
        self, payload: bytes, deadline: float, timeout: float
    ) -> tuple[int, bytes, bytes]:
        """qemu: exchange over the reused connection; drop it on error."""
        try:
            sock = self._persistent_conn(deadline)
            return self._exchange(sock, payload, deadline)
        except TimeoutError:
            self._reset_conn()
            preview = payload[:80].decode("utf-8", errors="replace")
            raise AgentTimeout(self.name, preview, timeout)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            self._reset_conn()
            raise AgentProtocolError(
                self.name, f"connect {self.socket_path!r}: {e}"
            )
        except _ProtocolMidstream as e:
            self._reset_conn()
            raise AgentProtocolError(self.name, str(e))
        except OSError as e:
            self._reset_conn()
            raise AgentProtocolError(self.name, f"socket error: {e}")

    def _request_oneshot(
        self, payload: bytes, deadline: float, timeout: float
    ) -> tuple[int, bytes, bytes]:
        """firecracker: a fresh vsock connection + handshake per request."""
        t0 = time.monotonic()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(max(_remaining(deadline), 0.001))
                s.connect(self.socket_path)
                log.debug(
                    "[%s] connected in %.3fs", self.name, time.monotonic() - t0
                )
                _write_all(s, b"CONNECT 52\n", deadline)
                handshake = _read_line(s, deadline, max_bytes=128)
                if not handshake.startswith(b"OK"):
                    raise _ProtocolMidstream(
                        f"vsock handshake: expected 'OK …', got {handshake!r}"
                    )
                return self._exchange(s, payload, deadline)
        except TimeoutError:
            preview = payload[:80].decode("utf-8", errors="replace")
            raise AgentTimeout(self.name, preview, timeout)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise AgentProtocolError(
                self.name, f"connect {self.socket_path!r}: {e}"
            )
        except _ProtocolMidstream as e:
            raise AgentProtocolError(self.name, str(e))

    # ------------------------------------------------------------------
    # Startup handshake
    # ------------------------------------------------------------------
    def wait_ready(self, deadline: float) -> None:
        """Block until the agent answers a PING, or raise on deadline."""
        if self.driver == "qemu":
            self._wait_ready_qemu(deadline)
        else:
            self._wait_ready_oneshot(deadline)

    def _wait_ready_oneshot(self, deadline: float) -> None:
        """firecracker: a timed-out ping leaves nothing buffered (each
        attempt is its own vsock connection), so plain retry is safe."""
        while True:
            try:
                if self.ping(timeout=2):
                    return
            except AgentTimeout:
                pass
            except AgentProtocolError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"[{self.name}] agent did not become ready"
                    " before manifest timeout"
                )
            time.sleep(0.5)

    def _wait_ready_qemu(self, deadline: float) -> None:
        """qemu: the persistent connection is opened now and held for the
        whole run.

        The guest agent is not reading its virtio-serial port yet — it
        only starts once the VM finishes booting — so PINGs sent during
        boot are buffered by QEMU and answered in a burst once the agent
        comes up. Because this connection never drops, every PING gets
        exactly one reply. So we count PINGs still unanswered and drain
        them all before declaring the agent ready; that keeps the
        request/response stream strictly 1:1, which the persistent
        transport relies on for every subsequent command.

        Error handling is asymmetric on purpose:
          - read timeout: legitimate (agent still booting, PING sits in
            QEMU's chardev queue). Loop, keep the connection AND the
            outstanding count — the buffered reply is still owed to us.
          - write timeout: only happens if QEMU's chardev outbound
            buffer is full, which for a 6-byte payload means the link
            is genuinely stuck. Partial bytes may have landed on the
            wire, so we must reset the connection rather than write
            another PING on top of them — otherwise framing desyncs.
          - any other error: connection is torn, reset and restart the
            count.
        """
        ping_frame = f"{len(b'PING')}\n".encode("ascii") + b"PING"
        outstanding = 0
        while time.monotonic() < deadline:
            try:
                sock = self._persistent_conn(deadline)
            except OSError:
                # Connect failed (UDS not there yet, refused, …) — wait
                # for QEMU to come up.
                self._reset_conn()
                time.sleep(0.5)
                continue
            try:
                _write_all(sock, ping_frame, time.monotonic() + 5)
            except TimeoutError:
                # Partial write → wire framing is now compromised.
                self._reset_conn()
                outstanding = 0
                continue
            except (OSError, _ProtocolMidstream):
                self._reset_conn()
                outstanding = 0
                time.sleep(0.5)
                continue
            outstanding += 1
            try:
                # Drain every reply owed so far. If the agent is still
                # booting the first read times out and we loop, keeping
                # the count; once it is up the whole burst drains here.
                while outstanding > 0:
                    self._read_frame(sock, time.monotonic() + 3)
                    outstanding -= 1
                return
            except TimeoutError:
                continue
            except (OSError, _ProtocolMidstream):
                self._reset_conn()
                outstanding = 0
                time.sleep(0.5)
        raise RuntimeError(
            f"[{self.name}] agent did not become ready before manifest timeout"
        )

    # ------------------------------------------------------------------
    def ping(self, timeout: float = 2.0) -> bool:
        """Send PING; return True if the agent responded with a valid frame."""
        exit_code, _, _ = self.request(b"PING", timeout=timeout)
        return exit_code == 0

    def shutdown(self, timeout: float = 5.0) -> tuple[int, bytes, bytes]:
        """Send SHUTDOWN; the agent calls reboot/poweroff -f."""
        return self.request(b"SHUTDOWN", timeout=timeout)
