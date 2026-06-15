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

    def wait_down(self, deadline: float) -> None:
        """Block until the agent stops answering PING (qemu in-VM reset).

        The in-VM-reset reboot path keeps QEMU (and its swtpm) running, so
        the pre-reboot agent keeps answering for the moment between issuing
        ``reboot`` and the kernel tearing the transport down. Callers must
        see the agent go silent before waiting for the new boot, or a PONG
        from the *old* boot is mistaken for the reboot having completed.

        Returns once two consecutive fresh-connection PINGs fail (the
        guest is rebooting), or when ``deadline`` passes (caller's
        subsequent ``wait_ready`` still bounds the overall wait).

        # Errors

        Never raises; a missed transition degrades to the readiness wait.
        """
        if self.driver != "qemu":
            return
        ping_frame = f"{len(b'PING')}\n".encode("ascii") + b"PING"
        consecutive_down = 0
        while time.monotonic() < deadline:
            self._reset_conn()
            try:
                sock = self._persistent_conn(time.monotonic() + 2)
                _write_all(sock, ping_frame, time.monotonic() + 2)
                self._read_frame(sock, time.monotonic() + 2)
                consecutive_down = 0  # still up
            except (OSError, TimeoutError, AgentProtocolError):
                consecutive_down += 1
                if consecutive_down >= 2:
                    self._reset_conn()
                    return
            time.sleep(0.3)
        self._reset_conn()

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
        """qemu: probe with one fresh connection + one PING per attempt;
        the connection that gets a reply becomes the persistent one.

        A PING written before the guest's virtio-serial port is up is
        NOT reliably buffered: while the port (or the whole
        virtio-console device, early in boot) is closed, QEMU can drop
        chardev bytes outright. A held connection therefore overcounts
        "replies owed" — the drain ledger never balances and readiness
        is never declared, even with the agent up and answering (seen
        on image-boot machines after a reboot: outstanding stuck at the
        number of PINGs sent during firmware/kernel bring-up).

        A fresh connection per attempt makes the accounting trivial:
        PINGs from previous attempts died with their connections (the
        guest's replies to them, if any, were written to a disconnected
        client and dropped by QEMU — they cannot leak into the new
        connection), so the first answered PING proves a strictly 1:1
        stream on the connection we keep, which is the invariant the
        persistent transport needs for every subsequent command.
        """
        ping_frame = f"{len(b'PING')}\n".encode("ascii") + b"PING"
        attempts = 0
        while time.monotonic() < deadline:
            self._reset_conn()
            attempts += 1
            try:
                sock = self._persistent_conn(deadline)
            except OSError as e:
                # Connect failed (UDS not there yet, refused, …) — wait
                # for QEMU to come up.
                if attempts % 20 == 1:
                    log.info(
                        "[%s] wait_ready: connect failed (%s), retrying",
                        self.name,
                        e,
                    )
                time.sleep(0.5)
                continue
            try:
                _write_all(sock, ping_frame, time.monotonic() + 5)
                self._read_frame(sock, time.monotonic() + 3)
                # Reply received. Almost certainly ours — but a PING
                # from a previous attempt that was still in flight when
                # we reconnected can produce a stray extra reply on
                # THIS connection. Confirm the stream is quiet before
                # declaring it the persistent conn; if a stray shows
                # up, discard the connection and probe again.
                try:
                    self._read_frame(sock, time.monotonic() + 0.25)
                except TimeoutError:
                    # Quiet → strictly 1:1; keep this connection.
                    return
                if attempts % 20 == 1:
                    log.info(
                        "[%s] wait_ready: stray reply drained, re-probing",
                        self.name,
                    )
                continue
            except TimeoutError:
                # Agent not up yet (or the PING fell into the
                # port-closed window) — discard this connection and
                # probe again.
                if attempts % 20 == 1:
                    log.info(
                        "[%s] wait_ready: no reply yet (attempt %d)",
                        self.name,
                        attempts,
                    )
                continue
            except (OSError, _ProtocolMidstream) as e:
                if attempts % 20 == 1:
                    log.info(
                        "[%s] wait_ready: probe failed (%s), retrying",
                        self.name,
                        e,
                    )
                time.sleep(0.5)
        self._reset_conn()
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
