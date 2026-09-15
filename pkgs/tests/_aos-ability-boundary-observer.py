"""Protected test controller for native execution-boundary fault injection.

The controller acknowledges canonical events until the root-owned target
selects one operation boundary. A disconnect target durably records that event
and holds the connection open while the fleet driver kills the package process
or QEMU machine. A pause target resumes only after the driver publishes its
sequence marker, which permits a controlled live-resource ownership change at
the real post-intent boundary. Recovery likewise holds the returned
reconciliation observation until release. The controls never select an adapter
result or bypass authorization.
"""

import hashlib
import json
import os
import socket
import struct
import sys
from pathlib import Path
from typing import Any


FORWARD_SOCKET_ENV = "AOS_ABILITY_FORWARD_SOCKET"
STATE_ROOT: Path
EVENT_LOG: Path
HELD_EVENT: Path
RESUMED_EVENT: Path
CONTINUE: Path
TARGET: Path
EVENT_SCHEMA = "aos.ability-execution-boundary-event/v1"
ACK_SCHEMA = "aos.ability-execution-boundary-ack/v1"
EVENT_DIGEST_DOMAIN = b"aos.ability-execution-boundary-event/v1\0"
MAX_FRAME_BYTES = 16 * 1024


def canonical_absolute_path(value: str, label: str) -> Path:
    """Parse one normalized absolute path from package-owned configuration."""
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError(f"{label} must be absolute and normalized")
    return path


def configure_state_root(value: str) -> None:
    """Bind all persistent fixture paths below one configured allocation."""
    global STATE_ROOT, EVENT_LOG, HELD_EVENT, RESUMED_EVENT, CONTINUE, TARGET

    STATE_ROOT = canonical_absolute_path(value, "state root")
    EVENT_LOG = STATE_ROOT / "events.jsonl"
    HELD_EVENT = STATE_ROOT / "held-event.json"
    RESUMED_EVENT = STATE_ROOT / "resumed-event.json"
    CONTINUE = STATE_ROOT / "continue.json"
    TARGET = STATE_ROOT / "target.json"


def canonical_bytes(value: Any) -> bytes:
    """Encode one value in the canonical JSON subset used by the test."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def read_exact(connection: socket.socket, length: int) -> bytes:
    """Read an exact byte count or report an unexpected peer close."""
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            raise EOFError("execution-boundary peer closed mid-frame")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(connection: socket.socket) -> bytes:
    """Read one bounded, big-endian length-framed message."""
    length = struct.unpack(">I", read_exact(connection, 4))[0]
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"execution-boundary frame exceeds {MAX_FRAME_BYTES} bytes")
    return read_exact(connection, length)


def write_frame(connection: socket.socket, payload: bytes) -> None:
    """Write one bounded, big-endian length-framed message."""
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError(f"execution-boundary frame exceeds {MAX_FRAME_BYTES} bytes")
    connection.sendall(struct.pack(">I", len(payload)) + payload)


def sync_directory(path: Path) -> None:
    """Persist a directory entry update before exposing it to the driver."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_canonical(path: Path, value: Any) -> None:
    """Atomically replace one canonical document and its directory entry."""
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("wb") as output:
        output.write(canonical_bytes(value))
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    sync_directory(path.parent)


def fixture_path(argument: str) -> Path:
    """Resolve one fixture-owned path below the persistent state root."""
    path = Path(argument)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("fixture path must be absolute and normalized")
    try:
        path.relative_to(STATE_ROOT)
    except ValueError as error:
        raise ValueError(f"fixture path escapes {STATE_ROOT}") from error
    return path


def persist_file(path: Path) -> None:
    """Persist an existing fixture input and the directory naming it."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    sync_directory(path.parent)


def append_event(payload: bytes) -> None:
    """Durably append an exact canonical event to the persistent transcript."""
    with EVENT_LOG.open("ab") as output:
        output.write(payload + b"\n")
        output.flush()
        os.fsync(output.fileno())


def load_target() -> dict[str, Any] | None:
    """Load the current root-owned hold target when the driver armed one."""
    try:
        payload = TARGET.read_bytes()
    except FileNotFoundError:
        return None
    target = json.loads(payload)
    if canonical_bytes(target) != payload:
        raise ValueError("execution-boundary target is not canonical")
    operation_key_fields = {"boundary", "operation_key", "purpose", "sequence"}
    operation_selector_fields = {
        "boundary",
        "interface",
        "method",
        "provider_key",
        "purpose",
        "resource_key",
        "sequence",
    }
    target_fields = set(target)
    if target_fields == operation_key_fields or target_fields == operation_selector_fields:
        target["action"] = "disconnect"
    elif (
        target_fields != operation_key_fields | {"action"}
        and target_fields != operation_selector_fields | {"action"}
    ):
        raise ValueError("execution-boundary target has unexpected fields")
    if target["action"] not in {"disconnect", "pause"}:
        raise ValueError("execution-boundary target has an unknown action")
    return target


def held_sequence() -> str | None:
    """Return the sequence already held across a service or machine restart."""
    try:
        held = json.loads(HELD_EVENT.read_bytes())
    except FileNotFoundError:
        return None
    sequence = held.get("sequence")
    return sequence if isinstance(sequence, str) else None


def matches_operation(event: dict[str, Any], target: dict[str, Any]) -> bool:
    """Match only the selected operation identity."""
    operation = event.get("operation", {}).get("operation", {})
    if "operation_key" in target:
        return operation.get("key") == target["operation_key"]

    resource = operation.get("target", {}).get("resource", {})
    provider = resource.get("provider", {})
    interface = operation.get("interface", {})
    return (
        interface.get("name") == target["interface"]
        and operation.get("method") == target["method"]
        and provider.get("key") == target["provider_key"]
        and resource.get("key") == target["resource_key"]
    )


def matches_initial_boundary(event: dict[str, Any], target: dict[str, Any]) -> bool:
    """Match the selected first-attempt boundary before its durable outcome."""
    return (
        matches_operation(event, target)
        and event.get("boundary") == target["boundary"]
        and event.get("purpose") == target["purpose"]
        and held_sequence() != target["sequence"]
    )


def matches_recovery_boundary(event: dict[str, Any], target: dict[str, Any]) -> bool:
    """Match returned reconciliation for the already interrupted attempt."""
    return (
        matches_operation(event, target)
        and event.get("boundary") == "reconciliation-returned"
        and event.get("purpose") == "reconcile"
        and held_sequence() == target["sequence"]
        and continued_sequence() != target["sequence"]
    )


def event_digest(payload: bytes) -> str:
    """Compute the protocol's domain-separated exact-byte event identity."""
    digest = hashlib.sha256(EVENT_DIGEST_DOMAIN + payload).hexdigest()
    return f"sha256:{digest}"


def acknowledge(connection: socket.socket, payload: bytes) -> None:
    """Send the protocol's sole digest-bound continue action."""
    acknowledgement = {
        "action": "continue",
        "event_digest": event_digest(payload),
        "schema": ACK_SCHEMA,
    }
    write_frame(connection, canonical_bytes(acknowledgement))


def forward_to_adapter(payload: bytes) -> dict[str, Any] | None:
    """Deliver one event through an optional digest-bound observer hop."""
    socket_path = os.environ.get(FORWARD_SOCKET_ENV)
    if socket_path is None:
        return None
    if not socket_path.startswith("/") or ".." in Path(socket_path).parts:
        raise ValueError("execution-boundary forward socket is not canonical")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(socket_path)
        write_frame(connection, payload)
        acknowledgement_payload = read_frame(connection)

    acknowledgement = json.loads(acknowledgement_payload)
    if canonical_bytes(acknowledgement) != acknowledgement_payload:
        raise ValueError("forwarded execution-boundary acknowledgement is not canonical")
    if set(acknowledgement) != {"action", "event_digest", "schema"}:
        raise ValueError("forwarded execution-boundary acknowledgement has unexpected fields")
    if acknowledgement != {
        "action": "continue",
        "event_digest": event_digest(payload),
        "schema": ACK_SCHEMA,
    }:
        raise ValueError("forwarded execution-boundary acknowledgement does not match event")

    return acknowledgement


def hold_until_peer_loss(
    connection: socket.socket,
    event: dict[str, Any],
    payload: bytes,
    sequence: str,
    forwarded_acknowledgement: dict[str, Any] | None,
) -> None:
    """Publish the held boundary durably, then wait for process or power loss."""
    replace_canonical(
        HELD_EVENT,
        {
            "event": event,
            "event_digest": event_digest(payload),
            "forwarded_acknowledgement": forwarded_acknowledgement,
            "sequence": sequence,
        },
    )
    connection.settimeout(0.2)
    while True:
        try:
            if not connection.recv(1):
                return
            raise ValueError("held execution-boundary peer sent unexpected bytes")
        except TimeoutError:
            continue


def pause_until_continued(
    connection: socket.socket,
    event: dict[str, Any],
    payload: bytes,
    sequence: str,
    forwarded_acknowledgement: dict[str, Any] | None,
) -> None:
    """Publish one held boundary and resume only after the driver releases it."""
    replace_canonical(
        HELD_EVENT,
        {
            "event": event,
            "event_digest": event_digest(payload),
            "forwarded_acknowledgement": forwarded_acknowledgement,
            "sequence": sequence,
        },
    )
    while continued_sequence() != sequence:
        connection.settimeout(0.2)
        try:
            if not connection.recv(1):
                return
            raise ValueError("paused execution-boundary peer sent unexpected bytes")
        except TimeoutError:
            continue
    acknowledge(connection, payload)


def continued_sequence() -> str | None:
    """Return the sequence the root-owned driver has released."""
    try:
        payload = CONTINUE.read_bytes()
    except FileNotFoundError:
        return None
    continuation = json.loads(payload)
    if canonical_bytes(continuation) != payload:
        raise ValueError("execution-boundary continuation is not canonical")
    if set(continuation) != {"sequence"}:
        raise ValueError("execution-boundary continuation has unexpected fields")
    sequence = continuation["sequence"]
    return sequence if isinstance(sequence, str) else None


def hold_until_continued(
    connection: socket.socket,
    event: dict[str, Any],
    payload: bytes,
    sequence: str,
    forwarded_acknowledgement: dict[str, Any] | None,
) -> None:
    """Expose returned reconciliation, then wait for the driver's release."""
    replace_canonical(
        RESUMED_EVENT,
        {
            "event": event,
            "event_digest": event_digest(payload),
            "forwarded_acknowledgement": forwarded_acknowledgement,
            "sequence": sequence,
        },
    )
    while continued_sequence() != sequence:
        connection.settimeout(0.2)
        try:
            if not connection.recv(1):
                return
            raise ValueError("held reconciliation peer sent unexpected bytes")
        except TimeoutError:
            continue
    acknowledge(connection, payload)


def serve_connection(connection: socket.socket) -> None:
    """Serve one package-runtime connection until it exits or is killed."""
    while True:
        try:
            payload = read_frame(connection)
        except EOFError:
            return
        event = json.loads(payload)
        if canonical_bytes(event) != payload:
            raise ValueError("execution-boundary event is not canonical")
        if event.get("schema") != EVENT_SCHEMA:
            raise ValueError("execution-bound event uses an unknown schema")
        append_event(payload)
        forwarded_acknowledgement = forward_to_adapter(payload)

        target = load_target()
        if target is not None and matches_initial_boundary(event, target):
            if target["action"] == "pause":
                pause_until_continued(
                    connection,
                    event,
                    payload,
                    target["sequence"],
                    forwarded_acknowledgement,
                )
                continue
            else:
                hold_until_peer_loss(
                    connection,
                    event,
                    payload,
                    target["sequence"],
                    forwarded_acknowledgement,
                )
                return
        if target is not None and matches_recovery_boundary(event, target):
            hold_until_continued(
                connection,
                event,
                payload,
                target["sequence"],
                forwarded_acknowledgement,
            )
            continue
        acknowledge(connection, payload)


def inherited_listener() -> socket.socket | None:
    """Adopt the single socket passed by the service manager when present."""
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = os.environ.get("LISTEN_FDS")
    if listen_pid is None and listen_fds is None:
        return None
    if listen_pid != str(os.getpid()) or listen_fds != "1":
        raise ValueError("socket activation must pass exactly one descriptor")
    return socket.socket(fileno=3)


def main(socket_path: Path) -> None:
    """Serve package runtimes through the inherited or configured socket."""
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    sync_directory(STATE_ROOT.parent)

    activated = inherited_listener()
    with activated or socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        if activated is None:
            socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                socket_path.unlink()
            except FileNotFoundError:
                pass
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o600)
            listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection:
                serve_connection(connection)


def run(arguments: list[str]) -> None:
    """Parse one closed controller command and execute it."""
    if arguments == ["--version"]:
        print("aos-ability-boundary-observer 1")
        return
    if len(arguments) < 3 or arguments[0] != "--state-root":
        raise ValueError("a state root and one controller command are required")

    configure_state_root(arguments[1])
    command = arguments[2]
    operands = arguments[3:]
    if command == "--version" and operands == []:
        print("aos-ability-boundary-observer 1")
        return
    if command == "serve" and len(operands) == 2 and operands[0] == "--socket":
        main(canonical_absolute_path(operands[1], "socket path"))
        return
    if command == "persist-file" and len(operands) == 1:
        persist_file(fixture_path(operands[0]))
        return
    if command == "write-canonical" and len(operands) == 2:
        path = fixture_path(operands[0])
        payload = bytes.fromhex(operands[1])
        value = json.loads(payload)
        if canonical_bytes(value) != payload:
            raise ValueError("fixture control input is not canonical")
        replace_canonical(path, value)
        return
    raise ValueError("unknown execution-boundary controller command")


if __name__ == "__main__":
    try:
        run(sys.argv[1:])
    except (OSError, ValueError) as error:
        print(
            f"aos-ability-boundary-observer rejected invalid input: {error}",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
