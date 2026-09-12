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


SOCKET_PATH = Path("/run/aos-instrumentation/controller.sock")
FORWARD_SOCKET_ENV = "AOS_ABILITY_FORWARD_SOCKET"
STATE_ROOT = Path("/var/lib/aos/ability-boundary-test")
EVENT_LOG = STATE_ROOT / "events.jsonl"
HELD_EVENT = STATE_ROOT / "held-event.json"
RESUMED_EVENT = STATE_ROOT / "resumed-event.json"
CONTINUE = STATE_ROOT / "continue.json"
TARGET = STATE_ROOT / "target.json"
EVENT_SCHEMA = "aos.ability-execution-boundary-event/v1"
ACK_SCHEMA = "aos.ability-execution-boundary-ack/v1"
EVENT_DIGEST_DOMAIN = b"aos.ability-execution-boundary-event/v1\0"
MAX_FRAME_BYTES = 16 * 1024


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
    legacy_fields = {"boundary", "operation_key", "purpose", "sequence"}
    if set(target) == legacy_fields:
        target["action"] = "disconnect"
    elif set(target) != legacy_fields | {"action"}:
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
    return operation.get("key") == target["operation_key"]


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


def main() -> None:
    """Bind the protected socket and serve package runtimes serially."""
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    sync_directory(STATE_ROOT.parent)
    SOCKET_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(SOCKET_PATH))
        os.chmod(SOCKET_PATH, 0o600)
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection:
                serve_connection(connection)


def command(arguments: list[str]) -> bool:
    """Persist fixture control input when invoked outside server mode."""
    if len(arguments) == 3 and arguments[1] == "persist-file":
        persist_file(fixture_path(arguments[2]))
        return True
    if len(arguments) == 4 and arguments[1] == "write-canonical":
        path = fixture_path(arguments[2])
        payload = bytes.fromhex(arguments[3])
        value = json.loads(payload)
        if canonical_bytes(value) != payload:
            raise ValueError("fixture control input is not canonical")
        replace_canonical(path, value)
        return True
    if len(arguments) == 1:
        return False
    raise ValueError("unknown execution-boundary controller command")


if __name__ == "__main__":
    if not command(sys.argv):
        main()
