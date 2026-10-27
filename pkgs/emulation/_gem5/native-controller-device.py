# SPDX-License-Identifier: MIT
"""Shared stopped native control for explicitly installed model adapters.

The legacy production owner is independent. This successor engine is not
registered for production admission; model adapters are source-owned code,
never selected from an operator-provided module path.

Frames use the shared uint32_be length plus closed UTF-8 JSON convention. This
channel supplies genuine native receipts, not public execution authority. The
owner stays between native events while reading controller commands. No drain,
synthetic horizon event, architectural checkpoint or stock fork is used.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys

import m5

sys.dont_write_bytecode = True


FRAME_LIMIT = 4 * 1024 * 1024
MAX_EVENTS = 10_000_000
MAX_OUTPUT = 65536
MAX_OPERATIONS = 65536
MAX_RETAINED_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 4 * 1024 * 1024
MAX_DIAGNOSTIC_TOTAL = 256 * 1024 * 1024
MAX_DIAGNOSTIC_FILES = 1024
U64_MAX = (1 << 64) - 1


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("private native frame has unknown or missing fields")
    return value


def u64(value):
    if (
        not isinstance(value, str) or not value.isascii() or not value.isdecimal()
        or (len(value) > 1 and value[0] == "0") or int(value) > U64_MAX
    ):
        raise ValueError("native integer is not a canonical u64 decimal string")
    return int(value)


def unique_object(items):
    value = {}
    for key, member in items:
        if key in value:
            raise ValueError("duplicate private native object key")
        value[key] = member
    return value


def receive(stream):
    def exact(length):
        result = bytearray()
        while len(result) < length:
            part = stream.recv(length - len(result))
            if not part:
                raise EOFError("native controller disconnected")
            result.extend(part)
        return bytes(result)

    length = struct.unpack("!I", exact(4))[0]
    if not 0 < length <= FRAME_LIMIT:
        raise ValueError("private native frame exceeds its allowance")
    return json.loads(
        exact(length).decode("utf-8"), object_pairs_hook=unique_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON number")),
    )


def send(stream, value):
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()
    if not 0 < len(encoded) <= FRAME_LIMIT:
        raise ValueError("native receipt exceeds frame allowance")
    try:
        stream.sendall(struct.pack("!I", len(encoded)) + encoded)
    except (BrokenPipeError, ConnectionResetError):
        # Original receipts and native state remain retained. The next read
        # re-establishes the same private route without servicing any event.
        pass


def connect(path, controller_uid):
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.connect(path)
    _, uid, _ = struct.unpack("3i", stream.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    ))
    if uid != controller_uid:
        stream.close()
        raise ValueError("native controller kernel credential differs")
    return stream


def diagnostic_census(directory):
    """Counts private original blobs without accepting aliases or unknown leaves."""
    directory.mkdir(mode=0o700, exist_ok=True)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode) or directory.resolve() != directory
        or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
    ):
        raise ValueError("native diagnostic directory lacks private canonical custody")
    count = 0
    total = 0
    for member in directory.iterdir():
        count += 1
        if count > MAX_DIAGNOSTIC_FILES:
            raise ValueError("native diagnostic census exceeds admitted file credit")
        name = member.name
        metadata = member.lstat()
        if (
            len(name) != 69 or not name.endswith(".json")
            or any(character not in "0123456789abcdef" for character in name[:-5])
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= MAX_DIAGNOSTIC_BYTES
        ):
            raise ValueError("native diagnostic census contains an unowned or invalid leaf")
        total += metadata.st_size
        if total > MAX_DIAGNOSTIC_TOTAL:
            raise ValueError("native diagnostic census exceeds admitted byte credit")
    return count, total


def reserve_diagnostic():
    """Reserves storage for the largest admitted full observation before events."""
    count, total = diagnostic_census(resource_root / "native-diagnostics")
    credit = {
        "required_files": "1", "available_files": str(MAX_DIAGNOSTIC_FILES - count),
        "required_bytes": str(MAX_DIAGNOSTIC_BYTES),
        "available_bytes": str(MAX_DIAGNOSTIC_TOTAL - total),
        "reserved_files": "0", "reserved_bytes": "0",
    }
    if count >= MAX_DIAGNOSTIC_FILES or total + MAX_DIAGNOSTIC_BYTES > MAX_DIAGNOSTIC_TOTAL:
        return None, credit

    # A real file allocation reserves filesystem capacity as well as protocol
    # credit. It is consumed by the next full observation, never a guest input.
    path = resource_root / ".native-diagnostic-reservation"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.posix_fallocate(descriptor, 0, MAX_DIAGNOSTIC_BYTES)
    except OSError:
        os.close(descriptor)
        path.unlink()
        # An operational filesystem failure does not change logical credit.
        # Preserve ordinary transport uncertainty rather than inventing a
        # zero-byte census or a successful original refusal receipt.
        raise
    return (descriptor, path), credit


def release_diagnostic(reservation):
    """Releases unused operational storage without touching original blobs."""
    if reservation is not None:
        descriptor, path = reservation
        os.close(descriptor)
        path.unlink()


def native_inventory(reservation=None):
    if not hasattr(m5, "crucibleStateInventory"):
        release_diagnostic(reservation)
        return {
            "schema": "crucible.gem5.modeled-state.v1", "complete": False,
            "unsupported_domains": ["native-modeled-state-observer-unavailable"],
            "native_tick": str(m5.curTick()),
        }
    inventory = model.native_inventory()
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema") != "crucible.gem5.causal-device-state.v1"
        or not isinstance(inventory.get("complete"), bool)
        or not isinstance(inventory.get("unsupported_domains"), list)
        or inventory.get("native_tick") != str(m5.curTick())
    ):
        raise ValueError("native state observer returned an invalid inventory")
    # Full CPU pipeline visitors can exceed private control credit. Preserve
    # every original byte in an immutable diagnostic object, while the explicit
    # summary schema avoids pretending section digests are typed field bodies.
    encoded = json.dumps(inventory, separators=(",", ":"), sort_keys=True,
                         allow_nan=False).encode()
    if len(encoded) > MAX_DIAGNOSTIC_BYTES:
        raise ValueError("native full diagnostic object exceeds its allowance")
    digest = hashlib.sha256(encoded).hexdigest()
    directory = resource_root / "native-diagnostics"
    count, total = diagnostic_census(directory)
    target = directory / f"{digest}.json"
    if target.exists():
        metadata = target.lstat()
        if not target.is_file() or target.is_symlink() or metadata.st_nlink != 1:
            raise ValueError("native diagnostic object has shared or symbolic custody")
        with target.open("rb") as source:
            if source.read(MAX_DIAGNOSTIC_BYTES + 1) != encoded:
                raise ValueError("original native diagnostic object changed")
    else:
        if count >= MAX_DIAGNOSTIC_FILES:
            raise ValueError("native diagnostic inventory credit exhausted")
        if total + len(encoded) > MAX_DIAGNOSTIC_TOTAL:
            raise ValueError("native diagnostic retained byte credit exhausted")
        if reservation is None:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(encoded)
                destination.flush()
                os.fsync(destination.fileno())
        else:
            descriptor, path = reservation
            cursor = 0
            while cursor < len(encoded):
                written = os.write(descriptor, encoded[cursor:])
                if written <= 0:
                    raise OSError("native diagnostic reservation write made no progress")
                cursor += written
            os.ftruncate(descriptor, len(encoded))
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            # Linking refuses an existing target atomically. The temporary link
            # is removed before publishing the original immutable blob route.
            os.link(path, target, follow_symlinks=False)
    release_diagnostic(reservation)
    sections = []
    for name, value in sorted(inventory.items()):
        if name in ("schema", "complete", "native_tick", "unsupported_domains"):
            continue
        section = json.dumps(value, separators=(",", ":"), sort_keys=True,
                             allow_nan=False).encode()
        sections.append({"name": name, "bytes": str(len(section)),
                         "sha256": hashlib.sha256(section).hexdigest()})
    return {
        "schema": "crucible.gem5.modeled-state-summary.v1",
        "native_schema": inventory["schema"], "complete": False,
        "native_complete": inventory["complete"], "native_tick": inventory["native_tick"],
        "unsupported_domains": inventory["unsupported_domains"],
        "full_blob": {"path": f"native-diagnostics/{digest}.json",
                      "bytes": str(len(encoded)), "sha256": digest},
        "sections": sections,
    }


def coordinate(position):
    closed(position, ("time_ps", "microstep", "phase"))
    phase = position["phase"]
    if type(phase) is not int or not 0 <= phase <= 3:
        raise ValueError("unsupported native coordinator phase")
    return (u64(position["time_ps"]), u64(position["microstep"]), phase)


def reaction_position(tick, tie):
    if not 0 < tie <= U64_MAX // 2:
        raise ValueError("native same-time reaction ordinal exhausted")
    return {"time_ps": str(tick), "microstep": str(2 * (tie - 1)), "phase": 3}


def next_reaction(observed):
    if not observed["has_next_event"]:
        return None
    tick = u64(observed["next_tick"])
    tie = tick_ordinal + 1 if tick == u64(observed["tick"]) else 1
    return reaction_position(tick, tie)


def boundary(reservation=None):
    observed = m5.simulateUntilBoundary(m5.MaxTick, 0)
    if hasattr(m5, "crucibleEventPosition"):
        position = m5.crucibleEventPosition()
        if (
            position["active"] or u64(position["ordinal"]) != ordinal
            or u64(position["tick_ordinal"]) != tick_ordinal
            or u64(position["tick"]) != observed.currentTick
        ):
            raise ValueError("native callback position differs from the parked cursor")
    return {
        "tick": str(observed.currentTick), "logical_position": dict(logical_position),
        "ordinal": str(ordinal),
        "tick_ordinal": str(tick_ordinal),
        "has_next_event": observed.hasNextEvent,
        "next_tick": str(observed.nextTick), "next_priority": observed.nextPriority,
        "inventory": native_inventory(reservation),
    }


def hello(stream, continuation):
    ready = {
        "kind": "ready", "schema": adapter_type.schema,
        "owner": bootstrap["owner"], "incarnation": bootstrap["incarnation"],
        "generation": str(generation), "continuation": continuation,
        "diagnostic_credit_policy": {
            "schema": "crucible.gem5.diagnostic-credit-policy.v1",
            "maximum_object_bytes": str(MAX_DIAGNOSTIC_BYTES),
            "maximum_total_bytes": str(MAX_DIAGNOSTIC_TOTAL),
            "maximum_files": str(MAX_DIAGNOSTIC_FILES),
            "refusal_schema": "crucible.gem5.run-refused.v1",
        },
        "boundary": boundary(),
    }
    scope = model.describe_scope()
    if scope is not None:
        ready["model_scope"] = scope
    send(stream, ready)


def serve(selected_adapter):
    """Runs one source-owned model with the shared exact boundary/custody loop.

    The enclosing installed policy must authenticate this engine and selected
    adapter bytes. This entry point grants no public deterministic authority.
    """
    global adapter_type, bootstrap, generation, controller_uid, resource_root
    global control_socket, output_path, model, root, ordinal, tick_ordinal
    global output_offset, operations, pending, last_ack, retained_receipt_bytes
    global logical_position

    adapter_type = selected_adapter
    bootstrap_channel = socket.socket(fileno=0)
    bootstrap = closed(receive(bootstrap_channel), adapter_type.bootstrap_fields)
    bootstrap_channel.close()
    # Preserve standard descriptor allocation without retaining a controller socket.
    # A closed fd0 can become a modeled output FD and violates DMTCP's standard-FD
    # restoration assumptions; the closed-input profile keeps deterministic EOF.
    empty_input = os.open(os.devnull, os.O_RDONLY)
    if empty_input != 0:
        os.dup2(empty_input, 0)
        os.close(empty_input)
    if bootstrap["schema"] != adapter_type.schema:
        raise ValueError("unsupported private native protocol")
    generation = u64(bootstrap["generation"])
    controller_uid = u64(bootstrap["controller_uid"])
    if generation == 0 or controller_uid != os.getuid():
        raise ValueError("invalid original native owner generation or UID")
    resource_root = Path(bootstrap["resource_root"])
    if (
        not resource_root.is_absolute() or resource_root.resolve() != resource_root
        or resource_root.stat().st_mode & 0o077
        or resource_root.stat().st_uid != os.getuid()
    ):
        raise ValueError("native resource root is not canonically private")
    control_socket = bootstrap["control_socket"]
    output_path = resource_root / adapter_type.output_basename
    if output_path.exists():
        raise ValueError("native output resource must be fresh")

    model = adapter_type(bootstrap, resource_root)
    root = model.realize()
    ordinal = 0
    tick_ordinal = 0
    output_offset = 0
    operations = {}
    pending = None
    last_ack = None
    retained_receipt_bytes = 0
    logical_position = {"time_ps": "0", "microstep": "0", "phase": 0}

    stream = connect(control_socket, controller_uid)
    hello(stream, "original")
    while True:
        try:
            request = receive(stream)
        except (EOFError, ConnectionResetError):
            stream.close()
            stream = connect(control_socket, controller_uid)
            hello(stream, "reconnected")
            continue
        kind = request.get("kind")
        if kind == "observe":
            closed(request, ("kind",))
            send(stream, {"kind": "observed", "boundary": boundary()})
        elif kind == "process_inventory":
            closed(request, ("kind",))
            library = ctypes.CDLL(None)
            if not hasattr(library, "dmtcp_is_protected_fd"):
                send(stream, {"kind": "unsupported", "operation": "process_inventory"})
                continue
            protected = library.dmtcp_is_protected_fd
            protected.argtypes = [ctypes.c_int]
            protected.restype = ctypes.c_int
            descriptors = []
            for member in os.listdir("/proc/self/fd"):
                descriptor = int(member)
                try:
                    target = os.readlink(f"/proc/self/fd/{descriptor}")
                except FileNotFoundError:
                    # The inventory directory's temporary descriptor is closed.
                    continue
                descriptors.append({"fd": str(descriptor), "target": target,
                                    "dmtcp_protected": protected(descriptor) != 0})
            descriptors.sort(key=lambda entry: int(entry["fd"]))
            thread_contexts = []
            operational_shared_maps = []
            captured_descriptors = []
            captured_maps = []
            captured_file_maps = []
            if hasattr(library, "dmtcp_crucible_checkpoint_thread_count"):
                count = library.dmtcp_crucible_checkpoint_thread_count
                count.restype = ctypes.c_int
                thread = library.dmtcp_crucible_checkpoint_thread
                thread.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                                   ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int),
                                   ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_size_t]
                thread.restype = ctypes.c_int
                thread_count = count()
                if not -1 <= thread_count <= 256:
                    raise ValueError("native captured thread roster exceeds its allowance")
                # No suspended-context ledger exists before the first checkpoint.
                # An empty roster is evidence of that omission, never qualification.
                thread_count = max(thread_count, 0)
                retained_context_bytes = 0
                for index in range(thread_count):
                    address = ctypes.c_uint64()
                    real_tid = ctypes.c_uint32()
                    state = ctypes.c_int()
                    role = ctypes.c_int()
                    context = ctypes.create_string_buffer(65536)
                    length = thread(index, ctypes.byref(address), ctypes.byref(real_tid),
                                    ctypes.byref(state), ctypes.byref(role), context, len(context))
                    retained_context_bytes += max(length, 0)
                    if not 0 < length <= len(context) or retained_context_bytes > 1024 * 1024:
                        raise ValueError("native captured thread context is unavailable or oversized")
                    if role.value not in (0, 1) or (role.value == 0 and state.value != 3):
                        raise ValueError("native application thread lacks a suspended captured context")
                    thread_contexts.append({
                        "address": str(address.value), "real_tid": str(real_tid.value),
                        "state": "suspended" if role.value == 0 else "checkpoint-worker",
                        "role": "application" if role.value == 0 else "checkpoint-worker",
                        "bytes_hex": context.raw[:length].hex(),
                    })
                shared = library.dmtcp_crucible_operational_shared_region
                shared.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
                shared.restype = ctypes.c_int
                shared_start, shared_end = ctypes.c_uint64(), ctypes.c_uint64()
                if shared(ctypes.byref(shared_start), ctypes.byref(shared_end)) == 0:
                    if shared_start.value >= shared_end.value:
                        raise ValueError("native operational shared region is invalid")
                    operational_shared_maps.append({"start": str(shared_start.value), "end": str(shared_end.value)})
            if hasattr(library, "dmtcp_crucible_checkpoint_fd_count"):
                count = library.dmtcp_crucible_checkpoint_fd_count
                count.restype = ctypes.c_int
                descriptor = library.dmtcp_crucible_checkpoint_fd
                descriptor.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                                      ctypes.c_void_p, ctypes.c_size_t]
                descriptor.restype = ctypes.c_int
                descriptor_count = count()
                if not -1 <= descriptor_count <= 256:
                    raise ValueError("native captured descriptor roster exceeds its allowance")
                for index in range(max(descriptor_count, 0)):
                    address = ctypes.c_uint64()
                    record = ctypes.create_string_buffer(65536)
                    length = descriptor(index, ctypes.byref(address), record, len(record))
                    if length != 4160:
                        raise ValueError("native captured descriptor record ABI differs")
                    captured_descriptors.append({"address": str(address.value),
                                                 "bytes_hex": record.raw[:length].hex()})
            if hasattr(library, "dmtcp_crucible_checkpoint_map_count"):
                count = library.dmtcp_crucible_checkpoint_map_count
                count.restype = ctypes.c_int
                mapping = library.dmtcp_crucible_checkpoint_map
                mapping.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                                   ctypes.c_void_p, ctypes.c_size_t]
                mapping.restype = ctypes.c_int
                mapping_count = count()
                if not -1 <= mapping_count <= 1024:
                    raise ValueError("native captured mapping roster exceeds controller credit")
                for index in range(max(mapping_count, 0)):
                    address = ctypes.c_uint64()
                    record = ctypes.create_string_buffer(65536)
                    length = mapping(index, ctypes.byref(address), record, len(record))
                    if length != 1112:
                        raise ValueError("native captured mapping record ABI differs")
                    captured_maps.append({"address": str(address.value),
                                          "bytes_hex": record.raw[:length].hex()})
            if hasattr(library, "dmtcp_crucible_checkpoint_file_map_count"):
                count = library.dmtcp_crucible_checkpoint_file_map_count
                count.restype = ctypes.c_int
                mapping = library.dmtcp_crucible_checkpoint_file_map
                mapping.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                                   ctypes.c_void_p, ctypes.c_size_t]
                mapping.restype = ctypes.c_int
                mapping_count = count()
                if not -1 <= mapping_count <= 64:
                    raise ValueError("native captured file mapping roster exceeds controller credit")
                for index in range(max(mapping_count, 0)):
                    address = ctypes.c_uint64()
                    record = ctypes.create_string_buffer(65536)
                    length = mapping(index, ctypes.byref(address), record, len(record))
                    if length != 5224:
                        raise ValueError("native captured file mapping record ABI differs")
                    captured_file_maps.append({"address": str(address.value),
                                               "bytes_hex": record.raw[:length].hex()})
            send(stream, {"kind": "process_inventory", "schema": "crucible.gem5.native-process-inventory.v1",
                          "control_fd": str(stream.fileno()), "descriptors": descriptors,
                          "thread_contexts": thread_contexts,
                          "captured_descriptors": captured_descriptors,
                          "captured_maps": captured_maps,
                          "captured_file_maps": captured_file_maps,
                          "operational_shared_maps": operational_shared_maps,
                          "boundary": boundary()})
        elif kind == "recover":
            closed(request, ("kind", "operation"))
            original = operations.get(request["operation"])
            if original is None:
                send(stream, {"kind": "not_started", "operation": request["operation"]})
            else:
                send(stream, original[1])
        elif kind == "run":
            closed(request, ("kind", "operation", "exclusive_tick", "maximum_events", "exact_range"))
            operation = request["operation"]
            if not isinstance(operation, str) or not operation or len(operation) > 256:
                raise ValueError("invalid original native operation identity")
            if operation in operations:
                old_request, receipt = operations[operation]
                if old_request != request:
                    raise ValueError("original native operation material changed")
                send(stream, receipt)
                continue
            if (
                pending is not None or len(operations) >= MAX_OPERATIONS
                or retained_receipt_bytes + FRAME_LIMIT > MAX_RETAINED_RECEIPT_BYTES
            ):
                raise ValueError("native output custody or operation credit remains held")
            limit = u64(request["exclusive_tick"])
            budget = u64(request["maximum_events"])
            if limit < m5.curTick() or not 0 < budget <= MAX_EVENTS:
                raise ValueError("native grant is unrepresentable or precedes the cursor")

            model.validate_run(request)
            exact_range = request["exact_range"]
            if exact_range is not None:
                closed(exact_range, ("start", "limit", "maximum_microsteps"))
                start_position = coordinate(exact_range["start"])
                limit_position = coordinate(exact_range["limit"])
                cap = u64(exact_range["maximum_microsteps"])
                if (
                    start_position != coordinate(logical_position) or start_position >= limit_position
                    or cap < 2 or start_position[1] >= cap or limit_position[1] >= cap
                    or limit != limit_position[0]
                ):
                    raise ValueError("exact native range differs from stopped cursor or closure budget")

            before = boundary()
            reservation, credit = reserve_diagnostic()
            if reservation is None:
                # This refusal applies to this original subordinate Poll only. The
                # host retains any progress from earlier prefixes of its grant.
                receipt = {
                    "kind": "run_refused", "schema": "crucible.gem5.run-refused.v1",
                    "operation": operation, "original": request,
                    "boundary": before, "processed_events": "0",
                    "reason": "diagnostic_credit", "credit": credit,
                }
                retained_receipt_bytes += len(json.dumps(receipt, sort_keys=True, allow_nan=False).encode())
                operations[operation] = (request, receipt)
                pending = operation
                send(stream, receipt)
                continue
            model.reserve_callback_credit()
            processed = 0
            reason = "event_budget"
            exit_cause = None
            exit_code = None
            output = b""
            publications = []
            while processed < budget:
                model.reserve_callback_credit()
                previous_tick = m5.curTick()
                native_limit = limit
                if exact_range is not None:
                    observed_queue = m5.simulateUntilBoundary(m5.MaxTick, 0)
                    queued = next_reaction({"has_next_event": observed_queue.hasNextEvent,
                                           "next_tick": str(observed_queue.nextTick),
                                           "tick": str(previous_tick)})
                    if queued is None or coordinate(queued) >= limit_position:
                        # The native queue and the installed closed no-ingress profile
                        # exclude every callback before this exact coordinator cut.
                        logical_position = dict(exact_range["limit"])
                        reason = "idle" if queued is None else "horizon"
                        break
                    queued_position = coordinate(queued)
                    if queued_position < coordinate(logical_position) or queued_position < start_position:
                        raise ValueError("native reaction precedes the sealed original input cut")
                    if queued_position[1] + 1 >= cap or ordinal == U64_MAX:
                        raise ValueError("native finite same-time closure exhausted before callback")
                    if queued_position[0] == U64_MAX:
                        raise ValueError("native physical exclusive ceiling is unrepresentable")
                    native_limit = queued_position[0] + 1
                native_budget = model.maximum_native_step_events(budget - processed, exact_range)
                step = m5.simulateUntilBoundary(native_limit, native_budget)
                if step.processedEvents == 0:
                    reason = "horizon" if step.hasNextEvent else "idle"
                    break
                processed += step.processedEvents
                if ordinal == U64_MAX:
                    raise ValueError("native event ordinal exhausted")
                ordinal += step.processedEvents
                native_position = m5.crucibleEventPosition()
                if native_position['active'] or u64(native_position['ordinal']) != ordinal:
                    raise ValueError('closed native batch differs from actual callback counter')
                tick_ordinal = u64(native_position['tick_ordinal'])
                if tick_ordinal > U64_MAX:
                    raise ValueError("native per-instant event ordinal exhausted")
                reacted = reaction_position(step.currentTick, tick_ordinal)
                logical_position = {"time_ps": reacted["time_ps"],
                                    "microstep": str(u64(reacted["microstep"]) + 1), "phase": 0}
                # Adapters expose only original native publication bodies. Host
                # output polling cannot qualify event birth or public custody.
                publications = model.publications()
                output = bytes(byte for publication in publications for byte in publication["payload"])
                if len(output) > MAX_OUTPUT:
                    raise ValueError("native modeled output exceeds retained allowance")
                if step.exitEvent is not None:
                    reason = "guest_exit"
                    exit_cause = step.exitEvent.getCause()
                    exit_code = step.exitEvent.getCode()
                    break
                if publications:
                    reason = "output"
                    break
            if exact_range is not None and reason == "event_budget":
                # Event credit and modeled horizon are independent. A last allowed
                # callback can consume the final credit while also reaching the cut.
                observed_queue = m5.simulateUntilBoundary(m5.MaxTick, 0)
                queued = next_reaction({"has_next_event": observed_queue.hasNextEvent,
                                       "next_tick": str(observed_queue.nextTick),
                                       "tick": str(m5.curTick())})
                if queued is None or coordinate(queued) >= limit_position:
                    logical_position = dict(exact_range["limit"])
                    reason = "idle" if queued is None else "horizon"
            output_offset += len(output)
            if publications:
                # This private diagnostic file is outside guest write semantics.
                with output_path.open("ab") as output_file:
                    output_file.write(output)
            receipt = {
                "kind": "completed", "operation": operation, "original": request,
                "before": before, "after": boundary(reservation), "processed_events": str(processed),
                "reason": reason, "output": list(output), "publications": publications,
                "exit_cause": exit_cause,
                "exit_code": exit_code,
            }
            retained_receipt_bytes += len(json.dumps(receipt, sort_keys=True, allow_nan=False).encode())
            operations[operation] = (request, receipt)
            pending = operation
            send(stream, receipt)
        elif kind in ("acknowledge", "ack_refused"):
            closed(request, ("kind", "operation"))
            operation = request["operation"]
            if operation != pending and operation != last_ack:
                raise ValueError("native acknowledgment lacks original output custody")
            refused = operations[operation][1]["kind"] == "run_refused"
            if refused != (kind == "ack_refused"):
                raise ValueError("native acknowledgment class differs from original custody")
            if operation == pending:
                for publication in operations[operation][1].get("publications", []):
                    model.acknowledge(u64(publication["output_id"]))
                pending = None
                last_ack = operation
            send(stream, {"kind": "refusal_acknowledged" if refused else "acknowledged",
                          "operation": operation})
        elif kind == "device_control":
            # The model retains the exact attempted input before staging any
            # native event. Diagnostic space is reserved before this effect;
            # the original input and all prior run receipts remain in custody.
            model.validate_control(request)
            retry = model.control_retry(request)
            if retry is not None:
                send(stream, retry)
                continue
            original_boundary = boundary()
            reservation, credit = reserve_diagnostic()
            if reservation is None:
                send(stream, model.refuse_control(request, original_boundary, credit))
                continue
            response = model.control(request)
            after = boundary(reservation)
            if any(after[key] != original_boundary[key] for key in (
                "tick", "ordinal", "tick_ordinal", "logical_position"
            )):
                raise ValueError("native device control serviced a modeled callback")
            send(stream, model.retain_control_response(
                request, response, original_boundary, after))
        elif kind == "capture":
            closed(request, ("kind", "capture"))
            library = ctypes.CDLL(None)
            if not hasattr(library, "dmtcp_checkpoint") or library.dmtcp_get_ckpt_signal() != 40:
                raise ValueError("durable process-image capture is not installed")
            before = boundary()
            # No controller descriptor survives the process image. Reconstruction
            # must establish a fresh peer before interpreting any further command.
            send(stream, {"kind": "capture_ready", "capture": request["capture"], "boundary": before})
            stream.close()
            checkpoint = library.dmtcp_checkpoint
            checkpoint.restype = ctypes.c_int
            status = checkpoint()
            if status not in (1, 2):
                raise ValueError("process image returned an invalid native continuation")
            continuation = "captured"
            if status == 2:
                restart_env = library.dmtcp_get_restart_env
                restart_env.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
                replacement = ctypes.create_string_buffer(4096)
                if restart_env(b"CRUCIBLE_GEM5_CONTROL_SOCKET", replacement, len(replacement)) != 0:
                    raise ValueError("fresh reconstruction has no private controller route")
                control_socket = replacement.value.decode("utf-8")
                restored_root = ctypes.create_string_buffer(4096)
                if restart_env(b"CRUCIBLE_RESTORE_RESOURCE_ROOT", restored_root, len(restored_root)) != 0:
                    raise ValueError("fresh reconstruction has no private resource root")
                output_path = Path(restored_root.value.decode("utf-8")) / adapter_type.output_basename
                resource_root = Path(restored_root.value.decode("utf-8"))
                if (
                    not resource_root.is_absolute() or resource_root.resolve() != resource_root
                    or not resource_root.is_dir() or resource_root.stat().st_mode & 0o077
                    or resource_root.stat().st_uid != os.getuid()
                ):
                    raise ValueError("restored native resource root is not canonically private")
                # File reconstruction has finished using the captured source root.
                # Onward captures must explicitly own this incarnation's files;
                # retaining the old root relies on DMTCP's unrelated file heuristics.
                os.environ["CRUCIBLE_CAPTURE_RESOURCE_ROOT"] = str(resource_root)
                native_setenv = library.setenv
                native_setenv.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
                native_setenv.restype = ctypes.c_int
                resource_bytes = os.fsencode(resource_root)
                if native_setenv(b"CRUCIBLE_CAPTURE_RESOURCE_ROOT", resource_bytes, 1) != 0:
                    raise ValueError("cannot rebind native capture resource custody")
                native_getenv = library.getenv
                native_getenv.argtypes = [ctypes.c_char_p]
                native_getenv.restype = ctypes.c_char_p
                if native_getenv(b"CRUCIBLE_CAPTURE_RESOURCE_ROOT") != resource_bytes:
                    raise ValueError("native capture resource custody did not rebind")
                operational_root = ctypes.create_string_buffer(4096)
                if restart_env(b"CRUCIBLE_GEM5_OPERATIONAL_ROOT", operational_root,
                               len(operational_root)) != 0:
                    raise ValueError("fresh reconstruction has no private operational root")
                # Operational checkpoint scripts must never return to a source
                # host directory. The closed guest profile cannot observe host cwd.
                os.chdir(operational_root.value.decode("utf-8"))
                continuation = "restored"
            model.rebind_resource_root(resource_root)
            # Rebind operational diagnostic paths before inspecting the native cut;
            # no modeled callback executes while reconstructing this fresh route.
            if boundary() != before:
                raise ValueError("process image changed the exact native cut")
            stream = connect(control_socket, controller_uid)
            if status == 2:
                rebind = closed(receive(stream), (
                    "kind", "owner", "source_incarnation", "source_generation",
                    "incarnation", "generation", "capture",
                ))
                fresh_generation = u64(rebind["generation"])
                if (
                    rebind["kind"] != "restore_bind" or rebind["owner"] != bootstrap["owner"]
                    or rebind["source_incarnation"] != bootstrap["incarnation"]
                    or u64(rebind["source_generation"]) != generation
                    or fresh_generation <= generation
                    or rebind["incarnation"] == bootstrap["incarnation"]
                    or rebind["capture"] != request["capture"]
                ):
                    raise ValueError("fresh controller rebind changed captured lineage")
                generation = fresh_generation
                bootstrap["incarnation"] = rebind["incarnation"]
            hello(stream, continuation)
        elif kind == "shutdown":
            closed(request, ("kind",))
            if pending is not None:
                raise ValueError("shutdown cannot erase unpublished native output")
            send(stream, {"kind": "shutdown"})
            stream.close()
            break
        else:
            raise ValueError("unknown private native operation")
