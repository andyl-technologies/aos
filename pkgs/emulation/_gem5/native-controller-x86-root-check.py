# SPDX-License-Identifier: MIT
"""Checks real x86 Linux serial birth through the shared stopped controller.

This control mechanism proof does not qualify a full-system process image,
guest readiness, device parity, or a production execution capability.
"""

import json
import importlib.util
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys


# The first UART may follow several successful event-budget receipts. This is
# one total search allowance, not a renewed allowance for each stopped grant.
FIRST_UART_EVENT_ALLOWANCE = 10_000_000
FIRST_UART_GRANT_EVENTS = 262_144
FIRST_UART_MAXIMUM_GRANTS = (
    FIRST_UART_EVENT_ALLOWANCE + FIRST_UART_GRANT_EVENTS - 1
) // FIRST_UART_GRANT_EVENTS
MAXIMUM_WITNESS_ORIGINALS = 1 + FIRST_UART_MAXIMUM_GRANTS + 8
# An additional accepted-receipt bound leaves the controller's next-frame
# reserve intact. Parsing and native allocation still have their own guards.
MAXIMUM_ACCEPTED_RECEIPT_BYTES = (
    16 * 1024 * 1024 - 4 * 1024 * 1024
) // MAXIMUM_WITNESS_ORIGINALS


native, source_directory, output_directory, configs, kernel, initrd = sys.argv[1:7]
process_tools = sys.argv[7:]
if len(process_tools) != 2:
    raise ValueError("capture proof requires the source-built DMTCP root and custody helper")
root = Path(output_directory).resolve()
root.mkdir(mode=0o700)
helper_spec = importlib.util.spec_from_file_location(
    "crucible_native_image_witness", Path(source_directory) / "native-controller-image-check.py")
image_check = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(image_check)
source_namespace = root / "source"
source_namespace.mkdir(mode=0o700)
resource = source_namespace / "resources"
resource.mkdir(mode=0o700)
temporary = source_namespace / "tmp"
temporary.mkdir(mode=0o700)
for name in ("native-controller.py", "native-controller-models.py",
             "native-controller-x86-model.py", "native-model-assets.py",
             "native-controller-x86-root.py", "native-controller-x86-root-model.py",
             "x86-linux-loader.py"):
    target = resource / name
    source = Path(source_directory) / name
    descriptor, metadata = image_check.checked_file(source)
    os.close(descriptor)
    image_check.copy_file(source, target, metadata, 0o600)
for origin, name in ((kernel, "kernel.elf"), (initrd, "initrd.img")):
    destination = resource / name
    descriptor, metadata = image_check.checked_file(origin)
    os.close(descriptor)
    image_check.copy_file(origin, destination, metadata, 0o600)
image_check.copy_tree(Path(configs), resource / "configs")
spec = importlib.util.spec_from_file_location("model_assets", resource / "native-model-assets.py")
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)
model = {"schema": "crucible.gem5.x86-linux-root-model.v1", "assets": {},
         "configs": assets.configuration_tree(resource / "configs")}
for role, name in (("kernel", "kernel.elf"), ("initramfs", "initrd.img")):
    model["assets"][role] = {"file": name, **assets.digest_file(resource / name, assets.MAX_ASSET_BYTES)}
endpoint = root / "control.sock"
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(str(endpoint))
listener.listen(1)
listener.settimeout(60)
parent, bootstrap = socket.socketpair()


def send(stream, value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert 0 < len(body) <= 4 * 1024 * 1024
    stream.sendall(struct.pack("!I", len(body)) + body)


def receive(stream):
    def exact(size):
        body = bytearray()
        while len(body) < size:
            part = stream.recv(size - len(body))
            if not part:
                raise EOFError("shared native controller disconnected")
            body.extend(part)
        return body

    length = struct.unpack("!I", exact(4))[0]
    assert 0 < length <= 4 * 1024 * 1024
    return json.loads(exact(length))


def exchange(stream, value):
    send(stream, value)
    return receive(stream)


def position(tick, microstep, phase):
    return {"time_ps": str(tick), "microstep": str(microstep), "phase": phase}


def grant(operation, start, limit):
    return {"kind": "run", "operation": operation, "exclusive_tick": limit["time_ps"],
            "maximum_events": "1", "exact_range": {
                "start": start, "limit": limit, "maximum_microsteps": "1000000"}}


def bounded_diagnostic_json(value):
    """Renders at most 16 KiB of ASCII JSON plus an explicit truncation marker."""
    remaining = 16 * 1024
    parts = []
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    for chunk in encoder.iterencode(value):
        if len(chunk) > remaining:
            parts.append(chunk[:remaining])
            return "".join(parts) + " [truncated]"
        parts.append(chunk)
        remaining -= len(chunk)
    return "".join(parts)


def native_log_diagnostic_tail(path):
    """Reads at most the final 4 KiB without changing the original log owner."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            end = stream.tell()
            stream.seek(max(0, end - 4 * 1024))
            tail = stream.read(4 * 1024)
    except OSError as error:
        return f"unavailable (errno={error.errno})"
    return bounded_diagnostic_json(tail.decode("utf-8", errors="backslashreplace"))


def first_receipt_diagnostic(receipt):
    """Keeps bounded failure context without classifying or replacing the refusal."""
    return ("first native Linux UART receipt: " + bounded_diagnostic_json(receipt)
            + "\nnative.log tail: " + native_log_diagnostic_tail(resource / "native.log"))


def accepted_receipt_extent(receipt):
    """Checks retained evidence after receipt, without substituting native credit."""
    encoded = json.dumps(receipt, sort_keys=True, allow_nan=False).encode()
    assert len(encoded) <= MAXIMUM_ACCEPTED_RECEIPT_BYTES


def unsigned_decimal(value):
    """Reads one canonical finite counter from the actual native receipt."""
    assert type(value) is str and value.isascii() and value.isdecimal()
    assert len(value) <= 20 and str(int(value)) == value
    result = int(value)
    assert result <= (1 << 64) - 1
    return result


def logical_coordinate(value):
    """Orders the exact returned cursor, including same-tick phase and microstep."""
    assert type(value) is dict and set(value) == {"time_ps", "microstep", "phase"}
    phase = value["phase"]
    assert type(phase) is int and 0 <= phase <= 3
    return (unsigned_decimal(value["time_ps"]),
            unsigned_decimal(value["microstep"]), phase)


def authenticate_search_receipt(receipt, request, previous):
    """Authenticates bounded genuine progress before any continuation or ACK."""
    accepted_receipt_extent(receipt)
    assert receipt["kind"] == "completed"
    assert receipt["operation"] == request["operation"] and receipt["original"] == request
    assert receipt["before"] == previous
    processed = unsigned_decimal(receipt["processed_events"])
    assert 0 < processed <= unsigned_decimal(request["maximum_events"])
    after = receipt["after"]
    assert unsigned_decimal(after["ordinal"]) == unsigned_decimal(previous["ordinal"]) + processed
    assert unsigned_decimal(after["tick"]) >= unsigned_decimal(previous["tick"])
    assert unsigned_decimal(after["tick"]) == unsigned_decimal(after["logical_position"]["time_ps"])
    assert unsigned_decimal(after["tick_ordinal"]) > 0
    assert (logical_coordinate(previous["logical_position"])
            < logical_coordinate(after["logical_position"])
            <= logical_coordinate(request["exact_range"]["limit"]))
    assert receipt["exit_cause"] is None and receipt["exit_code"] is None
    if receipt["reason"] == "event_budget":
        assert processed == unsigned_decimal(request["maximum_events"])
        assert receipt["output"] == [] and receipt["publications"] == []
        assert after["has_next_event"] is True
        assert (unsigned_decimal(after["tick"]) <= unsigned_decimal(after["next_tick"])
                < unsigned_decimal(request["exclusive_tick"]))
    else:
        assert receipt["reason"] == "output"
    return processed


def authenticate_retained_progress(stream, checkpoints):
    """Rechecks actual cached originals without granting any further callbacks."""
    for request, saved in checkpoints:
        assert exchange(stream, request) == saved
        assert exchange(stream, {"kind": "recover", "operation": request["operation"]}) == saved


command = [native, "--listener-mode=off", f"--outdir={resource / 'output'}",
           str(resource / "native-controller-x86-root.py")]
environment = os.environ.copy()
if process_tools:
    dmtcp, image_guard = process_tools
    images = source_namespace / "images"
    images.mkdir(mode=0o700)
    environment["CRUCIBLE_CAPTURE_RESOURCE_ROOT"] = str(resource)
    command = [str(Path(dmtcp) / "bin/dmtcp_launch"), "--new-coordinator", "--no-gzip",
               "--ckpt-signal", "40", "--with-plugin", image_guard,
               "--ckptdir", str(images), *command]
with os.fdopen(os.open(resource / "native.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
    child = subprocess.Popen(
        command, env=environment, stdin=bootstrap, stdout=log, stderr=log,
        start_new_session=True, cwd=temporary,
    )
bootstrap.close()
try:
    image_check.own_process(child)
    send(parent, {
        "schema": "crucible.gem5.x86-linux-native/1", "owner": "serial-node",
        "incarnation": "source", "generation": "1", "controller_uid": str(os.getuid()),
        "guest_isa": "x86_64", "executable": "", "resource_root": str(resource), "model": model,
        "control_socket": str(endpoint),
    })
    parent.close()
    control, _ = listener.accept()
    control.settimeout(60)
    peer_pid, uid, _ = struct.unpack("3i", control.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    assert peer_pid == child.pid and uid == os.getuid()
    ready = receive(control)
    assert ready["schema"] == "crucible.gem5.x86-linux-native/1"
    assert ready["model_scope"]["complete_process_closure_qualified"] is False
    original = ready["boundary"]
    assert original["ordinal"] == "0"
    assert exchange(control, {"kind": "observe"})["boundary"] == original

    blocked = grant("stop-before-first-native-reaction", original["logical_position"], position(0, 0, 3))
    excluded = exchange(control, blocked)
    assert excluded["kind"] == "completed" and excluded["reason"] == "horizon"
    assert excluded["processed_events"] == "0" and excluded["after"]["ordinal"] == "0"
    assert excluded["publications"] == []
    accepted_receipt_extent(excluded)
    assert exchange(control, {"kind": "acknowledge", "operation": blocked["operation"]})["kind"] == "acknowledged"

    previous = excluded["after"]
    pre_output_checkpoints = []
    processed_before_output = 0
    for attempt in range(FIRST_UART_MAXIMUM_GRANTS):
        remaining = FIRST_UART_EVENT_ALLOWANCE - processed_before_output
        assert remaining > 0
        operation = ("first-original-linux-uart-birth" if attempt == 0
                     else f"first-original-linux-uart-birth/{attempt}")
        first = grant(operation, previous["logical_position"], position(100000000000, 0, 3))
        first["maximum_events"] = str(min(FIRST_UART_GRANT_EVENTS, remaining))
        receipt = exchange(control, first)
        try:
            processed_before_output += authenticate_search_receipt(receipt, first, previous)
            assert processed_before_output <= FIRST_UART_EVENT_ALLOWANCE
            assert exchange(control, first) == receipt
            assert exchange(control, {"kind": "recover", "operation": operation}) == receipt
            assert exchange(control, {"kind": "observe"})["boundary"] == receipt["after"]
            if receipt["reason"] == "output":
                # Keep this actual publication pending through the original capture.
                break
            acknowledgement = {"kind": "acknowledge", "operation": operation}
            assert exchange(control, acknowledgement) == {
                "kind": "acknowledged", "operation": operation,
            }
        except (AssertionError, KeyError, TypeError, ValueError, OverflowError) as error:
            error.add_note(first_receipt_diagnostic(receipt))
            raise
        pre_output_checkpoints.append((first, receipt))
        previous = receipt["after"]
    else:
        raise AssertionError("first native UART exhausted its total callback allowance: "
                             + first_receipt_diagnostic(receipt))
    assert len(receipt["output"]) == 1 and len(receipt["publications"]) == 1
    assert type(receipt["output"][0]) is int and 0 <= receipt["output"][0] <= 255
    publication = receipt["publications"][0]
    assert publication["output_id"] == "1" and publication["causal_parent"] == "0"
    assert publication["tick"] == receipt["after"]["tick"]
    assert publication["event_ordinal"] == receipt["after"]["ordinal"]
    assert publication["tick_ordinal"] == receipt["after"]["tick_ordinal"]
    assert publication["facet"] == "serial" and "guest_fd" not in publication
    assert publication["terminal"] == "system.pc.com_1.device"
    assert exchange(control, first) == receipt
    assert exchange(control, {"kind": "recover", "operation": first["operation"]}) == receipt
    assert exchange(control, {"kind": "observe"})["boundary"] == receipt["after"]
    if process_tools:
        capture = {"kind": "capture", "capture": "first-held-linux-serial-image"}
        send(control, capture)
        captured = receive(control)
        assert captured["kind"] == "capture_ready" and captured["boundary"] == receipt["after"]
        control.close()
        control, _ = listener.accept()
        control.settimeout(120)
        captured_ready = receive(control)
        assert captured_ready["continuation"] == "captured"
        assert captured_ready["boundary"] == receipt["after"]
        primary = list(images.glob("*.dmtcp"))
        assert len(primary) == 1
        image_check.audit(exchange, control, child, root, resource, primary[0],
                          receipt["after"], ready["model_scope"], native, image_guard,
                          source_directory, "source")
        archive = root / "archive"
        archive.mkdir(mode=0o700)
        source_saved_root = primary[0].with_name(primary[0].stem + "_files")
        resource_bytes = image_check.census(resource)[2]
        saved_bytes = image_check.census(source_saved_root)[2]
        descriptor, primary_metadata = image_check.checked_file(primary[0])
        os.close(descriptor)
        assert resource_bytes + saved_bytes + primary_metadata.st_size <= image_check.MAX_TOTAL_BYTES
        image_digest = image_check.copy_file(primary[0], archive / primary[0].name,
                                              primary_metadata, 0o400)
        image_check.copy_tree(source_saved_root, archive / source_saved_root.name, mode=0o400)
        image_check.copy_tree(resource, archive / "resources")
    ack = {"kind": "acknowledge", "operation": first["operation"]}
    assert exchange(control, ack) == exchange(control, ack)

    def finish(stream):
        suffix = []
        previous = receipt["after"]
        for index in range(8):
            following = grant(f"following-original-linux-uart-birth/{index}",
                              previous["logical_position"], position(100000000000, 0, 3))
            following["maximum_events"] = "5000"
            result = exchange(stream, following)
            accepted_receipt_extent(result)
            assert result["reason"] == "output" and result["output"]
            assert int(result["publications"][0]["event_ordinal"]) > int(previous["ordinal"])
            assert result["publications"][0]["output_id"] == str(index + 2)
            assert exchange(stream, following) == result
            assert exchange(stream, {"kind": "acknowledge", "operation": following["operation"]})["kind"] == "acknowledged"
            suffix.append(result)
            previous = result["after"]
        return suffix

    suffix = finish(control)
    assert exchange(control, {"kind": "shutdown"}) == {"kind": "shutdown"}
    control.close()
    assert image_check.wait_exited(child, timeout=10) == 0
    source_group_reclaimed = image_check.reclaim(child)
    branches = []
    if process_tools:
        shutil.rmtree(source_namespace)
        assert not source_namespace.exists()
        historical_image = archive / primary[0].name
        saved_archive = archive / source_saved_root.name

        from threading import Barrier, Lock

        # Each original group stays retained and parked until both independent
        # recaptures/audits and both kernel-liveness censuses have completed.
        audited = Barrier(2, timeout=60)
        checked_live = Barrier(2, timeout=60)
        participants = {}
        participant_lock = Lock()

        def reconstruct(name):
            branch = root / name
            image_check.copy_tree(archive / "resources", branch)
            scratch = root / f"tmp-{name}"
            scratch.mkdir(mode=0o700)
            fresh_images = root / f"images-{name}"
            fresh_images.mkdir(mode=0o700)
            imported_saved = root / f"saved-{name}"
            image_check.copy_tree(saved_archive, imported_saved, mode=0o400)
            roster = root / f"saved-{name}.manifest"
            rows = ["crucible-saved-files-v1", str(source_saved_root), str(imported_saved)]
            for leaf in sorted(imported_saved.iterdir(), key=lambda path: path.name):
                assert leaf.is_file() and not leaf.is_symlink()
                rows.append(f"{image_check.digest(leaf)}\t{leaf.stat().st_size}\t{leaf.name}")
            body = ("\n".join(rows) + "\n").encode()
            assert len(body) <= 2 * 1024**2
            with os.fdopen(os.open(roster, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb") as writer:
                writer.write(body)
                writer.flush()
                os.fsync(writer.fileno())
            endpoint = root / f"control-{name}.sock"
            fresh_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            fresh_listener.bind(str(endpoint))
            fresh_listener.listen(1)
            environment = os.environ.copy()
            environment.update({
                "CRUCIBLE_RESTORE_RESOURCE_ROOT": str(branch),
                "CRUCIBLE_GEM5_OPERATIONAL_ROOT": str(scratch),
                "DMTCP_PATH_MAPPING": f"{resource}:{branch}",
                "CRUCIBLE_GEM5_CONTROL_SOCKET": str(endpoint),
                "CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT": str(source_saved_root),
                "CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT": str(imported_saved),
                "CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST": str(roster),
            })
            error_path = root / f"{name}.restart.stderr"
            with error_path.open("wb") as errors:
                restored = subprocess.Popen([
                    str(Path(dmtcp) / "bin/dmtcp_restart"), "--new-coordinator", "--coord-port", "0",
                    "--interval", "0", "--ckptdir", str(fresh_images), "--tmpdir", str(scratch),
                    str(historical_image),
                ], env=environment, cwd=scratch, start_new_session=True,
                   stdout=subprocess.DEVNULL, stderr=errors)
                coexistence_complete = False
                try:
                    image_check.own_process(restored)
                    fresh = image_check.accept(fresh_listener, restored)
                    image_check.authenticate(fresh, restored, native, dmtcp, image_guard)
                    send(fresh, {"kind": "restore_bind", "owner": "serial-node",
                                 "source_incarnation": "source", "source_generation": "1",
                                 "incarnation": name, "generation": "2",
                                 "capture": capture["capture"]})
                    rebound = receive(fresh)
                    assert rebound["continuation"] == "restored"
                    assert rebound["boundary"] == receipt["after"]
                    assert rebound["model_scope"] == ready["model_scope"]
                    assert exchange(fresh, first) == receipt
                    assert exchange(fresh, {"kind": "recover", "operation": first["operation"]}) == receipt
                    assert exchange(fresh, {"kind": "observe"})["boundary"] == receipt["after"]
                    recapture = {"kind": "capture", "capture": f"fresh/{name}"}
                    recaptured = exchange(fresh, recapture)
                    assert recaptured["boundary"] == receipt["after"]
                    assert fresh.recv(1) == b""
                    fresh.close()
                    fresh = image_check.accept(fresh_listener, restored)
                    image_check.authenticate(fresh, restored, native, dmtcp, image_guard)
                    current = receive(fresh)
                    assert current["continuation"] == "captured"
                    assert current["boundary"] == receipt["after"]
                    authenticate_retained_progress(fresh, pre_output_checkpoints)
                    current_images = list(fresh_images.glob("*.dmtcp"))
                    assert len(current_images) == 1
                    image_check.audit(exchange, fresh, restored, root, branch, current_images[0],
                                      receipt["after"], current["model_scope"], native,
                                      image_guard, source_directory, name)
                    with participant_lock:
                        if name in participants:
                            raise ValueError("fresh witness branch was already enrolled")
                        participants[name] = restored
                    audited.wait()
                    with participant_lock:
                        if set(participants) != {"child-a", "child-b"}:
                            raise ValueError("fresh witness lacks both audited original owners")
                        current_groups = tuple(participants[label] for label in ("child-a", "child-b"))
                    coexisting_anchors = image_check.require_coexisting_groups(current_groups)
                    original_anchor = next(row for row in coexisting_anchors
                                           if row["pid"] == str(restored.pid))
                    checked_live.wait()
                    coexistence_complete = True
                    assert exchange(fresh, first) == receipt
                    assert exchange(fresh, ack) == exchange(fresh, ack)
                    assert finish(fresh) == suffix
                    assert exchange(fresh, {"kind": "shutdown"}) == {"kind": "shutdown"}
                    fresh.close()
                    assert image_check.wait_exited(restored, timeout=10) == 0, error_path.read_text(errors="replace")
                    assert image_check.digest(historical_image) == image_digest
                    assert not source_namespace.exists()
                    return {"branch": name, "fresh_capture_byte_closure": True,
                            "original_held_receipt_unchanged": True, "exact_suffix": True,
                            "source_namespace_absent": True,
                            "coexisting_fresh_groups_checked": True,
                            "coexisting_kernel_anchors": coexisting_anchors,
                            "fresh_kernel_anchor": original_anchor,
                            "group_reclaimed": image_check.reclaim(restored)}
                finally:
                    # A failed branch cannot strand its sibling at either
                    # rendezvous or allow a partial result to become a witness.
                    if not coexistence_complete:
                        audited.abort()
                        checked_live.abort()
                    fresh_listener.close()
                    image_check.reclaim(restored)

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            branches = list(pool.map(reconstruct, ("child-a", "child-b")))
    result = {"schema": "crucible.gem5.shared-controller-x86-linux-root-mechanism.v1",
              "original_linux_serial_birth_retained": True,
              "exclusive_full_position_stop": True, "original_retry_unchanged": True,
              "native_uart_birth_preserved": True, "full_system_qualified": False,
              "complete_process_closure_qualified": False, "guest_readiness_qualified": False,
              "cpu_timing_qualified": False, "publications": receipt["publications"],
              "model_scope": ready["model_scope"], "source_group_reclaimed": source_group_reclaimed,
              "fresh_branches": branches}
    result["implementation_bindings"] = {
        "native_executable": image_check.digest(Path(native)),
        "image_guard": image_check.digest(Path(image_guard)),
        "dmtcp_launch": image_check.digest(Path(dmtcp) / "bin/dmtcp_launch"),
        "dmtcp_restart": image_check.digest(Path(dmtcp) / "bin/dmtcp_restart"),
        "mtcp_restart": image_check.digest(Path(dmtcp) / "bin/mtcp_restart"),
        "python": image_check.digest(Path(sys.executable).resolve()),
    }
    result["helper_bindings"] = {
        path.name: image_check.digest(path)
        for path in sorted(Path(source_directory).glob("*.py"))
    }
    (root / "result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
finally:
    listener.close()
    image_check.reclaim(child)
