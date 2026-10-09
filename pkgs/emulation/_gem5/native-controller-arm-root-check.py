# SPDX-License-Identifier: MIT
"""Checks real ARM Linux serial birth through the shared stopped controller.

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


native, source_directory, output_directory, configs, kernel, initrd, firmware = sys.argv[1:8]
process_tools = sys.argv[8:]
if process_tools and len(process_tools) != 2:
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
             "native-controller-arm-model.py", "native-model-assets.py",
             "native-controller-arm-root.py", "native-controller-arm-root-model.py"):
    target = resource / name
    source = Path(source_directory) / name
    descriptor, metadata = image_check.checked_file(source)
    os.close(descriptor)
    image_check.copy_file(source, target, metadata, 0o600)
for origin, name in ((kernel, "kernel.elf"), (initrd, "initrd.img"), (firmware, "boot_v2.arm64")):
    destination = resource / name
    descriptor, metadata = image_check.checked_file(origin)
    os.close(descriptor)
    image_check.copy_file(origin, destination, metadata, 0o600)
image_check.copy_tree(Path(configs), resource / "configs")
spec = importlib.util.spec_from_file_location("model_assets", resource / "native-model-assets.py")
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)
model = {"schema": "crucible.gem5.arm-linux-root-model.v1", "assets": {},
         "configs": assets.configuration_tree(resource / "configs")}
for role, name in (("kernel", "kernel.elf"), ("initramfs", "initrd.img"), ("firmware", "boot_v2.arm64")):
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


command = [native, "--listener-mode=off", f"--outdir={resource / 'output'}",
           str(resource / "native-controller-arm-root.py")]
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
        "schema": "crucible.gem5.arm-linux-native/1", "owner": "serial-node",
        "incarnation": "source", "generation": "1", "controller_uid": str(os.getuid()),
        "guest_isa": "aarch64", "executable": "", "resource_root": str(resource), "model": model,
        "control_socket": str(endpoint),
    })
    parent.close()
    control, _ = listener.accept()
    control.settimeout(60)
    peer_pid, uid, _ = struct.unpack("3i", control.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    assert peer_pid == child.pid and uid == os.getuid()
    ready = receive(control)
    assert ready["schema"] == "crucible.gem5.arm-linux-native/1"
    assert ready["model_scope"]["complete_process_closure_qualified"] is False
    original = ready["boundary"]
    assert original["ordinal"] == "0"
    assert exchange(control, {"kind": "observe"})["boundary"] == original

    blocked = grant("stop-before-first-native-reaction", original["logical_position"], position(0, 0, 3))
    excluded = exchange(control, blocked)
    assert excluded["kind"] == "completed" and excluded["reason"] == "horizon"
    assert excluded["processed_events"] == "0" and excluded["after"]["ordinal"] == "0"
    assert excluded["publications"] == []
    assert exchange(control, {"kind": "acknowledge", "operation": blocked["operation"]})["kind"] == "acknowledged"

    first = grant("first-original-linux-uart-birth", excluded["after"]["logical_position"], position(100000000000, 0, 3))
    first["maximum_events"] = "262144"
    receipt = exchange(control, first)
    assert receipt["reason"] == "output" and int(receipt["processed_events"]) > 0
    assert receipt["output"] == [ord("[")] and len(receipt["publications"]) == 1
    publication = receipt["publications"][0]
    assert publication["output_id"] == "1" and publication["causal_parent"] == "0"
    assert publication["tick"] == receipt["after"]["tick"]
    assert publication["event_ordinal"] == receipt["after"]["ordinal"]
    assert publication["tick_ordinal"] == receipt["after"]["tick_ordinal"]
    assert publication["facet"] == "serial" and "guest_fd" not in publication
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
                    current_images = list(fresh_images.glob("*.dmtcp"))
                    assert len(current_images) == 1
                    image_check.audit(exchange, fresh, restored, root, branch, current_images[0],
                                      receipt["after"], current["model_scope"], native,
                                      image_guard, source_directory, name)
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
                            "group_reclaimed": image_check.reclaim(restored)}
                finally:
                    fresh_listener.close()
                    image_check.reclaim(restored)

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            branches = list(pool.map(reconstruct, ("child-a", "child-b")))
    result = {"schema": "crucible.gem5.shared-controller-arm-linux-root-mechanism.v1",
              "original_linux_serial_birth_retained": True,
              "exclusive_full_position_stop": True, "original_retry_unchanged": True,
              "native_uart_birth_preserved": True, "full_system_qualified": False,
              "complete_process_closure_qualified": False, "guest_readiness_qualified": False,
              "cpu_timing_qualified": False, "publications": receipt["publications"],
              "model_scope": ready["model_scope"], "source_group_reclaimed": source_group_reclaimed,
              "fresh_branches": branches}
    (root / "result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
finally:
    listener.close()
    image_check.reclaim(child)
