# SPDX-License-Identifier: MIT
"""Exercises actual native owner control and source-death image continuation.

All executable arguments name installed source-built artifacts. The witness
never treats controller success as complete CPU/device profile qualification.
"""

import json
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time


gem5, owner_script, guest_isa, guest, native_guest, directory = sys.argv[1:7]
process_tools = sys.argv[7:]
if process_tools and len(process_tools) != 2:
    raise ValueError("process-image witness requires DMTCP root and resource helper")
root = Path(directory).resolve()
root.mkdir(mode=0o700)
resource = root / "origin"
resource.mkdir(mode=0o700)
expected_output = subprocess.check_output([native_guest])
guest_copy = resource / "guest.elf"
shutil.copy2(guest, guest_copy)
installed_owner = resource / "native-owner.py"
shutil.copy2(owner_script, installed_owner)
shutil.copy2(Path(owner_script).with_name("native-owner-model.py"), resource / "native-owner-model.py")
socket_path = root / "control.sock"
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(str(socket_path))
listener.listen(2)
listener.settimeout(180)


def send(stream, value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    stream.sendall(struct.pack("!I", len(encoded)) + encoded)


def receive(stream):
    def exact(length):
        result = bytearray()
        while len(result) < length:
            part = stream.recv(length - len(result))
            if not part:
                raise EOFError("native witness controller disconnected")
            result.extend(part)
        return result

    length = struct.unpack("!I", exact(4))[0]
    assert 0 < length <= 4 * 1024 * 1024
    return json.loads(exact(length))


def request(stream, value):
    send(stream, value)
    return receive(stream)


def artifact_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as artifact:
        for part in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def accept_native(endpoint, process):
    endpoint.settimeout(0.1)
    deadline = time.monotonic() + 180
    while True:
        try:
            stream, _ = endpoint.accept()
            return stream
        except socket.timeout:
            if process.poll() is not None:
                raise AssertionError("native child exited before authentic readiness")
            if time.monotonic() >= deadline:
                raise TimeoutError("native owner readiness deadline")



def reclaim_group(process):
    """Kills operational helper processes and proves the private group is empty."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)
    deadline = time.monotonic() + 10
    while True:
        members = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                stat = (entry / "stat").read_text()
                # A process command can contain spaces and parentheses.
                fields = stat[stat.rfind(")") + 2:].split()
                if int(fields[2]) == process.pid:
                    members.append(int(entry.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
        if not members:
            return True
        if time.monotonic() >= deadline:
            raise AssertionError(f"native private process group remains: {members}")
        time.sleep(0.02)


def authenticate_peer(stream, process, restored=False):
    pid, uid, _ = struct.unpack("3i", stream.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    ))
    assert uid == os.getuid() and pid == process.pid
    executable = os.readlink(f"/proc/{pid}/exe")
    mappings = Path(f"/proc/{pid}/maps").read_text().splitlines()
    # A restarted process may report mtcp_restart as its executable. Actual
    # executable gem5 mappings must still identify the measured original code.
    native_mappings = [line for line in mappings
                       if len(line.split()) >= 6 and line.split()[1][2] == "x"
                       and line.split(maxsplit=5)[5] == gem5]
    assert native_mappings and artifact_digest(gem5) == native_digest
    if not restored:
        assert artifact_digest(f"/proc/{pid}/exe") == native_digest
    else:
        assert artifact_digest(f"/proc/{pid}/exe") == artifact_digest(f"{dmtcp}/bin/mtcp_restart")
        assert any(len(line.split()) >= 6 and line.split(maxsplit=5)[5] == resource_helper
                   for line in mappings)
        assert artifact_digest(resource_helper) == helper_digest
    return {"pid": pid, "executable": executable,
            "gem5_code_mapped": True, "original_code_sha256": native_digest}


def audit_capture(control, process, owned, image, boundary, label):
    """Audits the actual current parked owner against its new native image."""
    inventory = request(control, {"kind": "process_inventory"})
    assert inventory["boundary"] == boundary
    source_stat = Path(f"/proc/{process.pid}/stat").read_text()
    start_ticks = source_stat[source_stat.rfind(")") + 2:].split()[19]
    audit_request = {
        "schema": "crucible.gem5.process-closure-request.v1",
        "pid": str(process.pid), "start_ticks": start_ticks,
        "owned_root": str(root), "image": str(image),
        "assets": [{"path": str(path), "sha256": artifact_digest(path)}
                   for path in (gem5, owned / "native-owner.py",
                                owned / "native-owner-model.py",
                                owned / "guest.elf", resource_helper)],
        "profile": "freestanding-o3-classic-ddr3-v1", "guest_isa": guest_isa,
        "guest_executable": str(owned / "guest.elf"),
        "boundary_sha256": hashlib.sha256(json.dumps(
            boundary, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "native_inventory": inventory,
        "thread_contexts": inventory["thread_contexts"],
        "captured_descriptors": inventory["captured_descriptors"],
        "captured_maps": inventory["captured_maps"],
        "captured_file_maps": inventory["captured_file_maps"],
        "operational_shared_maps": inventory["operational_shared_maps"],
    }
    prefix = "" if label == "source" else f"{label}-"
    (root / f"{prefix}closure-request.json").write_text(json.dumps(audit_request, sort_keys=True))
    (root / f"{prefix}closure-kernel-maps.txt").write_text(Path(f"/proc/{process.pid}/maps").read_text())
    auditor_command = ([sys.executable, "-B", auditor] if auditor.endswith(".py") else [auditor])
    inspected = subprocess.run(auditor_command, input=json.dumps(audit_request).encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=180, check=False)
    (root / f"{prefix}closure-result.json").write_bytes(inspected.stdout)
    (root / f"{prefix}closure-stderr.txt").write_bytes(inspected.stderr)
    if inspected.returncode != 0:
        raise AssertionError(inspected.stderr.decode())
    closure = json.loads(inspected.stdout)
    assert closure["complete"] is True
    assert closure["modeled_diagnostics_complete"] is False
    return artifact_digest(image)


native_digest = artifact_digest(gem5)
helper_digest = artifact_digest(process_tools[1]) if process_tools else None
bootstrap, inherited = socket.socketpair()
stdout = (resource / "native.stdout").open("wb")
stderr = (resource / "native.stderr").open("wb")
command = [gem5, f"--outdir={resource / 'output'}", str(installed_owner)]
environment = os.environ.copy()
if process_tools:
    dmtcp, resource_helper = process_tools
    images = root / "images"
    images.mkdir(mode=0o700)
    temporary = root / "tmp"
    temporary.mkdir(mode=0o700)
    environment["CRUCIBLE_CAPTURE_RESOURCE_ROOT"] = str(resource)
    command = [
        f"{dmtcp}/bin/dmtcp_launch", "--new-coordinator", "--coord-port", "0",
        "--interval", "0", "--no-gzip", "--ckpt-signal", "40",
        "--with-plugin", resource_helper, "--ckptdir", str(images),
        "--tmpdir", str(temporary),
    ] + command
child = subprocess.Popen(command, stdin=inherited, stdout=stdout, stderr=stderr,
                         env=environment, cwd=temporary if process_tools else resource,
                         start_new_session=True)
inherited.close()
send(bootstrap, {
    "schema": "crucible.gem5.native/2", "owner": "machine",
    "incarnation": "native/source", "generation": "1",
    "controller_uid": str(os.getuid()), "guest_isa": guest_isa,
    "executable": str(guest_copy), "resource_root": str(resource),
    "control_socket": str(socket_path),
})
bootstrap.close()
try:
    stream = accept_native(listener, child)
    stream.settimeout(180)
    original_identity = authenticate_peer(stream, child)
    ready = receive(stream)
    assert ready["kind"] == "ready" and ready["continuation"] == "original"
    assert ready["boundary"]["tick"] == "0"
    assert ready["boundary"]["ordinal"] == "0"
    # Missing microstate diagnostics cannot qualify exact CNP admission.
    assert ready["boundary"]["inventory"]["complete"] is False
    assert request(stream, {"kind": "observe"})["boundary"] == ready["boundary"]

    at_zero = {
        "kind": "run", "operation": "run/zero",
        "exclusive_tick": "0", "maximum_events": "100", "exact_range": None,
    }
    stopped = request(stream, at_zero)
    assert stopped["processed_events"] == "0"
    assert stopped["before"] == stopped["after"]
    assert request(stream, at_zero) == stopped
    assert request(stream, {"kind": "acknowledge", "operation": "run/zero"})["kind"] == "acknowledged"

    # Exercise full-coordinate mechanics using the same real native callback
    # queue. This witness does not manufacture installed profile authority.
    first_tick = ready["boundary"]["next_tick"]
    before_reaction = {"time_ps": first_tick, "microstep": "0", "phase": 3}
    precise_zero = {
        "kind": "run", "operation": "run/precise-zero", "exclusive_tick": first_tick,
        "maximum_events": "100", "exact_range": {
            "start": stopped["after"]["logical_position"], "limit": before_reaction,
            "maximum_microsteps": "1000000",
        },
    }
    precise = request(stream, precise_zero)
    assert precise["processed_events"] == "0" and precise["reason"] == "horizon"
    assert precise["after"]["logical_position"] == before_reaction
    assert precise["after"]["tick"] == ready["boundary"]["tick"]
    assert request(stream, precise_zero) == precise
    request(stream, {"kind": "acknowledge", "operation": precise["operation"]})

    after_reaction = {"time_ps": first_tick, "microstep": "1", "phase": 0}
    precise_one = {
        "kind": "run", "operation": "run/precise-one", "exclusive_tick": first_tick,
        "maximum_events": "1", "exact_range": {
            "start": before_reaction, "limit": after_reaction,
            "maximum_microsteps": "1000000",
        },
    }
    precise = request(stream, precise_one)
    assert precise["processed_events"] == "1" and precise["reason"] == "horizon"
    assert precise["after"]["logical_position"] == after_reaction
    assert request(stream, precise_one) == precise
    request(stream, {"kind": "acknowledge", "operation": precise["operation"]})

    cut_request = {
        "kind": "run", "operation": "run/cut",
        "exclusive_tick": str((1 << 64) - 1), "maximum_events": "4999", "exact_range": None,
    }
    cut = request(stream, cut_request)
    assert cut["processed_events"] == "4999"
    assert cut["reason"] == "event_budget"
    assert cut["after"]["ordinal"] == "5000"
    assert request(stream, {"kind": "observe"})["boundary"] == cut["after"]
    assert request(stream, cut_request) == cut
    stream.close()
    stream = accept_native(listener, child)
    stream.settimeout(180)
    authenticate_peer(stream, child)
    reconnected = receive(stream)
    assert reconnected["continuation"] == "reconnected"
    assert reconnected["boundary"] == cut["after"]
    assert request(stream, {"kind": "recover", "operation": "run/cut"}) == cut
    assert request(stream, {"kind": "recover", "operation": "run/never-started"}) == {
        "kind": "not_started", "operation": "run/never-started",
    }
    assert request(stream, {"kind": "observe"})["boundary"] == cut["after"]
    assert request(stream, {"kind": "acknowledge", "operation": "run/cut"})["kind"] == "acknowledged"

    if process_tools:
        capture = request(stream, {"kind": "capture", "capture": "capture/original"})
        assert capture == {"kind": "capture_ready", "capture": "capture/original", "boundary": cut["after"]}
        assert stream.recv(1) == b""
        stream.close()
        stream = accept_native(listener, child)
        stream.settimeout(180)
        continued = receive(stream)
        assert continued["continuation"] == "captured" and continued["boundary"] == cut["after"]
        image_files = list(images.glob("*.dmtcp"))
        assert len(image_files) == 1 and image_files[0].stat().st_size > 0
        image_digest = artifact_digest(image_files[0])
        auditor = os.environ.get("CRUCIBLE_GEM5_IMAGE_AUDITOR")
        if auditor:
            audit_capture(stream, child, resource, image_files[0], cut["after"], "source")
        # Capture writable resource contents at the original cut, before any
        # continuation can write future guest output into the preserved files.
        preserved = root / "preserved-files"
        shutil.copytree(resource, preserved)

    def finish(original_stream):
        output = bytearray()
        suffix = []
        for index in range(10):
            operation = f"run/suffix/{index}"
            result = request(original_stream, {
                "kind": "run", "operation": operation,
                "exclusive_tick": str((1 << 64) - 1), "maximum_events": "10000000", "exact_range": None,
            })
            assert int(result["after"]["ordinal"]) - int(result["before"]["ordinal"]) == int(result["processed_events"])
            for publication in result["publications"]:
                assert publication["tick"] == result["after"]["tick"]
                assert publication["event_ordinal"] == result["after"]["ordinal"]
                assert publication["tick_ordinal"] == result["after"]["tick_ordinal"]
                assert int(publication["event_ordinal"]) > int(result["before"]["ordinal"])
                assert publication["guest_fd"] == 1 and publication["payload"]
            if os.environ.get("CRUCIBLE_GEM5_REQUIRE_NATIVE_BIRTH") and result["output"]:
                assert result["publications"]
            if result["publications"]:
                assert result["output"] == [byte for publication in result["publications"]
                                           for byte in publication["payload"]]
            output.extend(result["output"])
            suffix.append({key: result[key] for key in ("processed_events", "reason", "after", "output", "publications", "exit_code")})
            assert request(original_stream, {"kind": "acknowledge", "operation": operation})["kind"] == "acknowledged"
            if result["reason"] == "guest_exit":
                assert result["exit_code"] == 0
                break
        else:
            raise AssertionError("guest failed to finish within bounded original native requests")
        assert bytes(output) == expected_output
        return output, suffix

    output, suffix = finish(stream)
    assert request(stream, {"kind": "shutdown"}) == {"kind": "shutdown"}
    stream.close()
    assert child.wait(timeout=10) == 0
    source_group_reclaimed = reclaim_group(child)
    if process_tools:
        shutil.rmtree(resource)

        def reconstruct(name):
            branch = root / name
            shutil.copytree(preserved, branch)
            branch.chmod(0o700)
            fresh_socket = root / f"control-{name}.sock"
            fresh_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            fresh_listener.bind(str(fresh_socket))
            fresh_listener.listen(1)
            fresh_listener.settimeout(0.1)
            scratch = root / f"tmp-{name}"
            scratch.mkdir(mode=0o700)
            fresh_images = root / f"images-{name}"
            fresh_images.mkdir(mode=0o700)
            restart_environment = os.environ.copy()
            restart_environment.update({
                "CRUCIBLE_RESTORE_RESOURCE_ROOT": str(branch),
                "CRUCIBLE_GEM5_OPERATIONAL_ROOT": str(scratch),
                "DMTCP_PATH_MAPPING": f"{resource}:{branch}",
                "CRUCIBLE_GEM5_CONTROL_SOCKET": str(fresh_socket),
            })
            error_path = root / f"{name}.restore.stderr"
            restart_errors = error_path.open("wb")
            restored = subprocess.Popen([
                f"{dmtcp}/bin/dmtcp_restart", "--new-coordinator", "--coord-port", "0",
                "--interval", "0", "--ckptdir", str(fresh_images),
                "--tmpdir", str(scratch), str(image_files[0]),
            ], env=restart_environment, stdout=subprocess.DEVNULL, stderr=restart_errors,
               cwd=scratch, start_new_session=True)
            try:
                deadline = time.monotonic() + 180
                while True:
                    try:
                        fresh, _ = fresh_listener.accept()
                        break
                    except TimeoutError:
                        if restored.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError(
                                "native restore failed before fresh controller: "
                                + error_path.read_text(errors="replace")
                            )
                fresh.settimeout(180)
                fresh_identity = authenticate_peer(fresh, restored, restored=True)
                assert artifact_digest(image_files[0]) == image_digest
                send(fresh, {
                    "kind": "restore_bind", "owner": "machine",
                    "source_incarnation": "native/source", "source_generation": "1",
                    "incarnation": f"native/{name}", "generation": "2",
                    "capture": "capture/original",
                })
                rebound = receive(fresh)
                assert rebound["continuation"] == "restored"
                assert rebound["incarnation"] == f"native/{name}" and rebound["generation"] == "2"
                assert rebound["boundary"] == cut["after"]
                assert request(fresh, {"kind": "observe"})["boundary"] == cut["after"]
                fresh_closure = False
                if os.environ.get("CRUCIBLE_GEM5_REQUIRE_FRESH_CLOSURE"):
                    if not auditor:
                        raise AssertionError("fresh native closure requires the installed auditor")
                    capture_id = f"capture/{name}"
                    captured = request(fresh, {"kind": "capture", "capture": capture_id})
                    assert captured == {"kind": "capture_ready", "capture": capture_id,
                                        "boundary": cut["after"]}
                    assert fresh.recv(1) == b""
                    fresh.close()
                    fresh = accept_native(fresh_listener, restored)
                    fresh.settimeout(180)
                    authenticate_peer(fresh, restored, restored=True)
                    recaptured = receive(fresh)
                    assert recaptured["continuation"] == "captured"
                    assert recaptured["boundary"] == cut["after"]
                    current_images = list(fresh_images.glob("*.dmtcp"))
                    assert len(current_images) == 1
                    assert current_images[0].parent != image_files[0].parent
                    audit_capture(fresh, restored, branch, current_images[0], cut["after"], name)
                    assert artifact_digest(image_files[0]) == image_digest
                    fresh_closure = True
                branch_output, branch_suffix = finish(fresh)
                assert branch_output == output and branch_suffix == suffix
                assert request(fresh, {"kind": "shutdown"}) == {"kind": "shutdown"}
                fresh.close()
                assert restored.wait(timeout=10) == 0, error_path.read_text(errors="replace")
                group_reclaimed = reclaim_group(restored)
                assert (branch / "guest.output").read_bytes() == bytes(output)
                return {"branch": name, "fresh_control": True, "unchanged_cut": True,
                        "native_identity": fresh_identity, "image_sha256": image_digest,
                        "group_reclaimed": group_reclaimed,
                        "fresh_capture_closure": fresh_closure}
            finally:
                fresh_listener.close()
                restart_errors.close()
                reclaim_group(restored)

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            restored_results = list(pool.map(reconstruct, ("child-a", "child-b")))
        assert not resource.exists()
    (root / "result.json").write_text(json.dumps({
        "guest_isa": guest_isa, "cut": cut["after"], "suffix": suffix,
        "actual_checksum_matches_native": True, "exact_profile_qualified": False,
        "source_dead_before_restore": bool(process_tools),
        "private_concurrent_reconstructions": restored_results if process_tools else [],
        "original_native_identity": original_identity,
        "group_reclaimed": source_group_reclaimed,
        "full_position_stop_before_reaction": True,
        "full_position_single_callback_at_budget_ceiling": True,
        "original_request_retry_unchanged": True,
    }, sort_keys=True) + "\n")
    print(json.dumps({"guest_isa": guest_isa, "native_control": "passed", "cut_events": 5000,
                      "output_bytes": len(output), "final_tick": suffix[-1]["after"]["tick"],
                      "fresh_restores": 2 if process_tools else 0}))
finally:
    reclaim_group(child)
    listener.close()
    stdout.close()
    stderr.close()
