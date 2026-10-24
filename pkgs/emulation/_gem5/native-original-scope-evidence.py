# SPDX-License-Identifier: MIT
"""Binds thirteen actual controls to the installed ELF and complete source archive."""

import hashlib
import json
import os
import sys
from pathlib import Path


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or identity(after) != identity(path.stat()):
        raise ValueError("Artifact changed while binding its digest")
    return {"path": str(path), "sha256": result.hexdigest(), "bytes": after.st_size}


def bounded_json(path, ceiling=65536):
    with path.open("rb") as stream:
        body = stream.read(ceiling + 1)
    if len(body) > ceiling:
        raise ValueError("Source binding exceeds the fixed metadata extent")
    return json.loads(body)


if len(sys.argv) != 7:
    raise ValueError("expected foundation, source, recipe, invoked check/guest and output")

foundation, source, check_recipe, invoked_check, invoked_guest, output = map(Path, sys.argv[1:])
record = bounded_json(foundation / "share/gem5/native-original-scope-source/manifest.json")
controls = source / "build/controls"
recipes = source / "build/recipes"
check = controls / "native-original-scope-check.py"
guest = controls / "native-diagnostic-guest.py"
if (digest(invoked_check)["sha256"] != digest(check)["sha256"] or
        digest(invoked_guest)["sha256"] != digest(guest)["sha256"] or
        digest(Path(__file__))["sha256"] != digest(controls / "native-original-scope-evidence.py")["sha256"] or
        digest(source / "patches/native-original-scope-and-diagnostic-atomic-owners.patch")["sha256"] != record["patchSha256"] or
        digest(source / "patches/native-system-counter-source-state.patch")["sha256"] != record["counterStatePatchSha256"] or
        digest(controls / "system-counter-observation-check.py")["sha256"] != record["counterObservationCheckSha256"] or
        digest(source / "patches/native-system-counter-callable-owner.patch")["sha256"] != record["counterCallablePatchSha256"] or
        digest(check)["sha256"] != record["checkSha256"] or
        digest(guest)["sha256"] != record["guestSourceSha256"] or
        digest(check_recipe)["sha256"] != record["diagnosticCheckRecipeSha256"] or
        digest(recipes / "gem5-native-original-scope-check.nix")["sha256"] != digest(check_recipe)["sha256"] or
        digest(recipes / "gem5-native-original-scope-foundation.nix")["sha256"] != record["recipeSha256"]):
    raise ValueError("Installed ELF source controls and recipes differ")

modes = ("owned", "unknown-bus", "changed-clock", "foreign-helper", "unarmed",
         "counter-owned", "counter-pending", "counter-invalid-table",
         "counter-copy-original", "counter-copy-foreign", "counter-owner-foreign",
         "counter-callable-foreign", "counter-callable-empty")
results = []
for mode in modes:
    log = Path(f"native-scope-{mode}.log")
    with log.open("rb") as stream:
        body = stream.read(65537)
    if len(body) > 65536:
        raise ValueError("Native diagnostic log exceeds the fixed extent")
    records = []
    counter_records = []
    for line in body.splitlines():
        if line.startswith(b'{"'):
            value = json.loads(line)
            if value.get("schema") == "crucible.gem5.diagnostic-original-native-ownership.v1":
                records.append(value)
            if value.get("schema") == "crucible.gem5.diagnostic-system-counter-source.v1":
                counter_records.append(value)
    if len(counter_records) != int(mode.startswith("counter-")):
        raise ValueError("Actual counter producer evidence is absent or duplicated")
    if counter_records:
        fields = counter_records[0]["counter"]["objects"][0]["modeled_fields"]
        type_matches = mode not in ("counter-callable-foreign", "counter-callable-empty")
        owner_matches = mode not in (
            "counter-copy-foreign", "counter-owner-foreign",
            "counter-callable-foreign", "counter-callable-empty"
        )
        if (fields["counter.frequency_callback_type_matches"] != str(int(type_matches)) or
                fields["counter.frequency_callback_owner_matches"] != str(int(owner_matches))):
            raise ValueError("Actual native counter callable differs from its attack control")
        counter = counter_records[0]
        if counter["mode"] != mode or any(counter[field] for field in (
                "source_cut_qualified", "listener_closure_qualified",
                "native_backing_qualified", "restore_qualified")):
            raise ValueError("Counter producer evidence changes scope or authority")
        if counter["native_position"] != {
                "tick": "0", "ordinal": "0", "tick_ordinal": "0", "active": False}:
            raise ValueError("Counter inspection serviced or advanced native work")
    if len(records) != 1 or records[0]["mode"] != mode:
        raise ValueError("Native control result is absent, duplicated or mismatched")
    value = records[0]
    expected_walk = mode in ("owned", "foreign-helper", "unarmed",
                             "counter-owned", "counter-pending", "counter-copy-original")
    if bool(value["ownership"][0]) != expected_walk:
        raise ValueError("Actual diagnostic ownership differs from the selected control")
    if any(value[field] for field in (
            "native_source_cut_qualified", "native_restore_qualified", "linux_qualified",
            "general_isa_qualified", "device_parity_qualified", "common_ready_qualified")):
        raise ValueError("Diagnostic control unexpectedly claims native node authority")
    with Path(f"native-scope-{mode}.status").open("rb") as stream:
        status_body = stream.read(9)
    expected_status = b"126\n" if mode == "unarmed" else b"0\n"
    if status_body != expected_status:
        raise ValueError("Original native process status differs")
    results.append({"mode": mode, "exit_status": int(status_body),
                    "result": value, "log": digest(log),
                    "counter_observation": counter_records[0] if counter_records else None})

counter_observation = bounded_json(output.parent / "counter-observation.json")
if (counter_observation.get("schema") != "crucible.gem5.system-counter-observation-mechanism.v1" or
        any(counter_observation[field] for field in (
            "source_cut_qualified", "listener_closure_qualified", "native_backing_qualified",
            "restore_qualified", "linux_qualified", "common_ready_qualified"))):
    raise ValueError("Actual stale-counter mechanism result changes authority")

binding = {
    "schema": "crucible.gem5.mandatory-native-diagnostic-source-binding.v1",
    "elf": digest(foundation / "bin/gem5"),
    "full_source_archive": digest(source / "gem5-patched-source.tar"),
    "upstream_source_archive": digest(source / "gem5-upstream.tar.gz"),
    "toolchain": bounded_json(source / "build/toolchain.json"),
    "foundation_recipe": digest(recipes / "gem5-native-original-scope-foundation.nix"),
    "check_recipe": digest(check_recipe),
    "check_script": digest(check),
    "guest_source": digest(guest),
    "invoked_check_script": digest(invoked_check),
    "invoked_guest_source": digest(invoked_guest),
    "evidence_writer": digest(controls / "native-original-scope-evidence.py"),
    "native_profile_source": record,
    "controls": results,
    "counter_observation_mechanism": counter_observation,
    "native_source_issuer_qualified": False,
    "native_restore_qualified": False,
    "common_ready_qualified": False,
}
output.write_text(json.dumps(binding, sort_keys=True, separators=(",", ":")) + "\n")
