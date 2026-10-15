# SPDX-License-Identifier: MIT
"""Checks actual x86 asset-copy data without running a native executable.

The caller supplies a finite source-bound artifact specification. A successful
build below checks actual kernel/compiled PID1/initramfs bytes and fixed helper
hashes. Returned argv is inspected only. No fake native permission is supplied.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 4:
        raise ValueError("expected bundle helper, fixed specification, fresh scratch")
    helper_path, specification, scratch = map(Path, sys.argv[1:])
    module_spec = importlib.util.spec_from_file_location("x86_bundle_checks", helper_path)
    helper = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(helper)
    scratch.mkdir(mode=0o700)
    prepared_root = scratch / "prepared"
    prepared_root.mkdir(mode=0o700)
    document = helper.build(helper.read_json(specification))
    observed = helper.prepare(document, prepared_root)
    valid_document = scratch / "bundle.json"
    helper.write_document(document, valid_document)
    if helper.read_json(valid_document) != document:
        raise AssertionError("actual bounded bundle document did not round-trip")
    oversized = scratch / "oversized-bundle.json"
    try:
        helper.write_document({"data_only": "x" * helper.MAX_DOCUMENT}, oversized)
    except ValueError:
        if oversized.exists():
            raise AssertionError("oversized document was opened before refusal")
    else:
        raise AssertionError("encoded document exceeded its readback bound")
    controls = ["actual_kernel_pid1_initramfs_loader_and_component_bindings"]

    if observed["qualification"] != helper.QUALIFICATION or any(observed["qualification"].values()):
        raise AssertionError("asset preparation promoted native qualification")
    expected_command = [document["artifacts"]["native_executable"]["path"],
                        "--listener-mode=off", "--outdir=" + str(prepared_root),
                        document["artifacts"]["entrypoint"]["path"]]
    if observed["argv"] != expected_command:
        raise AssertionError("fixed original native command changed")
    controls.append("fixed_native_argv_is_data_only_and_unexecuted")

    native_assets = helper.load_helper("x86_bundle_native_asset_checks", document["artifacts"]["asset_checker"]["path"])
    for role, basename in (("kernel", "kernel.elf"), ("initramfs", "initrd.img")):
        native_assets.verify_asset(prepared_root, observed["model"]["assets"][role], basename)
    controls.append("actual_private_kernel_and_initramfs_match_originals")
    if native_assets.configuration_tree(prepared_root / "configs") != observed["model"]["configs"]:
        raise AssertionError("private actual configs differ from native row codec")
    directories = sorted(str(path.relative_to(prepared_root / "configs"))
                         for path in (prepared_root / "configs").rglob("*") if path.is_dir())
    if directories != document["configuration"]["directories"]:
        raise AssertionError("private configuration lost original directories")
    controls.append("actual_private_configuration_bytes_and_empty_directories_preserved")

    def refused(name, operation):
        try:
            operation()
        except ValueError:
            controls.append(name)
        else:
            raise AssertionError("changed data was accepted: " + name)

    refused("occupied_original_root_never_reused", lambda: helper.prepare(document, prepared_root))
    wrong_hash = copy.deepcopy(document)
    wrong_hash["artifacts"]["kernel"]["sha256"] = "0" * 64
    unused = scratch / "unused"
    unused.mkdir(mode=0o700)
    refused("changed_kernel_binding_refuses_before_output_creation", lambda: helper.prepare(wrong_hash, unused))
    if list(unused.iterdir()):
        raise AssertionError("refused original kernel binding wrote output")
    extra = copy.deepcopy(document)
    extra["artifacts"]["foreign"] = document["artifacts"]["kernel"]
    refused("foreign_artifact_role", lambda: helper.verify_data(extra))
    promoted = copy.deepcopy(document)
    promoted["qualification"]["source_ready"] = True
    refused("native_source_ready_claim_is_refused", lambda: helper.verify_data(promoted))
    integer_flags = copy.deepcopy(document)
    integer_flags["qualification"]["source_ready"] = 0
    refused("integer_cannot_impersonate_false_qualification", lambda: helper.verify_data(integer_flags))
    arm = copy.deepcopy(document)
    arm["native_dialect"] = "crucible.gem5.arm-linux-native/1"
    refused("arm_dialect_never_falls_back", lambda: helper.verify_data(arm))
    configs = copy.deepcopy(document)
    configs["configuration"]["binding"]["sha256"] = "0" * 64
    refused("changed_configuration_census", lambda: helper.verify_data(configs))
    for name, route in (("parent_configuration_route", "../foreign"),
                        ("absolute_configuration_route", "/foreign")):
        refused(name, lambda route=route: helper.relative_name(route))
    try:
        helper.relative_name(".")
    except ValueError:
        pass
    else:
        raise AssertionError("dot root was accepted as a relative member route")

    partial = scratch / "copy-refusal"
    partial.mkdir(mode=0o700)
    descriptor = os.open(partial, os.O_RDONLY | os.O_DIRECTORY)
    try:
        row = dict(document["artifacts"]["initramfs"], sha256="0" * 64)
        refused("copy_hash_failure_retains_original_partial_file", lambda: helper.copy_file(row, descriptor, "initrd.img"))
        if not (partial / "initrd.img").is_file():
            raise AssertionError("partial output was discarded or rebound")
        try:
            helper.copy_file(document["artifacts"]["initramfs"], descriptor, "initrd.img")
        except FileExistsError:
            controls.append("partial_copy_never_overwrites_or_renews_name")
        else:
            raise AssertionError("partial output name was reused")
    finally:
        os.close(descriptor)
    if len(controls) != 15 or len(controls) != len(set(controls)):
        raise AssertionError("bundle controls differ from the exact expected roster")
    print(json.dumps({"passed": controls, "count": len(controls),
                      "scope": "Actual asset build/copy and data refusal only; no native executable, boot, capture, SourceReady or adoption"}, sort_keys=True))


if __name__ == "__main__":
    main()
