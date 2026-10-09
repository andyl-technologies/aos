# SPDX-License-Identifier: MIT
"""Seals source-owned closed-profile metadata after authentic native witnesses.

The caller is the immutable package recipe, not a scenario/operator. This
emitter validates the actual independent process-closure receipts and two fresh
continuations before binding installed artifacts to the fixed profile. Typed
modeled-state diagnostics remain explicitly incomplete.
"""

import hashlib
import json
from pathlib import Path
import shutil
import sys


POLICY = "freestanding-o3-classic-ddr3-v1"
MAX_JSON = 16 * 1024 * 1024


def read_json(path):
    data = Path(path).read_bytes()
    if len(data) > MAX_JSON:
        raise ValueError("profile witness exceeds bounded metadata size")
    return json.loads(data)


def artifact(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("profile artifact must be an installed regular file: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(),
            "length": str(path.stat().st_size)}


def require(value, message):
    if not value:
        raise ValueError(message)


def witness(directory, isa, native, installed):
    root = Path(directory)
    result = read_json(root / "result.json")
    closure = read_json(root / "closure-result.json")
    require(result["guest_isa"] == isa and closure["guest_isa"] == isa,
            "native and closure ISA identities differ")
    require(closure["schema"] == "crucible.gem5.process-closure.v1"
            and closure["profile"] == POLICY and closure["complete"] is True
            and closure["omissions"] == [], "opaque native capture is incomplete")
    require(closure["modeled_diagnostics_complete"] is False
            and result["exact_profile_qualified"] is False,
            "mechanism evidence must not promote typed diagnostic coverage")
    require(result["source_dead_before_restore"] is True
            and not (root / "origin").exists(),
            "original source or resource root survived reconstruction")
    require(result["actual_checksum_matches_native"] is True,
            "actual guest output differs from native checksum")
    require(result["original_native_identity"]["original_code_sha256"]
            == native["sha256"], "witness used another native binary")
    for flag in ("group_reclaimed", "full_position_stop_before_reaction",
                 "full_position_single_callback_at_budget_ceiling",
                 "original_request_retry_unchanged"):
        require(result.get(flag) is True, "native witness lacks actual " + flag)
    branches = result["private_concurrent_reconstructions"]
    require(len(branches) == 2 and {item["branch"] for item in branches}
            == {"child-a", "child-b"}, "two independent children are required")
    for branch in branches:
        require(branch["fresh_control"] is True and branch["unchanged_cut"] is True
                and branch.get("group_reclaimed") is True
                and branch.get("fresh_capture_closure") is True
                and branch["image_sha256"] == closure["image_sha256"]
                and branch["native_identity"]["original_code_sha256"] == native["sha256"],
                "fresh reconstruction did not preserve authentic original cut")
    require((root / "child-a/guest.elf").stat().st_ino
            != (root / "child-b/guest.elf").stat().st_ino,
            "reconstructed private guest resources alias")
    cut = result["cut"]
    require(cut["ordinal"] == "5000" and cut["inventory"]["complete"] is False,
            "witness cut or typed coverage differs")
    publications = [publication for stop in result["suffix"]
                    for publication in stop["publications"]]
    require(publications and sum(len(item["payload"]) for item in publications) == 8,
            "actual native publication birth evidence is absent")
    for item in publications:
        require(item["guest_fd"] == 1 and int(item["event_ordinal"]) > 5000
                and int(item["tick_ordinal"]) > 0,
                "publication is not the measured guest stdout native birth")

    # Bind every default and connection in the actual realized native model;
    # the compact typed model description alone does not replace config.ini.
    destination = installed / "models" / f"{isa}.ini"
    shutil.copyfile(root / "preserved-files/output/config.ini", destination)
    return {
        "guest_isa": isa, "native_artifact_sha256": native["sha256"],
        "opaque_capture_complete": True, "modeled_diagnostics_complete": False,
        "unchanged_capture_cut": True, "source_dead_before_restore": True,
        "original_owned_root_absent": True, "private_concurrent_reconstructions": "2",
        "full_position_exclusive_stop": True, "actual_native_publication_birth": True,
        "original_receipt_retry": True, "group_reclaimed": True,
        "fresh_reconstruction_capture_closure": True,
        "full_position_single_callback_at_budget_ceiling": True,
        "output_matches_native_checksum": True,
        "image_sha256": closure["image_sha256"], "image_length": closure["image_bytes"],
        "closure_receipt_sha256": artifact(root / "closure-result.json")["sha256"],
        "boundary_sha256": closure["boundary_sha256"],
        "host_abi": closure["host_abi"], "realized_configuration": artifact(destination),
    }


def main():
    specification_path, output, x86_witness, arm_witness = sys.argv[1:]
    specification = read_json(specification_path)
    root = Path(output)
    installed = root / "share/crucible/gem5"
    artifacts = {name: artifact(path.replace("@out@", str(root)))
                 for name, path in specification["artifacts"].items()}
    source = read_json(installed / "sources/gem5-source-manifest.json")
    require(source["schema"] == "crucible.gem5.source-foundation.v1"
            and source["revision"] == "f5c5a6e390f55dd5984977815bf9d0bd05da6945"
            and source["buildConfiguration"] == "ALL", "unknown native source foundation")
    require(source["recipeSha256"] == artifact(installed / "sources/gem5.nix")["sha256"],
            "native recipe differs from source manifest")
    for patch in source["patches"]:
        require(artifact(installed / "sources/gem5-patches" / patch["file"])["sha256"]
                == patch["sha256"], "native patch closure differs from measured binary")
    witnesses = {
        "x86_64": witness(x86_witness, "x86_64", artifacts["native_executable"], installed),
        "aarch64": witness(arm_witness, "aarch64", artifacts["native_executable"], installed),
    }
    require(witnesses["x86_64"]["host_abi"] == witnesses["aarch64"]["host_abi"],
            "guest profiles were tested on different native host ABIs")
    guests = {isa: {"artifact": artifact(installed / "guests" / f"{isa}.elf"),
                    "name": "crucible-o3-workload", "syscalls": ["write_fd1", "exit"]}
              for isa in ("x86_64", "aarch64")}
    manifest = {
        "schema": "crucible.gem5.installed-closed-profile.v1", "edition": 1,
        "policy_id": POLICY, "policy_version": "1", "artifacts": artifacts,
        "guests": guests, "source": source,
        "source_artifacts": {name: artifact(installed / "sources" / name)
                             for name in ("gem5-upstream.tar.gz", "dmtcp-upstream.tar.gz", "dmtcp.nix")},
        "dmtcp_patches": [{"file": path.name, **artifact(path)} for path in sorted(
            (installed / "sources/dmtcp-patches").glob("*.patch"))],
        "clock": {"native_tick_ps": "1",
                  "mapping_id": "gem5/even-reaction-odd-publication-v1",
                  "maximum_microsteps": "1000000"},
        "model": {"cpu": "O3", "cpu_clock": "1GHz", "memory_bytes": "536870912",
                  "cache_hierarchy": "classic-two-level", "memory_controller": "DDR3_1600_8x8",
                  "configuration_scope": "exact-owned-controller-and-model-with-fixed-known-guest",
                  "full_system": False, "ingress": [], "host_derived_guest_inputs": False,
                  "native_listeners": False},
        "witnesses": witnesses, "modeled_diagnostics_complete": False,
        "full_system_device_parity_qualified": False,
    }
    (installed / "closed-profile.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
