"""Run isolated actual mirror/pack and managed guard qualification.

The configuration selects reviewed source and source-built tools explicitly.
This driver never installs an operator configuration, signs review evidence,
or mutates cloud resources. Controlled effects, signed prerequisites, hosted
provider behavior and production admission retain separate evidence scopes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


RUNTIME_TEST = "mirror::hybrid::batch::tests::runtime::actual_worker_none_zstd_publication_and_restart"
GC_TEST = "mirror::hybrid::batch::tests::runtime::actual_worker_managed_gc_and_unknown_restart"
PURPOSE_TEST = "mirror::hybrid::batch::tests::runtime_purposes::independently_supplied_signed_purposes"
CASES = {
    "version_mismatch", "exact_delete_absence", "replay_preserves_new_writer",
    "unknown_delete_effect", "unknown_restart_refusal",
}
SOURCE_FILES = (
    "tests/fleet/_hub-mirror-pack-gc.py",
    "crates/aos-hub/src/mirror/hybrid/batch/tests.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime_gc.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime_purposes.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime_membership.rs",
    "pkgs/tools/aos-hub-mirror-runtime-e2e.mjs",
    "pkgs/tools/aos-hub-mirror-runtime-worker.mjs",
    "pkgs/tools/aos-hub-mirror-runtime-guard-state.mjs",
    "pkgs/tools/aos-hub-mirror-runtime-source.mjs",
    "pkgs/tools/aos-hub-mirror-r2-fixture.mjs",
)
OVERLAY_FILES = {
    "crates/aos-hub/src/mirror/hybrid/batch/tests.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime_gc.rs",
    "crates/aos-hub/src/mirror/hybrid/batch/tests/runtime_purposes.rs",
    "pkgs/tools/aos-hub-mirror-runtime-e2e.mjs",
    "pkgs/tools/aos-hub-mirror-runtime-worker.mjs",
    "pkgs/tools/aos-hub-mirror-runtime-guard-state.mjs",
    "pkgs/tools/aos-hub-mirror-runtime-guard-state.test.mjs",
    "tests/fleet/_hub-mirror-pack-gc.py",
    "tests/fleet/_hub-mirror-pack-gc-tests.py",
    "tests/fleet/hub-mirror-pack-gc.md",
}


def bounded_json(path, maximum=4 * 1024 * 1024):
    """Read one explicit regular evidence file within its control bound."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("evidence input is not a bounded regular file")
    return json.loads(path.read_bytes())


def digest(path):
    """Commit exact file bytes without retaining their content in the report."""
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_configuration(configuration):
    """Require explicit source/artifact commitments and source-built tool paths."""
    required = {
        "version", "sourceRoot", "sourceRevision", "sourceFiles", "workerDist",
        "workerWasmSha256", "workerShimSha256", "workerSourceSha256", "nix",
        "devShell", "node", "workerd", "targetDir", "evidenceDir",
        "sourceAssemblyManifest", "sourceAssemblyManifestSha256",
        "workerArtifactReceipt", "workerArtifactReceiptSha256",
    }
    require(set(configuration) in (required, required | {"purposeInput"}), "qualification configuration fields differ")
    require(configuration["version"] == 1, "qualification configuration version differs")
    for name in ("workerWasmSha256", "workerShimSha256", "workerSourceSha256"):
        require(re.fullmatch(r"[a-f0-9]{64}", configuration[name]) is not None, "artifact commitment invalid")
    require(re.fullmatch(r"[a-f0-9]{40}", configuration["sourceRevision"]) is not None, "source revision invalid")
    for name in ("nix", "devShell", "node", "workerd"):
        path = Path(configuration[name])
        require(path.is_absolute() and str(path).startswith("/nix/store/") and path.exists(), "source-built tool is unavailable")
    source = Path(configuration["sourceRoot"])
    require(source.is_absolute() and (source / "AGENTS.md").is_file(), "explicit runtime source unavailable")
    require(set(configuration["sourceFiles"]) == set(SOURCE_FILES), "runtime source manifest incomplete")
    for name, expected in configuration["sourceFiles"].items():
        require(re.fullmatch(r"[a-f0-9]{64}", expected) is not None and digest(source / name) == expected, "runtime source changed after review")
    require(digest(configuration["sourceAssemblyManifest"]) == configuration["sourceAssemblyManifestSha256"], "source assembly proof changed")
    assembly = bounded_json(configuration["sourceAssemblyManifest"], 16 * 1024 * 1024)
    require(assembly["version"] == 1 and assembly["baseCommit"] == configuration["sourceRevision"]
            and set(assembly["overlayPostimages"]) == OVERLAY_FILES, "source assembly scope differs")
    for name, expected in assembly["overlayPostimages"].items():
        require(digest(source / name) == expected, "fixture overlay changed after review")
    crate_files = {str(path.relative_to(source)) for path in (source / "crates").rglob("*")
                   if path.is_file() and not path.is_symlink()}
    require(crate_files == set(assembly["unchangedCrateFiles"]) | {name for name in OVERLAY_FILES if name.startswith("crates/")}, "production crate file set changed")
    for name, expected in assembly["unchangedCrateFiles"].items():
        require(digest(source / name) == expected and digest(Path(assembly["immutableBase"]) / name) == expected,
                "production source differs from immutable runtime base")
    for name, expected in assembly["compiledContractFilesExact"].items():
        require(digest(source / name) == expected and digest(Path(assembly["compiledWorkerSource"]) / name) == expected,
                "Native/Worker compiled contract differs")
    require(digest(configuration["workerArtifactReceipt"]) == configuration["workerArtifactReceiptSha256"], "Worker artifact receipt changed")
    receipt = bounded_json(configuration["workerArtifactReceipt"])
    require(receipt["commit"] == assembly["baseCommit"]
            and receipt["fullImmutableSource"] == assembly["immutableBase"]
            and receipt["workerSource"] == assembly["compiledWorkerSource"]
            and receipt["compiledSourceDigest"] == configuration["workerSourceSha256"], "historical runtime identity differs")
    output = receipt["outputs"]["doE2e"]
    require(output["out"] == configuration["workerDist"]
            and output["files"]["index.wasm"]["sha256"] == configuration["workerWasmSha256"]
            and output["files"]["shim.mjs"]["sha256"] == configuration["workerShimSha256"], "compiled receipt/artifact join differs")
    dist = Path(configuration["workerDist"])
    require(dist.is_absolute(), "compiled Worker path must be absolute")
    require(digest(dist / "index.wasm") == configuration["workerWasmSha256"], "compiled Worker bytes changed")
    require(digest(dist / "shim.mjs") == configuration["workerShimSha256"], "compiled Worker shim changed")
    for name in ("targetDir", "evidenceDir"):
        require(Path(configuration[name]).is_absolute(), "retained runtime path must be absolute")
    return configuration


def delete_count(snapshot):
    rows = snapshot["provider"]["operations"]
    require(len({row["action"] for row in rows}) == len(rows), "provider action observation duplicated")
    return next((row["requests"] for row in rows if row["action"] == "delete"), 0)


def object_at(snapshot, key):
    rows = [row for row in snapshot["provider"]["objects"] if row["object_key"] == key]
    require(len(rows) <= 1, "provider incarnation observation duplicated")
    return rows[0] if rows else None


def assess_gc(report):
    """Require actual closed custody, positive effects and unresolved refusal facts."""
    require(report["version"] == 1 and report["execution"] == "controlled", "GC evidence scope differs")
    placement, binding, writer = report["placement"], report["binding"], report["writer"]
    require(binding["kind"] == "deployment_r2" and placement["bindingId"] == binding["id"], "GC evidence is not selected managed storage")
    require(writer["reconciliationState"] == "ready"
            and writer["desiredPlacementId"] == writer["observedPlacementId"] == placement["id"]
            and writer["desiredWriteSpecVersion"] == writer["observedWriteSpecVersion"] == placement["writeSpecVersion"]
            and writer["desiredBindingWriteRevision"] == writer["observedBindingWriteRevision"] == report["currentWriteRevision"]
            and writer["desiredGeneration"] == writer["observedGeneration"], "GC writer generation is not settled")
    key = report["physicalKey"]
    require(key.startswith(placement["prefix"] + "/.aos-internal/conditional-delete-probes/"), "GC physical scope changed")
    original = report["original"]
    require(original["key"] == key and bool(original["provider_version"]), "original GC incarnation absent")
    rows = report["cases"]
    require(len(rows) == len(CASES) and {row["case"] for row in rows} == CASES, "closed GC cases incomplete")
    cases = {row["case"]: row for row in rows}
    for row in rows:
        require(row["before"]["guard"]["mirrorOwnerJobId"] is None, "foreign mirror original owns GC key")
        require(row["before"]["guard"]["pendingMutation"] is None, "GC writer outcome unknown")

    mismatch = cases["version_mismatch"]
    require(delete_count(mismatch["before"]) == delete_count(mismatch["after"])
            and object_at(mismatch["after"], key)["version"] == original["provider_version"], "mismatch deleted or changed original incarnation")
    exact = cases["exact_delete_absence"]
    receipt = exact["after"]["guard"]["deleteReceipt"]
    require(delete_count(exact["after"]) == delete_count(exact["before"]) + 1
            and object_at(exact["after"], key) is None
            and exact["after"]["guard"]["pendingDelete"] is None
            and receipt["outcome"]["kind"] == "deleted"
            and receipt["claim"]["expected_etag"] == original["etag"]
            and receipt["claim"]["expected_size"] == original["size"]
            and receipt["claim"]["expected_provider_version"] == original["provider_version"], "absence lacks exact positive delete receipt")
    replay = cases["replay_preserves_new_writer"]
    replacement = replay["replacement"]
    require(replacement["key"] == key and replacement["provider_version"] != original["provider_version"]
            and delete_count(replay["after"]) == delete_count(replay["before"])
            and object_at(replay["after"], key)["version"] == replacement["provider_version"]
            and replay["after"]["guard"]["deleteReceipt"] == receipt, "old claim damaged new writer or changed original receipt")
    unknown = cases["unknown_delete_effect"]
    pending = unknown["after"]["guard"]["pendingDelete"]
    require(delete_count(unknown["after"]) == delete_count(unknown["before"]) + 1
            and object_at(unknown["after"], key) is None
            and unknown["after"]["guard"]["deleteReceipt"] is None
            and pending["expected_provider_version"] == replacement["provider_version"], "unknown delete effect or custody observation missing")
    restart = cases["unknown_restart_refusal"]
    require(restart["before"] == restart["after"]
            and restart["after"]["guard"]["pendingDelete"] == pending
            and object_at(restart["after"], key) is None, "restart cleared or replayed unknown deletion")

    require(len(report["controls"]) > 0, "actual signed Native controls missing")
    failures = []
    require(len({exchange["plan"]["plan_id"] for exchange in report["controls"]}) == len(report["controls"]), "Native request identity reused for distinct attempts")
    for exchange in report["controls"]:
        plan = exchange["plan"]
        require(plan["deployment_id"] == report["deploymentId"]
                and plan["placement_id"] == placement["id"]
                and plan["placement_resource_version"] == placement["resourceVersion"]
                and plan["binding_id"] == binding["id"]
                and plan["binding_resource_version"] == binding["resourceVersion"]
                and plan["placement_prefix"] == placement["prefix"], "GC control changed frozen physical scope")
        if exchange["result"] is not None:
            require(exchange["result"]["plan_id"] == plan["plan_id"]
                    and exchange["result"]["source_bytes"] == 0, "GC reply does not join original control")
        else:
            require(exchange["outcome"] == "refused_or_unknown", "unknown control was promoted to positive")
            failures.append(plan["operation"])
    path = key[len(placement["prefix"]) + 1:]
    require([operation["kind"] for operation in failures] == ["delete_if_matches", "delete_if_matches", "head", "put_probe"]
            and all(operation["path"] == path for operation in failures)
            and failures[0] == failures[1]
            and failures[0]["expected_provider_version"] == replacement["provider_version"],
            "unknown delete, exact replay, HEAD and new writer refusals incomplete")
    return {
        "execution": "controlled", "managedPhysicalGuard": "passed", "closedCases": sorted(CASES),
        "unknownDelete": "blocked", "hostedConditionalDelete": "unknown", "sqlGcAccounting": "unknown",
        "nativeExecuteTransport": "unknown",
    }


def run(configuration):
    """Execute the actual connected runtime and retain a separately scoped report."""
    configuration = checked_configuration(configuration)
    root = Path(configuration["evidenceDir"])
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment.update({
        "AOS_MIRROR_RUNTIME_EVIDENCE": str(root),
        "AOS_MIRROR_RUNTIME_SOURCE_SHA256": configuration["workerSourceSha256"],
        "AOS_MIRROR_RUNTIME_DIST": configuration["workerDist"],
        "AOS_MIRROR_RUNTIME_WORKERD": configuration["workerd"],
        "AOS_MIRROR_RUNTIME_NODE": configuration["node"],
    })
    environment.pop("AOS_MIRROR_PURPOSE_INPUT", None)
    if configuration.get("purposeInput"):
        environment["AOS_MIRROR_PURPOSE_INPUT"] = configuration["purposeInput"]
    command = [configuration["nix"], "develop", configuration["devShell"], "-c", "cargo", "test",
               "--manifest-path", str(Path(configuration["sourceRoot"]) / "crates/Cargo.toml"),
               "-p", "aos-hub", "--features", "test-support", "--lib", "--target-dir", configuration["targetDir"]]
    invoked = []
    for name, test in (("purposes", PURPOSE_TEST), ("managed-gc", GC_TEST), ("mirror-runtime", RUNTIME_TEST)):
        case_environment = environment.copy()
        if name != "purposes":
            case_root = root / name
            case_root.mkdir(mode=0o700)
            case_environment["AOS_MIRROR_RUNTIME_EVIDENCE"] = str(case_root)
        arguments = command + [test, "--", "--ignored", "--exact", "--nocapture"]
        with (root / f"{name}.log").open("xb") as log:
            result = subprocess.run(arguments, cwd=configuration["sourceRoot"], env=case_environment,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=3600, check=False)
        invoked.append({"case": name, "arguments": arguments, "exitCode": result.returncode})
        (root / "invocations.json").write_text(json.dumps(invoked, indent=2) + "\n")
        if name == "purposes":
            require(result.returncode == 0, "purpose verification refused; original log retained")
    outcomes = {invocation["case"]: invocation["exitCode"] for invocation in invoked}
    gc = {"execution": "controlled", "managedPhysicalGuard": "failed", "unknownDelete": "unknown"}
    if outcomes["managed-gc"] == 0:
        require((root / "managed-gc/GC-PASS").is_file(), "actual managed guard completion missing")
        gc = assess_gc(bounded_json(root / "managed-gc/gc-observations.json"))
    mirror = "failed"
    if outcomes["mirror-runtime"] == 0:
        require((root / "mirror-runtime/PASS").is_file(), "actual connected mirror completion missing")
        mirror = "passed"
    purposes = bounded_json(root / "purpose-observations.json")
    require(purposes["productionAdmission"] == "unknown", "prerequisite validation became unobserved production admission")
    require(purposes["purposeChain"] in {"verified", "unknown"}, "purpose chain refused")
    evidence = ("purpose-observations.json", "invocations.json", "purposes.log", "managed-gc.log", "mirror-runtime.log",
                "managed-gc/controls.json", "managed-gc/gc-observations.json", "managed-gc/GC-PASS",
                "mirror-runtime/controls.json", "mirror-runtime/provider-observations.json",
                "mirror-runtime/membership-observations.json", "mirror-runtime/unknown-observations.json", "mirror-runtime/PASS")
    report = {
        "version": 1, "execution": "controlled", "sourceRevision": configuration["sourceRevision"],
        "sourceFiles": configuration["sourceFiles"],
        "sourceAssemblyManifestSha256": configuration["sourceAssemblyManifestSha256"],
        "workerArtifactReceiptSha256": configuration["workerArtifactReceiptSha256"],
        "workerSourceSha256": configuration["workerSourceSha256"],
        "workerWasmSha256": configuration["workerWasmSha256"], "workerShimSha256": configuration["workerShimSha256"],
        "tools": {name: configuration[name] for name in ("nix", "devShell", "node", "workerd")},
        "rawEvidence": {name: digest(root / name) for name in evidence if (root / name).is_file()},
        "managedGc": gc, "controlledMirrorPack": mirror,
        "purposeChain": purposes["purposeChain"], "productionAdmission": "unknown",
        "hostedR2ConditionalDelete": "unknown", "externalConditionalDelete": "unknown",
        "wholeWorkerMemory": "unknown", "wholeWorkerCpu": "unknown",
        "scope": "actual controlled Native/Worker/provider flow; independent purpose prerequisites never substitute for production dispatch evidence",
    }
    (root / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    require(all(outcome == 0 for outcome in outcomes.values()),
            "runtime qualification failed; independently scoped report and original effects retained")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=Path)
    arguments = parser.parse_args()
    report = run(bounded_json(arguments.configuration, 64 * 1024))
    print(json.dumps({"controlledManagedGuard": report["managedGc"]["managedPhysicalGuard"],
                      "purposeChain": report["purposeChain"], "productionAdmission": "unknown"}))


if __name__ == "__main__":
    main()
