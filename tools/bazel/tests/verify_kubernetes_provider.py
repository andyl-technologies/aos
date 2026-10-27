"""Qualifies installed Kubernetes handlers without claiming live cluster effects."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from installed_package import compare_installed, inventory, runtime_closures
from reconstruct_compiler_inputs import reconstruct
from verify_cache import execution_events
from verify_compiler_options import compiler_options
from verify_pilot import verify as verify_tests
from verify_protocol import compare_doctests, compare_features


COMMAND = "aos-kubernetes-provider"
PACKAGE = "aos-activation-kubernetes"
PREFIX = "//crates/activation/" + PACKAGE + ":"
PACKAGE_PATHS = {
    PACKAGE: "crates/activation/" + PACKAGE,
    "aos-activation": "crates/activation/aos-activation",
    "aos-core": "crates/core/aos-core",
    "aos-module-format": "crates/modules/aos-module-format",
    "aos-artifact-evidence": "crates/artifacts/aos-artifact-evidence",
}
MAX_DOCUMENT_BYTES = 256 * 1024


def cargo_tests(oracle):
    """Requires both independently compiled debug test executables."""
    names = {PACKAGE.replace("-", "_"): PREFIX + "unit", COMMAND: PREFIX + "bin_" + COMMAND}
    binaries = {}
    for line in (oracle / "cargo-messages.jsonl").read_text().splitlines():
        event = json.loads(line)
        name = event.get("target", {}).get("name")
        if (event.get("reason") != "compiler-artifact" or name not in names
                or not event.get("profile", {}).get("test") or not event.get("executable")):
            continue
        label = names[name]
        if label in binaries:
            raise ValueError("duplicate Kubernetes Cargo test target")
        binaries[label] = Path(event["executable"])
    if set(binaries) != set(names.values()) or any(not path.is_file() for path in binaries.values()):
        raise ValueError("Kubernetes Cargo oracle omitted a debug test executable")
    return binaries


def production_profiles(build, messages):
    """Compares every first-party production unit with Cargo's release profile."""
    cargo = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if (event.get("reason") != "compiler-artifact"
                or Path(event["manifest_path"]).parent.name not in PACKAGE_PATHS):
            continue
        name = event["target"]["name"].replace("-", "_")
        if name in cargo:
            raise ValueError("duplicate Kubernetes production Cargo unit")
        cargo[name] = event["profile"]
    evidence = build / "evidence"
    actions = reconstruct(json.loads((evidence / "actions.json").read_text()), execution_events(build),
                          json.loads((evidence / "compiler-inputs.json").read_text()))["actions"]
    result = {}
    for action in actions:
        if not action["target_label"].startswith("//crates/"):
            continue
        arguments = action["arguments"]
        names = [arguments[index + 1] if value == "--crate-name" else value.split("=", 1)[1]
                 for index, value in enumerate(arguments)
                 if value == "--crate-name" or value.startswith("--crate-name=")]
        if len(names) != 1 or names[0] not in cargo or names[0] in result:
            raise ValueError("Kubernetes production unit is missing or ambiguous")
        before = cargo[names[0]]
        after = compiler_options(arguments)["effective_scalar_codegen"]
        if (before["opt_level"] != "3" or before["debuginfo"] or before["debug_assertions"]
                or before["overflow_checks"] or after.get("opt-level") != "3"
                or after.get("debuginfo", "0") != "0"
                or after.get("debug-assertions") not in {"no", "off", "false"}
                or after.get("overflow-checks") not in {"no", "off", "false"}):
            raise ValueError("Kubernetes production compiler profile differs")
        result[names[0]] = {"cargo": before, "bazel": after}
    if set(result) != set(cargo) or len(result) != len(PACKAGE_PATHS) + 1:
        raise ValueError("Kubernetes production profiles omitted a first-party unit")
    return result


def command_parity(packages):
    """Compares argument validation, malformed envelopes, and the byte boundary."""
    cases = [([], b""), (["--help"], b""), (["invalid"], b""), (["observe", "extra"], b""),
             *[([operation], data) for operation in ["apply", "remove", "observe"] for data in [b"", b"{}"]],
             (["observe"], b"{}" + b" " * (MAX_DOCUMENT_BYTES - 2)),
             (["observe"], b"x" * (MAX_DOCUMENT_BYTES + 1))]
    records = []
    for arguments, data in cases:
        results = [subprocess.run([str(Path(packages[driver]["out"]) / "bin" / COMMAND), *arguments],
                                  input=data, capture_output=True, timeout=30)
                   for driver in ["ordinary", "bazel"]]
        before, after = [(item.returncode, item.stdout, item.stderr) for item in results]
        if before != after or before[0] != 1 or before[1] or not before[2].startswith(COMMAND.encode() + b":"):
            raise ValueError("Kubernetes argument or input rejection differs")
        if (len(data) > MAX_DOCUMENT_BYTES) != (b"module invocation exceeds its byte bound" in before[2]):
            raise ValueError("Kubernetes invocation boundary differs")
        records.append({"arguments": arguments, "stdin_bytes": len(data), "status": before[0],
                        "stdin_sha256": hashlib.sha256(data).hexdigest(), "stderr_sha256": hashlib.sha256(before[2]).hexdigest()})
    return records


def invocation(kubeconfig, action, timeout):
    """Builds a read-only object-set observation with no desired objects."""
    return {
        "id": "bazel-kubernetes-handler-qualification", "revision": "first", "action": action, "previous": None,
        "input": {"kubeconfig": str(kubeconfig), "object_sets": {}},
        "effect": {
            "owner": "k3s", "identity": ["qualification", "kubernetes", "objects", "fixture"],
            "input": {}, "inputs": {}, "input_type": {"kind": "submodule", "open": False, "fields": {}},
            "after": [], "results": {}, "dependencies": [], "revision": "first", "lifetime": "instance",
            "timeout_ms": timeout, "handler": {"kind": "process",
                "artifact": "/nix/store/00000000000000000000000000000000-handler",
                "executable": "/nix/store/00000000000000000000000000000000-handler/bin/handler"},
        },
    }


def sibling_protocol(packages, bash):
    """Exercises sibling admission and read-only protocol fixtures, not a cluster."""
    with tempfile.TemporaryDirectory(prefix="aos-kubernetes-protocol-") as temporary:
        root = Path(temporary)
        kubeconfig = root / "kubeconfig"
        kubeconfig.write_text("qualification fixture\n")
        trace = root / "arguments.json"
        sibling = root / "k3s-fixture"
        sibling.write_text("#!" + str(bash) + "\n"
                           "test \"${AOS_KUBE_QUAL_SENTINEL+x}\" != x || exit 19\n"
                           "printf '%s\\n' \"$@\" > " + shlex.quote(str(trace)) + "\n"
                           "printf '{\"metadata\":{\"uid\":\"fixture-cluster\"}}\\n'\n")
        sibling.chmod(0o755)
        results = {}
        for driver in ["ordinary", "bazel"]:
            directory = root / driver / "libexec"
            directory.mkdir(parents=True)
            program = directory / COMMAND
            shutil.copy2(Path(packages[driver]["out"]) / "bin" / COMMAND, program)
            entry = directory.parent / "bin" / COMMAND
            entry.parent.mkdir()
            entry.symlink_to("../libexec/" + COMMAND)
            records = []
            for mode in ["absent", "regular", "symlink"]:
                selected = directory / "k3s"
                if mode == "regular":
                    shutil.copy2(sibling, selected)
                elif mode == "symlink":
                    selected.unlink()
                    selected.symlink_to(sibling)
                for action in ["apply", "remove"]:
                    for timeout in [0, 1000, 50000]:
                        trace.unlink(missing_ok=True)
                        data = json.dumps(invocation(kubeconfig, action, timeout)).encode()
                        result = subprocess.run([str(entry), "observe"], input=data, capture_output=True,
                                                timeout=30, env={**os.environ, "AOS_KUBE_QUAL_SENTINEL": "must-not-reach-k3s"})
                        if mode == "symlink":
                            expected = {"status": "retry-safe" if action == "apply" else "absent"}
                            arguments = ["kubectl", "--kubeconfig", str(kubeconfig),
                                         "--request-timeout=" + str(max(1, min(timeout, 30000))) + "ms",
                                         "get", "namespace", "kube-system", "--output=json"]
                            if result.returncode or result.stderr or json.loads(result.stdout) != expected:
                                raise ValueError("Kubernetes sibling observation differs")
                            if trace.read_text().splitlines() != arguments:
                                raise ValueError("Kubernetes helper arguments or timeout clamping differ")
                            output = expected
                        else:
                            if result.returncode != 1 or result.stdout or trace.exists():
                                raise ValueError("Kubernetes admitted an unauthenticated sibling")
                            if mode == "regular" and b"not an authenticated sibling link" not in result.stderr:
                                raise ValueError("Kubernetes regular sibling rejection differs")
                            output = {"stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
                        records.append({"sibling": mode, "action": action, "timeout_ms": timeout,
                                        "status": result.returncode, "output": output})
            results[driver] = records
        if results["ordinary"] != results["bazel"]:
            raise ValueError("Kubernetes sibling protocol differs across builders")
        return {"drivers": results, "live_cluster_qualified": False,
                "scope": "Copied installed handlers with the role package's bin-to-libexec symlink layout, sibling-link admission, isolated child environment, read-only namespace fixture and timeout clamping."}


def verify(options):
    """Requires installed, runtime, profile, test and userspace behavior parity."""
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"} or any(set(value) != {"out"} for value in packages.values()):
        raise ValueError("Kubernetes qualification requires both installed packages")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    if closures["changes"] != {"out": {"added": [], "removed": []}}:
        raise ValueError("Kubernetes runtime closure differs")
    installed = {driver: inventory(value, options.readelf, options.loader) for driver, value in packages.items()}
    search_changes = compare_installed(installed["ordinary"], installed["bazel"])
    actions = {}
    for role, build in [("production", options.build), ("debug_tests", options.tests)]:
        events = execution_events(build)
        if not events or any(event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"] for event in events):
            raise ValueError("Kubernetes proof requires fresh Linux sandbox execution")
        actions[role] = len(events)
    manifests = [str(path) for path in options.workspace.rglob("Cargo.*") if path.name in {"Cargo.toml", "Cargo.lock"}]
    if manifests:
        raise ValueError("Kubernetes source selection retains first-party Cargo metadata")
    return {
        "schema_version": 1, "packages": packages, "installed": installed, "runtime_closures": closures,
        "library_search_changes": search_changes, "fresh_linux_sandbox_actions": actions,
        "features": {
            "production": compare_features(options.build / "inventory.json", Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl", PACKAGE_PATHS, required_packages=PACKAGE_PATHS),
            "debug_tests": compare_features(options.tests / "inventory.json", options.oracle / "cargo-messages.jsonl", PACKAGE_PATHS, required_packages=PACKAGE_PATHS),
        },
        "production_profiles": production_profiles(options.build, Path(packages["ordinary"]["out"]) / "nix-support/cargo-build-messages.jsonl"),
        "test_parity": verify_tests(options.tests / "evidence/tests", cargo_tests(options.oracle), allow_empty=[PREFIX + "bin_" + COMMAND]),
        "doctest_parity": compare_doctests(options.tests / "evidence/tests", options.oracle / "cargo-tests.log", {PACKAGE: PACKAGE_PATHS[PACKAGE]}),
        "cli_cases": command_parity(packages), "sibling_protocol": sibling_protocol(packages, options.bash),
        "live_cluster_qualified": False, "production_default_cutover": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["packages", "build", "tests", "oracle", "workspace", "readelf", "loader", "bash", "closure-attributes", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")
