"""Builds and runs the actual configured QEMU cached-writer registrations.

The package owns source extraction and configuration. Meson supplies each real
command; Ninja builds its eleven native binaries. Exact child dispositions are
checked in addition to the registered wrapper's result. Only evidence leaves
the sandbox, including hashes of objects and binaries rather than their bytes.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import shlex
import signal
import sys

SUITE = "crucible-cached-writer"
PREFIX = "test-crucible-cached-writer"
BUILD_SECONDS = 600
TEST_SECONDS = 60
REGISTERED_SECONDS = 15
ADDRESS_SPACE_BYTES = 6 * 1024**3

# The immediate native registration is a fixed contract. Changing a disposition
# requires reviewing the real Meson and wrapper changes together with this gate.
SCENARIOS = (
    "cpu-cached", "enrolled-ordinary", "io-nested", "scope-nested",
    "scope-promotion", "cpu-promotion", "foreign-close", "foreign-admission",
    "return-marker", "plain-return-first", "alias", "copied-fork",
    "copied-leave", "copied-rebind", "copied-status", "copied-readonly",
    "execution-return", "fresh-child-interval", "atfork-failure",
    "cache-suspended", "no-record", "layout", "self-cpu", "self-io", "upgrade",
)
OMISSIONS = (
    ("self-cpu", "omitted-deadlock", ""),
    ("self-cpu", "omitted-deadlock", ""),
    ("upgrade", "omitted-deadlock", ""),
    ("cpu-promotion", "assertion", "!ram_writer_cpus && ram_writer_io == 1"),
    ("scope-promotion", "assertion",
     "ram_writer_io == 1 && !qemu_hot_fork_current_thread->ram_writer_nested_io_depth"),
    ("copied-rebind", "assertion", "WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT"),
    ("io-nested", "assertion", "!qemu_hot_fork_current_thread->ram_writer_nested_io_depth"),
    ("copied-status", "assertion", "WIFEXITED(status) && !WEXITSTATUS(status)"),
    ("copied-readonly", "assertion", "WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT"),
    ("return-marker", "assertion", "writer_locks == before"),
)


def expected_tests():
    """Describes the reviewed 25 scenarios and ten distinct compiled omissions."""
    expected = {}
    for scenario in SCENARIOS:
        outcome = "deadlock" if scenario in ("self-cpu", "self-io", "upgrade") else "success"
        expected[f"{PREFIX}-{scenario}"] = (PREFIX, [scenario, outcome])
    for index, arguments in enumerate(OMISSIONS):
        name = f"{PREFIX}-omission-{index}"
        expected[name] = (name, list(arguments))
    return expected


def load_helpers(path):
    """Reuses the unchanged Source gate's bounded process and evidence helpers."""
    spec = importlib.util.spec_from_file_location("qemu_unit_evidence", path)
    if spec is None or spec.loader is None:
        raise ValueError("native unit evidence helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def registered_tests(source, build):
    """Requires the complete suite and genuine configured Python/native targets."""
    tests = json.loads((build / "meson-info/intro-tests.json").read_text())
    targets = json.loads((build / "meson-info/intro-targets.json").read_text())
    python_rows = [
        line.removeprefix("PYTHON=")
        for line in (build / "config-host.mak").read_text().splitlines()
        if line.startswith("PYTHON=")
    ]
    if len(python_rows) != 1 or not shlex.split(python_rows[0]):
        raise ValueError("configured Python identity is missing or ambiguous")
    python = shlex.split(python_rows[0])
    wrapper = source / "tests/unit/run-crucible-cached-writer.py"
    expected = expected_tests()
    selected = [
        test for test in tests
        if any(suite.split(":")[-1] == SUITE for suite in test.get("suite", []))
        or test.get("name", "").startswith(PREFIX)
    ]
    names = [test.get("name") for test in selected]
    if len(names) != len(expected) or set(names) != set(expected):
        raise ValueError("cached-writer registrations are missing, duplicated or unexpected")

    outputs = {}
    for name, (binary, arguments) in expected.items():
        matches = [test for test in selected if test["name"] == name]
        if len(matches) != 1:
            raise ValueError("cached-writer registration is ambiguous")
        test = matches[0]
        command = test.get("cmd", [])
        executable = build / "tests/unit" / binary
        # Meson serializes File/BuildTarget arguments relative to the test's
        # build cwd. Preserve that real argv while corroborating its identities.
        prefixes = (python[:1], python)
        valid_command = False
        for prefix in prefixes:
            offset = len(prefix)
            if (
                len(command) == offset + 2 + len(arguments)
                and Path(command[0]).is_absolute()
                and Path(command[0]).resolve() == Path(prefix[0]).resolve()
                and command[1:offset] == prefix[1:]
                and (build / command[offset]).resolve() == wrapper.resolve()
                and (build / command[offset + 1]).resolve() == executable.resolve()
                and command[offset + 2:] == arguments
            ):
                valid_command = True
        if not valid_command:
            raise ValueError(f"{name}: registered command or expected disposition differs: {command!r}")
        if (
            test.get("timeout") != REGISTERED_SECONDS
            or test.get("protocol") != "exitcode"
            or test.get("is_parallel") is not True
            # Meson introspection omits should_fail. This gate always requires
            # wrapper success and independently validates the child outcome.
            or test.get("should_fail", False) is not False
            or not any(s.split(":")[-1] == SUITE for s in test.get("suite", []))
            or test.get("env", {}) != {}
            or test.get("extra_paths", [])
            or test.get("workdir") not in (None, str(build))
        ):
            raise ValueError(f"{name}: registered environment, protocol or timeout differs: {test!r}")
        matching_targets = [
            target for target in targets
            if target.get("name") == binary and target.get("type") == "executable"
            and target.get("filename") == [str(executable)]
        ]
        if len(matching_targets) != 1 or matching_targets[0].get("installed") is not False:
            raise ValueError(f"{name}: genuine noninstalled native target is missing")
        outputs[binary] = str(executable.relative_to(build))
    if len(outputs) != 11:
        raise ValueError("cached-writer native executable roster differs")
    return sorted(selected, key=lambda test: test["name"]), sorted(outputs.values())


def validate_outcome(text, arguments):
    """Rejects skips, broad nonzero acceptance and unrelated setup assertions."""
    result = json.loads(text)
    if not isinstance(result, dict) or set(result) != {
        "case", "expected", "returncode", "stdout", "stderr",
    }:
        raise ValueError("registered wrapper did not report exactly one child result")
    scenario, outcome = arguments[:2]
    if (
        result["case"] != scenario or result["expected"] != outcome
        or type(result["returncode"]) is not int
        or not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)
    ):
        raise ValueError("registered wrapper child identity or result shape differs")
    status = result["returncode"]
    if outcome == "success":
        valid = status == 0
    elif outcome == "omitted-deadlock":
        valid = status == 0 and not result["stdout"] and not result["stderr"]
    else:
        message = (
            "qemu: qemu_thread_ram_writer_enter: Resource deadlock avoided"
            if outcome == "deadlock"
            else "Assertion `" + arguments[2] + "' failed."
        )
        valid = status == -signal.SIGABRT and message in result["stderr"]
    if not valid:
        raise ValueError(f"{scenario}: child did not reach its exact expected disposition")
    return result


def built_evidence(build, output, binaries, helper):
    """Retains compiler/generated/depfile identities for each real native binary."""
    objects = {}
    for entry in json.loads((build / "compile_commands.json").read_text()):
        arguments = entry.get("arguments") or shlex.split(entry["command"])
        name = entry.get("output")
        if name is None and "-o" in arguments:
            name = arguments[arguments.index("-o") + 1]
        if name is not None:
            path = (Path(entry["directory"]) / name).resolve()
            if path.is_file():
                objects[str(path.relative_to(build))] = helper.digest(path)
    for binary in binaries:
        if not (build / binary).is_file() or not any(
            name.startswith(binary + ".p/") for name in objects
        ):
            raise ValueError(f"native binary or actual compiler object missing: {binary}")
    depfiles = {
        str(path.relative_to(build)): {"sha256": helper.digest(path), "text": path.read_text()}
        for path in sorted(build.rglob("*.d"))
    }
    if len(depfiles) < len(binaries):
        raise ValueError("native compiler dependency evidence is incomplete")
    generated = {
        str(path.relative_to(build)): helper.digest(path)
        for path in sorted(build.rglob("*"))
        if path.is_file() and path.suffix in (".h", ".inc", ".c")
    }
    extraction = build / "tests/unit/crucible-cached-writer-extraction.json"
    if not extraction.is_file():
        raise ValueError("actual native extraction journal is missing")
    (output / "extraction.json").write_bytes(extraction.read_bytes())
    helper.write_json(output / "linked-inputs.json", {
        "objects": objects, "depfiles": depfiles, "generated_inputs": generated,
        "binaries": {binary: helper.digest(build / binary) for binary in binaries},
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ninja", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--abi-header", type=Path, required=True)
    parser.add_argument("--evidence-helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-timeout", type=int, choices=[BUILD_SECONDS], required=True)
    parser.add_argument("--test-timeout", type=int, choices=[TEST_SECONDS], required=True)
    parser.add_argument("--address-space-bytes", type=int, choices=[ADDRESS_SPACE_BYTES], required=True)
    args = parser.parse_args()
    helper = load_helpers(args.evidence_helper)
    source = args.source_root.resolve()
    build = source / "build"
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "identity.env").write_bytes(args.identity.read_bytes())
    soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY or soft > args.address_space_bytes:
        raise ValueError("builder did not establish the actual 6 GiB address-space bound")
    helper.configured_evidence(source, build, output, args.abi_header)
    tests, binaries = registered_tests(source, build)
    helper.write_json(output / "selected-registration.json", tests)
    environment = os.environ.copy()
    helper.run_group(
        [args.ninja, "-C", str(build), "-t", "commands", *binaries],
        source, environment, TEST_SECONDS, output, "commands",
    )
    build_result = helper.run_group(
        [args.ninja, "-C", str(build), "-j1", "-d", "keepdepfile", *binaries],
        source, environment, args.build_timeout, output, "build",
    )
    built_evidence(build, output, binaries, helper)
    initial = json.loads((output / "configured-inputs.json").read_text())
    helper.write_json(output / "configured-post-build.json", {
        path: helper.digest(source / path) for path in initial
    })
    if json.loads((output / "source-manifest.json").read_text()) != helper.source_manifest(source):
        raise ValueError("source inputs changed during the native unit build")

    dispositions = []
    for test in tests:
        name = test["name"]
        status = helper.run_group(
            test["cmd"], Path(test.get("workdir") or build),
            environment | test.get("env", {}), test["timeout"], output, name,
        )
        child = validate_outcome(
            (output / f"{name}.stdout").read_text(), expected_tests()[name][1],
        )
        dispositions.append({"name": name, "process": status, "child": child})
    helper.write_json(output / "check.json", {
        "check": "checks.crucible.phase7.qemuCachedWriterUnit",
        "scope": "configured native fixture only; no runtime performance qualification",
        "address_space_limit_bytes": soft, "build": build_result,
        "registrations": len(tests), "native_executables": len(binaries),
        "scenarios": len(SCENARIOS), "compiled_omissions": len(OMISSIONS),
        "dispositions": dispositions,
        "source_manifest_sha256": helper.digest(output / "source-manifest.json"),
        "configured_inputs_sha256": helper.digest(output / "configured-inputs.json"),
        "linked_inputs_sha256": helper.digest(output / "linked-inputs.json"),
        "identity_sha256": helper.digest(output / "identity.env"),
        "emulator_or_test_binary_published": False,
    })
    (output / "result").write_text(
        "PASS\ngate=gate:qemu-cached-writer-unit\n"
        "check=checks.crucible.phase7.qemuCachedWriterUnit\n"
        "scope=configured-native-fixture-only\n"
        "registered_tests=35\nnative_executables=11\n"
        "build_timeout_seconds=600\nregistered_test_timeout_seconds=15\n"
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        sys.exit(f"cached-writer unit check refused: {error}")
