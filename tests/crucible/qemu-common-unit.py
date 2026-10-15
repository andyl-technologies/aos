"""Links and runs ordinary QEMU consumers of the common allocation providers.

The real package configures the source and installs its canonical ABI header.
Existing Meson registrations exercise RCU, ordinary JSON serialization and QAPI
input errors. Only logs, dependency records and hashes leave the build sandbox.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys

NAMES = ("test-rcu-list", "check-qjson", "test-qobject-input-visitor")
SYMBOLS = (
    "qemu_crucible_qmp_string_append",
    "qemu_crucible_qmp_string_prepend",
    "qemu_crucible_qmp_string_erase",
    "qemu_crucible_qmp_json_writer_allocate",
    "qemu_crucible_qmp_json_writer_observe",
)
BUILD_SECONDS = 600
TEST_SECONDS = 60
REGISTERED_SECONDS = 30
ADDRESS_SPACE_BYTES = 6 * 1024**3


def registered_tests(source, build):
    """Requires every existing target, original TAP command and environment."""
    tests = json.loads((build / "meson-info/intro-tests.json").read_text())
    targets = json.loads((build / "meson-info/intro-targets.json").read_text())
    selected = []
    for name in NAMES:
        matches = [test for test in tests if test.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"{name}: genuine registration is missing or ambiguous")
        test = matches[0]
        binary = str(build / "tests/unit" / name)
        expected_environment = {
            "G_TEST_SRCDIR": str(source / "tests/unit"),
            "G_TEST_BUILDDIR": str(build / "tests/unit"),
        }
        if (
            test.get("cmd") != [binary, "--tap", "-k"]
            or test.get("timeout") != REGISTERED_SECONDS
            or test.get("protocol") != "tap"
            or test.get("is_parallel") is not True
            or test.get("should_fail", False) is not False
            or test.get("env") != expected_environment
            or test.get("extra_paths", [])
            or test.get("workdir") not in (None, str(build))
            or not any(suite.split(":")[-1] == "unit" for suite in test.get("suite", []))
        ):
            raise ValueError(f"{name}: original command, environment or disposition differs")
        native = [
            target for target in targets
            if target.get("name") == name and target.get("type") == "executable"
            and target.get("filename") == [binary]
        ]
        if len(native) != 1 or native[0].get("installed") is not False:
            raise ValueError(f"{name}: configured noninstalled executable is missing")
        selected.append(test)
    return selected


def defined_symbols(text, archive=False):
    """Requires strong definitions and their real negative-provider member."""
    definitions = {}
    for symbol in SYMBOLS:
        matches = [line for line in text.splitlines() if line.split()[-1:] == [symbol]]
        if not archive and not matches:
            continue
        if len(matches) != 1 or matches[0].split()[-2] != "T":
            raise ValueError(f"{symbol}: one strong native definition is required")
        if archive and "stubs_crucible-qmp-allocation.c.o:" not in matches[0]:
            raise ValueError(f"{symbol}: definition is outside the ordinary provider")
        definitions[symbol] = matches[0]
    return definitions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ninja", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--abi-header", type=Path, required=True)
    parser.add_argument("--evidence-helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-timeout", type=int, choices=[BUILD_SECONDS], required=True)
    parser.add_argument("--test-timeout", type=int, choices=[TEST_SECONDS], required=True)
    parser.add_argument("--address-space-bytes", type=int, choices=[ADDRESS_SPACE_BYTES], required=True)
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("qemu_unit_evidence", args.evidence_helper)
    if spec is None or spec.loader is None:
        raise ValueError("native evidence helper cannot be loaded")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    source = args.source_root.resolve()
    build = source / "build"
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY or soft > args.address_space_bytes:
        raise ValueError("builder did not establish the 6 GiB address-space bound")
    (output / "identity.env").write_bytes(args.identity.read_bytes())
    helper.configured_evidence(source, build, output, args.abi_header)
    tests = registered_tests(source, build)
    helper.write_json(output / "selected-registration.json", tests)
    binaries = ["tests/unit/" + name for name in NAMES]
    environment = os.environ.copy()
    helper.run_group(
        [args.ninja, "-C", str(build), "-t", "commands", *binaries],
        source, environment, TEST_SECONDS, output, "commands",
    )
    build_result = helper.run_group(
        [args.ninja, "-C", str(build), "-j1", "-d", "keepdepfile", *binaries],
        source, environment, args.build_timeout, output, "build",
    )
    helper.linked_evidence(build, output, binaries[0])
    symbols = {}
    for label, path in [("archive", build / "libqemuutil.a")] + [
        (name, build / "tests/unit" / name) for name in NAMES
    ]:
        helper.run_group(
            [args.nm, "-A", "-g", "--defined-only", str(path)],
            build, environment, TEST_SECONDS, output, label + "-symbols",
        )
        symbols[label] = defined_symbols(
            (output / (label + "-symbols.stdout")).read_text(), label == "archive",
        )
    if json.loads((output / "source-manifest.json").read_text()) != helper.source_manifest(source):
        raise ValueError("source inputs changed during the common-library build")
    configured = json.loads((output / "configured-inputs.json").read_text())
    configured_after = {path: helper.digest(source / path) for path in configured}
    helper.write_json(output / "configured-post-build.json", configured_after)
    if configured_after != configured:
        raise ValueError("configured inputs changed during the common-library build")

    results = []
    for test in tests:
        name = test["name"]
        status = helper.run_group(
            test["cmd"], Path(test.get("workdir") or build),
            environment | test["env"], test["timeout"], output, name,
        )
        counts = helper.validate_tap((output / (name + ".stdout")).read_text())
        if counts["skipped"]:
            raise ValueError(f"{name}: ordinary common tests were skipped")
        results.append({"name": name, "process": status, "tap": counts})
    helper.write_json(output / "check.json", {
        "check": "checks.crucible.phase7.qemuCommonUnit",
        "scope": "configured common-library link and ordinary unit tests",
        "build": build_result, "tests": results, "symbols": symbols,
        "address_space_limit_bytes": soft,
        "binaries": {name: helper.digest(build / "tests/unit" / name) for name in NAMES},
        "source_manifest_sha256": helper.digest(output / "source-manifest.json"),
        "configured_inputs_sha256": helper.digest(output / "configured-inputs.json"),
        "linked_inputs_sha256": helper.digest(output / "linked-inputs.json"),
        "identity_sha256": helper.digest(output / "identity.env"),
        "emulator_or_test_binary_published": False,
    })
    (output / "result").write_text(
        "PASS\ngate=gate:qemu-common-unit\n"
        "check=checks.crucible.phase7.qemuCommonUnit\n"
        "scope=configured-common-library-unit-tests\nregistered_tests=3\n"
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
        sys.exit(f"common-library unit check refused: {error}")
