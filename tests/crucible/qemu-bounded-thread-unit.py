"""Qualifies the registered QEMU worker against the matching installed libc.

The real package supplies patched source and genuine Meson configuration. This
check requires its public bounded-pthread capability, builds the registered
target and verifies the actual ELF interpreter, runtime resolution and header
dependency before exercising worker birth, terminal return and TSD last use.
Only text evidence leaves the sandbox. These component results grant no Source
application, stack allocation or runtime-profile admission.
"""

import argparse
import json
import os
from pathlib import Path
import resource
import re
import runpy
import sys

TARGET = "tests/unit/test-crucible-bounded-thread"
TEST_NAME = "test-crucible-bounded-thread"
ADDRESS_SPACE_BYTES = 6 * 1024**3
REQUIRED_CONTROLS = (
    "/crucible/bounded/provider-uncreated-return",
    "/crucible/bounded/provider-actual-birth-retirement",
    "/crucible/bounded/provider-tsd-last-use",
)


def registered_test(build):
    """Authenticates the unchanged Meson registration and original run bound."""
    tests = json.loads((build / "meson-info/intro-tests.json").read_text())
    matches = [test for test in tests if test.get("name") == TEST_NAME]
    if len(matches) != 1:
        raise ValueError("bounded-thread unit registration is absent or ambiguous")
    test = matches[0]
    if (
        test.get("cmd") != [str(build / TARGET), "--tap", "-k"]
        or test.get("timeout") != 30
        or test.get("protocol") != "tap"
        or test.get("is_parallel") is not True
        or test.get("extra_paths", [])
    ):
        raise ValueError("bounded-thread registered command or original limits differ")
    environment = test.get("env", {})
    if not isinstance(environment, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise ValueError("bounded-thread registered environment is malformed")
    return test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "source-root", "ninja", "identity", "abi-header", "output",
        "base-runner", "runtime", "runtime-header", "readelf",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--build-timeout", type=int, choices=[600], required=True)
    parser.add_argument("--test-timeout", type=int, choices=[30], required=True)
    parser.add_argument(
        "--address-space-bytes", type=int, choices=[ADDRESS_SPACE_BYTES], required=True,
    )
    args = parser.parse_args()
    base = runpy.run_path(str(args.base_runner))
    write_json = base["write_json"]
    run_group = base["run_group"]
    digest = base["digest"]
    source = args.source_root.resolve()
    build = source / "build"
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY or soft > ADDRESS_SPACE_BYTES:
        raise ValueError("builder did not establish the actual address-space limit")
    # Meson set(bool) emits a valueless define; set10(bool) emits one. Both
    # assert the capability, while an undefined or zero-valued marker refuses.
    capability = [
        line for line in (build / "config-host.h").read_text().splitlines()
        if "CONFIG_PTHREAD_BOUNDED_PROVIDER" in line
    ]
    write_json(output / "capability.json", {"config_host_lines": capability})
    print("bounded-thread capability: " + repr(capability), flush=True)
    if len(capability) != 1 or not re.fullmatch(
        r"#define CONFIG_PTHREAD_BOUNDED_PROVIDER(?: 1)?", capability[0]
    ):
        probe_log = (build / "meson-logs/meson-log.txt").read_text()
        lines = probe_log.splitlines()
        for index, line in enumerate(lines):
            if "pthread_bounded_init_np" in line:
                print("\n".join(lines[max(0, index - 12):index + 32]), file=sys.stderr)
        raise ValueError("genuine configure did not link the bounded-pthread capability")
    test = registered_test(build)
    (output / "identity.env").write_bytes(args.identity.read_bytes())
    base["configured_evidence"](source, build, output, args.abi_header)
    environment = os.environ.copy()
    run_group(
        [str(args.ninja), "-C", str(build), "-t", "commands", TARGET],
        source, environment, 30, output, "commands",
    )
    build_result = run_group(
        [str(args.ninja), "-C", str(build), "-j1", "-d", "keepdepfile", TARGET],
        source, environment, args.build_timeout, output, "build",
    )
    base["linked_evidence"](build, output, TARGET)
    initial_config = json.loads((output / "configured-inputs.json").read_text())
    write_json(output / "configured-post-build.json", {
        path: digest(source / path) for path in initial_config
    })
    linked = json.loads((output / "linked-inputs.json").read_text())
    if not any(
        str(args.runtime_header) in row["text"]
        for row in linked["depfiles"].values()
    ):
        raise ValueError("actual compile dependencies omit the installed bounded header")
    binary = build / TARGET
    loader = args.runtime / "lib/ld-linux-x86-64.so.2"
    run_group(
        [str(args.readelf), "--program-headers", "--wide", str(binary)],
        build, environment, 30, output, "interpreter",
    )
    if f"[Requesting program interpreter: {loader}]" not in (
        output / "interpreter.stdout"
    ).read_text():
        raise ValueError("actual unit selected a different ELF interpreter")
    run_group(
        [str(loader), "--list", str(binary)],
        build, environment, 30, output, "runtime",
    )
    if f"libc.so.6 => {args.runtime}/lib/libc.so.6 " not in (
        output / "runtime.stdout"
    ).read_text():
        raise ValueError("actual unit selected a different libc")
    if base["source_manifest"](source) != json.loads(
        (output / "source-manifest.json").read_text()
    ):
        raise ValueError("configured source changed during owning compilation")

    environment.update(test.get("env", {}))
    test_result = run_group(
        test["cmd"], Path(test.get("workdir") or build), environment,
        args.test_timeout, output, "test",
    )
    tap = (output / "test.stdout").read_text()
    counts = base["validate_tap"](tap)
    if counts["skipped"] or any(control not in tap for control in REQUIRED_CONTROLS):
        raise ValueError("actual supplied-stack or TSD last-use controls did not execute")
    write_json(output / "check.json", {
        "check": "checks.crucible.phase7.qemuBoundedThreadUnit",
        "scope": "registered matching-runtime component only",
        "build": build_result, "test": test_result, "tap_counts": counts,
        "header_sha256": digest(args.runtime_header),
        "libc_sha256": digest(args.runtime / "lib/libc.so.6"),
        "loader_sha256": digest(loader),
        "source_manifest_sha256": digest(output / "source-manifest.json"),
        "configured_inputs_sha256": digest(output / "configured-inputs.json"),
        "configured_post_build_sha256": digest(output / "configured-post-build.json"),
        "linked_inputs_sha256": digest(output / "linked-inputs.json"),
        "identity_sha256": digest(output / "identity.env"),
        "tap_sha256": digest(output / "test.stdout"),
        "emulator_or_test_binary_published": False,
    })
    (output / "result").write_text(
        "PASS\ngate=gate:qemu-bounded-thread-unit\n"
        "check=checks.crucible.phase7.qemuBoundedThreadUnit\n"
        "scope=registered-matching-runtime-component-only\n"
        "build_timeout_seconds=600\nunit_timeout_seconds=30\n"
    )
    print(tap, end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        sys.exit(f"bounded-thread unit check refused: {error}")
