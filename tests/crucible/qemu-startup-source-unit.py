"""Runs one registered native unit with genuine configured QEMU support.

The ordinary package owns unpacking, patching, ABI installation and configure.
This runner checks that exact registration, asks Ninja to build its dependency
closure, then runs the registered argv/environment with the original timeout.
Only text/JSON evidence leaves the sandbox; no executable or archive is copied.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import sys
import time

TARGET = "tests/unit/test-crucible-startup-source"
BUILD_SECONDS = 600
TEST_SECONDS = 60
ADDRESS_SPACE_BYTES = 6 * 1024**3


def digest(path):
    """Hashes actual file bytes without following a supplied directory graph."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    """Writes independently inspectable facts, including negative dispositions."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def registered_test(build):
    """Requires the actual Meson command, environment, protocol and timeout."""
    tests = json.loads((build / "meson-info/intro-tests.json").read_text())
    matches = [
        test for test in tests
        if test.get("name") == "test-crucible-startup-source"
    ]
    if len(matches) != 1:
        raise ValueError("startup Source unit is absent or registered more than once")
    test = matches[0]
    expected = [str(build / TARGET), "--tap", "-k"]
    if test.get("cmd") != expected or test.get("timeout") != TEST_SECONDS:
        raise ValueError("registered startup Source argv or original timeout differs")
    if test.get("protocol") != "tap" or test.get("is_parallel") is not True:
        raise ValueError("registered startup Source test protocol or options differ")
    environment = test.get("env", {})
    if not isinstance(environment, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise ValueError("registered startup Source environment is malformed")
    if test.get("extra_paths", []):
        raise ValueError("native Linux unit unexpectedly requires executable path injection")
    return test


def source_manifest(source):
    """Binds the complete configured source while excluding generated build output."""
    records = {}
    for directory, subdirs, files in os.walk(source, followlinks=False):
        parent = Path(directory)
        if parent == source:
            subdirs[:] = [name for name in subdirs if name not in ("build", ".git")]
        for name in sorted(subdirs + files):
            path = parent / name
            relative = str(path.relative_to(source))
            if path.is_symlink():
                records[relative] = {"symlink": os.readlink(path)}
            elif path.is_file():
                records[relative] = {"sha256": digest(path)}
    return dict(sorted(records.items()))


def configured_evidence(source, build, output, abi_header):
    """Captures actual generated inputs and rejects a substituted canonical ABI."""
    installed = source / "include/aos/crucible/crucible_shmem_abi.h"
    if digest(installed) != digest(abi_header):
        raise ValueError("configured shared ABI does not match the canonical input")
    paths = [
        build / "config-host.h",
        build / "config-host.mak",
        build / "compile_commands.json",
        build / "build.ninja",
        build / "meson-info/intro-targets.json",
        build / "meson-info/intro-tests.json",
        build / "meson-info/intro-buildoptions.json",
    ]
    target_headers = sorted(build.glob("*-config-target.h"))
    if not target_headers:
        raise ValueError("actual configured system target headers are missing")
    paths += target_headers
    records = {str(path.relative_to(source)): digest(path) for path in paths}
    records[str(installed.relative_to(source))] = digest(installed)
    write_json(output / "configured-inputs.json", records)
    # Keep compiler/link flags and Meson registration inspectable without objects.
    for path in paths:
        if path.name in (
            "compile_commands.json", "build.ninja", "intro-targets.json",
            "intro-tests.json", "intro-buildoptions.json",
        ):
            (output / path.name).write_bytes(path.read_bytes())
    write_json(output / "source-manifest.json", source_manifest(source))


def run_group(argv, cwd, environment, timeout, output, stem):
    """Runs once and kills remaining group members on every terminal failure."""
    started = time.monotonic()
    timed_out = False
    group_cleanup = None
    write_json(output / f"{stem}.json", {
        "argv": argv, "cwd": str(cwd),
        "timeout_seconds": timeout, "started": False,
    })
    with (
        (output / f"{stem}.stdout").open("wb") as stdout,
        (output / f"{stem}.stderr").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            argv, cwd=cwd, env=environment, stdout=stdout, stderr=stderr,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = 124

        if returncode:
            # A failed leader may have returned while compiler/fixture children
            # remain in its group. Disposing them never changes its first status.
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_cleanup = "signal-delivered"
            except ProcessLookupError:
                group_cleanup = "already-returned"
            process.wait()
    record = {
        "argv": argv, "cwd": str(cwd), "timeout_seconds": timeout,
        "elapsed_seconds": time.monotonic() - started,
        "timed_out": timed_out, "returncode": returncode, "started": True,
        "leader_returncode": process.returncode, "group_cleanup": group_cleanup,
    }
    write_json(output / f"{stem}.json", record)
    if returncode:
        for suffix in ("stdout", "stderr"):
            sys.stderr.write((output / f"{stem}.{suffix}").read_text(errors="replace"))
        raise SystemExit(returncode if returncode > 0 else 128 - returncode)
    return record


def linked_evidence(build, output, target=TARGET):
    """Binds every actually built compile object, archive and retained depfile."""
    objects = {}
    for entry in json.loads((build / "compile_commands.json").read_text()):
        arguments = entry.get("arguments") or shlex.split(entry["command"])
        path = entry.get("output")
        if path is None and "-o" in arguments:
            path = arguments[arguments.index("-o") + 1]
        if path is not None:
            actual = Path(entry["directory"]) / path
            if actual.is_file():
                objects[str(actual.relative_to(build))] = digest(actual)
    archives = {
        str(path.relative_to(build)): digest(path)
        for path in sorted(build.rglob("*.a"))
    }
    if not objects or "libqemuutil.a" not in archives:
        raise ValueError("matching QEMU support objects/archive were not built")
    if (
        not any("libqom" in name for name in objects)
        or not any("event-loop-base" in name for name in objects)
    ):
        raise ValueError("matching qom/event-loop-base support objects were not built")
    depfiles = {}
    for path in sorted(build.rglob("*.d")):
        depfiles[str(path.relative_to(build))] = {
            "sha256": digest(path), "text": path.read_text(),
        }
    if not depfiles:
        raise ValueError("actual compiler depfiles were not retained")
    generated = {
        str(path.relative_to(build)): digest(path)
        for path in sorted(build.rglob("*"))
        if path.is_file() and path.suffix in (".h", ".inc", ".c")
    }
    write_json(output / "linked-inputs.json", {
        "objects": objects, "archives": archives, "depfiles": depfiles,
        "generated_inputs": generated, "binary_sha256": digest(build / target),
    })


def validate_tap(text):
    """Requires one complete numbered top-level plan without discarding directives."""
    plans = []
    results = []
    skipped = 0
    for line in text.splitlines():
        version = re.fullmatch(r"TAP version ([0-9]+)\s*", line)
        if version and int(version.group(1)) < 13:
            raise ValueError("unit TAP explicitly declares a version below 13")
        if line.startswith("not ok") or line.startswith("Bail out!"):
            raise ValueError("unit TAP contains a failure or bailout")
        plan = re.fullmatch(r"1\.\.([0-9]+)(?:\s+#.*)?\s*", line)
        if plan:
            plans.append((int(plan.group(1)), len(results)))
        elif line.startswith("ok"):
            result = re.fullmatch(r"ok\s+([0-9]+)(?:\s+.*)?", line)
            if not result:
                raise ValueError("unit TAP result lacks its numbered identity")
            results.append(int(result.group(1)))
            skipped += bool(re.search(r"#\s*SKIP\b", line, re.I))
        elif line.startswith("1.."):
            raise ValueError("unit TAP has a malformed plan")
    if len(plans) != 1 or plans[0][0] <= 0:
        raise ValueError("unit TAP lacks one nonempty top-level plan")
    planned, position = plans[0]
    if position not in (0, len(results)):
        raise ValueError("unit TAP plan appears between test results")
    if len(results) != planned or any(
        result != expected for expected, result in enumerate(results, 1)
    ):
        raise ValueError("unit TAP result count/order differs from its plan")
    return {"planned": planned, "results": len(results), "skipped": skipped}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ninja", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--abi-header", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-timeout", type=int, choices=[BUILD_SECONDS], required=True)
    parser.add_argument("--test-timeout", type=int, choices=[TEST_SECONDS], required=True)
    parser.add_argument(
        "--address-space-bytes", type=int, choices=[ADDRESS_SPACE_BYTES], required=True,
    )
    args = parser.parse_args()
    source = args.source_root.resolve()
    build = source / "build"
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "identity.env").write_bytes(args.identity.read_bytes())
    soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY or soft > args.address_space_bytes:
        raise ValueError("builder did not establish the actual 6 GiB address-space bound")
    test = registered_test(build)
    configured_evidence(source, build, output, args.abi_header)
    environment = os.environ.copy()
    # Preserve real commands and dependency paths before running the target.
    commands = run_group(
        [args.ninja, "-C", str(build), "-t", "commands", TARGET],
        source, environment, TEST_SECONDS, output, "commands",
    )
    build_result = run_group(
        [args.ninja, "-C", str(build), "-j1", "-d", "keepdepfile", TARGET],
        source, environment, args.build_timeout, output, "build",
    )
    linked_evidence(build, output)
    initial_config = json.loads((output / "configured-inputs.json").read_text())
    write_json(output / "configured-post-build.json", {
        path: digest(source / path) for path in initial_config
    })
    if json.loads((output / "source-manifest.json").read_text()) != source_manifest(source):
        raise ValueError("source inputs changed during the native support build")
    environment.update(test.get("env", {}))
    test_result = run_group(
        test["cmd"], Path(test.get("workdir") or build), environment,
        args.test_timeout, output, "test",
    )
    tap = (output / "test.stdout").read_text()
    tap_counts = validate_tap(tap)
    (output / "startup-source.tap").write_text(tap)
    write_json(output / "check.json", {
        "check": "checks.crucible.phase7.qemuStartupSourceUnit",
        "scope": "registered native fixture only",
        "address_space_limit_bytes": soft, "build": build_result, "test": test_result,
        "command_inspection": commands,
        "source_manifest_sha256": digest(output / "source-manifest.json"),
        "configured_inputs_sha256": digest(output / "configured-inputs.json"),
        "configured_post_build_sha256": digest(output / "configured-post-build.json"),
        "linked_inputs_sha256": digest(output / "linked-inputs.json"),
        "identity_sha256": digest(output / "identity.env"),
        "tap_sha256": digest(output / "startup-source.tap"), "tap_counts": tap_counts,
        "emulator_or_test_binary_published": False,
    })
    (output / "result").write_text(
        "PASS\ngate=gate:qemu-startup-source-unit\n"
        "check=checks.crucible.phase7.qemuStartupSourceUnit\n"
        "scope=registered-native-fixture-only\n"
        "build_timeout_seconds=600\nunit_timeout_seconds=60\n"
    )
    print(tap, end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        sys.exit(f"startup Source unit check refused: {error}")
