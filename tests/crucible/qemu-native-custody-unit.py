"""Runs standalone custody controls against genuine configured QEMU inputs.

The registered Source unit builds the real support closure first. Each additional
component retains its separate 180-second manual bound, including descendant
address-space accounting. These components establish no launched Source grant.
"""

import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import signal
import subprocess
import sys
import time

COMPONENT_SECONDS = 180
ADDRESS_SPACE_BYTES = 6 * 1024**3
COMPONENTS = (
    "action-edge-post", "apic-getter-custody", "apic-getter-errors",
    "apic-timer-storage", "clock-callback-custody", "clock-canonical-rows",
    "clock-storage-return", "flatview-custody", "memory-discard-custody",
    "memory-region-custody", "provider-metadata", "publisher-member-return",
    "shmem-callback-return", "publisher-service-transfer",
    "initial-register-read", "ram-mapping-journal", "initial-native-read",
    "advance-content", "advance-post-refusal", "advance-recipient-leaves",
    "advance-registration", "publisher-initial-state",
)
POSITIONAL_ARGUMENTS = {
    "advance-content", "advance-post-refusal", "advance-recipient-leaves",
    "advance-registration", "publisher-initial-state",
}
FULL_LINK = {
    "action-edge-post", "apic-timer-storage", "clock-storage-return",
    "shmem-callback-return",
}
QOM_LINK = {
    "flatview-custody", "memory-discard-custody", "memory-region-custody",
    "ram-mapping-journal",
}
TARGET_FLAGS = {"apic-timer-storage", "clock-storage-return"}


def configured_flags(entry, build, source):
    """Preserves configured flags when a component changes its working directory."""
    if Path(entry["directory"]).resolve() != build:
        raise ValueError("compiler entry belongs to another build directory")
    command = shlex.split(entry["command"])
    compiler = Path(command[0])
    if not compiler.is_absolute() or not compiler.is_file():
        raise ValueError("configured compiler is not an actual absolute executable")
    if command.count("-c") != 1 or command.count("-o") != 1:
        raise ValueError("configured compilation has ambiguous input/output")
    if (build / command[command.index("-c") + 1]).resolve() != source:
        raise ValueError("configured compilation has another source input")

    flags = []
    arguments = iter(command[1:])
    for argument in arguments:
        if argument in ("-MQ", "-MF", "-o", "-c"):
            next(arguments)
        elif argument not in ("-MD", "-MMD", "-MP"):
            flags.append(argument)

    rebased = []
    arguments = iter(flags)
    for flag in arguments:
        if flag in ("-I", "-iquote", "-isystem", "-include", "-imacros"):
            rebased.extend((flag, str((build / next(arguments)).resolve())))
            continue
        for prefix in ("-iquote", "-isystem", "-I"):
            if flag.startswith(prefix) and len(flag) > len(prefix):
                flag = prefix + str((build / flag[len(prefix):]).resolve())
                break
        rebased.append(flag)
    return str(compiler), rebased


def descendant_memory(pid):
    """Measures all observable descendants, including compiler grandchildren."""
    rows = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            raw = path.read_text()
            fields = raw[raw.rindex(")") + 2:].split()
            rows[int(path.parent.name)] = (int(fields[1]), int(fields[20]))
        except (OSError, ValueError, IndexError):
            continue
    owned = {pid}
    while True:
        expanded = owned | {child for child, row in rows.items() if row[0] in owned}
        if expanded == owned:
            break
        owned = expanded
    return sum(row[1] for child, row in rows.items() if child in owned)


def run_component(argv, build, environment, cases, output, write_json):
    """Preserves the first failure and terminates its remaining process group."""
    started = time.monotonic()
    peak = 0
    reason = None
    record = {"argv": argv, "cwd": str(build), "started": False,
              "timeout_seconds": COMPONENT_SECONDS,
              "aggregate_address_space_bytes": ADDRESS_SPACE_BYTES}
    retained = cases / "runner"
    retained.mkdir()
    write_json(output / "run.json", record)
    write_json(retained / "run.json", record)
    with (output / "stdout").open("wb") as stdout, (output / "stderr").open("wb") as stderr:
        child = subprocess.Popen(argv, cwd=build, env=environment,
                                 stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            while child.poll() is None:
                peak = max(peak, descendant_memory(child.pid))
                elapsed = time.monotonic() - started
                if peak > ADDRESS_SPACE_BYTES or elapsed > COMPONENT_SECONDS:
                    reason = "aggregate-address-space" if peak > ADDRESS_SPACE_BYTES else "timeout"
                    break
                time.sleep(0.005)
        finally:
            # Also dispose descendants after a failed or successful leader. No
            # component may leave a background writer in the next observation.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            returncode = child.wait()
    record.update(started=True, returncode=returncode, reason=reason,
                  elapsed_seconds=time.monotonic() - started,
                  peak_aggregate_address_space_bytes=peak)
    write_json(output / "run.json", record)
    write_json(retained / "run.json", record)
    for name in ("stdout", "stderr"):
        shutil.copyfile(output / name, retained / name)
    if returncode or reason:
        # Failed derivation outputs are removed; the kept build and Nix log
        # must still explain the first failure without reconstructing a run.
        for name in ("stdout", "stderr"):
            text = (output / name).read_text(errors="replace")
            sys.stderr.write(f"{name} (last 65536 characters):\n{text[-65536:]}\n")
        raise SystemExit(f"native custody component failed: {argv[1]}: {record}")
    return record


def retain_text(cases, output, digest, write_json):
    """Retains generated sources and proof without publishing executable outputs."""
    records = {}
    for path in sorted(cases.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(cases)
        data = path.read_bytes()
        copied = False
        if b"\0" not in data:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                destination = output / "evidence" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
                copied = True
        records[str(relative)] = {"sha256": digest(path), "text_retained": copied}
    write_json(output / "generated-files.json", records)


def main():
    index = sys.argv.index("--base-runner")
    base_runner = Path(sys.argv[index + 1])
    del sys.argv[index:index + 2]
    source = Path(sys.argv[sys.argv.index("--source-root") + 1]).resolve()
    output_index = sys.argv.index("--output") + 1
    output = Path(sys.argv[output_index])
    sys.argv[output_index] = str(output / "source-unit")
    base = runpy.run_path(str(base_runner))
    base["main"]()

    build = source / "build"
    entries = json.loads((build / "compile_commands.json").read_text())
    common, = [entry for entry in entries if entry["file"].endswith("/plugins/api-system.c")]
    compiler, flags = configured_flags(common, build, source / "plugins/api-system.c")
    apic, = [entry for entry in entries if entry["file"].endswith("/hw/intc/apic.c")]
    apic_compiler, apic_flags = configured_flags(apic, build, source / "hw/intc/apic.c")
    if compiler != apic_compiler:
        raise ValueError("common and APIC objects use different configured compilers")
    target_flags = [flag for flag in apic_flags if flag.startswith(
        ("-DCOMPILING_PER_TARGET", "-DCONFIG_TARGET=", "-DCONFIG_DEVICES="))]
    if len(target_flags) != 3:
        raise ValueError("actual APIC target flags are incomplete or ambiguous")
    environment = os.environ.copy()
    environment.update(CC=compiler, CFLAGS=shlex.join(flags), LDFLAGS="")
    os.environ.update(environment)
    helper = runpy.run_path(str(source / "tests/unit/crucible-net-stop-support.py"))
    link = helper["native_link_arguments"]()
    link = [str((build / arg).resolve()) if not arg.startswith("-")
            and (build / arg).is_file() else arg for arg in link]
    glib, = [arg for arg in link if Path(arg).name.startswith("libglib-2.0.so")]
    qom = sorted({str((build / entry["output"]).resolve()) for entry in entries
                  if entry["output"].startswith("libqom.a.p/")})
    if not qom or any(not Path(path).is_file() for path in qom):
        raise ValueError("actual configured QOM support is incomplete")

    initial_source = base["source_manifest"](source)
    records = []
    for name in COMPONENTS:
        case_output = output / name
        case_output.mkdir(parents=True)
        cases = build / "native-custody" / name
        cases.mkdir(parents=True)
        settings = environment.copy()
        settings["LDFLAGS"] = shlex.join(link if name in FULL_LINK else [glib, "-pthread"])
        if name in TARGET_FLAGS:
            settings["CFLAGS"] = shlex.join(flags + target_flags)
        argv = [sys.executable, str(source / f"tests/unit/test-crucible-{name}.py")]
        if name in POSITIONAL_ARGUMENTS:
            argv.extend((str(source), str(cases)))
        else:
            argv.extend(("--output-dir", str(cases)))
        if name in QOM_LINK:
            argv.extend(("--qemu-util", str(build / "libqemuutil.a")))
            for path in qom:
                argv.extend(("--qom-object", path))
        base["write_json"](case_output / "environment.json", {
            key: settings[key] for key in ("CC", "CFLAGS", "LDFLAGS")})
        result = run_component(argv, build, settings, cases, case_output, base["write_json"])
        retain_text(cases, case_output, base["digest"], base["write_json"])
        if initial_source != base["source_manifest"](source):
            raise ValueError(f"component changed its source inputs: {name}")
        records.append({"component": name, **result})
        base["write_json"](output / "components.json", records)
        print(f"PASS native custody component: {name}", flush=True)
    (output / "result").write_text(
        "PASS\nscope=standalone-real-body-components-only\n"
        f"components={len(COMPONENTS)}\ncomponent_timeout_seconds=180\n"
        "aggregate_address_space_bytes=6442450944\n"
        "launched_source_authority=false\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, StopIteration) as error:
        sys.exit(f"native custody unit check refused: {error}")
