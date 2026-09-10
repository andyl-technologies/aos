"""Checks exported toolchain interpreters, loaders, and compiler contracts.

The JSON input maps tier names to maps of tool names and output paths. Build
dependencies and strings in documentation are deliberately not executable
dependencies. Missing outputs or inspection failures never count as a pass.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

from toolchain_elf import inspect_elf


C_ONLY_TIERS = {"bootstrap", "gcc3_4", "gcc3_4_cross", "gcc4_1"}


def inside(path, roots):
    """Resolves aliases before testing membership in a tier's output roots."""
    resolved = Path(path).resolve(strict=True)
    return any(resolved == root or root in resolved.parents for root in roots)


def inspect_path(path, root, roots, readelf=None, default_library_paths=()):
    """Checks executable aliases, loaders, and shebangs, excluding metadata."""
    executable_tree = path.relative_to(root).parts[0] in {
        "bin", "sbin", "lib", "libexec",
    }
    if path.is_symlink() and not path.exists() and executable_tree:
        return ["dangling executable or library alias"]

    executable_file = path.is_file() and os.access(path, os.X_OK)
    executable_alias = executable_file or (path.is_dir() and executable_tree)
    reasons = []
    if path.is_symlink() and executable_alias and not inside(path, roots):
        reasons.append("symlink leaves exported tier outputs")
    if not path.is_file() or not (executable_file or executable_tree):
        return reasons

    with path.open("rb") as source:
        prefix = source.read(4096)
    if prefix.startswith(b"\x7fELF"):
        if path.is_symlink() and not executable_alias and not inside(path, roots):
            reasons.append("ELF library symlink leaves exported tier outputs")
        if readelf is not None:
            reasons.extend(inspect_elf(path, roots, readelf, default_library_paths))
    if not executable_file or not prefix.startswith(b"#!"):
        return reasons

    words = prefix.splitlines()[0][2:].decode("utf-8").split()
    if not words or not Path(words[0]).is_absolute():
        reasons.append("missing or relative interpreter")
    elif not inside(words[0], roots):
        reasons.append(f"interpreter leaves exported tier: {words[0]}")
    elif Path(words[0]).resolve(strict=True).name == "env":
        reasons.append("env shebang defers interpreter selection to ambient PATH")
    return reasons


def inspect_drivers(packages, reject):
    """Asks every public compiler alias which assembler and linker it uses."""
    gcc = Path(packages["gcc"]) / "bin/gcc"
    drivers = {gcc}
    try:
        drivers.update(
            path for path in gcc.parent.iterdir()
            if re.search(r"(?:^|-)(?:gcc|g\+\+|cc|c\+\+)(?:-[0-9][0-9.]*)?$", path.name)
        )
    except OSError as error:
        reject(gcc.parent, f"cannot enumerate compiler drivers: {error}")

    # A modern-looking wrapper can still select a historical assembler via
    # GCC specs or -B. Ask the actual exported drivers with no ambient tools.
    for driver in sorted(drivers):
        for program in ("as", "ld"):
            expected = Path(packages["binutils"]) / "bin" / program
            try:
                result = subprocess.run(
                    [str(driver), f"-print-prog-name={program}"],
                    env={"PATH": "/nonexistent", "LC_ALL": "C"},
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True,
                )
                selected = Path(result.stdout.strip())
                matches = (
                    selected.is_absolute()
                    and selected.resolve(strict=True) == expected.resolve(strict=True)
                )
                if not matches:
                    reject(driver, f"{program} selects {selected}; expected {expected}")
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                reject(driver, f"cannot establish {program} selection: {error}")


def inspect_recipe_shell(packages, directory, environment, emulator=None):
    """Runs a Make recipe without overriding its compiled shell selection."""
    makefile = Path(directory) / "Makefile"
    readlink = Path(packages["coreutils"]) / "bin/readlink"

    # The trailing builtin prevents the shell from replacing itself with readlink.
    # Check pwd inside the sandbox too: a host-side check misses bind-mount bugs.
    commands = ["pwd -P >/dev/null || exit 1"]
    if emulator is not None:
        # The kernel reports QEMU as the process executable. Bash initializes
        # BASH to the guest shell path; the clean probe environment supplies no
        # BASH value that could substitute an unrelated shell's identity.
        commands.append("printf '%s\\n' \"$$BASH\"")
    commands.append(f"{readlink} -f /proc/$$$$/exe")
    makefile.write_text("all:\n\t@" + "; ".join(commands) + "; :\n")
    result = subprocess.run(
        [str(Path(packages["gnumake"]) / "bin/make"), "-f", str(makefile)],
        cwd=directory,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    expected = (Path(packages["bash"]) / "bin/bash").resolve(strict=True)
    identities = result.stdout.splitlines()
    allowed_executables = {expected}
    if emulator is not None:
        if len(identities) != 2:
            return "Make recipe must report both its guest shell and process executable"
        guest = Path(identities.pop(0))
        if not guest.is_absolute() or guest.resolve(strict=True) != expected:
            return f"Make recipe selects guest shell {guest}; expected {expected}"
        allowed_executables.add(Path(emulator).resolve(strict=True))

    if len(identities) != 1:
        return "Make recipe must report exactly one process executable"
    selected = Path(identities[0])
    if not selected.is_absolute() or selected.resolve(strict=True) not in allowed_executables:
        allowed = " or ".join(str(path) for path in sorted(allowed_executables))
        return f"Make recipe selects {selected}; expected {allowed}"
    return None


def run_compiled_probe(compiler, source, directory, environment):
    """Compiles and runs an optimized static probe using only exported tools."""
    executable = Path(directory) / "program"
    # The floating-point printf regression requires the compiler's optimizer.
    subprocess.run(
        [str(compiler), "-O2", "-static", str(Path(source).resolve()), "-o", str(executable)],
        cwd=directory,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    subprocess.run(
        [str(executable)],
        cwd=directory,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def inspect_mtrace(executable, directory, environment):
    """Checks balanced allocations and a real leak through the installed script."""
    trace = Path(directory) / "allocations.trace"
    cases = (
        ("+ 0x1234 0x10\n- 0x1234\n", 0, "No memory leaks."),
        ("+ 0x1234 0x10\n", 1, "Memory not freed:"),
    )
    for data, expected_status, expected_message in cases:
        trace.write_text(data)
        result = subprocess.run(
            [str(executable), str(trace)],
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != expected_status or expected_message not in result.stdout:
            return f"mtrace did not report {expected_message!r}: {result.stdout}{result.stderr}"
    return None


def inspect_perl_config(executable, packages, roots, environment):
    """Checks retained compiler settings before using Perl's build interface."""
    fields = ("cc", "ar", "nm", "ranlib", "ccflags", "cppflags", "ldflags", "lddlflags")
    result = subprocess.run(
        [str(executable), "-MConfig", "-e",
         'print join("\\0", map { defined($Config{$_}) ? $Config{$_} : "" } @ARGV)',
         *fields],
        env=environment, check=True, capture_output=True, text=True, timeout=30,
    )
    values = result.stdout.split("\0")
    if len(values) != len(fields):
        return "Perl Config returned incomplete compiler settings"

    config = dict(zip(fields, values))
    commands = {}
    for field in fields[:4]:
        # Config documents ':' when ar indexes archives without a separate
        # ranlib invocation. It names no external executable in that case.
        if field == "ranlib" and config[field] == ":":
            continue
        command = shlex.split(config[field])
        if not command:
            return f"Perl Config {field} has no command"
        selected = shutil.which(command[0], path=environment["PATH"])
        if selected is None or not inside(selected, roots):
            return f"Perl Config {field} leaves exported tier: {command[0]}"
        command[0] = selected
        commands[field] = command
        if field != "cc":
            expected = Path(packages["binutils"]) / "bin" / field
            if Path(selected).resolve(strict=True) != expected.resolve(strict=True):
                return f"Perl Config {field} selects {selected}; expected {expected}"

    # Flags also retain headers and libraries. Checking just the executable
    # would accept a public compiler configured against a private sysroot.
    for field, value in config.items():
        for path in re.findall(r"/nix/store/[^\s'\",;]+", value):
            if not inside(path, roots):
                return f"Perl Config {field} leaves exported tier: {path}"

    for program in ("as", "ld"):
        result = subprocess.run(
            commands["cc"] + [f"-print-prog-name={program}"],
            env=environment, check=True, capture_output=True, text=True, timeout=30,
        )
        selected = Path(result.stdout.strip())
        expected = Path(packages["binutils"]) / "bin" / program
        if not selected.is_absolute() or selected.resolve(strict=True) != expected.resolve(strict=True):
            return f"Perl compiler selects {selected}; expected {expected}"
    return None


def inspect_perl_compiler(executable, directory, environment):
    """Checks Perl's installed build configuration and filesystem behavior."""
    source = Path(directory) / "perl-boundary.c"
    object_file = Path(directory) / "perl-boundary.o"
    program = Path(directory) / "perl-boundary"
    source.write_text(
        '#include "EXTERN.h"\n#include "perl.h"\n'
        '#include <resolv.h>\n#include <string.h>\n\n'
        'int main(void) {\n'
        '    struct __res_state resolver;\n\n'
        '    memset(&resolver, 0, sizeof(resolver));\n'
        '    if (res_ninit(&resolver) != 0) {\n'
        '        return 1;\n'
        '    }\n'
        '    res_nclose(&resolver);\n'
        '    return 0;\n'
        '}\n'
    )
    script = (
        'my $expected = $ARGV[3];\n'
        'for my $cwd (Cwd::cwd(), Cwd::getcwd()) {\n'
        '    die "Perl returned an incorrect working directory"\n'
        '        unless defined($cwd) && $cwd eq $expected;\n'
        '}\n\n'
        'my $builder = ExtUtils::CBuilder->new(quiet => 1);\n'
        '$builder->compile('
        'source => $ARGV[0], object_file => $ARGV[1]);\n'
        '$builder->link_executable(objects => $ARGV[1], exe_file => $ARGV[2]);\n\n'
        'my $removed = "$expected/removed-cwd";\n'
        'mkdir($removed) or die "mkdir: $!";\n'
        'chdir($removed) or die "chdir: $!";\n'
        'rmdir($removed) or die "rmdir: $!";\n'
        'my $missing = Cwd::getcwd();\n'
        'die "Perl fabricated a working directory after removal"\n'
        '    if defined($missing) && length($missing);\n'
        'chdir($expected) or die "restore directory: $!";\n'
    )
    subprocess.run(
        [str(executable), "-MCwd", "-MExtUtils::CBuilder", "-e", script,
         str(source), str(object_file), str(program), str(Path(directory).resolve())],
        cwd=directory, env=environment, check=True, capture_output=True,
        text=True, timeout=60,
    )
    if not object_file.is_file() or object_file.stat().st_size == 0:
        return "Perl's installed compiler configuration did not produce an object"

    # Resolver initialization and cleanup need no DNS query. This catches the
    # old link workaround that replaced the cleanup function with address zero.
    subprocess.run(
        [str(program)], cwd=directory, env=environment, check=True,
        capture_output=True, text=True, timeout=30,
    )
    return None


def inspect_runtime(name, packages, roots, syscall_source, cxx_source, reject, emulator=None):
    """Checks recipe execution and the C/C++ header and library contracts."""
    if syscall_source is None and cxx_source is None:
        return

    with tempfile.TemporaryDirectory(prefix="aos-toolchain-contracts-") as directory:
        environment = {
            "PATH": os.pathsep.join(str(root / "bin") for root in roots),
            "LC_ALL": "C",
            "TMPDIR": directory,
        }
        if all(tool in packages for tool in ("gnumake", "coreutils", "bash")):
            try:
                reason = inspect_recipe_shell(packages, directory, environment, emulator)
                if reason:
                    reject(packages["gnumake"], reason)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                reject(packages["gnumake"], f"cannot establish Make recipe shell: {error}")
        else:
            reject(name, "runtime probes require gnumake, coreutils, and bash exports")

        if "perl" in packages:
            perl = Path(packages["perl"]) / "bin/perl"
            try:
                reason = inspect_perl_config(perl, packages, roots, environment)
                if reason:
                    reject(perl, reason)
                reason = inspect_perl_compiler(perl, directory, environment)
                if reason:
                    reject(perl, reason)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                detail = getattr(error, "stderr", "") or str(error)
                reject(perl, f"installed Perl compiler contract failed: {detail}")

        libc_tools = packages.get("glibc.bin", packages.get("glibc"))
        if libc_tools is not None:
            mtrace = Path(libc_tools) / "bin/mtrace"
            if mtrace.exists():
                try:
                    reason = inspect_mtrace(mtrace, directory, environment)
                    if reason:
                        reject(mtrace, reason)
                except (OSError, subprocess.SubprocessError) as error:
                    reject(mtrace, f"cannot execute mtrace contract: {error}")

        probes = []
        if syscall_source is not None:
            probes.append(("gcc", syscall_source, "syscall contract"))
        if cxx_source is not None and name not in C_ONLY_TIERS:
            probes.append(("g++", cxx_source, "C++ header/runtime contract"))

        for driver, source, description in probes:
            compiler = Path(packages["gcc"]) / "bin" / driver
            try:
                run_compiled_probe(compiler, source, directory, environment)
            except (OSError, subprocess.SubprocessError) as error:
                detail = getattr(error, "stderr", "") or str(error)
                reject(compiler, f"{description} probe failed: {detail}")


def inspect_tier(name, packages, syscall_source=None, readelf=None, cxx_source=None, emulator=None):
    """Returns violations at the public export boundary of one tier."""
    violations = []

    def reject(path, reason):
        violations.append({"tier": name, "path": str(path), "reason": reason})

    roots = []
    for path in sorted(set(packages.values())):
        try:
            roots.append(Path(path).resolve(strict=True))
        except OSError as error:
            reject(path, f"unavailable output: {error}")

    default_library_paths = []
    if "glibc" in packages:
        default_library_paths.append(Path(packages["glibc"]) / "lib")

    # Do not follow directory symlinks recursively: GCC links a whole target
    # tree, which can contain cycles. Every exported root is scanned directly;
    # external executable directory aliases must still stay inside this tier.
    for root in roots:
        entries = os.walk(root, onerror=lambda error: reject(root, str(error)))
        for directory, directories, filenames in entries:
            for filename in directories + filenames:
                path = Path(directory) / filename
                try:
                    reasons = inspect_path(path, root, roots, readelf, default_library_paths)
                    for reason in reasons:
                        reject(path, reason)
                except (OSError, UnicodeError, RuntimeError, subprocess.SubprocessError) as error:
                    reject(path, f"cannot inspect executable dependency: {error}")

    if "gcc" not in packages or "binutils" not in packages:
        reject(name, "tier must declare gcc and binutils outputs")
        return violations

    inspect_drivers(packages, reject)
    inspect_runtime(name, packages, roots, syscall_source, cxx_source, reject, emulator)
    return violations


def main():
    """Writes a machine-readable report and fails on any violation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--syscall-source", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--cxx-source", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, help="declared QEMU executable for foreign processes")
    arguments = parser.parse_args()
    inventory = json.loads(arguments.inventory.read_text())
    if not inventory:
        parser.error("the tier inventory must not be empty")

    violations = []
    for name, packages in sorted(inventory.items()):
        violations.extend(inspect_tier(
            name, packages, arguments.syscall_source, arguments.readelf, arguments.cxx_source,
            arguments.emulator,
        ))
    report = {"schema_version": 1, "tiers": sorted(inventory), "violations": violations}
    if arguments.emulator is not None:
        report["emulator"] = str(arguments.emulator.resolve())
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    for violation in violations:
        print(f"{violation['tier']}: {violation['path']}: {violation['reason']}")
    return bool(violations)


if __name__ == "__main__":
    raise SystemExit(main())
