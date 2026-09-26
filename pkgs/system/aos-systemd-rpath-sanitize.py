"""Removes only reviewed nuke-refs placeholders from systemd ELF RPATHs."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import subprocess


DUMMY_STORE_PREFIX = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-"
REVIEWED_DUMMY_RPATHS = frozenset(
    {
        f"{DUMMY_STORE_PREFIX}attr-2.6.0/lib",
        f"{DUMMY_STORE_PREFIX}device-mapper-2.03.28/lib",
        f"{DUMMY_STORE_PREFIX}json-c-0.19/lib",
        f"{DUMMY_STORE_PREFIX}libaio-0.3.113/lib",
        f"{DUMMY_STORE_PREFIX}libunistring-1.4.2/lib",
    }
)
REQUIRED_ROOT_NAMES = frozenset({"out", "tools"})
REVIEWED_OUTPUT_ELFS = frozenset(
    {
        "bin/bootctl",
        "bin/busctl",
        "bin/coredumpctl",
        "bin/hostnamectl",
        "bin/journalctl",
        "bin/kernel-install",
        "bin/loginctl",
        "bin/networkctl",
        "bin/oomctl",
        "bin/resolvectl",
        "bin/storagectl",
        "bin/systemctl",
        "bin/systemd-ac-power",
        "bin/systemd-analyze",
        "bin/systemd-ask-password",
        "bin/systemd-cat",
        "bin/systemd-cgls",
        "bin/systemd-cgtop",
        "bin/systemd-creds",
        "bin/systemd-cryptenroll.unwrapped",
        "bin/systemd-cryptsetup.unwrapped",
        "bin/systemd-delta",
        "bin/systemd-detect-virt",
        "bin/systemd-dissect",
        "bin/systemd-escape",
        "bin/systemd-hwdb",
        "bin/systemd-id128",
        "bin/systemd-inhibit",
        "bin/systemd-machine-id-setup",
        "bin/systemd-mount",
        "bin/systemd-mstack",
        "bin/systemd-mute-console",
        "bin/systemd-notify",
        "bin/systemd-nspawn",
        "bin/systemd-path",
        "bin/systemd-pty-forward",
        "bin/systemd-repart",
        "bin/systemd-run",
        "bin/systemd-socket-activate",
        "bin/systemd-stdio-bridge",
        "bin/systemd-sysinstall",
        "bin/systemd-sysusers",
        "bin/systemd-tmpfiles",
        "bin/systemd-tty-ask-password-agent",
        "bin/systemd-vpick",
        "bin/timedatectl",
        "bin/udevadm",
        "bin/varlinkctl",
        "lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so",
        "lib/libnss_myhostname.so.2",
        "lib/libnss_resolve.so.2",
        "lib/libnss_systemd.so.2",
        "lib/libsystemd.so.0.44.0",
        "lib/libudev.so.1.7.14",
        "lib/security/pam_systemd.so",
        "lib/security/pam_systemd_loadkey.so",
        "lib/systemd/libsystemd-core-261.so",
        "lib/systemd/libsystemd-shared-261.so",
    }
)
REVIEWED_DUMMY_LOCATIONS = frozenset(
    (f"out/{relative}", placeholder)
    for relative in REVIEWED_OUTPUT_ELFS
    for placeholder in REVIEWED_DUMMY_RPATHS
)


def fail(message: str) -> "None":
    raise SystemExit(f"aos-systemd-rpath-sanitize: {message}")


def sanitize_rpath(rpath: str) -> str:
    """Returns an RPATH with only exact reviewed dummy entries removed."""

    if not rpath:
        return rpath

    directories = rpath.split(":")
    if any(not directory for directory in directories):
        fail("RPATH contains an empty current-directory entry")

    unexpected_dummy = {
        directory
        for directory in directories
        if directory.startswith(DUMMY_STORE_PREFIX)
        and directory not in REVIEWED_DUMMY_RPATHS
    }
    if unexpected_dummy:
        fail(f"RPATH contains unexpected scrub placeholders: {sorted(unexpected_dummy)}")

    return ":".join(
        directory for directory in directories if directory not in REVIEWED_DUMMY_RPATHS
    )


def tool_output(tool: Path, option: str, elf: Path, *values: str) -> str:
    result = subprocess.run(
        [tool, option, *values, elf],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail(f"{tool.name} {option} failed for {elf}: {result.stderr.strip()}")
    return result.stdout.rstrip("\n")


def require_rpath_tag(readelf: Path, elf: Path) -> None:
    dynamic = tool_output(readelf, "-dW", elf)
    if "(RPATH)" not in dynamic or "(RUNPATH)" in dynamic:
        fail(f"{elf} must retain DT_RPATH while removing scrub placeholders")


def install_rpath(
    patchelf: Path, readelf: Path, elf: Path, current: str, sanitized: str
) -> None:
    """Installs one already-reviewed RPATH update."""

    require_rpath_tag(readelf, elf)
    original_mode = stat.S_IMODE(elf.stat().st_mode)
    try:
        elf.chmod(original_mode | stat.S_IWUSR)
        tool_output(patchelf, "--force-rpath", elf, "--set-rpath", sanitized)
    finally:
        elf.chmod(original_mode)
    installed = tool_output(patchelf, "--print-rpath", elf)
    if installed != sanitized:
        fail(f"RPATH update did not persist for {elf}")


def plan_tree(
    patchelf: Path, root_name: str, root: Path
) -> tuple[list[tuple[Path, str, str]], set[tuple[str, str]]]:
    """Plans one output tree without changing any file."""

    plan: list[tuple[Path, str, str]] = []
    observed: set[tuple[str, str]] = set()
    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        with candidate.open("rb") as source:
            if source.read(4) != b"\x7fELF":
                continue
        current = tool_output(patchelf, "--print-rpath", candidate)
        sanitized = sanitize_rpath(current)
        relative = candidate.relative_to(root).as_posix()
        for directory in current.split(":") if current else []:
            if directory.startswith(DUMMY_STORE_PREFIX):
                observed.add((f"{root_name}/{relative}", directory))
        if sanitized != current:
            plan.append((candidate, current, sanitized))

    return plan, observed


def plan_sanitization(
    patchelf: Path, roots: dict[str, Path]
) -> list[tuple[Path, str, str]]:
    """Requires the exact two-root reviewed inventory before any mutation."""

    if frozenset(roots) != REQUIRED_ROOT_NAMES:
        fail(f"root names must be exactly {sorted(REQUIRED_ROOT_NAMES)}")

    plan: list[tuple[Path, str, str]] = []
    observed: set[tuple[str, str]] = set()
    for root_name in sorted(roots):
        root_plan, root_observed = plan_tree(patchelf, root_name, roots[root_name])
        plan.extend(root_plan)
        observed.update(root_observed)

    missing = REVIEWED_DUMMY_LOCATIONS - observed
    unexpected = observed - REVIEWED_DUMMY_LOCATIONS
    if missing or unexpected:
        fail(
            "reviewed scrub-placeholder inventory drifted: "
            f"missing={sorted(missing)} unexpected={sorted(unexpected)}"
        )
    return plan


def apply_plan(
    patchelf: Path,
    readelf: Path,
    plan: list[tuple[Path, str, str]],
) -> None:
    """Applies a fully validated plan after rejecting pre-mutation drift."""

    for elf, current, _ in plan:
        if tool_output(patchelf, "--print-rpath", elf) != current:
            fail(f"RPATH changed after planning and before mutation: {elf}")
    for elf, current, sanitized in plan:
        install_rpath(patchelf, readelf, elf, current, sanitized)


def parse_root(value: str) -> tuple[str, Path]:
    """Parses a named output root in the form NAME=PATH."""

    name, separator, path = value.partition("=")
    if not separator or name not in REQUIRED_ROOT_NAMES or not path:
        fail(f"invalid named root {value!r}")
    return name, Path(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patchelf", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--root", action="append", required=True)
    arguments = parser.parse_args()

    roots: dict[str, Path] = {}
    for raw_root in arguments.root:
        name, root = parse_root(raw_root)
        if name in roots:
            fail(f"duplicate named root {name!r}")
        roots[name] = root

    plan = plan_sanitization(arguments.patchelf, roots)
    apply_plan(arguments.patchelf, arguments.readelf, plan)


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        fail(str(error))
