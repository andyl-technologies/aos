"""Removes device-mapper's reviewed post-scrub RPATH placeholders."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import subprocess


DUMMY_STORE_PREFIX = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-"
REVIEWED_DUMMY_RPATHS = frozenset(
    {
        f"{DUMMY_STORE_PREFIX}libselinux-3.10/lib",
        f"{DUMMY_STORE_PREFIX}libsepol-3.10/lib",
        f"{DUMMY_STORE_PREFIX}pcre2-10.47/lib",
    }
)


def fail(message: str) -> "None":
    raise SystemExit(f"aos-device-mapper-rpath-sanitize: {message}")


def split_rpath(rpath: str) -> list[str]:
    """Returns validated RPATH entries without accepting current-directory lookup."""

    if not rpath:
        return []

    directories = rpath.split(":")
    if any(not directory for directory in directories):
        fail("RPATH contains an empty current-directory entry")
    return directories


def dummy_directories(rpath: str) -> set[str]:
    """Returns nuke-refs placeholders from a validated RPATH."""

    return {
        directory
        for directory in split_rpath(rpath)
        if directory.startswith(DUMMY_STORE_PREFIX)
    }


def sanitize_rpath(rpath: str) -> str:
    """Returns an RPATH with only exact reviewed dummy entries removed."""

    directories = split_rpath(rpath)
    unexpected = dummy_directories(rpath) - REVIEWED_DUMMY_RPATHS
    if unexpected:
        fail(f"RPATH contains unexpected scrub placeholders: {sorted(unexpected)}")

    return ":".join(
        directory for directory in directories if directory not in REVIEWED_DUMMY_RPATHS
    )


def require_exact_review(discovered: set[str]) -> None:
    """Rejects stale or incomplete knowledge of device-mapper's placeholders."""

    missing = REVIEWED_DUMMY_RPATHS - discovered
    unexpected = discovered - REVIEWED_DUMMY_RPATHS
    if missing or unexpected:
        fail(
            "reviewed scrub-placeholder inventory drifted: "
            f"missing={sorted(missing)}, unexpected={sorted(unexpected)}"
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


def elf_rpaths(patchelf: Path, root: Path) -> list[tuple[Path, str, str]]:
    """Collects ELF RPATHs and their proposed sanitized values."""

    plans: list[tuple[Path, str, str]] = []
    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        with candidate.open("rb") as source:
            if source.read(4) != b"\x7fELF":
                continue

        current = tool_output(patchelf, "--print-rpath", candidate)
        plans.append((candidate, current, sanitize_rpath(current)))
    return plans


def sanitize_tree(patchelf: Path, readelf: Path, root: Path) -> None:
    plans = elf_rpaths(patchelf, root)
    discovered = {
        directory
        for _, current, _ in plans
        for directory in dummy_directories(current)
    }
    require_exact_review(discovered)

    for elf, current, sanitized in plans:
        if sanitized == current:
            continue

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
        if dummy_directories(installed):
            fail(f"scrub placeholder remains in RPATH for {elf}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patchelf", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args()

    sanitize_tree(arguments.patchelf, arguments.readelf, arguments.root)


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        fail(str(error))
