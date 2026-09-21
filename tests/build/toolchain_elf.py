"""Checks recorded ELF loaders and shared-library searches at a tier boundary."""

from pathlib import Path
import re
import subprocess


def inspect_elf(path, roots, readelf, default_library_paths=()):
    """Returns dependencies that escape the exported tier or need ambient paths."""
    result = subprocess.run(
        [str(readelf), "--wide", "--program-headers", "--dynamic", str(path)],
        env={"PATH": "/nonexistent", "LC_ALL": "C"},
        capture_output=True, text=True, timeout=30, check=True,
    )
    return inspect_loader_output(path, roots, result.stdout, default_library_paths)


def inspect_loader_output(path, roots, output, default_library_paths=()):
    """Resolves readelf's loader records without executing the inspected binary."""
    def belongs(candidate):
        resolved = candidate.resolve(strict=True)
        return any(resolved == root or root in resolved.parents for root in roots)

    reasons = []
    loader = re.search(r"Requesting program interpreter: ([^\]]+)\]", output)
    search_paths = list(default_library_paths)
    if loader:
        interpreter = Path(loader.group(1))
        if not interpreter.is_absolute() or not belongs(interpreter):
            reasons.append(f"ELF interpreter leaves exported tier: {interpreter}")
        else:
            search_paths.append(interpreter.parent)

    recorded_paths = re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]", output)
    for record in recorded_paths:
        for entry in record.split(":"):
            expanded = entry.replace("${ORIGIN}", str(path.parent)).replace("$ORIGIN", str(path.parent))
            directory = Path(expanded)
            if not entry or "$" in expanded or not directory.is_absolute():
                reasons.append(f"ambient or unsupported ELF library path: {entry}")
            elif not belongs(directory):
                reasons.append(f"ELF library path leaves exported tier: {entry}")
            else:
                search_paths.append(directory)

    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", output)
    for library in needed:
        if "/" in library:
            candidate = Path(library)
            resolved = candidate.is_absolute() and belongs(candidate)
        else:
            resolved = any(
                (directory / library).is_file() and belongs(directory / library)
                for directory in search_paths
            )
        if not resolved:
            reasons.append(f"ELF dependency has no recorded same-tier resolution: {library}")
    return reasons
