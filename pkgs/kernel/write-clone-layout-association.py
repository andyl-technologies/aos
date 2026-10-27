"""Writes build-only provenance for the selected kernel's FD-table facts.

The facts come from the configured target compiler. This file never samples a
running kernel or grants permission to use them; native consumers must match
the running kernel's notes under their own retained receiving owner.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


PREFIX = "AOS_KERNEL_CLONE_V1_"
FACTS = {
    "FORMAT",
    "FILES_STRUCT_BYTES",
    "FDTABLE_BYTES",
    "FILE_POINTER_BYTES",
    "ULONG_BYTES",
    "BITS_PER_LONG",
    "NR_OPEN_DEFAULT",
    "L1_CACHE_BYTES",
    "PAGE_BYTES",
}


def checked_layout(header: Path) -> None:
    """Requires the exact finite target-compiled fact vocabulary."""
    values = {}
    for line in header.read_text().splitlines():
        if not line.startswith("#define " + PREFIX):
            continue
        match = re.fullmatch(
            r"#define " + PREFIX + r"([A-Z0-9_]+)\s+(0x[0-9a-fA-F]+|[0-9]+)(?:\s+/\*.*\*/)?\s*",
            line,
        )
        if match is None or match[1] in values:
            raise ValueError("invalid or duplicate target-compiled kernel fact")
        value = int(match[2], 0)
        if not 0 < value < 1 << 64:
            raise ValueError("target-compiled kernel fact is not a positive u64")
        values[match[1]] = value

    if set(values) != FACTS or values["FORMAT"] != 1:
        raise ValueError("unexpected target-compiled kernel layout vocabulary")


def digest(path: Path) -> str:
    """Hashes large kernel artifacts without collecting them in memory."""
    state = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(128 * 1024):
            state.update(block)
    return state.hexdigest()


def write_association(directory: Path, image: Path, release_file: Path) -> None:
    """Associates the facts with this build's config, image and exact notes."""
    header = directory / "aos-kernel-clone-layout-v1.h"
    notes = directory / "kernel-notes"
    checked_layout(header)

    notes_bytes = notes.stat().st_size
    if not 0 < notes_bytes < 1 << 64:
        raise ValueError("kernel notes have no finite positive extent")
    release = release_file.read_text().strip()
    if not release or "\n" in release or "\x00" in release:
        raise ValueError("invalid configured kernel release")

    provenance = {
        "format": "AOS-KERNEL-CLONE-LAYOUT-V1",
        "kernel_release": release,
        "layout_sha256": digest(header),
        "config_sha256": digest(directory / "kernel.config"),
        "notes_sha256": digest(notes),
        "kernel_image_sha256": digest(image),
        "notes_bytes": notes_bytes,
    }
    association = [
        "#ifndef AOS_KERNEL_CLONE_ASSOCIATION_V1_H",
        "#define AOS_KERNEL_CLONE_ASSOCIATION_V1_H",
        f"#define {PREFIX}NOTES_BYTES {notes_bytes}ULL",
    ]
    for macro, field in [
        ("NOTES_SHA256", "notes_sha256"),
        ("CONFIG_SHA256", "config_sha256"),
        ("IMAGE_SHA256", "kernel_image_sha256"),
        ("LAYOUT_SHA256", "layout_sha256"),
        ("KERNEL_RELEASE", "kernel_release"),
    ]:
        # JSON string escaping also supplies the required C string quoting.
        association.append(f"#define {PREFIX}{macro} {json.dumps(provenance[field])}")
    association.append("#endif")
    (directory / "aos-kernel-clone-association-v1.h").write_text("\n".join(association) + "\n")
    (directory / "provenance").write_text(json.dumps(provenance, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--release-file", type=Path, required=True)
    args = parser.parse_args()
    write_association(args.directory, args.image, args.release_file)


if __name__ == "__main__":
    main()
