"""Remove opaque downloaded artifacts from Envoy's Bazel source inputs."""

import argparse
import json
import os
import shutil
import zipfile
from pathlib import Path


OPAQUE_SUFFIXES = {
    ".a",
    ".bin",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".jar",
    ".o",
    ".obj",
    ".pyc",
    ".so",
    ".syso",
    ".wasm",
    ".whl",
}
COMPILED_MAGIC = (
    b"\x7fELF",
    b"\x00asm",
    b"!<arch>\n",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)


def contains_opaque_zip_member(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return any(
                Path(member.filename).suffix.lower() in OPAQUE_SUFFIXES
                for member in archive.infolist()
            )
    except (OSError, zipfile.BadZipFile):
        # Malformed ZIPs are common parser test inputs and cannot be executed.
        return False


def is_opaque(path: Path) -> bool:
    if path.suffix.lower() in OPAQUE_SUFFIXES:
        return True

    with path.open("rb") as source:
        magic = source.read(16)

    if magic.startswith(COMPILED_MAGIC):
        return True

    return magic.startswith(b"PK\x03\x04") and contains_opaque_zip_member(path)


def clean(root: Path) -> list[str]:
    # Every fetched repository has already been copied into this tree. Bazel
    # consumes repository overrides offline, so archived cache copies would
    # only preserve binaries that the source repositories have discarded.
    shutil.rmtree(root / "repository_cache")
    (root / "repository_cache").mkdir()

    removed = []
    for directory, _, filenames in os.walk(root, followlinks=False):
        for filename in filenames:
            path = Path(directory) / filename
            if path.is_symlink() or not is_opaque(path):
                continue

            removed.append(str(path.relative_to(root)))
            path.unlink()

    return sorted(removed)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()

    removed = clean(args.root)
    report = args.root / "aos-source-cleanup.json"
    report.write_text(json.dumps({"removed": removed}, indent=2) + "\n")

    if any(
        is_opaque(path)
        for path in args.root.rglob("*")
        if path.is_file() and not path.is_symlink()
    ):
        raise SystemExit("opaque Bazel inputs remain after cleanup")


if __name__ == "__main__":
    main()
