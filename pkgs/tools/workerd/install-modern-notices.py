"""Retain upstream notices from the pinned Workers dependency source snapshot."""

import argparse
from pathlib import Path
import re
import shutil


def install_notices(dependencies, pyodide, destination):
    """Copy source notices without treating the inventory as a license conclusion."""
    notice_name = re.compile(r"^(licen[sc]e|copying|copyright|notice)([._-].*)?$", re.I)
    destination.mkdir(parents=True, exist_ok=True)
    copied = []
    for repository in sorted(dependencies.iterdir()):
        if not repository.is_dir() or repository.name == "repository_cache":
            continue
        for source in sorted(repository.rglob("*")):
            if not source.is_file() or not notice_name.fullmatch(source.name):
                continue
            relative = source.relative_to(dependencies)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            copied.append(relative.as_posix())

    # Cap'n Proto carries its MIT notices in source headers rather than a
    # separate license file. Preserve each distinct leading copyright block.
    capnp = dependencies / "+http+capnp-cpp"
    notices = set()
    for source in sorted((capnp / "src").rglob("*")):
        if not source.is_file() or source.suffix not in {".h", ".c++"}:
            continue
        lines = source.read_text().splitlines()
        if not lines or not lines[0].startswith("// Copyright"):
            continue
        end = next(
            (index for index, line in enumerate(lines) if not line.startswith("//")),
            len(lines),
        )
        notices.add("\n".join(lines[:end]) + "\n")
    if not notices or not copied:
        raise RuntimeError("Expected dependency notices and Cap'n Proto source notices")
    capnp_target = destination / "+http+capnp-cpp" / "SOURCE-NOTICES"
    capnp_target.parent.mkdir(parents=True, exist_ok=True)
    capnp_target.write_text("\n".join(sorted(notices)))

    shutil.copytree(pyodide / "share/licenses/workerd-pyodide", destination / "pyodide")
    (destination / "README").write_text(
        "Upstream notices retained from the pinned dependency source snapshot.\n"
        "This inventory includes build dependencies and optional components;\n"
        "it does not assert that every component is linked into the runtime.\n"
        "Cap'n Proto notices are extracted from its source headers.\n"
        "Pyodide notices cover its separately source-built embedded runtime.\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dependencies", type=Path)
    parser.add_argument("pyodide", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    install_notices(args.dependencies, args.pyodide, args.destination)


if __name__ == "__main__":
    main()
