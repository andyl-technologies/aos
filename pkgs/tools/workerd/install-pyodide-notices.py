"""Retain upstream notices for the sources embedded in the Pyodide runtime."""

import os
from pathlib import Path
import shutil
import tarfile
import zipfile


def source_file(component, relative):
    """Read an exact source member, rejecting unexpected archive layouts."""
    source = os.environ[f"PYODIDE_{component.upper()}_SRC"]
    if component == "bzip2":
        with zipfile.ZipFile(source) as archive:
            matches = [name for name in archive.namelist() if name.split("/", 1)[-1] == relative]
            if len(matches) != 1:
                raise RuntimeError(f"Missing or ambiguous {component}/{relative}")
            return archive.read(matches[0])

    with tarfile.open(source) as archive:
        matches = [member for member in archive if member.isfile() and member.name.split("/", 1)[-1] == relative]
        if len(matches) != 1:
            raise RuntimeError(f"Missing or ambiguous {component}/{relative}")
        with archive.extractfile(matches[0]) as member:
            return member.read()


destination = Path(os.environ["out"]) / "share/licenses/workerd-pyodide"
destination.mkdir(parents=True, exist_ok=True)
shutil.copyfile("LICENSE", destination / "LICENSE")

notices = {
    "python": ["LICENSE", "Modules/expat/COPYING"],
    "libffi": ["LICENSE"],
    "hiwire": ["LICENSE"],
    "xz": ["COPYING", "COPYING.LGPLv2.1", "COPYING.GPLv2", "COPYING.GPLv3"],
    "zstd": ["LICENSE", "COPYING"],
    "bzip2": ["LICENSE"],
}
for component, paths in notices.items():
    for relative in paths:
        target = destination / component / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_file(component, relative))

# These libraries place their notices in source headers, not separate licenses.
for component, relative, marker in [
    ("zlib", "zlib.h", b"/*"),
    ("sqlite", "sqlite3.c", b"/*\n** 2001 September 15"),
]:
    data = source_file(component, relative)
    start = data.index(marker)
    end = data.index(b"*/", start) + 2
    (destination / f"{component}-NOTICE").write_bytes(data[start:end] + b"\n")

emscripten = Path(os.environ["PYODIDE_EMSCRIPTEN"]) / "libexec/emscripten"
for relative in [
    "LICENSE",
    "system/lib/libc/musl/COPYRIGHT",
    "system/lib/libcxx/LICENSE.TXT",
    "system/lib/libcxxabi/LICENSE.TXT",
    "system/lib/compiler-rt/LICENSE.TXT",
    "system/lib/libunwind/LICENSE.TXT",
]:
    target = destination / "emscripten" / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(emscripten / relative, target)
