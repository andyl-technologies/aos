"""Extracts the real helper from the unpacked package and its original tarball."""

import os
from pathlib import Path
import tarfile


def extract_helper(source):
    start = source.index("static int wait_for_pid(")
    end = source.index("\nstatic int open_userns(", start)
    helper = source[start:end]
    assert helper.count("static int get_userns_fd_from_idmap(") == 1
    return helper


with tarfile.open(os.environ["src"], "r:xz") as archive:
    members = [
        item
        for item in archive.getmembers()
        if item.name.endswith("/libmount/src/hook_idmap.c")
    ]
    assert len(members) == 1, members
    original = archive.extractfile(members[0]).read().decode()

corrected = Path("libmount/src/hook_idmap.c").read_text()
Path("original-idmap.h").write_text(extract_helper(original))
Path("corrected-idmap.h").write_text(extract_helper(corrected))
assert extract_helper(original) != extract_helper(corrected)
