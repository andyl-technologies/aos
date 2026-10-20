"""Transfer only the four independently inventoried publisher source files.

Chunks are transport setup, not a Native payload observation. A source file is
usable only after its complete measured count and SHA match the original client
inventory. Partial files remain private and are never retried or overwritten.
"""

import base64
import hashlib
import os
from pathlib import Path
import stat

from bridge import private_directory


LEAVES = {"pack.bin": 8 * 1024 * 1024, "index.bin": 4 * 1024 * 1024,
    "metadata-0.bin": 256 * 1024, "metadata-1.bin": 256 * 1024}
CHUNK_BYTES = 128 * 1024


def transfer_chunk(root, selected):
    if set(selected) != {"leaf", "offset", "body", "bytes", "sha256", "final"}:
        raise ValueError("publisher chunk schema differs")
    leaf = selected["leaf"]
    maximum = LEAVES.get(leaf)
    if (maximum is None or type(selected["offset"]) is not int
            or type(selected["bytes"]) is not int or not 0 < selected["bytes"] <= maximum
            or type(selected["final"]) is not bool):
        raise ValueError("publisher chunk coordinate differs")
    body = base64.b64decode(selected["body"], validate=True)
    if not 0 < len(body) <= CHUNK_BYTES or not 0 <= selected["offset"] < selected["bytes"]:
        raise ValueError("publisher chunk exceeds its fixed bound")
    directory = private_directory(Path(root) / "source")
    partial = directory / (leaf + ".partial")
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_CREAT | os.O_EXCL if selected["offset"] == 0 else os.O_APPEND
    descriptor = os.open(partial, flags, 0o600)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size != selected["offset"]
                or before.st_size + len(body) > selected["bytes"]):
            raise ValueError("publisher partial custody or offset differs")
        with os.fdopen(os.dup(descriptor), "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        count = os.fstat(descriptor).st_size
    finally:
        os.close(descriptor)
    if not selected["final"]:
        if count >= selected["bytes"]:
            raise ValueError("publisher final chunk was not declared")
        return {"partialBytes": count, "reference": None}
    if count != selected["bytes"]:
        raise ValueError("publisher final count differs")
    descriptor = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if (digest != selected["sha256"] or any(getattr(before, key) != getattr(after, key)
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("publisher immutable source changed")
    destination = directory / leaf
    # link is create-only; the brief two-link transition is owned here. Both
    # names stay private and the final single-link file is checked afterward.
    os.link(partial, destination, follow_symlinks=False)
    partial.unlink()
    final = destination.lstat()
    if final.st_nlink != 1 or final.st_ino != before.st_ino or final.st_size != count:
        raise ValueError("publisher final custody differs")
    return {"partialBytes": count,
        "reference": {"file": str(destination), "bytes": count, "sha256": digest}}
