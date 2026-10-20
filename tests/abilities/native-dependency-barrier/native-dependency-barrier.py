"""Owns a tiny physical marker whose native dispatch can be observed separately."""

import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/var/lib/aos/native-dependency-barrier")
LIMIT = 16 * 1024 * 1024


def main():
    """Handles an exact apply, remove, or observation without adopting foreign files."""
    if len(sys.argv) != 2 or sys.argv[1] not in {"apply", "remove", "observe"}:
        raise ValueError("expected a native marker operation")
    payload = sys.stdin.buffer.read(LIMIT + 1)
    if len(payload) > LIMIT:
        raise ValueError("native marker invocation exceeds its bound")
    invocation = json.loads(payload)
    name = invocation["input"]["name"]
    if not isinstance(name, str) or len(name) > 128 or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None:
        raise ValueError("invalid fixture marker name")
    try:
        metadata = ROOT.lstat()
    except FileNotFoundError:
        metadata = None
        if sys.argv[1] == "apply":
            ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = ROOT.lstat()
    if metadata is not None and (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077):
        raise ValueError("fixture marker directory is not protected")
    marker = ROOT / name
    claim = {"effect": invocation["id"], "revision": invocation["revision"]}
    expected = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    try:
        descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        current = None
    else:
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
                raise ValueError("fixture marker is not protected")
            current = source.read(16385)
        if len(current) > 16384:
            raise ValueError("fixture marker claim exceeds its bound")
    if current is not None and current != expected:
        if sys.argv[1] == "observe":
            print('{"status":"indeterminate"}')
            return
        raise ValueError("fixture marker belongs to another invocation")
    outputs = {"resource": str(marker)}
    if sys.argv[1] == "observe":
        if current is not None and invocation["action"] == "apply":
            status = {"status": "current", "outputs": outputs}
        elif current is None and invocation["action"] == "remove":
            status = {"status": "absent"}
        else:
            status = {"status": "retry-safe"}
        print(json.dumps(status, sort_keys=True, separators=(",", ":")))
        return
    if sys.argv[1] != invocation["action"]:
        raise ValueError("fixture marker action disagrees with invocation")
    if sys.argv[1] == "apply" and current is None:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(expected)
            destination.flush()
            os.fsync(destination.fileno())
    if sys.argv[1] == "remove" and current is not None:
        marker.unlink()
    print(json.dumps(outputs, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
