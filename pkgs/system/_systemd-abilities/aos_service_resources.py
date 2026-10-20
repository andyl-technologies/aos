"""Durable resource ownership and IO for systemd service handlers.

Receipts claim absolute resource paths across all cooperating native handlers.
Pending writes retain prior destination evidence until cleanup is synchronized.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


def checked_text(value):
    if not isinstance(value, str) or "\0" in value:
        raise ValueError("expected a resolved string without NUL")
    return value


def absolute(value):
    value = checked_text(value)
    if not value.startswith("/") or ".." in Path(value).parts:
        raise ValueError("expected a normalized absolute path")
    return value


def mode(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-7]{3,4}", value):
        raise ValueError("invalid octal mode")
    return int(value, 8)


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


def synchronize_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_unlink(path):
    path = Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    synchronize_directory(path.parent)


def durable_write(path, contents, permissions=0o644):
    """Publishes fully synchronized contents without following a destination link."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".aos-native-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), permissions)
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        synchronize_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_digest(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("owned resource is not a regular file")
        return digest(source.read())


def owned_path(path):
    path = absolute(path)
    if path.startswith("/nix/store/"):
        raise ValueError("native mutation cannot modify immutable store artifacts")
    return Path(path)


class ResourceHandler:
    """Retains file ownership evidence before mutating any destination."""

    def __init__(self, invocation, state_directory):
        self.invocation = invocation
        self.value = invocation["input"]
        self.state_directory = Path(state_directory)
        self.receipt_path = self.state_directory / (digest(invocation["id"].encode()) + ".json")
        self.receipt = json.loads(self.receipt_path.read_text()) if self.receipt_path.exists() else None
        if self.receipt and self.receipt["id"] != invocation["id"]:
            raise ValueError("native ownership receipt identity differs")

    def save(self, value):
        self.state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        value = dict(value)
        for path in value["owned_paths"]:
            owned_path(path)
        value = dict(value, id=self.invocation["id"], revision=self.invocation["revision"])
        durable_write(self.receipt_path, json.dumps(value, sort_keys=True).encode(), 0o600)
        self.receipt = value

    def finish_remove(self):
        durable_unlink(self.receipt_path)
        return {}

    def claim_paths(self, paths):
        paths = set(paths)
        if not self.state_directory.exists():
            return
        for receipt_path in self.state_directory.glob("*.json"):
            if receipt_path == self.receipt_path:
                continue
            other = json.loads(receipt_path.read_text())
            if paths.intersection(other["owned_paths"]):
                raise ValueError("native resource is owned by another installation effect")


def read_invocation():
    """Reads the bounded native invocation without interpreting another protocol."""
    raw = sys.stdin.buffer.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("native invocation exceeds limit")
    return json.loads(raw)


def locked_dispatch(state_directory, dispatch):
    """Serializes cooperating resource claims and mutations in one namespace."""
    state_directory = Path(state_directory)
    state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(state_directory / ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return dispatch(state_directory)
