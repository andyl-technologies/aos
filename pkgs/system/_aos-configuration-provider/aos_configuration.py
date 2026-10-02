"""Portable durable configuration reconciliation shared with service handlers.

Receipts claim absolute resource paths across all cooperating native handlers.
Pending writes retain prior destination evidence until cleanup is synchronized.
"""

import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
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


def toml_value(value):
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return json.dumps(value, allow_nan=False)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(key) + " = " + toml_value(item) for key, item in value.items() if item is not None) + "}"
    raise ValueError("unsupported TOML value")


def serialize_toml(value):
    if not isinstance(value, dict):
        raise ValueError("TOML configuration must be an object")
    lines = []

    def table(current, path):
        if path:
            lines.extend(["", "[" + ".".join(json.dumps(key) for key in path) + "]"])
        for key, item in current.items():
            if item is not None and not isinstance(item, dict):
                lines.append(json.dumps(key) + " = " + toml_value(item))
        for key, item in current.items():
            if isinstance(item, dict):
                table(item, path + [key])

    table(value, [])
    return "\n".join(lines) + "\n"


def configuration_bytes(value):
    format = value.get("format", "text")
    if format == "json":
        return (json.dumps(value["value"], ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if format == "toml":
        return serialize_toml(value["value"]).encode()
    if value.get("content") is not None:
        return checked_text(value["content"]).encode()
    fragments = []
    for fragment in value.get("fragments", []):
        if isinstance(fragment, str):
            fragments.append(fragment.encode())
        else:
            path = absolute(fragment["credentialPath"])
            limit = fragment["maximumBytes"]
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(descriptor, "rb") as credential:
                metadata = os.fstat(credential.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("credential content source is not a regular file")
                contents = credential.read(limit + 1)
            if len(contents) > limit:
                raise ValueError("credential content exceeds configured limit")
            fragments.append(contents)
    return b"".join(fragments)


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


def file_identity(value):
    """Resolves optional account names without changing an unspecified identity."""
    owner = value.get("owner")
    group = value.get("group")
    uid = pwd.getpwnam(owner).pw_uid if owner is not None else -1
    gid = grp.getgrnam(group).gr_gid if group is not None else -1
    return uid, gid


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


class ConfigurationHandler:
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
        # Pending receipts retain both destinations until retirement is durable.
        value = dict(value)
        if value.get("kind") == "configuration":
            value["owned_paths"] = sorted({
                value["path"], *([value["previous_path"]] if value.get("previous_path") else []),
            })
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

    def file_results(self, path, contents):
        return {"path": str(path), "resource": "configuration:" + digest(str(path).encode()) + ":" + digest(contents)}

    def file(self, action):
        path = owned_path(self.value["path"])
        contents = configuration_bytes(self.value)
        expected = digest(contents)
        current = read_digest(path)
        if action == "observe" and self.invocation.get("action") == "remove":
            if self.receipt is None:
                return {"status": "absent" if current is None else "indeterminate"}
            owned = {self.receipt["path"]: {self.receipt["digest"], self.receipt.get("previous_digest")}}
            if self.receipt.get("previous_path"):
                owned[self.receipt["previous_path"]] = {self.receipt.get("previous_path_digest")}
            observed = {name: read_digest(owned_path(name)) for name in owned}
            if any(value is not None and value not in owned[name] for name, value in observed.items()):
                return {"status": "indeterminate"}
            if all(value is None for value in observed.values()):
                self.finish_remove()
                return {"status": "absent"}
            return {"status": "retry-safe"}
        if action == "observe":
            uid, gid = file_identity(self.value)
            if current == expected and self.receipt and self.receipt.get("digest") == expected and not self.receipt.get("pending"):
                metadata = os.stat(path, follow_symlinks=False)
                identity_matches = (uid == -1 or metadata.st_uid == uid) and (gid == -1 or metadata.st_gid == gid)
                if identity_matches and stat.S_IMODE(metadata.st_mode) == mode(self.value["mode"]):
                    return {"status": "current", "outputs": self.file_results(path, contents)}
            if current is None and self.receipt is None:
                return {"status": "absent"}
            safe = current in {None, expected, (self.receipt or {}).get("digest"), (self.receipt or {}).get("previous_digest")}
            return {"status": "retry-safe" if safe else "indeterminate"}
        if action == "remove":
            if self.receipt is None:
                if current is None:
                    return {}
                raise ValueError("configuration removal has no ownership receipt")
            owned = {
                self.receipt["path"]: {self.receipt["digest"], self.receipt.get("previous_digest")},
            }
            if self.receipt.get("previous_path"):
                old_path = self.receipt["previous_path"]
                owned.setdefault(old_path, set()).add(self.receipt.get("previous_path_digest"))
            for name, allowed in owned.items():
                if read_digest(owned_path(name)) not in allowed | {None}:
                    raise ValueError("configuration was modified outside its owning effect")
            for name in owned:
                durable_unlink(owned_path(name))
            return self.finish_remove()
        if current not in {None, expected, (self.receipt or {}).get("digest"), (self.receipt or {}).get("previous_digest")}:
            raise ValueError("configuration destination conflicts with externally modified data")
        previous = self.receipt or {}
        # A retry must retain the old destination until its deletion is durable.
        old_path = previous.get("previous_path") if previous.get("pending") else previous.get("path")
        old_digest = previous.get("previous_path_digest") if previous.get("pending") else previous.get("digest")
        uid, gid = file_identity(self.value)
        self.claim_paths([str(path)])
        self.save({"kind": "configuration", "path": str(path), "digest": expected, "previous_digest": current, "pending": True, "previous_path": old_path, "previous_path_digest": old_digest})
        durable_write(path, contents, mode(self.value["mode"]))
        if uid != -1 or gid != -1:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if old_path and old_path != str(path):
            old = owned_path(old_path)
            if read_digest(old) not in {None, old_digest}:
                raise ValueError("previous configuration path changed outside its effect")
            durable_unlink(old)
        self.save({"kind": "configuration", "path": str(path), "digest": expected, "pending": False})
        return self.file_results(path, contents)


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
