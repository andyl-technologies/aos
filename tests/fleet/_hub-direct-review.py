"""Retain actual External fixture evidence for an independent host-side reviewer.

The opt-in fixture stops at explicit review checkpoints. A selected input must
bind the exact retained observation hashes, including the installed source and
runtime. This channel supplies reviewed operator inputs; it neither generates
observations nor signs or activates a qualification artifact.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


def _closed_review_json(body):
    """Reject duplicate fields before interpreting an independent selection."""
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("independent review contains duplicate fields")
            result[key] = value
        return result

    return json.loads(body, object_pairs_hook=object_pairs)


def await_direct_review(label, observation_hashes, selection_fields, timeout=900):
    """Require owner-private independently selected inputs for these observations."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", label):
        raise ValueError("invalid independent review checkpoint label")
    hashes = dict(observation_hashes)
    if not hashes or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()):
        raise ValueError("review checkpoint requires actual observation hashes")
    fields = set(selection_fields)
    if not fields:
        raise ValueError("review checkpoint requires explicit selected inputs")

    root = Path("independent-direct-review")
    root.mkdir(mode=0o700, exist_ok=True)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("independent review directory has invalid custody")
    request_path = root / (label + ".request.json")
    selected_path = root / (label + ".selected.json")
    request = {
        "version": 1, "checkpoint": label, "observationHashes": hashes,
        "selectionFields": sorted(fields),
        "scope": "independent operator selection only; no automatic runtime acceptance",
    }
    request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(request_bytes)
        output.flush()
        os.fsync(output.fileno())
    request_hash = hashlib.sha256(request_bytes).hexdigest()
    print("Independent External review requested:", str(request_path.resolve()),
          request_hash, "selection:", str(selected_path.resolve()), flush=True)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            descriptor = os.open(selected_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            time.sleep(1)
            continue
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077 or metadata.st_size > 65536
            ):
                raise ValueError("independent selected input has invalid custody or size")
            body = source.read(65537)
            last = os.fstat(source.fileno())
            if len(body) != metadata.st_size or any(
                getattr(metadata, field) != getattr(last, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            ):
                raise ValueError("independent selected input changed during capture")
        selected = _closed_review_json(body)
        if set(selected) != {"version", "checkpoint", "requestSha256", "reviewSha256", "selection"}:
            raise ValueError("independent selected input differs from the closed schema")
        if (
            type(selected["version"]) is not int or selected["version"] != 1
            or selected["checkpoint"] != label
            or selected["requestSha256"] != request_hash
            or not re.fullmatch(r"[0-9a-f]{64}", selected["reviewSha256"])
            or not isinstance(selected["selection"], dict)
            or set(selected["selection"]) != fields
        ):
            raise ValueError("independent selection does not bind these exact observations")
        print("Independent External selection retained:", label,
              hashlib.sha256(body).hexdigest(), flush=True)
        return selected

    raise RuntimeError("independent External review remains pending; actual observations retained")
