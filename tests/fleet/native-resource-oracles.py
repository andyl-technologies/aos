"""Reads live resource ownership from native backend receipts and substrate.

Receipts come from the actual handler's protected state directory. They are
observations of its ownership claims, separate from the desired graph and
activation journal. File bytes and metadata are checked independently.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


MAX_RECEIPTS = 4096
MAX_RECEIPT_BYTES = 256 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024


def private_receipts(root: Path) -> list[dict[str, Any]]:
    """Reads a bounded inventory of actual protected native ownership records."""
    if not root.exists():
        return []
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("native receipt directory is not protected")
    paths = sorted(root.glob("*.json"))
    if len(paths) > MAX_RECEIPTS:
        raise ValueError("native ownership inventory exceeds its receipt limit")
    receipts = []
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("native ownership receipt is not protected")
            contents = source.read(MAX_RECEIPT_BYTES + 1)
        if len(contents) > MAX_RECEIPT_BYTES:
            raise ValueError("native ownership receipt exceeds its byte limit")
        receipt = json.loads(contents)
        if not isinstance(receipt, dict) or not isinstance(receipt.get("id"), str) or not receipt["id"]:
            raise ValueError("native receipt has no actual owning effect identity")
        receipts.append(receipt)
    return receipts


def file_snapshot(path: Path, receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Observes exact file bytes and actual claims on the selected path."""
    owners = sorted({receipt["id"] for receipt in receipts if str(path) in {receipt.get("path"), receipt.get("previous_path")}})
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"exists": False, "owners": owners}
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("file oracle encountered a non-regular resource")
        contents = source.read(MAX_FILE_BYTES + 1)
    if len(contents) > MAX_FILE_BYTES:
        raise ValueError("live file exceeds the oracle byte limit")
    return {
        "exists": True,
        "owners": owners,
        "digest": "sha256:" + hashlib.sha256(contents).hexdigest(),
        "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def observe_configuration(selected: Path, foreign: Path, root: Path = Path("/var/lib/aos/native-service-effects")) -> dict[str, Any]:
    """Collects configuration ownership and a separate foreign file snapshot."""
    receipts = private_receipts(root)
    return {"selected": file_snapshot(selected, receipts), "foreign": file_snapshot(foreign, receipts)}
