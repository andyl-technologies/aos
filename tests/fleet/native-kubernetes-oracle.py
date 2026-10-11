"""Observes Kubernetes objects and K3s files independently of activation state.

Only live API objects and protected filesystem bytes supply ownership facts.
Desired graphs, handler outputs, and activation journals are not oracle inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

OWNER = "aos.andyl.com/object-set-owner"
REVISION = "aos.andyl.com/object-revision"
MARKER_ROOT = Path("/var/lib/aos/native-dependency-barrier")
MAXIMUM_BYTES = 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch


def digest(contents: bytes) -> str:
    """Hashes actual bounded resource bytes without exporting their contents."""
    return "sha256:" + hashlib.sha256(contents).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def object_projection(document: Any, namespace: str, name: str) -> dict[str, Any]:
    """Projects actual ConfigMap identity, ownership annotations, and payload."""
    if document is None:
        return {"exists": False, "owners": []}
    if not isinstance(document, dict) or document.get("apiVersion") != "v1" or document.get("kind") != "ConfigMap":
        raise ValueError("oracle received another Kubernetes resource kind")
    metadata = document.get("metadata", {})
    if metadata.get("namespace") != namespace or metadata.get("name") != name:
        raise ValueError("oracle received another Kubernetes resource identity")
    uid = metadata.get("uid")
    if not isinstance(uid, str) or not 1 <= len(uid) <= 256:
        raise ValueError("live Kubernetes object lacks a bounded UID")
    annotations = metadata.get("annotations", {})
    owner = annotations.get(OWNER)
    revision = annotations.get(REVISION)
    if owner is not None and (not isinstance(owner, str) or DIGEST(owner) is None):
        raise ValueError("live Kubernetes ownership annotation is malformed")
    if revision is not None and (not isinstance(revision, str) or len(revision) > 256):
        raise ValueError("live Kubernetes revision annotation is malformed")
    return {
        "exists": True,
        "uid": uid,
        "owners": [] if owner is None else [owner],
        "contentDigest": digest(canonical({key: document.get(key, {}) for key in ("data", "binaryData")})),
        "labelsDigest": digest(canonical(metadata.get("labels", {}))),
    }


def read_object(kubectl: str, kubeconfig: str, namespace: str, name: str, *, foreign: bool = False) -> dict[str, Any]:
    """Reads a named live object; API errors never become an absent resource."""
    result = subprocess.run(
        [kubectl, "--kubeconfig", kubeconfig, "--namespace", namespace,
         "get", "configmap", name, "--ignore-not-found", "--output=json"],
        check=True, capture_output=True,
    )
    if len(result.stdout) > MAXIMUM_BYTES:
        raise ValueError("Kubernetes oracle response exceeds its byte bound")
    document = json.loads(result.stdout) if result.stdout.strip() else None
    projection = object_projection(document, namespace, name)
    if foreign and document is not None:
        projection["annotationsDigest"] = digest(canonical(document["metadata"].get("annotations", {})))
    return projection


def file_projection(path: str) -> dict[str, Any]:
    """Reads a regular protected file without following a replaced symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {"exists": False}
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAXIMUM_BYTES:
            raise ValueError("K3s oracle path is not a bounded regular file")
        contents = stream.read(MAXIMUM_BYTES + 1)
    if len(contents) > MAXIMUM_BYTES:
        raise ValueError("K3s oracle file grew beyond its byte bound")
    return {"exists": True, "digest": digest(contents), "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid, "gid": metadata.st_gid}


def configuration_projection(path: str) -> dict[str, Any]:
    """Checks a physical configuration marker against actual file bytes."""
    if Path(path).parent != Path("/run/aos/k3s") or Path(path).suffix != ".json":
        raise ValueError("K3s oracle selected path escapes its fixture domain")
    selected = file_projection(path)
    marker_path = str(Path(path).with_suffix(".state.json"))
    marker = file_projection(marker_path)
    if not selected["exists"]:
        if marker["exists"]:
            raise ValueError("removed K3s configuration retains an ownership marker")
        return {"exists": False, "owners": []}
    if not marker["exists"]:
        return selected | {"owners": [], "claimMatches": False}
    # Reopen through the same no-follow discipline; bounded metadata above does
    # not authorize a later symlink replacement or a growing document.
    descriptor = os.open(marker_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        contents = stream.read(MAXIMUM_BYTES + 1)
    if len(contents) > MAXIMUM_BYTES:
        raise ValueError("K3s marker exceeds its byte bound")
    state = json.loads(contents)
    if not isinstance(state, dict) or state.get("schema") != "aos.k3s.configuration-state/v1":
        raise ValueError("K3s marker has an unsupported schema")
    return selected | {"owners": ["configuration:" + marker_path],
                       "claimMatches": state.get("content_digest") == selected["digest"]}


def dependency_projection(path: str) -> dict[str, Any]:
    """Reads the independent protected marker's real claim and inode identity."""
    if Path(path).parent != MARKER_ROOT:
        raise ValueError("dependency marker escapes its fixture domain")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {"exists": False, "owners": []}
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError("dependency marker is not a protected regular file")
        contents = stream.read(16385)
    if len(contents) > 16384:
        raise ValueError("dependency marker claim exceeds its bound")
    claim = json.loads(contents)
    if not isinstance(claim, dict) or set(claim) != {"effect", "revision"} or not all(
        isinstance(claim[key], str) and 0 < len(claim[key].encode()) <= 256 for key in claim
    ):
        raise ValueError("dependency marker actual claim is malformed")
    return {"exists": True, "owners": ["marker:" + claim["effect"]], "digest": digest(contents),
            "inode": metadata.st_ino, "device": metadata.st_dev,
            "uid": metadata.st_uid, "gid": metadata.st_gid, "mode": stat.S_IMODE(metadata.st_mode)}


def observe(request: dict[str, Any]) -> dict[str, Any]:
    """Combines live selected and separately managed foreign observations."""
    if request["domain"] == "nativeDependencyBarrier":
        return {"selected": dependency_projection(request["selected"]),
                "foreign": file_projection(request["foreign"])}
    if request["domain"] == "kubernetes":
        arguments = (request["kubectl"], request["kubeconfig"], request["namespace"])
        return {"selected": read_object(*arguments, request["selected"]),
                "foreign": read_object(*arguments, request["foreign"], foreign=True)}
    if request["domain"] == "k3sConfiguration":
        return {"selected": configuration_projection(request["selected"]),
                "foreign": file_projection(request["foreign"])}
    raise ValueError("Kubernetes oracle request names an unsupported domain")


if __name__ == "__main__":
    print(json.dumps(observe(json.loads(sys.argv[1])), sort_keys=True, separators=(",", ":")))
