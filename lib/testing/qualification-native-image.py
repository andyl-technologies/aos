"""Checks native image bundle bytes against captured assembly provenance.

The final signed UKI authenticates its rebuilt initrd. Assembly file digests
bind the unchanged native deployment documents within that archive and the
verified host root. Native runtime verification separately checks NAR admission
and durable deployment completion on the guest.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any


BUNDLE_FILES = {
    "transaction.json": "transaction",
    "packages.json": "packages",
    "admission.json": "admission",
    "admission-sha256": "admission-digest",
    "evaluation.json": "evaluation",
}
STORE_ROOT = re.compile(r"/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def store_root(path: Any) -> str:
    """Returns the immutable root of a canonical native source locator."""
    if not isinstance(path, str):
        raise RuntimeError("native source locator is not a string")
    match = STORE_ROOT.match(path)
    if match is None or (match.end() != len(path) and path[match.end()] != "/"):
        raise RuntimeError("native source locator is not an immutable store path")
    if str(pathlib.PurePosixPath(path)) != path or ".." in pathlib.PurePosixPath(path).parts:
        raise RuntimeError("native source locator escapes its immutable root")
    return match.group()


def check_file(contents: bytes, fact: dict[str, Any]) -> None:
    """Requires the exact captured file length and SHA256 identity."""
    actual = "sha256:" + hashlib.sha256(contents).hexdigest()
    if len(contents) != fact["size_bytes"] or actual != fact["sha256"]:
        raise RuntimeError("native deployment bytes differ from the captured assembly")


def validate_bundle(stage: str, documents: dict[str, bytes], files: dict[str, Any],
                    platform: str) -> dict[str, Any]:
    """Checks an image-authenticated bundle's native descriptor and custody."""
    expected = dict(BUNDLE_FILES)
    if stage == "host":
        expected["installed.json"] = "installed"
    elif stage != "initrd":
        raise RuntimeError("unsupported native deployment stage")
    if set(documents) != set(expected):
        raise RuntimeError("native deployment bundle omits or adds a document")
    for filename, purpose in expected.items():
        check_file(documents[filename], files[f"{stage}-{purpose}"])
    return validate_documents(stage, documents, platform)


def validate_documents(stage: str, documents: dict[str, bytes], platform: str) -> dict[str, Any]:
    """Checks native bundle structure after the caller authenticates its bytes.

    This function does not admit an image or scenario. Image callers bind
    captured file identities; scenario callers check original executor NAR
    inventory and independently replay the locked source descriptor.
    """
    expected = set(BUNDLE_FILES) | ({"installed.json"} if stage == "host" else set())
    if stage not in {"host", "initrd"} or set(documents) != expected:
        raise RuntimeError("native deployment bundle omits or adds a document")
    decoded = {name: json.loads(contents) for name, contents in documents.items()
               if name.endswith(".json")}
    admission = decoded["admission.json"]
    if (not isinstance(admission, dict) or set(admission) != {"schema", "roots"}
            or admission["schema"] != "aos.package.admission"):
        raise RuntimeError("image bundle has an unsupported admission catalog")
    if documents["admission-sha256"].rstrip(b"\n") != (
        "sha256:" + hashlib.sha256(documents["admission.json"]).hexdigest()
    ).encode():
        raise RuntimeError("image admission digest differs from its exact catalog")
    roots = {}
    for root in admission["roots"]:
        if (not isinstance(root, dict) or set(root) != {"storePath", "narHash", "narSize", "references"}
                or store_root(root["storePath"]) != root["storePath"]
                or DIGEST.fullmatch(root["narHash"]) is None
                or type(root["narSize"]) is not int or root["narSize"] < 0
                or root["storePath"] in roots):
            raise RuntimeError("image admission catalog repeats or malforms a NAR root")
        roots[root["storePath"]] = root
    transaction = decoded["transaction.json"]
    packages = decoded["packages.json"]
    evaluation = decoded["evaluation.json"]
    if (transaction.get("schema") != "aos.package.transaction"
            or transaction.get("system") != platform
            or transaction.get("artifacts") != packages.get("artifacts")
            or transaction.get("packages") != packages.get("modules")
            or packages.get("system") != platform
            or evaluation.get("schema") != "aos.package.evaluation-input"
            or evaluation.get("packages") != packages
            or evaluation.get("scope") != transaction.get("scope")):
        raise RuntimeError("image native transaction differs from its evaluation inputs")
    scope = transaction["scope"]
    if ((stage == "host" and scope != ["profile", "system"])
            or (stage == "initrd" and (len(scope) != 2 or scope[-1] != "initrd"))):
        raise RuntimeError("native image deployment has another execution scope")
    library = store_root(evaluation["library"])
    if roots.get(library, {}).get("narHash") != evaluation["libraryNarHash"]:
        raise RuntimeError("image evaluator library lacks its exact admitted NAR identity")
    source_paths = [artifact["path"] for artifact in packages["artifacts"]]
    source_paths += [module["configRoot"] for module in packages["modules"]]
    source_paths += evaluation["configuration"] + evaluation.get("runtimeConfiguration", [])
    supplemental = evaluation.get("supplementalInputs", [])
    source_paths += supplemental + list(evaluation.get("moduleEnvelopes", {}).values())
    source_paths += list(evaluation.get("packageEnvelopes", {}).values())
    if any(store_root(path) not in transaction["inputs"] for path in supplemental):
        raise RuntimeError("image transaction does not retain an admitted supplemental source root")
    graph = transaction["graph"]
    if graph.get("schema") != "aos.activation.graph":
        raise RuntimeError("native image deployment lacks its checked activation graph")
    source_paths += [node["handler"]["artifact"] for node in graph["nodes"].values()
                     if node["handler"]["kind"] == "process"]
    if any(store_root(path) not in roots for path in source_paths):
        raise RuntimeError("image native deployment references an unadmitted source root")
    if stage == "host":
        installed = decoded["installed.json"]
        if (not isinstance(installed, list)
                or sorted(record["store_path"] for record in installed)
                != sorted(artifact["path"] for artifact in packages["artifacts"])):
            raise RuntimeError("image profile records differ from the exact selected payload roots")
        for record in installed:
            for key in ("deployment", "module_documentation", "qualification"):
                locator = record["apm"].get(key)
                if locator is None:
                    if key == "deployment":
                        raise RuntimeError("image profile omits its original native package envelope")
                    continue
                root = roots.get(locator["store_path"])
                if root is None or any(locator[field] != root[other] for field, other in (
                    ("nar_hash", "narHash"), ("nar_size", "narSize"), ("references", "references"),
                )):
                    raise RuntimeError("image profile native artifact locator differs from admitted NAR metadata")
    return {"transaction": transaction, "packages": packages, "evaluation": evaluation,
            "admission": admission, "roots": roots}


def archive_documents(image: Any, archive: pathlib.Path, stage: str) -> dict[str, bytes]:
    """Reads exact native alias targets without extracting an untrusted archive."""
    if stage != "initrd":
        raise RuntimeError("only the initrd bundle is embedded in this archive")
    directory = "lib/aos/initrd/deployment"
    mode, contents = image.read_newc_entries(archive, {directory})[directory]
    if mode & 0o170000 == 0o120000:
        target = contents.decode()
        if store_root(target) != target:
            raise RuntimeError("native bundle directory alias is not an exact immutable store root")
        directory = target.lstrip("/")
        mode, _ = image.read_newc_entries(archive, {directory})[directory]
    if mode & 0o170000 != 0o040000:
        raise RuntimeError("native bundle has a linked or non-directory store parent")
    wanted = {name: directory + "/" + name for name in BUNDLE_FILES}
    result = {}
    for _ in range(8):
        entries = image.read_newc_entries(archive, set(wanted.values()))
        remaining = {}
        for filename, path in wanted.items():
            mode, contents = entries[path]
            kind = mode & 0o170000
            if kind == 0o100000:
                result[filename] = contents
            elif kind == 0o120000:
                target = contents.decode()
                store_root(target)
                remaining[filename] = target.lstrip("/")
            else:
                raise RuntimeError("native initrd document is neither immutable bytes nor a store alias")
        if not remaining:
            return result
        wanted = remaining
    raise RuntimeError("native initrd aliases exceed the bounded resolution depth")
