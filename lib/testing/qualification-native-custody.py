"""Authenticates executor-authorized native scenario sources before pure replay.

Original archive and realized NAR inventory commitments come from the trusted
scenario registry. Bundle admission catalogs and runtime report digests never
provide authority for their own source bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch
STORE_ROOT = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\x00]+$").fullmatch
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024


def file_digest(path: Path) -> str:
    """Hashes original file bytes in bounded memory."""
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for contents in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(contents)
    return "sha256:" + hasher.hexdigest()


def verify_file(identity: Any, expected: Path, *, document: bool) -> bytes | None:
    """Requires the exact original immutable file selected by executor policy."""
    if (not isinstance(identity, dict) or set(identity) != {"path", "sha256", "size_bytes"}
            or identity["path"] != str(expected) or not str(expected).startswith("/nix/store/")
            or any(component in {".", ".."} for component in expected.parts)
            or not isinstance(identity["sha256"], str) or DIGEST(identity["sha256"]) is None
            or type(identity["size_bytes"]) is not int or identity["size_bytes"] <= 0
            or expected.is_symlink() or not expected.is_file()
            or expected.stat().st_size != identity["size_bytes"]
            or (document and identity["size_bytes"] > MAX_DOCUMENT_BYTES)
            or file_digest(expected) != identity["sha256"]):
        raise RuntimeError("native fixture bytes differ from the original trusted executor commitment")
    return expected.read_bytes() if document else None


def verify_fixture_inputs(registry: dict[str, Any], request: dict[str, Any],
                          paths: dict[str, Path], expected_evaluations: dict[str, Any],
                          normalize_hash: Callable[[str], str]) -> dict[str, dict[str, Any]]:
    """Checks original archive, inventory, and case-selected evaluation identities."""
    case = request["qualification_case"]
    executable = registry.get("case_scenarios", {}).get(case["id"], registry.get("scenarios", {}).get(request["policy_id"]))
    binding = registry.get("fixture_inputs", {}).get(executable)
    if not isinstance(binding, dict) or set(binding) != {"archive", "inventory", "evaluations"}:
        raise RuntimeError("native scenario lacks original executor-bound fixture inputs")
    verify_file(binding["archive"], paths["archive"], document=False)
    inventory = json.loads(verify_file(binding["inventory"], paths["inventory"], document=True))
    evaluations = json.loads(verify_file(binding["evaluations"], paths["evaluations"], document=True))
    if evaluations != expected_evaluations:
        raise RuntimeError("original fixture evaluations differ from the exact authored case")
    if (not isinstance(inventory, dict) or set(inventory) != {"schema", "roots", "subtractRoots", "paths"}
            or inventory["schema"] != "aos.reference-graph/v1" or inventory["subtractRoots"] != []
            or not isinstance(inventory["paths"], list) or len(inventory["paths"]) > 200000):
        raise RuntimeError("original native fixture NAR inventory is malformed")
    roots = {}
    for row in inventory["paths"]:
        if (not isinstance(row, dict) or set(row) != {"path", "narHash", "narSize", "references"}
                or not isinstance(row["path"], str) or STORE_ROOT(row["path"]) is None
                or row["path"] in roots or type(row["narSize"]) is not int or row["narSize"] < 0
                or not isinstance(row["references"], list)
                or not all(isinstance(reference, str) and STORE_ROOT(reference) is not None for reference in row["references"])
                or row["references"] != sorted(set(row["references"]))):
            raise RuntimeError("original fixture NAR inventory repeats or malforms a root")
        roots[row["path"]] = row | {"narHash": normalize_hash(row["narHash"])}
    if not isinstance(inventory["roots"], list) or any(root not in roots for root in inventory["roots"]):
        raise RuntimeError("original fixture inventory omits a selected root")
    if any(reference not in roots for row in roots.values() for reference in row["references"]):
        raise RuntimeError("original fixture inventory omits a NAR reference")
    return roots


def verify_realized_roots(selected: set[str], inventory: dict[str, dict[str, Any]],
                          nix_store: str, normalize_hash: Callable[[str], str]) -> None:
    """Checks actual source bytes and Nix metadata against the original inventory."""
    for root in sorted(selected):
        expected = inventory.get(root)
        if expected is None:
            raise RuntimeError("native scenario source is absent from original executor inventory")
        def query(option: str) -> str:
            result = subprocess.run([nix_store, "--query", option, root], check=True, capture_output=True, text=True)
            return result.stdout.strip()
        if (normalize_hash(query("--hash")) != expected["narHash"]
                or int(query("--size")) != expected["narSize"]
                or sorted(query("--references").splitlines()) != expected["references"]):
            raise RuntimeError("realized native fixture NAR metadata differs from original executor inventory")
        subprocess.run([nix_store, "--verify-path", root], check=True, capture_output=True)


def verify_admission(admission: dict[str, Any], inventory: dict[str, dict[str, Any]]) -> None:
    """Rejects a bundle catalog that contradicts its independently admitted sources."""
    for row in admission["roots"]:
        expected = inventory.get(row["storePath"])
        references = [] if expected is None else sorted({
            reference.rsplit("/", 1)[-1].split("-", 1)[0]
            for reference in expected["references"] if reference != expected["path"]
        })
        if (expected is None or row["narHash"] != expected["narHash"]
                or row["narSize"] != expected["narSize"] or row["references"] != references):
            raise RuntimeError("native scenario catalog differs from original executor NAR evidence")


def validate_evaluation_contexts(selected: dict[str, Any], adopted: dict[str, Any]) -> None:
    """Keeps authenticated baseline adoption in the selected library and package catalog.

    Both descriptors must have already passed native document validation and
    independent source admission. Their desired graphs and authored source
    lists may differ; adopting a fixture must not substitute another evaluator
    library, platform, profile scope, or frozen package selection.
    """
    if any(selected[key] != adopted[key] for key in ("library", "libraryNarHash", "scope", "packages")):
        raise RuntimeError("fixture adoption changes the exact selected library or package catalog")


def adoption_invocation(cohort: dict[str, Any], documents: dict[str, dict[str, bytes]],
                        driver: str, nix_store: str, profile: str) -> tuple[str, ...]:
    """Renders baseline adoption from already authenticated original bundle bytes.

    The selected target is never substituted for an absent adopted baseline.
    The caller verifies the driver's original NAR identity before executing
    this command; the raw admission digest binds bytes, not their authority.
    """
    selection = cohort.get("adoptionEvaluation")
    if not isinstance(selection, dict) or not isinstance(selection.get("locator"), str):
        raise RuntimeError("fixture adoption lacks its exact authored baseline")
    locator = selection["locator"]
    if STORE_ROOT(locator) is None or locator not in documents:
        raise RuntimeError("fixture adoption baseline lacks independently authenticated documents")
    contents = documents[locator].get("admission.json")
    if not isinstance(contents, bytes) or not 0 < len(contents) <= MAX_DOCUMENT_BYTES:
        raise RuntimeError("fixture adoption has no bounded original admission bytes")
    receipt_digest = "sha256:" + hashlib.sha256(contents).hexdigest()
    return driver, "adopt-native-fixture", locator, receipt_digest, nix_store, profile
