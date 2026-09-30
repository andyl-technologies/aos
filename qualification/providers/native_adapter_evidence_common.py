"""Canonical identities shared by native operation evidence consumers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PROBE_SCHEMA = "aos.release.native-adapter-postcondition-probe/v1"
CELL_SUBJECT_SCHEMA = "aos.release.native-adapter-cell-cohort-subject/v1"
TOKEN = re.compile(r"[a-z0-9.-]{1,96}").fullmatch
DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch

def _postcondition_kind(cell: dict[str, Any], name: str) -> str:
    """Returns the evidence kind projected from the scenario policy."""

    postconditions = cell.get("postconditions")
    kinds = cell.get("postcondition_kinds")
    if (
        not isinstance(postconditions, list)
        or not isinstance(kinds, dict)
        or set(kinds) != set(postconditions)
        or not isinstance(kinds.get(name), str)
        or not kinds[name]
    ):
        raise RuntimeError("matrix cell postcondition policy is malformed")
    return kinds[name]


def canonical(value: Any) -> bytes:
    """Encodes one value in the canonical JSON dialect used by evidence."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha256(value: Any) -> str:
    """Computes the raw canonical SHA-256 identity of one value."""

    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _bound_cohort_subject(
    cell: dict[str, Any], cohort_subject: dict[str, Any]
) -> dict[str, Any]:
    """Binds the dynamic production subject to one immutable matrix cell."""

    return {
        "schema": CELL_SUBJECT_SCHEMA,
        "cell_id": cell["id"],
        "cell_digest": sha256(cell),
        "boundary": cell["boundary"],
        "failure": cell["failure"],
        "candidate": cell["candidate"],
        "predecessor": cell["predecessor"],
        "subject": cohort_subject,
    }


def _expected_disposition(
    cell: dict[str, Any], cohort_subject: dict[str, Any] | None = None
) -> str:
    disposition = cell.get("disposition")
    if not isinstance(disposition, dict):
        raise RuntimeError("matrix cell has no typed disposition policy")
    if disposition.get("kind") == "exact":
        value = disposition.get("value")
        if not _matches(TOKEN, value):
            raise RuntimeError("matrix cell has an invalid exact disposition")
        return value
    raise RuntimeError("matrix cell has an unknown disposition policy")


def _canonical_evidence(evidence_bytes: Any, label: str) -> dict[str, Any]:
    if not isinstance(evidence_bytes, bytes) or len(evidence_bytes) > 16 * 1024 * 1024:
        raise RuntimeError(f"{label} evidence is not an exact byte string")
    try:
        value = json.loads(evidence_bytes)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{label} evidence is not JSON") from error
    if not isinstance(value, dict) or canonical(value) != evidence_bytes:
        raise RuntimeError(f"{label} evidence is not canonical JSON")
    return value


def _matches(pattern: Any, value: Any) -> bool:
    return isinstance(value, str) and pattern(value) is not None


def required_operations(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Checks the closed semantic operation selection retained by one cohort."""

    operations = spec.get("required_operations")
    operation_name = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,95}").fullmatch
    if not isinstance(operations, list) or not 1 <= len(operations) <= 128:
        raise RuntimeError("native matrix requires a bounded nonempty operation selection")
    for operation in operations:
        if (not isinstance(operation, dict) or set(operation) != {"ability", "name"}
                or any(not isinstance(value, str) or operation_name(value) is None
                       for value in operation.values())):
            raise RuntimeError("native matrix required operation is malformed")
    keys = [(operation["ability"], operation["name"]) for operation in operations]
    if keys != sorted(set(keys)):
        raise RuntimeError("native matrix required operations are duplicated or unordered")
    return operations


def selected_terminal_effects(spec: dict[str, Any], graph: dict[str, Any]) -> set[str]:
    """Expands selected semantic operations through actual checked child edges."""

    nodes = graph.get("nodes")
    if not isinstance(nodes, dict) or len(nodes) > 65536:
        raise RuntimeError("native candidate lacks a bounded checked effect graph")
    selected = set()
    for operation in required_operations(spec):
        roots = [effect_id for effect_id, node in nodes.items()
                 if node.get("identity", [])[-3:-1] == [operation["ability"], operation["name"]]]
        descendants = set()
        explored = set()
        pending = [(root, frozenset()) for root in roots]
        while pending:
            effect_id, ancestors = pending.pop()
            if effect_id in ancestors or effect_id not in nodes:
                raise RuntimeError("native composition has a cycle or missing child")
            if effect_id in explored:
                continue
            explored.add(effect_id)
            node = nodes[effect_id]
            handler = node.get("handler", {})
            if handler.get("kind") == "process":
                descendants.add(effect_id)
            elif handler.get("kind") == "composition":
                children = handler.get("children")
                if not isinstance(children, list) or not all(isinstance(child, str) for child in children):
                    raise RuntimeError("native composition lacks its exact child effects")
                pending.extend((child, ancestors | {effect_id}) for child in children)
            else:
                raise RuntimeError("native candidate has an unsupported handler")
        if not descendants:
            raise RuntimeError("required native operation has no enabled terminal effect")
        selected.update(descendants)
    return selected
