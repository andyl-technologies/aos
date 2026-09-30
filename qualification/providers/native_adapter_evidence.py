"""Provides the closed native flight validation boundary.

There is one native operation protocol. Provider-plan and static-interface
subjects are deliberately outside this evidence grammar.
"""

from __future__ import annotations

from typing import Any

import native_adapter_runtime_evidence as native


VALIDATION_RESULT_SCHEMA = "aos.qualification.native-operation-evidence-validation"


def validate_subject(cell: dict[str, Any], subject: Any, evidence_bytes: bytes,
                     matrix_spec: dict[str, Any], routes: list[dict[str, Any]]) -> dict[str, Any]:
    """Validates exact native evidence through its one closed parser."""
    native.validate_flight(cell, subject, evidence_bytes, matrix_spec, routes)
    return {"schema": VALIDATION_RESULT_SCHEMA, "cell-id": cell["id"], "kind": "subject"}
