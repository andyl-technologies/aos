"""Builds exact matrix cells from independently retained production probes.

This module owns one fail-closed aggregation transaction: it verifies the
matrix partition, binds every normalized subject and probe to the same subject,
policy, executor, and environment digests, rejects replay across cells, and
returns the closed cell map. Keeping those generic scenario validators together
lets one replay set and one partition check cover the whole result. Raw plan and
live-resource formats remain in provider-owned modules behind a small normalized
validation API.
"""

from __future__ import annotations

import re
from typing import Any

import native_adapter_evidence as provider_evidence
import native_adapter_runtime_evidence as runtime_evidence

from native_adapter_evidence_common import (
    DIGEST,
    LOCAL_KEY,
    MAX_PROBE_BYTES,
    MAX_PROBE_FACTS,
    PROBE_SCHEMA,
    TOKEN,
    _bound_cohort_subject,
    _cell_scenario,
    _expected_disposition,
    _matches,
    _postcondition_kind,
    canonical,
    sha256,
)


RELATIVE_PATH = re.compile(
    r"(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*"
).fullmatch
QUALIFICATION_SUBJECT_SCHEMA = (
    "aos.qualification.native-adapter-package-subject/v1"
)
MATRIX_APPLICABILITY_SCHEMA = (
    "aos.qualification.native-adapter-matrix-applicability/v1"
)
RESOURCE_LIFETIMES = {"attempt", "transaction", "instance", "persistent"}


def _inapplicable_reason(
    cell: dict[str, Any], contract: dict[str, Any]
) -> str | None:
    """Returns the exact provider-contract reason that excludes one cell."""

    if _cell_scenario(cell) != "adopt-compatible-state":
        return None
    if contract["resource_lifetime"] != "persistent":
        return "non-persistent-lifetime"
    if contract["state_format"] is None:
        return "missing-authenticated-state-format"
    return None


def _applicable_specification_cells(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Validates and applies the matrix's fail-closed applicability partition."""

    cells = spec.get("cells")
    if not isinstance(cells, list):
        raise RuntimeError("matrix specification cells are malformed")

    adapters = spec.get("surface", {}).get("adapters")
    if not isinstance(adapters, list):
        raise RuntimeError("matrix provider contracts are missing")
    contracts = {}
    for adapter in adapters:
        contract = adapter.get("provider_contract")
        if (
            not isinstance(contract, dict)
            or set(contract) != {"resource_lifetime", "state_format"}
            or contract.get("resource_lifetime") not in RESOURCE_LIFETIMES
            or (
                contract.get("state_format") is not None
                and (
                    not isinstance(contract.get("state_format"), str)
                    or len(contract["state_format"]) != 71
                    or not contract["state_format"].startswith("sha256:")
                    or any(
                        character not in "0123456789abcdef"
                        for character in contract["state_format"][7:]
                    )
                )
            )
            or adapter.get("adapter") in contracts
        ):
            raise RuntimeError("matrix provider contract metadata is malformed")
        contracts[adapter.get("adapter")] = contract

    expected = []
    for cell in cells:
        contract = contracts.get(cell.get("adapter"))
        if contract is None:
            raise RuntimeError("matrix cell has no authenticated provider contract")
        reason = _inapplicable_reason(cell, contract)
        if reason is not None:
            expected.append({"cell_id": cell["id"], "reason": reason})
    applicability = spec.get("applicability")
    if (
        not isinstance(applicability, dict)
        or set(applicability)
        != {"schema", "required_production_vm_cells", "inapplicable_cells"}
        or applicability.get("schema") != MATRIX_APPLICABILITY_SCHEMA
        or applicability.get("inapplicable_cells") != expected
        or applicability.get("required_production_vm_cells")
        != len(cells) - len(expected)
    ):
        raise RuntimeError(
            "matrix applicability differs from exact provider contract semantics"
        )

    excluded = {entry["cell_id"] for entry in expected}
    return [cell for cell in cells if cell["id"] not in excluded]


def _qualification_routes(
    subject: Any, spec: dict[str, Any]
) -> list[dict[str, Any]]:
    """Validates package-derived executable routes for the matrix surface."""

    if (
        not isinstance(subject, dict)
        or set(subject) != {"schema", "matrix-spec-digest", "routes"}
        or subject.get("schema") != QUALIFICATION_SUBJECT_SCHEMA
        or subject.get("matrix-spec-digest") != sha256(spec)
        or not isinstance(subject.get("routes"), list)
    ):
        raise RuntimeError("native adapter package subject is malformed")

    surface = spec.get("surface", {}).get("adapters")
    if not isinstance(surface, list):
        raise RuntimeError("native adapter package subject lacks a matrix surface")
    adapters = {entry.get("adapter"): entry for entry in surface}
    routes = subject["routes"]
    identities = set()
    coverage = set()
    for route in routes:
        if not isinstance(route, dict) or set(route) != {
            "adapter",
            "interface",
            "methods",
            "provenance",
            "implementation",
            "handler",
            "artifact",
            "entry-point",
        }:
            raise RuntimeError("native adapter package route is malformed")
        adapter = adapters.get(route.get("adapter"))
        methods = route.get("methods")
        provenance = route.get("provenance")
        identity = canonical(route)
        if (
            adapter is None
            or route.get("interface")
            != {
                "name": adapter.get("interface_name"),
                "abi": adapter.get("interface_abi"),
                "descriptor": adapter.get("interface_descriptor"),
            }
            or not isinstance(methods, list)
            or methods != sorted(set(methods))
            or not methods
            or any(not _matches(TOKEN, method) for method in methods)
            or not isinstance(provenance, list)
            or not provenance
            or provenance
            != sorted(
                provenance,
                key=lambda entry: (entry.get("package", ""), entry.get("ability-contract", "")),
            )
            or len({canonical(entry) for entry in provenance}) != len(provenance)
            or any(
                not isinstance(entry, dict)
                or set(entry) != {"package", "ability-contract"}
                or not _matches(TOKEN, entry.get("package"))
                or not _matches(DIGEST, entry.get("ability-contract"))
                for entry in provenance
            )
            or not _matches(DIGEST, route.get("implementation"))
            or not _matches(LOCAL_KEY, route.get("handler"))
            or not _matches(DIGEST, route.get("artifact"))
            or not _matches(RELATIVE_PATH, route.get("entry-point"))
            or identity in identities
        ):
            raise RuntimeError("native adapter package route differs from its matrix")
        identities.add(identity)
        coverage.update((route["adapter"], method) for method in methods)

    expected = {
        (adapter["adapter"], method["method"])
        for adapter in surface
        for method in adapter["methods"]
    }
    if coverage != expected:
        raise RuntimeError("package projections do not cover the native adapter surface")
    return routes


def _adapter_for_interface(
    spec: dict[str, Any], interface: Any
) -> str | None:
    """Finds the one matrix adapter owning an exact interface identity."""

    matches = [
        adapter["adapter"]
        for adapter in spec["surface"]["adapters"]
        if interface
        == {
            "name": adapter["interface_name"],
            "abi": adapter["interface_abi"],
            "descriptor": adapter["interface_descriptor"],
        }
    ]
    return matches[0] if len(matches) == 1 else None


def _matching_package_routes(
    routes: list[dict[str, Any]],
    cell: dict[str, Any],
    *,
    implementation: Any = None,
    handler: Any = None,
    artifact: Any = None,
    entry_point: Any = None,
) -> list[dict[str, Any]]:
    """Selects exact package routes matching one realized matrix operation."""

    return [
        route
        for route in routes
        if route["adapter"] == cell["adapter"]
        and route["interface"] == cell["interface"]
        and cell["method"] in route["methods"]
        and (implementation is None or route["implementation"] == implementation)
        and (handler is None or route["handler"] == handler)
        and (artifact is None or route["artifact"] == artifact)
        and (entry_point is None or route["entry-point"] == entry_point)
    ]


def build_cells(
    spec: dict[str, Any],
    submissions: dict[str, Any],
    expected_qualified_cells: list[str],
    cohort_subjects: dict[str, dict[str, Any]],
    cohort_evidence: dict[str, bytes],
    subject_digest: str,
    environment_digest: str,
    runtime_audit: dict[str, Any] | None = None,
    interruption_audit: dict[str, Any] | None = None,
    provider_negative_audit: dict[str, Any] | None = None,
    qualification_subject: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Builds all cell observations and proves every positive claim is expected."""

    has_runtime_audit = runtime_audit is not None
    runtime_audit = runtime_audit or {
        "schema": runtime_evidence.RUNTIME_AUDIT_SCHEMA,
        "matrix_spec_digest": "sha256:" + "0" * 64,
        "cells": {},
    }
    runtime_cells = runtime_audit.get("cells")
    if not isinstance(runtime_cells, dict):
        raise RuntimeError("runtime audit cells are malformed")
    has_interruption_audit = interruption_audit is not None
    interruption_audit = interruption_audit or {
        "schema": runtime_evidence.INTERRUPTION_AUDIT_SCHEMA,
        "matrix_spec_digest": "sha256:" + "0" * 64,
        "cells": {},
    }
    interruption_cells = interruption_audit.get("cells")
    if not isinstance(interruption_cells, dict):
        raise RuntimeError("interruption audit cells are malformed")
    provider_negative_audit = provider_negative_audit or {
        "schema": runtime_evidence.PROVIDER_NEGATIVE_AUDIT_SCHEMA,
        "matrix_spec_digest": "sha256:" + "0" * 64,
        "cells": {},
    }
    provider_negative_cells = provider_negative_audit.get("cells")
    if not isinstance(provider_negative_cells, dict):
        raise RuntimeError("provider-negative audit cells are malformed")
    routes = _qualification_routes(qualification_subject, spec)
    submitted_cells = (
        set(submissions)
        | set(runtime_cells)
        | set(interruption_cells)
        | set(provider_negative_cells)
    )
    if submitted_cells != set(expected_qualified_cells):
        raise RuntimeError("cohort probe cells differ from its explicit qualification scope")
    if len(set(expected_qualified_cells)) != len(expected_qualified_cells):
        raise RuntimeError("cohort qualification scope repeats a matrix cell")

    applicable_specification_cells = _applicable_specification_cells(spec)
    specification_cells = {cell["id"]: cell for cell in spec["cells"]}
    if len(specification_cells) != len(spec["cells"]):
        raise RuntimeError("matrix specification repeats a cell identity")
    if any(cell_id not in specification_cells for cell_id in submitted_cells):
        raise RuntimeError("cohort submitted a probe outside the exact matrix surface")
    if "schema" in spec and set(expected_qualified_cells) != {
        cell["id"] for cell in applicable_specification_cells
    }:
        raise RuntimeError(
            "cohort qualification scope differs from the applicable matrix partition"
        )
    if set(cohort_subjects) != set(submissions):
        raise RuntimeError("cohort subjects differ from its explicit qualification scope")
    if set(cohort_evidence) != set(submissions):
        raise RuntimeError("cohort evidence differs from its explicit qualification scope")
    for cell_id in submissions:
        _validate_cohort_subject(
            specification_cells[cell_id],
            cohort_subjects[cell_id],
            cohort_evidence[cell_id],
            spec,
            routes,
        )
    if has_runtime_audit:
        runtime_evidence.validate_runtime_audit(runtime_audit, spec, specification_cells)
    if has_interruption_audit:
        runtime_evidence.validate_interruption_audit(interruption_audit, spec, specification_cells)
    if provider_negative_cells:
        runtime_evidence.validate_provider_negative_audit(
            provider_negative_audit, spec, specification_cells, set(submissions)
        )

    observed_cells = []
    postcondition_count = 0
    probe_digests = set()
    for cell in applicable_specification_cells:
        submitted = submissions.get(cell["id"])
        runtime_record = runtime_cells.get(cell["id"])
        interruption_record = interruption_cells.get(cell["id"])
        provider_negative_record = provider_negative_cells.get(cell["id"])
        names = cell["postconditions"]
        postcondition_count += len(names)
        if runtime_record is not None:
            scenario = cell["id"].rsplit("/", 1)[-1]
            if scenario in runtime_evidence.ROLE_SCENARIOS:
                bound_subject, postconditions, probes = runtime_evidence.validate_authority_cell(
                    cell, runtime_record, subject_digest, probe_digests
                )
            elif scenario in runtime_evidence.REPLACEMENT_SCENARIOS:
                bound_subject, postconditions, probes = runtime_evidence.validate_replacement_cell(
                    cell, runtime_record, subject_digest, probe_digests
                )
            else:
                bound_subject, postconditions, probes = (
                    runtime_evidence.validate_failure_control_cell(
                        cell, runtime_record, subject_digest, probe_digests
                    )
                )
        elif interruption_record is not None:
            bound_subject, postconditions, probes = runtime_evidence.validate_interruption_cell(
                cell,
                interruption_record,
                subject_digest,
                probe_digests,
            )
        elif provider_negative_record is not None:
            bound_subject, postconditions, probes = (
                runtime_evidence.validate_provider_negative_cell(
                    cell,
                    provider_negative_record,
                    subject_digest,
                    probe_digests,
                    spec,
                )
            )
        elif submitted is None:
            postconditions = {
                name: {
                    "passed": False,
                    "detail": "not exercised by this production cohort",
                }
                for name in names
            }
            probes = {}
        else:
            cohort_subject = cohort_subjects[cell["id"]]
            bound_subject = _bound_cohort_subject(cell, cohort_subject)
            postconditions, probes = _validated_probes(
                cell,
                submitted,
                cohort_subject,
                bound_subject,
                subject_digest,
                probe_digests,
                spec,
            )

        observation = {
            "id": cell["id"],
            "cell_digest": sha256(cell),
            "environment_digest": environment_digest,
            "postconditions": postconditions,
        }
        if probes:
            observation["probes"] = probes
            observation["cohort_subject"] = bound_subject
        observed_cells.append(observation)

    return observed_cells, postcondition_count


def _validated_probes(
    cell: dict[str, Any],
    submitted: dict[str, Any],
    cohort_subject: dict[str, Any],
    bound_subject: dict[str, Any],
    subject_digest: str,
    cohort_probe_digests: set[str],
    matrix_spec: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    postcondition_names = cell["postconditions"]
    if set(submitted) != set(postcondition_names):
        raise RuntimeError("qualified cell lacks an exact postcondition probe set")
    if bound_subject != _bound_cohort_subject(cell, cohort_subject):
        raise RuntimeError("cohort subject is bound to another matrix cell")

    cell_digest = sha256(cell)
    cohort_subject_digest = sha256(bound_subject)
    expected_disposition = _expected_disposition(cell, cohort_subject)
    postconditions = {}
    probes = {}
    for name in postcondition_names:
        record = submitted[name]
        if set(record) != {"kind", "detail", "disposition", "observations"}:
            raise RuntimeError("postcondition probe has unknown or missing fields")
        expected_kind = _postcondition_kind(cell, name)
        observations = record["observations"]
        if (
            record["kind"] != expected_kind
            or not isinstance(record["detail"], str)
            or not record["detail"].strip()
            or record["disposition"] != expected_disposition
            or not isinstance(observations, dict)
            or not 1 <= len(observations) <= MAX_PROBE_FACTS
            or any(
                not isinstance(key, str) or TOKEN(key) is None or value is None
                for key, value in observations.items()
            )
            or len(canonical(observations)) > MAX_PROBE_BYTES
        ):
            raise RuntimeError("postcondition probe is malformed")
        _validate_probe_facts(name, observations, cohort_subject, cell, matrix_spec)
        observation_digest = sha256(observations)
        if observation_digest in cohort_probe_digests:
            raise RuntimeError("passing matrix postconditions replay a production probe")
        cohort_probe_digests.add(observation_digest)

        postconditions[name] = {"passed": True, "detail": record["detail"]}
        probes[name] = {
            "schema_version": PROBE_SCHEMA,
            "kind": record["kind"],
            "cell_id": cell["id"],
            "cell_digest": cell_digest,
            "disposition": record["disposition"],
            "subject_digest": subject_digest,
            "cohort_subject_digest": cohort_subject_digest,
            "observation_digest": observation_digest,
            "observations": observations,
        }

    return postconditions, probes


def _validate_probe_facts(
    postcondition: str,
    observations: dict[str, Any],
    cohort_subject: dict[str, Any],
    cell: dict[str, Any],
    matrix_spec: dict[str, Any] | None = None,
) -> None:
    """Checks semantic facts for one exact matrix postcondition."""

    result = provider_evidence.validate_probe(
        postcondition, observations, cohort_subject, cell, matrix_spec
    )
    if result != {
        "schema": "aos.qualification.provider-evidence-validation/v1",
        "cell-id": cell["id"],
        "kind": "postcondition",
        "postcondition": postcondition,
    }:
        raise RuntimeError("provider evidence returned a malformed validation result")


def _validate_cohort_subject(
    cell: dict[str, Any],
    subject: Any,
    evidence_bytes: Any,
    matrix_spec: dict[str, Any] | None = None,
    routes: list[dict[str, Any]] | None = None,
) -> None:
    """Validates a retained subject through its unique declared validator."""

    result = provider_evidence.validate_subject(
        cell, subject, evidence_bytes, matrix_spec, routes or []
    )
    if result != {
        "schema": "aos.qualification.provider-evidence-validation/v1",
        "cell-id": cell["id"],
        "kind": "subject",
    }:
        raise RuntimeError("provider evidence returned a malformed validation result")
