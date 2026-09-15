"""Validates image-rollout qualification evidence against its live substrate.

This module owns the rollout plan shape and boot-slot observation semantics. The
provider-neutral matrix aggregator supplies only common scenario and probe policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


LOCAL_KEY = re.compile(r"[A-Za-z0-9._-]{1,128}").fullmatch
DIGEST = re.compile(r"sha256:[0-9a-f]{64}").fullmatch
RAW_DIGEST = re.compile(r"[0-9a-f]{64}").fullmatch


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _matches(pattern: Any, value: Any) -> bool:
    return isinstance(value, str) and pattern(value) is not None


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _cell_scenario(cell: dict[str, Any]) -> str:
    return cell["id"].rsplit("/", 1)[-1]


def _adapter_claim(spec: dict[str, Any], adapter_name: str) -> dict[str, Any]:
    matches = [
        adapter
        for adapter in spec.get("surface", {}).get("adapters", [])
        if isinstance(adapter, dict) and adapter.get("adapter") == adapter_name
    ]
    if len(matches) != 1:
        raise RuntimeError("matrix surface lacks one exact adapter claim")
    return matches[0]


def _operation_key(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("key"), dict)


def _provider_negative_operation(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"key", "ordinal", "interface", "method", "resource"}
        and _operation_key(value)
        and _is_nonnegative_int(value.get("ordinal"))
        and isinstance(value.get("interface"), dict)
        and isinstance(value.get("method"), str)
        and isinstance(value.get("resource"), dict)
    )


def validate_provider_negative_cell(
    cell: dict[str, Any],
    record: dict[str, Any],
    subject_digest: str,
    probe_digests: set[str],
    spec: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Validates provider-specific evidence or declines a generic record."""

    if record.get("mode") not in {"rollout-dependency", "rollout-map-validation"}:
        return None

    if (
        set(record)
        != {"mode", "cell_digest", "subject", "plan_bundle", "evidence"}
        or record.get("cell_digest") != _sha256(cell)
    ):
        raise RuntimeError("rollout provider-negative record is malformed")
    mode = record["mode"]
    scenario = _cell_scenario(cell)
    if (mode, scenario) not in {
        ("rollout-dependency", "block-dependent-effect"),
        ("rollout-map-validation", "reject-foreign-resource-mutation"),
    }:
        raise RuntimeError("rollout provider-negative mode differs from its cell")

    subject = record["subject"]
    plan = record["plan_bundle"]
    evidence = record["evidence"]
    adapter = cell["adapter"]
    adapter_claim = _adapter_claim(spec, adapter)
    mutation_methods = {
        method["method"]
        for method in adapter_claim["methods"]
        if method.get("effect_class") == "mutation"
    }
    expected_subject = {
        "schema": policy["subject-schema"],
        "cell-id": cell["id"],
        "cell-digest": _sha256(cell),
        "adapter": adapter,
        "interface": cell["interface"],
        "method": cell["method"],
        "scenario": scenario,
        "plan": subject.get("plan"),
        "transaction": subject.get("transaction"),
        "flight": subject.get("flight"),
    }
    if (
        subject != expected_subject
        or not _matches(DIGEST, subject.get("plan"))
        or not _matches(LOCAL_KEY, subject.get("transaction"))
        or not _matches(LOCAL_KEY, subject.get("flight"))
    ):
        raise RuntimeError("rollout provider-negative subject is not exact")

    expected_plan_fields = {
        "schema",
        "digest",
        "plan",
        "foreign-operation",
        "dependent-operation",
        "required-success",
        "behavioral-witness",
    }
    foreign = plan.get("foreign-operation")
    dependent = plan.get("dependent-operation")
    witness = plan.get("behavioral-witness")
    if (
        set(plan) != expected_plan_fields
        or plan.get("schema") != policy["plan-schema"]
        or not _matches(DIGEST, plan.get("digest"))
        or plan.get("plan") != subject["plan"]
        or not isinstance(foreign, dict)
        or not isinstance(dependent, dict)
        or not _provider_negative_operation(foreign)
        or not _provider_negative_operation(dependent)
        or plan.get("required-success")
        != {"from": foreign, "to": dependent, "kind": "required-success"}
        or foreign.get("interface") != cell["interface"]
        or foreign.get("method") != cell["method"]
    ):
        raise RuntimeError("rollout provider-negative plan is not exact")
    same_machine = foreign.get("resource") == dependent.get("resource")
    if same_machine != (mode == "rollout-dependency"):
        raise RuntimeError("rollout resource relationship differs from its scenario")
    if cell["effect_class"] == "observation":
        if (
            not isinstance(witness, dict)
            or not _provider_negative_operation(witness)
            or (
                witness != dependent
                and witness.get("method") not in mutation_methods
            )
        ):
            raise RuntimeError("rollout observation lacks a real mutation witness")
    elif witness is not None:
        raise RuntimeError("rollout mutation unexpectedly has a witness")

    if set(evidence) != {
        "provider-route",
        "boundary",
        "classification",
        "ownership",
        "foreign-resource",
        "blocked-successor",
        "blocked-witness",
    }:
        raise RuntimeError("rollout provider-negative evidence has unexpected fields")
    route = evidence["provider-route"]
    if (
        not isinstance(route, dict)
        or set(route)
        != {
            "adapter",
            "interface",
            "method",
            "candidate-linked",
            "artifact",
            "implementation",
            "handler",
            "entry-point",
        }
        or route.get("adapter") != adapter
        or route.get("interface") != cell["interface"]
        or route.get("method") != cell["method"]
        or route.get("candidate-linked") is not True
        or not _matches(DIGEST, route.get("artifact"))
        or not _matches(DIGEST, route.get("implementation"))
        or not _matches(LOCAL_KEY, route.get("handler"))
        or not isinstance(route.get("entry-point"), str)
        or not route["entry-point"]
        or route["entry-point"].startswith("/")
    ):
        raise RuntimeError("rollout provider route is not candidate-linked")

    classification = evidence["classification"]
    ownership = evidence["ownership"]
    if mode == "rollout-dependency":
        expected_boundary = "after-durable-intent-before-external-effect"
        if (
            set(classification)
            != {
                "kind",
                "digest",
                "failure-record",
                "predecessor-timeline",
                "dependent-timeline",
                "witness-timeline",
                "classified",
            }
            or classification.get("kind") != "execution-journal"
            or not _matches(DIGEST, classification.get("digest"))
            or not _matches(DIGEST, classification.get("failure-record"))
            or [
                event.get("kind")
                for event in classification.get("predecessor-timeline", [])
            ]
            != ["operation-admitted", "effect-started", "rejected-before-effect"]
            or classification.get("dependent-timeline") != []
            or classification.get("witness-timeline") != []
            or classification.get("classified") != "boot-slot-authority-rejected"
            or ownership
            != {
                "machine-owner-count-before": 1,
                "machine-owner-count-after": 1,
                "candidate-owner-count": 0,
                "maximum-owner-count": 1,
            }
        ):
            raise RuntimeError("rollout dependency classification is incomplete")
    else:
        expected_boundary = "native-resource-map-validation"
        if (
            set(classification)
            != {
                "kind",
                "digest",
                "attempted-map-digest",
                "failure-record",
                "classified",
                "dependent-timeline",
                "witness-timeline",
            }
            or classification.get("kind") != "native-resource-map-validation"
            or not all(
                _matches(DIGEST, classification.get(field))
                for field in ["digest", "attempted-map-digest", "failure-record"]
            )
            or classification.get("classified") != "foreign-authority-rejected"
            or classification.get("dependent-timeline") != []
            or classification.get("witness-timeline") != []
            or ownership
            != {
                "machine-owner-count-before": 1,
                "machine-owner-count-after": 1,
                "forged-owner-count": 0,
                "maximum-owner-count": 1,
            }
        ):
            raise RuntimeError("rollout map-collision classification is incomplete")
    if evidence.get("boundary") != expected_boundary:
        raise RuntimeError("rollout provider-negative boundary differs")

    foreign_oracle = evidence["foreign-resource"]
    successor_oracle = evidence["blocked-successor"]
    witness_oracle = evidence["blocked-witness"]
    for label, oracle, kind in [
        ("foreign", foreign_oracle, "systemd-unit"),
        ("successor", successor_oracle, "boot-slot"),
    ]:
        if (
            not isinstance(oracle, dict)
            or set(oracle)
            != {"kind", "resource", "before", "after", "unchanged", "live"}
            or oracle.get("kind") != kind
            or not _matches(DIGEST, oracle.get("before"))
            or oracle.get("after") != oracle.get("before")
            or oracle.get("unchanged") is not True
            or oracle.get("live") is not True
        ):
            raise RuntimeError(f"rollout {label} oracle is not live and unchanged")
    if successor_oracle.get("resource") != dependent.get("resource"):
        raise RuntimeError("rollout successor oracle names another machine")
    if foreign_oracle.get("resource") == foreign.get(
        "resource"
    ) or foreign_oracle.get("resource") == dependent.get("resource"):
        raise RuntimeError("rollout foreign sentinel is not independently owned")
    if witness is None:
        if witness_oracle is not None:
            raise RuntimeError("rollout mutation unexpectedly reports a witness oracle")
    elif (
        not isinstance(witness_oracle, dict)
        or witness_oracle.get("kind") != "boot-slot"
        or witness_oracle.get("resource") != witness.get("resource")
        or witness_oracle.get("before") != witness_oracle.get("after")
        or witness_oracle.get("unchanged") is not True
        or witness_oracle.get("live") is not True
    ):
        raise RuntimeError("rollout mutation witness was not independently blocked")

    bound_subject = {
        "schema": policy["cell-subject-schema"],
        "cell": {
            "id": cell["id"],
            "digest": _sha256(cell),
            "boundary": cell["boundary"],
            "failure": cell["failure"],
            "candidate": cell["candidate"],
            "predecessor": cell["predecessor"],
        },
        "subject": subject,
    }
    cohort_subject_digest = _sha256(bound_subject)
    scenario_probe = (
        "prerequisite-failure-recorded"
        if scenario == "block-dependent-effect"
        else "foreign-attempt-rejected-before-mutation"
    )
    observations = {
        "durable-attempt-state-classified": classification,
        "at-most-one-resource-owner": ownership,
        "foreign-resources-unchanged": foreign_oracle,
        "dependent-effects-not-executed": {
            "successor": successor_oracle,
            "witness": witness_oracle,
        },
        scenario_probe: {
            "boundary": evidence["boundary"],
            "provider-route": route,
            "classification": classification,
            "foreign-operation": foreign,
            "dependent-operation": dependent,
            "behavioral-witness": witness,
        },
    }
    if set(observations) != set(cell["postconditions"]):
        raise RuntimeError("rollout evidence differs from cell postconditions")

    postconditions = {}
    probes = {}
    for name in cell["postconditions"]:
        observation = observations[name]
        observation_digest = _sha256(
            {
                "schema": policy["probe-schema"],
                "cell": _sha256(cell),
                "postcondition": name,
                "subject": cohort_subject_digest,
                "candidate-subject": subject_digest,
                "observations": observation,
            }
        )
        if observation_digest in probe_digests:
            raise RuntimeError("passing rollout postconditions replay a provider probe")
        probe_digests.add(observation_digest)
        postconditions[name] = {
            "passed": True,
            "detail": "candidate-linked rollout flight satisfied exact postcondition",
        }
        probes[name] = {
            "schema": policy["probe-schema"],
            "kind": policy["postcondition-kinds"][name],
            "disposition": policy["disposition"],
            "observation_digest": observation_digest,
            "cohort_subject_digest": cohort_subject_digest,
        }
    return bound_subject, postconditions, probes


def validate_cancellation_snapshot(expected_kind: str, value: Any) -> bool | None:
    """Validates a rollout cancellation snapshot or declines another kind."""

    if expected_kind != "image-rollout":
        return None
    if not isinstance(value, dict) or value.get("kind") != expected_kind:
        return False
    if set(value) != {
        "kind",
        "filesystem",
        "hook-state",
        "kernel-command-line",
    }:
        return False

    filesystem = value.get("filesystem")
    hooks = value.get("hook-state")
    if (
        not _cancellation_filesystem_snapshot(filesystem)
        or not _cancellation_filesystem_snapshot(hooks)
        or not isinstance(value.get("kernel-command-line"), str)
        or not value["kernel-command-line"]
    ):
        return False

    paths = [entry["path"] for entry in filesystem["entries"]]
    return (
        "/var/lib/profiles/image/state.json" in paths
        and any(
            path.startswith("/var/lib/profiles/image/ability-rollouts/")
            and path.endswith("/state.json")
            for path in paths
        )
    )


def _cancellation_filesystem_snapshot(value: Any) -> bool:
    """Checks the bounded file facts emitted by the rollout observer."""

    if not isinstance(value, dict) or set(value) != {"kind", "entries"}:
        return False
    entries = value.get("entries")
    if value.get("kind") != "filesystem" or not isinstance(entries, list):
        return False
    if len(entries) > 512:
        return False

    return all(
        isinstance(entry, dict)
        and set(entry) == {"path", "metadata", "digest"}
        and isinstance(entry.get("path"), str)
        and entry["path"].startswith("/")
        and isinstance(entry.get("metadata"), str)
        and (entry.get("digest") is None or _matches(RAW_DIGEST, entry.get("digest")))
        for entry in entries
    )
