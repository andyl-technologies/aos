"""Runs one targeted interruption through the production package runtime.

The importing fleet supplies the activation constructor and provider oracle.
This module owns only the shared process-loss protocol, durable transaction
inspection, and binding of those facts to the qualification evidence helper.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import textwrap
from dataclasses import dataclass
from typing import Any, Callable


BOUNDARY_ROOT = "/var/lib/aos/ability-boundary-test"
CONTINUE = f"{BOUNDARY_ROOT}/continue.json"
EVENTS = f"{BOUNDARY_ROOT}/events.jsonl"
HELD_EVENT = f"{BOUNDARY_ROOT}/held-event.json"
RESUMED_EVENT = f"{BOUNDARY_ROOT}/resumed-event.json"
TARGET = f"{BOUNDARY_ROOT}/target.json"
SCENARIO_BOUNDARIES = {
    "interrupt-after-acquisition": "resources-acquired",
    "interrupt-after-durable-intent": "effect-intent-durable",
    "lose-external-result": "effect-returned",
    "interrupt-after-durable-outcome": "effect-outcome-durable",
}


@dataclass(frozen=True)
class EffectFlight:
    """Names one exact matrix cell and its concrete provider resource."""

    cell_id: str
    interface: str
    method: str
    provider_key: str
    resource_key: str
    label: str


def canonical(value: Any) -> bytes:
    """Encodes a controller input with canonical JSON ordering."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def write_canonical(path: str, value: Any) -> None:
    """Publishes one root-owned controller input through its bounded helper."""

    payload = canonical(value)
    runtime.succeed(
        f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} {payload.hex()}"
    )


def write_target(
    flight: EffectFlight, boundary: str, sequence: str, action: str
) -> None:
    """Writes one exact operation selector for the protected observer."""

    if action not in {"disconnect", "pause"}:
        raise RuntimeError(f"unknown observer action {action!r}")
    write_canonical(
        TARGET,
        {
            "action": action,
            "boundary": boundary,
            "interface": flight.interface,
            "method": flight.method,
            "provider_key": flight.provider_key,
            "purpose": "effect",
            "resource_key": flight.resource_key,
            "sequence": sequence,
        },
    )


def arm(flight: EffectFlight) -> None:
    """Arms the exact operation at its selected interruption boundary."""

    scenario = flight.cell_id.rsplit("/", 1)[-1]
    runtime.succeed(
        f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} "
        f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
    )
    write_target(
        flight, SCENARIO_BOUNDARIES[scenario], flight.label, "disconnect"
    )


def arm_baseline(flight: EffectFlight) -> str:
    """Pauses after acquisition so the pre-effect substrate can be observed."""

    sequence = flight.label + "-baseline"
    runtime.succeed(
        f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} "
        f"{shlex.quote(RESUMED_EVENT)} {shlex.quote(CONTINUE)}"
    )
    write_target(flight, "resources-acquired", sequence, "pause")
    return sequence


def advance_from_baseline(flight: EffectFlight, sequence: str) -> None:
    """Rearms the later interruption before releasing the acquisition pause."""

    scenario = flight.cell_id.rsplit("/", 1)[-1]
    write_target(
        flight, SCENARIO_BOUNDARIES[scenario], flight.label, "disconnect"
    )
    write_canonical(CONTINUE, {"sequence": sequence})


def start_switch(unit: str, host: str) -> None:
    """Starts the candidate `apm switch` without hiding its exit status."""

    runtime.succeed(
        f"{SYSTEMCTL} reset-failed {shlex.quote(unit)} 2>/dev/null || true; "
        f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} --property=Type=exec "
        f"{APM} switch --from {shlex.quote(host)} "
        f"--eval-root /run/ability-effect-{shlex.quote(unit)}"
    )


def wait_held(
    flight: EffectFlight,
    *,
    sequence: str | None = None,
    boundary: str | None = None,
) -> dict[str, Any]:
    """Waits for the authenticated observer to retain the selected event."""

    expected_sequence = sequence or flight.label
    runtime.wait_until_succeeds(
        f"{JQ} -e --arg sequence {shlex.quote(expected_sequence)} "
        f"'.sequence == $sequence' {shlex.quote(HELD_EVENT)}",
        timeout=180,
    )
    held = json.loads(runtime.succeed(f"{COREUTILS}/cat {shlex.quote(HELD_EVENT)}"))
    event = held["event"]
    operation = event["operation"]["operation"]
    expected_boundary = boundary or SCENARIO_BOUNDARIES[
        flight.cell_id.rsplit("/", 1)[-1]
    ]
    assert held["sequence"] == expected_sequence, held
    assert event["purpose"] == "effect", held
    assert event["boundary"] == expected_boundary, held
    assert operation["interface"]["name"] == flight.interface, held
    assert operation["method"] == flight.method, held
    resource = operation["target"]["resource"]
    assert resource["provider"]["key"] == flight.provider_key, held
    assert resource["key"] == flight.resource_key, held
    return held


def current_generation() -> int:
    """Returns the committed system generation containing the transaction."""

    return int(
        runtime.succeed(f"{JQ} -er '.current' /var/lib/profiles/system/state.json").strip()
    )


def transaction_state(held: dict[str, Any], flight: EffectFlight) -> dict[str, Any]:
    """Loads and validates the exact durable plan selected by the observer."""

    generation = current_generation()
    event = held["event"]
    transaction = event["transaction"]
    plan = event["operation"]["plan"]
    operation_key = event["operation"]["operation"]["key"]
    root = (
        f"/var/lib/profiles/system/gen-{generation}/ability-transactions/{transaction}"
    )
    bundle_bytes = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(root + '/plan-bundle.json')}"
    ).encode()
    bundle = json.loads(bundle_bytes)
    assert canonical(bundle) == bundle_bytes, bundle
    assert bundle["plan"] == plan, (bundle, held)
    operations = bundle["transition"]["effect_document"]["operations"]
    matches = [
        (ordinal, operation)
        for ordinal, operation in enumerate(operations)
        if operation["key"] == operation_key
        and operation["interface"]["name"] == flight.interface
        and operation["method"] == flight.method
    ]
    assert len(matches) == 1, matches
    ordinal, operation = matches[0]
    identity = project_operation(operation, ordinal)
    dependent, edge = required_success_dependent(bundle, identity)
    diagnostic = ability_diagnostic(generation, transaction)
    dependent_before = timeline_events(diagnostic, dependent["ordinal"])
    assert dependent_before == [], dependent_before
    return {
        "generation": generation,
        "transaction": transaction,
        "plan": plan,
        "root": root,
        "bundle-bytes": bundle_bytes,
        "operation": identity,
        "operation-document": operation,
        "dependent": dependent,
        "edge": edge,
        "dependent-before": dependent_before,
        "journal-before-loss": runtime.succeed(
            f"{COREUTILS}/sha256sum {shlex.quote(root + '/execution.journal')}"
        ).split()[0],
    }


def project_operation(operation: dict[str, Any], ordinal: int) -> dict[str, Any]:
    """Projects the stable operation identity retained by qualification."""

    return {
        "key": operation["key"],
        "ordinal": ordinal,
        "interface": operation["interface"],
        "method": operation["method"],
        "target": operation["target"],
    }


def required_success_dependent(
    bundle: dict[str, Any], operation: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Selects one real downstream operation from the checked effect graph."""

    effect = bundle["transition"]["effect_document"]
    outgoing = [
        edge
        for edge in effect["edges"]
        if edge["from"] == {"kind": "operation", "key": operation["key"]}
        and edge["kind"] == "required-success"
        and edge["to"]["kind"] == "operation"
    ]
    assert outgoing, (operation, effect["edges"])
    outgoing.sort(key=lambda edge: canonical(edge["to"]["key"]))
    edge = outgoing[0]
    matches = [
        project_operation(candidate, ordinal)
        for ordinal, candidate in enumerate(effect["operations"])
        if candidate["key"] == edge["to"]["key"]
    ]
    assert len(matches) == 1, (edge, matches)
    return matches[0], edge


def ability_diagnostic(generation: int, transaction: str) -> dict[str, Any]:
    """Reads the production diagnostic reconstructed from the durable journal."""

    return json.loads(
        runtime.succeed(
            f"{AOS} --json ability diagnostic "
            f"/var/lib/profiles/system/gen-{generation} {shlex.quote(transaction)}"
        )
    )


def timeline_events(diagnostic: dict[str, Any], ordinal: int) -> list[dict[str, Any]]:
    """Projects durable journal events for one operation ordinal."""

    return [
        {
            "sequence": event["sequence"],
            "kind": event["kind"],
            "node-ordinal": event["node_ordinal"],
        }
        for event in diagnostic["timeline"]["events"]
        if event.get("node_ordinal") == ordinal
    ]


def operation_boundaries(
    transaction: str, plan: str, operation_key: dict[str, Any]
) -> list[dict[str, Any]]:
    """Projects the nonreplayable observer transcript for one operation."""

    result = []
    for position, line in enumerate(
        runtime.succeed(f"{COREUTILS}/cat {shlex.quote(EVENTS)}").splitlines()
    ):
        if not line:
            continue
        event = json.loads(line)
        if (
            event["transaction"] == transaction
            and event["operation"]["plan"] == plan
            and event["operation"]["operation"]["key"] == operation_key
        ):
            result.append(
                {
                    "transcript-position": position,
                    "purpose": event["purpose"],
                    "boundary": event["boundary"],
                }
            )
    return result


def kill_candidate_runtime() -> None:
    """Kills exactly one candidate `__activate-config` process."""

    killed = runtime.succeed(
        textwrap.dedent(
            f"""
            set -eu
            matches=""
            for executable in /proc/[0-9]*/exe; do
              target=$({COREUTILS}/readlink "$executable" 2>/dev/null || true)
              [ "$target" = {shlex.quote(PACKAGE_RUNTIME)} ] || continue
              process=''${{executable#/proc/}}
              process=''${{process%/exe}}
              command=$({COREUTILS}/tr '\\000' ' ' < "/proc/$process/cmdline" 2>/dev/null || true)
              case " $command " in
                *" __activate-config "*) matches="$matches $process" ;;
              esac
            done
            set -- $matches
            [ "$#" -eq 1 ]
            kill -KILL "$1"
            printf '%s\\n' "$1"
            """
        )
    )
    assert killed.strip().isdigit(), killed


def wait_switch_failed(unit: str) -> None:
    """Waits for the switch whose candidate runtime was interrupted."""

    runtime.wait_until_succeeds(
        f"state=$({SYSTEMCTL} show -p ActiveState --value {shlex.quote(unit)} "
        "2>/dev/null || true); "
        'test -z "$state" -o "$state" = inactive -o "$state" = failed',
        timeout=300,
    )
    status = runtime.succeed(
        f"{SYSTEMCTL} show -p ExecMainStatus --value {shlex.quote(unit)} "
        "2>/dev/null || true"
    ).strip()
    assert status != "0", (unit, status)


def resume_recovery(sequence: str) -> None:
    """Releases reconciliation when recovery reaches its returned boundary."""

    try:
        runtime.wait_until_succeeds(
            f"test -s {shlex.quote(RESUMED_EVENT)}", timeout=15
        )
    except Exception:
        return
    resumed = json.loads(
        runtime.succeed(f"{COREUTILS}/cat {shlex.quote(RESUMED_EVENT)}")
    )
    assert resumed["sequence"] == sequence, resumed
    assert resumed["event"]["purpose"] == "reconcile", resumed
    assert resumed["event"]["boundary"] == "reconciliation-returned", resumed
    write_canonical(CONTINUE, {"sequence": sequence})


def run_effect_flight(
    flight: EffectFlight,
    host: str,
    evidence_builder: Any,
    observe: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    """Interrupts, restarts, reconciles, and retains one production operation."""

    unit = f"ability-effect-{flight.label}.service"
    scenario = flight.cell_id.rsplit("/", 1)[-1]
    selected_boundary = SCENARIO_BOUNDARIES[scenario]
    if selected_boundary == "resources-acquired":
        arm(flight)
        start_switch(unit, host)
        held = wait_held(flight)
        state = transaction_state(held, flight)
        baseline = observe(state["operation-document"])
    else:
        baseline_sequence = arm_baseline(flight)
        start_switch(unit, host)
        baseline_held = wait_held(
            flight,
            sequence=baseline_sequence,
            boundary="resources-acquired",
        )
        baseline_state = transaction_state(baseline_held, flight)
        baseline = observe(baseline_state["operation-document"])
        advance_from_baseline(flight, baseline_sequence)
        held = wait_held(flight)
        state = transaction_state(held, flight)
        assert state["transaction"] == baseline_state["transaction"], (
            state,
            baseline_state,
        )
        assert state["operation"] == baseline_state["operation"], (
            state,
            baseline_state,
        )
    unsettled = observe(state["operation-document"])
    kill_candidate_runtime()
    wait_switch_failed(unit)

    runtime.succeed(f"{SYSTEMCTL} restart aos-activate.service")
    resume_recovery(flight.label)
    runtime.wait_until_succeeds(
        f"{SYSTEMCTL} is-active --quiet aos-activate.service", timeout=900
    )
    after = observe(state["operation-document"])
    diagnostic = ability_diagnostic(state["generation"], state["transaction"])
    timeline = timeline_events(diagnostic, state["operation"]["ordinal"])
    boundaries = operation_boundaries(
        state["transaction"], state["plan"], state["operation"]["key"]
    )
    dependent_after = timeline_events(diagnostic, state["dependent"]["ordinal"])
    dependent_boundaries = operation_boundaries(
        state["transaction"], state["plan"], state["dependent"]["key"]
    )
    assert timeline and boundaries, (timeline, boundaries)
    assert dependent_after and dependent_boundaries, (
        dependent_after,
        dependent_boundaries,
    )
    interruption_positions = [
        entry["transcript-position"]
        for entry in boundaries
        if entry["purpose"] == "effect" and entry["boundary"] == selected_boundary
    ]
    assert interruption_positions, boundaries

    observation = EFFECT_EVIDENCE.EffectBoundaryObservation(
        transaction=state["transaction"],
        operation_key=state["operation"]["key"],
        journal_before_loss=state["journal-before-loss"],
        timeline=timeline,
        boundary_timeline=boundaries,
        interruption_position=interruption_positions[0],
        settlement_sequence=timeline[-1]["sequence"],
        settlement_position=boundaries[-1]["transcript-position"],
        owner_baseline=baseline["owner"],
        owner_unsettled=unsettled["owner"],
        owner_after=after["owner"],
        live_baseline=baseline["live"],
        live_unsettled=unsettled["live"],
        live_after=after["live"],
        foreign_baseline=baseline["foreign"],
        foreign_unsettled=unsettled["foreign"],
        foreign_after=after["foreign"],
        dependent_operation=state["dependent"],
        dependent_before=state["dependent-before"],
        dependent_after=dependent_after,
        dependent_boundary_after=dependent_boundaries,
    )
    evidence_builder.retain(
        flight.cell_id, state["bundle-bytes"], observation
    )
