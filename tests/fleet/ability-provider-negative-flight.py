"""Runs exact foreign-authority and RequiredSuccess provider flights."""

from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass
from typing import Any


BOUNDARY_ROOT = "/var/lib/aos/ability-provider-negative"
CONTINUE = f"{BOUNDARY_ROOT}/continue.json"
EVENTS = f"{BOUNDARY_ROOT}/events.jsonl"
HELD_EVENT = f"{BOUNDARY_ROOT}/held-event.json"
TARGET = f"{BOUNDARY_ROOT}/target.json"


@dataclass(frozen=True)
class ProviderFlight:
    """Names one exact method pair in a production provider plan."""

    adapter: str
    interface: str
    method: str
    provider_key: str
    resource_key: str
    label: str
    observation: bool
    mapping: dict[str, Any]


def canonical(value: Any) -> bytes:
    """Encodes a controller document with canonical JSON ordering."""

    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def write_canonical(path: str, value: Any) -> None:
    """Publishes one bounded root-owned controller input."""

    runtime.succeed(
        f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} "
        f"{canonical(value).hex()}"
    )


def arm(flight: ProviderFlight) -> None:
    """Pauses the exact first provider call after its durable intent."""

    runtime.succeed(
        f"{COREUTILS}/rm -f {shlex.quote(HELD_EVENT)} {shlex.quote(CONTINUE)}"
    )
    write_canonical(
        TARGET,
        {
            "action": "pause",
            "boundary": "effect-intent-durable",
            "interface": flight.interface,
            "method": flight.method,
            "provider_key": flight.provider_key,
            "purpose": "effect",
            "resource_key": flight.resource_key,
            "sequence": flight.label,
        },
    )


def start_switch(unit: str, host: str) -> None:
    """Starts the candidate switch as a visible transient service."""

    runtime.succeed(
        f"{SYSTEMCTL} reset-failed {shlex.quote(unit)} 2>/dev/null || true; "
        f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} --property=Type=exec "
        f"{APM} switch --from {shlex.quote(host)} "
        f"--eval-root /run/provider-negative-{shlex.quote(unit)}"
    )


def wait_held(flight: ProviderFlight) -> dict[str, Any]:
    """Returns the authenticated boundary event for the selected operation."""

    timeout = 900 if flight.adapter == "image-rollout" else 180
    runtime.wait_until_succeeds(f"test -s {shlex.quote(HELD_EVENT)}", timeout=timeout)
    held = json.loads(runtime.succeed(f"{COREUTILS}/cat {shlex.quote(HELD_EVENT)}"))
    event = held["event"]
    operation = event["operation"]["operation"]
    assert held["sequence"] == flight.label, held
    assert event["purpose"] == "effect", held
    assert event["boundary"] == "effect-intent-durable", held
    assert operation["interface"]["name"] == flight.interface, held
    assert operation["method"] == flight.method, held
    assert operation["target"]["resource"] == {
        "provider": operation["target"]["resource"]["provider"],
        "key": flight.resource_key,
    }, held
    assert operation["target"]["resource"]["provider"]["key"] == flight.provider_key
    return held


def project_operation(operation: dict[str, Any], ordinal: int) -> dict[str, Any]:
    """Projects the operation identity retained by qualification."""

    return {
        "key": operation["key"],
        "ordinal": ordinal,
        "interface": operation["interface"],
        "method": operation["method"],
        "resource": operation["target"]["resource"],
        "target": operation["target"],
        "inputs": operation["inputs"],
    }


def transaction_state(
    held: dict[str, Any], flight: ProviderFlight
) -> dict[str, Any]:
    """Loads the exact pair and optional behavioral witness from durable state."""

    generation = int(
        runtime.succeed(
            f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
        ).strip()
    )
    event = held["event"]
    transaction = event["transaction"]
    plan = event["operation"]["plan"]
    selected_key = event["operation"]["operation"]["key"]
    root = f"/var/lib/profiles/system/gen-{generation}/ability-transactions/{transaction}"
    bundle_bytes = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(root + '/plan-bundle.json')}"
    ).encode()
    bundle = json.loads(bundle_bytes)
    assert canonical(bundle) == bundle_bytes, bundle
    assert bundle["plan"] == plan, (bundle, held)
    effect = bundle["transition"]["effect_document"]
    selected = [
        (ordinal, operation)
        for ordinal, operation in enumerate(effect["operations"])
        if operation["key"] == selected_key
    ]
    assert len(selected) == 1, selected
    foreign_ordinal, foreign = selected[0]
    foreign_identity = project_operation(foreign, foreign_ordinal)
    outgoing = [
        edge
        for edge in effect["edges"]
        if edge["from"] == {"kind": "operation", "key": foreign["key"]}
        and edge["kind"] == "required-success"
        and edge["to"]["kind"] == "operation"
    ]
    dependents = [
        (edge, ordinal, operation)
        for edge in outgoing
        for ordinal, operation in enumerate(effect["operations"])
        if operation["key"] == edge["to"]["key"]
        and operation["interface"] == foreign["interface"]
        and operation["method"] == foreign["method"]
    ]
    assert len(dependents) == 1, dependents
    edge, dependent_ordinal, dependent = dependents[0]
    dependent_identity = project_operation(dependent, dependent_ordinal)

    witness_identity = None
    if flight.observation:
        witness_targets = set()
        frontier = {dependent["key"]}
        while frontier:
            source = frontier.pop()
            reached = {
                candidate["to"]["key"]
                for candidate in effect["edges"]
                if candidate["from"] == {"kind": "operation", "key": source}
                and candidate["kind"] == "required-success"
                and candidate["to"]["kind"] == "operation"
            }
            frontier.update(reached - witness_targets)
            witness_targets.update(reached)
        witnesses = [
            project_operation(operation, ordinal)
            for ordinal, operation in enumerate(effect["operations"])
            if operation["key"] in witness_targets
            and operation["method"] not in {"acquire", "observe", "read"}
        ]
        assert witnesses, witnesses
        witnesses.sort(key=lambda operation: canonical(operation["key"]))
        witness_identity = witnesses[0]

    return {
        "generation": generation,
        "transaction": transaction,
        "root": root,
        "bundle-bytes": bundle_bytes,
        "foreign": foreign_identity,
        "dependent": dependent_identity,
        "edge": edge,
        "witness": witness_identity,
    }


def diagnostic(state: dict[str, Any]) -> dict[str, Any]:
    """Reads the durable transaction diagnostic."""

    return json.loads(
        runtime.succeed(
            f"{AOS} --json ability diagnostic "
            f"/var/lib/profiles/system/gen-{state['generation']} "
            f"{shlex.quote(state['transaction'])}"
        )
    )


def timeline(document: dict[str, Any], ordinal: int) -> list[dict[str, Any]]:
    """Projects journal events for one operation ordinal."""

    return [
        {
            "sequence": event["sequence"],
            "kind": event["kind"],
            "node-ordinal": event["node_ordinal"],
        }
        for event in document["timeline"]["events"]
        if event.get("node_ordinal") == ordinal
    ]


def run_provider_flight(
    flight: ProviderFlight,
    host: str,
    evidence_builder: Any,
) -> None:
    """Injects foreign ownership and retains the rejected pair."""

    baseline_generation = int(
        runtime.succeed(
            f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
        ).strip()
    )
    unit = f"provider-negative-{flight.label}.service"
    arm(flight)
    start_switch(unit, host)
    held = wait_held(flight)
    state = transaction_state(held, flight)

    PROVIDER_ORACLES.inject_foreign_owner(
        flight.adapter, state["foreign"], flight.mapping
    )
    foreign_before = PROVIDER_ORACLES.observe_exact(
        flight.adapter, state["foreign"], flight.mapping
    )
    successor_before = PROVIDER_ORACLES.observe_exact(
        flight.adapter, state["dependent"], flight.mapping
    )
    witness_before = (
        None
        if state["witness"] is None
        else PROVIDER_ORACLES.observe_operation(state["witness"], flight.mapping)
    )
    write_canonical(CONTINUE, {"sequence": flight.label})
    runtime.wait_until_succeeds(
        f"state=$({SYSTEMCTL} show -p ActiveState --value {shlex.quote(unit)}); "
        'test "$state" = inactive -o "$state" = failed',
        timeout=300,
    )
    status = runtime.succeed(
        f"{SYSTEMCTL} show -p ExecMainStatus --value {shlex.quote(unit)}"
    ).strip()
    assert status != "0", (unit, status)

    retained = diagnostic(state)
    foreign_timeline = timeline(retained, state["foreign"]["ordinal"])
    dependent_timeline = timeline(retained, state["dependent"]["ordinal"])
    witness_timeline = (
        []
        if state["witness"] is None
        else timeline(retained, state["witness"]["ordinal"])
    )
    assert [event["kind"] for event in foreign_timeline] == [
        "operation-admitted",
        "effect-started",
        "rejected-before-effect",
    ], retained
    assert dependent_timeline == [], retained
    assert witness_timeline == [], retained

    foreign_after = PROVIDER_ORACLES.observe_exact(
        flight.adapter, state["foreign"], flight.mapping
    )
    successor_after = PROVIDER_ORACLES.observe_exact(
        flight.adapter, state["dependent"], flight.mapping
    )
    witness_after = (
        None
        if state["witness"] is None
        else PROVIDER_ORACLES.observe_operation(state["witness"], flight.mapping)
    )
    journal_bytes = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(state['root'] + '/execution.journal')}"
    ).encode()
    failure_event = foreign_timeline[-1]
    observation = PROVIDER_EVIDENCE.PairedFlightObservation(
        transaction=state["transaction"],
        flight=flight.label,
        boundary="after-durable-intent-before-external-effect",
        journal_digest="sha256:" + hashlib.sha256(journal_bytes).hexdigest(),
        failure_record="sha256:" + hashlib.sha256(canonical(failure_event)).hexdigest(),
        foreign_timeline=foreign_timeline,
        dependent_timeline=dependent_timeline,
        witness_timeline=witness_timeline,
        foreign_owner_count_before=foreign_before["owner-count"],
        foreign_owner_count_after=foreign_after["owner-count"],
        candidate_owner_count=0,
        maximum_owner_count=1,
        foreign=PROVIDER_EVIDENCE.LiveOracle(
            resource=state["foreign"]["resource"],
            before=foreign_before["live"],
            after=foreign_after["live"],
            live=foreign_before["owner-count"] > 0,
        ),
        successor=PROVIDER_EVIDENCE.LiveOracle(
            resource=state["dependent"]["resource"],
            before=successor_before["live"],
            after=successor_after["live"],
            live=successor_before["owner-count"] > 0,
        ),
        witness=(
            None
            if state["witness"] is None
            else PROVIDER_EVIDENCE.LiveOracle(
                resource=state["witness"]["resource"],
                before=witness_before["live"],
                after=witness_after["live"],
                live=witness_before["owner-count"] > 0,
            )
        ),
    )
    evidence_builder.retain(
        flight.adapter, flight.method, state["bundle-bytes"], observation
    )
    PROVIDER_ORACLES.restore_foreign_owner(
        flight.adapter, state["foreign"], flight.mapping
    )
    runtime.succeed(
        f"{COREUTILS}/rm -f {shlex.quote(TARGET)} {shlex.quote(HELD_EVENT)} "
        f"{shlex.quote(CONTINUE)}"
    )
    runtime.succeed(
        f"{APM} rollback --system --generation {baseline_generation}", timeout=1200
    )


def run_rollout_dependency_flight(
    flight: ProviderFlight,
    host: str,
    evidence_builder: Any,
    observe_sentinel: Any,
) -> None:
    """Rejects changed boot-slot authority and proves the same-machine successor blocks."""

    arm(flight)
    start_switch(f"provider-negative-{flight.label}.service", host)
    held = wait_held(flight)
    state = transaction_state(held, flight)

    PROVIDER_ORACLES.inject_foreign_owner(
        flight.adapter, state["foreign"], flight.mapping
    )
    machine_before = PROVIDER_ORACLES.observe_exact(
        flight.adapter, state["foreign"], flight.mapping
    )
    sentinel_before = observe_sentinel()
    write_canonical(CONTINUE, {"sequence": flight.label})
    runtime.wait_until_succeeds(
        f"{AOS} --json ability diagnostic {shlex.quote(state['root'].rsplit('/ability-transactions', 1)[0])} "
        f"{shlex.quote(state['transaction'])} | {JQ} -e "
        f"'[.timeline.events[] | select(.node_ordinal == {state['foreign']['ordinal']}) | .kind] "
        "== [\"operation-admitted\",\"effect-started\",\"rejected-before-effect\"]'",
        timeout=900,
    )

    retained = diagnostic(state)
    predecessor_timeline = timeline(retained, state["foreign"]["ordinal"])
    dependent_timeline = timeline(retained, state["dependent"]["ordinal"])
    witness_timeline = (
        []
        if state["witness"] is None
        else timeline(retained, state["witness"]["ordinal"])
    )
    assert [event["kind"] for event in predecessor_timeline] == [
        "operation-admitted",
        "effect-started",
        "rejected-before-effect",
    ], retained
    assert dependent_timeline == [], retained
    assert witness_timeline == [], retained

    machine_after = PROVIDER_ORACLES.observe_exact(
        flight.adapter, state["foreign"], flight.mapping
    )
    sentinel_after = observe_sentinel()
    journal_bytes = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(state['root'] + '/execution.journal')}"
    ).encode()
    failure_event = predecessor_timeline[-1]
    evidence_builder.retain_rollout_dependency(
        flight.method,
        state["bundle-bytes"],
        PROVIDER_EVIDENCE.RolloutDependencyObservation(
            transaction=state["transaction"],
            flight=flight.label,
            journal_digest="sha256:" + hashlib.sha256(journal_bytes).hexdigest(),
            failure_record="sha256:" + hashlib.sha256(canonical(failure_event)).hexdigest(),
            predecessor_timeline=predecessor_timeline,
            dependent_timeline=dependent_timeline,
            witness_timeline=witness_timeline,
            machine=PROVIDER_EVIDENCE.LiveOracle(
                resource=state["foreign"]["resource"],
                before=machine_before["live"],
                after=machine_after["live"],
                live=True,
            ),
            sentinel=PROVIDER_EVIDENCE.LiveOracle(
                resource={
                    "provider": state["foreign"]["resource"]["provider"]
                    | {"key": "rollout-foreign"},
                    "key": "rollout-foreign-service",
                },
                before=sentinel_before,
                after=sentinel_after,
                live=True,
            ),
        ),
    )
    PROVIDER_ORACLES.restore_foreign_owner(
        flight.adapter, state["foreign"], flight.mapping
    )
    runtime.succeed(
        f"{COREUTILS}/rm -f {shlex.quote(TARGET)} {shlex.quote(HELD_EVENT)} "
        f"{shlex.quote(CONTINUE)}"
    )
