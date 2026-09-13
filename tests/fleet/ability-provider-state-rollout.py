"""Runs retained-target, adoption, and rejection A/B image flights.

Every flight uses the published-image fixture and production rollout composer.
Retained-target flights first commit the historical target, advance the host to
a later predecessor, and then execute the exact matrix method while activating
that historical generation again. Unsupported transfers inspect the exact
checked candidate operation while it is held before its provider effect.
"""

from __future__ import annotations

import json
import shlex
from typing import Any


def reverse_request(request: dict[str, Any]) -> dict[str, Any]:
    """Builds a fresh rollback request from the authenticated image pair."""

    reversed_request = json.loads(json.dumps(request))
    reversed_request["predecessor"] = request["candidate"]
    reversed_request["candidate"] = request["predecessor"]
    now = int(runtime.succeed(f"{DATE} +%s%3N").strip())
    reversed_request["retention_expires_at_millis"] = now + 600_000
    return reversed_request


def expire(request: dict[str, Any]) -> None:
    """Advances the fixture clock beyond one authenticated retention lease."""

    deadline = request["retention_expires_at_millis"] // 1000 + 1
    runtime.succeed(f"{DATE} -s @{deadline}")


def flight_for(state_cell_id: str, label: str) -> Any:
    """Projects one state cell onto its exact acquisition-boundary operation."""

    adapter, interface, _, method, _ = state_cell_id.split("/")
    if adapter != "image-rollout":
        raise RuntimeError(f"rollout cohort received foreign adapter {adapter!r}")
    flight_cell_id = "/".join(
        state_cell_id.split("/")[:-1] + ["interrupt-after-acquisition"]
    )
    return EFFECT_FLIGHT.EffectFlight(
        cell_id=flight_cell_id,
        interface=interface,
        method=method,
        provider_key="image-rollout",
        resource_key="machine",
        label=label,
    )


def observe_rollout(flight: Any, operation: dict[str, Any]) -> dict[str, Any]:
    """Observes the image state and an unrelated live systemd sentinel."""

    foreign = {
        "adapter": "systemd-manager",
        "operation": ROLLOUT_EFFECT.foreign_systemd_operation(operation),
    }
    return EFFECT_ORACLES.observe_resource(flight.cell_id, operation, foreign)


def set_health_branch(method: str, failing: bool) -> None:
    """Selects the real healthy or fallback branch needed by one method."""

    marker = "/var/lib/aos-test/rollout-health-fail"
    if failing and method in {"hold", "withdraw"}:
        runtime.succeed(f"{COREUTILS}/touch {marker}")
    else:
        runtime.succeed(f"{COREUTILS}/rm -f {marker}")


def settle(host: str, label: str) -> int:
    """Commits one production rollout activation and returns its generation."""

    runtime.succeed(f"{COREUTILS}/rm -f {EFFECT_FLIGHT.TARGET}")
    boot_id = runtime.succeed(
        f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id"
    ).strip()
    try:
        runtime.succeed(
            f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM_BASE} switch "
            f"--from {shlex.quote(host)} --eval-root /run/{shlex.quote(label)}",
            timeout=1800,
        )
    except Exception:
        runtime.wait_until_succeeds(
            f"test \"$({COREUTILS}/cat /proc/sys/kernel/random/boot_id)\" != "
            f"{shlex.quote(boot_id)}",
            timeout=900,
        )
    runtime.wait_until_succeeds(
        f"{SYSTEMCTL} is-active --quiet multi-user.target", timeout=420
    )
    return EFFECT_FLIGHT.current_generation()


def prepare_rollout_pair(
    label: str, settle_initial: bool = True
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Publishes and boots the alternate image, retaining both identities."""

    ROLLOUT_EFFECT.bootstrap_rollout_host()
    ROLLOUT_EFFECT.publish_system_candidate()
    publish_rollout_package()
    candidate = ROLLOUT_EFFECT.stage_candidate()
    forward = ROLLOUT_EFFECT.rollout_request(candidate)
    if settle_initial:
        ROLLOUT_EFFECT.settle_initial_rollout(forward, label + "-initial")
    return forward, reverse_request(forward)


def generation_bundle(generation: int) -> tuple[dict[str, Any], bytes, str]:
    """Returns one generation's canonical bundle bytes and transaction."""

    root = f"/var/lib/profiles/system/gen-{generation}"
    activation = json.loads(
        runtime.succeed(f"{COREUTILS}/cat {root}/activation.json")
    )
    transaction = activation["native_ability_transaction"]
    bundle_bytes = runtime.succeed(
        f"{COREUTILS}/cat "
        f"{root}/ability-transactions/{transaction}/plan-bundle.json"
    ).encode()
    bundle = json.loads(bundle_bytes)
    if PROVIDER_STATE_EVIDENCE.canonical(bundle) != bundle_bytes:
        raise RuntimeError("source rollout plan bundle is not canonical")
    return bundle, bundle_bytes, transaction


def generation_planning(generation: int) -> str:
    """Returns the authenticated desired planning digest for one generation."""

    bundle, _, _ = generation_bundle(generation)
    planning = bundle.get("desired", {}).get("snapshot_digest")
    if not isinstance(planning, str) or not planning.startswith("sha256:"):
        raise RuntimeError("source rollout generation lacks its planning digest")
    return planning


def policy_document(activation: dict[str, Any]) -> dict[str, Any]:
    """Loads the exact authenticated policy sidecar for one activation."""

    sidecar = activation["authenticated_policy_set"]
    path = f"{sidecar['store_path']}/{sidecar['document']}"
    return json.loads(runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}"))


def method_operation(
    bundle: dict[str, Any], method: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns an exact method and its required-success successor."""

    effect = bundle["transition"]["effect_document"]
    matches = [
        operation
        for operation in effect["operations"]
        if operation["interface"]["name"] == "aos.ab-image-rollout-effects"
        and operation["method"] == method
    ]
    if len(matches) != 1:
        raise RuntimeError("source rollout plan lacks one exact method")
    operation = matches[0]
    edges = [
        edge
        for edge in effect["edges"]
        if edge.get("from") == {"kind": "operation", "key": operation["key"]}
        and edge.get("kind") == "required-success"
        and edge.get("to", {}).get("kind") == "operation"
    ]
    if len(edges) != 1:
        raise RuntimeError("source rollout method lacks one exact successor")
    dependent_matches = [
        (ordinal, candidate)
        for ordinal, candidate in enumerate(effect["operations"])
        if candidate["key"] == edges[0]["to"]["key"]
    ]
    if len(dependent_matches) != 1:
        raise RuntimeError("source rollout successor is absent or repeated")
    ordinal, dependent = dependent_matches[0]
    dependent_identity = PROVIDER_STATE_EVIDENCE._operation_identity(
        dependent, ordinal
    )
    return operation, dependent_identity


def retained_hosts(
    label: str,
    method: str,
    forward: dict[str, Any],
    reverse: dict[str, Any],
) -> tuple[str, int, int]:
    """Creates an older target and a newer replay predecessor for rollback."""

    set_health_branch(method, False)
    if method == "retire":
        expire(forward)
        retained_host = ROLLOUT_EFFECT.rollout_host(
            forward,
            f"qualification-{method}",
            label + "-retained",
            provider_incarnation_revision=label + "-retained",
        )
        retained_generation = settle(retained_host, label + "-retained")

        predecessor_host = ROLLOUT_EFFECT.rollout_host(
            reverse,
            "rollout",
            label + "-predecessor",
            provider_incarnation_revision=label + "-predecessor",
        )
        predecessor_generation = settle(
            predecessor_host, label + "-predecessor"
        )
        expire(reverse)
    else:
        retained_host = ROLLOUT_EFFECT.rollout_host(
            reverse,
            f"qualification-{method}",
            label + "-retained",
            provider_incarnation_revision=label + "-retained",
        )
        retained_generation = settle(retained_host, label + "-retained")

        predecessor_host = ROLLOUT_EFFECT.rollout_host(
            forward,
            "rollout",
            label + "-predecessor",
            provider_incarnation_revision=label + "-predecessor",
        )
        predecessor_generation = settle(
            predecessor_host, label + "-predecessor"
        )

    if predecessor_generation <= retained_generation:
        raise RuntimeError("rollout predecessor did not follow retained generation")
    return retained_host, retained_generation, predecessor_generation


def run_retained_target(
    state_cell_id: str,
    label: str,
    flight: Any,
    forward: dict[str, Any],
    reverse: dict[str, Any],
    state_builder: Any,
) -> None:
    """Activates a retained rollout generation through its exact method."""

    method = state_cell_id.split("/")[3]
    retained_host, retained_generation, predecessor_generation = retained_hosts(
        label, method, forward, reverse
    )
    set_health_branch(method, True)

    def observe(operation: dict[str, Any]) -> dict[str, Any]:
        return observe_rollout(flight, operation)

    bridge = PROVIDER_STATE_FLIGHT.RetainedTargetBridge(
        state_builder=state_builder,
        state_cell_id=state_cell_id,
        flight_cell_id=flight.cell_id,
        retained_generation=retained_generation,
        predecessor_generation=predecessor_generation,
        source_authority=PROVIDER_STATE_FLIGHT.generation_runtime_authority(
            predecessor_generation
        ),
        observe=observe,
    )
    EFFECT_FLIGHT.run_effect_flight(
        flight,
        retained_host,
        bridge,
        observe,
        on_acquisition=bridge.on_acquisition,
        launch=PROVIDER_STATE_FLIGHT.retained_rollback_launcher(
            retained_generation
        ),
    )


def run_unsupported_transfer(
    state_cell_id: str,
    label: str,
    flight: Any,
    forward: dict[str, Any],
    state_builder: Any,
) -> None:
    """Rejects an authenticated incompatible format before provider effect."""

    method = state_cell_id.split("/")[3]
    source_revision = label + "-source"
    candidate_revision = label + "-candidate"
    ROLLOUT_EFFECT.settle_initial_rollout(
        forward,
        label + "-source",
        provider_incarnation_revision=source_revision,
        alternate_provider_incarnation_revision=candidate_revision,
    )
    source_generation = EFFECT_FLIGHT.current_generation()
    source_authority = PROVIDER_STATE_FLIGHT.generation_runtime_authority(
        source_generation
    )
    source_planning = generation_planning(source_generation)
    bundle, bundle_bytes, transaction = generation_bundle(source_generation)
    operation, dependent = method_operation(bundle, method)

    set_health_branch(method, True)
    if method == "retire":
        expire(forward)
    host, activation = ROLLOUT_EFFECT.rollout_host(
        forward,
        f"qualification-{method}",
        label + "-candidate",
        provider_incarnation_revision=candidate_revision,
        provider_package="incompatible",
        provider_adoption_source_package="compatible",
        provider_adoption_from=source_revision,
        provider_adoption_current_planning=source_planning,
        return_activation=True,
    )
    baseline = observe_rollout(flight, operation)
    ledger_before = EFFECT_ORACLES.native_resource_ledger()
    command = (
        f"HOME=/tmp PATH={NIX_BIN}:$PATH {APM_BASE} switch "
        f"--from {shlex.quote(host)} --eval-root /run/{shlex.quote(label)}"
    )
    error = runtime.fail(command, timeout=1800)
    if "state-format descriptors are incompatible" not in error:
        raise RuntimeError(f"rollout format mismatch failed differently: {error}")
    after = observe_rollout(flight, operation)

    observation = PROVIDER_STATE_EVIDENCE.IncompatibleTransferObservation(
        source_generation=source_generation,
        generation_after=EFFECT_FLIGHT.current_generation(),
        transaction=transaction,
        operation_key=operation["key"],
        activation_error=error,
        source_authority=source_authority,
        candidate_policy=policy_document(activation),
        ledger_before=ledger_before,
        ledger_after=EFFECT_ORACLES.native_resource_ledger(),
        live_before=baseline["live"],
        live_after=after["live"],
        foreign_before=baseline["foreign"],
        foreign_after=after["foreign"],
        dependent_operation=dependent,
    )
    state_builder.retain_incompatible_transfer(
        state_cell_id, bundle_bytes, observation
    )


def run_compatible_adoption(
    state_cell_id: str,
    label: str,
    flight: Any,
    forward: dict[str, Any],
    state_builder: Any,
) -> None:
    """Adopts retained machine state into a fresh provider instance."""

    method = state_cell_id.split("/")[3]
    source_revision = label + "-source"
    candidate_revision = label + "-candidate"
    ROLLOUT_EFFECT.settle_initial_rollout(
        forward,
        label + "-source",
        provider_incarnation_revision=source_revision,
        alternate_provider_incarnation_revision=candidate_revision,
    )
    source_generation = EFFECT_FLIGHT.current_generation()
    source_authority = PROVIDER_STATE_FLIGHT.generation_runtime_authority(
        source_generation
    )
    source_planning = generation_planning(source_generation)

    set_health_branch(method, True)
    if method == "retire":
        expire(forward)
    host = ROLLOUT_EFFECT.rollout_host(
        forward,
        f"qualification-{method}",
        label + "-candidate",
        provider_incarnation_revision=candidate_revision,
        provider_adoption_from=source_revision,
        provider_adoption_current_planning=source_planning,
    )

    def observe(operation: dict[str, Any]) -> dict[str, Any]:
        return observe_rollout(flight, operation)

    bridge = PROVIDER_STATE_FLIGHT.CompatibleAdoptionBridge(
        state_builder=state_builder,
        state_cell_id=state_cell_id,
        flight_cell_id=flight.cell_id,
        source_generation=source_generation,
        source_authority=source_authority,
        ledger_before=EFFECT_ORACLES.native_resource_ledger(),
        observe=observe,
        transfer_fixture=FIXTURE,
    )
    EFFECT_FLIGHT.run_effect_flight(
        flight,
        host,
        bridge,
        observe,
        on_acquisition=bridge.on_acquisition,
    )


def run_rollout_state_cell(state_cell_id: str, state_builder: Any) -> None:
    """Runs one fresh provider-state cell through the real A/B fixture."""

    method = state_cell_id.split("/")[3]
    scenario = state_cell_id.rsplit("/", 1)[-1]
    label = "rollout-state-" + method.replace("-", "_") + "-" + scenario
    flight = flight_for(state_cell_id, label)
    forward, reverse = prepare_rollout_pair(
        label,
        settle_initial=scenario
        not in {"adopt-compatible-state", "reject-unsupported-transfer"},
    )

    if scenario == "adopt-compatible-state":
        run_compatible_adoption(
            state_cell_id, label, flight, forward, state_builder
        )
    elif scenario == "activate-retained-target":
        run_retained_target(
            state_cell_id, label, flight, forward, reverse, state_builder
        )
    elif scenario == "reject-unsupported-transfer":
        run_unsupported_transfer(
            state_cell_id, label, flight, forward, state_builder
        )
    else:
        raise RuntimeError(f"unsupported rollout state scenario {scenario!r}")
