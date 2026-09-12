"""Runs retained-target and unsupported-transfer A/B image flights.

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


def prepare_rollout_pair(label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Publishes and boots the alternate image, retaining both identities."""

    ROLLOUT_EFFECT.bootstrap_rollout_host()
    ROLLOUT_EFFECT.publish_system_candidate()
    publish_rollout_package()
    candidate = ROLLOUT_EFFECT.stage_candidate()
    forward = ROLLOUT_EFFECT.rollout_request(candidate)
    ROLLOUT_EFFECT.settle_initial_rollout(forward, label + "-initial")
    return forward, reverse_request(forward)


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
            forward, "retire", label + "-retained"
        )
        retained_generation = settle(retained_host, label + "-retained")

        predecessor_host = ROLLOUT_EFFECT.rollout_host(
            reverse, "desired", label + "-predecessor"
        )
        predecessor_generation = settle(
            predecessor_host, label + "-predecessor"
        )
        expire(reverse)
    else:
        retained_host = ROLLOUT_EFFECT.rollout_host(
            reverse, "desired", label + "-retained"
        )
        retained_generation = settle(retained_host, label + "-retained")

        predecessor_host = ROLLOUT_EFFECT.rollout_host(
            forward, "desired", label + "-predecessor"
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
    reverse: dict[str, Any],
    state_builder: Any,
) -> None:
    """Rejects a fresh image provider route before the exact method effect."""

    method = state_cell_id.split("/")[3]
    set_health_branch(method, True)
    if method == "retire":
        expire(forward)
        host = ROLLOUT_EFFECT.rollout_host(forward, "retire", label)
    else:
        host = ROLLOUT_EFFECT.rollout_host(reverse, "desired", label)

    def observe(operation: dict[str, Any]) -> dict[str, Any]:
        return observe_rollout(flight, operation)

    PROVIDER_STATE_FLIGHT.run_unsupported_transfer_flight(
        flight,
        state_cell_id,
        host,
        state_builder,
        observe,
        FIXTURE,
    )


def run_rollout_state_cell(state_cell_id: str, state_builder: Any) -> None:
    """Runs one fresh provider-state cell through the real A/B fixture."""

    method = state_cell_id.split("/")[3]
    scenario = state_cell_id.rsplit("/", 1)[-1]
    label = "rollout-state-" + method.replace("-", "_") + "-" + scenario
    flight = flight_for(state_cell_id, label)
    forward, reverse = prepare_rollout_pair(label)

    if scenario == "activate-retained-target":
        run_retained_target(
            state_cell_id, label, flight, forward, reverse, state_builder
        )
    elif scenario == "reject-unsupported-transfer":
        run_unsupported_transfer(
            state_cell_id, label, flight, forward, reverse, state_builder
        )
    else:
        raise RuntimeError(f"unsupported rollout state scenario {scenario!r}")
