"""Runs provider-state qualification through production activation flights.

The shared effect flight selects and pauses an exact checked operation. This
module adds the state-family actions at that pause: a retained-generation
rollback is allowed to recover and execute, while an unsupported transfer is
inspected and durably rejected before the candidate process is aborted.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from typing import Any, Callable


def generation_runtime_authority(generation: int) -> dict[str, Any]:
    """Resolves the most recent transaction recorded by one active generation."""

    root = f"/var/lib/profiles/system/gen-{generation}"
    activation_path = root + "/activation.json"
    activation = json.loads(
        runtime.succeed(f"{COREUTILS}/cat {shlex.quote(activation_path)}")
    )
    transaction = activation.get("native_ability_transaction")
    if not isinstance(transaction, str) or not transaction:
        raise RuntimeError("generation activation lacks its native transaction")
    bundle_path = root + f"/ability-transactions/{transaction}/plan-bundle.json"
    bundle_payload = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(bundle_path)}"
    ).encode()
    bundle = json.loads(bundle_payload)
    if PROVIDER_STATE_EVIDENCE.canonical(bundle) != bundle_payload:
        raise RuntimeError("source generation plan bundle is not canonical")
    state = {"transaction": transaction, "plan": bundle["plan"]}
    return EFFECT_FLIGHT.current_runtime_authority(state)["document"]


def retained_rollback_launcher(retained_generation: int) -> Callable[[str, str], None]:
    """Returns an effect-flight launcher for an exact retained system generation."""

    def launch(unit: str, _host: str) -> None:
        runtime.succeed(
            f"{SYSTEMCTL} reset-failed {shlex.quote(unit)} 2>/dev/null || true; "
            f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(unit)} --property=Type=exec "
            f"{APM} rollback --system --generation {retained_generation}"
        )

    return launch


@dataclass
class RetainedTargetBridge:
    """Converts one recovered rollback flight into retained-target evidence."""

    state_builder: Any
    state_cell_id: str
    flight_cell_id: str
    retained_generation: int
    predecessor_generation: int
    observe: Callable[[dict[str, Any]], dict[str, Any]]
    acquisition: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None

    def on_acquisition(
        self, state: dict[str, Any], baseline: dict[str, Any]
    ) -> None:
        """Retains current authority and ownership before the exact method."""

        if state["source-generation"] != self.predecessor_generation:
            raise RuntimeError("rollback flight started from another predecessor")
        if state["generation"] != self.retained_generation:
            raise RuntimeError("rollback flight did not select the retained generation")
        authority = state["runtime-authority-acquisition"]["document"]
        ledger = EFFECT_ORACLES.native_resource_ledger()
        self.acquisition = (state, authority, ledger)

    def retain(
        self,
        cell_id: str,
        plan_bundle: bytes,
        _source_generation_authority: dict[str, Any],
        _candidate_generation_authority: dict[str, Any],
        effect_observation: Any,
    ) -> None:
        """Retains the recovered method, authority refresh, and live resource."""

        if cell_id != self.flight_cell_id or self.acquisition is None:
            raise RuntimeError("retained-target bridge received another flight")
        state, authority_before, ledger_before = self.acquisition
        if plan_bundle != state["bundle-bytes"]:
            raise RuntimeError("retained-target flight changed its checked plan bundle")

        authority_after = state["runtime-authority-after"]["document"]
        ledger_after = EFFECT_ORACLES.native_resource_ledger()
        activated_generation = EFFECT_FLIGHT.current_generation()
        observation = PROVIDER_STATE_EVIDENCE.RetainedTargetObservation(
            retained_generation=self.retained_generation,
            predecessor_generation=self.predecessor_generation,
            activated_generation=activated_generation,
            transaction=state["transaction"],
            operation_key=state["operation"]["key"],
            journal_before_loss=effect_observation.journal_before_loss,
            timeline=effect_observation.timeline,
            boundary_timeline=effect_observation.boundary_timeline,
            authority_before=authority_before,
            authority_after=authority_after,
            ledger_before=ledger_before,
            ledger_unsettled=ledger_before,
            ledger_after=ledger_after,
            live_before=effect_observation.live_baseline,
            live_unsettled=effect_observation.live_unsettled,
            live_after=effect_observation.live_after,
            foreign_before=effect_observation.foreign_baseline,
            foreign_unsettled=effect_observation.foreign_unsettled,
            foreign_after=effect_observation.foreign_after,
            dependent_operation=effect_observation.dependent_operation,
            dependent_before=effect_observation.dependent_before,
            dependent_after=effect_observation.dependent_after,
        )
        self.state_builder.retain_retained_target(
            self.state_cell_id, plan_bundle, observation
        )


def run_unsupported_transfer_flight(
    flight: Any,
    state_cell_id: str,
    host: str,
    state_builder: Any,
    observe: Callable[[dict[str, Any]], dict[str, Any]],
    transfer_fixture: str,
) -> None:
    """Rejects one exact checked transfer while its provider effect is held."""

    source_generation = EFFECT_FLIGHT.current_generation()
    source_authority = generation_runtime_authority(source_generation)
    baseline_sequence = EFFECT_FLIGHT.arm_baseline(flight)
    EFFECT_FLIGHT.start_switch(f"provider-transfer-{flight.label}.service", host)
    held = EFFECT_FLIGHT.wait_held(
        flight,
        sequence=baseline_sequence,
        boundary="resources-acquired",
    )
    state, baseline = EFFECT_FLIGHT.acquisition_state(held, flight, observe)
    state["source-generation"] = source_generation
    ledger_before = EFFECT_ORACLES.native_resource_ledger()

    operation_path = f"{EFFECT_FLIGHT.BOUNDARY_ROOT}/{flight.label}-operation.json"
    contract_path = state["root"] + "/provider-state-transfer-contract.json"
    EFFECT_FLIGHT.write_canonical(operation_path, state["operation-document"])
    contract_digest = runtime.succeed(
        f"{shlex.quote(transfer_fixture)} provider-state-transfer-contract "
        f"{shlex.quote(state['root'] + '/plan-bundle.json')} "
        f"{shlex.quote(operation_path)} {shlex.quote(contract_path)}"
    ).strip()
    contract = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(contract_path)}"
    ).encode()
    if not contract_digest.startswith("sha256:"):
        raise RuntimeError("production transfer inspector returned no contract digest")

    unit = f"provider-transfer-{flight.label}.service"
    aborted = EFFECT_FLIGHT.abort_acquisition(unit, flight, state)
    after = observe(state["operation-document"])
    ledger_after = EFFECT_ORACLES.native_resource_ledger()

    observation = PROVIDER_STATE_EVIDENCE.UnsupportedTransferObservation(
        source_generation=source_generation,
        candidate_generation=state["generation"],
        transaction=state["transaction"],
        operation_key=state["operation"]["key"],
        journal_at_rejection=state["journal-before-loss"],
        timeline_at_rejection=aborted["timeline"],
        boundary_timeline=aborted["boundary-timeline"],
        source_authority=source_authority,
        candidate_authority=aborted["runtime-authority"]["document"],
        ledger_before=ledger_before,
        ledger_after=ledger_after,
        live_before=baseline["live"],
        live_after=after["live"],
        foreign_before=baseline["foreign"],
        foreign_after=after["foreign"],
        dependent_operation=state["dependent"],
        dependent_timeline=aborted["dependent-timeline"],
    )
    state_builder.retain_unsupported_transfer(
        state_cell_id, state["bundle-bytes"], contract, observation
    )
