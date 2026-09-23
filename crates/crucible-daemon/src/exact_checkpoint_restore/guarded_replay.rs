//! Guarded physical replay of an authenticated exact checkpoint.
//!
//! The session owns one QEMU probe at a time. It advances the local guest in
//! charged physical steps and admits a recorded choice only at the matching
//! guest protocol boundary.

use std::fmt::{self, Write as _};

use crucible::{Configuration, Icount, ScenarioDefForm};
use crucible_campaign::{CampaignHash, ConfigurationId, ScenarioDefId, SelectionOrigin};
use crucible_protocol::SelectionReply;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_qemu::{
    QemuBakedGenesisSnapshot, QemuReplayOracleMatch, QemuReplayOracleThinObservation,
    QemuReplayValidationExecutor, QemuVmRealizationError, QemuVmReplayRequest, QemuVmSnapshot,
};

use crate::QemuAttemptProcessResourceGuard;
use crate::guest_selectable::{resolve_guest_selectable, selected_guest_reply};
use crate::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedCampaignReplaySelection,
};

// A physical step is charged separately and must not skip an unbounded guest span.
const MAX_GUARDED_REPLAY_ADVANCE_ICOUNT: u64 = 10_000_000;
const MAX_REPLAY_STALLED_REISSUES: u8 = 2;

/// Attempt-owned guarded executor for one exact fat/thin replay comparison.
///
/// The session routes the selected fat probe through the exact-root launcher
/// and every cached-ancestor or baked-genesis restore through a disjoint thin-
/// path launcher. It borrows the promotion's aggregate attempt guard while the
/// current node is active. Any realization failure transfers that aggregate
/// authority to quarantine after retaining any pre-install child.
pub(crate) struct QemuGuardedReplayOracleSession<'a, G>
where
    G: QemuAttemptProcessResourceGuard,
{
    executor: &'a mut QemuReplayValidationExecutor,
    guard: &'a mut G,
    realization_failed: bool,
    backend_reaped: bool,
    guard_terminal: bool,
}

impl<'a, G> QemuGuardedReplayOracleSession<'a, G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Borrows one aggregate attempt guard for node-local replay validation.
    #[must_use]
    pub(crate) const fn new(
        executor: &'a mut QemuReplayValidationExecutor,
        guard: &'a mut G,
    ) -> Self {
        Self {
            executor,
            guard,
            realization_failed: false,
            backend_reaped: false,
            guard_terminal: false,
        }
    }

    /// Reaps the final thin-path generation while retaining the aggregate guard.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::ReapQuarantined`] when realization or
    /// reap failed and resource ownership was transferred to quarantine. Other
    /// cleanup diagnostics are returned only after reap attestation.
    pub(crate) fn finish(mut self) -> Result<(), QemuVmRealizationError> {
        self.cleanup()
    }

    /// Compares one authenticated fat snapshot with replay from baked genesis.
    ///
    /// Runtime observations stay opaque outside `crucible-qemu`; this session
    /// may sequence guarded operations but cannot manufacture comparison
    /// evidence. The authenticated choice closure routes each selection to
    /// its owning node; a local reply requires the matching physical guest
    /// request before replay can advance.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when either guarded realization,
    /// replay quantum, or final source-bound comparison fails.
    pub(crate) fn check_snapshot_replay_oracle(
        &mut self,
        world: &crucible::World,
        source: &ScenarioDefForm,
        choices: &GuardedCampaignReplayClosure,
        configuration: &Configuration,
        snapshot: &QemuVmSnapshot,
        baked: &QemuBakedGenesisSnapshot,
    ) -> Result<QemuReplayOracleMatch, QemuVmRealizationError> {
        choices
            .validate_for_schedule(source, &configuration.schedule)
            .map_err(|error| invalid_replay_selection(error.to_string()))?;
        let target_icount = snapshot
            .checkpoint()
            .node_icounts
            .get(self.executor.node())
            .copied()
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded replay physical target",
                message: String::from("exact checkpoint has no count for the modeled node"),
            })?;

        self.guard.check_operational_boundary()?;
        let result = self
            .executor
            .load_materialized_exact_snapshot_probe_guarded(configuration, snapshot);
        let fat = self.observe_realization(result)?;
        self.guard.check_operational_boundary()?;
        let result = self.executor.drain_replay_selectable_requests();
        let fat_pending = self.observe_realization(result)?;
        if fat_pending.len() > 1 {
            return Err(invalid_replay_selection(
                "exact probe exposed multiple unanswered guest requests",
            ));
        }

        let genesis = Configuration::genesis(configuration.def.clone());
        self.guard.check_operational_boundary()?;
        let process_contract = self.guard.child_process_contract()?;
        let result = self.executor.load_prepared_baked_genesis_guarded(
            process_contract,
            &genesis,
            world,
            baked,
        );
        let mut thin = self.observe_realization(result)?;

        let mut current = genesis;
        for (decision_index, decision) in configuration.schedule.decisions().iter().enumerate() {
            let next = crucible::try_step(&current, decision.clone()).map_err(|source| {
                QemuVmRealizationError::InvalidCheckpoint {
                    role: "baked-genesis replay target",
                    message: format!("decision violates the scenario model: {source}"),
                }
            })?;
            let recorded = choices
                .selection_for_decision(decision_index, &configuration.schedule)
                .map_err(|error| invalid_replay_selection(error.to_string()))?;
            match recorded {
                Some(recorded) => {
                    let owner = recorded.guest_owner().ok_or_else(|| {
                        invalid_replay_selection("QEMU replay selection has no guest owner")
                    })?;
                    if owner == self.executor.node().name.as_str() {
                        thin = replay_one_local_guest_choice(
                            self,
                            thin,
                            target_icount,
                            source,
                            &current,
                            recorded,
                        )?;
                    } else {
                        reject_unrecorded_local_request(self)?;
                    }
                    let result = self.executor.apply_materialized_replay_decision(
                        thin,
                        QemuVmReplayRequest::new(current, decision.clone())?,
                    );
                    thin = self.observe_realization(result)?;
                }
                None => {
                    thin = replay_one_nonselection_boundary(self, thin, target_icount)?;
                    let result = self.executor.apply_materialized_replay_decision(
                        thin,
                        QemuVmReplayRequest::new(current, decision.clone())?,
                    );
                    thin = self.observe_realization(result)?;
                }
            }
            current = next;
        }
        if &current != configuration {
            return Err(QemuVmRealizationError::InvalidAncestor {
                message: String::from("baked-genesis replay did not reach target configuration"),
            });
        }

        let mut previous_ceiling = None;
        let mut stalled_reissues = 0;
        loop {
            let at = self.current_icount(&thin)?;
            if at == target_icount {
                verify_target_pending_request(self, at, fat_pending.first())?;
                if !self.executor.replay_selectable_reply_is_quiescent()? {
                    return Err(invalid_replay_selection(
                        "selected guest reply remains unconsumed at exact target count",
                    ));
                }
                break;
            }
            reject_unrecorded_local_request(self)?;
            let ceiling =
                next_replay_ceiling(at, target_icount, previous_ceiling, &mut stalled_reissues)?;
            thin = self.advance_to_ceiling(thin, ceiling)?;
            previous_ceiling = Some(ceiling);
        }

        self.executor
            .finish_replay_oracle_comparison(snapshot, configuration, fat, thin)
    }

    fn observe_realization<T>(
        &mut self,
        result: Result<T, QemuVmRealizationError>,
    ) -> Result<T, QemuVmRealizationError> {
        if result.is_err() {
            self.realization_failed = true;
            if let Some(child) = self.executor.take_failed_launch_child_for_quarantine() {
                self.guard.retain_failed_launch_child(child);
            }
        }
        let boundary = self.guard.check_operational_boundary();
        observed_realization(result, boundary)
    }

    fn cleanup(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.realization_failed && !self.guard_terminal {
            self.guard.quarantine();
            self.guard_terminal = true;
            return Err(QemuVmRealizationError::ReapQuarantined {
                operation: "finish guarded replay-oracle comparison",
                message: String::from(
                    "failed-realization process authority and attempt resources were quarantined",
                ),
            });
        }
        if !self.backend_reaped {
            match self.executor.shutdown_active_node() {
                Ok(()) => self.backend_reaped = true,
                Err(error) => {
                    if !self.guard_terminal {
                        self.guard.quarantine();
                        self.guard_terminal = true;
                    }
                    return Err(QemuVmRealizationError::ReapQuarantined {
                        operation: "finish guarded replay-oracle comparison",
                        message: error.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

trait GuardedReplayPhysicalNode {
    type Observation;

    fn node(&self) -> &crucible::NodeId;

    fn current_icount(
        &mut self,
        state: &Self::Observation,
    ) -> Result<Icount, QemuVmRealizationError>;

    fn advance_to_ceiling(
        &mut self,
        state: Self::Observation,
        ceiling: Icount,
    ) -> Result<Self::Observation, QemuVmRealizationError>;

    fn drain_pending(
        &mut self,
    ) -> Result<Vec<SelectablePlanPendingRequest>, QemuVmRealizationError>;

    fn enqueue_reply(
        &mut self,
        pending: &SelectablePlanPendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), QemuVmRealizationError>;
}

impl<G: QemuAttemptProcessResourceGuard> GuardedReplayPhysicalNode
    for QemuGuardedReplayOracleSession<'_, G>
{
    type Observation = QemuReplayOracleThinObservation;

    fn node(&self) -> &crucible::NodeId {
        self.executor.node()
    }

    fn current_icount(
        &mut self,
        state: &Self::Observation,
    ) -> Result<Icount, QemuVmRealizationError> {
        let result = self.executor.materialized_replay_icount(state);
        self.observe_realization(result)
    }

    fn advance_to_ceiling(
        &mut self,
        state: Self::Observation,
        ceiling: Icount,
    ) -> Result<Self::Observation, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        self.guard.charge_execution_quantum()?;
        let result = self
            .executor
            .advance_materialized_replay_to_ceiling(state, ceiling);
        self.observe_realization(result).map(|(state, _)| state)
    }

    fn drain_pending(
        &mut self,
    ) -> Result<Vec<SelectablePlanPendingRequest>, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self.executor.drain_replay_selectable_requests();
        self.observe_realization(result)
    }

    fn enqueue_reply(
        &mut self,
        pending: &SelectablePlanPendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self
            .executor
            .enqueue_replay_selectable_reply(pending, reply);
        self.observe_realization(result)
    }
}

fn replay_one_local_guest_choice<T: GuardedReplayPhysicalNode>(
    node: &mut T,
    mut state: T::Observation,
    target_icount: Icount,
    source: &ScenarioDefForm,
    current: &Configuration,
    recorded: &GuardedCampaignReplaySelection,
) -> Result<T::Observation, QemuVmRealizationError> {
    let mut previous_ceiling = None;
    let mut stalled_reissues = 0;
    loop {
        let pending = node.drain_pending()?;
        match pending.as_slice() {
            [request] => {
                let at = node.current_icount(&state)?;
                validate_guest_request_at_boundary(request, at)?;
                let reply = recorded_guest_reply(source, node.node(), current, recorded, request)?;
                node.enqueue_reply(request, &reply)?;
                return Ok(state);
            }
            [] => {}
            _ => {
                return Err(invalid_replay_selection(
                    "one replay boundary published multiple guest requests",
                ));
            }
        }

        let at = node.current_icount(&state)?;
        let ceiling =
            next_replay_ceiling(at, target_icount, previous_ceiling, &mut stalled_reissues)?;
        state = node.advance_to_ceiling(state, ceiling)?;
        previous_ceiling = Some(ceiling);
    }
}

fn replay_one_nonselection_boundary<T: GuardedReplayPhysicalNode>(
    node: &mut T,
    state: T::Observation,
    target_icount: Icount,
) -> Result<T::Observation, QemuVmRealizationError> {
    reject_unrecorded_local_request(node)?;
    let at = node.current_icount(&state)?;
    let retired = at
        .retired
        .checked_add(1)
        .ok_or_else(|| invalid_replay_selection("non-selection replay count overflowed"))?;
    if retired > target_icount.retired {
        return Err(invalid_replay_selection(
            "non-selection replay would cross the exact target count",
        ));
    }

    let state = node.advance_to_ceiling(state, Icount { retired })?;
    if node.current_icount(&state)?.retired != retired {
        return Err(invalid_replay_selection(
            "non-selection replay paused before its one-instruction boundary",
        ));
    }
    reject_unrecorded_local_request(node)?;
    Ok(state)
}

fn next_replay_ceiling(
    at: Icount,
    target: Icount,
    previous: Option<Icount>,
    stalled_reissues: &mut u8,
) -> Result<Icount, QemuVmRealizationError> {
    if at.retired >= target.retired {
        return Err(QemuVmRealizationError::InvalidCheckpoint {
            role: "guarded replay physical target",
            message: String::from("recorded guest choice was absent by the exact target count"),
        });
    }
    // Full quanta restart at the new count. An idle pause can instead leave
    // the count below its ceiling, so reissue briefly without extending one
    // request beyond the charged span or the exact target.
    let maximum = at
        .retired
        .saturating_add(MAX_GUARDED_REPLAY_ADVANCE_ICOUNT)
        .min(target.retired);
    let requested = match previous {
        Some(previous) if at.retired < previous.retired => previous.retired.saturating_add(1),
        _ => maximum,
    };
    let ceiling = requested.min(maximum);
    if let Some(previous) = previous {
        if ceiling < previous.retired
            || (ceiling == previous.retired && *stalled_reissues >= MAX_REPLAY_STALLED_REISSUES)
        {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "guarded replay physical target",
                message: String::from("QEMU remained paused below a bounded replay ceiling"),
            });
        }
        if ceiling == previous.retired {
            *stalled_reissues += 1;
        } else {
            *stalled_reissues = 0;
        }
    }
    Ok(Icount { retired: ceiling })
}

fn reject_unrecorded_local_request<T: GuardedReplayPhysicalNode>(
    node: &mut T,
) -> Result<(), QemuVmRealizationError> {
    if node.drain_pending()?.is_empty() {
        Ok(())
    } else {
        Err(invalid_replay_selection(
            "local guest requested a choice without a matching local recorded selection",
        ))
    }
}

fn verify_target_pending_request<T: GuardedReplayPhysicalNode>(
    node: &mut T,
    at: Icount,
    expected: Option<&SelectablePlanPendingRequest>,
) -> Result<(), QemuVmRealizationError> {
    let actual = node.drain_pending()?;
    let expected = expected.map_or(&[][..], std::slice::from_ref);
    if actual.len() == 1 {
        validate_guest_request_at_boundary(&actual[0], at)?;
    }
    if actual.as_slice() == expected {
        Ok(())
    } else {
        Err(invalid_replay_selection(
            "thin replay pending request differs from the exact probe at target",
        ))
    }
}

fn validate_guest_request_at_boundary(
    request: &SelectablePlanPendingRequest,
    at: Icount,
) -> Result<(), QemuVmRealizationError> {
    if request.icount().checked_add(1) == Some(at.retired) {
        Ok(())
    } else {
        Err(invalid_replay_selection(
            "guest request trap count does not match the physical pause",
        ))
    }
}

fn recorded_guest_reply(
    source: &ScenarioDefForm,
    node: &crucible::NodeId,
    current: &Configuration,
    recorded: &GuardedCampaignReplaySelection,
    request: &SelectablePlanPendingRequest,
) -> Result<SelectionReply, QemuVmRealizationError> {
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let discovery = resolve_guest_selectable(scenario, source, node, request)
        .map_err(|error| invalid_replay_selection(error.to_string()))?;
    if discovery.declaration() != recorded.declaration()
        || discovery.opportunity() != recorded.opportunity()
        || discovery.domain() != recorded.domain()
    {
        return Err(invalid_replay_selection(
            "physical guest request differs from the authenticated replay choice",
        ));
    }

    let selection = recorded.selection();
    let validation = match selection.origin() {
        SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
            selection.validate_replay(discovery.opportunity(), discovery.domain())
        }
        SelectionOrigin::CampaignBranch { .. } => {
            let parent = ConfigurationId::from_hash(CampaignHash::from_bytes(current.id().bytes));
            selection.validate_branch_replay(
                discovery.opportunity(),
                discovery.domain(),
                discovery.opportunity().branch_point_id(parent),
            )
        }
        SelectionOrigin::ModelSample(_) => {
            return Err(invalid_replay_selection(
                "guarded guest replay does not admit model-sample selection provenance",
            ));
        }
    };
    validation.map_err(|error| invalid_replay_selection(error.to_string()))?;
    selected_guest_reply(request, &discovery, selection)
        .map_err(|error| invalid_replay_selection(error.to_string()))
}

fn invalid_replay_selection(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::InvalidCheckpoint {
        role: "guarded replay guest selection",
        message: message.into(),
    }
}

fn observed_realization<T>(
    result: Result<T, QemuVmRealizationError>,
    boundary: Result<(), QemuVmRealizationError>,
) -> Result<T, QemuVmRealizationError> {
    match (result, boundary) {
        (Err(cause), Err(cleanup @ QemuVmRealizationError::ReapQuarantined { .. })) => {
            Err(replay_quarantine_with_cause(cause, cleanup))
        }
        // The session still quarantines a failed realization during finish.
        // Retain its cause when a second boundary error cannot explain it.
        (Err(cause), _) => Err(cause),
        (Ok(_), Err(boundary)) => Err(boundary),
        (Ok(value), Ok(())) => Ok(value),
    }
}

const MAX_REPLAY_QUARANTINE_DETAIL_BYTES: usize = 2 * 1024;
const REPLAY_QUARANTINE_TRUNCATION_SUFFIX: &str = " ... [truncated]";

struct BoundedReplayQuarantineDetail(String);

impl fmt::Write for BoundedReplayQuarantineDetail {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let available = MAX_REPLAY_QUARANTINE_DETAIL_BYTES
            .saturating_sub(REPLAY_QUARANTINE_TRUNCATION_SUFFIX.len())
            .saturating_sub(self.0.len());
        let mut boundary = available.min(value.len());
        while !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        self.0.push_str(&value[..boundary]);
        if boundary < value.len() {
            self.0.push_str(REPLAY_QUARANTINE_TRUNCATION_SUFFIX);
            return Err(fmt::Error);
        }
        Ok(())
    }
}

/// Keeps quarantine authoritative while placing the initiating replay failure first.
pub(crate) fn replay_quarantine_with_cause(
    cause: QemuVmRealizationError,
    cleanup: QemuVmRealizationError,
) -> QemuVmRealizationError {
    let QemuVmRealizationError::ReapQuarantined { operation, message } = cleanup else {
        return cause;
    };
    let mut detail = BoundedReplayQuarantineDetail(String::new());
    match &cause {
        QemuVmRealizationError::ReapQuarantined {
            message: earlier, ..
        } if earlier.starts_with("replay comparison failed: ") => {
            let _ = write!(detail, "{earlier}; cleanup: {message}");
        }
        _ => {
            let _ = write!(
                detail,
                "replay comparison failed: {cause}; cleanup: {message}"
            );
        }
    }
    QemuVmRealizationError::ReapQuarantined {
        operation,
        message: detail.0,
    }
}

impl<G> Drop for QemuGuardedReplayOracleSession<'_, G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests;
