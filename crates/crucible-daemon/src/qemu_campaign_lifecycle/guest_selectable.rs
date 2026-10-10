//! Guest request visibility and replies under the original lifecycle owner.

use super::*;

impl QemuFreshAttemptLifecycle<'_> {
    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// The result remains untrusted guest input until the modeled driver binds
    /// it to the scenario declaration and selects a legal value.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request stream is malformed.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.owner.drain_pending_selectable_requests()
    }

    /// Projects a retained guest pause into the shared scheduler clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the pause overflows or its admitted mapping is absent.
    pub fn pending_selectable_request_time(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        self.owner.pending_selectable_request_time(pending)
    }

    /// Authenticates an already committed held source without advancing peers.
    ///
    /// # Errors
    ///
    /// Returns an error when original ownership or the retained token changed.
    pub fn pending_selectable_request_is_committed_source(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<bool, SchedulerError> {
        self.owner
            .pending_selectable_request_is_committed_source(pending)
    }

    /// Applies one exact semantic reply at the authoritative scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request/reply binding fails.
    pub fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.owner
            .apply_selectable_reply(parent, decision, selected, pending, reply)
    }
}

pub(super) fn apply_replayed_guest_selectables<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    context: &AttemptExecutionContext,
    replay_context: GuestSelectableReplayContext<'_>,
    current: &mut Configuration,
    materialization: &mut QemuFreshStartMaterialization,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let pending = lifecycle
        .drain_pending_selectable_requests()
        .map_err(map_start_replay_scheduler_failure)?;
    let mut replayed = current.clone();
    let mut replies = Vec::with_capacity(pending.len());
    for pending in pending {
        let discovery = resolve_guest_selectable(
            replay_context.scenario,
            replay_context.source,
            pending.node(),
            pending.pending(),
        )
        .map_err(start_replay_guest_selectable_failure)?;
        materialization
            .retain_replayed_discovery(discovery.clone())
            .map_err(start_replay_guest_selectable_failure)?;
        let Some(Decision::Selection(decision)) = replay_context
            .target
            .schedule
            .decision_history()
            .get(replayed.schedule.len())
        else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: "pending guest selection",
                    index: replayed.schedule.len(),
                    expected: String::from("Selection"),
                    observed: replay_decision_detail(
                        replay_context
                            .target
                            .schedule
                            .decision_history()
                            .get(replayed.schedule.len()),
                    ),
                }),
            ));
        };
        let selection = decision
            .selection()
            .map_err(GuestSelectableError::Campaign)
            .map_err(start_replay_guest_selectable_failure)?;
        let expected_selection = replay_context
            .start
            .replay_selection(replayed.schedule.len());
        let fingerprint = if context.guest_selectable_boundary_diagnostic_sample_permitted() {
            lifecycle.sample_fingerprint(pending.node().clone()).ok()
        } else {
            None
        };
        record_guest_selectable_boundary_diagnostic(
            context,
            replay_context.attempt,
            GuestSelectableBoundaryDiagnosticStage::Replay,
            replayed.schedule.len(),
            pending.node(),
            pending.pending(),
            &discovery,
            expected_selection,
            fingerprint,
        );
        let validation = match selection.origin() {
            SelectionOrigin::Default | SelectionOrigin::LockedReplay => {
                selection.validate_replay(discovery.opportunity(), discovery.domain())
            }
            SelectionOrigin::CampaignBranch { .. } => {
                let parent =
                    ConfigurationId::from_hash(CampaignHash::from_bytes(replayed.id().bytes));
                selection.validate_branch_replay(
                    discovery.opportunity(),
                    discovery.domain(),
                    discovery.opportunity().branch_point_id(parent),
                )
            }
            SelectionOrigin::ModelSample(_) => {
                return Err(start_replay_guest_selectable_failure(
                    GuestSelectableError::Campaign(
                        crucible_campaign::CampaignCodecError::InvalidValue {
                            reason: "guest selectable replay does not admit model-sample provenance",
                        },
                    ),
                ));
            }
        };
        if let Err(error) = validation {
            let attempt = replay_context.attempt.id().ok();
            let mismatch = selection
                .replay_mismatch(discovery.opportunity(), discovery.domain())
                .ok()
                .flatten();
            let error = match (attempt, mismatch) {
                (Some(attempt), Some(mismatch)) => {
                    let request = pending.pending().request();
                    let replayed_configuration =
                        ConfigurationId::from_hash(CampaignHash::from_bytes(replayed.id().bytes));
                    let expected_opportunity = expected_selection.map(|selection| {
                        GuestSelectableReplayOpportunityContext::from_opportunity(
                            selection.opportunity(),
                        )
                    });
                    let correlation = GuestSelectableReplayCorrelation {
                        phase: replay_context.phase,
                        attempt_role: replay_context.attempt_role,
                        attempt,
                        replayed_configuration,
                        decision_index: replayed.schedule.len(),
                        node: pending.node().name.clone(),
                        selectable: request.selectable_id().to_owned(),
                        request_instance: request.instance_key().to_owned(),
                        request_sequence: request.sequence(),
                        request_icount: pending.pending().raw_icount(),
                        request_vcpu_index: pending.pending().vcpu_index(),
                        expected_opportunity,
                        replayed_opportunity:
                            GuestSelectableReplayOpportunityContext::from_opportunity(
                                discovery.opportunity(),
                            ),
                    };
                    GuestSelectableError::ReplayMismatch(Box::new(
                        GuestSelectableReplayMismatch::new(correlation, mismatch, error),
                    ))
                }
                _ => GuestSelectableError::Campaign(error),
            };
            return Err(start_replay_guest_selectable_failure(error));
        }
        let reply = selected_guest_reply(pending.pending(), &discovery, &selection)
            .map_err(start_replay_guest_selectable_failure)?;
        replies.push((pending, reply, decision.clone(), replayed.clone()));
        replayed = crucible::try_step(&replayed, Decision::Selection(decision.clone())).map_err(
            |error| {
                AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::DivergedAt {
                        reason: "selection schedule append",
                        index: replayed.schedule.len(),
                        expected: replay_decision_detail(Some(&Decision::Selection(
                            decision.clone(),
                        ))),
                        observed: error.to_string(),
                    },
                ))
            },
        )?;
    }
    let mut selection_entries = Vec::new();
    for (pending, reply, decision, parent) in replies {
        let selected = crucible::try_step(&parent, Decision::Selection(decision.clone())).map_err(
            |error| {
                AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::DivergedAt {
                        reason: "selection reply schedule append",
                        index: parent.schedule.len(),
                        expected: replay_decision_detail(Some(&Decision::Selection(
                            decision.clone(),
                        ))),
                        observed: error.to_string(),
                    },
                ))
            },
        )?;
        let entries = lifecycle
            .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
            .map_err(map_start_replay_scheduler_failure)?;
        selection_entries.extend(entries);
    }
    *current = replayed;
    Ok(selection_entries)
}

// A reply may commit held peer RUNs. Publish their original suffix before the
// replay returns so its count, frontier, and event log name the same boundary.
pub(super) fn publish_replayed_host_outcomes<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    target: &Configuration,
    current: &mut Configuration,
    materialization: &mut QemuFreshStartMaterialization,
) -> Result<bool, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let Some(outcome) = lifecycle
        .publish_released_host_outcomes(current)
        .map_err(map_start_replay_scheduler_failure)?
    else {
        return Ok(false);
    };
    if outcome.configuration.def != target.def
        || !target
            .schedule
            .decisions()
            .starts_with(outcome.configuration.schedule.decisions())
        || !outcome
            .configuration
            .schedule
            .decisions()
            .starts_with(current.schedule.decisions())
        || outcome
            .event_log_entries
            .iter()
            .enumerate()
            .any(|(offset, entry)| {
                entry.sequence() != materialization.event_log.len() as u64 + offset as u64
            })
    {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Diverged),
        ));
    }
    let completed_quanta = lifecycle.completed_quanta();
    if completed_quanta < materialization.completed_quanta {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::QuantumCounterRegressed {
                    before: materialization.completed_quanta,
                    after: completed_quanta,
                },
            ),
        ));
    }

    append_start_replay_events(materialization, &outcome.event_log_entries)?;
    materialization.completed_quanta = completed_quanta;
    materialization.frontier = outcome.frontier;
    materialization.terminal_quiescence = outcome.scheduler_quiescence;
    materialization.terminal_verdict = lifecycle.terminal_verdict_for_stop();
    *current = outcome.configuration;
    Ok(true)
}
