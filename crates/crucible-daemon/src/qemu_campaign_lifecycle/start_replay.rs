//! Deterministic start reconstruction and classified lifecycle cleanup.
//!
//! Replay authenticates each modeled decision and retains scheduler evidence
//! before ordinary attempt work begins. Error adapters preserve cancellation
//! and actual teardown failures across the guarded lifecycle boundary.

use super::*;

pub(super) fn materialize_fresh_start<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    target: &Configuration,
    context: &AttemptExecutionContext,
    retain_replayed_discoveries: bool,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let completed_quanta = lifecycle.completed_quanta();
    materialize_start_from(
        lifecycle,
        input,
        Configuration::genesis(target.def.clone()),
        target,
        context,
        QemuFreshStartMaterialization {
            retain_replayed_discoveries,
            ..QemuFreshStartMaterialization::at_quanta(completed_quanta)
        },
    )
}

pub(crate) fn materialize_start_from<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    mut current: Configuration,
    target: &Configuration,
    context: &AttemptExecutionContext,
    mut replay: QemuFreshStartMaterialization,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let authoritative_quanta = lifecycle.completed_quanta();
    if replay.completed_quanta != authoritative_quanta {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::QuantumCoordinateMismatch {
                    materialized: replay.completed_quanta,
                    authoritative: authoritative_quanta,
                },
            ),
        ));
    }
    if current == *target {
        return Ok(replay);
    }
    if replay.terminal_verdict.is_some() {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
        ));
    }

    lifecycle.set_live_network_choice_pause(target.schedule.decisions().iter().any(|decision| {
        matches!(decision, Decision::Selection(selection) if selection.is_campaign_branch())
    }));

    // A guest selectable can already be pending at lifecycle admission. Replay
    // it at the current boundary before charging a quantum so a saved choice at
    // genesis retains its original absolute quantum and event coordinates.
    let initial_selection_entries = apply_replayed_guest_selectables(
        lifecycle,
        context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: input.attempt(),
            start: input.start(),
            scenario: input.lineage().scenario(),
            source: input.scenario(),
            target,
        },
        &mut current,
        &mut replay,
    )?;
    append_start_replay_events(&mut replay, &initial_selection_entries)?;
    if current == *target {
        replay.restored_configuration = Some(current);
        return Ok(replay);
    }

    loop {
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }
        let prior_len = current.schedule.len();
        context.charge_execution_quantum().map_err(|error| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::ResourceRefusal(error),
            ))
        })?;
        let mut outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: current,
                control: Vec::new(),
            })
            .map_err(map_start_replay_scheduler_failure)?;
        if lifecycle.live_network_preselection().is_some_and(|choice| {
            !reserved_live_network_choice_matches(
                &choice,
                target
                    .schedule
                    .decisions()
                    .get(outcome.configuration.schedule.len()),
            )
        }) {
            outcome = lifecycle
                .settle_live_network_preselection()
                .map_err(map_start_replay_scheduler_failure)?;
        }
        let completed_quanta = lifecycle.completed_quanta();
        if completed_quanta < replay.completed_quanta {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::QuantumCounterRegressed {
                        before: replay.completed_quanta,
                        after: completed_quanta,
                    },
                ),
            ));
        }
        let prior_completed_quanta = replay.completed_quanta;
        replay.completed_quanta = completed_quanta;
        replay.frontier = outcome.frontier;
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }

        let mut next = outcome.configuration;
        let next_len = next.schedule.len();
        if next.def != target.def {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: "scenario identity",
                    index: prior_len,
                    expected: format!("{:?}", target.def.id()),
                    observed: format!("{:?}", next.def.id()),
                }),
            ));
        }
        if next_len < prior_len || next_len > target.schedule.len() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: "schedule length",
                    index: prior_len,
                    expected: format!("{prior_len}..={}", target.schedule.len()),
                    observed: next_len.to_string(),
                }),
            ));
        }
        if let Some(offset) = next.schedule.decisions()[prior_len..]
            .iter()
            .zip(&target.schedule.decisions()[prior_len..next_len])
            .position(|(observed, expected)| observed != expected)
        {
            let index = prior_len + offset;
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: "decision prefix",
                    index,
                    expected: replay_decision_detail(target.schedule.decisions().get(index)),
                    observed: replay_decision_detail(next.schedule.decisions().get(index)),
                }),
            ));
        }
        let terminal = lifecycle.terminal_verdict_for_stop();
        let live_network_entries = if terminal.is_none() {
            apply_replayed_live_network_selection(lifecycle, target, &mut next)?
        } else {
            Vec::new()
        };
        let selection_entries = if terminal.is_none() {
            apply_replayed_guest_selectables(
                lifecycle,
                context,
                GuestSelectableReplayContext {
                    phase: GuestSelectableReplayPhase::FreshStart,
                    attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
                    attempt: input.attempt(),
                    start: input.start(),
                    scenario: input.lineage().scenario(),
                    source: input.scenario(),
                    target,
                },
                &mut next,
                &mut replay,
            )?
        } else {
            Vec::new()
        };

        append_start_replay_events(&mut replay, &outcome.event_log_entries)?;
        append_start_replay_events(&mut replay, &live_network_entries)?;
        append_start_replay_events(&mut replay, &selection_entries)?;
        replay.terminal_quiescence = outcome.scheduler_quiescence;
        current = next;
        if current == *target {
            replay.restored_configuration = Some(current);
            replay.terminal_verdict = terminal;
            return Ok(replay);
        }
        if terminal.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
            ));
        }
        if replay.completed_quanta == prior_completed_quanta && current.schedule.len() == prior_len
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: "no progress",
                    index: prior_len,
                    expected: String::from("quantum or schedule progress"),
                    observed: format!(
                        "quanta={} schedule_len={}",
                        replay.completed_quanta,
                        current.schedule.len()
                    ),
                }),
            ));
        }
    }
}

pub(super) fn apply_replayed_live_network_selection<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    target: &Configuration,
    current: &mut Configuration,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let Some(choice) = lifecycle.live_network_preselection() else {
        return Ok(Vec::new());
    };
    let index = current.schedule.len();
    let Some(Decision::Selection(selection)) = target
        .schedule
        .decisions()
        .get(index)
        .filter(|decision| reserved_live_network_choice_matches(&choice, Some(decision)))
    else {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                reason: "reserved live-network choice",
                index,
                expected: String::from("Selection"),
                observed: replay_decision_detail(target.schedule.decisions().get(index)),
            }),
        ));
    };
    if choice.parent != *current {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                reason: "live-network parent",
                index,
                expected: format!("{:?}", choice.parent.id()),
                observed: format!("{:?}", current.id()),
            }),
        ));
    }
    let entries = lifecycle
        .select_live_network_preselection(selection.clone())
        .map_err(map_start_replay_scheduler_failure)?;
    *current =
        crucible::try_step(current, Decision::Selection(selection.clone())).map_err(|_| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::Diverged,
            ))
        })?;
    Ok(entries)
}

pub(super) fn reserved_live_network_choice_matches(
    choice: &crucible::LiveNetworkPreselection,
    decision: Option<&Decision>,
) -> bool {
    let Some(Decision::Selection(selection)) = decision else {
        return false;
    };
    selection.is_campaign_branch()
        && choice.frontier.choices.choices().iter().any(|alternative| {
            alternative.decisions().first() == Some(&Decision::Selection(selection.clone()))
        })
}

pub(super) fn authenticated_live_network_start_selection(
    start: &CrucibleResolvedAttemptStart,
) -> Option<SelectionDecision> {
    match start {
        CrucibleResolvedAttemptStart::Branch { selection, .. }
            if matches!(selection.declaration().source(), ChoiceSource::Scheduler { producer }
                if producer == "crucible.live-world-network.v1") =>
        {
            Some(SelectionDecision::new(selection.selection()))
        }
        CrucibleResolvedAttemptStart::AfterAttempt { base, .. } => {
            authenticated_live_network_start_selection(base)
        }
        CrucibleResolvedAttemptStart::Discover { .. }
        | CrucibleResolvedAttemptStart::Branch { .. } => None,
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
            .decisions()
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
                            .decisions()
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

pub(super) fn start_replay_guest_selectable_failure<F, D>(
    error: GuestSelectableError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(error),
    ))
}

pub(super) fn append_start_replay_events<F, D>(
    replay: &mut QemuFreshStartMaterialization,
    entries: &[SchedulerEventLogEntry],
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let count = replay
        .event_log
        .len()
        .checked_add(entries.len())
        .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-entry-count"))?;
    if count > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::LimitExceeded {
                limit: "fresh-campaign-event-log-entry-count",
            }),
        ));
    }
    let added = entries.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.canonical_material_len().map_err(|source| {
                AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                    QemuFreshStartReplayError::Scheduler(SchedulerError::from(source)),
                ))
            })?)
            .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-bytes"))
    })?;
    let bytes = replay
        .event_log_bytes
        .checked_add(added)
        .ok_or_else(|| start_replay_limit_failure("fresh-campaign-event-log-bytes"))?;
    if bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            }),
        ));
    }
    replay.event_log.extend_from_slice(entries);
    replay.event_log_bytes = bytes;
    Ok(())
}

pub(super) fn start_replay_limit_failure<F, D>(
    limit: &'static str,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::LimitExceeded { limit },
    ))
}

pub(super) fn map_start_replay_scheduler_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = error.operational_failure_class();
    let error =
        QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Scheduler(error));
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(super) fn map_checkpoint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = error.operational_failure_class();
    let error = QemuFreshExecutionRunnerError::CheckpointCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(super) fn map_terminal_fingerprint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = error.operational_failure_class();
    let error = QemuFreshExecutionRunnerError::TerminalFingerprintCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(super) fn map_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CheckpointHandoff(error))
        }
    }
}

pub(super) fn map_fresh_lifecycle_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Lifecycle(error))
        }
    }
}

pub(super) fn map_fresh_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error))
        }
    }
}

pub(super) fn cleanup_after_fresh_runner_failure<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
    cleanup: SchedulerError,
) -> QemuFreshExecutionRunnerError<F, D>
where
    D: std::fmt::Display,
{
    let driver = match failure {
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::Driver(error))
        | AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Driver(error)) => error,
        AttemptWorkerFailure::Retryable(error)
        | AttemptWorkerFailure::Canceled(error)
        | AttemptWorkerFailure::Terminal(error) => {
            return QemuFreshExecutionRunnerError::CleanupAfterRunner {
                failure: Box::new(error),
                cleanup,
            };
        }
    };
    let driver_diagnostic = bounded_driver_failure(&driver);
    QemuFreshExecutionRunnerError::CleanupAfterDriver {
        driver,
        driver_diagnostic,
        cleanup,
    }
}
