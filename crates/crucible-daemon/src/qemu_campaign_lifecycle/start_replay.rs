//! Start replay: driving a fresh or forked lifecycle to an attempt's start.
//!
//! Thin replay, anchoring, and hot children all reach their start boundary
//! through [`materialize_start_from`], which drives recorded quanta from a
//! source configuration to the target and answers every pause the recorded
//! schedule implies along the way: guest selectable requests, reserved
//! live-network choices, and network fault parks. It compares each produced
//! decision with the target schedule and never chooses anything itself.

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
        if publish_replayed_host_outcomes(lifecycle, target, &mut current, &mut replay)? {
            replay.restored_configuration = Some(current);
        }
        return Ok(replay);
    }
    if replay.terminal_verdict.is_some() {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
        ));
    }

    lifecycle.set_live_network_choice_pause(replay_pauses_before_live_network_choice(target));
    // The parent ran the audited Envoy boot prefix with concurrent RUNs; replay
    // must group them the same way to retain the parent's event log.
    let mut parallel_boot = crate::qemu_campaign_driver::envoy_choice_free_boot_replay_eligible(
        input,
        &replay.event_log,
    )
    .map_err(|error| {
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::EventLog(Box::new(error)),
        ))
    })?;
    lifecycle.set_choice_free_parallel_boot(parallel_boot);

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
    // A restored parent can already hold every VM at a network fault park.
    let initial_network_entries =
        cross_replayed_network_fault_boundary(lifecycle, input, target, &mut current, &mut replay)?;
    append_start_replay_events(&mut replay, &initial_network_entries)?;
    publish_replayed_host_outcomes(lifecycle, target, &mut current, &mut replay)?;
    if current == *target || replay.anchor_reached {
        replay.restored_configuration = Some(current);
        return Ok(replay);
    }
    if replay.terminal_verdict.is_some() {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
        ));
    }

    loop {
        if context.cancellation().is_canceled() {
            return Err(AttemptWorkerFailure::Canceled(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Canceled),
            ));
        }
        let prior_len = current.schedule.len();
        let prior_progress = StartReplayProgress::observe(&replay, prior_len);
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
        if parallel_boot {
            parallel_boot = observe_replayed_choice_free_boot(lifecycle, &outcome, prior_len)?;
        }
        park_replayed_network_fault_markers(lifecycle, input, &mut outcome)?;
        if lifecycle.live_network_preselection().is_some_and(|choice| {
            !reserved_live_network_choice_matches(
                &choice,
                target
                    .schedule
                    .decision_history()
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
        if let Some(offset) = next
            .schedule
            .decision_history()
            .iter_from(prior_len)
            .zip(
                target
                    .schedule
                    .decision_history()
                    .iter_from(prior_len)
                    .take(next_len - prior_len),
            )
            .position(|(observed, expected)| observed != expected)
        {
            let index = prior_len + offset;
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: "decision prefix",
                    index,
                    expected: replay_decision_detail(target.schedule.decision_history().get(index)),
                    observed: replay_decision_detail(next.schedule.decision_history().get(index)),
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
        let network_fault_entries = if terminal.is_none() {
            cross_replayed_network_fault_boundary(lifecycle, input, target, &mut next, &mut replay)?
        } else {
            Vec::new()
        };

        let appended = append_start_replay_events(&mut replay, &outcome.event_log_entries)
            .and_then(|()| append_start_replay_events(&mut replay, &live_network_entries))
            .and_then(|()| append_start_replay_events(&mut replay, &selection_entries))
            .and_then(|()| append_start_replay_events(&mut replay, &network_fault_entries));
        if let Err(failure) = appended {
            return Err(with_replay_progress(
                failure,
                &replay,
                next.schedule.len(),
                target.schedule.len(),
            ));
        }
        replay.terminal_quiescence = outcome.scheduler_quiescence;
        publish_replayed_host_outcomes(lifecycle, target, &mut next, &mut replay)?;
        current = next;
        // An anchor stop leaves the joined park unbranched; the caller
        // authenticates and retains that boundary instead of the target.
        if replay.anchor_reached {
            replay.restored_configuration = Some(current);
            return Ok(replay);
        }
        if current == *target {
            replay.restored_configuration = Some(current);
            if replay.terminal_verdict.is_none() {
                replay.terminal_verdict = terminal;
            }
            return Ok(replay);
        }
        if terminal.is_some() || replay.terminal_verdict.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::Terminated),
            ));
        }
        prior_progress.require_advance(StartReplayProgress::observe(
            &replay,
            current.schedule.len(),
        ))?;
    }
}

/// Returns whether start replay to `target` pauses before live-network choices.
///
/// Replay pauses exactly when the target carries a campaign branch, so the
/// branch's reserved live-network choice can be matched before it settles.
/// The mode groups RUNs, so every replay of one prefix must use the same mode.
pub(crate) fn replay_pauses_before_live_network_choice(target: &Configuration) -> bool {
    target.schedule.decision_history().iter().any(
        |decision| matches!(decision, Decision::Selection(selection) if selection.is_campaign_branch()),
    )
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
        .decision_history()
        .get(index)
        .filter(|decision| reserved_live_network_choice_matches(&choice, Some(decision)))
    else {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                reason: "reserved live-network choice",
                index,
                expected: String::from("Selection"),
                observed: replay_decision_detail(target.schedule.decision_history().get(index)),
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

pub(super) fn start_replay_guest_selectable_failure<F, D>(
    error: GuestSelectableError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(error),
    ))
}

pub(super) fn map_start_replay_scheduler_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. }
        | SchedulerError::UndeclaredConsoleMatcher(_) => None,
    };
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
