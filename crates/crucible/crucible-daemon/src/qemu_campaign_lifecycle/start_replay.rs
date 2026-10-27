//! Start replay: driving a fresh or forked lifecycle to an attempt's start.
//!
//! Thin replay, anchoring, and hot children all reach their start boundary
//! through [`materialize_start_from`], which drives recorded quanta from a
//! source configuration to the target and answers every pause the recorded
//! schedule implies along the way: guest selectable requests, reserved
//! live-network choices, and network fault parks. It compares each produced
//! decision with the target schedule and never chooses anything itself.
//!
//! A [`StartReplayCursor`] records how far replay verified the target and
//! whether it was applying a recorded decision when it stopped. A hot child
//! forked from an ancestor root uses it to tell a failure of the root's
//! suffix, which is operational, from a failure applying the attempt's own
//! edge, which belongs to the attempt.

use super::*;

/// Where one start replay stood, for classifying a failure by its position.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StartReplayCursor {
    /// Schedule length of the deepest configuration verified against the
    /// target.
    reached: usize,
    /// Whether replay was applying the recorded decision at `reached` (a
    /// guest reply, a network fault branch append, or a live-network
    /// selection) rather than driving or validating toward it.
    applying: bool,
}

impl StartReplayCursor {
    /// Records that replay verified the target up to `reached` decisions.
    pub(super) fn at(&mut self, reached: usize) {
        self.reached = reached;
        self.applying = false;
    }

    /// Records that replay is applying the recorded decision at `index`.
    pub(super) fn applying_at(&mut self, index: usize) {
        self.reached = index;
        self.applying = true;
    }

    /// Returns the deepest verified schedule length and whether replay was
    /// applying the recorded decision there.
    #[cfg(test)]
    pub(crate) const fn position(self) -> (usize, bool) {
        (self.reached, self.applying)
    }

    /// Reports whether a failure at this cursor arose before replay began
    /// applying the recorded decision at `edge`.
    ///
    /// A divergence names its own decision index, which takes precedence
    /// over the cursor; cancellation never counts.
    pub(crate) fn failed_before<F, D>(
        self,
        failure: &AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
        edge: usize,
    ) -> bool {
        let error = match failure {
            AttemptWorkerFailure::Canceled(_) => return false,
            AttemptWorkerFailure::Retryable(error) | AttemptWorkerFailure::Terminal(error) => error,
        };
        if let QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
            index,
            ..
        }) = error
        {
            return *index < edge;
        }
        self.reached < edge || (self.reached == edge && !self.applying)
    }
}

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
    current: Configuration,
    target: &Configuration,
    context: &AttemptExecutionContext,
    replay: QemuFreshStartMaterialization,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    materialize_start_from_tracked(
        lifecycle,
        input,
        current,
        target,
        context,
        replay,
        &mut StartReplayCursor::default(),
    )
}

/// Runs [`materialize_start_from`], keeping `cursor` at replay's position.
///
/// On failure, `cursor` names the deepest verified schedule length and
/// whether a recorded decision was being applied there.
pub(crate) fn materialize_start_from_tracked<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    mut current: Configuration,
    target: &Configuration,
    context: &AttemptExecutionContext,
    mut replay: QemuFreshStartMaterialization,
    cursor: &mut StartReplayCursor,
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    cursor.at(current.schedule.len());
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
    // Replay begins at `current`, so the lifecycle must stand exactly there:
    // a restored materialization names its boundary, and an unrestored one
    // is a fresh lifecycle at genesis. Anything else fails closed.
    let standing = match &replay.restored_configuration {
        Some(restored) => restored == &current,
        None => current == Configuration::genesis(current.def.clone()),
    };
    if !standing {
        let observed = replay.restored_configuration.as_ref().map_or_else(
            || String::from("genesis"),
            |restored| restored.id().to_hex(),
        );
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::SourceMismatch {
                expected: current.id().to_hex(),
                observed,
            }),
        ));
    }
    {
        // Names the exact recording each replay verifies, so two runs that
        // diverge differently can be told apart from two different recordings.
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "CRUCIBLE-START-REPLAY-V1 source={} source_decisions={} target={} target_decisions={}",
            current.id().to_hex(),
            current.schedule.len(),
            target.id().to_hex(),
            target.schedule.len(),
        );
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
    // RUN grouping no longer depends on this mark: every attempt runs each
    // node to its own graph horizon. Replay re-arms it so a choice inside the
    // audited Envoy boot prefix still fails closed, as it did in the parent.
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
        cursor,
    )?;
    append_start_replay_events(&mut replay, &initial_selection_entries)?;
    // A restored parent can already hold every VM at a network fault park.
    cursor.applying_at(current.schedule.len());
    let initial_network_entries =
        cross_replayed_network_fault_boundary(lifecycle, input, target, &mut current, &mut replay)?;
    cursor.at(current.schedule.len());
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
        cursor.at(prior_len);
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
            // The neighbours show whether the two runs ordered the same
            // decisions differently or produced different ones; the replayed
            // entries show the time each was logged at.
            use std::io::Write as _;
            let center = replay_window_center(
                target.schedule.decision_history(),
                index,
                target.schedule.len(),
            );
            let entries = replay_entry_window(
                outcome.event_log_entries.iter().map(|entry| {
                    (
                        entry.sequence(),
                        entry.at().ticks,
                        entry.event_payload().kind(),
                    )
                }),
                center,
            );
            let (observed_entries, observed_at) = observed_decision_entry_window(
                outcome.event_log_entries.iter().map(|entry| {
                    let payload = entry.event_payload();
                    ReplayEntrySummary {
                        sequence: entry.sequence(),
                        at: entry.at().ticks,
                        kind: payload.kind(),
                        stream: payload.string("stream_name"),
                        value: payload.u64("value"),
                        delivery_at: match payload.attribute("at") {
                            Some(crucible_engine::EventAttributeValue::VirtualTime(at)) => Some(at.ticks),
                            _ => None,
                        },
                    }
                }),
                next.schedule.decision_history().get(index),
            );
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "CRUCIBLE-REPLAY-DIVERGENCE-V1 index={index} quantum_start={prior_len} quantum_end={next_len} expected=[{}] observed=[{}] observed_entries=[{entries}] observed_decision_entries=[{observed_entries}]",
                replay_decision_window(
                    target.schedule.decision_history(),
                    index,
                    target.schedule.len()
                ),
                replay_decision_window(next.schedule.decision_history(), index, next_len),
            );
            // Admissions near either divergent position show each frame's
            // emission coordinate beside the time its admission was logged.
            if let Some(admission_center) = observed_at.or(center) {
                for record in crucible_engine::scheduler::network_admission_trace::records_near(
                    admission_center,
                    REPLAY_ADMISSION_HALF_WINDOW_PS,
                    REPLAY_ADMISSION_ROWS,
                ) {
                    let _ = writeln!(stderr, "{}", record.row());
                }
                // Committed host RUNs near the same time show where each
                // node stopped, how far it was settled, and which inputs
                // reached it there.
                for record in crucible_engine::scheduler::host_run_trace::records_near(
                    admission_center,
                    REPLAY_ADMISSION_HALF_WINDOW_PS,
                    REPLAY_ADMISSION_ROWS,
                ) {
                    let _ = writeln!(stderr, "{}", record.row());
                }
            }

            let expected = target.schedule.decision_history().get(index);
            let observed = next.schedule.decision_history().get(index);
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                    reason: replay_decision_divergence_reason(expected, observed),
                    index,
                    expected: replay_decision_detail(expected),
                    observed: replay_decision_detail(observed),
                }),
            ));
        }
        cursor.at(next_len);
        let terminal = lifecycle.terminal_verdict_for_stop();
        let live_network_entries = if terminal.is_none() {
            apply_replayed_live_network_selection(lifecycle, target, &mut next, cursor)?
        } else {
            Vec::new()
        };
        cursor.at(next.schedule.len());
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
                cursor,
            )?
        } else {
            Vec::new()
        };
        let network_fault_entries = if terminal.is_none() {
            cursor.applying_at(next.schedule.len());
            cross_replayed_network_fault_boundary(lifecycle, input, target, &mut next, &mut replay)?
        } else {
            Vec::new()
        };
        cursor.at(next.schedule.len());

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
        cursor.at(current.schedule.len());
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
    cursor: &mut StartReplayCursor,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    let Some(choice) = lifecycle.live_network_preselection() else {
        return Ok(Vec::new());
    };
    let index = current.schedule.len();
    cursor.applying_at(index);
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
        crucible_engine::try_step(current, Decision::Selection(selection.clone())).map_err(|_| {
            AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::Diverged,
            ))
        })?;
    Ok(entries)
}

pub(super) fn reserved_live_network_choice_matches(
    choice: &crucible_engine::LiveNetworkPreselection,
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

/// Returns the latest delivery time within eight decisions of `index`.
///
/// The decision window names positions only; this time centers the window of
/// replayed log entries that shows when each of them was logged.
fn replay_window_center(
    history: &crucible_engine::History<Decision>,
    index: usize,
    length: usize,
) -> Option<u64> {
    const RADIUS: usize = 8;

    let start = index.saturating_sub(RADIUS);
    let end = index.saturating_add(RADIUS).min(length);
    (start..end)
        .filter_map(|position| match history.get(position) {
            Some(Decision::DeliveryOrder(order)) => Some(order.at.ticks),
            _ => None,
        })
        .max()
}

/// Summarizes the replayed quantum's log entries near the divergence.
///
/// A draw admitted at a delivery's time but logged on the other side of it
/// shows its admission time here, and the evaluation boundaries between
/// entries show how the replayed RUNs split around it. Each entry is
/// `sequence@at:kind`. Only entries within 40 microseconds of `center` are
/// kept, at most 64, so the row stays one bounded line.
fn replay_entry_window<'a>(
    entries: impl IntoIterator<Item = (u64, u64, &'a str)>,
    center: Option<u64>,
) -> String {
    const HALF_WINDOW_PS: u64 = 40_000_000;
    const MAXIMUM_ENTRIES: usize = 64;

    let Some(center) = center else {
        return String::new();
    };
    entries
        .into_iter()
        .filter(|(_, at, _)| at.abs_diff(center) <= HALF_WINDOW_PS)
        .take(MAXIMUM_ENTRIES)
        .map(|(sequence, at, kind)| format!("{sequence}@{at}:{kind}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Admission and host-RUN rows printed beside a divergence are those within
/// this distance of the observed decision.
const REPLAY_ADMISSION_HALF_WINDOW_PS: u64 = 100_000_000;

/// Most admission rows, and most host-RUN rows, printed beside one divergence.
const REPLAY_ADMISSION_ROWS: usize = 48;

/// One replayed log entry, reduced to what a divergence row prints.
struct ReplayEntrySummary<'a> {
    sequence: u64,
    at: u64,
    kind: &'a str,
    stream: Option<&'a str>,
    value: Option<u64>,
    delivery_at: Option<u64>,
}

/// Summarizes the replayed entries around the observed divergent decision.
///
/// The expected side's window is centered on the recorded delivery time, so
/// an observed decision logged far from it is invisible there. This window
/// finds the replayed entry that carries the observed decision and prints
/// twelve entries on either side, as `sequence@at:kind`, with each draw's
/// stream. It also returns that entry's log time.
fn observed_decision_entry_window<'a>(
    entries: impl IntoIterator<Item = ReplayEntrySummary<'a>>,
    decision: Option<&Decision>,
) -> (String, Option<u64>) {
    const RADIUS: usize = 12;

    let entries = entries.into_iter().collect::<Vec<_>>();
    let carries_decision = |entry: &ReplayEntrySummary<'_>| match decision {
        Some(Decision::RngDraw(draw)) => {
            entry.kind == "rng_draw"
                && entry.value == Some(draw.value)
                && entry.stream == Some(draw.stream.name.as_str())
        }
        Some(Decision::DeliveryOrder(order)) => {
            entry.kind == "delivery_order" && entry.delivery_at == Some(order.at.ticks)
        }
        _ => false,
    };
    let Some(position) = entries.iter().position(carries_decision) else {
        return (String::new(), None);
    };

    let start = position.saturating_sub(RADIUS);
    let end = position.saturating_add(RADIUS + 1).min(entries.len());
    let window = entries[start..end]
        .iter()
        .map(|entry| match entry.stream {
            Some(stream) => format!(
                "{}@{}:{}[{}]",
                entry.sequence,
                entry.at,
                entry.kind,
                stream.replace('\n', ";")
            ),
            None => format!("{}@{}:{}", entry.sequence, entry.at, entry.kind),
        })
        .collect::<Vec<_>>()
        .join(" ");
    (window, Some(entries[position].at))
}

pub(super) fn start_replay_guest_selectable_failure<F, D>(
    error: GuestSelectableError,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(error),
    ))
}

#[cfg(test)]
mod tests {
    use super::{ReplayEntrySummary, observed_decision_entry_window, replay_entry_window};

    #[test]
    fn replayed_entries_near_the_divergence_carry_their_log_times() {
        let entries = [
            (9, 1_000, "delivery_order"),
            (10, 20_000_000, "delivery_order"),
            (11, 50_000_000, "evaluation_boundary"),
            (12, 50_000_000, "rng_draw"),
            (13, 95_000_000, "delivery_order"),
        ];

        assert_eq!(
            replay_entry_window(entries, Some(50_000_000)),
            "10@20000000:delivery_order 11@50000000:evaluation_boundary 12@50000000:rng_draw"
        );
    }

    #[test]
    fn the_observed_window_centers_on_the_entry_carrying_the_observed_draw() {
        let stream = "link_endpoint_a=router-a\nlink_endpoint_b=router-c";
        let entry = |sequence, at, kind, value| ReplayEntrySummary {
            sequence,
            at,
            kind,
            stream: (kind == "rng_draw").then_some(stream),
            value,
            delivery_at: (kind == "delivery_order").then_some(at),
        };
        let entries = [
            entry(1, 10, "delivery_order", None),
            entry(2, 39, "rng_draw", Some(7)),
            entry(3, 40, "delivery_order", None),
        ];
        let draw = crucible_engine::Decision::RngDraw(crucible_engine::RngDecision::ordinal(
            crucible_engine::RngStreamId {
                domain: String::from("crucible.decision-rng.link-stream.v1"),
                name: stream.to_owned(),
            },
            0,
            7,
        ));

        let (window, at) = observed_decision_entry_window(entries, Some(&draw));

        assert_eq!(at, Some(39));
        assert_eq!(
            window,
            "1@10:delivery_order 2@39:rng_draw[link_endpoint_a=router-a;link_endpoint_b=router-c] 3@40:delivery_order"
        );
        assert_eq!(
            observed_decision_entry_window(Vec::new(), Some(&draw)),
            (String::new(), None)
        );
    }

    #[test]
    fn a_window_without_a_delivery_prints_no_entries() {
        assert_eq!(replay_entry_window([(1, 5, "rng_draw")], None), "");
    }
}
