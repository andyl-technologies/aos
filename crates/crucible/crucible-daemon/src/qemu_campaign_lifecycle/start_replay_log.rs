//! Bounded event-log accounting, progress, and boot-prefix grouping for
//! start replay.
//!
//! Start replay retains the complete genesis log under the same storage
//! bound as result sealing, refuses a quantum that advances none of
//! its replay coordinates, and groups the audited Envoy boot prefix exactly
//! as the parent attempt did so the two logs stay identical.

use super::*;
use crate::attempt_event_log::AttemptEventLogError;

pub(super) fn append_start_replay_events<F, D>(
    replay: &mut QemuFreshStartMaterialization,
    entries: &[SchedulerEventLogEntry],
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    replay
        .event_log
        .append(entries.iter().cloned())
        .map_err(|error| match error {
            crate::QemuFreshModeledDriverError::EventLog(AttemptEventLogError::StorageLimit {
                ..
            }) => start_replay_limit_failure("attempt-event-log-bytes"),
            error => AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
                QemuFreshStartReplayError::EventLog(Box::new(error)),
            )),
        })
}

/// Attaches replay progress to an event-log limit failure from one quantum.
pub(super) fn with_replay_progress<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
    replay: &QemuFreshStartMaterialization,
    schedule_len: usize,
    target_schedule_len: usize,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::LimitExceeded { limit },
        )) => AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::EventLogLimitExceeded {
                limit,
                retained_entries: replay.event_log.len(),
                retained_bytes: replay.event_log.encoded_bytes(),
                completed_quanta: replay.completed_quanta,
                schedule_len,
                target_schedule_len,
            },
        )),
        failure => failure,
    }
}

/// The replay coordinates that one start-replay quantum must advance.
///
/// A control-only scheduler quantum can resolve a timer or input for an idle
/// node without a RUN or a decision. It appends the resolved happenings to the
/// log, and may move the frontier, while the quantum counter and schedule stay
/// put. The modeled driver accepts such quanta, so replay counts any advanced
/// coordinate as progress and refuses only a quantum that moved none of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StartReplayProgress {
    completed_quanta: u64,
    schedule_len: usize,
    event_log_entries: usize,
    frontier: crucible_engine::VirtualTime,
}

impl StartReplayProgress {
    /// Captures the coordinates of `replay` with its current schedule length.
    pub(super) fn observe(replay: &QemuFreshStartMaterialization, schedule_len: usize) -> Self {
        Self {
            completed_quanta: replay.completed_quanta,
            schedule_len,
            event_log_entries: replay.event_log.len(),
            frontier: replay.frontier,
        }
    }

    /// Requires `after` to advance at least one coordinate past `self`.
    ///
    /// # Errors
    ///
    /// Returns a terminal "no progress" divergence when every coordinate is
    /// unchanged, since another identical quantum could repeat forever.
    pub(super) fn require_advance<F, D>(
        self,
        after: Self,
    ) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
        if after != self {
            return Ok(());
        }

        Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                reason: "no progress",
                index: self.schedule_len,
                expected: String::from("quantum, schedule, event-log, or frontier progress"),
                observed: format!(
                    "quanta={} schedule_len={} event_log_entries={} frontier_ticks={}",
                    self.completed_quanta,
                    self.schedule_len,
                    self.event_log_entries,
                    self.frontier.ticks,
                ),
            }),
        ))
    }
}

/// Ends the replayed concurrent Envoy boot prefix at west's convergence marker.
///
/// Returns whether the prefix remains armed. The parent attempt refused any
/// choice inside this prefix, so one here means replay left the parent's path.
///
/// # Errors
///
/// Returns a terminal divergence when the quantum discovered or committed a
/// choice before west converged.
pub(super) fn observe_replayed_choice_free_boot<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    outcome: &QuantumOutcome,
    index: usize,
) -> Result<bool, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let selections = outcome
        .decisions
        .iter()
        .filter(|decision| matches!(decision, Decision::Selection(_) | Decision::Override(_)))
        .count();
    if selections > 0 || !outcome.discovered_choices.is_empty() {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartReplay(QemuFreshStartReplayError::DivergedAt {
                reason: "choice-free boot prefix",
                index,
                expected: String::from("no choice before west convergence"),
                observed: format!(
                    "{selections} selections and {} discovered choices",
                    outcome.discovered_choices.len()
                ),
            }),
        ));
    }

    if crate::qemu_campaign_driver::west_convergence_marker_seen(&outcome.event_log_entries) {
        lifecycle.set_choice_free_parallel_boot(false);
        return Ok(false);
    }
    Ok(true)
}
