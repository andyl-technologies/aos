//! Bounded event-log accounting and boot-prefix grouping for start replay.
//!
//! Start replay retains the complete genesis log under the same entry and
//! byte bounds as result sealing, and groups the audited Envoy boot prefix
//! exactly as the parent attempt did so the two logs stay identical.

use super::*;

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
            .checked_add(entry.canonical_material_len())
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
                retained_bytes: replay.event_log_bytes,
                completed_quanta: replay.completed_quanta,
                schedule_len,
                target_schedule_len,
            },
        )),
        failure => failure,
    }
}

pub(super) fn start_replay_limit_failure<F, D>(
    limit: &'static str,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::LimitExceeded { limit },
    ))
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
