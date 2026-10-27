//! Start replay limit and progress failures report how far replay progressed.

use super::*;
use crate::qemu_campaign_lifecycle::failure_classification::start_replay_limit_failure;
use crate::qemu_campaign_lifecycle::start_replay_log::StartReplayProgress;

type ReplayFailure = AttemptWorkerFailure<QemuFreshExecutionRunnerError<String, String>>;

#[test]
fn event_log_limit_failure_reports_replay_progress() {
    let replay = QemuFreshStartMaterialization::at_quanta(97_365);

    let failure: ReplayFailure = with_replay_progress(
        start_replay_limit_failure("fresh-campaign-event-log-bytes"),
        &replay,
        3,
        4,
    );

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(error)) = failure
    else {
        panic!("limit failure must remain a terminal start-replay failure");
    };
    assert!(matches!(
        error,
        QemuFreshStartReplayError::EventLogLimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
            retained_entries: 0,
            retained_bytes: 0,
            completed_quanta: 97_365,
            schedule_len: 3,
            target_schedule_len: 4,
        }
    ));
    assert!(error.to_string().contains("schedule 3 of 4"));
}

#[test]
fn replay_progress_preserves_other_failures() {
    let replay = QemuFreshStartMaterialization::at_quanta(1);

    let failure: ReplayFailure = with_replay_progress(
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Terminated,
        )),
        &replay,
        0,
        1,
    );

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Terminated
        ))
    ));
}

fn guest_marker_entry() -> crucible_engine::SchedulerEventLogEntry {
    crucible_engine::SchedulerEventLogEntry::guest_semantic_marker_observation(
        0,
        Icount { retired: 7 },
        NodeId {
            name: String::from("traffic-west"),
        },
        String::from("boot.route-probing"),
        String::from("instance-1"),
        Vec::new(),
    )
}

/// A control-only quantum resolves an idle node's input without a RUN or a
/// decision; its log entries are progress even though quanta stay put.
#[test]
fn replay_progress_counts_log_or_frontier_advance_without_a_quantum() {
    let mut replay = QemuFreshStartMaterialization::at_quanta(41_518);
    let before = StartReplayProgress::observe(&replay, 1_884);

    replay
        .event_log
        .append([guest_marker_entry()])
        .expect("dense genesis entry");
    let logged: Result<(), ReplayFailure> =
        before.require_advance(StartReplayProgress::observe(&replay, 1_884));
    assert!(logged.is_ok());

    let before = StartReplayProgress::observe(&replay, 1_884);
    replay.frontier = crucible_engine::VirtualTime { ticks: 250 };
    let advanced: Result<(), ReplayFailure> =
        before.require_advance(StartReplayProgress::observe(&replay, 1_884));
    assert!(advanced.is_ok());
}

#[test]
fn replay_progress_refuses_a_quantum_that_moved_nothing() {
    let replay = QemuFreshStartMaterialization::at_quanta(41_518);
    let before = StartReplayProgress::observe(&replay, 1_884);

    let failure: ReplayFailure = before
        .require_advance(StartReplayProgress::observe(&replay, 1_884))
        .expect_err("an unchanged quantum must fail closed");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::DivergedAt {
            reason,
            index,
            observed,
            ..
        },
    )) = failure
    else {
        panic!("expected a typed no-progress divergence: {failure:?}");
    };
    assert_eq!(reason, "no progress");
    assert_eq!(index, 1_884);
    assert_eq!(
        observed,
        "quanta=41518 schedule_len=1884 event_log_entries=0 frontier_ticks=0"
    );
}
