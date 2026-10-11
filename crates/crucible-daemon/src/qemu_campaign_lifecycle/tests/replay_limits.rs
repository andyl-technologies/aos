//! Start replay limit failures report how far replay progressed.

use super::*;
use crate::qemu_campaign_lifecycle::start_replay_log::start_replay_limit_failure;

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
