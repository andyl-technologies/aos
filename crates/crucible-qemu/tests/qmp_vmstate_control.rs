//! Checks checkpoint-tagged QMP VMState control.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible::{Checkpoint, CheckpointKind, ContentHash};
use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_CONT_COMMAND, QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND,
    QMP_HOT_FORK_BLOCK_BARRIER_COMMAND, QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND,
    QMP_HOT_FORK_RCU_BARRIER_COMMAND, QMP_HOT_FORK_TEMPLATE_COMMAND,
    QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_MONITOR_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_READINESS_COMMAND, QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND, QMP_QUERY_JOBS_COMMAND, QMP_QUIT_COMMAND_NAME,
    QMP_SNAPSHOT_LOAD_COMMAND, QMP_SNAPSHOT_SAVE_COMMAND, QemuExactSnapshotPolicy,
    QemuQmpVmStateControlChannel, QmpCommandKind, QmpHotForkBlockSnapshotBinding, QmpHotForkProof,
    QmpHotForkTemplateOutcome, QmpSnapshotTag, QmpTimeoutStream,
};
use serde_json::Value;

const HASH_AB_TAG: &str =
    "crucible-abababababababababababababababababababababababababababababababab";

#[test]
fn exact_restore_resume_does_not_probe_status_before_the_next_ceiling() -> Result<(), Box<dyn Error>>
{
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    control.resume_after_checkpoint()?;
    drop(control);

    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(lines.len(), 2);
    assert_eq!(execute_name(json_line(&lines, 1)), Some(QMP_CONT_COMMAND));
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_readiness() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"required-proofs":511,"acknowledged-proofs":7,"ready":false}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let readiness = control.query_hot_fork_readiness()?;
    assert_eq!(readiness.acknowledged_proofs(), 7);
    assert!(readiness.acknowledges(QmpHotForkProof::ExactPausedBoundary));

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_READINESS_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_thread_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":3,"complete":true,"overflowed":false,"unclassified-threads":0,"threads":[{"thread-id":41,"name":"qmp-main-loop","name-valid":true,"joinable":false,"disposition":"coordinator"}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_thread_inventory()?;
    assert_eq!(inventory.generation(), 3);
    assert_eq!(inventory.threads()[0].thread_id(), 41);

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_plugin_barrier_operations() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":3,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    assert!(control.hold_hot_fork_plugin_barrier()?.quiescent());
    assert!(!control.release_hot_fork_plugin_barrier()?.held());

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND)
    );
    assert_eq!(
        oob_execute_name(json_line(&lines, 2)),
        Some(QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_rcu_barrier_operations() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":3,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    assert!(control.hold_hot_fork_rcu_barrier()?.quiescent());
    assert!(!control.release_hot_fork_rcu_barrier()?.held());

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_RCU_BARRIER_COMMAND)
    );
    assert_eq!(
        oob_execute_name(json_line(&lines, 2)),
        Some(QMP_HOT_FORK_RCU_BARRIER_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_bh_timer_barrier_operations() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":3,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    assert!(control.hold_hot_fork_bh_timer_barrier()?.quiescent());
    assert!(!control.release_hot_fork_bh_timer_barrier()?.held());

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND)
    );
    assert_eq!(
        oob_execute_name(json_line(&lines, 2)),
        Some(QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_block_barrier_operations() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":2,"rooted-backends":1,"writable-backends":1,"writable-rooted-backends":1,"quiesced-rooted-backends":1,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":3,"owner-thread-id":0,"graph-barrier-generation":2,"graph-mutation-generation":7,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":2,"rooted-backends":1,"writable-backends":1,"writable-rooted-backends":1,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    assert!(control.hold_hot_fork_block_barrier()?.quiescent());
    assert!(!control.release_hot_fork_block_barrier()?.held());

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_BLOCK_BARRIER_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_HOT_FORK_BLOCK_BARRIER_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_hot_fork_template_coordination() -> Result<(), Box<dyn Error>> {
    let bindings = [QmpHotForkBlockSnapshotBinding::new(
        1,
        "drive0",
        "overlay0",
        "snapshot0",
        blake3::Hash::from_bytes([0xab; 32]),
    )?];
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":22,"generation":3,"outcome":"blocked","transaction-active":false,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":6,"generation":6,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"bh-timer-barrier":{"schema-version":2,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"resource-stage":{"schema-version":12,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let state = control.prepare_hot_fork_template(&bindings)?;
    assert_eq!(state.outcome(), QmpHotForkTemplateOutcome::Blocked);
    assert!(state.rollback_complete());

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_TEMPLATE_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("prepare")
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/block-snapshot-bindings/0/backend-name")
            .and_then(Value::as_str),
        Some("drive0")
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_rcu_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":4,"complete":true,"overflowed":false,"registered-readers":1,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":41,"active":false}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_rcu_inventory()?;
    assert_eq!(inventory.generation(), 4);
    assert_eq!(inventory.readers()[0].thread_id(), 41);

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_aio_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":5,"complete":true,"overflowed":false,"context-count":1,"assigned-contexts":1,"active-polls":0,"active-dispatches":1,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"contexts":[{"context-id":1,"home-thread-id":41,"active-polls":0,"active-dispatches":1,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"notify-pending":false}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_aio_inventory()?;
    assert_eq!(inventory.generation(), 5);
    assert_eq!(inventory.contexts()[0].home_thread_id(), Some(41));

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_aio_handler_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":6,"complete":true,"overflowed":false,"handler-count":1,"read-handlers":1,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[{"handler-id":2,"context-id":1,"fd":3,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_aio_handler_inventory()?;
    assert_eq!(inventory.generation(), 6);
    assert_eq!(inventory.handlers()[0].context_id(), 1);

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_bottom_half_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"complete":true,"overflowed":false,"stable":true,"bottom-half-count":1,"pending-bottom-halves":0,"scheduled-bottom-halves":0,"deleted-bottom-halves":0,"active-callbacks":0,"bottom-halves":[{"bottom-half-id":2,"context-id":1,"name":"co_schedule_bh","name-valid":true,"pending":false,"scheduled":false,"deleted":false,"oneshot":false,"idle":false,"active-callbacks":0}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_bottom_half_inventory()?;
    assert_eq!(inventory.generation(), 7);
    assert_eq!(inventory.bottom_halves()[0].context_id(), 1);

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_mutex_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":6,"complete":true,"overflowed":false,"mutex-count":1,"recursive-mutexes":0,"owned-mutexes":1,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":41,"recursion-depth":1,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_mutex_inventory()?;
    assert_eq!(inventory.generation(), 6);
    assert_eq!(inventory.mutexes()[0].owner_thread_id(), Some(41));

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_timer_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"complete":true,"overflowed":false,"timer-count":1,"pending-timers":1,"active-callbacks":0,"timers":[{"timer-id":2,"timer-list-id":1,"clock":"virtual","expire-time-ns":4096,"scale":1,"attributes":0,"pending":true,"callback-active":false}]}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_timer_inventory()?;
    assert_eq!(inventory.generation(), 7);
    assert_eq!(inventory.timers()[0].expire_time_ns(), Some(4096));

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_forwards_exact_hot_fork_monitor_inventory() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"complete":true,"overflowed":false,"monitor-count":1,"qmp-monitors":1,"hmp-monitors":0,"io-thread-monitors":1,"suspended-monitors":0,"negotiating-monitors":0,"oob-enabled-monitors":1,"queued-requests":0,"parser-buffered-bytes":0,"partial-parsers":0,"unstable-monitors":0}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;

    let inventory = control.query_hot_fork_monitor_inventory()?;
    assert_eq!(inventory.generation(), 7);
    assert!(inventory.is_supported_parent_profile());

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_MONITOR_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn vmstate_control_saves_and_restores_checkpoint_tags() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
    ]);
    let written = Arc::clone(&stream.written);
    let mut control = QemuQmpVmStateControlChannel::connect(stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);

    assert_eq!(
        control.save_checkpoint_vmstate(&checkpoint)?.command,
        QmpCommandKind::SaveVm
    );
    assert_eq!(
        control
            .restore_checkpoint_vmstate(&checkpoint, loadvm_probe_authorization())?
            .command,
        QmpCommandKind::LoadVm
    );
    assert_eq!(control.quit()?.command, QmpCommandKind::Quit);

    drop(control);
    let lines = written_json_lines(
        &written
            .lock()
            .expect("scripted QMP write audit should remain available"),
    )?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_SNAPSHOT_SAVE_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/tag")
            .and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 4)),
        Some(QMP_SNAPSHOT_LOAD_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 4)
            .pointer("/arguments/tag")
            .and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        execute_name(json_line(&lines, 5)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 7)),
        Some(QMP_QUIT_COMMAND_NAME)
    );
    Ok(())
}

#[test]
fn vmstate_control_uses_the_public_snapshot_tag_derivation() {
    let checkpoint = checkpoint_with_hash_byte(0xab);
    let tag = QmpSnapshotTag::from_checkpoint(&checkpoint);

    assert_eq!(tag.as_str(), HASH_AB_TAG);
}

fn loadvm_probe_authorization() -> crucible_qemu::QemuLoadvmCommandAuthorization {
    QemuExactSnapshotPolicy::production().authorize_loadvm_probe()
}

fn scripted_qmp<const N: usize>(lines: [&str; N]) -> ScriptedQmpStream {
    let mut input = Vec::new();
    for line in lines {
        input.extend_from_slice(line.as_bytes());
        input.extend_from_slice(b"\r\n");
    }
    ScriptedQmpStream {
        read: Cursor::new(input),
        written: Arc::new(Mutex::new(Vec::new())),
        read_timeouts: Vec::new(),
        write_timeouts: Vec::new(),
    }
}

fn written_json_lines(written: &[u8]) -> Result<Vec<Value>, serde_json::Error> {
    String::from_utf8_lossy(written)
        .lines()
        .map(serde_json::from_str)
        .collect()
}

fn json_line(lines: &[Value], index: usize) -> &Value {
    match lines.get(index) {
        Some(line) => line,
        None => panic!("missing written QMP line {index}"),
    }
}

fn execute_name(value: &Value) -> Option<&str> {
    value.get("execute").and_then(Value::as_str)
}

fn oob_execute_name(value: &Value) -> Option<&str> {
    value.get("exec-oob").and_then(Value::as_str)
}

fn checkpoint_with_hash_byte(byte: u8) -> Checkpoint {
    Checkpoint::new(
        content_hash_with_byte(byte),
        content_hash_with_byte(byte.wrapping_add(1)),
        CheckpointKind::Fat,
    )
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}

#[derive(Debug)]
struct ScriptedQmpStream {
    read: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
    read_timeouts: Vec<Duration>,
    write_timeouts: Vec<Duration>,
}

impl Read for ScriptedQmpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(buf)
    }
}

impl Write for ScriptedQmpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written
            .lock()
            .map_err(|_| io::Error::other("scripted QMP write audit lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedQmpStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.read_timeouts.push(timeout);
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.write_timeouts.push(timeout);
        Ok(())
    }
}
