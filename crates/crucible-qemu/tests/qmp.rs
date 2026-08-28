//! Checks the minimal typed QMP client.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible::{Checkpoint, CheckpointKind, ContentHash};
use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_COMMAND_TIMEOUT, QMP_GREETING_TIMEOUT,
    QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND, QMP_HOT_FORK_BLOCK_BARRIER_COMMAND,
    QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND, QMP_HOT_FORK_RCU_BARRIER_COMMAND,
    QMP_HOT_FORK_REQUIRED_PROOFS, QMP_HOT_FORK_TEMPLATE_COMMAND, QMP_QUERY_CPUS_FAST_COMMAND,
    QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND, QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_READINESS_COMMAND, QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND,
    QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND, QMP_QUERY_JOBS_COMMAND, QMP_QUERY_STATUS_COMMAND,
    QMP_QUIT_COMMAND_NAME, QMP_SNAPSHOT_DELETE_COMMAND, QMP_SNAPSHOT_LOAD_COMMAND,
    QMP_SNAPSHOT_SAVE_COMMAND, QMP_SNAPSHOT_VMSTATE_DEVICE, QemuExactSnapshotPolicy, QmpClient,
    QmpCommandKind, QmpError, QmpGreeting, QmpHotForkBlockSnapshotBinding,
    QmpHotForkBlockSnapshotBindingError, QmpHotForkProof, QmpHotForkTemplateOutcome,
    QmpHotForkThreadDisposition, QmpHotForkTimerClock, QmpIoTimeoutPolicy, QmpJobPollPolicy,
    QmpRunStateKind, QmpSnapshotTag, QmpTimeoutStream,
};
use serde_json::Value;

const HASH_AB_TAG: &str =
    "crucible-abababababababababababababababababababababababababababababababab";
const HASH_CD_TAG: &str =
    "crucible-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const HASH_EF_TAG: &str =
    "crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

#[test]
fn qmp_connect_reads_greeting_and_negotiates_capabilities() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{"qemu":{"major":10,"minor":0,"micro":0}},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let client = QmpClient::connect(stream)?;

    assert_eq!(
        client.greeting(),
        QmpGreeting {
            version_present: true,
            capabilities_present: true,
        }
    );
    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 0)
            .pointer("/arguments/enable/0")
            .and_then(Value::as_str),
        Some("oob")
    );
    assert!(!audit.read_timeouts.is_empty());
    assert!(
        audit
            .read_timeouts
            .iter()
            .all(|timeout| !timeout.is_zero() && *timeout <= QMP_GREETING_TIMEOUT)
    );
    assert_timeout_budget(&audit.write_timeouts, QMP_COMMAND_TIMEOUT);
    Ok(())
}

#[test]
fn qmp_client_installs_explicit_stream_timeouts() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect_with_policies(
        stream,
        QmpJobPollPolicy::fast_test(1),
        QmpIoTimeoutPolicy::new(Duration::from_millis(7), Duration::from_millis(11)),
    )?;

    assert_eq!(client.quit()?.command, QmpCommandKind::Quit);
    drop(client);
    let audit = audit_snapshot(&audit);
    assert!(!audit.read_timeouts.is_empty());
    assert!(
        audit
            .read_timeouts
            .iter()
            .all(|timeout| !timeout.is_zero() && *timeout <= Duration::from_millis(11))
    );
    assert!(audit.read_timeouts[0] <= Duration::from_millis(7));
    assert_timeout_budget(&audit.write_timeouts, Duration::from_millis(11));
    Ok(())
}

#[test]
fn qmp_client_rejects_unbounded_stream_timeouts() {
    match QmpClient::connect_with_policies(
        scripted_qmp([r#"{"QMP":{"version":{},"capabilities":[]}}"#]),
        QmpJobPollPolicy::fast_test(1),
        QmpIoTimeoutPolicy::new(Duration::ZERO, Duration::from_millis(1)),
    ) {
        Ok(_) => panic!("expected zero greeting timeout rejection"),
        Err(QmpError::UnboundedTimeout { operation }) => {
            assert_eq!(operation, "read QMP greeting");
        }
        Err(other) => panic!("expected timeout policy error, got {other:?}"),
    }

    match QmpClient::connect_with_policies(
        scripted_qmp([r#"{"QMP":{"version":{},"capabilities":[]}}"#]),
        QmpJobPollPolicy::fast_test(1),
        QmpIoTimeoutPolicy::new(Duration::from_millis(1), Duration::ZERO),
    ) {
        Ok(_) => panic!("expected zero command timeout rejection"),
        Err(QmpError::UnboundedTimeout { operation }) => {
            assert_eq!(operation, "QMP command");
        }
        Err(other) => panic!("expected timeout policy error, got {other:?}"),
    }
}

#[test]
fn qmp_client_bounds_async_event_floods() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect_with_policies(
        scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            r#"{"event":"STOP"}"#,
            r#"{"event":"RESUME"}"#,
            r#"{"return":{}}"#,
        ]),
        QmpJobPollPolicy::fast_test(1),
        QmpIoTimeoutPolicy::new(Duration::from_millis(7), Duration::from_millis(11))
            .with_max_async_events_per_command(1),
    )?;

    match client.quit() {
        Ok(_) => panic!("expected async event limit error"),
        Err(QmpError::AsyncEventLimitExceeded { command, limit }) => {
            assert_eq!(command, QmpCommandKind::Quit);
            assert_eq!(limit, 1);
        }
        Err(other) => panic!("expected async event limit error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn qmp_client_bounds_partial_line_progress() {
    match QmpClient::connect_with_policies(
        scripted_qmp([r#"{"QMP":{"version":{},"capabilities":[]}}"#]),
        QmpJobPollPolicy::fast_test(1),
        QmpIoTimeoutPolicy::new(Duration::from_millis(7), Duration::from_millis(11))
            .with_max_line_bytes(8),
    ) {
        Ok(_) => panic!("expected QMP line limit error"),
        Err(QmpError::LineTooLong {
            operation,
            max_bytes,
        }) => {
            assert_eq!(operation, "read QMP greeting");
            assert_eq!(max_bytes, 8);
        }
        Err(other) => panic!("expected QMP line limit error, got {other:?}"),
    }
}

#[test]
fn query_status_and_cpus_fast_are_typed_and_bounded() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":false,"status":"paused"}}"#,
        r#"{"return":[{"cpu-index":2},{"cpu-index":0},{"cpu-index":1}]}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let status = client.query_status()?;
    assert!(!status.running);
    assert_eq!(status.status, QmpRunStateKind::Paused);
    assert_eq!(client.query_cpus_fast()?.cpu_indexes(), &[0, 1, 2]);

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_STATUS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_CPUS_FAST_COMMAND)
    );
    assert_timeout_budget(&audit.read_timeouts, QMP_COMMAND_TIMEOUT);
    assert_timeout_budget(&audit.write_timeouts, QMP_COMMAND_TIMEOUT);
    Ok(())
}

#[test]
fn hot_fork_readiness_is_exact_versioned_and_fail_closed() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"required-proofs":511,"acknowledged-proofs":7,"ready":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let readiness = client.query_hot_fork_readiness()?;
    assert!(!readiness.ready());
    assert_eq!(readiness.acknowledged_proofs(), 7);
    assert!(readiness.acknowledges(QmpHotForkProof::PreciseIcount));
    assert!(readiness.acknowledges(QmpHotForkProof::SingleThreadedSimRoundRobin));
    assert!(readiness.acknowledges(QmpHotForkProof::ExactPausedBoundary));
    assert_eq!(
        readiness.missing_proofs().collect::<Vec<_>>(),
        vec![
            QmpHotForkProof::AioBottomHalvesAndTimers,
            QmpHotForkProof::Rcu,
            QmpHotForkProof::BlockSnapshot,
            QmpHotForkProof::PluginRings,
            QmpHotForkProof::MappingAndDescriptors,
            QmpHotForkProof::ChildReinitialization,
        ]
    );

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_READINESS_COMMAND)
    );
    assert_eq!(QMP_HOT_FORK_REQUIRED_PROOFS, 511);
    Ok(())
}

#[test]
fn hot_fork_readiness_accepts_only_the_complete_exact_bitmap() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"required-proofs":511,"acknowledged-proofs":511,"ready":true}}"#,
    ]))?;

    let readiness = client.query_hot_fork_readiness()?;
    assert!(readiness.ready());
    assert_eq!(readiness.missing_proofs().next(), None);
    Ok(())
}

#[test]
fn hot_fork_readiness_rejects_unknown_or_contradictory_proofs() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"required-proofs":511,"acknowledged-proofs":511,"ready":true}}"#,
        r#"{"return":{"schema-version":1,"required-proofs":1023,"acknowledged-proofs":1023,"ready":true}}"#,
        r#"{"return":{"schema-version":1,"required-proofs":511,"acknowledged-proofs":512,"ready":false}}"#,
        r#"{"return":{"schema-version":1,"required-proofs":511,"acknowledged-proofs":7,"ready":true}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_readiness(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkReadiness,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_thread_inventory_is_exact_bounded_and_sorted() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":9,"complete":true,"overflowed":false,"unclassified-threads":3,"threads":[{"thread-id":10,"name":"qmp-main-loop","name-valid":true,"joinable":false,"disposition":"coordinator"},{"thread-id":11,"name":"call_rcu","name-valid":true,"joinable":false,"disposition":"unclassified-rcu"},{"thread-id":12,"name":"IO mon_iothread","name-valid":true,"joinable":true,"disposition":"unclassified-aio"},{"thread-id":13,"name":"worker","name-valid":true,"joinable":true,"disposition":"unclassified"}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_thread_inventory()?;
    assert_eq!(inventory.generation(), 9);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.unclassified_threads(), 3);
    assert_eq!(inventory.threads().len(), 4);
    assert_eq!(inventory.threads()[0].thread_id(), 10);
    assert_eq!(inventory.threads()[0].name(), "qmp-main-loop");
    assert!(inventory.threads()[0].name_valid());
    assert!(!inventory.threads()[0].joinable());
    assert_eq!(
        inventory.threads()[0].disposition(),
        QmpHotForkThreadDisposition::Coordinator
    );
    assert_eq!(
        inventory.threads()[1].disposition(),
        QmpHotForkThreadDisposition::UnclassifiedRcu
    );
    assert_eq!(
        inventory.threads()[2].disposition(),
        QmpHotForkThreadDisposition::UnclassifiedAio
    );
    assert_eq!(
        inventory.threads()[3].disposition(),
        QmpHotForkThreadDisposition::Unclassified
    );

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_thread_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":false,"unclassified-threads":0,"threads":[]}}"#,
        r#"{"return":{"schema-version":2,"generation":1,"complete":false,"overflowed":false,"unclassified-threads":0,"threads":[],"extra":0}}"#,
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"unclassified-threads":0,"threads":[{"thread-id":11,"name":"qmp-main-loop","name-valid":true,"joinable":false,"disposition":"coordinator"},{"thread-id":10,"name":"worker","name-valid":true,"joinable":true,"disposition":"unclassified"}]}}"#,
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"unclassified-threads":1,"threads":[{"thread-id":10,"name":"qmp-main-loop","name-valid":true,"joinable":false,"disposition":"coordinator"}]}}"#,
        r#"{"return":{"schema-version":2,"generation":1,"complete":false,"overflowed":false,"unclassified-threads":0,"threads":[{"thread-id":10,"name":"qmp-main-loop","name-valid":true,"joinable":false,"disposition":"coordinator"}]}}"#,
        r#"{"return":{"schema-version":2,"generation":1,"complete":false,"overflowed":false,"unclassified-threads":0,"threads":[{"thread-id":10,"name":"a","name-valid":true,"joinable":false,"disposition":"coordinator"},{"thread-id":11,"name":"b","name-valid":true,"joinable":false,"disposition":"coordinator"}]}}"#,
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"unclassified-threads":1,"threads":[{"thread-id":10,"name":"qmp-main-loop","name-valid":true,"joinable":false,"disposition":"coordinator"},{"thread-id":11,"name":"worker","name-valid":true,"joinable":true,"disposition":"future-owner"}]}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_thread_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkThreadInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_rcu_inventory_is_exact_bounded_and_sorted() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"complete":true,"overflowed":false,"registered-readers":3,"active-readers":1,"pending-callbacks":2,"drain-active":true,"readers":[{"thread-id":10,"active":false},{"thread-id":11,"active":true},{"thread-id":12,"active":false}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_rcu_inventory()?;
    assert_eq!(inventory.generation(), 7);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.active_readers(), 1);
    assert_eq!(inventory.pending_callbacks(), 2);
    assert!(inventory.drain_active());
    assert_eq!(inventory.readers().len(), 3);
    assert_eq!(inventory.readers()[0].thread_id(), 10);
    assert!(!inventory.readers()[0].active());
    assert!(inventory.readers()[1].active());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_rcu_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"registered-readers":0,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"registered-readers":2,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":10,"active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"registered-readers":2,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":11,"active":false},{"thread-id":10,"active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"registered-readers":1,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":0,"active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"registered-readers":1,"active-readers":1,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":10,"active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":false,"registered-readers":1,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":10,"active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":true,"registered-readers":1,"active-readers":0,"pending-callbacks":0,"drain-active":false,"readers":[{"thread-id":10,"active":false}],"extra":0}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_rcu_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkRcuInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_aio_inventory_is_exact_bounded_and_thread_bound() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":8,"complete":true,"overflowed":false,"context-count":2,"assigned-contexts":2,"active-polls":1,"active-dispatches":1,"pending-bottom-halves":2,"active-bottom-halves":1,"queued-coroutines":3,"contexts":[{"context-id":1,"home-thread-id":10,"active-polls":1,"active-dispatches":0,"pending-bottom-halves":2,"active-bottom-halves":0,"queued-coroutines":3,"notify-pending":true},{"context-id":2,"home-thread-id":11,"active-polls":0,"active-dispatches":1,"pending-bottom-halves":0,"active-bottom-halves":1,"queued-coroutines":0,"notify-pending":false}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_aio_inventory()?;
    assert_eq!(inventory.generation(), 8);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.contexts().len(), 2);
    assert_eq!(inventory.contexts()[0].context_id(), 1);
    assert_eq!(inventory.contexts()[0].home_thread_id(), Some(10));
    assert_eq!(inventory.contexts()[0].active_polls(), 1);
    assert_eq!(inventory.contexts()[0].pending_bottom_halves(), 2);
    assert_eq!(inventory.contexts()[0].queued_coroutines(), 3);
    assert!(inventory.contexts()[0].notify_pending());
    assert_eq!(inventory.contexts()[1].active_dispatches(), 1);
    assert_eq!(inventory.contexts()[1].active_bottom_halves(), 1);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_aio_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"context-count":0,"assigned-contexts":0,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"contexts":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"context-count":2,"assigned-contexts":1,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"contexts":[{"context-id":1,"home-thread-id":10,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"notify-pending":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"context-count":2,"assigned-contexts":2,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"contexts":[{"context-id":2,"home-thread-id":10,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"notify-pending":false},{"context-id":1,"home-thread-id":11,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"notify-pending":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"context-count":1,"assigned-contexts":1,"active-polls":2,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"contexts":[{"context-id":1,"home-thread-id":10,"active-polls":1,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"notify-pending":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"context-count":1,"assigned-contexts":0,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"contexts":[{"context-id":1,"home-thread-id":0,"active-polls":0,"active-dispatches":0,"pending-bottom-halves":0,"active-bottom-halves":0,"queued-coroutines":0,"notify-pending":false}]}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_aio_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkAioInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_aio_handler_inventory_is_exact_bounded_and_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":9,"complete":true,"overflowed":false,"handler-count":2,"read-handlers":1,"write-handlers":1,"poll-handlers":1,"deleted-handlers":1,"active-callbacks":2,"handlers":[{"handler-id":1,"context-id":4,"fd":3,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0},{"handler-id":3,"context-id":4,"fd":5,"deleted":true,"read-callback":false,"write-callback":true,"poll-callback":true,"poll-ready-callback":true,"poll-begin-callback":true,"poll-end-callback":true,"active-callbacks":2}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_aio_handler_inventory()?;
    assert_eq!(inventory.generation(), 9);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.handlers().len(), 2);
    assert_eq!(inventory.handlers()[0].handler_id(), 1);
    assert_eq!(inventory.handlers()[0].context_id(), 4);
    assert_eq!(inventory.handlers()[0].descriptor(), 3);
    assert!(inventory.handlers()[0].read_callback());
    assert!(!inventory.handlers()[0].deleted());
    assert_eq!(inventory.handlers()[1].handler_id(), 3);
    assert_eq!(inventory.handlers()[1].descriptor(), 5);
    assert!(inventory.handlers()[1].write_callback());
    assert!(inventory.handlers()[1].poll_callback());
    assert!(inventory.handlers()[1].poll_ready_callback());
    assert!(inventory.handlers()[1].poll_begin_callback());
    assert!(inventory.handlers()[1].poll_end_callback());
    assert!(inventory.handlers()[1].deleted());
    assert_eq!(inventory.handlers()[1].active_callbacks(), 2);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_AIO_HANDLER_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_aio_handler_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"handler-count":0,"read-handlers":0,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"handler-count":2,"read-handlers":1,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[{"handler-id":1,"context-id":1,"fd":3,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"handler-count":2,"read-handlers":2,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[{"handler-id":2,"context-id":1,"fd":3,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0},{"handler-id":1,"context-id":1,"fd":4,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"handler-count":1,"read-handlers":1,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[{"handler-id":1,"context-id":0,"fd":3,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"handler-count":1,"read-handlers":1,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[{"handler-id":1,"context-id":1,"fd":-1,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"handler-count":1,"read-handlers":0,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[{"handler-id":1,"context-id":1,"fd":3,"deleted":false,"read-callback":false,"write-callback":false,"poll-callback":false,"poll-ready-callback":true,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"handler-count":1,"read-handlers":1,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":1,"handlers":[{"handler-id":1,"context-id":1,"fd":3,"deleted":false,"read-callback":true,"write-callback":false,"poll-callback":false,"poll-ready-callback":false,"poll-begin-callback":false,"poll-end-callback":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":false,"handler-count":0,"read-handlers":0,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":true,"handler-count":0,"read-handlers":0,"write-handlers":0,"poll-handlers":0,"deleted-handlers":0,"active-callbacks":0,"handlers":[],"extra":0}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_aio_handler_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkAioHandlerInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_block_backend_inventory_is_exact_bounded_and_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":11,"complete":true,"overflowed":false,"backend-count":2,"named-backends":1,"rooted-backends":2,"device-backends":1,"writable-backends":1,"quiesced-backends":1,"in-flight":3,"backends":[{"backend-id":1,"context-id":4,"reference-count":1,"name":"","named":false,"name-valid":true,"root-present":true,"device-attached":false,"permissions":2,"shared-permissions":31,"write-permission":true,"permissions-disabled":false,"quiesce-depth":0,"in-flight":0,"request-queuing-disabled":false},{"backend-id":3,"context-id":5,"reference-count":2,"name":"vmstate","named":true,"name-valid":true,"root-present":true,"device-attached":true,"permissions":1,"shared-permissions":31,"write-permission":false,"permissions-disabled":true,"quiesce-depth":2,"in-flight":3,"request-queuing-disabled":true}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_block_backend_inventory()?;
    assert_eq!(inventory.generation(), 11);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.backends().len(), 2);
    assert_eq!(inventory.backends()[0].backend_id(), 1);
    assert_eq!(inventory.backends()[0].context_id(), 4);
    assert!(inventory.backends()[0].write_permission());
    assert!(!inventory.backends()[0].named());
    assert!(inventory.backends()[0].name_valid());
    assert_eq!(inventory.backends()[1].name(), "vmstate");
    assert_eq!(inventory.backends()[1].reference_count(), 2);
    assert!(inventory.backends()[1].root_present());
    assert!(inventory.backends()[1].device_attached());
    assert!(inventory.backends()[1].permissions_disabled());
    assert_eq!(inventory.backends()[1].quiesce_depth(), 2);
    assert_eq!(inventory.backends()[1].in_flight(), 3);
    assert!(inventory.backends()[1].request_queuing_disabled());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_BLOCK_BACKEND_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_block_backend_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"backend-count":0,"named-backends":0,"rooted-backends":0,"device-backends":0,"writable-backends":0,"quiesced-backends":0,"in-flight":0,"backends":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"backend-count":1,"named-backends":0,"rooted-backends":1,"device-backends":0,"writable-backends":1,"quiesced-backends":0,"in-flight":0,"backends":[{"backend-id":1,"context-id":0,"reference-count":1,"name":"","named":false,"name-valid":true,"root-present":true,"device-attached":false,"permissions":2,"shared-permissions":31,"write-permission":true,"permissions-disabled":false,"quiesce-depth":0,"in-flight":0,"request-queuing-disabled":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"backend-count":1,"named-backends":0,"rooted-backends":1,"device-backends":0,"writable-backends":0,"quiesced-backends":0,"in-flight":0,"backends":[{"backend-id":1,"context-id":1,"reference-count":1,"name":"","named":false,"name-valid":true,"root-present":true,"device-attached":false,"permissions":2,"shared-permissions":31,"write-permission":false,"permissions-disabled":false,"quiesce-depth":0,"in-flight":0,"request-queuing-disabled":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"backend-count":1,"named-backends":1,"rooted-backends":1,"device-backends":0,"writable-backends":1,"quiesced-backends":0,"in-flight":0,"backends":[{"backend-id":1,"context-id":1,"reference-count":1,"name":"","named":true,"name-valid":true,"root-present":true,"device-attached":false,"permissions":2,"shared-permissions":31,"write-permission":true,"permissions-disabled":false,"quiesce-depth":0,"in-flight":0,"request-queuing-disabled":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"backend-count":1,"named-backends":0,"rooted-backends":1,"device-backends":0,"writable-backends":1,"quiesced-backends":0,"in-flight":1,"backends":[{"backend-id":1,"context-id":1,"reference-count":1,"name":"","named":false,"name-valid":true,"root-present":true,"device-attached":false,"permissions":2,"shared-permissions":31,"write-permission":true,"permissions-disabled":false,"quiesce-depth":0,"in-flight":0,"request-queuing-disabled":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":false,"backend-count":0,"named-backends":0,"rooted-backends":0,"device-backends":0,"writable-backends":0,"quiesced-backends":0,"in-flight":0,"backends":[]}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_block_backend_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkBlockBackendInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_plugin_resource_inventory_is_exact_and_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"state-dump":false,"app-random":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_plugin_resource_inventory()?;
    assert_eq!(inventory.generation(), 7);
    assert!(inventory.registered());
    assert!(inventory.complete());
    assert_eq!(inventory.process_generation(), 9);
    assert_eq!(inventory.plugin_id(), 12);
    assert_eq!(inventory.resource_mask(), 1023);
    assert_eq!(inventory.callback_mask(), 4093);
    assert_eq!(inventory.observed_callback_mask(), 4093);
    assert_eq!(inventory.shmem_device(), 1);
    assert_eq!(inventory.shmem_inode(), 2);
    assert_eq!(inventory.shmem_length(), 4096);
    assert_eq!(inventory.slot_index(), 0);
    assert_eq!(inventory.node_count(), 1);
    assert_eq!(inventory.control_fd(), 3);
    assert_eq!(inventory.wake_fd(), 4);
    assert!(!inventory.coverage());
    assert!(!inventory.whitebox());
    assert!(!inventory.fingerprint());
    assert!(!inventory.state_dump());
    assert!(!inventory.app_random());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_plugin_resource_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"state-dump":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":33791,"callback-mask":4093,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"state-dump":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"observed-callback-mask":4092,"callback-mask-consistent":false,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"state-dump":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":true,"whitebox":false,"fingerprint":false,"state-dump":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":1,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"state-dump":false,"app-random":false,"extra":0}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_plugin_resource_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkPluginResourceInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_plugin_barrier_holds_queries_and_releases_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":1,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":3,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let held = client.hold_hot_fork_plugin_barrier()?;
    assert!(held.registered());
    assert!(held.manifest_consistent());
    assert!(held.held());
    assert_eq!(held.in_flight(), 1);
    assert_eq!(held.ring_count(), 9);
    assert_eq!(held.rings_held(), 9);
    assert_eq!(held.ring_producers_in_flight(), 0);
    assert!(!held.quiescent());
    let drained = client.query_hot_fork_plugin_barrier()?;
    assert_eq!(drained.generation(), 2);
    assert!(drained.quiescent());
    let released = client.release_hot_fork_plugin_barrier()?;
    assert!(!released.held());
    assert!(!released.teardown_closed());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [(1, "hold"), (2, "query"), (3, "release")] {
        assert_eq!(
            oob_execute_name(json_line(&lines, index)),
            Some(QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND)
        );
        assert_eq!(
            json_line(&lines, index)
                .pointer("/arguments/action")
                .and_then(Value::as_str),
            Some(action)
        );
    }
    Ok(())
}

#[test]
fn hot_fork_plugin_barrier_rejects_malformed_or_wrong_action_state() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":3,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":1,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":8,"ring-producers-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":1,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":0,"registered":false,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.hold_hot_fork_plugin_barrier(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkPluginBarrier,
                ..
            })
        ));
    }

    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":0,"registered":false,"manifest-consistent":false,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":0,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false}}"#,
    ]))?;
    assert!(matches!(
        client.release_hot_fork_plugin_barrier(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::HotForkPluginBarrier,
            ..
        })
    ));
    Ok(())
}

#[test]
fn hot_fork_rcu_barrier_holds_drains_and_releases_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":1,"admissions-in-flight":0,"pending-callbacks":1,"drain-active":false,"quiescent":false}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":3,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let held = client.hold_hot_fork_rcu_barrier()?;
    assert!(held.held());
    assert_eq!(held.owner_thread_id(), 44);
    assert_eq!(held.active_readers(), 1);
    assert_eq!(held.pending_callbacks(), 1);
    assert!(!held.quiescent());
    let drained = client.query_hot_fork_rcu_barrier()?;
    assert_eq!(drained.generation(), 2);
    assert!(drained.complete());
    assert_eq!(drained.registered_readers(), 2);
    assert_eq!(drained.admissions_in_flight(), 0);
    assert!(!drained.drain_active());
    assert!(drained.quiescent());
    let released = client.release_hot_fork_rcu_barrier()?;
    assert!(!released.held());
    assert_eq!(released.owner_thread_id(), 0);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [(1, "hold"), (2, "query"), (3, "release")] {
        assert_eq!(
            oob_execute_name(json_line(&lines, index)),
            Some(QMP_HOT_FORK_RCU_BARRIER_COMMAND)
        );
        assert_eq!(
            json_line(&lines, index)
                .pointer("/arguments/action")
                .and_then(Value::as_str),
            Some(action)
        );
    }
    Ok(())
}

#[test]
fn hot_fork_rcu_barrier_rejects_malformed_or_wrong_action_state() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":0,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":1,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":65537,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":3,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.hold_hot_fork_rcu_barrier(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkRcuBarrier,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_bh_timer_barrier_parks_sources_and_releases_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":1,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":1,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":3,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let held = client.hold_hot_fork_bh_timer_barrier()?;
    assert!(held.held());
    assert_eq!(held.owner_thread_id(), 44);
    assert_eq!(held.admissions_in_flight(), 1);
    assert_eq!(held.active_bottom_half_callbacks(), 1);
    assert!(!held.quiescent());

    let drained = client.query_hot_fork_bh_timer_barrier()?;
    assert!(drained.complete());
    assert!(drained.bottom_halves_complete());
    assert!(drained.timers_complete());
    assert_eq!(drained.bottom_half_count(), 4);
    assert_eq!(drained.pending_bottom_halves(), 2);
    assert_eq!(drained.scheduled_bottom_halves(), 1);
    assert_eq!(drained.pending_timers(), 3);
    assert_eq!(drained.active_timer_callbacks(), 0);
    assert_eq!(drained.aio_context_count(), 2);
    assert_eq!(drained.active_aio_polls(), 0);
    assert_eq!(drained.active_aio_dispatches(), 0);
    assert_eq!(drained.queued_coroutines(), 1);
    assert_eq!(drained.aio_handler_count(), 3);
    assert_eq!(drained.active_aio_handler_callbacks(), 0);
    assert!(drained.aio_contexts_complete());
    assert!(drained.aio_handlers_complete());
    assert!(drained.quiescent());

    let released = client.release_hot_fork_bh_timer_barrier()?;
    assert!(!released.held());
    assert_eq!(released.owner_thread_id(), 0);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [(1, "hold"), (2, "query"), (3, "release")] {
        assert_eq!(
            oob_execute_name(json_line(&lines, index)),
            Some(QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND)
        );
        assert_eq!(
            json_line(&lines, index)
                .pointer("/arguments/action")
                .and_then(Value::as_str),
            Some(action)
        );
    }
    Ok(())
}

#[test]
fn hot_fork_bh_timer_barrier_rejects_malformed_states() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":false,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":1,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":0,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":false,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":1,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":3,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":65537,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":1,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":4294967296,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":1,"active-aio-handler-callbacks":4294967296,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.hold_hot_fork_bh_timer_barrier(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkBhTimerBarrier,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_block_snapshot_binding_rejects_noncanonical_identity() {
    let hash = blake3::Hash::from_bytes([0xab; 32]);
    assert_eq!(
        QmpHotForkBlockSnapshotBinding::new(0, "drive0", "overlay0", "snapshot0", hash),
        Err(QmpHotForkBlockSnapshotBindingError::InvalidBackendId)
    );
    assert!(matches!(
        QmpHotForkBlockSnapshotBinding::new(1, "0drive", "overlay0", "snapshot0", hash),
        Err(QmpHotForkBlockSnapshotBindingError::InvalidIdentifier {
            field: "backend-name",
            ..
        })
    ));
    assert!(matches!(
        QmpHotForkBlockSnapshotBinding::new(1, "drive0", "overlay/0", "snapshot0", hash),
        Err(QmpHotForkBlockSnapshotBindingError::InvalidIdentifier {
            field: "overlay-node-name",
            ..
        })
    ));
}

#[test]
fn hot_fork_block_barrier_holds_drains_and_releases_on_main_qmp() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":1,"quiescent":false}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":1,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":3,"owner-thread-id":0,"graph-barrier-generation":2,"graph-mutation-generation":7,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let held = client.hold_hot_fork_block_barrier()?;
    assert!(held.held());
    assert_eq!(held.owner_thread_id(), 44);
    assert_eq!(held.graph_barrier_generation(), 1);
    assert_eq!(held.graph_mutation_generation(), 7);
    assert_eq!(held.held_graph_mutation_generation(), 7);
    assert_eq!(held.graph_owner_thread_id(), 44);
    assert!(held.graph_held());
    assert!(!held.graph_writer_active());
    assert_eq!(held.graph_waiting_writers(), 0);
    assert!(held.graph_stable());
    assert_eq!(held.backend_count(), 3);
    assert_eq!(held.rooted_backends(), 2);
    assert_eq!(held.writable_backends(), 2);
    assert_eq!(held.writable_rooted_backends(), 2);
    assert_eq!(held.quiesced_rooted_backends(), 2);
    assert_eq!(held.in_flight(), 1);
    assert!(!held.quiescent());
    assert!(!held.snapshot_bound());
    assert!(!held.snapshot_complete());
    assert!(held.snapshot_roots().is_empty());

    let drained = client.query_hot_fork_block_barrier()?;
    assert_eq!(drained.generation(), 2);
    assert!(drained.complete());
    assert_eq!(drained.graph_waiting_writers(), 1);
    assert!(drained.quiescent());

    let released = client.release_hot_fork_block_barrier()?;
    assert!(!released.held());
    assert_eq!(released.owner_thread_id(), 0);
    assert!(!released.graph_held());
    assert!(!released.graph_stable());
    assert!(!released.snapshot_bound());
    assert_eq!(released.quiesced_rooted_backends(), 0);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [(1, "hold"), (2, "query"), (3, "release")] {
        assert_eq!(
            execute_name(json_line(&lines, index)),
            Some(QMP_HOT_FORK_BLOCK_BARRIER_COMMAND)
        );
        assert!(json_line(&lines, index).get("exec-oob").is_none());
        assert_eq!(
            json_line(&lines, index)
                .pointer("/arguments/action")
                .and_then(Value::as_str),
            Some(action)
        );
    }
    Ok(())
}

#[test]
fn hot_fork_block_barrier_rejects_malformed_or_wrong_action_state() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":6,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":45,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":true,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":3,"owner-thread-id":0,"graph-barrier-generation":2,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":4294967296,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":0,"held":true,"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"backend-count":1,"rooted-backends":2,"writable-backends":1,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":4,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"backend-count":65537,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":false,"backend-count":3,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":1,"in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":2,"in-flight":1,"quiescent":true}}"#,
        r#"{"return":{"schema-version":1,"generation":2,"owner-thread-id":44,"held":false,"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.hold_hot_fork_block_barrier(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkBlockBarrier,
                ..
            })
        ));
    }

    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true}}"#,
    ]))?;
    assert!(matches!(
        client.release_hot_fork_block_barrier(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::HotForkBlockBarrier,
            ..
        })
    ));
    Ok(())
}

#[test]
fn hot_fork_template_coordinator_retains_draining_and_rolls_back_blocked()
-> Result<(), Box<dyn Error>> {
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
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":8,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"bh-timer-barrier":{"schema-version":2,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":511,"acknowledged-proofs":39,"missing-proofs":472,"plugin-barrier":{"schema-version":2,"generation":8,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"bh-timer-barrier":{"schema-version":2,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":1,"snapshot-backend-generation":5,"snapshot-graph-mutation-generation":9,"snapshot-owner-thread-id":44,"snapshot-bound":true,"snapshot-complete":true,"snapshot-roots":[{"backend-id":1,"backend-name":"drive0","overlay-node-name":"overlay0","snapshot-node-name":"snapshot0","snapshot-content-id":"abababababababababababababababababababababababababababababababab","virtual-size":4096,"overlay-empty":true,"snapshot-read-only":true}],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":1,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":511,"acknowledged-proofs":63,"missing-proofs":448,"plugin-barrier":{"schema-version":2,"generation":8,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"bh-timer-barrier":{"schema-version":2,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":1,"snapshot-backend-generation":5,"snapshot-graph-mutation-generation":9,"snapshot-owner-thread-id":44,"snapshot-bound":true,"snapshot-complete":true,"snapshot-roots":[{"backend-id":1,"backend-name":"drive0","overlay-node-name":"overlay0","snapshot-node-name":"snapshot0","snapshot-content-id":"abababababababababababababababababababababababababababababababab","virtual-size":4096,"overlay-empty":true,"snapshot-read-only":true}],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":1,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"bh-timer-barrier":{"schema-version":2,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":true,"ready":false}}"#,
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"idle","transaction-active":false,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"bh-timer-barrier":{"schema-version":2,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":true,"ready":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let draining = client.prepare_hot_fork_template(&bindings)?;
    assert_eq!(draining.outcome(), QmpHotForkTemplateOutcome::Draining);
    assert!(draining.transaction_active());
    assert!(!draining.plugin_barrier().held());
    assert!(!draining.rcu_barrier().held());
    assert!(!draining.bh_timer_barrier().held());
    assert!(!draining.block_barrier().held());
    assert!(!draining.rollback_complete());

    let block_drained = client.query_hot_fork_template()?;
    assert_eq!(block_drained.outcome(), QmpHotForkTemplateOutcome::Draining);
    assert!(!block_drained.plugin_barrier().held());
    assert!(!block_drained.rcu_barrier().held());
    assert!(!block_drained.bh_timer_barrier().held());
    assert!(block_drained.block_barrier().quiescent());
    assert!(block_drained.acknowledges(QmpHotForkProof::BlockSnapshot));

    let drained = client.query_hot_fork_template()?;
    assert_eq!(drained.outcome(), QmpHotForkTemplateOutcome::Draining);
    assert!(drained.plugin_barrier().quiescent());
    assert!(drained.rcu_barrier().quiescent());
    assert!(drained.bh_timer_barrier().quiescent());
    assert!(drained.block_barrier().quiescent());
    assert!(drained.acknowledges(QmpHotForkProof::AioBottomHalvesAndTimers));
    assert!(drained.acknowledges(QmpHotForkProof::Rcu));
    assert!(drained.acknowledges(QmpHotForkProof::BlockSnapshot));

    let blocked = client.prepare_hot_fork_template(&bindings)?;
    assert_eq!(blocked.outcome(), QmpHotForkTemplateOutcome::Blocked);
    assert_eq!(blocked.generation(), 4);
    assert_eq!(blocked.acknowledged_proofs(), 7);
    assert_eq!(blocked.missing_proofs(), 504);
    assert!(!blocked.transaction_active());
    assert!(blocked.rollback_complete());
    assert!(!blocked.plugin_barrier().held());
    assert!(!blocked.rcu_barrier().held());
    assert!(!blocked.bh_timer_barrier().held());
    assert!(!blocked.block_barrier().held());
    assert!(!blocked.ready());

    assert_eq!(
        client.query_hot_fork_template()?.outcome(),
        QmpHotForkTemplateOutcome::Idle
    );

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [
        (1, "prepare"),
        (2, "query"),
        (3, "query"),
        (4, "prepare"),
        (5, "query"),
    ] {
        assert_eq!(
            oob_execute_name(json_line(&lines, index)),
            Some(QMP_HOT_FORK_TEMPLATE_COMMAND)
        );
        assert_eq!(
            json_line(&lines, index)
                .pointer("/arguments/action")
                .and_then(Value::as_str),
            Some(action)
        );
        if action == "prepare" {
            assert_eq!(
                json_line(&lines, index)
                    .pointer("/arguments/block-snapshot-bindings/0/backend-id")
                    .and_then(Value::as_u64),
                Some(1)
            );
            assert_eq!(
                json_line(&lines, index)
                    .pointer("/arguments/block-snapshot-bindings/0/snapshot-content-id")
                    .and_then(Value::as_str),
                Some("abababababababababababababababababababababababababababababababab")
            );
        } else {
            assert!(
                json_line(&lines, index)
                    .pointer("/arguments/block-snapshot-bindings")
                    .is_none()
            );
        }
    }
    Ok(())
}

#[test]
fn hot_fork_template_abort_is_exact_and_malformed_states_fail_closed() -> Result<(), Box<dyn Error>>
{
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":8,"generation":5,"outcome":"aborted","transaction-active":false,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":10,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"bh-timer-barrier":{"schema-version":2,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":true,"ready":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;
    let aborted = client.abort_hot_fork_template()?;
    assert_eq!(aborted.outcome(), QmpHotForkTemplateOutcome::Aborted);
    assert!(aborted.rollback_complete());
    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_TEMPLATE_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("abort")
    );

    for response in [
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":511,"acknowledged-proofs":23,"missing-proofs":488,"plugin-barrier":{"schema-version":2,"generation":8,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"bh-timer-barrier":{"schema-version":2,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":true,"ready":false}}"#,
        r#"{"return":{"schema-version":8,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":511,"acknowledged-proofs":39,"missing-proofs":472,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":true,"ready":false}}"#,
        r#"{"return":{"schema-version":2,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":511,"acknowledged-proofs":23,"missing-proofs":488,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":2,"generation":4,"outcome":"prepared","transaction-active":true,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true},"rollback-complete":false,"ready":true}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.prepare_hot_fork_template(&[]),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkTemplate,
                ..
            })
        ));
    }

    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":2,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":511,"acknowledged-proofs":7,"missing-proofs":504,"plugin-barrier":{"schema-version":2,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"block-barrier":{"schema-version":3,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false},"rollback-complete":true,"ready":false}}"#,
    ]))?;
    assert!(matches!(
        client.query_hot_fork_template(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::HotForkTemplate,
            ..
        })
    ));
    Ok(())
}

#[test]
fn hot_fork_bottom_half_inventory_is_exact_bounded_and_sorted() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":12,"complete":true,"overflowed":false,"stable":true,"bottom-half-count":2,"pending-bottom-halves":1,"scheduled-bottom-halves":1,"deleted-bottom-halves":1,"active-callbacks":2,"bottom-halves":[{"bottom-half-id":1,"context-id":4,"name":"co_schedule_bh","name-valid":true,"pending":false,"scheduled":false,"deleted":false,"oneshot":false,"idle":false,"active-callbacks":0},{"bottom-half-id":3,"context-id":4,"name":"aio_bh_call","name-valid":true,"pending":true,"scheduled":true,"deleted":true,"oneshot":true,"idle":false,"active-callbacks":2}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_bottom_half_inventory()?;
    assert_eq!(inventory.generation(), 12);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert!(inventory.stable());
    assert_eq!(inventory.bottom_halves().len(), 2);
    assert_eq!(inventory.bottom_halves()[0].bottom_half_id(), 1);
    assert_eq!(inventory.bottom_halves()[0].context_id(), 4);
    assert_eq!(inventory.bottom_halves()[0].name(), "co_schedule_bh");
    assert!(inventory.bottom_halves()[0].name_valid());
    assert!(!inventory.bottom_halves()[0].pending());
    assert!(inventory.bottom_halves()[1].scheduled());
    assert!(inventory.bottom_halves()[1].deleted());
    assert!(inventory.bottom_halves()[1].oneshot());
    assert!(!inventory.bottom_halves()[1].idle());
    assert_eq!(inventory.bottom_halves()[1].active_callbacks(), 2);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_BOTTOM_HALF_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_bottom_half_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"stable":true,"bottom-half-count":0,"pending-bottom-halves":0,"scheduled-bottom-halves":0,"deleted-bottom-halves":0,"active-callbacks":0,"bottom-halves":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"stable":true,"bottom-half-count":2,"pending-bottom-halves":0,"scheduled-bottom-halves":0,"deleted-bottom-halves":0,"active-callbacks":0,"bottom-halves":[{"bottom-half-id":1,"context-id":1,"name":"bh","name-valid":true,"pending":false,"scheduled":false,"deleted":false,"oneshot":false,"idle":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"stable":true,"bottom-half-count":2,"pending-bottom-halves":0,"scheduled-bottom-halves":0,"deleted-bottom-halves":0,"active-callbacks":0,"bottom-halves":[{"bottom-half-id":2,"context-id":1,"name":"bh2","name-valid":true,"pending":false,"scheduled":false,"deleted":false,"oneshot":false,"idle":false,"active-callbacks":0},{"bottom-half-id":1,"context-id":1,"name":"bh1","name-valid":true,"pending":false,"scheduled":false,"deleted":false,"oneshot":false,"idle":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"stable":true,"bottom-half-count":1,"pending-bottom-halves":0,"scheduled-bottom-halves":1,"deleted-bottom-halves":0,"active-callbacks":0,"bottom-halves":[{"bottom-half-id":1,"context-id":1,"name":"bh","name-valid":true,"pending":false,"scheduled":true,"deleted":false,"oneshot":false,"idle":false,"active-callbacks":0}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"stable":false,"bottom-half-count":0,"pending-bottom-halves":0,"scheduled-bottom-halves":0,"deleted-bottom-halves":0,"active-callbacks":0,"bottom-halves":[]}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_bottom_half_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkBottomHalfInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_mutex_inventory_is_exact_bounded_and_thread_bound() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":9,"complete":true,"overflowed":false,"mutex-count":2,"recursive-mutexes":1,"owned-mutexes":2,"acquisition-waiters":3,"condition-waiters":1,"unlock-transitions":1,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":10,"recursion-depth":1,"acquisition-waiters":2,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true},{"mutex-id":2,"owner-thread-id":11,"recursion-depth":2,"acquisition-waiters":1,"condition-waiters":1,"recursive":true,"unlock-active":true,"ownership-valid":true}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_mutex_inventory()?;
    assert_eq!(inventory.generation(), 9);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.mutexes().len(), 2);
    assert_eq!(inventory.mutexes()[0].mutex_id(), 1);
    assert_eq!(inventory.mutexes()[0].owner_thread_id(), Some(10));
    assert_eq!(inventory.mutexes()[0].recursion_depth(), 1);
    assert_eq!(inventory.mutexes()[0].acquisition_waiters(), 2);
    assert!(!inventory.mutexes()[0].recursive());
    assert_eq!(inventory.mutexes()[1].condition_waiters(), 1);
    assert!(inventory.mutexes()[1].recursive());
    assert!(inventory.mutexes()[1].unlock_active());
    assert!(inventory.mutexes()[1].ownership_valid());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_mutex_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"mutex-count":0,"recursive-mutexes":0,"owned-mutexes":0,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"mutex-count":2,"recursive-mutexes":0,"owned-mutexes":1,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":10,"recursion-depth":1,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"mutex-count":2,"recursive-mutexes":0,"owned-mutexes":0,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":2,"owner-thread-id":0,"recursion-depth":0,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true},{"mutex-id":1,"owner-thread-id":0,"recursion-depth":0,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"mutex-count":1,"recursive-mutexes":0,"owned-mutexes":1,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":10,"recursion-depth":0,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"mutex-count":1,"recursive-mutexes":0,"owned-mutexes":1,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":10,"recursion-depth":2,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"mutex-count":1,"recursive-mutexes":0,"owned-mutexes":0,"acquisition-waiters":1,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":0,"recursion-depth":0,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":false,"mutex-count":1,"recursive-mutexes":0,"owned-mutexes":0,"acquisition-waiters":0,"condition-waiters":0,"unlock-transitions":0,"invalid-mutexes":0,"mutexes":[{"mutex-id":1,"owner-thread-id":0,"recursion-depth":0,"acquisition-waiters":0,"condition-waiters":0,"recursive":false,"unlock-active":false,"ownership-valid":true}]}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_mutex_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkMutexInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn hot_fork_timer_inventory_is_exact_bounded_and_sorted() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":1,"generation":10,"complete":true,"overflowed":false,"timer-count":2,"pending-timers":2,"active-callbacks":1,"timers":[{"timer-id":1,"timer-list-id":4,"clock":"virtual","expire-time-ns":9000,"scale":1,"attributes":0,"pending":true,"callback-active":false},{"timer-id":3,"timer-list-id":5,"clock":"realtime","expire-time-ns":12000,"scale":1000000,"attributes":1,"pending":true,"callback-active":true}]}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let inventory = client.query_hot_fork_timer_inventory()?;
    assert_eq!(inventory.generation(), 10);
    assert!(inventory.complete());
    assert!(!inventory.overflowed());
    assert_eq!(inventory.timers().len(), 2);
    assert_eq!(inventory.timers()[0].timer_id(), 1);
    assert_eq!(inventory.timers()[0].timer_list_id(), 4);
    assert_eq!(inventory.timers()[0].clock(), QmpHotForkTimerClock::Virtual);
    assert_eq!(inventory.timers()[0].expire_time_ns(), Some(9_000));
    assert_eq!(inventory.timers()[0].scale(), 1);
    assert_eq!(inventory.timers()[0].attributes(), 0);
    assert!(inventory.timers()[0].pending());
    assert!(!inventory.timers()[0].callback_active());
    assert_eq!(inventory.timers()[1].timer_id(), 3);
    assert!(inventory.timers()[1].callback_active());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_TIMER_INVENTORY_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_timer_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":1,"complete":true,"overflowed":false,"timer-count":0,"pending-timers":0,"active-callbacks":0,"timers":[]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"timer-count":2,"pending-timers":1,"active-callbacks":0,"timers":[{"timer-id":1,"timer-list-id":1,"clock":"virtual","expire-time-ns":1,"scale":1,"attributes":0,"pending":true,"callback-active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"timer-count":2,"pending-timers":2,"active-callbacks":0,"timers":[{"timer-id":2,"timer-list-id":1,"clock":"virtual","expire-time-ns":1,"scale":1,"attributes":0,"pending":true,"callback-active":false},{"timer-id":1,"timer-list-id":1,"clock":"virtual","expire-time-ns":2,"scale":1,"attributes":0,"pending":true,"callback-active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"timer-count":1,"pending-timers":1,"active-callbacks":0,"timers":[{"timer-id":1,"timer-list-id":0,"clock":"virtual","expire-time-ns":1,"scale":1,"attributes":0,"pending":true,"callback-active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"timer-count":1,"pending-timers":0,"active-callbacks":0,"timers":[{"timer-id":1,"timer-list-id":1,"clock":"virtual","expire-time-ns":-1,"scale":1,"attributes":0,"pending":false,"callback-active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":true,"overflowed":false,"timer-count":1,"pending-timers":1,"active-callbacks":0,"timers":[{"timer-id":1,"timer-list-id":1,"clock":"virtual","expire-time-ns":-1,"scale":1,"attributes":0,"pending":true,"callback-active":false}]}}"#,
        r#"{"return":{"schema-version":1,"generation":1,"complete":false,"overflowed":false,"timer-count":1,"pending-timers":0,"active-callbacks":1,"timers":[{"timer-id":1,"timer-list-id":1,"clock":"future","expire-time-ns":-1,"scale":1,"attributes":0,"pending":false,"callback-active":true}]}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.query_hot_fork_timer_inventory(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::QueryHotForkTimerInventory,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn typed_queries_reject_missing_contradictory_and_noncontiguous_fields()
-> Result<(), Box<dyn Error>> {
    let mut status_client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"status":"paused"}}"#,
    ]))?;
    assert!(matches!(
        status_client.query_status(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::QueryStatus,
            ..
        })
    ));

    let mut contradictory_status_client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":true,"status":"paused"}}"#,
    ]))?;
    assert!(matches!(
        contradictory_status_client.query_status(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::QueryStatus,
            ..
        })
    ));

    let mut topology_client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"cpu-index":0},{"cpu-index":0}]}"#,
    ]))?;
    assert!(matches!(
        topology_client.query_cpus_fast(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::QueryCpusFast,
            ..
        })
    ));

    let mut gapped_topology_client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"cpu-index":0},{"cpu-index":2}]}"#,
    ]))?;
    assert!(matches!(
        gapped_topology_client.query_cpus_fast(),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::QueryCpusFast,
            ..
        })
    ));
    Ok(())
}

#[test]
fn qmp_timeout_errors_classify_node_channel_timeouts() {
    let error = crucible_qemu::QemuNodeChannelError::from(QmpError::Timeout {
        operation: "QMP command",
        timeout: Duration::from_millis(11),
    });

    assert_eq!(error.operation, "QMP command");
    assert_eq!(error.bounded_timeout(), Some(Duration::from_millis(11)));
}

#[test]
fn savevm_uses_snapshot_save_with_checkpoint_derived_tag() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;
    let checkpoint = checkpoint_with_hash_byte(0xab);
    let tag = QmpSnapshotTag::from_checkpoint(&checkpoint);

    let complete = client.savevm(&tag)?;
    assert_eq!(complete.command, QmpCommandKind::SaveVm);

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    let request = json_line(&lines, 1);
    assert_eq!(execute_name(request), Some(QMP_SNAPSHOT_SAVE_COMMAND));
    assert_eq!(
        request.pointer("/arguments/tag").and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        request
            .pointer("/arguments/vmstate")
            .and_then(Value::as_str),
        Some(QMP_SNAPSHOT_VMSTATE_DEVICE)
    );
    assert_eq!(
        request
            .pointer("/arguments/devices/0")
            .and_then(Value::as_str),
        Some(QMP_SNAPSHOT_VMSTATE_DEVICE)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    Ok(())
}

#[test]
fn loadvm_and_quit_are_typed_qmp_commands() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xcd));

    assert_eq!(
        client.loadvm(&tag, loadvm_probe_authorization())?.command,
        QmpCommandKind::LoadVm
    );
    assert_eq!(client.quit()?.command, QmpCommandKind::Quit);

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_SNAPSHOT_LOAD_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/tag")
            .and_then(Value::as_str),
        Some(HASH_CD_TAG)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 4)),
        Some(QMP_QUIT_COMMAND_NAME)
    );
    Ok(())
}

#[test]
fn snapshot_delete_uses_the_same_tag_and_vmstate_device() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-delete-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xab));

    assert_eq!(
        client.delete_snapshot(&tag)?.command,
        QmpCommandKind::DeleteSnapshot
    );

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    let request = json_line(&lines, 1);
    assert_eq!(execute_name(request), Some(QMP_SNAPSHOT_DELETE_COMMAND));
    assert_eq!(
        request.pointer("/arguments/tag").and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        request
            .pointer("/arguments/devices/0")
            .and_then(Value::as_str),
        Some(QMP_SNAPSHOT_VMSTATE_DEVICE)
    );
    assert!(request.pointer("/arguments/vmstate").is_none());
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    Ok(())
}

#[test]
fn predeclared_debug_guest_activation_emits_no_qmp_mutation() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let client = QmpClient::connect(stream)?.with_predeclared_debug_guest_endpoint();

    client.confirm_predeclared_debug_guest_endpoint()?;

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    assert_eq!(lines.len(), 1, "activation emitted a QMP mutation");
    Ok(())
}

#[test]
fn qmp_client_skips_async_events_until_command_return() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"event":"STOP","timestamp":{"seconds":1,"microseconds":2}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    assert_eq!(client.savevm(&tag)?.command, QmpCommandKind::SaveVm);
    Ok(())
}

#[test]
fn qmp_snapshot_job_error_is_typed_result_error() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"concluded","error":{"class":"GenericError","desc":"job failed"}}]}"#,
        r#"{"return":{}}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.savevm(&tag) {
        Ok(_) => panic!("expected typed QMP job error"),
        Err(QmpError::JobFailed {
            command,
            job_id,
            detail,
        }) => {
            assert_eq!(command, QmpCommandKind::SaveVm);
            assert_eq!(job_id, format!("crucible-save-{HASH_EF_TAG}"));
            assert!(detail.contains("job failed"));
        }
        Err(other) => panic!("expected QMP job error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn qmp_snapshot_job_polling_waits_until_concluded() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"running"}]}"#,
        r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client =
        QmpClient::connect_with_job_poll_policy(stream, QmpJobPollPolicy::fast_test(4))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    assert_eq!(client.savevm(&tag)?.command, QmpCommandKind::SaveVm);

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    Ok(())
}

#[test]
fn qmp_snapshot_job_timeout_is_typed_result_error() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect_with_job_poll_policy(
        scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            r#"{"return":{}}"#,
            r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"running"}]}"#,
            r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"running"}]}"#,
        ]),
        QmpJobPollPolicy::fast_test(2),
    )?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.savevm(&tag) {
        Ok(_) => panic!("expected QMP job timeout"),
        Err(QmpError::JobNotConcluded {
            command,
            job_id,
            polls,
        }) => {
            assert_eq!(command, QmpCommandKind::SaveVm);
            assert_eq!(job_id, format!("crucible-save-{HASH_EF_TAG}"));
            assert_eq!(polls, 2);
        }
        Err(other) => panic!("expected QMP job timeout, got {other:?}"),
    }
    Ok(())
}

#[test]
fn qmp_error_response_is_typed_result_error() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"error":{"class":"GenericError","desc":"snapshot missing"}}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.loadvm(&tag, loadvm_probe_authorization()) {
        Ok(_) => panic!("expected typed QMP error"),
        Err(QmpError::Command {
            command,
            class,
            description,
        }) => {
            assert_eq!(command, QmpCommandKind::LoadVm);
            assert_eq!(class, "GenericError");
            assert_eq!(description, "snapshot missing");
        }
        Err(other) => panic!("expected QMP command error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn unexpected_qmp_shapes_are_typed_errors() {
    match QmpClient::connect(scripted_qmp([r#"{"event":"RESET"}"#])) {
        Ok(_) => panic!("expected unexpected greeting error"),
        Err(QmpError::UnexpectedGreeting { response }) => {
            assert!(response.contains("RESET"));
        }
        Err(other) => panic!("expected unexpected greeting error, got {other:?}"),
    }
    match QmpClient::connect(scripted_qmp([r#"{"QMP":{"version":{}}}"#])) {
        Ok(_) => panic!("expected incomplete greeting error"),
        Err(QmpError::UnexpectedGreeting { response }) => {
            assert!(response.contains("version"));
        }
        Err(other) => panic!("expected incomplete greeting error, got {other:?}"),
    }

    let mut client = match QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"timestamp":{"seconds":1}}"#,
    ])) {
        Ok(client) => client,
        Err(error) => panic!("connect failed unexpectedly: {error}"),
    };
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.savevm(&tag) {
        Ok(_) => panic!("expected unexpected response error"),
        Err(QmpError::UnexpectedResponse { command, response }) => {
            assert_eq!(command, QmpCommandKind::SaveVm);
            assert!(response.contains("timestamp"));
        }
        Err(other) => panic!("expected unexpected response error, got {other:?}"),
    }
}

#[test]
fn snapshot_tags_are_derived_from_checkpoint_content_hash() {
    let checkpoint = checkpoint_with_hash_byte(0xab);

    assert_eq!(
        QmpSnapshotTag::from_checkpoint(&checkpoint),
        QmpSnapshotTag::from_checkpoint_content_address(checkpoint.id)
    );
    assert_eq!(
        QmpSnapshotTag::from_checkpoint(&checkpoint).as_str(),
        HASH_AB_TAG
    );
}

fn loadvm_probe_authorization() -> crucible_qemu::QemuLoadvmCommandAuthorization {
    QemuExactSnapshotPolicy::production().authorize_loadvm_probe()
}

#[path = "qmp/support.rs"]
mod support;

use support::*;
