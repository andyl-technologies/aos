//! Checks the minimal typed QMP client.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::io::{self, Cursor, Read, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_COMMAND_TIMEOUT, QMP_GREETING_TIMEOUT,
    QMP_HOT_FORK_ASYNC_WORKER_BARRIER_COMMAND, QMP_HOT_FORK_BLOCK_BARRIER_COMMAND,
    QMP_HOT_FORK_CHILD_CONSOLE_COMMAND, QMP_HOT_FORK_CHILD_DIAGNOSTICS_COMMAND,
    QMP_HOT_FORK_CHILD_QMP_COMMAND, QMP_HOT_FORK_PLUGIN_BARRIER_COMMAND,
    QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND, QMP_HOT_FORK_PRIVATE_RINGS_COMMAND,
    QMP_HOT_FORK_RCU_BARRIER_COMMAND, QMP_HOT_FORK_TEMPLATE_COMMAND,
    QMP_QUERY_HOT_FORK_CHILD_RUNTIME_COMMAND, QMP_QUERY_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_COMMAND,
    QMP_QUERY_STATUS_COMMAND, QmpClient, QmpCommandKind, QmpDescriptorName, QmpError, QmpGreeting,
    QmpHotForkBlockSnapshotBinding, QmpHotForkBlockSnapshotBindingError,
    QmpHotForkChildRuntimePhase, QmpHotForkPluginEndpointIdentity, QmpHotForkProof,
    QmpHotForkTemplateOutcome, QmpIoTimeoutPolicy, QmpJobPollPolicy, QmpRunStateKind,
    QmpTimeoutStream,
};
#[cfg(unix)]
use crucible_shmem::mmap_setup_region;
use serde_json::Value;

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
fn query_status_is_typed_and_bounded() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"running":false,"status":"paused"}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let status = client.query_status()?;
    assert!(!status.running);
    assert_eq!(status.status, QmpRunStateKind::Paused);

    drop(client);
    let audit = audit_snapshot(&audit);
    let lines = written_json_lines(&audit)?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_STATUS_COMMAND)
    );
    assert_timeout_budget(&audit.read_timeouts, QMP_COMMAND_TIMEOUT);
    assert_timeout_budget(&audit.write_timeouts, QMP_COMMAND_TIMEOUT);
    Ok(())
}

#[test]
fn hot_fork_plugin_resource_inventory_is_exact_and_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
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
    assert_eq!(inventory.worker_mask(), 3);
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
    assert!(inventory.run_control_worker());
    assert!(inventory.teardown_worker());
    assert!(!inventory.fingerprint_worker());
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
fn hot_fork_child_runtime_is_exact_and_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"manifest-consistent":true,"plugin-id":12,"process-generation":10,"phase":"workers-held","callbacks-held":true,"mapping-installed":true,"workers-ready":true,"active":false,"failed":false,"parent-process-generation":9,"child-process-generation":10,"template-generation":3,"private-ring-generation":4,"plugin-endpoint-generation":5,"plugin-barrier-generation":6,"control-socket-cookie":7,"wake-eventfd-id":8,"source-mapping-start":4096,"source-mapping-length":4096,"source-mapping-offset":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":1,"worker-operations-in-flight":0,"readiness-proof-acknowledged":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let runtime = client.query_hot_fork_child_runtime()?;
    assert_eq!(runtime.generation(), 7);
    assert!(runtime.registered());
    assert!(runtime.manifest_consistent());
    assert_eq!(runtime.plugin_id(), 12);
    assert_eq!(runtime.process_generation(), 10);
    assert_eq!(runtime.phase(), QmpHotForkChildRuntimePhase::WorkersHeld);
    assert!(runtime.callbacks_held());
    assert!(runtime.mapping_installed());
    assert!(runtime.workers_ready());
    assert!(!runtime.active());
    assert!(!runtime.failed());
    assert_eq!(runtime.parent_process_generation(), 9);
    assert_eq!(runtime.child_process_generation(), 10);
    assert_eq!(runtime.template_generation(), 3);
    assert_eq!(runtime.private_ring_generation(), 4);
    assert_eq!(runtime.plugin_endpoint_generation(), 5);
    assert_eq!(runtime.plugin_barrier_generation(), 6);
    assert_eq!(runtime.control_socket_cookie(), 7);
    assert_eq!(runtime.wake_eventfd_id(), 8);
    assert_eq!(runtime.source_mapping_start(), 4096);
    assert_eq!(runtime.source_mapping_length(), 4096);
    assert_eq!(runtime.source_mapping_offset(), 0);
    assert_eq!(runtime.worker_mask(), 3);
    assert_eq!(runtime.parked_worker_mask(), 3);
    assert_eq!(runtime.pending_worker_mask(), 1);
    assert_eq!(runtime.worker_operations_in_flight(), 0);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_QUERY_HOT_FORK_CHILD_RUNTIME_COMMAND)
    );
    Ok(())
}

#[test]
fn hot_fork_plugin_resource_inventory_rejects_malformed_contracts() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":2,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":9215,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4095,"worker-mask":3,"observed-callback-mask":4095,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":33791,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4092,"callback-mask-consistent":false,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":true,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":1,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":false,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":11,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":7,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":true,"app-random":false}}"#,
        r#"{"return":{"schema-version":3,"generation":7,"registered":true,"complete":true,"process-generation":9,"plugin-id":12,"resource-mask":1023,"callback-mask":4093,"worker-mask":3,"observed-callback-mask":4093,"callback-mask-consistent":true,"shmem-device":1,"shmem-inode":2,"shmem-length":4096,"slot-index":0,"node-count":1,"control-fd":3,"wake-fd":4,"coverage":false,"whitebox":false,"fingerprint":false,"run-control-worker":true,"teardown-worker":true,"fingerprint-worker":false,"app-random":false,"extra":0}}"#,
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
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":1,"worker-operations-in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":3,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let held = client.hold_hot_fork_plugin_barrier()?;
    assert!(held.registered());
    assert!(held.manifest_consistent());
    assert!(held.held());
    assert!(held.mapping_dontfork());
    assert_eq!(held.in_flight(), 0);
    assert_eq!(held.ring_count(), 9);
    assert_eq!(held.rings_held(), 9);
    assert_eq!(held.ring_producers_in_flight(), 0);
    assert_eq!(held.ring_consumers_in_flight(), 0);
    assert_eq!(held.worker_mask(), 3);
    assert_eq!(held.parked_worker_mask(), 3);
    assert_eq!(held.pending_worker_mask(), 1);
    assert_eq!(held.worker_operations_in_flight(), 0);
    assert!(!held.quiescent());
    let drained = client.query_hot_fork_plugin_barrier()?;
    assert_eq!(drained.generation(), 2);
    assert!(drained.mapping_dontfork());
    assert!(drained.quiescent());
    let released = client.release_hot_fork_plugin_barrier()?;
    assert!(!released.held());
    assert!(!released.mapping_dontfork());
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
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":11,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":2,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":1,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":8,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":1,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":1,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":0,"registered":false,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":0,"parked-worker-mask":0,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":1,"parked-worker-mask":1,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":1,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":1,"pending-worker-mask":2,"worker-operations-in-flight":0,"quiescent":false}}"#,
        r#"{"return":{"schema-version":6,"generation":2,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":1,"worker-operations-in-flight":0,"quiescent":true}}"#,
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
        r#"{"return":{"schema-version":6,"generation":0,"registered":false,"manifest-consistent":false,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":0,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":0,"parked-worker-mask":0,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false}}"#,
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
fn hot_fork_async_worker_barrier_parks_sources_and_releases_oob() -> Result<(), Box<dyn Error>> {
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":1,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":1,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":3,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let held = client.hold_hot_fork_async_worker_barrier()?;
    assert!(held.held());
    assert_eq!(held.owner_thread_id(), 44);
    assert_eq!(held.admissions_in_flight(), 1);
    assert_eq!(held.active_bottom_half_callbacks(), 1);
    assert!(!held.quiescent());

    let drained = client.query_hot_fork_async_worker_barrier()?;
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

    let released = client.release_hot_fork_async_worker_barrier()?;
    assert!(!released.held());
    assert_eq!(released.owner_thread_id(), 0);

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [(1, "hold"), (2, "query"), (3, "release")] {
        assert_eq!(
            oob_execute_name(json_line(&lines, index)),
            Some(QMP_HOT_FORK_ASYNC_WORKER_BARRIER_COMMAND)
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
fn hot_fork_async_worker_barrier_rejects_malformed_states() -> Result<(), Box<dyn Error>> {
    for response in [
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":false,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":1,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":0,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":false,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":1,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":3,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":65537,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":1,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":4294967296,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
        r#"{"return":{"schema-version":3,"generation":2,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":1,"active-aio-handler-callbacks":4294967296,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true}}"#,
    ] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            response,
        ]))?;
        assert!(matches!(
            client.hold_hot_fork_async_worker_barrier(),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkAsyncWorkerBarrier,
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
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":1,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":1,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
        r#"{"return":{"schema-version":4,"generation":3,"owner-thread-id":0,"graph-barrier-generation":2,"graph-mutation-generation":7,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
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
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":6,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":45,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":true,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
        r#"{"return":{"schema-version":4,"generation":3,"owner-thread-id":0,"graph-barrier-generation":2,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":4294967296,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
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
        r#"{"return":{"schema-version":4,"generation":2,"owner-thread-id":44,"graph-barrier-generation":1,"graph-mutation-generation":7,"held-graph-mutation-generation":7,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}}}"#,
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
fn hot_fork_template_coordinator_retains_draining_until_explicit_abort()
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
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":8,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"async-worker-barrier":{"schema-version":3,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":127,"acknowledged-proofs":39,"missing-proofs":88,"plugin-barrier":{"schema-version":6,"generation":8,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"async-worker-barrier":{"schema-version":3,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":1,"snapshot-backend-generation":5,"snapshot-graph-mutation-generation":9,"snapshot-owner-thread-id":44,"snapshot-bound":true,"snapshot-complete":true,"snapshot-roots":[{"backend-id":1,"backend-name":"drive0","overlay-node-name":"overlay0","snapshot-node-name":"snapshot0","snapshot-content-id":"abababababababababababababababababababababababababababababababab","virtual-size":4096,"overlay-empty":true,"snapshot-read-only":true}],"complete":true,"backend-count":2,"rooted-backends":2,"writable-backends":0,"writable-rooted-backends":0,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":true,"root-count":2,"node-count":4,"originally-writable-root-count":1,"originally-writable-backend-count":1}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"prepared","transaction-active":true,"required-proofs":127,"acknowledged-proofs":127,"missing-proofs":0,"plugin-barrier":{"schema-version":6,"generation":8,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"async-worker-barrier":{"schema-version":3,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":1,"snapshot-backend-generation":5,"snapshot-graph-mutation-generation":9,"snapshot-owner-thread-id":44,"snapshot-bound":true,"snapshot-complete":true,"snapshot-roots":[{"backend-id":1,"backend-name":"drive0","overlay-node-name":"overlay0","snapshot-node-name":"snapshot0","snapshot-content-id":"abababababababababababababababababababababababababababababababab","virtual-size":4096,"overlay-empty":true,"snapshot-read-only":true}],"complete":true,"backend-count":2,"rooted-backends":2,"writable-backends":0,"writable-rooted-backends":0,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":true,"root-count":2,"node-count":4,"originally-writable-root-count":1,"originally-writable-backend-count":1}},"resource-stage":{"schema-version":13,"template-generation":4,"private-ring-staged":true,"private-ring-generation":11,"diagnostics-staged":true,"diagnostic-generation":13,"diagnostics-resource-plan-bound":true,"qmp-staged":true,"qmp-generation":14,"qmp-resource-plan-bound":true,"console-staged":true,"console-generation":15,"console-resource-plan-bound":true,"plugin-endpoints-staged":true,"plugin-endpoint-generation":12,"plugin-private-ring-generation":11,"plugin-barrier-generation":8,"worker-mask":3,"parent-resume-worker-mask":3,"child-reinitialize-worker-mask":3,"pending-worker-mask":0,"worker-disposition-bound":true,"transaction-bound":true,"parent-process-generation":21,"child-process-generation":22,"plugin-child-plan-bound":true,"plugin-child-resource-plan-bound":true,"readiness-proof-acknowledged":true},"rollback-complete":false,"ready":true}}"#,
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"aborted","transaction-active":false,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"async-worker-barrier":{"schema-version":3,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":4,"private-ring-staged":true,"private-ring-generation":11,"diagnostics-staged":true,"diagnostic-generation":13,"diagnostics-resource-plan-bound":false,"qmp-staged":true,"qmp-generation":14,"qmp-resource-plan-bound":false,"console-staged":true,"console-generation":15,"console-resource-plan-bound":false,"plugin-endpoints-staged":true,"plugin-endpoint-generation":12,"plugin-private-ring-generation":11,"plugin-barrier-generation":8,"worker-mask":3,"parent-resume-worker-mask":3,"child-reinitialize-worker-mask":3,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"idle","transaction-active":false,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"async-worker-barrier":{"schema-version":3,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":4,"private-ring-staged":true,"private-ring-generation":11,"diagnostics-staged":true,"diagnostic-generation":13,"diagnostics-resource-plan-bound":false,"qmp-staged":true,"qmp-generation":14,"qmp-resource-plan-bound":false,"console-staged":true,"console-generation":15,"console-resource-plan-bound":false,"plugin-endpoints-staged":true,"plugin-endpoint-generation":12,"plugin-private-ring-generation":11,"plugin-barrier-generation":8,"worker-mask":3,"parent-resume-worker-mask":3,"child-reinitialize-worker-mask":3,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let draining = client.prepare_hot_fork_template(&bindings)?;
    assert_eq!(draining.outcome(), QmpHotForkTemplateOutcome::Draining);
    assert!(draining.transaction_active());
    assert!(!draining.plugin_barrier().held());
    assert!(!draining.rcu_barrier().held());
    assert!(!draining.async_worker_barrier().held());
    assert!(!draining.block_barrier().held());
    assert!(!draining.rollback_complete());

    let block_drained = client.query_hot_fork_template()?;
    assert_eq!(block_drained.outcome(), QmpHotForkTemplateOutcome::Draining);
    assert!(!block_drained.plugin_barrier().held());
    assert!(!block_drained.rcu_barrier().held());
    assert!(!block_drained.async_worker_barrier().held());
    assert!(block_drained.block_barrier().quiescent());
    assert!(block_drained.acknowledges(QmpHotForkProof::BlockSnapshot));

    let drained = client.query_hot_fork_template()?;
    assert_eq!(drained.outcome(), QmpHotForkTemplateOutcome::Prepared);
    assert!(drained.ready());
    assert!(drained.plugin_barrier().quiescent());
    assert!(drained.rcu_barrier().quiescent());
    assert!(drained.async_worker_barrier().quiescent());
    assert!(drained.block_barrier().quiescent());
    assert!(drained.acknowledges(QmpHotForkProof::AioBottomHalvesAndTimers));
    assert!(drained.acknowledges(QmpHotForkProof::Rcu));
    assert!(drained.acknowledges(QmpHotForkProof::BlockSnapshot));
    assert!(drained.acknowledges(QmpHotForkProof::PluginRings));
    assert_eq!(drained.resource_stage().template_generation(), 4);
    assert!(drained.resource_stage().private_ring_staged());
    assert_eq!(drained.resource_stage().private_ring_generation(), 11);
    assert!(drained.resource_stage().plugin_endpoints_staged());
    assert_eq!(drained.resource_stage().plugin_endpoint_generation(), 12);
    assert_eq!(
        drained.resource_stage().plugin_private_ring_generation(),
        11
    );
    assert!(drained.resource_stage().transaction_bound());
    assert_eq!(drained.resource_stage().parent_process_generation(), 21);
    assert_eq!(drained.resource_stage().child_process_generation(), 22);
    assert!(drained.resource_stage().plugin_child_plan_bound());
    assert!(drained.resource_stage().plugin_child_resource_plan_bound());
    assert!(drained.resource_stage().readiness_proof_acknowledged());

    let aborted = client.abort_hot_fork_template()?;
    assert_eq!(aborted.outcome(), QmpHotForkTemplateOutcome::Aborted);
    assert_eq!(aborted.generation(), 4);
    assert_eq!(aborted.acknowledged_proofs(), 7);
    assert_eq!(aborted.missing_proofs(), 120);
    assert!(!aborted.transaction_active());
    assert!(aborted.rollback_complete());
    assert!(!aborted.plugin_barrier().held());
    assert!(!aborted.rcu_barrier().held());
    assert!(!aborted.async_worker_barrier().held());
    assert!(!aborted.block_barrier().held());
    assert_eq!(aborted.resource_stage().template_generation(), 4);
    assert!(aborted.resource_stage().private_ring_staged());
    assert!(aborted.resource_stage().plugin_endpoints_staged());
    assert!(!aborted.resource_stage().transaction_bound());
    assert_eq!(aborted.resource_stage().parent_process_generation(), 0);
    assert_eq!(aborted.resource_stage().child_process_generation(), 0);
    assert!(!aborted.resource_stage().plugin_child_plan_bound());
    assert!(!aborted.resource_stage().plugin_child_resource_plan_bound());
    assert!(!aborted.resource_stage().readiness_proof_acknowledged());
    assert!(!aborted.ready());

    let idle = client.query_hot_fork_template()?;
    assert_eq!(idle.outcome(), QmpHotForkTemplateOutcome::Idle);
    assert_eq!(idle.resource_stage().template_generation(), 4);
    assert!(!idle.resource_stage().transaction_bound());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    for (index, action) in [
        (1, "prepare"),
        (2, "query"),
        (3, "query"),
        (4, "abort"),
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
        r#"{"return":{"schema-version":26,"generation":5,"outcome":"aborted","transaction-active":false,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":10,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"async-worker-barrier":{"schema-version":3,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
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
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"draining","transaction-active":true,"required-proofs":127,"acknowledged-proofs":23,"missing-proofs":104,"plugin-barrier":{"schema-version":6,"generation":8,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"async-worker-barrier":{"schema-version":3,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"bottom-halves-complete":true,"timers-complete":true,"admissions-in-flight":0,"bottom-half-count":4,"pending-bottom-halves":2,"scheduled-bottom-halves":1,"active-bottom-half-callbacks":0,"pending-timers":3,"active-timer-callbacks":0,"aio-context-count":2,"active-aio-polls":0,"active-aio-dispatches":0,"queued-coroutines":1,"aio-handler-count":3,"active-aio-handler-callbacks":0,"aio-contexts-complete":true,"aio-handlers-complete":true,"quiescent":true},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
        r#"{"return":{"schema-version":26,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":127,"acknowledged-proofs":39,"missing-proofs":88,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
        r#"{"return":{"schema-version":2,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":127,"acknowledged-proofs":23,"missing-proofs":104,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":false,"ready":false}}"#,
        r#"{"return":{"schema-version":2,"generation":4,"outcome":"prepared","transaction-active":true,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":true,"teardown-closed":false,"mapping-dontfork":true,"in-flight":0,"ring-count":9,"rings-held":9,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":true},"rcu-barrier":{"schema-version":1,"generation":6,"owner-thread-id":44,"held":true,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":true},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":44,"graph-barrier-generation":5,"graph-mutation-generation":9,"held-graph-mutation-generation":9,"graph-owner-thread-id":44,"held":true,"graph-held":true,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":true,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":2,"in-flight":0,"quiescent":true,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":false,"ready":true}}"#,
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
        r#"{"return":{"schema-version":2,"generation":4,"outcome":"blocked","transaction-active":false,"required-proofs":127,"acknowledged-proofs":7,"missing-proofs":120,"plugin-barrier":{"schema-version":6,"generation":9,"registered":true,"manifest-consistent":true,"held":false,"teardown-closed":false,"mapping-dontfork":false,"in-flight":0,"ring-count":9,"rings-held":0,"ring-producers-in-flight":0,"ring-consumers-in-flight":0,"worker-mask":3,"parked-worker-mask":3,"pending-worker-mask":0,"worker-operations-in-flight":0,"quiescent":false},"rcu-barrier":{"schema-version":1,"generation":7,"owner-thread-id":0,"held":false,"complete":true,"registered-readers":2,"active-readers":0,"admissions-in-flight":0,"pending-callbacks":0,"drain-active":false,"quiescent":false},"block-barrier":{"schema-version":4,"generation":4,"owner-thread-id":0,"graph-barrier-generation":6,"graph-mutation-generation":9,"held-graph-mutation-generation":0,"graph-owner-thread-id":0,"held":false,"graph-held":false,"graph-writer-active":false,"graph-waiting-writers":0,"graph-stable":false,"snapshot-generation":0,"snapshot-backend-generation":0,"snapshot-graph-mutation-generation":0,"snapshot-owner-thread-id":0,"snapshot-bound":false,"snapshot-complete":false,"snapshot-roots":[],"complete":true,"backend-count":3,"rooted-backends":2,"writable-backends":2,"writable-rooted-backends":2,"quiesced-rooted-backends":0,"in-flight":0,"quiescent":false,"snapshot-sources":{"schema-version":1,"frozen":false,"root-count":0,"node-count":0,"originally-writable-root-count":0,"originally-writable-backend-count":0}},"resource-stage":{"schema-version":13,"template-generation":0,"private-ring-staged":false,"private-ring-generation":0,"diagnostics-staged":false,"diagnostic-generation":0,"diagnostics-resource-plan-bound":false,"qmp-staged":false,"qmp-generation":0,"qmp-resource-plan-bound":false,"console-staged":false,"console-generation":0,"console-resource-plan-bound":false,"plugin-endpoints-staged":false,"plugin-endpoint-generation":0,"plugin-private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-bound":false,"transaction-bound":false,"parent-process-generation":0,"child-process-generation":0,"plugin-child-plan-bound":false,"plugin-child-resource-plan-bound":false,"readiness-proof-acknowledged":false},"rollback-complete":true,"ready":false}}"#,
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
fn typed_status_queries_reject_missing_and_contradictory_fields() -> Result<(), Box<dyn Error>> {
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

#[cfg(unix)]
#[test]
fn private_ring_stage_authenticates_exact_basis_and_releases_qemu_copy()
-> Result<(), Box<dyn Error>> {
    let file = tempfile::tempfile()?;
    file.set_len(4096)?;
    let mapping = mmap_setup_region(file.as_fd(), 4096)?;
    let identity = mapping.backing_identity();
    let name = QmpDescriptorName::new("crucible-hfork-rings-v1-test")?;
    let staged = format!(
        concat!(
            r#"{{"return":{{"schema-version":3,"generation":1,"template-generation":0,"staged":true,"fdname":"{}","device":{},"inode":{},"length":{},"shrink-sealed":true,"source-mapping-bound":false,"source-start":0,"source-length":0,"source-offset":0,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#
        ),
        name.as_str(),
        identity.device(),
        identity.inode(),
        identity.length(),
    );
    let released = r#"{"return":{"schema-version":3,"generation":2,"template-generation":0,"staged":false,"device":0,"inode":0,"length":0,"shrink-sealed":false,"source-mapping-bound":false,"source-start":0,"source-length":0,"source-offset":0,"disposition-complete":false,"readiness-proof-acknowledged":false}}"#;
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &staged,
        &staged,
        released,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let stage = client.stage_hot_fork_private_rings(&name, identity)?;
    assert_eq!(stage.descriptor_name(), Some(&name));
    assert_eq!(stage.template_generation(), 0);
    assert!(!stage.source_mapping_bound());
    assert_eq!(client.query_hot_fork_private_rings()?, stage);
    assert!(
        !client
            .release_hot_fork_private_rings(&name, identity)?
            .staged()
    );

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    let stage_request = json_line(&lines, 1);
    assert_eq!(
        oob_execute_name(stage_request),
        Some(QMP_HOT_FORK_PRIVATE_RINGS_COMMAND)
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("stage")
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/expected-device")
            .and_then(Value::as_u64),
        Some(identity.device())
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/expected-inode")
            .and_then(Value::as_u64),
        Some(identity.inode())
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/expected-length")
            .and_then(Value::as_u64),
        Some(identity.length())
    );
    assert_eq!(
        json_line(&lines, 2)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("query")
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/expected-inode")
            .and_then(Value::as_u64),
        Some(identity.inode())
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn contradictory_private_ring_stage_poisoned_the_qmp_client() -> Result<(), Box<dyn Error>> {
    let file = tempfile::tempfile()?;
    file.set_len(4096)?;
    let mapping = mmap_setup_region(file.as_fd(), 4096)?;
    let identity = mapping.backing_identity();
    let name = QmpDescriptorName::new("crucible-hfork-rings-v1-bad")?;
    let contradictory = format!(
        concat!(
            r#"{{"return":{{"schema-version":3,"generation":1,"template-generation":0,"staged":true,"fdname":"{}","device":{},"inode":{},"length":{},"shrink-sealed":true,"source-mapping-bound":false,"source-start":0,"source-length":0,"source-offset":0,"disposition-complete":true,"readiness-proof-acknowledged":false}}}}"#
        ),
        name.as_str(),
        identity.device(),
        identity.inode(),
        identity.length(),
    );
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &contradictory,
    ]))?;

    assert!(matches!(
        client.stage_hot_fork_private_rings(&name, identity),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::HotForkPrivateRings,
            ..
        })
    ));
    assert_eq!(client.quit(), Err(QmpError::ConnectionPoisoned));
    Ok(())
}

#[test]
fn plugin_endpoint_stage_authenticates_exact_basis_and_releases_qemu_copies()
-> Result<(), Box<dyn Error>> {
    let control_name = QmpDescriptorName::new("crucible-hfork-control-v1-test")?;
    let wake_name = QmpDescriptorName::new("crucible-hfork-wake-v1-test")?;
    let identity = QmpHotForkPluginEndpointIdentity::new(101, 202)
        .ok_or("nonzero endpoint identity should be valid")?;
    let staged = format!(
        concat!(
            r#"{{"return":{{"schema-version":4,"generation":1,"template-generation":0,"staged":true,"control-fdname":"{}","wake-fdname":"{}","control-socket-cookie":101,"wake-eventfd-id":202,"control-source-fd":30,"wake-source-fd":31,"control-target-fd":-1,"wake-target-fd":-1,"private-ring-generation":7,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-planned":false,"replacement-plan-bound":false,"control-unix-stream":true,"wake-eventfd":true,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#
        ),
        control_name.as_str(),
        wake_name.as_str(),
    );
    let released = r#"{"return":{"schema-version":4,"generation":2,"template-generation":0,"staged":false,"control-socket-cookie":0,"wake-eventfd-id":0,"control-source-fd":-1,"wake-source-fd":-1,"control-target-fd":-1,"wake-target-fd":-1,"private-ring-generation":0,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-planned":false,"replacement-plan-bound":false,"control-unix-stream":false,"wake-eventfd":false,"disposition-complete":false,"readiness-proof-acknowledged":false}}"#;
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &staged,
        &staged,
        released,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let stage = client.stage_hot_fork_plugin_endpoints(&control_name, &wake_name, identity, 7)?;
    assert_eq!(stage.identity(), Some(identity));
    assert_eq!(stage.private_ring_generation(), 7);
    assert_eq!(stage.control_source_descriptor(), Some(30));
    assert_eq!(stage.wake_source_descriptor(), Some(31));
    assert_eq!(stage.replacement_plan(), None);
    assert_eq!(stage.template_generation(), 0);
    assert_eq!(stage.plugin_barrier_generation(), 0);
    assert_eq!(stage.worker_mask(), 0);
    assert!(!stage.worker_disposition_planned());
    assert_eq!(client.query_hot_fork_plugin_endpoints()?, stage);
    assert!(
        !client
            .release_hot_fork_plugin_endpoints(&control_name, &wake_name, identity)?
            .staged()
    );

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    let stage_request = json_line(&lines, 1);
    assert_eq!(
        oob_execute_name(stage_request),
        Some(QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND)
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/control-fdname")
            .and_then(Value::as_str),
        Some(control_name.as_str())
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/wake-fdname")
            .and_then(Value::as_str),
        Some(wake_name.as_str())
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/expected-control-socket-cookie")
            .and_then(Value::as_u64),
        Some(identity.control_socket_cookie())
    );
    assert_eq!(
        stage_request
            .pointer("/arguments/expected-wake-eventfd-id")
            .and_then(Value::as_u64),
        Some(identity.wake_eventfd_id())
    );
    assert_eq!(
        json_line(&lines, 2)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("query")
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    Ok(())
}

#[test]
fn child_diagnostics_stage_authenticates_exact_stderr_basis_and_releases_qemu_copy()
-> Result<(), Box<dyn Error>> {
    let name = QmpDescriptorName::new("crucible-hfork-diagnostics-v1-test")?;
    let staged = format!(
        r#"{{"return":{{"schema-version":1,"generation":1,"template-generation":3,"staged":true,"fdname":"{}","socket-cookie":101,"source-fd":32,"target-fd":2,"replacement-plan-bound":false,"nonblocking-unix-stream":true,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#,
        name.as_str(),
    );
    let released = r#"{"return":{"schema-version":1,"generation":2,"template-generation":0,"staged":false,"socket-cookie":0,"source-fd":-1,"target-fd":-1,"replacement-plan-bound":false,"nonblocking-unix-stream":false,"disposition-complete":false,"readiness-proof-acknowledged":false}}"#;
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &staged,
        &staged,
        released,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let state = client.stage_hot_fork_child_diagnostics(&name, 101, 3)?;
    assert_eq!(state.descriptor_name(), Some(&name));
    assert_eq!(state.target_descriptor(), Some(2));
    assert!(!state.replacement_plan_bound());
    assert_eq!(client.query_hot_fork_child_diagnostics()?, state);
    assert!(
        !client
            .release_hot_fork_child_diagnostics(&name, 101)?
            .staged()
    );

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_CHILD_DIAGNOSTICS_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/expected-socket-cookie")
            .and_then(Value::as_u64),
        Some(101)
    );
    assert_eq!(
        json_line(&lines, 2)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("query")
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    Ok(())
}

#[test]
fn child_qmp_stage_authenticates_exact_stream_basis_and_releases_qemu_copy()
-> Result<(), Box<dyn Error>> {
    let name = QmpDescriptorName::new("crucible-hfork-qmp-v1-test")?;
    let staged = format!(
        r#"{{"return":{{"schema-version":8,"generation":1,"template-generation":3,"monitor-generation":5,"staged":true,"fdname":"{}","socket-cookie":103,"retained-fd":34,"resource-plan-bound":false,"nonblocking-unix-stream":true,"monitor-basis-bound":true,"monitor-disposition-bound":true,"monitor-socket-resources-bound":true,"reinitializer-prepared":true,"reinitialized":false,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#,
        name.as_str(),
    );
    let released = r#"{"return":{"schema-version":8,"generation":2,"template-generation":0,"monitor-generation":0,"staged":false,"socket-cookie":0,"retained-fd":-1,"resource-plan-bound":false,"nonblocking-unix-stream":false,"monitor-basis-bound":false,"monitor-disposition-bound":false,"monitor-socket-resources-bound":false,"reinitializer-prepared":false,"reinitialized":false,"disposition-complete":false,"readiness-proof-acknowledged":false}}"#;
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &staged,
        &staged,
        released,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let state = client.stage_hot_fork_child_qmp(&name, 103, 3)?;
    assert_eq!(state.descriptor_name(), Some(&name));
    assert_eq!(state.retained_descriptor(), Some(34));
    assert_eq!(state.monitor_generation(), 5);
    assert!(!state.resource_plan_bound());
    assert_eq!(client.query_hot_fork_child_qmp()?, state);
    assert!(!client.release_hot_fork_child_qmp(&name, 103)?.staged());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_CHILD_QMP_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/expected-socket-cookie")
            .and_then(Value::as_u64),
        Some(103)
    );
    assert_eq!(
        json_line(&lines, 2)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("query")
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    Ok(())
}

#[test]
fn hot_fork_child_console_stage_authenticates_exact_stream_basis_and_releases_qemu_copy()
-> Result<(), Box<dyn Error>> {
    let name = QmpDescriptorName::new("crucible-hfork-console-v1-test")?;
    let staged = format!(
        r#"{{"return":{{"schema-version":1,"generation":1,"template-generation":3,"staged":true,"fdname":"{}","socket-cookie":107,"retained-fd":35,"resource-plan-bound":false,"nonblocking-unix-stream":true,"console-basis-bound":true,"reinitializer-prepared":true,"reinitialized":false,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#,
        name.as_str(),
    );
    let released = r#"{"return":{"schema-version":1,"generation":2,"template-generation":0,"staged":false,"socket-cookie":0,"retained-fd":-1,"resource-plan-bound":false,"nonblocking-unix-stream":false,"console-basis-bound":false,"reinitializer-prepared":false,"reinitialized":false,"disposition-complete":false,"readiness-proof-acknowledged":false}}"#;
    let stream = scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &staged,
        &staged,
        released,
    ]);
    let audit = stream.audit_handle();
    let mut client = QmpClient::connect(stream)?;

    let state = client.stage_hot_fork_child_console(&name, 107, 3)?;
    assert_eq!(state.descriptor_name(), Some(&name));
    assert_eq!(state.retained_descriptor(), Some(35));
    assert!(state.console_basis_bound());
    assert!(!state.resource_plan_bound());
    assert_eq!(client.query_hot_fork_child_console()?, state);
    assert!(!client.release_hot_fork_child_console(&name, 107)?.staged());

    drop(client);
    let lines = written_json_lines(&audit_snapshot(&audit))?;
    assert_eq!(
        oob_execute_name(json_line(&lines, 1)),
        Some(QMP_HOT_FORK_CHILD_CONSOLE_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/fdname")
            .and_then(Value::as_str),
        Some(name.as_str())
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/expected-socket-cookie")
            .and_then(Value::as_u64),
        Some(107)
    );
    assert_eq!(
        json_line(&lines, 2)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("query")
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/action")
            .and_then(Value::as_str),
        Some("release")
    );
    Ok(())
}

#[test]
fn contradictory_plugin_endpoint_stage_poisons_the_qmp_client() -> Result<(), Box<dyn Error>> {
    let control_name = QmpDescriptorName::new("crucible-hfork-endpoint-v1-same")?;
    let wake_name = control_name.clone();
    let identity = QmpHotForkPluginEndpointIdentity::new(101, 202)
        .ok_or("nonzero endpoint identity should be valid")?;
    let contradictory = format!(
        concat!(
            r#"{{"return":{{"schema-version":4,"generation":1,"template-generation":0,"staged":true,"control-fdname":"{}","wake-fdname":"{}","control-socket-cookie":101,"wake-eventfd-id":202,"control-source-fd":30,"wake-source-fd":31,"control-target-fd":-1,"wake-target-fd":-1,"private-ring-generation":7,"plugin-barrier-generation":0,"worker-mask":0,"parent-resume-worker-mask":0,"child-reinitialize-worker-mask":0,"pending-worker-mask":0,"worker-disposition-planned":false,"replacement-plan-bound":false,"control-unix-stream":true,"wake-eventfd":true,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#
        ),
        control_name.as_str(),
        wake_name.as_str(),
    );
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &contradictory,
    ]))?;

    assert!(matches!(
        client.stage_hot_fork_plugin_endpoints(&control_name, &wake_name, identity, 7),
        Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::HotForkPluginEndpoints,
            ..
        })
    ));
    assert_eq!(client.quit(), Err(QmpError::ConnectionPoisoned));
    Ok(())
}

#[test]
fn plugin_endpoint_worker_disposition_is_exact_and_empty() -> Result<(), Box<dyn Error>> {
    let control_name = QmpDescriptorName::new("crucible-hfork-control-v1-workers")?;
    let wake_name = QmpDescriptorName::new("crucible-hfork-wake-v1-workers")?;
    let identity = QmpHotForkPluginEndpointIdentity::new(101, 202)
        .ok_or("nonzero endpoint identity should be valid")?;
    let response = |pending_worker_mask, child_reinitialize_worker_mask| {
        format!(
            concat!(
                r#"{{"return":{{"schema-version":4,"generation":1,"template-generation":4,"staged":true,"control-fdname":"{}","wake-fdname":"{}","control-socket-cookie":101,"wake-eventfd-id":202,"control-source-fd":30,"wake-source-fd":31,"control-target-fd":3,"wake-target-fd":4,"private-ring-generation":7,"plugin-barrier-generation":8,"worker-mask":3,"parent-resume-worker-mask":3,"child-reinitialize-worker-mask":{},"pending-worker-mask":{},"worker-disposition-planned":true,"replacement-plan-bound":true,"control-unix-stream":true,"wake-eventfd":true,"disposition-complete":false,"readiness-proof-acknowledged":false}}}}"#
            ),
            control_name.as_str(),
            wake_name.as_str(),
            child_reinitialize_worker_mask,
            pending_worker_mask,
        )
    };

    let valid = response(0, 3);
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        &valid,
    ]))?;
    let staged = client.stage_hot_fork_plugin_endpoints(&control_name, &wake_name, identity, 7)?;
    assert_eq!(staged.template_generation(), 4);
    assert_eq!(staged.plugin_barrier_generation(), 8);
    assert_eq!(staged.worker_mask(), 3);
    assert_eq!(staged.parent_resume_worker_mask(), 3);
    assert_eq!(staged.child_reinitialize_worker_mask(), 3);
    assert!(staged.worker_disposition_planned());
    let plan = staged
        .replacement_plan()
        .ok_or("template-bound endpoints should retain a replacement plan")?;
    assert_eq!(plan.control_source(), 30);
    assert_eq!(plan.wake_source(), 31);
    assert_eq!(plan.control_target(), 3);
    assert_eq!(plan.wake_target(), 4);

    let aliased_source = valid.replace("\"wake-source-fd\":31", "\"wake-source-fd\":30");
    let unbound_plan = valid.replace(
        "\"replacement-plan-bound\":true",
        "\"replacement-plan-bound\":false",
    );
    for invalid in [response(1, 3), response(0, 1), aliased_source, unbound_plan] {
        let mut client = QmpClient::connect(scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            &invalid,
        ]))?;
        assert!(matches!(
            client.stage_hot_fork_plugin_endpoints(&control_name, &wake_name, identity, 7),
            Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkPluginEndpoints,
                ..
            })
        ));
        assert_eq!(client.quit(), Err(QmpError::ConnectionPoisoned));
    }
    Ok(())
}

#[path = "qmp/support.rs"]
mod support;

use support::*;
