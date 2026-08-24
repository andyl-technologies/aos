//! Multi-node aggregate QEMU fault-event staging regressions.

use super::*;

#[test]
fn node_set_arms_one_node_from_one_aggregate_fault_event_budget() -> Result<(), Box<dyn Error>> {
    let log_a = shared_log();
    let log_b = shared_log();
    let mut nodes = QemuNodeSet::new();
    let node_a = node_id("vm-a");
    let node_b = node_id("vm-b");
    let _prior = nodes.insert(
        node_a.clone(),
        scripted_node_with_fault_events(Arc::clone(&log_a), [fault_event_with_sequence(1)])?,
    );
    let _prior = nodes.insert(
        node_b.clone(),
        scripted_node_with_fault_events(Arc::clone(&log_b), [fault_event_with_sequence(1)])?,
    );

    nodes.set_fault_event_staging_limit(4, 10)?;
    assert_eq!(
        recorded(&log_a).last(),
        Some(&ChannelCall::HostFaultEventLimit {
            maximum_local_records: 1,
            canonical_current_offset: 7,
            configured_event_records: 10,
        })
    );
    assert_eq!(recorded(&log_b).last(), recorded(&log_a).last());

    assert_eq!(nodes.fault_event_staging_allowance(&node_a, 4, 10)?, 3);
    assert_eq!(
        recorded(&log_a).last(),
        Some(&ChannelCall::HostFaultEventLimit {
            maximum_local_records: 3,
            canonical_current_offset: 7,
            configured_event_records: 10,
        })
    );
    assert_eq!(
        recorded(&log_b).last(),
        Some(&ChannelCall::HostFaultEventLimit {
            maximum_local_records: 1,
            canonical_current_offset: 7,
            configured_event_records: 10,
        })
    );
    Ok(())
}

#[test]
fn fault_event_limit_rejects_before_consuming_staged_ownership() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node =
        scripted_node_with_fault_events(Arc::clone(&log), [fault_event_with_sequence(1)])?;
    let mut events = Vec::new();
    let mut canonical_current = 3;

    assert!(matches!(
        node.drain_fault_events_with_budget(&mut events, &mut canonical_current, 3),
        Err(QemuNodeError::FaultEventStorage {
            current: 3,
            requested: 1,
            configured: 3,
        })
    ));
    assert!(events.is_empty());
    assert_eq!(canonical_current, 3);
    assert!(node.fault_event_pending()?);
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn fingerprint_nodes_spend_one_sequential_fault_event_budget() -> Result<(), Box<dyn Error>> {
    let log_a = shared_log();
    let log_b = shared_log();
    let mut nodes = QemuNodeSet::new();
    let _prior = nodes.insert(
        node_id("vm-a"),
        scripted_node_with_options(
            Arc::clone(&log_a),
            ScriptedNodeOptions {
                fingerprint_retry_countdown: 1,
                fingerprint_fault_event_count: 1,
                ..ScriptedNodeOptions::default()
            },
            std::iter::empty(),
        )?,
    );
    let _prior = nodes.insert(
        node_id("vm-b"),
        scripted_node_with_options(
            Arc::clone(&log_b),
            ScriptedNodeOptions {
                fingerprint_retry_countdown: 1,
                fingerprint_fault_event_count: 1,
                ..ScriptedNodeOptions::default()
            },
            std::iter::empty(),
        )?,
    );

    let fingerprints = nodes
        .execution_fingerprint_entries(2, 10)?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(fingerprints.len(), 2);
    assert!(
        recorded(&log_a).contains(&ChannelCall::HostFaultEventLimit {
            maximum_local_records: 2,
            canonical_current_offset: 8,
            configured_event_records: 10,
        })
    );
    assert!(
        recorded(&log_b).contains(&ChannelCall::HostFaultEventLimit {
            maximum_local_records: 1,
            canonical_current_offset: 9,
            configured_event_records: 10,
        })
    );
    assert_eq!(nodes.staged_fault_event_count()?, 2);

    for node in [node_id("vm-a"), node_id("vm-b")] {
        nodes
            .take(&node)
            .unwrap_or_else(|| panic!("scripted node should remain present"))
            .shutdown_child()?;
    }
    Ok(())
}

#[test]
fn production_restore_requires_clean_fault_event_ownership() -> Result<(), Box<dyn Error>> {
    let plan = crucible::model::FaultSignalPlan::new(
        Vec::new(),
        Vec::new(),
        crucible::model::FaultResourceLimits::default(),
    )?;
    let seed = ContentHash::from_bytes(b"restore-clean-event-ownership");
    let mut clean_nodes = QemuNodeSet::new();
    let clean_log = shared_log();
    let _prior = clean_nodes.insert(
        node_id("vm-a"),
        scripted_node(Arc::clone(&clean_log), false, false, false)?,
    );
    let runtime = crate::ProductionFaultRuntime::new(
        plan.clone(),
        None,
        crucible::model::SignalBoundarySnapshot::default(),
        seed,
        crate::production_fault_runtime::test_support::test_host_manifests(),
        &clean_nodes,
    )?;
    let checkpoint = runtime.checkpoint(&mut clean_nodes)?;
    clean_nodes
        .take(&node_id("vm-a"))
        .unwrap_or_else(|| panic!("clean source node should remain present"))
        .shutdown_child()?;

    let dirty_log = shared_log();
    let mut dirty_nodes = QemuNodeSet::new();
    let _prior = dirty_nodes.insert(
        node_id("vm-a"),
        scripted_node_with_fault_events(Arc::clone(&dirty_log), [fault_event_with_sequence(1)])?,
    );
    let restored = crate::ProductionFaultRuntime::restore(
        plan,
        None,
        seed,
        checkpoint,
        crate::production_fault_runtime::test_support::test_host_manifests(),
        &mut dirty_nodes,
    );
    assert!(matches!(
        restored,
        Err(crate::ProductionFaultRuntimeError::PendingQemuFaultEvents)
    ));
    assert!(
        !recorded(&dirty_log)
            .iter()
            .any(|call| matches!(call, ChannelCall::HostFaultEventLimit { .. }))
    );
    dirty_nodes
        .take(&node_id("vm-a"))
        .unwrap_or_else(|| panic!("dirty restore node should remain present"))
        .shutdown_child()?;
    Ok(())
}

#[test]
fn production_restore_rejects_fault_event_published_by_fingerprint() -> Result<(), Box<dyn Error>> {
    let plan = crucible::model::FaultSignalPlan::new(
        Vec::new(),
        Vec::new(),
        crucible::model::FaultResourceLimits::default(),
    )?;
    let seed = ContentHash::from_bytes(b"restore-fingerprint-event-ownership");
    let mut source_nodes = QemuNodeSet::new();
    let source_log = shared_log();
    let _prior = source_nodes.insert(
        node_id("vm-a"),
        scripted_node(Arc::clone(&source_log), false, false, false)?,
    );
    let runtime = crate::ProductionFaultRuntime::new(
        plan.clone(),
        None,
        crucible::model::SignalBoundarySnapshot::default(),
        seed,
        crate::production_fault_runtime::test_support::test_host_manifests(),
        &source_nodes,
    )?;
    let checkpoint = runtime.checkpoint(&mut source_nodes)?;
    source_nodes
        .take(&node_id("vm-a"))
        .unwrap_or_else(|| panic!("checkpoint source node should remain present"))
        .shutdown_child()?;

    let restore_log = shared_log();
    let mut restore_nodes = QemuNodeSet::new();
    let _prior = restore_nodes.insert(
        node_id("vm-a"),
        scripted_node_with_options(
            Arc::clone(&restore_log),
            ScriptedNodeOptions {
                fingerprint_retry_countdown: 1,
                fingerprint_fault_event_count: 1,
                ..ScriptedNodeOptions::default()
            },
            std::iter::empty(),
        )?,
    );
    let restored = crate::ProductionFaultRuntime::restore(
        plan,
        None,
        seed,
        checkpoint,
        crate::production_fault_runtime::test_support::test_host_manifests(),
        &mut restore_nodes,
    );
    assert!(matches!(
        restored,
        Err(crate::ProductionFaultRuntimeError::PendingQemuFaultEvents)
    ));
    assert!(recorded(&restore_log).contains(&ChannelCall::HostFingerprintBoundary));
    restore_nodes
        .take(&node_id("vm-a"))
        .unwrap_or_else(|| panic!("failed restore node should remain present"))
        .shutdown_child()?;
    Ok(())
}
