//! Multi-node aggregate QEMU fault-event staging regressions.

use super::*;

pub(super) fn snapshot_scripted_fault_events(
    events: &VecDeque<DequeuedFaultEvent>,
    destination: &mut Vec<DequeuedFaultEvent>,
    canonical_payload_bytes: &mut usize,
    configured_payload_bytes: usize,
    configured_inline_payload_bytes: usize,
) -> Result<(), QemuNodeError> {
    if destination.capacity().saturating_sub(destination.len()) < events.len() {
        return Err(QemuNodeError::FaultEventStorage {
            current: u64::try_from(destination.len()).unwrap_or(u64::MAX),
            requested: u64::try_from(events.len()).unwrap_or(u64::MAX),
            configured: u64::try_from(destination.capacity()).unwrap_or(u64::MAX),
        });
    }
    for event in events {
        if event.payload.len() > configured_inline_payload_bytes {
            return Err(QemuNodeError::FaultEventInlinePayloadStorage {
                requested: u64::try_from(event.payload.len()).unwrap_or(u64::MAX),
                configured: u64::try_from(configured_inline_payload_bytes).unwrap_or(u64::MAX),
            });
        }
        let record_bytes = event
            .payload
            .len()
            .checked_add(crucible_shmem::FAULT_EVENT_HEADER_V1_BYTES)
            .ok_or(QemuNodeError::FaultEventPayloadStorage {
                current: u64::MAX,
                requested: u64::MAX,
                configured: u64::try_from(configured_payload_bytes).unwrap_or(u64::MAX),
            })?;
        let admitted = canonical_payload_bytes.checked_add(record_bytes);
        if admitted.is_none_or(|total| total > configured_payload_bytes) {
            return Err(QemuNodeError::FaultEventPayloadStorage {
                current: u64::try_from(*canonical_payload_bytes).unwrap_or(u64::MAX),
                requested: u64::try_from(record_bytes).unwrap_or(u64::MAX),
                configured: u64::try_from(configured_payload_bytes).unwrap_or(u64::MAX),
            });
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(event.payload.len())
            .map_err(|_| QemuNodeError::FaultEventPayloadStorage {
                current: u64::try_from(*canonical_payload_bytes).unwrap_or(u64::MAX),
                requested: u64::try_from(record_bytes).unwrap_or(u64::MAX),
                configured: u64::try_from(configured_payload_bytes).unwrap_or(u64::MAX),
            })?;
        payload.extend_from_slice(&event.payload);
        destination.push(DequeuedFaultEvent {
            header: event.header.clone(),
            payload,
        });
        *canonical_payload_bytes = admitted.unwrap_or(configured_payload_bytes);
    }
    Ok(())
}

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
fn selected_node_step_rearms_the_retained_aggregate_fault_event_budget() {
    let log = shared_log();
    let mut nodes = QemuNodeSet::new();
    let node = node_id("vm-a");
    let _prior = nodes.insert(
        node.clone(),
        scripted_node(Arc::clone(&log), false, false, false)
            .unwrap_or_else(|error| panic!("construct scripted node: {error}")),
    );

    nodes
        .set_fault_event_staging_limit(4, 10)
        .unwrap_or_else(|error| panic!("install aggregate event budget: {error}"));
    assert_eq!(
        recorded(&log).last(),
        Some(&ChannelCall::HostFaultEventLimit {
            maximum_local_records: 0,
            canonical_current_offset: 6,
            configured_event_records: 10,
        })
    );

    let observation = SimulationBackend::step_node_to(&mut nodes, &node, VirtualTime { ticks: 19 })
        .unwrap_or_else(|error| panic!("step selected node: {error}"));
    assert_eq!(observation.reached, VirtualTime { ticks: 19 });
    let calls = recorded(&log);
    let allowance = calls
        .iter()
        .position(|call| {
            call == &ChannelCall::HostFaultEventLimit {
                maximum_local_records: 4,
                canonical_current_offset: 6,
                configured_event_records: 10,
            }
        })
        .unwrap_or_else(|| panic!("selected node was not armed from the aggregate budget"));
    let start = calls
        .iter()
        .position(|call| call == &ChannelCall::ShmemStart(19))
        .unwrap_or_else(|| panic!("selected node did not start its quantum"));
    assert!(allowance < start);

    nodes
        .take(&node)
        .unwrap_or_else(|| panic!("scripted node should remain present"))
        .shutdown_child()
        .unwrap_or_else(|error| panic!("shut down scripted node: {error}"));
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
fn fault_event_payload_limit_rejects_before_copying_or_consuming_ownership()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let payload = vec![0x5a; 17];
    let mut event = fault_event_with_sequence(1);
    event.header.payload_hash = *blake3::hash(&payload).as_bytes();
    event.header.payload_length = payload.len() as u32;
    event.payload = payload;
    let mut node = scripted_node_with_fault_events(Arc::clone(&log), [event])?;
    let mut canonical_records = 2;
    let mut canonical_payload_bytes = 11;
    let record_bytes = 17 + crucible_shmem::FAULT_EVENT_HEADER_V1_BYTES;

    let configured = 11 + record_bytes - 1;
    let preview = node.preview_fault_events(
        &mut canonical_records,
        10,
        &mut canonical_payload_bytes,
        configured,
        17,
    );
    assert!(
        matches!(
            preview,
            Err(QemuNodeError::FaultEventPayloadStorage {
                current: 11,
                requested,
                configured: observed_configured,
            })
                if requested == record_bytes as u64
                    && observed_configured == configured as u64
        ),
        "unexpected preview result: {preview:?}"
    );
    assert_eq!(canonical_records, 2);
    assert_eq!(canonical_payload_bytes, 11);
    assert!(node.fault_event_pending()?);
    node.shutdown_child()?;
    Ok(())
}

#[test]
fn fault_event_inline_payload_limit_rejects_before_copying_or_consuming_ownership()
-> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let payload = vec![0xa5; 17];
    let mut event = fault_event_with_sequence(1);
    event.header.payload_hash = *blake3::hash(&payload).as_bytes();
    event.header.payload_length = payload.len() as u32;
    event.payload = payload;
    let mut node = scripted_node_with_fault_events(Arc::clone(&log), [event])?;
    let mut canonical_records = 2;
    let mut canonical_event_log_bytes = 11;

    assert!(matches!(
        node.preview_fault_events(
            &mut canonical_records,
            10,
            &mut canonical_event_log_bytes,
            usize::MAX,
            16,
        ),
        Err(QemuNodeError::FaultEventInlinePayloadStorage {
            requested: 17,
            configured: 16,
        })
    ));
    assert_eq!(canonical_records, 2);
    assert_eq!(canonical_event_log_bytes, 11);
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
