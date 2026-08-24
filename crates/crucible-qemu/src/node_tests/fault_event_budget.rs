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
