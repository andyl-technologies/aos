//! Scheduler-owned network checkpoint resource-admission tests.

use super::*;

#[test]
fn rejects_declared_link_count_before_allocation() {
    let mut bytes = b"crucible.scheduler-network.v1\0".to_vec();
    bytes.extend_from_slice(&65_537_u32.to_le_bytes());

    assert_eq!(
        SchedulerNetworkCheckpoint::from_canonical_bytes(&bytes),
        Err(SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field: "directed links",
            current: 0,
            requested: 65_537,
            configured: 65_536,
            hard: 65_536,
        })
    );
}

#[test]
fn rejects_declared_rng_count_before_allocation() {
    let mut bytes = b"crucible.scheduler-network.v1\0".to_vec();
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&65_537_u32.to_le_bytes());

    assert_eq!(
        SchedulerNetworkCheckpoint::from_canonical_bytes(&bytes),
        Err(SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field: "RNG positions",
            current: 0,
            requested: 65_537,
            configured: 65_536,
            hard: 65_536,
        })
    );
}

#[test]
fn enforces_authored_aggregate_limit() {
    let checkpoint = SchedulerNetworkCheckpoint {
        links: Vec::new(),
        rng_positions: Vec::new(),
        signal_fault_wakeup_nanos: Some(17),
    };
    let bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("scheduler checkpoint should encode: {error}"));
    let maximum =
        u64::try_from(bytes.len() - 1).unwrap_or_else(|_| panic!("checkpoint size should fit u64"));

    assert!(matches!(
        checkpoint.canonical_bytes_with_limit(maximum),
        Err(SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field: "scheduler network checkpoint bytes",
            current,
            requested,
            configured,
            hard: 68_719_476_736,
        }) if current.saturating_add(requested) > maximum && configured == maximum
    ));
    assert!(matches!(
        SchedulerNetworkCheckpoint::from_canonical_bytes_with_limit(&bytes, maximum),
        Err(SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field: "scheduler network checkpoint bytes",
            current: 0,
            requested,
            configured,
            hard: 68_719_476_736,
        }) if requested == u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            && configured == maximum
    ));
}

#[test]
fn preserves_nested_link_resource_coordinates() {
    let link = LinkId::from_name("link-a");
    let state = crucible_device::NetLink::new(8, 3, 256, 256, crucible_device::LinkFaults::none())
        .unwrap_or_else(|error| panic!("test link should construct: {error}"))
        .snapshot();
    let state_bytes = state
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("test link should encode: {error}"));
    let maximum = u64::try_from(state_bytes.len() - 1)
        .unwrap_or_else(|_| panic!("link snapshot size should fit u64"));
    let checkpoint = SchedulerNetworkCheckpoint {
        links: vec![SchedulerNetworkLinkCheckpoint {
            link: link.clone(),
            direction: NetworkLinkDirection::EndpointAToEndpointB,
            state,
        }],
        rng_positions: vec![(link, 0)],
        signal_fault_wakeup_nanos: None,
    };

    assert!(matches!(
        checkpoint.canonical_bytes_with_limit(maximum),
        Err(SchedulerNetworkCheckpointCodecError::ResourceLimit {
            field: "link snapshot bytes",
            current,
            requested,
            configured,
            hard: 1_073_741_824,
        }) if current.saturating_add(requested) > maximum && configured == maximum
    ));
}
