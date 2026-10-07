//! Checks local lease/inventory reachability and explicit remote adapter selection.

#![cfg(target_os = "linux")]

use aos_sandbox::local_ownership::ProtectedFixedLocalLeaseOwnerV1;
use aos_sandbox::ownership_service::OwnershipProtocolRequestHandler;

#[test]
fn local_lease_owner_is_a_protocol_handler_without_remote_selection() {
    fn require_handler<T: OwnershipProtocolRequestHandler>() {}

    require_handler::<ProtectedFixedLocalLeaseOwnerV1>();
    let _open = ProtectedFixedLocalLeaseOwnerV1::open_fixed_protected;
    let _recover = ProtectedFixedLocalLeaseOwnerV1::recover;
}

#[test]
fn protected_snapshot_inventory_remains_available_without_remote_selection() {
    let _open = aos_sandbox::multi_node::ProtectedMultiNodeAuthorityOwnerV1::open_fixed_protected;
    let _resolve = aos_sandbox::multi_node::ProtectedMultiNodeAuthorityOwnerV1::resolve_store_write;
}

#[cfg(feature = "multi-node")]
#[test]
fn explicit_multi_node_selection_exposes_remote_adapters() {
    use aos_sandbox::local_ownership::ProtectedCommittedLeaseV1;
    use aos_sandbox::multi_node::{DormantOrderedWatchServiceV1, place_deterministically};

    let _watch = DormantOrderedWatchServiceV1::new;
    let _placement = place_deterministically;
    let _lease_wire = ProtectedCommittedLeaseV1::protobuf;
    let _transport =
        aos_sandbox::multi_node::ProtectedMultiNodeAuthorityOwnerV1::authenticate_dormant_transport;
}

#[cfg(feature = "multi-node")]
#[test]
fn explicitly_selected_placement_keeps_no_candidates_closed() {
    use aos_sandbox::multi_node::{
        PlacementBlockReasonV1, PlacementDecisionV1, place_deterministically,
    };
    use aos_sandbox_core::model::PlacementRequest;
    use aos_sandbox_core::{ResourceVector, SandboxId};

    let request = PlacementRequest::new(
        SandboxId::from_bytes([1; 16]),
        Vec::new(),
        Vec::new(),
        ResourceVector::default(),
    )
    .unwrap();

    let outcome = place_deterministically(&request, &[], &[], 100, 30).unwrap();

    assert_eq!(
        outcome,
        PlacementDecisionV1::Blocked {
            reason: PlacementBlockReasonV1::NoCandidates,
            rejections: Vec::new(),
        }
    );
}
