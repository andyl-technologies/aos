//! Checks explicit coordinator API selection and the closed empty-candidate result.

#![cfg(target_os = "linux")]

#[test]
fn explicit_multi_node_selection_exposes_remote_adapters() {
    use aos_sandbox_coordinator::placement::place_deterministically;
    use aos_sandbox_coordinator::watch_service::DormantOrderedWatchServiceV1;
    use aos_sandbox_coordinator::lease_projection::committed_lease_to_protobuf;

    let _watch = DormantOrderedWatchServiceV1::new;
    let _placement = place_deterministically;
    let _lease_wire = committed_lease_to_protobuf;
}

#[test]
fn explicitly_selected_placement_keeps_no_candidates_closed() {
    use aos_sandbox_coordinator::placement::{
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
