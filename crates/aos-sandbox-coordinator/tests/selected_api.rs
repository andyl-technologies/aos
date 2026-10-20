//! Checks explicit coordinator API selection and the closed empty-candidate result.

#![cfg(target_os = "linux")]

#[test]
fn explicit_multi_node_selection_exposes_remote_adapters() {
    use aos_sandbox_coordinator::placement::place_deterministically;
    use aos_sandbox_coordinator::watch_service::DormantOrderedWatchServiceV1;

    let _watch = DormantOrderedWatchServiceV1::new;
    let _placement = place_deterministically;
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

#[test]
fn protected_transport_is_owned_by_the_selected_coordinator() {
    let _authenticate = aos_sandbox_coordinator::transport::CoordinatorNodeTransportOriginalV1::authenticate_once_v1;
}

#[test]
fn real_drain_and_transfer_callers_belong_to_coordinator() {
    let _drain = aos_sandbox_coordinator::draining::prepare_current_drain_request;
    let _resume = aos_sandbox_coordinator::transfer::SnapshotTransferCoordinatorV1::prepare_snapshot_resume_request;
    let _chunk = aos_sandbox_coordinator::transfer::SnapshotTransferCoordinatorV1::prepare_next_snapshot_chunk_request;
    let _dependency = aos_sandbox_coordinator::transfer::SnapshotTransferCoordinatorV1::prepare_next_snapshot_dependency_request;
}
