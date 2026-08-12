//! Tests for destination object-generation binding derivation.

use super::*;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is non-zero")
}

fn request(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
) -> AllocationCollectorPollObjectByteCopyRequest {
    request_with_parts(
        source,
        destination,
        action,
        generation_for_destination_action(action),
        4,
    )
}

fn request_with_parts(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    destination_generation: HeapGeneration,
    size_bytes: usize,
) -> AllocationCollectorPollObjectByteCopyRequest {
    AllocationCollectorPollObjectByteCopyRequest::for_test(
        source,
        destination,
        action,
        destination_generation,
        size_bytes,
        8,
    )
}

fn object_bytes(
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
) -> EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
    EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(request, destination_bytes)
}

fn destination_storage(
    object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
) -> EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    let install_report = live_destination_storage_install_report(&object_bytes);
    EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        install_report,
        object_bytes,
    }
}

#[test]
fn matches_destination_snapshots_to_object_generations() {
    let copied_request = request(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let promoted_request = request(
        address(0x3000),
        address(0x4000),
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copied_bytes = vec![1, 2, 3, 4];
    let promoted_bytes = vec![5, 6, 7, 8];
    let destination_storage = destination_storage(vec![
        object_bytes(copied_request, copied_bytes.clone()),
        object_bytes(promoted_request, promoted_bytes.clone()),
    ]);

    let bindings = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
        .expect("destination generation bindings validate");

    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].source(), copied_request.source());
    assert_eq!(bindings[0].destination(), copied_request.destination());
    assert_eq!(bindings[0].action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(bindings[0].generation(), HeapGeneration::Young);
    assert_eq!(bindings[0].request(), copied_request);
    assert_eq!(bindings[0].destination_bytes(), copied_bytes);
    assert_eq!(bindings[1].source(), promoted_request.source());
    assert_eq!(bindings[1].destination(), promoted_request.destination());
    assert_eq!(bindings[1].action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(bindings[1].generation(), HeapGeneration::Old);
    assert_eq!(bindings[1].request(), promoted_request);
    assert_eq!(bindings[1].destination_bytes(), promoted_bytes);
}

#[test]
fn rejects_destination_action_generation_mismatch() {
    let request = request_with_parts(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Old,
        4,
    );
    let destination_storage = destination_storage(vec![object_bytes(request, vec![1, 2, 3, 4])]);

    let err = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
        .expect_err("action/generation mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
            destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if destination == request.destination()
    ));
}

#[test]
fn rejects_destination_payload_size_mismatch() {
    let request = request_with_parts(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        4,
    );
    let destination_storage = destination_storage(vec![object_bytes(request, vec![1, 2, 3])]);

    let err = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
        .expect_err("payload length mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
            destination,
            expected: 4,
            actual: 3,
        } if destination == request.destination()
    ));
}

#[test]
fn rejects_duplicate_destination_snapshot() {
    let destination = address(0x2000);
    let first = request(
        address(0x1000),
        destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let second = request(
        address(0x3000),
        destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let destination_storage = destination_storage(vec![
        object_bytes(first, vec![1, 2, 3, 4]),
        object_bytes(second, vec![5, 6, 7, 8]),
    ]);

    let err = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
        .expect_err("duplicate destination snapshot is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcLiveDestinationStorageDestinationCollision {
            source_address,
            existing_source_address,
            destination_address,
        } if source_address == second.source()
            && existing_source_address == first.source()
            && destination_address == destination
    ));
}

#[test]
fn live_destination_storage_install_validates_generation_metadata() {
    let request = request_with_parts(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Young,
        4,
    );
    let mut destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

    let err = destination_storage
        .install(vec![object_bytes(request, vec![1, 2, 3, 4])])
        .expect_err("standalone install rejects mismatched generation metadata");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
            destination,
            expected: HeapGeneration::Old,
            actual: HeapGeneration::Young,
            action: MinorGcSurvivorAction::PromoteToOld,
        } if destination == request.destination()
    ));
    assert!(destination_storage.is_empty());
}
