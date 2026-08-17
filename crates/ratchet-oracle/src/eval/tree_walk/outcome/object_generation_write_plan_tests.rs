//! Tests for the boundary minor-GC object-generation write plan.

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

fn object_generation(
    request: AllocationCollectorPollObjectByteCopyRequest,
) -> EvalGcStressBoundaryMinorGcLiveObjectGeneration {
    EvalGcStressBoundaryMinorGcLiveObjectGeneration::new(
        request.source(),
        request.destination(),
        request.action(),
        generation_for_destination_action(request.action()),
        request,
    )
}

fn object_generation_with_parts(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
) -> EvalGcStressBoundaryMinorGcLiveObjectGeneration {
    EvalGcStressBoundaryMinorGcLiveObjectGeneration::new(
        source,
        destination,
        action,
        generation,
        request,
    )
}

fn live_object_generations(
    object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
) -> EvalGcStressBoundaryMinorGcLiveObjectGenerations {
    let install_report = live_object_generation_install_report(&object_generations);
    EvalGcStressBoundaryMinorGcLiveObjectGenerations {
        install_report,
        object_generations,
    }
}

#[test]
fn plans_object_generation_writes_from_installed_live_metadata() {
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
    let object_generations = live_object_generations(vec![
        object_generation(copied_request),
        object_generation(promoted_request),
    ]);

    let write_plan =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect("object-generation write plan validates");

    assert_eq!(write_plan.len(), 2);
    assert_eq!(write_plan.report().objects(), 2);
    assert_eq!(write_plan.report().copied_to_nursery(), 1);
    assert_eq!(write_plan.report().promoted_to_old(), 1);
    assert_eq!(write_plan.report().payload_bytes(), 8);
    assert_eq!(write_plan.writes()[0].source(), copied_request.source());
    assert_eq!(
        write_plan.writes()[0].destination(),
        copied_request.destination()
    );
    assert_eq!(
        write_plan.writes()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(write_plan.writes()[0].generation(), HeapGeneration::Young);
    assert_eq!(write_plan.writes()[0].request(), copied_request);
    assert_eq!(write_plan.writes()[0].destination_bytes(), copied_bytes);
    assert_eq!(write_plan.writes()[1].source(), promoted_request.source());
    assert_eq!(
        write_plan.writes()[1].destination(),
        promoted_request.destination()
    );
    assert_eq!(
        write_plan.writes()[1].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(write_plan.writes()[1].generation(), HeapGeneration::Old);
    assert_eq!(write_plan.writes()[1].request(), promoted_request);
    assert_eq!(write_plan.writes()[1].destination_bytes(), promoted_bytes);
}

#[test]
fn plans_empty_object_generation_writes_when_no_metadata_is_installed() {
    let destination_storage = destination_storage(Vec::new());
    let object_generations = live_object_generations(Vec::new());

    let write_plan =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect("empty object-generation write plan validates");

    assert!(write_plan.is_empty());
    assert_eq!(write_plan.report().objects(), 0);
    assert_eq!(write_plan.report().payload_bytes(), 0);
}

#[test]
fn rejects_object_generation_without_destination_snapshot() {
    let copied_request = request(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let destination_storage = destination_storage(Vec::new());
    let object_generations = live_object_generations(vec![object_generation(copied_request)]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("object generation without destination bytes is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteMissingDestination {
            source_address,
            destination,
            action: MinorGcSurvivorAction::CopyToNursery,
            generation: HeapGeneration::Young,
        } if source_address == copied_request.source()
            && destination == copied_request.destination()
    ));
}

#[test]
fn rejects_destination_snapshot_without_object_generation() {
    let copied_request = request(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let destination_storage =
        destination_storage(vec![object_bytes(copied_request, vec![1, 2, 3, 4])]);
    let object_generations = live_object_generations(Vec::new());

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("destination bytes without object generation are rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteUnboundDestination {
            source_address,
            destination,
            action: MinorGcSurvivorAction::CopyToNursery,
            generation: HeapGeneration::Young,
        } if source_address == copied_request.source()
            && destination == copied_request.destination()
    ));
}

#[test]
fn rejects_stale_destination_snapshot_for_object_generation() {
    let source = address(0x1000);
    let installed_request = request(
        source,
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let current_request = request(
        source,
        address(0x3000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let destination_storage =
        destination_storage(vec![object_bytes(installed_request, vec![1, 2, 3, 4])]);
    let object_generations = live_object_generations(vec![object_generation(current_request)]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("stale destination snapshot is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteBindingMismatch {
            source_address,
            expected,
            expected_generation: HeapGeneration::Young,
            actual,
            actual_generation: HeapGeneration::Young,
        } if source_address == source
            && expected == current_request
            && actual == installed_request
    ));
}

#[test]
fn rejects_duplicate_object_generation_source() {
    let source = address(0x1000);
    let first = request(
        source,
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let second = request(
        source,
        address(0x3000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let destination_storage = destination_storage(Vec::new());
    let object_generations =
        live_object_generations(vec![object_generation(first), object_generation(second)]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("duplicate object-generation source is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateSource {
            index: 1,
            source_address,
        } if source_address == source
    ));
}

#[test]
fn rejects_duplicate_object_generation_destination() {
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
    let destination_storage = destination_storage(Vec::new());
    let object_generations =
        live_object_generations(vec![object_generation(first), object_generation(second)]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("duplicate object-generation destination is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestination {
            index: 1,
            source_address,
            existing_source_address,
            destination: duplicate_destination,
        } if source_address == second.source()
            && existing_source_address == first.source()
            && duplicate_destination == destination
    ));
}

#[test]
fn rejects_duplicate_destination_snapshot_source() {
    let source = address(0x1000);
    let first = request(
        source,
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let second = request(
        source,
        address(0x3000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let destination_storage = destination_storage(vec![
        object_bytes(first, vec![1, 2, 3, 4]),
        object_bytes(second, vec![5, 6, 7, 8]),
    ]);
    let object_generations = live_object_generations(Vec::new());

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("duplicate destination snapshot source is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestinationSource {
            index: 1,
            source_address,
        } if source_address == source
    ));
}

#[test]
fn rejects_duplicate_destination_snapshot_destination() {
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
    let object_generations = live_object_generations(Vec::new());

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("duplicate destination snapshot address is rejected");

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
fn rejects_object_generation_request_source_mismatch() {
    let source = address(0x1000);
    let request = request(
        address(0x3000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let generation = object_generation_with_parts(
        source,
        request.destination(),
        request.action(),
        HeapGeneration::Young,
        request,
    );
    let destination_storage = destination_storage(Vec::new());
    let object_generations = live_object_generations(vec![generation]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("request source mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestSourceMismatch {
            source_address,
            request_source,
        } if source_address == source && request_source == request.source()
    ));
}

#[test]
fn rejects_object_generation_request_destination_mismatch() {
    let source = address(0x1000);
    let generation_destination = address(0x2000);
    let request = request(
        source,
        address(0x3000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let generation = object_generation_with_parts(
        source,
        generation_destination,
        request.action(),
        HeapGeneration::Young,
        request,
    );
    let destination_storage = destination_storage(Vec::new());
    let object_generations = live_object_generations(vec![generation]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("request destination mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestDestinationMismatch {
            source_address,
            generation_destination: actual_generation_destination,
            request_destination,
        } if source_address == source
            && actual_generation_destination == generation_destination
            && request_destination == request.destination()
    ));
}

#[test]
fn rejects_object_generation_request_action_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let request = request(source, destination, MinorGcSurvivorAction::PromoteToOld);
    let generation = object_generation_with_parts(
        source,
        destination,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Old,
        request,
    );
    let destination_storage = destination_storage(Vec::new());
    let object_generations = live_object_generations(vec![generation]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("request action mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestActionMismatch {
            source_address,
            destination: actual_destination,
            generation_action: MinorGcSurvivorAction::CopyToNursery,
            request_action: MinorGcSurvivorAction::PromoteToOld,
        } if source_address == source && actual_destination == destination
    ));
}

#[test]
fn rejects_object_generation_generation_mismatch() {
    let request = request(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
    );
    let generation = object_generation_with_parts(
        request.source(),
        request.destination(),
        request.action(),
        HeapGeneration::Old,
        request,
    );
    let destination_storage = destination_storage(Vec::new());
    let object_generations = live_object_generations(vec![generation]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("generation mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcObjectGenerationWriteGenerationMismatch {
            source_address,
            destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if source_address == request.source()
            && destination == request.destination()
    ));
}

#[test]
fn rejects_destination_payload_size_mismatch_for_write_plan() {
    let request = request_with_parts(
        address(0x1000),
        address(0x2000),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        4,
    );
    let destination_storage = destination_storage(vec![object_bytes(request, vec![1, 2, 3])]);
    let object_generations = live_object_generations(vec![object_generation(request)]);

    let err =
        boundary_minor_gc_object_generation_write_plan(&destination_storage, &object_generations)
            .expect_err("destination payload length mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
            destination,
            expected: 4,
            actual: 3,
        } if destination == request.destination()
    ));
}
