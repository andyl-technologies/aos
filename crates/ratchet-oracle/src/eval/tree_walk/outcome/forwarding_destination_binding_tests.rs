//! Tests for forwarding destination-binding derivation.

use super::*;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is non-zero")
}

fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
    ResolvedValueGeneration::Heap {
        address,
        generation,
    }
}

fn request(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
) -> AllocationCollectorPollObjectByteCopyRequest {
    AllocationCollectorPollObjectByteCopyRequest::for_test(
        source,
        destination,
        action,
        generation_for_destination_action(action),
        4,
        8,
    )
}

fn object_bytes(
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
) -> EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
    EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(request, destination_bytes)
}

fn forwarding_slot(
    source: GcHeapAddress,
    destination: GcHeapAddress,
    generation: HeapGeneration,
) -> MinorGcForwardingSlot {
    MinorGcForwardingSlot::with_forwarded_value(source, heap(destination, generation))
}

#[test]
fn matches_forwarding_slots_to_destination_snapshots() {
    let copied_source = address(0x1000);
    let copied_destination = address(0x2000);
    let promoted_source = address(0x3000);
    let promoted_destination = address(0x4000);
    let copied_request = request(
        copied_source,
        copied_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let promoted_request = request(
        promoted_source,
        promoted_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copied_bytes = vec![1, 2, 3, 4];
    let promoted_bytes = vec![5, 6, 7, 8];
    let forwarding_slots = [
        forwarding_slot(copied_source, copied_destination, HeapGeneration::Young),
        forwarding_slot(promoted_source, promoted_destination, HeapGeneration::Old),
    ];
    let destination_objects = [
        object_bytes(copied_request, copied_bytes.clone()),
        object_bytes(promoted_request, promoted_bytes.clone()),
    ];

    let bindings = boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &forwarding_slots,
        &destination_objects,
    )
    .expect("forwarding destination bindings validate");

    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].source(), copied_source);
    assert_eq!(bindings[0].destination(), copied_destination);
    assert_eq!(bindings[0].generation(), HeapGeneration::Young);
    assert_eq!(
        bindings[0].forwarded_value(),
        heap(copied_destination, HeapGeneration::Young)
    );
    assert_eq!(bindings[0].request(), copied_request);
    assert_eq!(bindings[0].destination_bytes(), copied_bytes);
    assert_eq!(bindings[1].source(), promoted_source);
    assert_eq!(bindings[1].destination(), promoted_destination);
    assert_eq!(bindings[1].generation(), HeapGeneration::Old);
    assert_eq!(
        bindings[1].forwarded_value(),
        heap(promoted_destination, HeapGeneration::Old)
    );
    assert_eq!(bindings[1].request(), promoted_request);
    assert_eq!(bindings[1].destination_bytes(), promoted_bytes);
}

#[test]
fn rejects_destination_snapshot_without_forwarding_value() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

    let err =
        boundary_minor_gc_forwarding_destination_bindings_from_slots(&[], &destination_objects)
            .expect_err("missing forwarding value is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationForwardingMissing {
            source_address: actual_source,
            destination: actual_destination,
        } if actual_source == source && actual_destination == destination
    ));
}

#[test]
fn rejects_forwarding_value_without_destination_snapshot() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let forwarding_slots = [forwarding_slot(source, destination, HeapGeneration::Young)];

    let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(&forwarding_slots, &[])
        .expect_err("forwarding without destination is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingDestinationMissing {
            source_address: actual_source,
        } if actual_source == source
    ));
}

#[test]
fn rejects_duplicate_forwarding_source() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let forwarding_slots = [
        forwarding_slot(source, destination, HeapGeneration::Young),
        forwarding_slot(source, destination, HeapGeneration::Young),
    ];
    let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

    let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &forwarding_slots,
        &destination_objects,
    )
    .expect_err("duplicate forwarding source is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
            index: 1,
            address: source,
        }
    );
}

#[test]
fn rejects_non_heap_forwarding_metadata() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let forwarding_slots = [MinorGcForwardingSlot::with_forwarded_value(
        source,
        ResolvedValueGeneration::Inline,
    )];
    let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

    let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &forwarding_slots,
        &destination_objects,
    )
    .expect_err("non-heap forwarding metadata is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingDestinationNonHeap {
            source_address: actual_source,
            actual: ResolvedValueGeneration::Inline,
        } if actual_source == source
    ));
}

#[test]
fn rejects_forwarding_destination_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let other_destination = address(0x3000);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let forwarding_slots = [forwarding_slot(
        source,
        other_destination,
        HeapGeneration::Young,
    )];
    let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

    let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &forwarding_slots,
        &destination_objects,
    )
    .expect_err("destination mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingDestinationMismatch {
            source_address: actual_source,
            expected,
            actual,
        } if actual_source == source
            && expected == destination
            && actual == other_destination
    ));
}

#[test]
fn rejects_forwarding_generation_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let forwarding_slots = [forwarding_slot(source, destination, HeapGeneration::Old)];
    let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

    let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &forwarding_slots,
        &destination_objects,
    )
    .expect_err("generation mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcForwardingGenerationMismatch {
            source_address: actual_source,
            destination: actual_destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if actual_source == source && actual_destination == destination
    ));
}
