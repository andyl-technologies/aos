//! Tests for merging live remembered-set applications at the minor-GC boundary.

use super::*;
use crate::heap::HeapGeneration;

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is non-zero")
}

fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
    ResolvedValueGeneration::Heap {
        address,
        generation,
    }
}

#[test]
fn rejects_distinct_sources_with_same_destination_address() {
    let source = address(0x1000);
    let sibling_source = address(0x2000);
    let destination = address(0x3000);
    let mut relocations = Vec::new();
    let worker_slots = [MinorGcForwardingSlot::with_forwarded_value(
        source,
        heap(destination, HeapGeneration::Young),
    )];
    validate_boundary_minor_gc_relocations_match(&mut relocations, &worker_slots)
        .expect("first relocation is accepted");

    let permanent_slots = [MinorGcForwardingSlot::with_forwarded_value(
        sibling_source,
        heap(destination, HeapGeneration::Old),
    )];
    let err = validate_boundary_minor_gc_relocations_match(&mut relocations, &permanent_slots)
        .expect_err("same destination address is rejected");
    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationCollision {
            source_address,
            existing_source_address,
            destination: ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Old,
            },
        } if source_address == sibling_source
            && existing_source_address == source
            && address == destination
    ));
}

#[test]
fn rejects_previous_destination_as_later_source() {
    let source = address(0x1000);
    let middle = address(0x2000);
    let destination = address(0x3000);
    let mut relocations = Vec::new();
    let worker_slots = [MinorGcForwardingSlot::with_forwarded_value(
        source,
        heap(middle, HeapGeneration::Young),
    )];
    validate_boundary_minor_gc_relocations_match(&mut relocations, &worker_slots)
        .expect("first relocation is accepted");

    let permanent_slots = [MinorGcForwardingSlot::with_forwarded_value(
        middle,
        heap(destination, HeapGeneration::Old),
    )];
    let err = validate_boundary_minor_gc_relocations_match(&mut relocations, &permanent_slots)
        .expect_err("previous destination cannot become a later source");
    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
            source_address,
            destination: ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            },
        } if source_address == middle && address == middle
    ));
}
