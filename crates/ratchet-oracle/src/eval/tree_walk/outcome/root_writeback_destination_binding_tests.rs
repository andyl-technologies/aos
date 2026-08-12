//! Tests for root-writeback destination-binding derivation.

use std::ptr::NonNull;

use super::*;
use crate::value::{HeapObject, ValueError};

fn address(bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(bits).expect("test address is non-zero")
}

fn root_source(slot: usize) -> EvalRootSource {
    EvalRootSource::ValueStack { slot }
}

fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
    ResolvedValueGeneration::Heap {
        address,
        generation,
    }
}

fn heap_value(tag: ValueTag, address: GcHeapAddress) -> Value {
    Value::heap(
        tag,
        NonNull::new(address.address_bits() as *mut HeapObject)
            .expect("test heap address is non-null"),
    )
    .expect("test heap value is aligned")
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

fn writebacks(
    source: EvalRootSource,
    generation_value: ResolvedValueGeneration,
    typed_value: Value,
) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
        AllocationCollectorPollReferenceWritebackReport::default(),
        vec![AllocationCollectorPollRootWritebackSlot::new(
            source.clone(),
            generation_value,
        )],
        vec![AllocationCollectorPollRootValueWritebackSlot::new(
            source,
            typed_value,
        )],
        Vec::new(),
    );
    let applications =
        EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(Some(application), None);
    let install_report = live_reference_writeback_install_report(&applications);
    EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        install_report,
        applications,
    }
}

fn duplicated_writebacks(
    source: EvalRootSource,
    generation_value: ResolvedValueGeneration,
    typed_value: Value,
) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
        AllocationCollectorPollReferenceWritebackReport::default(),
        vec![
            AllocationCollectorPollRootWritebackSlot::new(source.clone(), generation_value),
            AllocationCollectorPollRootWritebackSlot::new(source.clone(), generation_value),
        ],
        vec![
            AllocationCollectorPollRootValueWritebackSlot::new(source.clone(), typed_value),
            AllocationCollectorPollRootValueWritebackSlot::new(source, typed_value),
        ],
        Vec::new(),
    );
    let applications =
        EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(Some(application), None);
    let install_report = live_reference_writeback_install_report(&applications);
    EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        install_report,
        applications,
    }
}

fn destination_storage(
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
) -> EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    let object_bytes = vec![EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(
        request,
        destination_bytes,
    )];
    let install_report = live_destination_storage_install_report(&object_bytes);
    EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        install_report,
        object_bytes,
    }
}

fn live_writeback_destination_bindings(
    root_writeback_bindings: Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
    let install_report =
        live_writeback_destination_binding_install_report(&root_writeback_bindings, &[]);
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
        install_report,
        root_writeback_bindings,
        heap_field_writeback_bindings: Vec::new(),
        expected_remembered_set: None,
    }
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn matches_typed_root_writeback_to_destination_snapshot() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let destination_bytes = vec![1, 2, 3, 4];
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let destination_storage = destination_storage(request, destination_bytes.clone());

    let bindings =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect("binding report succeeds");

    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(bindings[0].root_source(), &root_source);
    assert_eq!(bindings[0].replacement_tag(), ValueTag::Lambda);
    assert_eq!(bindings[0].destination(), destination);
    assert_eq!(bindings[0].generation(), HeapGeneration::Young);
    assert_eq!(bindings[0].request(), request);
    assert_eq!(bindings[0].destination_bytes(), destination_bytes);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn plans_root_writeback_writes_from_live_bindings() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let destination_bytes = vec![1, 2, 3, 4];
    let replacement_value = heap_value(ValueTag::Lambda, destination);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        replacement_value,
    );
    let destination_storage = destination_storage(request, destination_bytes.clone());
    let bindings =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect("binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(bindings);

    let write_plan = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
        .expect("root writeback write plan validates");

    assert_eq!(write_plan.len(), 1);
    assert_eq!(write_plan.report().roots(), 1);
    assert_eq!(write_plan.report().copied_to_nursery(), 1);
    assert_eq!(write_plan.report().promoted_to_old(), 0);
    assert_eq!(write_plan.report().payload_bytes(), destination_bytes.len());
    assert_eq!(
        write_plan.writes()[0].allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(write_plan.writes()[0].root_source(), &root_source);
    assert_eq!(write_plan.writes()[0].replacement_tag(), ValueTag::Lambda);
    assert!(
        write_plan.writes()[0]
            .replacement_value()
            .raw_eq(replacement_value)
    );
    assert_eq!(write_plan.writes()[0].destination(), destination);
    assert_eq!(write_plan.writes()[0].generation(), HeapGeneration::Young);
    assert_eq!(
        write_plan.writes()[0].replacement_metadata(),
        heap(destination, HeapGeneration::Young)
    );
    assert_eq!(write_plan.writes()[0].request(), request);
    assert_eq!(
        write_plan.writes()[0].destination_bytes(),
        destination_bytes
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn outcome_root_writebacks_reject_duplicate_physical_value_stack_slot() {
    let source = address(0x1000);
    let first_destination = address(0x2000);
    let second_destination = address(0x3000);
    let root_source = root_source(0);
    let first_replacement = heap_value(ValueTag::Lambda, first_destination);
    let second_replacement = heap_value(ValueTag::Lambda, second_destination);
    let plan = EvalGcStressBoundaryMinorGcRootWritebackWritePlan::new(vec![
        EvalGcStressBoundaryMinorGcRootWritebackWrite {
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: root_source.clone(),
            replacement_tag: ValueTag::Lambda,
            replacement_value: first_replacement,
            destination: first_destination,
            generation: HeapGeneration::Young,
            replacement_metadata: heap(first_destination, HeapGeneration::Young),
            request: request(
                source,
                first_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            destination_bytes: vec![1, 2, 3, 4],
        },
        EvalGcStressBoundaryMinorGcRootWritebackWrite {
            allocation_domain: HeapAllocationDomain::PermanentShared,
            root_source: root_source.clone(),
            replacement_tag: ValueTag::Lambda,
            replacement_value: second_replacement,
            destination: second_destination,
            generation: HeapGeneration::Young,
            replacement_metadata: heap(second_destination, HeapGeneration::Young),
            request: request(
                source,
                second_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            destination_bytes: vec![1, 2, 3, 4],
        },
    ]);
    let mut outcome_value = heap_value(ValueTag::Lambda, source);
    let original_value = outcome_value;
    let heap = EvalHeap::new();

    let err = apply_boundary_minor_gc_outcome_root_writebacks(&mut outcome_value, &heap, &plan)
        .expect_err("duplicate physical outcome root is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcOutcomeRootWritebackDuplicateValueStackRoot {
            index: 1,
            root_source: actual_root_source,
        } if actual_root_source == root_source
    ));
    assert!(outcome_value.raw_eq(original_value));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn live_outcome_root_writebacks_reject_source_tag_mismatch_before_body_write() {
    let mut eval_heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: object-copy requests describe record-table worker objects
    // (the Tier-B B2 relocation scaffolding placement).
    eval_heap.use_record_worker_closures_for_gc_scaffolding();
    let source = eval_heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = eval_heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = eval_heap
        .collector_poll_minor_gc_object_byte_copy_request_for_test(
            source,
            destination,
            MinorGcSurvivorAction::CopyToNursery,
        )
        .expect("test object-copy request builds");
    let root_source = root_source(0);
    let mut outcome_value = heap_value(ValueTag::String, request.source());
    let original_value = outcome_value;
    let plan = EvalGcStressBoundaryMinorGcRootWritebackWritePlan::new(vec![
        EvalGcStressBoundaryMinorGcRootWritebackWrite {
            allocation_domain: HeapAllocationDomain::Worker,
            root_source,
            replacement_tag: ValueTag::String,
            replacement_value: heap_value(ValueTag::String, request.destination()),
            destination: request.destination(),
            generation: HeapGeneration::Young,
            replacement_metadata: heap(request.destination(), HeapGeneration::Young),
            request,
            destination_bytes: vec![0; request.size_bytes()],
        },
    ]);
    assert!(matches!(
        eval_heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let err = apply_boundary_minor_gc_live_outcome_root_writebacks(
        &mut outcome_value,
        &mut eval_heap,
        &plan,
    )
    .expect_err("source tag mismatch is rejected before body writes");

    assert!(matches!(
        err,
        EvalHeapError::RecordTypeMismatch {
            expected: ValueTag::String,
            actual: ValueTag::Lambda,
            ..
        }
    ));
    assert!(outcome_value.raw_eq(original_value));
    assert!(matches!(
        eval_heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_root_writeback_write_without_installed_binding() {
    let destination = address(0x2000);
    let root_source = root_source(0);
    let current_writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let live_bindings = EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default();

    let err = boundary_minor_gc_root_writeback_write_plan(&current_writebacks, &live_bindings)
        .expect_err("missing root writeback binding is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackWriteMissingBinding {
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: actual_root_source,
            replacement_tag: ValueTag::Lambda,
            destination: actual_destination,
            generation: HeapGeneration::Young,
        } if actual_root_source == root_source && actual_destination == destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_root_writeback_write_stale_binding() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let stale_destination = address(0x3000);
    let root_source = root_source(0);
    let current_writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let stale_writebacks = writebacks(
        root_source.clone(),
        heap(stale_destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, stale_destination),
    );
    let stale_storage = destination_storage(
        request(
            source,
            stale_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
    );
    let stale_bindings =
        boundary_minor_gc_root_writeback_destination_bindings(&stale_writebacks, &stale_storage)
            .expect("stale binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(stale_bindings);

    let err = boundary_minor_gc_root_writeback_write_plan(&current_writebacks, &live_bindings)
        .expect_err("stale root writeback binding is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackWriteBindingMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: actual_root_source,
            expected_tag: ValueTag::Lambda,
            expected_destination,
            expected_generation: HeapGeneration::Young,
            actual_tag: ValueTag::Lambda,
            actual_destination,
            actual_generation: HeapGeneration::Young,
        } if actual_root_source == root_source
            && expected_destination == destination
            && actual_destination == stale_destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_unbound_root_writeback_binding() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let destination_storage = destination_storage(
        request(source, destination, MinorGcSurvivorAction::CopyToNursery),
        vec![1, 2, 3, 4],
    );
    let bindings =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect("binding report succeeds");
    let live_bindings = live_writeback_destination_bindings(bindings);
    let empty_writebacks = EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default();

    let err = boundary_minor_gc_root_writeback_write_plan(&empty_writebacks, &live_bindings)
        .expect_err("unbound root writeback binding is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackWriteUnboundBinding {
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: actual_root_source,
            replacement_tag: ValueTag::Lambda,
            destination: actual_destination,
            generation: HeapGeneration::Young,
        } if actual_root_source == root_source && actual_destination == destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_duplicate_root_writeback_write_sources() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let writebacks = duplicated_writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let destination_storage = destination_storage(
        request(source, destination, MinorGcSurvivorAction::CopyToNursery),
        vec![1, 2, 3, 4],
    );
    let bindings =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect("duplicate source binding report currently mirrors the slots");
    let live_bindings = live_writeback_destination_bindings(bindings);

    let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("duplicate live root writeback sources are rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateSource {
            index: 1,
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: actual_root_source,
        } if actual_root_source == root_source
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_duplicate_root_writeback_write_bindings() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let destination_storage = destination_storage(
        request(source, destination, MinorGcSurvivorAction::CopyToNursery),
        vec![1, 2, 3, 4],
    );
    let binding =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect("binding report succeeds")[0]
            .clone();
    let live_bindings = live_writeback_destination_bindings(vec![binding.clone(), binding]);

    let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("duplicate root writeback destination bindings are rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateBinding {
            index: 1,
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: actual_root_source,
        } if actual_root_source == root_source
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_root_writeback_binding_request_destination_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let request_destination = address(0x3000);
    let root_source = root_source(0);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let binding = EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
        HeapAllocationDomain::Worker,
        root_source.clone(),
        ValueTag::Lambda,
        destination,
        HeapGeneration::Young,
        request(
            source,
            request_destination,
            MinorGcSurvivorAction::CopyToNursery,
        ),
        vec![1, 2, 3, 4],
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("binding request destination mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackWriteRequestDestinationMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            root_source: actual_root_source,
            binding_destination,
            request_destination: actual_request_destination,
        } if actual_root_source == root_source
            && binding_destination == destination
            && actual_request_destination == request_destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_root_writeback_binding_generation_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let binding = EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
        HeapAllocationDomain::Worker,
        root_source.clone(),
        ValueTag::Lambda,
        destination,
        HeapGeneration::Old,
        request(source, destination, MinorGcSurvivorAction::CopyToNursery),
        vec![1, 2, 3, 4],
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("binding generation/action mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
            root_source: actual_root_source,
            destination: actual_destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if actual_root_source == root_source && actual_destination == destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_root_writeback_binding_payload_size_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let binding = EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
        HeapAllocationDomain::Worker,
        root_source,
        ValueTag::Lambda,
        destination,
        HeapGeneration::Young,
        request(source, destination, MinorGcSurvivorAction::CopyToNursery),
        vec![1, 2, 3],
    );
    let live_bindings = live_writeback_destination_bindings(vec![binding]);

    let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
        .expect_err("binding payload length mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
            destination: actual_destination,
            expected: 4,
            actual: 3,
        } if actual_destination == destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_root_writeback_without_installed_destination_snapshot() {
    let destination = address(0x2000);
    let root_source = root_source(0);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, destination),
    );
    let destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

    let err =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect_err("missing destination snapshot is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackDestinationMissing {
            root_source: actual_root_source,
            destination: actual_destination,
        } if actual_root_source == root_source && actual_destination == destination
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_typed_root_writeback_destination_mismatch() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let sibling_destination = address(0x3000);
    let root_source = root_source(0);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Young),
        heap_value(ValueTag::Lambda, sibling_destination),
    );
    let destination_storage = destination_storage(request, vec![1, 2, 3, 4]);

    let err =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect_err("mismatched typed destination is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackDestinationMismatch {
            root_source: actual_root_source,
            expected_destination,
            actual_tag: ValueTag::Lambda,
            actual_payload,
        } if actual_root_source == root_source
            && expected_destination == destination
            && actual_payload == sibling_destination.address_bits() as u64
    ));
}

#[test]
fn rejects_inline_typed_root_writeback_replacement() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let writebacks = writebacks(
        root_source,
        heap(destination, HeapGeneration::Young),
        Value::int(7),
    );
    let destination_storage = destination_storage(request, vec![1, 2, 3, 4]);

    let err =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect_err("inline typed root replacement is rejected");

    assert!(matches!(
        err,
        EvalHeapError::Value(ValueError::NotHeapTag { tag: ValueTag::Int })
    ));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn rejects_generation_that_disagrees_with_destination_action() {
    let source = address(0x1000);
    let destination = address(0x2000);
    let root_source = root_source(0);
    let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
    let writebacks = writebacks(
        root_source.clone(),
        heap(destination, HeapGeneration::Old),
        heap_value(ValueTag::Lambda, destination),
    );
    let destination_storage = destination_storage(request, vec![1, 2, 3, 4]);

    let err =
        boundary_minor_gc_root_writeback_destination_bindings(&writebacks, &destination_storage)
            .expect_err("generation/action mismatch is rejected");

    assert!(matches!(
        err,
        EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
            root_source: actual_root_source,
            destination: actual_destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        } if actual_root_source == root_source && actual_destination == destination
    ));
}
