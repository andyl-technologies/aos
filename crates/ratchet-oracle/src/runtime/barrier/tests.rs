use std::collections::BTreeSet;

use crate::compile::IrId;
use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};
use crate::eval::heap::{EvalHeap, EvalThunk};
use crate::heap::{GenerationalGcTier, RememberedSet, ThunkResolveWriteBarrier};
use crate::value::Value;

use super::*;

#[test]
fn runtime_write_barrier_symbol_matches_core_helper_inventory() {
    let helper_symbols = runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() == RuntimeHelperRole::WriteBarrier)
        .map(|symbol| symbol.name())
        .collect::<BTreeSet<_>>();
    let entrypoint_symbols = runtime_write_barrier_entrypoints()
        .iter()
        .copied()
        .map(RuntimeWriteBarrierEntryPoint::symbol_name)
        .collect::<BTreeSet<_>>();
    let signature_symbols = runtime_write_barrier_abi_signatures()
        .iter()
        .copied()
        .map(RuntimeWriteBarrierAbiSignature::symbol_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(helper_symbols, BTreeSet::from(["aos_gc_write_barrier"]));
    assert_eq!(entrypoint_symbols, helper_symbols);
    assert_eq!(signature_symbols, helper_symbols);
}

#[test]
fn write_barrier_entrypoint_symbols_round_trip() {
    assert_eq!(
        runtime_write_barrier_entrypoints(),
        [RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier]
    );

    for entrypoint in runtime_write_barrier_entrypoints() {
        assert_eq!(
            RuntimeWriteBarrierEntryPoint::from_symbol_name(entrypoint.symbol_name()),
            Some(*entrypoint)
        );
        assert_eq!(
            RuntimeWriteBarrierAbiSignature::from_symbol_name(entrypoint.symbol_name()),
            Some(entrypoint.abi_signature())
        );
    }
    for symbol in runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() != RuntimeHelperRole::WriteBarrier)
    {
        assert_eq!(
            RuntimeWriteBarrierEntryPoint::from_symbol_name(symbol.name()),
            None,
            "{} is not a write-barrier entry point",
            symbol.name()
        );
        assert_eq!(
            RuntimeWriteBarrierAbiSignature::from_symbol_name(symbol.name()),
            None,
            "{} has no write-barrier ABI signature",
            symbol.name()
        );
    }
}

#[test]
fn write_barrier_abi_signature_pins_runtime_parameters() {
    let signature = RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.abi_signature();

    assert_eq!(
        runtime_write_barrier_abi_signatures(),
        [RuntimeWriteBarrierAbiSignature::new(
            RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier,
            GC_WRITE_BARRIER_PARAMETERS,
            RuntimeWriteBarrierAbiReturnKind::Unit,
        )]
    );
    assert_eq!(
        signature.entrypoint(),
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier
    );
    assert_eq!(signature.symbol_name(), "aos_gc_write_barrier");
    assert_eq!(
        signature.parameters(),
        [
            RuntimeWriteBarrierAbiParameter::new(
                "rt",
                RuntimeWriteBarrierAbiParameterKind::RuntimeContext,
            ),
            RuntimeWriteBarrierAbiParameter::new(
                "thunk",
                RuntimeWriteBarrierAbiParameterKind::ThunkPointer,
            ),
            RuntimeWriteBarrierAbiParameter::new(
                "value",
                RuntimeWriteBarrierAbiParameterKind::Value,
            ),
        ]
        .as_slice()
    );
    assert_eq!(
        signature.return_kind(),
        RuntimeWriteBarrierAbiReturnKind::Unit
    );
}

#[test]
fn write_barrier_rust_callable_bindings_preserve_entrypoint_inventory() {
    let bindings = runtime_write_barrier_rust_callable_bindings();
    let expected = [(
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier,
        RuntimeWriteBarrierRustCallableShape::ThunkResolveConstructor,
        rust_callable_aos_gc_write_barrier as RuntimeThunkResolveWriteBarrierFn as *const (),
    )];

    assert_eq!(bindings.len(), expected.len());
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(RuntimeWriteBarrierRustCallableBinding::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_write_barrier_entrypoints()
    );
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(|binding| (
                binding.entrypoint(),
                binding.shape(),
                binding.address().as_ptr(),
            ))
            .collect::<Vec<_>>()
            .as_slice(),
        expected.as_slice()
    );
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(|binding| binding.entrypoint().abi_signature())
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_write_barrier_abi_signatures()
    );

    for binding in bindings {
        assert_eq!(binding.symbol_name(), binding.entrypoint().symbol_name());
        assert_eq!(binding.entrypoint().rust_callable_binding(), binding);
        assert_eq!(binding.shape(), binding.entrypoint().rust_callable_shape());
        assert_eq!(
            binding.address(),
            binding.entrypoint().rust_callable_address()
        );
        assert!(
            binding.address().is_non_null(),
            "{} has a callable write-barrier address",
            binding.symbol_name()
        );
    }
}

#[test]
fn write_barrier_native_export_preflight_preserves_frozen_abi_and_callable() {
    let preflight = runtime_write_barrier_native_export_preflight();

    assert!(!preflight.is_complete());
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeWriteBarrierNativeExportReadiness::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_write_barrier_entrypoints()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeWriteBarrierNativeExportReadiness::abi_signature)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_write_barrier_abi_signatures()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeWriteBarrierNativeExportReadiness::rust_callable_binding)
            .collect::<Vec<_>>(),
        runtime_write_barrier_rust_callable_bindings()
    );

    let record = preflight
        .readiness_for_symbol("aos_gc_write_barrier")
        .expect("write-barrier export readiness exists");
    assert_eq!(
        record.entrypoint(),
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier
    );
    assert_eq!(record.symbol_name(), "aos_gc_write_barrier");
    assert_eq!(
        record.blockers(),
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier.native_export_blockers()
    );
    assert_eq!(
        record.blockers(),
        [
            RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented,
        ]
        .as_slice()
    );
    assert!(!record.is_export_ready());
    assert!(
        record
            .blockers()
            .contains(&RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper)
    );
    assert!(
        record
            .blockers()
            .contains(&RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented)
    );
    assert!(
        record.blockers().contains(
            &RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented
        )
    );
    assert!(
        record.blockers().contains(
            &RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented
        )
    );
    assert!(
        record
            .blockers()
            .contains(&RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented)
    );
    assert!(
        record
            .blockers()
            .contains(&RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented)
    );
    assert!(
        record
            .blockers()
            .contains(&RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented)
    );
}

#[test]
fn runtime_write_barrier_vtable_selects_every_gc_tier() {
    for tier in [
        GenerationalGcTier::OneShotArena,
        GenerationalGcTier::DaemonGenerational,
    ] {
        let vtable = runtime_write_barrier_vtable(tier);

        assert_eq!(vtable.tier(), tier);
        assert_eq!(vtable.entrypoints(), runtime_write_barrier_entrypoints());
        assert_eq!(
            vtable.abi_signatures(),
            runtime_write_barrier_abi_signatures()
        );
    }
}

#[test]
fn one_shot_write_barrier_vtable_routes_to_disabled_adapter() {
    let heap = EvalHeap::new();
    let mut remembered_set = RememberedSet::new();
    let mut barrier = runtime_thunk_resolve_write_barrier(
        GenerationalGcTier::OneShotArena,
        &heap,
        Value::int(7),
        &mut remembered_set,
    )
    .expect("one-shot barrier creates");

    assert_eq!(barrier.tier(), GenerationalGcTier::OneShotArena);
    assert!(barrier.heap_barrier().is_none());
    barrier
        .before_publish_forced(Value::int(11))
        .expect("disabled barrier allows publish");
    drop(barrier);
    assert!(remembered_set.is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn write_barrier_rust_callable_routes_through_runtime_vtable() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: generational write barriers resolve their source against
    // record generations (Tier-B B2 scaffolding placement).
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    let mut remembered_set = RememberedSet::new();
    let mut barrier = rust_callable_aos_gc_write_barrier(
        &heap,
        GenerationalGcTier::OneShotArena,
        source,
        &mut remembered_set,
        None,
    )
    .expect("one-shot callable barrier creates");

    assert_eq!(barrier.tier(), GenerationalGcTier::OneShotArena);
    assert!(barrier.heap_barrier().is_none());
    barrier
        .before_publish_forced(Value::int(11))
        .expect("disabled barrier allows publish");
    drop(barrier);
    assert!(remembered_set.is_empty());

    let mut card_table = GcCardTable::default();
    let mut barrier = rust_callable_aos_gc_write_barrier(
        &heap,
        GenerationalGcTier::DaemonGenerational,
        source,
        &mut remembered_set,
        Some(&mut card_table),
    )
    .expect("daemon callable barrier creates");

    assert_eq!(barrier.tier(), GenerationalGcTier::DaemonGenerational);
    assert!(
        barrier
            .heap_barrier()
            .and_then(|barrier| barrier.card_table())
            .is_some()
    );
    barrier
        .before_publish_forced(Value::int(11))
        .expect("heap adapter allows inline publish");
    drop(barrier);
    assert!(remembered_set.is_empty());
    assert!(card_table.is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn daemon_write_barrier_vtable_routes_to_heap_adapter() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: generational write barriers resolve their source against
    // record generations (Tier-B B2 scaffolding placement).
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    let mut remembered_set = RememberedSet::new();
    let mut barrier = runtime_thunk_resolve_write_barrier(
        GenerationalGcTier::DaemonGenerational,
        &heap,
        source,
        &mut remembered_set,
    )
    .expect("daemon barrier creates");

    assert_eq!(barrier.tier(), GenerationalGcTier::DaemonGenerational);
    assert!(barrier.heap_barrier().is_some());
    barrier
        .before_publish_forced(Value::int(11))
        .expect("heap adapter allows inline publish");
    assert_eq!(
        barrier
            .heap_barrier()
            .and_then(|barrier| barrier.last_action()),
        Some(ThunkResolveWriteBarrier::NotRequired)
    );
    drop(barrier);
    assert!(remembered_set.is_empty());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn daemon_write_barrier_vtable_can_attach_card_table() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: generational write barriers resolve their source against
    // record generations (Tier-B B2 scaffolding placement).
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();
    let mut barrier = runtime_thunk_resolve_write_barrier_with_card_table(
        GenerationalGcTier::DaemonGenerational,
        &heap,
        source,
        &mut remembered_set,
        &mut card_table,
    )
    .expect("daemon barrier creates");

    let heap_barrier = barrier
        .heap_barrier()
        .expect("daemon barrier uses heap adapter");
    assert!(heap_barrier.card_table().is_some());
    barrier
        .before_publish_forced(Value::int(11))
        .expect("heap adapter allows inline publish");
    drop(barrier);
    assert!(remembered_set.is_empty());
    assert!(card_table.is_empty());
}
