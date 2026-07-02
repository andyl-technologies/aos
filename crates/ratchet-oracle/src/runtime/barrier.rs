//! Runtime write-barrier ABI metadata.
//!
//! The safe tree-walk evaluator routes thunk resolution through direct Rust
//! helpers today. Future native tiers still need one frozen helper symbol for
//! the GC-visible mutation wall: publishing a forced value into a thunk's state
//! slot. This module pins that symbol and its machine-level signature, and also
//! owns the current safe Rust dispatch table that selects the one-shot no-op or
//! heap-backed generational barrier body. It does not export FFI functions or
//! register native symbols.

use crate::eval::heap::{EvalHeap, EvalHeapError, EvalHeapThunkResolveBarrier};
use crate::eval::thunk::{DisabledThunkResolveBarrier, ForceError, ThunkResolveBarrier};
use crate::heap::{GcCardTable, GenerationalGcTier, RememberedSet};
use crate::value::Value;

/// The write-barrier entry point owned by the runtime ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierEntryPoint {
    /// The single GC write barrier used when publishing a forced thunk result.
    AosGcWriteBarrier,
}

/// Frozen write-barrier entry points registered by future native runtimes.
pub const RUNTIME_WRITE_BARRIER_ENTRYPOINTS: &[RuntimeWriteBarrierEntryPoint] =
    &[RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier];

const GC_WRITE_BARRIER_PARAMETERS: &[RuntimeWriteBarrierAbiParameter] = &[
    RuntimeWriteBarrierAbiParameter::new("rt", RuntimeWriteBarrierAbiParameterKind::RuntimeContext),
    RuntimeWriteBarrierAbiParameter::new(
        "thunk",
        RuntimeWriteBarrierAbiParameterKind::ThunkPointer,
    ),
    RuntimeWriteBarrierAbiParameter::new("value", RuntimeWriteBarrierAbiParameterKind::Value),
];

/// Frozen write-barrier ABI signatures for future native runtimes.
pub const RUNTIME_WRITE_BARRIER_ABI_SIGNATURES: &[RuntimeWriteBarrierAbiSignature] =
    &[RuntimeWriteBarrierAbiSignature::new(
        RuntimeWriteBarrierEntryPoint::AosGcWriteBarrier,
        GC_WRITE_BARRIER_PARAMETERS,
        RuntimeWriteBarrierAbiReturnKind::Unit,
    )];

/// Returns the frozen write-barrier entry-point inventory.
pub const fn runtime_write_barrier_entrypoints() -> &'static [RuntimeWriteBarrierEntryPoint] {
    RUNTIME_WRITE_BARRIER_ENTRYPOINTS
}

/// Returns the frozen write-barrier ABI signature inventory.
pub const fn runtime_write_barrier_abi_signatures() -> &'static [RuntimeWriteBarrierAbiSignature] {
    RUNTIME_WRITE_BARRIER_ABI_SIGNATURES
}

type RuntimeThunkResolveWriteBarrierFn =
    for<'a> fn(
        &'a EvalHeap,
        GenerationalGcTier,
        Value,
        &'a mut RememberedSet,
        Option<&'a mut GcCardTable>,
    ) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError>;

/// A selected safe write-barrier dispatch table for one evaluator GC tier.
#[derive(Clone, Copy)]
pub(crate) struct RuntimeWriteBarrierVTable {
    tier: GenerationalGcTier,
    entrypoints: &'static [RuntimeWriteBarrierEntryPoint],
    abi_signatures: &'static [RuntimeWriteBarrierAbiSignature],
    thunk_resolve: RuntimeThunkResolveWriteBarrierFn,
}

impl RuntimeWriteBarrierVTable {
    /// Returns the generational tier served by this dispatch table.
    pub(crate) const fn tier(&self) -> GenerationalGcTier {
        self.tier
    }

    /// Returns the write-barrier entry points implemented by this table.
    pub(crate) const fn entrypoints(&self) -> &'static [RuntimeWriteBarrierEntryPoint] {
        self.entrypoints
    }

    /// Returns the frozen ABI signatures implemented by this table.
    pub(crate) const fn abi_signatures(&self) -> &'static [RuntimeWriteBarrierAbiSignature] {
        self.abi_signatures
    }

    /// Creates the thunk-resolution write barrier selected by this table.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the selected heap-backed barrier cannot be
    /// created for `source_thunk`.
    pub(crate) fn aos_gc_write_barrier<'a>(
        &self,
        heap: &'a EvalHeap,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
        card_table: Option<&'a mut GcCardTable>,
    ) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError> {
        (self.thunk_resolve)(heap, self.tier, source_thunk, remembered_set, card_table)
    }
}

const ONE_SHOT_WRITE_BARRIER_VTABLE: RuntimeWriteBarrierVTable = RuntimeWriteBarrierVTable {
    tier: GenerationalGcTier::OneShotArena,
    entrypoints: RUNTIME_WRITE_BARRIER_ENTRYPOINTS,
    abi_signatures: RUNTIME_WRITE_BARRIER_ABI_SIGNATURES,
    thunk_resolve: one_shot_aos_gc_write_barrier,
};

const DAEMON_GENERATIONAL_WRITE_BARRIER_VTABLE: RuntimeWriteBarrierVTable =
    RuntimeWriteBarrierVTable {
        tier: GenerationalGcTier::DaemonGenerational,
        entrypoints: RUNTIME_WRITE_BARRIER_ENTRYPOINTS,
        abi_signatures: RUNTIME_WRITE_BARRIER_ABI_SIGNATURES,
        thunk_resolve: daemon_generational_aos_gc_write_barrier,
    };

/// Returns the safe write-barrier dispatch table for a generational GC tier.
pub(crate) fn runtime_write_barrier_vtable(
    tier: GenerationalGcTier,
) -> &'static RuntimeWriteBarrierVTable {
    let vtable = match tier {
        GenerationalGcTier::OneShotArena => &ONE_SHOT_WRITE_BARRIER_VTABLE,
        GenerationalGcTier::DaemonGenerational => &DAEMON_GENERATIONAL_WRITE_BARRIER_VTABLE,
    };
    debug_assert_eq!(vtable.tier(), tier);
    debug_assert_eq!(vtable.entrypoints(), runtime_write_barrier_entrypoints());
    debug_assert_eq!(
        vtable.abi_signatures(),
        runtime_write_barrier_abi_signatures()
    );
    vtable
}

/// Creates the safe runtime thunk-resolution barrier for the selected GC tier.
///
/// # Errors
///
/// Returns [`EvalHeapError`] if the selected heap-backed barrier cannot be
/// created for `source_thunk`.
pub(crate) fn runtime_thunk_resolve_write_barrier<'a>(
    tier: GenerationalGcTier,
    heap: &'a EvalHeap,
    source_thunk: Value,
    remembered_set: &'a mut RememberedSet,
) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError> {
    runtime_write_barrier_vtable(tier).aos_gc_write_barrier(
        heap,
        source_thunk,
        remembered_set,
        None,
    )
}

/// Creates the safe runtime thunk-resolution barrier with a mutable card table.
///
/// # Errors
///
/// Returns [`EvalHeapError`] if the selected heap-backed barrier cannot be
/// created for `source_thunk`.
pub(crate) fn runtime_thunk_resolve_write_barrier_with_card_table<'a>(
    tier: GenerationalGcTier,
    heap: &'a EvalHeap,
    source_thunk: Value,
    remembered_set: &'a mut RememberedSet,
    card_table: &'a mut GcCardTable,
) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError> {
    runtime_write_barrier_vtable(tier).aos_gc_write_barrier(
        heap,
        source_thunk,
        remembered_set,
        Some(card_table),
    )
}

/// The active safe thunk-resolution barrier selected by runtime dispatch.
#[derive(Debug)]
pub(crate) enum RuntimeThunkResolveBarrier<'a> {
    /// The one-shot arena tier does not maintain a remembered set.
    Disabled(DisabledThunkResolveBarrier),
    /// The daemon generational tier records heap-backed remembered edges.
    Heap(EvalHeapThunkResolveBarrier<'a>),
}

#[cfg(test)]
impl RuntimeThunkResolveBarrier<'_> {
    /// Returns the generational tier served by this active barrier.
    pub(crate) fn tier(&self) -> GenerationalGcTier {
        match self {
            Self::Disabled(_) => GenerationalGcTier::OneShotArena,
            Self::Heap(barrier) => barrier.tier(),
        }
    }

    /// Returns the heap-backed barrier when the daemon tier is active.
    pub(crate) fn heap_barrier(&self) -> Option<&EvalHeapThunkResolveBarrier<'_>> {
        match self {
            Self::Disabled(_) => None,
            Self::Heap(barrier) => Some(barrier),
        }
    }
}

impl ThunkResolveBarrier for RuntimeThunkResolveBarrier<'_> {
    fn before_publish_forced(&mut self, value: Value) -> Result<(), ForceError> {
        match self {
            Self::Disabled(barrier) => barrier.before_publish_forced(value),
            Self::Heap(barrier) => barrier.before_publish_forced(value),
        }
    }
}

fn one_shot_aos_gc_write_barrier<'a>(
    _heap: &'a EvalHeap,
    tier: GenerationalGcTier,
    _source_thunk: Value,
    _remembered_set: &'a mut RememberedSet,
    _card_table: Option<&'a mut GcCardTable>,
) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError> {
    debug_assert_eq!(tier, GenerationalGcTier::OneShotArena);
    Ok(RuntimeThunkResolveBarrier::Disabled(
        DisabledThunkResolveBarrier,
    ))
}

fn daemon_generational_aos_gc_write_barrier<'a>(
    heap: &'a EvalHeap,
    tier: GenerationalGcTier,
    source_thunk: Value,
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError> {
    debug_assert_eq!(tier, GenerationalGcTier::DaemonGenerational);
    match card_table {
        Some(card_table) => heap.thunk_resolve_write_barrier_with_card_table(
            tier,
            source_thunk,
            remembered_set,
            card_table,
        ),
        None => heap.thunk_resolve_write_barrier(tier, source_thunk, remembered_set),
    }
    .map(RuntimeThunkResolveBarrier::Heap)
}

impl RuntimeWriteBarrierEntryPoint {
    /// Returns the stable runtime symbol name for this write-barrier entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosGcWriteBarrier => "aos_gc_write_barrier",
        }
    }

    /// Returns the write-barrier entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_gc_write_barrier" => Some(Self::AosGcWriteBarrier),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this write-barrier entry point.
    pub const fn abi_signature(self) -> RuntimeWriteBarrierAbiSignature {
        match self {
            Self::AosGcWriteBarrier => RuntimeWriteBarrierAbiSignature::new(
                self,
                GC_WRITE_BARRIER_PARAMETERS,
                RuntimeWriteBarrierAbiReturnKind::Unit,
            ),
        }
    }
}

/// A frozen write-barrier ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierAbiSignature {
    entrypoint: RuntimeWriteBarrierEntryPoint,
    parameters: &'static [RuntimeWriteBarrierAbiParameter],
    return_kind: RuntimeWriteBarrierAbiReturnKind,
}

impl RuntimeWriteBarrierAbiSignature {
    const fn new(
        entrypoint: RuntimeWriteBarrierEntryPoint,
        parameters: &'static [RuntimeWriteBarrierAbiParameter],
        return_kind: RuntimeWriteBarrierAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the write-barrier ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeWriteBarrierEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeWriteBarrierEntryPoint::abi_signature)
    }

    /// Returns the write-barrier entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeWriteBarrierEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeWriteBarrierAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeWriteBarrierAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen write-barrier ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierAbiParameter {
    name: &'static str,
    kind: RuntimeWriteBarrierAbiParameterKind,
}

impl RuntimeWriteBarrierAbiParameter {
    const fn new(name: &'static str, kind: RuntimeWriteBarrierAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeWriteBarrierAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by write-barrier symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierAbiParameterKind {
    /// The evaluator runtime context that owns the installed heap strategy.
    RuntimeContext,
    /// A pointer to the claimed source thunk whose forced-result slot is updated.
    ThunkPointer,
    /// A by-value runtime value word pair being published.
    Value,
}

/// The success-path machine-level result kind returned by write-barrier symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierAbiReturnKind {
    /// The write barrier returns no value on success.
    Unit,
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn daemon_write_barrier_vtable_routes_to_heap_adapter() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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

    #[test]
    fn daemon_write_barrier_vtable_can_attach_card_table() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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
}
