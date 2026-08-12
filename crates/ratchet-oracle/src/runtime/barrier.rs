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

/// Returns write-barrier helper bindings with callable Rust storage-wrapper addresses.
///
/// The addresses are process-local Rust function addresses for registration
/// preflight metadata. They are not stable across builds or processes, are not
/// exported C symbols, and are not callable with [`RuntimeWriteBarrierAbiSignature`].
pub fn runtime_write_barrier_rust_callable_bindings() -> Vec<RuntimeWriteBarrierRustCallableBinding>
{
    runtime_write_barrier_entrypoints()
        .iter()
        .copied()
        .map(RuntimeWriteBarrierEntryPoint::rust_callable_binding)
        .collect()
}

/// Builds native-export readiness metadata for frozen write-barrier helpers.
pub fn runtime_write_barrier_native_export_preflight() -> RuntimeWriteBarrierNativeExportPreflight {
    RuntimeWriteBarrierNativeExportPreflight::new(
        runtime_write_barrier_entrypoints()
            .iter()
            .copied()
            .map(RuntimeWriteBarrierNativeExportReadiness::for_entrypoint)
            .collect(),
    )
}

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

fn rust_callable_aos_gc_write_barrier<'a>(
    heap: &'a EvalHeap,
    tier: GenerationalGcTier,
    source_thunk: Value,
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
) -> Result<RuntimeThunkResolveBarrier<'a>, EvalHeapError> {
    runtime_write_barrier_vtable(tier).aos_gc_write_barrier(
        heap,
        source_thunk,
        remembered_set,
        card_table,
    )
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

    /// Returns the callable Rust storage-wrapper binding for this entry point.
    ///
    /// The callable's Rust shape is separate from the frozen native ABI
    /// signature because runtime-context extraction, GC-state extraction,
    /// thunk-pointer decoding, value decoding, safe before-publish dispatch, and
    /// trap transfer are not implemented yet.
    pub fn rust_callable_binding(self) -> RuntimeWriteBarrierRustCallableBinding {
        RuntimeWriteBarrierRustCallableBinding::new(
            self,
            self.rust_callable_shape(),
            self.rust_callable_address(),
        )
    }

    /// Returns the Rust storage-wrapper call shape for this entry point.
    pub const fn rust_callable_shape(self) -> RuntimeWriteBarrierRustCallableShape {
        match self {
            Self::AosGcWriteBarrier => {
                RuntimeWriteBarrierRustCallableShape::ThunkResolveConstructor
            }
        }
    }

    /// Returns the process-local Rust storage-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeWriteBarrierRustCallableAddress {
        let ptr = match self {
            Self::AosGcWriteBarrier => {
                rust_callable_aos_gc_write_barrier as RuntimeThunkResolveWriteBarrierFn as *const ()
            }
        };
        RuntimeWriteBarrierRustCallableAddress::new(ptr)
    }

    /// Returns the current native-export blockers for this write-barrier helper.
    pub const fn native_export_blockers(self) -> &'static [RuntimeWriteBarrierNativeExportBlocker] {
        match self {
            Self::AosGcWriteBarrier => WRITE_BARRIER_NATIVE_EXPORT_BLOCKERS,
        }
    }
}

/// The Rust function shape behind a callable write-barrier storage wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierRustCallableShape {
    /// A thunk-resolution barrier constructor selected by explicit GC tier.
    ThunkResolveConstructor,
}

/// A process-local callable Rust write-barrier storage-wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used as
/// registration metadata for later native startup binding and is intentionally
/// not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierRustCallableAddress {
    ptr: *const (),
}

impl RuntimeWriteBarrierRustCallableAddress {
    const fn new(ptr: *const ()) -> Self {
        Self { ptr }
    }

    /// Returns the process-local function pointer.
    pub const fn as_ptr(self) -> *const () {
        self.ptr
    }

    /// Returns true when the address pointer is non-null.
    pub const fn is_non_null(self) -> bool {
        !self.ptr.is_null()
    }
}

/// A callable Rust storage-wrapper binding for the frozen write-barrier helper.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeWriteBarrierAbiSignature`] because this Rust callable constructs a
/// thunk-resolution barrier adapter while the frozen native ABI will eventually
/// publish a forced value through a runtime context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierRustCallableBinding {
    entrypoint: RuntimeWriteBarrierEntryPoint,
    shape: RuntimeWriteBarrierRustCallableShape,
    address: RuntimeWriteBarrierRustCallableAddress,
}

impl RuntimeWriteBarrierRustCallableBinding {
    const fn new(
        entrypoint: RuntimeWriteBarrierEntryPoint,
        shape: RuntimeWriteBarrierRustCallableShape,
        address: RuntimeWriteBarrierRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the write-barrier entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeWriteBarrierEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeWriteBarrierRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeWriteBarrierRustCallableAddress {
        self.address
    }
}

/// A missing piece before the safe write-barrier helper can become a native ABI export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeWriteBarrierNativeExportBlocker {
    /// No final exported C ABI wrapper is admitted for the frozen helper name.
    MissingFinalExportedWrapper,
    /// Native wrappers cannot yet decode the runtime context pointer.
    RuntimeContextAbiUnimplemented,
    /// Native wrappers cannot yet extract heap, remembered-set, and card-table state.
    RuntimeGcStateExtractionUnimplemented,
    /// Native wrappers cannot yet decode the source thunk pointer.
    NativeThunkPointerDecodeUnimplemented,
    /// Native wrappers cannot yet decode the by-value runtime value payload.
    NativeValueDecodeUnimplemented,
    /// Helper failures cannot yet transfer into evaluator trap/error machinery.
    TrapTransferUnimplemented,
    /// The frozen ABI does not yet invoke the safe before-publish barrier path.
    BarrierDispatchUnimplemented,
}

const WRITE_BARRIER_NATIVE_EXPORT_BLOCKERS: &[RuntimeWriteBarrierNativeExportBlocker] = &[
    RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented,
];

/// Native-export readiness for one frozen write-barrier helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierNativeExportReadiness {
    entrypoint: RuntimeWriteBarrierEntryPoint,
    abi_signature: RuntimeWriteBarrierAbiSignature,
    rust_callable_binding: RuntimeWriteBarrierRustCallableBinding,
    blockers: &'static [RuntimeWriteBarrierNativeExportBlocker],
}

impl RuntimeWriteBarrierNativeExportReadiness {
    fn for_entrypoint(entrypoint: RuntimeWriteBarrierEntryPoint) -> Self {
        Self {
            entrypoint,
            abi_signature: entrypoint.abi_signature(),
            rust_callable_binding: entrypoint.rust_callable_binding(),
            blockers: entrypoint.native_export_blockers(),
        }
    }

    /// Returns the write-barrier entry point served by this readiness record.
    pub const fn entrypoint(&self) -> RuntimeWriteBarrierEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this readiness record.
    pub const fn symbol_name(&self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen native ABI signature for this write-barrier helper.
    pub const fn abi_signature(&self) -> RuntimeWriteBarrierAbiSignature {
        self.abi_signature
    }

    /// Returns the current Rust callable binding.
    pub const fn rust_callable_binding(&self) -> RuntimeWriteBarrierRustCallableBinding {
        self.rust_callable_binding
    }

    /// Returns the current blockers before this helper can be a native ABI export.
    pub const fn blockers(&self) -> &'static [RuntimeWriteBarrierNativeExportBlocker] {
        self.blockers
    }

    /// Returns true when this helper has exported native ABI metadata.
    pub const fn is_export_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Native-export readiness report for frozen write-barrier helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeWriteBarrierNativeExportPreflight {
    readiness: Vec<RuntimeWriteBarrierNativeExportReadiness>,
}

impl RuntimeWriteBarrierNativeExportPreflight {
    fn new(readiness: Vec<RuntimeWriteBarrierNativeExportReadiness>) -> Self {
        Self { readiness }
    }

    /// Returns write-barrier native-export readiness in runtime entry-point order.
    pub fn readiness(&self) -> &[RuntimeWriteBarrierNativeExportReadiness] {
        &self.readiness
    }

    /// Returns true when every write-barrier helper has native ABI export metadata.
    pub fn is_complete(&self) -> bool {
        self.readiness.iter().all(|record| record.is_export_ready())
    }

    /// Returns the readiness record for `symbol_name`, when present.
    pub fn readiness_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeWriteBarrierNativeExportReadiness> {
        self.readiness
            .iter()
            .find(|record| record.symbol_name() == symbol_name)
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
mod tests;
