//! Allocator tier, entry-point, request, vtable, and region-mark types,
//! split from [`super`] (RFC-0007 §2 file-size cap).

use super::*;

/// The installed runtime allocation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocatorTier {
    /// One-shot CLI evaluation backed by a never-free bump arena.
    TierAOneShot,
    /// Hash-consed shared values backed by a non-collected permanent arena.
    PermanentShared,
}

/// A centralized allocation entry point that forms an allocation safepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationEntryPoint {
    /// The `aos_alloc_thunk` helper.
    AosAllocThunk,
    /// The `aos_alloc_lambda` helper.
    AosAllocLambda,
    /// The `aos_alloc_attrs` helper.
    AosAllocAttrs,
    /// The `aos_alloc_cons` helper.
    AosAllocCons,
    /// The `aos_alloc_list` helper.
    AosAllocList,
    /// The `aos_alloc_string` helper.
    AosAllocString,
    /// The `aos_alloc_raw` helper.
    AosAllocRaw,
}

/// A safe allocation request for the active runtime allocator.
///
/// The request captures the storage-reservation payload currently needed by the
/// tree-walk heap builders. Some frozen native ABI signatures carry additional
/// semantic payloads, such as thunk code pointers or cons-cell values; those are
/// outside this storage-request surface until native wrapper initialization is
/// implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationRequest {
    /// Allocate a thunk object.
    Thunk,
    /// Allocate a lambda object.
    Lambda,
    /// Allocate an attribute-set object.
    Attrs {
        /// The hidden-class shape identifier for this attrset.
        shape: u32,
        /// The number of value slots reserved in this attrset.
        slots: u32,
    },
    /// Allocate a cons-cell object.
    Cons,
    /// Allocate a contiguous list object.
    List {
        /// The number of elements reserved in this list object.
        len: usize,
    },
    /// Allocate a string or path header object.
    String {
        /// The byte length reserved in this string object.
        len: usize,
    },
    /// Allocate raw heap storage.
    Raw {
        /// The requested payload size in bytes.
        size: usize,
        /// The requested payload alignment in bytes.
        align: usize,
        /// The runtime type tag associated with the raw allocation.
        type_tag: u32,
    },
}

/// Worker allocator position captured for a future lexical region pop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeAllocatorRegionMark {
    arena: ArenaRegionMark,
    safepoints: AllocationSafepointState,
}

impl RuntimeAllocatorRegionMark {
    pub(in crate::runtime::alloc) const fn new(
        arena: ArenaRegionMark,
        safepoints: AllocationSafepointState,
    ) -> Self {
        Self { arena, safepoints }
    }

    /// Returns the raw arena marker captured with this runtime mark.
    pub(crate) const fn arena(self) -> ArenaRegionMark {
        self.arena
    }

    pub(in crate::runtime::alloc) const fn safepoints(self) -> AllocationSafepointState {
        self.safepoints
    }
}

/// Frozen allocation entry points registered by future native runtimes.
pub const RUNTIME_ALLOCATION_ENTRYPOINTS: &[RuntimeAllocationEntryPoint] = &[
    RuntimeAllocationEntryPoint::AosAllocAttrs,
    RuntimeAllocationEntryPoint::AosAllocCons,
    RuntimeAllocationEntryPoint::AosAllocLambda,
    RuntimeAllocationEntryPoint::AosAllocList,
    RuntimeAllocationEntryPoint::AosAllocRaw,
    RuntimeAllocationEntryPoint::AosAllocString,
    RuntimeAllocationEntryPoint::AosAllocThunk,
];

const ALLOC_ATTRS_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("shape", RuntimeAllocationAbiParameterKind::ShapeId),
    RuntimeAllocationAbiParameter::new("slots", RuntimeAllocationAbiParameterKind::U32),
];
const ALLOC_CONS_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("head", RuntimeAllocationAbiParameterKind::Value),
    RuntimeAllocationAbiParameter::new("tail", RuntimeAllocationAbiParameterKind::ListPointer),
];
const ALLOC_LAMBDA_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("code_ptr", RuntimeAllocationAbiParameterKind::CodePointer),
    RuntimeAllocationAbiParameter::new("env", RuntimeAllocationAbiParameterKind::EnvPointer),
];
const ALLOC_LIST_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
];
const ALLOC_RAW_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("size", RuntimeAllocationAbiParameterKind::Usize),
    RuntimeAllocationAbiParameter::new("align", RuntimeAllocationAbiParameterKind::Usize),
    RuntimeAllocationAbiParameter::new("type_tag", RuntimeAllocationAbiParameterKind::TypeTag),
];
const ALLOC_STRING_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
];
const ALLOC_THUNK_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("code_ptr", RuntimeAllocationAbiParameterKind::CodePointer),
    RuntimeAllocationAbiParameter::new("env", RuntimeAllocationAbiParameterKind::EnvPointer),
];

/// Frozen allocation-helper ABI signatures for future native runtimes.
pub const RUNTIME_ALLOCATION_ABI_SIGNATURES: &[RuntimeAllocationAbiSignature] = &[
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocAttrs,
        ALLOC_ATTRS_PARAMETERS,
        RuntimeAllocationAbiReturnKind::AttrsPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocCons,
        ALLOC_CONS_PARAMETERS,
        RuntimeAllocationAbiReturnKind::ListPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocLambda,
        ALLOC_LAMBDA_PARAMETERS,
        RuntimeAllocationAbiReturnKind::LambdaPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocList,
        ALLOC_LIST_PARAMETERS,
        RuntimeAllocationAbiReturnKind::ListPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocRaw,
        ALLOC_RAW_PARAMETERS,
        RuntimeAllocationAbiReturnKind::RawPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocString,
        ALLOC_STRING_PARAMETERS,
        RuntimeAllocationAbiReturnKind::StringHeaderPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocThunk,
        ALLOC_THUNK_PARAMETERS,
        RuntimeAllocationAbiReturnKind::ThunkPointer,
    ),
];

/// Returns allocation helper bindings with callable Rust storage-wrapper addresses.
///
/// The addresses are process-local Rust function addresses for registration
/// preflight metadata. They are not stable across builds or processes, are not
/// exported C symbols, and are not callable with [`RuntimeAllocationAbiSignature`].
pub fn runtime_allocation_rust_callable_bindings() -> Vec<RuntimeAllocationRustCallableBinding> {
    runtime_allocation_entrypoints()
        .iter()
        .copied()
        .map(RuntimeAllocationEntryPoint::rust_callable_binding)
        .collect()
}

/// Returns the frozen allocation entry-point inventory.
pub const fn runtime_allocation_entrypoints() -> &'static [RuntimeAllocationEntryPoint] {
    RUNTIME_ALLOCATION_ENTRYPOINTS
}

/// Returns the frozen allocation-helper ABI signature inventory.
pub const fn runtime_allocation_abi_signatures() -> &'static [RuntimeAllocationAbiSignature] {
    RUNTIME_ALLOCATION_ABI_SIGNATURES
}

/// Builds native-export readiness metadata for frozen allocation helpers.
///
/// The returned report is intentionally negative today: every `aos_alloc_*`
/// symbol has frozen ABI metadata, a storage-only Rust callable, and
/// process-local trap-only runtime-FFI wrapper provenance, but no wrapper is
/// admitted as a final native export. The blocker list is precise so later
/// unsafe wrapper work can clear individual obligations without treating Rust
/// callables as native ABI exports.
pub fn runtime_allocation_native_export_preflight() -> RuntimeAllocationNativeExportPreflight {
    RuntimeAllocationNativeExportPreflight::new(
        runtime_allocation_entrypoints()
            .iter()
            .copied()
            .map(RuntimeAllocationNativeExportReadiness::for_entrypoint)
            .collect(),
    )
}

pub(in crate::runtime::alloc) type RuntimeAllocationAttrsFn =
    fn(&mut RuntimeAllocator, shape: u32, slots: u32) -> Result<ArenaAllocation, ArenaError>;
pub(in crate::runtime::alloc) type RuntimeAllocationConsFn =
    fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>;
pub(in crate::runtime::alloc) type RuntimeAllocationLambdaFn =
    fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>;
pub(in crate::runtime::alloc) type RuntimeAllocationListFn =
    fn(&mut RuntimeAllocator, len: usize) -> Result<ArenaAllocation, ArenaError>;
pub(in crate::runtime::alloc) type RuntimeAllocationRawFn =
    fn(
        &mut RuntimeAllocator,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError>;
pub(in crate::runtime::alloc) type RuntimeAllocationStringFn =
    fn(&mut RuntimeAllocator, len: usize) -> Result<ArenaAllocation, ArenaError>;
pub(in crate::runtime::alloc) type RuntimeAllocationThunkFn =
    fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>;

/// A selected safe allocation dispatch table for one runtime allocator backend.
#[derive(Clone, Copy)]
pub(crate) struct RuntimeAllocationVTable {
    tier: RuntimeAllocatorTier,
    entrypoints: &'static [RuntimeAllocationEntryPoint],
    abi_signatures: &'static [RuntimeAllocationAbiSignature],
    alloc_attrs: RuntimeAllocationAttrsFn,
    alloc_cons: RuntimeAllocationConsFn,
    alloc_lambda: RuntimeAllocationLambdaFn,
    alloc_list: RuntimeAllocationListFn,
    alloc_raw: RuntimeAllocationRawFn,
    alloc_string: RuntimeAllocationStringFn,
    alloc_thunk: RuntimeAllocationThunkFn,
}

impl RuntimeAllocationVTable {
    /// Returns the allocator tier served by this dispatch table.
    pub(crate) const fn tier(&self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry points implemented by this table.
    pub(crate) const fn entrypoints(&self) -> &'static [RuntimeAllocationEntryPoint] {
        self.entrypoints
    }

    /// Returns the frozen ABI signatures implemented by this table.
    pub(crate) const fn abi_signatures(&self) -> &'static [RuntimeAllocationAbiSignature] {
        self.abi_signatures
    }

    /// Allocates through this table using a typed runtime allocation request.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn allocate(
        &self,
        allocator: &mut RuntimeAllocator,
        request: RuntimeAllocationRequest,
    ) -> Result<ArenaAllocation, ArenaError> {
        match request {
            RuntimeAllocationRequest::Thunk => self.aos_alloc_thunk(allocator),
            RuntimeAllocationRequest::Lambda => self.aos_alloc_lambda(allocator),
            RuntimeAllocationRequest::Attrs { shape, slots } => {
                self.aos_alloc_attrs(allocator, shape, slots)
            }
            RuntimeAllocationRequest::Cons => self.aos_alloc_cons(allocator),
            RuntimeAllocationRequest::List { len } => self.aos_alloc_list(allocator, len),
            RuntimeAllocationRequest::String { len } => self.aos_alloc_string(allocator, len),
            RuntimeAllocationRequest::Raw {
                size,
                align,
                type_tag,
            } => self.aos_alloc_raw(allocator, size, align, type_tag),
        }
    }

    /// Allocates an attribute-set heap object through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_attrs(
        &self,
        allocator: &mut RuntimeAllocator,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_attrs)(allocator, shape, slots)
    }

    /// Allocates a cons-cell heap object through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_cons(
        &self,
        allocator: &mut RuntimeAllocator,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_cons)(allocator)
    }

    /// Allocates a lambda-sized heap object through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_lambda(
        &self,
        allocator: &mut RuntimeAllocator,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_lambda)(allocator)
    }

    /// Allocates a contiguous list heap object through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_list(
        &self,
        allocator: &mut RuntimeAllocator,
        len: usize,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_list)(allocator, len)
    }

    /// Allocates raw heap storage through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_raw(
        &self,
        allocator: &mut RuntimeAllocator,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_raw)(allocator, size, align, type_tag)
    }

    /// Allocates a string heap object through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_string(
        &self,
        allocator: &mut RuntimeAllocator,
        len: usize,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_string)(allocator, len)
    }

    /// Allocates a thunk-sized heap object through this table.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the selected allocation strategy cannot reserve
    /// the requested object.
    pub(crate) fn aos_alloc_thunk(
        &self,
        allocator: &mut RuntimeAllocator,
    ) -> Result<ArenaAllocation, ArenaError> {
        (self.alloc_thunk)(allocator)
    }
}

pub(in crate::runtime::alloc) const TIER_A_ONE_SHOT_ALLOCATION_VTABLE: RuntimeAllocationVTable =
    RuntimeAllocationVTable {
        tier: RuntimeAllocatorTier::TierAOneShot,
        entrypoints: RUNTIME_ALLOCATION_ENTRYPOINTS,
        abi_signatures: RUNTIME_ALLOCATION_ABI_SIGNATURES,
        alloc_attrs: tier_a_alloc_attrs,
        alloc_cons: tier_a_alloc_cons,
        alloc_lambda: tier_a_alloc_lambda,
        alloc_list: tier_a_alloc_list,
        alloc_raw: tier_a_alloc_raw,
        alloc_string: tier_a_alloc_string,
        alloc_thunk: tier_a_alloc_thunk,
    };

impl RuntimeAllocationEntryPoint {
    /// Returns the stable runtime symbol name for this allocation entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosAllocThunk => "aos_alloc_thunk",
            Self::AosAllocLambda => "aos_alloc_lambda",
            Self::AosAllocAttrs => "aos_alloc_attrs",
            Self::AosAllocCons => "aos_alloc_cons",
            Self::AosAllocList => "aos_alloc_list",
            Self::AosAllocString => "aos_alloc_string",
            Self::AosAllocRaw => "aos_alloc_raw",
        }
    }

    /// Returns the allocation entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_alloc_thunk" => Some(Self::AosAllocThunk),
            "aos_alloc_lambda" => Some(Self::AosAllocLambda),
            "aos_alloc_attrs" => Some(Self::AosAllocAttrs),
            "aos_alloc_cons" => Some(Self::AosAllocCons),
            "aos_alloc_list" => Some(Self::AosAllocList),
            "aos_alloc_string" => Some(Self::AosAllocString),
            "aos_alloc_raw" => Some(Self::AosAllocRaw),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this allocation entry point.
    pub const fn abi_signature(self) -> RuntimeAllocationAbiSignature {
        match self {
            Self::AosAllocThunk => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_THUNK_PARAMETERS,
                RuntimeAllocationAbiReturnKind::ThunkPointer,
            ),
            Self::AosAllocLambda => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_LAMBDA_PARAMETERS,
                RuntimeAllocationAbiReturnKind::LambdaPointer,
            ),
            Self::AosAllocAttrs => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_ATTRS_PARAMETERS,
                RuntimeAllocationAbiReturnKind::AttrsPointer,
            ),
            Self::AosAllocCons => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_CONS_PARAMETERS,
                RuntimeAllocationAbiReturnKind::ListPointer,
            ),
            Self::AosAllocList => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_LIST_PARAMETERS,
                RuntimeAllocationAbiReturnKind::ListPointer,
            ),
            Self::AosAllocString => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_STRING_PARAMETERS,
                RuntimeAllocationAbiReturnKind::StringHeaderPointer,
            ),
            Self::AosAllocRaw => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_RAW_PARAMETERS,
                RuntimeAllocationAbiReturnKind::RawPointer,
            ),
        }
    }

    /// Returns the callable Rust storage-wrapper binding for this entry point.
    ///
    /// The binding dispatches through [`RuntimeAllocator`], so future caller-side
    /// registration metadata does not bake in the Tier-A arena body directly.
    /// The callable's Rust shape is separate from the frozen native ABI
    /// signature because semantic ABI payload initialization and trap transfer
    /// are not implemented yet.
    pub fn rust_callable_binding(self) -> RuntimeAllocationRustCallableBinding {
        RuntimeAllocationRustCallableBinding::new(
            self,
            self.rust_callable_shape(),
            self.rust_callable_address(),
        )
    }

    /// Returns the Rust storage-wrapper call shape for this entry point.
    pub const fn rust_callable_shape(self) -> RuntimeAllocationRustCallableShape {
        match self {
            Self::AosAllocAttrs => RuntimeAllocationRustCallableShape::AllocatorU32U32,
            Self::AosAllocCons | Self::AosAllocLambda | Self::AosAllocThunk => {
                RuntimeAllocationRustCallableShape::AllocatorOnly
            }
            Self::AosAllocList | Self::AosAllocString => {
                RuntimeAllocationRustCallableShape::AllocatorUsize
            }
            Self::AosAllocRaw => RuntimeAllocationRustCallableShape::AllocatorUsizeUsizeU32,
        }
    }

    /// Returns the process-local Rust storage-wrapper address for this entry point.
    ///
    /// The address is suitable for registration preflight metadata only. It is
    /// not an exported C ABI symbol, is not callable with the frozen native ABI
    /// signature, and must not be persisted.
    pub fn rust_callable_address(self) -> RuntimeAllocationRustCallableAddress {
        let ptr = match self {
            Self::AosAllocThunk => native_aos_alloc_thunk as RuntimeAllocationThunkFn as *const (),
            Self::AosAllocLambda => {
                native_aos_alloc_lambda as RuntimeAllocationLambdaFn as *const ()
            }
            Self::AosAllocAttrs => native_aos_alloc_attrs as RuntimeAllocationAttrsFn as *const (),
            Self::AosAllocCons => native_aos_alloc_cons as RuntimeAllocationConsFn as *const (),
            Self::AosAllocList => native_aos_alloc_list as RuntimeAllocationListFn as *const (),
            Self::AosAllocString => {
                native_aos_alloc_string as RuntimeAllocationStringFn as *const ()
            }
            Self::AosAllocRaw => native_aos_alloc_raw as RuntimeAllocationRawFn as *const (),
        };
        RuntimeAllocationRustCallableAddress::new(ptr)
    }

    /// Returns the current native-export blockers for this allocation helper.
    pub const fn native_export_blockers(self) -> &'static [RuntimeAllocationNativeExportBlocker] {
        match self {
            Self::AosAllocThunk | Self::AosAllocLambda | Self::AosAllocCons => {
                ALLOCATION_SEMANTIC_NATIVE_EXPORT_BLOCKERS
            }
            Self::AosAllocAttrs | Self::AosAllocList | Self::AosAllocString | Self::AosAllocRaw => {
                ALLOCATION_STORAGE_NATIVE_EXPORT_BLOCKERS
            }
        }
    }
}

impl RuntimeAllocationRequest {
    /// Returns the frozen allocation entry point served by this request.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        match self {
            Self::Thunk => RuntimeAllocationEntryPoint::AosAllocThunk,
            Self::Lambda => RuntimeAllocationEntryPoint::AosAllocLambda,
            Self::Attrs { .. } => RuntimeAllocationEntryPoint::AosAllocAttrs,
            Self::Cons => RuntimeAllocationEntryPoint::AosAllocCons,
            Self::List { .. } => RuntimeAllocationEntryPoint::AosAllocList,
            Self::String { .. } => RuntimeAllocationEntryPoint::AosAllocString,
            Self::Raw { .. } => RuntimeAllocationEntryPoint::AosAllocRaw,
        }
    }

    /// Returns the stable runtime symbol name served by this request.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint().symbol_name()
    }
}
