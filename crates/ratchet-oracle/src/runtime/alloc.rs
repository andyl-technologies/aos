//! Runtime allocation strategy dispatch for evaluator heap objects.
//!
//! The tree-walk oracle allocates through this layer instead of naming a heap
//! backend directly. Today the default worker strategy is the Tier-A one-shot
//! bump arena, an opt-in Tier-A backend can route through the current thread's
//! arena, and a separate permanent-shared bump arena stores hash-consed values.
//! Later Phase-3 work can install the precise generational collector behind the
//! same worker `aos_alloc_*` entry-point surface. A
//! [`RuntimeAllocationRequest`] provides the current safe Rust call boundary
//! that native wrappers can eventually lower into the same dispatch table.

use std::{
    collections::HashMap,
    mem,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, ThreadId},
};

use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionMark, ArenaRegionPopReport,
    ArenaStats, BumpArena, HeapObjectKind, ThreadLocalBumpArena,
};
use crate::heap::{HeapMemoryBudget, HeapMemoryBudgetResponse, HeapMemorySample, MemoryAdviceKind};

static NEXT_THREAD_LOCAL_RUNTIME_ALLOCATOR_TOKEN: AtomicU64 = AtomicU64::new(1);
static THREAD_LOCAL_RUNTIME_ALLOCATOR_OWNERS: LazyLock<Mutex<HashMap<ThreadId, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn with_thread_local_runtime_allocator_owners<R>(
    f: impl FnOnce(&mut HashMap<ThreadId, u64>) -> R,
) -> R {
    let owners = THREAD_LOCAL_RUNTIME_ALLOCATOR_OWNERS.lock();
    let mut owners = match owners {
        Ok(owners) => owners,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut owners)
}

fn reserve_thread_local_runtime_allocator(owner: ThreadId) -> u64 {
    let token = match NEXT_THREAD_LOCAL_RUNTIME_ALLOCATOR_TOKEN.fetch_update(
        Ordering::Relaxed,
        Ordering::Relaxed,
        |token| token.checked_add(1),
    ) {
        Ok(token) => token,
        Err(_) => panic!("thread-local runtime allocator token space exhausted"),
    };
    with_thread_local_runtime_allocator_owners(|owners| {
        assert!(
            !owners.contains_key(&owner),
            "thread already has an active thread-local runtime allocator"
        );
        owners.insert(owner, token);
    });
    token
}

fn release_thread_local_runtime_allocator(owner: ThreadId, token: u64) {
    with_thread_local_runtime_allocator_owners(|owners| {
        if owners.get(&owner).copied() == Some(token) {
            owners.remove(&owner);
        }
    });
}

fn assert_thread_local_runtime_allocator_owner(owner: ThreadId, token: u64) {
    assert_eq!(
        thread::current().id(),
        owner,
        "thread-local runtime allocator used from a different thread"
    );
    with_thread_local_runtime_allocator_owners(|owners| {
        assert_eq!(
            owners.get(&owner).copied(),
            Some(token),
            "thread-local runtime allocator is no longer active for this thread"
        );
    });
}

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
    const fn new(arena: ArenaRegionMark, safepoints: AllocationSafepointState) -> Self {
        Self { arena, safepoints }
    }

    /// Returns the raw arena marker captured with this runtime mark.
    pub(crate) const fn arena(self) -> ArenaRegionMark {
        self.arena
    }

    const fn safepoints(self) -> AllocationSafepointState {
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

type RuntimeAllocationAttrsFn =
    fn(&mut RuntimeAllocator, shape: u32, slots: u32) -> Result<ArenaAllocation, ArenaError>;
type RuntimeAllocationConsFn = fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>;
type RuntimeAllocationLambdaFn = fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>;
type RuntimeAllocationListFn =
    fn(&mut RuntimeAllocator, len: usize) -> Result<ArenaAllocation, ArenaError>;
type RuntimeAllocationRawFn = fn(
    &mut RuntimeAllocator,
    size: usize,
    align: usize,
    type_tag: u32,
) -> Result<ArenaAllocation, ArenaError>;
type RuntimeAllocationStringFn =
    fn(&mut RuntimeAllocator, len: usize) -> Result<ArenaAllocation, ArenaError>;
type RuntimeAllocationThunkFn = fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>;

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

const TIER_A_ONE_SHOT_ALLOCATION_VTABLE: RuntimeAllocationVTable = RuntimeAllocationVTable {
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

/// The Rust function shape behind a callable allocation storage wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationRustCallableShape {
    /// `fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorOnly,
    /// `fn(&mut RuntimeAllocator, u32, u32) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorU32U32,
    /// `fn(&mut RuntimeAllocator, usize) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorUsize,
    /// `fn(&mut RuntimeAllocator, usize, usize, u32) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorUsizeUsizeU32,
}

/// A process-local callable Rust storage-wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used as
/// registration metadata for later native startup binding and is intentionally
/// not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationRustCallableAddress {
    ptr: *const (),
}

impl RuntimeAllocationRustCallableAddress {
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

/// A callable Rust storage-wrapper binding for one allocation helper entry point.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeAllocationAbiSignature`] because these Rust callables return
/// [`ArenaAllocation`] through [`Result`] and some shapes omit semantic native
/// payloads that the frozen ABI will eventually initialize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationRustCallableBinding {
    entrypoint: RuntimeAllocationEntryPoint,
    shape: RuntimeAllocationRustCallableShape,
    address: RuntimeAllocationRustCallableAddress,
}

impl RuntimeAllocationRustCallableBinding {
    const fn new(
        entrypoint: RuntimeAllocationEntryPoint,
        shape: RuntimeAllocationRustCallableShape,
        address: RuntimeAllocationRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the allocation entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeAllocationRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeAllocationRustCallableAddress {
        self.address
    }
}

/// A missing piece before a storage-only allocation helper can become a native ABI export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationNativeExportBlocker {
    /// No final exported C ABI wrapper is admitted for the frozen helper name.
    MissingFinalExportedWrapper,
    /// Native wrappers cannot yet decode the runtime context pointer.
    RuntimeContextAbiUnimplemented,
    /// Helper failures cannot yet transfer into evaluator trap/error machinery.
    TrapTransferUnimplemented,
    /// Pointer-shaped ABI returns are not yet materialized as typed heap objects.
    TypedPointerReturnUnmaterialized,
    /// The frozen ABI's semantic payloads are not initialized by the storage wrapper.
    SemanticPayloadInitializationUnimplemented,
}

const ALLOCATION_STORAGE_NATIVE_EXPORT_BLOCKERS: &[RuntimeAllocationNativeExportBlocker] = &[
    RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
];

const ALLOCATION_SEMANTIC_NATIVE_EXPORT_BLOCKERS: &[RuntimeAllocationNativeExportBlocker] = &[
    RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
    RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented,
];

/// Native-export readiness for one frozen allocation helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationNativeExportReadiness {
    entrypoint: RuntimeAllocationEntryPoint,
    abi_signature: RuntimeAllocationAbiSignature,
    rust_callable_binding: RuntimeAllocationRustCallableBinding,
    blockers: &'static [RuntimeAllocationNativeExportBlocker],
}

impl RuntimeAllocationNativeExportReadiness {
    fn for_entrypoint(entrypoint: RuntimeAllocationEntryPoint) -> Self {
        Self {
            entrypoint,
            abi_signature: entrypoint.abi_signature(),
            rust_callable_binding: entrypoint.rust_callable_binding(),
            blockers: entrypoint.native_export_blockers(),
        }
    }

    /// Returns the allocation entry point served by this readiness record.
    pub const fn entrypoint(&self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this readiness record.
    pub const fn symbol_name(&self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen native ABI signature for this allocation helper.
    pub const fn abi_signature(&self) -> RuntimeAllocationAbiSignature {
        self.abi_signature
    }

    /// Returns the current storage-only Rust callable binding.
    pub const fn rust_callable_binding(&self) -> RuntimeAllocationRustCallableBinding {
        self.rust_callable_binding
    }

    /// Returns the current blockers before this helper can be a native ABI export.
    pub const fn blockers(&self) -> &'static [RuntimeAllocationNativeExportBlocker] {
        self.blockers
    }

    /// Returns true when this helper has exported native ABI metadata.
    pub const fn is_export_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Native-export readiness report for frozen allocation helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationNativeExportPreflight {
    readiness: Vec<RuntimeAllocationNativeExportReadiness>,
}

impl RuntimeAllocationNativeExportPreflight {
    fn new(readiness: Vec<RuntimeAllocationNativeExportReadiness>) -> Self {
        Self { readiness }
    }

    /// Returns allocation native-export readiness in runtime entry-point order.
    pub fn readiness(&self) -> &[RuntimeAllocationNativeExportReadiness] {
        &self.readiness
    }

    /// Returns true when every allocation helper has native ABI export metadata.
    pub fn is_complete(&self) -> bool {
        self.readiness.iter().all(|record| record.is_export_ready())
    }

    /// Returns the readiness record for `symbol_name`, when present.
    pub fn readiness_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeAllocationNativeExportReadiness> {
        self.readiness
            .iter()
            .find(|record| record.symbol_name() == symbol_name)
    }
}

/// A frozen allocation-helper ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationAbiSignature {
    entrypoint: RuntimeAllocationEntryPoint,
    parameters: &'static [RuntimeAllocationAbiParameter],
    return_kind: RuntimeAllocationAbiReturnKind,
}

impl RuntimeAllocationAbiSignature {
    const fn new(
        entrypoint: RuntimeAllocationEntryPoint,
        parameters: &'static [RuntimeAllocationAbiParameter],
        return_kind: RuntimeAllocationAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the allocation ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeAllocationEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeAllocationEntryPoint::abi_signature)
    }

    /// Returns the allocation entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeAllocationAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeAllocationAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen allocation-helper ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationAbiParameter {
    name: &'static str,
    kind: RuntimeAllocationAbiParameterKind,
}

impl RuntimeAllocationAbiParameter {
    const fn new(name: &'static str, kind: RuntimeAllocationAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeAllocationAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by allocation-helper symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationAbiParameterKind {
    /// The evaluator runtime context that owns the installed allocator strategy.
    RuntimeContext,
    /// A pointer to native code for a thunk or lambda body.
    CodePointer,
    /// A pointer to a captured environment frame.
    EnvPointer,
    /// A by-value runtime value word pair.
    Value,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A hidden-class shape identifier.
    ShapeId,
    /// A target-pointer-sized unsigned integer.
    Usize,
    /// A runtime-specific raw allocation type tag.
    TypeTag,
    /// A 32-bit unsigned integer.
    U32,
}

/// The success-path machine-level result kind returned by allocation-helper symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationAbiReturnKind {
    /// A pointer to a thunk object.
    ThunkPointer,
    /// A pointer to a lambda closure object.
    LambdaPointer,
    /// A pointer to an attrset object.
    AttrsPointer,
    /// A pointer to a list object.
    ListPointer,
    /// A pointer to a string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
}

/// GC-stress polling policy evaluated at allocation safepoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcStressPolicy {
    mode: GcStressPolicyMode,
}

impl Default for GcStressPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl GcStressPolicy {
    /// Creates a policy that never requests a GC-stress collector poll.
    pub const fn disabled() -> Self {
        Self {
            mode: GcStressPolicyMode::Disabled,
        }
    }

    /// Creates a policy that requests a GC-stress collector poll at every
    /// allocation safepoint.
    pub const fn every_safepoint() -> Self {
        Self {
            mode: GcStressPolicyMode::EverySafepoint,
        }
    }

    /// Creates a policy that requests a GC-stress collector poll every `period`
    /// allocation safepoints.
    ///
    /// The cadence is evaluated against the allocator's lifetime safepoint
    /// sequence, not the policy-installation epoch.
    ///
    /// # Errors
    ///
    /// Returns [`GcStressPolicyError::ZeroPeriod`] when `period` is zero.
    pub const fn every_n_safepoints(period: u64) -> Result<Self, GcStressPolicyError> {
        if period == 0 {
            return Err(GcStressPolicyError::ZeroPeriod);
        }
        Ok(Self {
            mode: GcStressPolicyMode::EveryNSafepoints { period },
        })
    }

    /// Returns whether this policy never requests a GC-stress collector poll.
    pub const fn is_disabled(self) -> bool {
        matches!(self.mode, GcStressPolicyMode::Disabled)
    }

    const fn poll_reason_for(self, sequence: u64) -> Option<AllocationGcPollReason> {
        match self.mode {
            GcStressPolicyMode::Disabled => None,
            _ if sequence == u64::MAX => Some(AllocationGcPollReason::GcStressSequenceSaturated),
            GcStressPolicyMode::EverySafepoint => {
                Some(AllocationGcPollReason::GcStressEverySafepoint)
            }
            GcStressPolicyMode::EveryNSafepoints { period } => {
                if sequence % period == 0 {
                    Some(AllocationGcPollReason::GcStressEveryNSafepoints { period })
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcStressPolicyMode {
    Disabled,
    EverySafepoint,
    EveryNSafepoints { period: u64 },
}

/// A GC-stress policy configuration failure.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GcStressPolicyError {
    /// Periodic GC-stress polling needs a non-zero period.
    #[error("GC-stress safepoint period cannot be zero")]
    ZeroPeriod,
}

/// The reason an allocation safepoint requested a collector poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationGcPollReason {
    /// GC-stress mode requested a collector poll at every safepoint.
    GcStressEverySafepoint,
    /// GC-stress mode requested a collector poll at a periodic safepoint.
    GcStressEveryNSafepoints {
        /// The configured safepoint period.
        period: u64,
    },
    /// GC-stress mode requested a collector poll because the safepoint sequence
    /// saturated.
    GcStressSequenceSaturated,
}

/// A collector poll requested by an allocation safepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationCollectorPoll {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    reason: AllocationGcPollReason,
    stats_after: ArenaStats,
}

impl AllocationCollectorPoll {
    const fn new(safepoint: AllocationSafepoint, reason: AllocationGcPollReason) -> Self {
        Self {
            sequence: safepoint.sequence,
            tier: safepoint.tier,
            request: safepoint.request,
            reason,
            stats_after: safepoint.stats_after,
        }
    }

    /// Returns the allocation safepoint sequence that requested the poll.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier that requested the poll.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry point that requested the poll.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.request.entrypoint()
    }

    /// Returns the typed allocation request that produced the poll.
    pub const fn request(self) -> RuntimeAllocationRequest {
        self.request
    }

    /// Returns why the collector poll was requested.
    pub const fn reason(self) -> AllocationGcPollReason {
        self.reason
    }

    /// Returns allocator accounting after the safepoint allocation completed.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }
}

/// A high-water memory-budget decision made at an allocation safepoint.
///
/// The current runtime does not have a live RSS sampler, so allocation
/// safepoints use post-allocation mapped arena bytes as the resident-memory
/// proxy and accept caller-supplied cheap-reclaim capacity for dead arena pages
/// and cold hash-consed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationMemoryBudgetDecision {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    budget: HeapMemoryBudget,
    sample: HeapMemorySample,
    stats_after: ArenaStats,
    response: HeapMemoryBudgetResponse,
}

impl AllocationMemoryBudgetDecision {
    const fn new(
        safepoint: AllocationSafepoint,
        budget: HeapMemoryBudget,
        sample: HeapMemorySample,
    ) -> Self {
        Self {
            sequence: safepoint.sequence,
            tier: safepoint.tier,
            request: safepoint.request,
            budget,
            sample,
            stats_after: safepoint.stats_after,
            response: budget.classify(sample),
        }
    }

    /// Returns the allocation safepoint sequence that produced this decision.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier sampled by this decision.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry point sampled by this decision.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.request.entrypoint()
    }

    /// Returns the typed allocation request sampled by this decision.
    pub const fn request(self) -> RuntimeAllocationRequest {
        self.request
    }

    /// Returns the budget used to classify memory pressure.
    pub const fn budget(self) -> HeapMemoryBudget {
        self.budget
    }

    /// Returns the memory sample classified by the budget policy.
    pub const fn sample(self) -> HeapMemorySample {
        self.sample
    }

    /// Returns allocator accounting captured after the safepoint allocation.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }

    /// Returns the high-water budget response selected for this safepoint.
    pub const fn response(self) -> HeapMemoryBudgetResponse {
        self.response
    }

    /// Returns whether the response asks runtime code to do more than continue.
    pub const fn requires_runtime_action(self) -> bool {
        match self.response {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => false,
            HeapMemoryBudgetResponse::SpillCold { .. }
            | HeapMemoryBudgetResponse::InstallTierB { .. } => true,
        }
    }

    /// Returns whether the response asks the runtime to install Tier B.
    pub const fn requests_tier_b(self) -> bool {
        matches!(self.response, HeapMemoryBudgetResponse::InstallTierB { .. })
    }
}

/// Metadata captured at one allocation safepoint.
///
/// The current tree-walk runtime records safepoints and GC-stress poll intent
/// only. It does not yet invoke a collector, build a root set, or run GC stress
/// collection from this event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationSafepoint {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    request: RuntimeAllocationRequest,
    kind: HeapObjectKind,
    requested_size: usize,
    reserved_size: usize,
    stats_after: ArenaStats,
    gc_poll_reason: Option<AllocationGcPollReason>,
}

impl AllocationSafepoint {
    const fn new(
        sequence: u64,
        tier: RuntimeAllocatorTier,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
        gc_poll_reason: Option<AllocationGcPollReason>,
    ) -> Self {
        Self {
            sequence,
            tier,
            request,
            kind: allocation.kind,
            requested_size: allocation.requested_size,
            reserved_size: allocation.reserved_size,
            stats_after,
            gc_poll_reason,
        }
    }

    /// Returns the monotonic safepoint sequence number for this allocator.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier that produced this safepoint.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the centralized allocation entry point.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.request.entrypoint()
    }

    /// Returns the typed allocation request that produced this safepoint.
    pub const fn request(self) -> RuntimeAllocationRequest {
        self.request
    }

    /// Returns the logical heap-object kind requested by the caller.
    pub const fn kind(self) -> HeapObjectKind {
        self.kind
    }

    /// Returns the caller-requested allocation size in bytes.
    pub const fn requested_size(self) -> usize {
        self.requested_size
    }

    /// Returns the word-rounded bump distance in bytes.
    pub const fn reserved_size(self) -> usize {
        self.reserved_size
    }

    /// Returns the full arena accounting snapshot after this allocation.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }

    /// Returns why this safepoint requested a collector poll.
    pub const fn gc_poll_reason(self) -> Option<AllocationGcPollReason> {
        self.gc_poll_reason
    }

    /// Returns the typed collector poll requested by this safepoint.
    pub const fn collector_poll(self) -> Option<AllocationCollectorPoll> {
        match self.gc_poll_reason {
            Some(reason) => Some(AllocationCollectorPoll::new(self, reason)),
            None => None,
        }
    }

    /// Builds the high-water budget sample for this safepoint.
    ///
    /// The active runtime does not have live RSS sampling yet, so the sample uses
    /// post-allocation mapped arena bytes as its resident-memory proxy. The
    /// caller supplies cheap-reclaim estimates for dead arena pages and cold
    /// hash-consed values.
    pub const fn memory_budget_sample(
        self,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> HeapMemorySample {
        HeapMemorySample::new(
            self.heap_mapped_bytes_after(),
            dead_arena_bytes,
            cold_hash_consed_bytes,
        )
    }

    /// Classifies this safepoint against a high-water memory budget.
    pub const fn classify_memory_budget(
        self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> AllocationMemoryBudgetDecision {
        let sample = self.memory_budget_sample(dead_arena_bytes, cold_hash_consed_bytes);
        AllocationMemoryBudgetDecision::new(self, budget, sample)
    }

    /// Returns heap chunks owned after this allocation completed.
    pub const fn heap_chunks_after(self) -> usize {
        self.stats_after.chunks
    }

    /// Returns heap bytes reserved after this allocation completed.
    pub const fn heap_reserved_bytes_after(self) -> usize {
        self.stats_after.reserved_bytes
    }

    /// Returns page-rounded mapped bytes after this allocation completed.
    pub const fn heap_mapped_bytes_after(self) -> usize {
        self.stats_after.mapped_bytes
    }

    /// Returns heap bytes consumed after this allocation completed.
    pub const fn heap_used_bytes_after(self) -> usize {
        self.stats_after.used_bytes
    }
}

/// Allocation-safepoint accounting for one allocator domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationSafepointState {
    count: u64,
    last: Option<AllocationSafepoint>,
}

impl AllocationSafepointState {
    /// Returns how many allocation safepoints have been recorded.
    pub const fn count(self) -> u64 {
        self.count
    }

    /// Returns the most recent allocation safepoint.
    pub const fn last(self) -> Option<AllocationSafepoint> {
        self.last
    }

    /// Returns the collector poll requested by the most recent safepoint.
    pub const fn last_safepoint_collector_poll(self) -> Option<AllocationCollectorPoll> {
        match self.last {
            Some(safepoint) => safepoint.collector_poll(),
            None => None,
        }
    }

    /// Classifies the most recent safepoint against a high-water memory budget.
    pub const fn last_memory_budget_decision(
        self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> Option<AllocationMemoryBudgetDecision> {
        match self.last {
            Some(safepoint) => Some(safepoint.classify_memory_budget(
                budget,
                dead_arena_bytes,
                cold_hash_consed_bytes,
            )),
            None => None,
        }
    }

    fn record(
        &mut self,
        tier: RuntimeAllocatorTier,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
        gc_stress_policy: GcStressPolicy,
    ) {
        let sequence = self.count.saturating_add(1);
        self.count = sequence;
        let gc_poll_reason = gc_stress_policy.poll_reason_for(sequence);
        self.last = Some(AllocationSafepoint::new(
            sequence,
            tier,
            request,
            allocation,
            stats_after,
            gc_poll_reason,
        ));
    }
}

/// Routes heap allocations through the active runtime allocation strategy.
#[derive(Debug)]
pub struct RuntimeAllocator {
    backend: RuntimeAllocatorBackend,
    safepoints: AllocationSafepointState,
    gc_stress_policy: GcStressPolicy,
}

impl Default for RuntimeAllocator {
    fn default() -> Self {
        Self::tier_a_one_shot()
    }
}

impl RuntimeAllocator {
    /// Creates a runtime allocator backed by the Tier-A one-shot arena.
    pub fn tier_a_one_shot() -> Self {
        Self {
            backend: RuntimeAllocatorBackend::TierAOneShot(BumpArena::new()),
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Creates a Tier-A runtime allocator with an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn tier_a_with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            backend: RuntimeAllocatorBackend::TierAOneShot(BumpArena::with_initial_chunk_bytes(
                chunk_bytes,
            )?),
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        })
    }

    /// Creates a Tier-A runtime allocator backed by the current thread's arena.
    ///
    /// The allocator preserves the same `TierAOneShot` safepoint tier and
    /// `aos_alloc_*` dispatch table as [`Self::tier_a_one_shot`], but allocation
    /// storage comes from [`ThreadLocalBumpArena`] instead of an owned
    /// [`BumpArena`]. Exactly one thread-local runtime allocator may be active
    /// on a worker thread at a time, and using that allocator from another
    /// thread fails closed. This is the per-worker arena precursor; it is
    /// opt-in and does not change the tree-walk evaluator's default owned
    /// arena.
    ///
    /// # Panics
    ///
    /// Panics if the current thread already has an active thread-local runtime
    /// allocator, or if the internal owner-token counter is exhausted.
    pub fn tier_a_thread_local() -> Self {
        let owner = thread::current().id();
        let token = reserve_thread_local_runtime_allocator(owner);
        Self {
            backend: RuntimeAllocatorBackend::TierAThreadLocal { owner, token },
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Creates a Tier-A thread-local allocator after clearing the worker arena.
    ///
    /// This constructor preserves the same dispatch and ownership checks as
    /// [`Self::tier_a_thread_local`], but it first replaces the current
    /// thread's [`ThreadLocalBumpArena`] with an empty arena. Owned evaluator
    /// runs use this path so a previous opt-in run cannot leak worker allocation
    /// accounting into the next one.
    ///
    /// # Panics
    ///
    /// Panics if the current thread already has an active thread-local runtime
    /// allocator, if the internal owner-token counter is exhausted, or if the
    /// current thread's arena is already mutably borrowed.
    pub fn tier_a_thread_local_empty() -> Self {
        let owner = thread::current().id();
        let token = reserve_thread_local_runtime_allocator(owner);
        if let Err(payload) = std::panic::catch_unwind(ThreadLocalBumpArena::reset_current) {
            release_thread_local_runtime_allocator(owner, token);
            std::panic::resume_unwind(payload);
        }
        Self {
            backend: RuntimeAllocatorBackend::TierAThreadLocal { owner, token },
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Returns this allocator with a GC-stress polling policy installed.
    pub fn with_gc_stress_policy(mut self, policy: GcStressPolicy) -> Self {
        self.gc_stress_policy = policy;
        self
    }

    /// Installs a GC-stress polling policy for later allocation safepoints.
    ///
    /// Periodic policies use this allocator's lifetime safepoint sequence, so
    /// installing a policy does not reset the cadence.
    pub fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Returns the installed GC-stress polling policy.
    pub const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the installed allocation tier.
    pub fn tier(&self) -> RuntimeAllocatorTier {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(_) => RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocatorBackend::TierAThreadLocal { .. } => RuntimeAllocatorTier::TierAOneShot,
        }
    }

    /// Returns whether this allocator stores worker allocations in thread-local Tier-A storage.
    pub fn uses_thread_local_tier_a(&self) -> bool {
        matches!(
            self.backend,
            RuntimeAllocatorBackend::TierAThreadLocal { .. }
        )
    }

    /// Returns the safe allocation dispatch table for the installed backend.
    fn allocation_vtable(&self) -> &'static RuntimeAllocationVTable {
        let vtable = match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(_)
            | RuntimeAllocatorBackend::TierAThreadLocal { .. } => {
                &TIER_A_ONE_SHOT_ALLOCATION_VTABLE
            }
        };
        debug_assert_eq!(vtable.tier(), self.tier());
        debug_assert_eq!(vtable.entrypoints(), runtime_allocation_entrypoints());
        debug_assert_eq!(vtable.abi_signatures(), runtime_allocation_abi_signatures());
        vtable
    }

    /// Returns current allocation accounting for the installed strategy.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn stats(&self) -> ArenaStats {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.stats(),
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| arena.stats())
            }
        }
    }

    /// Advises unused bytes at the end of chunks owned by this allocator.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.advise_unused_tail(kind),
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| arena.advise_unused_tail(kind))
            }
        }
    }

    /// Returns unused-tail bytes this allocator can lower to page advice.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                arena.supported_unused_tail_advice_bytes()
            }
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| {
                    arena.supported_unused_tail_advice_bytes()
                })
            }
        }
    }

    /// Captures the current worker allocator position for lexical reclamation.
    pub(crate) fn region_mark(&self) -> RuntimeAllocatorRegionMark {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                RuntimeAllocatorRegionMark::new(arena.region_mark(), self.safepoints)
            }
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(|arena| {
                    RuntimeAllocatorRegionMark::new(arena.region_mark(), self.safepoints)
                })
            }
        }
    }

    /// Restores the worker allocator to a previously captured region marker.
    ///
    /// The caller must first validate and invalidate any typed heap records for
    /// allocations above the marker. Successful pops also roll allocation
    /// safepoint accounting back to the marker so later collector polls cannot
    /// describe reclaimed allocations.
    pub(crate) fn pop_caller_validated_region(
        &mut self,
        mark: RuntimeAllocatorRegionMark,
        _reclaimed_records: usize,
    ) -> Result<ArenaRegionPopReport, ArenaError> {
        let report = self.with_tier_a_arena_mut(|arena| {
            arena.pop_caller_validated_region_to_mark(mark.arena())
        })?;
        self.safepoints = mark.safepoints();
        Ok(report)
    }

    /// Returns allocation-safepoint accounting for this allocator domain.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Drops the installed worker arena and replaces it with an empty arena.
    ///
    /// For owned Tier-A allocators, the method replaces the owned
    /// [`BumpArena`]. For thread-local allocators, it resets the current
    /// thread's [`ThreadLocalBumpArena`]. The returned accounting describes the
    /// dropped arena. The installed GC-stress policy is preserved for the next
    /// worker lifetime, while allocation-safepoint accounting is reset with the
    /// new empty arena. Any allocation handles returned before the reset must be
    /// considered dead by the caller;
    /// [`EvalHeap::reset_worker_allocator_if_idle`](crate::eval::heap::EvalHeap::reset_worker_allocator_if_idle)
    /// is the typed side-table admission boundary for evaluator-owned values.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub(crate) fn reset_to_empty(&mut self) -> ArenaStats {
        let stats = match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                let previous = mem::take(arena);
                previous.stats()
            }
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::reset_current()
            }
        };
        self.safepoints = AllocationSafepointState::default();
        stats
    }

    /// Allocates heap storage through the active runtime allocation request path.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics when this allocator uses [`Self::tier_a_thread_local`] from a
    /// different thread, when its thread-local owner token is inactive, or when
    /// the current thread's arena is already mutably borrowed.
    pub fn allocate(
        &mut self,
        request: RuntimeAllocationRequest,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocation_vtable().allocate(self, request)
    }

    /// Records a worker allocation safepoint for a flat thunk object.
    ///
    /// RFC-0007 doc 30 FV-3: flat worker closures are allocated by the
    /// evaluator heap's flat closure store, which owns its own arena. The
    /// worker domain's safepoint sequence and GC-stress polling cadence must
    /// keep observing those allocations exactly as they observed the
    /// record-backed thunk allocations, so the heap replays each flat
    /// allocation here under the same `aos_alloc_thunk` request shape.
    pub(crate) fn record_flat_thunk_allocation_safepoint(&mut self, allocation: ArenaAllocation) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::Thunk, allocation);
    }

    /// Records a worker allocation safepoint for a flat lambda object.
    ///
    /// The lambda analog of
    /// [`RuntimeAllocator::record_flat_thunk_allocation_safepoint`], replayed
    /// under the `aos_alloc_lambda` request shape.
    pub(crate) fn record_flat_lambda_allocation_safepoint(&mut self, allocation: ArenaAllocation) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::Lambda, allocation);
    }

    /// Records a worker allocation safepoint for a flat primop object.
    ///
    /// The builtin-record analog of
    /// [`RuntimeAllocator::record_flat_thunk_allocation_safepoint`], replayed
    /// under the raw request shape record-backed primop handles used.
    pub(crate) fn record_flat_primop_allocation_safepoint(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(
            RuntimeAllocationRequest::Raw {
                size,
                align,
                type_tag,
            },
            allocation,
        );
    }

    /// Allocates a thunk-sized heap object through `aos_alloc_thunk`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_thunk(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Thunk)
    }

    /// Allocates a lambda-sized heap object through `aos_alloc_lambda`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_lambda(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Lambda)
    }

    /// Allocates an attribute-set heap object through `aos_alloc_attrs`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Attrs { shape, slots })
    }

    /// Allocates a cons-cell heap object through `aos_alloc_cons`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_cons(&mut self) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Cons)
    }

    /// Allocates a contiguous list heap object through `aos_alloc_list`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::List { len })
    }

    /// Allocates a string heap object through `aos_alloc_string`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::String { len })
    }

    /// Allocates raw heap storage through `aos_alloc_raw`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::allocate`].
    pub fn aos_alloc_raw(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        self.allocate(RuntimeAllocationRequest::Raw {
            size,
            align,
            type_tag,
        })
    }

    fn with_tier_a_arena_mut<R>(&mut self, f: impl FnOnce(&mut BumpArena) -> R) -> R {
        match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => f(arena),
            RuntimeAllocatorBackend::TierAThreadLocal { owner, token } => {
                assert_thread_local_runtime_allocator_owner(*owner, *token);
                ThreadLocalBumpArena::with_current(f)
            }
        }
    }

    fn record_allocation_safepoint(
        &mut self,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
    ) {
        let tier = self.tier();
        let stats = self.stats();
        let gc_stress_policy = self.gc_stress_policy;
        self.safepoints
            .record(tier, request, allocation, stats, gc_stress_policy);
    }
}

impl Drop for RuntimeAllocator {
    fn drop(&mut self) {
        if let RuntimeAllocatorBackend::TierAThreadLocal { owner, token } = &self.backend {
            release_thread_local_runtime_allocator(*owner, *token);
        }
    }
}

fn tier_a_alloc_thunk(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(BumpArena::aos_alloc_thunk)?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::Thunk, allocation);
    Ok(allocation)
}

fn tier_a_alloc_lambda(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(BumpArena::aos_alloc_lambda)?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::Lambda, allocation);
    Ok(allocation)
}

fn tier_a_alloc_attrs(
    allocator: &mut RuntimeAllocator,
    shape: u32,
    slots: u32,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation =
        allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_attrs(shape, slots))?;
    allocator
        .record_allocation_safepoint(RuntimeAllocationRequest::Attrs { shape, slots }, allocation);
    Ok(allocation)
}

fn tier_a_alloc_cons(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(BumpArena::aos_alloc_cons)?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::Cons, allocation);
    Ok(allocation)
}

fn tier_a_alloc_list(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_list(len))?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::List { len }, allocation);
    Ok(allocation)
}

fn tier_a_alloc_string(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation = allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_string(len))?;
    allocator.record_allocation_safepoint(RuntimeAllocationRequest::String { len }, allocation);
    Ok(allocation)
}

fn tier_a_alloc_raw(
    allocator: &mut RuntimeAllocator,
    size: usize,
    align: usize,
    type_tag: u32,
) -> Result<ArenaAllocation, ArenaError> {
    let allocation =
        allocator.with_tier_a_arena_mut(|arena| arena.aos_alloc_raw(size, align, type_tag))?;
    allocator.record_allocation_safepoint(
        RuntimeAllocationRequest::Raw {
            size,
            align,
            type_tag,
        },
        allocation,
    );
    Ok(allocation)
}

fn native_aos_alloc_thunk(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_thunk()
}

fn native_aos_alloc_lambda(
    allocator: &mut RuntimeAllocator,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_lambda()
}

fn native_aos_alloc_attrs(
    allocator: &mut RuntimeAllocator,
    shape: u32,
    slots: u32,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_attrs(shape, slots)
}

fn native_aos_alloc_cons(allocator: &mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_cons()
}

fn native_aos_alloc_list(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_list(len)
}

fn native_aos_alloc_string(
    allocator: &mut RuntimeAllocator,
    len: usize,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_string(len)
}

fn native_aos_alloc_raw(
    allocator: &mut RuntimeAllocator,
    size: usize,
    align: usize,
    type_tag: u32,
) -> Result<ArenaAllocation, ArenaError> {
    allocator.aos_alloc_raw(size, align, type_tag)
}

#[derive(Debug)]
enum RuntimeAllocatorBackend {
    TierAOneShot(BumpArena),
    TierAThreadLocal { owner: ThreadId, token: u64 },
}

/// Allocates reusable hash-consed values in permanent shared storage.
#[derive(Debug)]
pub(crate) struct PermanentSharedAllocator {
    arena: BumpArena,
    safepoints: AllocationSafepointState,
    gc_stress_policy: GcStressPolicy,
}

impl Default for PermanentSharedAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PermanentSharedAllocator {
    /// Creates a permanent-shared allocator.
    pub(crate) fn new() -> Self {
        Self {
            arena: BumpArena::new(),
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Creates a permanent-shared allocator with an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub(crate) fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: BumpArena::with_initial_chunk_bytes(chunk_bytes)?,
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        })
    }

    /// Installs a GC-stress polling policy for later allocation safepoints.
    ///
    /// Periodic policies use this allocator's lifetime safepoint sequence, so
    /// installing a policy does not reset the cadence.
    pub(crate) fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Returns the installed GC-stress polling policy.
    pub(crate) const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the allocator tier for permanent shared storage.
    pub(crate) const fn tier(&self) -> RuntimeAllocatorTier {
        RuntimeAllocatorTier::PermanentShared
    }

    /// Returns current permanent shared allocation accounting.
    pub(crate) fn stats(&self) -> ArenaStats {
        self.arena.stats()
    }

    /// Advises unused bytes at the end of permanent shared arena chunks.
    pub(crate) fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        self.arena.advise_unused_tail(kind)
    }

    /// Returns unused-tail bytes this allocator can lower to page advice.
    pub(crate) fn supported_unused_tail_advice_bytes(&self) -> usize {
        self.arena.supported_unused_tail_advice_bytes()
    }

    /// Returns allocation-safepoint accounting for permanent shared storage.
    pub(crate) const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Test-only permanent allocation through the retired reusable route.
    ///
    /// FV-1/FV-2 moved every production string/list/attrs allocation into the
    /// evaluator heap's flat stores and FV-3 retired the permanent-shared
    /// typed-allocation vtable outright; this helper keeps the permanent
    /// domain's arena accounting, unused-tail advice, and GC-stress poll
    /// machinery testable by reserving arena storage and replaying the same
    /// safepoint shape the retired `aos_alloc_string` route recorded.
    #[cfg(test)]
    pub(crate) fn test_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_string(len)?;
        self.record_allocation_safepoint(RuntimeAllocationRequest::String { len }, allocation);
        Ok(allocation)
    }

    /// Records a permanent allocation safepoint for a flat string/path object.
    ///
    /// RFC-0007 doc 30 FV-1: flat strings and paths are allocated by the
    /// evaluator heap's flat object store, which owns its own arena. The
    /// permanent domain's safepoint sequence and GC-stress polling cadence
    /// must keep observing those allocations exactly as they observed the
    /// record-backed string allocations, so the heap replays each flat
    /// allocation here under the same `aos_alloc_string` request shape.
    pub(crate) fn record_flat_allocation_safepoint(
        &mut self,
        len: usize,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::String { len }, allocation);
    }

    /// Records a permanent allocation safepoint for a flat list object.
    ///
    /// The list analog of
    /// [`PermanentSharedAllocator::record_flat_allocation_safepoint`]: flat
    /// lists are allocated by the evaluator heap's flat list store, and the
    /// permanent domain's safepoint sequence and GC-stress polling cadence
    /// must observe them exactly as they observed record-backed list
    /// allocations, under the same `aos_alloc_list` request shape.
    pub(crate) fn record_flat_list_allocation_safepoint(
        &mut self,
        len: usize,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(RuntimeAllocationRequest::List { len }, allocation);
    }

    /// Records a permanent allocation safepoint for a flat attrset object.
    ///
    /// The attrs analog of
    /// [`PermanentSharedAllocator::record_flat_allocation_safepoint`]
    /// (doc 30 FV-2): flat attrsets are allocated by the evaluator heap's
    /// flat attrs store, and the permanent domain's safepoint sequence and
    /// GC-stress polling cadence must observe them exactly as they observed
    /// record-backed attrset allocations, under the same `aos_alloc_attrs`
    /// request shape.
    pub(crate) fn record_flat_attrs_allocation_safepoint(
        &mut self,
        shape: u32,
        slots: u32,
        allocation: ArenaAllocation,
    ) {
        self.record_allocation_safepoint(
            RuntimeAllocationRequest::Attrs { shape, slots },
            allocation,
        );
    }

    fn record_allocation_safepoint(
        &mut self,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
    ) {
        let tier = self.tier();
        let stats = self.stats();
        let gc_stress_policy = self.gc_stress_policy;
        self.safepoints
            .record(tier, request, allocation, stats, gc_stress_policy);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::thread;

    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};
    use crate::heap::arena::HeapObjectKind;

    use super::*;

    fn assert_last_safepoint(
        state: AllocationSafepointState,
        sequence: u64,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats: ArenaStats,
    ) {
        assert_eq!(state.count(), sequence);
        let event = state.last().expect("safepoint records");
        assert_eq!(event.sequence(), sequence);
        assert_eq!(event.tier(), tier);
        assert_eq!(event.entrypoint(), entrypoint);
        assert_eq!(event.request().entrypoint(), entrypoint);
        assert_eq!(event.kind(), allocation.kind);
        assert_eq!(event.requested_size(), allocation.requested_size);
        assert_eq!(event.reserved_size(), allocation.reserved_size);
        assert_eq!(event.stats_after(), stats);
        assert_eq!(event.heap_chunks_after(), stats.chunks);
        assert_eq!(event.heap_used_bytes_after(), stats.used_bytes);
        assert_eq!(event.heap_reserved_bytes_after(), stats.reserved_bytes);
        assert_eq!(event.heap_mapped_bytes_after(), stats.mapped_bytes);
        assert_eq!(event.gc_poll_reason(), None);
        assert_eq!(event.collector_poll(), None);
        assert_eq!(state.last_safepoint_collector_poll(), None);
    }

    fn assert_last_request_safepoint(
        state: AllocationSafepointState,
        sequence: u64,
        tier: RuntimeAllocatorTier,
        request: RuntimeAllocationRequest,
        allocation: ArenaAllocation,
        stats: ArenaStats,
    ) {
        assert_last_safepoint(
            state,
            sequence,
            tier,
            request.entrypoint(),
            allocation,
            stats,
        );
        let event = state.last().expect("safepoint records");
        assert_eq!(event.request(), request);
    }

    fn memory_budget(bytes: usize) -> HeapMemoryBudget {
        HeapMemoryBudget::new(bytes).expect("budget is non-zero")
    }

    #[test]
    fn tier_a_allocator_routes_every_entrypoint() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert!(allocator.gc_stress_policy().is_disabled());
        assert_eq!(
            allocator.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        let allocation = allocator.aos_alloc_thunk().expect("thunk allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Thunk);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocThunk,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_lambda().expect("lambda allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Lambda);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocLambda,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_attrs(7, 2).expect("attrs allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_cons().expect("cons allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Cons);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            4,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocCons,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_list(3).expect("list allocates");
        assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            5,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocList,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_string(5).expect("string allocates");
        assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            6,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocString,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator
            .aos_alloc_raw(8, 8, 0x7261_7770)
            .expect("raw allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Raw {
                type_tag: 0x7261_7770,
            }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            7,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocRaw,
            allocation,
            allocator.stats(),
        );

        let stats = allocator.stats();
        assert_eq!(stats.chunks, 1);
        assert!(stats.used_bytes > 0);
    }

    #[test]
    fn tier_a_allocator_dispatches_typed_allocation_requests() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");
        let requests = [
            (
                RuntimeAllocationRequest::Attrs { shape: 7, slots: 2 },
                HeapObjectKind::Attrs { shape: 7, slots: 2 },
            ),
            (RuntimeAllocationRequest::Cons, HeapObjectKind::Cons),
            (RuntimeAllocationRequest::Lambda, HeapObjectKind::Lambda),
            (
                RuntimeAllocationRequest::List { len: 3 },
                HeapObjectKind::List { len: 3 },
            ),
            (
                RuntimeAllocationRequest::Raw {
                    size: 8,
                    align: 8,
                    type_tag: 0x7261_7770,
                },
                HeapObjectKind::Raw {
                    type_tag: 0x7261_7770,
                },
            ),
            (
                RuntimeAllocationRequest::String { len: 5 },
                HeapObjectKind::String { len: 5 },
            ),
            (RuntimeAllocationRequest::Thunk, HeapObjectKind::Thunk),
        ];

        assert_eq!(
            requests
                .iter()
                .map(|(request, _)| request.entrypoint())
                .collect::<Vec<_>>(),
            runtime_allocation_entrypoints()
        );

        for (index, (request, expected_kind)) in requests.into_iter().enumerate() {
            assert_eq!(request.symbol_name(), request.entrypoint().symbol_name());
            let allocation = allocator
                .allocate(request)
                .expect("typed request allocates");
            assert_eq!(allocation.kind, expected_kind);
            assert_last_safepoint(
                allocator.allocation_safepoints(),
                u64::try_from(index + 1).expect("request index fits in u64"),
                RuntimeAllocatorTier::TierAOneShot,
                request.entrypoint(),
                allocation,
                allocator.stats(),
            );
            assert_eq!(
                allocator
                    .allocation_safepoints()
                    .last()
                    .expect("safepoint records")
                    .request(),
                request
            );
        }
    }

    #[test]
    fn allocation_safepoint_classifies_high_water_memory_budget() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
        let request = RuntimeAllocationRequest::Raw {
            size: 16,
            align: 8,
            type_tag: 0x7261_7770,
        };
        allocator
            .allocate(request)
            .expect("raw allocation succeeds");
        let state = allocator.allocation_safepoints();
        let safepoint = state.last().expect("safepoint records");
        let mapped_bytes = safepoint.heap_mapped_bytes_after();
        assert!(mapped_bytes > 1);

        let loose_budget = memory_budget(mapped_bytes.checked_mul(2).expect("budget doubles"));
        let continue_decision = safepoint.classify_memory_budget(loose_budget, 0, 0);
        assert_eq!(continue_decision.sequence(), safepoint.sequence());
        assert_eq!(continue_decision.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(
            continue_decision.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocRaw
        );
        assert_eq!(safepoint.request(), request);
        assert_eq!(continue_decision.request(), request);
        assert_eq!(continue_decision.budget(), loose_budget);
        assert_eq!(
            continue_decision.sample(),
            HeapMemorySample::new(mapped_bytes, 0, 0)
        );
        assert_eq!(continue_decision.stats_after(), safepoint.stats_after());
        assert_eq!(
            continue_decision.response(),
            HeapMemoryBudgetResponse::ContinueTierA {
                headroom_bytes: loose_budget.soft_limit_bytes() - mapped_bytes,
                projected_resident_bytes: mapped_bytes,
            }
        );
        assert!(!continue_decision.requires_runtime_action());
        assert!(!continue_decision.requests_tier_b());

        let spill_budget = memory_budget(mapped_bytes);
        let spill_reclaim_bytes = mapped_bytes - spill_budget.soft_limit_bytes();
        let spill_decision = state
            .last_memory_budget_decision(spill_budget, spill_reclaim_bytes, 0)
            .expect("last safepoint classifies");
        assert_eq!(spill_decision.request(), request);
        assert_eq!(
            spill_decision.sample(),
            HeapMemorySample::new(mapped_bytes, spill_reclaim_bytes, 0)
        );
        assert_eq!(
            spill_decision.response(),
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: spill_reclaim_bytes,
                available_reclaim_bytes: spill_reclaim_bytes,
                projected_resident_bytes: spill_budget.soft_limit_bytes(),
            }
        );
        assert!(spill_decision.requires_runtime_action());
        assert!(!spill_decision.requests_tier_b());

        let tier_b_budget = memory_budget(mapped_bytes / 2);
        let tier_b_decision = safepoint.classify_memory_budget(tier_b_budget, 0, 0);
        assert_eq!(tier_b_decision.request(), request);
        assert_eq!(
            tier_b_decision.response(),
            HeapMemoryBudgetResponse::InstallTierB {
                desired_reclaim_bytes: mapped_bytes - tier_b_budget.soft_limit_bytes(),
                available_reclaim_bytes: 0,
                projected_resident_bytes: mapped_bytes,
                over_budget_bytes: mapped_bytes - tier_b_budget.max_resident_bytes(),
            }
        );
        assert!(tier_b_decision.requires_runtime_action());
        assert!(tier_b_decision.requests_tier_b());

        assert_eq!(
            AllocationSafepointState::default().last_memory_budget_decision(loose_budget, 0, 0),
            None
        );
    }

    #[test]
    fn runtime_allocators_report_unused_tail_advice() {
        let mut worker =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(65536).expect("worker creates");
        worker.aos_alloc_thunk().expect("worker allocates");
        let worker_supported_tail_advice_bytes = worker.supported_unused_tail_advice_bytes();

        let worker_report = worker.advise_unused_tail(MemoryAdviceKind::Dead);

        assert_eq!(worker_report.kind(), MemoryAdviceKind::Dead);
        assert_eq!(worker_report.chunks(), 1);
        assert!(worker_report.requested_bytes() > 0);
        #[cfg(target_os = "linux")]
        assert!(worker_supported_tail_advice_bytes > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(worker_supported_tail_advice_bytes, 0);
        assert!(worker_supported_tail_advice_bytes <= worker_report.requested_bytes());
        assert_eq!(
            worker_report.applied()
                + worker_report.unsupported()
                + worker_report.empty_ranges()
                + worker_report.rejected(),
            1
        );

        let mut permanent =
            PermanentSharedAllocator::with_initial_chunk_bytes(65536).expect("permanent creates");
        permanent
            .test_alloc_string(1)
            .expect("permanent string allocates");
        let permanent_supported_tail_advice_bytes = permanent.supported_unused_tail_advice_bytes();

        let permanent_report = permanent.advise_unused_tail(MemoryAdviceKind::Dead);

        assert_eq!(permanent_report.kind(), MemoryAdviceKind::Dead);
        assert_eq!(permanent_report.chunks(), 1);
        assert!(permanent_report.requested_bytes() > 0);
        #[cfg(target_os = "linux")]
        assert!(permanent_supported_tail_advice_bytes > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(permanent_supported_tail_advice_bytes, 0);
        assert!(permanent_supported_tail_advice_bytes <= permanent_report.requested_bytes());
        assert_eq!(
            permanent_report.applied()
                + permanent_report.unsupported()
                + permanent_report.empty_ranges()
                + permanent_report.rejected(),
            1
        );
    }

    #[test]
    fn worker_allocator_reset_drops_worker_chunks_without_touching_permanent_storage() {
        let mut worker =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("worker creates");
        let mut permanent =
            PermanentSharedAllocator::with_initial_chunk_bytes(128).expect("permanent creates");
        worker.set_gc_stress_policy(GcStressPolicy::every_safepoint());
        worker.aos_alloc_thunk().expect("worker allocates");
        permanent
            .test_alloc_string(5)
            .expect("permanent string allocates");
        let worker_stats_before = worker.stats();
        let permanent_stats_before = permanent.stats();
        let permanent_safepoints_before = permanent.allocation_safepoints();

        let dropped_worker_stats = worker.reset_to_empty();

        assert_eq!(dropped_worker_stats, worker_stats_before);
        assert_eq!(worker.stats(), ArenaStats::default());
        assert_eq!(
            worker.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        assert_eq!(worker.gc_stress_policy(), GcStressPolicy::every_safepoint());
        assert_eq!(permanent.stats(), permanent_stats_before);
        assert_eq!(
            permanent.allocation_safepoints(),
            permanent_safepoints_before
        );

        permanent
            .test_alloc_string(7)
            .expect("permanent allocator remains usable after worker reset");
        assert_eq!(permanent.allocation_safepoints().count(), 2);
        assert!(permanent.stats().used_bytes > permanent_stats_before.used_bytes);
    }

    #[test]
    fn runtime_abi_declares_allocator_entrypoint_names() {
        let allocation_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::Allocation)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let runtime_entrypoint_symbols = runtime_allocation_entrypoints()
            .iter()
            .copied()
            .map(RuntimeAllocationEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let runtime_signature_symbols = runtime_allocation_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeAllocationAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            allocation_symbols,
            BTreeSet::from([
                "aos_alloc_attrs",
                "aos_alloc_cons",
                "aos_alloc_lambda",
                "aos_alloc_list",
                "aos_alloc_raw",
                "aos_alloc_string",
                "aos_alloc_thunk",
            ])
        );
        assert_eq!(runtime_entrypoint_symbols, allocation_symbols);
        assert_eq!(runtime_signature_symbols, allocation_symbols);
    }

    #[test]
    fn runtime_allocator_selects_tier_a_allocation_vtable() {
        let default_allocator = RuntimeAllocator::default();
        let configured_allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");
        let thread_local_allocator = RuntimeAllocator::tier_a_thread_local();

        for allocator in [
            &default_allocator,
            &configured_allocator,
            &thread_local_allocator,
        ] {
            let vtable = allocator.allocation_vtable();

            assert_eq!(vtable.tier(), RuntimeAllocatorTier::TierAOneShot);
            assert_eq!(vtable.entrypoints(), runtime_allocation_entrypoints());
            assert_eq!(vtable.abi_signatures(), runtime_allocation_abi_signatures());
        }
    }

    #[test]
    fn tier_a_thread_local_allocator_routes_allocations_and_reset() {
        ThreadLocalBumpArena::reset_current();
        let mut allocator = RuntimeAllocator::tier_a_thread_local();

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(allocator.stats(), ArenaStats::default());

        let allocation = allocator
            .aos_alloc_string(5)
            .expect("thread-local string allocates");
        let stats = allocator.stats();
        assert_eq!(
            ThreadLocalBumpArena::with_current(|arena| arena.stats()),
            stats
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocString,
            allocation,
            stats,
        );

        let worker = thread::spawn(|| {
            ThreadLocalBumpArena::reset_current();
            let before = ThreadLocalBumpArena::with_current(|arena| arena.stats());
            let mut allocator = RuntimeAllocator::tier_a_thread_local();
            allocator
                .aos_alloc_thunk()
                .expect("worker thread-local thunk allocates");
            let after = allocator.stats();
            ThreadLocalBumpArena::reset_current();
            (before, after)
        })
        .join()
        .expect("worker thread joins");
        assert_eq!(worker.0, ArenaStats::default());
        assert!(worker.1.chunks > 0);
        assert_eq!(allocator.stats(), stats);

        let dropped = allocator.reset_to_empty();
        assert_eq!(dropped, stats);
        assert_eq!(allocator.stats(), ArenaStats::default());
        assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
        ThreadLocalBumpArena::reset_current();
    }

    #[test]
    #[should_panic(expected = "thread already has an active thread-local runtime allocator")]
    fn tier_a_thread_local_allocator_rejects_same_thread_sharing() {
        ThreadLocalBumpArena::reset_current();
        let _first = RuntimeAllocator::tier_a_thread_local();
        let _second = RuntimeAllocator::tier_a_thread_local();
    }

    #[test]
    fn tier_a_thread_local_allocator_rejects_cross_thread_use() {
        ThreadLocalBumpArena::reset_current();
        let allocator = RuntimeAllocator::tier_a_thread_local();

        let rejected =
            thread::spawn(move || std::panic::catch_unwind(|| allocator.stats()).is_err())
                .join()
                .expect("worker thread joins");
        assert!(rejected);

        let replacement = RuntimeAllocator::tier_a_thread_local();
        assert_eq!(replacement.stats(), ArenaStats::default());
        drop(replacement);
        ThreadLocalBumpArena::reset_current();
    }

    #[test]
    fn tier_a_thread_local_allocator_region_pop_rewinds_current_thread_arena() {
        ThreadLocalBumpArena::reset_current();
        let mut allocator = RuntimeAllocator::tier_a_thread_local();

        allocator
            .aos_alloc_raw(16, 8, 1)
            .expect("first raw allocation succeeds");
        let mark = allocator.region_mark();
        allocator
            .aos_alloc_raw(24, 8, 2)
            .expect("second raw allocation succeeds");
        let before = allocator.stats();
        assert!(before.used_bytes > mark.arena().cursor());

        let report = allocator
            .pop_caller_validated_region(mark, 0)
            .expect("region pop succeeds");

        assert_eq!(report.before_stats(), before);
        assert_eq!(report.after_stats(), allocator.stats());
        assert_eq!(allocator.allocation_safepoints(), mark.safepoints());
        assert_eq!(
            ThreadLocalBumpArena::with_current(|arena| arena.stats()),
            report.after_stats()
        );
        drop(allocator);
        ThreadLocalBumpArena::reset_current();
    }

    #[test]
    fn tier_a_thread_local_allocator_records_gc_stress_poll_reason() {
        ThreadLocalBumpArena::reset_current();
        let mut allocator = RuntimeAllocator::tier_a_thread_local()
            .with_gc_stress_policy(GcStressPolicy::every_safepoint());

        allocator
            .aos_alloc_thunk()
            .expect("thread-local thunk allocates");

        let poll = allocator
            .allocation_safepoints()
            .last_safepoint_collector_poll()
            .expect("thread-local safepoint records poll");
        assert_eq!(poll.sequence(), 1);
        assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(
            poll.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocThunk
        );
        assert_eq!(
            poll.reason(),
            AllocationGcPollReason::GcStressEverySafepoint
        );
        assert_eq!(poll.stats_after(), allocator.stats());
        drop(allocator);
        ThreadLocalBumpArena::reset_current();
    }

    #[test]
    fn tier_a_allocation_vtable_routes_every_worker_entrypoint() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");
        let vtable = allocator.allocation_vtable();

        let thunk = vtable
            .aos_alloc_thunk(&mut allocator)
            .expect("thunk allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocThunk,
            thunk,
            allocator.stats(),
        );

        let lambda = vtable
            .aos_alloc_lambda(&mut allocator)
            .expect("lambda allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocLambda,
            lambda,
            allocator.stats(),
        );

        let attrs = vtable
            .aos_alloc_attrs(&mut allocator, 7, 2)
            .expect("attrs allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            attrs,
            allocator.stats(),
        );

        let cons = vtable
            .aos_alloc_cons(&mut allocator)
            .expect("cons allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            4,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocCons,
            cons,
            allocator.stats(),
        );

        let list = vtable
            .aos_alloc_list(&mut allocator, 3)
            .expect("list allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            5,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocList,
            list,
            allocator.stats(),
        );

        let string = vtable
            .aos_alloc_string(&mut allocator, 5)
            .expect("string allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            6,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocString,
            string,
            allocator.stats(),
        );

        let raw = vtable
            .aos_alloc_raw(&mut allocator, 8, 8, 0x7261_7770)
            .expect("raw allocates");
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            7,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocRaw,
            raw,
            allocator.stats(),
        );
    }

    #[test]
    fn allocation_rust_callable_bindings_preserve_entrypoint_inventory() {
        let bindings = runtime_allocation_rust_callable_bindings();
        let expected = [
            (
                RuntimeAllocationEntryPoint::AosAllocAttrs,
                RuntimeAllocationRustCallableShape::AllocatorU32U32,
                native_aos_alloc_attrs as RuntimeAllocationAttrsFn as *const (),
            ),
            (
                RuntimeAllocationEntryPoint::AosAllocCons,
                RuntimeAllocationRustCallableShape::AllocatorOnly,
                native_aos_alloc_cons as RuntimeAllocationConsFn as *const (),
            ),
            (
                RuntimeAllocationEntryPoint::AosAllocLambda,
                RuntimeAllocationRustCallableShape::AllocatorOnly,
                native_aos_alloc_lambda as RuntimeAllocationLambdaFn as *const (),
            ),
            (
                RuntimeAllocationEntryPoint::AosAllocList,
                RuntimeAllocationRustCallableShape::AllocatorUsize,
                native_aos_alloc_list as RuntimeAllocationListFn as *const (),
            ),
            (
                RuntimeAllocationEntryPoint::AosAllocRaw,
                RuntimeAllocationRustCallableShape::AllocatorUsizeUsizeU32,
                native_aos_alloc_raw as RuntimeAllocationRawFn as *const (),
            ),
            (
                RuntimeAllocationEntryPoint::AosAllocString,
                RuntimeAllocationRustCallableShape::AllocatorUsize,
                native_aos_alloc_string as RuntimeAllocationStringFn as *const (),
            ),
            (
                RuntimeAllocationEntryPoint::AosAllocThunk,
                RuntimeAllocationRustCallableShape::AllocatorOnly,
                native_aos_alloc_thunk as RuntimeAllocationThunkFn as *const (),
            ),
        ];

        assert_eq!(bindings.len(), expected.len());
        assert_eq!(
            bindings
                .iter()
                .copied()
                .map(RuntimeAllocationRustCallableBinding::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_allocation_entrypoints()
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
            runtime_allocation_abi_signatures()
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
                "{} has a callable allocation address",
                binding.symbol_name()
            );
        }
    }

    #[test]
    fn allocation_native_export_preflight_preserves_frozen_abi_and_storage_callables() {
        let preflight = runtime_allocation_native_export_preflight();

        assert!(!preflight.is_complete());
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeAllocationNativeExportReadiness::entrypoint)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_allocation_entrypoints()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeAllocationNativeExportReadiness::abi_signature)
                .collect::<Vec<_>>()
                .as_slice(),
            runtime_allocation_abi_signatures()
        );
        assert_eq!(
            preflight
                .readiness()
                .iter()
                .map(RuntimeAllocationNativeExportReadiness::rust_callable_binding)
                .collect::<Vec<_>>(),
            runtime_allocation_rust_callable_bindings()
        );

        for record in preflight.readiness() {
            assert_eq!(record.symbol_name(), record.entrypoint().symbol_name());
            assert_eq!(
                record.blockers(),
                record.entrypoint().native_export_blockers()
            );
            assert!(!record.is_export_ready());
            match record.entrypoint() {
                RuntimeAllocationEntryPoint::AosAllocCons
                | RuntimeAllocationEntryPoint::AosAllocLambda
                | RuntimeAllocationEntryPoint::AosAllocThunk => {
                    assert_eq!(
                        record.blockers(),
                        [
                            RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
                            RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
                            RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
                            RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
                            RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented,
                        ]
                        .as_slice()
                    );
                }
                RuntimeAllocationEntryPoint::AosAllocAttrs
                | RuntimeAllocationEntryPoint::AosAllocList
                | RuntimeAllocationEntryPoint::AosAllocRaw
                | RuntimeAllocationEntryPoint::AosAllocString => {
                    assert_eq!(
                        record.blockers(),
                        [
                            RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
                            RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
                            RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
                            RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
                        ]
                        .as_slice()
                    );
                }
            }
            assert_eq!(
                preflight.readiness_for_symbol(record.symbol_name()),
                Some(record)
            );
        }
    }

    #[test]
    fn allocation_native_export_preflight_marks_semantic_payload_gaps() {
        let preflight = runtime_allocation_native_export_preflight();
        let semantic_symbols = [
            RuntimeAllocationEntryPoint::AosAllocCons,
            RuntimeAllocationEntryPoint::AosAllocLambda,
            RuntimeAllocationEntryPoint::AosAllocThunk,
        ];
        let storage_only_symbols = [
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            RuntimeAllocationEntryPoint::AosAllocList,
            RuntimeAllocationEntryPoint::AosAllocRaw,
            RuntimeAllocationEntryPoint::AosAllocString,
        ];

        for entrypoint in semantic_symbols {
            let record = preflight
                .readiness_for_symbol(entrypoint.symbol_name())
                .expect("semantic allocation export readiness exists");
            assert!(
                record.blockers().contains(
                    &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                ),
                "{} must initialize frozen ABI semantic payloads",
                entrypoint.symbol_name()
            );
        }

        for entrypoint in storage_only_symbols {
            let record = preflight
                .readiness_for_symbol(entrypoint.symbol_name())
                .expect("storage allocation export readiness exists");
            assert!(
                !record.blockers().contains(
                    &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
                ),
                "{} has no extra semantic payload beyond storage reservation",
                entrypoint.symbol_name()
            );
        }
    }

    #[test]
    fn allocation_native_callables_route_through_request_wall() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

        let allocation =
            native_aos_alloc_attrs(&mut allocator, 7, 2).expect("native attrs wrapper allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::Attrs { shape: 7, slots: 2 },
            allocation,
            allocator.stats(),
        );

        let allocation =
            native_aos_alloc_cons(&mut allocator).expect("native cons wrapper allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Cons);
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::Cons,
            allocation,
            allocator.stats(),
        );

        let allocation =
            native_aos_alloc_lambda(&mut allocator).expect("native lambda wrapper allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Lambda);
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::Lambda,
            allocation,
            allocator.stats(),
        );

        let allocation =
            native_aos_alloc_list(&mut allocator, 3).expect("native list wrapper allocates");
        assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            4,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::List { len: 3 },
            allocation,
            allocator.stats(),
        );

        let allocation = native_aos_alloc_raw(&mut allocator, 8, 8, 0x7261_7770)
            .expect("native raw wrapper allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Raw {
                type_tag: 0x7261_7770
            }
        );
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            5,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::Raw {
                size: 8,
                align: 8,
                type_tag: 0x7261_7770,
            },
            allocation,
            allocator.stats(),
        );

        let allocation =
            native_aos_alloc_string(&mut allocator, 5).expect("native string wrapper allocates");
        assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            6,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::String { len: 5 },
            allocation,
            allocator.stats(),
        );

        let allocation =
            native_aos_alloc_thunk(&mut allocator).expect("native thunk wrapper allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Thunk);
        assert_last_request_safepoint(
            allocator.allocation_safepoints(),
            7,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationRequest::Thunk,
            allocation,
            allocator.stats(),
        );
    }

    #[test]
    fn allocation_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_allocation_entrypoints(),
            [
                RuntimeAllocationEntryPoint::AosAllocAttrs,
                RuntimeAllocationEntryPoint::AosAllocCons,
                RuntimeAllocationEntryPoint::AosAllocLambda,
                RuntimeAllocationEntryPoint::AosAllocList,
                RuntimeAllocationEntryPoint::AosAllocRaw,
                RuntimeAllocationEntryPoint::AosAllocString,
                RuntimeAllocationEntryPoint::AosAllocThunk,
            ]
        );

        for entrypoint in runtime_allocation_entrypoints() {
            assert_eq!(
                RuntimeAllocationEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeAllocationAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() != RuntimeHelperRole::Allocation)
        {
            assert_eq!(
                RuntimeAllocationEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not an allocation entry point",
                symbol.name()
            );
            assert_eq!(
                RuntimeAllocationAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no allocation ABI signature",
                symbol.name()
            );
        }
        assert_eq!(
            RuntimeAllocationEntryPoint::from_symbol_name("nix.builtin.derivationStrict"),
            None
        );
        assert_eq!(
            RuntimeAllocationAbiSignature::from_symbol_name("nix.builtin.derivationStrict"),
            None
        );
    }

    #[test]
    fn allocation_abi_signatures_pin_runtime_parameters() {
        fn assert_signature(
            entrypoint: RuntimeAllocationEntryPoint,
            parameters: &[RuntimeAllocationAbiParameter],
            return_kind: RuntimeAllocationAbiReturnKind,
        ) {
            let signature = entrypoint.abi_signature();
            assert_eq!(signature.entrypoint(), entrypoint);
            assert_eq!(signature.parameters(), parameters);
            assert_eq!(signature.return_kind(), return_kind);
        }

        assert_eq!(
            runtime_allocation_abi_signatures()
                .iter()
                .copied()
                .map(RuntimeAllocationAbiSignature::entrypoint)
                .collect::<Vec<_>>(),
            runtime_allocation_entrypoints()
        );

        for signature in runtime_allocation_abi_signatures().iter().copied() {
            assert_eq!(signature.entrypoint().abi_signature(), signature);
            assert_eq!(
                signature.symbol_name(),
                signature.entrypoint().symbol_name()
            );
            assert_eq!(
                signature.parameters().first().copied(),
                Some(RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                )),
                "{} takes the runtime context first",
                signature.symbol_name()
            );
        }

        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocThunk,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "code_ptr",
                    RuntimeAllocationAbiParameterKind::CodePointer,
                ),
                RuntimeAllocationAbiParameter::new(
                    "env",
                    RuntimeAllocationAbiParameterKind::EnvPointer,
                ),
            ],
            RuntimeAllocationAbiReturnKind::ThunkPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocLambda,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "code_ptr",
                    RuntimeAllocationAbiParameterKind::CodePointer,
                ),
                RuntimeAllocationAbiParameter::new(
                    "env",
                    RuntimeAllocationAbiParameterKind::EnvPointer,
                ),
            ],
            RuntimeAllocationAbiReturnKind::LambdaPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            [
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "shape",
                    RuntimeAllocationAbiParameterKind::ShapeId,
                ),
                RuntimeAllocationAbiParameter::new("slots", RuntimeAllocationAbiParameterKind::U32),
            ]
            .as_slice(),
            RuntimeAllocationAbiReturnKind::AttrsPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocCons,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "head",
                    RuntimeAllocationAbiParameterKind::Value,
                ),
                RuntimeAllocationAbiParameter::new(
                    "tail",
                    RuntimeAllocationAbiParameterKind::ListPointer,
                ),
            ],
            RuntimeAllocationAbiReturnKind::ListPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocList,
            [
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
            ]
            .as_slice(),
            RuntimeAllocationAbiReturnKind::ListPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocString,
            [
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
            ]
            .as_slice(),
            RuntimeAllocationAbiReturnKind::StringHeaderPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocRaw,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "size",
                    RuntimeAllocationAbiParameterKind::Usize,
                ),
                RuntimeAllocationAbiParameter::new(
                    "align",
                    RuntimeAllocationAbiParameterKind::Usize,
                ),
                RuntimeAllocationAbiParameter::new(
                    "type_tag",
                    RuntimeAllocationAbiParameterKind::TypeTag,
                ),
            ],
            RuntimeAllocationAbiReturnKind::RawPointer,
        );
    }

    #[test]
    fn invalid_tier_a_chunk_size_is_rejected() {
        let error = RuntimeAllocator::tier_a_with_initial_chunk_bytes(0)
            .expect_err("zero-sized chunks are invalid");

        assert_eq!(error, ArenaError::InvalidChunkSize { chunk_bytes: 0 });
    }

    #[test]
    fn gc_stress_period_rejects_zero() {
        assert_eq!(
            GcStressPolicy::every_n_safepoints(0),
            Err(GcStressPolicyError::ZeroPeriod)
        );
    }

    #[test]
    fn gc_stress_every_safepoint_records_poll_reason() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.set_gc_stress_policy(GcStressPolicy::every_safepoint());

        allocator.aos_alloc_thunk().expect("thunk allocates");

        let event = allocator
            .allocation_safepoints()
            .last()
            .expect("safepoint records");
        assert_eq!(event.sequence(), 1);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEverySafepoint)
        );
        let poll = event.collector_poll().expect("poll request records");
        assert_eq!(poll.sequence(), event.sequence());
        assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(event.request(), RuntimeAllocationRequest::Thunk);
        assert_eq!(poll.request(), RuntimeAllocationRequest::Thunk);
        assert_eq!(
            poll.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocThunk
        );
        assert_eq!(
            poll.reason(),
            AllocationGcPollReason::GcStressEverySafepoint
        );
        assert_eq!(poll.stats_after(), event.stats_after());
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last_safepoint_collector_poll(),
            Some(poll)
        );
    }

    #[test]
    fn gc_stress_periodic_policy_records_poll_on_matching_sequences() {
        let mut allocator = RuntimeAllocator::tier_a_with_initial_chunk_bytes(128)
            .expect("allocator creates")
            .with_gc_stress_policy(
                GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"),
            );

        allocator.aos_alloc_thunk().expect("first allocation");
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("first safepoint")
                .gc_poll_reason(),
            None
        );

        allocator.aos_alloc_lambda().expect("second allocation");
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("second safepoint")
                .gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 })
        );

        allocator.aos_alloc_cons().expect("third allocation");
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("third safepoint")
                .gc_poll_reason(),
            None
        );
    }

    #[test]
    fn periodic_gc_stress_uses_allocator_lifetime_sequence() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.aos_alloc_thunk().expect("first allocation");

        allocator.set_gc_stress_policy(
            GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"),
        );
        allocator.aos_alloc_lambda().expect("second allocation");

        let event = allocator
            .allocation_safepoints()
            .last()
            .expect("second safepoint");
        assert_eq!(event.sequence(), 2);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 })
        );
    }

    #[test]
    fn enabled_gc_stress_polls_when_safepoint_sequence_saturates() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        let request = RuntimeAllocationRequest::Raw {
            size: 16,
            align: 8,
            type_tag: 0x7261_7770,
        };
        let allocation = arena
            .aos_alloc_raw(16, 8, 0x7261_7770)
            .expect("raw allocation succeeds");
        let mut state = AllocationSafepointState {
            count: u64::MAX - 1,
            last: None,
        };
        let policy = GcStressPolicy::every_n_safepoints(2).expect("period is non-zero");

        state.record(
            RuntimeAllocatorTier::TierAOneShot,
            request,
            allocation,
            arena.stats(),
            policy,
        );
        let event = state.last().expect("saturated safepoint records");
        assert_eq!(event.sequence(), u64::MAX);
        assert_eq!(event.request(), request);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressSequenceSaturated)
        );
        let poll = event.collector_poll().expect("poll records");
        assert_eq!(poll.request(), request);
        assert_eq!(
            poll.reason(),
            AllocationGcPollReason::GcStressSequenceSaturated
        );

        state.record(
            RuntimeAllocatorTier::TierAOneShot,
            request,
            allocation,
            arena.stats(),
            policy,
        );
        let event = state.last().expect("post-saturation safepoint records");
        assert_eq!(event.sequence(), u64::MAX);
        assert_eq!(event.request(), request);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressSequenceSaturated)
        );
        let poll = state.last_safepoint_collector_poll().expect("poll records");
        assert_eq!(poll.sequence(), u64::MAX);
        assert_eq!(poll.request(), request);
    }

    #[test]
    fn permanent_shared_allocations_can_record_gc_stress_poll_reason() {
        let mut allocator =
            PermanentSharedAllocator::with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.set_gc_stress_policy(GcStressPolicy::every_safepoint());

        allocator.test_alloc_string(5).expect("string allocates");

        let event = allocator
            .allocation_safepoints()
            .last()
            .expect("safepoint records");
        assert_eq!(event.tier(), RuntimeAllocatorTier::PermanentShared);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEverySafepoint)
        );
        let poll = allocator
            .allocation_safepoints()
            .last_safepoint_collector_poll()
            .expect("permanent poll records");
        assert_eq!(poll.sequence(), event.sequence());
        assert_eq!(poll.tier(), RuntimeAllocatorTier::PermanentShared);
        assert_eq!(event.request(), RuntimeAllocationRequest::String { len: 5 });
        assert_eq!(poll.request(), RuntimeAllocationRequest::String { len: 5 });
        assert_eq!(
            poll.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocString
        );
        assert_eq!(
            poll.reason(),
            AllocationGcPollReason::GcStressEverySafepoint
        );
        assert_eq!(poll.stats_after(), event.stats_after());
    }
}
