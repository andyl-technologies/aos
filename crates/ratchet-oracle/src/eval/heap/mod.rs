//! Typed heap-object registry for the tree-walk evaluator.
//!
//! Runtime [`Value`] words carry opaque [`HeapObject`] pointers. This registry
//! owns the typed Rust-side objects behind those pointers for the safe tree-walk
//! oracle: the bump arena provides stable opaque handles, while a side table
//! maps those handles back to checked [`NixString`], path [`NixString`],
//! [`NixList`], [`FlatAttrs`], [`EvalLambda`], [`EvalPrimOp`], and
//! [`EvalThunk`] values.

use std::cell::Cell;
use std::ptr::NonNull;
use std::rc::Rc;

use thiserror::Error;

use super::env::{EvalEnv, EvalEnvError, EvalScopedGlobalEnv, EvalWithEnv};
use super::module::{EvalModuleId, EvalNodeRef};
use super::thunk::{ForceError, ThunkCell};
use crate::attrs::FlatAttrs;
use crate::cache::{HotXxh3Hash, ValueHash};
use crate::compile::{FrameId, IrAttrPathId, IrId};
use crate::hashcons::{HashConsError, HashConsReservation, HashConsSlot, HashConsTable};
use crate::heap::arena::{ArenaAllocation, ArenaError, ArenaStats};
use crate::heap::{GcHeapAddress, GenerationalGcError, HeapGeneration, ResolvedValueGeneration};
use crate::list::NixList;
use crate::runtime::alloc::{
    AllocationSafepointState, GcStressPolicy, PermanentSharedAllocator, RuntimeAllocator,
    RuntimeAllocatorTier,
};
use crate::runtime::builtins::Builtin;
use crate::string::NixString;
use crate::syntax::{Span, Symbol};
use crate::value::{HeapObject, Value, ValueError, ValueTag};

mod arena;
mod lambda;
mod primop;
mod roots;
mod thunk;

pub use roots::{
    AllocationCollectorPollMinorGcCommitBuffers, AllocationCollectorPollMinorGcCommitPlan,
    AllocationCollectorPollMinorGcPlan, AllocationCollectorPollMinorGcRelocationDestinations,
    AllocationCollectorPollNurseryField, AllocationCollectorPollNurseryFields,
    AllocationCollectorPollReferenceSlot, AllocationCollectorPollReferenceSource,
    AllocationCollectorPollScan, CapturedRootOwner, EvalRoot, EvalRootSet, EvalRootSetError,
    EvalRootSource, HeapEdge, HeapEdgeSource, HeapObjectScan, InternedRootTable, PreciseHeapScan,
    StackMapSlot,
};

const PRIMOP_TYPE_TAG: u32 = 0x7072_696d;
const PRIMOP_HANDLE_BYTES: usize = std::mem::size_of::<u64>() * 4;
const PRIMOP_HANDLE_ALIGN: usize = std::mem::align_of::<u64>();

/// The suspended work stored in a tree-walk thunk heap record.
#[derive(Debug)]
pub(crate) enum EvalThunkKind {
    /// Evaluates a lowered IR body under captured lexical and dynamic scopes.
    Node {
        /// The lowered body to evaluate when forced.
        body: EvalNodeRef,
        /// Captured lexical frames.
        env: EvalEnv,
        /// Captured dynamic `with` scopes.
        with_env: EvalWithEnv,
        /// Captured scoped-import global scopes.
        scoped_globals: EvalScopedGlobalEnv,
    },
    /// Applies a forced function value to a lazy argument value.
    Apply {
        /// The IR node that produced the function.
        function: EvalNodeRef,
        /// The source span associated with the function.
        function_span: Span,
        /// The forced function value.
        function_value: Value,
        /// The IR node that produced the argument.
        argument: EvalNodeRef,
        /// The lazy argument value.
        argument_value: Value,
    },
    /// Applies a forced function value to two lazy argument values.
    Apply2 {
        /// The IR node that produced the function.
        function: EvalNodeRef,
        /// The source span associated with the function.
        function_span: Span,
        /// The function value, forced only when this thunk is forced.
        function_value: Value,
        /// The IR node associated with the first argument.
        first_argument: EvalNodeRef,
        /// The source span associated with the first argument.
        first_argument_span: Span,
        /// The first lazy argument value.
        first_argument_value: Value,
        /// The IR node associated with the second argument.
        second_argument: EvalNodeRef,
        /// The second lazy argument value.
        second_argument_value: Value,
    },
    /// Selects an attribute path from an already allocated lazy receiver.
    Select {
        /// The IR select node that defines the path and diagnostic span.
        select: EvalNodeRef,
        /// The shared lazy receiver value.
        receiver: Value,
        /// The lowered attribute path to select.
        path: IrAttrPathId,
    },
    /// Evaluates a builtin attribute value when a reified `builtins` entry is forced.
    BuiltinAttr {
        /// The selected builtin attribute symbol.
        symbol: Symbol,
        /// The selected builtin declaration.
        builtin: Builtin,
    },
}

/// A suspended tree-walk thunk heap record.
///
/// The record stores deferred tree-walk work and a serial state/result cell.
#[derive(Debug)]
pub struct EvalThunk {
    kind: EvalThunkKind,
    cell: ThunkCell,
}

/// A user lambda closure heap record.
///
/// The record stores the lowered parameter pattern and body, the resolver frame
/// used for the call's argument slots, and the lexical and dynamic `with`
/// environments captured when the lambda was constructed.
#[derive(Debug)]
pub struct EvalLambda {
    module: EvalModuleId,
    pattern: IrId,
    body: IrId,
    frame: FrameId,
    env: EvalEnv,
    with_env: EvalWithEnv,
    scoped_globals: EvalScopedGlobalEnv,
}

/// One lazy argument captured by the tree-walk `PrimopApp` equivalent.
#[derive(Clone, Copy, Debug)]
pub struct EvalPrimOpArg {
    module: EvalModuleId,
    id: IrId,
    span: Span,
    value: Value,
}

/// A builtin function or partially applied builtin heap record.
///
/// This is the tree-walk oracle's representation of the RFC `PrimopApp`
/// wrapper. Evaluator-selected records carry the selected registry declaration,
/// `symbol` preserves the source symbol used for diagnostics, and `args`
/// stores the already supplied lazy arguments. A record with fewer captured
/// arguments than the builtin's declared arity is a WHNF function value; the
/// evaluator calls the builtin only after saturation.
#[derive(Debug)]
pub struct EvalPrimOp {
    builtin: Option<Builtin>,
    symbol: Symbol,
    args: Vec<EvalPrimOpArg>,
}

/// Owns typed heap values allocated by one tree-walk evaluation.
#[derive(Debug)]
pub struct EvalHeap {
    allocator: RuntimeAllocator,
    permanent_allocator: PermanentSharedAllocator,
    records: Vec<HeapRecord>,
    string_cons: HashConsTable<HotXxh3Hash, Value>,
    path_cons: HashConsTable<HotXxh3Hash, Value>,
    list_cons: HashConsTable<HotXxh3Hash, Value>,
    attrs_cons: HashConsTable<HotXxh3Hash, Value>,
}

impl Default for EvalHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct HeapRecord {
    ptr: NonNull<HeapObject>,
    layout: HeapRecordLayout,
    structural_hash: Option<HotXxh3Hash>,
    allocation_domain: HeapAllocationDomain,
    value_hash: Cell<Option<ValueHash>>,
    captured_value_hash: Cell<Option<ValueHash>>,
    object: HeapObjectValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeapRecordLayout {
    size_bytes: usize,
    align: usize,
}

impl HeapRecordLayout {
    const fn from_allocation(allocation: ArenaAllocation) -> Self {
        Self {
            size_bytes: allocation.requested_size,
            align: allocation.align,
        }
    }
}

/// The allocation domain that owns a typed evaluator heap record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapAllocationDomain {
    /// A per-worker allocator owns the record for the current evaluation.
    Worker,
    /// Permanent shared storage owns a hash-consed reusable value record.
    PermanentShared,
}

/// The result of writing a canonical value hash onto a heap record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapValueHashCacheUpdate {
    /// The record had no cached hash and now stores the supplied hash.
    Inserted,
    /// The record already stored the same hash.
    AlreadyPresent,
}

#[derive(Debug)]
enum HeapObjectValue {
    String(NixString),
    Path(NixString),
    List(NixList),
    Attrs { shape: u32, attrs: FlatAttrs },
    Lambda(Rc<EvalLambda>),
    Primop(Rc<EvalPrimOp>),
    Thunk(Rc<EvalThunk>),
}

impl HeapObjectValue {
    const fn tag(&self) -> ValueTag {
        match self {
            Self::String(_) => ValueTag::String,
            Self::Path(_) => ValueTag::Path,
            Self::List(_) => ValueTag::List,
            Self::Attrs { .. } => ValueTag::Attrs,
            Self::Lambda(_) => ValueTag::Lambda,
            Self::Primop(_) => ValueTag::Primop,
            Self::Thunk(_) => ValueTag::Thunk,
        }
    }
}

/// A typed evaluator-heap operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalHeapError {
    /// The runtime allocator could not allocate an opaque handle.
    #[error("evaluator heap allocation error: {0}")]
    Arena(#[from] ArenaError),
    /// The heap side table length overflowed.
    #[error("evaluator heap record length overflow")]
    RecordLengthOverflow,
    /// The heap side table could not reserve space for another object.
    #[error("evaluator heap failed to reserve {records} object records")]
    RecordAllocationFailed {
        /// The requested record capacity.
        records: usize,
    },
    /// The evaluator heap cons table length overflowed.
    #[error("evaluator heap cons table length overflow")]
    ConsTableLengthOverflow,
    /// The evaluator heap cons table could not reserve space for another entry.
    #[error("evaluator heap failed to reserve {entries} cons-table entries")]
    ConsTableAllocationFailed {
        /// The requested cons-table entry count.
        entries: usize,
    },
    /// A runtime value failed a checked heap-value operation.
    #[error("heap value operation failed: {0}")]
    Value(#[from] ValueError),
    /// A heap pointer did not belong to this evaluator heap.
    #[error("unknown heap pointer for {tag:?}: 0x{address:x}")]
    UnknownPointer {
        /// The expected runtime value tag.
        tag: ValueTag,
        /// The unrecognized pointer address.
        address: usize,
    },
    /// A heap pointer belonged to this heap but referenced another typed object.
    #[error("heap record type mismatch at 0x{address:x}: expected {expected:?}, got {actual:?}")]
    RecordTypeMismatch {
        /// The expected runtime value tag.
        expected: ValueTag,
        /// The actual typed record tag.
        actual: ValueTag,
        /// The pointer address shared by the runtime value and heap record.
        address: usize,
    },
    /// A heap record already carries a different canonical value hash.
    #[error("heap value hash mismatch: existing {existing:?}, attempted {attempted:?}")]
    ValueHashMismatch {
        /// The hash already cached on the heap record.
        existing: ValueHash,
        /// The hash the caller attempted to cache.
        attempted: ValueHash,
    },
    /// Lexical environment access failed during precise root scanning.
    #[error("heap root scan environment error: {0}")]
    Environment(#[from] EvalEnvError),
    /// Thunk state access failed during precise root scanning.
    #[error("heap root scan thunk error: {0}")]
    Thunk(#[from] ForceError),
    /// Precise root scanning overflowed a side table length.
    #[error("heap root scan {table} length overflow")]
    RootScanLengthOverflow {
        /// The scanner side table being grown.
        table: &'static str,
    },
    /// Precise root scanning could not reserve side table storage.
    #[error("heap root scan failed to reserve {entries} {table} entries")]
    RootScanAllocationFailed {
        /// The scanner side table being grown.
        table: &'static str,
        /// The requested side table capacity.
        entries: usize,
    },
    /// A collector-poll heap graph snapshot no longer matches the current heap
    /// record.
    #[error("collector-poll heap graph is stale for 0x{address:x}", address = address.address_bits())]
    CollectorPollScanStaleObject {
        /// The object whose current outgoing edges differ from the snapshot.
        address: GcHeapAddress,
    },
    /// A collector-poll heap graph snapshot no longer matches the current heap
    /// allocation state.
    #[error(
        "collector-poll heap graph snapshot is stale: {reason}; record count was {expected_records}, now {actual_records}"
    )]
    CollectorPollScanStaleHeapSnapshot {
        /// The stale snapshot condition that failed.
        reason: &'static str,
        /// The typed heap record count captured by the scan.
        expected_records: usize,
        /// The current typed heap record count.
        actual_records: usize,
    },
    /// A remembered-set edge referenced an address outside this evaluator heap.
    #[error("collector-poll remembered-set {role} address does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollRememberedEdgeAddress {
        /// Whether the unknown address was the edge source or target.
        role: &'static str,
        /// The unrecognized remembered-set address.
        address: GcHeapAddress,
    },
    /// A remembered-set edge did not describe a permanent-to-young edge in the
    /// current oracle heap.
    #[error(
        "collector-poll remembered-set edge is not permanent-to-young: 0x{source:x} ({source_generation:?}) -> 0x{target:x} ({target_generation:?})",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    InvalidCollectorPollRememberedEdge {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The current generation of the source record.
        source_generation: HeapGeneration,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
        /// The current generation of the target record.
        target_generation: HeapGeneration,
    },
    /// A visible permanent-to-young edge was absent from the supplied
    /// remembered-set snapshot.
    #[error(
        "collector-poll minor-GC plan is missing remembered permanent-to-young edge: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    MissingCollectorPollRememberedEdge {
        /// The permanent source object containing the young reference.
        source_address: GcHeapAddress,
        /// The young target object that must be remembered.
        target_address: GcHeapAddress,
    },
    /// A remembered-set edge no longer matches any concrete source field.
    #[error(
        "collector-poll remembered-set edge has no current source field: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    StaleCollectorPollRememberedEdge {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
    },
    /// A planned minor-GC survivor no longer belongs to this evaluator heap.
    #[error("collector-poll minor-GC survivor address does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollSurvivorAddress {
        /// The unrecognized survivor address.
        address: GcHeapAddress,
    },
    /// A collector-poll commit application did not receive one reference value
    /// per copied reference-slot label.
    #[error(
        "collector-poll minor-GC commit reference buffer length {actual} does not match copied slot count {expected}"
    )]
    CollectorPollCommitReferenceSlotLengthMismatch {
        /// The copied allocation-poll reference-slot count.
        expected: usize,
        /// The caller-supplied reference buffer length.
        actual: usize,
    },
    /// A collector-poll commit application found a reference value that no
    /// longer matches the copied reference-slot label.
    #[error(
        "collector-poll minor-GC commit reference slot {index} expected {expected:?}, found {actual:?}"
    )]
    CollectorPollCommitReferenceSlotMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The reference value captured with the poll plan.
        expected: ResolvedValueGeneration,
        /// The caller-supplied reference value.
        actual: ResolvedValueGeneration,
    },
    /// A live reference buffer cannot be derived for copied root-only slots yet.
    #[error(
        "collector-poll minor-GC reference slot {index} is not heap-field-backed: {root_source:?}"
    )]
    CollectorPollReferenceSlotNotHeapBacked {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The copied root source that still needs external mutable storage.
        root_source: EvalRootSource,
    },
    /// A heap-field-backed reference slot no longer points at the same field.
    #[error(
        "collector-poll minor-GC reference slot {index} source mismatch: expected {expected:?}, found {actual:?}"
    )]
    CollectorPollReferenceSlotSourceMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The precise field source captured by the poll plan.
        expected: HeapEdgeSource,
        /// The current field source at the saved index, if any.
        actual: Option<HeapEdgeSource>,
    },
    /// A heap-field-backed reference slot object no longer belongs to this heap.
    #[error("collector-poll minor-GC reference slot object does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollReferenceSlotAddress {
        /// The unrecognized reference-slot object address.
        address: GcHeapAddress,
    },
    /// The generational minor-GC planner rejected the oracle snapshot.
    #[error("collector-poll minor-GC planning error: {0}")]
    GenerationalGc(#[from] GenerationalGcError),
}

impl EvalHeapError {
    fn unknown(tag: ValueTag, ptr: NonNull<HeapObject>) -> Self {
        Self::UnknownPointer {
            tag,
            address: ptr.as_ptr() as usize,
        }
    }

    fn record_type_mismatch(
        expected: ValueTag,
        actual: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Self {
        Self::RecordTypeMismatch {
            expected,
            actual,
            address: ptr.as_ptr() as usize,
        }
    }
}

impl From<HashConsError> for EvalHeapError {
    fn from(error: HashConsError) -> Self {
        match error {
            HashConsError::BucketLengthOverflow => Self::ConsTableLengthOverflow,
            HashConsError::TableAllocationFailed { entries }
            | HashConsError::BucketAllocationFailed { entries } => {
                Self::ConsTableAllocationFailed { entries }
            }
        }
    }
}

#[cfg(test)]
mod tests;
