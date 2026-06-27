//! Typed heap-object registry for the tree-walk evaluator.
//!
//! Runtime [`Value`] words carry opaque [`HeapObject`] pointers. This registry
//! owns the typed Rust-side objects behind those pointers for the safe tree-walk
//! oracle: the bump arena provides stable opaque handles, while a side table
//! maps those handles back to checked [`NixString`], path [`NixString`],
//! [`NixList`], [`FlatAttrs`], [`EvalLambda`], [`EvalPrimOp`], and
//! [`EvalThunk`] values.

use std::ptr::NonNull;
use std::rc::Rc;

use thiserror::Error;

use super::env::{EvalEnv, EvalScopedGlobalEnv, EvalWithEnv};
use super::module::{EvalModuleId, EvalNodeRef};
use super::thunk::ThunkCell;
use crate::attrs::FlatAttrs;
use crate::cache::HotXxh3Hash;
use crate::compile::{FrameId, IrAttrPathId, IrId};
use crate::hashcons::{HashConsError, HashConsSlot, HashConsTable};
use crate::heap::arena::{ArenaError, ArenaStats, BumpArena};
use crate::list::NixList;
use crate::runtime::builtins::Builtin;
use crate::string::NixString;
use crate::syntax::{Span, Symbol};
use crate::value::{HeapObject, Value, ValueError, ValueTag};

mod arena;
mod lambda;
mod primop;
mod thunk;

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
    arena: BumpArena,
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
    structural_hash: Option<HotXxh3Hash>,
    object: HeapObjectValue,
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
    /// The underlying bump arena could not allocate an opaque handle.
    #[error("evaluator heap arena error: {0}")]
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
