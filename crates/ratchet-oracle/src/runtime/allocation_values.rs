//! Safe semantic allocation helpers shared by evaluator execution tiers.
//!
//! Storage reservation alone is insufficient for an evaluator value: the heap
//! must initialize the payload, register its edges, preserve transient roots,
//! and return the active representation's object address. Helpers in this
//! module accept the complete frozen ABI payload and delegate those obligations
//! to the tree-walk heap.

use std::ptr::NonNull;

use crate::compile::IrId;
use crate::eval::tree_walk::{TreeWalk, TreeWalkError};
use crate::syntax::Span;
use crate::value::{HeapObject, Value};

/// Allocates and initializes the semantic list represented by one cons cell.
///
/// A null `tail` represents the empty list. The returned pointer identifies an
/// ordinary evaluator-owned, hash-consed flat list; callers do not receive the
/// obsolete storage-only arena reservation used by the precursor metadata.
///
/// # Errors
///
/// Returns [`TreeWalkError`] when the tail is not an evaluator-owned list,
/// allocation fails, or an allocation safepoint cannot preserve the imported
/// values.
///
/// # Panics
///
/// Resumes a panic raised by lower heap machinery after evaluator allocation
/// state has been restored.
pub fn rust_callable_aos_alloc_cons(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    head: Value,
    tail: Option<NonNull<HeapObject>>,
) -> Result<NonNull<HeapObject>, TreeWalkError> {
    eval.alloc_runtime_cons(id, span, head, tail)
}
