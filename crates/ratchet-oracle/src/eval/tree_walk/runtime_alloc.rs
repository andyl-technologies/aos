//! Semantic allocation entry points used by native runtime wrappers.
//!
//! The frozen allocation ABI contains both storage-only helpers and helpers
//! whose arguments fully describe the resulting value. This module owns the
//! latter tree-walk bridge. It keeps imported native values in the transient
//! root stack while construction crosses an allocation safepoint, then returns
//! a pointer to an ordinary evaluator-owned flat object.

use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    ptr::NonNull,
};

use super::*;
use crate::value::HeapObject;

impl TreeWalk {
    /// Allocates and initializes one list cons through the evaluator heap.
    ///
    /// A null `tail` denotes the empty list. A non-null tail must identify a
    /// list owned by this evaluator. `head` and the tail handle are registered
    /// as transient roots, so a GC-stress allocation safepoint observes and
    /// rewrites them before the new flat list is published.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if the tail is not a live evaluator-owned
    /// list, temporary spine storage cannot be reserved, the flat list cannot
    /// be allocated, or GC-stress processing rejects the allocation.
    ///
    /// # Panics
    ///
    /// Resumes a panic raised by lower heap machinery after restoring the
    /// evaluator's prior active-root marker.
    pub fn alloc_runtime_cons(
        &mut self,
        id: IrId,
        span: Span,
        head: Value,
        tail: Option<NonNull<HeapObject>>,
    ) -> Result<NonNull<HeapObject>, TreeWalkError> {
        let tail = tail.map(Value::list).transpose().map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::Value(source),
                },
                span,
            )
        })?;
        let mut roots = [head, tail.unwrap_or_else(Value::null)];
        let previous_root = self.active_root_eval_node.replace(id);
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.with_indexed_transient_value_stack_roots(id, span, &mut roots, |eval, slots| {
                let rooted_head = eval.runtime_cons_root(id, span, slots.start)?;
                let rooted_tail = eval.runtime_cons_root(id, span, slots.start + 1)?;
                let tail_values = if rooted_tail.tag() == ValueTag::Null {
                    &[][..]
                } else {
                    eval.heap
                        .get_list(rooted_tail)
                        .map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                        })?
                        .as_slice()
                };
                let len = tail_values.len().checked_add(1).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: tail_values.len(),
                        },
                        span,
                    )
                })?;
                let mut values = Vec::new();
                values.try_reserve_exact(len).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
                })?;
                values.push(rooted_head);
                values.extend_from_slice(tail_values);
                let value = eval.alloc_tree_walk_list(id, span, NixList::new(values))?;
                value.as_list_ptr().map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id,
                            source: EvalHeapError::Value(source),
                        },
                        span,
                    )
                })
            })
        }));
        self.active_root_eval_node = previous_root;
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    fn runtime_cons_root(&self, id: IrId, span: Span, slot: usize) -> Result<Value, TreeWalkError> {
        self.current_transient_value_stack_root(slot)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len: slot },
                    span,
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve;
    use crate::runtime::alloc::{GcStressPolicy, RuntimeAllocationEntryPoint};
    use crate::syntax::parse_str;

    #[test]
    fn runtime_cons_builds_flat_lists_and_accepts_null_tail() {
        let resolved = resolve(parse_str("null").expect("source parses")).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        let span = ir.arena.node(ir.root).expect("root exists").span;
        let options = TreeWalkOptions::with_gc_stress_policy(GcStressPolicy::every_safepoint());
        let mut eval = TreeWalk::with_options(&ir, options);

        let tail = eval
            .alloc_runtime_cons(ir.root, span, Value::int(2), None)
            .expect("tail cons allocates");
        let list = eval
            .alloc_runtime_cons(ir.root, span, Value::int(1), Some(tail))
            .expect("head cons allocates");
        let value = Value::list(list).expect("list pointer is aligned");

        let list = eval.heap().get_list(value).expect("list resolves");
        assert!(list.get(0).is_some_and(|value| value.raw_eq(Value::int(1))));
        assert!(list.get(1).is_some_and(|value| value.raw_eq(Value::int(2))));
        assert_eq!(list.len(), 2);
        assert_eq!(eval.heap().record_count(), 0, "cons uses the flat store");
        assert_eq!(
            eval.gc_stress_permanent_root_allocation_dispatches(),
            [RuntimeAllocationEntryPoint::AosAllocList],
            "semantic cons dispatches a registered allocation safepoint"
        );
    }
}
