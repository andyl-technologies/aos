//! Evaluator-owned leases for typed thunk work detached during forcing.
//!
//! Claiming a typed thunk head installs a blackhole and moves its [`EvalThunk`]
//! out of the reusable work pool. This module keeps that moved work in
//! `TreeWalk` state so precise safepoint scans never depend on a Rust local.

use std::ptr::NonNull;

use crate::eval::heap::TypedThunkWorkHandle;
use crate::value::HeapObject;

use super::*;

/// One strictly nested typed-head force whose work is detached from the pool.
#[derive(Debug)]
pub(super) struct ActiveTypedThunkWorkLease {
    /// Stable typed-head identity retained for exact restore or release.
    pub(super) head: NonNull<HeapObject>,
    /// Source value retained for evaluator identity bookkeeping.
    pub(super) source: Value,
    /// ABA-safe coordinate of the reserved work slot.
    pub(super) handle: TypedThunkWorkHandle,
    /// Authoritative suspended work while the head is blackholed.
    pub(super) work: EvalThunk,
}

impl TreeWalk {
    /// Publishes detached typed work in evaluator-owned storage.
    ///
    /// # Errors
    ///
    /// Returns the untouched work together with [`TreeWalkError`] if the lease
    /// count overflows or the evaluator cannot reserve another lease slot.
    pub(super) fn push_active_typed_thunk_work_lease(
        &mut self,
        id: IrId,
        span: Span,
        source: Value,
        head: NonNull<HeapObject>,
        handle: TypedThunkWorkHandle,
        work: EvalThunk,
    ) -> Result<(), (TreeWalkError, EvalThunk)> {
        let leases = match self.active_typed_thunk_work_leases.len().checked_add(1) {
            Some(leases) => leases,
            None => {
                return Err((
                    TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    ),
                    work,
                ));
            }
        };
        if self.active_typed_thunk_work_leases.try_reserve(1).is_err() {
            return Err((
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots: leases },
                    span,
                ),
                work,
            ));
        }
        self.active_typed_thunk_work_leases
            .push(ActiveTypedThunkWorkLease {
                head,
                source,
                handle,
                work,
            });
        Ok(())
    }

    /// Removes the innermost matching detached typed-work lease.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if the active lease stack is empty or its
    /// innermost identity does not match the force being completed.
    pub(super) fn pop_active_typed_thunk_work_lease(
        &mut self,
        id: IrId,
        span: Span,
        source: Value,
        head: NonNull<HeapObject>,
        handle: TypedThunkWorkHandle,
    ) -> Result<EvalThunk, TreeWalkError> {
        let matches = self
            .active_typed_thunk_work_leases
            .last()
            .is_some_and(|lease| {
                lease.source.raw_eq(source) && lease.head == head && lease.handle == handle
            });
        if !matches {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::TypedThunkWorkLeaseInvariant { id },
                span,
            ));
        }
        match self.active_typed_thunk_work_leases.pop() {
            Some(lease) => Ok(lease.work),
            None => Err(TreeWalkError::new(
                TreeWalkErrorKind::TypedThunkWorkLeaseInvariant { id },
                span,
            )),
        }
    }
}
