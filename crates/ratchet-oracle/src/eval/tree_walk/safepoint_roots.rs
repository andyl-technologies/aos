//! Safepoint root-set construction for the tree-walk evaluator.
//!
//! Allocation safepoints need a precise set of live heap values before a moving
//! collector can run. This module exposes the tree-walk evaluator state that is
//! already explicit in Rust data structures: active lexical frames, dynamic
//! `with` scopes, scoped-import globals, active force continuations,
//! first-class primop arguments, and permanent hash-cons roots.

use std::{
    collections::BTreeMap,
    ops::Range,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
};

use thiserror::Error;

use crate::heap::MinorGcForwardingSlot;

use crate::eval::heap::{
    AllocationCollectorPollForwardingInstallReport,
    AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    AllocationCollectorPollObjectByteCopyPlan, EvalRootSource,
};

use super::*;

const TREE_WALK_SAFEPOINT_ROOT_WRITEBACK_SLOTS_TABLE: &str =
    "tree-walk safepoint root writeback slots";

mod root_set;
mod types;
mod writeback_apply;
mod writeback_fields;
mod writeback_io;
mod writeback_validate;

pub use types::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn gc_stress_boundary_scans(
        &self,
        value: Value,
    ) -> Result<EvalGcStressBoundaryScans, TreeWalkSafepointScanError> {
        let worker = match self.current_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot)
        {
            Some(poll) => Some(self.safepoint_collector_poll_scan(poll, [value])?),
            None => None,
        };
        let permanent_shared =
            match self.current_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared) {
                Some(poll) => Some(self.safepoint_collector_poll_scan(poll, [value])?),
                None => None,
            };
        Ok(EvalGcStressBoundaryScans::new(worker, permanent_shared))
    }

    fn validate_current_collector_poll(
        &self,
        poll: AllocationCollectorPoll,
    ) -> Result<(), TreeWalkSafepointScanError> {
        let current = self.current_collector_poll_for_tier(poll.tier());
        if current == Some(poll) {
            return Ok(());
        }
        Err(TreeWalkSafepointScanError::StaleCollectorPoll { poll, current })
    }

    fn current_collector_poll_for_tier(
        &self,
        tier: RuntimeAllocatorTier,
    ) -> Option<AllocationCollectorPoll> {
        match tier {
            RuntimeAllocatorTier::TierAOneShot => self
                .heap
                .allocation_safepoints()
                .last_safepoint_collector_poll(),
            RuntimeAllocatorTier::PermanentShared => self
                .heap
                .permanent_allocation_safepoints()
                .last_safepoint_collector_poll(),
        }
    }

    pub(in crate::eval::tree_walk) fn push_active_force_root(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let roots = self
            .active_force_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        // Amortized (doubling) reservation, not `try_reserve_exact`: this stack is
        // pushed once per thunk force and pop-reused, so exact growth would
        // reallocate on every push while the stack deepens. Values and the
        // allocation-failure error are unchanged.
        self.active_force_roots.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots },
                span,
            )
        })?;
        self.active_force_roots.push(value);
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn reserve_suspended_env_root_frame(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let roots = self
            .suspended_env_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        // Amortized reservation: this frame stack is reserved once per thunk-body
        // force, so exact growth would reallocate on every deepening push.
        self.suspended_env_roots.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots },
                span,
            )
        })?;
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn push_suspended_env_roots(
        &mut self,
        env: impl Into<ActiveEvalEnv>,
        with_scopes: impl Into<EvalWithEnv>,
        scoped_globals: impl Into<EvalScopedGlobalEnv>,
    ) {
        self.suspended_env_roots.push(SuspendedTreeWalkEnv::new(
            env.into(),
            with_scopes.into(),
            scoped_globals.into(),
        ));
    }

    pub(in crate::eval::tree_walk) fn pop_suspended_env_roots(
        &mut self,
    ) -> Option<SuspendedTreeWalkEnv> {
        self.suspended_env_roots.pop()
    }

    /// Installs `new_env` as the active frames plus the captured dynamic scopes,
    /// saving the displaced state as a suspended GC root. Pair with
    /// [`Self::pop_env_scope`].
    ///
    /// When the active *and* captured `with` / scoped-global scopes are all
    /// empty — the ~100% case on real workloads (RFC-0007 instruction-tax
    /// lever 3) — installing empty over empty is a no-op, so the dynamic-scope
    /// clone and swap are skipped and empty scopes are rooted: only the env
    /// frames move. A body's own `with` / `scopedImport` reads push and pop in
    /// balance, so the active dynamic scopes are empty again when the body
    /// returns and [`Self::pop_env_scope`]'s unconditional restore writes empty
    /// over empty.
    ///
    /// The caller must have reserved a suspended-root frame
    /// ([`Self::reserve_suspended_env_root_frame`]) beforehand.
    ///
    /// # Errors
    ///
    /// Propagates the dynamic-scope clone helpers on the slow path (infallible
    /// in practice); the fast path cannot error. Cloning precedes the swap, so
    /// a clone failure leaves the active env untouched.
    pub(in crate::eval::tree_walk) fn push_env_scope(
        &mut self,
        id: IrId,
        span: Span,
        new_env: impl Into<ActiveEvalEnv>,
        captured_with: &EvalWithEnv,
        captured_scoped: &EvalScopedGlobalEnv,
    ) -> Result<(), TreeWalkError> {
        if self.with_scopes.is_empty()
            && captured_with.is_empty()
            && self.scoped_globals.is_empty()
            && captured_scoped.is_empty()
        {
            let saved_env = self.swap_env_frames(new_env);
            self.push_suspended_env_roots(
                saved_env,
                EvalWithEnv::default(),
                EvalScopedGlobalEnv::default(),
            );
            return Ok(());
        }
        let new_with = self.clone_with_scopes(id, captured_with, span)?;
        let new_scoped = self.clone_scoped_globals(id, captured_scoped, span)?;
        let saved_env = self.swap_env_frames(new_env);
        let saved_with = std::mem::replace(&mut self.with_scopes, new_with);
        let saved_scoped = std::mem::replace(&mut self.scoped_globals, new_scoped);
        self.push_suspended_env_roots(saved_env, saved_with, saved_scoped);
        Ok(())
    }

    /// Restores the env frames and dynamic scopes displaced by
    /// [`Self::push_env_scope`].
    ///
    /// Always restores — the body run reaches here on both success and error
    /// unwind — so the fast path's empty scopes are written back
    /// unconditionally, a no-op that keeps this branch identical to the slow
    /// path (the audit invariant: no control path skips a restore the swap
    /// established).
    pub(in crate::eval::tree_walk) fn pop_env_scope(&mut self) {
        if let Some(saved) = self.pop_suspended_env_roots() {
            self.restore_env_frames(saved.env);
            self.with_scopes = saved.with_scopes;
            self.scoped_globals = saved.scoped_globals;
        } else {
            debug_assert!(false, "suspended env root stack is unbalanced");
        }
    }

    pub(in crate::eval::tree_walk) fn pop_active_force_root(&mut self) -> Value {
        let Some(value) = self.active_force_roots.pop() else {
            unreachable!("active force root stack is unbalanced");
        };
        value
    }

    pub(in crate::eval::tree_walk) fn push_active_primop_arg_roots(
        &mut self,
        id: IrId,
        span: Span,
        args: &[EvalPrimOpArg],
    ) -> Result<(), TreeWalkError> {
        let arg_roots = self
            .active_primop_arg_roots
            .len()
            .checked_add(args.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        let frames = self
            .active_primop_arg_frames
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_primop_arg_roots
            .try_reserve(args.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                        id,
                        roots: arg_roots,
                    },
                    span,
                )
            })?;
        self.active_primop_arg_frames.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots: frames },
                span,
            )
        })?;

        let start = self.active_primop_arg_roots.len();
        self.active_primop_arg_roots.extend_from_slice(args);
        self.active_primop_arg_frames.push(ActivePrimopArgFrame {
            start,
            len: args.len(),
        });
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn pop_active_primop_arg_roots(&mut self) {
        let Some(frame) = self.active_primop_arg_frames.pop() else {
            debug_assert!(false, "active primop root stack is unbalanced");
            return;
        };
        debug_assert_eq!(
            self.active_primop_arg_roots.len(),
            frame.start.saturating_add(frame.len),
            "active primop root frame length is unbalanced"
        );
        self.active_primop_arg_roots.truncate(frame.start);
    }
}

fn validate_live_heap_field_writeback_count(
    live_heap_field_writebacks: usize,
    buffer_heap_field_writebacks: usize,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    if live_heap_field_writebacks != buffer_heap_field_writebacks {
        return Err(
            TreeWalkSafepointRootWritebackError::LiveHeapFieldWritebackCountMismatch {
                live_heap_field_writebacks,
                buffer_heap_field_writebacks,
            },
        );
    }

    Ok(())
}

fn validate_safepoint_source_remembered_set(
    expected: &RememberedSet,
    actual: &RememberedSet,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    if expected.epoch() != actual.epoch() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceRememberedSetEpochMismatch {
                expected: expected.epoch(),
                actual: actual.epoch(),
            },
        );
    }
    if expected.len() != actual.len() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceRememberedSetLengthMismatch {
                expected: expected.len(),
                actual: actual.len(),
            },
        );
    }
    for (index, (expected, actual)) in expected.edges().iter().zip(actual.edges()).enumerate() {
        if expected != actual {
            return Err(
                TreeWalkSafepointRootWritebackError::SourceRememberedSetEdgeMismatch {
                    index,
                    expected: *expected,
                    actual: *actual,
                },
            );
        }
    }
    Ok(())
}

fn validate_safepoint_source_card_table(
    expected: &GcCardTable,
    actual: &GcCardTable,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    if expected.card_size_bytes() != actual.card_size_bytes() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceCardTableCardSizeMismatch {
                expected: expected.card_size_bytes(),
                actual: actual.card_size_bytes(),
            },
        );
    }
    if expected.len() != actual.len() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceCardTableLengthMismatch {
                expected: expected.len(),
                actual: actual.len(),
            },
        );
    }
    for (index, (expected, actual)) in expected
        .dirty_cards()
        .iter()
        .zip(actual.dirty_cards())
        .enumerate()
    {
        if expected != actual {
            return Err(
                TreeWalkSafepointRootWritebackError::SourceCardTableDirtyCardMismatch {
                    index,
                    expected: *expected,
                    actual: *actual,
                },
            );
        }
    }
    Ok(())
}

fn root_writeback_source_unavailable(
    source: &EvalRootSource,
) -> TreeWalkSafepointRootWritebackError {
    TreeWalkSafepointRootWritebackError::SourceUnavailable {
        root_source: source.clone(),
    }
}

fn root_writeback_source_unsupported(
    source: &EvalRootSource,
) -> TreeWalkSafepointRootWritebackError {
    TreeWalkSafepointRootWritebackError::UnsupportedSource {
        root_source: source.clone(),
    }
}

fn root_writeback_frame_slot(
    source: &EvalRootSource,
    slot: usize,
) -> Result<u32, TreeWalkSafepointRootWritebackError> {
    u32::try_from(slot).map_err(|_| root_writeback_source_unavailable(source))
}

fn reverse_root_index(
    len: usize,
    depth: usize,
    source: &EvalRootSource,
) -> Result<usize, TreeWalkSafepointRootWritebackError> {
    if depth >= len {
        return Err(root_writeback_source_unavailable(source));
    }
    Ok(len - 1 - depth)
}

fn suspended_root_index(
    len: usize,
    depth: usize,
    source: &EvalRootSource,
) -> Result<usize, TreeWalkSafepointRootWritebackError> {
    reverse_root_index(len, depth, source)
}

fn active_primop_arg_root_index(
    eval: &TreeWalk,
    call_depth: usize,
    index: usize,
    source: &EvalRootSource,
) -> Result<usize, TreeWalkSafepointRootWritebackError> {
    let frame_index = reverse_root_index(eval.active_primop_arg_frames.len(), call_depth, source)?;
    let frame = eval
        .active_primop_arg_frames
        .get(frame_index)
        .ok_or_else(|| root_writeback_source_unavailable(source))?;
    if index >= frame.len {
        return Err(root_writeback_source_unavailable(source));
    }
    let root_index = frame
        .start
        .checked_add(index)
        .ok_or_else(|| root_writeback_source_unavailable(source))?;
    if root_index >= eval.active_primop_arg_roots.len() {
        return Err(root_writeback_source_unavailable(source));
    }
    Ok(root_index)
}

fn read_import_cache_root(
    import_cache: &BTreeMap<PathBuf, ImportCacheEntry>,
    index: usize,
    source: &EvalRootSource,
) -> Result<Value, TreeWalkSafepointRootWritebackError> {
    let mut ready_index = 0usize;
    for entry in import_cache.values() {
        let ImportCacheEntry::Ready { value, .. } = entry else {
            continue;
        };
        if ready_index == index {
            return Ok(*value);
        }
        ready_index = ready_index.saturating_add(1);
    }
    Err(root_writeback_source_unavailable(source))
}

fn write_import_cache_root(
    import_cache: &mut BTreeMap<PathBuf, ImportCacheEntry>,
    index: usize,
    next: Value,
    source: &EvalRootSource,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    let mut ready_index = 0usize;
    for entry in import_cache.values_mut() {
        let ImportCacheEntry::Ready { value, .. } = entry else {
            continue;
        };
        if ready_index == index {
            *value = next;
            return Ok(());
        }
        ready_index = ready_index.saturating_add(1);
    }
    Err(root_writeback_source_unavailable(source))
}
