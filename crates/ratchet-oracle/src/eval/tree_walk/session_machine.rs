//! Session-wide explicit force/eval/update execution.
//!
//! The first admitted producer is the exact `genList` element-selection
//! marker. A session claims a chain of marker thunks, tail-enters each selected
//! child, and publishes the terminal result back through the update stack.
//! This establishes the ownership and unwind boundary that later `Apply`,
//! lexical-access, selection, and strict-primop instructions can share.

use super::genlist_elem_at::GenListElemAtSelected;
use super::*;

/// The retained ordinary Apply payload for one exact marker.
#[derive(Clone, Copy)]
struct MarkerWork {
    function: EvalNodeRef,
    function_span: Span,
    function_value: Value,
    argument: EvalNodeRef,
    argument_value: Value,
}

/// Result of claiming one marker onto the compact update stack.
#[derive(Clone, Copy)]
enum BeginMarkerUpdate {
    AlreadyForced(Value),
    Claimed,
}

impl TreeWalk {
    /// Forces an exact marker's selected child through one explicit session.
    ///
    /// The session is entered only from the already-admitted exact marker fast
    /// path. Nested marker children use source handles in the evaluator's
    /// scanned force-root stack as their update frames, so no Rust stack frame
    /// or borrowing force guard survives a tail entry.
    ///
    /// # Errors
    ///
    /// Returns the ordinary force, heap, marker evaluation, or publication
    /// error after aborting every still-owned marker claim in reverse order.
    ///
    /// # Panics
    ///
    /// Resumes a panic after aborting every still-owned marker claim and
    /// clearing the active-session guard.
    pub(super) fn force_genlist_selected_session(
        &mut self,
        selected: GenListElemAtSelected,
    ) -> Result<Value, TreeWalkError> {
        debug_assert!(self.options.stg_session_enabled());
        debug_assert!(!self.stg_session_active);
        let update_base = self.active_force_roots.len();
        let diagnostic_id = selected.force_id;
        let diagnostic_span = selected.force_span;
        self.stg_session_active = true;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_genlist_selected_session(selected)
        }));

        match outcome {
            Ok(Ok(value)) => {
                let result = self.publish_session_updates(
                    update_base,
                    diagnostic_id,
                    diagnostic_span,
                    value,
                );
                self.stg_session_active = false;
                result
            }
            Ok(Err(error)) => {
                self.abort_session_updates(update_base);
                self.stg_session_active = false;
                Err(error)
            }
            Err(payload) => {
                self.abort_session_updates(update_base);
                self.stg_session_active = false;
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Runs marker tail entries until a WHNF or oracle terminal is reached.
    fn run_genlist_selected_session(
        &mut self,
        selected: GenListElemAtSelected,
    ) -> Result<Value, TreeWalkError> {
        let mut id = selected.force_id;
        let mut span = selected.force_span;
        let mut value = selected.value;
        loop {
            if !value.is_thunk() || self.is_suspended_lazy_identity_thunk(id, span, value)? {
                return Ok(value);
            }

            let Some(marker) = self.session_marker_work(id, span, value)? else {
                let forced = self.force_value(id, span, value)?;
                self.heap.observe_value_identity(forced);
                self.heap.observe_value_identity(value);
                if forced.raw_eq(value) {
                    return Ok(forced);
                }
                value = forced;
                continue;
            };

            match self.begin_marker_session_update(id, span, value)? {
                BeginMarkerUpdate::AlreadyForced(forced) => {
                    value = forced;
                }
                BeginMarkerUpdate::Claimed => {
                    self.note_direct_island_force();
                    self.increment_thunks_forced();
                    match self.try_eval_genlist_elem_at_add_one_session_step(
                        id,
                        span,
                        marker.function_value,
                        marker.argument_value,
                    ) {
                        Some(Ok(selected)) => {
                            id = selected.force_id;
                            span = selected.force_span;
                            value = selected.value;
                        }
                        Some(Err(error)) => return Err(error),
                        None => {
                            value = self.eval_genlist_elem_at_add_one_oracle_body(
                                id,
                                span,
                                marker.function,
                                marker.function_span,
                                marker.function_value,
                                marker.argument,
                                marker.argument_value,
                            )?;
                        }
                    }
                }
            }
        }
    }

    /// Claims one marker and records only its source handle as an update frame.
    fn begin_marker_session_update(
        &mut self,
        id: IrId,
        span: Span,
        source: Value,
    ) -> Result<BeginMarkerUpdate, TreeWalkError> {
        let root_count = self
            .active_force_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_force_roots.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                    id,
                    roots: root_count,
                },
                span,
            )
        })?;
        let claim = {
            let thunk = self.heap.get_thunk(source).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            thunk.cell().begin_detached_force().map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
            })?
        };
        match claim {
            DetachedForceClaim::AlreadyForced(value) => {
                self.unmark_relocated_lazy_identity_thunk(source);
                self.increment_thunk_cache_hits();
                Ok(BeginMarkerUpdate::AlreadyForced(value))
            }
            DetachedForceClaim::Claimed => {
                self.active_force_roots.push(source);
                self.stg_session_marker_claims = self.stg_session_marker_claims.saturating_add(1);
                self.stg_session_max_update_depth = self
                    .stg_session_max_update_depth
                    .max(self.active_force_roots.len());
                Ok(BeginMarkerUpdate::Claimed)
            }
        }
    }

    /// Copies a marker's immutable coordinates before any force-state mutation.
    fn session_marker_work(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Option<MarkerWork>, TreeWalkError> {
        if !self.genlist_elem_at_add_one_fast_path_admitted() {
            return Ok(None);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let EvalThunkKind::GenListElemAtAddOne {
            function,
            function_span,
            function_value,
            argument,
            argument_value,
        } = thunk.kind()
        else {
            return Ok(None);
        };
        Ok(Some(MarkerWork {
            function: *function,
            function_span: *function_span,
            function_value: *function_value,
            argument: *argument,
            argument_value: *argument_value,
        }))
    }

    /// Publishes every update frame above `base` from inner to outer.
    fn publish_session_updates(
        &mut self,
        base: usize,
        id: IrId,
        span: Span,
        mut value: Value,
    ) -> Result<Value, TreeWalkError> {
        while self.active_force_roots.len() > base {
            let Some(source) = self.active_force_roots.last().copied() else {
                unreachable!("checked session force lease disappeared");
            };
            let thunk = self.heap.get_thunk(source).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut barrier = crate::eval::DisabledThunkResolveBarrier;
            value = match thunk.cell().finish_detached_force(value, &mut barrier) {
                Ok(published) => published,
                Err(source_error) => {
                    let _ = thunk.cell().abort_detached_force();
                    self.active_force_roots.pop();
                    self.abort_session_updates(base);
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::Force {
                            id,
                            source: source_error,
                        },
                        span,
                    ));
                }
            };
            self.active_force_roots.pop();
            self.unmark_relocated_lazy_identity_thunk(source);
        }
        Ok(value)
    }

    /// Aborts every update frame above `base` from inner to outer.
    fn abort_session_updates(&mut self, base: usize) {
        while self.active_force_roots.len() > base {
            let Some(source) = self.active_force_roots.last().copied() else {
                break;
            };
            let Ok(thunk) = self.heap.get_thunk(source) else {
                break;
            };
            if thunk.cell().abort_detached_force().is_err() {
                break;
            }
            self.active_force_roots.pop();
        }
    }
}
