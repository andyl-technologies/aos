//! Mutating forced-thunk collapse (RFC-0007 doc 31 §1 step 3, increment 4).
//!
//! A forced thunk already holds its computed value in its cell; the thunk
//! object is a wrapper. This capture-time pre-pass — off the normal eval path,
//! run on a quiesced serial heap that will only be captured afterwards —
//! rewrites every reachable `Value` word that points at a forced thunk to the
//! thunk's cached value, and sheds each collapsed wrapper's deferred work and
//! captured environments ([`EvalThunk::released_forced`], the Tier-B shed
//! representation). The census measured the collapse clean on the real prelude
//! (0 chains, 0 unknowns), so the pass is single-pass — but cleanliness is an
//! empirical fact, not an invariant: a forced thunk whose cached value is
//! itself a thunk, or whose cell holds no classifiable value, **refuses** the
//! collapse rather than mis-collapsing.
//!
//! Rewritten word locations:
//!
//! - environment frame slots (shared `Arc<EvalFrame>`s, deduplicated) — safe
//!   atomic slot stores;
//! - list element spines (out-of-arena `Vec`s) and attrset entry runs (arena
//!   inline, through the reviewed [`FlatAttrs::rewrite_entry_values`] door);
//!   both recompute the structural-hash header afterwards so the dumped image
//!   carries a hash consistent with its contents;
//! - closure payload value fields (apply/apply2/select thunk operands,
//!   `with`-scope and scoped-global stacks, primop applied arguments) and each
//!   closure's inline capture value tail.
//!
//! An `Arc`-shared thunk whose handle is aliased cannot be rewritten in place
//! and is skipped (counted): a missed rewrite is only a missed optimization,
//! never a correctness gap, because a forced thunk also *serializes* as its
//! cached value (the collapsed-thunk closure payload) and restores as a
//! released forced wrapper.
//!
//! After the pass the heap must not be evaluated further except through
//! capture/restore: hash-cons table buckets keyed by the pre-collapse hashes
//! are stale (raw-equality confirmation keeps them correct but dedup may
//! miss), and the shed wrappers no longer carry their deferred work.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::eval::env::EvalFrame;
use crate::eval::thunk::ThunkState;
use crate::heap::flat::FlatObjectKind;
use crate::list::NixList;
use crate::value::{Value, ValueTag};

use super::super::arena::{attrs_structural_hash, list_structural_hash};
use super::super::{EvalHeap, EvalThunk, EvalThunkKind, FlatClosurePayload};
use super::EvalHeapSnapshotError;

/// What one [`EvalHeap::collapse_forced_thunks`] pass did, for tests and the
/// campaign's honest accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ForcedThunkCollapseReport {
    /// Forced thunk wrappers whose deferred work and captures were shed.
    pub thunks_collapsed: u64,
    /// Forced thunks left unshed because their force storage is not
    /// serial-only (a parallel payload cell other workers may claim through).
    pub shared_thunks_skipped: u64,
    /// Environment frame slots rewritten to cached values.
    pub frame_slots_rewritten: u64,
    /// List elements rewritten (their lists' structural hashes recomputed).
    pub list_elements_rewritten: u64,
    /// Attrset entries rewritten (their attrs' structural hashes recomputed).
    pub attrs_entries_rewritten: u64,
    /// Closure payload value fields rewritten (thunk operands, `with` scopes,
    /// scoped globals, primop arguments).
    pub closure_fields_rewritten: u64,
    /// Inline capture-tail values rewritten.
    pub tail_values_rewritten: u64,
}

impl EvalHeap {
    /// Collapses every forced thunk before heap-image capture (RFC-0007
    /// doc 31 §1 step-3 increment 4).
    ///
    /// See the module docs for what is rewritten and the quiesced-heap /
    /// capture-only-afterwards contract.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::ParallelMode`] for a shared heap,
    /// [`EvalHeapSnapshotError::ForcedThunkChain`] when a forced thunk's
    /// cached value is itself a thunk, and
    /// [`EvalHeapSnapshotError::UnsnapshottableThunkState`] for an in-flight,
    /// poisoned, or value-less forced cell — the collapse refuses rather than
    /// mis-collapsing, per the census's chain/unknown cleanliness being an
    /// empirical measurement rather than an invariant.
    pub(crate) fn collapse_forced_thunks(
        &mut self,
    ) -> Result<ForcedThunkCollapseReport, EvalHeapSnapshotError> {
        if self.shared.is_some() {
            return Err(EvalHeapSnapshotError::ParallelMode);
        }
        let mut report = ForcedThunkCollapseReport::default();

        // Pass 1 (read-only): classify every thunk, refusing on a chain or an
        // unclassifiable cell, and build the collapse map.
        let mut map: HashMap<usize, Value> = HashMap::new();
        let mut shed: Vec<(
            std::ptr::NonNull<crate::value::HeapObject>,
            u32,
            Value,
            bool,
        )> = Vec::new();
        for object in self.flat_closures.iter() {
            // No wildcard arm: a new closure payload class must decide its
            // collapse treatment explicitly (the default-deny discipline).
            let thunk = match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => thunk,
                FlatClosurePayload::SharedThunk(thunk) => &**thunk,
                FlatClosurePayload::Lambda(_)
                | FlatClosurePayload::Primop(_)
                | FlatClosurePayload::Retired(_) => continue,
            };
            let index = self
                .flat_arena
                .index_for_pointer(object.ptr())
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?
                .raw();
            match thunk.cell().state() {
                Ok(ThunkState::Suspended) => {}
                Ok(ThunkState::Forced) => match thunk.cell().cached_value() {
                    Ok(Some(value)) if value.tag() == ValueTag::Thunk => {
                        return Err(EvalHeapSnapshotError::ForcedThunkChain { index });
                    }
                    Ok(Some(value)) => {
                        map.insert(object.ptr().as_ptr() as usize, value);
                        // `Arc`-shared handles shed too: the payload swap drops
                        // the heap's handle while any alias keeps the old
                        // forced record alive independently (plain `Arc`
                        // semantics) — only parallel force storage, whose cell
                        // other workers may still claim through, is skipped.
                        let sheddable = thunk.has_serial_only_force_storage();
                        shed.push((object.ptr(), index, value, sheddable));
                    }
                    _ => {
                        return Err(EvalHeapSnapshotError::UnsnapshottableThunkState { index });
                    }
                },
                Ok(ThunkState::Blackhole) | Err(_) => {
                    return Err(EvalHeapSnapshotError::UnsnapshottableThunkState { index });
                }
            }
        }
        if map.is_empty() {
            return Ok(report);
        }
        let rewrite = |value: Value| -> Option<Value> {
            if value.tag() != ValueTag::Thunk {
                return None;
            }
            let ptr = value.as_thunk_ptr().ok()?;
            map.get(&(ptr.as_ptr() as usize)).copied()
        };

        // Pass 2: shed the collapsed wrappers first, so environments retained
        // only by forced thunks drop and are neither rewritten nor captured.
        for (ptr, index, value, sheddable) in &shed {
            if *sheddable {
                self.flat_swap_thunk_payload(*ptr, EvalThunk::released_forced(*value))
                    .map_err(|_| EvalHeapSnapshotError::UnsnapshottableThunkState {
                        index: *index,
                    })?;
                report.thunks_collapsed += 1;
            } else {
                report.shared_thunks_skipped += 1;
            }
        }

        // Pass 3: rewrite every reachable word class.
        report.frame_slots_rewritten = self.collapse_env_frames(&rewrite)?;
        report.list_elements_rewritten = self.collapse_list_elements(&rewrite)?;
        report.attrs_entries_rewritten = self.collapse_attrs_entries(&rewrite)?;
        let (fields, tails) = self.collapse_closure_fields(&rewrite)?;
        report.closure_fields_rewritten = fields;
        report.tail_values_rewritten = tails;
        Ok(report)
    }

    /// Rewrites collapsed words in every closure-captured frame slot.
    fn collapse_env_frames(
        &self,
        rewrite: &dyn Fn(Value) -> Option<Value>,
    ) -> Result<u64, EvalHeapSnapshotError> {
        let mut seen: HashSet<*const EvalFrame> = HashSet::new();
        let mut frames: Vec<Arc<EvalFrame>> = Vec::new();
        for object in self.flat_closures.iter() {
            let env = match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => thunk.env(),
                FlatClosurePayload::SharedThunk(thunk) => thunk.env(),
                FlatClosurePayload::Lambda(lambda) => Some(lambda.env()),
                FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => None,
            };
            if let Some(env) = env {
                for frame in env.frames().iter() {
                    if seen.insert(Arc::as_ptr(frame)) {
                        frames.push(Arc::clone(frame));
                    }
                }
            }
        }
        let mut rewritten = 0;
        for frame in frames {
            let slots = frame
                .slot_values()
                .map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
            for (slot, value) in slots.iter().enumerate() {
                if let Some(replacement) = rewrite(*value) {
                    frame
                        .set(slot as u32, replacement)
                        .map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
                    rewritten += 1;
                }
            }
        }
        Ok(rewritten)
    }

    /// Rewrites collapsed words in every list spine, repairing its hash.
    fn collapse_list_elements(
        &mut self,
        rewrite: &dyn Fn(Value) -> Option<Value>,
    ) -> Result<u64, EvalHeapSnapshotError> {
        let ptrs: Vec<_> = self.flat_lists.iter().map(|object| object.ptr()).collect();
        let mut rewritten = 0;
        for ptr in ptrs {
            let list = self
                .flat_lists
                .resolve_mut(ptr, FlatObjectKind::List)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            let mut changed = 0;
            let mut elements = list.as_slice().to_vec();
            for element in &mut elements {
                if let Some(replacement) = rewrite(*element) {
                    *element = replacement;
                    changed += 1;
                }
            }
            if changed == 0 {
                continue;
            }
            *list = NixList::new(elements);
            let hash = list_structural_hash(list);
            self.flat_lists
                .update_structural_hash(ptr, FlatObjectKind::List, hash.raw())
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            rewritten += changed;
        }
        Ok(rewritten)
    }

    /// Rewrites collapsed words in every attrset entry run, repairing its hash.
    fn collapse_attrs_entries(
        &mut self,
        rewrite: &dyn Fn(Value) -> Option<Value>,
    ) -> Result<u64, EvalHeapSnapshotError> {
        let ptrs: Vec<_> = self.flat_attrs.iter().map(|object| object.ptr()).collect();
        let mut rewritten = 0;
        for ptr in ptrs {
            let payload = self
                .flat_attrs
                .resolve_mut(ptr, FlatObjectKind::Attrs)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            let changed = payload
                .attrs
                .rewrite_entry_values(&mut |value| rewrite(value));
            if changed == 0 {
                continue;
            }
            let hash = attrs_structural_hash(payload.metadata, &payload.attrs);
            self.flat_attrs
                .update_structural_hash(ptr, FlatObjectKind::Attrs, hash.raw())
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            rewritten += changed as u64;
        }
        Ok(rewritten)
    }

    /// Rewrites collapsed words in closure payload fields and capture tails.
    fn collapse_closure_fields(
        &mut self,
        rewrite: &dyn Fn(Value) -> Option<Value>,
    ) -> Result<(u64, u64), EvalHeapSnapshotError> {
        let objects: Vec<_> = self
            .flat_closures
            .iter()
            .map(|object| (object.ptr(), object.object().payload().tag()))
            .collect();
        let mut fields = 0;
        let mut tails = 0;
        for (ptr, tag) in objects {
            let kind = match tag {
                ValueTag::Thunk => FlatObjectKind::Thunk,
                ValueTag::Lambda => FlatObjectKind::Lambda,
                ValueTag::Primop => FlatObjectKind::Primop,
                // Retired slots resolve under their original kind; they hold
                // no live payload values, so skip them entirely.
                _ => continue,
            };
            let payload = self
                .flat_closures
                .resolve_mut(ptr, kind)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            fields += collapse_payload_fields(payload, rewrite);
            let (_, tail) = self
                .flat_closures
                .resolve_mut_with_value_tail(ptr, kind)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            if let Some(tail) = tail {
                for value in tail {
                    if let Some(replacement) = rewrite(*value) {
                        *value = replacement;
                        tails += 1;
                    }
                }
            }
        }
        Ok((fields, tails))
    }
}

/// Rewrites the value fields of one closure payload; returns the change count.
fn collapse_payload_fields(
    payload: &mut FlatClosurePayload,
    rewrite: &dyn Fn(Value) -> Option<Value>,
) -> u64 {
    let mut changed = 0;
    let mut apply = |value: &mut Value| {
        if let Some(replacement) = rewrite(*value) {
            *value = replacement;
            changed += 1;
        }
    };
    match payload {
        FlatClosurePayload::Thunk(thunk) => {
            collapse_thunk_fields(thunk, &mut apply);
        }
        FlatClosurePayload::SharedThunk(shared) => {
            // An aliased shared handle cannot be rewritten in place; the
            // collapsed-thunk serialization keeps a missed rewrite correct.
            if let Some(thunk) = Arc::get_mut(shared) {
                collapse_thunk_fields(thunk, &mut apply);
            }
        }
        FlatClosurePayload::Lambda(lambda) => {
            drop(apply);
            changed += collapse_scope_stacks(
                Some(&mut lambda.with_env),
                Some(&mut lambda.scoped_globals),
                rewrite,
            );
            return changed;
        }
        FlatClosurePayload::Primop(primop) => {
            for argument in &mut primop.args {
                apply(&mut argument.value);
            }
        }
        FlatClosurePayload::Retired(_) => {}
    }
    drop(apply);
    // Thunk node kinds also carry `with`/scoped-global stacks.
    if let FlatClosurePayload::Thunk(thunk) = payload {
        if let EvalThunkKind::Node {
            with_env,
            scoped_globals,
            ..
        } = &mut thunk.kind
        {
            changed += collapse_scope_stacks(Some(with_env), Some(scoped_globals), rewrite);
        }
    }
    changed
}

/// Rewrites one thunk's operand value fields through `apply`.
fn collapse_thunk_fields(thunk: &mut EvalThunk, apply: &mut dyn FnMut(&mut Value)) {
    match &mut thunk.kind {
        EvalThunkKind::Apply {
            function_value,
            argument_value,
            ..
        } => {
            apply(function_value);
            apply(argument_value);
        }
        EvalThunkKind::Apply2 {
            function_value,
            first_argument_value,
            second_argument_value,
            ..
        } => {
            apply(function_value);
            apply(first_argument_value);
            apply(second_argument_value);
        }
        EvalThunkKind::Select { receiver, .. } => apply(receiver),
        EvalThunkKind::Node { .. }
        | EvalThunkKind::BuiltinAttr { .. }
        | EvalThunkKind::Released => {}
    }
}

/// Rewrites `with`-scope and scoped-global stack values; returns the count.
fn collapse_scope_stacks(
    with_env: Option<&mut crate::eval::env::EvalWithEnv>,
    scoped_globals: Option<&mut crate::eval::env::EvalScopedGlobalEnv>,
    rewrite: &dyn Fn(Value) -> Option<Value>,
) -> u64 {
    let mut changed = 0;
    if let Some(with_env) = with_env {
        let replacements: Vec<(usize, Value)> = with_env
            .scopes()
            .iter()
            .enumerate()
            .filter_map(|(index, scope)| rewrite(scope.value()).map(|value| (index, value)))
            .collect();
        for (index, value) in replacements {
            if with_env.replace_value(index, value) {
                changed += 1;
            }
        }
    }
    if let Some(scoped_globals) = scoped_globals {
        let replacements: Vec<(usize, Value)> = scoped_globals
            .scopes()
            .iter()
            .enumerate()
            .filter_map(|(index, value)| rewrite(*value).map(|value| (index, value)))
            .collect();
        for (index, value) in replacements {
            if scoped_globals.replace_value(index, value) {
                changed += 1;
            }
        }
    }
    changed
}
