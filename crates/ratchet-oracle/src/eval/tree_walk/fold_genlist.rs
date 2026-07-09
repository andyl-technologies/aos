//! Fused evaluation of `builtins.foldl' op init (builtins.genList g n)`.
//!
//! When a *direct* `foldl'` primop node's list argument is itself a *direct*
//! `genList` primop application, the generated list is a pure local
//! temporary: the direct primop path evaluates the list node eagerly, clones
//! its elements, and drops the list value without ever memoizing it — no
//! binding names it, no thunk wraps it, and nothing survives the fold. The
//! only observations the program can make of that list are the ones the fold
//! loop itself performs: its length, and the demand-driven forcing of the
//! per-element `g i` apply-thunks.
//!
//! This module therefore replaces the materialize-then-fold pipeline with an
//! **index loop** that is observationally identical step for step:
//!
//! - the `genList` arguments are evaluated exactly as
//!   `eval_gen_list_primop` would (same order — length first, then the
//!   generator — same call accounting, same error identities), stopping just
//!   short of allocating the element vector and the list;
//! - each iteration allocates the *same* `g i` apply-thunk `genList` would
//!   have put at that position (same allocation-site ids and spans, so a
//!   forced element's error trace is byte-identical) and runs the *same* two
//!   interpreted applies the materialized loop runs;
//! - an element the operator never demands is simply never created, which is
//!   unobservable for the same reason an undemanded materialized thunk is
//!   never forced.
//!
//! The loop consults the tier-2 engine at most twice per fold (the
//! fused-list-generation seam, [`Tier1Engine::on_foldl_strict_genlist`]): a
//! compiled fused entry generates and folds elements entirely in native code
//! — no element thunk exists at all on that path — and a deopt at generated
//! element `k` resumes this interpreted index loop at `k`, whose re-run of
//! that element reproduces the exact tree-walk result or error.
//!
//! The fusion fires **only** on the direct-application shape. The
//! first-class path (`let fold = builtins.foldl'; in fold ...`) receives its
//! list as an already-allocated lazy value whose thunk may be shared (a
//! variable binding or a hoisted expression makes the list observable
//! elsewhere), so it keeps the materialized loop.
//!
//! [`Tier1Engine::on_foldl_strict_genlist`]: super::Tier1Engine::on_foldl_strict_genlist

use super::tier2_apply::{TIER2_FOLDL_CONSULT_FLOOR, Tier2FoldGenConsult};
use super::*;

/// A detected direct `builtins.genList generator length` list argument.
#[derive(Clone, Copy, Debug)]
pub(super) struct FoldlGenListCandidate {
    /// The generator argument node of the `genList` application.
    generator_id: IrId,
    /// The length argument node of the `genList` application.
    length_id: IrId,
}

impl TreeWalk {
    /// Detects a direct `genList` application as a fold's list argument.
    ///
    /// Returns the candidate only when `list_id` is a direct
    /// [`IrKind::PrimOp`] node whose symbol resolves to the `genList` builtin
    /// with exactly two lowered arguments — the shape whose evaluation this
    /// module replicates. Anything else (a variable reference, another
    /// expression, a shadowed or malformed primop node) falls back to the
    /// materialized fold path. Detection is pure: no evaluation, no side
    /// effects.
    pub(super) fn foldl_genlist_fusion_candidate(
        &self,
        list_id: IrId,
    ) -> Option<FoldlGenListCandidate> {
        let node = *self.node(list_id).ok()?;
        if node.kind != IrKind::PrimOp {
            return None;
        }
        let IrData::PrimOp { symbol, args } = node.data else {
            return None;
        };
        let name = self.symbols.resolve(symbol)?;
        let builtin = lookup_builtin(name)?;
        if !matches!(
            builtin.execution(),
            BuiltinExecution::StrictBinary {
                primop: StrictBinaryPrimOp::GenList,
                ..
            }
        ) {
            return None;
        }
        let args = self.current_ir().arena.child_slice(args)?;
        let [generator_id, length_id] = args else {
            return None;
        };
        Some(FoldlGenListCandidate {
            generator_id: *generator_id,
            length_id: *length_id,
        })
    }

    /// Runs a direct strict fold over a direct `genList` without a list.
    ///
    /// Byte-equivalent to `eval_foldl_strict_primop` evaluating its list
    /// argument through `eval_gen_list_primop`: the operator is already
    /// forced by the caller, the `genList` arguments are evaluated here in
    /// the interpreted order under the same `enter_call` accounting, and the
    /// element loop performs the same lazy-thunk allocation and the same two
    /// applies per element — indexed directly instead of through a
    /// materialized element vector. See the [module docs](self) for the
    /// unobservability argument.
    ///
    /// # Errors
    ///
    /// Exactly the errors of the replaced pipeline at the same evaluation
    /// points: `genList` argument type/negative-length errors, call-depth
    /// exhaustion, and any operator application or forcing error.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_foldl_strict_over_genlist(
        &mut self,
        id: IrId,
        span: Span,
        op_id: IrId,
        op_span: Span,
        op: Value,
        initial_id: IrId,
        list_id: IrId,
        candidate: FoldlGenListCandidate,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let FoldlGenListCandidate {
            generator_id,
            length_id,
        } = candidate;

        // Mirror `apply_builtin_direct`'s call accounting around the genList
        // node, then `eval_gen_list_primop`'s argument order: length first,
        // then the generator, with identical error identities.
        self.enter_call(list_id, list_span)?;
        let generated = (|| {
            let length_span = self.node(length_id)?.span;
            let length_value = self.eval_node(length_id)?;
            let length_value = self.force_value(length_id, length_span, length_value)?;
            let length = self.expect_int(length_id, length_value, length_span)?;
            let length = self.expect_non_negative_list_length(length_id, length, length_span)?;

            let generator_span = self.node(generator_id)?.span;
            let generator = self.eval_node(generator_id)?;
            let generator = self.force_callable_value(generator_id, generator_span, generator)?;
            Ok((generator, generator_span, length))
        })();
        self.leave_call();
        let (generator, generator_span, length) = generated?;

        let initial_span = self.node(initial_id)?.span;
        let mut accumulator = self.alloc_thunk_for_node(initial_id, initial_id, initial_span)?;
        if length == 0 {
            return self.eval_lazy_foldl_initial_value(initial_id, initial_span, accumulator);
        }

        // Tier-2 fused-generation seam: at most two engine consults per fold
        // (undecided operators cost two probes, never per element), and only
        // for runs long enough to recover the consult cost. A native run
        // advances the index past its generated prefix; a transient decline
        // (an unforced operator callee) runs one element interpreted so the
        // second consult can promote; a *permanent* decline — or exhausting
        // the consults with elements left — hands the remaining run to the
        // materialized fold seam below, which restores the landing-2 native
        // fold over element thunks whenever the operator alone compiles.
        let mut index = 0usize;
        let mut fold_consults = 0u32;
        while index < length {
            if self.tier1_engine.is_some() && length - index >= TIER2_FOLDL_CONSULT_FLOOR {
                if fold_consults >= 2 {
                    break;
                }
                fold_consults += 1;
                match self
                    .try_tier2_foldl_genlist(id, span, op, generator, accumulator, index, length)
                {
                    Tier2FoldGenConsult::Ran {
                        consumed,
                        accumulator: folded,
                    } => {
                        accumulator = folded;
                        index += consumed;
                        continue;
                    }
                    Tier2FoldGenConsult::Declined { permanent: true } => break,
                    Tier2FoldGenConsult::Declined { permanent: false } => {}
                }
            }
            let element = self.alloc_genlist_element_thunk(
                list_id,
                list_span,
                generator_id,
                generator_span,
                generator,
                length_id,
                index,
                length,
            )?;
            let step =
                self.apply_lambda_value(id, span, op_id, op, op_span, initial_id, accumulator)?;
            let result =
                self.apply_lambda_value(id, span, op_id, step, op_span, list_id, element)?;
            accumulator = self.force_value(op_id, op_span, result)?;
            index += 1;
        }
        if index >= length {
            return Ok(accumulator);
        }

        // Materialized tail: allocate the remaining element thunks exactly as
        // `alloc_generated_list` would (same ids and spans, same wrap) and run
        // the landing-2 fold loop over them, plain fold seam included.
        let mut elements = Vec::new();
        elements.try_reserve_exact(length - index).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: list_id,
                    len: length - index,
                },
                list_span,
            )
        })?;
        for element_index in index..length {
            elements.push(self.alloc_genlist_element_thunk(
                list_id,
                list_span,
                generator_id,
                generator_span,
                generator,
                length_id,
                element_index,
                length,
            )?);
        }
        let mut tail_index = 0usize;
        let mut tail_consults = 0u32;
        while tail_index < elements.len() {
            if tail_consults < 2 && self.tier1_engine.is_some() {
                tail_consults += 1;
                if let Some((consumed, folded)) =
                    self.try_tier2_foldl(id, span, op, accumulator, &elements[tail_index..])
                {
                    accumulator = folded;
                    tail_index += consumed;
                    continue;
                }
            }
            let element = elements[tail_index];
            let step =
                self.apply_lambda_value(id, span, op_id, op, op_span, initial_id, accumulator)?;
            let result =
                self.apply_lambda_value(id, span, op_id, step, op_span, list_id, element)?;
            accumulator = self.force_value(op_id, op_span, result)?;
            tail_index += 1;
        }

        Ok(accumulator)
    }

    /// Allocates the exact `g i` apply-thunk `genList` would put at `index`.
    ///
    /// Same allocation-site ids and spans as `alloc_generated_list`, so a
    /// forced element behaves — and fails — byte-identically.
    #[allow(clippy::too_many_arguments)]
    fn alloc_genlist_element_thunk(
        &mut self,
        list_id: IrId,
        list_span: Span,
        generator_id: IrId,
        generator_span: Span,
        generator: Value,
        length_id: IrId,
        index: usize,
        length: usize,
    ) -> Result<Value, TreeWalkError> {
        let element_index = i64::try_from(index).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id: length_id,
                    len: length,
                },
                list_span,
            )
        })?;
        self.alloc_apply_thunk(
            list_id,
            list_span,
            generator_id,
            generator_span,
            generator,
            length_id,
            Value::int(element_index),
        )
    }
}
