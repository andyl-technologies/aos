//! Fused `foldl' op acc (genList g n)` lowering: the generator in the loop.
//!
//! Landing 2's fold seam compiles the fold *operator* and pays one bare
//! native call per element — but the elements themselves are still `g i`
//! apply-thunks materialized by `builtins.genList`, so a strict fold over a
//! generated list pays one thunk allocation plus one `aos_force` round-trip
//! into the interpreter per element just to run a trivial generator body.
//! For sum-fold's 1.5M elements that forcing is ~65% of the residual wall.
//!
//! This module compiles the generator INTO the fold step: the fused inner
//! function receives `(acc, index)` instead of `(acc, element)`, emits the
//! generator's call-free body over the raw index (always an inline integer
//! supplied by the native loop), seeds the result as the operator's
//! already-forced element parameter, and then emits the operator body
//! unchanged. The native loop (see
//! `run_context_finalized_native_fold_genlist_loop` in `ratchet-runtime-ffi`)
//! then synthesizes each element from its index: no element thunk is ever
//! allocated and no force ever leaves native code.
//!
//! # Soundness
//!
//! - The generator body is validated by [`scan_tier2_pinned_callee`] with
//!   arity 1: bare formal, call-free arithmetic over its own parameter and
//!   literals only — no environment reads, no calls, no forces. Its emission
//!   is therefore *pure and effect-free*: the only exits are a value or the
//!   shared deopt block. Evaluating it eagerly — even for an element the
//!   operator never demands — is unobservable: a guard failure is a deopt
//!   (never a committed error), and the interpreted re-run of that element
//!   reproduces the tree walk's exact behavior, demanded or not.
//! - The generated element equals the value the interpreter would produce by
//!   forcing the materialized `g i` thunk: same body, same integer index
//!   argument (`builtins.genList` wraps each index as an inline int), and
//!   every non-integer intermediate deopts rather than diverging.
//!
//! [`scan_tier2_pinned_callee`]: super::scan_tier2_pinned_callee

#[cfg(not(feature = "candidate_c_value"))]
use ratchet_core::runtime_lambda_argv_call_signature;
use ratchet_core::{IrArena, IrBinding, IrId};

use super::super::JitLowerError;
#[cfg(not(feature = "candidate_c_value"))]
use super::super::verify_clif_function;
#[cfg(not(feature = "candidate_c_value"))]
use super::emit::{ChainInnerBody, build_inner_function};
use super::{JitTier2ChainLowering, JitTier2ChainScan, JitTier2PinnedCallee};
#[cfg(not(feature = "candidate_c_value"))]
use super::{JitTier2EnvBoundary, build_entry_function, inner_signature_for_arity};
#[cfg(not(feature = "candidate_c_value"))]
use crate::abi::clif_signature_for_runtime_call;

/// Lowers a fold operator fused with a `builtins.genList` generator body.
///
/// `scan` must be an arity-2 operator chain scan (the `foldl'` shape) with
/// every callee site resolved into `pinned`, and `generator_body` the
/// innermost body of the generator lambda as validated by
/// [`scan_tier2_pinned_callee`](super::scan_tier2_pinned_callee) with
/// expected arity 1. The produced lowering has the frozen argv entry ABI of
/// an ordinary arity-2 chain, but its second argument is the **element
/// index** (an inline integer), not a materialized element: only the fused
/// fold-genlist native loop may dispatch it. Environment reads in the
/// operator body translate against the operator closure's environment
/// ([`JitTier2EnvBoundary::OperatorEnv`]).
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedArithOperand`] when `scan` is not
/// arity 2 (or a body shape drifts from the scans), plus the ABI and
/// verifier errors of [`lower_tier2_curried_chain`](super::lower_tier2_curried_chain).
pub fn lower_tier2_fold_genlist(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    pinned: &[JitTier2PinnedCallee],
    generator_body: IrId,
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    // The body emitter is per-carrier codegen: this one threads (tag, payload)
    // pairs, the compressed sibling threads one-word values.
    #[cfg(feature = "candidate_c_value")]
    return super::compressed::lower_tier2_fold_genlist_compressed(
        arena,
        bindings,
        scan,
        pinned,
        generator_body,
        depth_budget,
    );
    #[cfg(not(feature = "candidate_c_value"))]
    lower_tier2_fold_genlist_two_word(arena, bindings, scan, pinned, generator_body, depth_budget)
}

/// Lowers a fold operator onto the decoded-`i64`-accumulator fold-step ABI.
///
/// The single-boundary-crossing fold variant: the compiled entry has the frozen
/// `(rt, env, acc: i64, elem) -> i64` fold-step signature, so a native fold loop
/// threads its accumulator as a plain decoded integer across every element with
/// no per-element encode/decode round-trip and no wide-accumulator boxing. Pass
/// `generator_body = Some(_)` to additionally fuse a `builtins.genList`
/// generator into the step (the element parameter is then the raw index);
/// `None` folds a materialized element run.
///
/// This lowering is one-word-carrier only: it depends on the compressed
/// carrier's decoded-core emitter (the operator body threads decoded integers),
/// which the two-word carrier does not have. On the two-word carrier the
/// accumulator already holds a full `i64` in its payload word with no boxing
/// cliff, so the ordinary value-threading fold loop is used and this lowering
/// declines.
///
/// # Errors
///
/// Returns [`JitLowerError::UnsupportedArithOperand`] when `scan` is not arity 2
/// or the operator body is not statically integer-typed, when the caller is
/// built on the two-word carrier, plus the ABI and verifier errors of the
/// compressed fold-step lowerer.
pub fn lower_tier2_fold_i64acc(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    pinned: &[JitTier2PinnedCallee],
    generator_body: Option<IrId>,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    #[cfg(feature = "candidate_c_value")]
    return super::compressed::lower_tier2_fold_i64acc_compressed(
        arena,
        bindings,
        scan,
        pinned,
        generator_body,
    );
    #[cfg(not(feature = "candidate_c_value"))]
    {
        let _ = (arena, bindings, pinned, generator_body);
        Err(JitLowerError::UnsupportedArithOperand {
            operand: scan.inner_body(),
            kind: ratchet_core::IrKind::Lambda,
        })
    }
}

/// The two-word (baseline-carrier) body of [`lower_tier2_fold_genlist`].
#[cfg(not(feature = "candidate_c_value"))]
fn lower_tier2_fold_genlist_two_word(
    arena: &IrArena,
    bindings: &[IrBinding],
    scan: &JitTier2ChainScan,
    pinned: &[JitTier2PinnedCallee],
    generator_body: IrId,
    depth_budget: i64,
) -> Result<JitTier2ChainLowering, JitLowerError> {
    if scan.arity() != 2 {
        return Err(JitLowerError::UnsupportedArithOperand {
            operand: scan.inner_body(),
            kind: ratchet_core::IrKind::Lambda,
        });
    }
    let entry_signature = clif_signature_for_runtime_call(runtime_lambda_argv_call_signature())?;
    let inner_signature = inner_signature_for_arity(&entry_signature, scan.arity());

    let (inner, self_call_count) = build_inner_function(
        arena,
        bindings,
        scan,
        inner_signature.clone(),
        None,
        pinned,
        JitTier2EnvBoundary::OperatorEnv,
        ChainInnerBody::FusedGenerator(generator_body),
    )?;
    let entry = build_entry_function(
        scan.inner_body(),
        entry_signature,
        &inner_signature,
        scan.arity(),
        depth_budget,
    )?;

    verify_clif_function(&inner)?;
    verify_clif_function(&entry)?;

    Ok(JitTier2ChainLowering {
        entry,
        inner,
        source: scan.inner_body(),
        arity: scan.arity(),
        self_upval: None,
        self_call_count,
    })
}
