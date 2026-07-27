//! Safe orchestration of a registered native thunk call.
//!
//! `ratchet-jit` exposes the native thunk-call boundary as an `unsafe fn`: the
//! caller must supply valid runtime-context and environment pointers plus
//! candidate wrapper addresses that match the compiled artifact's imports. This
//! module wraps that boundary in a single reviewed `unsafe` block and hands
//! callers a safe API instead.
//!
//! The wrapper owns the pieces that make the call sound:
//!
//! - it pins a [`RuntimeJitContext`] over the caller's evaluator and derives the
//!   `rt` pointer the forcing/attr wrappers decode,
//! - it carries the caller's hybrid [`EvalEnv`] in that pinned context and
//!   passes the same opaque pointer through the frozen `env` ABI slot, and
//! - it installs a [`RuntimeTrapScope`] for the duration of the call so a forcing
//!   evaluator error is transferred out as a [`RuntimeTrap`] instead of aborting.
//!
//! Safe crates that forbid `unsafe` (such as `aos-nix`) can build the artifact,
//! candidates, evaluator, and frame themselves and then run the compiled body
//! through [`run_registered_native_thunk_call`].

use ratchet_jit::{
    JitClifArtifact, JitCraneliftNativeCallError,
    JitCraneliftRegisteredArtifactFinalizationPreflight, JitModuleContextFinalizedBody,
    JitRuntimeSymbolAddressCandidate, JitValueAbi,
    jit_cranelift_call_context_finalized_candidate_b_thunk_entry,
    jit_cranelift_call_context_finalized_candidate_c_thunk_entry,
    jit_cranelift_call_context_finalized_fold_step_i64acc_entry,
    jit_cranelift_call_context_finalized_lambda_argv_entry,
    jit_cranelift_call_context_finalized_lambda_entry,
    jit_cranelift_call_context_finalized_thunk_entry, jit_cranelift_call_finalized_thunk_entry,
    jit_cranelift_registered_artifact_finalization_preflight_with_candidates,
};
use ratchet_oracle::value::Value;
use ratchet_oracle::{compile::IrId, eval::EvalEnv, eval::tree_walk::TreeWalk, syntax::Span};

use crate::context::RuntimeJitContext;
use crate::trap::{RuntimeTrap, RuntimeTrapScope};

mod value_abi;
use value_abi::NativeThunkReturn;
mod outcomes;
pub use outcomes::*;

/// Finalizes and runs one registered native thunk artifact against `eval`.
///
/// The compiled artifact is a thunk body that reads a captured slot from `frame`
/// and forces it through the runtime-FFI wrappers named by `candidates`. The
/// call runs under a fresh [`RuntimeTrapScope`], so a forcing evaluator error is
/// returned as a [`NativeThunkCallOutcome`] whose `trap` is `Some` rather than
/// aborting the process. `id` and `span` seed the [`RuntimeJitContext`] used by
/// the forcing wrappers to report failures.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the artifact cannot be finalized
/// against the supplied candidates, the host lacks a supported native value ABI,
/// the artifact is not a thunk body, or the compiled body returns a value whose
/// payload violates the runtime layout.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`].
pub fn run_registered_native_thunk_call(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let finalization = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact, candidates,
    )
    .map_err(|source| JitCraneliftNativeCallError::FinalizeArtifact { source })?;
    run_finalized_native_thunk_call(eval, id, span, env, &finalization)
}

/// Runs a pre-finalized native thunk artifact against `eval`.
///
/// This mirrors [`run_registered_native_thunk_call`] but takes an artifact that
/// has already been lowered, finalized, and had its runtime symbols registered
/// into an owned [`JitCraneliftRegisteredArtifactFinalizationPreflight`]. The
/// tier-1 publish path uses this so a promoted artifact is finalized once at
/// install time and then dispatched repeatedly without re-running Cranelift
/// module setup on every call. The borrowed `finalization` pins the finalized
/// code memory for the duration of the call.
///
/// Like the registered path, the call runs under a fresh [`RuntimeTrapScope`] so
/// a forcing evaluator error is returned as a [`NativeThunkCallOutcome`] whose
/// `trap` is `Some` rather than aborting the process. `id` and `span` seed the
/// [`RuntimeJitContext`] used by the forcing wrappers to report failures.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported native
/// value ABI, the finalized artifact is not a thunk body, or the compiled body
/// returns a value whose payload violates the runtime layout.
pub fn run_finalized_native_thunk_call(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    finalization: &JitCraneliftRegisteredArtifactFinalizationPreflight,
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let stack_maps = finalization.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    // SAFETY: `rt` comes from the pinned context over `eval` and `env` from the
    // live `frame`; the borrowed `finalization` keeps its registered frozen-ABI
    // wrappers and finalized code alive, and the scope converts a forcing trap.
    let dispatched = unsafe { jit_cranelift_call_finalized_thunk_entry(finalization, rt, env) };
    match dispatched {
        Ok(value) => {
            let trap = scope.take_trap();
            drop(scope);
            drop(context);
            Ok(NativeThunkCallOutcome { value, trap })
        }
        Err(error) => {
            drop(scope);
            Err(error)
        }
    }
}

/// Runs a native thunk body finalized into a shared [`JitModuleContext`].
///
/// This mirrors [`run_finalized_native_thunk_call`] but dispatches a body compiled
/// into a shared module context rather than one that owns its own module. The
/// batched tier-1 publish path uses it so many promoted bodies share a single
/// Cranelift module, paying its setup once. The borrowed `body` reads a code
/// pointer into the shared module, which the caller keeps alive for the call (the
/// tier-1 engine holds the owning context and each dispatch entry keeps a
/// keep-alive handle).
///
/// Like the other paths, the call runs under a fresh [`RuntimeTrapScope`] so a
/// forcing evaluator error is returned as a [`NativeThunkCallOutcome`] whose `trap`
/// is `Some` rather than aborting. `id` and `span` seed the [`RuntimeJitContext`]
/// the forcing wrappers use to report failures.
///
/// [`JitModuleContext`]: ratchet_jit::JitModuleContext
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported native
/// value ABI, the finalized body is not a thunk body, or the compiled body returns
/// a value whose payload violates the runtime layout.
pub fn run_context_finalized_native_thunk_call(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    let native_return = match body.artifact().value_abi() {
        // The Candidate-B one-word return ABI is gone under the `candidate_c_value`
        // carrier (its heap bridge decode does not exist there), so a Candidate-B
        // artifact can never dispatch; keep the match exhaustive with a value-ABI
        // mismatch rather than the Candidate-B path.
        #[cfg(feature = "candidate_c_value")]
        JitValueAbi::CandidateB => Err(JitCraneliftNativeCallError::UnsupportedArtifactValueAbi {
            expected: JitValueAbi::CandidateC,
            actual: JitValueAbi::CandidateB,
        }),
        #[cfg(not(feature = "candidate_c_value"))]
        JitValueAbi::CandidateB => {
            // SAFETY: `rt` comes from the pinned context over `eval`; the current
            // Candidate-B literal body ignores raw inputs, and the caller keeps the
            // shared module context that finalized `body` alive across the call.
            unsafe { jit_cranelift_call_context_finalized_candidate_b_thunk_entry(body, rt, env) }
                .map(NativeThunkReturn::CandidateB)
        }
        JitValueAbi::CandidateC => {
            // SAFETY: `rt` comes from the pinned context over `eval`; the current
            // Candidate-C literal body ignores raw inputs, and the caller keeps the
            // shared module context that finalized `body` alive across the call.
            unsafe { jit_cranelift_call_context_finalized_candidate_c_thunk_entry(body, rt, env) }
                .map(NativeThunkReturn::CandidateC)
        }
        JitValueAbi::Active => {
            // SAFETY: `rt` comes from the pinned context over `eval` and `env` from
            // the live frame; the caller keeps the shared module context alive, so
            // its frozen-ABI wrappers and finalized code stay live for the call.
            unsafe { jit_cranelift_call_context_finalized_thunk_entry(body, rt, env) }
                .map(NativeThunkReturn::Active)
        }
    };
    let trap = scope.take_trap();
    drop(scope);
    drop(context);
    match native_return {
        Ok(native_return) => Ok(NativeThunkCallOutcome {
            value: native_return.into_active(eval.heap(), body)?,
            trap,
        }),
        Err(error) => Err(error),
    }
}

/// Runs a tier-2 lambda entry finalized into a shared [`JitModuleContext`].
///
/// This mirrors [`run_context_finalized_native_thunk_call`] for the frozen
/// lambda-call ABI: the compiled entry receives the runtime context, the
/// dispatcher-owned environment, and the applied `argument` (which may still be
/// a suspended thunk — the compiled body forces it at its first strict use,
/// exactly where the tree walk would). The call runs under a fresh
/// [`RuntimeTrapScope`], so both an evaluator error transferred by a forcing
/// wrapper and a compiled-body deopt (guard failure, exhausted depth budget)
/// come back as a [`NativeThunkCallOutcome`] whose `trap` is `Some`; the
/// dispatcher treats any trap as a deopt and re-runs the call through the tree
/// walk.
///
/// [`JitModuleContext`]: ratchet_jit::JitModuleContext
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI, the finalized body is not a tier-2 lambda entry, or the
/// compiled body returns a value whose payload violates the runtime layout.
pub fn run_context_finalized_native_lambda_call(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    argument: Value,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    // SAFETY: `rt` is the pinned context over `eval`, `env` the caller-owned
    // environment clone, `argument` a live value on `eval`'s heap; the caller
    // keeps `body`'s module alive and the scope converts errors/deopts to traps.
    let lambda_dispatched =
        unsafe { jit_cranelift_call_context_finalized_lambda_entry(body, rt, env, argument) };
    match lambda_dispatched {
        Ok(value) => {
            let trap = scope.take_trap();
            drop(scope);
            drop(context);
            Ok(NativeThunkCallOutcome { value, trap })
        }
        Err(error) => {
            drop(scope);
            Err(error)
        }
    }
}

/// Runs a tier-2 fused chain entry finalized into a shared [`JitModuleContext`].
///
/// This mirrors [`run_context_finalized_native_lambda_call`] for the frozen
/// multi-argument `argv` entry ABI: the compiled entry receives the runtime
/// context, the dispatcher-owned environment, and a pointer to the caller's
/// contiguous run of chain arguments (`argv`, outermost chain parameter first;
/// each may still be a suspended thunk — the compiled body forces it at its
/// first strict use). The call runs under a fresh [`RuntimeTrapScope`], so
/// both a forcing evaluator error and a compiled-body deopt come back as an
/// outcome whose `trap` is `Some`; the dispatcher treats any trap as a deopt
/// and re-runs the boundary application through the tree walk.
///
/// [`JitModuleContext`]: ratchet_jit::JitModuleContext
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI, the finalized body is not a tier-2 chain entry of arity
/// `argv.len()`, or the compiled body returns a value whose payload violates
/// the runtime layout.
pub fn run_context_finalized_native_chain_call(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    argv: &[Value],
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    // SAFETY: `rt` is the pinned context over `eval`, `env` the caller-owned
    // environment clone, every `argv` element a live value on `eval`'s heap;
    // the caller keeps `body`'s module alive and the scope converts traps.
    let chain_call =
        unsafe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, argv) };
    match chain_call {
        Ok(value) => {
            let trap = scope.take_trap();
            drop(scope);
            drop(context);
            Ok(NativeThunkCallOutcome { value, trap })
        }
        Err(error) => {
            drop(scope);
            Err(error)
        }
    }
}

/// Runs a compiled arity-2 fold operator natively over an element run.
///
/// This is the lean per-element boundary for the tier-2 fold seam: the
/// [`RuntimeJitContext`] pin and the [`RuntimeTrapScope`] are set up **once**
/// for the whole run, and each element costs one native call through the
/// frozen `argv` entry ABI plus one thread-local trap probe — none of the
/// per-dispatch environment cloning the generic apply boundary pays. The
/// accumulator starts as `initial` (which may be a suspended thunk; the
/// compiled body forces it at first strict use, exactly like the interpreted
/// first iteration) and each element's native result becomes the next
/// accumulator.
///
/// Any transferred trap — a compiled-body deopt or a forcing evaluator error
/// while folding element `k` — stops the loop with `consumed == k`; the
/// caller re-runs that element interpreted (see [`NativeFoldLoopOutcome`]).
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI, the finalized body is not a tier-2 chain entry of arity
/// 2, or a compiled call returns a value whose payload violates the runtime
/// layout.
pub fn run_context_finalized_native_fold_loop(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    initial: Value,
    elements: &[Value],
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFoldLoopOutcome, JitCraneliftNativeCallError> {
    run_native_fold_loop(
        eval,
        id,
        span,
        env,
        initial,
        FoldElementSource::Slice(elements),
        body,
    )
}

/// Runs a fused fold-generator entry natively over a `genList` index range.
///
/// This is the fused-list-generation boundary: the compiled entry was lowered
/// by `lower_tier2_fold_genlist`, so its second `argv` value is the **element
/// index** and the generator body runs inside the native step — no element
/// thunk exists anywhere. The loop covers indices `start_index ..
/// start_index + run_len` and otherwise behaves exactly like
/// [`run_context_finalized_native_fold_loop`]: context pin and trap scope are
/// set up once, each index costs one bare native call plus one thread-local
/// trap probe, and any trap while folding the element at offset `k` stops the
/// loop with `consumed == k` so the caller re-runs that element interpreted
/// (materializing its `g i` apply-thunk exactly as `builtins.genList` would).
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI, the finalized body is not a tier-2 chain entry of arity
/// 2, or a compiled call returns a value whose payload violates the runtime
/// layout.
pub fn run_context_finalized_native_fold_genlist_loop(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    initial: Value,
    start_index: usize,
    run_len: usize,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFoldLoopOutcome, JitCraneliftNativeCallError> {
    run_native_fold_loop(
        eval,
        id,
        span,
        env,
        initial,
        FoldElementSource::GenIndices {
            start: start_index,
            len: run_len,
        },
        body,
    )
}

/// Runs a fold operator natively over an element run with a decoded `i64`
/// accumulator.
///
/// The single-boundary-crossing counterpart of
/// [`run_context_finalized_native_fold_loop`]: `body` must be a fold-step entry
/// (lowered by `lower_tier2_fold_i64acc`), and the accumulator is threaded as a
/// plain decoded `i64` across every element — no per-element encode/decode
/// round-trip and no wide-accumulator boxing, so an accumulator that grows past
/// the inline range keeps folding natively. `initial_acc` is the decoded initial
/// accumulator; the caller re-encodes the returned accumulator to a runtime
/// value exactly once (on both the full-run and deopt paths).
///
/// Any transferred trap — a compiled-body deopt (for example a wide or
/// non-integer element the step could not decode) or a forcing evaluator error
/// while folding element `k` — stops the loop with `consumed == k`; the caller
/// re-runs that element interpreted (see [`NativeFoldI64AccLoopOutcome`]).
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI or the finalized body is not a fold-step entry.
pub fn run_context_finalized_native_fold_loop_i64acc(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    initial_acc: i64,
    elements: &[Value],
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFoldI64AccLoopOutcome, JitCraneliftNativeCallError> {
    run_native_fold_loop_i64acc(
        eval,
        id,
        span,
        env,
        initial_acc,
        FoldElementSource::Slice(elements),
        body,
    )
}

/// Runs a fused fold-generator entry natively over a `genList` index range with
/// a decoded `i64` accumulator.
///
/// The decoded-accumulator counterpart of
/// [`run_context_finalized_native_fold_genlist_loop`]: the compiled entry fuses
/// the `builtins.genList` generator, so its element argument is the raw index,
/// and the accumulator is threaded as a plain decoded `i64`. The loop covers
/// indices `start_index .. start_index + run_len` and otherwise behaves exactly
/// like [`run_context_finalized_native_fold_loop_i64acc`].
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI or the finalized body is not a fold-step entry.
pub fn run_context_finalized_native_fold_genlist_loop_i64acc(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    initial_acc: i64,
    start_index: usize,
    run_len: usize,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFoldI64AccLoopOutcome, JitCraneliftNativeCallError> {
    run_native_fold_loop_i64acc(
        eval,
        id,
        span,
        env,
        initial_acc,
        FoldElementSource::GenIndices {
            start: start_index,
            len: run_len,
        },
        body,
    )
}

/// Runs a compiled arity-1 filter predicate natively over an element run.
///
/// This is the lean per-element boundary for the tier-2 filter seam,
/// mirroring [`run_context_finalized_native_fold_loop`]: the
/// [`RuntimeJitContext`] pin and the [`RuntimeTrapScope`] are set up **once**
/// for the whole run, and each element costs one native call through the
/// frozen `argv` entry ABI plus one thread-local trap probe. Each element
/// (which may be a suspended thunk; the compiled predicate forces it at
/// first strict use, exactly like the interpreted call) is passed as the
/// entry's single argument, and a `true` result keeps the element.
///
/// Any transferred trap — a compiled-body deopt or a forcing evaluator error
/// while deciding element `k` — stops the loop with `consumed == k`, as does
/// a non-boolean predicate result (the interpreted re-run of that element
/// reproduces the tree walk's type error byte-for-byte); the caller re-runs
/// that element interpreted (see [`NativeFilterLoopOutcome`]).
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI, the finalized body is not a tier-2 chain entry of arity
/// 1, or a compiled call returns a value whose payload violates the runtime
/// layout.
pub fn run_context_finalized_native_filter_loop(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    elements: &[Value],
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFilterLoopOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    let mut kept = Vec::with_capacity(elements.len());
    for (index, element) in elements.iter().copied().enumerate() {
        let argv = [element];
        // SAFETY: `rt` is the pinned context over `eval`, `env` the caller-owned
        // environment clone, the argv element a live value on `eval`'s heap; the
        // caller keeps `body`'s module alive and the armed scope converts every trap.
        let filter_step =
            unsafe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, &argv) };
        let value = match filter_step {
            Ok(value) => value,
            Err(error) => {
                if index == 0 {
                    drop(scope);
                    return Err(error);
                }
                // A mid-run boundary error abandons this element natively;
                // the interpreted re-run of element `index` is authoritative.
                drop(scope);
                drop(context);
                return Ok(NativeFilterLoopOutcome {
                    consumed: index,
                    kept,
                    deopted: true,
                });
            }
        };
        if scope.take_trap().is_some() {
            drop(scope);
            drop(context);
            return Ok(NativeFilterLoopOutcome {
                consumed: index,
                kept,
                deopted: true,
            });
        }
        match value.as_bool() {
            Ok(true) => kept.push(element),
            Ok(false) => {}
            // A non-boolean predicate result is the tree walk's type error;
            // deopt so the interpreted re-run reproduces it exactly.
            Err(_) => {
                drop(scope);
                drop(context);
                return Ok(NativeFilterLoopOutcome {
                    consumed: index,
                    kept,
                    deopted: true,
                });
            }
        }
    }
    drop(scope);
    drop(context);
    Ok(NativeFilterLoopOutcome {
        consumed: elements.len(),
        kept,
        deopted: false,
    })
}

/// Runs a compiled arity-1 predicate until `all` or `any` is decided.
///
/// The runtime context and trap scope are installed once for the whole run.
/// `short_circuit_on` is false for `all` and true for `any`; once the native
/// predicate produces that value, later elements remain unevaluated. A trap,
/// boundary failure, or non-boolean result at element `k` returns
/// `consumed == k` so the evaluator can retry it through the tree walk.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError`] when the host lacks a supported
/// native value ABI, the body is not an arity-1 tier-2 entry, or the first
/// native call fails before any element has been decided.
pub fn run_context_finalized_native_all_any_loop(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    elements: &[Value],
    short_circuit_on: bool,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeAllAnyLoopOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;
    let scope = RuntimeTrapScope::new();
    for (index, element) in elements.iter().copied().enumerate() {
        let argv = [element];
        // SAFETY: `rt` is pinned over `eval`, `env` is the operator-boundary
        // context pointer, `argv` is live, the owner keeps `body` alive, and
        // the trap scope is armed for the call.
        let step =
            unsafe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, &argv) };
        let value = match step {
            Ok(value) => value,
            Err(error) if index == 0 => {
                drop(scope);
                return Err(error);
            }
            Err(_) => {
                drop(scope);
                drop(context);
                return Ok(NativeAllAnyLoopOutcome {
                    consumed: index,
                    short_circuited: false,
                    deopted: true,
                });
            }
        };
        if scope.take_trap().is_some() {
            drop(scope);
            drop(context);
            return Ok(NativeAllAnyLoopOutcome {
                consumed: index,
                short_circuited: false,
                deopted: true,
            });
        }
        let Ok(result) = value.as_bool() else {
            drop(scope);
            drop(context);
            return Ok(NativeAllAnyLoopOutcome {
                consumed: index,
                short_circuited: false,
                deopted: true,
            });
        };
        if result == short_circuit_on {
            drop(scope);
            drop(context);
            return Ok(NativeAllAnyLoopOutcome {
                consumed: index + 1,
                short_circuited: true,
                deopted: false,
            });
        }
    }
    drop(scope);
    drop(context);
    Ok(NativeAllAnyLoopOutcome {
        consumed: elements.len(),
        short_circuited: false,
        deopted: false,
    })
}

/// The per-step element supply of one native fold run.
#[derive(Clone, Copy)]
enum FoldElementSource<'a> {
    /// Materialized elements from the caller's list run.
    Slice(&'a [Value]),
    /// Synthesized inline-integer indices for a fused `genList` fold.
    GenIndices { start: usize, len: usize },
}

impl FoldElementSource<'_> {
    /// Returns the number of fold steps this source supplies.
    fn len(&self) -> usize {
        match self {
            Self::Slice(elements) => elements.len(),
            Self::GenIndices { len, .. } => *len,
        }
    }

    /// Returns the second `argv` value for the step at `offset`.
    ///
    /// `None` only when a generated index exceeds `i64` — unreachable for
    /// lengths produced by the evaluator's list-length validation, and
    /// reported as a deopt (never an unwrap) by the loop.
    fn step_value(&self, offset: usize) -> Option<Value> {
        match self {
            Self::Slice(elements) => elements.get(offset).copied(),
            Self::GenIndices { start, .. } => {
                let index = start.checked_add(offset)?;
                i64::try_from(index).ok().map(Value::int)
            }
        }
    }
}

/// Shared native fold-loop core for both element sources.
///
/// See [`run_context_finalized_native_fold_loop`] for the boundary contract.
fn run_native_fold_loop(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    initial: Value,
    source: FoldElementSource<'_>,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFoldLoopOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    let mut accumulator = initial;
    for index in 0..source.len() {
        let Some(element) = source.step_value(index) else {
            drop(scope);
            drop(context);
            return Ok(NativeFoldLoopOutcome {
                consumed: index,
                accumulator,
                deopted: true,
            });
        };
        let argv = [accumulator, element];
        // SAFETY: `rt` is the pinned context over `eval`, `env` the caller-owned
        // environment clone, both argv values live on `eval`'s heap; the caller
        // keeps `body`'s module alive and the armed scope converts every trap.
        let fold_step =
            unsafe { jit_cranelift_call_context_finalized_lambda_argv_entry(body, rt, env, &argv) };
        let value = match fold_step {
            Ok(value) => value,
            Err(error) => {
                if index == 0 {
                    drop(scope);
                    return Err(error);
                }
                // A mid-run boundary error abandons this element natively;
                // the interpreted re-run of element `index` is authoritative.
                drop(scope);
                drop(context);
                return Ok(NativeFoldLoopOutcome {
                    consumed: index,
                    accumulator,
                    deopted: true,
                });
            }
        };
        if scope.take_trap().is_some() {
            drop(scope);
            drop(context);
            return Ok(NativeFoldLoopOutcome {
                consumed: index,
                accumulator,
                deopted: true,
            });
        }
        accumulator = value;
    }
    drop(scope);
    drop(context);
    Ok(NativeFoldLoopOutcome {
        consumed: source.len(),
        accumulator,
        deopted: false,
    })
}

/// Shared native fold-loop core threading a decoded `i64` accumulator.
///
/// See [`run_context_finalized_native_fold_loop_i64acc`] for the boundary
/// contract. Structurally identical to [`run_native_fold_loop`] but the
/// accumulator lives in a plain `i64` register across the whole run: each step
/// receives the decoded accumulator and the current element word and returns
/// the next decoded accumulator, so nothing is encoded or decoded per element.
fn run_native_fold_loop_i64acc(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    env: &EvalEnv,
    initial_acc: i64,
    source: FoldElementSource<'_>,
    body: &JitModuleContextFinalizedBody,
) -> Result<NativeFoldI64AccLoopOutcome, JitCraneliftNativeCallError> {
    let stack_maps = body.finalized_function().runtime_user_stack_maps();
    let mut context = std::pin::pin!(RuntimeJitContext::new_with_env_and_stack_maps(
        eval, id, span, env, stack_maps,
    ));
    let rt = context.as_mut().as_mut_ptr();
    let env = rt;

    let scope = RuntimeTrapScope::new();
    let mut accumulator = initial_acc;
    for index in 0..source.len() {
        let Some(element) = source.step_value(index) else {
            drop(scope);
            drop(context);
            return Ok(NativeFoldI64AccLoopOutcome {
                consumed: index,
                accumulator,
                deopted: true,
            });
        };
        // SAFETY: `rt` is the pinned context over `eval`, `env` the caller-owned
        // environment clone, the element a live value on `eval`'s heap; the
        // caller keeps `body`'s module alive and the armed scope converts every
        // trap. `accumulator` is a plain decoded integer requiring no validation.
        let fold_step = unsafe {
            jit_cranelift_call_context_finalized_fold_step_i64acc_entry(
                body,
                rt,
                env,
                accumulator,
                element,
            )
        };
        let next = match fold_step {
            Ok(next) => next,
            Err(error) => {
                if index == 0 {
                    drop(scope);
                    return Err(error);
                }
                // A mid-run boundary error abandons this element natively; the
                // interpreted re-run of element `index` is authoritative.
                drop(scope);
                drop(context);
                return Ok(NativeFoldI64AccLoopOutcome {
                    consumed: index,
                    accumulator,
                    deopted: true,
                });
            }
        };
        if scope.take_trap().is_some() {
            drop(scope);
            drop(context);
            return Ok(NativeFoldI64AccLoopOutcome {
                consumed: index,
                accumulator,
                deopted: true,
            });
        }
        accumulator = next;
    }
    drop(scope);
    drop(context);
    Ok(NativeFoldI64AccLoopOutcome {
        consumed: source.len(),
        accumulator,
        deopted: false,
    })
}

#[cfg(test)]
mod tests;
