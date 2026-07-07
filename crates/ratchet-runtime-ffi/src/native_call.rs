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
//! - it derives the `env` pointer from the caller's capture [`EvalFrame`], and
//! - it installs a [`RuntimeTrapScope`] for the duration of the call so a forcing
//!   evaluator error is transferred out as a [`RuntimeTrap`] instead of aborting.
//!
//! Safe crates that forbid `unsafe` (such as `aos-nix`) can build the artifact,
//! candidates, evaluator, and frame themselves and then run the compiled body
//! through [`run_registered_native_thunk_call`].

use std::ffi::c_void;
use std::rc::Rc;

use ratchet_jit::{
    JitClifArtifact, JitCraneliftNativeCallError,
    JitCraneliftRegisteredArtifactFinalizationPreflight, JitRuntimeSymbolAddressCandidate,
    jit_cranelift_call_finalized_thunk_entry,
    jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates,
};
use ratchet_oracle::value::Value;
use ratchet_oracle::{compile::IrId, eval::EvalFrame, eval::tree_walk::TreeWalk, syntax::Span};

use crate::context::RuntimeJitContext;
use crate::trap::{RuntimeTrap, RuntimeTrapScope};

/// The value and optional trap observed from one native thunk execution.
///
/// `value` is the raw runtime value the compiled body returned. When `trap` is
/// `Some`, a forcing or environment-access wrapper transferred an evaluator
/// error out of the call and `value` is the meaningless trap sentinel.
#[derive(Clone, Debug)]
pub struct NativeThunkCallOutcome {
    value: Value,
    trap: Option<RuntimeTrap>,
}

impl NativeThunkCallOutcome {
    /// Returns the raw runtime value returned by the compiled thunk body.
    ///
    /// The value is only meaningful when [`Self::trap`] is `None`.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the trap transferred out of the call, if any.
    pub const fn trap(&self) -> Option<&RuntimeTrap> {
        self.trap.as_ref()
    }

    /// Returns true when a wrapper transferred a trap out of the call.
    pub const fn is_trap(&self) -> bool {
        self.trap.is_some()
    }

    /// Consumes the outcome and returns the transferred trap, if any.
    pub fn into_trap(self) -> Option<RuntimeTrap> {
        self.trap
    }
}

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
    frame: &Rc<EvalFrame>,
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let mut context = std::pin::pin!(RuntimeJitContext::new(eval, id, span));
    let rt = context.as_mut().as_mut_ptr();
    let env = Rc::as_ptr(frame) as *mut c_void;

    let scope = RuntimeTrapScope::new();
    // SAFETY: `rt` comes from the pinned context over `eval` and `env` from the
    // live `frame`; every candidate is a caller-guaranteed frozen-ABI runtime-FFI
    // wrapper that does not unwind, and the installed scope converts a trap.
    let call = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact, candidates, rt, env,
        )
    };
    match call {
        Ok(invocation) => {
            let value = invocation.value();
            let trap = scope.take_trap();
            drop(invocation);
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
    frame: &Rc<EvalFrame>,
    finalization: &JitCraneliftRegisteredArtifactFinalizationPreflight,
) -> Result<NativeThunkCallOutcome, JitCraneliftNativeCallError> {
    let mut context = std::pin::pin!(RuntimeJitContext::new(eval, id, span));
    let rt = context.as_mut().as_mut_ptr();
    let env = Rc::as_ptr(frame) as *mut c_void;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_thunk_call_outcome_reports_value_and_trap() {
        let value_outcome = NativeThunkCallOutcome {
            value: Value::int(7),
            trap: None,
        };
        assert!(!value_outcome.is_trap());
        assert!(value_outcome.trap().is_none());
        assert_eq!(value_outcome.value().as_int(), Ok(7));
        assert!(value_outcome.into_trap().is_none());
    }
}
