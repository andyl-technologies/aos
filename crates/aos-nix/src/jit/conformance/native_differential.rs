//! Helper-calling native differential against a live tree-walk evaluator.
//!
//! The literal differential in the parent module compiles no-import constant
//! thunk bodies and compares them against a safe literal projection. This module
//! takes the next step: it compiles a *helper-calling* artifact — a local
//! environment-slot read forced through `aos_env_get` and `aos_force` — links it
//! against the real process-local runtime-FFI wrappers, and executes it against
//! a live [`TreeWalk`]-backed [`RuntimeJitContext`]. It then compares the value
//! (or trap) produced by native code with the value (or error) produced by
//! forcing the same thunk directly through the tree-walk oracle.
//!
//! ```text
//! source `{ v = 40 + 2; }`, binding `v`
//!   oracle:  eval -> take `v` thunk -> rust_callable_aos_force -> Ok(42) / Err
//!   native:  compile env-slot-read+force artifact
//!            register aos_env_get + aos_force real wrapper addresses
//!            frame[0] = `v` thunk; rt = RuntimeJitContext(eval)
//!            RuntimeTrapScope installed
//!            call compiled thunk(rt, env) -> Value / trap
//!   verify:  Ok values match, or both sides fail (oracle Err <-> native trap)
//! ```
//!
//! Executing native code that can hit an evaluator error is only safe because a
//! [`RuntimeTrapScope`] is installed for the call: a forcing failure is
//! transferred out as a [`RuntimeTrap`] instead of aborting the test process.

use ratchet_core::{
    EffectClass, Ir, IrArena, IrData, IrId, IrKind, IrNode,
    syntax::{BinOpKind, Span, Symbol},
};
use ratchet_jit::{
    JitCraneliftNativeCallError, JitLowerError, JitRuntimeSymbolAddressCandidate,
    lower_forced_env_get_ir_thunk_body_artifact, lower_forced_upval_get_ir_thunk_body_artifact,
    lower_tier1_ir_thunk_body_artifact,
};
use ratchet_oracle::eval::tree_walk::TreeWalkError;
use ratchet_oracle::{
    compile::resolve,
    eval::{EvalEnv, EvalEnvError, EvalFrame, tree_walk::TreeWalk},
    runtime::forcing::rust_callable_aos_force,
    syntax::parse_str,
};
use ratchet_runtime_ffi::{RuntimeTrap, run_registered_native_thunk_call};
use ratchet_value::value::Value;
use thiserror::Error;

use crate::jit::{
    NixJitRuntimeSymbolAddressCandidateError, nix_jit_deopt_address_candidate,
    nix_jit_runtime_symbol_address_candidate_preflight, nix_jit_upval_get_address_candidate,
};

/// The runtime symbols imported by a forced environment-slot artifact, in order.
///
/// The `aos_env_get` wrapper reads the captured slot and the `aos_force` wrapper
/// forces the loaded value. Both must be registered with their real wrapper
/// addresses before the compiled body can call them.
pub(super) const FORCED_ENV_SLOT_IMPORTS: [&str; 2] = ["aos_env_get", "aos_force"];

/// The reconciled result of one forced environment-slot native differential.
///
/// A run agrees in one of two ways: both sides produce the same value, or both
/// sides fail (the oracle returns a tree-walk error and native code transfers a
/// trap). Any other combination is a divergence and is reported as an error.
#[derive(Clone, Debug)]
pub enum NixJitForcedEnvSlotNativeOutcome {
    /// Both sides succeeded and produced representationally equal values.
    Value {
        /// The value from forcing the thunk directly through the oracle.
        oracle: Value,
        /// The value returned by the compiled native thunk body.
        native: Value,
    },
    /// Both sides failed: the oracle errored and native code transferred a trap.
    Trap {
        /// The tree-walk error from forcing the thunk directly through the oracle.
        oracle_error: TreeWalkError,
        /// The trap transferred out of the native forcing wrapper.
        native_trap: RuntimeTrap,
    },
}

impl NixJitForcedEnvSlotNativeOutcome {
    /// Returns true when both sides produced equal values.
    pub const fn is_value(&self) -> bool {
        matches!(self, Self::Value { .. })
    }

    /// Returns true when both sides failed (oracle error and native trap).
    pub const fn is_trap(&self) -> bool {
        matches!(self, Self::Trap { .. })
    }
}

/// A failure while running a forced environment-slot native differential.
#[derive(Debug, Error)]
pub enum NixJitForcedEnvSlotNativeDifferentialError {
    /// The differential source program could not be parsed, resolved, or lowered.
    #[error("differential source program could not be lowered: {message}")]
    SourceProgram {
        /// The display text of the underlying parse, resolve, or lower error.
        message: String,
    },

    /// The named binding could not be projected into a forceable slot thunk.
    #[error("differential binding could not be projected into a slot thunk: {reason}")]
    BindingProjection {
        /// The reason the binding thunk could not be produced.
        reason: BindingProjectionReason,
    },

    /// The capture frame could not be allocated or populated.
    #[error(transparent)]
    Frame(#[from] EvalEnvError),

    /// The forced environment-slot artifact could not be lowered.
    #[error("forced environment-slot artifact could not be lowered")]
    LowerArtifact(#[source] JitLowerError),

    /// The registered runtime-symbol candidates could not be built.
    #[error("runtime-symbol address candidates could not be built")]
    Candidates(#[from] NixJitRuntimeSymbolAddressCandidateError),

    /// A required runtime symbol had no address candidate in the preflight.
    #[error("runtime symbol {symbol_name} has no address candidate")]
    MissingCandidate {
        /// The stable runtime symbol name that was missing.
        symbol_name: &'static str,
    },

    /// The registered native thunk call failed to finalize or execute.
    #[error("registered native thunk call failed")]
    NativeCall(#[source] JitCraneliftNativeCallError),

    /// The oracle and native sides disagreed on success, failure, or value.
    #[error("native differential diverged from the tree-walk oracle: {reason}")]
    Divergence {
        /// A human-readable description of how the two sides diverged.
        reason: String,
    },
}

/// Why a named binding could not be projected into a forceable slot thunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingProjectionReason {
    /// The differential source root did not evaluate to an attribute set.
    RootNotAttrs,
    /// The binding name was not interned in the source program's symbol table.
    UnknownSymbol,
    /// The attribute set had no binding with the requested name.
    MissingBinding,
}

impl std::fmt::Display for BindingProjectionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::RootNotAttrs => "source root did not evaluate to an attribute set",
            Self::UnknownSymbol => "binding name is not interned in the source symbol table",
            Self::MissingBinding => "attribute set has no binding with that name",
        };
        formatter.write_str(text)
    }
}

/// Result returned by forced environment-slot native differentials.
pub type NixJitForcedEnvSlotNativeDifferentialResult =
    Result<NixJitForcedEnvSlotNativeOutcome, NixJitForcedEnvSlotNativeDifferentialError>;

/// Compiles and runs a forced environment-slot artifact against a live tree walk.
///
/// `source` must be an attribute set literal and `binding` names one of its
/// attributes. The attribute's suspended thunk is placed in environment slot 0
/// and forced two ways: once directly through the tree-walk oracle
/// ([`rust_callable_aos_force`]) and once through a compiled `aos_env_get` +
/// `aos_force` thunk body executed against a live [`RuntimeJitContext`]. The
/// returned [`NixJitForcedEnvSlotNativeOutcome`] records agreement; disagreement
/// is a [`NixJitForcedEnvSlotNativeDifferentialError::Divergence`].
///
/// The native call runs under an installed [`RuntimeTrapScope`], so a forcing
/// failure is transferred out as a [`RuntimeTrap`] rather than aborting the
/// process. This is what makes the error-path differential observable.
///
/// # Errors
///
/// Returns [`NixJitForcedEnvSlotNativeDifferentialError::SourceProgram`] when the
/// source cannot be parsed, resolved, or lowered;
/// [`NixJitForcedEnvSlotNativeDifferentialError::BindingProjection`] when the
/// named binding is not a forceable attribute thunk;
/// [`NixJitForcedEnvSlotNativeDifferentialError::Frame`] when the capture frame
/// cannot be built; [`NixJitForcedEnvSlotNativeDifferentialError::LowerArtifact`]
/// when the artifact cannot be lowered;
/// [`NixJitForcedEnvSlotNativeDifferentialError::Candidates`] or
/// [`NixJitForcedEnvSlotNativeDifferentialError::MissingCandidate`] when the
/// runtime-symbol candidates cannot be built;
/// [`NixJitForcedEnvSlotNativeDifferentialError::NativeCall`] when the registered
/// native thunk call fails to finalize or execute; and
/// [`NixJitForcedEnvSlotNativeDifferentialError::Divergence`] when the oracle and
/// native sides disagree.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`].
pub fn nix_jit_forced_env_slot_native_differential(
    source: &str,
    binding: &[u8],
) -> NixJitForcedEnvSlotNativeDifferentialResult {
    let source_ir = lower_source(source)?;
    let source_span = Span::new(0, source.len() as u32);

    let oracle = oracle_force_binding(&source_ir, binding, source_span)?;
    let native = native_force_binding(&source_ir, binding, source_span)?;

    reconcile(oracle, native)
}

/// Forces the named binding thunk directly through the tree-walk oracle.
fn oracle_force_binding(
    source_ir: &Ir,
    binding: &[u8],
    source_span: Span,
) -> Result<Result<Value, TreeWalkError>, NixJitForcedEnvSlotNativeDifferentialError> {
    let mut eval = TreeWalk::new(source_ir);
    let thunk = binding_thunk(&mut eval, source_ir, binding)?;
    Ok(rust_callable_aos_force(
        &mut eval,
        source_ir.root,
        source_span,
        thunk,
    ))
}

/// Runs the compiled env-slot-read + force artifact against a live tree walk.
fn native_force_binding(
    source_ir: &Ir,
    binding: &[u8],
    source_span: Span,
) -> Result<NativeForceResult, NixJitForcedEnvSlotNativeDifferentialError> {
    let arena = local_slot_zero_arena();
    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .map_err(NixJitForcedEnvSlotNativeDifferentialError::LowerArtifact)?;
    let candidates = forced_env_slot_candidates()?;

    let mut eval = TreeWalk::new(source_ir);
    let thunk = binding_thunk(&mut eval, source_ir, binding)?;
    let frame = EvalFrame::new(1)?;
    frame.set(0, thunk)?;
    // Dispatch owns the environment snapshot the wrapper decodes; the captured
    // frame is the innermost (and only) frame `aos_env_get` reads.
    let env = EvalEnv::capture(&[frame])?;

    // The unsafe native-call boundary lives in `ratchet-runtime-ffi`, which pins
    // the runtime context, installs the trap scope, and returns the value plus
    // any transferred trap. This crate forbids `unsafe`, so it drives the call
    // entirely through that safe primitive.
    let outcome = run_registered_native_thunk_call(
        &mut eval,
        source_ir.root,
        source_span,
        &env,
        artifact,
        &candidates,
    )
    .map_err(NixJitForcedEnvSlotNativeDifferentialError::NativeCall)?;

    Ok(NativeForceResult {
        value: outcome.value(),
        trap: outcome.into_trap(),
    })
}

/// The value and trap observed from one native execution of the artifact.
struct NativeForceResult {
    value: Value,
    trap: Option<RuntimeTrap>,
}

/// Reconciles the oracle force result with the native execution result.
fn reconcile(
    oracle: Result<Value, TreeWalkError>,
    native: NativeForceResult,
) -> NixJitForcedEnvSlotNativeDifferentialResult {
    match (oracle, native.trap) {
        (Ok(oracle_value), None) => {
            if oracle_value.raw_eq(native.value) {
                Ok(NixJitForcedEnvSlotNativeOutcome::Value {
                    oracle: oracle_value,
                    native: native.value,
                })
            } else {
                Err(NixJitForcedEnvSlotNativeDifferentialError::Divergence {
                    reason: format!(
                        "oracle produced {oracle_value:?} but native produced {:?}",
                        native.value
                    ),
                })
            }
        }
        (Err(oracle_error), Some(native_trap)) => Ok(NixJitForcedEnvSlotNativeOutcome::Trap {
            oracle_error,
            native_trap,
        }),
        (Ok(oracle_value), Some(native_trap)) => {
            Err(NixJitForcedEnvSlotNativeDifferentialError::Divergence {
                reason: format!(
                    "oracle produced {oracle_value:?} but native transferred a trap {native_trap:?}"
                ),
            })
        }
        (Err(oracle_error), None) => Err(NixJitForcedEnvSlotNativeDifferentialError::Divergence {
            reason: format!(
                "oracle failed with {oracle_error:?} but native produced {:?}",
                native.value
            ),
        }),
    }
}

/// Builds the two registered candidates the forced artifact imports.
///
/// The addresses come from the shared runtime-symbol address-candidate
/// preflight, which sources `aos_env_get` and `aos_force` from the real
/// runtime-FFI native wrappers.
pub(super) fn forced_env_slot_candidates()
-> Result<Vec<JitRuntimeSymbolAddressCandidate>, NixJitForcedEnvSlotNativeDifferentialError> {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
    let mut candidates = Vec::with_capacity(FORCED_ENV_SLOT_IMPORTS.len());
    for symbol_name in FORCED_ENV_SLOT_IMPORTS {
        let candidate = preflight
            .address_candidate_for(symbol_name)
            .ok_or(NixJitForcedEnvSlotNativeDifferentialError::MissingCandidate { symbol_name })?;
        candidates.push(JitRuntimeSymbolAddressCandidate::new(
            candidate.symbol_name().to_owned(),
            candidate.kind(),
            candidate.address(),
        ));
    }
    Ok(candidates)
}

/// Returns the arena holding a single local-slot-0 read for the artifact root.
pub(super) fn local_slot_zero_arena() -> IrArena {
    IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Local { slot: 0 },
        )],
        Vec::new(),
    )
}

/// Returns the arena holding a single depth-1, slot-0 upvalue read.
pub(super) fn upval_slot_zero_depth_one_arena() -> IrArena {
    IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::UpvalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Upval { depth: 1, slot: 0 },
        )],
        Vec::new(),
    )
}

/// Builds the two registered candidates the forced upvalue artifact imports.
///
/// `aos_upval_get` is registered directly from its runtime-FFI standalone wrapper
/// (like `aos_deopt`), while `aos_force` comes from the shared address-candidate
/// preflight.
fn forced_upval_slot_candidates()
-> Result<Vec<JitRuntimeSymbolAddressCandidate>, NixJitForcedEnvSlotNativeDifferentialError> {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
    let upval_get = nix_jit_upval_get_address_candidate()?;
    let force = preflight.address_candidate_for("aos_force").ok_or(
        NixJitForcedEnvSlotNativeDifferentialError::MissingCandidate {
            symbol_name: "aos_force",
        },
    )?;
    Ok(vec![
        JitRuntimeSymbolAddressCandidate::new(
            upval_get.symbol_name().to_owned(),
            upval_get.kind(),
            upval_get.address(),
        ),
        JitRuntimeSymbolAddressCandidate::new(
            force.symbol_name().to_owned(),
            force.kind(),
            force.address(),
        ),
    ])
}

/// Runs the compiled depth-1 upvalue-read + force artifact against a live tree walk.
///
/// When `include_outer_frame` is true the captured environment has two frames —
/// an outer frame holding the binding thunk at slot 0 and an innermost dummy
/// frame — so a depth-1 read resolves the thunk. When it is false the environment
/// has only the innermost frame, so the depth-1 read walks past the captured
/// stack and the wrapper transfers a [`RuntimeTrap::Deopt`].
fn native_force_binding_upval(
    source_ir: &Ir,
    binding: &[u8],
    source_span: Span,
    include_outer_frame: bool,
) -> Result<NativeForceResult, NixJitForcedEnvSlotNativeDifferentialError> {
    let arena = upval_slot_zero_depth_one_arena();
    let artifact = lower_forced_upval_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .map_err(NixJitForcedEnvSlotNativeDifferentialError::LowerArtifact)?;
    let candidates = forced_upval_slot_candidates()?;

    let mut eval = TreeWalk::new(source_ir);
    let thunk = binding_thunk(&mut eval, source_ir, binding)?;
    let inner = EvalFrame::new(1)?;
    // Dispatch owns the environment snapshot; frames are ordered outermost first.
    let env = if include_outer_frame {
        let outer = EvalFrame::new(1)?;
        outer.set(0, thunk)?;
        EvalEnv::capture(&[outer, inner])?
    } else {
        EvalEnv::capture(&[inner])?
    };

    let outcome = run_registered_native_thunk_call(
        &mut eval,
        source_ir.root,
        source_span,
        &env,
        artifact,
        &candidates,
    )
    .map_err(NixJitForcedEnvSlotNativeDifferentialError::NativeCall)?;

    Ok(NativeForceResult {
        value: outcome.value(),
        trap: outcome.into_trap(),
    })
}

/// Compiles and runs a forced depth-1 upvalue-slot artifact against a live tree walk.
///
/// This mirrors [`nix_jit_forced_env_slot_native_differential`] but places the
/// binding thunk one frame above the innermost captured frame and reads it
/// through a compiled `aos_upval_get` + `aos_force` body, proving the native
/// upvalue read resolves the same value the tree-walk oracle produces.
///
/// # Errors
///
/// Returns the same error variants as
/// [`nix_jit_forced_env_slot_native_differential`].
pub fn nix_jit_forced_upval_slot_native_differential(
    source: &str,
    binding: &[u8],
) -> NixJitForcedEnvSlotNativeDifferentialResult {
    let source_ir = lower_source(source)?;
    let source_span = Span::new(0, source.len() as u32);

    let oracle = oracle_force_binding(&source_ir, binding, source_span)?;
    let native = native_force_binding_upval(&source_ir, binding, source_span, true)?;

    reconcile(oracle, native)
}

/// Evaluates `source_ir` and returns the suspended thunk for attribute `binding`.
pub(super) fn binding_thunk(
    eval: &mut TreeWalk,
    source_ir: &Ir,
    binding: &[u8],
) -> Result<Value, NixJitForcedEnvSlotNativeDifferentialError> {
    let root = eval.eval_root().map_err(|_| {
        NixJitForcedEnvSlotNativeDifferentialError::BindingProjection {
            reason: BindingProjectionReason::RootNotAttrs,
        }
    })?;
    let symbol = binding_symbol(source_ir, binding)?;
    let attrs = eval.heap().get_attrs(root).map_err(|_| {
        NixJitForcedEnvSlotNativeDifferentialError::BindingProjection {
            reason: BindingProjectionReason::RootNotAttrs,
        }
    })?;
    attrs.get(symbol).ok_or(
        NixJitForcedEnvSlotNativeDifferentialError::BindingProjection {
            reason: BindingProjectionReason::MissingBinding,
        },
    )
}

/// Resolves the interned symbol for attribute `binding` in the source program.
fn binding_symbol(
    source_ir: &Ir,
    binding: &[u8],
) -> Result<Symbol, NixJitForcedEnvSlotNativeDifferentialError> {
    source_ir
        .symbols
        .symbols()
        .iter()
        .position(|symbol| symbol.as_slice() == binding)
        .map(|index| Symbol::new(index as u32))
        .ok_or(
            NixJitForcedEnvSlotNativeDifferentialError::BindingProjection {
                reason: BindingProjectionReason::UnknownSymbol,
            },
        )
}

/// Parses, resolves, and lowers a differential source program into Core IR.
pub(super) fn lower_source(source: &str) -> Result<Ir, NixJitForcedEnvSlotNativeDifferentialError> {
    let parsed = parse_str(source).map_err(|error| {
        NixJitForcedEnvSlotNativeDifferentialError::SourceProgram {
            message: format!("{error:?}"),
        }
    })?;
    let resolved = resolve(parsed).map_err(|error| {
        NixJitForcedEnvSlotNativeDifferentialError::SourceProgram {
            message: format!("{error:?}"),
        }
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| {
        NixJitForcedEnvSlotNativeDifferentialError::SourceProgram {
            message: format!("{error:?}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_env_slot_native_matches_tree_walk_scalar() {
        let outcome = nix_jit_forced_env_slot_native_differential("{ v = 40 + 2; }", b"v")
            .expect("forced env-slot native differential runs");

        let NixJitForcedEnvSlotNativeOutcome::Value { oracle, native } = outcome else {
            panic!("expected a value-agreement outcome, got {outcome:?}");
        };
        assert_eq!(oracle.as_int(), Ok(42));
        assert_eq!(native.as_int(), Ok(42));
        assert!(oracle.raw_eq(native));
    }

    #[test]
    fn forced_env_slot_native_matches_tree_walk_bool() {
        let outcome = nix_jit_forced_env_slot_native_differential("{ v = true && false; }", b"v")
            .expect("forced env-slot native differential runs");

        assert!(outcome.is_value());
        let NixJitForcedEnvSlotNativeOutcome::Value { native, .. } = outcome else {
            panic!("expected a value-agreement outcome, got {outcome:?}");
        };
        assert_eq!(native.as_bool(), Ok(false));
    }

    #[test]
    fn forced_env_slot_native_transfers_trap_instead_of_aborting() {
        // Forcing `1 / 0` fails in the tree walk. Because the native call runs
        // under a RuntimeTrapScope, the forcing wrapper transfers the error out
        // as a trap instead of aborting this test process.
        let outcome = nix_jit_forced_env_slot_native_differential("{ v = 1 / 0; }", b"v")
            .expect("forced env-slot native differential runs to a trap agreement");

        let NixJitForcedEnvSlotNativeOutcome::Trap {
            oracle_error,
            native_trap,
        } = outcome
        else {
            panic!("expected a trap-agreement outcome, got {outcome:?}");
        };
        // The trap transferred out of native code carries the exact tree-walk
        // error the oracle produced when forcing the same failing thunk.
        assert!(matches!(
            native_trap,
            RuntimeTrap::Force(trap_error) if trap_error == oracle_error
        ));
    }

    #[test]
    fn forced_upval_slot_native_matches_tree_walk_scalar() {
        // The binding thunk sits one frame above the innermost captured frame, so
        // the compiled body reads it through `aos_upval_get(env, 1, 0)` and must
        // agree with the value the oracle forces directly.
        let outcome = nix_jit_forced_upval_slot_native_differential("{ v = 40 + 2; }", b"v")
            .expect("forced upval-slot native differential runs");

        let NixJitForcedEnvSlotNativeOutcome::Value { oracle, native } = outcome else {
            panic!("expected a value-agreement outcome, got {outcome:?}");
        };
        assert_eq!(oracle.as_int(), Ok(42));
        assert_eq!(native.as_int(), Ok(42));
        assert!(oracle.raw_eq(native));
    }

    #[test]
    fn forced_upval_slot_native_deopts_on_bad_depth() {
        // With only the innermost frame captured, a depth-1 upvalue read walks
        // past the captured stack. The wrapper transfers a deopt so the engine can
        // re-run the body on the tree walk, rather than aborting or miscompiling.
        let source_ir = lower_source("{ v = 40 + 2; }").expect("source lowers");
        let source_span = Span::new(0, "{ v = 40 + 2; }".len() as u32);
        let native = native_force_binding_upval(&source_ir, b"v", source_span, false)
            .expect("native upval call runs to a deopt");

        assert_eq!(native.trap, Some(RuntimeTrap::Deopt));
    }

    #[test]
    fn upvalue_operand_arith_native_computes_through_aos_upval_get() {
        // Body: `upval(depth 1, slot 0) + 1`. The upvalue holds 41 one frame above
        // the innermost, so the compiled arithmetic — which loads the operand via
        // aos_upval_get, forces it, and adds inline — must produce 42. This
        // exercises the widened operand path (an upvalue operand inside a shape)
        // on executed machine code, not just lowering.
        let arena = IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::UpvalVar,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Upval { depth: 1, slot: 0 },
                ),
                IrNode::new(
                    IrKind::Int,
                    Span::new(0, 1),
                    EffectClass::pure(),
                    IrData::Int(1),
                ),
                IrNode::new(
                    IrKind::BinOp,
                    Span::new(0, 3),
                    EffectClass::pure(),
                    IrData::Binary {
                        op: BinOpKind::Add,
                        lhs: IrId::new(0),
                        rhs: IrId::new(1),
                    },
                ),
            ],
            Vec::new(),
        );
        let artifact = lower_tier1_ir_thunk_body_artifact(&arena, IrId::new(2))
            .expect("upvalue-operand arithmetic lowers");

        let preflight =
            nix_jit_runtime_symbol_address_candidate_preflight().expect("preflight builds");
        let mut candidates = Vec::new();
        for symbol in ["aos_env_get", "aos_force"] {
            let candidate = preflight
                .address_candidate_for(symbol)
                .unwrap_or_else(|| panic!("{symbol} candidate exists"));
            candidates.push(JitRuntimeSymbolAddressCandidate::new(
                candidate.symbol_name().to_owned(),
                candidate.kind(),
                candidate.address(),
            ));
        }
        candidates.push(nix_jit_upval_get_address_candidate().expect("upval candidate builds"));
        candidates.push(nix_jit_deopt_address_candidate().expect("deopt candidate builds"));

        let source_ir = lower_source("1").expect("trivial source lowers");
        let mut eval = TreeWalk::new(&source_ir);
        let outer = EvalFrame::new(1).expect("outer frame allocates");
        outer.set(0, Value::int(41)).expect("outer slot stores");
        let inner = EvalFrame::new(1).expect("inner frame allocates");
        let env = EvalEnv::capture(&[outer, inner]).expect("env captures");

        let outcome = run_registered_native_thunk_call(
            &mut eval,
            source_ir.root,
            Span::new(0, 1),
            &env,
            artifact,
            &candidates,
        )
        .expect("native arithmetic call runs");

        assert!(
            outcome.trap().is_none(),
            "unexpected trap: {:?}",
            outcome.trap()
        );
        assert_eq!(outcome.value().as_int(), Ok(42));
    }

    #[test]
    fn forced_env_slot_candidates_report_runtime_ffi_wrapper_with_no_blockers() {
        let preflight = nix_jit_runtime_symbol_address_candidate_preflight()
            .expect("address candidate preflight builds");

        for symbol_name in FORCED_ENV_SLOT_IMPORTS {
            let provenance = preflight
                .address_provenance_for_symbol(symbol_name)
                .expect("forced env-slot import has address provenance");
            assert!(
                provenance.is_runtime_ffi_native_wrapper(),
                "{symbol_name} must resolve to a runtime-FFI native wrapper"
            );
            let blockers = provenance
                .runtime_ffi_remaining_export_blockers()
                .expect("runtime-FFI wrapper provenance carries blockers");
            assert!(
                blockers.is_empty(),
                "{symbol_name} runtime-FFI wrapper must have no remaining blockers"
            );
        }
    }
}
