//! Helper-calling native differentials for the remaining lowerable shapes.
//!
//! The sibling `native_differential` module covers the forced environment-slot
//! read (`aos_env_get` + `aos_force`). This module extends the same
//! compile-execute-compare pattern to the other bounded tier-1 shapes the
//! lowerer supports: static attribute selection (`aos_select_ic`), attribute
//! presence (`aos_has_attr`), direct application (`aos_apply`), and attribute-set
//! update (`aos_update`). Together they are the foundation for the RFC-0007
//! Phase-B conformance CHECK across the compiled helper surface.
//!
//! Each shape is verified two ways against a live tree-walk oracle:
//!
//! - value mode: both sides compute a value; scalar results are compared by
//!   representation (`raw_eq`) after forcing to weak head normal form, and the
//!   attribute-set result of `update` is compared leaf-by-leaf on named keys
//!   (heap identities differ across the two evaluators, so container identity
//!   equality is not meaningful).
//! - trap mode: the operation itself fails (a missing attribute, applying a
//!   non-function, updating a non-attribute-set, or forcing a failing receiver).
//!   The native side transfers a [`RuntimeTrap`] instead of aborting and the
//!   oracle returns the matching tree-walk error.
//!
//! Native execution runs through [`run_registered_native_thunk_call`], which
//! installs a [`RuntimeTrapScope`] so a failing shape is observable rather than
//! fatal. Each side runs on its own [`TreeWalk`]; both evaluators stay live
//! through reconciliation so their results can be forced to weak head normal
//! form before comparison.

use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode,
    syntax::{BinOpKind, Span, Symbol, SymbolTable},
};
use ratchet_jit::{
    JitClifArtifact, JitCraneliftNativeCallError, JitLowerError, JitRuntimeSymbolAddressCandidate,
    lower_apply_local_slots_ir_root_thunk_body_artifact,
    lower_force_aware_tier1_ir_thunk_body_artifact,
    lower_has_attr_local_slot_ir_root_thunk_body_artifact,
    lower_select_local_slot_ir_root_thunk_body_artifact,
    lower_update_local_slots_ir_root_thunk_body_artifact,
};
use ratchet_oracle::eval::tree_walk::TreeWalkError;
use ratchet_oracle::runtime::attr::{
    rust_callable_aos_has_attr, rust_callable_aos_select_ic, rust_callable_aos_update,
};
use ratchet_oracle::runtime::forcing::rust_callable_aos_force;
use ratchet_oracle::{
    compile::resolve,
    eval::{EvalEnv, EvalEnvError, EvalFrame, tree_walk::TreeWalk},
    runtime::apply::rust_callable_aos_apply,
    syntax::parse_str,
};
use ratchet_runtime_ffi::{RuntimeTrap, run_registered_native_thunk_call};
use ratchet_value::value::Value;
use thiserror::Error;

use crate::jit::{
    NixJitRuntimeSymbolAddressCandidateError, nix_jit_deopt_address_candidate,
    nix_jit_runtime_symbol_address_candidate_preflight,
};

/// The inline-cache site id used by the attribute-access shape fixtures.
const SHAPE_SITE: IrInlineCacheSiteId = IrInlineCacheSiteId::new(13);

/// The reconciled result of one shape native differential.
///
/// A run agrees either by producing equal values or by both sides failing (the
/// oracle returns a tree-walk error and native code transfers a trap). Any other
/// combination is a divergence and is surfaced as an error.
#[derive(Clone, Debug)]
pub enum ShapeDifferentialOutcome {
    /// Both sides produced values judged equal for the shape's comparison mode.
    Value {
        /// The forced value (or container) from the tree-walk oracle.
        oracle: Value,
        /// The forced value (or container) returned by native code.
        native: Value,
    },
    /// Both sides failed: the oracle errored and native code transferred a trap.
    Trap {
        /// The tree-walk error from the oracle side.
        oracle_error: TreeWalkError,
        /// The trap transferred out of native code.
        native_trap: RuntimeTrap,
    },
}

impl ShapeDifferentialOutcome {
    /// Returns true when both sides produced equal values.
    pub const fn is_value(&self) -> bool {
        matches!(self, Self::Value { .. })
    }

    /// Returns true when both sides failed (oracle error and native trap).
    pub const fn is_trap(&self) -> bool {
        matches!(self, Self::Trap { .. })
    }
}

/// A failure while running a shape native differential.
#[derive(Debug, Error)]
pub enum ShapeDifferentialError {
    /// The differential source program could not be parsed, resolved, or lowered.
    #[error("differential source program could not be lowered: {message}")]
    SourceProgram {
        /// The display text of the underlying parse, resolve, or lower error.
        message: String,
    },

    /// A named binding could not be projected out of the source program.
    #[error("differential binding {binding} could not be projected: {reason}")]
    BindingProjection {
        /// The binding name that could not be projected.
        binding: String,
        /// Why the projection failed.
        reason: &'static str,
    },

    /// The capture frame could not be allocated or populated.
    #[error(transparent)]
    Frame(#[from] EvalEnvError),

    /// The shape artifact could not be lowered.
    #[error("shape artifact could not be lowered")]
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

    /// Native code produced a value that could not be forced to WHNF in value mode.
    #[error("forcing the native result to weak head normal form failed: {error:?}")]
    ForceNativeResult {
        /// The underlying tree-walk error.
        error: TreeWalkError,
    },

    /// The oracle and native sides disagreed on success, failure, or value.
    #[error("shape native differential diverged from the tree-walk oracle: {reason}")]
    Divergence {
        /// A human-readable description of how the two sides diverged.
        reason: String,
    },
}

/// Result returned by shape native differentials.
pub type ShapeDifferentialResult = Result<ShapeDifferentialOutcome, ShapeDifferentialError>;

/// Runs a static attribute-selection differential against the tree-walk oracle.
///
/// `receiver_source` must evaluate to an attribute set; that set is captured in
/// slot 0 and `attr` is selected through the compiled `aos_env_get` +
/// `aos_force` + `aos_select_ic` body. Selecting a present scalar attribute is a
/// value-mode run; selecting a missing attribute is a trap-mode run.
///
/// # Errors
///
/// Returns a [`ShapeDifferentialError`] variant when the source cannot be
/// lowered, the receiver is not an attribute set, the artifact or candidates
/// cannot be built, the native call fails, the native result cannot be forced,
/// or the two sides diverge.
pub fn nix_jit_static_select_native_differential(
    receiver_source: &str,
    attr: &[u8],
) -> ShapeDifferentialResult {
    let source_ir = lower_source(receiver_source)?;
    let span = source_span(receiver_source);
    let id = source_ir.root;
    let (symbols, symbol) = intern_attr(&source_ir, attr)?;
    let shape_ir = static_select_ir(symbols, symbol);

    let mut oracle_eval = TreeWalk::new(&source_ir);
    let oracle_attrs = eval_attrs(&mut oracle_eval, attr)?;
    let oracle =
        rust_callable_aos_select_ic(&mut oracle_eval, id, span, oracle_attrs, symbol, SHAPE_SITE)
            .and_then(|value| rust_callable_aos_force(&mut oracle_eval, id, span, value));

    let artifact = lower_select_local_slot_ir_root_thunk_body_artifact(&shape_ir)
        .map_err(ShapeDifferentialError::LowerArtifact)?;
    let candidates = candidates_for(&[
        "aos_env_get",
        "aos_force",
        "aos_jit_stack_map_enter",
        "aos_jit_stack_map_exit",
        "aos_select_ic",
    ])?;
    let mut native_eval = TreeWalk::new(&source_ir);
    let attrs = eval_attrs(&mut native_eval, attr)?;
    let native = run_and_force_scalar(&mut native_eval, id, span, &[attrs], artifact, &candidates)?;

    reconcile_scalar(oracle, native)
}

/// Runs an attribute-presence differential against the tree-walk oracle.
///
/// `receiver_source` must evaluate to an attribute set captured in slot 0;
/// `attr` presence is tested through the compiled `aos_env_get` + `aos_force` +
/// `aos_has_attr` body. Presence and absence are both value-mode runs (the
/// result is a boolean), so this path exercises value agreement only.
///
/// # Errors
///
/// Returns a [`ShapeDifferentialError`] variant under the same conditions as
/// [`nix_jit_static_select_native_differential`].
pub fn nix_jit_static_has_attr_native_differential(
    receiver_source: &str,
    attr: &[u8],
) -> ShapeDifferentialResult {
    let source_ir = lower_source(receiver_source)?;
    let span = source_span(receiver_source);
    let id = source_ir.root;
    let (symbols, symbol) = intern_attr(&source_ir, attr)?;
    let shape_ir = static_has_attr_ir(symbols, symbol);

    let mut oracle_eval = TreeWalk::new(&source_ir);
    let oracle_attrs = eval_attrs(&mut oracle_eval, attr)?;
    let oracle =
        rust_callable_aos_has_attr(&mut oracle_eval, id, span, oracle_attrs, symbol, SHAPE_SITE)
            .and_then(|value| rust_callable_aos_force(&mut oracle_eval, id, span, value));

    let artifact = lower_has_attr_local_slot_ir_root_thunk_body_artifact(&shape_ir)
        .map_err(ShapeDifferentialError::LowerArtifact)?;
    let candidates = candidates_for(&[
        "aos_env_get",
        "aos_force",
        "aos_jit_stack_map_enter",
        "aos_jit_stack_map_exit",
        "aos_has_attr",
    ])?;
    let mut native_eval = TreeWalk::new(&source_ir);
    let attrs = eval_attrs(&mut native_eval, attr)?;
    let native = run_and_force_scalar(&mut native_eval, id, span, &[attrs], artifact, &candidates)?;

    reconcile_scalar(oracle, native)
}

/// Runs a direct-application differential against the tree-walk oracle.
///
/// `function_source` is captured in slot 0 and `argument` in slot 1, then
/// applied through the compiled `aos_env_get` + `aos_apply` body. A lambda whose
/// forced result is a scalar is a value-mode run; a non-function receiver is a
/// trap-mode run.
///
/// # Errors
///
/// Returns a [`ShapeDifferentialError`] variant under the same conditions as
/// [`nix_jit_static_select_native_differential`].
pub fn nix_jit_apply_native_differential(
    function_source: &str,
    argument: Value,
) -> ShapeDifferentialResult {
    let source_ir = lower_source(function_source)?;
    let span = source_span(function_source);
    let id = source_ir.root;
    let shape_ir = apply_ir();

    let mut oracle_eval = TreeWalk::new(&source_ir);
    let oracle_function = eval_root_value(&mut oracle_eval, b"function")?;
    let oracle = rust_callable_aos_apply(&mut oracle_eval, id, span, oracle_function, argument)
        .and_then(|value| rust_callable_aos_force(&mut oracle_eval, id, span, value));

    let artifact = lower_apply_local_slots_ir_root_thunk_body_artifact(&shape_ir)
        .map_err(ShapeDifferentialError::LowerArtifact)?;
    let candidates = candidates_for(&["aos_env_get", "aos_apply"])?;
    let mut native_eval = TreeWalk::new(&source_ir);
    let function = eval_root_value(&mut native_eval, b"function")?;
    let native = run_and_force_scalar(
        &mut native_eval,
        id,
        span,
        &[function, argument],
        artifact,
        &candidates,
    )?;

    reconcile_scalar(oracle, native)
}

/// Runs an attribute-set update differential against the tree-walk oracle.
///
/// `source` must bind `left` and `right`; their values are captured in slots 0
/// and 1 and merged through the compiled `aos_env_get` + `aos_force` +
/// `aos_update` body. When both operands are attribute sets it is a value-mode
/// run whose merged result is compared leaf-by-leaf on `leaf_keys`; when an
/// operand is not an attribute set it is a trap-mode run.
///
/// # Errors
///
/// Returns a [`ShapeDifferentialError`] variant under the same conditions as
/// [`nix_jit_static_select_native_differential`], plus a divergence when any
/// compared leaf key differs between the two merged attribute sets.
pub fn nix_jit_update_native_differential(
    source: &str,
    leaf_keys: &[&[u8]],
) -> ShapeDifferentialResult {
    let source_ir = lower_source(source)?;
    let span = source_span(source);
    let id = source_ir.root;
    let left_symbol = attr_symbol(&source_ir, b"left")?;
    let right_symbol = attr_symbol(&source_ir, b"right")?;
    let shape_ir = update_ir();

    let mut oracle_eval = TreeWalk::new(&source_ir);
    let (oracle_left, oracle_right) =
        capture_binding_pair(&mut oracle_eval, left_symbol, right_symbol)?;
    let oracle = rust_callable_aos_force(&mut oracle_eval, id, span, oracle_left)
        .and_then(|left| {
            rust_callable_aos_force(&mut oracle_eval, id, span, oracle_right)
                .map(|right| (left, right))
        })
        .and_then(|(left, right)| {
            rust_callable_aos_update(&mut oracle_eval, id, span, left, right)
        });

    let artifact = lower_update_local_slots_ir_root_thunk_body_artifact(&shape_ir)
        .map_err(ShapeDifferentialError::LowerArtifact)?;
    let candidates = candidates_for(&[
        "aos_env_get",
        "aos_force",
        "aos_jit_stack_map_enter",
        "aos_jit_stack_map_exit",
        "aos_update",
    ])?;
    let mut native_eval = TreeWalk::new(&source_ir);
    let (native_left, native_right) =
        capture_binding_pair(&mut native_eval, left_symbol, right_symbol)?;
    let native = run_native(
        &mut native_eval,
        id,
        span,
        &[native_left, native_right],
        artifact,
        &candidates,
    )?;

    reconcile_update(
        oracle,
        native,
        &source_ir,
        leaf_keys,
        &mut oracle_eval,
        &mut native_eval,
        id,
        span,
    )
}

/// Runs a scalar integer arithmetic/comparison differential against the oracle.
///
/// `left_src` and `right_src` are Nix expressions captured in slots 0 and 1;
/// they are combined through the compiled `aos_env_get` + `aos_force` + inline
/// arithmetic body for `op`. The oracle side evaluates the equivalent
/// `(left_src) <op> (right_src)` source directly. Integer operands that both
/// sides evaluate successfully are a value-mode run; an operation the tree walk
/// errors on (division by zero or the `i64::MIN / -1` overflow) is a trap-mode
/// run in which the inline guards branch to the deopt trampoline.
///
/// Cases where the tree walk succeeds but the inline path must deopt (a
/// non-integer operand) are intentionally not exercised here: this harness runs
/// the compiled body directly and treats a native trap as a failure, whereas the
/// live engine re-runs such a body on the tree walk. Those silent-deopt cases are
/// covered end to end by the engine-level tests.
///
/// # Errors
///
/// Returns a [`ShapeDifferentialError`] variant under the same conditions as
/// [`nix_jit_static_select_native_differential`].
pub fn nix_jit_arith_native_differential(
    left_src: &str,
    right_src: &str,
    op: BinOpKind,
) -> ShapeDifferentialResult {
    let op_text = op_source_text(op);
    let oracle_source = format!("({left_src}) {op_text} ({right_src})");
    let oracle_ir = lower_source(&oracle_source)?;
    let oracle_span = source_span(&oracle_source);
    let oracle_id = oracle_ir.root;
    let mut oracle_eval = TreeWalk::new(&oracle_ir);
    let oracle = match oracle_eval.eval_root() {
        Ok(value) => rust_callable_aos_force(&mut oracle_eval, oracle_id, oracle_span, value),
        Err(error) => Err(error),
    };

    let capture_source = format!("{{ left = ({left_src}); right = ({right_src}); }}");
    let source_ir = lower_source(&capture_source)?;
    let span = source_span(&capture_source);
    let id = source_ir.root;
    let left_symbol = attr_symbol(&source_ir, b"left")?;
    let right_symbol = attr_symbol(&source_ir, b"right")?;
    let shape_ir = arith_ir(op);

    let artifact = lower_force_aware_tier1_ir_thunk_body_artifact(&shape_ir.arena, shape_ir.root)
        .map_err(ShapeDifferentialError::LowerArtifact)?;
    let candidates = candidates_for(&[
        "aos_env_get",
        "aos_force",
        "aos_jit_stack_map_enter",
        "aos_jit_stack_map_exit",
        "aos_deopt",
    ])?;
    let mut native_eval = TreeWalk::new(&source_ir);
    let (left, right) = capture_binding_pair(&mut native_eval, left_symbol, right_symbol)?;
    let native = run_and_force_scalar(
        &mut native_eval,
        id,
        span,
        &[left, right],
        artifact,
        &candidates,
    )?;

    reconcile_scalar(oracle, native)
}

/// Returns the Nix source operator text for a supported scalar operator.
fn op_source_text(op: BinOpKind) -> &'static str {
    match op {
        BinOpKind::Add => "+",
        BinOpKind::Sub => "-",
        BinOpKind::Mul => "*",
        BinOpKind::Div => "/",
        BinOpKind::Lt => "<",
        BinOpKind::Gt => ">",
        BinOpKind::Le => "<=",
        BinOpKind::Ge => ">=",
        BinOpKind::Eq => "==",
        BinOpKind::Ne => "!=",
        _ => "+",
    }
}

/// The value and trap observed from one native execution.
struct NativeResult {
    value: Value,
    trap: Option<RuntimeTrap>,
}

/// The forced native side of a scalar shape: either a trap or a forced value.
enum NativeScalar {
    /// Native code transferred a trap out of the call.
    Trap(RuntimeTrap),
    /// Native code produced a value, forced here to weak head normal form.
    Value(Value),
}

/// Builds a capture frame from `slots`, runs the artifact, and returns the raw result.
fn run_native(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    slots: &[Value],
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<NativeResult, ShapeDifferentialError> {
    let frame = EvalFrame::new(slots.len())?;
    for (slot, value) in slots.iter().enumerate() {
        frame.set(slot as u32, *value)?;
    }
    // Dispatch owns the environment snapshot the wrapper decodes; the populated
    // frame is the innermost frame `aos_env_get` reads its locals from.
    let env = EvalEnv::capture(&[frame])?;
    let outcome = run_registered_native_thunk_call(eval, id, span, &env, artifact, candidates)
        .map_err(ShapeDifferentialError::NativeCall)?;
    Ok(NativeResult {
        value: outcome.value(),
        trap: outcome.into_trap(),
    })
}

/// Runs the artifact and forces its result to WHNF unless it transferred a trap.
fn run_and_force_scalar(
    eval: &mut TreeWalk,
    id: IrId,
    span: Span,
    slots: &[Value],
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<NativeScalar, ShapeDifferentialError> {
    let native = run_native(eval, id, span, slots, artifact, candidates)?;
    match native.trap {
        Some(trap) => Ok(NativeScalar::Trap(trap)),
        None => rust_callable_aos_force(eval, id, span, native.value)
            .map(NativeScalar::Value)
            .map_err(|error| ShapeDifferentialError::ForceNativeResult { error }),
    }
}

/// Reconciles a scalar-result shape: values must be equal, or both sides fail.
fn reconcile_scalar(
    oracle: Result<Value, TreeWalkError>,
    native: NativeScalar,
) -> ShapeDifferentialResult {
    match (oracle, native) {
        (Ok(oracle), NativeScalar::Value(native)) => {
            if oracle.raw_eq(native) {
                Ok(ShapeDifferentialOutcome::Value { oracle, native })
            } else {
                Err(ShapeDifferentialError::Divergence {
                    reason: format!("oracle produced {oracle:?} but native produced {native:?}"),
                })
            }
        }
        (Err(oracle_error), NativeScalar::Trap(native_trap)) => {
            Ok(ShapeDifferentialOutcome::Trap {
                oracle_error,
                native_trap,
            })
        }
        (Ok(oracle), NativeScalar::Trap(native_trap)) => Err(ShapeDifferentialError::Divergence {
            reason: format!(
                "oracle produced {oracle:?} but native transferred a trap {native_trap:?}"
            ),
        }),
        (Err(oracle_error), NativeScalar::Value(native)) => {
            Err(ShapeDifferentialError::Divergence {
                reason: format!(
                    "oracle failed with {oracle_error:?} but native produced {native:?}"
                ),
            })
        }
    }
}

/// Reconciles the attribute-set `update` shape by comparing forced leaf keys.
#[allow(clippy::too_many_arguments)]
fn reconcile_update(
    oracle: Result<Value, TreeWalkError>,
    native: NativeResult,
    source_ir: &Ir,
    leaf_keys: &[&[u8]],
    oracle_eval: &mut TreeWalk,
    native_eval: &mut TreeWalk,
    id: IrId,
    span: Span,
) -> ShapeDifferentialResult {
    match (oracle, native.trap) {
        (Ok(oracle_attrs), None) => {
            for key in leaf_keys {
                let symbol = attr_symbol(source_ir, key)?;
                let oracle_leaf =
                    forced_attr_leaf(oracle_eval, oracle_attrs, symbol, id, span, key)?;
                let native_leaf =
                    forced_attr_leaf(native_eval, native.value, symbol, id, span, key)?;
                if !oracle_leaf.raw_eq(native_leaf) {
                    return Err(ShapeDifferentialError::Divergence {
                        reason: format!(
                            "update leaf {:?} diverged: oracle {oracle_leaf:?} vs native {native_leaf:?}",
                            String::from_utf8_lossy(key)
                        ),
                    });
                }
            }
            Ok(ShapeDifferentialOutcome::Value {
                oracle: oracle_attrs,
                native: native.value,
            })
        }
        (Err(oracle_error), Some(native_trap)) => Ok(ShapeDifferentialOutcome::Trap {
            oracle_error,
            native_trap,
        }),
        (Ok(_), Some(native_trap)) => Err(ShapeDifferentialError::Divergence {
            reason: format!(
                "oracle produced an attrset but native transferred a trap {native_trap:?}"
            ),
        }),
        (Err(oracle_error), None) => Err(ShapeDifferentialError::Divergence {
            reason: format!("oracle failed with {oracle_error:?} but native produced an attrset"),
        }),
    }
}

/// Forces the value of attribute `key` in `attrs` to a WHNF leaf.
fn forced_attr_leaf(
    eval: &mut TreeWalk,
    attrs: Value,
    symbol: Symbol,
    id: IrId,
    span: Span,
    key: &[u8],
) -> Result<Value, ShapeDifferentialError> {
    let binding = eval
        .heap()
        .get_attrs(attrs)
        .map_err(|_| ShapeDifferentialError::Divergence {
            reason: "update result is not an attribute set".to_owned(),
        })?
        .get(symbol)
        .ok_or_else(|| ShapeDifferentialError::Divergence {
            reason: format!(
                "update result is missing leaf {:?}",
                String::from_utf8_lossy(key)
            ),
        })?;
    rust_callable_aos_force(eval, id, span, binding)
        .map_err(|error| ShapeDifferentialError::ForceNativeResult { error })
}

/// Evaluates the source root and returns it as an attribute-set value.
fn eval_attrs(eval: &mut TreeWalk, binding: &[u8]) -> Result<Value, ShapeDifferentialError> {
    eval.eval_root()
        .map_err(|_| ShapeDifferentialError::BindingProjection {
            binding: String::from_utf8_lossy(binding).into_owned(),
            reason: "source root did not evaluate to an attribute set",
        })
}

/// Evaluates the source root and returns it as a value (e.g. a lambda).
fn eval_root_value(eval: &mut TreeWalk, binding: &[u8]) -> Result<Value, ShapeDifferentialError> {
    eval.eval_root()
        .map_err(|_| ShapeDifferentialError::BindingProjection {
            binding: String::from_utf8_lossy(binding).into_owned(),
            reason: "source root did not evaluate",
        })
}

/// Evaluates `{ left = ...; right = ...; }` and returns the raw `left`/`right` values.
fn capture_binding_pair(
    eval: &mut TreeWalk,
    left_symbol: Symbol,
    right_symbol: Symbol,
) -> Result<(Value, Value), ShapeDifferentialError> {
    let root = eval_attrs(eval, b"root")?;
    let attrs =
        eval.heap()
            .get_attrs(root)
            .map_err(|_| ShapeDifferentialError::BindingProjection {
                binding: "root".to_owned(),
                reason: "source root did not evaluate to an attribute set",
            })?;
    let left = attrs
        .get(left_symbol)
        .ok_or(ShapeDifferentialError::BindingProjection {
            binding: "left".to_owned(),
            reason: "attribute set has no `left` binding",
        })?;
    let right = attrs
        .get(right_symbol)
        .ok_or(ShapeDifferentialError::BindingProjection {
            binding: "right".to_owned(),
            reason: "attribute set has no `right` binding",
        })?;
    Ok((left, right))
}

/// Builds the registered candidates named by `symbols` from the shared preflight.
///
/// `aos_deopt` is a JIT-internal deopt trampoline rather than an oracle helper,
/// so it is not present in the preflight and is sourced from its dedicated
/// address candidate.
fn candidates_for(
    symbols: &[&'static str],
) -> Result<Vec<JitRuntimeSymbolAddressCandidate>, ShapeDifferentialError> {
    let preflight = nix_jit_runtime_symbol_address_candidate_preflight()?;
    let mut candidates = Vec::with_capacity(symbols.len());
    for symbol_name in symbols {
        if *symbol_name == "aos_deopt" {
            candidates.push(nix_jit_deopt_address_candidate()?);
            continue;
        }
        let candidate = preflight
            .address_candidate_for(symbol_name)
            .ok_or(ShapeDifferentialError::MissingCandidate { symbol_name })?;
        candidates.push(JitRuntimeSymbolAddressCandidate::new(
            candidate.symbol_name().to_owned(),
            candidate.kind(),
            candidate.address(),
        ));
    }
    Ok(candidates)
}

/// Interns attribute `name` into a clone of the source symbol table.
///
/// Returning the interned table alongside the symbol lets the shape IR reference
/// an attribute that the receiver may not contain (an absent-attribute or
/// missing-selection fixture): interning yields the existing id when the name is
/// already present and a fresh id otherwise, and the same id is used by both the
/// lowered artifact and the oracle helper.
fn intern_attr(
    source_ir: &Ir,
    name: &[u8],
) -> Result<(SymbolTable, Symbol), ShapeDifferentialError> {
    let mut symbols = source_ir.symbols.clone();
    let symbol = symbols
        .intern(name)
        .map_err(|_| ShapeDifferentialError::BindingProjection {
            binding: String::from_utf8_lossy(name).into_owned(),
            reason: "attribute name could not be interned",
        })?;
    Ok((symbols, symbol))
}

/// Resolves the interned symbol for attribute `name` in `source_ir`.
fn attr_symbol(source_ir: &Ir, name: &[u8]) -> Result<Symbol, ShapeDifferentialError> {
    source_ir
        .symbols
        .symbols()
        .iter()
        .position(|symbol| symbol.as_slice() == name)
        .map(|index| Symbol::new(index as u32))
        .ok_or_else(|| ShapeDifferentialError::BindingProjection {
            binding: String::from_utf8_lossy(name).into_owned(),
            reason: "attribute name is not interned in the source symbol table",
        })
}

/// Returns the full-source span for a differential program.
fn source_span(source: &str) -> Span {
    Span::new(0, source.len() as u32)
}

/// Parses, resolves, and lowers a differential source program into Core IR.
fn lower_source(source: &str) -> Result<Ir, ShapeDifferentialError> {
    let parsed = parse_str(source).map_err(|error| ShapeDifferentialError::SourceProgram {
        message: format!("{error:?}"),
    })?;
    let resolved = resolve(parsed).map_err(|error| ShapeDifferentialError::SourceProgram {
        message: format!("{error:?}"),
    })?;
    aos_nix_dialect::nix_lower(resolved).map_err(|error| ShapeDifferentialError::SourceProgram {
        message: format!("{error:?}"),
    })
}

/// Builds the lowered IR for a static attribute selection on local slot 0.
fn static_select_ir(symbols: SymbolTable, symbol: Symbol) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    default: None,
                    site: SHAPE_SITE,
                },
            ),
        ],
        Vec::new(),
    );
    single_attr_ir(arena, symbols, symbol)
}

/// Builds the lowered IR for a static attribute presence test on local slot 0.
fn static_has_attr_ir(symbols: SymbolTable, symbol: Symbol) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
            IrNode::new(
                IrKind::HasAttr,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::HasAttr {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: SHAPE_SITE,
                },
            ),
        ],
        Vec::new(),
    );
    single_attr_ir(arena, symbols, symbol)
}

/// Wraps a two-node attribute-access arena into a full single-key `Ir`.
fn single_attr_ir(arena: IrArena, symbols: SymbolTable, symbol: Symbol) -> Ir {
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

/// Builds the lowered IR for applying local slot 0 to local slot 1.
fn apply_ir() -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local { slot: 1 },
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    binary_slot_ir(arena)
}

/// Builds the lowered IR for updating local slot 0 with local slot 1.
fn update_ir() -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local { slot: 1 },
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    binary_slot_ir(arena)
}

/// Builds the lowered IR for applying `op` to local slot 0 and local slot 1.
fn arith_ir(op: BinOpKind) -> Ir {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 0 },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local { slot: 1 },
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );
    binary_slot_ir(arena)
}

/// Wraps a three-node binary-of-two-slots arena into a full `Ir` with root 2.
fn binary_slot_ir(arena: IrArena) -> Ir {
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

#[cfg(test)]
mod tests;
