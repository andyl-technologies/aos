//! Tier-1 publish-then-dispatch conformance against the tree-walk oracle.
//!
//! [`native_differential`](super::native_differential) finalizes a forced
//! environment-slot artifact and calls it once through the registered
//! native-call path. This module takes the next step on the publish path: it
//! finalizes the same artifact *once*, installs it into the evaluator's
//! type-erased tier-1 side-table as an [`OpaqueTier1Slot`], publishes the slot
//! behind the [`jit_tier1_publish_enabled`](TreeWalkOptions::jit_tier1_publish_enabled)
//! flag, and then dispatches the published entry through the finalized-thunk
//! wrapper. It compares the dispatched value (or trap) with the value (or error)
//! produced by forcing the same thunk directly through the tree-walk oracle.
//!
//! ```text
//! finalize: lower forced env-slot artifact -> Rc<finalization> (pins native code)
//! install:  side_table[thunk] = OpaqueTier1Slot{ entry_addr, owner=Tier1Entry(Rc), Empty }
//! publish:  eval.publish_tier1_slot(thunk)  // Ok(true) iff flag on AND thunk Suspended
//! dispatch: downcast owner -> Rc<finalization> -> run_finalized_native_thunk_call
//! verify:   dispatched value/trap == oracle force value/error; code pointer unmoved
//! ```
//!
//! The publish step never touches the force path: force advances the thunk cell's
//! own `Suspended -> Blackhole -> Forced` state machine and never reads the
//! side-table, so a prior or racing force always beats publish. Three
//! configurations exercise that contract: publish enabled over a suspended thunk
//! (publish wins), a force before publish (force wins, publish no-ops), and the
//! flag disabled (publish is a no-op and dispatch still agrees with the oracle).

use std::rc::Rc;

use ratchet_core::{Ir, IrId, syntax::Span};
use ratchet_jit::{
    JitCraneliftModuleSetupError, JitCraneliftNativeCallError,
    JitCraneliftRegisteredArtifactFinalizationPreflight,
    jit_cranelift_registered_artifact_finalization_preflight_with_candidates,
    lower_forced_env_get_ir_thunk_body_artifact,
};
use ratchet_oracle::eval::tree_walk::{TreeWalk, TreeWalkError, TreeWalkOptions};
use ratchet_oracle::eval::{EvalEnv, EvalFrame, ForceError, OpaqueTier1Slot};
use ratchet_oracle::runtime::forcing::rust_callable_aos_force;
use ratchet_runtime_ffi::{RuntimeTrap, run_finalized_native_thunk_call};
use ratchet_value::value::Value;
use thiserror::Error;

use super::native_differential::{
    NixJitForcedEnvSlotNativeDifferentialError, binding_thunk, forced_env_slot_candidates,
    local_slot_zero_arena, lower_source,
};

/// Configuration selecting how a tier-1 publish-then-dispatch run is exercised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixJitTier1PublishDispatchConfig {
    /// Whether the evaluator's tier-1 publish flag is enabled for the run.
    pub publish_enabled: bool,
    /// Whether the target thunk is forced through the oracle before publishing.
    ///
    /// When true, the thunk cell advances past `Suspended` before publish runs,
    /// so publish must lose to the force and become a no-op.
    pub force_before_publish: bool,
}

impl NixJitTier1PublishDispatchConfig {
    /// Publishes over a suspended thunk with the flag enabled (publish wins).
    pub const fn publish_wins() -> Self {
        Self {
            publish_enabled: true,
            force_before_publish: false,
        }
    }

    /// Forces the thunk before publishing with the flag enabled (force wins).
    pub const fn force_before_publish() -> Self {
        Self {
            publish_enabled: true,
            force_before_publish: true,
        }
    }

    /// Leaves the publish flag disabled (publish is a no-op).
    pub const fn flag_disabled() -> Self {
        Self {
            publish_enabled: false,
            force_before_publish: false,
        }
    }
}

/// The reconciled result of one tier-1 publish-then-dispatch run.
///
/// The dispatched side and the oracle side agree in one of two ways: both
/// produce the same value, or both fail (the oracle returns a tree-walk error
/// and dispatched native code transfers a trap).
#[derive(Clone, Debug)]
pub enum NixJitTier1DispatchAgreement {
    /// Both sides succeeded and produced representationally equal values.
    Value {
        /// The value from forcing the thunk directly through the oracle.
        oracle: Value,
        /// The value returned by dispatching the published tier-1 entry.
        native: Value,
    },
    /// Both sides failed: the oracle errored and dispatch transferred a trap.
    Trap {
        /// The tree-walk error from forcing the thunk directly through the oracle.
        oracle_error: TreeWalkError,
        /// The trap transferred out of the dispatched native forcing wrapper.
        native_trap: RuntimeTrap,
    },
}

impl NixJitTier1DispatchAgreement {
    /// Returns true when both sides produced equal values.
    pub const fn is_value(&self) -> bool {
        matches!(self, Self::Value { .. })
    }

    /// Returns true when both sides failed (oracle error and native trap).
    pub const fn is_trap(&self) -> bool {
        matches!(self, Self::Trap { .. })
    }
}

/// The full report of one tier-1 publish-then-dispatch run.
#[derive(Clone, Debug)]
pub struct NixJitTier1PublishDispatchOutcome {
    /// How the dispatched entry agreed with the tree-walk oracle.
    agreement: NixJitTier1DispatchAgreement,
    /// Whether [`TreeWalk::publish_tier1_slot`] performed the publish transition.
    published: bool,
    /// Whether the installed slot is published after the publish attempt.
    slot_published: bool,
    /// Whether the finalized code pointer was identical before and after dispatch
    /// and matched the address recorded in the installed slot (no moving GC).
    code_pointer_stable: bool,
}

impl NixJitTier1PublishDispatchOutcome {
    /// Returns how the dispatched entry agreed with the tree-walk oracle.
    pub const fn agreement(&self) -> &NixJitTier1DispatchAgreement {
        &self.agreement
    }

    /// Returns whether this run performed the `Empty -> Published` transition.
    pub const fn published(&self) -> bool {
        self.published
    }

    /// Returns whether the installed slot is published after the attempt.
    pub const fn slot_published(&self) -> bool {
        self.slot_published
    }

    /// Returns whether the finalized code pointer stayed pinned across dispatch.
    pub const fn code_pointer_stable(&self) -> bool {
        self.code_pointer_stable
    }
}

/// Owns a finalized tier-1 artifact so its native entry stays callable.
///
/// The finalized artifact keeps its encapsulated Cranelift module — and hence the
/// executable code the entry address points at — alive. Wrapping it in an [`Rc`]
/// lets the evaluator side-table own the entry (type-erased) while a dispatcher
/// clones an independent handle to run the call without aliasing the mutable
/// evaluator borrow.
struct NixJitTier1DispatchEntry {
    finalization: Rc<JitCraneliftRegisteredArtifactFinalizationPreflight>,
}

impl NixJitTier1DispatchEntry {
    /// Wraps a finalized artifact as a shareable tier-1 dispatch entry.
    fn new(finalization: JitCraneliftRegisteredArtifactFinalizationPreflight) -> Self {
        Self {
            finalization: Rc::new(finalization),
        }
    }

    /// Returns the finalized native entry address the dispatcher calls through.
    fn entry_addr(&self) -> usize {
        self.finalization.finalized_function().code_ptr().as_ptr() as usize
    }

    /// Returns an independent shared handle to the finalized artifact.
    fn finalization(&self) -> Rc<JitCraneliftRegisteredArtifactFinalizationPreflight> {
        Rc::clone(&self.finalization)
    }
}

/// A failure while running a tier-1 publish-then-dispatch conformance sample.
#[derive(Debug, Error)]
pub enum NixJitTier1PublishDispatchError {
    /// A shared setup step (source lowering, binding projection, frame, or
    /// candidate building) borrowed from the native differential failed.
    #[error(transparent)]
    Setup(#[from] NixJitForcedEnvSlotNativeDifferentialError),

    /// The forced environment-slot artifact could not be finalized.
    #[error("forced environment-slot artifact could not be finalized")]
    Finalize(#[source] JitCraneliftModuleSetupError),

    /// The target thunk could not be installed into the tier-1 side-table.
    #[error("target thunk could not be installed into the tier-1 side-table")]
    Install,

    /// No installed slot was found for the target thunk at dispatch time.
    #[error("no tier-1 slot was installed for the target thunk")]
    SlotMissing,

    /// The installed slot owner was not the expected tier-1 dispatch entry.
    #[error("installed tier-1 slot owner was not a dispatch entry")]
    OwnerDowncast,

    /// Forcing the thunk through the oracle before publishing failed unexpectedly.
    #[error("forcing the target thunk through the oracle failed")]
    OracleForce(#[source] TreeWalkError),

    /// Decoding the target thunk state during publish failed.
    #[error("target thunk state could not be decoded during publish")]
    Publish(#[source] ForceError),

    /// The dispatched finalized native thunk call failed to execute.
    #[error("dispatched finalized native thunk call failed")]
    NativeCall(#[source] JitCraneliftNativeCallError),

    /// The oracle and dispatched sides disagreed on success, failure, or value.
    #[error("tier-1 dispatch diverged from the tree-walk oracle: {reason}")]
    Divergence {
        /// A human-readable description of how the two sides diverged.
        reason: String,
    },
}

/// Result returned by tier-1 publish-then-dispatch conformance samples.
pub type NixJitTier1PublishDispatchResult =
    Result<NixJitTier1PublishDispatchOutcome, NixJitTier1PublishDispatchError>;

/// Finalizes, installs, publishes, and dispatches a forced env-slot tier-1 entry.
///
/// `source` must be an attribute set literal and `binding` names one of its
/// attributes. The attribute's suspended thunk is placed in environment slot 0
/// of a capture frame. A forced env-slot artifact is finalized once and installed
/// into the evaluator's tier-1 side-table; the slot is then published (subject to
/// `config`) and dispatched through the finalized-thunk wrapper. The dispatched
/// value (or trap) is reconciled against forcing the same thunk directly through
/// the oracle on a separate evaluator.
///
/// The returned [`NixJitTier1PublishDispatchOutcome`] records the oracle
/// agreement, whether publish performed its transition, whether the slot is
/// published, and whether the finalized code pointer stayed pinned across
/// dispatch. Callers inspect [`NixJitTier1PublishDispatchOutcome::published`] to
/// confirm publish wins over a suspended thunk and loses to a prior force.
///
/// # Errors
///
/// Returns [`NixJitTier1PublishDispatchError::Setup`] when a shared setup step
/// fails; [`NixJitTier1PublishDispatchError::Finalize`] when the artifact cannot
/// be finalized; [`NixJitTier1PublishDispatchError::Install`] when the slot
/// cannot be installed; [`NixJitTier1PublishDispatchError::SlotMissing`] or
/// [`NixJitTier1PublishDispatchError::OwnerDowncast`] when the installed slot
/// cannot be recovered for dispatch;
/// [`NixJitTier1PublishDispatchError::OracleForce`] when the pre-publish force
/// fails; [`NixJitTier1PublishDispatchError::NativeCall`] when dispatch fails; and
/// [`NixJitTier1PublishDispatchError::Divergence`] when the two sides disagree.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
pub fn nix_jit_tier1_forced_env_slot_publish_dispatch(
    source: &str,
    binding: &[u8],
    config: NixJitTier1PublishDispatchConfig,
) -> NixJitTier1PublishDispatchResult {
    let source_ir = lower_source(source)?;
    let source_span = Span::new(0, source.len() as u32);

    let oracle = oracle_force_binding(&source_ir, binding, source_span)?;
    let dispatch = native_publish_dispatch(&source_ir, binding, source_span, config)?;

    let agreement = reconcile(oracle, &dispatch)?;
    Ok(NixJitTier1PublishDispatchOutcome {
        agreement,
        published: dispatch.published,
        slot_published: dispatch.slot_published,
        code_pointer_stable: dispatch.code_pointer_stable,
    })
}

/// Forces the named binding thunk directly through the tree-walk oracle.
fn oracle_force_binding(
    source_ir: &Ir,
    binding: &[u8],
    source_span: Span,
) -> Result<Result<Value, TreeWalkError>, NixJitTier1PublishDispatchError> {
    let mut eval = TreeWalk::new(source_ir);
    let thunk = binding_thunk(&mut eval, source_ir, binding)?;
    Ok(rust_callable_aos_force(
        &mut eval,
        source_ir.root,
        source_span,
        thunk,
    ))
}

/// The dispatched-side result of one publish-then-dispatch run.
struct NativeDispatchResult {
    value: Value,
    trap: Option<RuntimeTrap>,
    published: bool,
    slot_published: bool,
    code_pointer_stable: bool,
}

/// Installs, publishes, and dispatches the finalized tier-1 entry against a walk.
fn native_publish_dispatch(
    source_ir: &Ir,
    binding: &[u8],
    source_span: Span,
    config: NixJitTier1PublishDispatchConfig,
) -> Result<NativeDispatchResult, NixJitTier1PublishDispatchError> {
    let arena = local_slot_zero_arena();
    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .map_err(NixJitForcedEnvSlotNativeDifferentialError::LowerArtifact)?;
    let candidates = forced_env_slot_candidates()?;
    let finalization = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact,
        &candidates,
    )
    .map_err(NixJitTier1PublishDispatchError::Finalize)?;

    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(config.publish_enabled);
    let mut eval = TreeWalk::with_options(source_ir, options);
    let thunk = binding_thunk(&mut eval, source_ir, binding)?;
    let frame = EvalFrame::new(1).map_err(NixJitForcedEnvSlotNativeDifferentialError::Frame)?;
    frame
        .set(0, thunk)
        .map_err(NixJitForcedEnvSlotNativeDifferentialError::Frame)?;
    // Dispatch owns the environment snapshot the wrapper decodes; the captured
    // frame is the innermost frame `aos_env_get` reads its locals from.
    let env =
        EvalEnv::capture(&[frame]).map_err(NixJitForcedEnvSlotNativeDifferentialError::Frame)?;

    let entry = NixJitTier1DispatchEntry::new(finalization);
    let entry_addr = entry.entry_addr();
    if !eval.install_tier1_slot(thunk, OpaqueTier1Slot::new(entry_addr, Box::new(entry))) {
        return Err(NixJitTier1PublishDispatchError::Install);
    }

    // A prior force must beat publish: forcing here advances the thunk cell past
    // `Suspended` before publish consults the side-table, so publish no-ops.
    if config.force_before_publish {
        rust_callable_aos_force(&mut eval, source_ir.root, source_span, thunk)
            .map_err(NixJitTier1PublishDispatchError::OracleForce)?;
    }

    let published = eval
        .publish_tier1_slot(thunk)
        .map_err(NixJitTier1PublishDispatchError::Publish)?;

    // Recover the finalized artifact from the type-erased slot for dispatch, and
    // record the pre-dispatch code pointer for the no-moving-GC invariant. The
    // immutable borrow of `eval` ends with this block so the dispatch below can
    // take the mutable evaluator borrow the runtime context needs.
    let (finalization, pre_code_ptr, slot_entry_addr, slot_published) = {
        let slot = eval
            .tier1_slot(thunk)
            .ok_or(NixJitTier1PublishDispatchError::SlotMissing)?;
        let entry = slot
            .owner()
            .downcast_ref::<NixJitTier1DispatchEntry>()
            .ok_or(NixJitTier1PublishDispatchError::OwnerDowncast)?;
        let finalization = entry.finalization();
        let pre_code_ptr = finalization.finalized_function().code_ptr();
        (
            finalization,
            pre_code_ptr,
            slot.entry_addr(),
            slot.is_published(),
        )
    };

    let outcome = run_finalized_native_thunk_call(
        &mut eval,
        source_ir.root,
        source_span,
        &env,
        &finalization,
    )
    .map_err(NixJitTier1PublishDispatchError::NativeCall)?;

    // No moving GC relocated the finalized code: the module owner is retained
    // through the shared handle, so the code pointer is identical before and
    // after dispatch and matches the address recorded in the slot.
    let post_code_ptr = finalization.finalized_function().code_ptr();
    let code_pointer_stable =
        pre_code_ptr == post_code_ptr && pre_code_ptr.as_ptr() as usize == slot_entry_addr;

    Ok(NativeDispatchResult {
        value: outcome.value(),
        trap: outcome.into_trap(),
        published,
        slot_published,
        code_pointer_stable,
    })
}

/// Reconciles the oracle force result with the dispatched native result.
fn reconcile(
    oracle: Result<Value, TreeWalkError>,
    dispatch: &NativeDispatchResult,
) -> Result<NixJitTier1DispatchAgreement, NixJitTier1PublishDispatchError> {
    match (oracle, &dispatch.trap) {
        (Ok(oracle_value), None) => {
            if oracle_value.raw_eq(dispatch.value) {
                Ok(NixJitTier1DispatchAgreement::Value {
                    oracle: oracle_value,
                    native: dispatch.value,
                })
            } else {
                Err(NixJitTier1PublishDispatchError::Divergence {
                    reason: format!(
                        "oracle produced {oracle_value:?} but dispatch produced {:?}",
                        dispatch.value
                    ),
                })
            }
        }
        (Err(oracle_error), Some(native_trap)) => Ok(NixJitTier1DispatchAgreement::Trap {
            oracle_error,
            native_trap: native_trap.clone(),
        }),
        (Ok(oracle_value), Some(native_trap)) => Err(NixJitTier1PublishDispatchError::Divergence {
            reason: format!(
                "oracle produced {oracle_value:?} but dispatch transferred a trap {native_trap:?}"
            ),
        }),
        (Err(oracle_error), None) => Err(NixJitTier1PublishDispatchError::Divergence {
            reason: format!(
                "oracle failed with {oracle_error:?} but dispatch produced {:?}",
                dispatch.value
            ),
        }),
    }
}

// JIT is off by construction under the Candidate-C variant; re-enabled at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use super::*;

    #[test]
    fn publish_then_dispatch_matches_tree_walk_scalar() {
        let outcome = nix_jit_tier1_forced_env_slot_publish_dispatch(
            "{ v = 40 + 2; }",
            b"v",
            NixJitTier1PublishDispatchConfig::publish_wins(),
        )
        .expect("tier-1 publish-then-dispatch runs");

        assert!(outcome.published(), "publish wins over a suspended thunk");
        assert!(outcome.slot_published());
        assert!(
            outcome.code_pointer_stable(),
            "finalized code pointer must stay pinned across dispatch"
        );
        let NixJitTier1DispatchAgreement::Value { oracle, native } = outcome.agreement() else {
            panic!(
                "expected a value-agreement outcome, got {:?}",
                outcome.agreement()
            );
        };
        assert_eq!(oracle.as_int(), Ok(42));
        assert_eq!(native.as_int(), Ok(42));
        assert!(oracle.raw_eq(*native));
    }

    #[test]
    fn publish_then_dispatch_matches_tree_walk_bool() {
        let outcome = nix_jit_tier1_forced_env_slot_publish_dispatch(
            "{ v = true && false; }",
            b"v",
            NixJitTier1PublishDispatchConfig::publish_wins(),
        )
        .expect("tier-1 publish-then-dispatch runs");

        assert!(outcome.published());
        assert!(outcome.agreement().is_value());
        let NixJitTier1DispatchAgreement::Value { native, .. } = outcome.agreement() else {
            panic!(
                "expected a value-agreement outcome, got {:?}",
                outcome.agreement()
            );
        };
        assert_eq!(native.as_bool(), Ok(false));
    }

    #[test]
    fn publish_then_dispatch_transfers_trap_instead_of_aborting() {
        // Forcing `1 / 0` fails in the tree walk. Because dispatch runs under a
        // RuntimeTrapScope, the forcing wrapper transfers the error out as a trap
        // instead of aborting this test process.
        let outcome = nix_jit_tier1_forced_env_slot_publish_dispatch(
            "{ v = 1 / 0; }",
            b"v",
            NixJitTier1PublishDispatchConfig::publish_wins(),
        )
        .expect("tier-1 publish-then-dispatch runs to a trap agreement");

        assert!(outcome.published());
        let NixJitTier1DispatchAgreement::Trap {
            oracle_error,
            native_trap,
        } = outcome.agreement()
        else {
            panic!(
                "expected a trap-agreement outcome, got {:?}",
                outcome.agreement()
            );
        };
        assert!(matches!(
            native_trap,
            RuntimeTrap::Force(trap_error) if trap_error == oracle_error
        ));
    }

    #[test]
    fn a_prior_force_beats_publish() {
        let outcome = nix_jit_tier1_forced_env_slot_publish_dispatch(
            "{ v = 40 + 2; }",
            b"v",
            NixJitTier1PublishDispatchConfig::force_before_publish(),
        )
        .expect("tier-1 publish-then-dispatch runs");

        assert!(
            !outcome.published(),
            "publish must lose to a thunk that a prior force already advanced past Suspended"
        );
        assert!(!outcome.slot_published());
        // Dispatch still agrees with the oracle: the already-forced thunk yields
        // its cached value through the finalized entry.
        let NixJitTier1DispatchAgreement::Value { native, .. } = outcome.agreement() else {
            panic!(
                "expected a value-agreement outcome, got {:?}",
                outcome.agreement()
            );
        };
        assert_eq!(native.as_int(), Ok(42));
    }

    #[test]
    fn flag_disabled_leaves_publish_a_no_op_but_dispatch_still_agrees() {
        let outcome = nix_jit_tier1_forced_env_slot_publish_dispatch(
            "{ v = 40 + 2; }",
            b"v",
            NixJitTier1PublishDispatchConfig::flag_disabled(),
        )
        .expect("tier-1 publish-then-dispatch runs");

        assert!(
            !outcome.published(),
            "publish is a no-op when the tier-1 publish flag is disabled"
        );
        assert!(!outcome.slot_published());
        assert!(outcome.code_pointer_stable());
        // Flag off changes no observable behavior: dispatch still matches oracle.
        let NixJitTier1DispatchAgreement::Value { oracle, native } = outcome.agreement() else {
            panic!(
                "expected a value-agreement outcome, got {:?}",
                outcome.agreement()
            );
        };
        assert_eq!(oracle.as_int(), Ok(42));
        assert!(oracle.raw_eq(*native));
    }
}
