//! Non-executable CLIF artifact records for verified JIT lowerer output.
//!
//! This module wraps Cranelift [`Function`] values with the metadata the future
//! compile-once tier needs before executable code exists: tier, body kind, and
//! source identity. It does not allocate executable memory, create a
//! `JITModule`, bind symbols, or call native code.

use cranelift_codegen::ir::{Function, UserFuncName};
use ratchet_core::IrId;

use crate::tier::JitTier;

/// The by-value runtime representation used at one compiled artifact boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitValueAbi {
    /// The active two-word [`ratchet_value::value::Value`] ABI.
    Active,
    /// The Candidate-B one-word tagged-value ABI.
    CandidateB,
    /// The Candidate-C one-word compressed-value ABI.
    CandidateC,
}

/// The lowered body shape stored in a CLIF artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitClifArtifactKind {
    /// A compiled-thunk body using the frozen thunk runtime ABI.
    ThunkBody,
    /// A tier-2 compiled-lambda boundary entry using the frozen lambda ABI.
    ///
    /// The entry adapts the frozen `(rt, env, argument) -> Value` lambda-call
    /// signature onto a module-local recursive body function; only the entry is
    /// ever called from Rust (see `lower::lambda_rec`).
    Tier2LambdaEntry,
    /// A tier-2 fused curried-chain boundary entry using the frozen argv ABI.
    ///
    /// The entry adapts the frozen `(rt, env, argv) -> Value` multi-argument
    /// lambda-entry signature onto a module-local body function with `arity`
    /// unboxed chain parameters; only the entry is ever called from Rust (see
    /// `lower::lambda_chain`). The arity is recorded so the native call
    /// boundary can reject an `argv` run of the wrong length.
    Tier2LambdaChainEntry {
        /// The chain arity K the entry's `argv` run must carry.
        arity: u8,
    },
    /// A tier-2 fold-step boundary entry with a decoded `i64` accumulator.
    ///
    /// The entry adapts the frozen `(rt, env, acc: i64, elem) -> i64` fold-step
    /// signature ([`ratchet_core::RUNTIME_FOLD_STEP_I64ACC_CALL_SIGNATURE`]) onto
    /// a module-local arity-2 body function whose first parameter is the running
    /// accumulator, threaded across the native fold loop as a plain decoded
    /// integer with no per-element encode/decode round-trip. Only the entry is
    /// ever called from Rust (see `lower::lambda_chain`); it is produced only
    /// when the fold operator body is statically integer-typed, so its result is
    /// always a decoded integer and a per-element deopt is signaled out of band
    /// by the runtime trap flag.
    Tier2FoldStepI64AccEntry,
}

/// The source identity for a non-executable CLIF artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitClifArtifactSource {
    /// A standalone constant-body smoke test not associated with a Core IR root.
    ConstantSmoke,
    /// A Core IR root lowered as one per-expression thunk body.
    IrRoot(IrId),
}

/// A verified CLIF artifact that has not been made executable.
///
/// The contained [`Function`] is Cranelift IR only. This record is deliberately
/// address-free so future code can choose between inspection, caching,
/// `JITModule` compilation, or differential testing without conflating those
/// later steps with safe lowering. Artifacts are constructed by lowerer
/// entrypoints that verify the contained function first.
pub struct JitClifArtifact {
    tier: JitTier,
    kind: JitClifArtifactKind,
    source: JitClifArtifactSource,
    value_abi: JitValueAbi,
    function: Function,
}

impl JitClifArtifact {
    pub(crate) fn new(
        tier: JitTier,
        kind: JitClifArtifactKind,
        source: JitClifArtifactSource,
        function: Function,
    ) -> Self {
        Self {
            tier,
            kind,
            source,
            value_abi: JitValueAbi::Active,
            function,
        }
    }

    pub(crate) fn new_with_value_abi(
        tier: JitTier,
        kind: JitClifArtifactKind,
        source: JitClifArtifactSource,
        value_abi: JitValueAbi,
        function: Function,
    ) -> Self {
        Self {
            tier,
            kind,
            source,
            value_abi,
            function,
        }
    }

    /// Returns the JIT tier this artifact is intended to feed.
    pub const fn tier(&self) -> JitTier {
        self.tier
    }

    /// Returns the lowered body shape.
    pub const fn kind(&self) -> JitClifArtifactKind {
        self.kind
    }

    /// Returns the source identity associated with the artifact.
    pub const fn source(&self) -> JitClifArtifactSource {
        self.source
    }

    /// Returns the by-value representation used by this artifact's boundary.
    pub const fn value_abi(&self) -> JitValueAbi {
        self.value_abi
    }

    /// Returns the contained verified CLIF function.
    pub fn function(&self) -> &Function {
        &self.function
    }

    /// Returns the lowering-time cost estimate for this body.
    ///
    /// This is the profit proxy a promotion policy gates on: it classifies the
    /// body's CLIF instructions into runtime helper calls (which delegate rather
    /// than save work) and native compute (which replaces interpreter dispatch).
    /// See [`crate::cost`] for the model.
    pub fn cost_estimate(&self) -> crate::cost::Tier1BodyCost {
        crate::cost::estimate_tier1_body_cost(&self.function)
    }

    /// Returns the Cranelift user-function name for this artifact.
    pub fn function_name(&self) -> &UserFuncName {
        &self.function.name
    }

    /// Consumes the artifact and returns the contained CLIF function.
    pub fn into_function(self) -> Function {
        self.function
    }
}
