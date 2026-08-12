//! Candidate value-ABI selection and literal lowering policy.

use ratchet_core::{IrArena, IrId};
use ratchet_jit::{
    JitClifArtifact, JitValueAbi, lower_candidate_b_constant_ir_thunk_body_artifact,
    lower_candidate_c_constant_ir_thunk_body_artifact,
};

use super::NixJitTier1Engine;

pub(super) fn configured_literal_value_abi() -> JitValueAbi {
    match std::env::var("AOS_NIX_JIT_VALUE_ABI").as_deref() {
        Ok("candidate-b") => JitValueAbi::CandidateB,
        Ok("candidate-c") => JitValueAbi::CandidateC,
        _ => JitValueAbi::Active,
    }
}

pub(super) fn lower_literal(
    value_abi: JitValueAbi,
    arena: &IrArena,
    root: IrId,
) -> Option<JitClifArtifact> {
    match value_abi {
        JitValueAbi::CandidateB => {
            lower_candidate_b_constant_ir_thunk_body_artifact(arena, root).ok()
        }
        JitValueAbi::CandidateC => {
            lower_candidate_c_constant_ir_thunk_body_artifact(arena, root).ok()
        }
        JitValueAbi::Active => None,
    }
}

impl NixJitTier1Engine {
    /// Enables Candidate C's one-word ABI for arena-independent literal thunks.
    ///
    /// Other bodies, wide integers, and floats retain the active two-word ABI.
    /// This is the deterministic builder counterpart of setting
    /// `AOS_NIX_JIT_VALUE_ABI=candidate-c`.
    #[must_use]
    pub fn candidate_c_value_abi(mut self) -> Self {
        self.literal_value_abi = JitValueAbi::CandidateC;
        self
    }

    /// Enables Candidate B's one-word ABI for allocation-free literal thunks.
    ///
    /// Other bodies, boxed integers, and floats retain the active two-word ABI.
    /// This is the deterministic builder counterpart of setting
    /// `AOS_NIX_JIT_VALUE_ABI=candidate-b`.
    #[must_use]
    pub fn candidate_b_value_abi(mut self) -> Self {
        self.literal_value_abi = JitValueAbi::CandidateB;
        self
    }
}
