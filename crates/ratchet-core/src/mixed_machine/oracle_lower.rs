//! Exact-identity lowering of real oracle Node bodies into packed superblocks.
//!
//! This is the front end of the mixed runner adapter. It recovers the Node
//! body's resolver frame from immutable IR, lowers the real body through the
//! packed STG table, and retains an exact work identity suitable for
//! [`MixedForceGuards`]. Translation from the packed expression table into the
//! validated force/update CFG remains a separate mechanical step.

use thiserror::Error;

use super::MixedCodeIdentity;
use crate::analysis::{IrFrameIdentity, IrFrameIdentityError, resolve_unique_ir_frame};
use crate::stg::{
    StgCodeBlock, StgCodeKey, StgDecline, StgLowerError, StgLowerOutcome, StgModuleId, StgOpcode,
    lower_stg_code_block,
};
use crate::{Ir, IrId};

/// A real frame-specialized Node body ready for mixed-CFG translation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedOracleNodeBlock {
    work: MixedCodeIdentity,
    code: StgCodeBlock,
    apply_sites: u32,
}

impl MixedOracleNodeBlock {
    /// Returns the exact identity a runtime must match before claiming work.
    pub const fn work(&self) -> MixedCodeIdentity {
        self.work
    }

    /// Returns the packed real-IR expression table.
    pub const fn code(&self) -> &StgCodeBlock {
        &self.code
    }

    /// Returns the number of unary application nodes in the lowered block.
    pub const fn apply_sites(&self) -> u32 {
        self.apply_sites
    }
}

/// Conservative reason a real Node body did not enter the target grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedOracleNodeDecline {
    /// The body is not reachable from the immutable module root.
    UnreachableFrame,
    /// The shared body occurs under more than one resolver frame.
    AmbiguousFrame,
    /// Packed STG lowering conservatively rejected part of the body.
    Stg(StgDecline),
    /// The body contains no unary application and cannot cover Node/Apply work.
    NoApply,
}

/// Result of attempting the first real Node/Apply superblock lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedOracleNodeLowerOutcome {
    /// The complete body and at least one unary application were lowered.
    Lowered(MixedOracleNodeBlock),
    /// The body was conservatively declined without an executable fragment.
    Declined(MixedOracleNodeDecline),
}

/// Reports malformed immutable IR encountered before atomic lowering.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MixedOracleNodeLowerError {
    /// Resolver-frame recovery encountered malformed IR side tables.
    #[error("mixed oracle frame recovery failed")]
    Frame(#[from] IrFrameIdentityError),
    /// Packed STG lowering encountered malformed IR.
    #[error("mixed oracle packed lowering failed")]
    Stg(#[from] StgLowerError),
}

/// Lowers one real source-backed Node body into the Node/Apply front-end grammar.
///
/// `module_id` is the evaluator-assigned collision-free identity used by the
/// packed-code cache, while `module_digest` remains the full identity checked
/// by the force guard. `definition` names the thunk-allocation or other stable
/// definition site. `capture_layout_digest` is supplied by the evaluator's
/// versioned capture layout analysis and participates in the pre-claim work
/// identity.
///
/// # Errors
///
/// Returns [`MixedOracleNodeLowerError`] when the immutable IR is malformed.
/// Unsupported but well-formed bodies return
/// [`MixedOracleNodeLowerOutcome::Declined`].
pub fn lower_mixed_oracle_node(
    ir: &Ir,
    module_id: StgModuleId,
    module_digest: [u8; 32],
    definition: IrId,
    body: IrId,
    capture_layout_digest: [u8; 32],
) -> Result<MixedOracleNodeLowerOutcome, MixedOracleNodeLowerError> {
    let frame = match resolve_unique_ir_frame(ir, body)? {
        IrFrameIdentity::Unique(frame) => frame,
        IrFrameIdentity::Ambiguous => {
            return Ok(MixedOracleNodeLowerOutcome::Declined(
                MixedOracleNodeDecline::AmbiguousFrame,
            ));
        }
        IrFrameIdentity::Unreachable => {
            return Ok(MixedOracleNodeLowerOutcome::Declined(
                MixedOracleNodeDecline::UnreachableFrame,
            ));
        }
    };
    let key = StgCodeKey::new(module_id, body, frame);
    let code = match lower_stg_code_block(ir, key)? {
        StgLowerOutcome::Lowered(code) => code,
        StgLowerOutcome::Declined(decline) => {
            return Ok(MixedOracleNodeLowerOutcome::Declined(
                MixedOracleNodeDecline::Stg(decline),
            ));
        }
    };
    let apply_sites = code
        .words()
        .iter()
        .filter(|word| word.opcode() == StgOpcode::Apply1)
        .count() as u32;
    if apply_sites == 0 {
        return Ok(MixedOracleNodeLowerOutcome::Declined(
            MixedOracleNodeDecline::NoApply,
        ));
    }
    Ok(MixedOracleNodeLowerOutcome::Lowered(MixedOracleNodeBlock {
        work: MixedCodeIdentity::new(
            module_digest,
            definition,
            body,
            frame,
            capture_layout_digest,
        ),
        code,
        apply_sites,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::parse_str;
    use crate::{IrData, lower, resolve};

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    #[test]
    fn lowers_a_real_frame_specialized_node_apply_body() {
        let ir = lowered("f: f 1");
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda { body, frame, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        let outcome =
            lower_mixed_oracle_node(&ir, StgModuleId::new(7), [7; 32], ir.root, body, [9; 32])
                .expect("lowering succeeds");
        let MixedOracleNodeLowerOutcome::Lowered(block) = outcome else {
            panic!("real unary apply body must lower");
        };
        assert_eq!(block.work().body, body);
        assert_eq!(block.work().frame, frame);
        assert_eq!(block.apply_sites(), 1);
    }

    #[test]
    fn declines_a_real_body_that_cannot_cover_apply_work() {
        let ir = lowered("x: x");
        let lambda = *ir.arena.node(ir.root).expect("lambda exists");
        let IrData::Lambda { body, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        assert_eq!(
            lower_mixed_oracle_node(&ir, StgModuleId::new(7), [7; 32], ir.root, body, [9; 32],)
                .expect("lowering succeeds"),
            MixedOracleNodeLowerOutcome::Declined(MixedOracleNodeDecline::NoApply)
        );
    }
}
