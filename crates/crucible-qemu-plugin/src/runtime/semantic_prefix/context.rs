//! Correlation checks for source-private prospective and active observations.
//!
//! The 192-byte record is copied inside the QEMU process. It has no wire codec
//! and grants no callback, FIFO or output permission. An installed consumer must
//! first authenticate the exact native root, epoch and cut through the source
//! getter. A prospective record cannot substitute for an active getter result.

// SPDX-License-Identifier: GPL-2.0-or-later

use crucible_node_contract::{Phase, Position, U64};

/// Copies the agreed source-native context layout without adopting native pointers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct NativeEffectContext {
    /// Identifies this closed native record as version one.
    pub version: u32,
    /// Specifies the complete 192-byte native record extent.
    pub size: u32,
    /// Correlates the original prepared owner scope.
    pub scope: [u8; 32],
    /// Correlates the complete original effect preparation.
    pub effect_preparation: [u8; 32],
    /// Correlates the original host-admitted grant.
    pub grant_digest: [u8; 32],
    /// Identifies the retained original command.
    pub command_sequence: u64,
    /// Copies the actual prospective or active native evaluation instant.
    pub time_ps: u64,
    /// Copies the actual evaluation's causal microstep.
    pub microstep: u64,
    /// Copies the evaluation phase, which must be Reaction.
    pub phase: u32,
    /// Remains zero in version one.
    pub reserved: u32,
    /// Identifies CPU service as one or an original timer evaluation as two.
    pub evaluation_kind: u32,
    /// Identifies no parent as zero, a CPU parent as one or a timer parent as two.
    pub parent_kind: u32,
    /// Identifies the source-selected original evaluation.
    pub evaluation_id: u64,
    /// Identifies that original evaluation's native incarnation.
    pub evaluation_generation: u64,
    /// Retains the genuine causal parent identity, or zero for an independent root.
    pub parent_id: u64,
    /// Retains the genuine causal parent incarnation, or zero without a parent.
    pub parent_generation: u64,
    /// Copies the actual live native raw counter without deriving a Position.
    pub actual_raw_counter: u64,
    /// Identifies the same source-retained original effect cut.
    pub effect_cut_id: u64,
}

/// Correlates observations against the already retained original command owner.
pub struct OriginalEffectExpectation {
    /// Retains the original prepared scope identity.
    pub scope: [u8; 32],
    /// Retains the complete original preparation identity.
    pub effect_preparation: [u8; 32],
    /// Retains the original admitted grant identity.
    pub grant_digest: [u8; 32],
    /// Retains the original command sequence.
    pub command_sequence: u64,
    /// Retains the source-issued cut identity previously bound to that command.
    pub effect_cut_id: u64,
    /// Bounds evaluations inclusively at the original full start position.
    pub start: Position,
    /// Bounds evaluations exclusively at the original full limit position.
    pub limit: Position,
    /// Bounds causal microsteps exclusively under the original preparation.
    pub maximum_microstep: u64,
}

/// Refuses malformed, foreign or out-of-grant copied observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectContextRefusal {
    /// Rejects an incomplete, unknown or internally inconsistent native record.
    Shape,
    /// Rejects correlation with another original preparation, grant or cut.
    Original,
    /// Rejects a position outside the original full-position interval.
    Position,
}

impl NativeEffectContext {
    /// Checks copied fields without installing admission or output authority.
    ///
    /// The raw counter is retained as an independent observation. This check
    /// neither derives a Position from it nor interprets a pending-begin record
    /// as an active callback. Authentic native getter identity remains mandatory.
    ///
    /// # Errors
    /// Rejects malformed fields, foreign original identities, exhausted bounds
    /// or an evaluation outside the retained full-position grant.
    pub fn validate_against(
        &self,
        original: &OriginalEffectExpectation,
    ) -> Result<Position, EffectContextRefusal> {
        if self.version != 1
            || self.size != 192
            || self.reserved != 0
            || self.phase != 3
            || !matches!(self.evaluation_kind, 1 | 2)
            || !matches!(self.parent_kind, 0..=2)
            || self.evaluation_id == 0
            || self.evaluation_generation == 0
            || (self.parent_kind == 0
                && (self.parent_id != 0 || self.parent_generation != 0 || self.microstep != 0))
            || (self.parent_kind != 0 && (self.parent_id == 0 || self.parent_generation == 0))
        {
            return Err(EffectContextRefusal::Shape);
        }
        if original.scope == [0; 32]
            || original.effect_preparation == [0; 32]
            || original.grant_digest == [0; 32]
            || original.command_sequence == 0
            || original.effect_cut_id == 0
            || self.scope != original.scope
            || self.effect_preparation != original.effect_preparation
            || self.grant_digest != original.grant_digest
            || self.command_sequence != original.command_sequence
            || self.effect_cut_id != original.effect_cut_id
        {
            return Err(EffectContextRefusal::Original);
        }

        let position = Position::new(
            U64::new(self.time_ps),
            U64::new(self.microstep),
            Phase::Reaction,
        );
        if original.start >= original.limit
            || original.maximum_microstep == 0
            || self.microstep >= original.maximum_microstep
            || position < original.start
            || position >= original.limit
        {
            return Err(EffectContextRefusal::Position);
        }
        Ok(position)
    }
}
