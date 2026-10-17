//! Canonical historical original native service prefixes on controller eight.
//!
//! The fixed 256-byte big-endian record copies original source evidence. It
//! contains no native pointer and cannot admit another evaluation or certify
//! readiness, input closure or complete owner custody.
//!
//! ```text
//! version:u32be=1 | size:u32be=256 | scope/preparation/grant/command:[32;4]
//! sequence/cut/raw_before/raw_after:u64be | evaluated:Position24
//! evaluation_id/generation:u64be | resulting:Position24 | service_count:u64be
//! status/flags:u32be | signed_end:i32be | reserved:u32be
//! Position24: time_ps/microstep:u64be | phase/reserved:u32be
//! ```

// SPDX-License-Identifier: Apache-2.0

use super::{NativeCommandError, NativeEffectCompute};
use crucible_node_contract::{Phase, Position, U64};

/// Distinguishes an original partial prefix from completion and uncertain effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeEffectProgressStatus {
    /// Preserves authentic service progress within an outstanding original grant.
    PartialPrefix = 1,
    /// Preserves a genuinely completed interval and source-owned exclusive park.
    Completed = 2,
    /// Retains original progress whose effects or final custody remain uncertain.
    EffectsUnknown = 3,
}

/// Retains exact original native progress without sampling a stop or rerunning effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEffectProgress {
    /// Correlates the complete original prepared scope.
    pub scope: [u8; 32],
    /// Correlates the complete original effect preparation.
    pub effect_preparation: [u8; 32],
    /// Correlates the original independently admitted grant.
    pub grant_digest: [u8; 32],
    /// Correlates the unchanged complete original command.
    pub command_digest: [u8; 32],
    /// Identifies that original command sequence.
    pub sequence: U64,
    /// Identifies the source-owned original effect cut.
    pub cut_id: U64,
    /// Copies actual raw progress before the retained evaluation.
    pub raw_before: U64,
    /// Copies actual raw progress after the retained evaluation.
    pub raw_after: U64,
    /// Copies the actual source evaluation position.
    pub evaluated: Position,
    /// Identifies the evaluated original source entry.
    pub evaluation_id: U64,
    /// Identifies its original source incarnation.
    pub evaluation_generation: U64,
    /// Copies the source-owned resulting cursor without raw-count projection.
    pub resulting: Position,
    /// Copies the authentic returned service count.
    pub returned_service_count: U64,
    /// Retains the original disposition without converting a prefix to completion.
    pub status: NativeEffectProgressStatus,
    /// Preserves the signed original source end outcome.
    pub end_result: i32,
}

impl NativeEffectProgress {
    /// Checks exact original correlation and retained bounds without granting effects.
    ///
    /// # Errors
    /// Rejects foreign identity, inconsistent retained counters, invalid position or false completion.
    pub fn validate_against(
        &self,
        original: &NativeEffectCompute,
    ) -> Result<(), NativeCommandError> {
        original.validate()?;
        if self.scope != original.command.scope.identity_digest()?
            || self.effect_preparation != original.effect_preparation
            || self.grant_digest != original.command.authorization_digest
            || self.command_digest != original.command.identity_digest()?
            || self.sequence != original.command.sequence
            || self.cut_id.get() == 0
            || self.evaluation_id.get() == 0
            || self.evaluation_generation.get() == 0
            || (self.status != NativeEffectProgressStatus::EffectsUnknown
                && (self.raw_after.get().checked_sub(self.raw_before.get())
                    != Some(self.returned_service_count.get())
                    || self.returned_service_count > original.maximum_service_span))
            || self.evaluated.phase != Phase::Reaction
            || self.evaluated < original.command.kind.start()
            || self.evaluated >= original.command.kind.limit()
            || self.resulting < original.command.kind.start()
            || (self.status != NativeEffectProgressStatus::EffectsUnknown
                && self.resulting < self.evaluated)
            || self.resulting > original.command.kind.limit()
            || (self.status == NativeEffectProgressStatus::Completed
                && self.resulting != original.command.kind.limit())
            || (self.end_result != 0 && self.status != NativeEffectProgressStatus::EffectsUnknown)
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes fixed canonical scalars; no Rust or QEMU native layout crosses the boundary.
    ///
    /// # Errors
    /// Rejects empty source identity or an invalid reserved record shape.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        if self.sequence.get() == 0 || self.cut_id.get() == 0 {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(256)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&256u32.to_be_bytes());
        for digest in [
            &self.scope,
            &self.effect_preparation,
            &self.grant_digest,
            &self.command_digest,
        ] {
            bytes.extend_from_slice(digest);
        }
        for scalar in [self.sequence, self.cut_id, self.raw_before, self.raw_after] {
            bytes.extend_from_slice(&scalar.get().to_be_bytes());
        }
        encode_position(&mut bytes, self.evaluated);
        bytes.extend_from_slice(&self.evaluation_id.get().to_be_bytes());
        bytes.extend_from_slice(&self.evaluation_generation.get().to_be_bytes());
        encode_position(&mut bytes, self.resulting);
        bytes.extend_from_slice(&self.returned_service_count.get().to_be_bytes());
        bytes.extend_from_slice(&(self.status as u32).to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&self.end_result.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes the closed original 256-byte record without source authority.
    ///
    /// # Errors
    /// Rejects incorrect extent/version, unknown statuses/phases or reserved fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        use super::codec::Cursor;
        if bytes.len() != 256 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != 256 {
            return Err(NativeCommandError::UnsupportedVersion(8));
        }
        let scope = cursor.array()?;
        let effect_preparation = cursor.array()?;
        let grant_digest = cursor.array()?;
        let command_digest = cursor.array()?;
        let sequence = U64::new(cursor.u64()?);
        let cut_id = U64::new(cursor.u64()?);
        let raw_before = U64::new(cursor.u64()?);
        let raw_after = U64::new(cursor.u64()?);
        let evaluated = decode_position(&mut cursor)?;
        let evaluation_id = U64::new(cursor.u64()?);
        let evaluation_generation = U64::new(cursor.u64()?);
        let resulting = decode_position(&mut cursor)?;
        let returned_service_count = U64::new(cursor.u64()?);
        let status = match cursor.u32()? {
            1 => NativeEffectProgressStatus::PartialPrefix,
            2 => NativeEffectProgressStatus::Completed,
            3 => NativeEffectProgressStatus::EffectsUnknown,
            _ => return Err(NativeCommandError::Conflict),
        };
        if cursor.u32()? != 0 {
            return Err(NativeCommandError::Conflict);
        }
        let end_result = i32::from_be_bytes(
            cursor
                .take(4)?
                .try_into()
                .map_err(|_| NativeCommandError::ResourceLimit)?,
        );
        if cursor.u32()? != 0 || sequence.get() == 0 || cut_id.get() == 0 {
            return Err(NativeCommandError::Conflict);
        }
        Ok(Self {
            scope,
            effect_preparation,
            grant_digest,
            command_digest,
            sequence,
            cut_id,
            raw_before,
            raw_after,
            evaluated,
            evaluation_id,
            evaluation_generation,
            resulting,
            returned_service_count,
            status,
            end_result,
        })
    }
}

fn encode_position(bytes: &mut Vec<u8>, position: Position) {
    bytes.extend_from_slice(&position.time_ps.get().to_be_bytes());
    bytes.extend_from_slice(&position.microstep.get().to_be_bytes());
    bytes.extend_from_slice(&(position.phase as u32).to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
}

fn decode_position(cursor: &mut super::codec::Cursor<'_>) -> Result<Position, NativeCommandError> {
    let time_ps = U64::new(cursor.u64()?);
    let microstep = U64::new(cursor.u64()?);
    let phase = match cursor.u32()? {
        0 => Phase::BoundaryControl,
        1 => Phase::Publication,
        2 => Phase::Delivery,
        3 => Phase::Reaction,
        _ => return Err(NativeCommandError::Conflict),
    };
    if cursor.u32()? != 0 {
        return Err(NativeCommandError::Conflict);
    }
    Ok(Position {
        time_ps,
        microstep,
        phase,
    })
}
