//! Typed original prefix history with distinct CPU and timer callback counts.
//!
//! These copied scalars establish correlation only. Native source authenticates
//! evaluation ancestry and retains the original cut independently of this record.
//! A timer callback can change device state without advancing the CPU raw count.
//!
//! ```text
//! version:u32be=2 | size:u32be=320 | scope/preparation/grant/command:[32;4]
//! sequence/cut/previous_cut/acknowledgement_sequence:u64be | raw_before/after:u64be
//! evaluated:Position24 | evaluation_kind/parent_kind:u32be | evaluation_id/generation/parent_id/generation:u64be
//! resulting:Position24 | prefix_cpu/prefix_callbacks/cumulative_cpu/cumulative_callbacks:u64be
//! status/flags:u32be | signed_end:i32be | reserved:u32be
//! ```

// SPDX-License-Identifier: Apache-2.0

use crucible_node_contract::{Phase, Position, U64};
use sha2::{Digest, Sha256};

use super::codec::Cursor;
use super::{
    NativeCommandError, NativeEffectCompute, NativeEffectProgress, NativeEffectProgressStatus,
};

/// Distinguishes one actual CPU service from an original timer callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativePrefixEvaluationKind {
    /// Identifies an original instruction service and its native CPU incarnation.
    CpuService = 1,
    /// Identifies an original timer arm and its retained arm generation.
    TimerCallback = 2,
}

/// Retains one source-produced original typed prefix without issuing another cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixProgress {
    /// Correlates the complete original prepared scope.
    pub scope: [u8; 32],
    /// Correlates the distinct controller-nine preparation.
    pub prefix_preparation: [u8; 32],
    /// Correlates the original host-admitted grant.
    pub grant_digest: [u8; 32],
    /// Correlates the immutable original command.
    pub command_digest: [u8; 32],
    /// Identifies that original command sequence.
    pub sequence: U64,
    /// Identifies the native retained cut for this prefix.
    pub cut_id: U64,
    /// Identifies the immutable preceding original cut.
    pub previous_cut_id: U64,
    /// Copies the native consumed acknowledgement of that preceding cut.
    pub acknowledgement_sequence: U64,
    /// Copies actual raw CPU progress before this evaluation.
    pub raw_before: U64,
    /// Copies actual raw CPU progress after this evaluation.
    pub raw_after: U64,
    /// Copies the authentic full source evaluation position.
    pub evaluated: Position,
    /// Identifies the evaluated source class independently of raw progress.
    pub evaluation_kind: NativePrefixEvaluationKind,
    /// Identifies the retained source parent class, or an independent root.
    pub parent_kind: Option<NativePrefixEvaluationKind>,
    /// Identifies the original CPU or timer entry.
    pub evaluation_id: U64,
    /// Identifies that entry's native incarnation or original arm generation.
    pub evaluation_generation: U64,
    /// Identifies the actual source parent, or zero for an independent root.
    pub parent_id: U64,
    /// Identifies its original generation, or zero for an independent root.
    pub parent_generation: U64,
    /// Copies the native resulting cursor without a raw-count projection.
    pub resulting: Position,
    /// Counts instruction retirements in this prefix independently of callbacks.
    pub cpu_retirements: U64,
    /// Counts timer callbacks in this prefix independently of CPU progress.
    pub timer_callbacks: U64,
    /// Counts cumulative retirements against the unchanged original command budget.
    pub cumulative_cpu_retirements: U64,
    /// Counts cumulative callbacks against the unchanged original command budget.
    pub cumulative_timer_callbacks: U64,
    /// Preserves PartialPrefix, Completed or EffectsUnknown exactly as returned.
    pub status: NativeEffectProgressStatus,
    /// Preserves the genuine signed scope-end outcome independently of progress.
    pub end_result: i32,
}

impl NativePrefixProgress {
    /// Checks local shape and complete original correlation without admitting effects.
    ///
    /// Parent identity is copied evidence. Native source must separately verify
    /// actual parent positions and callback payload ownership.
    ///
    /// # Errors
    /// Rejects foreign original fields, invalid class/ancestry shape, renewed budgets,
    /// inconsistent raw progress, positions outside the grant or false completion.
    pub fn validate_against(
        &self,
        original: &NativeEffectCompute,
    ) -> Result<(), NativeCommandError> {
        original.validate()?;
        self.validate_shape()?;
        let unknown = self.status == NativeEffectProgressStatus::EffectsUnknown;
        if self.scope != original.command.scope.identity_digest()?
            || self.prefix_preparation != original.effect_preparation
            || self.grant_digest != original.command.authorization_digest
            || self.command_digest != original.command.identity_digest()?
            || self.sequence != original.command.sequence
            || self.cumulative_cpu_retirements > original.maximum_service_span
            || self.cumulative_timer_callbacks.get() > u64::from(original.maximum_callbacks)
            || self.evaluated < original.command.kind.start()
            || self.evaluated >= original.command.kind.limit()
            || self.resulting < original.command.kind.start()
            || self.resulting > original.command.kind.limit()
            || (!unknown && self.resulting < self.evaluated)
            || (self.status == NativeEffectProgressStatus::Completed
                && self.resulting != original.command.kind.limit())
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Checks an original continuation against its exact retained initial prefix.
    ///
    /// # Errors
    /// Rejects foreign history, continuation after completion/uncertainty, changed
    /// cursor/raw anchors, wrong preceding ACK or renewed cumulative allowances.
    pub fn validate_after_initial(
        &self,
        original: &NativeEffectCompute,
        previous: &NativeEffectProgress,
    ) -> Result<(), NativeCommandError> {
        previous.validate_against(original)?;
        self.validate_link(
            original,
            Predecessor {
                cut_id: previous.cut_id,
                cursor: previous.resulting,
                raw_after: previous.raw_after,
                cpu_retirements: previous.returned_service_count,
                timer_callbacks: U64::new(0),
                next_acknowledgement_sequence: U64::new(1),
                status: previous.status,
            },
        )
    }

    /// Checks another typed prefix against the unchanged preceding original record.
    ///
    /// # Errors
    /// Rejects foreign history, completion/uncertainty, wrong original links, ACK
    /// sequence overflow or cumulative counts that do not subtract original budgets.
    pub fn validate_after_progress(
        &self,
        original: &NativeEffectCompute,
        previous: &Self,
    ) -> Result<(), NativeCommandError> {
        previous.validate_against(original)?;
        let next = previous
            .acknowledgement_sequence
            .get()
            .checked_add(1)
            .ok_or(NativeCommandError::ResourceLimit)?;
        self.validate_link(
            original,
            Predecessor {
                cut_id: previous.cut_id,
                cursor: previous.resulting,
                raw_after: previous.raw_after,
                cpu_retirements: previous.cumulative_cpu_retirements,
                timer_callbacks: previous.cumulative_timer_callbacks,
                next_acknowledgement_sequence: U64::new(next),
                status: previous.status,
            },
        )
    }

    fn validate_link(
        &self,
        original: &NativeEffectCompute,
        previous: Predecessor,
    ) -> Result<(), NativeCommandError> {
        self.validate_against(original)?;
        if previous.status != NativeEffectProgressStatus::PartialPrefix
            || self.previous_cut_id != previous.cut_id
            || self.acknowledgement_sequence != previous.next_acknowledgement_sequence
            || self.raw_before != previous.raw_after
            || self.evaluated < previous.cursor
            || previous
                .cpu_retirements
                .get()
                .checked_add(self.cpu_retirements.get())
                != Some(self.cumulative_cpu_retirements.get())
            || previous
                .timer_callbacks
                .get()
                .checked_add(self.timer_callbacks.get())
                != Some(self.cumulative_timer_callbacks.get())
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), NativeCommandError> {
        let unknown = self.status == NativeEffectProgressStatus::EffectsUnknown;
        if self.sequence.get() == 0
            || self.cut_id.get() == 0
            || self.previous_cut_id.get() == 0
            || self.cut_id == self.previous_cut_id
            || self.acknowledgement_sequence.get() == 0
            || self.evaluation_id.get() == 0
            || self.evaluation_generation.get() == 0
            || self.evaluated.phase != Phase::Reaction
            || (self.parent_kind.is_none()
                && (self.parent_id.get() != 0 || self.parent_generation.get() != 0))
            || (self.parent_kind.is_some()
                && (self.parent_id.get() == 0 || self.parent_generation.get() == 0))
            || (self.evaluation_kind == NativePrefixEvaluationKind::CpuService
                && self.timer_callbacks.get() != 0)
            || (self.evaluation_kind == NativePrefixEvaluationKind::TimerCallback
                && self.cpu_retirements.get() != 0)
            || self.cpu_retirements > self.cumulative_cpu_retirements
            || self.timer_callbacks > self.cumulative_timer_callbacks
            || (!unknown
                && (self.end_result != 0
                    || self.raw_after.get().checked_sub(self.raw_before.get())
                        != Some(self.cpu_retirements.get())))
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes the fixed version-two canonical record without native addresses.
    ///
    /// # Errors
    /// Rejects malformed local shape or bounded allocation failure.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate_shape()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(320)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&320u32.to_be_bytes());
        for digest in [
            &self.scope,
            &self.prefix_preparation,
            &self.grant_digest,
            &self.command_digest,
        ] {
            bytes.extend_from_slice(digest);
        }
        for scalar in [
            self.sequence,
            self.cut_id,
            self.previous_cut_id,
            self.acknowledgement_sequence,
            self.raw_before,
            self.raw_after,
        ] {
            bytes.extend_from_slice(&scalar.get().to_be_bytes());
        }
        encode_position(&mut bytes, self.evaluated);
        bytes.extend_from_slice(&(self.evaluation_kind as u32).to_be_bytes());
        bytes.extend_from_slice(&self.parent_kind.map_or(0, |kind| kind as u32).to_be_bytes());
        for scalar in [
            self.evaluation_id,
            self.evaluation_generation,
            self.parent_id,
            self.parent_generation,
        ] {
            bytes.extend_from_slice(&scalar.get().to_be_bytes());
        }
        encode_position(&mut bytes, self.resulting);
        for scalar in [
            self.cpu_retirements,
            self.timer_callbacks,
            self.cumulative_cpu_retirements,
            self.cumulative_timer_callbacks,
        ] {
            bytes.extend_from_slice(&scalar.get().to_be_bytes());
        }
        bytes.extend_from_slice(&(self.status as u32).to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&self.end_result.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one closed typed prefix record without adopting its authority.
    ///
    /// # Errors
    /// Rejects incorrect size/version, unknown classes/statuses/phases, reserved fields
    /// or malformed local identity, counters and ancestry shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 320 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 2 || cursor.u32()? != 320 {
            return Err(NativeCommandError::Conflict);
        }
        let scope = cursor.array()?;
        let prefix_preparation = cursor.array()?;
        let grant_digest = cursor.array()?;
        let command_digest = cursor.array()?;
        let sequence = U64::new(cursor.u64()?);
        let cut_id = U64::new(cursor.u64()?);
        let previous_cut_id = U64::new(cursor.u64()?);
        let acknowledgement_sequence = U64::new(cursor.u64()?);
        let raw_before = U64::new(cursor.u64()?);
        let raw_after = U64::new(cursor.u64()?);
        let evaluated = decode_position(&mut cursor)?;
        let evaluation_kind = decode_kind(cursor.u32()?)?;
        let parent_kind = match cursor.u32()? {
            0 => None,
            kind => Some(decode_kind(kind)?),
        };
        let evaluation_id = U64::new(cursor.u64()?);
        let evaluation_generation = U64::new(cursor.u64()?);
        let parent_id = U64::new(cursor.u64()?);
        let parent_generation = U64::new(cursor.u64()?);
        let resulting = decode_position(&mut cursor)?;
        let cpu_retirements = U64::new(cursor.u64()?);
        let timer_callbacks = U64::new(cursor.u64()?);
        let cumulative_cpu_retirements = U64::new(cursor.u64()?);
        let cumulative_timer_callbacks = U64::new(cursor.u64()?);
        let status = match cursor.u32()? {
            1 => NativeEffectProgressStatus::PartialPrefix,
            2 => NativeEffectProgressStatus::Completed,
            3 => NativeEffectProgressStatus::EffectsUnknown,
            _ => return Err(NativeCommandError::Conflict),
        };
        if cursor.u32()? != 0 {
            return Err(NativeCommandError::Conflict);
        }
        let end_result = cursor.u32()? as i32;
        if cursor.u32()? != 0 {
            return Err(NativeCommandError::Conflict);
        }
        let result = Self {
            scope,
            prefix_preparation,
            grant_digest,
            command_digest,
            sequence,
            cut_id,
            previous_cut_id,
            acknowledgement_sequence,
            raw_before,
            raw_after,
            evaluated,
            evaluation_kind,
            parent_kind,
            evaluation_id,
            evaluation_generation,
            parent_id,
            parent_generation,
            resulting,
            cpu_retirements,
            timer_callbacks,
            cumulative_cpu_retirements,
            cumulative_timer_callbacks,
            status,
            end_result,
        };
        result.validate_shape()?;
        Ok(result)
    }

    /// Hashes the exact typed source record under the separate version-two ACK domain.
    ///
    /// # Errors
    /// Rejects malformed local fields or insufficient encoding credit.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let mut hash = Sha256::new();
        hash.update(b"crucible.native-effect-prefix.v2\0");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}

struct Predecessor {
    cut_id: U64,
    cursor: Position,
    raw_after: U64,
    cpu_retirements: U64,
    timer_callbacks: U64,
    next_acknowledgement_sequence: U64,
    status: NativeEffectProgressStatus,
}

fn decode_kind(kind: u32) -> Result<NativePrefixEvaluationKind, NativeCommandError> {
    match kind {
        1 => Ok(NativePrefixEvaluationKind::CpuService),
        2 => Ok(NativePrefixEvaluationKind::TimerCallback),
        _ => Err(NativeCommandError::Conflict),
    }
}

pub(super) fn encode_position(bytes: &mut Vec<u8>, position: Position) {
    bytes.extend_from_slice(&position.time_ps.get().to_be_bytes());
    bytes.extend_from_slice(&position.microstep.get().to_be_bytes());
    bytes.extend_from_slice(&(position.phase as u32).to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
}

pub(super) fn decode_position(cursor: &mut Cursor<'_>) -> Result<Position, NativeCommandError> {
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
