//! Closed controller-eight preparation and original finite compute records.
//!
//! The retained complete preparation selects this envelope before launch.
//! Decoding establishes correlation; only the installed source-native issuer
//! can admit its owned epoch and original finite effect cut.
//!
//! ```text
//! EffectCompute: effect_preparation[32] | callbacks:u32be | service_span:u64be
//! input_batch_sequence:u64be | command_length:u32be | unchanged_command_bytes
//! Envelope: magic[8] | edition:u16be=8 | kind:u16be | body_length:u32be | body
//! ```

// SPDX-License-Identifier: Apache-2.0

use crucible_node_contract::U64;

use super::codec::{Cursor, MAGIC};
use super::{
    ExecutionCommand, ExecutionKind, NativeCommandError, NativeControlEdition, NativeFrame,
};

/// Retains a complete original compute command and narrower finite budgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEffectCompute {
    /// Retains the unchanged host-authored grant, input prefix and original command.
    pub command: ExecutionCommand,
    /// Correlates the complete original effect preparation.
    pub effect_preparation: [u8; 32],
    /// Bounds original callbacks within the pinned preparation.
    pub maximum_callbacks: u32,
    /// Bounds original CPU instruction services within the pinned preparation.
    pub maximum_service_span: U64,
    /// Orders the complete canonical empty batch; no guest input event is representable.
    pub input_batch_sequence: U64,
}

impl NativeEffectCompute {
    /// Validates closed shape without supplying native effect permission.
    ///
    /// # Errors
    /// Rejects non-compute operations, empty identities or zero finite budgets.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.command.validate()?;
        let empty = crucible_node_contract::InputBatch {
            schema_version: 1,
            execution_owner_id: self.command.scope.owner.clone(),
            input_epoch: self.command.input_epoch.clone(),
            batch_id: self.command.input_batch.clone(),
            batch_sequence: self.input_batch_sequence,
            events: Vec::new(),
            extensions: Default::default(),
        };
        if self.input_batch_sequence.get() == 0
            || empty
                .identity()
                .map_err(|_| NativeCommandError::Invalid("invalid original empty input batch"))?
                != self.command.input_batch_hash
        {
            return Err(NativeCommandError::Invalid(
                "fixed profile requires complete original empty input batch",
            ));
        }
        if !matches!(self.command.kind, ExecutionKind::ExactRun { .. })
            || self.command.authorization_digest == [0; 32]
            || self.effect_preparation == [0; 32]
            || self.maximum_callbacks == 0
            || self.maximum_service_span.get() == 0
        {
            return Err(NativeCommandError::Invalid(
                "invalid original finite compute",
            ));
        }
        Ok(())
    }
}

pub(super) fn encode(frame: &NativeFrame) -> Result<Vec<u8>, NativeCommandError> {
    let (kind, body) = match frame {
        NativeFrame::PrepareEffect(preparation) => (30u16, preparation.encode()?),
        NativeFrame::EffectCompute(compute) => {
            compute.validate()?;
            let original = super::encode_command(&compute.command)?;
            let mut body = Vec::new();
            body.try_reserve_exact(56 + original.len())
                .map_err(|_| NativeCommandError::ResourceLimit)?;
            body.extend_from_slice(&compute.effect_preparation);
            body.extend_from_slice(&compute.maximum_callbacks.to_be_bytes());
            body.extend_from_slice(&compute.maximum_service_span.get().to_be_bytes());
            body.extend_from_slice(&compute.input_batch_sequence.get().to_be_bytes());
            body.extend_from_slice(&(original.len() as u32).to_be_bytes());
            body.extend_from_slice(&original);
            (31, body)
        }
        NativeFrame::EffectProgress(progress) => (32, progress.encode()?),
        NativeFrame::PrepareFixedMicrovm(_) => {
            return Err(NativeCommandError::Invalid(
                "effect controller requires complete effect preparation",
            ));
        }
        _ => {
            let mut original =
                super::encode_frame_for_edition(NativeControlEdition::FixedMicrovm, frame)?;
            original[8..10].copy_from_slice(&8u16.to_be_bytes());
            return Ok(original);
        }
    };
    if body.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(super::NODE_CONTROL_HEADER_BYTES + body.len())
        .map_err(|_| NativeCommandError::ResourceLimit)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&8u16.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<NativeFrame, NativeCommandError> {
    let mut cursor = Cursor(bytes);
    if cursor.take(8)? != MAGIC || cursor.u16()? != 8 {
        return Err(NativeCommandError::UnsupportedVersion(8));
    }
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if length > super::NODE_CONTROL_MAX_BODY_BYTES || cursor.0.len() != length {
        return Err(NativeCommandError::ResourceLimit);
    }
    let frame = match kind {
        30 => NativeFrame::PrepareEffect(Box::new(super::NativeEffectPreparation::decode(
            cursor.take(length)?,
        )?)),
        31 => {
            let effect_preparation = cursor.array()?;
            let maximum_callbacks = cursor.u32()?;
            let maximum_service_span = U64::new(cursor.u64()?);
            let input_batch_sequence = U64::new(cursor.u64()?);
            let original_length = cursor.u32()? as usize;
            let compute = NativeEffectCompute {
                command: super::decode_command(cursor.take(original_length)?)?,
                effect_preparation,
                maximum_callbacks,
                maximum_service_span,
                input_batch_sequence,
            };
            if !cursor.0.is_empty() {
                return Err(NativeCommandError::ResourceLimit);
            }
            compute.validate()?;
            NativeFrame::EffectCompute(Box::new(compute))
        }
        32 => NativeFrame::EffectProgress(Box::new(super::NativeEffectProgress::decode(
            cursor.take(length)?,
        )?)),
        29 => {
            return Err(NativeCommandError::Invalid(
                "effect controller requires complete effect preparation",
            ));
        }
        _ => {
            let mut original = bytes.to_vec();
            original[8..10].copy_from_slice(&7u16.to_be_bytes());
            return super::decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &original);
        }
    };
    Ok(frame)
}
