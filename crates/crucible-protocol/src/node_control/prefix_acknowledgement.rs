//! Canonical acknowledgements of immutable source prefix history.
//!
//! An offered acknowledgement is correlation data. Only the native consumed
//! acknowledgement getter can establish that the original source journal accepted
//! it. A continuation names that exact retained ACK and cursor; it renews no budget.
//!
//! ```text
//! ACK192: version/size:u32be | scope/preparation/grant/command/result:[32;5]
//! command_sequence/cut_id/acknowledgement_sequence:u64be
//! Continue216: unchanged ACK192 | expected_cursor:Position24
//! Result identity: SHA256(domain including NUL | canonical source result bytes)
//! ```

// SPDX-License-Identifier: Apache-2.0

use crucible_node_contract::{Position, U64};
use sha2::{Digest, Sha256};

use super::codec::Cursor;
use super::prefix_progress::{decode_position, encode_position};
use super::{NativeCommandError, NativeEffectProgress, NativePrefixProgress};

/// Correlates an exact initial or typed prefix acknowledgement without echo authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixAcknowledgement {
    /// Selects initial Result256 version one or typed Result320 version two.
    pub result_version: u32,
    /// Correlates the complete original prepared scope.
    pub scope: [u8; 32],
    /// Correlates the distinct controller-nine prefix preparation.
    pub prefix_preparation: [u8; 32],
    /// Correlates the unchanged original admitted grant.
    pub grant_digest: [u8; 32],
    /// Correlates the immutable original command.
    pub command_digest: [u8; 32],
    /// Commits to the exact original canonical source result under its versioned domain.
    pub result_digest: [u8; 32],
    /// Identifies the unchanged original command sequence.
    pub sequence: U64,
    /// Identifies the retained original native cut being acknowledged.
    pub cut_id: U64,
    /// Orders original prefix ACKs without authorizing another evaluation.
    pub acknowledgement_sequence: U64,
}

impl NativePrefixAcknowledgement {
    /// Derives the first ACK from exact immutable Result256 bytes.
    ///
    /// # Errors
    /// Rejects malformed initial source identity or insufficient encoding credit.
    pub fn from_initial(result: &NativeEffectProgress) -> Result<Self, NativeCommandError> {
        let mut hash = Sha256::new();
        hash.update(b"crucible.native-effect-prefix.v1\0");
        hash.update(result.encode()?);
        let acknowledgement = Self {
            result_version: 1,
            scope: result.scope,
            prefix_preparation: result.effect_preparation,
            grant_digest: result.grant_digest,
            command_digest: result.command_digest,
            result_digest: hash.finalize().into(),
            sequence: result.sequence,
            cut_id: result.cut_id,
            acknowledgement_sequence: U64::new(1),
        };
        acknowledgement.validate_shape()?;
        Ok(acknowledgement)
    }

    /// Derives a typed prefix ACK without reinterpreting the initial record.
    ///
    /// # Errors
    /// Rejects invalid local result shape, ACK sequence overflow or encoding failure.
    pub fn from_progress(result: &NativePrefixProgress) -> Result<Self, NativeCommandError> {
        let next = result
            .acknowledgement_sequence
            .get()
            .checked_add(1)
            .ok_or(NativeCommandError::ResourceLimit)?;
        let acknowledgement = Self {
            result_version: 2,
            scope: result.scope,
            prefix_preparation: result.prefix_preparation,
            grant_digest: result.grant_digest,
            command_digest: result.command_digest,
            result_digest: result.identity_digest()?,
            sequence: result.sequence,
            cut_id: result.cut_id,
            acknowledgement_sequence: U64::new(next),
        };
        acknowledgement.validate_shape()?;
        Ok(acknowledgement)
    }

    /// Checks every copied field against exact initial history.
    ///
    /// # Errors
    /// Rejects a foreign version, original identity, cut, sequence or result hash.
    pub fn validate_initial(
        &self,
        result: &NativeEffectProgress,
    ) -> Result<(), NativeCommandError> {
        if self != &Self::from_initial(result)? {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Checks every copied field against exact typed history.
    ///
    /// # Errors
    /// Rejects a foreign version, original identity, cut, sequence or result hash.
    pub fn validate_progress(
        &self,
        result: &NativePrefixProgress,
    ) -> Result<(), NativeCommandError> {
        if self != &Self::from_progress(result)? {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), NativeCommandError> {
        if !matches!(self.result_version, 1 | 2)
            || [
                self.scope,
                self.prefix_preparation,
                self.grant_digest,
                self.command_digest,
                self.result_digest,
            ]
            .contains(&[0; 32])
            || self.sequence.get() == 0
            || self.cut_id.get() == 0
            || self.acknowledgement_sequence.get() == 0
            || (self.result_version == 1 && self.acknowledgement_sequence.get() != 1)
            || (self.result_version == 2 && self.acknowledgement_sequence.get() < 2)
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes fixed ACK192 without native handles or renewed allowances.
    ///
    /// # Errors
    /// Rejects invalid local identity/version or bounded allocation failure.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate_shape()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(192)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(&self.result_version.to_be_bytes());
        bytes.extend_from_slice(&192u32.to_be_bytes());
        for digest in [
            &self.scope,
            &self.prefix_preparation,
            &self.grant_digest,
            &self.command_digest,
            &self.result_digest,
        ] {
            bytes.extend_from_slice(digest);
        }
        for scalar in [self.sequence, self.cut_id, self.acknowledgement_sequence] {
            bytes.extend_from_slice(&scalar.get().to_be_bytes());
        }
        Ok(bytes)
    }

    /// Decodes only an exact versioned ACK192 extent.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, unknown versions or invalid local identity.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 192 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        let result_version = cursor.u32()?;
        if cursor.u32()? != 192 {
            return Err(NativeCommandError::Conflict);
        }
        let acknowledgement = Self {
            result_version,
            scope: cursor.array()?,
            prefix_preparation: cursor.array()?,
            grant_digest: cursor.array()?,
            command_digest: cursor.array()?,
            result_digest: cursor.array()?,
            sequence: U64::new(cursor.u64()?),
            cut_id: U64::new(cursor.u64()?),
            acknowledgement_sequence: U64::new(cursor.u64()?),
        };
        acknowledgement.validate_shape()?;
        Ok(acknowledgement)
    }
}

/// Names the exact preceding acknowledgement and cursor for a separately selected cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixContinuation {
    /// Retains the complete original ACK accepted by the native source journal.
    pub acknowledgement: NativePrefixAcknowledgement,
    /// Names the exact original source cursor without proposing a new allowance.
    pub expected_cursor: Position,
}

impl NativePrefixContinuation {
    /// Checks correlation to an acknowledged initial prefix that remains outstanding.
    ///
    /// # Errors
    /// Rejects a foreign ACK/cursor or continuation after completion or unknown effects.
    pub fn validate_initial(
        &self,
        previous: &NativeEffectProgress,
    ) -> Result<(), NativeCommandError> {
        self.acknowledgement.validate_initial(previous)?;
        self.validate_cursor(previous.resulting, previous.status, previous.end_result)
    }

    /// Checks correlation to an acknowledged typed prefix that remains outstanding.
    ///
    /// # Errors
    /// Rejects a foreign ACK/cursor or continuation after completion or unknown effects.
    pub fn validate_progress(
        &self,
        previous: &NativePrefixProgress,
    ) -> Result<(), NativeCommandError> {
        self.acknowledgement.validate_progress(previous)?;
        self.validate_cursor(previous.resulting, previous.status, previous.end_result)
    }

    fn validate_cursor(
        &self,
        cursor: Position,
        status: super::NativeEffectProgressStatus,
        end_result: i32,
    ) -> Result<(), NativeCommandError> {
        if self.expected_cursor != cursor
            || status != super::NativeEffectProgressStatus::PartialPrefix
            || end_result != 0
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes fixed Continue216 correlation bytes without granting continuation.
    ///
    /// # Errors
    /// Rejects invalid ACK fields or bounded allocation failure.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        let mut bytes = self.acknowledgement.encode()?;
        bytes
            .try_reserve_exact(24)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        encode_position(&mut bytes, self.expected_cursor);
        Ok(bytes)
    }

    /// Decodes an exact preceding ACK and full expected cursor.
    ///
    /// # Errors
    /// Rejects truncation/trailing bytes, invalid ACK shape or unknown/reserved position fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 216 {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(Self {
            acknowledgement: NativePrefixAcknowledgement::decode(&bytes[..192])?,
            expected_cursor: decode_position(&mut Cursor(&bytes[192..]))?,
        })
    }
}
