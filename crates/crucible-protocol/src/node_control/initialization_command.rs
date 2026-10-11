//! Bound original construction commands and retained administrative results.
//!
//! ```text
//! command: version:u32=1 | bytes:u32=184 | class_mask:u32 | budget:u32
//!          sequence:u64 | scope[32] | commitment[32] | realize[32]
//!          policy[32] | original_cut[32]
//! receipt: version:u32=1 | bytes:u32=160 | status:u32 | applied:u32
//!          sequence:u64 | hold_generation:u64 | scope[32] | commitment[32]
//!          original_cut[32] | realize[32]
//! ```
//!
//! Scalars are big endian. These records authorize no execution grant, input,
//! timers, snapshot cleanup or world activation. Applied reports the enrolled
//! administrative construction callbacks only; it is never a Ready receipt.

use crucible_node_contract::U64;

use super::initialization::{NATIVE_INITIALIZATION_MAX_CALLBACKS, NativeInitializationPreparation};
use super::initialization_cut::NativeInitializationCut;
use super::{NativeCommandError, codec::Cursor};

/// Binds one retained construction command to the pinned original source cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationCommand {
    /// Names the original positive sequence, retained unchanged across retries.
    pub sequence: U64,
    /// Names the pinned construction callback classes, with no polling permission.
    pub class_mask: u32,
    /// Bounds the original callback allowance within the source-selected cut.
    pub maximum_callbacks: u32,
    /// Binds the complete originally prepared scope.
    pub prepared_scope_hash: [u8; 32],
    /// Binds the complete original Realize operation and preparation policy.
    pub initialization_commitment: [u8; 32],
    /// Binds the exact originally accepted CNP Realize envelope.
    pub realize_request_digest: [u8; 32],
    /// Binds the installed construction policy.
    pub policy_digest: [u8; 32],
    /// Names the unchanged original source-selected finite arm cut.
    pub original_cut_digest: [u8; 32],
}

impl NativeInitializationCommand {
    /// Validates closed command data without granting native initialization.
    ///
    /// # Errors
    /// Rejects zero identities, unknown callback classes or an open allowance.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.sequence.get() == 0
            || self.class_mask == 0
            || self.class_mask & !7 != 0
            || self.maximum_callbacks == 0
            || self.maximum_callbacks > NATIVE_INITIALIZATION_MAX_CALLBACKS
            || [
                self.prepared_scope_hash,
                self.initialization_commitment,
                self.realize_request_digest,
                self.policy_digest,
                self.original_cut_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Compares every original field against preparation and native cut data.
    ///
    /// Callers must supply the authentic retained source cut and accepted Realize
    /// record. Correlating externally supplied values creates no authority.
    ///
    /// # Errors
    /// Rejects invalid inputs or any changed policy, allowance, scope or cut.
    pub fn validate_against(
        &self,
        preparation: &NativeInitializationPreparation,
        cut: &NativeInitializationCut,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        cut.validate_against(preparation)?;
        if self.class_mask != preparation.class_mask
            || self.maximum_callbacks != preparation.maximum_callbacks
            || self.prepared_scope_hash != cut.prepared_scope_hash
            || self.initialization_commitment != cut.initialization_commitment
            || self.realize_request_digest != preparation.realize_request_digest
            || self.policy_digest != preparation.policy_digest
            || self.original_cut_digest != cut.original_cut_digest
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes exactly one complete original command in portable bytes.
    ///
    /// # Errors
    /// Rejects any command that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; 184], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 184];
        for (offset, value) in [
            (0, 1),
            (4, 184),
            (8, self.class_mask),
            (12, self.maximum_callbacks),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        bytes[16..24].copy_from_slice(&self.sequence.get().to_be_bytes());
        for (offset, digest) in [
            (24, &self.prepared_scope_hash),
            (56, &self.initialization_commitment),
            (88, &self.realize_request_digest),
            (120, &self.policy_digest),
            (152, &self.original_cut_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(digest);
        }
        Ok(bytes)
    }

    /// Computes the immutable public command identity used for original ACKs.
    ///
    /// # Errors
    /// Rejects any locally invalid command field.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.qemu-native-initialization-command.v1\0");
        hash.update(&self.encode()?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Decodes a closed original command without adopting native custody.
    ///
    /// # Errors
    /// Rejects invalid prefixes, lengths or any open command field.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 184 {
            return Err(NativeCommandError::Invalid("initialization command length"));
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != 184 {
            return Err(NativeCommandError::Invalid("initialization command format"));
        }
        let result = Self {
            class_mask: cursor.u32()?,
            maximum_callbacks: cursor.u32()?,
            sequence: U64::new(cursor.u64()?),
            prepared_scope_hash: cursor.array()?,
            initialization_commitment: cursor.array()?,
            realize_request_digest: cursor.array()?,
            policy_digest: cursor.array()?,
            original_cut_digest: cursor.array()?,
        };
        result.validate()?;
        Ok(result)
    }
}

/// Selects the original source-selected cut under a pinned construction record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationQuery {
    /// Names the complete originally prepared scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the complete original construction preparation.
    pub initialization_commitment: [u8; 32],
}

impl NativeInitializationQuery {
    /// Encodes the pinned query without authorizing a source resampling.
    ///
    /// # Errors
    /// Rejects either absent original identity.
    pub fn encode(&self) -> Result<[u8; 64], NativeCommandError> {
        if self.prepared_scope_hash == [0; 32] || self.initialization_commitment == [0; 32] {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.prepared_scope_hash);
        bytes[32..].copy_from_slice(&self.initialization_commitment);
        Ok(bytes)
    }

    /// Decodes exactly one original pinned query without native authority.
    ///
    /// # Errors
    /// Rejects an invalid length or missing original identity.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 64 {
            return Err(NativeCommandError::Invalid("initialization query length"));
        }
        let mut cursor = Cursor(bytes);
        let result = Self {
            prepared_scope_hash: cursor.array()?,
            initialization_commitment: cursor.array()?,
        };
        result.encode()?;
        Ok(result)
    }
}

/// Correlates settlement of the original construction journal, without readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationAcknowledgement {
    /// Names the complete originally prepared scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the complete originally pinned construction preparation.
    pub initialization_commitment: [u8; 32],
    /// Names the original positive initialization command sequence.
    pub sequence: U64,
    /// Binds every original public command field, requiring journal comparison.
    pub command_digest: [u8; 32],
}

impl NativeInitializationAcknowledgement {
    /// Encodes an original journal ACK without certifying native reclamation.
    ///
    /// # Errors
    /// Rejects absent scope, preparation, sequence or command identities.
    pub fn encode(&self) -> Result<[u8; 104], NativeCommandError> {
        if self.sequence.get() == 0
            || self.prepared_scope_hash == [0; 32]
            || self.initialization_commitment == [0; 32]
            || self.command_digest == [0; 32]
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = [0; 104];
        bytes[..32].copy_from_slice(&self.prepared_scope_hash);
        bytes[32..64].copy_from_slice(&self.initialization_commitment);
        bytes[64..72].copy_from_slice(&self.sequence.get().to_be_bytes());
        bytes[72..].copy_from_slice(&self.command_digest);
        Ok(bytes)
    }

    /// Decodes one complete original settlement record without granting authority.
    ///
    /// # Errors
    /// Rejects invalid lengths or absent original correlation fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 104 {
            return Err(NativeCommandError::Invalid("initialization ACK length"));
        }
        let mut cursor = Cursor(bytes);
        let result = Self {
            prepared_scope_hash: cursor.array()?,
            initialization_commitment: cursor.array()?,
            sequence: U64::new(cursor.u64()?),
            command_digest: cursor.array()?,
        };
        result.encode()?;
        Ok(result)
    }
}

/// Reports an original source initialization result without readiness authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeInitializationStatus {
    /// Reports only the enrolled administrative construction callbacks applied.
    Applied = 1,
    /// Reports an unsupported source predicate before any initialization effects.
    Unsupported = 2,
    /// Reports a mismatched original cut before any initialization effects.
    Stale = 3,
    /// Reports invalid pinned command data before any initialization effects.
    Invalid = 4,
    /// Reports unknown effects, requiring retained whole-world custody.
    EffectsUnknown = 5,
}

/// Preserves an original bound administrative initialization result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationReceipt {
    /// Separates administrative completion, pre-effect refusal and unknown effects.
    pub status: NativeInitializationStatus,
    /// Counts enrolled original callbacks, not a general main-loop iteration.
    pub applied_callbacks: u32,
    /// Correlates the exact original command sequence.
    pub sequence: U64,
    /// Names the original retained HOLD lifetime, without implying new closure.
    pub hold_generation: U64,
    /// Names the complete original prepared scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the pinned original construction preparation.
    pub initialization_commitment: [u8; 32],
    /// Names the original command's cut, never a substituted later observation.
    pub original_cut_digest: [u8; 32],
    /// Names the originally accepted CNP Realize envelope.
    pub realize_request_digest: [u8; 32],
}

impl NativeInitializationReceipt {
    /// Validates result data without establishing stop, readiness or containment.
    ///
    /// # Errors
    /// Rejects missing original identities, excessive callbacks or a pre-effect
    /// refusal that also claims callbacks were applied.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.sequence.get() == 0
            || self.hold_generation.get() == 0
            || self.applied_callbacks > NATIVE_INITIALIZATION_MAX_CALLBACKS
            || [
                self.prepared_scope_hash,
                self.initialization_commitment,
                self.original_cut_digest,
                self.realize_request_digest,
            ]
            .contains(&[0; 32])
            || (matches!(
                self.status,
                NativeInitializationStatus::Unsupported
                    | NativeInitializationStatus::Stale
                    | NativeInitializationStatus::Invalid
            ) && self.applied_callbacks != 0)
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Checks the result against the authentic original command and cut data.
    ///
    /// # Errors
    /// Rejects any changed original correlation or impossible applied count.
    pub fn validate_against(
        &self,
        command: &NativeInitializationCommand,
        cut: &NativeInitializationCut,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        command.validate()?;
        cut.validate()?;
        if self.sequence != command.sequence
            || self.hold_generation != cut.hold_generation
            || self.prepared_scope_hash != command.prepared_scope_hash
            || self.prepared_scope_hash != cut.prepared_scope_hash
            || self.initialization_commitment != command.initialization_commitment
            || self.initialization_commitment != cut.initialization_commitment
            || self.original_cut_digest != command.original_cut_digest
            || self.original_cut_digest != cut.original_cut_digest
            || self.realize_request_digest != command.realize_request_digest
            || self.applied_callbacks as usize > cut.rows.len()
            || (self.status == NativeInitializationStatus::Applied
                && self.applied_callbacks as usize != cut.rows.len())
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes the complete original result without promoting its guarantees.
    ///
    /// # Errors
    /// Rejects any result that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; 160], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 160];
        for (offset, value) in [
            (0, 1),
            (4, 160),
            (8, self.status as u32),
            (12, self.applied_callbacks),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        bytes[16..24].copy_from_slice(&self.sequence.get().to_be_bytes());
        bytes[24..32].copy_from_slice(&self.hold_generation.get().to_be_bytes());
        for (offset, digest) in [
            (32, &self.prepared_scope_hash),
            (64, &self.initialization_commitment),
            (96, &self.original_cut_digest),
            (128, &self.realize_request_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(digest);
        }
        Ok(bytes)
    }

    /// Decodes one closed original result without granting native readiness.
    ///
    /// # Errors
    /// Rejects invalid lengths, format prefixes, open statuses or local fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 160 {
            return Err(NativeCommandError::Invalid("initialization receipt length"));
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != 160 {
            return Err(NativeCommandError::Invalid("initialization receipt format"));
        }
        let status = match cursor.u32()? {
            1 => NativeInitializationStatus::Applied,
            2 => NativeInitializationStatus::Unsupported,
            3 => NativeInitializationStatus::Stale,
            4 => NativeInitializationStatus::Invalid,
            5 => NativeInitializationStatus::EffectsUnknown,
            _ => return Err(NativeCommandError::Invalid("initialization status")),
        };
        let result = Self {
            status,
            applied_callbacks: cursor.u32()?,
            sequence: U64::new(cursor.u64()?),
            hold_generation: U64::new(cursor.u64()?),
            prepared_scope_hash: cursor.array()?,
            initialization_commitment: cursor.array()?,
            original_cut_digest: cursor.array()?,
            realize_request_digest: cursor.array()?,
        };
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "initialization_command_tests.rs"]
mod tests;
