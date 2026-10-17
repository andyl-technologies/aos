//! Original construction preparation, separate from native execution grants.
//!
//! Preparation values are data, not proof that a caller owns a realization.
//! The installed host must compare the original CNP Realize envelope and policy
//! before pinning this commitment in launch arguments. Native registration pins
//! those fields before model construction; a later hash cannot adopt a running
//! process or authorize cleanup of a captured cut.
//!
//! ```text
//! old_preparation_bytes:u32 | exact_v1_Prepare_frame[old_preparation_bytes]
//! operation_bytes:u16 | original_realize_operation[operation_bytes]
//! realize_digest[32] | policy_digest[32] | class_mask:u32 | max_callbacks:u32
//! ```
//!
//! Integers are big endian. The original version-one preparation is preserved
//! byte for byte inside this distinct preparation variant.

use crucible_node_contract::{Id, Phase};
use std::fmt::Write;

use super::{NativeCommandError, NativeFrame, NativePreparation, codec::Cursor};

/// Bounds the original construction callback allowance.
pub const NATIVE_INITIALIZATION_MAX_CALLBACKS: u32 = 64;

/// Pins one original Realize operation and its finite initialization policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeInitializationPreparation {
    /// Preserves the complete original inactive owner preparation.
    pub preparation: NativePreparation,
    /// Identifies the original retained CNP Realize operation.
    pub realize_operation: Id,
    /// Commits to the exact originally accepted Realize envelope bytes.
    pub realize_request_digest: [u8; 32],
    /// Commits to the installed construction policy, requiring original comparison.
    pub policy_digest: [u8; 32],
    /// Selects QMP startup (1), empty coroutine notification (2), or IDE cleanup (4).
    pub class_mask: u32,
    /// Bounds source-selected original callbacks; it never permits a polling loop.
    pub maximum_callbacks: u32,
}

impl NativeInitializationPreparation {
    /// Validates a fresh construction record without granting realization authority.
    ///
    /// # Errors
    /// Rejects nonzero initial time or microstep, a non-control phase, an invalid
    /// owner preparation, missing commitments, or an open callback allowance.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.preparation.validate()?;
        let boundary = self.preparation.boundary;
        if boundary.time_ps.get() != 0
            || boundary.microstep.get() != 0
            || boundary.phase != Phase::BoundaryControl
            || self.realize_request_digest == [0; 32]
            || self.policy_digest == [0; 32]
            || self.class_mask == 0
            || self.class_mask & !7 != 0
            || self.maximum_callbacks == 0
            || self.maximum_callbacks > NATIVE_INITIALIZATION_MAX_CALLBACKS
        {
            return Err(NativeCommandError::Invalid(
                "invalid original native initialization preparation",
            ));
        }
        Ok(())
    }

    /// Computes the launch-pinned identity of the complete original preparation.
    ///
    /// A matching digest is not a readiness attestation or ownership credential.
    /// Native registration also compares each separately pinned policy field.
    ///
    /// # Errors
    /// Rejects any invalid or unrepresentable preparation record.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let bytes = self.encode()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.qemu-native-initialization-preparation.v1\0");
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Encodes the fixed early QEMU launch pin before subsystem construction.
    ///
    /// The source parses `v1:` followed by exactly 272 lowercase hexadecimal
    /// characters: scope, commitment, Realize and policy digests, then the class
    /// mask and callback allowance in little endian. The installed launcher must
    /// compare actual original custody before passing this as the argument of
    /// `-crucible-node-initialization`; the string itself proves no ownership.
    ///
    /// # Errors
    /// Rejects invalid preparation data or an unrepresentable commitment.
    pub fn early_launch_argument(&self) -> Result<String, NativeCommandError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(136);
        bytes.extend_from_slice(&self.preparation.scope.identity_digest()?);
        bytes.extend_from_slice(&self.identity_digest()?);
        bytes.extend_from_slice(&self.realize_request_digest);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.class_mask.to_le_bytes());
        bytes.extend_from_slice(&self.maximum_callbacks.to_le_bytes());

        let mut argument = String::with_capacity(275);
        argument.push_str("v1:");
        for byte in bytes {
            write!(&mut argument, "{byte:02x}")
                .map_err(|_| NativeCommandError::Invalid("initialization pin formatting"))?;
        }
        Ok(argument)
    }

    /// Encodes the complete bounded preparation without granting initialization.
    ///
    /// # Errors
    /// Rejects invalid local fields or a body beyond the public frame allowance.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let original =
            super::encode_frame(&NativeFrame::Prepare(Box::new(self.preparation.clone())))?;
        let mut bytes = Vec::with_capacity(original.len() + 206);
        bytes.extend_from_slice(&(original.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&original);
        let operation = self.realize_operation.as_str().as_bytes();
        bytes.extend_from_slice(&(operation.len() as u16).to_be_bytes());
        bytes.extend_from_slice(operation);
        bytes.extend_from_slice(&self.realize_request_digest);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.class_mask.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_callbacks.to_be_bytes());
        if bytes.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Decodes a closed construction record without adopting native custody.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, excessive lengths, a different embedded
    /// frame kind, invalid identities, or any inconsistency in [`Self::validate`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        let original_length = cursor.u32()? as usize;
        if original_length > super::NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let NativeFrame::Prepare(preparation) = super::decode_frame(cursor.take(original_length)?)?
        else {
            return Err(NativeCommandError::Invalid(
                "initialization requires the original preparation frame",
            ));
        };
        let operation_length = cursor.u16()? as usize;
        if operation_length > 128 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let operation = std::str::from_utf8(cursor.take(operation_length)?)
            .map_err(|_| NativeCommandError::Invalid("invalid Realize operation identity"))?;
        let result = Self {
            preparation: *preparation,
            realize_operation: Id::new(operation)
                .map_err(|_| NativeCommandError::Invalid("invalid Realize operation identity"))?,
            realize_request_digest: cursor.array()?,
            policy_digest: cursor.array()?,
            class_mask: cursor.u32()?,
            maximum_callbacks: cursor.u32()?,
        };
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Invalid(
                "trailing native initialization preparation",
            ));
        }
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "initialization_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn test_preparation() -> NativeInitializationPreparation {
    tests::original()
}
