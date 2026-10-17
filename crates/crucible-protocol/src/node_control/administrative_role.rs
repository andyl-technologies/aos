//! Historical native socket/thread observations for one originally pinned role.
//!
//! The fixed record never asserts thread liveness, complete writer containment,
//! readiness or effect permission. Unknown other roots remain explicit. Its
//! source must be authenticated independently of this pure scalar decoder.
//!
//! ```text
//! version:u32be=1, size:u32be=192, kind:u32be=1, flags:u32be=7,
//! registration:u64be, thread:u64be, device:u64be, inode:u64be, process:u64be,
//! descriptor:i32be, reserved:u32be=0,
//! scope[32], role_commitment[32], Realize_digest[32], policy_digest[32]
//! ```

use crucible_node_contract::U64;

use super::{NativeAdministrativePreparation, NativeCommandError};

/// Preserves a native source's original observed reader registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAdministrativeFacts {
    /// Identifies one original registration, distinct from an execution token.
    pub registration_id: U64,
    /// Preserves the original self-registering OS thread identity.
    pub thread_id: U64,
    /// Preserves the endpoint device observed at original registration.
    pub socket_device: U64,
    /// Preserves the endpoint inode observed at original registration.
    pub socket_inode: U64,
    /// Preserves the source process at original registration, without fork rebinding.
    pub process_id: U64,
    /// Names the original inherited descriptor slot, not portable descriptor custody.
    pub descriptor_slot: i32,
    /// Binds the source's original preparation scope.
    pub prepared_scope_hash: [u8; 32],
    /// Binds the complete original role preparation, including endpoint identity.
    pub role_commitment: [u8; 32],
    /// Binds the original Realize request, never a later adoption.
    pub realize_request_digest: [u8; 32],
    /// Identifies the originally pinned administrative role policy.
    pub policy_digest: [u8; 32],
}

#[cfg(test)]
#[path = "administrative_role_tests.rs"]
mod tests;

impl NativeAdministrativeFacts {
    /// Validates closed historical scalars while preserving unknown other roots.
    ///
    /// # Errors
    /// Rejects zero registrations/identities, invalid descriptor slots or hashes.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if [
            self.registration_id,
            self.thread_id,
            self.socket_device,
            self.socket_inode,
            self.process_id,
        ]
        .iter()
        .any(|value| value.get() == 0)
            || self.descriptor_slot < 3
            || [
                self.prepared_scope_hash,
                self.role_commitment,
                self.realize_request_digest,
                self.policy_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(NativeCommandError::Invalid(
                "invalid original reader observation",
            ));
        }
        Ok(())
    }

    /// Compares historical record fields with their original preparation.
    ///
    /// This comparison authenticates neither the source nor current thread life.
    ///
    /// # Errors
    /// Rejects malformed records or differing original scope, request, policy,
    /// descriptor slot, socket identity or role commitment.
    pub fn validate_against(
        &self,
        preparation: &NativeAdministrativePreparation,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        preparation.validate()?;
        if self.prepared_scope_hash
            != preparation
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()?
            || self.role_commitment != preparation.identity_digest()?
            || self.realize_request_digest
                != preparation.phase.initialization.realize_request_digest
            || self.policy_digest != preparation.policy_digest
            || self.descriptor_slot != preparation.descriptor_slot
            || self.socket_device.get() != preparation.socket_device
            || self.socket_inode.get() != preparation.socket_inode
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes the fixed historical record with unknown-other-roots flags intact.
    ///
    /// # Errors
    /// Rejects malformed scalar identities or zero original commitments.
    pub fn encode(&self) -> Result<[u8; 192], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 192];
        for (offset, value) in [(0, 1u32), (4, 192), (8, 1), (12, 7)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (16, self.registration_id),
            (24, self.thread_id),
            (32, self.socket_device),
            (40, self.socket_inode),
            (48, self.process_id),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.get().to_be_bytes());
        }
        bytes[56..60].copy_from_slice(&self.descriptor_slot.to_be_bytes());
        for (offset, value) in [
            (64, &self.prepared_scope_hash),
            (96, &self.role_commitment),
            (128, &self.realize_request_digest),
            (160, &self.policy_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(value);
        }
        Ok(bytes)
    }

    /// Decodes exactly one historical observation without adopting its role.
    ///
    /// # Errors
    /// Rejects truncated/trailing bytes, unknown edition/kind/flags, nonzero
    /// reserved fields and malformed scalar identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 192 {
            return Err(NativeCommandError::Invalid(
                "invalid reader observation extent",
            ));
        }
        let u32_at = |offset| -> Result<u32, NativeCommandError> {
            Ok(u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| NativeCommandError::Invalid("invalid reader scalar"))?,
            ))
        };
        let u64_at = |offset| -> Result<U64, NativeCommandError> {
            Ok(U64::new(u64::from_be_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| NativeCommandError::Invalid("invalid reader identity"))?,
            )))
        };
        let hash_at = |offset| -> Result<[u8; 32], NativeCommandError> {
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| NativeCommandError::Invalid("invalid reader commitment"))
        };
        if u32_at(0)? != 1
            || u32_at(4)? != 192
            || u32_at(8)? != 1
            || u32_at(12)? != 7
            || u32_at(60)? != 0
        {
            return Err(NativeCommandError::Invalid(
                "unsupported reader observation",
            ));
        }
        let value = Self {
            registration_id: u64_at(16)?,
            thread_id: u64_at(24)?,
            socket_device: u64_at(32)?,
            socket_inode: u64_at(40)?,
            process_id: u64_at(48)?,
            descriptor_slot: u32_at(56)? as i32,
            prepared_scope_hash: hash_at(64)?,
            role_commitment: hash_at(96)?,
            realize_request_digest: hash_at(128)?,
            policy_digest: hash_at(160)?,
        };
        value.validate()?;
        Ok(value)
    }
}
