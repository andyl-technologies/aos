//! Complete original effect-policy correlation beside the unchanged Root328 ancestor.
//!
//! This private portable prototype derives early192/native200 from the retained
//! Realize and every original root companion. It installs no reducer, source
//! registration or effect authority. Mapping3 defines independent roots at
//! Reaction microstep zero with timer-before-CPU native tie order; same-time
//! scheduled consequences require genuine parent ancestry at a later microstep.
//!
//! ```text
//! CNEFFC01 | root_length:u32be | unchanged_root_bytes
//! effect_policy_digest[32] | maximum_callbacks:u32be | maximum_service_span:u64be
//! Early192: five digests | mapping/controller/callbacks/reserved:u32le | max_microstep/span:u64le
//! Native200: version:u32le=1 | size:u32le=200 | exact early192
//! ```

// SPDX-License-Identifier: Apache-2.0

use super::{NODE_CONTROL_MAX_BODY_BYTES, NativeCommandError, NativeFixedMicrovmPreparation};
use crucible_node_contract::U64;

const MAGIC: &[u8; 8] = b"CNEFFC01";
const SUFFIX_BYTES: usize = 44;

/// Retains the complete original constructor preparation and narrowed effect limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeEffectPreparation {
    /// Retains every unchanged Realize, initialization, phase and administrative companion.
    pub original_root: NativeFixedMicrovmPreparation,
    /// Correlates the separately installed mapping3 policy without granting effects.
    pub policy_digest: [u8; 32],
    /// Bounds original callbacks to no more than the complete root ancestor.
    pub maximum_callbacks: u32,
    /// Bounds actual instruction services to no more than the complete root ancestor.
    pub maximum_service_span: U64,
}

impl NativeEffectPreparation {
    /// Validates every original companion and narrows the actual ancestor budgets.
    ///
    /// # Errors
    /// Rejects an invalid original root, zero digest, zero budget or widened bound.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.original_root.validate()?;
        if self.policy_digest == [0; 32]
            || self.maximum_callbacks == 0
            || self.maximum_callbacks > self.original_root.maximum_callbacks
            || self.maximum_service_span.get() == 0
            || self.maximum_service_span > self.original_root.maximum_service_span
        {
            return Err(NativeCommandError::Invalid(
                "invalid original effect preparation",
            ));
        }
        Ok(())
    }

    /// Encodes the unchanged root and every narrowed original effect field.
    ///
    /// # Errors
    /// Rejects invalid preparation, excessive frame extent or allocation failure.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let root = self.original_root.encode()?;
        let length = 12usize
            .checked_add(root.len())
            .and_then(|length| length.checked_add(SUFFIX_BYTES))
            .filter(|length| *length <= NODE_CONTROL_MAX_BODY_BYTES)
            .ok_or(NativeCommandError::ResourceLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(root.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&root);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.maximum_callbacks.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_service_span.get().to_be_bytes());
        Ok(bytes)
    }

    /// Decodes the exact original record with closed extents and no trailing bytes.
    ///
    /// # Errors
    /// Rejects malformed lengths, truncated or trailing data, or invalid ancestors.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let prefix = bytes.get(..12).ok_or(NativeCommandError::ResourceLimit)?;
        if &prefix[..8] != MAGIC {
            return Err(NativeCommandError::Invalid(
                "unknown effect preparation tag",
            ));
        }
        let encoded_length: [u8; 4] = prefix[8..12]
            .try_into()
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let root_length = u32::from_be_bytes(encoded_length) as usize;
        let suffix_offset = 12usize
            .checked_add(root_length)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if suffix_offset.checked_add(SUFFIX_BYTES) != Some(bytes.len()) {
            return Err(NativeCommandError::ResourceLimit);
        }
        let original_root = NativeFixedMicrovmPreparation::decode(&bytes[12..suffix_offset])?;
        let suffix = &bytes[suffix_offset..];
        let policy_digest = suffix[..32]
            .try_into()
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let callback_bytes = suffix[32..36]
            .try_into()
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let span_bytes = suffix[36..44]
            .try_into()
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let preparation = Self {
            original_root,
            policy_digest,
            maximum_callbacks: u32::from_be_bytes(callback_bytes),
            maximum_service_span: U64::new(u64::from_be_bytes(span_bytes)),
        };
        preparation.validate()?;
        Ok(preparation)
    }

    /// Commits to the complete original effect preparation without native authority.
    ///
    /// # Errors
    /// Rejects malformed preparation or insufficient bounded encoding credit.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.qemu-native-effect-preparation.v1\0");
        hash.update(&self.encode()?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Derives the exact early192 source pin from the complete retained ancestor.
    ///
    /// The exclusive microstep bound is the original root's bound, not a duplicate
    /// supplied coordinate. The native source still independently validates it.
    ///
    /// # Errors
    /// Rejects invalid original companion or effect-budget commitments.
    pub fn early_pin(&self) -> Result<[u8; 192], NativeCommandError> {
        self.validate()?;
        let initialization = &self.original_root.administration.phase.initialization;
        let mut bytes = [0; 192];
        let digests = [
            initialization.preparation.scope.identity_digest()?,
            self.identity_digest()?,
            initialization.realize_request_digest,
            self.policy_digest,
            self.original_root.identity_digest()?,
        ];
        for (destination, digest) in bytes[..160].as_chunks_mut::<32>().0.iter_mut().zip(digests) {
            destination.copy_from_slice(&digest);
        }
        for (destination, selector) in bytes[160..176].as_chunks_mut::<4>().0.iter_mut().zip([
            3u32,
            8,
            self.maximum_callbacks,
            0,
        ]) {
            destination.copy_from_slice(&selector.to_le_bytes());
        }
        bytes[176..184].copy_from_slice(&self.original_root.maximum_microstep.get().to_le_bytes());
        bytes[184..192].copy_from_slice(&self.maximum_service_span.get().to_le_bytes());
        Ok(bytes)
    }

    /// Encodes native200 scalar correlation without relying on Rust-native layout.
    ///
    /// # Errors
    /// Rejects invalid original preparation. These bytes cannot issue an epoch.
    pub fn native_policy(&self) -> Result<[u8; 200], NativeCommandError> {
        let mut bytes = [0; 200];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&200u32.to_le_bytes());
        bytes[8..].copy_from_slice(&self.early_pin()?);
        Ok(bytes)
    }

    /// Formats canonical lowercase early-policy bytes for source argv validation.
    ///
    /// # Errors
    /// Rejects invalid preparation or inadequate bounded argument allocation.
    pub fn early_launch_argument(&self) -> Result<String, NativeCommandError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut argument = String::new();
        argument
            .try_reserve_exact(387)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        argument.push_str("v1:");
        for byte in self.early_pin()? {
            argument.push(char::from(HEX[usize::from(byte >> 4)]));
            argument.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(argument)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed original-companion codec invariants deliberately panic on divergence.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "effect_preparation_tests.rs"]
mod tests;
