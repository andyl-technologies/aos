//! Complete controller-nine preparation beside the unchanged controller-eight ancestor.
//!
//! This portable record correlates a bounded prefix journal. It contains no
//! native handles or callback tables and cannot issue an epoch or effect cut.
//! The new commitment includes the complete original effect preparation;
//! changing an edition field in the ancestor cannot create this preparation.
//!
//! ```text
//! CNPFXP01 | effect_length:u32be | unchanged_effect_bytes
//! prefix_policy_digest[32] | maximum_prefixes:u32be
//! Early264: unchanged early192 | prefix_commitment[32] | policy_digest[32] | controller9/max_prefixes:u32le
//! Native280: version/size:u32le | unchanged native200 | prefix_commitment[32] | policy_digest[32] | controller9/max_prefixes:u32le
//! ```

// SPDX-License-Identifier: Apache-2.0

use super::{NODE_CONTROL_MAX_BODY_BYTES, NativeCommandError, NativeEffectPreparation};

const MAGIC: &[u8; 8] = b"CNPFXP01";
const SUFFIX_BYTES: usize = 36;

/// Retains the complete original effect ancestor and separately bounded prefix journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixPreparation {
    /// Retains every unchanged controller-eight and original root companion.
    pub original_effect: NativeEffectPreparation,
    /// Commits to the separate controller-nine prefix and callback contract.
    pub policy_digest: [u8; 32],
    /// Bounds preallocated immutable original prefix slots from two through 64.
    pub maximum_prefixes: u32,
}

impl NativePrefixPreparation {
    /// Validates complete ancestry and the finite original journal bound.
    ///
    /// # Errors
    /// Rejects an invalid ancestor, absent policy commitment or prefix cap outside 2..=64.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.original_effect.validate()?;
        if self.policy_digest == [0; 32] || !(2..=64).contains(&self.maximum_prefixes) {
            return Err(NativeCommandError::Invalid(
                "invalid original prefix preparation",
            ));
        }
        Ok(())
    }

    /// Encodes the complete unchanged ancestor and closed prefix fields.
    ///
    /// # Errors
    /// Rejects invalid preparation, excessive encoded extent or allocation failure.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let ancestor = self.original_effect.encode()?;
        let length = 12usize
            .checked_add(ancestor.len())
            .and_then(|length| length.checked_add(SUFFIX_BYTES))
            .filter(|length| *length <= NODE_CONTROL_MAX_BODY_BYTES)
            .ok_or(NativeCommandError::ResourceLimit)?;
        let ancestor_length =
            u32::try_from(ancestor.len()).map_err(|_| NativeCommandError::ResourceLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCommandError::ResourceLimit)?;

        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&ancestor_length.to_be_bytes());
        bytes.extend_from_slice(&ancestor);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.maximum_prefixes.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes complete ancestry with exact extents and no trailing bytes.
    ///
    /// # Errors
    /// Rejects unknown tags, malformed or truncated lengths, trailing bytes or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let prefix = bytes.get(..12).ok_or(NativeCommandError::ResourceLimit)?;
        if &prefix[..8] != MAGIC {
            return Err(NativeCommandError::Invalid(
                "unknown prefix preparation tag",
            ));
        }
        let ancestor_length = u32::from_be_bytes(
            prefix[8..12]
                .try_into()
                .map_err(|_| NativeCommandError::ResourceLimit)?,
        ) as usize;
        let suffix_offset = 12usize
            .checked_add(ancestor_length)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if suffix_offset.checked_add(SUFFIX_BYTES) != Some(bytes.len()) {
            return Err(NativeCommandError::ResourceLimit);
        }
        let suffix = &bytes[suffix_offset..];
        let preparation = Self {
            original_effect: NativeEffectPreparation::decode(&bytes[12..suffix_offset])?,
            policy_digest: suffix[..32]
                .try_into()
                .map_err(|_| NativeCommandError::ResourceLimit)?,
            maximum_prefixes: u32::from_be_bytes(
                suffix[32..]
                    .try_into()
                    .map_err(|_| NativeCommandError::ResourceLimit)?,
            ),
        };
        preparation.validate()?;
        Ok(preparation)
    }

    /// Commits to the complete controller-nine preparation without native authority.
    ///
    /// # Errors
    /// Rejects invalid preparation or insufficient bounded encoding credit.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.qemu-native-prefix-preparation.v1\0");
        hash.update(&self.encode()?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Derives early264 without altering the ancestor's early192 bytes.
    ///
    /// # Errors
    /// Rejects invalid original companions, budgets or prefix-policy commitments.
    pub fn early_pin(&self) -> Result<[u8; 264], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 264];
        bytes[..192].copy_from_slice(&self.original_effect.early_pin()?);
        bytes[192..224].copy_from_slice(&self.identity_digest()?);
        bytes[224..256].copy_from_slice(&self.policy_digest);
        bytes[256..260].copy_from_slice(&9u32.to_le_bytes());
        bytes[260..264].copy_from_slice(&self.maximum_prefixes.to_le_bytes());
        Ok(bytes)
    }

    /// Encodes native280 scalars with the complete unchanged native200 ancestor.
    ///
    /// # Errors
    /// Rejects invalid preparation. Encoded bytes cannot issue an epoch or cut.
    pub fn native_policy(&self) -> Result<[u8; 280], NativeCommandError> {
        let early = self.early_pin()?;
        let mut bytes = [0; 280];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&280u32.to_le_bytes());
        bytes[8..208].copy_from_slice(&self.original_effect.native_policy()?);
        bytes[208..].copy_from_slice(&early[192..]);
        Ok(bytes)
    }

    /// Formats canonical lowercase early-policy bytes for source argv validation.
    ///
    /// # Errors
    /// Rejects malformed ancestry or inadequate bounded argument allocation.
    pub fn early_launch_argument(&self) -> Result<String, NativeCommandError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut argument = String::new();
        argument
            .try_reserve_exact(531)
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
// crucible-lint: allow rust-allow -- Closed ancestry and native layout tests intentionally panic on mismatch.
// crucible-lint: allow panic-shortcut -- Closed ancestry and native layout tests intentionally panic on mismatch.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "prefix_preparation_tests.rs"]
mod tests;
