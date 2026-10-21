//! Owns the sole canonical Root binding-hold DATA codec.
//!
//! ```text
//! AOSPCH01 | version1 | phase1|2 | reserved5 | issuer16 | binding32 | epoch8 | SHA32
//! ```
//!
//! A checked hold record grants no native, barrier, handoff or release authority.

use super::BindingDataErrorV1;
use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};
const HOLD_RECORD_BYTES: usize = 104;
const HOLD_MAGIC: &[u8; 8] = b"AOSPCH01";
const HOLD_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-hold.v1\0";

/// Retains the existing canonical held/released fields as unbranded DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootBindingHoldV1 {
    pub issuer_owner: [u8; 16],
    pub binding: ObjectDigest,
    pub epoch: u64,
    pub held: bool,
}

impl RootBindingHoldV1 {
    /// Returns the sole hold codec's complete fixed encoded width.
    #[must_use]
    pub const fn encoded_bytes_v1() -> usize {
        HOLD_RECORD_BYTES
    }

    /// Encodes the exact existing hold framing and checksum.
    ///
    /// # Errors
    /// Rejects a zero issuer, binding or epoch.
    pub fn encode(self) -> Result<[u8; HOLD_RECORD_BYTES], BindingDataErrorV1> {
        if self.issuer_owner == [0; 16] || self.binding.as_bytes() == &[0; 32] || self.epoch == 0 {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = [0_u8; HOLD_RECORD_BYTES];
        bytes[..8].copy_from_slice(HOLD_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(&self.issuer_owner);
        bytes[32..64].copy_from_slice(self.binding.as_bytes());
        bytes[64..72].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(HOLD_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..72])
            .finalize();
        bytes[72..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes and compares the complete canonical hold record.
    ///
    /// # Errors
    /// Rejects wrong framing, phase, reserved bytes, checksum or fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, BindingDataErrorV1> {
        if bytes.len() != HOLD_RECORD_BYTES
            || bytes.get(..8) != Some(HOLD_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        let record = Self {
            issuer_owner: bytes[16..32]
                .try_into()
                .map_err(|_| BindingDataErrorV1::UnauthenticatedCandidate)?,
            binding: ObjectDigest::from_bytes(
                bytes[32..64]
                    .try_into()
                    .map_err(|_| BindingDataErrorV1::UnauthenticatedCandidate)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[64..72]
                    .try_into()
                    .map_err(|_| BindingDataErrorV1::UnauthenticatedCandidate)?,
            ),
            held: bytes[10] == 1,
        };
        if record.encode()?.as_slice() != bytes {
            return Err(BindingDataErrorV1::UnauthenticatedCandidate);
        }
        Ok(record)
    }
}
