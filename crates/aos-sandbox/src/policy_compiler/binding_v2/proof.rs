//! Root-owned evidence of the two signer packets verified at a held Q04 CAS.
//!
//! ```text
//! AOSPCP01 | version=1 | reserved[6]=0 | binding[32] | epoch[8] |
//! Source-generation[8] | Cache-generation[8] | challenge[16] | cut[32] |
//! Source-packet-digest[32] | Cache-packet-digest[32] |
//! Source-pin-digest[32] | Cache-pin-digest[32] | SHA-256[32]
//! ```
//!
//! This record is committed with AOSPCB02 and its Root hold. It preserves the
//! exact signer flight across a lost reply, but confers no effect authority.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::PolicyCompilerJournalErrorV1;

pub(super) const PROOF_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-q04-proof-v1\0";
const MAGIC: &[u8; 8] = b"AOSPCP01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.q04-proof.v1\0";
const RECORD_BYTES: usize = 280;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootQualifiedProofV1 {
    pub(super) binding: ObjectDigest,
    pub(super) epoch: u64,
    pub(super) source_generation: u64,
    pub(super) cache_generation: u64,
    pub(super) challenge: [u8; 16],
    pub(super) cut: ObjectDigest,
    pub(super) source_packet: ObjectDigest,
    pub(super) cache_packet: ObjectDigest,
    pub(super) source_pin: ObjectDigest,
    pub(super) cache_pin: ObjectDigest,
}

impl RootQualifiedProofV1 {
    pub(super) fn encode(self) -> Result<[u8; RECORD_BYTES], PolicyCompilerJournalErrorV1> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.source_generation == 0
            || self.cache_generation == 0
            || self.challenge == [0; 16]
            || self.cut.as_bytes() == &[0; 32]
            || self.source_packet.as_bytes() == &[0; 32]
            || self.cache_packet.as_bytes() == &[0; 32]
            || self.source_pin.as_bytes() == &[0; 32]
            || self.cache_pin.as_bytes() == &[0; 32]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.source_generation.to_be_bytes());
        bytes[64..72].copy_from_slice(&self.cache_generation.to_be_bytes());
        bytes[72..88].copy_from_slice(&self.challenge);
        bytes[88..120].copy_from_slice(self.cut.as_bytes());
        bytes[120..152].copy_from_slice(self.source_packet.as_bytes());
        bytes[152..184].copy_from_slice(self.cache_packet.as_bytes());
        bytes[184..216].copy_from_slice(self.source_pin.as_bytes());
        bytes[216..248].copy_from_slice(self.cache_pin.as_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..248])
            .finalize();
        bytes[248..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let digest =
            |range: std::ops::Range<usize>| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
                Ok(ObjectDigest::from_bytes(bytes[range].try_into().map_err(
                    |_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate,
                )?))
            };
        let number = |range: std::ops::Range<usize>| -> Result<u64, PolicyCompilerJournalErrorV1> {
            Ok(u64::from_be_bytes(bytes[range].try_into().map_err(
                |_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate,
            )?))
        };
        let record = Self {
            binding: digest(16..48)?,
            epoch: number(48..56)?,
            source_generation: number(56..64)?,
            cache_generation: number(64..72)?,
            challenge: bytes[72..88]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
            cut: digest(88..120)?,
            source_packet: digest(120..152)?,
            cache_packet: digest(152..184)?,
            source_pin: digest(184..216)?,
            cache_pin: digest(216..248)?,
        };
        if record.encode()?.as_slice() != bytes {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(record)
    }
}

pub(super) fn proof_key(binding: ObjectDigest) -> Vec<u8> {
    let mut key = PROOF_KEY_PREFIX.to_vec();
    key.extend_from_slice(binding.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_proof_rejects_changed_signer_or_cut_fields() {
        let proof = RootQualifiedProofV1 {
            binding: ObjectDigest::from_bytes([1; 32]),
            epoch: 7,
            source_generation: 3,
            cache_generation: 4,
            challenge: [5; 16],
            cut: ObjectDigest::from_bytes([6; 32]),
            source_packet: ObjectDigest::from_bytes([7; 32]),
            cache_packet: ObjectDigest::from_bytes([8; 32]),
            source_pin: ObjectDigest::from_bytes([9; 32]),
            cache_pin: ObjectDigest::from_bytes([10; 32]),
        };
        let bytes = proof.encode().expect("canonical proof");
        assert_eq!(RootQualifiedProofV1::decode(&bytes).unwrap(), proof);

        for index in [16, 48, 56, 64, 72, 88, 120, 152, 184, 216, 248] {
            let mut altered = bytes;
            altered[index] ^= 1;
            assert!(RootQualifiedProofV1::decode(&altered).is_err());
        }
    }
}
