//! Non-authorizing Root custody of the V7 protected Cache and Source join.
//!
//! ```text
//! AOSPCP02 | version:u16=2 | reserved[6]=0 | terminal-digest[32] |
//! binding[32] | epoch:u64 | stage-nonce[16] | stage-issue:u64 |
//! Source-nonce[16] | Source-issue:u64 | named-Source-inodes[48] |
//! Source-packet[32] | Cache-packet[32] | Source-pin[32] |
//! Cache-pin[32] | Controller-pin[32] | Source-generation:u64 |
//! Cache-generation:u64 | Controller-generation:u64 | project[16] |
//! partition[32] | Cache-head[32] | quota-envelope[32] | SHA-256[32]
//! ```
//!
//! The companion row is committed with AOSSFT01, never with AOSPCB02. It
//! preserves the exact held preview for cold replay but is not a writer lease,
//! CAS proof, publication capability, or effect authorization.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use crate::journal::ProtectedJournalNamesV1;

use super::PolicyCompilerJournalErrorV1;

pub(super) const KEY: &[u8] = b"\0aos-policy-compiler-held-proof-v2\0";
const MAGIC: &[u8; 8] = b"AOSPCP02";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.held-proof.v2\0";
pub(super) const RECORD_BYTES: usize = 16 + 32 * 10 + 8 * 6 + 16 * 3 + 48 + 32;

#[derive(Clone, Copy)]
pub(super) struct RootHeldProofV2 {
    pub(super) terminal: ObjectDigest,
    pub(super) binding: ObjectDigest,
    pub(super) epoch: u64,
    pub(super) stage_nonce: [u8; 16],
    pub(super) stage_issue: u64,
    pub(super) source_nonce: [u8; 16],
    pub(super) source_issue: u64,
    pub(super) names: ProtectedJournalNamesV1,
    pub(super) source_packet: ObjectDigest,
    pub(super) cache_packet: ObjectDigest,
    pub(super) source_pin: ObjectDigest,
    pub(super) cache_pin: ObjectDigest,
    pub(super) controller_pin: ObjectDigest,
    pub(super) source_generation: u64,
    pub(super) cache_generation: u64,
    pub(super) controller_generation: u64,
    pub(super) project: ProjectId,
    pub(super) partition: ObjectDigest,
    pub(super) cache_head: ObjectDigest,
    pub(super) quota: ObjectDigest,
}

impl RootHeldProofV2 {
    pub(super) fn encode(self) -> Result<[u8; RECORD_BYTES], PolicyCompilerJournalErrorV1> {
        if self.terminal.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.stage_nonce == [0; 16]
            || self.stage_issue == 0
            || self.source_nonce == [0; 16]
            || self.source_issue == 0
            || self.source_packet.as_bytes() == &[0; 32]
            || self.cache_packet.as_bytes() == &[0; 32]
            || self.source_pin.as_bytes() == &[0; 32]
            || self.cache_pin.as_bytes() == &[0; 32]
            || self.controller_pin.as_bytes() == &[0; 32]
            || self.source_generation == 0
            || self.cache_generation == 0
            || self.controller_generation == 0
            || self.project.as_bytes() == &[0; 16]
            || self.partition.as_bytes() == &[0; 32]
            || self.cache_head.as_bytes() == &[0; 32]
            || self.quota.as_bytes() == &[0; 32]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        let mut offset = 16;
        for field in [
            self.terminal.as_bytes().as_slice(),
            self.binding.as_bytes(),
            self.epoch.to_be_bytes().as_slice(),
            self.stage_nonce.as_slice(),
            self.stage_issue.to_be_bytes().as_slice(),
            self.source_nonce.as_slice(),
            self.source_issue.to_be_bytes().as_slice(),
            self.names.to_bytes().as_slice(),
            self.source_packet.as_bytes(),
            self.cache_packet.as_bytes(),
            self.source_pin.as_bytes(),
            self.cache_pin.as_bytes(),
            self.controller_pin.as_bytes(),
            self.source_generation.to_be_bytes().as_slice(),
            self.cache_generation.to_be_bytes().as_slice(),
            self.controller_generation.to_be_bytes().as_slice(),
            self.project.as_bytes(),
            self.partition.as_bytes(),
            self.cache_head.as_bytes(),
            self.quota.as_bytes(),
        ] {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..offset])
            .finalize();
        bytes[offset..].copy_from_slice(&checksum);
        Ok(bytes)
    }
}
