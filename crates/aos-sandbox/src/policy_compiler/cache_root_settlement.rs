//! Durable, nonauthorizing settlement of one Cache-only signer challenge.
//!
//! The fixed Root record retains only the latest settled challenge. A Root
//! writer compares it with the still-current challenge before replacement;
//! cold replay can identify an exact recorded packet but cannot grant effect
//! authority from this record alone.
//!
//! ```text
//! AOSCRS02 | epoch:u64 | nonce:16 | root-source-cut:32 |
//! SHA-256(exact signed V2 packet) or zero for explicit abandonment:32 |
//! SHA-256(record-domain || body):32
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

pub(super) const SETTLEMENT_KEY: &[u8] = b"\0aos-policy-cache-signer-settlement-v2\0";
const MAGIC: &[u8; 8] = b"AOSCRS02";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-signer-settlement-record.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-signer-settlement-transaction.v2\0";
const BODY_BYTES: usize = 96;
pub(super) const RECORD_BYTES: usize = BODY_BYTES + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CacheRootSettlementV2 {
    pub(super) epoch: u64,
    pub(super) nonce: [u8; 16],
    pub(super) cut: ObjectDigest,
    pub(super) packet_digest: ObjectDigest,
}

impl CacheRootSettlementV2 {
    pub(super) fn abandoned(self) -> bool {
        self.packet_digest.as_bytes() == &[0; 32]
    }

    pub(super) fn encode(self) -> [u8; RECORD_BYTES] {
        let mut record = [0_u8; RECORD_BYTES];
        record[..8].copy_from_slice(MAGIC);
        record[8..16].copy_from_slice(&self.epoch.to_be_bytes());
        record[16..32].copy_from_slice(&self.nonce);
        record[32..64].copy_from_slice(self.cut.as_bytes());
        record[64..96].copy_from_slice(self.packet_digest.as_bytes());
        let checksum = Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(&record[..BODY_BYTES])
            .finalize();
        record[BODY_BYTES..].copy_from_slice(&checksum);
        record
    }

    pub(super) fn decode(record: &[u8]) -> Option<Self> {
        if record.len() != RECORD_BYTES || record[..8] != MAGIC[..] {
            return None;
        }
        let checksum = Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(&record[..BODY_BYTES])
            .finalize();
        if record[BODY_BYTES..] != checksum[..] {
            return None;
        }
        let settlement = Self {
            epoch: u64::from_be_bytes(record[8..16].try_into().ok()?),
            nonce: record[16..32].try_into().ok()?,
            cut: ObjectDigest::from_bytes(record[32..64].try_into().ok()?),
            packet_digest: ObjectDigest::from_bytes(record[64..96].try_into().ok()?),
        };
        (settlement.epoch != 0
            && settlement.nonce != [0; 16]
            && settlement.cut.as_bytes() != &[0; 32])
            .then_some(settlement)
    }

    pub(super) fn transaction(self) -> Result<JournalTransaction, JournalError> {
        let record = self.encode();
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(record)
            .finalize();
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&digest[..16]);
        JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                SETTLEMENT_KEY.to_vec(),
                record.to_vec(),
            )],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_encoding_rejects_tampering_and_noncanonical_fields() {
        let settlement = CacheRootSettlementV2 {
            epoch: 3,
            nonce: [1; 16],
            cut: ObjectDigest::from_bytes([2; 32]),
            packet_digest: ObjectDigest::from_bytes([3; 32]),
        };
        let encoded = settlement.encode();
        assert_eq!(CacheRootSettlementV2::decode(&encoded), Some(settlement));
        for offset in [0, 8, 16, 32, 64, 96, 127] {
            let mut altered = encoded;
            altered[offset] ^= 1;
            assert_eq!(CacheRootSettlementV2::decode(&altered), None);
        }
        let noncanonical = [
            CacheRootSettlementV2 {
                epoch: 0,
                ..settlement
            },
            CacheRootSettlementV2 {
                nonce: [0; 16],
                ..settlement
            },
            CacheRootSettlementV2 {
                cut: ObjectDigest::from_bytes([0; 32]),
                ..settlement
            },
        ];
        for altered in noncanonical {
            assert_eq!(CacheRootSettlementV2::decode(&altered.encode()), None);
        }
        let abandoned = CacheRootSettlementV2 {
            packet_digest: ObjectDigest::from_bytes([0; 32]),
            ..settlement
        };
        assert_eq!(
            CacheRootSettlementV2::decode(&abandoned.encode()),
            Some(abandoned)
        );
        assert!(abandoned.abandoned());
    }
}
