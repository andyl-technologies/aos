//! Durable, nonauthorizing settlement of one Cache-only signer challenge.
//!
//! The fixed Root head retains the latest settled challenge, while an
//! bounded set of per-epoch records preserves recent exact-packet recovery.
//! Neither record grants effect authority.
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
const SETTLEMENT_ARCHIVE_PREFIX: &[u8] = b"\0aos-policy-cache-signer-settlement-epoch-v2\0";
pub(super) const SETTLEMENT_ARCHIVE_WINDOW: u64 = 1_024;
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
    /// Names Root custody for an epoch within the bounded recovery window.
    pub(super) fn archive_key(self) -> Vec<u8> {
        archive_key(self.epoch)
    }

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
        let mut records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                SETTLEMENT_KEY.to_vec(),
                record.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                self.archive_key(),
                record.to_vec(),
            ),
        ];
        if self.epoch > SETTLEMENT_ARCHIVE_WINDOW {
            records.push(JournalRecord::delete(
                RecordNamespace::DesiredState,
                archive_key(self.epoch - SETTLEMENT_ARCHIVE_WINDOW),
            ));
        }
        JournalTransaction::new(transaction_id, records)
    }
}

pub(super) fn archive_key(epoch: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(SETTLEMENT_ARCHIVE_PREFIX.len() + 8);
    key.extend_from_slice(SETTLEMENT_ARCHIVE_PREFIX);
    key.extend_from_slice(&epoch.to_be_bytes());
    key
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

    #[test]
    fn settlement_rollover_atomically_retires_only_the_oldest_archive() {
        let settlement = CacheRootSettlementV2 {
            epoch: SETTLEMENT_ARCHIVE_WINDOW + 1,
            nonce: [1; 16],
            cut: ObjectDigest::from_bytes([2; 32]),
            packet_digest: ObjectDigest::from_bytes([3; 32]),
        };
        let transaction = settlement.transaction().expect("bounded settlement");
        assert_eq!(transaction.records().len(), 3);
        assert_eq!(transaction.records()[1].key(), settlement.archive_key());
        assert_eq!(transaction.records()[2].key(), archive_key(1));
        assert_eq!(transaction.records()[2].value(), None);

        let before_rollover = CacheRootSettlementV2 {
            epoch: SETTLEMENT_ARCHIVE_WINDOW,
            ..settlement
        };
        assert_eq!(
            before_rollover
                .transaction()
                .expect("full window")
                .records()
                .len(),
            2
        );
    }
}
