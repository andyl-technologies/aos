//! Canonical root-journal challenge records shared by closed owner readbacks.
//!
//! ```text
//! magic[8] | epoch:u64be | nonce[16] | owner-specific-cut[32] |
//! SHA-256(record-domain || preceding 64 bytes)[32]
//! ```
//!
//! Each owner supplies distinct magic, domains, and key. This codec neither
//! chooses a cut nor grants authority; callers keep their own spend ordering
//! and map malformed prior records to their own stale error.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

pub(super) const RECORD_BYTES: usize = 96;

pub(super) struct RootChallengeRecordCodec {
    magic: &'static [u8; 8],
    record_domain: &'static [u8],
    transaction_domain: &'static [u8],
    key: &'static [u8],
}

impl RootChallengeRecordCodec {
    pub(super) const fn new(
        magic: &'static [u8; 8],
        record_domain: &'static [u8],
        transaction_domain: &'static [u8],
        key: &'static [u8],
    ) -> Self {
        Self {
            magic,
            record_domain,
            transaction_domain,
            key,
        }
    }

    pub(super) fn read_prior(&self, record: Option<&[u8]>) -> Option<(u64, [u8; 16])> {
        let Some(record) = record else {
            return Some((0, [0; 16]));
        };
        if record.len() != RECORD_BYTES || record[..8] != self.magic[..] {
            return None;
        }
        let checksum = Sha256::new()
            .chain_update(self.record_domain)
            .chain_update(&record[..64])
            .finalize();
        if record[64..] != checksum[..] || record[16..32] == [0; 16] || record[32..64] == [0; 32] {
            return None;
        }

        let epoch = u64::from_be_bytes(record[8..16].try_into().ok()?);
        let nonce = record[16..32].try_into().ok()?;
        (epoch != 0).then_some((epoch, nonce))
    }

    pub(super) fn encode(
        &self,
        epoch: u64,
        nonce: [u8; 16],
        cut: ObjectDigest,
    ) -> [u8; RECORD_BYTES] {
        let mut record = [0_u8; RECORD_BYTES];
        record[..8].copy_from_slice(self.magic);
        record[8..16].copy_from_slice(&epoch.to_be_bytes());
        record[16..32].copy_from_slice(&nonce);
        record[32..64].copy_from_slice(cut.as_bytes());
        let checksum = Sha256::new()
            .chain_update(self.record_domain)
            .chain_update(&record[..64])
            .finalize();
        record[64..].copy_from_slice(&checksum);
        record
    }

    pub(super) fn transaction(
        &self,
        record: [u8; RECORD_BYTES],
    ) -> Result<JournalTransaction, JournalError> {
        let digest = Sha256::new()
            .chain_update(self.transaction_domain)
            .chain_update(record)
            .finalize();
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&digest[..16]);
        JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                self.key.to_vec(),
                record.to_vec(),
            )],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
        b"AOSCTH01",
        b"aos.sandbox.policy-controller-hold-challenge-record.v1\0",
        b"aos.sandbox.policy-controller-hold-challenge-transaction.v1\0",
        b"\0aos-policy-controller-hold-challenge-v1\0",
    );
    const CACHE: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
        b"AOSCRH01",
        b"aos.sandbox.policy-cache-readback-challenge-record.v1\0",
        b"aos.sandbox.policy-cache-readback-challenge-transaction.v1\0",
        b"\0aos-policy-cache-readback-challenge-v1\0",
    );

    #[test]
    fn both_owner_records_round_trip_with_distinct_transactions() {
        let nonce = [3; 16];
        let cut = ObjectDigest::from_bytes([4; 32]);
        for codec in [&CONTROLLER, &CACHE] {
            assert_eq!(codec.read_prior(None), Some((0, [0; 16])));
            let record = codec.encode(7, nonce, cut);
            assert_eq!(codec.read_prior(Some(&record)), Some((7, nonce)));

            let transaction = codec
                .transaction(record)
                .expect("valid challenge transaction");
            let expected_id = Sha256::new()
                .chain_update(codec.transaction_domain)
                .chain_update(record)
                .finalize();
            assert_eq!(transaction.id(), &expected_id[..16]);
            assert_eq!(transaction.records().len(), 1);
            assert_eq!(
                transaction.records()[0].namespace(),
                RecordNamespace::DesiredState
            );
            assert_eq!(transaction.records()[0].key(), codec.key);
            assert_eq!(transaction.records()[0].value(), Some(record.as_slice()));
        }
        let controller = CONTROLLER.encode(7, nonce, cut);
        let cache = CACHE.encode(7, nonce, cut);
        assert_ne!(controller, cache);
        assert_eq!(CONTROLLER.read_prior(Some(&cache)), None);
        assert_eq!(CACHE.read_prior(Some(&controller)), None);
        assert_ne!(
            CONTROLLER.transaction(controller).unwrap().id(),
            CACHE.transaction(cache).unwrap().id()
        );
    }

    #[test]
    fn malformed_or_replayed_owner_bytes_fail_closed() {
        let record = CONTROLLER.encode(7, [3; 16], ObjectDigest::from_bytes([4; 32]));
        for offset in [0, 8, 16, 32, 64, 95] {
            let mut changed = record;
            changed[offset] ^= 1;
            assert_eq!(CONTROLLER.read_prior(Some(&changed)), None);
        }
        for (start, end) in [(8, 16), (16, 32), (32, 64)] {
            let mut changed = record;
            changed[start..end].fill(0);
            let checksum = Sha256::new()
                .chain_update(CONTROLLER.record_domain)
                .chain_update(&changed[..64])
                .finalize();
            changed[64..].copy_from_slice(&checksum);
            assert_eq!(CONTROLLER.read_prior(Some(&changed)), None);
        }
        assert_eq!(CONTROLLER.read_prior(Some(&record[..95])), None);
        let mut extended = record.to_vec();
        extended.push(0);
        assert_eq!(CONTROLLER.read_prior(Some(&extended)), None);

        let other_domain = RootChallengeRecordCodec::new(
            CONTROLLER.magic,
            CACHE.record_domain,
            CACHE.transaction_domain,
            CACHE.key,
        );
        assert_eq!(other_domain.read_prior(Some(&record)), None);
    }
}
