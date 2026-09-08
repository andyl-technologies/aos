//! Durable exactly-once claims for privileged Network preparation workers.
//!
//! A broker request remains replayable bytes even though its in-memory dispatch
//! permit is non-reconstructible. The fixed worker therefore commits one claim
//! to this separately root-owned ledger before its first namespace, policy, or
//! link mutation. An existing request ID always rejects, including an exact
//! byte-for-byte replay; recovery never turns a claim back into effect authority.

use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::worker_protocol::NetworkWorkerProtocolError;

const JOURNAL_FILE: &str = "network-worker-replay.journal";
const CLAIM_MAGIC: &[u8; 8] = b"AOSNWC01";
const CLAIM_VERSION: u16 = 1;
const CLAIM_BYTES: usize = 124;
const CLAIM_KEY_BYTES: usize = 16;

// Journal record accounting includes its namespace and length header. The
// materialized view retains only the key and value.
const JOURNAL_RECORD_HEADER_BYTES: usize = 7;
const ENCODED_CLAIM_RECORD_BYTES: usize =
    JOURNAL_RECORD_HEADER_BYTES + CLAIM_KEY_BYTES + CLAIM_BYTES;
const MATERIALIZED_CLAIM_BYTES: usize = CLAIM_KEY_BYTES + CLAIM_BYTES;

// One claim uses begin, record, and commit frames. Keep the disk ceiling tied
// to the journal's version-one framing rather than an unrelated round number.
const JOURNAL_FRAME_HEADER_BYTES: usize = 72;
const JOURNAL_BEGIN_PAYLOAD_BYTES: usize = 4;
const JOURNAL_COMMIT_PAYLOAD_BYTES: usize = 36;
const ENCODED_CLAIM_TRANSACTION_BYTES: usize = 3 * JOURNAL_FRAME_HEADER_BYTES
    + JOURNAL_BEGIN_PAYLOAD_BYTES
    + ENCODED_CLAIM_RECORD_BYTES
    + JOURNAL_COMMIT_PAYLOAD_BYTES;
const MAXIMUM_CLAIMS: usize = 16_384;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.worker-replay.v1\0";

/// Owns the exclusive root-protected Network worker replay ledger.
pub struct NetworkWorkerReplayLedger {
    journal: Journal,
    maximum_claims: usize,
}

impl NetworkWorkerReplayLedger {
    /// Opens and validates the complete root-owned replay ledger.
    ///
    /// The directory must have a root-owned, non-writable ancestry and exact
    /// mode 0700. The journal and lock are retained root-owned mode-0600 files.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkWorkerProtocolError::ReplayStore`] for an unsafe path,
    /// corrupt journal, malformed claim, exhausted bound, or lock conflict.
    pub fn open_root_owned(directory: &Path) -> Result<Self, NetworkWorkerProtocolError> {
        let (journal, _) =
            Journal::open_protected_at(directory, JOURNAL_FILE, journal_limits(MAXIMUM_CLAIMS))
                .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?;
        Self::from_journal(journal, MAXIMUM_CLAIMS)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(directory: &Path) -> Result<Self, NetworkWorkerProtocolError> {
        Self::open_for_test_with_limit(directory, MAXIMUM_CLAIMS)
    }

    #[cfg(test)]
    fn open_for_test_with_limit(
        directory: &Path,
        maximum_claims: usize,
    ) -> Result<Self, NetworkWorkerProtocolError> {
        let (journal, _) =
            Journal::open(directory.join(JOURNAL_FILE), journal_limits(maximum_claims))
                .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?;
        Self::from_journal(journal, maximum_claims)
    }

    fn from_journal(
        journal: Journal,
        maximum_claims: usize,
    ) -> Result<Self, NetworkWorkerProtocolError> {
        let mut count = 0_usize;
        for (key, value) in journal.records(RecordNamespace::Effect) {
            count = count
                .checked_add(1)
                .ok_or(NetworkWorkerProtocolError::ReplayStore)?;
            let request_id: [u8; 16] = key
                .try_into()
                .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?;
            let claim = decode_claim(value)?;
            if claim.request_id != request_id {
                return Err(NetworkWorkerProtocolError::ReplayStore);
            }
        }
        if count > maximum_claims {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        Ok(Self {
            journal,
            maximum_claims,
        })
    }

    pub(crate) fn claim(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        dispatch_digest: ObjectDigest,
    ) -> Result<(), NetworkWorkerProtocolError> {
        if self
            .journal
            .get(RecordNamespace::Effect, &request_id)
            .is_some()
        {
            return Err(NetworkWorkerProtocolError::Replay);
        }
        if self.journal.records(RecordNamespace::Effect).count() >= self.maximum_claims {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }

        let claim = WorkerClaimV1 {
            request_id,
            effect_digest,
            kernel_plan_digest,
            dispatch_digest,
        };
        let bytes = encode_claim(claim)?;
        let transaction = JournalTransaction::new(
            transaction_id(claim),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                request_id.to_vec(),
                bytes.to_vec(),
            )],
        )
        .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?;
        self.journal
            .commit(&transaction)
            .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?;
        if self.journal.get(RecordNamespace::Effect, &request_id) != Some(bytes.as_slice()) {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerClaimV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    dispatch_digest: ObjectDigest,
}

fn encode_claim(claim: WorkerClaimV1) -> Result<[u8; CLAIM_BYTES], NetworkWorkerProtocolError> {
    if claim.request_id == [0; 16]
        || claim.effect_digest.as_bytes() == &[0; 32]
        || claim.kernel_plan_digest.as_bytes() == &[0; 32]
        || claim.dispatch_digest.as_bytes() == &[0; 32]
    {
        return Err(NetworkWorkerProtocolError::ReplayStore);
    }
    let mut bytes = [0_u8; CLAIM_BYTES];
    bytes[..8].copy_from_slice(CLAIM_MAGIC);
    bytes[8..10].copy_from_slice(&CLAIM_VERSION.to_be_bytes());
    bytes[12..28].copy_from_slice(&claim.request_id);
    bytes[28..60].copy_from_slice(claim.effect_digest.as_bytes());
    bytes[60..92].copy_from_slice(claim.kernel_plan_digest.as_bytes());
    bytes[92..124].copy_from_slice(claim.dispatch_digest.as_bytes());
    Ok(bytes)
}

fn decode_claim(bytes: &[u8]) -> Result<WorkerClaimV1, NetworkWorkerProtocolError> {
    if bytes.len() != CLAIM_BYTES
        || &bytes[..8] != CLAIM_MAGIC
        || bytes[8..10] != CLAIM_VERSION.to_be_bytes()
        || bytes[10..12] != [0, 0]
    {
        return Err(NetworkWorkerProtocolError::ReplayStore);
    }
    let claim = WorkerClaimV1 {
        request_id: bytes[12..28]
            .try_into()
            .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?,
        effect_digest: ObjectDigest::from_bytes(
            bytes[28..60]
                .try_into()
                .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?,
        ),
        kernel_plan_digest: ObjectDigest::from_bytes(
            bytes[60..92]
                .try_into()
                .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?,
        ),
        dispatch_digest: ObjectDigest::from_bytes(
            bytes[92..124]
                .try_into()
                .map_err(|_| NetworkWorkerProtocolError::ReplayStore)?,
        ),
    };
    if encode_claim(claim)?.as_slice() != bytes {
        return Err(NetworkWorkerProtocolError::ReplayStore);
    }
    Ok(claim)
}

fn transaction_id(claim: WorkerClaimV1) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(claim.request_id)
        .chain_update(claim.effect_digest.as_bytes())
        .chain_update(claim.kernel_plan_digest.as_bytes())
        .chain_update(claim.dispatch_digest.as_bytes())
        .finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] { [1; 16] } else { id }
}

const fn journal_limits(maximum_claims: usize) -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: (ENCODED_CLAIM_TRANSACTION_BYTES * maximum_claims) as u64,
        maximum_record_bytes: ENCODED_CLAIM_RECORD_BYTES,
        maximum_key_bytes: CLAIM_KEY_BYTES,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: ENCODED_CLAIM_RECORD_BYTES,
        maximum_transactions: maximum_claims,
        maximum_materialized_bytes: MATERIALIZED_CLAIM_BYTES * maximum_claims,
        maximum_materialized_records: maximum_claims,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use tempfile::TempDir;

    use super::*;

    fn claim(ledger: &mut NetworkWorkerReplayLedger, request: u8) {
        ledger
            .claim(
                [request; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
            )
            .expect("claim");
    }

    #[test]
    fn journal_bounds_cover_the_exact_claim_encoding() {
        let limits = journal_limits(MAXIMUM_CLAIMS);
        assert_eq!(limits.maximum_record_bytes, 7 + 16 + 124);
        assert_eq!(limits.maximum_transaction_bytes, 7 + 16 + 124);
        assert_eq!(
            limits.maximum_materialized_bytes,
            (16 + 124) * MAXIMUM_CLAIMS
        );
        assert_eq!(
            limits.maximum_journal_bytes,
            (3 * 72 + 4 + (7 + 16 + 124) + 36) as u64 * MAXIMUM_CLAIMS as u64
        );

        let directory = TempDir::new().expect("temporary directory");
        let mut ledger =
            NetworkWorkerReplayLedger::open_for_test_with_limit(directory.path(), 1).expect("open");
        claim(&mut ledger, 1);
        drop(ledger);

        let journal_bytes = std::fs::metadata(directory.path().join(JOURNAL_FILE))
            .expect("journal metadata")
            .len();
        assert_eq!(journal_bytes, ENCODED_CLAIM_TRANSACTION_BYTES as u64);
    }

    #[test]
    fn claim_limit_is_exact_and_survives_reopen() {
        let directory = TempDir::new().expect("temporary directory");
        let mut ledger =
            NetworkWorkerReplayLedger::open_for_test_with_limit(directory.path(), 2).expect("open");
        claim(&mut ledger, 1);
        claim(&mut ledger, 2);
        assert_eq!(
            ledger.claim(
                [3; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
            ),
            Err(NetworkWorkerProtocolError::ReplayStore)
        );
        drop(ledger);

        let mut reopened = NetworkWorkerReplayLedger::open_for_test_with_limit(directory.path(), 2)
            .expect("reopen");
        assert_eq!(
            reopened.claim(
                [3; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
            ),
            Err(NetworkWorkerProtocolError::ReplayStore)
        );
    }

    #[test]
    fn exact_and_equivocated_replays_are_both_rejected() {
        let directory = TempDir::new().expect("temporary directory");
        let mut ledger = NetworkWorkerReplayLedger::open_for_test(directory.path()).expect("open");
        claim(&mut ledger, 1);
        assert_eq!(
            ledger.claim(
                [1; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
            ),
            Err(NetworkWorkerProtocolError::Replay)
        );
        assert_eq!(
            ledger.claim(
                [1; 16],
                ObjectDigest::from_bytes([9; 32]),
                ObjectDigest::from_bytes([8; 32]),
                ObjectDigest::from_bytes([7; 32]),
            ),
            Err(NetworkWorkerProtocolError::Replay)
        );
    }

    #[test]
    fn claim_survives_reopen_and_does_not_block_another_request() {
        let directory = TempDir::new().expect("temporary directory");
        {
            let mut ledger =
                NetworkWorkerReplayLedger::open_for_test(directory.path()).expect("open");
            claim(&mut ledger, 1);
        }
        let mut ledger =
            NetworkWorkerReplayLedger::open_for_test(directory.path()).expect("reopen");
        assert_eq!(
            ledger.claim(
                [1; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
            ),
            Err(NetworkWorkerProtocolError::Replay)
        );
        claim(&mut ledger, 5);
    }
}
