//! Durable claims for privileged Network workers.
//!
//! A broker request remains replayable bytes even though its in-memory dispatch
//! permit is non-reconstructible. The fixed worker therefore commits one claim
//! to this separately root-owned ledger before its first namespace, policy, or
//! link mutation. Preparation rejects every replay. Lifecycle effects may
//! admit an exact byte-for-byte replay only when each fixed step is a
//! replacement or an exact absence-tolerant removal. A reused request ID with
//! different effect bytes always rejects.

mod retained;
pub use retained::{NetworkWorkerReplayOpeningOriginalV4, NetworkWorkerReplayClaimOriginalV4};

use std::path::Path;

use crate::journal::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_model::ObjectDigest;
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
    retained_native: bool,
    claim_original: Option<NetworkWorkerReplayClaimOriginalV4>,
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
        let ledger = Self {
            journal,
            maximum_claims,
            retained_native: false,
            claim_original: None,
        };
        ledger.validate_claims_v4()?;
        Ok(ledger)
    }

    fn validate_claims_v4(&self) -> Result<(), NetworkWorkerProtocolError> {
        let mut count = 0_usize;
        for (key, value) in self.journal.records(RecordNamespace::Effect) {
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
        if count > self.maximum_claims {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        Ok(())
    }

    pub(crate) fn claim(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        dispatch_digest: ObjectDigest,
    ) -> Result<(), NetworkWorkerProtocolError> {
        if self.retained_native {
            return self.claim_retaining_v4(request_id, effect_digest, kernel_plan_digest, dispatch_digest);
        }
        let mut original = NetworkWorkerReplayClaimOriginalV4::new();
        Self::claim_engine_v4(&mut self.journal, self.maximum_claims, false,
            request_id, effect_digest, kernel_plan_digest, dispatch_digest, &mut original)
    }

    /// Prices the actual held prefix before any claim encoder or TX allocation.
    ///
    /// # Errors
    /// Preserves the actual metadata/native geometry and accounting error.
    pub fn claim_receiving_demand_v4(&self) -> Result<aos_sandbox_model::ResourceVector,
        crate::journal::JournalAppendReceivingDemandErrorV1>
    {
        Self::claim_demand_v4(&self.journal)
    }

    fn claim_demand_v4(journal: &Journal) -> Result<aos_sandbox_model::ResourceVector,
        crate::journal::JournalAppendReceivingDemandErrorV1>
    {
        journal.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: CLAIM_KEY_BYTES,
                value_bytes: Some(CLAIM_BYTES),
            },
        ))
    }

    /// Claims once in the inline slot owned by this same fixed worker ledger.
    ///
    /// The parent has funded the complete compiled child source before issue.
    /// This mechanical method grants no namespace or link mutation permission.
    ///
    /// # Errors
    /// Refuses ordinary/lifecycle ledgers, replay, reentry or any actual native,
    /// codec, TX, commit or readback error without dropping reached custody.
    pub fn claim_retaining_v4(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        dispatch_digest: ObjectDigest,
    ) -> Result<(), NetworkWorkerProtocolError> {
        if let Some(original) = self.claim_original.as_mut() {
            original.reentry.get_or_insert(NetworkWorkerProtocolError::ReplayStore);
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        self.claim_original = Some(NetworkWorkerReplayClaimOriginalV4::new());
        let Some(original) = self.claim_original.as_mut() else {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        };
        if !self.retained_native {
            original.entered = true;
            original.entry = Some(Err(NetworkWorkerProtocolError::ReplayStore));
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        Self::claim_engine_v4(&mut self.journal, self.maximum_claims, true,
            request_id, effect_digest, kernel_plan_digest, dispatch_digest, original)
    }

    /// Borrows this same ledger's sole actual claim attempt, including failures.
    #[must_use]
    pub fn claim_original_v4(&self) -> Option<&NetworkWorkerReplayClaimOriginalV4> {
        self.claim_original.as_ref()
    }

    /// Borrows the earliest whole claim error without selecting a later cause.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.claim_original.as_ref().and_then(NetworkWorkerReplayClaimOriginalV4::failure)
    }

    fn claim_engine_v4(
        journal: &mut Journal,
        maximum_claims: usize,
        selected: bool,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        dispatch_digest: ObjectDigest,
        original: &mut NetworkWorkerReplayClaimOriginalV4,
    ) -> Result<(), NetworkWorkerProtocolError> {
        if original.entered {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        original.entered = true;
        original.entry = Some(if journal.get(RecordNamespace::Effect, &request_id).is_some() {
            Err(NetworkWorkerProtocolError::Replay)
        } else if journal.records(RecordNamespace::Effect).count() >= maximum_claims {
            Err(NetworkWorkerProtocolError::ReplayStore)
        } else {
            Ok(())
        });
        if let Some(Err(error)) = &original.entry {
            return Err(if matches!(error, NetworkWorkerProtocolError::Replay) {
                NetworkWorkerProtocolError::Replay
            } else {
                NetworkWorkerProtocolError::ReplayStore
            });
        }

        if selected {
            original.forecast = Some(Self::claim_demand_v4(journal));
            if !matches!(original.forecast, Some(Ok(_))) {
                return Err(NetworkWorkerProtocolError::ReplayStore);
            }
        }
        let claim = WorkerClaimV1 {
            request_id, effect_digest, kernel_plan_digest, dispatch_digest,
        };
        original.encoded = Some(encode_claim(claim));
        let bytes = match original.encoded.as_ref() {
            Some(Ok(bytes)) => bytes,
            _ => return Err(NetworkWorkerProtocolError::ReplayStore),
        };
        original.transaction = Some(JournalTransaction::new(transaction_id(claim), vec![
            JournalRecord::put(RecordNamespace::Effect, request_id.to_vec(), bytes.to_vec()),
        ]));
        let transaction = match original.transaction.as_ref() {
            Some(Ok(transaction)) => transaction,
            _ => return Err(NetworkWorkerProtocolError::ReplayStore),
        };
        original.commit = Some(journal.commit(transaction));
        if !matches!(original.commit, Some(Ok(_))) {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        original.readback = Some(if journal.get(RecordNamespace::Effect, &request_id) == Some(bytes.as_slice()) {
            Ok(())
        } else {
            Err(NetworkWorkerProtocolError::ReplayStore)
        });
        if matches!(original.readback, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NetworkWorkerProtocolError::ReplayStore)
        }
    }

    /// Claims a fresh effect or admits an exact idempotent lifecycle replay.
    ///
    /// The caller must restrict this entry point to lifecycle actions whose
    /// complete ordered step sequence is safe to repeat. A reused request ID
    /// with any different effect, plan, or dispatch commitment is rejected.
    pub(crate) fn claim_idempotent_lifecycle(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        dispatch_digest: ObjectDigest,
    ) -> Result<(), NetworkWorkerProtocolError> {
        if self.retained_native {
            return Err(NetworkWorkerProtocolError::ReplayStore);
        }
        let claim = WorkerClaimV1 {
            request_id,
            effect_digest,
            kernel_plan_digest,
            dispatch_digest,
        };
        if let Some(existing) = self.journal.get(RecordNamespace::Effect, &request_id) {
            return if decode_claim(existing)? == claim {
                Ok(())
            } else {
                Err(NetworkWorkerProtocolError::Replay)
            };
        }

        self.claim(
            request_id,
            effect_digest,
            kernel_plan_digest,
            dispatch_digest,
        )
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
    fn idempotent_lifecycle_claim_admits_only_an_exact_replay() {
        let directory = TempDir::new().expect("temporary directory");
        let mut ledger = NetworkWorkerReplayLedger::open_for_test(directory.path()).expect("open");
        claim(&mut ledger, 1);

        assert_eq!(
            ledger.claim_idempotent_lifecycle(
                [1; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
            ),
            Ok(())
        );
        assert_eq!(
            ledger.claim_idempotent_lifecycle(
                [1; 16],
                ObjectDigest::from_bytes([9; 32]),
                ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]),
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
