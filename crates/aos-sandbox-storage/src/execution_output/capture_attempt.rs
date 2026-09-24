//! Protected, observation-only custody of one execution capture create attempt.
//!
//! A future authenticated Storage-target grant and Host AOSEOR02 receipt must
//! construct the private source witness. This module never accepts caller
//! scalars as effect authority and never issues a worker token. Its durable
//! record means a ZFS create *may* have happened: retry is forbidden until
//! independent catalog and live-ZFS observation settle the original attempt.
//!
//! ```text
//! AOSCOA01 | execution[16] | create[16] | AOSEOR03-digest[32]
//!          | Controller-grant-digest[32] | Host-receipt-digest[32]
//!          | Host-correlation-digest[32] | Host-claim-digest[32]
//!          | Host-request-id[16] | assignment-digest[32]
//!          | Storage-create-operation[16] | dataset-policy-digest[32]
//!          | attempt-id[16] | kernel-boot[16] | deadline-boottime:u64be
//!          | Storage-HMAC[32]
//! ```

use aos_sandbox::{JournalRecord, JournalTransaction};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use sha2::{Digest as _, Sha256};

use super::{
    ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerKeyV1, ExecutionOutputLedgerV1, NAMESPACE,
    STATE_RETAINED, decode_record, reservation_key, transaction_id,
};
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;
use crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1;
use crate::execution_output::ProtectedRetainedCaptureV1;
use crate::pin_worker::boottime_now_nanoseconds;

const MAGIC: &[u8; 8] = b"AOSCOA01";
const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-create-issuer.v1\0";
const RECORD_BYTES: usize = 368;

/// Carries independently verified Controller and Host source identities.
///
/// There is deliberately no production constructor. A future issuer must
/// verify a signed Storage-target grant, the original Controller request, and
/// the protected Host AOSHOP01 receipt before it can create this witness.
pub(super) struct VerifiedCaptureAttemptSourcesV1 {
    execution: [u8; 16],
    create: [u8; 16],
    record_digest: ObjectDigest,
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    host_correlation_digest: ObjectDigest,
    host_claim_digest: ObjectDigest,
    host_request_id: [u8; 16],
    assignment_digest: ObjectDigest,
    storage_create_operation: [u8; 16],
    dataset_policy_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
}

impl VerifiedCaptureAttemptSourcesV1 {
    #[cfg(test)]
    fn for_test(
        retained: &ProtectedRetainedCaptureV1,
        requirement: &CaptureDatasetRequirementV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Self {
        Self {
            execution: retained.execution,
            create: retained.create,
            record_digest: retained.record_digest(),
            controller_grant_digest: ObjectDigest::from_bytes([5; 32]),
            host_receipt_digest: ObjectDigest::from_bytes([6; 32]),
            host_correlation_digest: ObjectDigest::from_bytes([7; 32]),
            host_claim_digest: retained.claim_digest,
            host_request_id: [8; 16],
            assignment_digest: ObjectDigest::from_bytes([3; 32]),
            storage_create_operation: *requirement.storage_create_operation().as_bytes(),
            dataset_policy_digest: requirement
                .attempt_policy_digest(metadata_headroom_bytes, minimum_remaining_bytes),
            kernel_boot_id: KernelBootId::current().unwrap().into_bytes(),
            deadline_boottime_nanoseconds: boottime_now_nanoseconds().unwrap() + 30_000_000_000,
        }
    }

    fn current_for_issue(&self) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let boot = KernelBootId::current().map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let now =
            boottime_now_nanoseconds().map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        if self.kernel_boot_id != boot.into_bytes() || now >= self.deadline_boottime_nanoseconds {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureAttemptRecordV1 {
    execution: [u8; 16],
    create: [u8; 16],
    record_digest: ObjectDigest,
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    host_correlation_digest: ObjectDigest,
    host_claim_digest: ObjectDigest,
    host_request_id: [u8; 16],
    assignment_digest: ObjectDigest,
    storage_create_operation: [u8; 16],
    dataset_policy_digest: ObjectDigest,
    attempt: [u8; 16],
    kernel_boot_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
}

impl CaptureAttemptRecordV1 {
    fn from_sources(sources: &VerifiedCaptureAttemptSourcesV1) -> Self {
        let mut record = Self {
            execution: sources.execution,
            create: sources.create,
            record_digest: sources.record_digest,
            controller_grant_digest: sources.controller_grant_digest,
            host_receipt_digest: sources.host_receipt_digest,
            host_correlation_digest: sources.host_correlation_digest,
            host_claim_digest: sources.host_claim_digest,
            host_request_id: sources.host_request_id,
            assignment_digest: sources.assignment_digest,
            storage_create_operation: sources.storage_create_operation,
            dataset_policy_digest: sources.dataset_policy_digest,
            attempt: [0; 16],
            kernel_boot_id: sources.kernel_boot_id,
            deadline_boottime_nanoseconds: sources.deadline_boottime_nanoseconds,
        };
        record.attempt = record.expected_attempt();
        record
    }

    fn expected_attempt(&self) -> [u8; 16] {
        let mut digest = Sha256::new();
        digest.update(ATTEMPT_DOMAIN);
        digest.update(self.execution);
        digest.update(self.create);
        digest.update(self.record_digest.as_bytes());
        digest.update(self.controller_grant_digest.as_bytes());
        digest.update(self.host_receipt_digest.as_bytes());
        digest.update(self.host_correlation_digest.as_bytes());
        digest.update(self.host_claim_digest.as_bytes());
        digest.update(self.host_request_id);
        digest.update(self.assignment_digest.as_bytes());
        digest.update(self.storage_create_operation);
        digest.update(self.dataset_policy_digest.as_bytes());
        digest.update(self.kernel_boot_id);
        digest.update(self.deadline_boottime_nanoseconds.to_be_bytes());
        let mut attempt = [0; 16];
        attempt.copy_from_slice(&digest.finalize()[..16]);
        attempt
    }

    fn matches_sources(&self, sources: &VerifiedCaptureAttemptSourcesV1) -> bool {
        self.execution == sources.execution
            && self.create == sources.create
            && self.record_digest == sources.record_digest
            && self.controller_grant_digest == sources.controller_grant_digest
            && self.host_receipt_digest == sources.host_receipt_digest
            && self.host_correlation_digest == sources.host_correlation_digest
            && self.host_claim_digest == sources.host_claim_digest
            && self.host_request_id == sources.host_request_id
            && self.assignment_digest == sources.assignment_digest
            && self.storage_create_operation == sources.storage_create_operation
            && self.dataset_policy_digest == sources.dataset_policy_digest
            && self.kernel_boot_id == sources.kernel_boot_id
            && self.deadline_boottime_nanoseconds == sources.deadline_boottime_nanoseconds
    }

    fn valid(&self) -> bool {
        self.execution != [0; 16]
            && self.create != [0; 16]
            && self.record_digest.as_bytes() != &[0; 32]
            && self.controller_grant_digest.as_bytes() != &[0; 32]
            && self.host_receipt_digest.as_bytes() != &[0; 32]
            && self.host_correlation_digest.as_bytes() != &[0; 32]
            && self.host_claim_digest.as_bytes() != &[0; 32]
            && self.host_request_id != [0; 16]
            && self.assignment_digest.as_bytes() != &[0; 32]
            && self.storage_create_operation != [0; 16]
            && self.dataset_policy_digest.as_bytes() != &[0; 32]
            && self.attempt != [0; 16]
            && self.attempt == self.expected_attempt()
            && self.kernel_boot_id != [0; 16]
            && self.deadline_boottime_nanoseconds != 0
    }
}

/// Reports only that one exact ZFS create effect may have occurred.
///
/// This local receipt is journal-MAC authenticated, but is not a signed broker
/// response, physical dataset witness, or permission to retry the effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProtectedCaptureCreateAttemptReceiptV1 {
    pub(super) attempt: [u8; 16],
    pub(super) execution: [u8; 16],
    pub(super) create: [u8; 16],
    pub(super) record_digest: ObjectDigest,
    pub(super) controller_grant_digest: ObjectDigest,
    pub(super) host_receipt_digest: ObjectDigest,
    pub(super) host_correlation_digest: ObjectDigest,
    pub(super) storage_create_operation: [u8; 16],
    pub(super) dataset_policy_digest: ObjectDigest,
    pub(super) durable_attempt_digest: ObjectDigest,
}

impl ExecutionOutputLedgerV1 {
    /// Commits one effect-may-have-occurred fence before any ZFS mutation.
    ///
    /// The source witness has no production constructor. A failed or uncertain
    /// commit returns no receipt; recovery must reopen and query. Even an
    /// identical replay cannot mint a second effect permit.
    pub(super) fn issue_capture_create_attempt(
        &mut self,
        sources: &VerifiedCaptureAttemptSourcesV1,
        retained: &ProtectedRetainedCaptureV1,
        requirement: &CaptureDatasetRequirementV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Result<ProtectedCaptureCreateAttemptReceiptV1, ExecutionOutputLedgerErrorV1> {
        sources.current_for_issue()?;
        if sources.execution != retained.execution
            || sources.create != retained.create
            || sources.record_digest != retained.record_digest()
            || sources.host_claim_digest != retained.claim_digest
            || sources.storage_create_operation
                != *requirement.storage_create_operation().as_bytes()
            || sources.dataset_policy_digest
                != requirement
                    .attempt_policy_digest(metadata_headroom_bytes, minimum_remaining_bytes)
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        CaptureZfsPreflightPlanV1::new(
            requirement,
            retained,
            metadata_headroom_bytes,
            minimum_remaining_bytes,
        )
        .map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;

        let logical = self.read_protected_retained_capture(
            sources.execution,
            sources.create,
            sources.record_digest,
        )?;
        if logical != *retained {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let logical_key = reservation_key(sources.execution);
        let logical_bytes = self
            .journal
            .get(NAMESPACE, &logical_key)
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let logical_record = decode_record(&logical_key, logical_bytes, &self.key)?;
        if logical_record.assignment != *sources.assignment_digest.as_bytes() {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        let location = capture_attempt_key(sources.execution);
        if self.journal.get(NAMESPACE, &location).is_some() {
            return Err(ExecutionOutputLedgerErrorV1::Conflict);
        }
        let record = CaptureAttemptRecordV1::from_sources(sources);
        let bytes = encode_attempt(&location, &record, &self.key)?;
        self.journal.commit(&JournalTransaction::new(
            transaction_id(b"capture-create-attempt", &location, &bytes),
            vec![JournalRecord::put(
                NAMESPACE,
                location.to_vec(),
                bytes.to_vec(),
            )],
        )?)?;
        Ok(receipt(&record, &bytes))
    }

    /// Cold-queries only the exact original Controller and Host correlation.
    ///
    /// Query never returns a worker token, including after boot or deadline
    /// expiry. An absent row is distinguishable from a committed ambiguous
    /// effect, while a mismatched correlation is rejected.
    pub(super) fn query_capture_create_attempt(
        &self,
        sources: &VerifiedCaptureAttemptSourcesV1,
    ) -> Result<Option<ProtectedCaptureCreateAttemptReceiptV1>, ExecutionOutputLedgerErrorV1> {
        let location = capture_attempt_key(sources.execution);
        let Some(bytes) = self.journal.get(NAMESPACE, &location) else {
            return Ok(None);
        };
        let record = decode_attempt(&location, bytes, &self.key)?;
        if !record.matches_sources(sources) {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        Ok(Some(receipt(&record, bytes)))
    }
}

pub(super) fn verify_replayed_capture_attempt(
    journal: &aos_sandbox::Journal,
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<(), ExecutionOutputLedgerErrorV1> {
    let record = decode_attempt(location, bytes, key)?;
    let logical_key = reservation_key(record.execution);
    let logical_bytes = journal
        .get(NAMESPACE, &logical_key)
        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
    let logical = decode_record(&logical_key, logical_bytes, key)?;
    if logical.create != record.create
        || logical.claim_digest != *record.host_claim_digest.as_bytes()
        || logical.assignment != *record.assignment_digest.as_bytes()
        || (logical.state == STATE_RETAINED
            && ObjectDigest::from_bytes(Sha256::digest(logical_bytes).into())
                != record.record_digest)
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(())
}

fn capture_attempt_key(execution: [u8; 16]) -> [u8; 17] {
    let mut location = [0; 17];
    location[0] = b'a';
    location[1..].copy_from_slice(&execution);
    location
}

fn receipt(
    record: &CaptureAttemptRecordV1,
    bytes: &[u8],
) -> ProtectedCaptureCreateAttemptReceiptV1 {
    ProtectedCaptureCreateAttemptReceiptV1 {
        attempt: record.attempt,
        execution: record.execution,
        create: record.create,
        record_digest: record.record_digest,
        controller_grant_digest: record.controller_grant_digest,
        host_receipt_digest: record.host_receipt_digest,
        host_correlation_digest: record.host_correlation_digest,
        storage_create_operation: record.storage_create_operation,
        dataset_policy_digest: record.dataset_policy_digest,
        durable_attempt_digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
    }
}

fn encode_attempt(
    location: &[u8],
    record: &CaptureAttemptRecordV1,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<[u8; RECORD_BYTES], ExecutionOutputLedgerErrorV1> {
    if !record.valid() || location != capture_attempt_key(record.execution) {
        return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
    }
    let mut bytes = [0; RECORD_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&record.execution);
    bytes[24..40].copy_from_slice(&record.create);
    bytes[40..72].copy_from_slice(record.record_digest.as_bytes());
    bytes[72..104].copy_from_slice(record.controller_grant_digest.as_bytes());
    bytes[104..136].copy_from_slice(record.host_receipt_digest.as_bytes());
    bytes[136..168].copy_from_slice(record.host_correlation_digest.as_bytes());
    bytes[168..200].copy_from_slice(record.host_claim_digest.as_bytes());
    bytes[200..216].copy_from_slice(&record.host_request_id);
    bytes[216..248].copy_from_slice(record.assignment_digest.as_bytes());
    bytes[248..264].copy_from_slice(&record.storage_create_operation);
    bytes[264..296].copy_from_slice(record.dataset_policy_digest.as_bytes());
    bytes[296..312].copy_from_slice(&record.attempt);
    bytes[312..328].copy_from_slice(&record.kernel_boot_id);
    bytes[328..336].copy_from_slice(&record.deadline_boottime_nanoseconds.to_be_bytes());
    let mac = key.mac(location, &bytes[..336])?;
    bytes[336..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_attempt(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<CaptureAttemptRecordV1, ExecutionOutputLedgerErrorV1> {
    if location.len() != 17
        || location[0] != b'a'
        || bytes.len() != RECORD_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..24] != location[1..]
        || !key.verify_mac(location, &bytes[..336], &bytes[336..])?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    let field = |range: std::ops::Range<usize>| -> Result<[u8; 16], ExecutionOutputLedgerErrorV1> {
        bytes[range]
            .try_into()
            .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)
    };
    let digest =
        |range: std::ops::Range<usize>| -> Result<ObjectDigest, ExecutionOutputLedgerErrorV1> {
            Ok(ObjectDigest::from_bytes(
                bytes[range]
                    .try_into()
                    .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
            ))
        };
    let record = CaptureAttemptRecordV1 {
        execution: field(8..24)?,
        create: field(24..40)?,
        record_digest: digest(40..72)?,
        controller_grant_digest: digest(72..104)?,
        host_receipt_digest: digest(104..136)?,
        host_correlation_digest: digest(136..168)?,
        host_claim_digest: digest(168..200)?,
        host_request_id: field(200..216)?,
        assignment_digest: digest(216..248)?,
        storage_create_operation: field(248..264)?,
        dataset_policy_digest: digest(264..296)?,
        attempt: field(296..312)?,
        kernel_boot_id: field(312..328)?,
        deadline_boottime_nanoseconds: u64::from_be_bytes(
            bytes[328..336]
                .try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?,
        ),
    };
    if !record.valid() || capture_attempt_key(record.execution) != location {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aos_sandbox::{Journal, JournalLimits};
    use tempfile::TempDir;

    use super::*;
    use crate::catalog_transition::execution_capture::tests::fixture;
    use crate::execution_output::{RetainedOutputRecord, STATE_RETAINED};

    fn key() -> ExecutionOutputLedgerKeyV1 {
        ExecutionOutputLedgerKeyV1::new([7; 16], [9; 32]).unwrap()
    }

    fn open(path: &Path) -> ExecutionOutputLedgerV1 {
        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        ExecutionOutputLedgerV1::from_journal(journal, 200, key()).unwrap()
    }

    fn reserve(ledger: &mut ExecutionOutputLedgerV1) -> ProtectedRetainedCaptureV1 {
        let record = RetainedOutputRecord {
            execution: [1; 16],
            create: [2; 16],
            assignment: [3; 32],
            claim_digest: [3; 32],
            bytes: 100,
            maximum_stdout_bytes: 60,
            maximum_stderr_bytes: 40,
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        };
        let digest = ledger.reserve_record(record).unwrap();
        ledger
            .read_protected_retained_capture([1; 16], [2; 16], digest)
            .unwrap()
    }

    #[test]
    fn exact_capture_attempt_is_cold_queryable_but_never_reissued() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path);
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let sources = VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);
        assert!(
            ledger
                .query_capture_create_attempt(&sources)
                .unwrap()
                .is_none()
        );

        let receipt = ledger
            .issue_capture_create_attempt(&sources, &retained, &requirement, 20, 100)
            .unwrap();
        assert_eq!(receipt.execution, [1; 16]);
        assert_eq!(receipt.create, [2; 16]);
        assert_eq!(receipt.record_digest, retained.record_digest());
        assert_ne!(receipt.attempt, [0; 16]);
        assert_ne!(receipt.durable_attempt_digest.as_bytes(), &[0; 32]);
        drop(ledger);

        let mut recovered = open(&path);
        assert_eq!(
            recovered.query_capture_create_attempt(&sources).unwrap(),
            Some(receipt)
        );
        assert!(matches!(
            recovered.issue_capture_create_attempt(&sources, &retained, &requirement, 20, 100),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));

        let mut substituted = sources;
        substituted.host_receipt_digest = ObjectDigest::from_bytes([10; 32]);
        assert!(matches!(
            recovered.query_capture_create_attempt(&substituted),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(matches!(
            recovered.issue_capture_create_attempt(&substituted, &retained, &requirement, 20, 100,),
            Err(ExecutionOutputLedgerErrorV1::Conflict)
        ));
        substituted.host_receipt_digest = receipt.host_receipt_digest;
        substituted.controller_grant_digest = ObjectDigest::from_bytes([11; 32]);
        assert!(matches!(
            recovered.query_capture_create_attempt(&substituted),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
    }

    #[test]
    fn stale_or_substituted_sources_never_append_an_attempt() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path);
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let mut sources =
            VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);

        sources.assignment_digest = ObjectDigest::from_bytes([12; 32]);
        assert!(matches!(
            ledger.issue_capture_create_attempt(&sources, &retained, &requirement, 20, 100),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        sources.assignment_digest = ObjectDigest::from_bytes([3; 32]);
        sources.dataset_policy_digest = ObjectDigest::from_bytes([13; 32]);
        assert!(matches!(
            ledger.issue_capture_create_attempt(&sources, &retained, &requirement, 20, 100),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        sources.dataset_policy_digest = requirement.attempt_policy_digest(20, 100);
        sources.deadline_boottime_nanoseconds = 1;
        assert!(matches!(
            ledger.issue_capture_create_attempt(&sources, &retained, &requirement, 20, 100),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(
            ledger
                .query_capture_create_attempt(&sources)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn tampered_attempt_record_fails_cold_replay() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.journal");
        let mut ledger = open(&path);
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let sources = VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);
        ledger
            .issue_capture_create_attempt(&sources, &retained, &requirement, 20, 100)
            .unwrap();

        let location = capture_attempt_key([1; 16]);
        let mut tampered = ledger.journal.get(NAMESPACE, &location).unwrap().to_vec();
        tampered[136] ^= 1;
        ledger
            .journal
            .commit(
                &JournalTransaction::new(
                    [15; 16],
                    vec![JournalRecord::put(NAMESPACE, location.to_vec(), tampered)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(ledger);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(matches!(
            ExecutionOutputLedgerV1::from_journal(journal, 200, key()),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)
        ));
    }
}
