//! Protected, observation-only custody of one execution capture create attempt.
//!
//! A future authenticated Storage-target grant and Host AOSEOR02 receipt must
//! construct the private source witness. This module never accepts caller
//! scalars as effect authority and never issues a worker token. Its durable
//! record means a ZFS create *may* have happened: retry is forbidden until
//! independent catalog and live-ZFS observation settle the original attempt.
//!
//! ```text
//! AOSCOA03 | execution[16] | create[16] | AOSEOR03-digest[32]
//!          | Controller-grant-digest[32] | Host-receipt-digest[32]
//!          | Host-correlation-digest[32] | Host-claim-digest[32]
//!          | Host-request-id[16] | assignment-digest[32]
//!          | Storage-create-operation[16] | dataset-policy-digest[32]
//!          | attempt-id[16] | kernel-boot[16] | ongoing-deadline:u64be
//!          | complete-Source944-digest[32] | original60-request[16]
//!          | original-acquisition-deadline:u64be | Storage-HMAC[32]
//!
//! The canonical record is exactly424 bytes. Earlier PR-only368/416-byte
//! records are refused explicitly; they never become an ongoing admission.
//! ```

use aos_sandbox_controller_domain::{JournalRecord, JournalTransaction};
use aos_sandbox_model::ObjectDigest;
use aos_linux_descriptors::boot::KernelBootId;
use sha2::{Digest as _, Sha256};

mod complete;
pub(crate) use complete::CaptureCompletePersistenceOriginalV2;
pub(super) use complete::verify_replayed_complete_v2;

mod admission;
pub(crate) use admission::CaptureSourceAdmissionErrorV2;

mod issuance;
pub(crate) use issuance::{CaptureCreateIssuanceOriginalV3, FreshCaptureCreateCommitV3};

use super::{
    ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerKeyV1, ExecutionOutputLedgerV1, NAMESPACE,
    STATE_RETAINED, decode_record, reservation_key, transaction_id,
};
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;
use crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightPlanV1;
use crate::execution_output::ProtectedRetainedCaptureV1;
use crate::pin_worker::boottime_now_nanoseconds;

const MAGIC: &[u8; 8] = b"AOSCOA03";
const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-create-issuer.v1\0";
const RECORD_BYTES: usize = 424;
const CONTENT_BYTES: usize = RECORD_BYTES - 32;

/// Carries independently verified Controller and Host source identities.
///
/// Only the private physical-reserve admission joins the actual authenticated
/// signed60 request, original Controller records, current protected output and
/// authenticated Host readback. Its coordinator must retain those real owners
/// through the separately funded native/durable attempt; this is no worker or
/// physical-completion factory.
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
    source: CaptureSourceAssociationV2,
}

impl VerifiedCaptureAttemptSourcesV1 {
    #[cfg(test)]
    pub(super) fn for_test(
        retained: &ProtectedRetainedCaptureV1,
        requirement: &CaptureDatasetRequirementV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Self {
        let deadline = boottime_now_nanoseconds().unwrap() + 30_000_000_000;
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
            deadline_boottime_nanoseconds: deadline,
            source: CaptureSourceAssociationV2 {
                digest: ObjectDigest::from_bytes([31; 32]),
                original_reserve_request_id: [32; 16],
                acquisition_deadline: Some(deadline),
            },
        }
    }

    #[cfg(test)]
    fn current_for_issue(&self) -> Result<(), ExecutionOutputLedgerErrorV1> {
        let boot = KernelBootId::current().map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let now =
            boottime_now_nanoseconds().map_err(|_| ExecutionOutputLedgerErrorV1::NotCurrent)?;
        self.require_issue_time_v3(boot.into_bytes(), now)
    }

    fn require_issue_time_v3(&self, boot: [u8; 16], now: u64)
        -> Result<(), ExecutionOutputLedgerErrorV1>
    {
        let issue_deadline = self.source.acquisition_deadline
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?
            .min(self.deadline_boottime_nanoseconds);
        if self.kernel_boot_id != boot || now >= issue_deadline {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureSourceAssociationV2 {
    digest: ObjectDigest,
    original_reserve_request_id: [u8; 16],
    // Present only in AOSCOA03. The primary deadline is then the separately
    // verified ongoing execution bound; this remains the short entry bound.
    acquisition_deadline: Option<u64>,
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
    source: Option<CaptureSourceAssociationV2>,
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
            source: Some(sources.source),
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
        if let Some(source) = self.source {
            digest.update(source.digest.as_bytes());
            digest.update(source.original_reserve_request_id);
            if let Some(acquisition) = source.acquisition_deadline {
                digest.update(acquisition.to_be_bytes());
            }
        }
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
            && self.source == Some(sources.source)
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
            && self.source.is_some_and(|source| source.digest.as_bytes() != &[0; 32]
                && source.original_reserve_request_id != [0; 16]
                && source.acquisition_deadline.is_some_and(|deadline| deadline != 0))
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
    pub(super) effective_deadline_boottime_nanoseconds: u64,
}

/// Holds MAC-verified historical query DATA without native completion authority.
///
/// It cannot issue another attempt, supply pipes or settle a same-F worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedCaptureQueryDataV2 {
    attempt: ProtectedCaptureCreateAttemptReceiptV1,
    complete: Option<aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2>,
}

impl ProtectedCaptureQueryDataV2 {
    /// Prices the actual historical response models and bounded encoding planes.
    ///
    /// Query self-decodes only its locally built canonical response. Its generated
    /// byte fields have the fixed widths below, never an untrusted repeated-field
    /// roster. This supplier adds bytes only; it introduces no namespace or IO.
    pub(crate) fn query_response_receiving_demand_v3()
        -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>
    {
        use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
        use aos_sandbox_protocol::storage_capture_grant::{
            MAXIMUM_RESPONSE_BODY_BYTES, ValidatedStorageCaptureQueryResponseV2,
        };
        use aos_sandbox_protocol::storage_capture_result::{
            CAPTURE_COMPLETE_RECORD_BYTES_V2, CaptureCompleteRecordDataV2,
        };
        use aos_sandbox_api::aos::sandbox::local::v1::StorageExecutionCaptureAttemptV1;

        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        // Four IDs and three digests are the seven generated byte fields.
        // The optional Complete is one additional fixed canonical byte field.
        let generated_fields = 4usize.checked_mul(16)
            .and_then(|ids| ids.checked_add(3usize.checked_mul(32)?))
            .and_then(|fields| fields.checked_add(CAPTURE_COMPLETE_RECORD_BYTES_V2))
            .ok_or_else(overflow)?;
        let typed = [
            std::mem::size_of::<CaptureAttemptRecordV1>(),
            std::mem::size_of::<ProtectedCaptureCreateAttemptReceiptV1>(),
            std::mem::size_of::<Self>(),
            std::mem::size_of::<CaptureCompleteRecordDataV2>(),
            std::mem::size_of::<StorageExecutionCaptureAttemptV1>(),
            std::mem::size_of::<ValidatedStorageCaptureQueryResponseV2>(),
        ].into_iter().try_fold(0usize, |bytes, width|
            bytes.checked_add(width).ok_or_else(overflow))?;
        let buffers = [
            generated_fields,               // locally built generated message
            CAPTURE_COMPLETE_RECORD_BYTES_V2, // Complete encoder's stack array
            MAXIMUM_RESPONSE_BODY_BYTES,    // retained canonical response Vec
            generated_fields,               // generated decoder's owned fields
            MAXIMUM_RESPONSE_BODY_BYTES,    // decoder canonical-reencode comparison
            MAXIMUM_RESPONSE_BODY_BYTES,    // outgoing common-outcome response copy
        ].into_iter().try_fold(0usize, |bytes, width|
            bytes.checked_add(width).ok_or_else(overflow))?;
        let bytes = typed.checked_add(buffers).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(crate) const fn attempt_v2(&self) -> &ProtectedCaptureCreateAttemptReceiptV1 { &self.attempt }

    pub(crate) const fn complete_record_v2(&self)
        -> Option<&aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2>
    { self.complete.as_ref() }
}

impl ExecutionOutputLedgerV1 {
    /// Prices actual retained signed-lifetime/attempt carriers before materialization.
    pub(crate) fn capture_ongoing_attempt_receiving_demand_v3(&self)
        -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1>
    {
        use aos_sandbox_model::{ResourceDimension, ResourceVector};
        let append = self.journal.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape { key_bytes: 17, value_bytes: Some(RECORD_BYTES) },
        ))?;
        let bytes = std::mem::size_of::<crate::authorization::VerifiedCaptureReserveOngoingAdmissionV3>()
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<VerifiedCaptureAttemptSourcesV1>().checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(RECORD_BYTES.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(aos_sandbox_controller_domain::JournalError::JournalTooLarge)?;
        Ok(append.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))?)
    }
    // Existing unit fixtures use the same validator/encoder/commit engine.
    // No production Source-only receipt entry remains after the actual issuer
    // requires the full verified admission and both retained native bookends.
    #[cfg(test)]
    pub(super) fn issue_capture_create_attempt(
        &mut self,
        sources: &VerifiedCaptureAttemptSourcesV1,
        retained: &ProtectedRetainedCaptureV1,
        requirement: &CaptureDatasetRequirementV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
    ) -> Result<ProtectedCaptureCreateAttemptReceiptV1, ExecutionOutputLedgerErrorV1> {
        sources.current_for_issue()?;
        let mut original = issuance::CaptureAttemptCommitOriginalV3::default();
        original.returned = Some(self.commit_capture_attempt_inner_v3(sources, retained,
            requirement, metadata_headroom_bytes, minimum_remaining_bytes, &mut original));
        original.into_result_v3()
    }

    fn commit_capture_attempt_inner_v3(
        &mut self,
        sources: &VerifiedCaptureAttemptSourcesV1,
        retained: &ProtectedRetainedCaptureV1,
        requirement: &CaptureDatasetRequirementV1,
        metadata_headroom_bytes: u64,
        minimum_remaining_bytes: u64,
        original: &mut issuance::CaptureAttemptCommitOriginalV3,
    ) -> Result<ProtectedCaptureCreateAttemptReceiptV1, ExecutionOutputLedgerErrorV1> {
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
        original.canonical_encoded = Some(encode_attempt(&location, &record, &self.key));
        original.encoded = Some(match original.canonical_encoded.as_ref() {
            Some(Ok(bytes)) => bytes.as_slice().try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt),
            _ => return Err(ExecutionOutputLedgerErrorV1::NotCurrent),
        });
        let bytes = original.encoded.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        original.transaction = Some(JournalTransaction::new(
            transaction_id(b"capture-create-attempt", &location, bytes),
            vec![JournalRecord::put(NAMESPACE, location.to_vec(), bytes.to_vec())],
        ).map_err(aos_sandbox_controller_domain::JournalError::from));
        let transaction = original.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        original.commit = Some(self.journal.commit(transaction).map(|_| ()));
        if !matches!(original.commit, Some(Ok(()))) {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        original.readback = Some((|| {
            self.journal.ensure_healthy()?;
            let actual = self.journal.get(NAMESPACE, &location)
                .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
            if actual != bytes || decode_attempt(&location, actual, &self.key)? != record {
                return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
            }
            Ok(())
        })());
        if !matches!(original.readback, Some(Ok(()))) {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        Ok(receipt(&record, bytes))
    }

    /// Cold-queries the complete signed Source944 without lending a worker.
    pub(crate) fn query_capture_ongoing_source_v3(
        &self,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    ) -> Result<Option<ProtectedCaptureCreateAttemptReceiptV1>, ExecutionOutputLedgerErrorV1> {
        let original = source.original_source_v1();
        let location = capture_attempt_key(*original.settlement().execution().as_bytes());
        let Some(bytes) = self.journal.get(NAMESPACE, &location) else { return Ok(None); };
        let record = decode_attempt(&location, bytes, &self.key)?;
        let Some(association) = record.source else { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); };
        let version_matches = association.acquisition_deadline.is_some_and(|deadline|
                deadline <= original.original_deadline_boottime_nanoseconds())
            && association.digest == source.source_digest_v2()
            && record.deadline_boottime_nanoseconds <= source.effective_execution_deadline_v2();
        if !version_matches
            || association.original_reserve_request_id != original.original_reserve_request_id()
            || record.execution != *original.settlement().execution().as_bytes()
            || record.create != *original.settlement().create_operation().as_bytes()
            || record.record_digest != original.output_record_digest()
            || record.host_correlation_digest != original.settlement().host_correlation_digest()
            || record.host_claim_digest != original.output_claim_digest()
            || record.host_request_id != original.original_host_request_id()
            || record.assignment_digest != original.assignment().digest()
            || record.storage_create_operation != *original.storage_create_operation().as_bytes()
            || record.kernel_boot_id != original.host_boot_id()
        { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
        Ok(Some(receipt(&record, bytes)))
    }

    /// Reads the immutable full terminal under the complete signed Source944.
    ///
    /// A fresh signed61/native interval remains independently required. Neither
    /// expired execution DATA nor Complete can renew the original worker grant.
    pub(crate) fn query_capture_terminal_ongoing_data_v3(
        &self,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    ) -> Result<Option<ProtectedCaptureQueryDataV2>, ExecutionOutputLedgerErrorV1> {
        let attempt = self.query_capture_ongoing_source_v3(source)?;
        let complete = self.query_capture_complete_ongoing_data_v3(source)?;
        match (attempt, complete) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(ExecutionOutputLedgerErrorV1::Corrupt),
            (Some(attempt), complete) => Ok(Some(ProtectedCaptureQueryDataV2 { attempt, complete })),
        }
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
    journal: &aos_sandbox_controller_domain::Journal,
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

pub(super) fn verify_capture_observation_anchor(
    journal: &aos_sandbox_controller_domain::Journal,
    execution: [u8; 16],
    create: [u8; 16],
    output_record_digest: ObjectDigest,
    durable_attempt_digest: ObjectDigest,
    controller_grant_digest: ObjectDigest,
    host_receipt_digest: ObjectDigest,
    dataset_policy_digest: ObjectDigest,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<(), ExecutionOutputLedgerErrorV1> {
    let location = capture_attempt_key(execution);
    let bytes = journal
        .get(NAMESPACE, &location)
        .ok_or(ExecutionOutputLedgerErrorV1::Corrupt)?;
    let record = decode_attempt(&location, bytes, key)?;
    if record.create != create
        || record.record_digest != output_record_digest
        || record.controller_grant_digest != controller_grant_digest
        || record.host_receipt_digest != host_receipt_digest
        || record.dataset_policy_digest != dataset_policy_digest
        || ObjectDigest::from_bytes(Sha256::digest(bytes).into()) != durable_attempt_digest
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
        effective_deadline_boottime_nanoseconds: record.deadline_boottime_nanoseconds,
    }
}

fn encode_attempt(
    location: &[u8],
    record: &CaptureAttemptRecordV1,
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<Vec<u8>, ExecutionOutputLedgerErrorV1> {
    if !record.valid() || location != capture_attempt_key(record.execution) {
        return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
    }
    let Some(source) = record.source else { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); };
    let Some(acquisition) = source.acquisition_deadline else {
        return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
    };
    let mut bytes = vec![0; RECORD_BYTES];
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
    bytes[336..368].copy_from_slice(source.digest.as_bytes());
    bytes[368..384].copy_from_slice(&source.original_reserve_request_id);
    bytes[384..392].copy_from_slice(&acquisition.to_be_bytes());
    let mac = key.mac(location, &bytes[..CONTENT_BYTES])?;
    bytes[CONTENT_BYTES..].copy_from_slice(&mac);
    Ok(bytes)
}

fn decode_attempt(
    location: &[u8],
    bytes: &[u8],
    key: &ExecutionOutputLedgerKeyV1,
) -> Result<CaptureAttemptRecordV1, ExecutionOutputLedgerErrorV1> {
    if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    if location.len() != 17
        || location[0] != b'a'
        || bytes[8..24] != location[1..]
        || !key.verify_mac(location, &bytes[..CONTENT_BYTES], &bytes[CONTENT_BYTES..])?
    {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    decode_attempt_content_v3(location, bytes)
}

fn decode_attempt_content_v3(
    location: &[u8],
    bytes: &[u8],
) -> Result<CaptureAttemptRecordV1, ExecutionOutputLedgerErrorV1> {
    if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice())
        || location.len() != 17 || location[0] != b'a' || bytes[8..24] != location[1..]
    { return Err(ExecutionOutputLedgerErrorV1::Corrupt); }
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
        source: Some(CaptureSourceAssociationV2 {
            digest: digest(336..368)?,
            original_reserve_request_id: field(368..384)?,
            acquisition_deadline: Some(u64::from_be_bytes(bytes[384..392].try_into()
                .map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?)),
        }),
    };
    if !record.valid() || capture_attempt_key(record.execution) != location {
        return Err(ExecutionOutputLedgerErrorV1::Corrupt);
    }
    Ok(record)
}

pub(crate) fn capture_worker_inputs_v3(
    context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
) -> Result<(ProtectedRetainedCaptureV1, [u8; 16], ObjectDigest, ObjectDigest, ObjectDigest, [u8; 16], u64), ExecutionOutputLedgerErrorV1> {
    let source = context.source_v3();
    let original = source.original_source_v1();
    let location = capture_attempt_key(*original.settlement().execution().as_bytes());
    // Signature/HMAC validation belonged to the actual authenticated parent,
    // which retained its genuine Source944/F/Host45 and freshly committed424.
    // This child reuses the SAME canonical record parser, with no key delivery.
    let record = decode_attempt_content_v3(&location, context.attempt_bytes_v3())?;
    let association = record.source.ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
    let (bytes, stdout, stderr) = original.output_limits();
    if association.digest != source.source_digest_v2()
        || association.original_reserve_request_id != original.original_reserve_request_id()
        || association.acquisition_deadline.is_none_or(|deadline|
            deadline > original.original_deadline_boottime_nanoseconds())
        || record.execution != *original.settlement().execution().as_bytes()
        || record.create != *original.settlement().create_operation().as_bytes()
        || record.record_digest != original.output_record_digest()
        || record.host_claim_digest != original.output_claim_digest()
        || record.host_correlation_digest != original.settlement().host_correlation_digest()
        || record.host_request_id != original.original_host_request_id()
        || record.assignment_digest != original.assignment().digest()
        || record.storage_create_operation != *original.storage_create_operation().as_bytes()
        || record.kernel_boot_id != original.host_boot_id()
        || record.deadline_boottime_nanoseconds > source.effective_execution_deadline_v2()
        || record.dataset_policy_digest != context.requirement_v3().attempt_policy_digest(
            context.metadata_headroom_v3(), context.remaining_floor_v3())
    { return Err(ExecutionOutputLedgerErrorV1::NotCurrent); }
    let retained = ProtectedRetainedCaptureV1 {
        execution: record.execution, create: record.create, claim_digest: record.host_claim_digest,
        record_digest: record.record_digest, admitted_bytes: bytes,
        maximum_stdout_bytes: stdout, maximum_stderr_bytes: stderr,
    };
    let receipt = receipt(&record, context.attempt_bytes_v3());
    Ok((retained, receipt.attempt, receipt.controller_grant_digest,
        receipt.host_receipt_digest, receipt.durable_attempt_digest,
        record.kernel_boot_id, record.deadline_boottime_nanoseconds))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aos_sandbox_controller_domain::{Journal, JournalLimits};
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

    #[test]
    fn exact_source_association_is_mac_bound_and_cannot_match_another_reserve() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open(&directory.path().join("output.journal"));
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let mut sources = VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);
        let record = CaptureAttemptRecordV1::from_sources(&sources);
        let location = capture_attempt_key(record.execution);
        let bytes = encode_attempt(&location, &record, &key()).unwrap();

        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(decode_attempt(&location, &bytes, &key()).unwrap(), record);
        sources.source.original_reserve_request_id[0] ^= 1;
        assert!(!record.matches_sources(&sources));
        let mut tampered = bytes;
        tampered[336] ^= 1;
        assert!(matches!(decode_attempt(&location, &tampered, &key()),
            Err(ExecutionOutputLedgerErrorV1::Corrupt)));
    }

    #[test]
    fn obsolete_attempt_versions_refuse_even_with_an_authentic_journal_mac() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open(&directory.path().join("output.journal"));
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let sources = VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);
        let record = CaptureAttemptRecordV1::from_sources(&sources);
        let location = capture_attempt_key(record.execution);
        let canonical = encode_attempt(&location, &record, &key()).unwrap();

        for (magic, width, source_bound) in [
            (b"AOSCOA01", 368usize, false), (b"AOSCOA02", 416usize, true),
        ] {
            let mut old = record;
            if source_bound { old.source.as_mut().unwrap().acquisition_deadline = None; }
            else { old.source = None; }
            old.attempt = old.expected_attempt();
            let mut obsolete = canonical[..width].to_vec();
            obsolete[..8].copy_from_slice(magic);
            obsolete[296..312].copy_from_slice(&old.attempt);
            let content = width - 32;
            let mac = key().mac(&location, &obsolete[..content]).unwrap();
            obsolete[content..].copy_from_slice(&mac);

            assert!(key().verify_mac(&location, &obsolete[..content], &obsolete[content..]).unwrap());
            assert!(matches!(decode_attempt(&location, &obsolete, &key()),
                Err(ExecutionOutputLedgerErrorV1::Corrupt)));
            assert!(encode_attempt(&location, &old, &key()).is_err());
        }
        assert_eq!(decode_attempt(&location, &canonical, &key()).unwrap(), record);
    }

    #[test]
    fn ongoing_attempt_keeps_distinct_short_and_execution_horizons() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open(&directory.path().join("output.journal"));
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let mut sources = VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);
        sources.source.acquisition_deadline = Some(3);
        sources.deadline_boottime_nanoseconds = 30;
        let record = CaptureAttemptRecordV1::from_sources(&sources);
        let location = capture_attempt_key(record.execution);

        let bytes = encode_attempt(&location, &record, &key()).unwrap();
        let recovered = decode_attempt(&location, &bytes, &key()).unwrap();

        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes.len(), RECORD_BYTES);
        assert_eq!(recovered.deadline_boottime_nanoseconds, 30);
        assert_eq!(recovered.source.unwrap().acquisition_deadline, Some(3));
        let mut changed = record;
        changed.source.as_mut().unwrap().acquisition_deadline = Some(4);
        assert_ne!(record.expected_attempt(), changed.expected_attempt());
        assert!(!changed.valid());
    }

    #[test]
    fn ongoing_attempt_rejects_zero_acquisition_and_authenticated_field_substitution() {
        let directory = TempDir::new().unwrap();
        let mut ledger = open(&directory.path().join("output.journal"));
        let retained = reserve(&mut ledger);
        let (requirement, _) = fixture();
        let mut sources = VerifiedCaptureAttemptSourcesV1::for_test(&retained, &requirement, 20, 100);
        sources.source.acquisition_deadline = Some(3);
        let mut record = CaptureAttemptRecordV1::from_sources(&sources);
        let location = capture_attempt_key(record.execution);
        let mut bytes = encode_attempt(&location, &record, &key()).unwrap();
        bytes[384] ^= 1;
        assert!(decode_attempt(&location, &bytes, &key()).is_err());

        record.source.as_mut().unwrap().acquisition_deadline = Some(0);
        record.attempt = record.expected_attempt();
        assert!(encode_attempt(&location, &record, &key()).is_err());
    }

}

impl ProtectedCaptureQueryDataV2 {
    pub(crate) fn canonical_query_response_v3(
        value: Option<&Self>,
        source: &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    ) -> Result<Vec<u8>, aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordErrorV2> {
        use aos_sandbox_api::aos::sandbox::local::v1::{StorageExecutionCaptureAttemptV1,
            StorageExecutionCaptureAttemptStatusV1 as Status};
        use buffa::Message as _;
        let locator = source.locator_v2();
        let mut response = StorageExecutionCaptureAttemptV1 {
            execution_id: locator.execution().as_bytes().to_vec(),
            create_operation_id: locator.create_operation().as_bytes().to_vec(),
            original_reserve_request_id: locator.original_reserve_request_id().to_vec(),
            grant_source_digest: locator.source_digest().as_bytes().to_vec(),
            output_record_digest: locator.output_record_digest().as_bytes().to_vec(),
            status: Status::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_ABSENT.into(),
            ..Default::default()
        };
        if let Some(value) = value {
            let attempt = value.attempt_v2();
            response.status = Status::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE.into();
            response.attempt_id = attempt.attempt.to_vec();
            response.durable_attempt_digest = attempt.durable_attempt_digest.as_bytes().to_vec();
            response.effective_deadline_boottime_nanoseconds = attempt.effective_deadline_boottime_nanoseconds;
            if let Some(complete) = value.complete_record_v2() {
                response.status = Status::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_COMPLETE.into();
                response.canonical_complete_result = complete.encode()?.to_vec();
            }
        }
        Ok(response.encode_to_vec())
    }
}
