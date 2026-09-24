//! Controller custody of one authenticated Host output-reserve settlement.
//!
//! AOSCIS01 records a COMMITTED method-35/36 signed Host outcome after the
//! protected AOSCIA01 original attempt, complete locator, original signed
//! plan/semantic digests, and current assignment/Host boot are compared. It
//! proves provisional AOSEOR02/AOSHOP01 custody, not physical Storage backing,
//! fresh ARG_MAX acquisition, an ExecutionSpec handoff, or public Create.
//!
//! ```text
//! AOSCIS01 || execution[16] || Create-operation[16] || AOSCIA01-digest[32]
//!          || AOSHOP01-digest[32] || original-Host-sequence:u64be
//!          || signed-request-packet-SHA256[32]
//!          || signed-outcome-packet-SHA256[32]
//!          || SHA256("aos.sandbox.controller-output-settlement.v1\0" || preceding)[32]
//! ```

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, QueryHostExecutionOutputRequestV1, ReserveHostExecutionOutputRequestV1,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::host_output::{
    HostOutputReservationStatusV1, decode_host_output_reservation_response_v1,
    host_output_locator_from_source_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_preissue::{
    ControllerExecutionOutputAttemptErrorV1, ControllerExecutionOutputAttemptV1,
    load_controller_execution_output_attempt_v1,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentAssignmentTarget, CurrentRuntimeScopeError};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSCIS01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-output-settlement.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-output-settlement-tx.v1\0";
const RECORD_BYTES: usize = 8 + 16 + 16 + 32 + 32 + 8 + 32 + 32 + 32;
const CONTENT_BYTES: usize = RECORD_BYTES - 32;

/// Reports invalid or unresolved authenticated Host output custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionOutputSettlementErrorV1 {
    /// The protected original attempt or accepted Host outcome is absent.
    #[error("authenticated Host output settlement is absent")]
    Absent,
    /// The signed request, Host receipt, or current assignment differs.
    #[error("Host output settlement differs from original accepted Create")]
    Mismatch,
    /// A different settlement already owns this execution.
    #[error("execution already has a different Host output settlement")]
    Conflict,
    /// A protected append may have committed; cold readback is required.
    #[error("Host output settlement append is ambiguous; reopen the Controller journal")]
    OutcomeUnknown,
    /// The protected Controller journal is unavailable or poisoned.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The protected original attempt is unavailable or malformed.
    #[error(transparent)]
    Attempt(#[from] ControllerExecutionOutputAttemptErrorV1),
    /// The signed current assignment or lease changed.
    #[error(transparent)]
    Assignment(#[from] CurrentRuntimeScopeError),
    /// The protected clock could not be sampled.
    #[error(transparent)]
    Clock(#[from] ProtectedOwnershipClockError),
}

/// Holds one exact, current Controller-authenticated Host output settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedControllerOutputSettlementV1 {
    attempt: ControllerExecutionOutputAttemptV1,
    correlation_digest: ObjectDigest,
    original_host_journal_sequence: u64,
    request_packet_digest: ObjectDigest,
    outcome_packet_digest: ObjectDigest,
    record_digest: ObjectDigest,
}

impl ProtectedControllerOutputSettlementV1 {
    /// Returns the execution bound to the original accepted Create.
    #[must_use]
    pub fn execution(&self) -> ExecutionId {
        self.attempt.execution()
    }

    /// Returns the exact accepted Create operation.
    #[must_use]
    pub fn create_operation(&self) -> OperationId {
        self.attempt.create_operation()
    }

    /// Returns raw SHA-256 of the settled AOSEOR02 claim bytes.
    #[must_use]
    pub fn claim_digest(&self) -> ObjectDigest {
        self.attempt.source().output_claim_digest()
    }

    /// Returns the protected AOSHOP01 correlation digest on Host.
    #[must_use]
    pub const fn correlation_digest(&self) -> ObjectDigest {
        self.correlation_digest
    }

    /// Returns the original atomic Host append sequence.
    #[must_use]
    pub const fn original_host_journal_sequence(&self) -> u64 {
        self.original_host_journal_sequence
    }

    /// Returns the digest of the immutable AOSCIS01 Controller record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SettlementRecordV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    attempt_digest: ObjectDigest,
    correlation_digest: ObjectDigest,
    original_host_journal_sequence: u64,
    request_packet_digest: ObjectDigest,
    outcome_packet_digest: ObjectDigest,
    record_digest: ObjectDigest,
}

impl SettlementRecordV1 {
    fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(self.execution.as_bytes());
        bytes[24..40].copy_from_slice(self.create_operation.as_bytes());
        bytes[40..72].copy_from_slice(self.attempt_digest.as_bytes());
        bytes[72..104].copy_from_slice(self.correlation_digest.as_bytes());
        bytes[104..112].copy_from_slice(&self.original_host_journal_sequence.to_be_bytes());
        bytes[112..144].copy_from_slice(self.request_packet_digest.as_bytes());
        bytes[144..176].copy_from_slice(self.outcome_packet_digest.as_bytes());
        bytes[CONTENT_BYTES..].copy_from_slice(self.record_digest.as_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerExecutionOutputSettlementErrorV1> {
        if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
        }
        let read_16 =
            |start: usize| -> Result<[u8; 16], ControllerExecutionOutputSettlementErrorV1> {
                bytes[start..start + 16]
                    .try_into()
                    .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)
            };
        let read_32 =
            |start: usize| -> Result<ObjectDigest, ControllerExecutionOutputSettlementErrorV1> {
                Ok(ObjectDigest::from_bytes(
                    bytes[start..start + 32]
                        .try_into()
                        .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?,
                ))
            };
        let record = Self {
            execution: ExecutionId::from_bytes(read_16(8)?),
            create_operation: OperationId::from_bytes(read_16(24)?),
            attempt_digest: read_32(40)?,
            correlation_digest: read_32(72)?,
            original_host_journal_sequence: u64::from_be_bytes(
                bytes[104..112]
                    .try_into()
                    .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?,
            ),
            request_packet_digest: read_32(112)?,
            outcome_packet_digest: read_32(144)?,
            record_digest: read_32(CONTENT_BYTES)?,
        };
        if !record.is_valid() || record.record_digest != digest_record(&bytes[..CONTENT_BYTES]) {
            return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
        }
        Ok(record)
    }

    fn is_valid(&self) -> bool {
        self.execution.as_bytes() != &[0; 16]
            && self.create_operation.as_bytes() != &[0; 16]
            && self.attempt_digest.as_bytes() != &[0; 32]
            && self.correlation_digest.as_bytes() != &[0; 32]
            && self.original_host_journal_sequence != 0
            && self.request_packet_digest.as_bytes() != &[0; 32]
            && self.outcome_packet_digest.as_bytes() != &[0; 32]
    }
}

/// Commits one signed-session Host COMMITTED receipt under Controller custody.
///
/// The outcome must be from the Controller's authenticated client receive
/// path. A matching historical record replays exactly; a different receipt
/// cannot replace it. This is still not physical Storage or Host exec authority.
///
/// # Errors
///
/// Rejects stale assignment/boot, missing AOSCIA01, malformed or foreign
/// signed request/response, an existing different settlement, or an ambiguous
/// protected append.
pub fn settle_authenticated_host_output_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    execution: ExecutionId,
    create_operation: OperationId,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    clock: &mut T,
) -> Result<ProtectedControllerOutputSettlementV1, ControllerExecutionOutputSettlementErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let attempt = current_attempt(controller, assignment, execution, create_operation, clock)?;
    let receipt = authenticated_committed_receipt(&attempt, outcome)?;
    let mut record = SettlementRecordV1 {
        execution,
        create_operation,
        attempt_digest: attempt.record_digest(),
        correlation_digest: receipt.0,
        original_host_journal_sequence: receipt.1,
        request_packet_digest: ObjectDigest::from_bytes(
            Sha256::digest(outcome.request().canonical_packet()).into(),
        ),
        outcome_packet_digest: ObjectDigest::from_bytes(
            Sha256::digest(outcome.canonical_packet()).into(),
        ),
        record_digest: ObjectDigest::from_bytes([0; 32]),
    };
    if !record.is_valid() {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    record.record_digest = digest_record(&record.encode()[..CONTENT_BYTES]);

    // The Controller journal is held exclusively throughout both currentness
    // checks and the one-shot append. No Host journal is opened here.
    if current_attempt(controller, assignment, execution, create_operation, clock)? != attempt {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    persist_settlement(controller, &record)?;
    read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ControllerExecutionOutputSettlementErrorV1::OutcomeUnknown)
}

/// Replays one settled original Host claim under current assignment and boot.
///
/// This cannot renew AOSCIA01 or authorize execution. A stale or malformed
/// settlement is rejected even when a record with the execution key exists.
///
/// # Errors
///
/// Rejects unprotected/corrupt custody, a changed original attempt, or stale
/// signed assignment and Host boot.
pub fn read_current_controller_output_settlement_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<Option<ProtectedControllerOutputSettlementV1>, ControllerExecutionOutputSettlementErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let attempt = current_attempt(controller, assignment, execution, create_operation, clock)?;
    let Some(bytes) = controller.get(
        RecordNamespace::ControllerExecutionOutputSettlement,
        execution.as_bytes(),
    ) else {
        return Ok(None);
    };
    let record = SettlementRecordV1::decode(bytes)?;
    if record.execution != execution
        || record.create_operation != create_operation
        || record.attempt_digest != attempt.record_digest()
    {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    assignment.recheck(controller, clock)?;
    Ok(Some(ProtectedControllerOutputSettlementV1 {
        attempt,
        correlation_digest: record.correlation_digest,
        original_host_journal_sequence: record.original_host_journal_sequence,
        request_packet_digest: record.request_packet_digest,
        outcome_packet_digest: record.outcome_packet_digest,
        record_digest: record.record_digest,
    }))
}

fn current_attempt<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<ControllerExecutionOutputAttemptV1, ControllerExecutionOutputSettlementErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    controller.ensure_protected_authority()?;
    assignment.recheck(controller, clock)?;
    let attempt = load_controller_execution_output_attempt_v1(controller, execution)?
        .ok_or(ControllerExecutionOutputSettlementErrorV1::Absent)?;
    let source = attempt.source();
    let manifest = assignment.binding().manifest().manifest();
    let boot = clock()?.host_boot_id();
    if attempt.create_operation() != create_operation
        || source.sandbox() != manifest.sandbox()
        || source.incarnation() != manifest.incarnation()
        || source.node() != manifest.node()
        || source.assignment_epoch() != manifest.epoch().get()
        || source.desired_generation() != manifest.desired_generation().get()
        || source.namespace_generation() != manifest.namespace_generation().get()
        || source.assignment_manifest_digest() != assignment.binding().assignment_digest()
        || source.preissue().host_boot_id() != boot
    {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    assignment.recheck(controller, clock)?;
    Ok(attempt)
}

fn authenticated_committed_receipt(
    attempt: &ControllerExecutionOutputAttemptV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(ObjectDigest, u64), ControllerExecutionOutputSettlementErrorV1> {
    let request = outcome.request();
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        || request.canonical_packet().is_empty()
        || outcome.canonical_packet().is_empty()
        || !request_matches_attempt(attempt, outcome)?
    {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    };
    let locator = host_output_locator_from_source_v1(
        &attempt.source().canonical_bytes(),
        attempt.original_request_id(),
    )
    .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?;
    let response = decode_host_output_reservation_response_v1(exact_body, locator, true)
        .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?;
    if response.status() != HostOutputReservationStatusV1::Committed
        || response.original_plan_digest() != Some(attempt.plan_digest())
        || response.original_semantic_request_digest() != Some(attempt.semantic_request_digest())
    {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    Ok((
        response
            .correlation_digest()
            .ok_or(ControllerExecutionOutputSettlementErrorV1::Mismatch)?,
        response
            .original_host_journal_sequence()
            .ok_or(ControllerExecutionOutputSettlementErrorV1::Mismatch)?,
    ))
}

fn request_matches_attempt(
    attempt: &ControllerExecutionOutputAttemptV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<bool, ControllerExecutionOutputSettlementErrorV1> {
    let request = outcome.request();
    let source = attempt.source();
    let body = request.exact_body();
    match outcome.method() {
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
            let decoded = ReserveHostExecutionOutputRequestV1::decode_from_slice(body)
                .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?;
            Ok(decoded.encode_to_vec() == body
                && decoded.canonical_source == source.canonical_bytes()
                && request.request_id() == attempt.original_request_id()
                && request.deadline_boottime_nanoseconds()
                    == attempt.request_deadline_boottime_nanoseconds())
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => {
            let decoded = QueryHostExecutionOutputRequestV1::decode_from_slice(body)
                .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?;
            Ok(decoded.encode_to_vec() == body
                && decoded.execution_id == attempt.execution().as_bytes()
                && decoded.create_operation_id == attempt.create_operation().as_bytes()
                && decoded.original_reserve_request_id == attempt.original_request_id()
                && decoded.preissue_record_digest == source.preissue().record_digest().as_bytes()
                && decoded.output_claim_digest == source.output_claim_digest().as_bytes()
                && decoded.reserve_source_digest == source.carrier_digest().as_bytes()
                && decoded.assignment_digest == source.assignment_manifest_digest().as_bytes()
                && decoded.host_boot_id == source.preissue().host_boot_id()
                && decoded
                    .header
                    .as_option()
                    .is_some_and(|header| header.request_id == request.request_id()))
        }
        _ => Ok(false),
    }
}

fn persist_settlement(
    controller: &mut Journal,
    record: &SettlementRecordV1,
) -> Result<(), ControllerExecutionOutputSettlementErrorV1> {
    controller.ensure_protected_authority()?;
    if !record.is_valid()
        || record.record_digest != digest_record(&record.encode()[..CONTENT_BYTES])
    {
        return Err(ControllerExecutionOutputSettlementErrorV1::Mismatch);
    }
    if let Some(existing) = controller.get(
        RecordNamespace::ControllerExecutionOutputSettlement,
        record.execution.as_bytes(),
    ) {
        return if existing == record.encode() {
            Ok(())
        } else {
            Err(ControllerExecutionOutputSettlementErrorV1::Conflict)
        };
    }
    let transaction_hash: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(record.execution.as_bytes())
        .chain_update(record.create_operation.as_bytes())
        .finalize()
        .into();
    let transaction_id = transaction_hash[..16]
        .try_into()
        .map_err(|_| ControllerExecutionOutputSettlementErrorV1::Mismatch)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionOutputSettlement,
            record.execution.as_bytes().to_vec(),
            record.encode().to_vec(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerExecutionOutputSettlementErrorV1::OutcomeUnknown)?;
    Ok(())
}

fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use crate::JournalLimits;

    use super::*;

    fn fixture() -> SettlementRecordV1 {
        let mut record = SettlementRecordV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            attempt_digest: ObjectDigest::from_bytes([3; 32]),
            correlation_digest: ObjectDigest::from_bytes([4; 32]),
            original_host_journal_sequence: 5,
            request_packet_digest: ObjectDigest::from_bytes([6; 32]),
            outcome_packet_digest: ObjectDigest::from_bytes([7; 32]),
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        record.record_digest = digest_record(&record.encode()[..CONTENT_BYTES]);
        record
    }

    #[test]
    fn settlement_record_is_versioned_and_rejects_field_substitution() {
        let record = fixture();
        let mut bytes = record.encode();
        assert_eq!(SettlementRecordV1::decode(&bytes).unwrap(), record);

        for offset in [0, 8, 24, 40, 72, 104, 112, 144, 176] {
            bytes[offset] ^= 1;
            assert!(SettlementRecordV1::decode(&bytes).is_err());
            bytes[offset] ^= 1;
        }
    }

    #[test]
    fn protected_settlement_is_one_shot_and_cold_replayable() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut controller, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let record = fixture();

        persist_settlement(&mut controller, &record).unwrap();
        persist_settlement(&mut controller, &record).unwrap();
        let mut foreign = record.clone();
        foreign.correlation_digest = ObjectDigest::from_bytes([8; 32]);
        foreign.record_digest = digest_record(&foreign.encode()[..CONTENT_BYTES]);
        assert!(matches!(
            persist_settlement(&mut controller, &foreign),
            Err(ControllerExecutionOutputSettlementErrorV1::Conflict)
        ));
        drop(controller);

        let (reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let bytes = reopened
            .get(
                RecordNamespace::ControllerExecutionOutputSettlement,
                record.execution.as_bytes(),
            )
            .unwrap();
        assert_eq!(SettlementRecordV1::decode(bytes).unwrap(), record);
    }
}
