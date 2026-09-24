//! Controller custody of one fresh Host-attested Guest argument observation.
//!
//! AOSCAF01 retains the exact AOSHAR01 response and signed broker packet
//! digests after method 37 succeeds for the protected AOSCIA02 attempt. Its
//! cold replay is historical audit only: the fresh typed observation exists
//! only in the same authenticated outcome handoff, with current Controller
//! owners held. The Host, not the Controller, verifies the fixed Guest key.
//! No spec admission, physical output backing, or Host Apply follows here.
//!
//! ```text
//! AOSCAF01 || execution:16 || Create-operation:16 || AOSCIA02-digest:32
//!          || signed-request-SHA256:32 || signed-outcome-SHA256:32
//!          || AOSHAR01-length:u16be || exact-AOSHAR01
//!          || SHA256("aos.sandbox.controller-argument-receipt.v1\0" || preceding):32
//! ```

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, ObserveHostExecutionArgumentRequestV1, ObserveHostExecutionArgumentResponseV1,
};
use aos_sandbox_agent::GuestRuntimeArgumentObserveRequestV1;
use aos_sandbox_core::{
    ExecutionId, ExecutionRuntimeArgumentLimitV1, ExecutionTargetV1, InvalidExecutionSpec,
    ObjectDigest, OperationId, PayloadBootId, RawPairedClockSample,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::host_execution_argument::receipt::{
    HostExecutionArgumentFreshReceiptV1, HostExecutionArgumentReceiptErrorV1,
    MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_argument_attempt::{
    ControllerExecutionArgumentAttemptErrorV1, ControllerExecutionArgumentAttemptV1,
    read_current_controller_execution_argument_attempt_v1,
    read_historical_controller_execution_argument_attempt_v1,
};
use crate::environment::EnvironmentProtectedJournalOwnerV1;
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentAssignmentTarget, CurrentRuntimeScopeError};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSCAF01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-argument-receipt.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-argument-receipt-tx.v1\0";
const FIXED_BYTES: usize = 8 + 16 + 16 + 32 + 32 + 32 + 2 + 32;
const MAXIMUM_RECORD_BYTES: usize = FIXED_BYTES + MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1;

/// Reports invalid fresh Host attestation or ambiguous Controller custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionArgumentReceiptErrorV1 {
    /// The signed request, response, Guest source, or current owner differs.
    #[error("Host argument observation differs from protected Controller source")]
    Mismatch,
    /// A Host observation has already been consumed for this execution.
    #[error("execution already has a Host argument receipt")]
    Conflict,
    /// A protected append may have committed; cold audit cannot restore freshness.
    #[error("Host argument receipt append is ambiguous; reopen for historical audit")]
    OutcomeUnknown,
    /// The protected Controller journal is unavailable.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The original accepted-Create observation attempt is stale.
    #[error(transparent)]
    Attempt(#[from] ControllerExecutionArgumentAttemptErrorV1),
    /// The current signed assignment changed.
    #[error(transparent)]
    Assignment(#[from] CurrentRuntimeScopeError),
    /// The Host receipt format is inconsistent.
    #[error(transparent)]
    HostReceipt(#[from] HostExecutionArgumentReceiptErrorV1),
    /// The Host-attested Guest request is malformed.
    #[error(transparent)]
    GuestRequest(#[from] aos_sandbox_agent::GuestRuntimeArgumentObservationErrorV1),
    /// The Host-attested argument evidence cannot form a canonical target.
    #[error(transparent)]
    Evidence(#[from] InvalidExecutionSpec),
    /// The protected Controller clock failed.
    #[error(transparent)]
    Clock(#[from] ProtectedOwnershipClockError),
}

/// Carries same-handoff Host-attested ARG_MAX evidence without Host effect authority.
///
/// This value cannot be cold-constructed. A producer must still revalidate the
/// protected Controller record and acquire a separate live Host/physical cut
/// before it may admit or hand off a canonical execution specification.
pub struct AuthenticatedControllerHostArgumentObservationV1 {
    attempt: ControllerExecutionArgumentAttemptV1,
    evidence: ExecutionRuntimeArgumentLimitV1,
    record_digest: ObjectDigest,
    host_custody_digest: ObjectDigest,
    host_custody_sequence: u64,
}

impl AuthenticatedControllerHostArgumentObservationV1 {
    /// Borrows the Host-attested, target-bound runtime argument limit.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionRuntimeArgumentLimitV1 {
        &self.evidence
    }

    /// Returns the exact execution named by the original Controller attempt.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.attempt.execution()
    }

    /// Returns the accepted Create operation bound to this observation.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.attempt.create_operation()
    }

    /// Returns the immutable Controller receipt record commitment.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    /// Returns the Host protected observation custody commitment.
    #[must_use]
    pub const fn host_custody_digest(&self) -> ObjectDigest {
        self.host_custody_digest
    }

    /// Returns the Host protected observation custody sequence.
    #[must_use]
    pub const fn host_custody_sequence(&self) -> u64 {
        self.host_custody_sequence
    }
}

/// Reports only historical Controller custody, never fresh ARG_MAX evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalControllerHostArgumentReceiptV1 {
    record_digest: ObjectDigest,
    outcome_packet_digest: ObjectDigest,
    host_custody_digest: ObjectDigest,
    host_custody_sequence: u64,
}

impl HistoricalControllerHostArgumentReceiptV1 {
    /// Returns the Controller record commitment for audit correlation.
    #[must_use]
    pub const fn record_digest(self) -> ObjectDigest {
        self.record_digest
    }

    /// Returns the signed Host outcome packet digest for audit correlation.
    #[must_use]
    pub const fn outcome_packet_digest(self) -> ObjectDigest {
        self.outcome_packet_digest
    }

    /// Returns the Host custody digest for audit correlation.
    #[must_use]
    pub const fn host_custody_digest(self) -> ObjectDigest {
        self.host_custody_digest
    }

    /// Returns the Host custody sequence for audit correlation.
    #[must_use]
    pub const fn host_custody_sequence(self) -> u64 {
        self.host_custody_sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReceiptRecordV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    attempt_digest: ObjectDigest,
    request_packet_digest: ObjectDigest,
    outcome_packet_digest: ObjectDigest,
    exact_host_receipt: Vec<u8>,
    record_digest: ObjectDigest,
}

impl ReceiptRecordV1 {
    fn encode(&self) -> Result<Vec<u8>, ControllerExecutionArgumentReceiptErrorV1> {
        let receipt_length = u16::try_from(self.exact_host_receipt.len())
            .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
        let mut bytes = Vec::with_capacity(FIXED_BYTES + self.exact_host_receipt.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(self.attempt_digest.as_bytes());
        bytes.extend_from_slice(self.request_packet_digest.as_bytes());
        bytes.extend_from_slice(self.outcome_packet_digest.as_bytes());
        bytes.extend_from_slice(&receipt_length.to_be_bytes());
        bytes.extend_from_slice(&self.exact_host_receipt);
        bytes.extend_from_slice(self.record_digest.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ControllerExecutionArgumentReceiptErrorV1> {
        if bytes.len() < FIXED_BYTES
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
        }
        let read_16 =
            |start: usize| -> Result<[u8; 16], ControllerExecutionArgumentReceiptErrorV1> {
                bytes[start..start + 16]
                    .try_into()
                    .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)
            };
        let read_32 =
            |start: usize| -> Result<ObjectDigest, ControllerExecutionArgumentReceiptErrorV1> {
                Ok(ObjectDigest::from_bytes(
                    bytes[start..start + 32]
                        .try_into()
                        .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)?,
                ))
            };
        let receipt_length = usize::from(u16::from_be_bytes(
            bytes[136..138]
                .try_into()
                .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)?,
        ));
        if receipt_length == 0 || bytes.len() != FIXED_BYTES + receipt_length {
            return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
        }
        let checksum_start = bytes.len() - 32;
        let record = Self {
            execution: ExecutionId::from_bytes(read_16(8)?),
            create_operation: OperationId::from_bytes(read_16(24)?),
            attempt_digest: read_32(40)?,
            request_packet_digest: read_32(72)?,
            outcome_packet_digest: read_32(104)?,
            exact_host_receipt: bytes[138..checksum_start].to_vec(),
            record_digest: read_32(checksum_start)?,
        };
        if !record.is_valid()
            || record.record_digest != digest_record(&bytes[..checksum_start])
            || record.encode()? != bytes
        {
            return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
        }
        Ok(record)
    }

    fn is_valid(&self) -> bool {
        self.execution.as_bytes() != &[0; 16]
            && self.create_operation.as_bytes() != &[0; 16]
            && self.attempt_digest.as_bytes() != &[0; 32]
            && self.request_packet_digest.as_bytes() != &[0; 32]
            && self.outcome_packet_digest.as_bytes() != &[0; 32]
            && !self.exact_host_receipt.is_empty()
            && self.exact_host_receipt.len() <= MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1
    }
}

/// Retains one authenticated fresh method-37 Host outcome under Controller custody.
///
/// AOSHQR01 method-38 replies cannot enter this constructor. Ambiguous append
/// recovery is audit-only and cannot mint a fresh observation after restart.
///
/// # Errors
///
/// Rejects a stale accepted Create/assignment/boot, substituted original
/// request or Host receipt, malformed Guest runtime, or ambiguous durability.
#[allow(clippy::too_many_arguments)]
pub fn retain_authenticated_controller_host_argument_receipt_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    clock: &mut T,
) -> Result<
    AuthenticatedControllerHostArgumentObservationV1,
    ControllerExecutionArgumentReceiptErrorV1,
>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let attempt = read_current_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
    let host_receipt = authenticated_fresh_receipt(&attempt, outcome)?;
    let evidence = attested_evidence(assignment, &attempt, &host_receipt)?;
    let mut record = ReceiptRecordV1 {
        execution,
        create_operation,
        attempt_digest: attempt.record_digest(),
        request_packet_digest: raw_digest(outcome.request().canonical_packet()),
        outcome_packet_digest: raw_digest(outcome.canonical_packet()),
        exact_host_receipt: host_receipt.canonical_bytes(),
        record_digest: ObjectDigest::from_bytes([0; 32]),
    };
    if !record.is_valid() {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    let encoded = record.encode()?;
    record.record_digest = digest_record(&encoded[..encoded.len() - 32]);

    // The Controller journal is held across source recheck and immutable append.
    let rechecked = read_current_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        clock,
    )?;
    if rechecked.as_ref() != Some(&attempt) {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    persist_receipt(controller, &record)?;
    let stored = load_receipt(controller, execution)?
        .ok_or(ControllerExecutionArgumentReceiptErrorV1::OutcomeUnknown)?;
    if stored != record {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    let proof = AuthenticatedControllerHostArgumentObservationV1 {
        attempt,
        evidence,
        record_digest: record.record_digest,
        host_custody_digest: host_receipt.custody_digest(),
        host_custody_sequence: host_receipt.custody_sequence(),
    };
    revalidate_current_controller_host_argument_observation_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        &proof,
        clock,
    )?;
    Ok(proof)
}

/// Rechecks Controller custody without upgrading cold replay to a fresh proof.
///
/// # Errors
///
/// Rejects changed assignment/accepted Create, altered AOSCAF01 custody, or
/// expiration of the original fresh observation attempt.
#[allow(clippy::too_many_arguments)]
pub fn revalidate_current_controller_host_argument_observation_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    proof: &AuthenticatedControllerHostArgumentObservationV1,
    clock: &mut T,
) -> Result<(), ControllerExecutionArgumentReceiptErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let attempt = read_current_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        proof.execution(),
        proof.create_operation(),
        clock,
    )?
    .ok_or(ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
    let record = load_receipt(controller, proof.execution())?
        .ok_or(ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
    let host_receipt =
        HostExecutionArgumentFreshReceiptV1::decode_canonical(&record.exact_host_receipt)?;
    let evidence = attested_evidence(assignment, &attempt, &host_receipt)?;
    if attempt != proof.attempt
        || record.create_operation != proof.create_operation()
        || record.attempt_digest != proof.attempt.record_digest()
        || record.record_digest != proof.record_digest
        || host_receipt.custody_digest() != proof.host_custody_digest
        || host_receipt.custody_sequence() != proof.host_custody_sequence
        || evidence != proof.evidence
    {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    assignment.recheck(controller, clock)?;
    Ok(())
}

/// Cold-reads an authenticated record for audit, never spec-admission authority.
///
/// # Errors
///
/// Rejects altered Controller custody, changed current assignment/Host boot,
/// or a substituted historical output settlement.
pub fn read_historical_controller_host_argument_receipt_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<
    Option<HistoricalControllerHostArgumentReceiptV1>,
    ControllerExecutionArgumentReceiptErrorV1,
>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let attempt = read_historical_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?;
    let Some(attempt) = attempt else {
        return Ok(None);
    };
    let Some(record) = load_receipt(controller, execution)? else {
        return Ok(None);
    };
    let receipt =
        HostExecutionArgumentFreshReceiptV1::decode_canonical(&record.exact_host_receipt)?;
    if record.execution != execution
        || record.create_operation != create_operation
        || record.attempt_digest != attempt.record_digest()
        || receipt.source() != &attempt.canonical_bytes()
    {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    assignment.recheck(controller, clock)?;
    Ok(Some(HistoricalControllerHostArgumentReceiptV1 {
        record_digest: record.record_digest,
        outcome_packet_digest: record.outcome_packet_digest,
        host_custody_digest: receipt.custody_digest(),
        host_custody_sequence: receipt.custody_sequence(),
    }))
}

fn authenticated_fresh_receipt(
    attempt: &ControllerExecutionArgumentAttemptV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<HostExecutionArgumentFreshReceiptV1, ControllerExecutionArgumentReceiptErrorV1> {
    let request = outcome.request();
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
        || request.request_id() != attempt.request_id()
        || request.canonical_packet().is_empty()
        || outcome.canonical_packet().is_empty()
    {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    let observed = ObserveHostExecutionArgumentRequestV1::decode_from_slice(request.exact_body())
        .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
    if !observed.__buffa_unknown_fields.is_empty()
        || observed.encode_to_vec() != request.exact_body()
        || observed.canonical_attempt != attempt.canonical_bytes()
        || observed.header.as_option().is_none_or(|header| {
            header.request_id != request.request_id()
                || header.deadline_boottime_nanoseconds != attempt.deadline_boottime_nanoseconds()
        })
    {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    };
    let response = ObserveHostExecutionArgumentResponseV1::decode_from_slice(exact_body)
        .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != *exact_body {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    let receipt =
        HostExecutionArgumentFreshReceiptV1::decode_canonical(&response.canonical_receipt)?;
    if receipt.source() != &attempt.canonical_bytes() {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    Ok(receipt)
}

fn attested_evidence(
    assignment: &CurrentAssignmentTarget,
    attempt: &ControllerExecutionArgumentAttemptV1,
    receipt: &HostExecutionArgumentFreshReceiptV1,
) -> Result<ExecutionRuntimeArgumentLimitV1, ControllerExecutionArgumentReceiptErrorV1> {
    let guest_request = GuestRuntimeArgumentObserveRequestV1::decode(receipt.canonical_request())?;
    let runtime = guest_request.runtime();
    let manifest = assignment.binding().manifest().manifest();
    if receipt.source() != &attempt.canonical_bytes()
        || runtime.sandbox() != manifest.sandbox()
        || runtime.incarnation() != manifest.incarnation()
        || runtime.assignment_epoch() != manifest.epoch()
        || runtime.assignment_digest() != attempt.assignment_digest()
        || runtime.desired_generation() != manifest.desired_generation()
        || runtime.namespace_generation() != manifest.namespace_generation()
        || receipt.session_binding() != guest_request.session().digest()
    {
        return Err(ControllerExecutionArgumentReceiptErrorV1::Mismatch);
    }
    let target = ExecutionTargetV1::new(
        runtime.sandbox(),
        runtime.incarnation(),
        runtime.assignment_epoch(),
        runtime.assignment_digest(),
        runtime.namespace_generation(),
        PayloadBootId::new(*runtime.payload_boot_id())?,
    )?;
    ExecutionRuntimeArgumentLimitV1::new(
        guest_request.profile().clone(),
        guest_request.profile_commitment(),
        target,
        receipt.argument_limit_bytes(),
    )
    .map_err(Into::into)
}

fn load_receipt(
    controller: &mut Journal,
    execution: ExecutionId,
) -> Result<Option<ReceiptRecordV1>, ControllerExecutionArgumentReceiptErrorV1> {
    controller.ensure_protected_authority()?;
    controller
        .get(
            RecordNamespace::ControllerExecutionArgumentReceipt,
            execution.as_bytes(),
        )
        .map(ReceiptRecordV1::decode)
        .transpose()
}

fn persist_receipt(
    controller: &mut Journal,
    record: &ReceiptRecordV1,
) -> Result<(), ControllerExecutionArgumentReceiptErrorV1> {
    controller.ensure_protected_authority()?;
    let bytes = record.encode()?;
    ReceiptRecordV1::decode(&bytes)?;
    if controller
        .get(
            RecordNamespace::ControllerExecutionArgumentReceipt,
            record.execution.as_bytes(),
        )
        .is_some()
    {
        // Even exact replay must not turn a historical Host packet into fresh evidence.
        return Err(ControllerExecutionArgumentReceiptErrorV1::Conflict);
    }
    HostExecutionArgumentFreshReceiptV1::decode_canonical(&record.exact_host_receipt)?;
    let transaction_hash: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(record.execution.as_bytes())
        .chain_update(record.create_operation.as_bytes())
        .finalize()
        .into();
    let transaction_id = transaction_hash[..16]
        .try_into()
        .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::Mismatch)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionArgumentReceipt,
            record.execution.as_bytes().to_vec(),
            bytes,
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerExecutionArgumentReceiptErrorV1::OutcomeUnknown)?;
    Ok(())
}

fn raw_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
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

    fn structural_fixture() -> ReceiptRecordV1 {
        let mut record = ReceiptRecordV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            attempt_digest: ObjectDigest::from_bytes([3; 32]),
            request_packet_digest: ObjectDigest::from_bytes([4; 32]),
            outcome_packet_digest: ObjectDigest::from_bytes([5; 32]),
            exact_host_receipt: vec![6; 64],
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        let encoded = record.encode().unwrap();
        record.record_digest = digest_record(&encoded[..encoded.len() - 32]);
        record
    }

    #[test]
    fn versioned_record_rejects_every_binding_substitution() {
        let record = structural_fixture();
        let encoded = record.encode().unwrap();
        assert_eq!(ReceiptRecordV1::decode(&encoded).unwrap(), record);

        for offset in [0, 8, 24, 40, 72, 104, 136, 138, encoded.len() - 32] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                ReceiptRecordV1::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
        assert!(ReceiptRecordV1::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn structural_record_cannot_be_persisted_as_a_host_receipt() {
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
        let record = structural_fixture();

        assert!(matches!(
            persist_receipt(&mut controller, &record),
            Err(ControllerExecutionArgumentReceiptErrorV1::HostReceipt(_))
        ));
        assert!(
            controller
                .get(
                    RecordNamespace::ControllerExecutionArgumentReceipt,
                    record.execution.as_bytes(),
                )
                .is_none()
        );
    }

    #[test]
    fn even_identical_cold_record_cannot_mint_a_second_fresh_receipt() {
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
        let record = structural_fixture();
        let transaction = JournalTransaction::new(
            [7; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerExecutionArgumentReceipt,
                record.execution.as_bytes().to_vec(),
                record.encode().unwrap(),
            )],
        )
        .unwrap();
        controller.commit(&transaction).unwrap();

        assert!(matches!(
            persist_receipt(&mut controller, &record),
            Err(ControllerExecutionArgumentReceiptErrorV1::Conflict)
        ));
    }
}
