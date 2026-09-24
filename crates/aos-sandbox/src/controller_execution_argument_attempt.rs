//! One-shot Controller custody for a cross-process Host argument observation.
//!
//! AOSCIA02 binds the actual authenticated-session request ID to the accepted
//! Create preissue and authenticated Host output settlement. Its checksum is
//! structural integrity, not a signature or permission to contact a Guest.
//! A future method-37 broker grant must sign these exact bytes, and Host must
//! independently verify its current assignment, output claim, runtime, and
//! retained Guest session before returning a signed observation. No public
//! Create or Host execution authority follows from this record.
//!
//! ```text
//! AOSCIA02 || execution:16 || Create-operation:16 || request-id:16
//!          || AOSCIP01-digest:32 || AOSCIS01-digest:32
//!          || AOSEOR02-claim-digest:32 || AOSHOP01-correlation-digest:32
//!          || assignment-digest:32 || AOSCIR01-carrier-digest:32
//!          || Host-boot-id:16 || issuer-nonce:32 || deadline-boottime:u64be
//!          || SHA256("aos.sandbox.controller-argument-attempt.v1\0" || preceding):32
//! ```

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

use crate::controller_execution_output_settlement::{
    ControllerExecutionOutputSettlementErrorV1, read_current_controller_output_settlement_v1,
};
use crate::controller_execution_preissue::{
    ControllerExecutionOutputAttemptErrorV1, ControllerExecutionPreissueErrorV1,
    load_controller_execution_output_attempt_v1, revalidate_accepted_execution_preissue_v1,
};
use crate::environment::EnvironmentProtectedJournalOwnerV1;
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentAssignmentTarget, CurrentRuntimeScopeError};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSCIA02";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-argument-attempt.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-argument-attempt-tx.v1\0";
/// Exact length of the canonical, nonauthorizing attempt record.
pub const CONTROLLER_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1: usize = 336;
const CONTENT_BYTES: usize = CONTROLLER_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1 - 32;

/// Reports absent, stale, or ambiguous Controller argument-attempt custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerExecutionArgumentAttemptErrorV1 {
    /// The original accepted Create or current independent owner differs.
    #[error("Controller argument source is not current")]
    NotCurrent,
    /// Another request ID or source already owns this execution.
    #[error("execution already has a different argument observation attempt")]
    Conflict,
    /// The original nonrenewable Host-boot deadline has passed.
    #[error("Controller argument attempt expired")]
    Expired,
    /// The append may have committed; cold readback is required.
    #[error("Controller argument attempt append is ambiguous; reopen the journal")]
    OutcomeUnknown,
    /// The protected Controller journal is unavailable.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The accepted Create preissue is absent or stale.
    #[error(transparent)]
    Preissue(#[from] ControllerExecutionPreissueErrorV1),
    /// The original Host-output attempt is absent or stale.
    #[error(transparent)]
    OutputAttempt(#[from] ControllerExecutionOutputAttemptErrorV1),
    /// The authenticated Host output settlement is absent or stale.
    #[error(transparent)]
    OutputSettlement(#[from] ControllerExecutionOutputSettlementErrorV1),
    /// The signed assignment or lease changed.
    #[error(transparent)]
    Assignment(#[from] CurrentRuntimeScopeError),
    /// The protected clock failed.
    #[error(transparent)]
    Clock(#[from] ProtectedOwnershipClockError),
}

/// Retains the sole original, nonauthorizing method-37 request source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerExecutionArgumentAttemptV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    request_id: [u8; 16],
    preissue_digest: ObjectDigest,
    output_settlement_digest: ObjectDigest,
    output_claim_digest: ObjectDigest,
    host_correlation_digest: ObjectDigest,
    assignment_digest: ObjectDigest,
    reserve_source_digest: ObjectDigest,
    host_boot_id: [u8; 16],
    issuer_nonce: [u8; 32],
    deadline_boottime_nanoseconds: u64,
    record_digest: ObjectDigest,
}

impl ControllerExecutionArgumentAttemptV1 {
    /// Returns the execution selected by accepted Create.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the accepted Create operation.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the actual original signed-session request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the protected accepted-Create preissue digest.
    #[must_use]
    pub const fn preissue_digest(&self) -> ObjectDigest {
        self.preissue_digest
    }

    /// Returns the authenticated Controller Host-output settlement digest.
    #[must_use]
    pub const fn output_settlement_digest(&self) -> ObjectDigest {
        self.output_settlement_digest
    }

    /// Returns the exact authenticated Host-output claim digest.
    #[must_use]
    pub const fn output_claim_digest(&self) -> ObjectDigest {
        self.output_claim_digest
    }

    /// Returns the exact protected Host output correlation digest.
    #[must_use]
    pub const fn host_correlation_digest(&self) -> ObjectDigest {
        self.host_correlation_digest
    }

    /// Returns the current assignment-manifest digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the original signed Host-output reserve carrier commitment.
    #[must_use]
    pub const fn reserve_source_digest(&self) -> ObjectDigest {
        self.reserve_source_digest
    }

    /// Returns the original Host kernel boot ID.
    #[must_use]
    pub const fn host_boot_id(&self) -> [u8; 16] {
        self.host_boot_id
    }

    /// Returns the preissue's nonrenewable nonce.
    #[must_use]
    pub const fn issuer_nonce(&self) -> [u8; 32] {
        self.issuer_nonce
    }

    /// Returns the immutable method-37 deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the commitment to this exact Controller journal record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    /// Encodes the canonical source a future signed broker plan must bind.
    ///
    /// These bytes alone carry no Controller signature or Host authority.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; CONTROLLER_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        let mut bytes = [0; CONTROLLER_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(self.execution.as_bytes());
        bytes[24..40].copy_from_slice(self.create_operation.as_bytes());
        bytes[40..56].copy_from_slice(&self.request_id);
        bytes[56..88].copy_from_slice(self.preissue_digest.as_bytes());
        bytes[88..120].copy_from_slice(self.output_settlement_digest.as_bytes());
        bytes[120..152].copy_from_slice(self.output_claim_digest.as_bytes());
        bytes[152..184].copy_from_slice(self.host_correlation_digest.as_bytes());
        bytes[184..216].copy_from_slice(self.assignment_digest.as_bytes());
        bytes[216..248].copy_from_slice(self.reserve_source_digest.as_bytes());
        bytes[248..264].copy_from_slice(&self.host_boot_id);
        bytes[264..296].copy_from_slice(&self.issuer_nonce);
        bytes[296..304].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[304..].copy_from_slice(self.record_digest.as_bytes());
        bytes
    }

    /// Decodes structurally canonical, but not authenticated, source bytes.
    ///
    /// # Errors
    ///
    /// Rejects an unknown version, wrong length, zero identity, or altered
    /// checksum. A caller must still verify a signed broker plan and current
    /// Host owners before using the result.
    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, ControllerExecutionArgumentAttemptErrorV1> {
        if bytes.len() != CONTROLLER_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
        }
        let read_16 = |start| -> Result<[u8; 16], ControllerExecutionArgumentAttemptErrorV1> {
            bytes[start..start + 16]
                .try_into()
                .map_err(|_| ControllerExecutionArgumentAttemptErrorV1::NotCurrent)
        };
        let read_32 = |start| -> Result<ObjectDigest, ControllerExecutionArgumentAttemptErrorV1> {
            Ok(ObjectDigest::from_bytes(
                bytes[start..start + 32]
                    .try_into()
                    .map_err(|_| ControllerExecutionArgumentAttemptErrorV1::NotCurrent)?,
            ))
        };
        let record = Self {
            execution: ExecutionId::from_bytes(read_16(8)?),
            create_operation: OperationId::from_bytes(read_16(24)?),
            request_id: read_16(40)?,
            preissue_digest: read_32(56)?,
            output_settlement_digest: read_32(88)?,
            output_claim_digest: read_32(120)?,
            host_correlation_digest: read_32(152)?,
            assignment_digest: read_32(184)?,
            reserve_source_digest: read_32(216)?,
            host_boot_id: read_16(248)?,
            issuer_nonce: bytes[264..296]
                .try_into()
                .map_err(|_| ControllerExecutionArgumentAttemptErrorV1::NotCurrent)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(
                bytes[296..304]
                    .try_into()
                    .map_err(|_| ControllerExecutionArgumentAttemptErrorV1::NotCurrent)?,
            ),
            record_digest: read_32(304)?,
        };
        if !record.is_valid() || record.record_digest != digest_record(&bytes[..CONTENT_BYTES]) {
            return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
        }
        Ok(record)
    }

    fn is_valid(&self) -> bool {
        self.execution.as_bytes() != &[0; 16]
            && self.create_operation.as_bytes() != &[0; 16]
            && self.request_id != [0; 16]
            && self.preissue_digest.as_bytes() != &[0; 32]
            && self.output_settlement_digest.as_bytes() != &[0; 32]
            && self.output_claim_digest.as_bytes() != &[0; 32]
            && self.host_correlation_digest.as_bytes() != &[0; 32]
            && self.assignment_digest.as_bytes() != &[0; 32]
            && self.reserve_source_digest.as_bytes() != &[0; 32]
            && self.host_boot_id != [0; 16]
            && self.issuer_nonce != [0; 32]
            && self.deadline_boottime_nanoseconds != 0
    }
}

/// Retains the sole original method-37 attempt under current Controller owners.
///
/// The caller must use the actual request ID selected by the authenticated
/// broker session. Replays with another ID or deadline are conflicts, including
/// after an ambiguous send. The returned source still needs a signed broker
/// plan and an independently authenticated Host response.
///
/// # Errors
///
/// Rejects missing accepted Create, currentness, preissue, output settlement,
/// expired deadline, a foreign prior attempt, or ambiguous protected commit.
#[allow(clippy::too_many_arguments)]
pub fn retain_controller_execution_argument_attempt_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    request_id: [u8; 16],
    request_deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<ControllerExecutionArgumentAttemptV1, ControllerExecutionArgumentAttemptErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let source = current_source(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        clock,
    )?;
    let sample = clock()?;
    if request_id == [0; 16]
        || sample.host_boot_id() != source.preissue.host_boot_id()
        || request_deadline_boottime_nanoseconds <= sample.boottime_nanoseconds()
        || request_deadline_boottime_nanoseconds > source.preissue.deadline_boottime_nanoseconds()
    {
        return Err(ControllerExecutionArgumentAttemptErrorV1::Expired);
    }
    let mut record = ControllerExecutionArgumentAttemptV1 {
        execution,
        create_operation,
        request_id,
        preissue_digest: source.preissue.record_digest(),
        output_settlement_digest: source.settlement.record_digest(),
        output_claim_digest: source.settlement.claim_digest(),
        host_correlation_digest: source.settlement.correlation_digest(),
        assignment_digest: assignment.binding().assignment_digest(),
        reserve_source_digest: source.reserve_source_digest,
        host_boot_id: source.preissue.host_boot_id(),
        issuer_nonce: source.preissue.issuer_nonce(),
        deadline_boottime_nanoseconds: request_deadline_boottime_nanoseconds,
        record_digest: ObjectDigest::from_bytes([0; 32]),
    };
    record.record_digest = digest_record(&record.canonical_bytes()[..CONTENT_BYTES]);
    if !record.is_valid() {
        return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
    }

    // Both independent sources remain current at the final protected append.
    let confirmed = current_source(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        clock,
    )?;
    if confirmed != source {
        return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
    }
    let final_sample = clock()?;
    if final_sample.host_boot_id() != record.host_boot_id
        || final_sample.boottime_nanoseconds() >= record.deadline_boottime_nanoseconds
    {
        return Err(ControllerExecutionArgumentAttemptErrorV1::Expired);
    }
    persist_attempt(controller, &record)?;
    read_current_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ControllerExecutionArgumentAttemptErrorV1::OutcomeUnknown)
}

/// Cold-replays the original attempt while rechecking all Controller owners.
///
/// A missing record is absence, never permission to regenerate after a known
/// ambiguous send. Its request ID and deadline are immutable across restart.
///
/// # Errors
///
/// Rejects stale source, assignment, Host boot, deadline, or corrupt custody.
#[allow(clippy::too_many_arguments)]
pub fn read_current_controller_execution_argument_attempt_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<Option<ControllerExecutionArgumentAttemptV1>, ControllerExecutionArgumentAttemptErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let source = current_source(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        clock,
    )?;
    let Some(bytes) = controller.get(
        RecordNamespace::ControllerExecutionArgumentAttempt,
        execution.as_bytes(),
    ) else {
        return Ok(None);
    };
    let record = ControllerExecutionArgumentAttemptV1::decode_canonical(bytes)?;
    let sample = clock()?;
    if record.execution != execution
        || record.create_operation != create_operation
        || record.preissue_digest != source.preissue.record_digest()
        || record.output_settlement_digest != source.settlement.record_digest()
        || record.output_claim_digest != source.settlement.claim_digest()
        || record.host_correlation_digest != source.settlement.correlation_digest()
        || record.assignment_digest != assignment.binding().assignment_digest()
        || record.reserve_source_digest != source.reserve_source_digest
        || record.host_boot_id != sample.host_boot_id()
        || record.host_boot_id != source.preissue.host_boot_id()
        || record.issuer_nonce != source.preissue.issuer_nonce()
        || record.deadline_boottime_nanoseconds > source.preissue.deadline_boottime_nanoseconds()
        || record.deadline_boottime_nanoseconds <= sample.boottime_nanoseconds()
    {
        return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
    }
    assignment.recheck(controller, clock)?;
    Ok(Some(record))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CurrentSourceV1 {
    preissue: crate::controller_execution_preissue::ControllerExecutionPreissueV1,
    settlement:
        crate::controller_execution_output_settlement::ProtectedControllerOutputSettlementV1,
    reserve_source_digest: ObjectDigest,
}

fn current_source<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    clock: &mut T,
) -> Result<CurrentSourceV1, ControllerExecutionArgumentAttemptErrorV1>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    controller.ensure_protected_authority()?;
    let output_attempt = load_controller_execution_output_attempt_v1(controller, execution)?
        .ok_or(ControllerExecutionArgumentAttemptErrorV1::NotCurrent)?;
    if output_attempt.create_operation() != create_operation {
        return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
    }
    let preissue = output_attempt.source().preissue().clone();
    revalidate_accepted_execution_preissue_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        &preissue,
        clock,
    )?;
    let settlement = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )?
    .ok_or(ControllerExecutionArgumentAttemptErrorV1::NotCurrent)?;
    if settlement.claim_digest() != output_attempt.source().output_claim_digest() {
        return Err(ControllerExecutionArgumentAttemptErrorV1::NotCurrent);
    }
    Ok(CurrentSourceV1 {
        preissue,
        settlement,
        reserve_source_digest: output_attempt.source().carrier_digest(),
    })
}

fn persist_attempt(
    controller: &mut Journal,
    record: &ControllerExecutionArgumentAttemptV1,
) -> Result<(), ControllerExecutionArgumentAttemptErrorV1> {
    controller.ensure_protected_authority()?;
    let bytes = record.canonical_bytes();
    ControllerExecutionArgumentAttemptV1::decode_canonical(&bytes)?;
    if let Some(existing) = controller.get(
        RecordNamespace::ControllerExecutionArgumentAttempt,
        record.execution.as_bytes(),
    ) {
        return if existing == bytes {
            Ok(())
        } else {
            Err(ControllerExecutionArgumentAttemptErrorV1::Conflict)
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
        .map_err(|_| ControllerExecutionArgumentAttemptErrorV1::NotCurrent)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionArgumentAttempt,
            record.execution.as_bytes().to_vec(),
            bytes.to_vec(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerExecutionArgumentAttemptErrorV1::OutcomeUnknown)?;
    Ok(())
}

fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DIGEST_DOMAIN)
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

    fn fixture() -> ControllerExecutionArgumentAttemptV1 {
        let mut record = ControllerExecutionArgumentAttemptV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([2; 16]),
            request_id: [3; 16],
            preissue_digest: ObjectDigest::from_bytes([4; 32]),
            output_settlement_digest: ObjectDigest::from_bytes([5; 32]),
            output_claim_digest: ObjectDigest::from_bytes([6; 32]),
            host_correlation_digest: ObjectDigest::from_bytes([7; 32]),
            assignment_digest: ObjectDigest::from_bytes([8; 32]),
            reserve_source_digest: ObjectDigest::from_bytes([9; 32]),
            host_boot_id: [10; 16],
            issuer_nonce: [11; 32],
            deadline_boottime_nanoseconds: 42,
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        record.record_digest = digest_record(&record.canonical_bytes()[..CONTENT_BYTES]);
        record
    }

    #[test]
    fn record_rejects_every_field_substitution_and_truncation() {
        let record = fixture();
        let original = record.canonical_bytes();
        assert_eq!(
            ControllerExecutionArgumentAttemptV1::decode_canonical(&original).unwrap(),
            record
        );
        for offset in [0, 8, 24, 40, 56, 88, 120, 152, 184, 216, 248, 264, 296, 304] {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(ControllerExecutionArgumentAttemptV1::decode_canonical(&changed).is_err());
        }
        assert!(ControllerExecutionArgumentAttemptV1::decode_canonical(&original[..335]).is_err());
    }

    #[test]
    fn protected_attempt_cold_replay_refuses_new_request_id() {
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

        persist_attempt(&mut controller, &record).unwrap();
        persist_attempt(&mut controller, &record).unwrap();
        let mut foreign = record.clone();
        foreign.request_id = [12; 16];
        foreign.record_digest = digest_record(&foreign.canonical_bytes()[..CONTENT_BYTES]);
        assert!(matches!(
            persist_attempt(&mut controller, &foreign),
            Err(ControllerExecutionArgumentAttemptErrorV1::Conflict)
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
                RecordNamespace::ControllerExecutionArgumentAttempt,
                record.execution.as_bytes(),
            )
            .unwrap();
        assert_eq!(
            ControllerExecutionArgumentAttemptV1::decode_canonical(bytes).unwrap(),
            record
        );
    }
}
