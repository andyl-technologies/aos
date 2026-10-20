//! Shares metadata-only public Recover admission and its joint terminal recipe.
//!
//! Admission atomically records four rows: the original authenticated observation,
//! a distinct Accepted public Operation, its authorization and its Idempotency
//! decision. Completion preserves the exact three historical Create terminal rows
//! and appends only that new Recover's Succeeded row. These are pure DATA recipes;
//! genuine Recover/Root originals retain authorization, currentness, paid native
//! crossings and the exact Root acknowledgement before using either transaction.

use aos_sandbox_core::{
    OperationId, ProjectId, RawPairedClockSample, RecordNamespace, ResourceId,
    ResourceKind, SandboxId, Selector,
};
use sha2::{Digest as _, Sha256};

use super::{CreateFinalityObservationAdmissionDataV1 as Data, FinalityRecoverDataErrorV1};
use crate::domain_ledger::{
    JournalTransactionDataError,
    operation::{OperationRecord, decode_operation, encode_operation_record},
    public_operation::{
        DurablePublicOperationV1, OperationState, PublicOperationAuthorizationV1,
        PublicOperationDataError,
    },
    transaction::{IdempotencyKey, JournalRecord, JournalTransaction},
};
#[cfg(target_os = "linux")]
use crate::domain_ledger::effect_history::{CreateStoppedTerminalDataErrorV1,
    CreateStoppedTerminalTransactionDataV1};

/// Retains canonical codec causes from the metadata-only transaction recipe.
#[derive(Debug, thiserror::Error)]
pub enum MetadataCompleteDataErrorV1 {
    /// Original observation framing or key association differs.
    #[error(transparent)]
    Observation(#[from] FinalityRecoverDataErrorV1),
    /// Public operation or authorization metadata is malformed.
    #[error(transparent)]
    Operation(#[from] PublicOperationDataError),
    /// Canonical native transaction DATA is invalid.
    #[error(transparent)]
    Transaction(#[from] JournalTransactionDataError),
    /// The historical Create terminal recipe refused.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Terminal(#[from] CreateStoppedTerminalDataErrorV1),
    /// The exact operation, immutable admission or ordered transaction differs.
    #[error("metadata-completion operation or transaction differs")]
    Mismatch,
}

#[derive(Clone, Copy)]
enum RecoveryAdmissionPurposeV2 { MetadataComplete, StopCleanup, ExecutionNoApply }

mod cleanup_completion;
pub use cleanup_completion::{
    closed_cleanup_terminal_transaction_data_v2,
    require_closed_cleanup_completed_operation_data_v2,
    require_stop_cleanup_superseded_operation_data_v1,
    stop_cleanup_superseded_operation_data_v1,
};

/// Hashes the established Controller public request inputs without authority.
///
/// The ordinary Controller and independent Root use this same byte recipe.
#[must_use]
pub fn public_controller_request_digest_v1(scope: [u8; 32], principal: [u8; 16],
    project: [u8; 16], canonical_request: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.controller-public-request.v1\0")
        .chain_update(scope).chain_update(principal).chain_update(project)
        .chain_update((canonical_request.len() as u64).to_be_bytes())
        .chain_update(canonical_request).finalize().into()
}

/// Assembles the sole initial metadata-completion Operation as inert DATA.
///
/// # Errors
/// Refuses malformed original admission fields or public authorization metadata.
pub fn metadata_complete_operation_v1(data: Data<'_>)
    -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    recovery_operation_engine_v2(data, RecoveryAdmissionPurposeV2::MetadataComplete)
}

/// Constructs only the separately admitted Stop-cleanup Recover metadata.
///
/// The concrete owner independently proves the exact protected old Stop,
/// current authorization and Source parent. This operation has no ordinary
/// executable Effect and cannot authorize cleanup from its stored row.
///
/// # Errors
/// Refuses malformed original admission fields or public metadata.
pub fn stop_cleanup_operation_v1(data: Data<'_>)
    -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    recovery_operation_engine_v2(data, RecoveryAdmissionPurposeV2::StopCleanup)
}

/// Constructs zero-effect metadata for the finite Execution NoApply Recover.
///
/// # Errors
/// Refuses malformed admission fields or public-operation metadata.
pub fn execution_no_apply_operation_v1(data: Data<'_>)
    -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    recovery_operation_engine_v2(data, RecoveryAdmissionPurposeV2::ExecutionNoApply)
}

fn recovery_operation_engine_v2(data: Data<'_>, purpose: RecoveryAdmissionPurposeV2)
    -> Result<OperationRecord, MetadataCompleteDataErrorV1> {
    data.encoded_bytes_v1()?;

    let metadata = match purpose {
        RecoveryAdmissionPurposeV2::ExecutionNoApply => DurablePublicOperationV1::execution_no_apply_initial_v1(
            data.operation, data.original.wall_seconds())?,
        RecoveryAdmissionPurposeV2::StopCleanup => DurablePublicOperationV1::stop_cleanup_initial_v1(
            data.operation, data.original.wall_seconds())?,
        RecoveryAdmissionPurposeV2::MetadataComplete => DurablePublicOperationV1::metadata_complete_initial_v1(
            data.operation, data.original.wall_seconds())?,
    };
    Ok(OperationRecord::new(OperationState::Accepted, 0, false, None, Some(metadata)))
}

/// Measures the same pure admission candidate before either caller builds it.
///
/// This includes concrete encoded members, their retained/incoming candidate
/// planes and real transaction/record carriers. A physical append owner must
/// separately join its actual native forecast and append-loan carrier.
#[must_use]
pub fn metadata_complete_admission_receiving_bytes_v1(width: usize, idempotency: usize)
    -> Option<usize> {
    width.checked_add(super::OBSERVATION_ADMISSION_KEY_BYTES_V1)
        .and_then(|bytes| bytes.checked_add(crate::domain_ledger::operation::OPERATION_RECORD_V2_BYTES))
        .and_then(|bytes| bytes.checked_add(PublicOperationAuthorizationV1::maximum_receiving_bytes_v1()))
        .and_then(|bytes| bytes.checked_add(2 * 16))
        .and_then(|bytes| bytes.checked_add(idempotency))
        .and_then(|bytes| bytes.checked_add(crate::domain_ledger::transaction::idempotency_value_encoded_bytes_v1()))
        .and_then(|bytes| bytes.checked_mul(8))
        .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<JournalTransaction>()))
        .and_then(|bytes| bytes.checked_add(12 * std::mem::size_of::<JournalRecord>()))
}

/// Compares current admission rows to the same retained canonical candidate.
///
/// The caller retains the candidate from the sole paid recipe. This borrowed
/// comparison allocates nothing and cannot establish native authority.
///
/// # Errors
/// Refuses any changed, missing or deleted member of the original admission.
pub fn require_metadata_complete_admission_rows_v1(candidate: &JournalTransaction,
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), MetadataCompleteDataErrorV1> {
    if candidate.records().len() != 4 { return Err(MetadataCompleteDataErrorV1::Mismatch); }
    for record in candidate.records() {
        let actual = state.iter().find_map(|((namespace, key), value)|
            (*namespace == record.namespace() && key.as_slice() == record.key())
                .then_some(value.as_slice()));
        if actual != record.value() { return Err(MetadataCompleteDataErrorV1::Mismatch); }
    }
    Ok(())
}

/// Constructs the exact four-row admission after the genuine owner pays its geometry.
///
/// # Errors
/// Refuses a substituted original idempotency key, malformed observation or codec error.
pub fn metadata_complete_admission_transaction_v1(data: Data<'_>, idempotency: &[u8])
    -> Result<JournalTransaction, MetadataCompleteDataErrorV1> {
    recovery_admission_transaction_engine_v2(data, idempotency, RecoveryAdmissionPurposeV2::MetadataComplete)
}

/// Uses the same four-row admission recipe for a distinct Stop-cleanup Recover.
///
/// Its original request, clock, holder, target and idempotency bytes retain the
/// existing observation grammar. Only the public operation kind distinguishes
/// this effectful cleanup programme from Create metadata completion.
///
/// # Errors
/// Refuses malformed admission fields, idempotency or canonical row encoding.
pub fn stop_cleanup_admission_transaction_v1(data: Data<'_>, idempotency: &[u8])
    -> Result<JournalTransaction, MetadataCompleteDataErrorV1> {
    recovery_admission_transaction_engine_v2(data, idempotency, RecoveryAdmissionPurposeV2::StopCleanup)
}

/// Shares the canonical four-row engine for a distinct NoApply Recover.
///
/// The actual owner independently validates its protected Execution target and
/// current capability. These zero-effect rows grant neither Apply nor cleanup.
///
/// # Errors
/// Refuses malformed admission, idempotency or canonical row encoding.
pub fn execution_no_apply_admission_transaction_v1(data: Data<'_>, idempotency: &[u8])
    -> Result<JournalTransaction, MetadataCompleteDataErrorV1> {
    recovery_admission_transaction_engine_v2(data, idempotency, RecoveryAdmissionPurposeV2::ExecutionNoApply)
}

fn recovery_admission_transaction_engine_v2(data: Data<'_>, idempotency: &[u8], purpose: RecoveryAdmissionPurposeV2)
    -> Result<JournalTransaction, MetadataCompleteDataErrorV1> {
    if Data::idempotency_digest_v1(data.holder, idempotency) != data.idempotency_digest {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    let operation = recovery_operation_engine_v2(data, purpose)?;
    let authorization = PublicOperationAuthorizationV1::new(
        ProjectId::from_bytes(data.project), ResourceKind::Operation,
        Selector::Resource { resource: ResourceId::from_bytes(data.target) })?;

    let mut encoded = vec![0; data.encoded_bytes_v1()?];
    data.encode_into_v1(&mut encoded)?;
    let key = data.key_v1();
    let idempotency = IdempotencyKey::new(idempotency.to_vec())?;
    let original_id = Data::transaction_id_v1(&key, &encoded);
    let transaction_id = match purpose {
        RecoveryAdmissionPurposeV2::MetadataComplete => original_id,
        RecoveryAdmissionPurposeV2::StopCleanup | RecoveryAdmissionPurposeV2::ExecutionNoApply => {
            let domain: &[u8] = match purpose {
                RecoveryAdmissionPurposeV2::StopCleanup => b"aos.sandbox.stop-cleanup-recover.admission.v1\0",
                RecoveryAdmissionPurposeV2::ExecutionNoApply => b"aos.sandbox.execution-no-apply-recover.admission.v1\0",
                RecoveryAdmissionPurposeV2::MetadataComplete => return Err(MetadataCompleteDataErrorV1::Mismatch),
            };
            let digest = Sha256::new()
                .chain_update(domain)
                .chain_update(original_id).finalize();
            let mut id = [0; 16];
            id.copy_from_slice(&digest[..16]);
            id[0] |= 0x80;
            id
        }
    };

    Ok(JournalTransaction::new(transaction_id, vec![
        JournalRecord::put(RecordNamespace::OperatorRecovery, key.to_vec(), encoded),
        JournalRecord::put(RecordNamespace::Operation, data.operation.to_vec(), encode_operation_record(operation)),
        JournalRecord::put(RecordNamespace::PublicOperationAuthorization, data.operation.to_vec(), authorization.encode()?),
        JournalRecord::idempotency(&idempotency, data.request_digest_v1(), OperationId::from_bytes(data.operation)),
    ])?)
}

/// Compares every ordered admission member using the sole canonical recipe.
///
/// This pure comparison runs only after the original owner paid the candidate and
/// comparator models. It does not accept a row as current native authority.
///
/// # Errors
/// Refuses any extra, reordered, changed or deleted admission member.
pub fn require_metadata_complete_admission_transaction_v1(data: Data<'_>,
    idempotency: &[u8], transaction: &JournalTransaction,
) -> Result<(), MetadataCompleteDataErrorV1> {
    if transaction != &metadata_complete_admission_transaction_v1(data, idempotency)? {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    Ok(())
}

/// Compares every ordered member of the exact Stop-cleanup admission recipe.
///
/// # Errors
/// Refuses another operation kind or any changed, reordered or extra row.
pub fn require_stop_cleanup_admission_transaction_v1(data: Data<'_>,
    idempotency: &[u8], transaction: &JournalTransaction,
) -> Result<(), MetadataCompleteDataErrorV1> {
    if transaction != &stop_cleanup_admission_transaction_v1(data, idempotency)? {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    Ok(())
}

/// Compares every ordered member of the exact NoApply admission recipe.
///
/// # Errors
/// Refuses another purpose or any changed, reordered or extra row.
pub fn require_execution_no_apply_admission_transaction_v1(data: Data<'_>,
    idempotency: &[u8], transaction: &JournalTransaction,
) -> Result<(), MetadataCompleteDataErrorV1> {
    if transaction != &execution_no_apply_admission_transaction_v1(data, idempotency)? {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    Ok(())
}

/// Builds joint4 from the unchanged canonical old Create three-row terminal recipe.
///
/// The supplied new Operation must be exactly this observation's Accepted metadata
/// operation. The real Root final sample is DATA here; the opaque lender separately
/// owns its native origin and currentness. No effect is sent or replayed.
///
/// # Errors
/// Refuses another Create transaction, new admission, pending operation or backward clock.
#[cfg(target_os = "linux")]
pub fn metadata_complete_terminal_transaction_v1(old_create: &JournalTransaction,
    observation: Data<'_>, sandbox: SandboxId, admitted: OperationRecord,
    actual_final_clock: RawPairedClockSample,
) -> Result<JournalTransaction, MetadataCompleteDataErrorV1> {
    let [effect, operation, _] = old_create.records() else {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    };
    let terminal = CreateStoppedTerminalTransactionDataV1::from_data_v1(
        OperationId::from_bytes(observation.target), ProjectId::from_bytes(observation.project), sandbox,
        operation.value().ok_or(MetadataCompleteDataErrorV1::Mismatch)?,
        effect.value().ok_or(MetadataCompleteDataErrorV1::Mismatch)?)?;
    terminal.require_transaction_v1(old_create)?;

    if admitted != metadata_complete_operation_v1(observation)? {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    let public = admitted.public_operation().ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    let completed = admitted.with_state_and_public_operation(OperationState::Succeeded,
        Some(public.advance(OperationState::Succeeded, actual_final_clock.wall_seconds())?));
    let encoded = encode_operation_record(completed);
    require_metadata_complete_completed_operation_v1(observation, &encoded)?;

    let mut records = Vec::with_capacity(4);
    records.extend_from_slice(old_create.records());
    records.push(JournalRecord::put(RecordNamespace::Operation, observation.operation.to_vec(), encoded));
    let id = metadata_complete_joint_transaction_id_v1(old_create.id(), &observation.key_v1(),
        records[3].value().ok_or(MetadataCompleteDataErrorV1::Mismatch)?);
    Ok(JournalTransaction::new(id, records)?)
}

/// Checks completed fixed-width Recover DATA without allocating a virtual transaction.
///
/// The normal native observer separately checks its actual joint COMMIT and
/// original observation. Matching bytes grant no Root acknowledgement or custody.
///
/// # Errors
/// Refuses another operation kind, immutable admission or completion sequence.
pub fn require_metadata_complete_completed_operation_v1(observation: Data<'_>, encoded: &[u8])
    -> Result<(), MetadataCompleteDataErrorV1> {
    let actual = decode_operation(encoded)?;
    let admitted = metadata_complete_operation_v1(observation)?;
    let public = actual.public_operation().ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    let wall = public.completed_wall_seconds_v1().ok_or(MetadataCompleteDataErrorV1::Mismatch)?;
    let expected = admitted.with_state_and_public_operation(OperationState::Succeeded,
        Some(admitted.public_operation().ok_or(MetadataCompleteDataErrorV1::Mismatch)?
            .advance(OperationState::Succeeded, wall)?));
    if actual != expected {
        return Err(MetadataCompleteDataErrorV1::Mismatch);
    }
    Ok(())
}

/// Derives the historical joint identity from immutable rows as passive DATA.
///
/// The observer separately validates all four members, including the historical
/// projection. That projection may later change after an admitted Start, so this
/// selector uses the unchanged old terminal ID and exact completed new Operation.
/// The Root acknowledgement independently commits the entire transaction.
/// Fixed u64 lengths keep this recipe independent of pointer width.
#[must_use]
pub fn metadata_complete_joint_transaction_id_v1(old_create: &[u8; 16],
    observation_key: &[u8], completed_operation: &[u8],
) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.create-finality-recover.joint-terminal.v1\0")
        .chain_update(old_create)
        .chain_update((observation_key.len() as u64).to_be_bytes())
        .chain_update(observation_key)
        .chain_update((completed_operation.len() as u64).to_be_bytes())
        .chain_update(completed_operation).finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id[0] |= 0x80;
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};

    fn observation(request: &[u8]) -> Data<'_> {
        let holder = [3; 16];
        let idempotency_digest = Data::idempotency_digest_v1(holder, b"metadata-recovery");
        let key = Data::key_from_original_v1(holder, idempotency_digest);
        Data {
            operation: Data::operation_id_v1(&key), request_scope: [10; 32],
            target: [1; 16], node: [2; 16], holder, project: [4; 16], capability: [5; 16],
            channel: [6; 32], authorization_revision: [7; 32], idempotency_digest,
            original: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
                [9; 16], 100, 10_000_000_000).unwrap(),
            cutoff: 40_000_000_000, wall_expiry: 140, canonical_request: request,
        }
    }

    fn request() -> Vec<u8> {
        let mut request = b"AOSPMR01".to_vec();
        request.extend_from_slice(&26_u16.to_be_bytes());
        request.extend_from_slice(&2_u32.to_be_bytes());
        request.extend_from_slice(&[8, 1]);
        request
    }

    #[test]
    fn execution_cleanup_terminal_cannot_complete_other_purposes_or_repeat_success() {
        let request = request();
        let data = observation(&request);
        let final_clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [9; 16], 110, 20_000_000_000).unwrap();
        let admitted = execution_no_apply_operation_v1(data).unwrap();
        let purpose = crate::domain_ledger::public_operation::PublicRecoveryKindV1::ExecutionNoApply;
        let transaction = closed_cleanup_terminal_transaction_data_v2(purpose, data, admitted, final_clock).unwrap();
        assert_eq!(transaction.records().len(), 1);
        let row = &transaction.records()[0];
        assert_eq!(row.namespace(), RecordNamespace::Operation);
        assert_eq!(row.key(), data.operation);
        require_closed_cleanup_completed_operation_data_v2(purpose, data, row.value().unwrap()).unwrap();

        for wrong in [metadata_complete_operation_v1(data).unwrap(), stop_cleanup_operation_v1(data).unwrap(),
            decode_operation(row.value().unwrap()).unwrap()] {
            assert!(closed_cleanup_terminal_transaction_data_v2(purpose, data, wrong, final_clock).is_err());
        }
        let expired = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [9; 16], 140, 40_000_000_000).unwrap();
        assert!(closed_cleanup_terminal_transaction_data_v2(purpose, data, admitted, expired).is_err());
    }

    #[test]
    fn stop_terminal_metadata_is_finite_and_does_not_change_other_admission_rows() {
        use crate::domain_ledger::public_operation::PublicRecoveryKindV1 as Purpose;
        let request = request();
        let data = observation(&request);
        let initial = stop_cleanup_admission_transaction_v1(data, b"metadata-recovery").unwrap();
        let admitted = stop_cleanup_operation_v1(data).unwrap();
        let clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [9; 16], 110, 20_000_000_000).unwrap();

        let terminal = closed_cleanup_terminal_transaction_data_v2(
            Purpose::StopCleanup, data, admitted, clock).unwrap();
        assert_eq!(terminal.records().len(), 1);
        let row = &terminal.records()[0];
        assert_eq!(row.namespace(), RecordNamespace::Operation);
        assert_eq!(row.key(), data.operation);
        require_closed_cleanup_completed_operation_data_v2(
            Purpose::StopCleanup, data, row.value().unwrap()).unwrap();
        for immutable in initial.records().iter().filter(|row| row.namespace() != RecordNamespace::Operation) {
            assert!(!terminal.records().iter().any(|row|
                row.namespace() == immutable.namespace() && row.key() == immutable.key()));
        }

        for wrong in [Purpose::Ordinary, Purpose::MetadataComplete, Purpose::ExecutionNoApply] {
            assert!(closed_cleanup_terminal_transaction_data_v2(wrong, data, admitted, clock).is_err());
            assert!(require_closed_cleanup_completed_operation_data_v2(wrong, data, row.value().unwrap()).is_err());
        }
        assert!(closed_cleanup_terminal_transaction_data_v2(Purpose::StopCleanup, data,
            decode_operation(row.value().unwrap()).unwrap(), clock).is_err());

        // BOOTTIME remains inside the original interval; neither a wall step
        // across the cap nor a foreign boot can complete the public metadata.
        for stale in [
            RawPairedClockSample::new_untrusted(clock.provenance(), [9; 16], 140, 20_000_000_000).unwrap(),
            RawPairedClockSample::new_untrusted(clock.provenance(), [8; 16], 110, 20_000_000_000).unwrap(),
        ] {
            assert!(closed_cleanup_terminal_transaction_data_v2(Purpose::StopCleanup, data, admitted, stale).is_err());
        }
    }

    #[test]
    fn superseded_stop_recover_is_terminal_without_claiming_old_success_or_expiry() {
        let request = request();
        let data = observation(&request);
        let admitted = stop_cleanup_operation_v1(data).unwrap();
        // Another current interval may settle this historical admission after
        // its old boot and authority have expired; none of them is revived.
        let now = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [44; 16], 150, 90_000_000_000,
        ).unwrap();
        let terminal = stop_cleanup_superseded_operation_data_v1(data, admitted, now).unwrap();
        let encoded = encode_operation_record(terminal);
        let decoded = decode_operation(&encoded).unwrap();
        assert_eq!(decoded.state(), OperationState::PermanentlyBlocked);
        assert!(decoded.state().is_terminal());
        assert_eq!(decoded.effect_count(), 0);
        require_stop_cleanup_superseded_operation_data_v1(data, &encoded).unwrap();
        let projected = decoded.public_operation().unwrap().project(
            OperationId::from_bytes(data.operation), decoded.state(), 0, 0,
            false, false, &encoded, &[],
        );
        assert_eq!(projected.progress.as_option().unwrap().milestone, "superseded-by-stop-completion");
        assert_eq!(projected.retry_class.as_known(), Some(aos_proto::aos::sandbox::v1::RetryClass::RETRY_CLASS_NEVER));
        let checked = crate::public_api::CheckedOperationResourceV1::try_from(projected.clone()).unwrap();
        assert_eq!(checked.milestone(), crate::public_api::PublicMilestoneV1::SupersededByStopCompletion);
        assert_eq!(crate::public_api::resource::operation_progress_stage(checked.phase(), checked.milestone()), 5);
        assert!(crate::public_api::operation_phase_can_follow(
            crate::public_api::CheckedOperationPhaseV1::Accepted, checked.phase()));
        for change in 0..6 {
            let mut invalid = projected.clone();
            match change {
                0 => invalid.method = crate::public_api::PublicOperationMethodV1::StopSandbox.as_str().to_owned(),
                1 => invalid.phase = aos_proto::aos::sandbox::v1::OperationPhase::OPERATION_PHASE_SUCCEEDED.into(),
                2 => invalid.progress.get_or_insert_default().total_units = 1,
                3 => invalid.retry_class = aos_proto::aos::sandbox::v1::RetryClass::RETRY_CLASS_SAME_REQUEST.into(),
                4 => invalid.cancelable = true,
                _ => invalid.completed_at = Default::default(),
            }
            assert!(crate::public_api::CheckedOperationResourceV1::try_from(invalid).is_err());
        }
        assert_eq!(decoded.public_operation().unwrap().accepted_wall_seconds_v1(), 100);
        assert_eq!(decoded.public_operation().unwrap().completed_wall_seconds_v1(), Some(150));
        assert!(stop_cleanup_superseded_operation_data_v1(data, terminal, now).is_err());

        for other in [metadata_complete_operation_v1(data).unwrap(), execution_no_apply_operation_v1(data).unwrap()] {
            let invalid = other.with_state_and_public_operation(OperationState::PermanentlyBlocked,
                Some(other.public_operation().unwrap().advance(OperationState::PermanentlyBlocked, 150).unwrap()));
            assert!(decode_operation(&encode_operation_record(invalid)).is_err());
            assert!(stop_cleanup_superseded_operation_data_v1(data, other, now).is_err());
        }
        let changed = Data { original: RawPairedClockSample::new_untrusted(
            data.original.provenance(), [9; 16], 101, 10_000_000_000).unwrap(), ..data };
        assert!(require_stop_cleanup_superseded_operation_data_v1(changed, &encoded).is_err());
        let rollback = RawPairedClockSample::new_untrusted(now.provenance(), [44; 16], 99, 91_000_000_000).unwrap();
        assert!(stop_cleanup_superseded_operation_data_v1(data, admitted, rollback).is_err());
        let repeated = terminal.with_state_and_public_operation(OperationState::PermanentlyBlocked,
            Some(terminal.public_operation().unwrap().advance(OperationState::PermanentlyBlocked, 151).unwrap()));
        assert!(decode_operation(&encode_operation_record(repeated)).is_err());
    }

    #[test]
    fn stop_cleanup_preserves_shared_admission_identity_but_cannot_impersonate_metadata_completion() {
        let request = request();
        let data = observation(&request);
        let metadata = metadata_complete_admission_transaction_v1(data, b"metadata-recovery").unwrap();
        let cleanup = stop_cleanup_admission_transaction_v1(data, b"metadata-recovery").unwrap();
        assert_eq!(metadata.records().len(), 4);
        assert_eq!(cleanup.records().len(), 4);
        assert_ne!(metadata.id(), cleanup.id());
        for index in [0, 2, 3] {
            assert_eq!(metadata.records()[index], cleanup.records()[index]);
        }
        assert_ne!(metadata.records()[1], cleanup.records()[1]);
        require_stop_cleanup_admission_transaction_v1(data, b"metadata-recovery", &cleanup).unwrap();
        assert!(require_metadata_complete_admission_transaction_v1(data, b"metadata-recovery", &cleanup).is_err());
        assert!(require_stop_cleanup_admission_transaction_v1(data, b"metadata-recovery", &metadata).is_err());
    }

    #[test]
    fn admission_atomically_binds_new_pending_operation_authorization_and_idempotency() {
        let request = request();
        let data = observation(&request);
        let transaction = metadata_complete_admission_transaction_v1(data, b"metadata-recovery").unwrap();
        require_metadata_complete_admission_transaction_v1(data, b"metadata-recovery", &transaction).unwrap();
        let [observation, operation, authorization, idempotency] = transaction.records() else { panic!() };
        assert_eq!(Data::decode_v1(observation.value().unwrap()).unwrap().operation, data.operation);
        assert_eq!(operation.key(), data.operation);
        let pending = decode_operation(operation.value().unwrap()).unwrap();
        assert_eq!(pending.state(), OperationState::Accepted);
        assert_eq!(pending.effect_count(), 0);
        assert_eq!(PublicOperationAuthorizationV1::decode(authorization.value().unwrap()).unwrap().project(),
            ProjectId::from_bytes(data.project));
        assert_eq!(idempotency.value().unwrap(),
            [data.request_digest_v1().as_slice(), data.operation.as_slice()].concat());
        assert!(metadata_complete_admission_transaction_v1(data, b"changed-key").is_err());

        let mut changed = transaction.records().to_vec();
        changed.swap(1, 2);
        let changed = JournalTransaction::new(*transaction.id(), changed).unwrap();
        assert!(require_metadata_complete_admission_transaction_v1(data, b"metadata-recovery", &changed).is_err());
        assert!(require_metadata_complete_admission_transaction_v1(
            Data { request_scope: [11; 32], ..data }, b"metadata-recovery", &transaction).is_err());
        let mut old = observation.value().unwrap().to_vec();
        old[..8].copy_from_slice(b"AOSFAD01");
        assert!(Data::decode_v1(&old).is_err());
    }

    #[test]
    fn completed_operation_preserves_original_admission_and_only_one_terminal_transition() {
        let request = request();
        let data = observation(&request);
        let pending = metadata_complete_operation_v1(data).unwrap();
        let complete = pending.with_state_and_public_operation(OperationState::Succeeded,
            Some(pending.public_operation().unwrap().advance(OperationState::Succeeded, 101).unwrap()));
        let encoded = encode_operation_record(complete);
        require_metadata_complete_completed_operation_v1(data, &encoded).unwrap();
        assert!(require_metadata_complete_completed_operation_v1(data, &encode_operation_record(pending)).is_err());
        let mut changed = encoded.clone();
        changed[40 + 24] ^= 1;
        assert!(require_metadata_complete_completed_operation_v1(data, &changed).is_err());
        let advanced = complete.with_state_and_public_operation(OperationState::Succeeded,
            Some(complete.public_operation().unwrap().advance(OperationState::Succeeded, 102).unwrap()));
        assert!(require_metadata_complete_completed_operation_v1(data, &encode_operation_record(advanced)).is_err());
        let identity = metadata_complete_joint_transaction_id_v1(&[12; 16], &data.key_v1(), &encoded);
        assert_ne!(identity, metadata_complete_joint_transaction_id_v1(&[13; 16], &data.key_v1(), &encoded));
        assert_ne!(identity, metadata_complete_joint_transaction_id_v1(&[12; 16], &data.key_v1(), &changed));
    }
}
