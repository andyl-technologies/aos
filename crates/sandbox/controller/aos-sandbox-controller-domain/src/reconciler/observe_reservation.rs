//! Admission interlock for retained Controller execution Observe identities.
//!
//! The reconciler validates the Controller's complete reservation record
//! before assigning a fresh generic Operation ID. This check does not confer
//! dispatch authority for the reserved Observe operation.

use std::collections::BTreeSet;

use aos_sandbox_model::OperationId;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
use crate::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};

use super::{
    OperationRecord, OperationState, ReconcilerError, decode_operation, effect_key,
    encode_operation_record,
};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectLedgerRecord, EffectPlan, EffectState, decode_effect, encode_effect,
};

const CHILD_IDEMPOTENCY_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-child-key.v1\0";
const CHILD_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-child-request.v1\0";
const CHILD_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller.execution-observe-child-adoption.v1\0";

fn corrupt() -> ReconcilerError {
    ReconcilerError::CorruptLedger("invalid Controller execution Observe child")
}

/// Derives the private idempotency identity of one exact Observe reservation.
///
/// # Errors
///
/// Returns an error if the derived key cannot satisfy journal key bounds.
pub fn observe_child_identity_v1(
    reservation: &ControllerExecutionObserveReservationV1,
) -> Result<(IdempotencyKey, [u8; 32]), ReconcilerError> {
    let key: [u8; 32] = Sha256::new()
        .chain_update(CHILD_IDEMPOTENCY_DOMAIN)
        .chain_update(reservation.observe_operation().as_bytes())
        .finalize()
        .into();
    let request_digest: [u8; 32] = Sha256::new()
        .chain_update(CHILD_REQUEST_DOMAIN)
        .chain_update(reservation.encode())
        .finalize()
        .into();
    Ok((IdempotencyKey::new(key.to_vec())
        .map_err(crate::journal::JournalError::from)?, request_digest))
}

fn validate_child(
    journal: &Journal,
    reservation: &ControllerExecutionObserveReservationV1,
) -> Result<bool, ReconcilerError> {
    validate_child_retaining_completion_v4(journal, reservation).map(|(present, _)| present)
}

type CompletedChildV4 = (EffectLedgerRecord,
    aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1);

fn validate_child_retaining_completion_v4(
    journal: &Journal,
    reservation: &ControllerExecutionObserveReservationV1,
) -> Result<(bool, Option<CompletedChildV4>), ReconcilerError> {
    let operation_id = reservation.observe_operation();
    let (key, request_digest) = observe_child_identity_v1(reservation)?;
    let operation = journal.get(RecordNamespace::Operation, operation_id.as_bytes());
    let effect = journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0));
    let decision = journal.check_idempotency(&key, request_digest);

    if operation.is_none() && effect.is_none() && decision == IdempotencyOutcome::Vacant {
        return Ok((false, None));
    }
    let operation = operation
        .ok_or_else(corrupt)
        .and_then(|bytes| decode_operation(bytes).map_err(ReconcilerError::from))?;
    if decision != IdempotencyOutcome::Replay(operation_id)
        || journal.get(RecordNamespace::PublicOperationAuthorization, operation_id.as_bytes()).is_some()
    { return Err(corrupt()); }
    let effect_bytes = effect.ok_or_else(corrupt)?;
    use aos_sandbox_protocol::domain_ledger::effect_history::observe_completion::{
        COMPLETED_OBSERVE_EFFECT_VERSION, decode_completed_observe_effect_v1};
    let (effect, completion) = if effect_bytes.first() == Some(&COMPLETED_OBSERVE_EFFECT_VERSION) {
        let (effect, completion) = decode_completed_observe_effect_v1(effect_bytes).map_err(ReconcilerError::from)?;
        (effect, Some(completion))
    } else {
        (decode_effect(effect_bytes).map_err(ReconcilerError::from)?, None)
    };
    if effect.plan() != &EffectPlan::reserved_observe(reservation) || effect.dispatch().is_some() {
        return Err(corrupt());
    }
    match (effect_bytes.first().copied(), effect.state()) {
        (Some(aos_sandbox_protocol::domain_ledger::effect_history::RESERVED_OBSERVE_EFFECT_VERSION), EffectState::Planned)
            if operation == OperationRecord::new(OperationState::Accepted, 1, false, None, None) => {}
        (Some(COMPLETED_OBSERVE_EFFECT_VERSION), EffectState::Applied { attempt: 1, .. })
            if operation == OperationRecord::new(OperationState::Succeeded, 1, false, None, None) => {
            let completion = completion.as_ref().ok_or_else(corrupt)?;
            validate_completed_sources(journal, reservation, completion)?;
        }
        _ => return Err(corrupt()),
    }

    Ok((true, completion.map(|completion| (effect, completion))))
}

/// Retains the same complete protected first-Observe validation for a read.
///
/// This historical DATA grants no native interval, Host dispatch or terminal
/// projection. A real caller pays all complete decoder models before entry.
///
/// # Errors
/// Refuses an unhealthy Controller, malformed reservation, noncanonical child,
/// substituted idempotency or changed CSI/CAF/Capture source companions.
#[doc(hidden)]
pub fn completed_execution_observe_from_journal_v4(
    journal: &Journal,
    execution: aos_sandbox_model::ExecutionId,
) -> Result<Option<(ControllerExecutionObserveReservationV1, EffectLedgerRecord,
    aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1)>, ReconcilerError> {
    journal.ensure_healthy()?;
    let Some(bytes) = journal.get(RecordNamespace::ControllerExecutionObserveReservation, execution.as_bytes()) else {
        return Ok(None);
    };
    let reservation = ControllerExecutionObserveReservationV1::decode(execution.as_bytes(), bytes)
        .map_err(|_| corrupt())?;
    let (_, completed) = validate_child_retaining_completion_v4(journal, &reservation)?;
    Ok(completed.map(|(effect, completion)| (reservation, effect, completion)))
}

fn validate_completed_sources(
    journal: &Journal, reservation: &ControllerExecutionObserveReservationV1,
    completion: &aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1,
) -> Result<(), ReconcilerError> {
    let sources = completion.sources().map_err(|_| corrupt())?;
    if journal.get(RecordNamespace::ControllerExecutionSpecAttempt, reservation.execution().as_bytes()) != Some(sources.specification)
        || journal.get(RecordNamespace::ControllerExecutionArgumentReceipt, reservation.execution().as_bytes()) != Some(sources.argument_receipt)
    { return Err(corrupt()); }
    if let Some(anchor) = sources.capture_admission_anchor {
        // The admission snapshot is an immutable C18 row. A replacement live
        // Storage Session or later Query61 must not change its cold source pin.
        if journal.get(RecordNamespace::ControllerStorageCaptureAdmission,
            reservation.execution().as_bytes()) != Some(anchor)
        {
            return Err(corrupt());
        }
    }
    let caf = aos_sandbox_protocol::execution_argument_receipt::ControllerArgumentReceiptDataV1::decode(sources.argument_receipt)
        .map_err(|_| corrupt())?;
    let receipt = aos_sandbox_protocol::host_execution_argument::receipt::HostExecutionArgumentFreshReceiptV1::decode_canonical(&caf.exact_host_receipt)
        .map_err(|_| corrupt())?;
    let source = crate::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1::decode_canonical(receipt.source())
        .map_err(|_| corrupt())?;
    if journal.get(RecordNamespace::ControllerExecutionArgumentAttempt, reservation.execution().as_bytes()) != Some(receipt.source().as_slice())
        || source.record_digest() != caf.attempt_digest || source.host_boot_id() != sources.host_boot
        || sources.cutoff > source.deadline_boottime_nanoseconds()
        || source.execution() != reservation.execution() || source.create_operation() != reservation.create_operation()
    { return Err(corrupt()); }
    Ok(())
}

/// Prepares the exact atomic Effect/Operation completion of one inert child.
///
/// The complete signed history and embedded source rows must match this SAME
/// Controller. The returned records are DATA; the genuine existing writer and
/// receiving scope must independently admit and commit the one transaction.
///
/// # Errors
/// Rejects missing or contradictory reservation/adoption, an incompatible prior
/// terminal, foreign protected source rows, or invalid complete signed evidence.
pub fn prepare_completed_execution_observe_child_v1(
    journal: &Journal, reservation: &ControllerExecutionObserveReservationV1,
    completion: &aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1,
    receipt: aos_sandbox_protocol::domain_ledger::effect_history::EffectReceipt,
    completion_wall_seconds: i64,
) -> Result<Option<[JournalRecord; 2]>, ReconcilerError> {
    journal.ensure_healthy()?;
    if journal.get(RecordNamespace::ControllerExecutionObserveReservation, reservation.execution().as_bytes()) != Some(reservation.encode().as_slice())
        || !validate_child(journal, reservation)? { return Err(corrupt()); }
    validate_completed_sources(journal, reservation, completion)?;
    let operation = journal.get(RecordNamespace::Operation, reservation.observe_operation().as_bytes())
        .ok_or_else(corrupt).and_then(|bytes| decode_operation(bytes).map_err(ReconcilerError::from))?;
    let effect_bytes = journal.get(RecordNamespace::Effect, &effect_key(reservation.observe_operation(), 0)).ok_or_else(corrupt)?;
    let effect = decode_effect(effect_bytes).map_err(ReconcilerError::from)?;
    if let EffectState::Applied { attempt: 1, receipt: existing } = effect.state() {
        let (_, existing_evidence) = aos_sandbox_protocol::domain_ledger::effect_history::observe_completion::decode_completed_observe_effect_v1(effect_bytes)
            .map_err(ReconcilerError::from)?;
        if *existing != receipt || existing_evidence != *completion { return Err(corrupt()); }
        return Ok(None);
    }
    super::completed_effect_operation_records_v1(reservation.observe_operation(), operation, effect.into_parts(),
        receipt, completion_wall_seconds, OperationState::Succeeded, super::CompletionPurposeV1::ReservedObserve(completion))
        .map(Some)
}

pub(super) fn validate_all(journal: &Journal) -> Result<(), ReconcilerError> {
    let mut reserved_operations = BTreeSet::new();
    let mut adopted_operations = BTreeSet::new();
    for (key, value) in journal.records(RecordNamespace::ControllerExecutionObserveReservation) {
        let reservation =
            ControllerExecutionObserveReservationV1::decode(key, value).map_err(|_| corrupt())?;
        if !reserved_operations.insert(reservation.observe_operation()) {
            return Err(corrupt());
        }
        if validate_child(journal, &reservation)? {
            adopted_operations.insert(reservation.observe_operation());
        }
    }
    for (key, value) in journal.records(RecordNamespace::Effect) {
        if key.len() >= 16 {
            let operation_bytes: [u8; 16] = key[..16].try_into().map_err(|_| corrupt())?;
            let operation = OperationId::from_bytes(operation_bytes);
            if adopted_operations.contains(&operation) && key != effect_key(operation, 0) {
                return Err(corrupt());
            }
        }
        let effect = decode_effect(value).map_err(ReconcilerError::from)?;
        if effect.plan().is_reserved_observe() {
            if !matches!(value.first().copied(),
                Some(aos_sandbox_protocol::domain_ledger::effect_history::RESERVED_OBSERVE_EFFECT_VERSION)
                | Some(aos_sandbox_protocol::domain_ledger::effect_history::observe_completion::COMPLETED_OBSERVE_EFFECT_VERSION)) {
                return Err(corrupt());
            }
            let reservation = ControllerExecutionObserveReservationV1::decode(
                effect.plan().request().get(8..24).ok_or_else(corrupt)?,
                effect.plan().request(),
            )
            .map_err(|_| corrupt())?;
            if key != super::effect_key(reservation.observe_operation(), 0)
                || journal.get(
                    RecordNamespace::ControllerExecutionObserveReservation,
                    reservation.execution().as_bytes(),
                ) != Some(reservation.encode().as_slice())
                || !validate_child(journal, &reservation)?
            {
                return Err(corrupt());
            }
        }
    }
    Ok(())
}

pub(super) fn is_adopted_child(
    journal: &Journal,
    operation: OperationId,
) -> Result<bool, ReconcilerError> {
    for (key, value) in journal.records(RecordNamespace::ControllerExecutionObserveReservation) {
        let reservation =
            ControllerExecutionObserveReservationV1::decode(key, value).map_err(|_| corrupt())?;
        if reservation.observe_operation() == operation {
            return validate_child(journal, &reservation);
        }
    }
    Ok(false)
}

pub(super) fn adopted_operations(
    journal: &Journal,
) -> Result<BTreeSet<OperationId>, ReconcilerError> {
    let mut adopted = BTreeSet::new();
    for (key, value) in journal.records(RecordNamespace::ControllerExecutionObserveReservation) {
        let reservation =
            ControllerExecutionObserveReservationV1::decode(key, value).map_err(|_| corrupt())?;
        if validate_child(journal, &reservation)? {
            adopted.insert(reservation.observe_operation());
        }
    }
    Ok(adopted)
}

/// Checks whether one exact retained Observe reservation owns its inert child ledger.
///
/// # Errors
///
/// Rejects absent or contradictory reservation, operation, effect, or
/// idempotency custody.
pub fn observe_child_adoption_state_v1(
    journal: &Journal,
    reservation: &ControllerExecutionObserveReservationV1,
) -> Result<bool, ReconcilerError> {
    journal.ensure_healthy()?;
    validate_all(journal)?;
    if journal.get(
        RecordNamespace::ControllerExecutionObserveReservation,
        reservation.execution().as_bytes(),
    ) != Some(reservation.encode().as_slice())
    {
        return Err(corrupt());
    }
    validate_child(journal, reservation)
}

/// Atomically adopts a retained Observe reservation into an inert child ledger.
///
/// The child has no public operation, broker method, or dispatch authority.
/// A prior signed Host Authorize classification must have retained the exact
/// reservation under this same protected Controller writer.
///
/// # Errors
///
/// Returns an error for absent or conflicting reservation custody, an occupied
/// operation/effect/idempotency identity, or ambiguous journal durability.
pub fn adopt_execution_observe_child_v1(
    journal: &mut Journal,
    reservation: &ControllerExecutionObserveReservationV1,
) -> Result<bool, ReconcilerError> {
    journal.ensure_protected_authority()?;
    if journal.get(
        RecordNamespace::ControllerExecutionObserveReservation,
        reservation.execution().as_bytes(),
    ) != Some(reservation.encode().as_slice())
    {
        return Err(corrupt());
    }
    for (key, value) in journal.records(RecordNamespace::ControllerExecutionObserveReservation) {
        let other =
            ControllerExecutionObserveReservationV1::decode(key, value).map_err(|_| corrupt())?;
        if other.execution() != reservation.execution()
            && other.observe_operation() == reservation.observe_operation()
        {
            return Err(corrupt());
        }
    }
    if validate_child(journal, reservation)? {
        validate_all(journal)?;
        return Ok(false);
    }
    let operation_id = reservation.observe_operation();
    if journal
        .records(RecordNamespace::Effect)
        .any(|(key, _)| key.starts_with(operation_id.as_bytes()))
    {
        return Err(corrupt());
    }

    let (key, request_digest) = observe_child_identity_v1(reservation)?;
    let effect = EffectLedgerRecord::from_parts((
        EffectPlan::reserved_observe(reservation),
        EffectState::Planned,
        None,
        None,
    ));
    let transaction_digest: [u8; 32] = Sha256::new()
        .chain_update(CHILD_TRANSACTION_DOMAIN)
        .chain_update(reservation.encode())
        .finalize()
        .into();
    let transaction_id: [u8; 16] = transaction_digest[..16].try_into().map_err(|_| corrupt())?;
    if transaction_id == [0; 16] {
        return Err(corrupt());
    }
    let records = vec![
        JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.as_bytes().to_vec(),
            encode_operation_record(OperationRecord::new(
                OperationState::Accepted,
                1,
                false,
                None,
                None,
            )),
        ),
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, 0).to_vec(),
            encode_effect(&effect).map_err(ReconcilerError::from)?,
        ),
        JournalRecord::idempotency(&key, request_digest, operation_id),
    ];
    journal.commit(
        &JournalTransaction::new(transaction_id, records)
            .map_err(crate::journal::JournalError::from)?,
    )?;
    Ok(true)
}

pub(super) fn claims_operation(
    journal: &Journal,
    operation: OperationId,
) -> Result<bool, ReconcilerError> {
    for (key, value) in journal.records(RecordNamespace::ControllerExecutionObserveReservation) {
        let reservation =
            ControllerExecutionObserveReservationV1::decode(key, value).map_err(|_| {
                ReconcilerError::CorruptLedger("invalid Controller execution Observe reservation")
            })?;
        if reservation.observe_operation() == operation {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_model::{ExecutionId, ObjectDigest};

    use super::*;
    use crate::journal::JournalLimits;
    use crate::reconciler::{
        EffectFailure, EffectObservation, OperationPlan, ReconcileOutcome, Reconciler,
        SingleNodeEffectExecutor,
    };
    use aos_sandbox_protocol::domain_ledger::effect_history::{EffectDomain, EffectReceipt};

    struct NoDispatch;

    impl SingleNodeEffectExecutor for NoDispatch {
        fn observe(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            panic!("adopted Observe child reached the executor")
        }

        fn apply(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            panic!("adopted Observe child reached the executor")
        }
    }

    fn reservation() -> ControllerExecutionObserveReservationV1 {
        let mut receipt = [7; 40];
        receipt[..8].copy_from_slice(b"AOSEXE01");
        ControllerExecutionObserveReservationV1::new(
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 32],
            &receipt,
        )
        .unwrap()
    }

    fn retain_reservation(
        journal: &mut Journal,
        reservation: &ControllerExecutionObserveReservationV1,
    ) {
        journal
            .commit(
                &JournalTransaction::new(
                    [5; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::ControllerExecutionObserveReservation,
                        reservation.execution().as_bytes().to_vec(),
                        reservation.encode(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
    }

    fn protected_journal(directory: &std::path::Path) -> (Journal, crate::journal::RecoveryReport) {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(directory).unwrap().uid();
        Journal::open_protected_at_uid(
            directory,
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap()
    }

    #[test]
    fn atomic_adoption_replays_once_and_never_dispatches() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        let reservation = reservation();
        retain_reservation(&mut journal, &reservation);

        let before_adoption = journal.snapshot_sequence();
        assert!(adopt_execution_observe_child_v1(&mut journal, &reservation).unwrap());
        assert_eq!(journal.snapshot_sequence(), before_adoption + 5);
        validate_all(&journal).unwrap();
        drop(journal);

        let (mut reopened, report) = protected_journal(directory.path());
        assert_eq!(report.truncated_bytes, 0);
        validate_all(&reopened).unwrap();
        let replay_sequence = reopened.snapshot_sequence();
        assert!(!adopt_execution_observe_child_v1(&mut reopened, &reservation).unwrap());
        assert_eq!(reopened.snapshot_sequence(), replay_sequence);

        let mut reconciler = Reconciler::new(reopened, NoDispatch);
        assert_eq!(
            reconciler
                .reconcile_once(reservation.observe_operation())
                .unwrap(),
            ReconcileOutcome::ObserveChildPending
        );
        assert!(
            reconciler
                .validated_unfinished_operation()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn orphan_claims_and_changed_effect_fail_before_dispatch() {
        for namespace in [RecordNamespace::Operation, RecordNamespace::Effect] {
            let directory = tempfile::tempdir().unwrap();
            let (mut journal, _) = protected_journal(directory.path());
            let reservation = reservation();
            retain_reservation(&mut journal, &reservation);
            let key = if namespace == RecordNamespace::Operation {
                reservation.observe_operation().as_bytes().to_vec()
            } else {
                effect_key(reservation.observe_operation(), 0).to_vec()
            };
            journal
                .commit(
                    &JournalTransaction::new(
                        [6; 16],
                        vec![JournalRecord::put(namespace, key, b"foreign".to_vec())],
                    )
                    .unwrap(),
                )
                .unwrap();
            let sequence = journal.snapshot_sequence();
            assert!(adopt_execution_observe_child_v1(&mut journal, &reservation).is_err());
            assert_eq!(journal.snapshot_sequence(), sequence);
        }

        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        let reservation = reservation();
        retain_reservation(&mut journal, &reservation);
        adopt_execution_observe_child_v1(&mut journal, &reservation).unwrap();
        let key = effect_key(reservation.observe_operation(), 0);
        let mut effect = journal.get(RecordNamespace::Effect, &key).unwrap().to_vec();
        effect[0] = 1;
        journal
            .commit(
                &JournalTransaction::new(
                    [8; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Effect,
                        key.to_vec(),
                        effect,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(validate_all(&journal).is_err());
        assert!(
            Reconciler::new(journal, NoDispatch)
                .reconcile_once(reservation.observe_operation())
                .is_err()
        );
    }

    #[test]
    fn generic_admission_cannot_replay_an_adopted_child() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        let reservation = reservation();
        retain_reservation(&mut journal, &reservation);
        adopt_execution_observe_child_v1(&mut journal, &reservation).unwrap();
        let (key, digest) = observe_child_identity_v1(&reservation).unwrap();
        let plan = OperationPlan::new(
            reservation.observe_operation(),
            key,
            digest,
            b"foreign-desired-state".to_vec(),
            b"running".to_vec(),
            vec![
                EffectPlan::new(
                    EffectDomain::Host,
                    aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                    b"foreign".to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap();

        assert!(matches!(
            Reconciler::new(journal, NoDispatch).accept(&plan),
            Err(ReconcilerError::OperationAlreadyExists)
        ));
    }

    #[test]
    fn partial_crash_tail_preserves_the_committed_child() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller.journal");
        let (mut journal, _) = protected_journal(directory.path());
        let reservation = reservation();
        retain_reservation(&mut journal, &reservation);
        adopt_execution_observe_child_v1(&mut journal, &reservation).unwrap();
        drop(journal);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[0x55; 13]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let (mut journal, report) = protected_journal(directory.path());
        assert_eq!(report.truncated_bytes, 13);
        assert!(observe_child_adoption_state_v1(&journal, &reservation).unwrap());
        assert!(!adopt_execution_observe_child_v1(&mut journal, &reservation).unwrap());
    }
    #[test]
    fn succeeded_operation_without_exact_signed_child_completion_refuses_before_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        let reservation = reservation();
        retain_reservation(&mut journal, &reservation);
        adopt_execution_observe_child_v1(&mut journal, &reservation).unwrap();
        journal.commit(&JournalTransaction::new([91; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, reservation.observe_operation().as_bytes().to_vec(),
            encode_operation_record(OperationRecord::new(OperationState::Succeeded, 1, false, None, None)),
        )]).unwrap()).unwrap();

        assert!(observe_child_adoption_state_v1(&journal, &reservation).is_err());
        assert!(validate_all(&journal).is_err());
    }


    fn retain_signed_sources(journal: &mut Journal,
        fixture: &aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::fixture::SignedObserveCompletionFixtureV1)
    {
        let execution = fixture.reservation.execution().as_bytes().to_vec();
        journal.commit(&JournalTransaction::new([92; 16], vec![
            JournalRecord::put(RecordNamespace::ControllerExecutionArgumentAttempt, execution.clone(), fixture.argument_attempt.clone()),
            JournalRecord::put(RecordNamespace::ControllerExecutionArgumentReceipt, execution.clone(), fixture.argument_receipt.clone()),
            JournalRecord::put(RecordNamespace::ControllerExecutionSpecAttempt, execution.clone(), fixture.specification.clone()),
            JournalRecord::put(RecordNamespace::ControllerExecutionObserveReservation, execution, fixture.reservation.encode()),
        ]).unwrap()).unwrap();
    }

    #[test]
    fn signed_first_observe_completes_two_rows_reopens_and_never_dispatches() {
        let fixture = aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::fixture::signed_observe_completion_fixture_v1();
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        retain_signed_sources(&mut journal, &fixture);
        assert!(adopt_execution_observe_child_v1(&mut journal, &fixture.reservation).unwrap());
        let reservation_bytes = fixture.reservation.encode();
        let before = journal.snapshot_sequence();
        let receipt = EffectReceipt::new(fixture.receipt.to_vec()).unwrap();
        let records = prepare_completed_execution_observe_child_v1(&journal, &fixture.reservation,
            &fixture.completion, receipt.clone(), 50).unwrap().unwrap();
        assert_eq!(records.len(), 2);
        journal.commit(&JournalTransaction::new([93; 16], Vec::from(records)).unwrap()).unwrap();
        assert_eq!(journal.snapshot_sequence(), before + 4);
        assert_eq!(journal.get(RecordNamespace::ControllerExecutionObserveReservation,
            fixture.reservation.execution().as_bytes()), Some(reservation_bytes.as_slice()));
        validate_all(&journal).unwrap();
        assert!(prepare_completed_execution_observe_child_v1(&journal, &fixture.reservation,
            &fixture.completion, receipt.clone(), 50).unwrap().is_none());
        drop(journal);

        let (reopened, report) = protected_journal(directory.path());
        assert_eq!(report.truncated_bytes, 0);
        validate_all(&reopened).unwrap();
        assert_eq!(reopened.get(RecordNamespace::Effect, &effect_key(fixture.reservation.observe_operation(), 0)).unwrap()[0], 7);
        let mut reconciler = Reconciler::new(reopened, NoDispatch);
        assert!(reconciler.validated_unfinished_operation().unwrap().is_none());
        assert_eq!(reconciler.reconcile_once(fixture.reservation.observe_operation()).unwrap(), ReconcileOutcome::ObserveChildPending);
    }

    #[test]
    fn signed_completion_rejects_foreign_protected_source_before_append() {
        let fixture = aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::fixture::signed_observe_completion_fixture_v1();
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        retain_signed_sources(&mut journal, &fixture);
        adopt_execution_observe_child_v1(&mut journal, &fixture.reservation).unwrap();
        let mut changed = fixture.argument_receipt.clone();
        changed[40] ^= 1;
        journal.commit(&JournalTransaction::new([94; 16], vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionArgumentReceipt, fixture.reservation.execution().as_bytes().to_vec(), changed,
        )]).unwrap()).unwrap();
        let before = journal.snapshot_sequence();
        assert!(prepare_completed_execution_observe_child_v1(&journal, &fixture.reservation,
            &fixture.completion, EffectReceipt::new(fixture.receipt.to_vec()).unwrap(), 50).is_err());
        assert_eq!(journal.snapshot_sequence(), before);
    }


    #[test]
    fn signed_capture_requires_actual_anchor_then_completes_and_cold_reopens() {
        let (fixture, anchor) = aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::fixture::signed_ongoing_capture_observe_completion_fixture_v3();
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = protected_journal(directory.path());
        retain_signed_sources(&mut journal, &fixture);
        adopt_execution_observe_child_v1(&mut journal, &fixture.reservation).unwrap();
        let receipt = EffectReceipt::new(fixture.receipt.to_vec()).unwrap();
        let before = journal.snapshot_sequence();
        assert!(prepare_completed_execution_observe_child_v1(&journal, &fixture.reservation,
            &fixture.completion, receipt.clone(), 50).is_err());
        assert_eq!(journal.snapshot_sequence(), before);

        journal.commit(&JournalTransaction::new([95; 16], vec![JournalRecord::put(
            RecordNamespace::ControllerStorageCaptureAdmission,
            fixture.reservation.execution().as_bytes().to_vec(), anchor.clone(),
        )]).unwrap()).unwrap();
        let records = prepare_completed_execution_observe_child_v1(&journal, &fixture.reservation,
            &fixture.completion, receipt.clone(), 50).unwrap().unwrap();
        journal.commit(&JournalTransaction::new([96; 16], Vec::from(records)).unwrap()).unwrap();
        validate_all(&journal).unwrap();
        drop(journal);

        let (reopened, report) = protected_journal(directory.path());
        assert_eq!(report.truncated_bytes, 0);
        assert_eq!(reopened.get(RecordNamespace::ControllerStorageCaptureAdmission,
            fixture.reservation.execution().as_bytes()), Some(anchor.as_slice()));
        assert!(prepare_completed_execution_observe_child_v1(&reopened, &fixture.reservation,
            &fixture.completion, receipt, 50).unwrap().is_none());
        validate_all(&reopened).unwrap();
        let mut reconciler = Reconciler::new(reopened, NoDispatch);
        assert!(reconciler.validated_unfinished_operation().unwrap().is_none());
        assert_eq!(reconciler.reconcile_once(fixture.reservation.observe_operation()).unwrap(),
            ReconcileOutcome::ObserveChildPending);
    }

}
