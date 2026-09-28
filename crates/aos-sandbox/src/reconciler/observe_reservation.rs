//! Admission interlock for retained Controller execution Observe identities.
//!
//! The reconciler validates the Controller's complete reservation record
//! before assigning a fresh generic Operation ID. This check does not confer
//! dispatch authority for the reserved Observe operation.

use std::collections::BTreeSet;

use aos_sandbox_core::OperationId;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
use crate::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};

use super::{
    EffectLedgerRecord, EffectPlan, EffectState, OperationRecord, OperationState, ReconcilerError,
    decode_effect, decode_operation, effect_key, encode_effect, encode_operation_record,
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
    Ok((IdempotencyKey::new(key.to_vec())?, request_digest))
}

fn validate_child(
    journal: &Journal,
    reservation: &ControllerExecutionObserveReservationV1,
) -> Result<bool, ReconcilerError> {
    let operation_id = reservation.observe_operation();
    let (key, request_digest) = observe_child_identity_v1(reservation)?;
    let operation = journal.get(RecordNamespace::Operation, operation_id.as_bytes());
    let effect = journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0));
    let decision = journal.check_idempotency(&key, request_digest);

    if operation.is_none() && effect.is_none() && decision == IdempotencyOutcome::Vacant {
        return Ok(false);
    }
    let operation = operation.ok_or_else(corrupt).and_then(decode_operation)?;
    if operation
        != (OperationRecord {
            state: OperationState::Accepted,
            effect_count: 1,
            ownership_gated: false,
            runtime_intent_digest: None,
            public_operation: None,
        })
        || decision != IdempotencyOutcome::Replay(operation_id)
        || journal
            .get(
                RecordNamespace::PublicOperationAuthorization,
                operation_id.as_bytes(),
            )
            .is_some()
    {
        return Err(corrupt());
    }

    let effect_bytes = effect.ok_or_else(corrupt)?;
    if effect_bytes.first() != Some(&super::effect::RESERVED_OBSERVE_EFFECT_VERSION) {
        return Err(corrupt());
    }
    let effect = decode_effect(effect_bytes)?;
    if effect.plan != EffectPlan::reserved_observe(reservation)
        || effect.state != EffectState::Planned
        || effect.dispatch.is_some()
    {
        return Err(corrupt());
    }
    Ok(true)
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
        let effect = decode_effect(value)?;
        if effect.plan.is_reserved_observe() {
            if value.first() != Some(&super::effect::RESERVED_OBSERVE_EFFECT_VERSION) {
                return Err(corrupt());
            }
            let reservation = ControllerExecutionObserveReservationV1::decode(
                effect.plan.request().get(8..24).ok_or_else(corrupt)?,
                effect.plan.request(),
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
    let effect = EffectLedgerRecord {
        plan: EffectPlan::reserved_observe(reservation),
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    };
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
            encode_operation_record(OperationRecord {
                state: OperationState::Accepted,
                effect_count: 1,
                ownership_gated: false,
                runtime_intent_digest: None,
                public_operation: None,
            }),
        ),
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, 0).to_vec(),
            encode_effect(&effect)?,
        ),
        JournalRecord::idempotency(&key, request_digest, operation_id),
    ];
    journal.commit(&JournalTransaction::new(transaction_id, records)?)?;
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

    use aos_sandbox_core::{ExecutionId, ObjectDigest};

    use super::*;
    use crate::journal::JournalLimits;
    use crate::reconciler::{
        EffectDomain, EffectFailure, EffectObservation, EffectReceipt, OperationPlan,
        ReconcileOutcome, Reconciler, SingleNodeEffectExecutor,
    };

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
                    aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
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
}
