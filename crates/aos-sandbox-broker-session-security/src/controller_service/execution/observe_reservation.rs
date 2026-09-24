//! Durable, closed reservation of a Host Observe after authenticated Authorize.
//!
//! The AOSCOB01 record binds one distinct Observe operation to the retained
//! Create specification and the exact Controller receipt derived from signed
//! Host authorization evidence. It does not grant or dispatch the Observe.
//!
//! ```text
//! AOSCOB01 || execution:16 || Create-operation:16 || Observe-operation:16
//!          || spec-digest:32 || source-operation-commitment:32
//!          || authorization-receipt:40 || record-digest:32
//! ```

use aos_proto::aos::sandbox::v1::ExecutionPhase;
use aos_sandbox::controller_execution_observe_reservation::{
    ControllerExecutionObserveReservationV1 as ObserveReservation, ObserveReservationCodecErrorV1,
};
use aos_sandbox::{EffectFailure, Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::runtime_backend::BackendExecutionPhaseV1;
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, execution_spec_digest_v1};
use sha2::{Digest as _, Sha256};

use super::{
    ControllerExecutionActionV1, ControllerExecutionCompletionV1, ControllerExecutionIntentV1,
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
    load_controller_execution_spec_attempt_v1,
};

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-reservation-tx.v1\0";

fn matches_intent(reservation: &ObserveReservation, intent: &ControllerExecutionIntentV1) -> bool {
    intent.action == ControllerExecutionActionV1::Observe
        && intent.specification.is_none()
        && reservation.create_operation() == intent.projection_operation_id
        && reservation.observe_operation() == intent.operation_id
        && Some(reservation.specification_digest()) == intent.observation_specification_digest
        && reservation.source_operation_commitment() == intent.source_operation_commitment
}

fn codec_error(error: ObserveReservationCodecErrorV1) -> EffectFailure {
    let diagnostic = match error {
        ObserveReservationCodecErrorV1::ReceiptLength => {
            "Host authorization receipt has the wrong size"
        }
        ObserveReservationCodecErrorV1::InvalidBinding => {
            "Host authorization receipt or Create binding is invalid"
        }
        ObserveReservationCodecErrorV1::InvalidOperation => "Observe operation identity is invalid",
        ObserveReservationCodecErrorV1::NotDistinct => {
            "Observe operation is not distinct from Create"
        }
        ObserveReservationCodecErrorV1::CorruptRecord => {
            "protected execution Observe reservation is corrupt"
        }
    };
    EffectFailure::Permanent(diagnostic.to_owned())
}

fn corrupt() -> EffectFailure {
    EffectFailure::Permanent("protected execution Observe reservation is corrupt".to_owned())
}

fn load(
    journal: &Journal,
    execution: ExecutionId,
) -> Result<Option<ObserveReservation>, EffectFailure> {
    journal
        .ensure_healthy()
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
    journal
        .get(
            RecordNamespace::ControllerExecutionObserveReservation,
            execution.as_bytes(),
        )
        .map(|bytes| ObserveReservation::decode(execution.as_bytes(), bytes).map_err(codec_error))
        .transpose()
}

fn require_unclaimed_operation(
    journal: &Journal,
    operation: OperationId,
) -> Result<(), EffectFailure> {
    let operation_claimed = journal
        .get(RecordNamespace::Operation, operation.as_bytes())
        .is_some();
    let effect_claimed = journal
        .records(RecordNamespace::Effect)
        .any(|(key, _)| key.starts_with(operation.as_bytes()));
    if operation_claimed || effect_claimed {
        // The closed reservation has no reconciler Operation/Effect proof yet.
        // Even an exact record replay cannot treat an unknown ledger owner as ours.
        return Err(EffectFailure::Permanent(
            "execution Observe operation identity already belongs to another operation".to_owned(),
        ));
    }
    Ok(())
}

fn retain(journal: &mut Journal, reservation: &ObserveReservation) -> Result<(), EffectFailure> {
    require_unclaimed_operation(journal, reservation.observe_operation())?;
    if let Some(existing) = load(journal, reservation.execution())? {
        return if existing == *reservation {
            Ok(())
        } else {
            Err(EffectFailure::Permanent(
                "execution Observe reservation conflicts with retained authorization".to_owned(),
            ))
        };
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(reservation.execution().as_bytes())
        .chain_update(reservation.create_operation().as_bytes())
        .finalize()
        .into();
    let transaction_id: [u8; 16] = digest[..16].try_into().map_err(|_| corrupt())?;
    if transaction_id == [0; 16] {
        return Err(corrupt());
    }
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerExecutionObserveReservation,
            reservation.execution().as_bytes().to_vec(),
            reservation.encode(),
        )],
    )
    .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
    journal.commit(&transaction).map_err(|_| {
        EffectFailure::Retryable(
            "execution Observe reservation append is ambiguous; cold-reopen Controller custody"
                .to_owned(),
        )
    })?;
    Ok(())
}

pub(super) fn require_current(
    journal: &Journal,
    intent: &ControllerExecutionIntentV1,
) -> Result<(), EffectFailure> {
    // The protected Create read establishes custody for every subsequent
    // reservation and collision read on this same borrowed journal.
    let execution = ExecutionId::from_bytes(intent.execution_id);
    let retained = load_controller_execution_spec_attempt_v1(journal, execution)
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?
        .ok_or_else(|| {
            EffectFailure::Retryable("protected Create specification is absent".to_owned())
        })?;
    let reservation = load(journal, execution)?.ok_or_else(|| {
        EffectFailure::Retryable("protected execution Observe reservation is absent".to_owned())
    })?;
    require_unclaimed_operation(journal, reservation.observe_operation())?;
    if !matches_intent(&reservation, intent)
        || retained.create_operation() != reservation.create_operation()
        || retained.specification_digest() != reservation.specification_digest()
    {
        return Err(EffectFailure::Permanent(
            "execution Observe differs from retained authorization".to_owned(),
        ));
    }
    Ok(())
}

impl ControllerExecutionIntentV1 {
    /// Reserves one distinct Observe identity after exact Host authorization.
    ///
    /// This stage is deliberately closed: it returns an intent but neither
    /// dispatches the Host method nor authorizes a public phase transition.
    /// The original Create specification and signed Host receipt must be
    /// recovered byte-identically before a later caller can replay it.
    ///
    /// # Errors
    ///
    /// Rejects missing or changed Create custody, a non-Authorize completion,
    /// conflicting retained identity, or ambiguous journal durability.
    #[allow(dead_code)]
    pub(crate) fn reserve_observe_after_authorization(
        &self,
        journal: &mut Journal,
        completion: &ControllerExecutionCompletionV1,
    ) -> Result<Self, EffectFailure> {
        if self.action != ControllerExecutionActionV1::Authorize
            || self.operation_id != self.projection_operation_id
            || completion.phase != BackendExecutionPhaseV1::Authorized
            || completion.terminal.is_some()
            || completion.observation_sequence == 0
        {
            return Err(EffectFailure::Permanent(
                "execution Observe has no exact Host Authorize completion".to_owned(),
            ));
        }
        let authorization = completion.authorization_binding.as_ref().ok_or_else(|| {
            EffectFailure::Permanent(
                "Host authorization receipt lacks an authenticated Create binding".to_owned(),
            )
        })?;
        if !authorization.matches_source(
            self.operation_id,
            self.execution_id,
            self.source_operation_commitment,
            &completion.receipt,
        ) {
            return Err(EffectFailure::Permanent(
                "Host authorization receipt belongs to another Create intent".to_owned(),
            ));
        }
        let specification = self.specification.as_ref().ok_or_else(|| {
            EffectFailure::Permanent(
                "execution Observe has no retained Create specification".to_owned(),
            )
        })?;
        let specification_digest = execution_spec_digest_v1(specification);
        if authorization.specification_digest != specification_digest {
            return Err(EffectFailure::Permanent(
                "Host authorization receipt belongs to another Create intent".to_owned(),
            ));
        }
        let retained = load_controller_execution_spec_attempt_v1(
            journal,
            ExecutionId::from_bytes(self.execution_id),
        )
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?
        .ok_or_else(|| {
            EffectFailure::Retryable("protected Create specification is absent".to_owned())
        })?;
        if retained.create_operation() != self.operation_id
            || retained.specification_digest() != specification_digest
            || retained
                .decoded_specification()
                .map_err(|error| EffectFailure::Retryable(error.to_string()))?
                != *specification
        {
            return Err(EffectFailure::Permanent(
                "execution Observe differs from retained Create specification".to_owned(),
            ));
        }
        let projection = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Execution, self.execution_id)
            .map_err(|error| EffectFailure::Retryable(error.to_string()))?
            .ok_or_else(|| {
                EffectFailure::Retryable("execution Create projection is absent".to_owned())
            })?;
        let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
            return Err(corrupt());
        };
        if projection.operation() != self.projection_operation_id
            || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
        {
            return Err(EffectFailure::Retryable(
                "execution Create projection is no longer current".to_owned(),
            ));
        }

        let reservation = ObserveReservation::new(
            ExecutionId::from_bytes(self.execution_id),
            self.operation_id,
            specification_digest,
            self.source_operation_commitment,
            completion.receipt.as_bytes(),
        )
        .map_err(codec_error)?;
        retain(journal, &reservation)?;
        let observe = Self {
            operation_id: reservation.observe_operation(),
            projection_operation_id: self.projection_operation_id,
            execution_id: self.execution_id,
            action: ControllerExecutionActionV1::Observe,
            specification: None,
            observation_specification_digest: Some(specification_digest),
            source_operation_commitment: self.source_operation_commitment,
        };
        require_current(journal, &observe)?;
        Ok(observe)
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox::{EffectReceipt, JournalLimits};
    use aos_sandbox_core::{NodeId, ProjectId};
    use aos_sandbox_protocol::host_execution::HostExecutionTerminalResultV1;

    use super::super::AuthenticatedHostAuthorizationBindingV1;
    use super::*;

    const RECEIPT_MAGIC: &[u8; 8] = b"AOSEXE01";
    const RECEIPT_BYTES: usize = 40;

    #[test]
    fn authenticated_receipt_binding_rejects_another_create() {
        let mut receipt_bytes = [9; RECEIPT_BYTES];
        receipt_bytes[..8].copy_from_slice(RECEIPT_MAGIC);
        let receipt = EffectReceipt::new(receipt_bytes.to_vec()).unwrap();
        let binding = AuthenticatedHostAuthorizationBindingV1 {
            operation_id: OperationId::from_bytes([1; 16]),
            execution_id: [2; 16],
            specification_digest: ObjectDigest::from_bytes([3; 32]),
            source_operation_commitment: [4; 32],
            receipt: receipt.clone(),
        };
        assert!(binding.matches_source(
            binding.operation_id,
            binding.execution_id,
            binding.source_operation_commitment,
            &receipt,
        ));
        assert!(!binding.matches_source(
            OperationId::from_bytes([5; 16]),
            binding.execution_id,
            binding.source_operation_commitment,
            &receipt,
        ));
        assert!(!binding.matches_source(
            binding.operation_id,
            [6; 16],
            binding.source_operation_commitment,
            &receipt,
        ));
        assert!(!binding.matches_source(
            binding.operation_id,
            binding.execution_id,
            [8; 32],
            &receipt,
        ));
        let changed_receipt = EffectReceipt::new(vec![1; RECEIPT_BYTES]).unwrap();
        assert!(!binding.matches_source(
            binding.operation_id,
            binding.execution_id,
            binding.source_operation_commitment,
            &changed_receipt,
        ));
    }

    #[test]
    fn cross_create_authorization_cannot_reserve_observe() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let initial_sequence = journal.snapshot_sequence();
        let create = ControllerExecutionIntentV1 {
            operation_id: OperationId::from_bytes([1; 16]),
            projection_operation_id: OperationId::from_bytes([1; 16]),
            execution_id: [2; 16],
            action: ControllerExecutionActionV1::Authorize,
            specification: None,
            observation_specification_digest: None,
            source_operation_commitment: [3; 32],
        };
        let mut receipt_bytes = [4; RECEIPT_BYTES];
        receipt_bytes[..8].copy_from_slice(RECEIPT_MAGIC);
        let receipt = EffectReceipt::new(receipt_bytes.to_vec()).unwrap();
        let other_create = ControllerExecutionCompletionV1 {
            receipt: receipt.clone(),
            phase: BackendExecutionPhaseV1::Authorized,
            observation_sequence: 2,
            terminal: None,
            authorization_binding: Some(AuthenticatedHostAuthorizationBindingV1 {
                operation_id: OperationId::from_bytes([9; 16]),
                execution_id: create.execution_id,
                specification_digest: ObjectDigest::from_bytes([5; 32]),
                source_operation_commitment: create.source_operation_commitment,
                receipt,
            }),
        };

        assert!(matches!(
            create.reserve_observe_after_authorization(&mut journal, &other_create),
            Err(EffectFailure::Permanent(message)) if message.contains("another Create intent")
        ));
        assert_eq!(journal.snapshot_sequence(), initial_sequence);
        assert!(
            load(&journal, ExecutionId::from_bytes(create.execution_id))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reservation_replays_only_exact_authorization_receipt_after_cold_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut receipt = [3; RECEIPT_BYTES];
        receipt[..8].copy_from_slice(RECEIPT_MAGIC);
        let reservation = ObserveReservation::new(
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([4; 32]),
            [5; 32],
            &receipt,
        )
        .unwrap();
        retain(&mut journal, &reservation).unwrap();

        drop(journal);
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let durable_sequence = journal.snapshot_sequence();
        assert_eq!(
            load(&journal, reservation.execution()).unwrap(),
            Some(reservation.clone())
        );
        retain(&mut journal, &reservation).unwrap();
        assert_eq!(journal.snapshot_sequence(), durable_sequence);

        let intent = ControllerExecutionIntentV1 {
            operation_id: reservation.observe_operation(),
            projection_operation_id: reservation.create_operation(),
            execution_id: *reservation.execution().as_bytes(),
            action: ControllerExecutionActionV1::Observe,
            specification: None,
            observation_specification_digest: Some(reservation.specification_digest()),
            source_operation_commitment: reservation.source_operation_commitment(),
        };
        assert!(matches_intent(&reservation, &intent));
        assert!(matches!(
            require_current(&journal, &intent),
            Err(EffectFailure::Retryable(_))
        ));
        let substituted = ControllerExecutionIntentV1 {
            operation_id: OperationId::from_bytes([9; 16]),
            ..intent
        };
        assert!(!matches_intent(&reservation, &substituted));

        receipt[39] ^= 1;
        let changed = ObserveReservation::new(
            reservation.execution(),
            reservation.create_operation(),
            reservation.specification_digest(),
            reservation.source_operation_commitment(),
            &receipt,
        )
        .unwrap();
        assert_ne!(changed.observe_operation(), reservation.observe_operation());
        assert!(matches!(
            retain(&mut journal, &changed),
            Err(EffectFailure::Permanent(_))
        ));
        assert_eq!(journal.snapshot_sequence(), durable_sequence);
    }

    #[test]
    fn late_operation_or_effect_collision_blocks_exact_reservation_replay() {
        for namespace in [RecordNamespace::Operation, RecordNamespace::Effect] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("controller.journal");
            let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut receipt = [3; RECEIPT_BYTES];
            receipt[..8].copy_from_slice(RECEIPT_MAGIC);
            let reservation = ObserveReservation::new(
                ExecutionId::from_bytes([1; 16]),
                OperationId::from_bytes([2; 16]),
                ObjectDigest::from_bytes([4; 32]),
                [5; 32],
                &receipt,
            )
            .unwrap();
            retain(&mut journal, &reservation).unwrap();

            let mut collision_key = reservation.observe_operation().as_bytes().to_vec();
            if namespace == RecordNamespace::Effect {
                collision_key.extend_from_slice(&0_u32.to_be_bytes());
            }
            let collision = JournalTransaction::new(
                [6; 16],
                vec![JournalRecord::put(
                    namespace,
                    collision_key,
                    b"other-owner".to_vec(),
                )],
            )
            .unwrap();
            journal.commit(&collision).unwrap();
            let sequence = journal.snapshot_sequence();

            assert!(matches!(
                retain(&mut journal, &reservation),
                Err(EffectFailure::Permanent(_))
            ));
            assert!(matches!(
                require_unclaimed_operation(&journal, reservation.observe_operation()),
                Err(EffectFailure::Permanent(_))
            ));
            assert_eq!(journal.snapshot_sequence(), sequence);
        }
    }

    #[test]
    fn reservation_rejects_untyped_or_zero_authorization_receipt() {
        let execution = ExecutionId::from_bytes([1; 16]);
        let create = OperationId::from_bytes([2; 16]);
        let spec = ObjectDigest::from_bytes([3; 32]);
        assert!(ObserveReservation::new(execution, create, spec, [4; 32], &[5; 40]).is_err());
        let mut zero = [0; RECEIPT_BYTES];
        zero[..8].copy_from_slice(RECEIPT_MAGIC);
        assert!(ObserveReservation::new(execution, create, spec, [4; 32], &zero).is_err());
    }

    #[test]
    fn terminal_observe_completion_cannot_be_used_as_authorization() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("controller.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let original_sequence = journal.snapshot_sequence();
        let authorize = ControllerExecutionIntentV1 {
            operation_id: OperationId::from_bytes([1; 16]),
            projection_operation_id: OperationId::from_bytes([1; 16]),
            execution_id: [2; 16],
            action: ControllerExecutionActionV1::Authorize,
            specification: None,
            observation_specification_digest: None,
            source_operation_commitment: [3; 32],
        };
        let mut receipt = [4; RECEIPT_BYTES];
        receipt[..8].copy_from_slice(RECEIPT_MAGIC);
        let observe_completion = ControllerExecutionCompletionV1 {
            receipt: EffectReceipt::new(receipt.to_vec()).unwrap(),
            phase: BackendExecutionPhaseV1::Exited,
            observation_sequence: 2,
            terminal: Some(HostExecutionTerminalResultV1::Exited(0)),
            authorization_binding: None,
        };

        assert!(matches!(
            authorize.reserve_observe_after_authorization(&mut journal, &observe_completion),
            Err(EffectFailure::Permanent(_))
        ));
        assert_eq!(journal.snapshot_sequence(), original_sequence);
        assert!(
            load(&journal, ExecutionId::from_bytes([2; 16]))
                .unwrap()
                .is_none()
        );

        let unreserved = ControllerExecutionIntentV1 {
            action: ControllerExecutionActionV1::Observe,
            observation_specification_digest: Some(ObjectDigest::from_bytes([5; 32])),
            ..authorize
        };
        assert!(matches!(
            unreserved.prepare_authorization(
                super::super::ExecutionAuthorizationKindV1::Apply,
                ProjectId::from_bytes([6; 16]),
                NodeId::from_bytes([7; 16]),
                &mut journal,
                None,
            ),
            Err(EffectFailure::Retryable(_))
        ));
    }
}
