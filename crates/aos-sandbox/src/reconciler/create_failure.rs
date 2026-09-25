//! Closed Controller receipt for an exact Create failed-before-commit settlement.
//!
//! ```text
//! AOSCFB01 | version:u16be | reserved:2 | H-head:32 | signed-outcome:32 |
//! current-Host-cut:32 | AOSHNA01:384 | predecessor-revision:32 |
//! successor-revision:32 | successor-operation:32 | predecessor-sequence:u64be |
//! effect-attempt:u32be | wall-seconds:i64be |
//! SHA256(domain || preceding):32
//! ```
//!
//! The receipt is a local transaction witness, not Host authorization. There
//! is deliberately no production constructor for its proof input until a
//! current signed 39/40 readback and anti-rollback cut can be supplied.

mod prepare;

use aos_proto::aos::sandbox::v1::{ExecutionPhase, Timestamp};
use aos_sandbox_core::{ObjectDigest, OperationId, ResourceKind};
use aos_sandbox_protocol::host_execution_no_apply::{
    HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1, HostExecutionNoApplyRecordV1,
};
use sha2::{Digest as _, Sha256};

use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1,
};
use crate::journal::{Journal, JournalRecord, RecordNamespace};

use prepare::{CreateFailurePrepareV1, load_floor, record_digest};

use super::{
    EffectReceipt, EffectState, OperationRecord, OperationState, Reconciler, ReconcilerError,
    SingleNodeEffectExecutor, decode_effect, decode_operation, effect_key, encode_effect,
    encode_operation_record, recovered_public_operation_admission_v1, transition_operation,
};

const MAGIC: &[u8; 8] = b"AOSCFB01";
const DOMAIN: &[u8] = b"aos.sandbox.create-failed-before-commit.v1\0";
const VERSION: u16 = 1;
const RECEIPT_BYTES: usize =
    8 + 2 + 2 + 32 * 3 + HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1 + 32 * 3 + 8 + 4 + 8 + 32;
const RESOURCE_VERSION_DOMAIN: &[u8] = b"aos.sandbox.failed-create-resource-version.v1\0";

/// Carries a joined H archive, signed Host outcome, and current Host cut.
///
/// Its fields cannot be constructed by production code until those three
/// owners have a typed currentness bridge. Merely decoding a Host marker is
/// intentionally insufficient.
#[allow(
    dead_code,
    reason = "production Host currentness bridge remains closed"
)]
#[derive(Clone, Copy)]
pub(crate) struct CreateFailureSettlementProofV1 {
    marker: HostExecutionNoApplyRecordV1,
    archive_head: ObjectDigest,
    signed_outcome: ObjectDigest,
    current_host_cut: ObjectDigest,
    host_lease_epoch: u64,
    host_lease_head: ObjectDigest,
}

impl CreateFailureSettlementProofV1 {
    pub(super) fn into_receipt(
        self,
        predecessor_revision: ObjectDigest,
        successor_revision: ObjectDigest,
        successor_operation: ObjectDigest,
        predecessor_sequence: u64,
        effect_attempt: u32,
        wall_seconds: i64,
    ) -> CreateFailureReceiptV1 {
        CreateFailureReceiptV1 {
            marker: self.marker,
            archive_head: self.archive_head,
            signed_outcome: self.signed_outcome,
            current_host_cut: self.current_host_cut,
            predecessor_revision,
            successor_revision,
            successor_operation,
            predecessor_sequence,
            effect_attempt,
            wall_seconds,
        }
    }

    pub(super) const fn marker(&self) -> HostExecutionNoApplyRecordV1 {
        self.marker
    }

    #[cfg(test)]
    pub(super) fn test_only(marker: HostExecutionNoApplyRecordV1) -> Self {
        Self {
            marker,
            archive_head: ObjectDigest::from_bytes([0xa1; 32]),
            signed_outcome: ObjectDigest::from_bytes([0xa2; 32]),
            current_host_cut: ObjectDigest::from_bytes([0xa3; 32]),
            host_lease_epoch: 1,
            host_lease_head: ObjectDigest::from_bytes([0xa4; 32]),
        }
    }
}

/// Retains a fresh held-Host proof only across one Controller prepare-to-CAS.
///
/// Cold replay of the durable floor never recreates this token. A future Host
/// bridge must reacquire the matching live lease before retrying preparation.
#[allow(dead_code, reason = "production Host lease bridge remains closed")]
pub(crate) struct PreparedCreateFailureSettlementV1 {
    operation_id: OperationId,
    proof: CreateFailureSettlementProofV1,
    floor: CreateFailurePrepareV1,
    wall_seconds: i64,
}

struct PlannedCreateFailureV1 {
    operation: OperationRecord,
    records: [JournalRecord; 3],
    predecessor: [ObjectDigest; 3],
    successor: [ObjectDigest; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CreateFailureReceiptV1 {
    pub(super) marker: HostExecutionNoApplyRecordV1,
    pub(super) archive_head: ObjectDigest,
    pub(super) signed_outcome: ObjectDigest,
    pub(super) current_host_cut: ObjectDigest,
    pub(super) predecessor_revision: ObjectDigest,
    pub(super) successor_revision: ObjectDigest,
    pub(super) successor_operation: ObjectDigest,
    pub(super) predecessor_sequence: u64,
    pub(super) effect_attempt: u32,
    pub(super) wall_seconds: i64,
}

impl CreateFailureReceiptV1 {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        for digest in [
            self.archive_head,
            self.signed_outcome,
            self.current_host_cut,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.marker.encode_canonical());
        bytes.extend_from_slice(self.predecessor_revision.as_bytes());
        bytes.extend_from_slice(self.successor_revision.as_bytes());
        bytes.extend_from_slice(self.successor_operation.as_bytes());
        bytes.extend_from_slice(&self.predecessor_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.effect_attempt.to_be_bytes());
        bytes.extend_from_slice(&self.wall_seconds.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Option<Self>, ()> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if bytes.len() != RECEIPT_BYTES
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..12] != [0; 2]
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..RECEIPT_BYTES - 32])
                .finalize()
                .as_slice()
                != &bytes[RECEIPT_BYTES - 32..]
        {
            return Err(());
        }

        let digest = |start: usize| -> Result<ObjectDigest, ()> {
            let raw: [u8; 32] = bytes[start..start + 32].try_into().map_err(|_| ())?;
            if raw == [0; 32] {
                return Err(());
            }
            Ok(ObjectDigest::from_bytes(raw))
        };
        let marker =
            HostExecutionNoApplyRecordV1::decode_canonical(&bytes[108..492]).map_err(|_| ())?;
        let predecessor_sequence = u64::from_be_bytes(bytes[588..596].try_into().map_err(|_| ())?);
        let effect_attempt = u32::from_be_bytes(bytes[596..600].try_into().map_err(|_| ())?);
        let wall_seconds = i64::from_be_bytes(bytes[600..608].try_into().map_err(|_| ())?);
        if predecessor_sequence == 0 || effect_attempt == 0 {
            return Err(());
        }

        Ok(Some(Self {
            marker,
            archive_head: digest(12)?,
            signed_outcome: digest(44)?,
            current_host_cut: digest(76)?,
            predecessor_revision: digest(492)?,
            successor_revision: digest(524)?,
            successor_operation: digest(556)?,
            predecessor_sequence,
            effect_attempt,
            wall_seconds,
        }))
    }

    pub(super) fn resource_version(self) -> [u8; 32] {
        Sha256::new()
            .chain_update(RESOURCE_VERSION_DOMAIN)
            .chain_update(self.marker.encode_canonical())
            .chain_update(self.archive_head.as_bytes())
            .chain_update(self.signed_outcome.as_bytes())
            .chain_update(self.current_host_cut.as_bytes())
            .chain_update(self.predecessor_revision.as_bytes())
            .finalize()
            .into()
    }
}

fn invalid_settlement() -> ReconcilerError {
    ReconcilerError::CorruptLedger("failed-Create settlement is not an exact three-record cut")
}

pub(super) fn has_prepare_floor(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<bool, ReconcilerError> {
    Ok(load_floor(journal, operation_id)?.is_some())
}

pub(super) fn validate_all_prepare_floors(journal: &Journal) -> Result<(), ReconcilerError> {
    prepare::validate_all_floors(journal)
}

fn operation_digest(operation: OperationRecord) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(encode_operation_record(operation)).into())
}

fn desired_execution_key(
    journal: &Journal,
    execution_id: [u8; 16],
) -> Result<Vec<u8>, ReconcilerError> {
    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, execution_id)
        .map_err(|_| invalid_settlement())?
        .ok_or_else(invalid_settlement)?;
    let plan = PublicProjectionPlanV1::new(
        projection.project(),
        projection.operation(),
        projection.resource().clone(),
    )
    .map_err(|_| invalid_settlement())?;
    Ok(plan.into_desired_state().0)
}

fn validate_accepted_create_identity(
    effect: &super::EffectLedgerRecord,
    operation_id: OperationId,
    execution: &aos_proto::aos::sandbox::v1::Execution,
) -> Result<(), ReconcilerError> {
    let context = effect
        .plan
        .public_mutation_context()?
        .ok_or_else(invalid_settlement)?;
    let crate::cli_model::DormantSandboxRequestKindV1::Exec(request) =
        context.validated_request()?
    else {
        return Err(invalid_settlement());
    };
    if execution.audit_id != operation_id.as_bytes()
        || execution.sandbox_id != request.sandbox_id
        || execution.command.as_option() != request.command.as_option()
        || request.mutation.as_option().is_none_or(|mutation| {
            execution.sandbox_incarnation_id != mutation.expected_incarnation_id
        })
    {
        return Err(invalid_settlement());
    }
    Ok(())
}

/// Validates the entire local cut on cold replay, including absence of a
/// special failed-Create receipt in every other operation state.
pub(super) fn validate_failed_create_operation(
    journal: &Journal,
    operation_id: OperationId,
    operation: OperationRecord,
) -> Result<(), ReconcilerError> {
    if operation.effect_count != 1 {
        if operation.state == OperationState::FailedBeforeCommit {
            return Err(invalid_settlement());
        }

        // A special receipt on any step of a multi-effect operation must not
        // evade cold replay merely because the operation cannot settle Create.
        for step in 0..operation.effect_count {
            let bytes = journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, step))
                .ok_or_else(invalid_settlement)?;
            let effect = decode_effect(bytes)?;
            if let EffectState::Applied { receipt, .. } = effect.state {
                if receipt
                    .create_failure_receipt()
                    .map_err(|()| invalid_settlement())?
                    .is_some()
                {
                    return Err(invalid_settlement());
                }
            }
        }
        return Ok(());
    }
    let bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or_else(invalid_settlement)?;
    let effect = decode_effect(bytes)?;
    let (receipt, effect_attempt) = match &effect.state {
        EffectState::Applied { attempt, receipt } => (
            receipt
                .create_failure_receipt()
                .map_err(|()| invalid_settlement())?,
            *attempt,
        ),
        _ => (None, 0),
    };
    if operation.state != OperationState::FailedBeforeCommit {
        return if receipt.is_some() {
            Err(invalid_settlement())
        } else {
            Ok(())
        };
    }

    journal.ensure_protected_authority()?;
    let receipt = receipt.ok_or_else(invalid_settlement)?;
    let floor = load_floor(journal, operation_id)?.ok_or_else(invalid_settlement)?;
    let marker = receipt.marker.fields();
    if operation.ownership_gated
        || operation.runtime_intent_digest.is_some()
        || operation.public_operation.map(|public| public.method())
            != Some(PublicOperationMethodV1::CreateExecution)
        || effect.plan.public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || marker.create_operation_id != operation_id.into_bytes()
        || receipt.successor_operation != operation_digest(operation)
        || receipt.effect_attempt != effect_attempt
        || floor.marker != receipt.marker
        || floor.archive_head != receipt.archive_head
        || floor.signed_outcome != receipt.signed_outcome
        || floor.current_host_cut != receipt.current_host_cut
        || floor.wall_seconds != receipt.wall_seconds
    {
        return Err(invalid_settlement());
    }

    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, marker.execution_id)
        .map_err(|_| invalid_settlement())?
        .ok_or_else(invalid_settlement)?;
    let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
        return Err(invalid_settlement());
    };
    let admission = recovered_public_operation_admission_v1(journal, operation_id)?
        .ok_or_else(invalid_settlement)?;
    if admission.authorization().project() != projection.project()
        || admission.authorization().resource_kind() != ResourceKind::Execution
    {
        return Err(invalid_settlement());
    }
    validate_accepted_create_identity(&effect, operation_id, execution)?;
    let expected_sequence = receipt
        .predecessor_sequence
        .checked_add(1)
        .ok_or_else(invalid_settlement)?;
    if projection.operation() != operation_id
        || projection.revision() != receipt.successor_revision
        || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_FAILED)
        || execution.observation_sequence != expected_sequence
        || execution.resource_version.as_slice() != receipt.resource_version()
        || execution.access.as_option().is_some()
        || execution.result.as_option().is_some()
        || execution
            .last_successful_reconciliation_time
            .as_option()
            .is_none_or(|time| time.seconds != receipt.wall_seconds || time.nanoseconds != 0)
    {
        return Err(invalid_settlement());
    }
    Ok(())
}

impl<E: SingleNodeEffectExecutor> Reconciler<E> {
    /// Durably anchors one exact failed-Create CAS before its terminal write.
    ///
    /// A floor left by a crash quarantines the Applying operation. Repeating
    /// this call requires fresh held-Host proof; replaying the floor alone does
    /// not create the returned settlement token.
    ///
    /// # Errors
    ///
    /// Rejects a non-Create or changed preimage, a foreign Host identity or
    /// lease cut, a conflicting floor, or uncertain journal durability.
    #[allow(dead_code, reason = "production Host lease bridge remains closed")]
    pub(crate) fn prepare_create_failed_before_commit(
        &mut self,
        operation_id: OperationId,
        proof: CreateFailureSettlementProofV1,
        wall_seconds: i64,
    ) -> Result<PreparedCreateFailureSettlementV1, ReconcilerError> {
        let plan = self.plan_create_failure(operation_id, &proof, wall_seconds)?;
        let floor = CreateFailurePrepareV1::from_plan(
            operation_id,
            &proof,
            wall_seconds,
            plan.predecessor,
            plan.successor,
        )?;
        match load_floor(&self.journal, operation_id)? {
            Some(existing) if existing == floor => {}
            Some(_) => return Err(invalid_settlement()),
            None => self.commit_records(vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation_id.into_bytes().to_vec(),
                floor.encode(),
            )])?,
        }
        if load_floor(&self.journal, operation_id)? != Some(floor) {
            return Err(invalid_settlement());
        }
        Ok(PreparedCreateFailureSettlementV1 {
            operation_id,
            proof,
            floor,
            wall_seconds,
        })
    }

    /// Commits only the three records bound by a prior Controller prepare.
    ///
    /// # Errors
    ///
    /// Rejects a changed protected preimage or floor, or uncertain durability.
    #[allow(dead_code, reason = "production Host lease bridge remains closed")]
    pub(crate) fn settle_create_failed_before_commit(
        &mut self,
        prepared: PreparedCreateFailureSettlementV1,
    ) -> Result<(), ReconcilerError> {
        let plan = self.plan_create_failure(
            prepared.operation_id,
            &prepared.proof,
            prepared.wall_seconds,
        )?;
        let rebuilt = CreateFailurePrepareV1::from_plan(
            prepared.operation_id,
            &prepared.proof,
            prepared.wall_seconds,
            plan.predecessor,
            plan.successor,
        )?;
        if rebuilt != prepared.floor
            || load_floor(&self.journal, prepared.operation_id)? != Some(prepared.floor)
        {
            return Err(invalid_settlement());
        }
        self.commit_records(plan.records.into())?;
        validate_failed_create_operation(&self.journal, prepared.operation_id, plan.operation)
    }

    fn plan_create_failure(
        &mut self,
        operation_id: OperationId,
        proof: &CreateFailureSettlementProofV1,
        wall_seconds: i64,
    ) -> Result<PlannedCreateFailureV1, ReconcilerError> {
        self.journal.ensure_protected_authority()?;
        self.ensure_ledger_validated()?;
        let operation = self.load_operation(operation_id)?;
        let marker = proof.marker().fields();
        if operation.state != OperationState::Applying
            || operation.effect_count != 1
            || operation.ownership_gated
            || operation.runtime_intent_digest.is_some()
            || operation.public_operation.map(|public| public.method())
                != Some(PublicOperationMethodV1::CreateExecution)
            || marker.create_operation_id != operation_id.into_bytes()
        {
            return Err(invalid_settlement());
        }
        let operation_bytes = self
            .journal
            .get(RecordNamespace::Operation, operation_id.as_bytes())
            .ok_or_else(invalid_settlement)?
            .to_vec();
        let effect_bytes = self
            .journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
            .ok_or_else(invalid_settlement)?
            .to_vec();
        let mut effect = decode_effect(&effect_bytes)?;
        let EffectState::Applying { attempt, .. } = effect.state else {
            return Err(invalid_settlement());
        };
        if effect.plan.public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
            || effect.dispatch.is_some()
        {
            return Err(invalid_settlement());
        }

        let projection = PublicProjectionStoreV1::new(&self.journal)
            .get(PublicProjectionKindV1::Execution, marker.execution_id)
            .map_err(|_| invalid_settlement())?
            .ok_or_else(invalid_settlement)?;
        let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
            return Err(invalid_settlement());
        };
        let admission = recovered_public_operation_admission_v1(&self.journal, operation_id)?
            .ok_or_else(invalid_settlement)?;
        if admission.authorization().project() != projection.project()
            || admission.authorization().resource_kind() != ResourceKind::Execution
        {
            return Err(invalid_settlement());
        }
        validate_accepted_create_identity(&effect, operation_id, execution)?;
        if projection.operation() != operation_id
            || execution.phase.as_known() != Some(ExecutionPhase::EXECUTION_PHASE_REQUESTED)
            || execution.result.as_option().is_some()
        {
            return Err(invalid_settlement());
        }

        let mut failed = execution.clone();
        failed.phase = ExecutionPhase::EXECUTION_PHASE_FAILED.into();
        failed.observation_sequence = failed
            .observation_sequence
            .checked_add(1)
            .ok_or_else(invalid_settlement)?;
        failed.access = None.into();
        failed.last_successful_reconciliation_time = Timestamp {
            seconds: wall_seconds,
            nanoseconds: 0,
            ..Default::default()
        }
        .into();

        let predecessor_sequence = execution.observation_sequence;
        let predecessor_revision = projection.revision();
        let operation = transition_operation(
            operation,
            OperationState::FailedBeforeCommit,
            Some(wall_seconds),
        )?;
        let pending_receipt = (*proof).into_receipt(
            predecessor_revision,
            predecessor_revision,
            operation_digest(operation),
            predecessor_sequence,
            attempt,
            wall_seconds,
        );
        failed.resource_version = pending_receipt.resource_version().to_vec();
        let successor = PublicProjectionPlanV1::new(
            projection.project(),
            operation_id,
            PublicProjectionResourceV1::Execution(failed),
        )
        .map_err(|_| invalid_settlement())?;
        let successor_revision = successor
            .checked_record()
            .map_err(|_| invalid_settlement())?
            .revision();
        let receipt = CreateFailureReceiptV1 {
            successor_revision,
            ..pending_receipt
        };
        effect.state = EffectState::Applied {
            attempt,
            receipt: EffectReceipt(receipt.encode()),
        };
        let (desired_key, desired_value) = successor.into_desired_state();
        let predecessor_desired = self
            .journal
            .get(RecordNamespace::DesiredState, &desired_key)
            .ok_or_else(invalid_settlement)?
            .to_vec();
        let records = [
            JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(operation_id, 0).to_vec(),
                encode_effect(&effect)?,
            ),
            JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(operation),
            ),
            JournalRecord::put(RecordNamespace::DesiredState, desired_key, desired_value),
        ];
        let predecessor_records = [
            JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(operation_id, 0).to_vec(),
                effect_bytes,
            ),
            JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                operation_bytes,
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                records[2].key().to_vec(),
                predecessor_desired,
            ),
        ];
        let predecessor = [
            record_digest(&predecessor_records[0])?,
            record_digest(&predecessor_records[1])?,
            record_digest(&predecessor_records[2])?,
        ];
        let successor = [
            record_digest(&records[0])?,
            record_digest(&records[1])?,
            record_digest(&records[2])?,
        ];
        Ok(PlannedCreateFailureV1 {
            operation,
            records,
            predecessor,
            successor,
        })
    }
}
