//! Computes the sole exact three-row failed-Create relation.

use super::*;

/// Retains the computed predecessor and exact three successor row DATA.
pub struct PlannedCreateFailureV1 {
    /// Names the computed successor operation.
    pub operation: OperationRecord,
    /// Retains Effect, Operation and DesiredState successors in original order.
    pub records: [JournalRecord; 3],
    /// Commits the three original row encodings.
    pub predecessor: [ObjectDigest; 3],
    /// Commits the three computed row encodings.
    pub successor: [ObjectDigest; 3],
}

/// Retains the complete closed historical row relation without native grants.
pub struct ClosedCreateFailurePlanDataV2 {
    identity: ClosedCreateFailureIdentityDataV2,
    wall_seconds: i64,
    plan: PlannedCreateFailureV1,
    prepared: Option<ClosedCreateFailurePrepareDataV2>,
    settled: bool,
}

impl ClosedCreateFailurePlanDataV2 {
    /// Returns the accepted Create operation identity.
    pub fn operation_data_v2(&self) -> OperationId {
        OperationId::from_bytes(
            self.identity
                .marker
                .fields()
                .source
                .fields()
                .create_operation,
        )
    }

    /// Returns the canonical closed-before-argument marker DATA.
    pub fn marker_data_v2(&self) -> ClosedBeforeArgumentNoApplyRecordV2 {
        self.identity.marker
    }

    /// Returns the historical terminal archive commitment.
    pub fn terminal_archive_data_v2(&self) -> ObjectDigest {
        self.identity.terminal_archive
    }

    /// Returns the historical signed terminal commitment.
    pub fn signed_terminal_data_v2(&self) -> ObjectDigest {
        self.identity.signed_terminal
    }

    /// Returns the wall coordinate used by the terminal row relation.
    pub fn wall_seconds_data_v2(&self) -> i64 {
        self.wall_seconds
    }

    /// Returns the three predecessor and successor row commitments.
    pub fn row_digests_data_v2(&self) -> ([[u8; 32]; 3], [[u8; 32]; 3]) {
        (
            self.plan.predecessor.map(|digest| *digest.as_bytes()),
            self.plan.successor.map(|digest| *digest.as_bytes()),
        )
    }

    /// Borrows the exact three planned successor encodings.
    pub fn records_data_v2(&self) -> &[JournalRecord; 3] {
        &self.plan.records
    }

    /// Borrows only the actual captured C prepare's immutable Root reference.
    pub fn prepared_root_reference_data_v2(&self) -> Option<(ObjectDigest, u64)> {
        self.prepared
            .map(|prepared| (prepared.root_floor, prepared.root_sequence))
    }

    /// Borrows the canonical prepare independently decoded from actual C.
    /// This is historical comparison DATA, never a fresh append or lease grant.
    pub fn prepared_data_v2(&self) -> Option<ClosedCreateFailurePrepareDataV2> {
        self.prepared
    }

    /// Reports an independently validated exact three-row terminal relation.
    /// A missing prepare or a partially changed terminal cannot produce `true`.
    pub fn settled_data_v2(&self) -> bool {
        self.settled
    }
}

/// Computes either exact three-row failed-Create successor relation.
///
/// # Errors
/// Preserves diagnostic protection/health and canonical row decoder causes.
pub fn plan_create_failure_rows_data_v2(
    journal: &CreateFailureHistoricalDataV2<'_>, operation_id: OperationId, identity: CreateFailurePlanIdentityV2<'_>, wall_seconds: i64,
) -> Result<PlannedCreateFailureV1, CreateFailureDataErrorV2> {
    identity.require_identity_data_v2()?;
    journal.ensure_protected_authority()?;
    identity.require_current_journal_data_v2(journal)?;
    let operation = load_operation(journal, operation_id)?;
    let (create_operation, execution_id) = identity.target_data_v2();
    if operation.state() != OperationState::Applying
        || operation.effect_count() != 1
        || operation.ownership_gated()
        || operation.runtime_intent_digest().is_some()
        || operation.public_operation().map(|public| public.method())
            != Some(PublicOperationMethodV1::CreateExecution)
        || create_operation != operation_id.into_bytes()
    {
        return Err(invalid_settlement());
    }
    let operation_bytes = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or_else(invalid_settlement)?
        .to_vec();
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or_else(invalid_settlement)?
        .to_vec();
    let mut effect = decode_effect(&effect_bytes).map_err(CreateFailureDataErrorV2::from)?;
    let EffectState::Applying { attempt, .. } = *effect.state() else {
        return Err(invalid_settlement());
    };
    if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
        || effect.dispatch().is_some()
    {
        return Err(invalid_settlement());
    }

    let projection = PublicProjectionStoreV1::new(journal)
        .get(PublicProjectionKindV1::Execution, execution_id)
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
    let pending_receipt = identity.receipt_data_v2(
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
    let receipt = pending_receipt.with_successor_revision_v2(successor_revision);
    let state = EffectState::Applied {
        attempt,
        receipt: EffectReceipt::from_bytes_unchecked(receipt.encode()),
    };
    effect = {
        // Keep the original mutable binding and replace only its state.
        // The old state dies before the remaining fields are reassembled.
        let mut parts = effect.into_parts();
        parts.1 = state;
        crate::domain_ledger::effect_history::EffectLedgerRecord::from_parts(
            parts,
        )
    };
    let (desired_key, desired_value) = successor.into_desired_state();
    let predecessor_desired = journal
        .get(RecordNamespace::DesiredState, &desired_key)
        .ok_or_else(invalid_settlement)?
        .to_vec();
    let records = [
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, 0).to_vec(),
            encode_effect(&effect).map_err(CreateFailureDataErrorV2::from)?,
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

pub fn plan_closed_create_failure_rows_data_v2(
    journal: &CreateFailureHistoricalDataV2<'_>,
    marker: ClosedBeforeArgumentNoApplyRecordV2,
    terminal_archive: ObjectDigest,
    signed_terminal: ObjectDigest,
    wall_seconds: i64,
) -> Result<ClosedCreateFailurePlanDataV2, CreateFailureDataErrorV2> {
    let identity = ClosedCreateFailureIdentityDataV2 {
        marker,
        terminal_archive,
        signed_terminal,
    };
    let operation = OperationId::from_bytes(marker.fields().source.fields().create_operation);
    let prepared = journal
        .get(
            RecordNamespace::ControllerCreateFailurePrepare,
            operation.as_bytes(),
        )
        .map(|bytes| {
            ClosedCreateFailurePrepareDataV2::decode_canonical(operation.as_bytes(), bytes)
                .map_err(|_| invalid_settlement())
        })
        .transpose()?;

    // A cold cleanup must not try to replay the Applying reducer over already
    // terminal rows. The sole existing terminal validator checks the receipt,
    // accepted request and all three actual digests against the stored prepare.
    let current = load_operation(journal, operation)?;
    let settled = current.state() == OperationState::FailedBeforeCommit;
    let plan = if settled {
        let prepared = prepared.ok_or_else(invalid_settlement)?;
        let bytes = journal
            .get(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation.as_bytes(),
            )
            .ok_or_else(invalid_settlement)?;
        validate_floor_v2(journal, operation.as_bytes(), bytes)?;
        PlannedCreateFailureV1 {
            operation: current,
            records: super::validation::actual_records_data_v2(journal, prepared)?,
            predecessor: prepared.predecessor,
            successor: prepared.successor,
        }
    } else {
        plan_create_failure_rows_data_v2(
            journal,
            operation,
            CreateFailurePlanIdentityV2::ClosedBeforeArgument(&identity),
            wall_seconds,
        )?
    };
    if prepared.is_some_and(|prepared| {
        prepared.identity != identity
            || prepared.wall_seconds != wall_seconds
            || prepared.predecessor != plan.predecessor
            || prepared.successor != plan.successor
    }) {
        return Err(invalid_settlement());
    }
    Ok(ClosedCreateFailurePlanDataV2 {
        identity,
        wall_seconds,
        plan,
        prepared,
        settled,
    })
}

pub(super) fn require_accepted_request_digest_data_v2(
    journal: &CreateFailureHistoricalDataV2<'_>,
    marker: ClosedBeforeArgumentNoApplyRecordV2,
) -> Result<(), CreateFailureDataErrorV2> {
    let source = marker.fields().source.fields();
    let operation = OperationId::from_bytes(source.create_operation);
    let view = journal.historical_read_view_v1();
    let mut matched = false;
    // The existing native replay built this SAME complete canonical index.
    // Borrow its typed decisions; no second idempotency decoder/map is built.
    for (key, _) in journal.records(RecordNamespace::Idempotency) {
        let decision = view
            .idempotency_decision_data_v2(key)
            .ok_or_else(invalid_settlement)?;
        if decision.operation_id != operation {
            continue;
        }
        if matched || decision.request_digest != source.accepted_request_digest {
            return Err(invalid_settlement());
        }
        matched = true;
    }
    if matched {
        Ok(())
    } else {
        Err(invalid_settlement())
    }
}
