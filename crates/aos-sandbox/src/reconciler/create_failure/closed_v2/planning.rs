//! Lends exact closed-Create row DATA from the sole Controller/Root reducer.
//!
//! Actual callers independently prepay the complete canonical models and retain
//! their native C reader/receiving owner. These rows and digests grant no append,
//! current Host lease, Root floor or permission to settle a Controller journal.

use super::*;

/// Retains one canonical planned relation while the actual native owner is held.
pub(crate) struct ClosedCreateFailurePlanDataV2 {
    identity: ClosedCreateFailureIdentityDataV2,
    wall_seconds: i64,
    plan: super::super::PlannedCreateFailureV1,
    prepared: Option<ClosedCreateFailurePrepareDataV2>,
    settled: bool,
}

impl ClosedCreateFailurePlanDataV2 {
    /// Prices the complete existing reducer before it copies or decodes rows.
    ///
    /// Native replay owns the canonical index already. This pays the additional
    /// Effect graph, public authorization/projections, six row buffers and
    /// receipt/encoding growth; it creates no namespace metadata or native FD.
    pub(crate) fn receiving_demand_data_v2(
        journal: &Journal,
    ) -> Result<
        aos_sandbox_core::ResourceVector,
        crate::controller_resource_reservation::ResourceReservationErrorV1,
    > {
        use crate::controller_resource_reservation::ResourceReservationErrorV1 as Error;
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use std::mem::size_of;

        let accepted =
            crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(journal)?;
        let memory = (|| {
            let mut rows = 0_usize;
            let mut effect_width = 0_usize;
            for namespace in [
                RecordNamespace::Effect,
                RecordNamespace::Operation,
                RecordNamespace::DesiredState,
            ] {
                let maximum = journal
                    .records(namespace)
                    .try_fold(0_usize, |maximum, (key, value)| {
                        Some(maximum.max(key.len().checked_add(value.len())?))
                    })?;
                rows = rows.checked_add(maximum)?;
                if namespace == RecordNamespace::Effect {
                    effect_width = maximum;
                }
            }
            let effect = aos_sandbox_protocol::domain_ledger::effect_history::
                effect_decoding_receiving_bytes_v1(effect_width)?;
            let projections = crate::controller_service::public_projection::
                execution_source_receiving_bytes_v1(journal)?
                .checked_add(crate::controller_service::public_projection::
                    sandbox_source_receiving_bytes_v1(journal)?)?
                .checked_add(crate::controller_service::public_projection::
                    metadata_source_receiving_bytes_v2(journal)?)?;
            let authorization = aos_sandbox_protocol::domain_ledger::public_operation::
                PublicOperationAuthorizationV1::maximum_receiving_bytes_v1();
            // Three old/new row pairs coexist with decoder inputs and growing
            // canonical outputs. Four complete pairs cover those destinations.
            let row_buffers = rows.checked_mul(2)?.checked_mul(4)?;
            let receipt_buffers = RECEIPT_BYTES_V2.checked_mul(4)?;
            let prepare_buffers = aos_sandbox_protocol::host_execution_no_apply::closed_controller::CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2.checked_mul(3)?;
            let carriers = size_of::<Self>()
                .checked_mul(2)?
                .checked_add(size_of::<JournalRecord>().checked_mul(6)?)?;
            let bytes = accepted
                .checked_add(effect)?
                .checked_add(authorization)?
                .checked_add(row_buffers)?
                .checked_add(receipt_buffers)?
                .checked_add(prepare_buffers)?
                .checked_add(carriers)?;
            u64::try_from(bytes).ok()?.checked_add(projections)
        })()
        .ok_or(Error::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
    }

    pub(crate) fn operation_data_v2(&self) -> OperationId {
        OperationId::from_bytes(
            self.identity
                .marker
                .fields()
                .source
                .fields()
                .create_operation,
        )
    }

    pub(crate) fn marker_data_v2(&self) -> ClosedBeforeArgumentNoApplyRecordV2 {
        self.identity.marker
    }

    pub(crate) fn terminal_archive_data_v2(&self) -> ObjectDigest {
        self.identity.terminal_archive
    }

    pub(crate) fn signed_terminal_data_v2(&self) -> ObjectDigest {
        self.identity.signed_terminal
    }

    pub(crate) fn wall_seconds_data_v2(&self) -> i64 {
        self.wall_seconds
    }

    pub(crate) fn row_digests_data_v2(&self) -> ([[u8; 32]; 3], [[u8; 32]; 3]) {
        (
            self.plan.predecessor.map(|digest| *digest.as_bytes()),
            self.plan.successor.map(|digest| *digest.as_bytes()),
        )
    }

    pub(crate) fn records_data_v2(&self) -> &[JournalRecord; 3] {
        &self.plan.records
    }

    /// Borrows only the actual captured C prepare's immutable Root reference.
    pub(crate) fn prepared_root_reference_data_v2(&self) -> Option<(ObjectDigest, u64)> {
        self.prepared
            .map(|prepared| (prepared.root_floor, prepared.root_sequence))
    }

    /// Borrows the canonical prepare independently decoded from actual C.
    /// This is historical comparison DATA, never a fresh append or lease grant.
    pub(crate) fn prepared_data_v2(&self) -> Option<ClosedCreateFailurePrepareDataV2> {
        self.prepared
    }

    /// Reports an independently validated exact three-row terminal relation.
    /// A missing prepare or a partially changed terminal cannot produce `true`.
    pub(crate) fn settled_data_v2(&self) -> bool {
        self.settled
    }
}

/// Shares the existing reducer over the actual independently paid native C.
///
/// # Errors
/// Rejects a changed Create/Requested preimage, accepted request digest, exact
/// terminal identity or invalid canonical Effect/Operation/projection relation.
pub(crate) fn plan_closed_create_failure_rows_data_v2(
    journal: &Journal,
    marker: ClosedBeforeArgumentNoApplyRecordV2,
    terminal_archive: ObjectDigest,
    signed_terminal: ObjectDigest,
    wall_seconds: i64,
) -> Result<ClosedCreateFailurePlanDataV2, ReconcilerError> {
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
    let current = crate::reconciler::core_journal::readonly::load_operation(journal, operation)?;
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
        super::super::PlannedCreateFailureV1 {
            operation: current,
            records: actual_records_data_v2(journal, prepared)?,
            predecessor: prepared.predecessor,
            successor: prepared.successor,
        }
    } else {
        super::super::plan_create_failure_rows_data_v2(
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
    journal: &Journal,
    marker: ClosedBeforeArgumentNoApplyRecordV2,
) -> Result<(), ReconcilerError> {
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
