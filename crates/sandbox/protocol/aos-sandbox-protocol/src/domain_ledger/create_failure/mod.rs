//! Computes exact failed-Create row DATA over one immutable historical view.
//!
//! The diagnostic status bits reproduce the original CPU checks at their old
//! positions. Neither those bits, supplied rows nor a planned relation grants
//! a native owner, role, floor, receiving account or commit permission. Actual
//! native consumers retain their original custody and recompute this relation.

mod receipt;
mod planning;
mod validation;
mod prepare;
mod geometry;
mod controls;
pub use controls::interface_control_bytes_data_v2;

pub use receipt::{CreateFailureReceiptV1, ClosedCreateFailureReceiptV2, CreateFailureReceiptDataV2, CreateFailurePlanIdentityV2, AfterArgumentCreateFailureIdentityDataV1};
pub use planning::{ClosedCreateFailurePlanDataV2, PlannedCreateFailureV1, plan_create_failure_rows_data_v2, plan_closed_create_failure_rows_data_v2};
pub use prepare::{CreateFailurePrepareV1, load_floor, validate_all_floors};
pub use geometry::{CreateFailureGeometryErrorV2, accepted_effect_models_receiving_bytes_v4, closed_create_failure_receiving_demand_data_v2};
pub use validation::{validate_failed_create_operation, validate_failed_operation_v2, validate_floor_v2};

use aos_sandbox_api::aos::sandbox::v1::{ExecutionPhase, Timestamp};
use aos_sandbox_model::{ObjectDigest, OperationId, ResourceKind, RecordNamespace};
use crate::domain_ledger::operation::{OperationRecord, decode_operation, encode_operation_record, effect_key};
use crate::domain_ledger::public_operation::{OperationState, PublicOperationDataError, PublicOperationAdmissionV1, PublicOperationAuthorizationV1};
use crate::domain_ledger::effect_history::{EffectReceipt, EffectState, decode_effect, encode_effect, EffectHistoryDataError};
use crate::domain_ledger::transaction::JournalRecord;
use crate::host_execution_no_apply::{HostExecutionNoApplyRecordV1, ClosedBeforeArgumentNoApplyRecordV2, HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1, BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2};
use crate::host_execution_no_apply::closed_controller::{ClosedCreateFailureIdentityDataV2, ClosedCreateFailurePrepareDataV2};
use crate::public_api::PublicOperationMethodV1;
use crate::public_api::projection::{PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1};
use aos_sandbox_model::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};

/// Reports only representation and diagnostic historical failures.
#[derive(Debug, thiserror::Error)]
pub enum CreateFailureDataErrorV2 {
    /// The exact three-record relation or its immutable identity differs.
    #[error("failed-Create settlement is not an exact three-record cut")]
    InvalidSettlement,
    /// The canonical admission record is malformed.
    #[error("corrupt ledger: {0}")]
    CorruptLedger(&'static str),
    /// The retained operation row is absent.
    #[error("operation is absent from the durable ledger")]
    OperationNotFound,
    /// The same historical owner was poisoned at the diagnostic snapshot.
    #[error("journal handle is poisoned and must be reopened")]
    Poisoned,
    /// The same historical owner had no protected provenance.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// Preserves the canonical public-operation decoder or transition cause.
    #[error(transparent)]
    PublicOperation(#[from] PublicOperationDataError),
    /// Preserves the canonical Effect decoder or encoder cause.
    #[error(transparent)]
    Effect(#[from] EffectHistoryDataError),
}

/// Borrows historical rows and nonauthorizing diagnostic state from one cut.
#[derive(Clone, Copy)]
pub struct CreateFailureHistoricalDataV2<'rows> {
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'rows>,
    poisoned: bool,
    protected: bool,
}

impl<'rows> CreateFailureHistoricalDataV2<'rows> {
    /// Assembles diagnostic DATA without adopting storage or granting a role.
    pub const fn new_data_v2(
        rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'rows>,
        poisoned: bool,
        protected: bool,
    ) -> Self {
        Self { rows, poisoned, protected }
    }

    fn ensure_healthy(&self) -> Result<(), CreateFailureDataErrorV2> {
        if self.poisoned {
            Err(CreateFailureDataErrorV2::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_protected_authority(&self) -> Result<(), CreateFailureDataErrorV2> {
        self.ensure_healthy()?;
        if !self.protected {
            return Err(CreateFailureDataErrorV2::ProtectedBoundary);
        }
        Ok(())
    }

    fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        self.rows.get_data_v2(namespace, key)
    }

    fn records(&self, namespace: RecordNamespace)
        -> impl Iterator<Item = (&'rows [u8], &'rows [u8])> + 'rows + use<'rows> {
        self.rows.records_data_v2(namespace)
    }

    fn historical_read_view_v1(&self)
        -> crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'rows> { self.rows }
}

fn invalid_settlement() -> CreateFailureDataErrorV2 { CreateFailureDataErrorV2::InvalidSettlement }

struct PublicProjectionStoreV1<'view, 'rows> { journal: &'view CreateFailureHistoricalDataV2<'rows> }

impl<'view, 'rows> PublicProjectionStoreV1<'view, 'rows> {
    fn new(journal: &'view CreateFailureHistoricalDataV2<'rows>) -> Self { Self { journal } }

    fn get(&self, kind: PublicProjectionKindV1, resource_id: [u8; 16])
        -> Result<Option<crate::public_api::projection::PublicProjectionRecordV1>, crate::public_api::projection::PublicProjectionError> {
        use crate::public_api::projection::PublicProjectionError;
        crate::checked_public_projection_read_data_v1! {
            kind = kind, resource_id = resource_id,
            invalid_identity = PublicProjectionError::InvalidIdentity,
            healthy = { self.journal.ensure_healthy().map_err(|_| PublicProjectionError::CorruptRecord)?; },
            key = key,
            read = self.journal.get(RecordNamespace::DesiredState, &key),
            output = projection
        }
        Ok(projection)
    }
}

fn operation_digest(operation: OperationRecord) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(encode_operation_record(operation)).into())
}

fn desired_execution_key(
    journal: &CreateFailureHistoricalDataV2<'_>,
    execution_id: [u8; 16],
) -> Result<Vec<u8>, CreateFailureDataErrorV2> {
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
    effect: &crate::domain_ledger::effect_history::EffectLedgerRecord,
    operation_id: OperationId,
    execution: &aos_sandbox_api::aos::sandbox::v1::Execution,
) -> Result<(), CreateFailureDataErrorV2> {
    let context = effect
        .plan()
        .public_mutation_context()
        .map_err(CreateFailureDataErrorV2::from)?
        .ok_or_else(invalid_settlement)?;
    let crate::public_api::request::DormantSandboxRequestKindV1::Exec(request) =
        context.validated_request().map_err(CreateFailureDataErrorV2::from)?
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

 fn load_operation(
        journal: &CreateFailureHistoricalDataV2<'_>,
        operation_id: OperationId,
    ) -> Result<OperationRecord, CreateFailureDataErrorV2> {
    crate::historical_operation_read_data_v2! {
        read = journal.get(RecordNamespace::Operation, operation_id.as_bytes()),
        missing = CreateFailureDataErrorV2::OperationNotFound,
        project = CreateFailureDataErrorV2::from
    }
}

fn recovered_public_operation_admission_v1(
    journal: &CreateFailureHistoricalDataV2<'_>,
    operation_id: OperationId,
) -> Result<Option<PublicOperationAdmissionV1>, CreateFailureDataErrorV2> {
    use crate::domain_ledger::create_admission::CreateAdmissionDataErrorV1 as AdmissionError;
    crate::domain_ledger::create_admission::recovered_public_operation_admission_from_rows_v1(
        journal.historical_read_view_v1(), operation_id,
    ).map_err(|error| match error {
        AdmissionError::InvalidPlan(reason) => CreateFailureDataErrorV2::PublicOperation(PublicOperationDataError::InvalidPlan(reason)),
        AdmissionError::CorruptLedger(reason) => CreateFailureDataErrorV2::CorruptLedger(reason),
        AdmissionError::InvalidExecutorOutput(reason) => CreateFailureDataErrorV2::Effect(EffectHistoryDataError::InvalidExecutorOutput(reason)),
        AdmissionError::PublicOperationClock => CreateFailureDataErrorV2::PublicOperation(PublicOperationDataError::PublicOperationClock),
        AdmissionError::PublicOperationSequenceExhausted => CreateFailureDataErrorV2::PublicOperation(PublicOperationDataError::PublicOperationSequenceExhausted),
    })
}

fn transition_operation(
    operation: OperationRecord,
    state: OperationState,
    wall_seconds: Option<i64>,
) -> Result<OperationRecord, CreateFailureDataErrorV2> {
    let public_operation = operation
        .public_operation()
        .map(|public| {
            let wall_seconds = wall_seconds.ok_or(CreateFailureDataErrorV2::PublicOperation(PublicOperationDataError::PublicOperationClock))?;
            public.advance(state, wall_seconds).map_err(CreateFailureDataErrorV2::from)
        })
        .transpose()?;

    Ok(operation.with_state_and_public_operation(state, public_operation))
}

fn record_digest(record: &JournalRecord) -> Result<ObjectDigest, CreateFailureDataErrorV2> {
    let value = record.value().ok_or_else(invalid_settlement)?;
    let key_len = u64::try_from(record.key().len()).map_err(|_| invalid_settlement())?;
    let value_len = u64::try_from(value.len()).map_err(|_| invalid_settlement())?;
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update([record.namespace() as u8])
            .chain_update(key_len.to_be_bytes())
            .chain_update(record.key())
            .chain_update(value_len.to_be_bytes())
            .chain_update(value)
            .finalize()
            .into(),
    ))
}

const RECORD_DOMAIN: &[u8] = b"aos.sandbox.create-failure-prepare-record.v1\0";
/// Recognizes either canonical failed-Create receipt grammar.
///
/// # Errors
/// Refuses a malformed recognized receipt or an unknown special version.
pub fn has_special_receipt_data_v2(bytes: &[u8]) -> Result<bool, ()> {
    CreateFailureReceiptDataV2::decode(bytes).map(|value| value.is_some())
}
