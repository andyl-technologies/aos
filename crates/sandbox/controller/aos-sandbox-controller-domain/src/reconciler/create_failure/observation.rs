//! Lends one actual historical owner to the sole failed-Create DATA reducer.
//!
//! Native floor, purpose, currentness and receiving checks remain with their
//! genuine owners. These adapters neither adopt rows nor mint a commit grant.

use super::*;
use crate::journal::historical_observation::HistoricalObservationV1;
use aos_sandbox_protocol::domain_ledger::create_failure as data;

pub(crate) fn historical_data_v2(
    observation: HistoricalObservationV1<'_>,
) -> Result<data::CreateFailureHistoricalDataV2<'_>, ReconcilerError> {
    let (poisoned, protected) = observation.historical_status_data_v2()?;
    Ok(data::CreateFailureHistoricalDataV2::new_data_v2(
        observation.rows_data_v2(), poisoned, protected,
    ))
}

/// Prices the sole reducer from the same actual immutable owner.
pub(crate) fn closed_create_failure_receiving_demand_from_observation_v2(
    observation: HistoricalObservationV1<'_>,
) -> Result<aos_sandbox_model::ResourceVector,
    crate::controller_resource_reservation::ResourceReservationErrorV1> {
    use crate::controller_resource_reservation::ResourceReservationErrorV1 as Error;
    let native = data::closed_create_failure_receiving_demand_data_v2(observation.rows_data_v2())
        .map_err(|error| match error {
            data::CreateFailureGeometryErrorV2::Frame(error) => Error::Journal(crate::JournalError::from(error)),
            data::CreateFailureGeometryErrorV2::Overflow => Error::Conflict,
        })?;
    let controls = upper_interface_control_bytes_v2().ok_or(Error::Conflict)?;
    native.checked_add(aos_sandbox_model::ResourceVector::ZERO.with(
        aos_sandbox_model::ResourceDimension::MemoryBytes,
        u64::try_from(controls).map_err(|_| Error::Conflict)?,
    )).map_err(Error::from)

}

/// Recomputes the exact row relation without granting native settlement.
pub(crate) fn plan_closed_create_failure_rows_from_observation_v2(
    observation: HistoricalObservationV1<'_>,
    marker: aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2,
    terminal_archive: ObjectDigest,
    signed_terminal: ObjectDigest,
    wall_seconds: i64,
) -> Result<ClosedCreateFailurePlanDataV2, ReconcilerError> {
    let historical = historical_data_v2(observation)?;
    data::plan_closed_create_failure_rows_data_v2(
        &historical, marker, terminal_archive, signed_terminal, wall_seconds,
    ).map_err(ReconcilerError::from)
}

/// Validates either historical terminal grammar over the same actual owner.
pub(crate) fn validate_failed_create_operation_from_observation_v2(
    observation: HistoricalObservationV1<'_>,
    operation_id: OperationId,
    operation: OperationRecord,
) -> Result<(), ReconcilerError> {
    let historical = historical_data_v2(observation)?;
    data::validate_failed_create_operation(&historical, operation_id, operation)
        .map_err(ReconcilerError::from)
}

impl From<data::CreateFailureDataErrorV2> for ReconcilerError {
    fn from(error: data::CreateFailureDataErrorV2) -> Self {
        match error {
            data::CreateFailureDataErrorV2::InvalidSettlement => invalid_settlement(),
            data::CreateFailureDataErrorV2::CorruptLedger(reason) => Self::CorruptLedger(reason),
            data::CreateFailureDataErrorV2::OperationNotFound => Self::OperationNotFound,
            data::CreateFailureDataErrorV2::Poisoned => crate::JournalError::Poisoned.into(),
            data::CreateFailureDataErrorV2::ProtectedBoundary => crate::JournalError::ProtectedBoundary.into(),
            data::CreateFailureDataErrorV2::PublicOperation(error) => error.into(),
            data::CreateFailureDataErrorV2::Effect(error) => error.into(),
        }
    }
}

fn upper_interface_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    type Observation = HistoricalObservationV1<'static>;
    type Historical = data::CreateFailureHistoricalDataV2<'static>;
    type Plan = data::ClosedCreateFailurePlanDataV2;
    type Error = crate::controller_resource_reservation::ResourceReservationErrorV1;
    let snapshot = size_of::<Observation>()
        .checked_add(size_of::<Result<Historical, ReconcilerError>>().checked_mul(3)?)?;
    let planner = size_of::<(Observation,
        aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2,
        ObjectDigest, ObjectDigest, i64)>()
        .checked_add(size_of::<Result<Plan, ReconcilerError>>().checked_mul(3)?)?;
    let terminal = size_of::<(Observation, OperationId, OperationRecord)>()
        .checked_add(size_of::<Result<(), ReconcilerError>>().checked_mul(3)?)?;
    let receiving = size_of::<Observation>()
        .checked_add(size_of::<Result<aos_sandbox_model::ResourceVector, Error>>().checked_mul(3)?)?;
    let projection = size_of::<data::CreateFailureDataErrorV2>().checked_mul(2)?
        .checked_add(size_of::<ReconcilerError>().checked_mul(3)?)?;
    snapshot.checked_add(planner)?.checked_add(terminal)?
        .checked_add(receiving)?.checked_add(projection)
}
