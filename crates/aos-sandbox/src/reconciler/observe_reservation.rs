//! Admission interlock for retained Controller execution Observe identities.
//!
//! The reconciler validates the Controller's complete reservation record
//! before assigning a fresh generic Operation ID. This check does not confer
//! dispatch authority for the reserved Observe operation.

use aos_sandbox_core::OperationId;

use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
use crate::journal::{Journal, RecordNamespace};

use super::ReconcilerError;

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
