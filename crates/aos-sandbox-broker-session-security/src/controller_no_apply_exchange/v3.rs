//! Scoped original-history capture before failed-Create gate or quarantine.
//!
//! The existing accepted-Create, projection, Environment, parent, assignment,
//! output and Host-boot checks sandwich the fixed Host-session capture. This
//! child owns no request reservation, floor, signer or effect continuation.

use aos_sandbox::controller_execution_argument_attempt::{
    ControllerExecutionArgumentAttemptV1, read_historical_controller_execution_argument_attempt_v1,
};
use aos_sandbox::controller_execution_preissue::{
    load_controller_execution_output_attempt_v1, revalidate_historical_execution_preissue_source_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{EffectFailure, Journal};
use aos_sandbox_core::RawPairedClockSample;

use crate::recovery::RetainedFailedCreateOriginalsDataV3;
use crate::DormantAuthenticatedBrokerSessionV1;

/// Captures only after the original accepted operation is independently current.
///
/// The caller must complete this read before gate/quarantine/Prepare53. Failure
/// keeps that continuation closed; the result itself is only historical DATA.
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_originals_before_quarantine_v3<T>(
    session: &mut DormantAuthenticatedBrokerSessionV1,
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    source: &ControllerExecutionArgumentAttemptV1,
    clock: &mut T,
) -> Result<RetainedFailedCreateOriginalsDataV3, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    require_original_source(controller, assignment, environment, parent, source, clock)?;

    let originals = session
        .capture_failed_create_originals_v3(source)
        .map_err(|_| super::retryable("complete signed original Host histories are unavailable"))?;

    require_original_source(controller, assignment, environment, parent, source, clock)?;
    Ok(originals)
}

#[allow(clippy::too_many_arguments)]
fn require_original_source<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    source: &ControllerExecutionArgumentAttemptV1,
    clock: &mut T,
) -> Result<(), EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let output = load_controller_execution_output_attempt_v1(controller, source.execution())
        .map_err(|_| super::retryable("Controller output attempt is unavailable"))?
        .ok_or_else(|| super::retryable("Controller output attempt is absent"))?;
    revalidate_historical_execution_preissue_source_v1(
        controller,
        assignment,
        environment,
        parent,
        output.source().preissue(),
        clock,
    )
    .map_err(|_| super::retryable("accepted Controller execution source is not current"))?;

    let current = read_historical_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        source.execution(),
        source.create_operation(),
        clock,
    )
    .map_err(|_| super::retryable("Controller argument source is not current"))?;
    if current.as_ref() != Some(source) {
        return Err(super::retryable("Controller argument source changed"));
    }
    Ok(())
}
