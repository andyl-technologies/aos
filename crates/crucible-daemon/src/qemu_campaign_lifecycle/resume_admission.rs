//! Exact campaign resume request admission.

use super::*;

pub(super) fn validate_exact_resume_request(
    checkpoint: ExactCheckpointId,
    basis: QemuExactResumeBasis<'_>,
    context: &AttemptExecutionContext,
) -> Result<(), QemuAttemptProductionVmLifecycleError> {
    if context.resume_checkpoint() != Some(checkpoint)
        || !context.selected_checkpoint_authorizes(checkpoint)
    {
        return Err(QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(checkpoint));
    }
    if basis.source.scenario_def() != *basis.scenario {
        return Err(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch);
    }

    Ok(())
}
