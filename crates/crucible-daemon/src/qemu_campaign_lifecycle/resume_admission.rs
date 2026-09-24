//! Exact campaign resume request admission.

use super::*;

pub(super) fn validate_exact_resume_request(
    checkpoint: ExactCheckpointId,
    basis: QemuExactResumeBasis<'_>,
    context: &AttemptExecutionContext,
) -> Result<(), QemuAttemptProductionVmLifecycleError> {
    // The supervisor mints this non-cloneable selection only after the paused
    // ledger root advances to a running execution. It is the launch authority;
    // replay evidence in the immutable checkpoint is only the restore proof.
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
