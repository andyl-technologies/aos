//! Connects imported campaigns to the actual owned executor before retirement.
//!
//! Required settings are decoded through the closed workflow profile. Each
//! preborn coordinator is installed in the already-paid model slot before
//! command or driver effects, and remains there on every error or unwind.

use super::*;
use crucible::owned_decode::json_profiles::workflow::WorkflowProjection;

impl OriginalWorkflowArtifactsOwner {
    /// Drives every actually created campaign through the same original factory.
    ///
    /// # Errors
    /// Preserves malformed settings, missing actual requests/creation responses,
    /// original admission, authorization or typed driver refusal. Partial work
    /// retains its actual model, coordinator, commands and factory aliases.
    pub(in crate::private_measurement_runtime::workflow) fn execute_campaigns(
        &mut self,
        bytes: &[u8],
        service: &OriginalPreparedCampaignServiceOwner,
        executor: &crate::private_measurement_runtime::OriginalPreparedPackagedExecutor<'_>,
    ) -> Result<(), OriginalWorkflowArtifactsError> {
        let original = || service.verify_original();
        let mut failure = ArtifactFailurePurpose::prepare(&self.budget, &original)?;
        let result = {
            let check = failure.work(&original);
            let work = (|| {
                check.verify_original()?;
                self.budget.verify_live()?;
                if self.closed {
                    return Err(ArtifactCause::Identity);
                }
                let _scope = self.budget.enter();
                let workflow: WorkflowProjection<'_> = from_json_slice_closed(bytes, &self.budget)?;
                let settings = workflow
                    .service_profile
                    .operator
                    .executor
                    .campaign_execution;
                for model in &mut self.models {
                    check.verify_original()?;
                    self.budget.verify_live()?;
                    if model.response.is_none() || model.coordinator.is_some() {
                        return Err(ArtifactCause::Identity);
                    }
                    let request = model.request.as_ref().ok_or(ArtifactCause::Identity)?;
                    model.coordinator = Some(
                        crate::campaign_bootstrap::OriginalCampaignCoordinator::prepare(
                            &self.budget,
                        )?,
                    );
                    let coordinator = model.coordinator.as_mut().ok_or(ArtifactCause::Identity)?;
                    coordinator.execute(service, executor, request, settings, &self.budget)?;
                    // Actual driver/command bodies are freed before their
                    // original receipt. Failed work never takes this close.
                    coordinator.try_close()?;
                    drop(model.coordinator.take());
                    check.verify_original()?;
                    self.budget.verify_live()?;
                }
                Ok(())
            })();
            checked(&check, work)
        };
        failure.finish(result)
    }
}
