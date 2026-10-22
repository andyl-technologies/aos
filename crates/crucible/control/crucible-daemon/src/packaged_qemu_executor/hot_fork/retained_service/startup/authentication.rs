//! Retains one authentication Original in the same prepaid Service phase.
//!
//! Callers exchange selectors and scoped projections. The actual guard remains
//! here through publication, World admission, postcheck and final destruction.

use super::*;

impl RetainedServiceStart {
    /// Enters the caller's existing authentication class once after admission.
    pub(crate) fn begin_authentication_original(
        &mut self,
        class: crucible_host_resources::host_supervision::HostOperationClass,
    ) -> Result<(), RetainedServiceStartRefusal> {
        if self.authentication_original.is_some()
            || self.authentication_completion_attempted
            || self.first.is_some()
        {
            return Err(RetainedServiceStartRefusal);
        }
        let result = (|| {
            let service = self.ready().ok_or(HostOperationalError::Unavailable)?;
            service
                .context()
                .host_operation_supervisor()
                .ok_or(HostOperationalError::Unavailable)?
                .begin(class)
                .map_err(|source| HostOperationalError::OriginalBoundary { source })
        })();
        match result {
            Ok(original) => {
                self.authentication_original = Some(original);
                self.check_authentication_original()
            }
            Err(first) => Err(self.refuse(first.into())),
        }
    }

    /// Checks the same live authentication Original without lending its body.
    pub(crate) fn check_authentication_original(
        &mut self,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let first = self
            .authentication_original
            .as_ref()
            .ok_or(crucible_host_resources::host_supervision::HostSupervisionError::Unavailable)
            .and_then(|original| original.wait_slice().map(|_| ()));
        first.map_err(|first| {
            if let ServiceStartPhase::Ready(service) = &self.phase {
                service.context().cancellation().cancel();
            }
            self.record_external_supervision(first);
            RetainedServiceStartRefusal
        })
    }

    /// Consumes the selected root only under the same retained Restore.
    pub(crate) fn bind_debug_from_saved_original(
        &mut self,
        checkpoint: crucible_campaign::ExactCheckpointId,
        selected: &mut Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let original = self
            .authentication_original
            .take()
            .ok_or(RetainedServiceStartRefusal)?;
        let result = self.bind_authenticated_finding_debug(checkpoint, selected, &original);
        self.authentication_original = Some(original);
        result
    }

    /// Completes this exact original once and retains its independent status.
    pub(crate) fn complete_authentication_original(
        &mut self,
    ) -> Result<(), RetainedServiceStartRefusal> {
        let original = self
            .authentication_original
            .as_ref()
            .ok_or(RetainedServiceStartRefusal)?;
        if !self.authentication_completion_attempted {
            self.authentication_completion_attempted = true;
            self.authentication_completion = original.complete().err();
        }
        let post = original.status().err();
        if self.projection_post.is_none() {
            self.projection_post = post;
        }
        if let Some(first) = self.authentication_completion.or(post) {
            self.record_external_supervision(first);
            return Err(RetainedServiceStartRefusal);
        }
        Ok(())
    }
}
