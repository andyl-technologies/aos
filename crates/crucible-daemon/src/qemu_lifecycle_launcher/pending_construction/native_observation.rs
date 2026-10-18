//! Keeps Flight operations inside the actual Main-held launcher allocation.

use super::*;
use crate::qemu_campaign_lifecycle::NativeObservationOwner;
use std::error::Error;

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: crate::QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(crate) fn prepare_native_observation_launcher(
        &mut self,
        context: &crate::AttemptExecutionContext,
        source: &crucible::ScenarioDefForm,
        config: crate::ProductionVmLifecycleConfig,
        registration: crate::qemu_campaign_lifecycle::ConfiguredParkDrainRegistration,
        terminal: Option<std::sync::Arc<crate::ExactCheckpointStore>>,
    ) -> Result<(), ()> {
        // Ordinary configuration remains local through the shared World begin.
        // Its actual launcher is already retained on every refusal. Before the
        // first Flight launch/trace/capture callback, keep config in that Box.
        self.prepare_retained_launcher(context, source, &config, registration, terminal)?;
        self.with_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>, _>(
            |launcher| {
                launcher.native_observation_config = Some(config);
            },
        )
        .map_err(|_| self.record_unavailable())
    }

    pub(crate) fn with_native_observation(
        &mut self,
        apply: &mut dyn FnMut(&mut dyn NativeObservationOwner) -> Result<(), Box<dyn Error>>,
    ) -> Result<Result<(), Box<dyn Error>>, ()> {
        if self.transferred
            || self.carrier_active
            || self.body_cleanup_complete
            || self.body_disposed
            || self.post_body_taken
            || self.history.first.is_some()
        {
            return Err(());
        }
        let observed = self
            .with_launcher::<crate::QemuAttemptProductionVmNodeLauncher<F::Guard, F>, _>(
                |launcher| {
                    launcher
                        .native_observation_config
                        .is_some()
                        .then(|| apply(launcher))
                },
            )
            .map_err(|_| self.record_unavailable())?;
        match observed {
            Some(result) => Ok(result),
            None => {
                self.record_unavailable();
                Err(())
            }
        }
    }
}
