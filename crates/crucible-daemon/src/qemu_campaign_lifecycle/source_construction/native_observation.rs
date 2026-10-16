//! Lends native observations from the exact Main-held Source launcher.
//!
//! A driver borrows operations from the existing factory cell. The same Box,
//! saved Originals, body loan and reservation stay there until publication to
//! Main cleanup; a panic or semantic failure cannot drop a local owner.

use super::*;
use crate::qemu_lifecycle_launcher::ObservedNativeNode;
use std::error::Error;
use std::io::BufRead;

/// Exposes operations, never a movable backend guard or an admission recipe.
pub(crate) trait NativeObservationOwner: ProductionVmNodeLauncher {
    fn launch_observation(
        &mut self,
        node: &crucible::NodeId,
        profile: &crucible_qemu::QemuLiveNodeStepGateConfig,
        router: &str,
        crash: &str,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError>;

    fn borrow_observation<'a>(
        &'a mut self,
        context: &'a AttemptExecutionContext,
    ) -> Result<ObservedNativeNode<'a>, LifecycleApiError>;

    fn inspect_trace(
        &self,
        node: &crucible::NodeId,
        generation: u64,
        maximum_bytes: u64,
        inspect: &mut dyn FnMut(&mut dyn BufRead) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>>;

    fn liveness_tail(
        &self,
        node: &crucible::NodeId,
        generation: u64,
    ) -> Result<String, Box<dyn Error>>;

    fn into_cleanup(self: Box<Self>) -> Box<dyn ProductionVmNodeLauncher>;
}

impl<G, F> NativeObservationOwner for QemuAttemptProductionVmNodeLauncher<G, F>
where
    G: QemuAttemptProcessResourceGuard + Send + 'static,
    F: Send + 'static,
{
    fn launch_observation(
        &mut self,
        node: &crucible::NodeId,
        profile: &crucible_qemu::QemuLiveNodeStepGateConfig,
        router: &str,
        crash: &str,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        self.launch_native_observation(node, profile, router, crash)
    }

    fn borrow_observation<'a>(
        &'a mut self,
        context: &'a AttemptExecutionContext,
    ) -> Result<ObservedNativeNode<'a>, LifecycleApiError> {
        self.borrow_native_observation(context)
    }

    fn inspect_trace(
        &self,
        node: &crucible::NodeId,
        generation: u64,
        maximum_bytes: u64,
        inspect: &mut dyn FnMut(&mut dyn BufRead) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        self.inspect_native_observation_trace(node, generation, maximum_bytes, inspect)
    }

    fn liveness_tail(
        &self,
        node: &crucible::NodeId,
        generation: u64,
    ) -> Result<String, Box<dyn Error>> {
        self.native_observation_liveness_tail(node, generation)
    }

    fn into_cleanup(self: Box<Self>) -> Box<dyn ProductionVmNodeLauncher> {
        self
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Projects the same admitted lifecycle under the accepted worker's account.
    pub(crate) fn begin_native_observation_default(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        let config = self
            .config
            .try_clone_admitted()
            .map_err(|first| QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(first)))?;
        let (config, registration) = config_for_assignment_host_watchdog(config, context)?;
        let mut launcher = self.prepare_attempt_launcher(context, source, &config, registration)?;
        launcher.native_observation_config = Some(config);
        self.retained_install = Some(RetainedSourceInstall::NativeObservation(launcher));
        Ok(())
    }

    /// Borrows only the operation interface stored in this exact factory.
    pub(crate) fn native_observation(
        &mut self,
    ) -> Result<&mut (dyn NativeObservationOwner + 'static), LifecycleApiError> {
        match self.retained_install.as_mut() {
            Some(RetainedSourceInstall::NativeObservation(owner)) => Ok(owner.as_mut()),
            _ => Err(LifecycleApiError::ConstructionCustodyUnavailable),
        }
    }

    /// Observes body absence; this query grants no next effect or native role.
    pub(crate) fn native_observation_is_closed(&self) -> bool {
        self.retained_install.is_none() && !self.lifecycle_outstanding
    }

    /// Transfers the same Box and token without allocating another owner.
    pub(crate) fn retire_native_observation(
        &mut self,
    ) -> Result<(), QemuAttemptProductionVmLifecycleError> {
        let retained = self.retained_install.take();
        let Some(RetainedSourceInstall::NativeObservation(mut owner)) = retained else {
            self.retained_install = retained;
            return self.retry_retained_source_installation();
        };
        let reservation = owner.take_cleanup_reservation();
        match crate::qemu_lifecycle_launcher::publish_source_owner(
            reservation,
            owner.into_cleanup(),
        ) {
            Ok(handoff) => {
                self.retain_cleanup_handoff(handoff);
                self.retry_retained_source_installation()
            }
            Err(owner) => Err(self.park_install_from_checked_vacancy(
                RetainedSourceInstall::Begin {
                    owner,
                    handoff: None,
                },
            )),
        }
    }
}
