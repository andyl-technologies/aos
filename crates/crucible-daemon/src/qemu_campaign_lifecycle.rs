//! Attempt-guarded construction of the production QEMU lifecycle.
//!
//! This module is the daemon-side join between an admitted campaign execution
//! context and the production lifecycle scheduler. It installs one exact
//! process/resource guard before lifecycle construction, validates the guard's
//! resource and cancellation incarnation, and transfers that authority into
//! [`QemuAttemptProductionVmNodeLauncher`]. The fresh path never silently
//! substitutes for an exact-checkpoint resume.

use crucible::{ScenarioDef, ScenarioDefForm};
use crucible_api::{
    LifecycleApiError, ProductionVmLifecycleConfig, ProductionVmLifecycleLoop,
    build_production_vm_lifecycle_loop_with_launcher,
};
use crucible_campaign::ExactCheckpointId;
use crucible_qemu::QemuVmRealizationError;
use thiserror::Error;

use crate::{
    AttemptExecutionContext, MAX_QEMU_ATTEMPT_GENERATION_NODES, QemuAttemptGenerationResourceOwner,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptProductionVmNodeLauncher, QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory,
};

/// Failure to bind an admitted attempt to a fresh production VM lifecycle.
#[derive(Debug, Error)]
pub enum QemuAttemptProductionVmLifecycleError {
    /// The fresh lifecycle path was asked to resume an exact checkpoint.
    #[error("fresh production VM lifecycle cannot resume exact checkpoint `{0}`")]
    ResumeCheckpointUnsupported(ExactCheckpointId),
    /// The serialized scenario form did not reconstruct the supplied identity.
    #[error("production VM lifecycle scenario form does not match the supplied scenario")]
    ScenarioIdentityMismatch,
    /// The scenario's QEMU-node count is outside the attempt-owner bound.
    #[error(
        "production VM lifecycle node count {0} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
    )]
    InvalidNodeCount(usize),
    /// Installing the attempt resource guard failed.
    #[error("install production VM attempt resources: {0}")]
    ResourceInstallation(#[source] QemuVmRealizationError),
    /// The installed guard did not echo the exact admitted attempt contract.
    #[error(
        "production VM resource guard did not install the exact admitted limits and cancellation signal"
    )]
    ResourceContractMismatch,
    /// Releasing a mismatched resource guard failed.
    #[error("release mismatched production VM attempt resources: {0}")]
    ResourceContractCleanup(#[source] QemuVmRealizationError),
    /// The production lifecycle rejected construction under the installed guard.
    #[error("build guarded production VM lifecycle: {0}")]
    Lifecycle(#[source] LifecycleApiError),
}

/// Factory that binds one admitted attempt to the guarded production lifecycle.
pub struct QemuAttemptProductionVmLifecycleFactory<R> {
    config: ProductionVmLifecycleConfig,
    resources: R,
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R> {
    /// Creates a factory from trusted lifecycle configuration and host resources.
    #[must_use]
    pub const fn new(config: ProductionVmLifecycleConfig, resources: R) -> Self {
        Self { config, resources }
    }

    /// Returns the trusted lifecycle configuration.
    #[must_use]
    pub const fn config(&self) -> &ProductionVmLifecycleConfig {
        &self.config
    }

    /// Returns the resource-guard factory.
    #[must_use]
    pub const fn resources(&self) -> &R {
        &self.resources
    }

    /// Returns the mutable resource-guard factory.
    #[must_use]
    pub const fn resources_mut(&mut self) -> &mut R {
        &mut self.resources
    }

    /// Consumes the factory into its lifecycle configuration and resource owner.
    #[must_use]
    pub fn into_parts(self) -> (ProductionVmLifecycleConfig, R) {
        (self.config, self.resources)
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Builds one fresh lifecycle under the exact admitted attempt guard.
    ///
    /// Exact-checkpoint resume is deliberately not accepted by this method. A
    /// resumed execution must use the exact-root realization path so a missing
    /// or unavailable root cannot silently become a fresh guest execution.
    /// Construction failure drops the installed generation owner, which
    /// transfers the guard to quarantine rather than releasing it without a
    /// complete lifecycle shutdown attestation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAttemptProductionVmLifecycleError`] when the context names
    /// an exact resume root, scenario identity or node bounds do not match, the
    /// resource guard cannot install the exact contract, or lifecycle
    /// construction fails.
    pub fn begin_fresh(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmLifecycleLoop, QemuAttemptProductionVmLifecycleError> {
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(
                QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(checkpoint),
            );
        }
        if source.scenario_def() != *scenario {
            return Err(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch);
        }
        let maximum_nodes = source.world().vm_nodes().len();
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(QemuAttemptProductionVmLifecycleError::InvalidNodeCount(
                maximum_nodes,
            ));
        }

        let config = self.config.clone();
        self.with_attempt_launcher(context, maximum_nodes, |launcher| {
            build_production_vm_lifecycle_loop_with_launcher(scenario, source, &config, launcher)
        })
    }

    fn with_attempt_launcher<T>(
        &mut self,
        context: &AttemptExecutionContext,
        maximum_nodes: usize,
        build: impl FnOnce(
            QemuAttemptProductionVmNodeLauncher<R::Guard>,
        ) -> Result<T, LifecycleApiError>,
    ) -> Result<T, QemuAttemptProductionVmLifecycleError> {
        let mut guard = self
            .resources
            .begin(context.resources(), context.cancellation().clone())
            .map_err(QemuAttemptProductionVmLifecycleError::ResourceInstallation)?;
        if guard.resource_limits() != context.resources()
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            guard
                .finish()
                .map_err(QemuAttemptProductionVmLifecycleError::ResourceContractCleanup)?;
            return Err(QemuAttemptProductionVmLifecycleError::ResourceContractMismatch);
        }

        let owner = QemuAttemptGenerationResourceOwner::new(guard, maximum_nodes)
            .map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)?;
        build(QemuAttemptProductionVmNodeLauncher::new(owner))
            .map_err(QemuAttemptProductionVmLifecycleError::Lifecycle)
    }
}

#[cfg(test)]
mod tests;
