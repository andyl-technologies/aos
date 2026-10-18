//! Borrows one Main-owned Source constructor without moving its native guard.
//!
//! Every copy selects the same original cell and epoch. The containing Main
//! mutex serializes operations, and the Pending journal permits a single World
//! entry. A role-bound failure closes that work path and keeps its actual first
//! cause in the original allocation.

use super::PendingSourceConstruction;
use crate::lifecycle_cleanup::{
    PreparedSourceFailure, PreparedSourceRetirement, ServiceMainHandle, ServiceMainPreclaimError,
};
use crate::{QemuAttemptProcessResourceGuard, QemuAttemptResourceGuardFactory};

/// Selects the same concrete Source body retained in its original Main role.
pub(crate) struct PreparedSourceHandle<R: QemuAttemptResourceGuardFactory> {
    inner: crate::lifecycle_cleanup::PreparedSourceHandle<PendingSourceConstruction<R>>,
}

impl<R: QemuAttemptResourceGuardFactory> Clone for PreparedSourceHandle<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<R> PreparedSourceHandle<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(crate) fn from_main(
        inner: crate::lifecycle_cleanup::PreparedSourceHandle<PendingSourceConstruction<R>>,
    ) -> Self {
        Self { inner }
    }

    /// Retypes the same erased selection without checking or issuing new work.
    ///
    /// The actual concrete type is checked only under the originating Main
    /// mutex; a foreign type remains a refusal and cannot replace its body.
    pub(crate) fn from_selector(
        selector: crate::lifecycle_cleanup::PreparedSourceSelector,
    ) -> Self {
        Self::from_main(selector.typed::<PendingSourceConstruction<R>>())
    }

    /// Borrows the same typed body exclusively for one operation.
    pub(crate) fn with_pending<T>(
        &self,
        apply: impl FnOnce(&mut PendingSourceConstruction<R>) -> T,
    ) -> Result<T, ServiceMainPreclaimError> {
        self.inner.with_prepared(apply)
    }

    /// Selects Service in the same Main role without creating an owning alias.
    pub(crate) fn service_main_handle(&self) -> ServiceMainHandle {
        self.inner.service_main_handle()
    }

    /// Borrows only the actual entered guard still retained by this Pending.
    pub(crate) fn with_native<T>(
        &self,
        apply: impl FnOnce(&mut R::Guard) -> T,
    ) -> Result<T, ServiceMainPreclaimError> {
        self.with_pending(|pending| pending.with_native(apply))?
    }

    /// Starts replay through this same preborn World's keyed constructor.
    ///
    /// The actual guard remains inside Pending on every result. A refusal
    /// closes future work and exposes its typed first through the original role.
    pub(crate) fn begin_replay_world(
        &self,
        context: &crate::AttemptExecutionContext,
        source: &crucible::ScenarioDefForm,
        config: &crate::ProductionVmLifecycleConfig,
    ) -> Result<(), PreparedSourceFailure> {
        match self.with_pending(|pending| pending.begin_replay_world(context, source, config)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) => Err(self.failure("prepare replay World")),
            Err(first) => {
                Err(self.failure_with_refusal("borrow original prepared replay World", first))
            }
        }
    }

    /// Lends only scoped Flight operations from the same retained native Box.
    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(crate) fn with_native_observation(
        &self,
        apply: &mut dyn FnMut(
            &mut dyn crate::qemu_campaign_lifecycle::NativeObservationOwner,
        ) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.with_pending(|pending| pending.with_native_observation(apply)) {
            Ok(Ok(result)) => {
                if result.is_err() {
                    self.service_main_handle()
                        .prepared_selector()
                        .request_retirement();
                }
                result
            }
            Ok(Err(())) => Err(Box::new(
                self.failure("borrow same native observation body"),
            )),
            Err(raw) => Err(Box::new(
                self.failure_with_refusal("borrow Main native observation", raw),
            )),
        }
    }

    /// Builds and captures a fresh Source while its whole body remains Main-owned.
    pub(crate) fn capture_fresh_source_world(
        &self,
        config: &crate::ProductionVmLifecycleConfig,
        terminal: Option<std::sync::Arc<crate::ExactCheckpointStore>>,
        source: &crucible::ScenarioDefForm,
        start: &crucible::Configuration,
        context: &crate::AttemptExecutionContext,
        network: &[crucible::SelectionDecision],
        continuations: &[crate::qemu_campaign_lifecycle::OwnedQemuAttemptContinuation],
    ) -> Result<
        crate::vm_lifecycle::ProductionVmHotForkSourceWorld,
        crate::QemuAttemptProductionVmLifecycleError,
    > {
        crate::qemu_campaign_lifecycle::capture_fresh_prepared_source(
            self,
            config,
            terminal,
            source,
            start,
            context,
            network,
            continuations,
        )
    }

    /// Restores and validates an exact Source before its pure same-owner export.
    pub(crate) fn capture_exact_source_world(
        &self,
        config: &crate::ProductionVmLifecycleConfig,
        terminal: Option<std::sync::Arc<crate::ExactCheckpointStore>>,
        checkpoints: &crate::ExactCheckpointStore,
        checkpoint: crucible_campaign::ExactCheckpointId,
        basis: crate::QemuExactResumeBasis<'_>,
        requested: &crucible::Configuration,
        context: &crate::AttemptExecutionContext,
    ) -> Result<
        Option<crate::vm_lifecycle::ProductionVmHotForkSourceWorld>,
        crate::QemuAttemptProductionVmLifecycleError,
    > {
        crate::qemu_campaign_lifecycle::capture_exact_prepared_source(
            self,
            config,
            terminal,
            checkpoints,
            checkpoint,
            basis,
            requested,
            context,
        )
    }

    /// Closes further work while preserving the actual phase's typed first.
    pub(crate) fn failure(&self, phase: &'static str) -> PreparedSourceFailure {
        self.inner.failure(phase)
    }

    /// Retains the independent refusal of the same scoped Main observation.
    pub(crate) fn failure_with_refusal(
        &self,
        phase: &'static str,
        refusal: ServiceMainPreclaimError,
    ) -> PreparedSourceFailure {
        self.inner.failure_with_refusal(phase, refusal)
    }

    /// Observes actual disposal of this role's body and protected payloads.
    pub(crate) fn is_released(&self) -> Result<bool, ServiceMainPreclaimError> {
        self.inner.is_released()
    }

    /// Transfers this selector to the same Main role's physical cleanup path.
    pub(crate) fn into_retirement(self) -> PreparedSourceRetirement {
        self.inner.into_retirement()
    }
}
