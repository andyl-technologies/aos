//! Authenticates and checks out the actual retained Source before Target admission.
//!
//! Selection preserves the provider's checkout identity and the exact semantic
//! continuation. Unavailable Sources decline before effects; a selected refusal
//! keeps its original owning checkout or restores it through the same provider.

use super::*;

/// Retains the authenticated source input for one actual Target constructor.
pub(crate) struct SelectedTargetSource {
    pub(super) key: QemuHotForkSourceWorldKey,
    pub(super) lease: QemuHotForkSourceWorldLease,
    pub(super) world: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    pub(super) continuation: crate::ProductionVmHotForkWorldContinuation,
    pub(super) runtime_basis: crate::AttemptExecutionRuntimeBasis,
}

impl<S, R, O> QemuProductionHotForkWorldLifecycleFactory<S, R, O>
where
    S: QemuHotForkSourceWorldProvider,
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>
        + Send
        + 'static,
{
    /// Checks out the exact original Source without creating Target resources.
    ///
    /// # Errors
    /// Preserves provider, parent park, runtime provenance and Source failures.
    pub(super) fn select_source_for_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<SelectedTargetSource>,
        AttemptWorkerFailure<QemuProductionHotForkWorldLifecycleFactoryError<S::Error>>,
    > {
        // This factory has one exclusive worker. Refuse before checkout or any
        // new native effect while its fixed installation slot is occupied.
        if self.retained_target.is_some() || self.retained_target_admission.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::RetainedTarget,
            ));
        }
        if self.retained_installation.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::RetainedInstallation,
            ));
        }

        if matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Ok(None);
        }
        let runtime_basis = context.runtime_basis().ok_or_else(|| {
            AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::MissingRuntimeBasis,
            )
        })?;
        validate_fresh_qemu_scenario_resources(input.scenario(), context.resources()).map_err(
            |error| {
                AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::ScenarioResources(error),
                )
            },
        )?;
        let source_key = QemuHotForkSourceWorldKey::for_execution(input, context, runtime_basis)
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(
                    QemuProductionHotForkWorldLifecycleFactoryError::SourceKey(error),
                )
            })?;
        let Some(source_lease) = self
            .sources
            .checkout_for_attempt(input, context, &source_key)
            .map_err(|error| {
                let class = S::failure_class(&error);
                let error = QemuProductionHotForkWorldLifecycleFactoryError::SourceProvider(error);
                match class {
                    SchedulerOperationalFailureClass::Retryable => {
                        AttemptWorkerFailure::Retryable(error)
                    }
                    SchedulerOperationalFailureClass::Canceled => {
                        AttemptWorkerFailure::Canceled(error)
                    }
                    SchedulerOperationalFailureClass::Terminal => {
                        AttemptWorkerFailure::Terminal(error)
                    }
                }
            })?
        else {
            return Ok(None);
        };
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if let Err(first) = self.sources.parent_park_before_fork(&source_lease) {
            // No fresh-start fallback, supervisor replacement or source restore
            // follows a selected refusal. Its pool record keeps the reservation
            // and any published gate keeps the whole actual source and caller.
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::ParentPark(first),
            ));
        }
        let Some(source_world) = source_lease.source_owner() else {
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionHotForkWorldLifecycleFactoryError::Source(String::from(
                    "retained source-world return custody is unavailable",
                )),
            ));
        };
        let mut source = match source_world.lock() {
            Ok(source) => source,
            Err(_error) => {
                self.sources.abandon();
                drop(source_lease);
                return Err(AttemptWorkerFailure::Retryable(
                    QemuProductionHotForkWorldLifecycleFactoryError::Source(String::from(
                        "retained source-world lock is poisoned",
                    )),
                ));
            }
        };
        if let Some(supervisor) = context.host_operation_supervisor()
            && let Err(error) = source.attach_borrowed_host_operation_supervisor(supervisor)
        {
            drop(source);
            drop(source_world);
            self.sources.restore(source_lease);
            return Err(AttemptWorkerFailure::Retryable(
                QemuProductionHotForkWorldLifecycleFactoryError::Source(error.to_string()),
            ));
        }
        let source_matches = source.continuation().is_ok_and(|continuation| {
            continuation.configuration().def.id() == source_key.scenario()
                && continuation.configuration().id() == source_key.configuration()
        });
        if !source_matches {
            drop(source);
            drop(source_world);
            self.sources.restore(source_lease);
            return Ok(None);
        }
        let continuation = match source.fork_continuation() {
            Ok(continuation) => continuation,
            Err(error) => {
                drop(source);
                drop(source_world);
                self.sources.restore(source_lease);
                return Err(AttemptWorkerFailure::Retryable(
                    QemuProductionHotForkWorldLifecycleFactoryError::Source(error.to_string()),
                ));
            }
        };
        drop(source);
        Ok(Some(SelectedTargetSource {
            key: source_key,
            lease: source_lease,
            world: source_world,
            continuation,
            runtime_basis,
        }))
    }
}
