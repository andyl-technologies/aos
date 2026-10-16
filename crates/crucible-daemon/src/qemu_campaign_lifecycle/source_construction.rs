//! Joins actual before-effects custody to the boxed Source launcher and API.

use super::*;
use crate::ProductionVmNodeLauncher;
use crate::qemu_lifecycle_launcher::{
    PendingSourceConstruction, UnbornSourceConstruction, retain_source_owner,
};
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
mod native_observation;
mod retained;
#[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
pub(crate) use native_observation::NativeObservationOwner;
pub(super) use retained::RetainedSourceInstall;

/// Preserves metadata refusal and the native boundary's independent result.
#[derive(Debug, Error)]
#[error("Source generation storage refused: {source}; native boundary: {boundary}")]
pub struct SourceGenerationStorageRefusal {
    #[source]
    source: LifecycleApiError,
    boundary: QemuVmRealizationError,
}

/// Preserves the exact entered post-installation operation that refused.
#[derive(Debug, Error)]
pub enum SourcePostInstallationRefusal {
    /// The actual guard does not match its admitted resources or cancellation.
    #[error("Source guard does not match its admitted contract")]
    ContractMismatch,
    /// Actual native ownership or publication refused.
    #[error(transparent)]
    Native(#[from] QemuVmRealizationError),
    /// Actual host RAM ownership or publication refused.
    #[error(transparent)]
    HostRam(#[from] crucible_api::host_operational::HostRamAdmissionError),
}

impl SourcePostInstallationRefusal {
    fn into_original(self) -> QemuAttemptProductionVmLifecycleError {
        match self {
            Self::ContractMismatch => {
                QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
            }
            Self::Native(first) => {
                QemuAttemptProductionVmLifecycleError::ResourceInstallation(first)
            }
            Self::HostRam(first) => QemuAttemptProductionVmLifecycleError::HostRamAdmission(first),
        }
    }
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn begin_retained_native_world_guard(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        config: &ProductionVmLifecycleConfig,
    ) -> Result<
        (
            R::Guard,
            crucible_campaign::AttemptResourceLimits,
            Box<PendingSourceConstruction<R>>,
        ),
        QemuAttemptProductionVmLifecycleError,
    > {
        let mut factory = Some(self.resources.retain_fork_target_factory().ok_or_else(|| {
            QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                QemuVmRealizationError::ExecutorUnavailable {
                    operation: "retain partial native Source construction",
                    message: String::from("actual same-factory owner is unavailable"),
                },
            )
        })?);
        let mut pending = None;
        let mut metadata_failure = None;
        let mut before_effects = |loan, controls| {
            let Some(factory) = factory.take() else {
                return Err(QemuVmRealizationError::ExecutorUnavailable {
                    operation: "retain partial native Source construction",
                    message: String::from("before-effects callback was repeated"),
                });
            };
            let mut owner = PendingSourceConstruction::new_prepaid(factory, loan, controls);
            let result = owner.reserve_cleanup().and_then(|()| {
                match owner
                    .prepare_generation_storage(source.world().vm_nodes().iter().map(|vm| &vm.id))
                {
                    Ok(()) => Ok(()),
                    Err(first) => {
                        metadata_failure = Some(first);
                        Err(QemuVmRealizationError::ExecutorUnavailable {
                            operation: "prepare selected generation storage",
                            message: String::from("selected metadata admission refused"),
                        })
                    }
                }
            });
            pending = Some(owner);
            result
        };
        let result = self.begin_native_world_guard(context, source, config, &mut before_effects);
        drop(before_effects);
        match result {
            Err(NativeWorldBeginFailure::Configuration(first)) => Err(first),
            Err(NativeWorldBeginFailure::Native(boundary)) => {
                if let Some(first) = metadata_failure {
                    let first = SourceGenerationStorageRefusal {
                        source: first,
                        boundary,
                    };
                    let first = match pending {
                        Some(mut owner) => {
                            let reservation = owner.take_cleanup_reservation();
                            match retain_source_owner(reservation, owner, first) {
                                Ok((first, handoff)) => {
                                    self.retain_cleanup_handoff(handoff);
                                    first
                                }
                                Err(owner) => {
                                    return Err(self.park_install_from_checked_vacancy(
                                        RetainedSourceInstall::Storage {
                                            owner,
                                            handoff: None,
                                        },
                                    ));
                                }
                            }
                        }
                        None => first,
                    };
                    return Err(first.into());
                }
                let first = match pending {
                    Some(owner) if owner.has_unreserved_controls() => {
                        return Err(self.park_install_from_checked_vacancy(
                            RetainedSourceInstall::Unborn(UnbornSourceConstruction::new(
                                owner, boundary,
                            )),
                        ));
                    }
                    Some(owner) => match owner.retain_after_begin_error(boundary) {
                        Ok((first, handoff)) => {
                            self.retain_cleanup_handoff(handoff);
                            first
                        }
                        Err(owner) => {
                            return Err(self.park_install_from_checked_vacancy(
                                RetainedSourceInstall::Begin {
                                    owner,
                                    handoff: None,
                                },
                            ));
                        }
                    },
                    None => boundary,
                };
                Err(QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                    first,
                ))
            }
            Ok((guard, expected)) => {
                let Some(owner) = pending else {
                    // Unsupported defaults refuse before begin. A concrete
                    // implementation must never return G without calling its
                    // authenticated before-effects consumer.
                    return Err(self.park_install_from_checked_vacancy(
                        RetainedSourceInstall::MissingCallback {
                            guard,
                            first_cleanup: None,
                        },
                    ));
                };
                Ok((guard, expected, owner))
            }
        }
    }

    fn prepare_attempt_launcher(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        config: &ProductionVmLifecycleConfig,
        park_drain_registration: ConfiguredParkDrainRegistration,
    ) -> Result<
        Box<QemuAttemptProductionVmNodeLauncher<R::Guard, R>>,
        QemuAttemptProductionVmLifecycleError,
    > {
        self.require_install_vacancy()?;
        // All fallible ordinary copies precede native begin. The selected
        // generation storage itself is paid and built inside before_effects.
        let terminal_source = if self.terminal_checkpoints.is_some() {
            Some(source.try_clone_admitted().map_err(|first| {
                QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(first))
            })?)
        } else {
            None
        };
        let (guard, expected, pending) =
            self.begin_retained_native_world_guard(context, source, config)?;
        let (guard, storage, factory, reservation, custody) =
            match pending.into_launcher_parts(guard) {
                Ok(parts) => parts,
                Err(owner) => {
                    let first = QemuVmRealizationError::ExecutorUnavailable {
                        operation: "transfer actual Source constructor",
                        message: String::from(
                            "same pending owner retains an incomplete launcher transfer",
                        ),
                    };
                    let first = match owner.retain_after_begin_error(first) {
                        Ok((first, handoff)) => {
                            self.retain_cleanup_handoff(handoff);
                            first
                        }
                        Err(owner) => {
                            return Err(self.park_install_from_checked_vacancy(
                                RetainedSourceInstall::Begin {
                                    owner,
                                    handoff: None,
                                },
                            ));
                        }
                    };
                    return Err(QemuAttemptProductionVmLifecycleError::ResourceInstallation(
                        first,
                    ));
                }
            };
        let owner = QemuAttemptGenerationResourceOwner::new(guard, storage);
        // This is the one actual launcher Box included in the selected body
        // request. It exists before every remaining post-begin error cut.
        let mut launcher = Box::new(
            QemuAttemptProductionVmNodeLauncher::new_registered(
                owner,
                park_drain_registration,
                Some(factory),
            )
            .with_cleanup_reservation(reservation)
            .with_construction_custody(custody),
        );
        let installed = launcher.with_native_guard(|guard| {
            Self::complete_native_world_guard_installation(context, source, config, guard, expected)
        });
        if let Err(first) = installed {
            let reservation = launcher.take_cleanup_reservation();
            let first = match retain_source_owner(reservation, launcher, first) {
                Ok((first, handoff)) => {
                    self.retain_cleanup_handoff(handoff);
                    first
                }
                Err(owner) => {
                    return Err(self.park_install_from_checked_vacancy(
                        RetainedSourceInstall::Post {
                            owner,
                            handoff: None,
                        },
                    ));
                }
            };
            return Err(first.into_original());
        }
        if let (Some(checkpoints), Some(terminal_source)) =
            (&self.terminal_checkpoints, terminal_source)
        {
            // The admitted source copy already exists, so this transition only
            // moves fields and existing aliases into the retained launcher.
            launcher.install_terminal_checkpoint_import(
                Arc::clone(checkpoints),
                terminal_source,
                context.cancellation().clone(),
            );
        }
        Ok(launcher)
    }

    pub(super) fn with_attempt_launcher<T>(
        &mut self,
        context: &AttemptExecutionContext,
        source: &ScenarioDefForm,
        _maximum_nodes: usize,
        config: &ProductionVmLifecycleConfig,
        park_drain_registration: ConfiguredParkDrainRegistration,
        build: impl FnOnce(
            Box<dyn ProductionVmNodeLauncher>,
        ) -> Result<T, crate::ProductionVmConstructionFailure>,
    ) -> Result<T, QemuAttemptProductionVmLifecycleError> {
        let launcher =
            self.prepare_attempt_launcher(context, source, config, park_drain_registration)?;
        match build(launcher) {
            Ok(lifecycle) => {
                self.lifecycle_outstanding = true;
                Ok(lifecycle)
            }
            Err(failure) => match failure.retain_in_reserved_cleanup() {
                Ok((first, handoff)) => {
                    self.retain_cleanup_handoff(handoff);
                    Err(QemuAttemptProductionVmLifecycleError::Lifecycle(first))
                }
                Err(failure) => Err(self.park_install_from_checked_vacancy(
                    RetainedSourceInstall::Api {
                        owner: failure,
                        handoff: None,
                    },
                )),
            },
        }
    }
}
