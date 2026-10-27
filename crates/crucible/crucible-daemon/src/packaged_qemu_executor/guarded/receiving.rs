//! Private stopped receiving World and live maintenance-original custody.
//!
//! A prebound input destination owns the existing alias receiver before the
//! actual basis/maintenance handoff. Every exit publishes those same aliases
//! before the witnessed native body; only Main proves physical retirement.

use super::*;
mod commit;
pub(crate) use commit::GuardedReceivingReady;
pub use commit::{
    GuardedSourceTransferOffer, GuardedSourceTransferOperation, GuardedTransferError,
};

use crate::ProductionVmStoppedLifecycle;
use crate::imported_checkpoint::{
    AuthenticatedImportedCheckpoint, ImportedCheckpointBasis, ImportedCheckpointMaintenance,
};
use crate::lifecycle_cleanup::{PreparedSourceSelector, ServiceInputReturn};
use crucible_host_resources::host_supervision::HostSupervisionError;

/// Groups the actual aliases with their prebound same-Main destination.
struct GuardedMaintenanceAliases<'owner> {
    fields: Option<MaintenanceAliasFields<'owner>>,
}

struct MaintenanceAliasFields<'owner> {
    basis: ImportedCheckpointBasis,
    maintenance: ImportedCheckpointMaintenance<'owner>,
    return_to: ServiceInputReturn,
    retirement: PreparedSourceSelector,
}

impl MaintenanceAliasFields<'_> {
    fn publish(self, semantic_shutdown: Option<crucible_engine::SchedulerError>) {
        let Self {
            basis,
            maintenance,
            return_to,
            retirement,
        } = self;
        return_to.return_maintenance(basis, maintenance, semantic_shutdown);
        // Input custody is durable before cleanup is requested or body delivery.
        retirement.request_retirement();
    }
}

impl<'owner> GuardedMaintenanceAliases<'owner> {
    fn basis(&self) -> Option<&ImportedCheckpointBasis> {
        self.fields.as_ref().map(|fields| &fields.basis)
    }

    fn maintenance(&self) -> Option<&ImportedCheckpointMaintenance<'owner>> {
        self.fields.as_ref().map(|fields| &fields.maintenance)
    }

    fn matches_body(&self, body: &ProductionVmStoppedLifecycle) -> bool {
        self.fields
            .as_ref()
            .is_some_and(|fields| body.matches_input_return(&fields.return_to))
    }

    fn return_to_main(
        mut self,
        semantic_shutdown: Option<crucible_engine::SchedulerError>,
    ) -> Result<(), crucible_engine::SchedulerError> {
        match self.fields.take() {
            Some(fields) => {
                fields.publish(semantic_shutdown);
                Ok(())
            }
            None => match semantic_shutdown {
                Some(first) => Err(first),
                None => Ok(()),
            },
        }
    }
}

impl Drop for GuardedMaintenanceAliases<'_> {
    fn drop(&mut self) {
        if let Some(fields) = self.fields.take() {
            fields.publish(None);
        }
    }
}

/// Retains the stopped World and its original alias destination together.
///
/// No scheduler or native resume interface escapes this owner. Its destructor
/// delivers fixed custody only; successful shutdown or Drop is not World-return
/// proof. The same Main queue retains all physical cleanup and original facts.
pub struct ReceivingExecutionPreparation<'owner> {
    lifecycle: Option<ProductionVmStoppedLifecycle>,
    aliases: Option<GuardedMaintenanceAliases<'owner>>,
    source: Option<GuardedServiceSource>,
    retirement: Option<crate::PreparedSourceRetirement>,
    destination: Option<GuardedCampaignOwner>,
    possession: Option<crate::campaign_transfer::CampaignArchiveExecutionPossession>,
    journal: Option<crate::assignment_ledger::ReceivingTransferRecord>,
    ready: Option<GuardedReceivingReady>,
    completed: bool,
    terminal_failure_returned: bool,
}

impl ReceivingExecutionPreparation<'_> {
    /// Physically retires the stopped receiver without restoring source rights.
    ///
    /// # Errors
    /// Preserves journal, semantic shutdown and independent Main cleanup causes.
    /// A terminal error owns the full returned raw history; a later call cannot
    /// turn that already-reported failure into success or repeat native restore.
    pub fn abort(&mut self) -> Result<(), ReceivingExecutionPreparationError> {
        if self.completed {
            return if self.terminal_failure_returned {
                Err(ReceivingExecutionPreparationError::HistoryAlreadyReturned)
            } else {
                Ok(())
            };
        }
        self.abort_journal()
            .map_err(|source| ReceivingExecutionPreparationError::Transfer(Box::new(source)))?;
        let semantic_shutdown = self
            .lifecycle
            .as_mut()
            .and_then(|lifecycle| lifecycle.shutdown_before_main_return().err());
        if let Some(aliases) = self.aliases.take() {
            aliases
                .return_to_main(semantic_shutdown)
                .map_err(ReceivingExecutionPreparationError::Cleanup)?;
        } else if let Some(first) = semantic_shutdown {
            return Err(ReceivingExecutionPreparationError::Cleanup(first));
        }
        if let Some(lifecycle) = self.lifecycle.as_mut() {
            // This private field came only from the selected factory's required
            // paired export; no API permits replacing it with a component body.
            if !lifecycle.return_to_main() {
                return Err(ReceivingExecutionPreparationError::ReceiverPending);
            }
        }
        self.lifecycle = None;
        let result = finish_service_retirement(&mut self.source, &mut self.retirement);
        match result {
            Ok(()) => self.completed = true,
            Err(ReceivingExecutionPreparationError::Terminal(history)) => {
                self.completed = true;
                self.terminal_failure_returned = true;
                self.destination = None;
                self.possession = None;
                return Err(ReceivingExecutionPreparationError::Terminal(history));
            }
            Err(first) => return Err(first),
        }
        self.destination = None;
        self.possession = None;
        Ok(())
    }
}

impl Drop for ReceivingExecutionPreparation<'_> {
    fn drop(&mut self) {
        // The grouped destructor infallibly publishes the actual aliases first.
        drop(self.aliases.take());
        // The selected factory prepared this Loop's own destination before its
        // committed export. Its destructor delivers that same body, not proof.
        drop(self.lifecycle.take());
        if let Some(source) = &self.source {
            source
                .service_handle()
                .prepared_selector()
                .request_retirement();
        }
    }
}

impl GuardedCampaignOwner {
    fn prepare_retained_maintenance<'owner>(
        &self,
        imported: AuthenticatedImportedCheckpoint<'owner>,
        cancellation: ExecutionCancellation,
    ) -> Result<
        (GuardedServiceSource, GuardedMaintenanceAliases<'owner>),
        ReceivingExecutionPreparationError,
    > {
        let (capsule, owner) = imported.into_start_custody();
        let source = self
            .prepare_imported_service_source(capsule)
            .map_err(ReceivingExecutionPreparationError::Preparation)?;
        source
            .start("validate durable receiving input", |start| {
                start.check_imported_receiver(
                    crate::host_operational_registry::operational_identity(
                        self.inner.config.daemon_epoch.as_bytes(),
                    ),
                    &self.inner.checkpoints,
                )
            })
            .map_err(|first| ReceivingExecutionPreparationError::Prepared {
                first,
                receiver_return: None,
            })?;
        let services = self.replay_services().map_err(|first| {
            let (first, custody) = source
                .admission_failure("select receiving Service admission", first)
                .into_parts();
            match first {
                Some(first) => ReceivingExecutionPreparationError::ServiceAdmission {
                    first,
                    access: custody,
                },
                None => ReceivingExecutionPreparationError::Prepared {
                    first: custody,
                    receiver_return: None,
                },
            }
        })?;
        source
            .start("start retained maintenance Service", |start| {
                services.start_for_maintenance_import(start, cancellation)
            })
            .map_err(|first| ReceivingExecutionPreparationError::Prepared {
                first,
                receiver_return: None,
            })?;
        let receiver = source
            .retain_receiver("retain maintenance output aliases")
            .map_err(|first| ReceivingExecutionPreparationError::Prepared {
                first,
                receiver_return: None,
            })?;
        let return_to = match receiver.prepare_input_return() {
            Ok(return_to) => return_to,
            Err((receiver, raw)) => {
                let first = source
                    .service_handle()
                    .failure_with_refusal("reserve maintenance input return", raw);
                let receiver_return = receiver
                    .return_after_alias_destruction()
                    .err()
                    .map(|receiver| receiver.into_failure("return unaliased maintenance receiver"));
                return Err(ReceivingExecutionPreparationError::Prepared {
                    first,
                    receiver_return,
                });
            }
        };
        match source.start("hand off maintenance aliases", |start| {
            start.take_maintenance_output(owner)
        }) {
            Ok((basis, maintenance)) => {
                let retirement = source.service_handle().prepared_selector();
                Ok((
                    source,
                    GuardedMaintenanceAliases {
                        fields: Some(MaintenanceAliasFields {
                            basis,
                            maintenance,
                            return_to,
                            retirement,
                        }),
                    },
                ))
            }
            Err(first) => {
                let receiver_return = return_to
                    .cancel_before_aliases()
                    .return_after_alias_destruction()
                    .err()
                    .map(|receiver| receiver.into_failure("return refused maintenance output"));
                Err(ReceivingExecutionPreparationError::Prepared {
                    first,
                    receiver_return,
                })
            }
        }
    }

    /// Reconstructs an authenticated import as an unexposed stopped World.
    ///
    /// # Errors
    /// Refuses incompatible input, Service admission, actual restoration or its
    /// final Original check. Every error retains input in the same Main before
    /// canonical body cleanup; no Ready or execution grant is created here.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the restored lifecycle and retained aliases
    /// identify different underlying owners.
    pub fn prepare_receiving_execution<'owner>(
        &self,
        imported: AuthenticatedImportedCheckpoint<'owner>,
        cancellation: ExecutionCancellation,
    ) -> Result<ReceivingExecutionPreparation<'owner>, ReceivingExecutionPreparationError> {
        let (source, aliases) = self.prepare_retained_maintenance(imported, cancellation)?;
        let mut receiving = ReceivingExecutionPreparation {
            lifecycle: None,
            aliases: Some(aliases),
            source: Some(source),
            retirement: None,
            destination: Some(self.clone()),
            possession: None,
            journal: None,
            ready: None,
            completed: false,
            terminal_failure_returned: false,
        };
        {
            let source = receiving
                .source
                .as_mut()
                .ok_or(ReceivingExecutionPreparationError::Unavailable)?;
            let basis = receiving
                .aliases
                .as_ref()
                .and_then(GuardedMaintenanceAliases::basis)
                .ok_or(ReceivingExecutionPreparationError::Unavailable)?;
            let scenario = basis.source.scenario_def();
            let context = match source.with_ready("borrow stopped receiving context", |service| {
                service.context().clone()
            }) {
                Ok(context) => context,
                Err(first) => {
                    drop(receiving.aliases.take());
                    return Err(ReceivingExecutionPreparationError::Prepared {
                        first,
                        receiver_return: None,
                    });
                }
            };
            match source.factory.begin_stopped_transfer(
                &self.inner.checkpoints,
                basis.checkpoint,
                crate::QemuExactResumeBasis::new(
                    &scenario,
                    &basis.source,
                    &basis.configuration,
                    None,
                ),
                &context,
            ) {
                Ok(lifecycle) => {
                    // Arm the aliases-first destructor before the projected
                    // context can unwind while releasing its own local fields.
                    receiving.lifecycle = Some(lifecycle);
                }
                Err(first) => {
                    drop(context);
                    drop(receiving.aliases.take());
                    return Err(ReceivingExecutionPreparationError::RestoreRetained {
                        first: Box::new(first),
                        custody: source.failure("restore stopped receiver"),
                    });
                }
            }
        }
        // The fixed selected Source producer prepares the actual private Main
        // pair before committed export. Check its exact witness correspondence
        // only after the full grouped owner exists, including during unwind.
        debug_assert!(receiving.lifecycle.as_ref().is_some_and(|body| {
            receiving
                .aliases
                .as_ref()
                .is_some_and(|aliases| aliases.matches_body(body))
        }));
        receiving
            .aliases
            .as_ref()
            .and_then(GuardedMaintenanceAliases::maintenance)
            .ok_or(ReceivingExecutionPreparationError::Unavailable)?
            .check()
            .map_err(ReceivingExecutionPreparationError::Original)?;
        Ok(receiving)
    }
}

fn finish_service_retirement(
    source: &mut Option<GuardedServiceSource>,
    retirement: &mut Option<crate::PreparedSourceRetirement>,
) -> Result<(), ReceivingExecutionPreparationError> {
    if retirement.is_none() {
        let owner = source
            .as_ref()
            .ok_or(ReceivingExecutionPreparationError::Unavailable)?;
        *retirement = Some(owner.service_handle().into_retirement());
    }
    let owner = retirement
        .as_mut()
        .ok_or(ReceivingExecutionPreparationError::Unavailable)?;
    if !owner
        .retry()
        .map_err(ReceivingExecutionPreparationError::Retirement)?
    {
        return Err(ReceivingExecutionPreparationError::ReceiverPending);
    }
    let owner = retirement
        .take()
        .ok_or(ReceivingExecutionPreparationError::Unavailable)?;
    match owner.finish() {
        Ok(history) => {
            *source = None;
            if history.first_failure().is_some() {
                Err(ReceivingExecutionPreparationError::Terminal(history))
            } else {
                drop(history);
                Ok(())
            }
        }
        Err(owner) => {
            *retirement = Some(owner);
            Err(ReceivingExecutionPreparationError::ReceiverPending)
        }
    }
}

/// Typed refusal while retaining or physically retiring a stopped receiver.
#[derive(Debug, thiserror::Error)]
pub enum ReceivingExecutionPreparationError {
    /// A durable receiving observation could not be closed safely.
    #[error("receiving execution transfer journal refused")]
    Transfer(#[source] Box<GuardedTransferError>),
    /// Required live preparation custody was already consumed.
    #[error("receiving execution preparation is unavailable")]
    Unavailable,
    /// The actual Original refused before native exposure.
    #[error("receiving execution original refused")]
    Original(#[source] HostSupervisionError),
    /// An actual semantic cause could not be handed to an already-closed owner.
    #[error("receiving semantic shutdown refused")]
    Cleanup(#[source] crucible_engine::SchedulerError),
    /// The same actual Main role refused its bounded cleanup attempt.
    #[error("receiving execution Service retirement refused")]
    Retirement(#[source] crate::PreparedSourceRefusal),
    /// Physical body/aliases or their exact acknowledgment remain retained.
    #[error("receiving execution physical return remains pending")]
    ReceiverPending,
    /// Input remained owned when preparation refused before Main installation.
    #[error("receiving input preparation refused")]
    Preparation(#[source] crate::ImportedSourcePreparationFailure),
    /// Actual first did not enter Main, and its independent report stays owned.
    #[error("receiving Service admission failed: {first}")]
    ServiceAdmission {
        /// Actual initiating cause, preserved without stringification.
        #[source]
        first: PackagedQemuExecutorError,
        /// Same actual Main role and independent projection-access facts.
        access: crate::PreparedSourceFailure,
    },
    /// Main retains the first and any independent unaliased receiver refusal.
    #[error("receiving Service preparation refused: {first}")]
    Prepared {
        /// Actual same-role first failure.
        #[source]
        first: crate::PreparedSourceFailure,
        /// Actual refused acknowledgement before aliases were exposed.
        receiver_return: Option<crate::PreparedSourceFailure>,
    },
    /// The restore error and actual Main construction owner stay independent.
    #[error("receiving stopped restore failed: {first}")]
    RestoreRetained {
        /// Actual restore failure.
        #[source]
        first: Box<crate::QemuAttemptProductionVmLifecycleError>,
        /// Original Main role retaining construction and actual input custody.
        custody: crate::PreparedSourceFailure,
    },
    /// Physical completion retains its independent raw failure history.
    #[error("receiving retirement retained terminal failure history")]
    Terminal(#[source] crate::ProductionVmConstructionPostBody),
    /// The previous abort already handed its actual raw history to the caller.
    #[error("receiving terminal failure history was already returned")]
    HistoryAlreadyReturned,
}
