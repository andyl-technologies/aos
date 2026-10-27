//! Receiver-owned replay through its original Main-held Service and Source body.
//!
//! Imported input is installed before Service effects. The receiving aliases
//! move back to that same Main before the complete lifecycle leaves this facade;
//! neither a semantic shutdown sign nor an empty local slot proves World return.

use super::*;
use crate::imported_checkpoint::{
    AuthenticatedImportedCheckpoint, ImportedCheckpointBasis, ImportedCheckpointOwner,
    RetainedImportedCheckpoint, UnpublishedImportedInput,
};
use crate::packaged_qemu_executor::ServiceRetirementInput;
use crate::vm_lifecycle::{
    MainSourceLifecycle, MainSourceLifecycleFailure, ProductionVmLifecycleLoop,
};

type ReplayResources = crate::ComposedQemuAttemptResourceGuardFactory<
    crate::SharedQemuAttemptHostResourceFactory<crate::LinuxQemuAttemptHostResourceFactory>,
>;
type ReplaySource = crate::qemu_lifecycle_launcher::PreparedSourceHandle<ReplayResources>;

/// Native receiver and its exact original Main-owned Service and import basis.
///
/// Only the lifecycle stays local while it can execute. Successful setup moves
/// its imported basis and receiver back to the original Main before exposing
/// this facade. Unwind first destroys its actual scoped aliases before their
/// receiver return; Main still owns native body, control and World retirement.
/// Final history remains owning even after cleanup.
pub struct ImportedProductionCheckpointReplay {
    lifecycle: Option<MainSourceLifecycle>,
    prepared: Option<ReplaySource>,
    retirement: Option<crate::PreparedSourceRetirement>,
    unaccepted_input: Option<ServiceRetirementInput>,
    archive: crucible_campaign::CampaignArchiveManifestId,
    closed: bool,
}

impl ImportedProductionCheckpointReplay {
    /// Moves native custody to an actor with admitted concrete session retention.
    pub(crate) fn into_debug_lifecycle(
        mut self,
    ) -> Result<
        (
            ProductionVmLifecycleLoop,
            crucible_control_server::SessionLifetimeRetention,
        ),
        ImportedProductionReplayError,
    > {
        if self.unaccepted_input.is_some() {
            return Err(ImportedProductionReplayError::Unavailable);
        }
        let source = self
            .prepared
            .as_ref()
            .ok_or(ImportedProductionReplayError::Unavailable)?
            .clone();
        // Admission precedes both the concrete Box and actual Loop exposure.
        // A refused allocation leaves the whole Loop in this facade.
        let retention =
            crucible_control_server::SessionLifetimeRetention::try_new_admitted(DebugReplayCustody {
                source: Some(source),
            })
            .map_err(ImportedProductionReplayError::Retention)?;
        let lifecycle = self
            .lifecycle
            .take()
            .and_then(MainSourceLifecycle::into_lifecycle)
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        self.prepared = None;
        Ok((lifecycle, retention))
    }

    /// Returns the authenticated receiver archive realized by this lifecycle.
    #[must_use]
    pub fn archive(&self) -> crucible_campaign::CampaignArchiveManifestId {
        self.archive
    }

    /// Projects the original receiver context under its bounded Service borrow.
    ///
    /// A caller retaining aliases from the projection must first retain an
    /// ordinary receiver and acknowledge it only after those aliases drop.
    ///
    /// # Errors
    /// Refuses a retired, borrowed, unavailable or failed original Service.
    #[cfg(test)]
    pub(crate) fn with_context<T>(
        &self,
        apply: impl FnOnce(&AttemptExecutionContext) -> T,
    ) -> Result<T, ImportedProductionReplayError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        prepared
            .service_main_handle()
            .with_ready(|service| apply(service.context()))
            .map_err(|first| {
                ImportedProductionReplayError::Prepared(
                    prepared.failure_with_refusal("project imported receiver context", first),
                )
            })
    }

    /// Retains the actual receiver before creating independent context aliases.
    #[cfg(test)]
    pub(crate) fn retain_context_receiver(
        &self,
    ) -> Result<crate::ServiceMainReceiver, ImportedProductionReplayError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        prepared
            .service_main_handle()
            .retain_receiver()
            .map_err(|first| {
                ImportedProductionReplayError::Prepared(
                    prepared
                        .failure_with_refusal("retain imported receiver context aliases", first),
                )
            })
    }

    /// Borrows the authenticated lifecycle without detaching its cleanup owner.
    ///
    /// # Errors
    /// Refuses a lifecycle already handed back to its original Main.
    pub fn lifecycle_mut(
        &mut self,
    ) -> Result<&mut dyn crate::QemuFreshAttemptLifecycleOwner, ImportedProductionReplayError> {
        self.lifecycle
            .as_mut()
            .and_then(MainSourceLifecycle::lifecycle_mut)
            .ok_or(ImportedProductionReplayError::Unavailable)
    }

    /// Borrows only the actual body for the existing native qualification.
    ///
    /// The sole caller returns owned receiver evidence. It neither replaces nor
    /// extracts the Loop, its original carrier or its return destination.
    #[cfg(test)]
    pub(crate) fn with_qualification_lifecycle<T>(
        &mut self,
        project: impl FnOnce(&mut ProductionVmLifecycleLoop) -> T,
    ) -> Result<T, ImportedProductionReplayError> {
        self.lifecycle
            .as_mut()
            .and_then(|lifecycle| lifecycle.with_lifecycle_mut(project))
            .ok_or(ImportedProductionReplayError::Unavailable)
    }

    /// Returns the same actual Loop and observes complete typed terminal history.
    ///
    /// Terminal extraction closes this facade even when its returned history
    /// is negative; the owning error retains that history until disposal.
    ///
    /// # Errors
    /// Keeps the actual body or its owning return failure when publication
    /// refuses. Pending native cleanup retains its Main role and original first
    /// cause. A terminal negative returns its complete owning PostBody.
    pub fn finish(&mut self) -> Result<(), ImportedProductionReplayError> {
        if self.closed {
            return Ok(());
        }
        if let Some(source) = self.prepared.as_ref() {
            if self.unaccepted_input.is_some() {
                source
                    .service_main_handle()
                    .adopt_retirement_input(&mut self.unaccepted_input)
                    .map_err(|first| {
                        ImportedProductionReplayError::Prepared(
                            source
                                .failure_with_refusal("retry imported replay input return", first),
                        )
                    })?;
            }
            if let Some(lifecycle) = self.lifecycle.as_mut() {
                lifecycle.return_to_main();
            }
        }
        if let Some(source) = self.prepared.take() {
            self.retirement = Some(source.into_retirement());
        }
        let retirement = self
            .retirement
            .as_mut()
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        if !retirement
            .retry()
            .map_err(ImportedProductionReplayError::Retirement)?
        {
            return Err(ImportedProductionReplayError::Retirement(
                crate::PreparedSourceRefusal::Pending,
            ));
        }
        let Some(retirement) = self.retirement.take() else {
            return Err(ImportedProductionReplayError::Unavailable);
        };
        match retirement.finish() {
            Ok(terminal) => {
                self.closed = true;
                if terminal.first_failure().is_some() {
                    return Err(ImportedProductionReplayError::Terminal(terminal));
                }
                drop(terminal);
                Ok(())
            }
            Err(retirement) => {
                self.retirement = Some(retirement);
                Err(ImportedProductionReplayError::Retirement(
                    crate::PreparedSourceRefusal::Pending,
                ))
            }
        }
    }
}

impl ProductionBakedGenesisReplayCatalogFactory<ReplayResources> {
    /// Starts one authenticated receiver under the original prepared Main.
    ///
    /// Authentication custody moves before configuration, compatibility or
    /// backend checks. Pre-Main refusals retain that actual unpublished input;
    /// later refusals select the same installed owner and its typed raw cause.
    ///
    /// # Errors
    /// Refuses unsupported replay, incompatible storage or checkpoint identity,
    /// admission failure, expired authority, or uncertain native/physical return.
    pub fn begin_imported_checkpoint(
        &self,
        checkpoints: &crate::ExactCheckpointStore,
        imported: AuthenticatedImportedCheckpoint<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<ImportedProductionCheckpointReplay, ImportedProductionReplayError> {
        let (capsule, owner) = imported.into_start_custody();
        self.begin_retained_imported_checkpoint(checkpoints, capsule, owner, cancellation)
    }

    pub(crate) fn begin_retained_imported_checkpoint(
        &self,
        checkpoints: &crate::ExactCheckpointStore,
        capsule: RetainedImportedCheckpoint,
        _owner: ImportedCheckpointOwner<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<ImportedProductionCheckpointReplay, ImportedProductionReplayError> {
        let Some(config) = self.savepoint_replay_config.as_ref() else {
            return Err(ImportedProductionReplayError::UnavailableInput(
                UnpublishedImportedInput::new(capsule),
            ));
        };
        let Some(services) = self.replay_services.as_ref() else {
            return Err(ImportedProductionReplayError::UnavailableInput(
                UnpublishedImportedInput::new(capsule),
            ));
        };
        let Some(basis) = capsule.basis() else {
            return Err(ImportedProductionReplayError::UnavailableInput(
                UnpublishedImportedInput::new(capsule),
            ));
        };
        if let Err(first) = checkpoints.require_reuse_backend(&basis.repository.blob_backend()) {
            return Err(ImportedProductionReplayError::StoreInput {
                first,
                input: UnpublishedImportedInput::new(capsule),
            });
        }
        if let Err(first) =
            self.require_basis(basis.source.world().id, basis.source.scenario_def().id())
        {
            return Err(ImportedProductionReplayError::CompatibilityInput {
                first,
                input: UnpublishedImportedInput::new(capsule),
            });
        }

        let mut factory =
            QemuAttemptProductionVmLifecycleFactory::new(config.clone(), self.resources.clone());
        let service = factory
            .prepare_source_construction_with_import(capsule)
            .map_err(ImportedProductionReplayError::Preparation)?;
        let prepared = factory.prepared_source_handle().map_err(|first| {
            ImportedProductionReplayError::Prepared(
                service.failure_with_refusal("select imported replay Source", first),
            )
        })?;
        match service
            .with_start(|start| services.start_for_imported_checkpoint(start, cancellation))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(ImportedProductionReplayError::Prepared(
                    prepared.failure("start imported replay Service"),
                ));
            }
            Err(first) => {
                return Err(ImportedProductionReplayError::Prepared(
                    prepared.failure_with_refusal("borrow imported replay Service", first),
                ));
            }
        }

        // Register this concrete output before taking its actual basis or
        // cloning the live Service context. No Service lock spans World entry.
        let receiver = service.retain_receiver().map_err(|first| {
            ImportedProductionReplayError::Prepared(
                prepared.failure_with_refusal("retain imported replay output", first),
            )
        })?;
        let basis = match service.with_start(|start| start.take_imported_basis()) {
            Ok(Ok(basis)) => basis,
            Ok(Err(_)) => {
                return Err(return_unopened_receiver(
                    prepared.failure("take imported replay input"),
                    receiver,
                ));
            }
            Err(first) => {
                return Err(return_unopened_receiver(
                    prepared.failure_with_refusal("borrow imported replay input", first),
                    receiver,
                ));
            }
        };
        let archive = basis.archive;
        let mut projection = ImportedReplayProjection::new(basis, receiver);
        let setup = projection.begin_resume(&service, &prepared, &mut factory, checkpoints);
        let mut replay = ImportedProductionCheckpointReplay {
            lifecycle: None,
            prepared: Some(prepared),
            retirement: None,
            unaccepted_input: None,
            archive,
            closed: false,
        };
        let mut unissued = None;
        let mut first = match setup {
            Ok(lifecycle) => {
                match lifecycle.into_main_lifecycle() {
                    Ok(lifecycle) => replay.lifecycle = Some(lifecycle),
                    Err(first) => unissued = Some(first),
                }
                None
            }
            Err(first) => Some(first),
        };
        // The witnessed Loop is armed before any projection destructor runs.
        // Normal refusal moves these aliases to Main; unwind destroys them and
        // records only their own return. Native body and World stay Main-owned.
        let input = projection.into_retirement_input().ok_or_else(|| {
            ImportedProductionReplayError::Prepared(
                service.failure("retain imported replay projection output"),
            )
        })?;
        replay.unaccepted_input = Some(input);
        if let Some(first) = unissued {
            // An invalid export stays an explicit owning error, never a live
            // facade. Preserve its same body even if input adoption also fails.
            let receiver_return = replay.prepared.as_ref().and_then(|prepared| {
                prepared
                    .service_main_handle()
                    .adopt_retirement_input(&mut replay.unaccepted_input)
                    .err()
                    .map(|refusal| {
                        prepared.failure_with_refusal(
                            "retain unissued imported replay aliases",
                            refusal,
                        )
                    })
            });
            return Err(ImportedProductionReplayError::Unissued {
                first,
                custody: replay,
                receiver_return,
            });
        }
        let replay = replay.adopt_input(&mut first)?;
        match first {
            Some(first) => Err(ImportedProductionReplayError::Launch(Box::new(first))),
            None => {
                let Some(source) = replay.prepared.as_ref() else {
                    return Err(ImportedProductionReplayError::Unavailable);
                };
                // Custody-only adoption can accept a poisoned destination into
                // quarantine. It must never make that body available for work.
                source
                    .service_main_handle()
                    .with_ready(|_| ())
                    .map_err(|first| {
                        ImportedProductionReplayError::Prepared(source.failure_with_refusal(
                            "publish imported replay from live Service",
                            first,
                        ))
                    })?;
                Ok(replay)
            }
        }
    }
}

impl Drop for ImportedProductionCheckpointReplay {
    fn drop(&mut self) {
        if let Some(mut lifecycle) = self.lifecycle.take() {
            // The validated wrapper owns its nonoptional original destination.
            // This fixed move cannot refuse or discard an owning return error.
            lifecycle.return_to_main();
        }
        if let Some(source) = self.prepared.take() {
            drop(source.into_retirement());
        }
    }
}

/// Returns only aliases actually owned by this scoped construction projection.
///
/// The input pair moves together on success. During unwind, context and basis
/// destruction precede the recorded receiver ACK; the original Main still owns
/// native partial construction and no World return is inferred from this Drop.
struct ImportedReplayProjection {
    input: Option<(ImportedCheckpointBasis, crate::ServiceMainReceiver)>,
    context: Option<AttemptExecutionContext>,
    context_release_started: bool,
    context_released: bool,
}

impl ImportedReplayProjection {
    fn new(basis: ImportedCheckpointBasis, receiver: crate::ServiceMainReceiver) -> Self {
        Self {
            input: Some((basis, receiver)),
            context: None,
            context_release_started: false,
            context_released: false,
        }
    }

    fn begin_resume(
        &mut self,
        service: &crate::lifecycle_cleanup::ServiceMainHandle,
        prepared: &ReplaySource,
        factory: &mut QemuAttemptProductionVmLifecycleFactory<ReplayResources>,
        checkpoints: &crate::ExactCheckpointStore,
    ) -> Result<ProductionVmLifecycleLoop, crate::QemuAttemptProductionVmLifecycleError> {
        self.context = Some(
            service
                .with_ready(|ready| ready.context().clone())
                .map_err(|first| {
                    crate::QemuAttemptProductionVmLifecycleError::from(
                        prepared.failure_with_refusal(
                            "project imported replay construction context",
                            first,
                        ),
                    )
                })?,
        );
        let (Some((basis, _)), Some(context)) = (&self.input, &self.context) else {
            return Err(prepared
                .failure("borrow imported replay construction inputs")
                .into());
        };
        let scenario = basis.source.scenario_def();
        factory.begin_resume(
            checkpoints,
            basis.checkpoint,
            crate::QemuExactResumeBasis::new(&scenario, &basis.source, &basis.configuration, None),
            context,
        )
    }

    fn release_context(&mut self) {
        if !self.context_release_started {
            // Taking an Option is not evidence that its destructor returned.
            // A later guard Drop must preserve an entered, uncertain release.
            self.context_release_started = true;
            drop(self.context.take());
            self.context_released = true;
        }
    }

    fn into_retirement_input(mut self) -> Option<ServiceRetirementInput> {
        self.release_context();
        if !self.context_released {
            return None;
        }
        self.input
            .take()
            .map(|(basis, receiver)| ServiceRetirementInput::from_imported_basis(basis, receiver))
    }
}

impl Drop for ImportedReplayProjection {
    fn drop(&mut self) {
        self.release_context();
        if !self.context_released {
            // Ordinary field destruction cannot acknowledge unknown aliases.
            // The same unacknowledged receiver leaves Main credit occupied.
            return;
        }
        if let Some((basis, receiver)) = self.input.take() {
            drop(basis);
            match receiver.return_after_alias_destruction() {
                Ok(()) => {}
                Err(receiver) => {
                    // This same token has recorded actual alias destruction.
                    // Its Drop retries only that pure ACK; failure never proves
                    // native closure or returns the containing Service credit.
                    drop(receiver);
                }
            }
        }
    }
}

/// Requests only original-role retirement after actor-owned aliases are gone.
struct DebugReplayCustody {
    source: Option<ReplaySource>,
}

impl Drop for DebugReplayCustody {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            // The actor still owns and returns the real Loop. This selector is
            // neither a synthetic body return nor an independent Service owner.
            drop(source.into_retirement());
        }
    }
}

// No alias left the Service when taking the basis refused. The ordinary
// receiver records actual destruction separately from the initiating refusal.
fn return_unopened_receiver(
    first: crate::PreparedSourceFailure,
    receiver: crate::ServiceMainReceiver,
) -> ImportedProductionReplayError {
    match receiver.return_after_alias_destruction() {
        Ok(()) => ImportedProductionReplayError::Prepared(first),
        Err(receiver) => ImportedProductionReplayError::PreparedReturn {
            first,
            receiver_return: receiver.into_failure("return unopened replay output"),
        },
    }
}

impl ImportedProductionCheckpointReplay {
    fn adopt_input(
        mut self,
        first: &mut Option<crate::QemuAttemptProductionVmLifecycleError>,
    ) -> Result<Self, ImportedProductionReplayError> {
        let Some(prepared) = self.prepared.as_ref() else {
            return Err(ImportedProductionReplayError::Unavailable);
        };
        if let Err(refusal) = prepared
            .service_main_handle()
            .adopt_retirement_input(&mut self.unaccepted_input)
        {
            let refusal = prepared.failure_with_refusal("retain imported replay aliases", refusal);
            let (first, receiver_return) = match first.take() {
                Some(first) => (first, Some(refusal)),
                None => (refusal.into(), None),
            };
            return Err(ImportedProductionReplayError::InputReturn {
                first: Box::new(first),
                custody: self,
                receiver_return,
            });
        }
        Ok(self)
    }
}

impl std::fmt::Debug for ImportedProductionCheckpointReplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedProductionCheckpointReplay")
            .field("archive", &self.archive)
            .field("lifecycle", &self.lifecycle.is_some())
            .field("prepared", &self.prepared.is_some())
            .field("retirement", &self.retirement.is_some())
            .field("unaccepted_input", &self.unaccepted_input.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// Refusal while realizing a receiver-authenticated imported root.
#[derive(Debug, Error)]
pub enum ImportedProductionReplayError {
    /// The packaged replay factory or terminal lifecycle has no live authority.
    #[error("imported replay authority is unavailable")]
    Unavailable,
    /// Unpublished input remains owned when no replay configuration is selected.
    #[error("imported replay authority is unavailable before Main publication")]
    UnavailableInput(UnpublishedImportedInput),
    /// Actual backend refusal retains the same unpublished imported body.
    #[error("imported replay checkpoint store before Main: {first}")]
    StoreInput {
        /// Retains the actual backend refusal.
        #[source]
        first: crate::ExactCheckpointStoreError,
        /// Owns the input until its cleanup-only alias return.
        input: UnpublishedImportedInput,
    },
    /// Actual compatibility refusal retains the same unpublished imported body.
    #[error("imported replay compatibility before Main: {first}")]
    CompatibilityInput {
        /// Retains the actual selected-basis refusal.
        #[source]
        first: QemuVmRealizationError,
        /// Owns the input until its cleanup-only alias return.
        input: UnpublishedImportedInput,
    },
    /// The actual prebirth Source refusal retains its unpublished input.
    #[error("imported replay Source preparation: {0}")]
    Preparation(#[source] crate::ImportedSourcePreparationFailure),
    /// Service admission preserves the initiating failure when Main was not entered.
    #[error("imported replay Service admission: {first}; Main access: {access}")]
    ServiceAdmission {
        /// Retains the actual earlier admission failure without string conversion.
        #[source]
        first: crate::PackagedQemuExecutorError,
        /// Retains the separate failed attempt to install that cause in Main.
        access: crate::PreparedSourceFailure,
    },
    /// The same Main retains the actual Service or construction cause.
    #[error("imported replay prepared Source: {0}")]
    Prepared(#[source] crate::PreparedSourceFailure),
    /// Exact physical retirement remains bounded or uncertain.
    #[error("imported replay retirement: {0}")]
    Retirement(#[source] crate::PreparedSourceRefusal),
    /// Pristine input remains owned when the genesis Service cannot close.
    #[error("imported replay genesis handoff: {0}")]
    GenesisHandoff(#[source] crate::imported_checkpoint::ImportedCheckpointHandoffFailure),
    /// Genesis capture and its independent receiver-return refusal stay separate.
    #[error("imported replay genesis capture: {first}")]
    GenesisRetained {
        /// Retains the original capture failure.
        #[source]
        first: Box<
            crate::ProductionBakedGenesisCaptureError<crate::QemuAttemptProductionVmLifecycleError>,
        >,
        /// Selects the same Main holding actual imported input and native state.
        custody: crate::PreparedSourceFailure,
        /// Retains the independent exact receiving-alias refusal.
        receiver_return: Option<crate::PreparedSourceFailure>,
    },
    /// Catalog failure retains the original Main input.
    #[error("imported replay catalog: {first}")]
    CatalogRetained {
        /// Retains the actual catalog refusal.
        #[source]
        first: crate::ProductionBakedGenesisReplayCatalogError,
        /// Selects the Main that still owns the original input.
        custody: crate::PreparedSourceFailure,
    },
    /// Keeps independent initiating and receiving-alias return refusals.
    #[error("imported replay prepared Source: {first}")]
    PreparedReturn {
        /// Selects the original initiating cause.
        #[source]
        first: crate::PreparedSourceFailure,
        /// Selects the independent receiver-return refusal.
        receiver_return: crate::PreparedSourceFailure,
    },
    /// Rejected Main input adoption keeps the complete local owner intact.
    #[error("imported replay input return: {first}")]
    InputReturn {
        /// Retains the actual first construction or input-adoption refusal.
        #[source]
        first: Box<crate::QemuAttemptProductionVmLifecycleError>,
        /// Owns the actual lifecycle and unaccepted receiving input.
        custody: ImportedProductionCheckpointReplay,
        /// Retains a later independent same-role adoption refusal.
        receiver_return: Option<crate::PreparedSourceFailure>,
    },
    /// Invalid export keeps the actual unissued body and original input custody.
    #[error("imported replay lifecycle export: {first}")]
    Unissued {
        /// Owns the same actual Loop and its refused export precondition.
        #[source]
        first: MainSourceLifecycleFailure,
        /// Retains the exact Main selection and any unaccepted input.
        custody: ImportedProductionCheckpointReplay,
        /// Records an independent input-adoption refusal without replacing first.
        receiver_return: Option<crate::PreparedSourceFailure>,
    },
    /// Actual returned body retains negative terminal history.
    #[error("imported replay terminal history: {0}")]
    Terminal(#[source] crate::ProductionVmConstructionPostBody),
    /// Concrete debug-session retention admission refused before Loop exposure.
    #[error("imported replay debug retention: {0}")]
    Retention(#[source] crucible_engine::owned_decode::DecodeAdmissionError),
    /// Exact native lifecycle construction refused the selected root.
    #[error("imported replay native launch: {0}")]
    Launch(#[source] Box<crate::QemuAttemptProductionVmLifecycleError>),
}

#[cfg(test)]
mod tests;
