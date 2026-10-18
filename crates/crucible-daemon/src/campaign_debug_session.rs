//! Production composition for snapshot-bound campaign debug sessions.
//!
//! This module joins campaign proof authentication, the owner-only exact
//! checkpoint store, guarded QEMU restoration, and the shared lifecycle
//! control plane. No checkpoint bytes or mutable campaign capability cross the
//! component protocol.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use crate::{ProductionVmLifecycleConfig, ProductionVmLifecycleLoop};
use crucible::{Checkpoint, Configuration, ScenarioDef, ScenarioDefForm};
use crucible_api::{
    InProcessLifecycleClient, LifecycleApiError, ResumeSessionResponse, SessionLifetimeRetention,
    SessionRef, SessionRetentionUpdateError,
};
use crucible_campaign::{
    CampaignFindingObject, CampaignHash, CampaignName, CampaignRepository, CampaignServiceFailure,
    CampaignSnapshotId, ExactCheckpointId, FindingExactPins, FindingId,
    GetCampaignFindingObjectResponse,
};

use crate::campaign_debug_inventory::CampaignDebugSessionInventory;
use crate::crucible_artifact::{
    campaign_configuration_id, campaign_scenario_id,
    decode_crucible_configuration_artifact_from_repository,
};
use crate::executor_supervisor::SelectedExactCheckpointRoot;
use crate::packaged_qemu_executor::RetainedTemplateServiceFactory;
use crate::packaged_qemu_executor::guarded::RetainedOperationError;
use crate::qemu_campaign_resume::QemuExactResumeBasis;
use crate::qemu_resource_guard::QemuAttemptSelectedHostResourceFactory;
use crate::{
    CampaignDebugCheckpointRole, CampaignDebugControlService,
    ComposedQemuAttemptResourceGuardFactory, ExactCheckpointStore, ExecutionCancellation,
    LoadedProductionExactCheckpoint, OpenCampaignDebugSessionRequest,
    OpenCampaignDebugSessionResponse, QemuAttemptHostResourceFactory, QemuAttemptHostResourceOwner,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleFactory,
    SharedQemuAttemptHostResourceFactory, decode_crucible_scenario_artifact,
};

/// Owner-side admission into the lifecycle plane shared with the debug relay.
pub trait CampaignDebugLifecycleAdmission: Send + Sync {
    /// Admits an authenticated restore and returns its stable session identity.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] for capacity, identity, graph, or guarded
    /// lifecycle construction failures.
    fn admit(
        &self,
        request: PreparedCampaignDebugLifecycle,
    ) -> Result<ResumeSessionResponse, LifecycleApiError>;
}

/// Complete owner-authenticated input for one read-only lifecycle admission.
pub struct PreparedCampaignDebugLifecycle {
    pub(crate) source: ScenarioDefForm,
    pub(crate) configuration: Configuration,
    pub(crate) checkpoint: Checkpoint,
    pub(crate) build_loop: Box<
        dyn FnOnce() -> Result<ProductionVmLifecycleLoop, CampaignDebugLifecycleBuildError> + Send,
    >,
    pub(crate) retention: SessionLifetimeRetention,
    pub(crate) decoding: Option<crucible::owned_decode::DecodeBudget>,
}

impl PreparedCampaignDebugLifecycle {
    /// Admits this prepared restore through an in-process lifecycle client.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] for capacity, identity, graph, or guarded
    /// lifecycle construction failures.
    pub async fn admit<F>(
        self,
        lifecycle: &InProcessLifecycleClient<ProductionVmLifecycleLoop, F>,
    ) -> Result<ResumeSessionResponse, LifecycleApiError>
    where
        F: Fn(
                &ScenarioDef,
                Option<&ScenarioDefForm>,
                crucible::Seed,
            ) -> Result<ProductionVmLifecycleLoop, LifecycleApiError>
            + Send
            + Sync
            + 'static,
    {
        let Self {
            source,
            configuration,
            checkpoint,
            retention,
            decoding,
            build_loop,
        } = self;
        let seed = source.scenario_def().seed();
        lifecycle
            .admit_authenticated_read_only_session_with_decode_budget(
                source,
                configuration,
                checkpoint,
                seed,
                (build_loop, retention, decoding),
            )
            .await
    }
}

/// Stable opaque failure from guarded production lifecycle construction.
#[derive(Debug, thiserror::Error)]
#[error("guarded campaign debug lifecycle construction failed: {source}")]
pub struct CampaignDebugLifecycleBuildError {
    #[source]
    source: RetainedOperationError,
}

impl CampaignDebugLifecycleBuildError {
    fn new(source: impl std::error::Error + Send + 'static) -> Self {
        Self {
            source: RetainedOperationError::new(source),
        }
    }
}

/// Linear root authentication and the session's actual physical Service slot.
struct AuthenticatedDebugRestore {
    checkpoint: ExactCheckpointId,
    selected: Option<SelectedExactCheckpointRoot>,
    service: crate::lifecycle_cleanup::ServiceMainHandle,
}

enum DebugSourceRequest<'a> {
    Prepare,
    Resume {
        scenario: &'a ScenarioDef,
        source: &'a ScenarioDefForm,
        configuration: &'a Configuration,
        restore: AuthenticatedDebugRestore,
    },
}

enum DebugSourceOutput {
    Prepared(crate::lifecycle_cleanup::ServiceMainHandle),
    Restored(ProductionVmLifecycleLoop),
}

type GuardedResumeBuilder = dyn for<'a> Fn(
        DebugSourceRequest<'a>,
    ) -> Result<DebugSourceOutput, CampaignDebugLifecycleBuildError>
    + Send
    + Sync;

/// Cloneable owner capability for inspecting and restoring packaged checkpoints.
pub struct CampaignDebugQemuCapability {
    checkpoints: Arc<ExactCheckpointStore>,
    services: RetainedTemplateServiceFactory,
    build_resume: Arc<GuardedResumeBuilder>,
}

impl CampaignDebugQemuCapability {
    pub(crate) fn new<H>(
        checkpoints: Arc<ExactCheckpointStore>,
        lifecycle: impl Into<Arc<ProductionVmLifecycleConfig>>,
        shared: SharedQemuAttemptHostResourceFactory<H>,
        services: RetainedTemplateServiceFactory,
    ) -> Self
    where
        H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
        H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
        crate::ComposedQemuAttemptResourceGuard<H::Owner>:
            QemuAttemptProcessResourceGuard + Send + 'static,
    {
        let lifecycle = lifecycle.into();
        let restore_checkpoints = Arc::clone(&checkpoints);
        let build_resume: Arc<GuardedResumeBuilder> = Arc::new(move |request| match request {
            DebugSourceRequest::Prepare => {
                let resource_guards = ComposedQemuAttemptResourceGuardFactory::new(shared.clone());
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    Arc::clone(&lifecycle),
                    resource_guards,
                );
                factory
                    .prepare_source_construction()
                    .map(DebugSourceOutput::Prepared)
                    .map_err(CampaignDebugLifecycleBuildError::new)
            }
            DebugSourceRequest::Resume {
                scenario,
                source,
                configuration,
                mut restore,
            } => {
                type Resources<H> = ComposedQemuAttemptResourceGuardFactory<
                    SharedQemuAttemptHostResourceFactory<H>,
                >;
                let prepared = crate::qemu_lifecycle_launcher::PreparedSourceHandle::<Resources<H>>::from_selector(
                        restore.service.prepared_selector(),
                    );
                let result = restore.service.with_start(|start| {
                    start.bind_debug_from_saved_original(restore.checkpoint, &mut restore.selected)
                });
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        return Err(CampaignDebugLifecycleBuildError::new(
                            prepared.failure("bind debug selected root"),
                        ));
                    }
                    Err(first) => {
                        return Err(CampaignDebugLifecycleBuildError::new(
                            prepared.failure_with_refusal("bind debug selected root", first),
                        ));
                    }
                }
                // Session retention holds the same one Main receiver across
                // this builder and the actor body; these local projections
                // stay inside that already registered receiver's lifetime.
                let restored = (|| {
                    let context = restore
                        .service
                        .with_ready(|service| service.context().clone())
                        .map_err(|first| {
                            CampaignDebugLifecycleBuildError::new(
                                prepared
                                    .failure_with_refusal("borrow debug restore context", first),
                            )
                        })?;
                    let lifecycle = crate::qemu_campaign_lifecycle::resume_prepared_source(
                        &prepared,
                        lifecycle.as_ref(),
                        None,
                        &restore_checkpoints,
                        restore.checkpoint,
                        QemuExactResumeBasis::new(scenario, source, configuration, None),
                        &context,
                        crate::vm_lifecycle::RetainedConstructionExposure::Released,
                    )
                    .map_err(CampaignDebugLifecycleBuildError::new)?;
                    match restore
                        .service
                        .with_start(|start| start.complete_authentication_original())
                    {
                        Ok(Ok(())) => Ok(lifecycle),
                        Ok(Err(_)) => {
                            drop(lifecycle);
                            Err(CampaignDebugLifecycleBuildError::new(
                                prepared.failure("complete debug restore original"),
                            ))
                        }
                        Err(first) => {
                            drop(lifecycle);
                            Err(CampaignDebugLifecycleBuildError::new(
                                prepared
                                    .failure_with_refusal("complete debug restore original", first),
                            ))
                        }
                    }
                })();
                restored.map(DebugSourceOutput::Restored)
            }
        });
        Self {
            checkpoints,
            services,
            build_resume,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DebugSessionKey {
    campaign: CampaignName,
    finding: FindingId,
}

enum DebugSessionReservation {
    Preparing(CampaignHash),
    Active {
        request_digest: CampaignHash,
        snapshot: CampaignSnapshotId,
        response: Box<OpenCampaignDebugSessionResponse>,
    },
}

struct DebugSessionReservations {
    entries: Mutex<BTreeMap<DebugSessionKey, DebugSessionReservation>>,
}

impl DebugSessionReservations {
    fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }
}

/// Session-owned lease that releases only its exact reservation generation.
struct DebugSessionReservationLease {
    reservations: Weak<DebugSessionReservations>,
    key: DebugSessionKey,
    request_digest: CampaignHash,
    session: Mutex<Option<SessionRef>>,
}

impl DebugSessionReservationLease {
    fn new(
        reservations: &Arc<DebugSessionReservations>,
        key: DebugSessionKey,
        request_digest: CampaignHash,
    ) -> Self {
        Self {
            reservations: Arc::downgrade(reservations),
            key,
            request_digest,
            session: Mutex::new(None),
        }
    }

    fn bind_session(&self, session: SessionRef) {
        let mut bound = match self.session.lock() {
            Ok(bound) => bound,
            Err(poisoned) => poisoned.into_inner(),
        };
        *bound = Some(session);
    }
}

impl Drop for DebugSessionReservationLease {
    fn drop(&mut self) {
        let Some(reservations) = self.reservations.upgrade() else {
            return;
        };
        let bound_session = match self.session.lock() {
            Ok(bound) => *bound,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let mut entries = match reservations.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        let matches_lease = match entries.get(&self.key) {
            Some(DebugSessionReservation::Preparing(digest)) => *digest == self.request_digest,
            Some(DebugSessionReservation::Active {
                request_digest,
                response,
                ..
            }) => {
                *request_digest == self.request_digest
                    && bound_session.is_some_and(|session| response.session() == session)
            }
            None => false,
        };
        if matches_lease {
            entries.remove(&self.key);
        }
    }
}

/// Canonical campaign-proof and exact-restore debug session owner.
pub struct CanonicalCampaignDebugController {
    repository: Arc<CampaignRepository>,
    qemu: Arc<CampaignDebugQemuCapability>,
    lifecycle: Arc<dyn CampaignDebugLifecycleAdmission>,
    inventory: Arc<CampaignDebugSessionInventory>,
    reservations: Arc<DebugSessionReservations>,
}

impl CanonicalCampaignDebugController {
    /// Creates a controller and recovers every durable debug session.
    ///
    /// # Errors
    ///
    /// Returns a campaign service failure when a retained proof, checkpoint,
    /// artifact, or lifecycle admission cannot be recovered exactly.
    pub(crate) fn new(
        repository: Arc<CampaignRepository>,
        qemu: Arc<CampaignDebugQemuCapability>,
        lifecycle: Arc<dyn CampaignDebugLifecycleAdmission>,
        inventory: Arc<CampaignDebugSessionInventory>,
    ) -> Result<Self, CampaignServiceFailure> {
        let controller = Self {
            repository,
            qemu,
            lifecycle,
            inventory,
            reservations: Arc::new(DebugSessionReservations::new()),
        };
        for record in controller
            .inventory
            .records()
            .map_err(map_inventory_failure)?
        {
            controller.open(record.request(), record.finding().clone())?;
        }
        Ok(controller)
    }

    fn open(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: GetCampaignFindingObjectResponse,
    ) -> Result<OpenCampaignDebugSessionResponse, CampaignServiceFailure> {
        authenticate_finding_response(request, &finding)?;
        let key = DebugSessionKey {
            campaign: request.campaign().clone(),
            finding: request.finding(),
        };
        let digest = request.request_digest();
        {
            let mut reservations = self
                .reservations
                .entries
                .lock()
                .map_err(|_| CampaignServiceFailure::Unavailable)?;
            match reservations.get(&key) {
                Some(DebugSessionReservation::Active {
                    snapshot, response, ..
                }) if *snapshot == request.snapshot() => {
                    response
                        .validate_for(request)
                        .map_err(|_| CampaignServiceFailure::CommandReuse)?;
                    return Ok(response.as_ref().clone());
                }
                Some(DebugSessionReservation::Preparing(existing)) if *existing == digest => {
                    return Err(CampaignServiceFailure::Unavailable);
                }
                Some(_) => return Err(CampaignServiceFailure::AlreadyExists),
                None => {
                    reservations.insert(key.clone(), DebugSessionReservation::Preparing(digest));
                }
            }
        }

        let lease = Arc::new(DebugSessionReservationLease::new(
            &self.reservations,
            key.clone(),
            digest,
        ));
        let result = self.prepare_and_admit(request, finding, Arc::clone(&lease));
        let mut reservations = self
            .reservations
            .entries
            .lock()
            .map_err(|_| CampaignServiceFailure::Unavailable)?;
        match result {
            Ok(response) => {
                reservations.insert(
                    key,
                    DebugSessionReservation::Active {
                        request_digest: digest,
                        snapshot: request.snapshot(),
                        response: Box::new(response.clone()),
                    },
                );
                Ok(response)
            }
            Err(error) => {
                if matches!(
                    reservations.get(&key),
                    Some(DebugSessionReservation::Preparing(existing)) if *existing == digest
                ) {
                    reservations.remove(&key);
                }
                Err(error)
            }
        }
    }

    fn prepare_and_admit(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: GetCampaignFindingObjectResponse,
        reservation: Arc<DebugSessionReservationLease>,
    ) -> Result<OpenCampaignDebugSessionResponse, CampaignServiceFailure> {
        let reproduction = match finding.object() {
            CampaignFindingObject::Reproduction(reproduction) => reproduction,
            _ => return Err(CampaignServiceFailure::ProtocolViolation),
        };
        let scenario_artifact = self
            .repository
            .load_scenario_artifact(reproduction.scenario_artifact())
            .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
        let source = decode_crucible_scenario_artifact(&scenario_artifact)
            .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
        let configuration_artifact = self
            .repository
            .load_configuration_artifact(reproduction.configuration_artifact())
            .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
        let reproduction_configuration = decode_crucible_configuration_artifact_from_repository(
            &source,
            &scenario_artifact,
            &configuration_artifact,
            &self.repository,
        )
        .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
        if reproduction.scenario() != campaign_scenario_id(source.id())
            || reproduction.configuration()
                != campaign_configuration_id(reproduction_configuration.id())
        {
            return Err(CampaignServiceFailure::IntegrityFailure);
        }

        let service = match (self.qemu.build_resume)(DebugSourceRequest::Prepare)
            .map_err(|_| CampaignServiceFailure::Unavailable)?
        {
            DebugSourceOutput::Prepared(service) => service,
            DebugSourceOutput::Restored(_unexpected) => {
                return Err(CampaignServiceFailure::ProtocolViolation);
            }
        };
        let startup = service.with_start(|start| {
            self.qemu.services.start_for_archive_authentication(
                start,
                &source,
                ExecutionCancellation::default(),
            )?;
            start.begin_authentication_original(
                crucible_linux_resource::host_supervision::HostOperationClass::Restore,
            )
        });
        match startup {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                let _retained = service
                    .prepared_selector()
                    .typed::<()>()
                    .failure("start debug authentication Service");
                return Err(CampaignServiceFailure::Unavailable);
            }
            Err(first) => {
                let _retained =
                    service.failure_with_refusal("start debug authentication Service", first);
                return Err(CampaignServiceFailure::Unavailable);
            }
        }
        let service_borrow =
            DebugServiceBorrow::new(service.prepared_selector().service_main_handle())
                .map_err(|_| CampaignServiceFailure::Unavailable)?;
        let cancellation = service_borrow
            .cancellation
            .as_ref()
            .ok_or(CampaignServiceFailure::Unavailable)?;
        let mut selection_boundary =
            || match service.with_start(|start| start.check_authentication_original()) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(CampaignServiceFailure::Unavailable),
                Err(first) => {
                    let _retained =
                        service.failure_with_refusal("check debug selection original", first);
                    Err(CampaignServiceFailure::Unavailable)
                }
            };
        selection_boundary()?;

        let SelectedCampaignDebugCheckpoint {
            role,
            checkpoint,
            loaded,
            configuration,
            modeled_checkpoint,
            ..
        } = select_finding_debug_checkpoint_with_boundary(
            &source,
            &reproduction_configuration,
            finding.finding().exact_pin_retention(),
            &self.qemu.checkpoints,
            &cancellation,
            &mut selection_boundary,
        )?;
        selection_boundary()?;
        let response_encoding = OpenCampaignDebugSessionResponse::prepare_encoding(checkpoint)
            .map_err(|_| CampaignServiceFailure::InvalidRequest)?;
        let build_resume = Arc::clone(&self.qemu.build_resume);
        let restore = AuthenticatedDebugRestore {
            checkpoint,
            selected: Some(
                SelectedExactCheckpointRoot::after_authenticated_campaign_finding(checkpoint),
            ),
            service,
        };
        let build_source = source
            .try_clone_admitted()
            .map_err(|_| CampaignServiceFailure::ResourceExhausted)?;
        let build_configuration = configuration
            .try_clone_admitted()
            .map_err(|_| CampaignServiceFailure::ResourceExhausted)?;
        let configuration_id = configuration.id();
        let build_scenario = source.scenario_def();
        let destroy_inventory = Arc::clone(&self.inventory);
        let destroy_request = request.clone();
        let admitted = admit_with_inventory(&self.inventory, request, finding, |finding| {
            let destroy_callback = move || {
                destroy_inventory
                    .remove(&destroy_request)
                    .map_err(|error| SessionRetentionUpdateError::new(error.to_string()))
            };
            // The configured Arc header and this concrete closure are a
            // separate fixed allocation. Captured payloads retain their
            // existing admitted owners; this charges no invented allowance.
            let callback_layout = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
                .extend(std::alloc::Layout::for_value(&destroy_callback))
                .map_err(|first| {
                    LifecycleApiError::ConfigurationCopy(
                        crucible::owned_decode::DecodeAdmissionError::new(first),
                    )
                })?
                .0
                .pad_to_align();
            let _same_request = crucible::owned_decode::require_current_custody()
                .map_err(LifecycleApiError::ConfigurationCopy)?;
            crucible::owned_decode::charge_bytes(callback_layout.size() as u64)
                .map_err(LifecycleApiError::ConfigurationCopy)?;
            let retention = SessionLifetimeRetention::try_new_admitted(DebugSessionRetention {
                _finding_proof: finding,
                _checkpoint: loaded,
                _reservation: Arc::clone(&reservation),
                _service: service_borrow,
            })
            .map_err(LifecycleApiError::ConfigurationCopy)?
            .with_destroy_callback(destroy_callback);
            let build_loop = move || match build_resume(DebugSourceRequest::Resume {
                scenario: &build_scenario,
                source: &build_source,
                configuration: &build_configuration,
                restore,
            })? {
                DebugSourceOutput::Restored(lifecycle) => Ok(lifecycle),
                DebugSourceOutput::Prepared(_unexpected) => Err(
                    CampaignDebugLifecycleBuildError::new(std::io::Error::other(
                        "debug restore returned preparation instead of World",
                    )),
                ),
            };
            crucible::owned_decode::charge_bytes(
                std::alloc::Layout::for_value(&build_loop).size() as u64
            )
            .map_err(LifecycleApiError::ConfigurationCopy)?;
            let lifecycle = PreparedCampaignDebugLifecycle {
                source,
                configuration,
                checkpoint: modeled_checkpoint,
                retention,
                decoding: crucible::owned_decode::current_budget(),
                build_loop: Box::new(build_loop),
            };
            self.lifecycle.admit(lifecycle)
        })?;
        reservation.bind_session(admitted.session);
        Ok(response_encoding.finish(request, role, configuration_id, admitted.session))
    }
}

fn admit_with_inventory<T>(
    inventory: &CampaignDebugSessionInventory,
    request: &OpenCampaignDebugSessionRequest,
    finding: GetCampaignFindingObjectResponse,
    admit: impl FnOnce(GetCampaignFindingObjectResponse) -> Result<T, LifecycleApiError>,
) -> Result<T, CampaignServiceFailure> {
    // Persist before admission so a live session always has a recovery basis.
    // A failed readmission must leave its previously durable record intact.
    let newly_retained = inventory
        .retain(request, &finding)
        .map_err(map_inventory_failure)?;

    match admit(finding) {
        Ok(admitted) => Ok(admitted),
        Err(error) => {
            if newly_retained {
                inventory.remove(request).map_err(map_inventory_failure)?;
            }
            Err(map_lifecycle_failure(error))
        }
    }
}

/// Applies the live debug selection rule to one authenticated finding pin set.
pub(crate) fn select_finding_debug_checkpoint_with_boundary(
    source: &ScenarioDefForm,
    reproduction: &Configuration,
    pins: &FindingExactPins,
    checkpoints: &ExactCheckpointStore,
    cancellation: &ExecutionCancellation,
    boundary: &mut dyn FnMut() -> Result<(), CampaignServiceFailure>,
) -> Result<SelectedCampaignDebugCheckpoint, CampaignServiceFailure> {
    let roles = [
        (
            CampaignDebugCheckpointRole::PostFailure,
            pins.post_failure(),
        ),
        (CampaignDebugCheckpointRole::PreFailure, pins.pre_failure()),
        (
            CampaignDebugCheckpointRole::MeasurementBoundary,
            pins.measurement_boundary(),
        ),
        (CampaignDebugCheckpointRole::Additional, pins.additional()),
    ];
    let mut selected: Option<SelectedCampaignDebugCheckpoint> = None;
    for (role, candidates) in roles {
        for checkpoint in candidates {
            boundary()?;
            let loaded = checkpoints
                .load_production_closure_with_cancellation(*checkpoint, cancellation)
                .map_err(map_checkpoint_selection_failure)?;
            if loaded.scenario() != source.scenario_def().id() {
                return Err(CampaignServiceFailure::IntegrityFailure);
            }
            let loaded = Arc::new(loaded);
            let decoded = checkpoints
                .decode_semantic_checkpoint(&loaded, source, cancellation)
                .map_err(map_checkpoint_selection_failure)?;
            let configuration = decoded
                .configuration()
                .try_clone_admitted()
                .map_err(|_| CampaignServiceFailure::ResourceExhausted)?;
            if !reproduction
                .schedule
                .decisions()
                .starts_with(configuration.schedule.decisions())
            {
                return Err(CampaignServiceFailure::IntegrityFailure);
            }
            let modeled = decoded
                .modeled_checkpoint()
                .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
            let cost = loaded
                .authenticated_restore_bytes()
                .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
            let candidate = SelectedCampaignDebugCheckpoint {
                restore_bytes: cost,
                checkpoint: *checkpoint,
                role,
                loaded,
                configuration,
                modeled_checkpoint: modeled,
            };
            if selected
                .as_ref()
                .is_none_or(|current| candidate.selection_key() < current.selection_key())
            {
                selected = Some(candidate);
            }
        }
    }
    selected.ok_or(CampaignServiceFailure::NotFound)
}

pub(crate) struct SelectedCampaignDebugCheckpoint {
    pub(crate) restore_bytes: u64,
    pub(crate) checkpoint: ExactCheckpointId,
    pub(crate) role: CampaignDebugCheckpointRole,
    pub(crate) loaded: Arc<LoadedProductionExactCheckpoint>,
    pub(crate) configuration: Configuration,
    pub(crate) modeled_checkpoint: Checkpoint,
}

impl SelectedCampaignDebugCheckpoint {
    fn selection_key(&self) -> (u64, u8, ExactCheckpointId) {
        debug_checkpoint_selection_key(self.restore_bytes, self.role, self.checkpoint)
    }
}

struct DebugSessionRetention {
    _finding_proof: GetCampaignFindingObjectResponse,
    _checkpoint: Arc<LoadedProductionExactCheckpoint>,
    _reservation: Arc<DebugSessionReservationLease>,
    _service: DebugServiceBorrow,
}

// Declaration order destroys the retention's checkpoint aliases before this
// final receiver. The actual actor/World body has its independent Main return.
struct DebugServiceBorrow {
    cancellation: Option<ExecutionCancellation>,
    receiver: Option<crate::lifecycle_cleanup::ServiceMainReceiverHandle>,
    service: crate::lifecycle_cleanup::ServiceMainHandle,
}

impl DebugServiceBorrow {
    fn new(
        service: crate::lifecycle_cleanup::ServiceMainHandle,
    ) -> Result<Self, crate::PreparedSourceFailure> {
        let receiver = service.retain_receiver_in_main().map_err(|first| {
            service.failure_with_refusal("retain debug selection aliases", first)
        })?;
        let cancellation = match service.with_ready(|ready| ready.context().cancellation().clone())
        {
            Ok(cancellation) => cancellation,
            Err(first) => {
                let _returned = receiver.return_after_alias_destruction();
                return Err(service.failure_with_refusal("borrow debug selection aliases", first));
            }
        };
        Ok(Self {
            cancellation: Some(cancellation),
            receiver: Some(receiver),
            service,
        })
    }
}

impl Drop for DebugServiceBorrow {
    fn drop(&mut self) {
        drop(self.cancellation.take());
        if let Some(receiver) = self.receiver.take()
            && let Err(first) = receiver.return_after_alias_destruction()
        {
            let _retained = self
                .service
                .failure_with_refusal("return debug selection aliases", first);
        }
        // Any refused atomic acknowledgment remains in the original Main slot.
        // Dropping this selector cannot drop that actual receiver or its debt.
        let _retained = self
            .service
            .prepared_selector()
            .typed::<()>()
            .failure("retire debug session Service");
    }
}

/// Breaks equal complete-closure costs by semantic proximity, then root ID.
const fn debug_role_tie_break_rank(role: CampaignDebugCheckpointRole) -> u8 {
    match role {
        CampaignDebugCheckpointRole::PostFailure => 0,
        CampaignDebugCheckpointRole::PreFailure => 1,
        CampaignDebugCheckpointRole::MeasurementBoundary => 2,
        CampaignDebugCheckpointRole::Additional => 3,
    }
}

const fn debug_checkpoint_selection_key(
    restore_bytes: u64,
    role: CampaignDebugCheckpointRole,
    checkpoint: ExactCheckpointId,
) -> (u64, u8, ExactCheckpointId) {
    (restore_bytes, debug_role_tie_break_rank(role), checkpoint)
}

impl CampaignDebugControlService for CanonicalCampaignDebugController {
    fn open_campaign_debug_session(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: GetCampaignFindingObjectResponse,
    ) -> Result<OpenCampaignDebugSessionResponse, CampaignServiceFailure> {
        self.open(request, finding)
    }
}

fn authenticate_finding_response(
    request: &OpenCampaignDebugSessionRequest,
    finding: &GetCampaignFindingObjectResponse,
) -> Result<(), CampaignServiceFailure> {
    let proof_request = request
        .finding_object_request()
        .map_err(|_| CampaignServiceFailure::InvalidRequest)?;
    finding
        .validate_for(&proof_request)
        .map_err(|_| CampaignServiceFailure::ProtocolViolation)
}

fn map_inventory_failure(
    error: crate::CampaignDebugSessionInventoryError,
) -> CampaignServiceFailure {
    match error {
        crate::CampaignDebugSessionInventoryError::Capacity => {
            CampaignServiceFailure::ResourceExhausted
        }
        crate::CampaignDebugSessionInventoryError::Io(_)
        | crate::CampaignDebugSessionInventoryError::Poisoned => {
            CampaignServiceFailure::Unavailable
        }
        crate::CampaignDebugSessionInventoryError::Invalid
        | crate::CampaignDebugSessionInventoryError::InvalidRecord
        | crate::CampaignDebugSessionInventoryError::Conflict => {
            CampaignServiceFailure::IntegrityFailure
        }
    }
}

/// Keeps host cancellation and capacity refusal outside guest integrity claims.
fn map_checkpoint_selection_failure(
    error: crate::ExactCheckpointStoreError,
) -> CampaignServiceFailure {
    use crate::ExactCheckpointStoreError;
    match error {
        ExactCheckpointStoreError::Canceled
        | ExactCheckpointStoreError::Supervision(_)
        | ExactCheckpointStoreError::HostAuthority(_)
        | ExactCheckpointStoreError::UnsupportedBackend { .. }
        | ExactCheckpointStoreError::InvalidLimit
        | ExactCheckpointStoreError::NativeRetirement(_) => CampaignServiceFailure::Unavailable,
        ExactCheckpointStoreError::Store(source) => checkpoint_store_selection_failure(&source),
        ExactCheckpointStoreError::Ram(source) => checkpoint_ram_selection_failure(&source),
        ExactCheckpointStoreError::ArtifactLimit { .. } => {
            CampaignServiceFailure::ResourceExhausted
        }
        ExactCheckpointStoreError::Production(source) => map_lifecycle_failure(source),
        ExactCheckpointStoreError::InvalidRoot { .. }
        | ExactCheckpointStoreError::InvalidReceipt { .. }
        | ExactCheckpointStoreError::Envelope(_) => CampaignServiceFailure::IntegrityFailure,
    }
}

fn checkpoint_store_selection_failure(
    source: &crucible_cas::content_store::StoreError,
) -> CampaignServiceFailure {
    use crucible_cas::content_store::StoreError;

    match source.original_failure() {
        StoreError::RamValidation { source } => {
            checkpoint_ram_selection_failure(source.storage_failure())
        }
        StoreError::RamReadBoundary { source } => checkpoint_ram_selection_failure(
            source
                .first_boundary()
                .unwrap_or_else(|| source.storage_failure()),
        ),
        StoreError::RamReadValidation { source } => {
            checkpoint_ram_selection_failure(source.first_validation())
        }
        StoreError::RamReadContinuation { source } => {
            checkpoint_ram_selection_failure(source.first_failure())
        }
        StoreError::RamBoundary { .. } | StoreError::CompositeBoundary { .. } => {
            CampaignServiceFailure::IntegrityFailure
        }
        StoreError::Quota => CampaignServiceFailure::ResourceExhausted,
        StoreError::ProviderDiagnostic { source } => match source.kind() {
            crucible_cas::content_store::ProviderFailureKind::Resources => {
                CampaignServiceFailure::ResourceExhausted
            }
            crucible_cas::content_store::ProviderFailureKind::Supervision
            | crucible_cas::content_store::ProviderFailureKind::PhysicalQuota => {
                CampaignServiceFailure::Unavailable
            }
        },
        StoreError::Supervision { .. }
        | StoreError::Unavailable
        | StoreError::Unsupported { .. }
        | StoreError::Poisoned { .. }
        | StoreError::Io { .. }
        | StoreError::StreamIo { .. }
        | StoreError::DecodeAdmission { .. }
        | StoreError::Allocation { .. }
        | StoreError::SqliteDiagnostic { .. }
        | StoreError::DirectoryScope { .. }
        | StoreError::PackedScope { .. }
        | StoreError::MemoryScope { .. }
        | StoreError::AdministrativeScope { .. }
        | StoreError::CompositeScope { .. }
        | StoreError::SqliteHeap { .. }
        | StoreError::SqliteScope { .. }
        | StoreError::Unauthorized
        | StoreError::InvalidComposition { .. }
        | StoreError::InvalidGraph { .. }
        | StoreError::DurabilityUnsatisfied { .. }
        | StoreError::MultipartCleanupRequired => CampaignServiceFailure::Unavailable,
        StoreError::NotFound { .. }
        | StoreError::Corrupt { .. }
        | StoreError::InvalidId
        | StoreError::InvalidRefName { .. }
        | StoreError::InvalidRange { .. }
        | StoreError::Incompatible
        | StoreError::InvalidSourceLength { .. } => CampaignServiceFailure::IntegrityFailure,
    }
}

fn checkpoint_ram_selection_failure(
    source: &crucible_cas::ram::RamStoreError,
) -> CampaignServiceFailure {
    use crucible_cas::ram::RamStoreError;

    match source {
        RamStoreError::Boundary(cause) => checkpoint_ram_selection_failure(
            cause
                .first_boundary()
                .unwrap_or_else(|| cause.storage_failure()),
        ),
        RamStoreError::Store(error) => checkpoint_store_selection_failure(error),
        RamStoreError::Canceled | RamStoreError::Retention(_) => {
            CampaignServiceFailure::Unavailable
        }
        RamStoreError::Limit(_) => CampaignServiceFailure::ResourceExhausted,
        RamStoreError::Invalid(_)
        | RamStoreError::Logical(_)
        | RamStoreError::LogicalValidation(_)
        | RamStoreError::Envelope(_)
        | RamStoreError::Transfer(_) => CampaignServiceFailure::IntegrityFailure,
    }
}

fn map_lifecycle_failure(error: LifecycleApiError) -> CampaignServiceFailure {
    match error {
        LifecycleApiError::SessionLimitReached { .. }
        | LifecycleApiError::ResourceLimit(_)
        | LifecycleApiError::ConfigurationCopy(_) => CampaignServiceFailure::ResourceExhausted,
        LifecycleApiError::LoopFactory { .. }
        | LifecycleApiError::CleanupRetained
        | LifecycleApiError::BackendConstruction { .. }
        | LifecycleApiError::AttemptOperational { .. } => CampaignServiceFailure::Unavailable,
        _ => CampaignServiceFailure::IntegrityFailure,
    }
}

#[cfg(test)]
mod tests {
    use crucible::ContentHash;
    use crucible_api::{SessionId, SessionRef};
    use crucible_campaign::{
        CampaignAuthorizationError, CampaignPrincipal, CampaignPrincipalAuthorizer,
        CampaignService, CampaignServiceOperation, CampaignSnapshotId, RepositoryCampaignService,
    };
    use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn retained_cleanup_has_the_same_availability_policy_as_factory_refusal() {
        for error in [
            LifecycleApiError::CleanupRetained,
            LifecycleApiError::LoopFactory {
                message: String::from("component cleanup refusal"),
            },
        ] {
            assert_eq!(
                map_lifecycle_failure(error),
                CampaignServiceFailure::Unavailable
            );
        }
    }

    #[test]
    fn selection_distinguishes_host_refusal_from_checkpoint_corruption() {
        use crate::ExactCheckpointStoreError;
        use crucible_cas::content_store::StoreError;
        use crucible_cas::ram::RamStoreError;

        assert_eq!(
            map_checkpoint_selection_failure(ExactCheckpointStoreError::Canceled),
            CampaignServiceFailure::Unavailable,
        );
        assert_eq!(
            map_checkpoint_selection_failure(ExactCheckpointStoreError::Store(StoreError::Quota)),
            CampaignServiceFailure::ResourceExhausted,
        );
        assert_eq!(
            map_checkpoint_selection_failure(ExactCheckpointStoreError::Ram(RamStoreError::Limit(
                "metadata",
            ))),
            CampaignServiceFailure::ResourceExhausted,
        );
        assert_eq!(
            map_checkpoint_selection_failure(ExactCheckpointStoreError::Store(
                StoreError::Supervision {
                    source: Box::new(std::io::Error::other("original host deadline")),
                },
            )),
            CampaignServiceFailure::Unavailable,
        );
        assert_eq!(
            map_checkpoint_selection_failure(ExactCheckpointStoreError::InvalidRoot {
                reason: "corrupt authenticated region",
            }),
            CampaignServiceFailure::IntegrityFailure,
        );
        assert_eq!(
            map_checkpoint_selection_failure(ExactCheckpointStoreError::Ram(
                RamStoreError::LogicalValidation(crucible_ram::RamError::OutOfRange),
            )),
            CampaignServiceFailure::IntegrityFailure,
        );
    }

    #[test]
    fn build_failure_retains_its_original_descriptor_until_final_drop() {
        #[derive(Debug, thiserror::Error)]
        #[error("restore failure retains source descriptor")]
        struct DescriptorFailure {
            _file: Arc<std::fs::File>,
        }

        let directory =
            TempDir::new().unwrap_or_else(|error| panic!("descriptor fixture directory: {error}"));
        let descriptor = Arc::new(
            std::fs::File::create(directory.path().join("source"))
                .unwrap_or_else(|error| panic!("source descriptor: {error}")),
        );
        let retained_descriptor = Arc::downgrade(&descriptor);
        let failure =
            CampaignDebugLifecycleBuildError::new(DescriptorFailure { _file: descriptor });

        assert!(std::error::Error::source(&failure).is_some());
        assert!(retained_descriptor.upgrade().is_some());
        assert!(failure.to_string().contains("retains source descriptor"));

        drop(failure);

        assert!(retained_descriptor.upgrade().is_none());
    }

    struct AllowFindingRead;

    impl CampaignPrincipalAuthorizer for AllowFindingRead {
        fn authorize(
            &self,
            _principal: &CampaignPrincipal,
            _operation: CampaignServiceOperation,
            _campaign: &CampaignName,
            _request_digest: CampaignHash,
        ) -> Result<(), CampaignAuthorizationError> {
            Ok(())
        }
    }

    #[test]
    fn failed_admission_removes_only_its_new_recovery_record() {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("debug-admission-rollback", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
            crucible_campaign::CampaignRamAdmission::Unavailable,
        );
        let (campaign, snapshot, finding, _) =
            crate::campaign_gc::publish_retained_finding_fixture(&repository);
        let request = OpenCampaignDebugSessionRequest::new(
            CampaignPrincipal::new("debugger")
                .unwrap_or_else(|error| panic!("principal should parse: {error}")),
            campaign,
            snapshot,
            finding,
        )
        .unwrap_or_else(|error| panic!("request should encode: {error}"));
        let proof_request = request
            .finding_object_request()
            .unwrap_or_else(|error| panic!("proof request should encode: {error}"));
        let proof = RepositoryCampaignService::new(&repository, AllowFindingRead)
            .get_campaign_finding_object(&proof_request)
            .unwrap_or_else(|error| panic!("finding proof should load: {error}"));
        let directory = TempDir::new()
            .unwrap_or_else(|error| panic!("temporary directory should open: {error}"));
        let path = directory.path().join("debug-sessions.v1");
        let inventory = CampaignDebugSessionInventory::open(path.clone())
            .unwrap_or_else(|error| panic!("inventory should open: {error}"));

        let failed = admit_with_inventory(&inventory, &request, proof.clone(), |_| {
            Err::<(), _>(LifecycleApiError::SessionLimitReached { limit: 0 })
        });
        assert!(matches!(
            failed,
            Err(CampaignServiceFailure::ResourceExhausted)
        ));
        let restarted = CampaignDebugSessionInventory::open(path.clone())
            .unwrap_or_else(|error| panic!("inventory should reopen: {error}"));
        assert!(
            restarted
                .records()
                .unwrap_or_else(|error| panic!("restarted inventory should load: {error}"))
                .is_empty()
        );

        admit_with_inventory(&restarted, &request, proof.clone(), |_| Ok(()))
            .unwrap_or_else(|error| panic!("admission should succeed: {error}"));
        let failed_recovery = admit_with_inventory(&restarted, &request, proof, |_| {
            Err::<(), _>(LifecycleApiError::SessionLimitReached { limit: 0 })
        });
        assert!(matches!(
            failed_recovery,
            Err(CampaignServiceFailure::ResourceExhausted)
        ));
        let restarted = CampaignDebugSessionInventory::open(path)
            .unwrap_or_else(|error| panic!("inventory should reopen again: {error}"));
        assert_eq!(
            restarted
                .records()
                .unwrap_or_else(|error| panic!("retained recovery record should load: {error}"))
                .len(),
            1
        );
    }

    #[test]
    fn reservation_lease_releases_only_its_exact_session_generation() {
        let reservations = Arc::new(DebugSessionReservations::new());
        let request = debug_request("lease-one");
        let key = DebugSessionKey {
            campaign: request.campaign().clone(),
            finding: request.finding(),
        };
        let digest = request.request_digest();
        let session = SessionRef::new(SessionId::new(7), 1, crucible::Seed::from_u64(9));
        let response = debug_response(&request, session);
        let lease = Arc::new(DebugSessionReservationLease::new(
            &reservations,
            key.clone(),
            digest,
        ));
        lease.bind_session(session);
        reservations
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                key.clone(),
                DebugSessionReservation::Active {
                    request_digest: digest,
                    snapshot: request.snapshot(),
                    response: Box::new(response),
                },
            );

        drop(lease);
        assert!(
            !reservations
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&key)
        );

        let stale = Arc::new(DebugSessionReservationLease::new(
            &reservations,
            key.clone(),
            digest,
        ));
        stale.bind_session(session);
        let replacement = debug_request("lease-two");
        let replacement_digest = replacement.request_digest();
        let replacement_session =
            SessionRef::new(SessionId::new(8), 2, crucible::Seed::from_u64(10));
        reservations
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                key.clone(),
                DebugSessionReservation::Active {
                    request_digest: replacement_digest,
                    snapshot: replacement.snapshot(),
                    response: Box::new(debug_response(&replacement, replacement_session)),
                },
            );

        drop(stale);
        assert!(
            reservations
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&key),
            "a stale lease must not remove a replacement generation"
        );
    }

    #[test]
    fn failed_admission_lease_releases_its_preparing_reservation() {
        let reservations = Arc::new(DebugSessionReservations::new());
        let request = debug_request("preparing");
        let key = DebugSessionKey {
            campaign: request.campaign().clone(),
            finding: request.finding(),
        };
        let digest = request.request_digest();
        reservations
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.clone(), DebugSessionReservation::Preparing(digest));
        let lease = DebugSessionReservationLease::new(&reservations, key.clone(), digest);

        drop(lease);
        assert!(
            !reservations
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&key)
        );
    }

    #[test]
    fn checkpoint_selection_orders_complete_cost_then_role_then_root() {
        let mut roots = [checkpoint_id("root-a"), checkpoint_id("root-b")];
        roots.sort();
        let [lower_root, higher_root] = roots;

        let candidates = [
            debug_checkpoint_selection_key(
                512,
                CampaignDebugCheckpointRole::PostFailure,
                lower_root,
            ),
            debug_checkpoint_selection_key(
                128,
                CampaignDebugCheckpointRole::Additional,
                lower_root,
            ),
            debug_checkpoint_selection_key(
                128,
                CampaignDebugCheckpointRole::PreFailure,
                higher_root,
            ),
            debug_checkpoint_selection_key(
                128,
                CampaignDebugCheckpointRole::PreFailure,
                lower_root,
            ),
        ];

        assert_eq!(
            candidates.into_iter().min(),
            Some(debug_checkpoint_selection_key(
                128,
                CampaignDebugCheckpointRole::PreFailure,
                lower_root,
            )),
            "selection must prefer complete restore bytes, then semantic role, then root identity"
        );
    }

    fn debug_request(label: &str) -> OpenCampaignDebugSessionRequest {
        let snapshot = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 3, label.as_bytes());
        let finding = ContentId::for_bytes(ObjectKind::Finding, 4, label.as_bytes());
        OpenCampaignDebugSessionRequest::new(
            CampaignPrincipal::new("debugger")
                .unwrap_or_else(|error| panic!("principal should parse: {error}")),
            CampaignName::new("campaign")
                .unwrap_or_else(|error| panic!("campaign should parse: {error}")),
            CampaignSnapshotId::parse(&format!("crucible.campaign.snapshot@{}", snapshot.encode()))
                .unwrap_or_else(|error| panic!("snapshot should parse: {error}")),
            FindingId::parse(&format!("crucible.campaign.finding@{}", finding.encode()))
                .unwrap_or_else(|error| panic!("finding should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("debug request should encode: {error}"))
    }

    fn debug_response(
        request: &OpenCampaignDebugSessionRequest,
        session: SessionRef,
    ) -> OpenCampaignDebugSessionResponse {
        let checkpoint = checkpoint_id("checkpoint");
        OpenCampaignDebugSessionResponse::new(
            request,
            checkpoint,
            CampaignDebugCheckpointRole::PostFailure,
            ContentHash::from_bytes(b"configuration"),
            session,
        )
        .unwrap_or_else(|error| panic!("debug response should encode: {error}"))
    }

    fn checkpoint_id(label: &str) -> ExactCheckpointId {
        let content = ContentId::for_bytes(ObjectKind::ExactManifest, 6, label.as_bytes());
        ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@{}",
            content.encode()
        ))
        .unwrap_or_else(|error| panic!("checkpoint should parse: {error}"))
    }
}
