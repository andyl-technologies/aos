//! Production composition for snapshot-bound campaign debug sessions.
//!
//! This module joins campaign proof authentication, the owner-only exact
//! checkpoint store, guarded QEMU restoration, and the shared lifecycle
//! control plane. No checkpoint bytes or mutable campaign capability cross the
//! component protocol.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use crucible::{Checkpoint, Configuration, ScenarioDef, ScenarioDefForm};
use crucible_api::{
    InProcessLifecycleClient, LifecycleApiError, ProductionVmLifecycleConfig,
    ProductionVmLifecycleLoop, ResumeSessionResponse, SessionLifetimeRetention, SessionRef,
    SessionRetentionUpdateError,
};
use crucible_campaign::{
    AttemptResourceLimits, AttemptRetentionPolicyDisposition, CampaignFindingObject, CampaignHash,
    CampaignName, CampaignRepository, CampaignServiceFailure, CampaignSnapshotId,
    ExactCheckpointId, ExecutionRetentionIntent, FindingId, GetCampaignFindingObjectResponse,
};

use crate::campaign_debug_inventory::CampaignDebugSessionInventory;
use crate::crucible_artifact::{
    campaign_configuration_id, campaign_scenario_id,
    decode_crucible_configuration_artifact_from_repository,
};
use crate::executor_supervisor::SelectedExactCheckpointRoot;
use crate::qemu_campaign_resume::QemuExactResumeBasis;
use crate::qemu_resource_guard::QemuAttemptSelectedHostResourceFactory;
use crate::{
    AttemptExecutionContext, CampaignDebugCheckpointRole, CampaignDebugControlService,
    ComposedQemuAttemptResourceGuardFactory, ExactCheckpointStore, ExecutionCancellation,
    ExecutionCheckpointRequest, LoadedProductionExactCheckpoint, OpenCampaignDebugSessionRequest,
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
    source: ScenarioDefForm,
    configuration: Configuration,
    checkpoint: Checkpoint,
    retention: SessionLifetimeRetention,
    build_loop: Box<
        dyn FnOnce() -> Result<ProductionVmLifecycleLoop, CampaignDebugLifecycleBuildError> + Send,
    >,
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
            build_loop,
        } = self;
        let seed = source.scenario_def().seed();
        lifecycle
            .admit_authenticated_read_only_session(
                source,
                configuration,
                checkpoint,
                seed,
                retention,
                build_loop,
            )
            .await
    }
}

/// Stable opaque failure from guarded production lifecycle construction.
#[derive(Debug, thiserror::Error)]
#[error("guarded campaign debug lifecycle construction failed: {message}")]
pub struct CampaignDebugLifecycleBuildError {
    message: String,
}

type GuardedResumeBuilder = dyn Fn(
        &ScenarioDef,
        &ScenarioDefForm,
        &Configuration,
        ExactCheckpointId,
    ) -> Result<ProductionVmLifecycleLoop, CampaignDebugLifecycleBuildError>
    + Send
    + Sync;

/// Cloneable owner capability for inspecting and restoring packaged checkpoints.
pub struct CampaignDebugQemuCapability {
    checkpoints: Arc<ExactCheckpointStore>,
    build_resume: Arc<GuardedResumeBuilder>,
}

impl CampaignDebugQemuCapability {
    pub(crate) fn new<H>(
        checkpoints: Arc<ExactCheckpointStore>,
        lifecycle: ProductionVmLifecycleConfig,
        shared: SharedQemuAttemptHostResourceFactory<H>,
        resources: AttemptResourceLimits,
    ) -> Self
    where
        H: QemuAttemptHostResourceFactory + QemuAttemptSelectedHostResourceFactory + Send + 'static,
        H::Owner: QemuAttemptHostResourceOwner + Send + 'static,
        crate::ComposedQemuAttemptResourceGuard<H::Owner>:
            QemuAttemptProcessResourceGuard + Send + 'static,
    {
        let restore_checkpoints = Arc::clone(&checkpoints);
        let build_resume = Arc::new(
            move |scenario: &ScenarioDef,
                  source: &ScenarioDefForm,
                  configuration: &Configuration,
                  checkpoint: ExactCheckpointId| {
                let context = AttemptExecutionContext::new(
                    resources,
                    ExecutionRetentionIntent::Discard,
                    ExecutionCancellation::default(),
                    ExecutionCheckpointRequest::default(),
                    AttemptRetentionPolicyDisposition::Disabled,
                )
                .with_resume_checkpoint(Some(checkpoint))
                .install_selected_checkpoint(Some(
                    SelectedExactCheckpointRoot::after_authenticated_campaign_finding(checkpoint),
                ));
                let resource_guards = ComposedQemuAttemptResourceGuardFactory::new(shared.clone());
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    lifecycle.clone(),
                    resource_guards,
                );
                factory
                    .begin_resume(
                        &restore_checkpoints,
                        checkpoint,
                        QemuExactResumeBasis::new(scenario, source, configuration, None),
                        &context,
                    )
                    .map_err(|error| CampaignDebugLifecycleBuildError {
                        message: error.to_string(),
                    })
            },
        );
        Self {
            checkpoints,
            build_resume,
        }
    }

    fn load(
        &self,
        checkpoint: ExactCheckpointId,
    ) -> Result<LoadedProductionExactCheckpoint, CampaignServiceFailure> {
        self.checkpoints
            .load_attempt_checkpoint(checkpoint)
            .map_err(|_| CampaignServiceFailure::IntegrityFailure)
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

        let SelectedCampaignDebugCheckpoint {
            role,
            checkpoint,
            loaded,
            configuration,
            modeled_checkpoint,
            ..
        } = self.select_checkpoint(&source, &reproduction_configuration, &finding)?;
        let response_encoding = OpenCampaignDebugSessionResponse::prepare_encoding(checkpoint)
            .map_err(|_| CampaignServiceFailure::InvalidRequest)?;
        self.inventory
            .retain(request, &finding)
            .map_err(map_inventory_failure)?;
        let build_resume = Arc::clone(&self.qemu.build_resume);
        let build_source = source.clone();
        let build_configuration = configuration.clone();
        let scenario = source.scenario_def();
        let build_scenario = scenario.clone();
        let destroy_inventory = Arc::clone(&self.inventory);
        let destroy_request = request.clone();
        let retention = SessionLifetimeRetention::new(Box::new(DebugSessionRetention {
            _finding_proof: finding,
            _checkpoint: loaded,
            _reservation: Arc::clone(&reservation),
        }))
        .with_destroy_callback(move || {
            destroy_inventory
                .remove(&destroy_request)
                .map_err(|error| SessionRetentionUpdateError::new(error.to_string()))
        });
        let lifecycle = PreparedCampaignDebugLifecycle {
            source,
            configuration: configuration.clone(),
            checkpoint: modeled_checkpoint,
            retention,
            build_loop: Box::new(move || {
                build_resume(
                    &build_scenario,
                    &build_source,
                    &build_configuration,
                    checkpoint,
                )
            }),
        };
        let admitted = self
            .lifecycle
            .admit(lifecycle)
            .map_err(map_lifecycle_failure)?;
        reservation.bind_session(admitted.session);
        Ok(response_encoding.finish(request, role, configuration.id(), admitted.session))
    }

    fn select_checkpoint(
        &self,
        source: &ScenarioDefForm,
        reproduction: &Configuration,
        finding: &GetCampaignFindingObjectResponse,
    ) -> Result<SelectedCampaignDebugCheckpoint, CampaignServiceFailure> {
        let pins = finding.finding().exact_pin_retention();
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
                let loaded = self.qemu.load(*checkpoint)?;
                if loaded.scenario() != source.scenario_def().id() {
                    return Err(CampaignServiceFailure::IntegrityFailure);
                }
                let loaded = Arc::new(loaded);
                let decoded = loaded
                    .decode_semantic_checkpoint(source, &ExecutionCancellation::default())
                    .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
                let configuration = decoded.configuration().clone();
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
}

struct SelectedCampaignDebugCheckpoint {
    restore_bytes: u64,
    checkpoint: ExactCheckpointId,
    role: CampaignDebugCheckpointRole,
    loaded: Arc<LoadedProductionExactCheckpoint>,
    configuration: Configuration,
    modeled_checkpoint: Checkpoint,
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

fn map_lifecycle_failure(error: LifecycleApiError) -> CampaignServiceFailure {
    match error {
        LifecycleApiError::SessionLimitReached { .. } => CampaignServiceFailure::ResourceExhausted,
        LifecycleApiError::LoopFactory { .. } | LifecycleApiError::AttemptOperational { .. } => {
            CampaignServiceFailure::Unavailable
        }
        _ => CampaignServiceFailure::IntegrityFailure,
    }
}

#[cfg(test)]
mod tests {
    use crucible::ContentHash;
    use crucible_api::{SessionId, SessionRef};
    use crucible_campaign::{CampaignPrincipal, CampaignSnapshotId};
    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

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
        let content = ContentId::for_bytes(ObjectKind::ExactManifest, 4, label.as_bytes());
        ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@{}",
            content.encode()
        ))
        .unwrap_or_else(|error| panic!("checkpoint should parse: {error}"))
    }
}
