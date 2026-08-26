//! Bounded ownership for dynamically attached canonical campaign runtimes.
//!
//! The registry is the sole owner of attached runtime threads and their
//! completion monitors. A weak public handle may begin an attachment only while
//! the service owner remains live. Shutdown closes admission, waits for every
//! bounded preparation already in flight, requests cancellation for all
//! attached runtimes before joining any one of them, and retains the repository
//! namespace lock through the final join.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};

use crucible_campaign::{
    CampaignHash, CampaignName, CampaignRepository, CampaignServiceFailure,
    CampaignServiceFailureSource, PlannerAuthorityKey, ScenarioArtifactId,
};

use crate::{
    AttachCampaignRuntimeRequest, AttachCampaignRuntimeResponse,
    CampaignRuntimeAttachmentDisposition, CampaignRuntimeControlService,
    CanonicalCampaignRuntimeError, CanonicalPlannerProcessConfig, ExecutorLoopbackEndpointConfig,
};

use super::{
    AttachedCanonicalCampaignRuntime, CampaignLocalServiceError, CampaignLocalServiceMode,
    CampaignLoopbackServerShutdown, CampaignStateOwner, CanonicalCampaignRuntimeConfig,
    MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES, PreparedCanonicalCampaignRuntime,
    prepare_canonical_campaign_runtime,
};

/// Weak operational capability for attaching one runtime to a live service.
///
/// The handle exposes neither repository nor component-authority access. It
/// becomes permanently closed when the owning [`super::CampaignLocalService`]
/// begins shutdown or is dropped.
#[derive(Clone)]
pub struct CampaignRuntimeAttachmentHandle {
    shared: Weak<CampaignRuntimeRegistry>,
}

impl CampaignRuntimeAttachmentHandle {
    /// Authenticates and attaches one campaign runtime to the live service.
    ///
    /// `executor_stream` must already be connected to and authenticated as the
    /// intended local executor by the deployment owner. The registry reserves
    /// the campaign and one bounded attachment slot before any executor or
    /// repository I/O. Capability negotiation and planner-basis publication run
    /// without holding the registry mutex. The runtime is started only if this
    /// exact service incarnation is still accepting attachments afterward.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when the service is closed or
    /// read-only, component authority is unavailable, the campaign is already
    /// attached or being prepared, the fixed attachment ceiling is reached,
    /// executor/repository negotiation fails, or runtime/monitor startup fails.
    pub fn attach(
        &self,
        executor_stream: UnixStream,
        config: &CanonicalCampaignRuntimeConfig,
    ) -> Result<(), CampaignLocalServiceError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(CampaignLocalServiceError::RuntimeAttachmentClosed)?;
        let reservation = shared.reserve(config.campaign().clone(), true, None)?;
        shared.validate_packaged_scenario(config.campaign(), None)?;
        let planner_authority = shared
            .planner_authority
            .as_ref()
            .ok_or(CampaignLocalServiceError::RuntimeAuthorityUnavailable)?
            .clone();
        let prepared = prepare_canonical_campaign_runtime(
            Arc::clone(&shared.repository),
            planner_authority,
            executor_stream,
            config,
        )?;
        reservation.install(prepared).map(|_| ())
    }

    /// Connects through an exact executor endpoint and attaches one runtime.
    ///
    /// The registry reserves the campaign and one bounded slot before any
    /// endpoint filesystem or socket operation. The endpoint capability then
    /// authenticates its parent namespace, named socket identity, exact owner
    /// and mode, and connected `SO_PEERCRED` before component negotiation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] for the same registry, authority,
    /// repository, and runtime failures as [`Self::attach`], or when the exact
    /// executor endpoint cannot be authenticated and connected.
    pub fn attach_endpoint(
        &self,
        endpoint: &ExecutorLoopbackEndpointConfig,
        config: &CanonicalCampaignRuntimeConfig,
    ) -> Result<(), CampaignLocalServiceError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(CampaignLocalServiceError::RuntimeAttachmentClosed)?;
        let reservation = shared.reserve(config.campaign().clone(), true, None)?;
        shared.validate_packaged_scenario(config.campaign(), Some(endpoint.path()))?;
        let planner_authority = shared
            .planner_authority
            .as_ref()
            .ok_or(CampaignLocalServiceError::RuntimeAuthorityUnavailable)?
            .clone();
        let executor_stream = endpoint.connect()?;
        let prepared = prepare_canonical_campaign_runtime(
            Arc::clone(&shared.repository),
            planner_authority,
            executor_stream,
            config,
        )?;
        reservation.install(prepared).map(|_| ())
    }

    /// Returns the currently attached campaign names in canonical order.
    ///
    /// In-flight reservations are deliberately omitted because they do not yet
    /// own a live runtime.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::RuntimeAttachmentClosed`] after the
    /// service owner is gone, or
    /// [`CampaignLocalServiceError::RuntimeRegistryPoisoned`] if an invariant
    /// panic poisoned the registry mutex.
    pub fn attached_campaigns(&self) -> Result<Vec<CampaignName>, CampaignLocalServiceError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(CampaignLocalServiceError::RuntimeAttachmentClosed)?;
        let state = shared.lock_state()?;
        if !state.accepting {
            return Err(CampaignLocalServiceError::RuntimeAttachmentClosed);
        }
        Ok(state.runtimes.keys().cloned().collect())
    }
}

pub(super) struct CanonicalCampaignRuntimeController {
    attachment: CampaignRuntimeAttachmentHandle,
    planner_process: CanonicalPlannerProcessConfig,
    executor_owner_user_id: u32,
    executor_owner_group_id: u32,
}

impl CanonicalCampaignRuntimeController {
    pub(super) fn new(
        attachment: CampaignRuntimeAttachmentHandle,
        planner_process: CanonicalPlannerProcessConfig,
        executor_owner_user_id: u32,
        executor_owner_group_id: u32,
    ) -> Self {
        Self {
            attachment,
            planner_process,
            executor_owner_user_id,
            executor_owner_group_id,
        }
    }
}

impl CampaignRuntimeControlService for CanonicalCampaignRuntimeController {
    fn attach_campaign_runtime(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<AttachCampaignRuntimeResponse, CampaignServiceFailure> {
        let shared = self
            .attachment
            .shared
            .upgrade()
            .ok_or(CampaignServiceFailure::Unavailable)?;
        let reservation = match shared
            .reserve_control(request.campaign().clone(), request.request_digest())
            .map_err(|error| runtime_control_failure(&error))?
        {
            RuntimeControlReservation::Replay(attached_runtime_count) => {
                return AttachCampaignRuntimeResponse::new(
                    request,
                    CampaignRuntimeAttachmentDisposition::Replayed,
                    attached_runtime_count,
                )
                .map_err(|_| CampaignServiceFailure::IntegrityFailure);
            }
            RuntimeControlReservation::Reserved(reservation) => reservation,
        };
        let planner_authority = shared
            .planner_authority
            .as_ref()
            .ok_or(CampaignServiceFailure::Unauthorized)?
            .clone();
        shared
            .validate_packaged_scenario(request.campaign(), Some(request.executor_endpoint()))
            .map_err(|error| runtime_control_failure(&error))?;
        let endpoint = ExecutorLoopbackEndpointConfig::new(
            request.executor_endpoint().to_owned(),
            self.executor_owner_user_id,
            self.executor_owner_group_id,
            0o600,
        )
        .map_err(|_| CampaignServiceFailure::InvalidRequest)?;
        let config = CanonicalCampaignRuntimeConfig::canonical_defaults(
            request.campaign().clone(),
            self.planner_process.clone(),
        )
        .map_err(|_| CampaignServiceFailure::IntegrityFailure)?;
        let executor_stream = endpoint
            .connect()
            .map_err(|_| CampaignServiceFailure::Unavailable)?;
        let prepared = prepare_canonical_campaign_runtime(
            Arc::clone(&shared.repository),
            planner_authority,
            executor_stream,
            &config,
        )
        .map_err(|error| runtime_control_runtime_failure(&error))?;
        let attached_runtime_count = reservation
            .install(prepared)
            .map_err(|error| runtime_control_failure(&error))?;
        AttachCampaignRuntimeResponse::new(
            request,
            CampaignRuntimeAttachmentDisposition::Attached,
            attached_runtime_count,
        )
        .map_err(|_| CampaignServiceFailure::IntegrityFailure)
    }
}

pub(super) struct CampaignRuntimeRegistryOwner {
    shared: Arc<CampaignRuntimeRegistry>,
}

impl CampaignRuntimeRegistryOwner {
    pub(super) fn new(
        repository: Arc<CampaignRepository>,
        planner_authority: Option<PlannerAuthorityKey>,
        mode: CampaignLocalServiceMode,
        shutdown: CampaignLoopbackServerShutdown,
        repository_owner: CampaignStateOwner,
        packaged_scope: Option<(PathBuf, BTreeSet<ScenarioArtifactId>)>,
    ) -> Self {
        Self {
            shared: Arc::new(CampaignRuntimeRegistry {
                repository,
                planner_authority,
                mode,
                shutdown,
                packaged_scope,
                state: Mutex::new(RegistryState::open()),
                changed: Condvar::new(),
                _repository_owner: repository_owner,
            }),
        }
    }

    pub(super) fn handle(&self) -> CampaignRuntimeAttachmentHandle {
        CampaignRuntimeAttachmentHandle {
            shared: Arc::downgrade(&self.shared),
        }
    }

    pub(super) fn attach_prepared(
        &self,
        prepared: PreparedCanonicalCampaignRuntime,
    ) -> Result<(), CampaignLocalServiceError> {
        self.shared.attach_prepared(prepared)
    }

    pub(super) fn close_and_join(&self) -> Result<(), CampaignLocalServiceError> {
        self.shared.close_and_join()
    }
}

impl Drop for CampaignRuntimeRegistryOwner {
    fn drop(&mut self) {
        let _ = self.shared.close_and_join();
    }
}

struct CampaignRuntimeRegistry {
    repository: Arc<CampaignRepository>,
    planner_authority: Option<PlannerAuthorityKey>,
    mode: CampaignLocalServiceMode,
    shutdown: CampaignLoopbackServerShutdown,
    packaged_scope: Option<(PathBuf, BTreeSet<ScenarioArtifactId>)>,
    state: Mutex<RegistryState>,
    changed: Condvar,
    _repository_owner: CampaignStateOwner,
}

impl CampaignRuntimeRegistry {
    fn attach_prepared(
        self: &Arc<Self>,
        prepared: PreparedCanonicalCampaignRuntime,
    ) -> Result<(), CampaignLocalServiceError> {
        if !prepared.uses_repository(&self.repository) {
            return Err(CampaignLocalServiceError::RuntimeRepositoryMismatch);
        }
        let reservation = self.reserve(prepared.campaign().clone(), false, None)?;
        reservation.install(prepared).map(|_| ())
    }

    fn validate_packaged_scenario(
        &self,
        campaign: &CampaignName,
        endpoint: Option<&Path>,
    ) -> Result<(), CampaignLocalServiceError> {
        let Some((packaged_endpoint, admitted)) = self.packaged_scope.as_ref() else {
            return Ok(());
        };
        if endpoint.is_some_and(|endpoint| endpoint != packaged_endpoint.as_path()) {
            return Ok(());
        };
        let head = self
            .repository
            .head(campaign.as_str())
            .map_err(CanonicalCampaignRuntimeError::Repository)?;
        let lineage = self
            .repository
            .load_lineage(head.snapshot().lineage())
            .map_err(CanonicalCampaignRuntimeError::Repository)?;
        if !admitted.contains(&lineage.scenario_content()) {
            return Err(CampaignLocalServiceError::RuntimeScenarioMismatch);
        }
        Ok(())
    }

    fn reserve(
        self: &Arc<Self>,
        campaign: CampaignName,
        require_dynamic_authority: bool,
        request_digest: Option<CampaignHash>,
    ) -> Result<RuntimeReservation, CampaignLocalServiceError> {
        let mut state = self.lock_state()?;
        if !state.accepting {
            return Err(CampaignLocalServiceError::RuntimeAttachmentClosed);
        }
        if require_dynamic_authority {
            if self.mode == CampaignLocalServiceMode::ReadOnly {
                return Err(CampaignLocalServiceError::RuntimeReadOnly);
            }
            if self.planner_authority.is_none() {
                return Err(CampaignLocalServiceError::RuntimeAuthorityUnavailable);
            }
        }
        if state.reserved.contains_key(&campaign) || state.runtimes.contains_key(&campaign) {
            return Err(CampaignLocalServiceError::DuplicateRuntimeCampaign);
        }
        let occupied = state
            .reserved
            .len()
            .checked_add(state.runtimes.len())
            .ok_or(CampaignLocalServiceError::InvalidRuntimeCount)?;
        if occupied >= MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES {
            return Err(CampaignLocalServiceError::InvalidRuntimeCount);
        }
        let next_in_flight = state
            .in_flight
            .checked_add(1)
            .ok_or(CampaignLocalServiceError::InvalidRuntimeCount)?;
        state.reserved.insert(campaign.clone(), request_digest);
        state.in_flight = next_in_flight;
        drop(state);
        Ok(RuntimeReservation {
            shared: Arc::clone(self),
            campaign,
            request_digest,
            active: true,
        })
    }

    fn reserve_control(
        self: &Arc<Self>,
        campaign: CampaignName,
        request_digest: CampaignHash,
    ) -> Result<RuntimeControlReservation, CampaignLocalServiceError> {
        let state = self.lock_state()?;
        if !state.accepting {
            return Err(CampaignLocalServiceError::RuntimeAttachmentClosed);
        }
        if self.mode == CampaignLocalServiceMode::ReadOnly {
            return Err(CampaignLocalServiceError::RuntimeReadOnly);
        }
        if self.planner_authority.is_none() {
            return Err(CampaignLocalServiceError::RuntimeAuthorityUnavailable);
        }
        if let Some(entry) = state.runtimes.get(&campaign) {
            if entry.request_digest == Some(request_digest) {
                let count = u32::try_from(state.runtimes.len())
                    .map_err(|_| CampaignLocalServiceError::InvalidRuntimeCount)?;
                return Ok(RuntimeControlReservation::Replay(count));
            }
            return Err(CampaignLocalServiceError::DuplicateRuntimeCampaign);
        }
        if let Some(pending_digest) = state.reserved.get(&campaign) {
            return if *pending_digest == Some(request_digest) {
                Err(CampaignLocalServiceError::RuntimeAttachmentInFlight)
            } else {
                Err(CampaignLocalServiceError::DuplicateRuntimeCampaign)
            };
        }
        drop(state);
        match self.reserve(campaign.clone(), true, Some(request_digest)) {
            Ok(reservation) => Ok(RuntimeControlReservation::Reserved(reservation)),
            Err(CampaignLocalServiceError::DuplicateRuntimeCampaign) => {
                let state = self.lock_state()?;
                if state
                    .runtimes
                    .get(&campaign)
                    .is_some_and(|entry| entry.request_digest == Some(request_digest))
                {
                    let count = u32::try_from(state.runtimes.len())
                        .map_err(|_| CampaignLocalServiceError::InvalidRuntimeCount)?;
                    Ok(RuntimeControlReservation::Replay(count))
                } else if state.reserved.get(&campaign) == Some(&Some(request_digest)) {
                    Err(CampaignLocalServiceError::RuntimeAttachmentInFlight)
                } else {
                    Err(CampaignLocalServiceError::DuplicateRuntimeCampaign)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn close_and_join(&self) -> Result<(), CampaignLocalServiceError> {
        let (entries, poisoned) = self.close_and_take_entries();
        let result = shutdown_entries(entries);
        result?;
        if poisoned {
            Err(CampaignLocalServiceError::RuntimeRegistryPoisoned)
        } else {
            Ok(())
        }
    }

    fn close_and_take_entries(&self) -> (Vec<AttachedRuntimeEntry>, bool) {
        let (mut state, mut poisoned) = match self.state.lock() {
            Ok(state) => (state, false),
            Err(source) => (source.into_inner(), true),
        };
        state.accepting = false;
        while state.in_flight != 0 {
            match self.changed.wait(state) {
                Ok(next) => state = next,
                Err(source) => {
                    state = source.into_inner();
                    poisoned = true;
                }
            }
        }
        let entries = std::mem::take(&mut state.runtimes).into_values().collect();
        (entries, poisoned)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, RegistryState>, CampaignLocalServiceError> {
        self.state
            .lock()
            .map_err(|_| CampaignLocalServiceError::RuntimeRegistryPoisoned)
    }
}

impl Drop for CampaignRuntimeRegistry {
    fn drop(&mut self) {
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(source) => source.into_inner(),
        };
        state.accepting = false;
        let entries = std::mem::take(&mut state.runtimes).into_values().collect();
        let _ = shutdown_entries(entries);
    }
}

struct RuntimeReservation {
    shared: Arc<CampaignRuntimeRegistry>,
    campaign: CampaignName,
    request_digest: Option<CampaignHash>,
    active: bool,
}

impl RuntimeReservation {
    fn install(
        mut self,
        prepared: PreparedCanonicalCampaignRuntime,
    ) -> Result<u32, CampaignLocalServiceError> {
        if prepared.campaign() != &self.campaign
            || !prepared.uses_repository(&self.shared.repository)
        {
            return Err(CampaignLocalServiceError::RuntimeRepositoryMismatch);
        }

        let mut state = self.shared.lock_state()?;
        if !state.accepting {
            return Err(CampaignLocalServiceError::RuntimeAttachmentClosed);
        }
        let runtime = prepared.start()?;
        let completion = runtime.completion_handle();
        let shutdown = self.shared.shutdown.clone();
        let monitor_id = state.next_monitor_id;
        state.next_monitor_id = state
            .next_monitor_id
            .checked_add(1)
            .ok_or(CampaignLocalServiceError::InvalidRuntimeCount)?;
        let monitor = match thread::Builder::new()
            .name(format!("crucible-campaign-runtime-monitor-{monitor_id:03}"))
            .spawn(move || {
                completion.wait();
                shutdown.shutdown();
            }) {
            Ok(monitor) => monitor,
            Err(source) => {
                release_reservation(&self.shared, &mut state, &self.campaign);
                self.active = false;
                drop(state);
                runtime.shutdown_and_join()?;
                return Err(CampaignLocalServiceError::RuntimeMonitorSpawn { source });
            }
        };
        state.runtimes.insert(
            self.campaign.clone(),
            AttachedRuntimeEntry {
                runtime,
                monitor,
                request_digest: self.request_digest,
            },
        );
        release_reservation(&self.shared, &mut state, &self.campaign);
        let attached_runtime_count = u32::try_from(state.runtimes.len())
            .map_err(|_| CampaignLocalServiceError::InvalidRuntimeCount)?;
        self.active = false;
        Ok(attached_runtime_count)
    }
}

impl Drop for RuntimeReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = match self.shared.state.lock() {
            Ok(state) => state,
            Err(source) => source.into_inner(),
        };
        release_reservation(&self.shared, &mut state, &self.campaign);
    }
}

#[derive(Default)]
struct RegistryState {
    accepting: bool,
    in_flight: usize,
    next_monitor_id: u64,
    reserved: BTreeMap<CampaignName, Option<CampaignHash>>,
    runtimes: BTreeMap<CampaignName, AttachedRuntimeEntry>,
}

impl RegistryState {
    fn open() -> Self {
        Self {
            accepting: true,
            ..Self::default()
        }
    }
}

struct AttachedRuntimeEntry {
    runtime: AttachedCanonicalCampaignRuntime,
    monitor: JoinHandle<()>,
    request_digest: Option<CampaignHash>,
}

fn release_reservation(
    shared: &CampaignRuntimeRegistry,
    state: &mut RegistryState,
    campaign: &CampaignName,
) {
    if state.reserved.remove(campaign).is_some() {
        state.in_flight -= 1;
        shared.changed.notify_all();
    }
}

fn shutdown_entries(
    mut entries: Vec<AttachedRuntimeEntry>,
) -> Result<(), CampaignLocalServiceError> {
    for entry in &entries {
        entry.runtime.request_shutdown();
    }

    let mut first_runtime_error = None;
    let mut monitors = Vec::with_capacity(entries.len());
    for entry in entries.drain(..) {
        let AttachedRuntimeEntry {
            runtime,
            monitor,
            request_digest: _,
        } = entry;
        if let Err(source) = runtime.shutdown_and_join()
            && first_runtime_error.is_none()
        {
            first_runtime_error = Some(CampaignLocalServiceError::Runtime(source));
        }
        monitors.push(monitor);
    }
    let mut monitor_panicked = false;
    for monitor in monitors {
        monitor_panicked |= monitor.join().is_err();
    }

    if let Some(error) = first_runtime_error {
        Err(error)
    } else if monitor_panicked {
        Err(CampaignLocalServiceError::RuntimeMonitorPanicked)
    } else {
        Ok(())
    }
}

enum RuntimeControlReservation {
    Replay(u32),
    Reserved(RuntimeReservation),
}

fn runtime_control_failure(error: &CampaignLocalServiceError) -> CampaignServiceFailure {
    match error {
        CampaignLocalServiceError::RuntimeReadOnly
        | CampaignLocalServiceError::RuntimeAuthorityUnavailable => {
            CampaignServiceFailure::Unauthorized
        }
        CampaignLocalServiceError::DuplicateRuntimeCampaign => CampaignServiceFailure::CommandReuse,
        CampaignLocalServiceError::RuntimeAttachmentInFlight
        | CampaignLocalServiceError::RuntimeAttachmentClosed
        | CampaignLocalServiceError::RuntimeMonitorSpawn { .. } => {
            CampaignServiceFailure::Unavailable
        }
        CampaignLocalServiceError::InvalidRuntimeCount => CampaignServiceFailure::ResourceExhausted,
        CampaignLocalServiceError::RuntimeScenarioMismatch => {
            CampaignServiceFailure::InvalidRequest
        }
        CampaignLocalServiceError::RuntimeRepositoryMismatch
        | CampaignLocalServiceError::CampaignCatalog(_)
        | CampaignLocalServiceError::CampaignCatalogName(_)
        | CampaignLocalServiceError::RuntimeRegistryPoisoned
        | CampaignLocalServiceError::RuntimeMonitorPanicked => {
            CampaignServiceFailure::IntegrityFailure
        }
        CampaignLocalServiceError::Runtime(error) => runtime_control_runtime_failure(error),
        CampaignLocalServiceError::Endpoint(_) => CampaignServiceFailure::Unavailable,
        CampaignLocalServiceError::InvalidStatePath
        | CampaignLocalServiceError::InvalidPolicyPath
        | CampaignLocalServiceError::InvalidComponentAuthorityPath
        | CampaignLocalServiceError::InvalidStateDirectory
        | CampaignLocalServiceError::StateInUse
        | CampaignLocalServiceError::InvalidStateLock
        | CampaignLocalServiceError::InvalidStateSubdirectory
        | CampaignLocalServiceError::InvalidPolicyFile
        | CampaignLocalServiceError::InvalidComponentAuthorityFile
        | CampaignLocalServiceError::Policy(_)
        | CampaignLocalServiceError::ArtifactImportReadOnly
        | CampaignLocalServiceError::Artifact(_)
        | CampaignLocalServiceError::PackagedExecutor(_)
        | CampaignLocalServiceError::PackagedExecutorStart(_)
        | CampaignLocalServiceError::PackagedExecutorJoin(_)
        | CampaignLocalServiceError::PackagedExecutorMonitorSpawn { .. }
        | CampaignLocalServiceError::PackagedExecutorMonitorPanicked
        | CampaignLocalServiceError::Listener(_)
        | CampaignLocalServiceError::Io { .. } => CampaignServiceFailure::IntegrityFailure,
    }
}

fn runtime_control_runtime_failure(
    error: &CanonicalCampaignRuntimeError,
) -> CampaignServiceFailure {
    match error {
        CanonicalCampaignRuntimeError::Repository(error) => error.campaign_service_failure(),
        CanonicalCampaignRuntimeError::ExecutorIncompatible
        | CanonicalCampaignRuntimeError::ExecutorResourcesExceedCeiling
        | CanonicalCampaignRuntimeError::ExecutorSlotsExceedCeiling
        | CanonicalCampaignRuntimeError::PlannerDriver(_)
        | CanonicalCampaignRuntimeError::ExecutorDriver(_)
        | CanonicalCampaignRuntimeError::Supervisor(_) => CampaignServiceFailure::InvalidRequest,
        CanonicalCampaignRuntimeError::ExecutorProtocol(_)
        | CanonicalCampaignRuntimeError::ExecutorDescription(_)
        | CanonicalCampaignRuntimeError::RuntimeStart(_)
        | CanonicalCampaignRuntimeError::Runtime(_) => CampaignServiceFailure::Unavailable,
    }
}
