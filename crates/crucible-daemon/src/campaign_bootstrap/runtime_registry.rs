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
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};

use crucible_campaign::{CampaignName, CampaignRepository, PlannerAuthorityKey};

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
        let reservation = shared.reserve(config.campaign().clone(), true)?;
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
        reservation.install(prepared)
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
    ) -> Self {
        Self {
            shared: Arc::new(CampaignRuntimeRegistry {
                repository,
                planner_authority,
                mode,
                shutdown,
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
        let reservation = self.reserve(prepared.campaign().clone(), false)?;
        reservation.install(prepared)
    }

    fn reserve(
        self: &Arc<Self>,
        campaign: CampaignName,
        require_dynamic_authority: bool,
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
        if state.reserved.contains(&campaign) || state.runtimes.contains_key(&campaign) {
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
        state.reserved.insert(campaign.clone());
        state.in_flight = next_in_flight;
        drop(state);
        Ok(RuntimeReservation {
            shared: Arc::clone(self),
            campaign,
            active: true,
        })
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
    active: bool,
}

impl RuntimeReservation {
    fn install(
        mut self,
        prepared: PreparedCanonicalCampaignRuntime,
    ) -> Result<(), CampaignLocalServiceError> {
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
            AttachedRuntimeEntry { runtime, monitor },
        );
        release_reservation(&self.shared, &mut state, &self.campaign);
        self.active = false;
        Ok(())
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
    reserved: BTreeSet<CampaignName>,
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
}

fn release_reservation(
    shared: &CampaignRuntimeRegistry,
    state: &mut RegistryState,
    campaign: &CampaignName,
) {
    if state.reserved.remove(campaign) {
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
        let AttachedRuntimeEntry { runtime, monitor } = entry;
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
