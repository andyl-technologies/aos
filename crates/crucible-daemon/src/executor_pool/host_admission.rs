//! Weak operational admission bridge to the existing short executor actor lock.

use crucible_api::host_operational::{HostOperationalError, HostReservationAmendment};
use crucible_linux_resource::ram_policy::{
    HostRamTarget, HostResourceTransition, HostResourceVector,
};

use super::*;

mod campaign;
mod checkpoint_handoff;
pub(crate) use campaign::CampaignActorPort;
pub(super) mod custody;
use custody::TerminalHook;

/// Shares one original capability actor allocation.
pub(super) type SharedActor<L, V> = Arc<Mutex<LocalExecutorCapabilityService<L, V>>>;

/// Pairs the unchanged actor allocation with its one forwarding authority.
type PreparedActorParts<L, V> = (ActorAllocation<L, V>, Arc<HostAdmission<L, V>>);

/// Retains the original actor and its cleanup guard through fallible pool startup.
pub(super) struct ActorAllocation<L, V> {
    /// Holds the same actor before and after worker-pool publication.
    pub(super) actor: SharedActor<L, V>,
    /// Shares the already admitted repository validation authority.
    pub(super) validator: Arc<V>,
    /// Transfers final accounting custody on pre-publication startup failure.
    pub(super) terminal: Option<TerminalHook>,
}

impl<L, V> From<LocalExecutorCapabilityService<L, V>> for ActorAllocation<L, V> {
    fn from(executor: LocalExecutorCapabilityService<L, V>) -> Self {
        let validator = executor.supervisor().admission_validator();
        Self {
            actor: Arc::new(Mutex::new(executor)),
            validator,
            terminal: None,
        }
    }
}

/// Actual actor retained while no modeled worker is yet permitted to run.
pub(crate) struct PreparedExecutorActor<L, V> {
    state: Arc<PreparationState<L, V>>,
    admission: Arc<HostAdmission<L, V>>,
    terminal: TerminalHook,
}

struct PreparationState<L, V> {
    supervisor: Mutex<Option<LocalExecutorSupervisor<L, V>>>,
    running: Mutex<Option<SharedActor<L, V>>>,
}

/// Exclusive loan retaining the same charged actor outside its short mutex.
struct StartupSupervisorLoan<'a, L, V> {
    actor: &'a PreparedExecutorActor<L, V>,
    supervisor: Option<LocalExecutorSupervisor<L, V>>,
}

impl<L, V> Drop for StartupSupervisorLoan<'_, L, V> {
    fn drop(&mut self) {
        let Some(supervisor) = self.supervisor.take() else {
            return;
        };
        let Ok(mut route) = self.actor.admission.route.lock() else {
            // Poisoned restoration is uncertain ownership. Retain the genuine
            // ledger and all reservations rather than making them reusable.
            std::mem::forget(supervisor);
            return;
        };
        let Ok(mut slot) = self.actor.state.supervisor.lock() else {
            std::mem::forget(supervisor);
            return;
        };
        if slot.is_some() || !matches!(*route, AdmissionRoute::Handoff) {
            std::mem::forget(supervisor);
            return;
        }
        *slot = Some(supervisor);
        *route = AdmissionRoute::Preparing(Arc::downgrade(&self.actor.state));
    }
}

enum AdmissionRoute<L, V> {
    Preparing(Weak<PreparationState<L, V>>),
    Handoff,
    Running(Weak<SharedExecutor<L, V>>),
    Terminal(Weak<PreparationState<L, V>>),
}

pub(super) struct HostAdmission<L, V> {
    route: Mutex<AdmissionRoute<L, V>>,
    custody: Arc<PreparationState<L, V>>,
}

impl<L: Send + 'static, V: Send + Sync + 'static> PreparedExecutorActor<L, V> {
    /// Attaches one forwarding admission authority before any preparation VM.
    ///
    /// # Errors
    /// Refuses a registry that already has an admission owner.
    pub(crate) fn new(
        supervisor: LocalExecutorSupervisor<L, V>,
    ) -> Result<Self, HostOperationalError> {
        let registry = supervisor.host_operational_registry();
        let state = Arc::new(PreparationState {
            supervisor: Mutex::new(Some(supervisor)),
            running: Mutex::new(None),
        });
        let admission = Arc::new(HostAdmission {
            route: Mutex::new(AdmissionRoute::Preparing(Arc::downgrade(&state))),
            custody: state.clone(),
        });
        if let Err(error) = registry.attach_admission(admission.clone()) {
            // Registry refusal cannot prove that earlier startup filesystem
            // work and reservations were cleaned. Retain the original ledger
            // and its accounting authority rather than releasing its lock.
            std::mem::forget((state, admission));
            return Err(error);
        }
        let terminal = TerminalHook::new(state.clone(), Arc::downgrade(&admission));
        Ok(Self {
            state,
            admission,
            terminal,
        })
    }

    /// Returns a campaign port sharing this actor's original admission route.
    pub(crate) fn campaign_port(&self) -> CampaignActorPort<L, V> {
        CampaignActorPort::new(Arc::clone(&self.admission))
    }

    /// Applies a short admission operation to the genuinely charged actor.
    ///
    /// # Errors
    /// Refuses poisoned state or a completed preparation-to-pool handoff.
    pub(crate) fn with_supervisor<T>(
        &self,
        operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, HostOperationalError>,
    ) -> Result<T, HostOperationalError> {
        self.admission.with_supervisor(operation)
    }

    /// Loans the same charged supervisor for startup filesystem reconciliation.
    ///
    /// All admissions refuse while the original actor is exclusively loaned.
    /// The callback runs without actor locks; its return or unwind restores
    /// the same ledger, reservations, and capability epoch through an owned
    /// guard. This is only available before the worker-pool handoff.
    ///
    /// # Errors
    /// Refuses uncertain ownership, an overlapping loan, or completed handoff.
    pub(crate) fn with_startup_supervisor<T, E>(
        &self,
        operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, E>,
    ) -> Result<Result<T, E>, HostOperationalError> {
        let mut route = self
            .admission
            .route
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if !matches!(*route, AdmissionRoute::Preparing(_)) {
            return Err(HostOperationalError::Unavailable);
        }
        let mut slot = self
            .state
            .supervisor
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        let supervisor = slot.take().ok_or(HostOperationalError::Unavailable)?;
        *route = AdmissionRoute::Handoff;
        drop(slot);
        drop(route);

        let mut loan = StartupSupervisorLoan {
            actor: self,
            supervisor: Some(supervisor),
        };
        let supervisor = loan
            .supervisor
            .as_mut()
            .ok_or(HostOperationalError::Unavailable)?;
        Ok(operation(supervisor))
    }

    /// Retains the genuinely charged startup actor during uncertain cleanup.
    ///
    /// The opaque owner contains the original ledger and registry, rather than
    /// another admission facade. A successful handoff installs the pool's
    /// same actor allocation in this owner, so earlier durable holders continue
    /// to retain its original counters after normal pool shutdown.
    pub(crate) fn preparation_custody(&self) -> Arc<dyn Send + Sync> {
        self.state.clone()
    }

    /// Moves the existing supervisor while temporarily closing admissions.
    ///
    /// # Errors
    /// Refuses uncertain ownership or a description that does not match the
    /// actual supervisor. No replacement capacity state is constructed.
    pub(super) fn into_parts(
        mut self,
        description: ExecutorDescription,
    ) -> Result<PreparedActorParts<L, V>, LocalExecutorPoolConfigError> {
        let mut route = self
            .admission
            .route
            .lock()
            .map_err(|_| LocalExecutorPoolConfigError::HostOperationalAdmission)?;
        let mut slot = self
            .state
            .supervisor
            .lock()
            .map_err(|_| LocalExecutorPoolConfigError::HostOperationalAdmission)?;
        crate::executor_capability::validate_description(
            slot.as_ref()
                .ok_or(LocalExecutorPoolConfigError::HostOperationalAdmission)?,
            &description,
        )
        .map_err(|_| LocalExecutorPoolConfigError::HostOperationalAdmission)?;
        let supervisor = slot
            .take()
            .ok_or(LocalExecutorPoolConfigError::HostOperationalAdmission)?;
        *route = AdmissionRoute::Handoff;
        let executor = LocalExecutorCapabilityService::new(supervisor, description)
            .map_err(|_| LocalExecutorPoolConfigError::HostOperationalAdmission)?;
        drop(slot);
        drop(route);
        let mut executor = ActorAllocation::from(executor);
        let Ok(mut running) = self.state.running.lock() else {
            std::mem::forget(executor);
            return Err(LocalExecutorPoolConfigError::HostOperationalAdmission);
        };
        *running = Some(executor.actor.clone());
        drop(running);
        executor.terminal = Some(TerminalHook::new(
            self.state.clone(),
            Arc::downgrade(&self.admission),
        ));
        self.terminal.disarm();
        Ok((executor, self.admission.clone()))
    }
}

impl<L: Send + 'static, V: Send + Sync + 'static> HostAdmission<L, V> {
    pub(super) fn running(shared: &Arc<SharedExecutor<L, V>>) -> Self {
        let custody = Arc::new(PreparationState {
            supervisor: Mutex::new(None),
            running: Mutex::new(Some(shared.executor.clone())),
        });
        Self {
            route: Mutex::new(AdmissionRoute::Running(Arc::downgrade(shared))),
            custody,
        }
    }

    pub(super) fn bind(
        self: &Arc<Self>,
        shared: &Arc<SharedExecutor<L, V>>,
    ) -> Result<(), HostOperationalError> {
        let mut route = self
            .route
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if !matches!(*route, AdmissionRoute::Handoff) {
            return Err(HostOperationalError::Unavailable);
        }
        *self
            .custody
            .running
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)? = Some(shared.executor.clone());
        let mut terminal = shared
            .terminal_hook
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if terminal.is_none() {
            *terminal = Some(TerminalHook::new(
                self.custody.clone(),
                Arc::downgrade(self),
            ));
        }
        drop(terminal);
        *route = AdmissionRoute::Running(Arc::downgrade(shared));
        Ok(())
    }

    pub(super) fn install_terminal_hook(self: &Arc<Self>, shared: &Arc<SharedExecutor<L, V>>) {
        if let Ok(mut slot) = shared.terminal_hook.lock()
            && slot.is_none()
        {
            *slot = Some(TerminalHook::new(
                self.custody.clone(),
                Arc::downgrade(self),
            ));
        }
    }

    fn with_supervisor<T>(
        &self,
        operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, HostOperationalError>,
    ) -> Result<T, HostOperationalError> {
        self.with_routed_supervisor(false, operation)
    }

    fn with_cleanup_supervisor<T>(
        &self,
        operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, HostOperationalError>,
    ) -> Result<T, HostOperationalError> {
        self.with_routed_supervisor(true, operation)
    }

    fn with_routed_supervisor<T>(
        &self,
        cleanup: bool,
        operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, HostOperationalError>,
    ) -> Result<T, HostOperationalError> {
        // Routing and actor mutation share one order. Handoff cannot race a
        // successful admission or briefly introduce a second capacity ledger.
        let route = self
            .route
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        match &*route {
            AdmissionRoute::Preparing(state) => {
                let state = state.upgrade().ok_or(HostOperationalError::Unavailable)?;
                let mut slot = state
                    .supervisor
                    .lock()
                    .map_err(|_| HostOperationalError::Unavailable)?;
                operation(slot.as_mut().ok_or(HostOperationalError::Unavailable)?)
            }
            AdmissionRoute::Handoff => Err(HostOperationalError::Unavailable),
            AdmissionRoute::Terminal(state) if cleanup => {
                let state = state.upgrade().ok_or(HostOperationalError::Unavailable)?;
                custody::with_actor(&state, operation)
            }
            AdmissionRoute::Terminal(_) => Err(HostOperationalError::Unavailable),
            AdmissionRoute::Running(shared) => {
                let shared = shared.upgrade().ok_or(HostOperationalError::Unavailable)?;
                if !cleanup && shared.state.load(Ordering::Acquire) != POOL_RUNNING {
                    return Err(HostOperationalError::Unavailable);
                }
                // No filesystem or socket I/O occurs under the actor lock.
                let mut executor = shared
                    .executor
                    .lock()
                    .map_err(|_| HostOperationalError::Unavailable)?;
                let result = operation(executor.supervisor_mut());
                if result.is_ok() {
                    shared.ownership_revision.fetch_add(1, Ordering::AcqRel);
                    shared.ready.notify_all();
                }
                result
            }
        }
    }
}

impl<L: Send + 'static, V: Send + Sync + 'static>
    crate::host_operational_registry::HostResourceAdmission for HostAdmission<L, V>
{
    fn capacity_custody(&self) -> Result<Arc<dyn Send + Sync>, HostOperationalError> {
        let route = self
            .route
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        match &*route {
            AdmissionRoute::Preparing(state) => {
                Ok(state.upgrade().ok_or(HostOperationalError::Unavailable)?)
            }
            AdmissionRoute::Handoff => Err(HostOperationalError::Unavailable),
            AdmissionRoute::Running(shared) => {
                // Validate the live route without making a durable holder
                // retain the pool that points back to this registry.
                let _live = shared.upgrade().ok_or(HostOperationalError::Unavailable)?;
                Ok(self.custody.clone())
            }
            AdmissionRoute::Terminal(state) => {
                Ok(state.upgrade().ok_or(HostOperationalError::Unavailable)?)
            }
        }
    }

    fn owner_ceiling(
        &self,
        daemon_epoch: [u8; 32],
        owner: [u8; 32],
    ) -> Result<HostResourceVector, HostOperationalError> {
        self.with_cleanup_supervisor(|supervisor| {
            supervisor.host_ram_owner_ceiling(daemon_epoch, owner)
        })
    }

    fn reserve_service_with_assignment_headroom(
        &self,
        owner: [u8; 32],
        service: HostResourceVector,
        assignment: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.with_supervisor(|supervisor| {
            supervisor.reserve_host_ram_service_with_assignment_headroom(owner, service, assignment)
        })
    }

    fn reserve_service_with_admitted_assignment(
        &self,
        owner: [u8; 32],
        service: HostResourceVector,
        existing_execution_owner: [u8; 32],
    ) -> Result<(), HostOperationalError> {
        self.with_supervisor(|supervisor| {
            supervisor.reserve_host_ram_service_with_admitted_assignment(
                owner,
                service,
                existing_execution_owner,
            )
        })
    }

    fn service_nodes_cleaned(&self, owner: [u8; 32]) -> Result<bool, HostOperationalError> {
        self.with_cleanup_supervisor(|supervisor| supervisor.host_ram_service_nodes_cleaned(owner))
    }

    fn release_service_after_cleanup(&self, owner: [u8; 32]) -> Result<(), HostOperationalError> {
        self.with_cleanup_supervisor(|supervisor| {
            supervisor.release_host_ram_service_after_cleanup(owner)
        })
    }

    fn repartition_node_before_cpu(
        &self,
        target: HostRamTarget,
        expected_initial: HostResourceVector,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.with_supervisor(|supervisor| {
            supervisor.repartition_host_ram_node_before_cpu(target, expected_initial, resources)
        })
    }

    fn release_unpublished_after_cleanup(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.with_cleanup_supervisor(|supervisor| {
            supervisor.release_unpublished_host_ram_node_after_cleanup(target, resources)
        })
    }

    fn quarantine_unpublished(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.with_cleanup_supervisor(|supervisor| {
            supervisor.quarantine_unpublished_host_ram_node(target, resources)
        })
    }

    fn release_after_cleanup(&self, target: HostRamTarget) -> Result<(), HostOperationalError> {
        self.with_cleanup_supervisor(|supervisor| {
            supervisor.release_host_ram_node_after_cleanup(target)
        })
    }

    fn configure_owner(
        &self,
        daemon_epoch: [u8; 32],
        owner: [u8; 32],
        ceiling: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.with_supervisor(|supervisor| {
            supervisor.configure_host_ram_owner(daemon_epoch, owner, ceiling)
        })
    }

    fn admit_node(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.with_supervisor(|supervisor| supervisor.admit_host_ram_node(target, resources))
    }

    fn begin_transition(
        &self,
        target: HostRamTarget,
        amendment: HostReservationAmendment,
    ) -> Result<HostResourceTransition, HostOperationalError> {
        self.with_supervisor(|supervisor| supervisor.begin_host_ram_transition(target, amendment))
    }

    fn finish_transition(
        &self,
        transition: HostResourceTransition,
    ) -> Result<(), HostOperationalError> {
        self.with_supervisor(|supervisor| supervisor.finish_host_ram_transition(transition))
    }
}
