//! Terminal custody of the original charged actor across pool handoff.
//!
//! Preparation holders and the worker pool share the same actor allocation.
//! Terminal hooks detach its registry before the registry receives an owned
//! cleanup authority, so durable holders retain accounting without an actor
//! to registry ownership cycle.

use super::*;

/// Executes one terminal ownership transfer when normal actor ownership ends.
pub(in crate::executor_pool) struct TerminalHook {
    transfer: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl TerminalHook {
    pub(super) fn new<L: Send + 'static, V: Send + Sync + 'static>(
        state: Arc<PreparationState<L, V>>,
        admission: Weak<HostAdmission<L, V>>,
    ) -> Self {
        Self {
            transfer: Some(Box::new(move || transfer_to_registry(state, admission))),
        }
    }

    pub(super) fn disarm(&mut self) {
        self.transfer = None;
    }
}

impl Drop for TerminalHook {
    fn drop(&mut self) {
        if let Some(transfer) = self.transfer.take() {
            transfer();
        }
    }
}

/// Applies cleanup to the same supervisor, whether preparation or pool owned.
pub(super) fn with_actor<L, V, T>(
    state: &PreparationState<L, V>,
    operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, HostOperationalError>,
) -> Result<T, HostOperationalError> {
    let mut preparing = state
        .supervisor
        .lock()
        .map_err(|_| HostOperationalError::Unavailable)?;
    if let Some(supervisor) = preparing.as_mut() {
        return operation(supervisor);
    }
    drop(preparing);

    let running = state
        .running
        .lock()
        .map_err(|_| HostOperationalError::Unavailable)?;
    let actor = running.as_ref().ok_or(HostOperationalError::Unavailable)?;
    let mut actor = actor
        .lock()
        .map_err(|_| HostOperationalError::Unavailable)?;
    operation(actor.supervisor_mut())
}

struct RegistryActor<L, V> {
    state: Arc<PreparationState<L, V>>,
}

impl<L: Send + 'static, V: Send + Sync + 'static>
    crate::host_operational_registry::RegistryRetirementAuthority for RegistryActor<L, V>
{
    fn retire_after_cleanup(&mut self, owner: [u8; 32]) -> Result<(), HostOperationalError> {
        with_actor(&self.state, |actor| {
            actor.release_host_ram_service_after_cleanup(owner)?;
            let (aggregate, _) = actor
                .host_resource_capacities()
                .ok_or(HostOperationalError::Unavailable)?;
            let available = actor
                .host_resource_availability()
                .ok_or(HostOperationalError::Unavailable)?;
            if available != aggregate {
                // Registry closure proves only its own physical disposition.
                // Persisted catalogs or unknown execution owners still retain
                // the original actor even when every wrapper has disappeared.
                return Err(HostOperationalError::Unavailable);
            }
            Ok(())
        })
    }
}

fn transfer_to_registry<L: Send + 'static, V: Send + Sync + 'static>(
    state: Arc<PreparationState<L, V>>,
    admission: Weak<HostAdmission<L, V>>,
) {
    let registry = match with_actor(&state, |actor| {
        Ok(actor.detach_registry_for_terminal_cleanup())
    }) {
        Ok(registry) => registry,
        Err(_) => {
            // No counter or physical owner may disappear after uncertain
            // mutex ownership. Quarantine the original actor allocation.
            std::mem::forget(state);
            return;
        }
    };
    if let Some(admission) = admission.upgrade() {
        let Ok(mut route) = admission.route.lock() else {
            std::mem::forget((registry, state));
            return;
        };
        *route = AdmissionRoute::Terminal(Arc::downgrade(&state));
    }
    if registry.admitted_registry_service().is_some() {
        let authority = Box::new(RegistryActor { state });
        if let Err(authority) = registry.retain_retirement_authority(authority) {
            std::mem::forget((registry, authority));
        }
    }
}
