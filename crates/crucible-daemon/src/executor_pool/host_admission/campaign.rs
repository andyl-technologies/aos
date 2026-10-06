//! Private campaign operations routed to the original sole-writer actor.
//!
//! A port retains the unchanged actor allocation across preparation and pool
//! handoff. It owns no pool and creates no ledger. New operations refuse after
//! terminal shutdown; physical cleanup continues through the registry route.

use super::*;

pub(crate) struct CampaignActorPort<L, V> {
    admission: Arc<HostAdmission<L, V>>,
}

impl<L, V> Clone for CampaignActorPort<L, V> {
    fn clone(&self) -> Self {
        Self {
            admission: Arc::clone(&self.admission),
        }
    }
}

impl<L: Send + 'static, V: Send + Sync + 'static> CampaignActorPort<L, V> {
    pub(super) fn new(admission: Arc<HostAdmission<L, V>>) -> Self {
        Self { admission }
    }

    /// Applies a short campaign operation to the same charged actor.
    ///
    /// # Errors
    /// Refuses poisoned, handoff, or terminal state and propagates the callback
    /// error. Callbacks must not perform filesystem or socket I/O.
    pub(crate) fn with_supervisor<T>(
        &self,
        operation: impl FnOnce(&mut LocalExecutorSupervisor<L, V>) -> Result<T, HostOperationalError>,
    ) -> Result<T, HostOperationalError> {
        self.admission.with_supervisor(operation)
    }
}

impl<L: Send + 'static, V: Send + Sync + 'static> CampaignActorPort<L, V> {
    /// Retains the original accounting authority during uncertain cleanup.
    pub(crate) fn capacity_custody(&self) -> Arc<dyn Send + Sync> {
        self.admission.custody.clone()
    }
}

impl<L, V> CampaignActorPort<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    /// Attaches genuine pre-teardown staging to the accepted queue identity.
    pub(crate) fn install_checkpoint_handoff(
        &self,
        queued: &mut QueuedAttempt,
        checkpoints: Arc<ExactCheckpointStore>,
    ) {
        checkpoint_handoff::install(Arc::clone(&self.admission), queued, checkpoints);
    }
}
