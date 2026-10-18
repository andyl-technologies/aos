//! Installs construction inputs without moving them across a refused admission.
//!
//! Owned callers retain every input before requesting the original carrier.
//! Borrowed callers validate that same empty carrier before moving their slots.

use super::*;

/// Retains every incoming owner before inspecting the launcher's storage slot.
pub(in crate::vm_lifecycle) fn with_inputs(
    launcher: Box<dyn ProductionVmNodeLauncher>,
    checkpoint: Option<ProductionVmExactCheckpointSet>,
    restore: Option<ProductionVmHotForkRestore>,
    continuation: Option<ProductionVmHotForkWorldContinuation>,
    adoptions: Vec<ProductionVmHotForkNodeAdoption>,
) -> Result<Box<ProductionVmConstructionCustody>, ProductionVmConstructionFailure> {
    let mut incoming = Partial::new();
    incoming.node_launcher = Some(launcher);
    incoming.restore_checkpoint = checkpoint;
    incoming.hot_fork_restore = restore;
    incoming.hot_fork_continuation = continuation;
    incoming.hot_fork_adoptions = adoptions;
    let existing = incoming
        .node_launcher
        .as_mut()
        .and_then(|launcher| launcher.take_construction_custody());
    if let Some(mut custody) = existing {
        if let Ok(partial) = custody.empty_input_slot() {
            *partial = incoming;
            return Ok(custody);
        }
        return Err(ProductionVmConstructionFailure {
            storage: FailureStorage::Missing(MissingStorage {
                first: LifecycleApiError::ConstructionCustodyUnavailable,
                partial: Mutex::new(incoming),
                existing: Some(custody),
            }),
            additional: None,
        });
    }
    Err(ProductionVmConstructionFailure {
        storage: FailureStorage::Missing(MissingStorage {
            first: LifecycleApiError::ConstructionCustodyUnavailable,
            partial: Mutex::new(incoming),
            existing: None,
        }),
        additional: None,
    })
}

impl ProductionVmConstructionCustody {
    /// Moves already retained inputs into the original empty carrier.
    ///
    /// Every validation precedes the first move. Refusal leaves all incoming
    /// slots unchanged; success performs no allocation or launcher callback.
    ///
    /// # Errors
    /// Refuses an absent launcher or a closed, occupied, poisoned or previously
    /// failed carrier, including one already attached to a cleanup reservation.
    pub(crate) fn install_inputs(
        &mut self,
        launcher: &mut Option<Box<dyn ProductionVmNodeLauncher>>,
        checkpoint: &mut Option<ProductionVmExactCheckpointSet>,
    ) -> Result<(), LifecycleApiError> {
        if launcher.is_none() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        let partial = self.empty_input_slot()?;

        partial.node_launcher = launcher.take();
        partial.restore_checkpoint = checkpoint.take();
        Ok(())
    }

    /// Moves a complete set of retained fork inputs into this original carrier.
    ///
    /// The caller keeps each slot on refusal. Success transfers only existing
    /// owners; validation and scheduler construction are separate operations.
    ///
    /// # Errors
    /// Refuses a missing launcher or continuation, or a carrier that is closed,
    /// occupied, poisoned, already failed or attached to a cleanup reservation.
    pub(crate) fn install_hot_fork_inputs(
        &mut self,
        launcher: &mut Option<Box<dyn ProductionVmNodeLauncher>>,
        continuation: &mut Option<ProductionVmHotForkWorldContinuation>,
        adoptions: &mut Vec<ProductionVmHotForkNodeAdoption>,
    ) -> Result<(), LifecycleApiError> {
        if launcher.is_none() || continuation.is_none() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        let partial = self.empty_input_slot()?;

        partial.node_launcher = launcher.take();
        partial.hot_fork_continuation = continuation.take();
        partial.hot_fork_adoptions = std::mem::take(adoptions);
        Ok(())
    }

    /// Retains partial adoptions for the carrier's existing cleanup algorithm.
    ///
    /// No launcher or executable lifecycle is published by this operation.
    /// The original vector allocation moves intact after validating the slot.
    ///
    /// # Errors
    /// Refuses a nonempty input vector when this carrier is no longer pristine.
    pub(crate) fn install_adoption_cleanup(
        &mut self,
        adoptions: &mut Vec<ProductionVmHotForkNodeAdoption>,
    ) -> Result<(), LifecycleApiError> {
        if adoptions.is_empty() {
            return Ok(());
        }
        let partial = self.empty_input_slot()?;

        partial.hot_fork_adoptions = std::mem::take(adoptions);
        Ok(())
    }

    /// Refuses terminal or previously failed custody before preparation effects.
    pub(in crate::vm_lifecycle) fn preparation_phase(
        &mut self,
    ) -> Result<&mut Partial, LifecycleApiError> {
        let partial = self.open_partial()?;
        if partial.cleanup_complete
            || partial.pending_reaped.is_some()
            || partial.node_launcher.is_none()
        {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        Ok(partial)
    }

    fn empty_input_slot(&mut self) -> Result<&mut Partial, LifecycleApiError> {
        let partial = self.open_partial()?;
        if !partial.is_empty() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        Ok(partial)
    }

    fn open_partial(&mut self) -> Result<&mut Partial, LifecycleApiError> {
        if self.first.is_some() || self.physically_closed.load(Ordering::Acquire) {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        #[cfg(target_os = "linux")]
        if self.reservation.is_some() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        match self.phase.get_mut() {
            Ok(Phase::Partial(partial)) => Ok(partial),
            _ => Err(LifecycleApiError::ConstructionCustodyUnavailable),
        }
    }
}
