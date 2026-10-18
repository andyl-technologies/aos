//! Original Source/input Group finalization before native command publication.
//!
//! Backend current is mandatory before and after the semantic transaction.
//! A refused suffix retains the registered owner and blocks ordinary RUN.

use super::*;
use crate::{DeviceGroupSelectionPublication, PreparedDeviceGroupSelection};

impl<B: SimulationBackend, I> BackendQuantumLoop<SingleScheduler, B, I> {
    /// Finalizes one actual backend opportunity under complete World input.
    ///
    /// This returns semantic ownership only. The backend must independently
    /// authenticate the same Source and received record before command13.
    ///
    /// # Errors
    ///
    /// Refuses another retained actor, unavailable original physical ownership,
    /// incomplete input, stale scheduler state, or changed retry identity.
    /// Failure after registration retains the original owner for retry/cleanup.
    pub fn prepare_device_group_selection(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<PreparedDeviceGroupSelection>, SchedulerError> {
        if self.continuation_poisoned
            || self.held_host_continuation.is_some()
            || self.preselection.is_some()
            || self.pending_fixed_input.is_some()
            || self.failed_input_resolution.is_some()
            || self.failed_cap_negotiation.is_some()
            || self.failed_dispatch_resolution.is_some()
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("Group selection crosses another retained actor"),
            });
        }
        let Some(observation) = self.backend.observe_device_group_opportunity(node)? else {
            if self.device_group_selection.is_retained() {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("original retained Group opportunity disappeared"),
                });
            }
            return Ok(None);
        };
        if observation.input_inventory().node != *node {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("Group opportunity targets a different requested node"),
            });
        }
        self.backend
            .device_group_opportunity_current(&observation)?;
        let mut staged = self.loop_impl.clone();
        staged.import_initial_io_inventory(observation.input_inventory().clone())?;
        let prepared = self
            .device_group_selection
            .prepare(&staged, observation.clone())?;
        // Preserve the actual semantic return before the fallible physical
        // suffix. Its registered owner vetoes ordinary dispatch on refusal.
        self.loop_impl = staged;
        self.backend
            .device_group_opportunity_current(&observation)?;
        self.device_group_selection
            .current(&self.loop_impl, &prepared)?;
        Ok(Some(prepared))
    }

    /// Queues one registered selection from its original issuing loop.
    ///
    /// Fresh publication checks semantic and physical current immediately before
    /// the backend callback. An issued uncertain attempt retains its original
    /// pending association; retry asks that callback for the same factual ACK
    /// without requiring physical Held after native acceptance. A cached queued
    /// ACK is never replayed. Later acceptance and release remain independent.
    ///
    /// # Errors
    ///
    /// Refuses a foreign or stale semantic owner, cleanup-only loop, unavailable
    /// first-publication physical ownership, or unresolved actual queue ACK.
    /// Every refusal retains the original selection and publication obligation.
    pub fn publish_device_group_selection(
        &mut self,
        prepared: &PreparedDeviceGroupSelection,
    ) -> Result<DeviceGroupSelectionPublication, SchedulerError> {
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("Group publication belongs to a cleanup-only backend"),
            });
        }
        self.device_group_selection
            .current(&self.loop_impl, prepared)?;
        if !self.device_group_selection.publication_issued() {
            self.device_group_selection_current(prepared)?;
            self.device_group_selection.begin_publication();
        }
        if !self.device_group_selection.publication_queued() {
            self.backend.queue_device_group_selection(prepared)?;
            // Record actual callback0 before any fallible semantic suffix. The
            // backend owns pending-command retries when its reply is uncertain.
            self.device_group_selection.acknowledge_publication();
        }
        self.device_group_selection
            .current(&self.loop_impl, prepared)?;
        Ok(DeviceGroupSelectionPublication::Queued)
    }

    /// Rejoins a registered selection before any native command publication.
    ///
    /// # Errors
    ///
    /// Refuses a foreign owner/controller, changed semantic state or unavailable
    /// original physical Source and received publication. This is preaccept
    /// current; postaccept cleanup requires its independent native receipt.
    pub fn device_group_selection_current(
        &mut self,
        prepared: &PreparedDeviceGroupSelection,
    ) -> Result<(), SchedulerError> {
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("Group selection belongs to a cleanup-only backend"),
            });
        }
        self.device_group_selection
            .current(&self.loop_impl, prepared)?;
        self.backend
            .device_group_opportunity_current(prepared.observation())?;
        self.device_group_selection
            .current(&self.loop_impl, prepared)
    }
}
