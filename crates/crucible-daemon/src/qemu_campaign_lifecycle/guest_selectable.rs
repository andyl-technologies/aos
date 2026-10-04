//! Guest request visibility and replies under the original lifecycle owner.

use super::*;

impl QemuFreshAttemptLifecycle<'_> {
    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// The result remains untrusted guest input until the modeled driver binds
    /// it to the scenario declaration and selects a legal value.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request stream is malformed.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.owner.drain_pending_selectable_requests()
    }

    /// Projects a retained guest pause into the shared scheduler clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the pause overflows or its admitted mapping is absent.
    pub fn pending_selectable_request_time(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        self.owner.pending_selectable_request_time(pending)
    }

    /// Authenticates an already committed held source without advancing peers.
    ///
    /// # Errors
    ///
    /// Returns an error when original ownership or the retained token changed.
    pub fn pending_selectable_request_is_committed_source(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<bool, SchedulerError> {
        self.owner
            .pending_selectable_request_is_committed_source(pending)
    }

    /// Applies one exact semantic reply at the authoritative scheduler frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the live request/reply binding fails.
    pub fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.owner
            .apply_selectable_reply(parent, decision, selected, pending, reply)
    }
}
