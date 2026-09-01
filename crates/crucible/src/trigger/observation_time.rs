//! Observation admission-time normalization.

use super::*;

impl ObservableEvent {
    /// Rebinds when this event becomes visible to condition evaluation.
    ///
    /// The event payload retains its original device or guest execution
    /// coordinate. This is used when a bounded setup phase captures an event
    /// before the authoritative scheduler admits that observation at its
    /// ready-point boundary.
    pub fn set_observation_time(&mut self, at: VirtualTime) {
        self.at = at;
    }
}
