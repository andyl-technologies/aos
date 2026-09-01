//! Scheduler-owned network settlement results.

use super::*;

/// Scheduler changes produced while settling network frames at one boundary.
#[derive(Clone, Debug)]
pub struct BackendNetworkSettlement {
    pub(super) decisions: Vec<Decision>,
    pub(super) configuration: Option<Configuration>,
    pub(super) appends: Vec<SchedulerEventLogAppend>,
}

impl BackendNetworkSettlement {
    /// Consumes the settlement into decisions, the latest configuration, and appends.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<Decision>,
        Option<Configuration>,
        Vec<SchedulerEventLogAppend>,
    ) {
        (self.decisions, self.configuration, self.appends)
    }
}
