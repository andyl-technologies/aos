//! QEMU error adapters for shared modeled event and choice retention.

use std::ops::{Deref, DerefMut};

use super::*;
use crate::modeled_campaign_driver::event_log_retention as modeled;

pub(super) fn append_quantum(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    event_log_bytes: &mut usize,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
    retain_environment_fault_discoveries: bool,
    outcome: QuantumOutcome,
) -> Result<crucible::Configuration, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    modeled::append_quantum(
        event_log,
        event_log_bytes,
        &mut discoveries.0,
        terminal_quiescence,
        terminal_at,
        retain_environment_fault_discoveries,
        outcome,
    )
    .map_err(|error| AttemptWorkerFailure::Terminal(error.into()))
}

pub(super) fn append_event_entries(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    retained_bytes: &mut usize,
    entries: Vec<SchedulerEventLogEntry>,
) -> Result<(), QemuFreshModeledDriverError> {
    modeled::append_event_entries(event_log, retained_bytes, entries).map_err(Into::into)
}

/// Preserves the implementation error API without duplicating logical state.
#[derive(Default)]
pub(super) struct RetainedChoiceDiscoveries(modeled::RetainedChoiceDiscoveries);

impl RetainedChoiceDiscoveries {
    pub(super) fn into_discoveries(self) -> BTreeMap<ChoiceOpportunityId, ChoiceDiscovery> {
        self.0.discoveries
    }

    pub(super) fn from_replayed(
        replayed: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        modeled::RetainedChoiceDiscoveries::from_replayed(replayed)
            .map(Self)
            .map_err(Into::into)
    }

    pub(super) fn insert(
        &mut self,
        discovery: ChoiceDiscovery,
    ) -> Result<(), QemuFreshModeledDriverError> {
        self.0.insert(discovery).map_err(Into::into)
    }
}

impl Deref for RetainedChoiceDiscoveries {
    type Target = modeled::RetainedChoiceDiscoveries;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RetainedChoiceDiscoveries {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
