//! Bounded event-log and choice-discovery retention for modeled attempts.

use super::*;

pub(super) fn append_quantum(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    event_log_bytes: &mut usize,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
    retain_environment_fault_discoveries: bool,
    outcome: QuantumOutcome,
) -> Result<crucible::Configuration, AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    let QuantumOutcome {
        configuration,
        discovered_choices,
        event_log_entries,
        scheduler_quiescence,
        frontier,
        ..
    } = outcome;
    append_event_entries(event_log, event_log_bytes, event_log_entries)
        .map_err(AttemptWorkerFailure::Terminal)?;
    for discovery in discovered_choices {
        if is_environment_fault_discovery(&discovery) && !retain_environment_fault_discoveries {
            continue;
        }
        discoveries
            .insert(discovery)
            .map_err(AttemptWorkerFailure::Terminal)?;
    }
    *terminal_quiescence = scheduler_quiescence;
    *terminal_at = (*terminal_at).max(frontier);
    Ok(configuration)
}

fn is_environment_fault_discovery(discovery: &ChoiceDiscovery) -> bool {
    matches!(
        discovery.opportunity().source(),
        crucible_campaign::ChoiceSource::Environment { adapter, .. }
            if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
                || adapter == crucible::NETWORK_FAULT_CAMPAIGN_ADAPTER
    )
}

pub(super) fn append_event_entries(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    retained_bytes: &mut usize,
    entries: Vec<SchedulerEventLogEntry>,
) -> Result<(), QemuFreshModeledDriverError> {
    let total = event_log.len().checked_add(entries.len()).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        },
    )?;
    if total > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-entry-count",
        });
    }
    let added_bytes = entries.iter().try_fold(0usize, |total, entry| {
        total.checked_add(entry.canonical_material_len()).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-event-log-bytes",
            },
        )
    })?;
    let total_bytes = retained_bytes.checked_add(added_bytes).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        },
    )?;
    if total_bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes",
        });
    }
    event_log.extend(entries);
    *retained_bytes = total_bytes;
    Ok(())
}

#[derive(Default)]
pub(super) struct RetainedChoiceDiscoveries {
    pub(super) discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    pub(super) representatives: BTreeMap<(SelectableId, ChoiceDomainId), ChoiceDiscovery>,
    pub(super) charged_records: BTreeSet<ContentId>,
    pub(super) charged_bytes: usize,
}

impl RetainedChoiceDiscoveries {
    pub(super) fn from_replayed(
        replayed: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    ) -> Result<Self, QemuFreshModeledDriverError> {
        let mut discoveries = Self::default();
        for discovery in replayed.into_values() {
            discoveries.insert(discovery)?;
        }
        Ok(discoveries)
    }

    pub(super) fn insert(
        &mut self,
        mut discovery: ChoiceDiscovery,
    ) -> Result<(), QemuFreshModeledDriverError> {
        let declaration = discovery.opportunity().declaration();
        let domain = discovery.opportunity().domain();
        let opportunity = discovery.opportunity().id()?;
        let contract = (declaration, domain);
        if let Some(validated) = self.representatives.get(&contract) {
            discovery.share_dependencies_from(validated)?;
        } else {
            self.charge(
                declaration.content_id(),
                discovery.declaration().canonical_bytes().len(),
            )?;
            self.charge(
                domain.content_id(),
                discovery.domain().canonical_bytes().len(),
            )?;
            self.representatives.insert(contract, discovery.clone());
        }

        if let Some(existing) = self.discoveries.get(&opportunity) {
            if existing.opportunity() != discovery.opportunity() {
                return Err(QemuFreshModeledDriverError::ConflictingChoice(opportunity));
            }
            return Ok(());
        }
        if self.discoveries.len() == MAX_OBSERVATION_CHOICE_DISCOVERIES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-count",
            });
        }
        self.charge(
            opportunity.content_id(),
            discovery.opportunity().canonical_bytes().len(),
        )?;
        self.discoveries.insert(opportunity, discovery);
        Ok(())
    }

    fn charge(&mut self, id: ContentId, bytes: usize) -> Result<(), QemuFreshModeledDriverError> {
        if !self.charged_records.insert(id) {
            return Ok(());
        }
        let total = self.charged_bytes.checked_add(bytes).ok_or(
            QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            },
        )?;
        if total > MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-discovered-choice-bytes",
            });
        }
        self.charged_bytes = total;
        Ok(())
    }
}
