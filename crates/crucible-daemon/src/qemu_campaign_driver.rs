//! Concrete modeled driving and observation projection for fresh campaign QEMU attempts.
//!
//! The driver advances only through [`crate::QemuFreshAttemptLifecycle`], stops
//! on the attempt's exact semantic boundary or a modeled terminal verdict, and
//! retains a bounded dense event log until runner-owned shutdown contributes
//! its final observational suffix. Sealing then reconstructs the exact child
//! artifact, evaluates scenario properties offline, derives grow-only coverage
//! identities, and produces one self-contained campaign observation candidate.

use std::collections::{BTreeMap, BTreeSet};

use crucible::model::{
    BoundarySelector, CohortPolicy, MeasurementDefinitions, MeasurementId, MeasurementInstanceKey,
    MeasurementRuntimeSample, MeasurementSampleValue, MeasurementTerminalState, MetricDefinition,
    MetricId, MetricSource, MetricValueType, ReducedRational, append_model_measurement_samples,
};
use crucible::{
    EventLogCoverageObservation, GuestMeasurementEvent, GuestMeasurementValue,
    HostAssertionOutcomeKind, NodeId, ObservableEventPayload, OfflineAssertionCheckError,
    OfflineAssertionChecker, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict,
    SchedulerError, SchedulerEventLogEntry, SchedulerEventLogPayload,
    SchedulerOperationalFailureClass, SchedulerQuiescence, VirtualTime,
};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ChoiceDiscovery, ChoiceDomainId, ChoiceOpportunityId,
    CoverageProjection, MAX_OBSERVATION_CHOICE_DISCOVERIES, MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
    Observation, ObservationCandidate, PropertyEvidence, PropertyVerdict, PropertyVerdictSet,
    SelectableId, StopCondition, StopOutcome,
};
use crucible_cas::content_store::ContentId;
use thiserror::Error;

use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure, CrucibleArtifactError,
    CrucibleAttemptExecution, CrucibleMeasurementError, CrucibleResolvedAttemptStart,
    QemuFreshAttemptDriver, QemuFreshAttemptLifecycle, QemuFreshStartMaterialization,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
    evaluate_crucible_measurement_set,
};

/// Maximum scheduler entries retained by one in-memory fresh-attempt projection.
pub const MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES: usize = 1_000_000;

/// Maximum aggregate canonical event material retained by one fresh attempt.
pub const MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES: usize = 64 * 1024 * 1024;

/// Maximum property-by-event evaluations admitted by one fresh-attempt seal.
pub const MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS: usize = 1_000_000;

/// Maximum simultaneously open guest measurement instances in one attempt.
pub const MAX_QEMU_CAMPAIGN_OPEN_MEASUREMENT_INSTANCES: usize = 65_536;

/// Failure while driving or projecting one fresh modeled campaign attempt.
#[derive(Debug, Error)]
pub enum QemuFreshModeledDriverError {
    /// The attempt was canceled at a modeled boundary.
    #[error("fresh campaign attempt was canceled")]
    Canceled,
    /// An exact checkpoint request reached a runner without capture authority.
    #[error("fresh campaign driver cannot satisfy an exact-checkpoint request")]
    ExactCheckpointUnsupported,
    /// Scheduler progress or final event validation failed.
    #[error("fresh campaign scheduler failed: {0}")]
    Scheduler(#[source] SchedulerError),
    /// Strict Crucible artifact reconstruction failed.
    #[error("fresh campaign artifact projection failed: {0}")]
    Artifact(#[source] CrucibleArtifactError),
    /// Campaign canonical construction failed.
    #[error("fresh campaign observation projection failed: {0}")]
    Campaign(#[source] CampaignCodecError),
    /// Offline property evaluation rejected the complete retained event log.
    #[error("fresh campaign property evaluation failed: {0}")]
    Assertions(#[source] OfflineAssertionCheckError),
    /// Measurement evaluation or campaign binding rejected the retained run.
    #[error("fresh campaign measurement evaluation failed: {0}")]
    Measurements(#[source] CrucibleMeasurementError),
    /// A guest measurement or semantic-marker message violated the scenario contract.
    #[error("fresh campaign guest measurement protocol failed at sequence {sequence}: {reason}")]
    GuestMeasurementProtocol {
        /// Exact scheduler sequence carrying the invalid message.
        sequence: u64,
        /// Stable validation diagnostic.
        reason: String,
    },
    /// The lifecycle returned a child configuration for another scenario.
    #[error("fresh campaign lifecycle returned a configuration for another scenario")]
    ScenarioMismatch,
    /// A repeated opportunity ID carried conflicting canonical bodies.
    #[error("fresh campaign lifecycle returned conflicting bodies for opportunity `{0}`")]
    ConflictingChoice(ChoiceOpportunityId),
    /// Retained event or property-evaluation work exceeded the driver bound.
    #[error("fresh campaign modeled projection exceeded `{limit}`")]
    LimitExceeded {
        /// Stable name of the exceeded limit.
        limit: &'static str,
    },
    /// A modeled stop was reported while network output remained uncommitted.
    #[error("fresh campaign stop retained {0} uncommitted network outputs")]
    PendingNetworkOutput(usize),
}

impl From<CrucibleArtifactError> for QemuFreshModeledDriverError {
    fn from(error: CrucibleArtifactError) -> Self {
        Self::Artifact(error)
    }
}

impl From<CampaignCodecError> for QemuFreshModeledDriverError {
    fn from(error: CampaignCodecError) -> Self {
        Self::Campaign(error)
    }
}

impl From<OfflineAssertionCheckError> for QemuFreshModeledDriverError {
    fn from(error: OfflineAssertionCheckError) -> Self {
        Self::Assertions(error)
    }
}

/// Concrete bounded modeled driver for one fresh campaign QEMU lifecycle.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuFreshModeledDriver;

/// Bounded modeled state retained until runner-owned final drain completes.
#[derive(Debug)]
pub struct QemuFreshPendingObservation {
    input: CrucibleAttemptExecution,
    configuration: crucible::Configuration,
    stop: ModeledStop,
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_bytes: usize,
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    terminal_at: VirtualTime,
}

#[derive(Debug)]
enum ModeledStop {
    Reached(StopCondition),
    TerminalPassed,
    TerminalFailed,
}

impl QemuFreshModeledDriver {
    /// Creates the stateless fresh-attempt driver.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl QemuFreshAttemptDriver for QemuFreshModeledDriver {
    type Pending = QemuFreshPendingObservation;
    type Error = QemuFreshModeledDriverError;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<Self::Pending, AttemptWorkerFailure<Self::Error>> {
        let scenario = input.scenario().scenario_def();
        let mut configuration = match input.start() {
            CrucibleResolvedAttemptStart::Discover { configuration } => configuration.clone(),
            CrucibleResolvedAttemptStart::Branch { selected, .. } => selected.clone(),
        };
        if configuration.def != scenario {
            return Err(AttemptWorkerFailure::Terminal(
                QemuFreshModeledDriverError::ScenarioMismatch,
            ));
        }

        let (mut event_log, mut event_log_bytes, mut terminal_quiescence, terminal_verdict) =
            materialization.into_parts();
        let mut terminal_at = event_log
            .last()
            .map_or(VirtualTime { ticks: 0 }, SchedulerEventLogEntry::at);
        let mut discoveries = RetainedChoiceDiscoveries::default();
        if let Some(verdict) = terminal_verdict {
            let stop = match verdict {
                QuantumTerminalVerdict::Passed => ModeledStop::TerminalPassed,
                QuantumTerminalVerdict::Failed(_) => ModeledStop::TerminalFailed,
            };
            let pending = lifecycle.pending_network_output_count();
            if pending != 0 {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::PendingNetworkOutput(pending),
                ));
            }
            return Ok(QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
            });
        }
        let mut observed_event_count = 0usize;
        loop {
            check_operational_signals(context)?;
            let outcome = lifecycle
                .drive_quantum(QuantumRequest {
                    configuration: configuration.clone(),
                    control: Vec::new(),
                })
                .map_err(classify_scheduler_error)?;
            if outcome.configuration.def != scenario {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::ScenarioMismatch,
                ));
            }

            check_operational_signals(context)?;

            let stop = match lifecycle.terminal_verdict_for_stop() {
                Some(QuantumTerminalVerdict::Passed) => Some(ModeledStop::TerminalPassed),
                Some(QuantumTerminalVerdict::Failed(_)) => Some(ModeledStop::TerminalFailed),
                None => reached_requested_stop(
                    input.attempt().stop(),
                    &outcome,
                    observed_event_count,
                    &discoveries.discoveries,
                ),
            };
            observed_event_count = observed_event_count
                .checked_add(outcome.event_log_entries.len())
                .ok_or(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::LimitExceeded {
                        limit: "fresh-campaign-event-log-entry-count",
                    },
                ))?;
            configuration = append_quantum(
                &mut event_log,
                &mut event_log_bytes,
                &mut discoveries,
                &mut terminal_quiescence,
                &mut terminal_at,
                outcome,
            )?;
            let Some(stop) = stop else {
                continue;
            };

            let pending = lifecycle.pending_network_output_count();
            if pending != 0 {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuFreshModeledDriverError::PendingNetworkOutput(pending),
                ));
            }
            return Ok(QemuFreshPendingObservation {
                input: input.clone(),
                configuration,
                stop,
                event_log,
                event_log_bytes,
                discoveries: discoveries.discoveries,
                terminal_quiescence,
                terminal_at,
            });
        }
    }

    fn seal(
        &mut self,
        mut pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        append_event_entries(
            &mut pending.event_log,
            &mut pending.event_log_bytes,
            final_events,
        )
        .map_err(AttemptWorkerFailure::Terminal)?;
        build_observation_candidate(pending)
            .map(AttemptExecutionProduct::observation)
            .map_err(AttemptWorkerFailure::Terminal)
    }
}

fn check_operational_signals(
    context: &AttemptExecutionContext,
) -> Result<(), AttemptWorkerFailure<QemuFreshModeledDriverError>> {
    if context.cancellation().is_canceled() {
        return Err(AttemptWorkerFailure::Canceled(
            QemuFreshModeledDriverError::Canceled,
        ));
    }
    if context.checkpoint_request().is_requested() {
        return Err(AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::ExactCheckpointUnsupported,
        ));
    }
    Ok(())
}

fn classify_scheduler_error(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuFreshModeledDriverError> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuFreshModeledDriverError::Scheduler(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn append_quantum(
    event_log: &mut Vec<SchedulerEventLogEntry>,
    event_log_bytes: &mut usize,
    discoveries: &mut RetainedChoiceDiscoveries,
    terminal_quiescence: &mut Option<SchedulerQuiescence>,
    terminal_at: &mut VirtualTime,
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
        discoveries
            .insert(discovery)
            .map_err(AttemptWorkerFailure::Terminal)?;
    }
    *terminal_quiescence = scheduler_quiescence;
    *terminal_at = (*terminal_at).max(frontier);
    Ok(configuration)
}

fn append_event_entries(
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
struct RetainedChoiceDiscoveries {
    discoveries: BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    representatives: BTreeMap<(SelectableId, ChoiceDomainId), ChoiceDiscovery>,
    charged_records: BTreeSet<ContentId>,
    charged_bytes: usize,
}

impl RetainedChoiceDiscoveries {
    fn insert(
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

fn reached_requested_stop(
    requested: &StopCondition,
    outcome: &QuantumOutcome,
    observed_event_count: usize,
    discoveries: &BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
) -> Option<ModeledStop> {
    let reached = match requested {
        StopCondition::NextChoice => {
            !discoveries.is_empty() || !outcome.discovered_choices.is_empty()
        }
        StopCondition::NamedBoundary(name) => outcome.event_log_entries.iter().any(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                    marker,
                    ..
                }) if marker.name == *name
            )
        }),
        StopCondition::VirtualTimeNanoseconds(deadline) => outcome.frontier.ticks >= *deadline,
        StopCondition::EventCount(count) => observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .and_then(|events| u64::try_from(events).ok())
            .is_some_and(|events| events >= *count),
        StopCondition::Terminal => false,
    };
    reached.then(|| ModeledStop::Reached(requested.clone()))
}

fn build_observation_candidate(
    pending: QemuFreshPendingObservation,
) -> Result<ObservationCandidate, QemuFreshModeledDriverError> {
    let assertion_count = pending
        .input
        .scenario()
        .properties()
        .assertions()
        .len()
        .max(1);
    let assertion_visits = pending.event_log.len().checked_mul(assertion_count).ok_or(
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-assertion-event-visits",
        },
    )?;
    if assertion_visits > MAX_QEMU_CAMPAIGN_ASSERTION_EVENT_VISITS {
        return Err(QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-assertion-event-visits",
        });
    }

    let mut checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(pending.input.scenario().world());
    if let Some(quiescence) = pending.terminal_quiescence.clone() {
        checker = checker.with_terminal_scheduler_quiescence(quiescence);
    }
    let report = checker.check_run(pending.input.scenario().properties(), &pending.event_log)?;
    let properties = property_verdicts(&report)?;
    let measurements = campaign_measurements(&pending)?;
    let stop = stop_outcome(pending.stop, &report);

    let scenario_artifact = encode_crucible_scenario_artifact(pending.input.scenario())?;
    if scenario_artifact.id()? != pending.input.lineage().scenario_content()
        || scenario_artifact.scenario() != pending.input.lineage().scenario()
    {
        return Err(QemuFreshModeledDriverError::ScenarioMismatch);
    }
    let child = encode_crucible_configuration_artifact(
        &scenario_artifact,
        &pending.configuration.schedule,
    )?;
    let coverage = coverage_projection(&pending.event_log)?;
    let discovered_choices = pending.discoveries.into_values().collect::<Vec<_>>();
    let discovered_ids = discovered_choices
        .iter()
        .map(|discovery| discovery.opportunity().id())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let observation = Observation::new(
        pending.input.attempt().id()?,
        child.configuration(),
        child.id()?,
        pending.input.path().id()?,
        stop,
        measurements.id()?,
        properties.id()?,
        coverage.id()?,
        discovered_ids,
    )?;
    ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        discovered_choices,
        observation,
    )
    .map_err(Into::into)
}

fn campaign_measurements(
    pending: &QemuFreshPendingObservation,
) -> Result<crucible_campaign::MeasurementSet, QemuFreshModeledDriverError> {
    let definitions = pending.input.scenario().measurements();
    let mut samples = normalize_guest_measurements(definitions, &pending.event_log)?;
    append_model_measurement_samples(definitions, &pending.event_log, &mut samples)
        .map_err(CrucibleMeasurementError::from)
        .map_err(QemuFreshModeledDriverError::Measurements)?;
    let mut node_icounts = BTreeMap::new();
    for entry in &pending.event_log {
        if let Some(node) = &entry.time().icount.node {
            node_icounts
                .entry(node.clone())
                .and_modify(|value: &mut crucible::Icount| {
                    *value = (*value).max(entry.time().icount.icount);
                })
                .or_insert(entry.time().icount.icount);
        }
    }
    let terminal = MeasurementTerminalState {
        scenario_ready_at: pending
            .event_log
            .iter()
            .find(|entry| entry.event_payload().kind() == "scenario_ready")
            .map(SchedulerEventLogEntry::at),
        at: pending
            .event_log
            .last()
            .map_or(pending.terminal_at, |entry| {
                pending.terminal_at.max(entry.at())
            }),
        node_icounts,
        scheduler_quiescent: pending
            .terminal_quiescence
            .as_ref()
            .is_some_and(SchedulerQuiescence::is_quiescent),
    };
    evaluate_crucible_measurement_set(
        definitions,
        &pending.event_log,
        samples,
        &terminal,
        BTreeSet::new(),
    )
    .map_err(QemuFreshModeledDriverError::Measurements)
}

fn normalize_guest_measurements(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<MeasurementRuntimeSample>, QemuFreshModeledDriverError> {
    let definitions_by_id = definitions
        .definitions()
        .iter()
        .map(|definition| (definition.id.clone(), definition))
        .collect::<BTreeMap<_, _>>();
    let mut open = BTreeSet::<(NodeId, MeasurementId, MeasurementInstanceKey)>::new();
    let mut samples = Vec::new();

    for entry in entries {
        match entry.payload() {
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMeasurement {
                node,
                event,
                ..
            }) => match event {
                GuestMeasurementEvent::Begin {
                    measurement,
                    instance,
                } => {
                    let (measurement, instance, definition) = guest_measurement_basis(
                        &definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if open.len() >= MAX_QEMU_CAMPAIGN_OPEN_MEASUREMENT_INSTANCES {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            "open measurement instance limit exceeded",
                        ));
                    }
                    if !open.insert((node.clone(), measurement, instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("measurement `{}` instance is already open", definition.id),
                        ));
                    }
                }
                GuestMeasurementEvent::Sample {
                    measurement,
                    instance,
                    metric,
                    value,
                } => {
                    let (measurement, instance, definition) = guest_measurement_basis(
                        &definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if !open.contains(&(node.clone(), measurement.clone(), instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("measurement `{measurement}` instance is not open"),
                        ));
                    }
                    let metric = MetricId::parse(metric.clone()).map_err(|error| {
                        guest_measurement_error(entry.sequence(), error.to_string())
                    })?;
                    let contract = definition
                        .metrics
                        .iter()
                        .find(|candidate| candidate.id == metric)
                        .ok_or_else(|| {
                            guest_measurement_error(
                                entry.sequence(),
                                format!(
                                    "measurement `{measurement}` does not declare metric `{metric}`"
                                ),
                            )
                        })?;
                    if contract.source != MetricSource::Guest {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("metric `{metric}` is not guest-sourced"),
                        ));
                    }
                    let value = normalize_guest_measurement_value(value)
                        .map_err(|reason| guest_measurement_error(entry.sequence(), reason))?;
                    if !guest_sample_matches_type(&value, contract) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("metric `{metric}` value does not match its declared type"),
                        ));
                    }
                    samples.push(MeasurementRuntimeSample::new(
                        entry.sequence(),
                        measurement,
                        metric,
                        value,
                    ));
                }
                GuestMeasurementEvent::End {
                    measurement,
                    instance,
                } => {
                    let (measurement, instance, _definition) = guest_measurement_basis(
                        &definitions_by_id,
                        node,
                        measurement,
                        instance,
                        entry.sequence(),
                    )?;
                    if !open.remove(&(node.clone(), measurement.clone(), instance)) {
                        return Err(guest_measurement_error(
                            entry.sequence(),
                            format!("measurement `{measurement}` instance is not open"),
                        ));
                    }
                }
            },
            SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestSemanticMarker {
                node,
                marker,
                instance,
                ..
            }) => {
                let instance =
                    MeasurementInstanceKey::parse(instance.clone()).map_err(|error| {
                        guest_measurement_error(entry.sequence(), error.to_string())
                    })?;
                if !definitions.definitions().iter().any(|definition| {
                    cohort_contains(&definition.cohort, node)
                        && (boundary_accepts_semantic_marker(&definition.begin, marker, &instance)
                            || boundary_accepts_semantic_marker(&definition.end, marker, &instance))
                }) {
                    return Err(guest_measurement_error(
                        entry.sequence(),
                        format!("semantic marker `{marker}` instance `{instance}` is not declared"),
                    ));
                }
            }
            _ => {}
        }
    }

    if let Some((_node, measurement, instance)) = open.into_iter().next() {
        return Err(guest_measurement_error(
            entries
                .last()
                .map_or(0, SchedulerEventLogEntry::sequence)
                .saturating_add(1),
            format!("measurement `{measurement}` instance `{instance}` was not ended"),
        ));
    }
    Ok(samples)
}

fn guest_measurement_basis<'a>(
    definitions: &'a BTreeMap<MeasurementId, &'a crucible::model::MeasurementDefinition>,
    node: &NodeId,
    measurement: &str,
    instance: &str,
    sequence: u64,
) -> Result<
    (
        MeasurementId,
        MeasurementInstanceKey,
        &'a crucible::model::MeasurementDefinition,
    ),
    QemuFreshModeledDriverError,
> {
    let measurement = MeasurementId::parse(measurement.to_owned())
        .map_err(|error| guest_measurement_error(sequence, error.to_string()))?;
    let instance = MeasurementInstanceKey::parse(instance.to_owned())
        .map_err(|error| guest_measurement_error(sequence, error.to_string()))?;
    let definition = definitions.get(&measurement).copied().ok_or_else(|| {
        guest_measurement_error(
            sequence,
            format!("measurement `{measurement}` is not declared"),
        )
    })?;
    if !cohort_contains(&definition.cohort, node) {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "node `{}` is outside measurement `{measurement}` cohort",
                node.name
            ),
        ));
    }
    let expected_instance = guest_measurement_instance(definition, sequence)?;
    if &instance != expected_instance {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "measurement `{measurement}` requires instance `{expected_instance}`, got `{instance}`"
            ),
        ));
    }
    Ok((measurement, instance, definition))
}

fn guest_measurement_instance(
    definition: &crucible::model::MeasurementDefinition,
    sequence: u64,
) -> Result<&MeasurementInstanceKey, QemuFreshModeledDriverError> {
    let mut instances = BTreeSet::new();
    collect_boundary_instances(&definition.begin, &mut instances);
    collect_boundary_instances(&definition.end, &mut instances);
    let mut instances = instances.into_iter();
    let Some(instance) = instances.next() else {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "guest-sourced measurement `{}` does not declare an exact marker instance",
                definition.id
            ),
        ));
    };
    if instances.next().is_some() {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "guest-sourced measurement `{}` declares conflicting marker instances",
                definition.id
            ),
        ));
    }
    Ok(instance)
}

fn collect_boundary_instances<'a>(
    selector: &'a BoundarySelector,
    instances: &mut BTreeSet<&'a MeasurementInstanceKey>,
) {
    match selector {
        BoundarySelector::GuestMarker {
            instance: Some(instance),
            ..
        } => {
            instances.insert(instance);
        }
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => {
            for selector in selectors {
                collect_boundary_instances(selector, instances);
            }
        }
        _ => {}
    }
}

fn cohort_contains(cohort: &CohortPolicy, node: &NodeId) -> bool {
    match cohort {
        CohortPolicy::All(nodes) | CohortPolicy::Any(nodes) => nodes.binary_search(node).is_ok(),
        CohortPolicy::Quorum { nodes, .. } => nodes.binary_search(node).is_ok(),
    }
}

fn normalize_guest_measurement_value(
    value: &GuestMeasurementValue,
) -> Result<MeasurementSampleValue, String> {
    match value {
        GuestMeasurementValue::Signed(value) => Ok(MeasurementSampleValue::Signed(*value)),
        GuestMeasurementValue::Unsigned(value) => Ok(MeasurementSampleValue::Unsigned(*value)),
        GuestMeasurementValue::Rational(value) => {
            let reduced = ReducedRational::new(value.negative, value.numerator, value.denominator)
                .map_err(|error| error.to_string())?;
            if reduced.is_negative() != value.negative
                || reduced.numerator() != value.numerator
                || reduced.denominator() != value.denominator
            {
                return Err(String::from(
                    "rational sample is not canonical reduced form",
                ));
            }
            Ok(MeasurementSampleValue::Rational(reduced))
        }
        GuestMeasurementValue::Boolean(value) => Ok(MeasurementSampleValue::Boolean(*value)),
        GuestMeasurementValue::Enumerated(value) => {
            Ok(MeasurementSampleValue::Enumerated(value.clone()))
        }
        GuestMeasurementValue::SignedVector(value) => {
            Ok(MeasurementSampleValue::SignedVector(value.clone()))
        }
        GuestMeasurementValue::UnsignedVector(value) => {
            Ok(MeasurementSampleValue::UnsignedVector(value.clone()))
        }
    }
}

fn guest_sample_matches_type(value: &MeasurementSampleValue, metric: &MetricDefinition) -> bool {
    match (value, &metric.value_type) {
        (MeasurementSampleValue::Signed(_), MetricValueType::SignedInteger)
        | (MeasurementSampleValue::Unsigned(_), MetricValueType::UnsignedInteger)
        | (MeasurementSampleValue::Rational(_), MetricValueType::ReducedRational)
        | (MeasurementSampleValue::Boolean(_), MetricValueType::Boolean) => true,
        (MeasurementSampleValue::Enumerated(value), MetricValueType::Enumerated { variants }) => {
            variants.binary_search(value).is_ok()
        }
        (
            MeasurementSampleValue::SignedVector(values),
            MetricValueType::IntegerVector {
                signed: true,
                maximum_elements,
            },
        ) => values.len() <= *maximum_elements as usize,
        (
            MeasurementSampleValue::UnsignedVector(values),
            MetricValueType::IntegerVector {
                signed: false,
                maximum_elements,
            },
        ) => values.len() <= *maximum_elements as usize,
        _ => false,
    }
}

fn boundary_accepts_semantic_marker(
    selector: &BoundarySelector,
    marker: &str,
    instance: &MeasurementInstanceKey,
) -> bool {
    match selector {
        BoundarySelector::GuestMarker {
            marker: expected,
            instance: Some(expected_instance),
        } => expected.name == marker && expected_instance == instance,
        BoundarySelector::All { selectors } | BoundarySelector::Any { selectors } => selectors
            .iter()
            .any(|selector| boundary_accepts_semantic_marker(selector, marker, instance)),
        _ => false,
    }
}

fn guest_measurement_error(
    sequence: u64,
    reason: impl Into<String>,
) -> QemuFreshModeledDriverError {
    QemuFreshModeledDriverError::GuestMeasurementProtocol {
        sequence,
        reason: reason.into(),
    }
}

fn property_verdicts(
    report: &crucible::HostAssertionReport,
) -> Result<PropertyVerdictSet, QemuFreshModeledDriverError> {
    let mut properties = BTreeMap::new();
    for outcome in report.outcomes() {
        let verdict = match outcome.kind {
            HostAssertionOutcomeKind::Passed | HostAssertionOutcomeKind::Satisfied => {
                PropertyVerdict::Passed
            }
            HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail => {
                PropertyVerdict::Failed
            }
            HostAssertionOutcomeKind::Warning
            | HostAssertionOutcomeKind::NeverEvaluated
            | HostAssertionOutcomeKind::NeverTriggered
            | HostAssertionOutcomeKind::NeverReachedWarn => PropertyVerdict::Inconclusive,
        };
        let evidence = PropertyEvidence::new(verdict, BTreeSet::new())?;
        if properties
            .insert(outcome.assertion.name.clone(), evidence)
            .is_some()
        {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-duplicate-property-outcome",
            });
        }
    }
    PropertyVerdictSet::new(properties).map_err(Into::into)
}

fn stop_outcome(stop: ModeledStop, report: &crucible::HostAssertionReport) -> StopOutcome {
    if let Some(failure) = report.verdict().failures().first() {
        return StopOutcome::AssertionFailure(failure.assertion.name.clone());
    }
    match stop {
        ModeledStop::Reached(stop) => StopOutcome::Reached(stop),
        ModeledStop::TerminalPassed => StopOutcome::TerminalSuccess,
        ModeledStop::TerminalFailed => {
            StopOutcome::GuestCrash(String::from("scenario-trigger-failure"))
        }
    }
}

fn coverage_projection(
    event_log: &[SchedulerEventLogEntry],
) -> Result<CoverageProjection, QemuFreshModeledDriverError> {
    let projection = crucible::event_log_coverage_projection(event_log);
    let identities = projection
        .entries()
        .iter()
        .map(|entry| coverage_identity(&entry.observation))
        .collect();
    CoverageProjection::new(identities, BTreeSet::new()).map_err(Into::into)
}

fn coverage_identity(observation: &EventLogCoverageObservation) -> CampaignHash {
    CampaignHash::from_bytes(observation.content_hash().bytes)
}

#[cfg(test)]
mod tests;
