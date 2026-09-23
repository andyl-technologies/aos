//! Canonical replay evidence for retained Crucible measurement evaluations.
//!
//! A Crucible measurement evaluation payload using schema v2 contains the
//! compact derived evaluation. This module owns its independently
//! content-addressed raw input leaf:
//!
//! ```text
//! canonical CBOR map:
//!   schema_version: 2
//!   scenario: <scenario definition identity>
//!   configuration: <configuration identity>
//!   definitions: <measurement-definition identity>
//!   entries: [<complete SchedulerEventLogEntry sequence>]
//!   terminal:
//!     scenario_ready_at: <optional virtual time>
//!     at: <terminal virtual time>
//!     node_icounts: {<node>: <retired instructions>}
//!     scheduler_quiescent: <boolean>
//!   stop: <campaign stop or exact observation-stop boundary>
//! ```
//!
//! Decoding is strict: bytes are size-bounded before allocation, the CBOR must
//! be the unique serializer output, scheduler entries must be dense and
//! authenticated, and terminal coordinates must cover the retained log.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use crucible::model::{
    BoundarySelector, CohortPolicy, MAX_MEASUREMENT_EVENT_ENTRIES,
    MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES, MAX_MEASUREMENT_RUNTIME_SAMPLES,
    MAX_MEASUREMENT_TERMINAL_NODES, MeasurementDefinition, MeasurementDefinitions,
    MeasurementEvaluation, MeasurementId, MeasurementInstanceKey, MeasurementRuntimeSample,
    MeasurementSampleValue, MeasurementTerminalState, MetricDefinition, MetricId, MetricSource,
    MetricValueType, ReducedRational, append_model_measurement_samples, evaluate_measurements,
    validate_measurement_event_log,
};
use crucible::{
    AssertionPhase, EventLogOffset, EventSource, GuestMeasurementEvent, GuestMeasurementValue,
    Icount, NodeId, ObservableEventPayload, SchedulerEventLogEntry, SchedulerEventLogPayload,
    VirtualTime,
};
use crucible_campaign::{
    CampaignHash, ConfigurationId, FindingAssertionFailureBoundary, MeasurementSet,
    ObservationCondition, ObservationStopProof, ObservationStopSatisfaction, ScenarioDefId,
};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_protocol::{
    WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES, WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::{CrucibleMeasurementError, campaign_hash};

mod guest;
mod wire;

use guest::normalize_guest_measurements;
#[cfg(test)]
use guest::validate_guest_measurement_value;
use wire::{EvidenceWireRef, EvidenceWireV2, enforce_evidence_bytes, measure_canonical_bytes};

/// Payload schema requiring retained raw replay evidence.
pub const CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2: u32 = 2;

/// Content-object schema retaining an explicit campaign or observation stop.
pub const CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2: u32 = 2;

/// Maximum canonical bytes retained by one measurement replay-evidence leaf.
///
/// This matches the producer's aggregate event-material budget. Callers with a
/// smaller attempt or journal budget can select that lower ceiling through
/// [`CrucibleMeasurementReplayEvidence::canonical_bytes_with_limit`].
pub const MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum simultaneously open guest measurement instances during projection.
const MAX_OPEN_GUEST_MEASUREMENT_INSTANCES: usize = 65_536;

/// Raw, replayable inputs for one retained measurement evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleMeasurementReplayEvidence {
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: Vec<SchedulerEventLogEntry>,
    terminal: MeasurementTerminalState,
    stop: CrucibleMeasurementStopEvidence,
}

/// Exact stop shape retained with one measurement evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "boundary", rename_all = "snake_case")]
pub enum CrucibleMeasurementStopEvidence {
    /// The run ended at its requested or modeled campaign stop boundary.
    Campaign,
    /// The run ended at an authenticated post-quantum observation boundary.
    Observation(CrucibleObservationBoundaryEvidence),
}

/// Independently retained scheduler coordinates for an observation stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrucibleObservationBoundaryEvidence {
    frontier: VirtualTime,
    quantum_start_completed_quanta: u64,
    completed_quanta: u64,
    quantum_start_events: u64,
    event_log_offset: EventLogOffset,
    scheduler_quiescent: bool,
}

impl CrucibleObservationBoundaryEvidence {
    /// Builds an exact boundary captured from one completed scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns an error when the quantum coordinate did not advance exactly
    /// once or the offset precedes the pre-quantum event count.
    pub fn new(
        frontier: VirtualTime,
        quantum_start_completed_quanta: u64,
        completed_quanta: u64,
        quantum_start_events: u64,
        event_log_offset: EventLogOffset,
        scheduler_quiescent: bool,
    ) -> Result<Self, CrucibleMeasurementError> {
        if quantum_start_completed_quanta.checked_add(1) != Some(completed_quanta)
            || event_log_offset.events < quantum_start_events
        {
            return Err(CrucibleMeasurementError::EvidenceBindingMismatch {
                binding: "observation-boundary",
            });
        }
        Ok(Self {
            frontier,
            quantum_start_completed_quanta,
            completed_quanta,
            quantum_start_events,
            event_log_offset,
            scheduler_quiescent,
        })
    }

    /// Returns the exact frontier reported by the matching quantum.
    #[must_use]
    pub const fn frontier(self) -> VirtualTime {
        self.frontier
    }

    /// Returns the completed-quantum coordinate before the matching drive.
    #[must_use]
    pub const fn quantum_start_completed_quanta(self) -> u64 {
        self.quantum_start_completed_quanta
    }

    /// Returns the completed-quantum coordinate after the matching drive.
    #[must_use]
    pub const fn completed_quanta(self) -> u64 {
        self.completed_quanta
    }

    /// Returns the retained event count before the matching drive.
    #[must_use]
    pub const fn quantum_start_events(self) -> u64 {
        self.quantum_start_events
    }

    /// Returns the exact event-log offset reported by the matching quantum.
    #[must_use]
    pub const fn event_log_offset(self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns whether the matching quantum reported scheduler-owned quiescence.
    #[must_use]
    pub const fn scheduler_quiescent(self) -> bool {
        self.scheduler_quiescent
    }
}

impl CrucibleMeasurementReplayEvidence {
    /// Returns the exact scenario definition identity.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the exact scheduled configuration identity.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the bound measurement-definition identity.
    #[must_use]
    pub const fn definitions(&self) -> CampaignHash {
        self.definitions
    }

    /// Returns the complete scheduler event-log sequence.
    #[must_use]
    pub fn entries(&self) -> &[SchedulerEventLogEntry] {
        &self.entries
    }

    /// Returns the exact terminal evaluation state.
    #[must_use]
    pub const fn terminal(&self) -> &MeasurementTerminalState {
        &self.terminal
    }

    /// Returns the exact stop shape retained by this evidence.
    #[must_use]
    pub const fn stop(&self) -> CrucibleMeasurementStopEvidence {
        self.stop
    }

    /// Verifies an observation-stop proof against this retained raw boundary.
    ///
    /// The check binds the proof to the exact configuration, quantum counters,
    /// event-log offset and prefix, scheduler quiescence state, and assertion
    /// transition captured by the executor. It does not infer a later matching
    /// observation from the replay schedule.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] when any proof field differs from
    /// the retained v2 execution evidence.
    pub fn verify_observation_stop_proof(
        &self,
        proof: &ObservationStopProof,
    ) -> Result<(), CrucibleMeasurementError> {
        let mismatch = |binding| CrucibleMeasurementError::EvidenceBindingMismatch { binding };
        if self.configuration != proof.child() {
            return Err(mismatch("observation-stop-configuration"));
        }

        let boundary = proof.boundary();
        let event_log = proof.event_log();
        let CrucibleMeasurementStopEvidence::Observation(retained_boundary) = self.stop else {
            return Err(mismatch("observation-stop-execution-boundary"));
        };
        let retained_offset = retained_boundary.event_log_offset();
        if retained_boundary.frontier().ticks != boundary.frontier_nanoseconds()
            || retained_boundary.quantum_start_completed_quanta()
                != boundary.start_completed_quanta()
            || retained_boundary.completed_quanta() != boundary.completed_quanta()
            || retained_boundary.quantum_start_events() != boundary.start_events()
            || CampaignHash::from_bytes(retained_offset.prefix.bytes) != event_log.prefix()
            || retained_offset
                .appended_segment
                .map(|hash| CampaignHash::from_bytes(hash.bytes))
                != event_log.appended_segment()
            || retained_offset.bytes != event_log.bytes()
            || retained_offset.events != event_log.events()
        {
            return Err(mismatch("observation-stop-execution-boundary"));
        }

        let event_count = usize::try_from(event_log.events())
            .map_err(|_| mismatch("observation-stop-event-count"))?;
        let quantum_start = usize::try_from(boundary.start_events())
            .map_err(|_| mismatch("observation-stop-quantum-event-count"))?;
        let prefix = self
            .entries
            .get(..event_count)
            .ok_or_else(|| mismatch("observation-stop-event-prefix"))?;
        if quantum_start > event_count
            || observation_event_prefix_digest(prefix) != event_log.digest()
            || prefix
                .iter()
                .any(|entry| entry.at().ticks > boundary.frontier_nanoseconds())
            || self.terminal.at.ticks < boundary.frontier_nanoseconds()
        {
            return Err(mismatch("observation-stop-event-prefix"));
        }

        match proof.condition() {
            ObservationCondition::SchedulerQuiescent => {
                if proof.satisfaction() != ObservationStopSatisfaction::SchedulerQuiescent
                    || proof.assertion_witness().is_some()
                    || !retained_boundary.scheduler_quiescent()
                {
                    return Err(mismatch("scheduler-quiescent-observation-stop"));
                }
            }
            ObservationCondition::AssertionViolationTransition(assertion) => {
                verify_assertion_observation_stop(proof, prefix, quantum_start, Some(assertion))?;
            }
            ObservationCondition::AnyAssertionViolationTransition => {
                verify_assertion_observation_stop(proof, prefix, quantum_start, None)?;
            }
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
                let expected_satisfaction = if retained_boundary.scheduler_quiescent() {
                    ObservationStopSatisfaction::SchedulerQuiescent
                } else if boundary.completed_quanta() >= *execution_quanta {
                    ObservationStopSatisfaction::ExecutionQuanta
                } else {
                    return Err(mismatch("compound-observation-stop"));
                };
                if proof.satisfaction() != expected_satisfaction
                    || proof.assertion_witness().is_some()
                {
                    return Err(mismatch("compound-observation-stop"));
                }
            }
        }

        Ok(())
    }

    /// Returns the exact content-object schema used by this evidence leaf.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2
    }

    /// Replays the raw leaf against its exact semantic bindings.
    ///
    /// Guest and model samples are rederived from the retained scheduler
    /// entries on every call; no caller-supplied normalized sample is trusted.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] for a scenario, configuration, or
    /// definition mismatch, invalid guest protocol input, invalid model sample
    /// source, unauthenticated log, invalid terminal state, or evaluation bound.
    pub fn replay(
        &self,
        scenario: ScenarioDefId,
        configuration: ConfigurationId,
        definitions: &MeasurementDefinitions,
    ) -> Result<MeasurementEvaluation, CrucibleMeasurementError> {
        if self.scenario != scenario {
            return Err(CrucibleMeasurementError::EvidenceBindingMismatch {
                binding: "scenario",
            });
        }
        if self.configuration != configuration {
            return Err(CrucibleMeasurementError::EvidenceBindingMismatch {
                binding: "configuration",
            });
        }
        if self.definitions != campaign_hash(definitions.content_hash()) {
            return Err(CrucibleMeasurementError::EvidenceBindingMismatch {
                binding: "measurement-definitions",
            });
        }

        let samples = derive_crucible_measurement_samples(definitions, &self.entries)?;
        evaluate_measurements(definitions, &self.entries, samples, &self.terminal)
            .map_err(Into::into)
    }

    /// Returns strict canonical replay-evidence bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] if CBOR serialization fails or the
    /// encoded leaf exceeds its format ceiling.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CrucibleMeasurementError> {
        self.canonical_bytes_with_limit(MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES)
    }

    /// Returns canonical bytes under a caller-selected operational ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] if CBOR serialization fails or the
    /// encoded leaf exceeds the smaller of `maximum_bytes` and the format
    /// ceiling.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, CrucibleMeasurementError> {
        let encoded_length = measure_canonical_bytes(self, maximum_bytes)?;
        let mut bytes = Vec::with_capacity(encoded_length);
        ciborium::ser::into_writer(&EvidenceWireRef::from(self), &mut bytes).map_err(|error| {
            CrucibleMeasurementError::EvidenceEncoding {
                reason: error.to_string(),
            }
        })?;
        debug_assert_eq!(bytes.len(), encoded_length);
        Ok(bytes)
    }

    /// Decodes and validates strict canonical replay-evidence bytes.
    ///
    /// Semantic guest and model projection is checked later by [`Self::replay`]
    /// because decoding alone does not possess the bound scenario definitions.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] for oversized, malformed,
    /// unsupported, noncanonical, unauthenticated, non-dense, or terminally
    /// inconsistent input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CrucibleMeasurementError> {
        Self::from_canonical_bytes_with_limit(bytes, MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES)
    }

    /// Decodes strict bytes under a caller-selected operational ceiling.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_canonical_bytes`], and rejects
    /// input above the smaller of `maximum_bytes` and the format ceiling.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, CrucibleMeasurementError> {
        enforce_evidence_bytes(bytes.len(), maximum_bytes)?;
        let wire: EvidenceWireV2 = ciborium::de::from_reader(bytes).map_err(|error| {
            CrucibleMeasurementError::EvidenceEncoding {
                reason: error.to_string(),
            }
        })?;
        if wire.schema_version != CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2 {
            return Err(CrucibleMeasurementError::UnsupportedEvidenceSchema {
                actual: wire.schema_version,
                expected: CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2,
            });
        }
        if let CrucibleMeasurementStopEvidence::Observation(boundary) = wire.stop {
            CrucibleObservationBoundaryEvidence::new(
                boundary.frontier,
                boundary.quantum_start_completed_quanta,
                boundary.completed_quanta,
                boundary.quantum_start_events,
                boundary.event_log_offset,
                boundary.scheduler_quiescent,
            )?;
        }
        let value = Self::from(wire);

        // Empty definitions exercise the shared log and terminal validators
        // without claiming that semantic sample projection has run.
        evaluate_measurements(
            &MeasurementDefinitions::empty(),
            &value.entries,
            Vec::new(),
            &value.terminal,
        )?;
        if value.canonical_bytes_with_limit(maximum_bytes)? != bytes {
            return Err(CrucibleMeasurementError::NonCanonicalEvidence);
        }
        Ok(value)
    }

    /// Returns the content identity used by measurement-set evidence edges.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] when canonical encoding fails or
    /// exceeds the evidence format ceiling.
    pub fn id(&self) -> Result<ContentId, CrucibleMeasurementError> {
        let bytes = self.canonical_bytes()?;
        Ok(ContentId::for_bytes(
            ObjectKind::Trace,
            self.schema_version(),
            &bytes,
        ))
    }
}

fn verify_assertion_observation_stop(
    proof: &ObservationStopProof,
    prefix: &[SchedulerEventLogEntry],
    quantum_start: usize,
    expected_assertion: Option<&String>,
) -> Result<(), CrucibleMeasurementError> {
    let mismatch = || CrucibleMeasurementError::EvidenceBindingMismatch {
        binding: "assertion-observation-stop-witness",
    };
    if proof.satisfaction() != ObservationStopSatisfaction::AssertionViolationTransition {
        return Err(mismatch());
    }
    let witness = proof.assertion_witness().ok_or_else(mismatch)?;
    let entry = prefix
        .get(quantum_start..)
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.sequence() == witness.sequence())
        })
        .ok_or_else(mismatch)?;
    if CampaignHash::from_bytes(entry.content_hash().bytes) != witness.entry()
        || !matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(
                ObservableEventPayload::AssertionStateChanged { name, state }
            ) if name.name == witness.assertion()
                && expected_assertion.is_none_or(|expected| name.name == *expected)
                && *state == crucible::AssertionPhase::Violated
        )
    {
        return Err(mismatch());
    }
    Ok(())
}

pub(crate) fn observation_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> CampaignHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.sequence().to_be_bytes());
        hasher.update(&entry.content_hash().bytes);
    }
    CampaignHash::from_bytes(*hasher.finalize().as_bytes())
}

pub(crate) fn verified_assertion_transition<'a>(
    entries: &'a [SchedulerEventLogEntry],
    quantum_start_events: u64,
    property: &str,
) -> Option<&'a SchedulerEventLogEntry> {
    if entries
        .iter()
        .enumerate()
        .any(|(index, entry)| entry.sequence() != index as u64 || !entry.has_valid_content_hash())
    {
        return None;
    }
    let mut transitions = entries
        .get(usize::try_from(quantum_start_events).ok()?..)?
        .iter()
        .filter(|entry| {
            matches!(entry.source(), EventSource::Engine)
                && matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::AssertionStateChanged { name, state }
                    ) if name.name == property && *state == AssertionPhase::Violated
                )
        });
    let transition = transitions.next()?;
    transitions.next().is_none().then_some(transition)
}

pub(crate) fn verify_assertion_failure_boundary(
    leaf: &CrucibleMeasurementReplayEvidence,
    boundary: &FindingAssertionFailureBoundary,
) -> bool {
    let entries = leaf.entries();
    let Some(transition) = verified_assertion_transition(
        entries,
        boundary.quantum_start_events(),
        boundary.property(),
    ) else {
        return false;
    };
    leaf.id().ok() == Some(boundary.trace())
        && leaf.stop() == CrucibleMeasurementStopEvidence::Campaign
        && entries.len() as u64 == boundary.terminal_events()
        && observation_event_prefix_digest(entries) == boundary.prefix_digest()
        && transition.sequence() == boundary.transition_sequence()
        && CampaignHash::from_bytes(transition.content_hash().bytes) == boundary.transition_hash()
}

/// A derived measurement set paired with the raw leaf required to verify it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleMeasurementPublication {
    measurement_set: MeasurementSet,
    evidence: CrucibleMeasurementReplayEvidence,
    evidence_bytes: Vec<u8>,
}

impl CrucibleMeasurementPublication {
    /// Returns the derived campaign measurement set.
    #[must_use]
    pub const fn measurement_set(&self) -> &MeasurementSet {
        &self.measurement_set
    }

    /// Returns the raw replay-evidence leaf.
    #[must_use]
    pub const fn evidence(&self) -> &CrucibleMeasurementReplayEvidence {
        &self.evidence
    }

    /// Returns the canonical bytes to publish under the trace identity.
    #[must_use]
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }

    /// Splits the publication into its child trace bytes and parent record.
    #[must_use]
    pub fn into_parts(self) -> (CrucibleMeasurementReplayEvidence, Vec<u8>, MeasurementSet) {
        (self.evidence, self.evidence_bytes, self.measurement_set)
    }
}

/// Derives all guest and model measurement samples from retained raw entries.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for an invalid guest measurement or
/// semantic-marker protocol message, an invalid model sample source, an
/// unauthenticated or non-dense log, or a deterministic projection bound.
pub fn derive_crucible_measurement_samples(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<MeasurementRuntimeSample>, CrucibleMeasurementError> {
    validate_measurement_event_log(entries)?;
    let mut samples = normalize_guest_measurements(definitions, entries)?;
    append_model_measurement_samples(definitions, entries, &mut samples)?;
    Ok(samples)
}

/// Evaluates one run and builds its child-first measurement publication pair.
///
/// The resulting measurement set owns exactly the raw measurement trace. Other
/// audit evidence belongs to its explicit observation or finding owner.
/// `maximum_evidence_bytes` is the caller-selected minimum of every active
/// model, attempt, prepared-result, and journal ceiling.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for invalid replay inputs, semantic
/// binding mismatches, evaluation failures, canonical trace limits, or
/// campaign measurement-set limits.
pub fn evaluate_crucible_measurement_publication(
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
    entries: Vec<SchedulerEventLogEntry>,
    terminal: MeasurementTerminalState,
    maximum_evidence_bytes: usize,
) -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
    let evidence = CrucibleMeasurementReplayEvidence {
        scenario,
        configuration,
        definitions: campaign_hash(definitions.content_hash()),
        entries,
        terminal,
        stop: CrucibleMeasurementStopEvidence::Campaign,
    };
    evaluate_crucible_measurement_evidence(evidence, definitions, maximum_evidence_bytes)
}

/// Evaluates one run and retains its exact observation-stop boundary.
///
/// # Errors
///
/// Returns the same failures as the ordinary measurement publication path.
pub fn evaluate_crucible_observation_measurement_publication(
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
    entries: Vec<SchedulerEventLogEntry>,
    terminal: MeasurementTerminalState,
    observation_boundary: CrucibleObservationBoundaryEvidence,
    maximum_evidence_bytes: usize,
) -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
    let evidence = CrucibleMeasurementReplayEvidence {
        scenario,
        configuration,
        definitions: campaign_hash(definitions.content_hash()),
        entries,
        terminal,
        stop: CrucibleMeasurementStopEvidence::Observation(observation_boundary),
    };
    evaluate_crucible_measurement_evidence(evidence, definitions, maximum_evidence_bytes)
}

fn evaluate_crucible_measurement_evidence(
    evidence: CrucibleMeasurementReplayEvidence,
    definitions: &MeasurementDefinitions,
    maximum_evidence_bytes: usize,
) -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
    let evidence_bytes = evidence.canonical_bytes_with_limit(maximum_evidence_bytes)?;
    let evaluation = evidence.replay(evidence.scenario, evidence.configuration, definitions)?;
    let evidence_id = ContentId::for_bytes(
        ObjectKind::Trace,
        evidence.schema_version(),
        &evidence_bytes,
    );
    let measurement_set = MeasurementSet::from_evaluation(
        campaign_hash(evaluation.definitions()),
        CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2,
        campaign_hash(evaluation.content_hash()),
        evaluation.canonical_bytes().to_vec(),
        BTreeSet::from([evidence_id]),
    )?;
    Ok(CrucibleMeasurementPublication {
        measurement_set,
        evidence,
        evidence_bytes,
    })
}

/// Recomputes a retained measurement set solely from its raw evidence leaf.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for an unsupported payload,
/// non-singleton evidence set, binding mismatch, invalid raw input, or disagreement
/// between replay output and the retained derived evaluation.
pub fn verify_crucible_measurement_publication(
    measurement_set: &MeasurementSet,
    evidence: &CrucibleMeasurementReplayEvidence,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
) -> Result<MeasurementEvaluation, CrucibleMeasurementError> {
    let retained = measurement_set.evaluation();
    if retained.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2 {
        return Err(CrucibleMeasurementError::UnsupportedPayloadSchema {
            actual: retained.payload_schema(),
            expected: CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2,
        });
    }
    let evidence_id = evidence.id()?;
    if retained.evidence() != &BTreeSet::from([evidence_id]) {
        return Err(CrucibleMeasurementError::ReplayEvidenceSetMismatch {
            expected: evidence_id,
            actual_count: retained.evidence().len(),
        });
    }

    let evaluation = evidence.replay(scenario, configuration, definitions)?;
    if retained.definitions() != campaign_hash(evaluation.definitions()) {
        return Err(CrucibleMeasurementError::DefinitionIdentityMismatch);
    }
    if retained.evaluation() != campaign_hash(evaluation.content_hash())
        || retained.payload() != evaluation.canonical_bytes()
    {
        return Err(CrucibleMeasurementError::EvaluationIdentityMismatch);
    }
    Ok(evaluation)
}

#[cfg(test)]
mod tests;
