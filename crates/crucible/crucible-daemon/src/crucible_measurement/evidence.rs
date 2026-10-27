//! Canonical replay evidence for retained Crucible measurement evaluations.
//!
//! A Crucible measurement evaluation payload using schema v2 contains the
//! compact derived evaluation. This module owns its independently
//! content-addressed raw input leaf. Version 3, the only version new attempts
//! publish, is a manifest that references the attempt log as separately
//! stored segment leaves (RFC-0020 section 15.7):
//!
//! ```text
//! canonical CBOR map:
//!   schema_version: 3
//!   scenario: <scenario definition identity>
//!   configuration: <configuration identity>
//!   definitions: <measurement-definition identity>
//!   log:
//!     entry_count: <entries in the attempt log>
//!     chain: <attempt-log chain hash after the last segment>
//!     segments: [{id, first_sequence, entry_count, encoded_bytes}, ...]
//!   terminal:
//!     scenario_ready_at: <optional virtual time>
//!     at: <terminal virtual time>
//!     node_icounts: {<node>: <retired instructions>}
//!     scheduler_quiescent: <boolean>
//!   stop: <campaign stop or exact observation-stop boundary>
//! ```
//!
//! Version 2 embeds `entries: [<complete SchedulerEventLogEntry sequence>]`
//! in place of `log`; it remains readable for retained findings.
//!
//! Decoding is strict: bytes are size-bounded before allocation, the CBOR must
//! be the unique serializer output, and a manifest must be a dense chain of
//! bounded segments. Entries are read through a segment source one segment at
//! a time, and every segment is authenticated before its entries are used.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use crucible_campaign::{
    CampaignHash, ConfigurationId, FindingAssertionFailureBoundary, MeasurementSet,
    ObservationCondition, ObservationStopProof, ObservationStopSatisfaction, ScenarioDefId,
};
use crucible_engine::model::{
    BoundarySelector, CohortPolicy, MAX_MEASUREMENT_EVENT_ENTRIES, MAX_MEASUREMENT_TERMINAL_NODES,
    MeasurementDefinition, MeasurementDefinitions, MeasurementEvaluation,
    MeasurementEvaluationError, MeasurementId, MeasurementInstanceKey, MeasurementReplay,
    MeasurementRuntimeSample, MeasurementSampleValue, MeasurementTerminalState, MetricDefinition,
    MetricId, MetricSource, MetricValueType, ModelSampleProjector, ReducedRational,
    append_model_measurement_samples, evaluate_measurements, validate_measurement_event_log,
};
use crucible_engine::{
    AssertionPhase, EventLogOffset, EventSource, GuestMeasurementEvent, GuestMeasurementValue,
    Icount, NodeId, ObservableEventPayload, SchedulerEventLogEntry, SchedulerEventLogPayload,
    VirtualTime,
};
use crucible_qemu_protocol::{
    WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES, WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS,
};
use crucible_store::content_store::{ContentId, ObjectKind};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::{CrucibleMeasurementError, campaign_hash};
use crate::attempt_event_log::{
    AttemptLogManifest, AttemptLogSegmentRef, AttemptLogSegmentSource,
    MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS,
};

mod assertion_boundary;
mod bundle;
mod guest;
mod wire;

pub(crate) use assertion_boundary::{
    AssertionTransitionScan, ObservationPrefixDigest, verify_assertion_failure_boundary,
};
#[cfg(test)]
pub(crate) use assertion_boundary::{
    observation_event_prefix_digest, verified_assertion_transition,
};

pub use bundle::CrucibleMeasurementEvidenceBundle;

#[cfg(test)]
use guest::validate_guest_measurement_value;
use guest::{GuestMeasurementNormalizer, normalize_guest_measurements};
use wire::{EvidenceWire, EvidenceWireRef, enforce_evidence_bytes, measure_canonical_bytes};

/// Payload schema carrying a folded evaluation and retained raw replay evidence.
///
/// Version 3 carries `crucible.model.measurement-evaluation.v3`, whose metrics
/// report a sample count and aggregate rather than every sample.
pub const CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3: u32 = 3;

/// Content-object schema embedding the complete log; read-only.
pub const CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2: u32 = 2;

/// Content-object schema referencing the attempt log as segment leaves.
pub const CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3: u32 = 3;

/// Maximum canonical bytes retained by one measurement replay-evidence leaf.
///
/// The bound applies to both versions. A version 3 manifest at its segment
/// limit encodes to well under a megabyte. Callers with a smaller attempt or
/// journal budget can select that lower ceiling through
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
    log: ReplayLog,
    terminal: MeasurementTerminalState,
    stop: CrucibleMeasurementStopEvidence,
}

/// Where a replay leaf keeps its scheduler entries.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ReplayLog {
    /// Version 2: the complete dense log, embedded in the leaf.
    Inline(Vec<SchedulerEventLogEntry>),
    /// Version 3: segment leaves referenced by a manifest.
    Segmented(AttemptLogManifest),
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

    /// Returns the number of scheduler entries in the retained log.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        match &self.log {
            ReplayLog::Inline(entries) => entries.len() as u64,
            ReplayLog::Segmented(manifest) => manifest.entry_count(),
        }
    }

    /// Returns the sealed log's manifest, or `None` for a version 2 leaf,
    /// which embeds its entries.
    #[must_use]
    pub fn log_manifest(&self) -> Option<&AttemptLogManifest> {
        match &self.log {
            ReplayLog::Inline(_) => None,
            ReplayLog::Segmented(manifest) => Some(manifest),
        }
    }

    /// Returns the log segments this leaf references, in order.
    ///
    /// Version 2 leaves embed their entries and reference no segment.
    #[must_use]
    pub fn segments(&self) -> &[AttemptLogSegmentRef] {
        match &self.log {
            ReplayLog::Inline(_) => &[],
            ReplayLog::Segmented(manifest) => manifest.segments(),
        }
    }

    /// Returns every content object a measurement set must own for this leaf.
    ///
    /// The set holds this leaf's identity and every referenced segment.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] when the leaf cannot be encoded.
    pub fn evidence_ids(&self) -> Result<BTreeSet<ContentId>, CrucibleMeasurementError> {
        let mut ids = BTreeSet::from([self.id()?]);
        ids.extend(self.segments().iter().map(|segment| segment.id));
        Ok(ids)
    }

    /// Visits the entries whose sequences fall in `range`, in order.
    ///
    /// Version 3 leaves read only the segments overlapping `range` from
    /// `source` and authenticate each before visiting its entries. Version 2
    /// leaves ignore `source`.
    ///
    /// # Errors
    ///
    /// Returns an error converted from the segment failure when a segment is
    /// absent or fails authentication, or the first error `visit` returns.
    pub fn try_for_each_entry_in<E>(
        &self,
        source: &dyn AttemptLogSegmentSource,
        range: std::ops::Range<u64>,
        mut visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<crate::attempt_event_log::AttemptEventLogError>,
    {
        match &self.log {
            ReplayLog::Inline(entries) => {
                for entry in entries {
                    if range.contains(&entry.sequence()) {
                        visit(entry)?;
                    }
                }
                Ok(())
            }
            ReplayLog::Segmented(manifest) => manifest.try_for_each_entry_in(source, range, visit),
        }
    }

    /// Visits every retained entry; see [`Self::try_for_each_entry_in`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_for_each_entry_in`].
    pub fn try_for_each_entry<E>(
        &self,
        source: &dyn AttemptLogSegmentSource,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<crate::attempt_event_log::AttemptEventLogError>,
    {
        self.try_for_each_entry_in(source, 0..u64::MAX, visit)
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
    /// Only the segments covering the proof's event prefix are read from
    /// `source`.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] when any proof field differs from
    /// the retained execution evidence, or a covering segment is absent or
    /// fails authentication.
    pub fn verify_observation_stop_proof(
        &self,
        source: &dyn AttemptLogSegmentSource,
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
        if retained_boundary.frontier().ticks != boundary.frontier_picoseconds()
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

        let event_count = event_log.events();
        let quantum_start = boundary.start_events();
        let frontier = boundary.frontier_picoseconds();
        if quantum_start > event_count
            || event_count > self.entry_count()
            || self.terminal.at.ticks < frontier
        {
            return Err(mismatch("observation-stop-event-prefix"));
        }

        // One pass over the proof's prefix computes its digest, checks every
        // entry against the frontier, and captures the witness entry.
        let witness_sequence = proof.assertion_witness().map(|witness| witness.sequence());
        let mut digest = ObservationPrefixDigest::new(event_count);
        let mut beyond_frontier = false;
        let mut witness_entry = None;
        self.try_for_each_entry_in(source, 0..event_count, |entry| {
            digest.update(entry);
            beyond_frontier |= entry.at().ticks > frontier;
            if entry.sequence() >= quantum_start
                && Some(entry.sequence()) == witness_sequence
                && witness_entry.is_none()
            {
                witness_entry = Some(entry.clone());
            }
            Ok::<_, CrucibleMeasurementError>(())
        })?;
        if beyond_frontier || digest.finish() != Some(event_log.digest()) {
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
                verify_assertion_observation_stop(proof, witness_entry.as_ref(), Some(assertion))?;
            }
            ObservationCondition::AnyAssertionViolationTransition => {
                verify_assertion_observation_stop(proof, witness_entry.as_ref(), None)?;
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
        match self.log {
            ReplayLog::Inline(_) => CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2,
            ReplayLog::Segmented(_) => CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3,
        }
    }

    /// Replays the raw leaf against its exact semantic bindings.
    ///
    /// Guest and model samples are rederived from the retained scheduler
    /// entries on every call; no caller-supplied normalized sample is trusted.
    /// Entries are streamed from `source` in one forward pass, holding one
    /// segment at a time.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] for a scenario, configuration, or
    /// definition mismatch, invalid guest protocol input, invalid model sample
    /// source, absent or unauthenticated segment, non-dense log, invalid
    /// terminal state, or evaluation bound.
    pub fn replay(
        &self,
        source: &dyn AttemptLogSegmentSource,
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

        let mut guest = GuestMeasurementNormalizer::new(definitions);
        let model = ModelSampleProjector::new(definitions);
        let mut replay = MeasurementReplay::new(definitions, &self.terminal)?;
        let mut next_sequence = 0_u64;
        self.try_for_each_entry(source, |entry| {
            // Producers interpret typed payloads, so the entry is
            // authenticated before either sees it.
            if !entry.has_valid_content_hash() {
                return Err(MeasurementEvaluationError::InvalidEventHash {
                    sequence: entry.sequence(),
                }
                .into());
            }
            let mut samples = Vec::from_iter(guest.observe(entry)?);
            model.project(entry, &mut samples)?;
            replay.observe(entry, samples)?;
            next_sequence = entry.sequence().saturating_add(1);
            Ok::<_, CrucibleMeasurementError>(())
        })?;
        guest.finish(next_sequence)?;
        replay.finish().map_err(Into::into)
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
    /// inconsistent input, or a manifest whose segments are not a dense
    /// bounded chain.
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
        let value = EvidenceWire::decode(bytes)?.into_evidence()?;
        if let CrucibleMeasurementStopEvidence::Observation(boundary) = value.stop {
            CrucibleObservationBoundaryEvidence::new(
                boundary.frontier,
                boundary.quantum_start_completed_quanta,
                boundary.completed_quanta,
                boundary.quantum_start_events,
                boundary.event_log_offset,
                boundary.scheduler_quiescent,
            )?;
        }

        match &value.log {
            // Empty definitions exercise the shared log and terminal
            // validators without claiming that semantic sample projection
            // has run.
            ReplayLog::Inline(entries) => {
                evaluate_measurements(
                    &MeasurementDefinitions::empty(),
                    entries,
                    Vec::new(),
                    &value.terminal,
                )?;
            }
            // Segment contents are authenticated when read; decoding checks
            // only what the manifest itself carries.
            ReplayLog::Segmented(_) => {
                MeasurementReplay::new(&MeasurementDefinitions::empty(), &value.terminal)?;
                if value
                    .terminal
                    .scenario_ready_at
                    .is_some_and(|ready| ready > value.terminal.at)
                {
                    return Err(MeasurementEvaluationError::TerminalBeforeEvent {
                        sequence: value.entry_count().saturating_sub(1),
                    }
                    .into());
                }
            }
        }
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
    witness_entry: Option<&SchedulerEventLogEntry>,
    expected_assertion: Option<&String>,
) -> Result<(), CrucibleMeasurementError> {
    let mismatch = || CrucibleMeasurementError::EvidenceBindingMismatch {
        binding: "assertion-observation-stop-witness",
    };
    if proof.satisfaction() != ObservationStopSatisfaction::AssertionViolationTransition {
        return Err(mismatch());
    }
    let witness = proof.assertion_witness().ok_or_else(mismatch)?;
    let entry = witness_entry.ok_or_else(mismatch)?;
    if CampaignHash::from_bytes(entry.content_hash().bytes) != witness.entry()
        || !matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(
                ObservableEventPayload::AssertionStateChanged { name, state }
            ) if name.name == witness.assertion()
                && expected_assertion.is_none_or(|expected| name.name == *expected)
                && *state == crucible_engine::AssertionPhase::Violated
        )
    {
        return Err(mismatch());
    }
    Ok(())
}

/// Returns the replay leaf among a measurement set's evidence identities.
///
/// A measurement set owns one replay leaf (schema 2 or 3) and, for version 3,
/// the log segments it references. Returns `None` unless exactly one evidence
/// identity carries a replay-leaf schema.
#[must_use]
pub fn measurement_replay_leaf_id(evidence: &BTreeSet<ContentId>) -> Option<ContentId> {
    let mut leaves = evidence.iter().copied().filter(|id| {
        matches!(
            id.schema_version(),
            CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2
                | CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3
        )
    });
    let leaf = leaves.next()?;
    leaves.next().is_none().then_some(leaf)
}

/// A derived measurement set paired with the raw leaf required to verify it.
///
/// The measurement set owns the replay leaf and every segment it references.
/// A publisher stores each segment from the attempt's segment store before
/// the leaf and the leaf before the measurement set, so no published object
/// references an absent child (RFC-0020 CCOMP-29).
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
/// The resulting measurement set owns exactly the replay leaf and the log
/// segments it references. Other audit evidence belongs to its explicit
/// observation or finding owner. `maximum_evidence_bytes` is the
/// caller-selected minimum of every active model, attempt, prepared-result,
/// and journal ceiling for the leaf itself; segments are bounded separately.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for invalid replay inputs, an absent
/// or unauthenticated segment, semantic binding mismatches, evaluation
/// failures, canonical leaf limits, or campaign measurement-set limits.
pub fn evaluate_crucible_measurement_publication(
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
    log: AttemptLogManifest,
    source: &dyn AttemptLogSegmentSource,
    terminal: MeasurementTerminalState,
    maximum_evidence_bytes: usize,
) -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
    let evidence = CrucibleMeasurementReplayEvidence {
        scenario,
        configuration,
        definitions: campaign_hash(definitions.content_hash()),
        log: ReplayLog::Segmented(log),
        terminal,
        stop: CrucibleMeasurementStopEvidence::Campaign,
    };
    evaluate_crucible_measurement_evidence(evidence, source, definitions, maximum_evidence_bytes)
}

/// Evaluates one run and retains its exact observation-stop boundary.
///
/// # Errors
///
/// Returns the same failures as the ordinary measurement publication path.
// crucible-lint: allow rust-allow -- the stop proof adds its boundary to the ordinary publication inputs.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_crucible_observation_measurement_publication(
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
    log: AttemptLogManifest,
    source: &dyn AttemptLogSegmentSource,
    terminal: MeasurementTerminalState,
    observation_boundary: CrucibleObservationBoundaryEvidence,
    maximum_evidence_bytes: usize,
) -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
    let evidence = CrucibleMeasurementReplayEvidence {
        scenario,
        configuration,
        definitions: campaign_hash(definitions.content_hash()),
        log: ReplayLog::Segmented(log),
        terminal,
        stop: CrucibleMeasurementStopEvidence::Observation(observation_boundary),
    };
    evaluate_crucible_measurement_evidence(evidence, source, definitions, maximum_evidence_bytes)
}

fn evaluate_crucible_measurement_evidence(
    evidence: CrucibleMeasurementReplayEvidence,
    source: &dyn AttemptLogSegmentSource,
    definitions: &MeasurementDefinitions,
    maximum_evidence_bytes: usize,
) -> Result<CrucibleMeasurementPublication, CrucibleMeasurementError> {
    let evidence_bytes = evidence.canonical_bytes_with_limit(maximum_evidence_bytes)?;
    let evaluation = evidence.replay(
        source,
        evidence.scenario,
        evidence.configuration,
        definitions,
    )?;
    let measurement_set = MeasurementSet::from_evaluation(
        campaign_hash(evaluation.definitions()),
        CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3,
        campaign_hash(evaluation.content_hash()),
        evaluation.canonical_bytes().to_vec(),
        evidence.evidence_ids()?,
    )?;
    Ok(CrucibleMeasurementPublication {
        measurement_set,
        evidence,
        evidence_bytes,
    })
}

/// Recomputes a retained measurement set solely from its raw evidence leaf.
///
/// Segments are streamed from `source`, which for retained evidence is the
/// repository that stores the measurement set's evidence children.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for an unsupported payload, an
/// evidence set other than the leaf and its segments, binding mismatch,
/// invalid raw input, an absent or unauthenticated segment, or disagreement
/// between replay output and the retained derived evaluation.
pub fn verify_crucible_measurement_publication(
    measurement_set: &MeasurementSet,
    evidence: &CrucibleMeasurementReplayEvidence,
    source: &dyn AttemptLogSegmentSource,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
) -> Result<MeasurementEvaluation, CrucibleMeasurementError> {
    let retained = measurement_set.evaluation();
    if retained.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3 {
        return Err(CrucibleMeasurementError::UnsupportedPayloadSchema {
            actual: retained.payload_schema(),
            expected: CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V3,
        });
    }
    if retained.evidence() != &evidence.evidence_ids()? {
        return Err(CrucibleMeasurementError::ReplayEvidenceSetMismatch {
            expected: evidence.id()?,
            actual_count: retained.evidence().len(),
        });
    }

    let evaluation = evidence.replay(source, scenario, configuration, definitions)?;
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
