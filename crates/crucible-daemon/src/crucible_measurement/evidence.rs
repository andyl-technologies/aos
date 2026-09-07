//! Canonical replay evidence for retained Crucible measurement evaluations.
//!
//! A Crucible measurement evaluation payload using schema v2 contains the
//! compact derived evaluation. This module owns its independently
//! content-addressed raw input leaf:
//!
//! ```text
//! canonical CBOR map:
//!   schema_version: 1
//!   scenario: <scenario definition identity>
//!   configuration: <configuration identity>
//!   definitions: <measurement-definition identity>
//!   entries: [<complete SchedulerEventLogEntry sequence>]
//!   terminal:
//!     scenario_ready_at: <optional virtual time>
//!     at: <terminal virtual time>
//!     node_icounts: {<node>: <retired instructions>}
//!     scheduler_quiescent: <boolean>
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
    GuestMeasurementEvent, GuestMeasurementValue, Icount, NodeId, ObservableEventPayload,
    SchedulerEventLogEntry, SchedulerEventLogPayload, VirtualTime,
};
use crucible_campaign::{CampaignHash, ConfigurationId, MeasurementSet, ScenarioDefId};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_protocol::{
    WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES, WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::{CrucibleMeasurementError, campaign_hash};

/// Payload schema requiring retained raw replay evidence.
pub const CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2: u32 = 2;

/// Content-object schema for canonical measurement replay evidence.
pub const CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1: u32 = 1;

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
}

impl CrucibleMeasurementReplayEvidence {
    /// Builds and verifies one complete raw measurement replay leaf.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] when scheduler entries, guest
    /// measurement messages, model projections, terminal state, evaluation, or
    /// canonical encoding violate their bounds or contracts. `maximum_bytes`
    /// must be the minimum active model, attempt, prepared-result, and journal
    /// budget selected by the caller.
    pub fn new(
        scenario: ScenarioDefId,
        configuration: ConfigurationId,
        definitions: &MeasurementDefinitions,
        entries: Vec<SchedulerEventLogEntry>,
        terminal: MeasurementTerminalState,
        maximum_bytes: usize,
    ) -> Result<Self, CrucibleMeasurementError> {
        let value = Self {
            scenario,
            configuration,
            definitions: campaign_hash(definitions.content_hash()),
            entries,
            terminal,
        };
        // Reject the caller's effective attempt/journal budget before hashing
        // the log or allocating the canonical payload.
        measure_canonical_bytes(&value, maximum_bytes)?;
        value.replay(scenario, configuration, definitions)?;
        Ok(value)
    }

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
        let wire: EvidenceWireV1 = ciborium::de::from_reader(bytes).map_err(|error| {
            CrucibleMeasurementError::EvidenceEncoding {
                reason: error.to_string(),
            }
        })?;
        if wire.schema_version != CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1 {
            return Err(CrucibleMeasurementError::UnsupportedEvidenceSchema {
                actual: wire.schema_version,
                expected: CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1,
            });
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
            CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1,
            &bytes,
        ))
    }
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
    };
    let evidence_bytes = evidence.canonical_bytes_with_limit(maximum_evidence_bytes)?;
    let evaluation = evidence.replay(scenario, configuration, definitions)?;
    let evidence_id = ContentId::for_bytes(
        ObjectKind::Trace,
        CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1,
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
/// Returns [`CrucibleMeasurementError`] for a legacy or unsupported payload,
/// non-singleton evidence set, binding mismatch, invalid raw input, or disagreement
/// between replay output and the retained derived evaluation.
pub fn verify_crucible_measurement_publication(
    measurement_set: &MeasurementSet,
    evidence: &CrucibleMeasurementReplayEvidence,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: &MeasurementDefinitions,
) -> Result<MeasurementEvaluation, CrucibleMeasurementError> {
    let retained = measurement_set
        .evaluation()
        .ok_or(CrucibleMeasurementError::LegacyMeasurementSet)?;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWireV1 {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: BoundedEntries,
    terminal: TerminalStateWire,
}

#[derive(Serialize)]
struct EvidenceWireRef<'a> {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: &'a [SchedulerEventLogEntry],
    terminal: TerminalStateRef<'a>,
}

impl<'a> From<&'a CrucibleMeasurementReplayEvidence> for EvidenceWireRef<'a> {
    fn from(value: &'a CrucibleMeasurementReplayEvidence) -> Self {
        Self {
            schema_version: CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V1,
            scenario: value.scenario,
            configuration: value.configuration,
            definitions: value.definitions,
            entries: &value.entries,
            terminal: TerminalStateRef::from(&value.terminal),
        }
    }
}

impl From<EvidenceWireV1> for CrucibleMeasurementReplayEvidence {
    fn from(value: EvidenceWireV1) -> Self {
        Self {
            scenario: value.scenario,
            configuration: value.configuration,
            definitions: value.definitions,
            entries: value.entries.0,
            terminal: value.terminal.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalStateWire {
    scenario_ready_at: Option<VirtualTime>,
    at: VirtualTime,
    node_icounts: BoundedNodeIcounts,
    scheduler_quiescent: bool,
}

#[derive(Serialize)]
struct TerminalStateRef<'a> {
    scenario_ready_at: Option<VirtualTime>,
    at: VirtualTime,
    node_icounts: &'a BTreeMap<NodeId, Icount>,
    scheduler_quiescent: bool,
}

impl<'a> From<&'a MeasurementTerminalState> for TerminalStateRef<'a> {
    fn from(value: &'a MeasurementTerminalState) -> Self {
        Self {
            scenario_ready_at: value.scenario_ready_at,
            at: value.at,
            node_icounts: &value.node_icounts,
            scheduler_quiescent: value.scheduler_quiescent,
        }
    }
}

impl From<TerminalStateWire> for MeasurementTerminalState {
    fn from(value: TerminalStateWire) -> Self {
        Self {
            scenario_ready_at: value.scenario_ready_at,
            at: value.at,
            node_icounts: value.node_icounts.0,
            scheduler_quiescent: value.scheduler_quiescent,
        }
    }
}

struct BoundedEntries(Vec<SchedulerEventLogEntry>);

impl<'de> Deserialize<'de> for BoundedEntries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedEntriesVisitor)
    }
}

struct BoundedEntriesVisitor;

impl<'de> Visitor<'de> for BoundedEntriesVisitor {
    type Value = BoundedEntries;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "at most {MAX_MEASUREMENT_EVENT_ENTRIES} scheduler entries"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let declared = sequence.size_hint().unwrap_or(0);
        if declared > MAX_MEASUREMENT_EVENT_ENTRIES {
            return Err(de::Error::invalid_length(declared, &self));
        }
        // A declared length is attacker controlled even when it is within the
        // semantic count limit. Grow only as actual entries are decoded.
        let mut entries = Vec::new();
        while let Some(entry) = sequence.next_element()? {
            if entries.len() == MAX_MEASUREMENT_EVENT_ENTRIES {
                return Err(de::Error::invalid_length(entries.len() + 1, &self));
            }
            entries.push(entry);
        }
        Ok(BoundedEntries(entries))
    }
}

struct BoundedNodeIcounts(BTreeMap<NodeId, Icount>);

impl<'de> Deserialize<'de> for BoundedNodeIcounts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(BoundedNodeIcountsVisitor)
    }
}

struct BoundedNodeIcountsVisitor;

impl<'de> Visitor<'de> for BoundedNodeIcountsVisitor {
    type Value = BoundedNodeIcounts;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "at most {MAX_MEASUREMENT_TERMINAL_NODES} terminal node counters"
        )
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if map
            .size_hint()
            .is_some_and(|declared| declared > MAX_MEASUREMENT_TERMINAL_NODES)
        {
            return Err(de::Error::invalid_length(
                map.size_hint().unwrap_or(usize::MAX),
                &self,
            ));
        }
        let mut counters = BTreeMap::new();
        while let Some((node, icount)) = map.next_entry()? {
            if counters.len() == MAX_MEASUREMENT_TERMINAL_NODES {
                return Err(de::Error::invalid_length(counters.len() + 1, &self));
            }
            if counters.insert(node, icount).is_some() {
                return Err(de::Error::custom("duplicate terminal node counter"));
            }
        }
        Ok(BoundedNodeIcounts(counters))
    }
}

fn enforce_evidence_bytes(
    actual: usize,
    maximum_bytes: usize,
) -> Result<(), CrucibleMeasurementError> {
    let maximum = maximum_bytes.min(MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES);
    if actual > maximum {
        return Err(CrucibleMeasurementError::EvidenceTooLarge { actual, maximum });
    }
    Ok(())
}

fn measure_canonical_bytes(
    value: &CrucibleMeasurementReplayEvidence,
    maximum_bytes: usize,
) -> Result<usize, CrucibleMeasurementError> {
    if value.entries.len() > MAX_MEASUREMENT_EVENT_ENTRIES {
        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-event-entries",
        }
        .into());
    }
    if value.terminal.node_icounts.len() > MAX_MEASUREMENT_TERMINAL_NODES {
        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-terminal-nodes",
        }
        .into());
    }

    let maximum = maximum_bytes.min(MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES);
    let mut counter = BoundedSizeCounter::new(maximum);
    let result = ciborium::ser::into_writer(&EvidenceWireRef::from(value), &mut counter);
    if let Some(actual) = counter.exceeded_at {
        return Err(CrucibleMeasurementError::EvidenceTooLarge { actual, maximum });
    }
    result.map_err(|error| CrucibleMeasurementError::EvidenceEncoding {
        reason: error.to_string(),
    })?;
    Ok(counter.length)
}

struct BoundedSizeCounter {
    length: usize,
    maximum: usize,
    exceeded_at: Option<usize>,
}

impl BoundedSizeCounter {
    const fn new(maximum: usize) -> Self {
        Self {
            length: 0,
            maximum,
            exceeded_at: None,
        }
    }
}

impl Write for BoundedSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempted = self.length.saturating_add(bytes.len());
        if attempted > self.maximum {
            self.exceeded_at = Some(attempted);
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "measurement replay evidence exceeds its active byte limit",
            ));
        }
        self.length = attempted;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn normalize_guest_measurements(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
) -> Result<Vec<MeasurementRuntimeSample>, CrucibleMeasurementError> {
    let definitions_by_id = definitions
        .definitions()
        .iter()
        .map(|definition| (definition.id.clone(), definition))
        .collect::<BTreeMap<_, _>>();
    let mut open = BTreeSet::<(NodeId, MeasurementId, MeasurementInstanceKey)>::new();
    let mut samples = Vec::new();
    let mut sample_work_bytes = 0usize;

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
                    if open.len() >= MAX_OPEN_GUEST_MEASUREMENT_INSTANCES {
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
                    validate_protocol_identifier(metric, entry.sequence(), "metric")?;
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
                    if samples.len() == MAX_MEASUREMENT_RUNTIME_SAMPLES {
                        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-samples",
                        }
                        .into());
                    }
                    validate_guest_measurement_value(value, contract)
                        .map_err(|reason| guest_measurement_error(entry.sequence(), reason))?;
                    sample_work_bytes = sample_work_bytes
                        .checked_add(guest_sample_normalization_work(
                            measurement.as_str(),
                            metric.as_str(),
                            value,
                        )?)
                        .ok_or(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-sample-bytes",
                        })?;
                    if sample_work_bytes > MAX_MEASUREMENT_RUNTIME_SAMPLE_BYTES {
                        return Err(crucible::model::MeasurementEvaluationError::LimitExceeded {
                            limit: "measurement-runtime-sample-bytes",
                        }
                        .into());
                    }
                    let value = normalize_guest_measurement_value(value)
                        .map_err(|reason| guest_measurement_error(entry.sequence(), reason))?;
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
                validate_protocol_identifier(marker, entry.sequence(), "semantic marker")?;
                validate_protocol_identifier(instance, entry.sequence(), "marker instance")?;
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
    definitions: &'a BTreeMap<MeasurementId, &'a MeasurementDefinition>,
    node: &NodeId,
    measurement: &str,
    instance: &str,
    sequence: u64,
) -> Result<
    (
        MeasurementId,
        MeasurementInstanceKey,
        &'a MeasurementDefinition,
    ),
    CrucibleMeasurementError,
> {
    validate_protocol_identifier(measurement, sequence, "measurement")?;
    validate_protocol_identifier(instance, sequence, "measurement instance")?;
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
    definition: &MeasurementDefinition,
    sequence: u64,
) -> Result<&MeasurementInstanceKey, CrucibleMeasurementError> {
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

fn validate_guest_measurement_value(
    value: &GuestMeasurementValue,
    metric: &MetricDefinition,
) -> Result<(), String> {
    let valid = match (value, &metric.value_type) {
        (GuestMeasurementValue::Signed(_), MetricValueType::SignedInteger)
        | (GuestMeasurementValue::Unsigned(_), MetricValueType::UnsignedInteger)
        | (GuestMeasurementValue::Rational(_), MetricValueType::ReducedRational)
        | (GuestMeasurementValue::Boolean(_), MetricValueType::Boolean) => true,
        (GuestMeasurementValue::Enumerated(value), MetricValueType::Enumerated { variants }) => {
            value.len() <= WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES
                && variants.binary_search(value).is_ok()
        }
        (
            GuestMeasurementValue::SignedVector(values),
            MetricValueType::IntegerVector {
                signed: true,
                maximum_elements,
            },
        ) => {
            values.len() <= WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                && values.len() <= *maximum_elements as usize
        }
        (
            GuestMeasurementValue::UnsignedVector(values),
            MetricValueType::IntegerVector {
                signed: false,
                maximum_elements,
            },
        ) => {
            values.len() <= WHITEBOX_MEASUREMENT_VECTOR_MAX_ELEMENTS
                && values.len() <= *maximum_elements as usize
        }
        _ => false,
    };
    if !valid {
        return Err(format!(
            "metric `{}` value violates its declared type or guest protocol bound",
            metric.id
        ));
    }
    Ok(())
}

fn guest_sample_normalization_work(
    measurement: &str,
    metric: &str,
    value: &GuestMeasurementValue,
) -> Result<usize, CrucibleMeasurementError> {
    let value_bytes = match value {
        GuestMeasurementValue::Signed(_)
        | GuestMeasurementValue::Unsigned(_)
        | GuestMeasurementValue::Rational(_)
        | GuestMeasurementValue::Boolean(_) => 64,
        GuestMeasurementValue::Enumerated(value) => value.len(),
        GuestMeasurementValue::SignedVector(values) => values.len().saturating_mul(21),
        GuestMeasurementValue::UnsignedVector(values) => values.len().saturating_mul(20),
    };
    256usize
        .checked_add(measurement.len())
        .and_then(|bytes| bytes.checked_add(metric.len()))
        .and_then(|bytes| bytes.checked_add(value_bytes))
        .ok_or_else(|| {
            crucible::model::MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-runtime-sample-bytes",
            }
            .into()
        })
}

fn validate_protocol_identifier(
    value: &str,
    sequence: u64,
    kind: &'static str,
) -> Result<(), CrucibleMeasurementError> {
    if value.len() > WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES {
        return Err(guest_measurement_error(
            sequence,
            format!(
                "{kind} identifier exceeds {} bytes",
                WHITEBOX_MEASUREMENT_IDENTIFIER_MAX_BYTES
            ),
        ));
    }
    Ok(())
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

fn guest_measurement_error(sequence: u64, reason: impl Into<String>) -> CrucibleMeasurementError {
    CrucibleMeasurementError::GuestMeasurementProtocol {
        sequence,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
