//! Bounded canonical wire encoding for measurement replay evidence.

use super::*;

/// A decoded leaf of either supported version.
pub(super) enum EvidenceWire {
    V2(EvidenceWireV2),
    V3(EvidenceWireV3),
}

impl EvidenceWire {
    /// Decodes a leaf after reading its schema version.
    ///
    /// The version probe skips the remaining fields without retaining them,
    /// then the matching strict structure decodes the bytes.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, CrucibleMeasurementError> {
        let encoding =
            |error: ciborium::de::Error<io::Error>| CrucibleMeasurementError::EvidenceEncoding {
                reason: error.to_string(),
            };
        let probe: SchemaProbe = ciborium::de::from_reader(bytes).map_err(encoding)?;
        match probe.schema_version {
            CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2 => Ok(Self::V2(
                ciborium::de::from_reader(bytes).map_err(encoding)?,
            )),
            CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3 => Ok(Self::V3(
                ciborium::de::from_reader(bytes).map_err(encoding)?,
            )),
            actual => Err(CrucibleMeasurementError::UnsupportedEvidenceSchema {
                actual,
                expected: CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3,
            }),
        }
    }

    pub(super) fn into_evidence(
        self,
    ) -> Result<CrucibleMeasurementReplayEvidence, CrucibleMeasurementError> {
        let schema_version = match &self {
            Self::V2(wire) => wire.schema_version,
            Self::V3(wire) => wire.schema_version,
        };
        let expected = match &self {
            Self::V2(_) => CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2,
            Self::V3(_) => CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V3,
        };
        if schema_version != expected {
            return Err(CrucibleMeasurementError::UnsupportedEvidenceSchema {
                actual: schema_version,
                expected,
            });
        }
        match self {
            Self::V2(wire) => Ok(CrucibleMeasurementReplayEvidence {
                scenario: wire.scenario,
                configuration: wire.configuration,
                definitions: wire.definitions,
                log: ReplayLog::Inline(wire.entries.0),
                terminal: wire.terminal.into(),
                stop: wire.stop,
            }),
            Self::V3(wire) => {
                let segments = wire
                    .log
                    .segments
                    .0
                    .into_iter()
                    .map(SegmentRefWire::into_ref)
                    .collect::<Result<Vec<_>, _>>()?;
                let manifest =
                    AttemptLogManifest::from_parts(segments, wire.log.entry_count, wire.log.chain)?;
                Ok(CrucibleMeasurementReplayEvidence {
                    scenario: wire.scenario,
                    configuration: wire.configuration,
                    definitions: wire.definitions,
                    log: ReplayLog::Segmented(manifest),
                    terminal: wire.terminal.into(),
                    stop: wire.stop,
                })
            }
        }
    }
}

/// The leading `schema_version` field of a leaf.
///
/// Canonical leaves encode `schema_version` first, so the probe reads that one
/// entry and stops; the matching strict structure then decodes and bounds the
/// remaining fields, including oversized declared container lengths.
struct SchemaProbe {
    schema_version: u32,
}

impl<'de> Deserialize<'de> for SchemaProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SchemaProbeVisitor)
    }
}

struct SchemaProbeVisitor;

impl<'de> Visitor<'de> for SchemaProbeVisitor {
    type Value = SchemaProbe;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a replay leaf beginning with schema_version")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        match map.next_key::<String>()?.as_deref() {
            Some("schema_version") => Ok(SchemaProbe {
                schema_version: map.next_value()?,
            }),
            _ => Err(de::Error::custom(
                "replay leaf must begin with schema_version",
            )),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceWireV2 {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: BoundedEntries,
    terminal: TerminalStateWire,
    stop: CrucibleMeasurementStopEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceWireV3 {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    log: LogManifestWire,
    terminal: TerminalStateWire,
    stop: CrucibleMeasurementStopEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogManifestWire {
    entry_count: u64,
    chain: crucible_engine::ContentHash,
    segments: BoundedSegments,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentRefWire {
    id: String,
    first_sequence: u64,
    entry_count: u64,
    encoded_bytes: u64,
}

impl SegmentRefWire {
    fn from_ref(segment: &AttemptLogSegmentRef) -> Self {
        Self {
            id: segment.id.encode(),
            first_sequence: segment.first_sequence,
            entry_count: segment.entry_count,
            encoded_bytes: segment.encoded_bytes,
        }
    }

    fn into_ref(self) -> Result<AttemptLogSegmentRef, CrucibleMeasurementError> {
        let id = ContentId::parse(&self.id).map_err(|error| {
            CrucibleMeasurementError::EvidenceEncoding {
                reason: format!("segment identity: {error}"),
            }
        })?;
        Ok(AttemptLogSegmentRef {
            id,
            first_sequence: self.first_sequence,
            entry_count: self.entry_count,
            encoded_bytes: self.encoded_bytes,
        })
    }
}

/// Canonical encoding of a leaf of either version.
#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum EvidenceWireRef<'a> {
    V2(EvidenceWireV2Ref<'a>),
    V3(EvidenceWireV3Ref<'a>),
}

#[derive(Serialize)]
pub(super) struct EvidenceWireV2Ref<'a> {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: &'a [SchedulerEventLogEntry],
    terminal: TerminalStateRef<'a>,
    stop: CrucibleMeasurementStopEvidence,
}

#[derive(Serialize)]
pub(super) struct EvidenceWireV3Ref<'a> {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    log: LogManifestRef,
    terminal: TerminalStateRef<'a>,
    stop: CrucibleMeasurementStopEvidence,
}

#[derive(Serialize)]
struct LogManifestRef {
    entry_count: u64,
    chain: crucible_engine::ContentHash,
    segments: Vec<SegmentRefWire>,
}

impl<'a> From<&'a CrucibleMeasurementReplayEvidence> for EvidenceWireRef<'a> {
    fn from(value: &'a CrucibleMeasurementReplayEvidence) -> Self {
        let terminal = TerminalStateRef::from(&value.terminal);
        match &value.log {
            ReplayLog::Inline(entries) => Self::V2(EvidenceWireV2Ref {
                schema_version: value.schema_version(),
                scenario: value.scenario,
                configuration: value.configuration,
                definitions: value.definitions,
                entries,
                terminal,
                stop: value.stop,
            }),
            ReplayLog::Segmented(manifest) => Self::V3(EvidenceWireV3Ref {
                schema_version: value.schema_version(),
                scenario: value.scenario,
                configuration: value.configuration,
                definitions: value.definitions,
                log: LogManifestRef {
                    entry_count: manifest.entry_count(),
                    chain: manifest.chain(),
                    segments: manifest
                        .segments()
                        .iter()
                        .map(SegmentRefWire::from_ref)
                        .collect(),
                },
                terminal,
                stop: value.stop,
            }),
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

struct BoundedSegments(Vec<SegmentRefWire>);

impl<'de> Deserialize<'de> for BoundedSegments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedSegmentsVisitor)
    }
}

struct BoundedSegmentsVisitor;

impl<'de> Visitor<'de> for BoundedSegmentsVisitor {
    type Value = BoundedSegments;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "at most {MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS} attempt-log segments"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let declared = sequence.size_hint().unwrap_or(0);
        if declared > MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS {
            return Err(de::Error::invalid_length(declared, &self));
        }
        let mut segments = Vec::new();
        while let Some(segment) = sequence.next_element()? {
            if segments.len() == MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS {
                return Err(de::Error::invalid_length(segments.len() + 1, &self));
            }
            segments.push(segment);
        }
        Ok(BoundedSegments(segments))
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

pub(super) fn enforce_evidence_bytes(
    actual: usize,
    maximum_bytes: usize,
) -> Result<(), CrucibleMeasurementError> {
    let maximum = maximum_bytes.min(MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES);
    if actual > maximum {
        return Err(CrucibleMeasurementError::EvidenceTooLarge { actual, maximum });
    }
    Ok(())
}

pub(super) fn measure_canonical_bytes(
    value: &CrucibleMeasurementReplayEvidence,
    maximum_bytes: usize,
) -> Result<usize, CrucibleMeasurementError> {
    if let ReplayLog::Inline(entries) = &value.log
        && entries.len() > MAX_MEASUREMENT_EVENT_ENTRIES
    {
        return Err(crucible_engine::model::MeasurementEvaluationError::LimitExceeded {
            limit: "measurement-event-entries",
        }
        .into());
    }
    if value.terminal.node_icounts.len() > MAX_MEASUREMENT_TERMINAL_NODES {
        return Err(
            crucible_engine::model::MeasurementEvaluationError::LimitExceeded {
                limit: "measurement-terminal-nodes",
            }
            .into(),
        );
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
