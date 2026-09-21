//! Bounded canonical wire encoding for measurement replay evidence.

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceWireV2 {
    pub(super) schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: BoundedEntries,
    terminal: TerminalStateWire,
    pub(super) stop: CrucibleMeasurementStopEvidence,
}

#[derive(Serialize)]
pub(super) struct EvidenceWireRef<'a> {
    schema_version: u32,
    scenario: ScenarioDefId,
    configuration: ConfigurationId,
    definitions: CampaignHash,
    entries: &'a [SchedulerEventLogEntry],
    terminal: TerminalStateRef<'a>,
    stop: CrucibleMeasurementStopEvidence,
}

impl<'a> From<&'a CrucibleMeasurementReplayEvidence> for EvidenceWireRef<'a> {
    fn from(value: &'a CrucibleMeasurementReplayEvidence) -> Self {
        Self {
            schema_version: value.schema_version(),
            scenario: value.scenario,
            configuration: value.configuration,
            definitions: value.definitions,
            entries: &value.entries,
            terminal: TerminalStateRef::from(&value.terminal),
            stop: value.stop,
        }
    }
}

impl From<EvidenceWireV2> for CrucibleMeasurementReplayEvidence {
    fn from(value: EvidenceWireV2) -> Self {
        Self {
            scenario: value.scenario,
            configuration: value.configuration,
            definitions: value.definitions,
            entries: value.entries.0,
            terminal: value.terminal.into(),
            stop: value.stop,
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
