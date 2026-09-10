//! Portable evidence for independently observed failure-signature replays.
//!
//! A replay-evidence payload deliberately omits the reproduction bytes. Its
//! caller supplies the authenticated [`FindingReproductionArtifact`] named by
//! the surrounding campaign object, and decoding binds every retained record
//! back to that exact artifact before exposing the recomputed signature.

use super::*;
use crate::compare_event_log_determinism;
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::io::{self, Write};

/// Latest schema version encoded by [`FailureTriageReplayEvidence::to_compact_binary`].
pub const FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION: u32 = 2;

// The final magic byte is the payload schema. This assertion keeps the public
// version used by campaign envelopes synchronized with the compact codec.
const FAILURE_TRIAGE_REPLAY_EVIDENCE_V1_MAGIC: &[u8] =
    b"CRUCIBLE_FAILURE_TRIAGE_REPLAY_EVIDENCE\0\x01";
const FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC: &[u8] =
    b"CRUCIBLE_FAILURE_TRIAGE_REPLAY_EVIDENCE\0\x02";
const _: () = assert!(
    FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC[FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC.len() - 1]
        as u32
        == FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
);
const MAX_FAILURE_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_CAUSAL_ENTRIES_BYTES: usize = 16 * 1024 * 1024;
const MAX_CAUSAL_ENTRIES: usize = 65_536;
const MAX_RECORDED_EVENT_FRAMES: usize = 65_536;
const MAX_RECORDED_EVENT_FRAME_BYTES: usize = 1024 * 1024;
const MAX_RECORDED_EVENT_FRAME_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_FAILURE_SIGNATURE_MATERIAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_V1_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES: usize = 48 * 1024 * 1024;

/// Maximum canonical size of one portable failure replay-evidence payload.
pub const MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES: usize = 80 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairedDivergenceLogs {
    expected: Vec<SchedulerEventLogEntry>,
    reproduced: Vec<SchedulerEventLogEntry>,
}

/// Replay-owned inputs and the full failure signature recomputed from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureTriageReplayEvidence {
    schema_version: u32,
    finding: FindingReproductionArtifact,
    failure: FailureClusterReportFailure,
    causal_entries: Vec<SchedulerEventLogEntry>,
    coverage_fingerprint: ContentHash,
    recorded_event_frames: Vec<Vec<u8>>,
    recorded_event_log: FailureRecordedEventLog,
    signature: FailureSignature,
    paired_divergence_logs: Option<PairedDivergenceLogs>,
}

impl FailureTriageReplayEvidence {
    /// Builds evidence from one independently executed reproduction.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the failure source, causal entries, or
    /// retained frames do not reconstruct a valid signature for `finding`, or
    /// when the canonical payload exceeds a fixed evidence bound.
    pub fn new(
        finding: FindingReproductionArtifact,
        failure: FailureClusterReportFailure,
        causal_entries: Vec<SchedulerEventLogEntry>,
        coverage_fingerprint: ContentHash,
        recorded_event_frames: Vec<Vec<u8>>,
    ) -> Result<Self, EngineError> {
        validate_failure_bounds(&failure)?;
        validate_causal_entry_bounds(&causal_entries)?;
        validate_frame_bounds(&recorded_event_frames)?;
        let recorded_event_log = FailureRecordedEventLog::from_causal_entries_coverage_and_frames(
            &finding,
            &causal_entries,
            coverage_fingerprint,
            &recorded_event_frames,
        )?;
        let signature = recompute_failure_signature(&finding, &recorded_event_log, &failure)?;
        let value = Self {
            schema_version: 1,
            finding,
            failure,
            causal_entries,
            coverage_fingerprint,
            recorded_event_frames,
            recorded_event_log,
            signature,
            paired_divergence_logs: None,
        };
        if value.encode()?.len() > MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES {
            return Err(scenario_serialization_error(
                "failure triage replay evidence exceeds canonical size limit",
            ));
        }
        Ok(value)
    }

    /// Builds divergence evidence from two logs attributed to one reproduction.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the logs have identical causal projections,
    /// either log exceeds its bound, or the reconstructed evidence is invalid.
    pub fn new_paired_divergence(
        finding: FindingReproductionArtifact,
        expected: Vec<SchedulerEventLogEntry>,
        reproduced: Vec<SchedulerEventLogEntry>,
        coverage_fingerprint: ContentHash,
        recorded_event_frames: Vec<Vec<u8>>,
    ) -> Result<Self, EngineError> {
        validate_causal_entry_bounds(&expected)?;
        validate_causal_entry_bounds(&reproduced)?;
        validate_frame_bounds(&recorded_event_frames)?;

        let failure = divergence_failure_from_logs(&expected, &reproduced)?;
        let comparison = compare_event_log_determinism(&expected, &reproduced);
        let mismatch = comparison.mismatch().ok_or_else(|| {
            scenario_serialization_error("paired divergence logs have equal causal projections")
        })?;
        let causal_entries = if mismatch.expected_location.is_some() {
            expected.clone()
        } else {
            reproduced.clone()
        };
        let recorded_event_log = FailureRecordedEventLog::from_causal_entries_coverage_and_frames(
            &finding,
            &causal_entries,
            coverage_fingerprint,
            &recorded_event_frames,
        )?;
        let signature = recompute_failure_signature(&finding, &recorded_event_log, &failure)?;
        let value = Self {
            schema_version: FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION,
            finding,
            failure,
            causal_entries,
            coverage_fingerprint,
            recorded_event_frames,
            recorded_event_log,
            signature,
            paired_divergence_logs: Some(PairedDivergenceLogs {
                expected,
                reproduced,
            }),
        };
        if value.encode()?.len() > MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES {
            return Err(scenario_serialization_error(
                "failure triage replay evidence exceeds canonical size limit",
            ));
        }
        Ok(value)
    }

    /// Decodes evidence against its authenticated reproduction artifact.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] for malformed, noncanonical, oversized, or
    /// semantically inconsistent evidence. The decoder reconstructs the event
    /// log and full signature instead of trusting the serialized signature.
    pub fn from_compact_binary(
        finding: FindingReproductionArtifact,
        bytes: &[u8],
    ) -> Result<Self, EngineError> {
        if bytes.len() > MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES {
            return Err(scenario_serialization_error(
                "failure triage replay evidence exceeds canonical size limit",
            ));
        }
        let schema_version = if bytes.starts_with(FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC) {
            2
        } else {
            1
        };
        if schema_version == 1 && bytes.len() > MAX_V1_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES {
            return Err(scenario_serialization_error(
                "failure triage replay evidence exceeds schema-v1 canonical size limit",
            ));
        }
        let magic = if schema_version == 2 {
            FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC
        } else {
            FAILURE_TRIAGE_REPLAY_EVIDENCE_V1_MAGIC
        };
        let mut reader = ScenarioBinaryReader::new(bytes, magic)?;
        validate_finding_binding(&finding, &mut reader)?;
        let failure = decode_failure_source(&mut reader, finding.artifact.id())?;
        let expected =
            decode_causal_entries(&mut reader, "failure triage expected causal entries")?;
        let reproduced = (schema_version == 2)
            .then(|| decode_causal_entries(&mut reader, "failure triage reproduced causal entries"))
            .transpose()?;
        let coverage_fingerprint = reader.read_hash()?;
        let frame_count = reader.read_collection_count("failure triage recorded frames")?;
        if frame_count > MAX_RECORDED_EVENT_FRAMES {
            return Err(scenario_serialization_error(
                "failure triage recorded frame count exceeds limit",
            ));
        }
        let mut recorded_event_frames = Vec::with_capacity(frame_count);
        let mut frame_bytes = 0usize;
        for _ in 0..frame_count {
            let frame = reader.read_binary_blob_bounded(
                "failure triage recorded frame",
                MAX_RECORDED_EVENT_FRAME_BYTES,
            )?;
            frame_bytes = frame_bytes.checked_add(frame.len()).ok_or_else(|| {
                scenario_serialization_error("failure triage recorded frame size overflow")
            })?;
            if frame_bytes > MAX_RECORDED_EVENT_FRAME_TOTAL_BYTES {
                return Err(scenario_serialization_error(
                    "failure triage recorded frames exceed aggregate limit",
                ));
            }
            recorded_event_frames.push(frame.to_vec());
        }
        let expected_signature_material = reader.read_binary_blob_bounded(
            "failure triage signature material",
            MAX_FAILURE_SIGNATURE_MATERIAL_BYTES,
        )?;
        let expected_signature_material = std::str::from_utf8(expected_signature_material)
            .map_err(|error| {
                scenario_serialization_error(format!(
                    "failure triage signature material is not UTF-8: {error}"
                ))
            })?;
        reader.finish()?;

        let value = if let Some(reproduced) = reproduced {
            let value = Self::new_paired_divergence(
                finding,
                expected,
                reproduced,
                coverage_fingerprint,
                recorded_event_frames,
            )?;
            if value.failure != failure {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-replay-evidence",
                    reason: "recorded divergence is not the paired logs' first causal mismatch",
                });
            }
            value
        } else {
            Self::new(
                finding,
                failure,
                expected,
                coverage_fingerprint,
                recorded_event_frames,
            )?
        };
        if value.signature.report_material() != expected_signature_material {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-replay-evidence",
                reason: "recorded signature does not match reconstructed replay evidence",
            });
        }
        if value.encode()? != bytes {
            return Err(scenario_serialization_error(
                "failure triage replay evidence is not canonically encoded",
            ));
        }
        Ok(value)
    }

    /// Returns canonical bounded bytes for campaign retention.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if a nested causal entry
    /// or failure source cannot be encoded.
    pub fn to_compact_binary(&self) -> Result<Vec<u8>, EngineError> {
        self.encode()
    }

    /// Returns the encoded payload schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns whether `schema_version` is supported by this decoder.
    #[must_use]
    pub const fn supports_schema(schema_version: u32) -> bool {
        schema_version == 1 || schema_version == FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
    }

    /// Returns both complete execution logs retained for divergence evidence.
    #[must_use]
    pub fn paired_divergence_logs(
        &self,
    ) -> Option<(&[SchedulerEventLogEntry], &[SchedulerEventLogEntry])> {
        self.paired_divergence_logs
            .as_ref()
            .map(|logs| (logs.expected.as_slice(), logs.reproduced.as_slice()))
    }

    /// Returns the exact reproduction whose replay produced this evidence.
    #[must_use]
    pub const fn finding(&self) -> &FindingReproductionArtifact {
        &self.finding
    }

    /// Returns the replay-owned failure source record.
    #[must_use]
    pub const fn failure(&self) -> &FailureClusterReportFailure {
        &self.failure
    }

    /// Returns the causal scheduler entries retained from this replay.
    #[must_use]
    pub fn causal_entries(&self) -> &[SchedulerEventLogEntry] {
        &self.causal_entries
    }

    /// Returns the retained coverage fingerprint observed for this replay.
    #[must_use]
    pub const fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
    }

    /// Returns the exact retained transport frames, when available.
    #[must_use]
    pub fn recorded_event_frames(&self) -> &[Vec<u8>] {
        &self.recorded_event_frames
    }

    /// Returns the checked event-log projection reconstructed from raw inputs.
    #[must_use]
    pub const fn recorded_event_log(&self) -> &FailureRecordedEventLog {
        &self.recorded_event_log
    }

    /// Returns the full failure signature reconstructed from this replay.
    #[must_use]
    pub const fn signature(&self) -> &FailureSignature {
        &self.signature
    }

    fn encode(&self) -> Result<Vec<u8>, EngineError> {
        validate_failure_bounds(&self.failure)?;
        validate_causal_entry_bounds(&self.causal_entries)?;
        validate_frame_bounds(&self.recorded_event_frames)?;

        let failure = FailureSourceWire::from_failure(&self.failure)?;
        let failure =
            bounded_json_bytes(&failure, MAX_FAILURE_SOURCE_BYTES, "failure triage source")?;
        let (expected_entries, reproduced_entries) = match &self.paired_divergence_logs {
            Some(logs) => {
                validate_causal_entry_bounds(&logs.expected)?;
                validate_causal_entry_bounds(&logs.reproduced)?;
                (
                    bounded_json_bytes(
                        &logs.expected,
                        MAX_CAUSAL_ENTRIES_BYTES,
                        "failure triage expected causal entries",
                    )?,
                    Some(bounded_json_bytes(
                        &logs.reproduced,
                        MAX_CAUSAL_ENTRIES_BYTES,
                        "failure triage reproduced causal entries",
                    )?),
                )
            }
            None => (
                bounded_json_bytes(
                    &self.causal_entries,
                    MAX_CAUSAL_ENTRIES_BYTES,
                    "failure triage causal entries",
                )?,
                None,
            ),
        };
        let signature_material = self.signature.report_material();
        if signature_material.len() > MAX_FAILURE_SIGNATURE_MATERIAL_BYTES {
            return Err(scenario_serialization_error(
                "failure triage signature material exceeds encoded size limit",
            ));
        }

        let encoded_size = encoded_size(
            self.schema_version,
            failure.len(),
            expected_entries.len(),
            reproduced_entries.as_ref().map_or(0, Vec::len),
            &self.recorded_event_frames,
            signature_material.len(),
        )?;
        let maximum = if self.schema_version == 1 {
            MAX_V1_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES
        } else {
            MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES
        };
        if encoded_size > maximum {
            return Err(scenario_serialization_error(
                "failure triage replay evidence exceeds canonical size limit",
            ));
        }

        let magic = if self.schema_version == 2 {
            FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC
        } else {
            FAILURE_TRIAGE_REPLAY_EVIDENCE_V1_MAGIC
        };
        let mut writer = ScenarioBinaryWriter::new(magic);
        writer.write_u8(discovery_path_tag(self.finding.discovery_path));
        writer.write_hash(self.finding.finding_fingerprint);
        writer.write_hash(self.finding.configuration);
        writer.write_hash(self.finding.artifact.id());
        writer.write_binary_blob(&failure);
        writer.write_binary_blob(&expected_entries);
        if let Some(reproduced_entries) = reproduced_entries {
            writer.write_binary_blob(&reproduced_entries);
        }
        writer.write_hash(self.coverage_fingerprint);
        writer.write_count(self.recorded_event_frames.len());
        for frame in &self.recorded_event_frames {
            writer.write_binary_blob(frame);
        }
        writer.write_binary_blob(signature_material.as_bytes());
        Ok(writer.finish())
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
enum FailureSourceWire {
    Property {
        assertion: AssertionId,
        message: String,
        quantifier: AssertionQuantifierKind,
        event_kind: String,
        at_icount: Option<Icount>,
        at_virtual_time: VirtualTime,
        node: Option<NodeId>,
        detail: String,
    },
    Divergence {
        raw_index: u64,
        node: Option<NodeId>,
        icount_node: Option<NodeId>,
        icount: Icount,
        source: EventSource,
        kind: String,
        expected_state_summary: String,
        reproduced_state_summary: String,
    },
    Timeout {
        budget_kind: FailureTimeoutBudgetKindWire,
        configured_limit: Option<u64>,
        observed_quanta: u64,
        at_virtual_time: VirtualTime,
        at_icount: Option<Icount>,
        node: Option<NodeId>,
    },
}

impl FailureSourceWire {
    fn from_failure(failure: &FailureClusterReportFailure) -> Result<Self, EngineError> {
        let value = match failure {
            FailureClusterReportFailure::Property(property) => Self::Property {
                assertion: property.violation.assertion.clone(),
                message: property.violation.message.clone(),
                quantifier: property.violation.quantifier,
                event_kind: property.violation.event_kind.clone(),
                at_icount: property.violation.at_icount,
                at_virtual_time: property.violation.at_virtual_time,
                node: property.violation.node.clone(),
                detail: property.violation.detail.clone(),
            },
            FailureClusterReportFailure::Divergence(divergence) => Self::Divergence {
                raw_index: u64::try_from(divergence.raw_index).map_err(|_| {
                    scenario_serialization_error(
                        "failure triage divergence index does not fit portable wire format",
                    )
                })?,
                node: divergence.node.clone(),
                icount_node: divergence.icount_node.clone(),
                icount: divergence.icount,
                source: divergence.source.clone(),
                kind: divergence.kind.clone(),
                expected_state_summary: divergence.expected_state_summary.clone(),
                reproduced_state_summary: divergence.reproduced_state_summary.clone(),
            },
            FailureClusterReportFailure::Timeout(timeout) => Self::Timeout {
                budget_kind: timeout.budget_kind.into(),
                configured_limit: timeout.configured_limit,
                observed_quanta: timeout.observed_quanta,
                at_virtual_time: timeout.at_virtual_time,
                at_icount: timeout.at_icount,
                node: timeout.node.clone(),
            },
        };
        Ok(value)
    }

    fn into_failure(
        self,
        reproduction_artifact: ContentHash,
    ) -> Result<FailureClusterReportFailure, EngineError> {
        let failure = match self {
            Self::Property {
                assertion,
                message,
                quantifier,
                event_kind,
                at_icount,
                at_virtual_time,
                node,
                detail,
            } => FailureClusterReportFailure::property(FailurePropertyViolationRecord::new(
                HostAssertionViolation {
                    assertion,
                    message,
                    quantifier,
                    event_kind,
                    at_icount,
                    at_virtual_time,
                    node,
                    detail,
                    reproduction_artifact,
                },
            )),
            Self::Divergence {
                raw_index,
                node,
                icount_node,
                icount,
                source,
                kind,
                expected_state_summary,
                reproduced_state_summary,
            } => FailureClusterReportFailure::divergence(FailureClusterReportDivergence {
                raw_index: usize::try_from(raw_index).map_err(|_| {
                    scenario_serialization_error(
                        "failure triage divergence index does not fit this platform",
                    )
                })?,
                node,
                icount_node,
                icount,
                source,
                kind,
                expected_state_summary,
                reproduced_state_summary,
            }),
            Self::Timeout {
                budget_kind,
                configured_limit,
                observed_quanta,
                at_virtual_time,
                at_icount,
                node,
            } => FailureClusterReportFailure::timeout(FailureTimeoutRecord::new(
                budget_kind.into(),
                configured_limit,
                observed_quanta,
                at_virtual_time,
                at_icount,
                node,
                reproduction_artifact,
            )),
        };
        Ok(failure)
    }
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
enum FailureTimeoutBudgetKindWire {
    ExecutionQuanta,
    VirtualTime,
}

impl From<FailureTimeoutBudgetKind> for FailureTimeoutBudgetKindWire {
    fn from(value: FailureTimeoutBudgetKind) -> Self {
        match value {
            FailureTimeoutBudgetKind::ExecutionQuanta => Self::ExecutionQuanta,
            FailureTimeoutBudgetKind::VirtualTime => Self::VirtualTime,
        }
    }
}

impl From<FailureTimeoutBudgetKindWire> for FailureTimeoutBudgetKind {
    fn from(value: FailureTimeoutBudgetKindWire) -> Self {
        match value {
            FailureTimeoutBudgetKindWire::ExecutionQuanta => Self::ExecutionQuanta,
            FailureTimeoutBudgetKindWire::VirtualTime => Self::VirtualTime,
        }
    }
}

fn decode_failure_source(
    reader: &mut ScenarioBinaryReader<'_>,
    reproduction_artifact: ContentHash,
) -> Result<FailureClusterReportFailure, EngineError> {
    let bytes =
        reader.read_binary_blob_bounded("failure triage source", MAX_FAILURE_SOURCE_BYTES)?;
    let wire = serde_json::from_slice::<FailureSourceWire>(bytes).map_err(|error| {
        scenario_serialization_error(format!("decode failure triage source: {error}"))
    })?;
    let canonical = bounded_json_bytes(&wire, MAX_FAILURE_SOURCE_BYTES, "failure triage source")?;
    if canonical != bytes {
        return Err(scenario_serialization_error(
            "failure triage source is not canonically encoded",
        ));
    }
    wire.into_failure(reproduction_artifact)
}

fn decode_causal_entries(
    reader: &mut ScenarioBinaryReader<'_>,
    label: &'static str,
) -> Result<Vec<SchedulerEventLogEntry>, EngineError> {
    let bytes = reader.read_binary_blob_bounded(label, MAX_CAUSAL_ENTRIES_BYTES)?;
    let BoundedSequence(entries) = serde_json::from_slice::<
        BoundedSequence<SchedulerEventLogEntry, MAX_CAUSAL_ENTRIES>,
    >(bytes)
    .map_err(|error| scenario_serialization_error(format!("decode {label}: {error}")))?;
    validate_causal_entry_bounds(&entries)?;
    let canonical = bounded_json_bytes(&entries, MAX_CAUSAL_ENTRIES_BYTES, label)?;
    if canonical != bytes {
        return Err(scenario_serialization_error(format!(
            "{label} are not canonically encoded"
        )));
    }
    Ok(entries)
}

fn divergence_failure_from_logs(
    expected: &[SchedulerEventLogEntry],
    reproduced: &[SchedulerEventLogEntry],
) -> Result<FailureClusterReportFailure, EngineError> {
    let comparison = compare_event_log_determinism(expected, reproduced);
    let mismatch = comparison.mismatch().ok_or_else(|| {
        scenario_serialization_error("paired divergence logs have equal causal projections")
    })?;
    let point = mismatch.first_location().ok_or_else(|| {
        scenario_serialization_error("paired divergence has no causal mismatch location")
    })?;
    Ok(FailureClusterReportFailure::divergence(
        FailureClusterReportDivergence::from_bisected_first_diff(
            point,
            divergence_entry_summary(mismatch.expected_entry.as_ref()),
            divergence_entry_summary(mismatch.reproduced_entry.as_ref()),
        ),
    ))
}

fn divergence_entry_summary(entry: Option<&SchedulerEventLogEntry>) -> String {
    entry.map_or_else(
        || String::from("entry=absent"),
        |entry| {
            format!(
                "entry.content_hash={};entry.sequence={};entry.kind={}",
                entry.content_hash().to_hex(),
                entry.sequence(),
                entry.event_payload().kind(),
            )
        },
    )
}

fn validate_finding_binding(
    finding: &FindingReproductionArtifact,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<(), EngineError> {
    let discovery_path = decode_discovery_path(reader.read_u8()?)?;
    let finding_fingerprint = reader.read_hash()?;
    let configuration = reader.read_hash()?;
    let artifact = reader.read_hash()?;
    if discovery_path != finding.discovery_path
        || finding_fingerprint != finding.finding_fingerprint
        || configuration != finding.configuration
        || artifact != finding.artifact.id()
    {
        return Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "failure-triage-replay-evidence",
            reason: "replay evidence names another finding reproduction",
        });
    }
    Ok(())
}

fn validate_failure_bounds(failure: &FailureClusterReportFailure) -> Result<(), EngineError> {
    let mut source_bytes = 0usize;
    match failure {
        FailureClusterReportFailure::Property(property) => {
            for value in [
                property.violation.assertion.name.as_str(),
                property.violation.message.as_str(),
                property.violation.event_kind.as_str(),
                property.violation.detail.as_str(),
            ] {
                add_failure_source_bytes(&mut source_bytes, value)?;
            }
            if let Some(node) = &property.violation.node {
                add_failure_source_bytes(&mut source_bytes, &node.name)?;
            }
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            for value in [
                divergence.kind.as_str(),
                divergence.expected_state_summary.as_str(),
                divergence.reproduced_state_summary.as_str(),
            ] {
                add_failure_source_bytes(&mut source_bytes, value)?;
            }
            for node in [divergence.node.as_ref(), divergence.icount_node.as_ref()]
                .into_iter()
                .flatten()
            {
                add_failure_source_bytes(&mut source_bytes, &node.name)?;
            }
            match &divergence.source {
                EventSource::Scenario { event } => {
                    add_failure_source_bytes(&mut source_bytes, &event.name)?;
                }
                EventSource::Node { node } | EventSource::Guest { node } => {
                    add_failure_source_bytes(&mut source_bytes, &node.name)?;
                }
                EventSource::Engine | EventSource::Command { .. } => {}
            }
        }
        FailureClusterReportFailure::Timeout(timeout) => {
            if let Some(node) = &timeout.node {
                add_failure_source_bytes(&mut source_bytes, &node.name)?;
            }
        }
    }

    let wire = FailureSourceWire::from_failure(failure)?;
    bounded_json_bytes(&wire, MAX_FAILURE_SOURCE_BYTES, "failure triage source")?;
    Ok(())
}

fn add_failure_source_bytes(total: &mut usize, value: &str) -> Result<(), EngineError> {
    *total = total
        .checked_add(value.len())
        .ok_or_else(|| scenario_serialization_error("failure triage source size overflow"))?;
    if *total > MAX_FAILURE_SOURCE_BYTES {
        return Err(scenario_serialization_error(
            "failure triage source exceeds material size limit",
        ));
    }
    Ok(())
}

fn validate_causal_entry_bounds(
    causal_entries: &[SchedulerEventLogEntry],
) -> Result<(), EngineError> {
    if causal_entries.len() > MAX_CAUSAL_ENTRIES {
        return Err(scenario_serialization_error(
            "failure triage causal entry count exceeds limit",
        ));
    }
    bounded_json_bytes(
        &causal_entries,
        MAX_CAUSAL_ENTRIES_BYTES,
        "failure triage causal entries",
    )?;
    Ok(())
}

fn validate_frame_bounds(frames: &[Vec<u8>]) -> Result<(), EngineError> {
    if frames.len() > MAX_RECORDED_EVENT_FRAMES {
        return Err(scenario_serialization_error(
            "failure triage recorded frame count exceeds limit",
        ));
    }
    let mut total = 0usize;
    for frame in frames {
        if frame.len() > MAX_RECORDED_EVENT_FRAME_BYTES {
            return Err(scenario_serialization_error(
                "failure triage recorded frame exceeds size limit",
            ));
        }
        total = total.checked_add(frame.len()).ok_or_else(|| {
            scenario_serialization_error("failure triage recorded frame size overflow")
        })?;
        if total > MAX_RECORDED_EVENT_FRAME_TOTAL_BYTES {
            return Err(scenario_serialization_error(
                "failure triage recorded frames exceed aggregate limit",
            ));
        }
    }
    Ok(())
}

fn encoded_size(
    schema_version: u32,
    failure_bytes: usize,
    expected_entry_bytes: usize,
    reproduced_entry_bytes: usize,
    frames: &[Vec<u8>],
    signature_material_bytes: usize,
) -> Result<usize, EngineError> {
    let length_fields = if schema_version == 1 { 4 } else { 5 };
    let fixed_size = FAILURE_TRIAGE_REPLAY_EVIDENCE_V2_MAGIC
        .len()
        .checked_add(1)
        .and_then(|size| size.checked_add(4 * ContentHash::default().bytes.len()))
        .and_then(|size| size.checked_add(length_fields * std::mem::size_of::<u64>()))
        .ok_or_else(|| {
            scenario_serialization_error("failure triage evidence encoded size overflow")
        })?;
    let variable_size = frames.iter().try_fold(
        failure_bytes
            .checked_add(expected_entry_bytes)
            .and_then(|size| size.checked_add(reproduced_entry_bytes))
            .and_then(|size| size.checked_add(signature_material_bytes))
            .ok_or_else(|| {
                scenario_serialization_error("failure triage evidence encoded size overflow")
            })?,
        |size, frame| {
            size.checked_add(std::mem::size_of::<u64>())
                .and_then(|size| size.checked_add(frame.len()))
                .ok_or_else(|| {
                    scenario_serialization_error("failure triage evidence encoded size overflow")
                })
        },
    )?;
    fixed_size.checked_add(variable_size).ok_or_else(|| {
        scenario_serialization_error("failure triage evidence encoded size overflow")
    })
}

struct BoundedSequence<T, const MAX: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedSequence<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedSequenceVisitor<T, const MAX: usize>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedSequenceVisitor<T, MAX> {
            type Value = BoundedSequence<T, MAX>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "at most {MAX} failure triage causal entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let hint = sequence.size_hint().unwrap_or(0);
                if hint > MAX {
                    return Err(serde::de::Error::custom(
                        "failure triage causal entry count exceeds limit",
                    ));
                }

                let mut values = Vec::new();
                values.try_reserve_exact(hint.min(1024)).map_err(|_| {
                    serde::de::Error::custom("failure triage causal entry allocation failed")
                })?;
                loop {
                    if values.len() == MAX {
                        if sequence.next_element::<IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(
                                "failure triage causal entry count exceeds limit",
                            ));
                        }
                        break;
                    }
                    let Some(value) = sequence.next_element()? else {
                        break;
                    };
                    if values.len() == values.capacity() {
                        values.try_reserve(1).map_err(|_| {
                            serde::de::Error::custom(
                                "failure triage causal entry allocation failed",
                            )
                        })?;
                    }
                    values.push(value);
                }
                Ok(BoundedSequence(values))
            }
        }

        deserializer.deserialize_seq(BoundedSequenceVisitor::<T, MAX>(std::marker::PhantomData))
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum: usize,
    label: &'static str,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other(format!("{} size overflow", self.label)))?;
        if next > self.maximum {
            return Err(io::Error::other(format!(
                "{} exceeds encoded size limit",
                self.label
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_bytes<T: serde::Serialize + ?Sized>(
    value: &T,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, EngineError> {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::new(),
        maximum,
        label,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| scenario_serialization_error(format!("encode {label}: {error}")))?;
    Ok(writer.bytes)
}

fn recompute_failure_signature(
    finding: &FindingReproductionArtifact,
    recorded_event_log: &FailureRecordedEventLog,
    failure: &FailureClusterReportFailure,
) -> Result<FailureSignature, EngineError> {
    let artifact = finding.artifact.id();
    match failure {
        FailureClusterReportFailure::Property(property) => {
            if property.violation.reproduction_artifact != artifact {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-replay-evidence",
                    reason: "property failure names another reproduction",
                });
            }
            FailureSignature::from_recorded_property_violation(
                finding,
                recorded_event_log,
                property,
            )
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            let point = divergence.to_divergence_point();
            let reconstructed = FailureClusterReportDivergence::from_bisected_first_diff(
                &point,
                divergence.expected_state_summary.clone(),
                divergence.reproduced_state_summary.clone(),
            );
            if reconstructed != *divergence {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-replay-evidence",
                    reason: "divergence failure detail is internally inconsistent",
                });
            }
            FailureSignature::from_recorded_divergence(finding, recorded_event_log, &point)
        }
        FailureClusterReportFailure::Timeout(timeout) => {
            if timeout.reproduction_artifact != artifact {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-replay-evidence",
                    reason: "timeout failure names another reproduction",
                });
            }
            FailureSignature::from_recorded_timeout(finding, recorded_event_log, timeout)
        }
    }
}

const fn discovery_path_tag(path: FindingDiscoveryPath) -> u8 {
    match path {
        FindingDiscoveryPath::InteractiveFork => 0,
        FindingDiscoveryPath::StateSpaceSearch => 1,
        FindingDiscoveryPath::CoverageGuidedFuzzing => 2,
        FindingDiscoveryPath::RetainedCorpusEntry => 3,
    }
}

fn decode_discovery_path(tag: u8) -> Result<FindingDiscoveryPath, EngineError> {
    match tag {
        0 => Ok(FindingDiscoveryPath::InteractiveFork),
        1 => Ok(FindingDiscoveryPath::StateSpaceSearch),
        2 => Ok(FindingDiscoveryPath::CoverageGuidedFuzzing),
        3 => Ok(FindingDiscoveryPath::RetainedCorpusEntry),
        _ => Err(scenario_serialization_error(
            "failure triage replay evidence has an invalid discovery path",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divergence_index_uses_a_portable_u64_wire_value() -> Result<(), EngineError> {
        let wire = FailureSourceWire::Divergence {
            raw_index: u64::from(u32::MAX) + 1,
            node: None,
            icount_node: None,
            icount: Icount { retired: 1 },
            source: EventSource::Engine,
            kind: String::from("portable-divergence-index"),
            expected_state_summary: String::from("expected"),
            reproduced_state_summary: String::from("reproduced"),
        };
        let bytes = bounded_json_bytes(&wire, MAX_FAILURE_SOURCE_BYTES, "test failure source")?;
        assert!(
            std::str::from_utf8(&bytes).is_ok_and(|json| json.contains("\"raw_index\":4294967296"))
        );

        let decoded = serde_json::from_slice::<FailureSourceWire>(&bytes)
            .map_err(|error| scenario_serialization_error(error.to_string()))?;
        let result = decoded.into_failure(ContentHash::default());
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            result?,
            FailureClusterReportFailure::Divergence(value)
                if value.raw_index == 4_294_967_296
        ));
        #[cfg(target_pointer_width = "32")]
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn bounded_sequence_decoder_rejects_before_growing_past_its_limit() {
        let result = serde_json::from_slice::<BoundedSequence<u8, 2>>(b"[0,1,2]");
        let error = match result {
            Ok(_) => panic!("the bounded sequence must reject a third entry"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("failure triage causal entry count exceeds limit")
        );
    }
}
