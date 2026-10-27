//! Portable evidence for independently observed failure-signature replays.
//!
//! A replay-evidence payload deliberately omits the reproduction bytes and the
//! replayed event log. Its caller supplies the authenticated
//! [`FindingReproductionArtifact`] named by the surrounding campaign object and
//! a [`SegmentSource`] holding the attempt-log segments the payload references.
//! Decoding binds the payload back to that exact artifact, streams the
//! referenced segments to rebuild the failure signature, and compares it with
//! the recorded report material instead of trusting it (RFC-0020 CMEAS-27).
//!
//! # Payload format
//!
//! ```text
//! magic         "CRUCIBLE_FAILURE_TRIAGE_REPLAY_EVIDENCE\0\x04"
//! u8            discovery path
//! hash          finding fingerprint
//! hash          configuration
//! hash          reproduction artifact
//! blob          failure source (canonical JSON, at most 1 MiB)
//! blob          expected attempt-log manifest (AttemptLogManifest::to_bytes)
//! u8            0 = single replay, 1 = paired divergence
//! [blob]        reproduced attempt-log manifest, paired divergence only
//! hash          coverage fingerprint
//! blob          failure-signature report material (UTF-8)
//! ```
//!
//! A single replay's log is its expected manifest. Paired divergence keeps both
//! complete logs; the signature reads the side that holds the first causal
//! mismatch.

use super::*;
use crate::attempt_log::{
    AttemptEventLogError, AttemptLogManifest, AttemptLogSegmentRef, MAX_ATTEMPT_LOG_MANIFEST_BYTES,
};
use crate::scheduler::{EventLogDeterminismMismatch, first_event_log_causal_mismatch};
use crate::segment_store::SegmentSource;
use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};

/// Latest schema version encoded by [`FailureTriageReplayEvidence::to_compact_binary`].
pub const FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION: u32 = 4;

// The final magic byte is the payload schema. This assertion keeps the public
// version used by campaign envelopes synchronized with the compact codec.
const FAILURE_TRIAGE_REPLAY_EVIDENCE_MAGIC: &[u8] =
    b"CRUCIBLE_FAILURE_TRIAGE_REPLAY_EVIDENCE\0\x04";
const _: () = assert!(
    FAILURE_TRIAGE_REPLAY_EVIDENCE_MAGIC[FAILURE_TRIAGE_REPLAY_EVIDENCE_MAGIC.len() - 1] as u32
        == FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
);
const MAX_FAILURE_SOURCE_BYTES: usize = 1024 * 1024;

// The report material no longer embeds the causal cone, only its hash and
// event count, so its size is set by the failure source and fixed-shape lines.
// This bound is a decoder guard, not a run-length limit.
const MAX_FAILURE_SIGNATURE_MATERIAL_BYTES: usize = 16 * 1024 * 1024;

/// Maximum canonical size of one portable failure replay-evidence payload.
///
/// The payload is a manifest: a bounded failure source, at most two attempt-log
/// manifests, and fixed-shape report material. It fits one 32 MiB campaign
/// storage chunk regardless of how long the replayed attempt ran.
pub const MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;

const _: () = assert!(
    FAILURE_TRIAGE_REPLAY_EVIDENCE_MAGIC.len()
        + 1
        + 1
        + 4 * 32
        + 6 * 8
        + MAX_FAILURE_SOURCE_BYTES
        + 2 * MAX_ATTEMPT_LOG_MANIFEST_BYTES
        + MAX_FAILURE_SIGNATURE_MATERIAL_BYTES
        <= MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES
);

/// Shared read access to the attempt-log segments replay evidence references.
pub type FailureTriageReplaySegments = RecordedEventLogSegments;

/// The replayed logs, exactly as the payload names them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayLogs {
    expected: AttemptLogManifest,
    reproduced: Option<AttemptLogManifest>,
}

/// Replay-owned inputs and the full failure signature recomputed from them.
#[derive(Clone)]
pub struct FailureTriageReplayEvidence {
    finding: FindingReproductionArtifact,
    failure: FailureClusterReportFailure,
    logs: ReplayLogs,
    coverage_fingerprint: ContentHash,
    recorded_event_log: FailureRecordedEventLog,
    signature: FailureSignature,
    segments: FailureTriageReplaySegments,
}

impl PartialEq for FailureTriageReplayEvidence {
    // The segment source is a read handle; the manifests name the content.
    fn eq(&self, other: &Self) -> bool {
        self.finding == other.finding
            && self.failure == other.failure
            && self.logs == other.logs
            && self.coverage_fingerprint == other.coverage_fingerprint
            && self.recorded_event_log == other.recorded_event_log
            && self.signature == other.signature
    }
}

impl Eq for FailureTriageReplayEvidence {}

impl fmt::Debug for FailureTriageReplayEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailureTriageReplayEvidence")
            .field("finding", &self.finding)
            .field("failure", &self.failure)
            .field("logs", &self.logs)
            .field("coverage_fingerprint", &self.coverage_fingerprint)
            .field("recorded_event_log", &self.recorded_event_log)
            .field("signature", &self.signature)
            .finish_non_exhaustive()
    }
}

/// The payload fields, decoded but not yet bound to a finding.
struct ReplayEvidenceWire<'a> {
    discovery_path: FindingDiscoveryPath,
    finding_fingerprint: ContentHash,
    configuration: ContentHash,
    artifact: ContentHash,
    failure: FailureClusterReportFailure,
    logs: ReplayLogs,
    coverage_fingerprint: ContentHash,
    signature_material: &'a str,
}

impl FailureTriageReplayEvidence {
    /// Builds evidence from one independently executed reproduction.
    ///
    /// `event_log` names the replay's sealed attempt log, whose segments
    /// `segments` supplies.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when a referenced segment is absent or fails
    /// authentication, when the failure source and log do not reconstruct a
    /// valid signature for `finding`, or when the canonical payload exceeds a
    /// fixed evidence bound.
    pub fn new(
        finding: FindingReproductionArtifact,
        failure: FailureClusterReportFailure,
        event_log: AttemptLogManifest,
        segments: FailureTriageReplaySegments,
        coverage_fingerprint: ContentHash,
    ) -> Result<Self, EngineError> {
        validate_failure_bounds(&failure)?;
        let recorded_event_log = FailureRecordedEventLog::from_segmented_log(
            &finding,
            event_log.clone(),
            segments.clone(),
            coverage_fingerprint,
        )?;
        let signature = recompute_failure_signature(&finding, &recorded_event_log, &failure)?;

        let value = Self {
            finding,
            failure,
            logs: ReplayLogs {
                expected: event_log,
                reproduced: None,
            },
            coverage_fingerprint,
            recorded_event_log,
            signature,
            segments,
        };
        value.encode()?;
        Ok(value)
    }

    /// Builds divergence evidence from two logs attributed to one reproduction.
    ///
    /// The logs are compared in lockstep, one segment at a time, until their
    /// first causal mismatch; the side holding that mismatch becomes the
    /// signature's recorded log. Both complete logs stay referenced, so the
    /// other side is streamed once more to authenticate every segment.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the logs have identical causal projections,
    /// a referenced segment is absent or fails authentication, or the
    /// reconstructed evidence is invalid.
    pub fn new_paired_divergence(
        finding: FindingReproductionArtifact,
        expected: AttemptLogManifest,
        reproduced: AttemptLogManifest,
        segments: FailureTriageReplaySegments,
        coverage_fingerprint: ContentHash,
    ) -> Result<Self, EngineError> {
        let source: &dyn SegmentSource = segments.as_ref();
        let mismatch =
            first_event_log_causal_mismatch(expected.entries(source), reproduced.entries(source))
                .map_err(attempt_log_error)?
                .ok_or_else(|| {
                    scenario_serialization_error(
                        "paired divergence logs have equal causal projections",
                    )
                })?;
        let failure = divergence_failure_from_mismatch(&mismatch)?;
        let (selected, other) = if mismatch.expected_location.is_some() {
            (&expected, &reproduced)
        } else {
            (&reproduced, &expected)
        };
        authenticate_log(other, source)?;

        let recorded_event_log = FailureRecordedEventLog::from_segmented_log(
            &finding,
            selected.clone(),
            segments.clone(),
            coverage_fingerprint,
        )?;
        let signature = recompute_failure_signature(&finding, &recorded_event_log, &failure)?;

        let value = Self {
            finding,
            failure,
            logs: ReplayLogs {
                expected,
                reproduced: Some(reproduced),
            },
            coverage_fingerprint,
            recorded_event_log,
            signature,
            segments,
        };
        value.encode()?;
        Ok(value)
    }

    /// Decodes evidence against its authenticated reproduction artifact.
    ///
    /// `segments` must supply every segment the payload references; see
    /// [`Self::referenced_segments_in`].
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] for malformed, noncanonical, oversized, or
    /// semantically inconsistent evidence, or for a referenced segment that is
    /// absent or fails authentication. The decoder reconstructs the signature
    /// from the streamed logs instead of trusting the serialized material.
    pub fn from_compact_binary(
        finding: FindingReproductionArtifact,
        bytes: &[u8],
        segments: FailureTriageReplaySegments,
    ) -> Result<Self, EngineError> {
        let wire = decode_wire(bytes)?;
        if wire.discovery_path != finding.discovery_path
            || wire.finding_fingerprint != finding.finding_fingerprint
            || wire.configuration != finding.configuration
            || wire.artifact != finding.artifact.id()
        {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-replay-evidence",
                reason: "replay evidence names another finding reproduction",
            });
        }

        let ReplayLogs {
            expected,
            reproduced,
        } = wire.logs;
        let value = if let Some(reproduced) = reproduced {
            let value = Self::new_paired_divergence(
                finding,
                expected,
                reproduced,
                segments,
                wire.coverage_fingerprint,
            )?;
            if value.failure != wire.failure {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-replay-evidence",
                    reason: "recorded divergence is not the paired logs' first causal mismatch",
                });
            }
            value
        } else {
            Self::new(
                finding,
                wire.failure,
                expected,
                segments,
                wire.coverage_fingerprint,
            )?
        };

        if value.signature.report_material() != wire.signature_material {
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

    /// Decodes evidence while reconstructing its finding from an authenticated reproduction.
    ///
    /// The compact replay evidence carries the discovery path and exact finding
    /// binding. This entry point is for content-addressed owners, such as a
    /// campaign repository, that retain the reproduction and fingerprint but do
    /// not separately retain Crucible's native finding wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the evidence is malformed, the retained
    /// fingerprint or reproduction disagrees with its binding, the
    /// reproduction cannot be replayed, or a referenced segment is absent or
    /// fails authentication.
    pub fn from_compact_binary_for_reproduction(
        finding_fingerprint: ContentHash,
        artifact: ReproductionArtifact,
        bytes: &[u8],
        segments: FailureTriageReplaySegments,
    ) -> Result<Self, EngineError> {
        let wire = decode_wire(bytes)?;
        let configuration = Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        };
        if wire.finding_fingerprint != finding_fingerprint
            || wire.configuration != configuration.id()
            || wire.artifact != artifact.id()
        {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-replay-evidence",
                reason: "replay evidence names another finding reproduction",
            });
        }

        let replay = artifact.replay()?;
        let finding = FindingReproductionArtifact {
            discovery_path: wire.discovery_path,
            finding_fingerprint,
            configuration: configuration.id(),
            artifact,
            replay,
        };
        Self::from_compact_binary(finding, bytes, segments)
    }

    /// Returns every attempt-log segment an encoded payload references, in log
    /// order and without duplicates.
    ///
    /// Owners call this to fetch or retain the segments before decoding. It
    /// checks the payload's structure, not its finding binding or signature.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] for a malformed or oversized payload.
    pub fn referenced_segments_in(bytes: &[u8]) -> Result<Vec<AttemptLogSegmentRef>, EngineError> {
        Ok(decode_wire(bytes)?.logs.referenced_segments())
    }

    /// Returns canonical bounded bytes for campaign retention.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the failure source
    /// cannot be encoded or the payload exceeds its bound.
    pub fn to_compact_binary(&self) -> Result<Vec<u8>, EngineError> {
        self.encode()
    }

    /// Returns the encoded payload schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
    }

    /// Returns whether `schema_version` is supported by this decoder.
    #[must_use]
    pub const fn supports_schema(schema_version: u32) -> bool {
        schema_version == FAILURE_TRIAGE_REPLAY_EVIDENCE_SCHEMA_VERSION
    }

    /// Returns the manifests of both complete logs retained for divergence
    /// evidence, expected first.
    #[must_use]
    pub fn paired_divergence_logs(&self) -> Option<(&AttemptLogManifest, &AttemptLogManifest)> {
        self.logs
            .reproduced
            .as_ref()
            .map(|reproduced| (&self.logs.expected, reproduced))
    }

    /// Returns the manifest of the log the signature was rebuilt from.
    #[must_use]
    pub fn event_log_manifest(&self) -> &AttemptLogManifest {
        self.recorded_event_log
            .event_log_manifest()
            .unwrap_or(&self.logs.expected)
    }

    /// Returns every attempt-log segment this evidence references, in log
    /// order and without duplicates.
    #[must_use]
    pub fn referenced_segments(&self) -> Vec<AttemptLogSegmentRef> {
        self.logs.referenced_segments()
    }

    /// Returns the source that supplies the referenced segments.
    #[must_use]
    pub fn log_segments(&self) -> &FailureTriageReplaySegments {
        &self.segments
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

    /// Returns the retained coverage fingerprint observed for this replay.
    #[must_use]
    pub const fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
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
        let failure = FailureSourceWire::from_failure(&self.failure)?;
        let failure =
            bounded_json_bytes(&failure, MAX_FAILURE_SOURCE_BYTES, "failure triage source")?;
        let signature_material = self.signature.report_material();
        if signature_material.len() > MAX_FAILURE_SIGNATURE_MATERIAL_BYTES {
            return Err(scenario_serialization_error(
                "failure triage signature material exceeds encoded size limit",
            ));
        }

        let mut writer = ScenarioBinaryWriter::new(FAILURE_TRIAGE_REPLAY_EVIDENCE_MAGIC);
        writer.write_u8(discovery_path_tag(self.finding.discovery_path));
        writer.write_hash(self.finding.finding_fingerprint);
        writer.write_hash(self.finding.configuration);
        writer.write_hash(self.finding.artifact.id());
        writer.write_binary_blob(&failure);
        writer.write_binary_blob(&self.logs.expected.to_bytes());
        if let Some(reproduced) = &self.logs.reproduced {
            writer.write_u8(1);
            writer.write_binary_blob(&reproduced.to_bytes());
        } else {
            writer.write_u8(0);
        }
        writer.write_hash(self.coverage_fingerprint);
        writer.write_binary_blob(signature_material.as_bytes());

        let bytes = writer.finish();
        if bytes.len() > MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES {
            return Err(scenario_serialization_error(
                "failure triage replay evidence exceeds canonical size limit",
            ));
        }
        Ok(bytes)
    }
}

impl ReplayLogs {
    fn referenced_segments(&self) -> Vec<AttemptLogSegmentRef> {
        let mut seen = BTreeSet::new();
        self.expected
            .segments()
            .iter()
            .chain(self.reproduced.iter().flat_map(|log| log.segments()))
            .filter(|segment| seen.insert(segment.id))
            .copied()
            .collect()
    }
}

fn decode_wire(bytes: &[u8]) -> Result<ReplayEvidenceWire<'_>, EngineError> {
    if bytes.len() > MAX_FAILURE_TRIAGE_REPLAY_EVIDENCE_BYTES {
        return Err(scenario_serialization_error(
            "failure triage replay evidence exceeds canonical size limit",
        ));
    }

    let mut reader = ScenarioBinaryReader::new(bytes, FAILURE_TRIAGE_REPLAY_EVIDENCE_MAGIC)?;
    let discovery_path = decode_discovery_path(reader.read_u8()?)?;
    let finding_fingerprint = reader.read_hash()?;
    let configuration = reader.read_hash()?;
    let artifact = reader.read_hash()?;
    let failure = decode_failure_source(&mut reader, artifact)?;
    let expected = decode_manifest(&mut reader, "failure triage expected log")?;
    let reproduced = match reader.read_u8()? {
        0 => None,
        1 => Some(decode_manifest(
            &mut reader,
            "failure triage reproduced log",
        )?),
        _ => {
            return Err(scenario_serialization_error(
                "failure triage replay evidence has an invalid replay-log tag",
            ));
        }
    };
    let coverage_fingerprint = reader.read_hash()?;
    let signature_material = reader.read_binary_blob_bounded(
        "failure triage signature material",
        MAX_FAILURE_SIGNATURE_MATERIAL_BYTES,
    )?;
    let signature_material = std::str::from_utf8(signature_material).map_err(|error| {
        scenario_serialization_error(format!(
            "failure triage signature material is not UTF-8: {error}"
        ))
    })?;
    reader.finish()?;

    Ok(ReplayEvidenceWire {
        discovery_path,
        finding_fingerprint,
        configuration,
        artifact,
        failure,
        logs: ReplayLogs {
            expected,
            reproduced,
        },
        coverage_fingerprint,
        signature_material,
    })
}

fn decode_manifest(
    reader: &mut ScenarioBinaryReader<'_>,
    label: &'static str,
) -> Result<AttemptLogManifest, EngineError> {
    let bytes = reader.read_binary_blob_bounded(label, MAX_ATTEMPT_LOG_MANIFEST_BYTES)?;
    AttemptLogManifest::from_bytes(bytes)
        .map_err(|error| scenario_serialization_error(format!("decode {label}: {error}")))
}

fn attempt_log_error(error: AttemptEventLogError) -> EngineError {
    scenario_serialization_error(format!("failure triage replay log is unreadable: {error}"))
}

/// Streams `log` once so every segment is read and authenticated.
fn authenticate_log(
    log: &AttemptLogManifest,
    source: &dyn SegmentSource,
) -> Result<(), EngineError> {
    log.try_for_each_entry(source, |_| Ok::<(), AttemptEventLogError>(()))
        .map_err(attempt_log_error)
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
        tick: SimInstant,
        icount: Option<Icount>,
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
                tick: divergence.tick,
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
                tick,
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
                tick,
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

fn divergence_failure_from_mismatch(
    mismatch: &EventLogDeterminismMismatch,
) -> Result<FailureClusterReportFailure, EngineError> {
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
        FindingDiscoveryPath::CampaignFork => 0,
        FindingDiscoveryPath::StateSpaceSearch => 1,
        FindingDiscoveryPath::CoverageGuidedFuzzing => 2,
        FindingDiscoveryPath::RetainedCorpusEntry => 3,
    }
}

fn decode_discovery_path(tag: u8) -> Result<FindingDiscoveryPath, EngineError> {
    match tag {
        0 => Ok(FindingDiscoveryPath::CampaignFork),
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
            tick: SimInstant { ticks: 50 },
            icount: Some(Icount { retired: 1 }),
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
}
