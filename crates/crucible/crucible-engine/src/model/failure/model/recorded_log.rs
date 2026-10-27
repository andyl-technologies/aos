//! Checked event-log evidence for failure-signature construction.
//!
//! [`FailureRecordedEventLog`] binds a reproduction to the event log replayed
//! for it. The log is read, never held whole by this type: a resident log
//! shares the caller's entries, and a segmented log keeps an
//! [`AttemptLogManifest`] with a segment source and decodes one segment at a
//! time. Construction streams the log once to count it and once to derive its
//! causal-projection identity; signature construction streams it again for
//! each fold it needs, so memory never grows with the log (RFC-0020 CMEAS-22).

use std::fmt;
use std::ops::{ControlFlow, RangeInclusive};
use std::sync::Arc;

use super::*;
use crate::attempt_log::AttemptLogManifest;
use crate::model::canonical::CanonicalMaterialStream;
use crate::scheduler::{EventLogCausalDigest, EventLogCausalSummary, is_causal_event_log_entry};
use crate::segment_store::SegmentSource;
use crate::trigger::RecordedLogShape;

/// Shared read access to the segments a segmented recorded log references.
pub type RecordedEventLogSegments = Arc<dyn SegmentSource + Send + Sync>;

/// Where a recorded log's entries are read from.
#[derive(Clone)]
pub(in crate::model) enum RecordedEntries {
    /// Entries already resident in the caller, shared without copying.
    Resident(Arc<[SchedulerEventLogEntry]>),
    /// A sealed attempt log read one authenticated segment at a time.
    Segmented {
        manifest: AttemptLogManifest,
        segments: RecordedEventLogSegments,
    },
}

impl RecordedEntries {
    /// Visits entries in log order until `visit` breaks.
    fn try_for_each(
        &self,
        mut visit: impl FnMut(&SchedulerEventLogEntry) -> Result<ControlFlow<()>, EngineError>,
    ) -> Result<(), EngineError> {
        match self {
            Self::Resident(entries) => {
                for entry in entries.iter() {
                    if visit(entry)?.is_break() {
                        break;
                    }
                }
            }
            Self::Segmented { manifest, segments } => {
                let source: &dyn SegmentSource = segments.as_ref();
                for entry in manifest.entries(source) {
                    let entry = entry.map_err(|error| {
                        scenario_serialization_error(format!(
                            "recorded event log is unreadable: {error}"
                        ))
                    })?;
                    if visit(&entry)?.is_break() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns whether both name the same log: equal resident entries or an
    /// equal manifest. Segment sources are read handles, not content.
    fn same_log(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Resident(left), Self::Resident(right)) => left == right,
            (
                Self::Segmented { manifest: left, .. },
                Self::Segmented {
                    manifest: right, ..
                },
            ) => left == right,
            _ => false,
        }
    }
}

/// Checked event-log evidence for failure-signature construction.
///
/// This value binds the supplied event log to the
/// [`ReproductionEventLogArtifact`] recorded for the same reproduction
/// artifact. It retains the log's causal-projection identity and read access
/// to its entries, which signature construction streams to recheck
/// host-derived violations and to fold the causal cone.
#[derive(Clone)]
pub struct FailureRecordedEventLog {
    pub(in crate::model) artifact: ContentHash,
    pub(in crate::model) event_log_artifact: ContentHash,
    pub(in crate::model) causal_subsequence: ContentHash,
    pub(in crate::model) causal_subsequence_events: usize,
    pub(in crate::model) coverage_fingerprint: ContentHash,
    pub(in crate::model) evidence_binding: ContentHash,
    pub(in crate::model) shape: RecordedLogShape,
    pub(in crate::model) entries: RecordedEntries,
}

impl PartialEq for FailureRecordedEventLog {
    fn eq(&self, other: &Self) -> bool {
        self.artifact == other.artifact
            && self.event_log_artifact == other.event_log_artifact
            && self.causal_subsequence == other.causal_subsequence
            && self.causal_subsequence_events == other.causal_subsequence_events
            && self.coverage_fingerprint == other.coverage_fingerprint
            && self.evidence_binding == other.evidence_binding
            && self.shape == other.shape
            && self.entries.same_log(&other.entries)
    }
}

impl Eq for FailureRecordedEventLog {}

impl fmt::Debug for FailureRecordedEventLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("FailureRecordedEventLog");
        debug
            .field("artifact", &self.artifact)
            .field("event_log_artifact", &self.event_log_artifact)
            .field("causal_subsequence", &self.causal_subsequence)
            .field("causal_subsequence_events", &self.causal_subsequence_events)
            .field("coverage_fingerprint", &self.coverage_fingerprint)
            .field("evidence_binding", &self.evidence_binding)
            .field("shape", &self.shape);
        match &self.entries {
            RecordedEntries::Resident(entries) => debug.field("resident_entries", &entries.len()),
            RecordedEntries::Segmented { manifest, .. } => debug.field("manifest", manifest),
        };
        debug.finish()
    }
}

/// Identity of a log derived in two streamed passes.
struct RecordedLogSummary {
    shape: RecordedLogShape,
    causal: EventLogCausalSummary,
    evidence_binding: ContentHash,
}

/// Domain of [`RecordedLogSummary::evidence_binding`].
const EVIDENCE_BINDING_DOMAIN: &str = "crucible.failure-recorded-evidence.v2";

/// Counts the log, digests its causal projection, and binds that projection.
///
/// The projection encoding carries the entry count first, so the count pass
/// must finish before the digest pass starts. The binding covers the causal
/// projection and coverage only: like the signature it feeds, it omits raw
/// observational entries, so independent replays that differ only in
/// diagnostics share one signature. It never depends on how a sealed log split
/// its entries into segments, so a resident and a segmented copy of one log
/// bind identically.
fn summarize(
    entries: &RecordedEntries,
    coverage_fingerprint: ContentHash,
) -> Result<RecordedLogSummary, EngineError> {
    let mut count = 0_u64;
    let mut causal = 0_u64;
    let mut final_at = None;
    entries.try_for_each(|entry| {
        count += 1;
        if is_causal_event_log_entry(entry) {
            causal += 1;
        }
        final_at = Some(entry.at());
        Ok(ControlFlow::Continue(()))
    })?;

    let mut digest = EventLogCausalDigest::new(causal);
    entries.try_for_each(|entry| {
        digest.observe(entry);
        Ok(ControlFlow::Continue(()))
    })?;
    let causal = digest.finish().ok_or_else(|| {
        scenario_serialization_error("recorded event log changed between its two passes")
    })?;

    let hash_len = ContentHash::default().bytes.len() as u64;
    let mut binding = CanonicalMaterialStream::new(EVIDENCE_BINDING_DOMAIN, 2 * hash_len);
    binding.write(&causal.content_hash.bytes);
    binding.write(&coverage_fingerprint.bytes);
    let evidence_binding = binding
        .finish()
        .ok_or_else(|| scenario_serialization_error("evidence binding material is malformed"))?;

    Ok(RecordedLogSummary {
        shape: RecordedLogShape::with_final_time(count, final_at),
        causal,
        evidence_binding,
    })
}

impl FailureRecordedEventLog {
    /// Builds checked signature evidence from retained causal entries and an
    /// independently reconstructed coverage fingerprint.
    ///
    /// This is the adapter boundary used when a remote event stream retains
    /// exact causal events while coverage observations are transported through
    /// the shared coverage-feedback projection.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when the finding's
    /// embedded reproduction identity is inconsistent.
    pub fn from_causal_entries_and_coverage(
        finding: &FindingReproductionArtifact,
        causal_entries: &[SchedulerEventLogEntry],
        coverage_fingerprint: ContentHash,
    ) -> Result<Self, EngineError> {
        Self::from_entries(
            finding,
            RecordedEntries::Resident(Arc::from(causal_entries)),
            coverage_fingerprint,
        )
    }

    /// Builds checked signature evidence over a sealed attempt log.
    ///
    /// Each segment is read from `segments` and authenticated against
    /// `manifest` whenever the log is streamed, here and during signature
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when the finding's
    /// embedded reproduction identity is inconsistent, or
    /// [`EngineError::ScenarioSerialization`] when a segment is absent or
    /// fails authentication.
    pub fn from_segmented_log(
        finding: &FindingReproductionArtifact,
        manifest: AttemptLogManifest,
        segments: RecordedEventLogSegments,
        coverage_fingerprint: ContentHash,
    ) -> Result<Self, EngineError> {
        Self::from_entries(
            finding,
            RecordedEntries::Segmented { manifest, segments },
            coverage_fingerprint,
        )
    }

    fn from_entries(
        finding: &FindingReproductionArtifact,
        entries: RecordedEntries,
        coverage_fingerprint: ContentHash,
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        let summary = summarize(&entries, coverage_fingerprint)?;
        let causal = summary.causal;
        let event_log_artifact = ReproductionEventLogArtifact::from_causal_projection(
            finding.artifact.id(),
            EventLogOffset::new(ContentHash::default(), 0, 0),
            causal.content_hash,
            causal.canonical_bytes,
            causal.entries,
            coverage_fingerprint,
            Vec::new(),
        );

        Ok(Self {
            artifact: finding.artifact.id(),
            event_log_artifact: event_log_artifact.id(),
            causal_subsequence: causal.content_hash,
            causal_subsequence_events: causal.entries,
            coverage_fingerprint,
            evidence_binding: summary.evidence_binding,
            shape: summary.shape,
            entries,
        })
    }

    /// Builds checked signature evidence from recorded event-log entries.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] when `finding`,
    /// `event_log_artifact`, and the supplied `event_log` do not identify the
    /// same reproduction artifact and causal subsequence. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when non-hash projection
    /// metadata is inconsistent.
    pub fn from_recorded_artifact(
        finding: &FindingReproductionArtifact,
        event_log_artifact: &ReproductionEventLogArtifact,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        let artifact = finding.artifact.id();
        if event_log_artifact.reproduction_artifact != artifact {
            return Err(EngineError::ReplayTargetMismatch {
                expected: artifact,
                actual: event_log_artifact.reproduction_artifact,
            });
        }

        let entries = RecordedEntries::Resident(Arc::from(event_log));
        let summary = summarize(&entries, event_log_artifact.coverage_fingerprint)?;
        let causal = summary.causal;
        if causal.content_hash != event_log_artifact.causal_subsequence {
            return Err(EngineError::ReplayTargetMismatch {
                expected: event_log_artifact.causal_subsequence,
                actual: causal.content_hash,
            });
        }
        if causal.canonical_bytes != event_log_artifact.causal_subsequence_bytes {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.event-log",
                reason: "causal subsequence byte length does not match recorded metadata",
            });
        }
        if causal.entries != event_log_artifact.causal_subsequence_events {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.event-log",
                reason: "causal subsequence event count does not match recorded metadata",
            });
        }
        let coverage_fingerprint = coverage_fingerprint_from_event_log(event_log);
        if coverage_fingerprint != event_log_artifact.coverage_fingerprint {
            return Err(EngineError::ReplayTargetMismatch {
                expected: event_log_artifact.coverage_fingerprint,
                actual: coverage_fingerprint,
            });
        }

        Ok(Self {
            artifact,
            event_log_artifact: event_log_artifact.id(),
            causal_subsequence: causal.content_hash,
            causal_subsequence_events: causal.entries,
            coverage_fingerprint: event_log_artifact.coverage_fingerprint,
            evidence_binding: summary.evidence_binding,
            shape: summary.shape,
            entries,
        })
    }

    /// Returns the reproduction artifact this checked log belongs to.
    #[must_use]
    pub fn artifact(&self) -> ContentHash {
        self.artifact
    }

    /// Returns the content address of the event-log metadata record.
    #[must_use]
    pub fn event_log_artifact(&self) -> ContentHash {
        self.event_log_artifact
    }

    /// Returns the recorded causal-subsequence hash.
    #[must_use]
    pub fn causal_subsequence(&self) -> ContentHash {
        self.causal_subsequence
    }

    /// Returns the number of causal events retained by the projection.
    #[must_use]
    pub fn causal_subsequence_events(&self) -> usize {
        self.causal_subsequence_events
    }

    /// Returns the number of entries in the recorded log.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.shape.entries()
    }

    /// Returns the sealed log's manifest, or `None` for a resident log.
    #[must_use]
    pub fn event_log_manifest(&self) -> Option<&AttemptLogManifest> {
        match &self.entries {
            RecordedEntries::Resident(_) => None,
            RecordedEntries::Segmented { manifest, .. } => Some(manifest),
        }
    }

    /// Returns the recorded deterministic coverage fingerprint validated against the log.
    #[must_use]
    pub fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
    }

    /// Returns the binding over every recorded entry, the causal projection,
    /// and coverage.
    #[must_use]
    pub fn evidence_binding(&self) -> ContentHash {
        self.evidence_binding
    }

    /// Returns the bucketed failure coverage class for this recorded log.
    #[must_use]
    pub fn coverage_class(&self) -> FailureCoverageClass {
        FailureCoverageClass::from_coverage_fingerprint(self.coverage_fingerprint)
    }

    /// Builds a symmetry canonicalizer bound to this log's recorded coverage.
    #[must_use]
    pub fn symmetry_canonicalizer(
        &self,
        normalization: &FailureSignatureNormalization,
    ) -> FailureSymmetryCanonicalizer {
        FailureSymmetryCanonicalizer::new(
            self.coverage_fingerprint,
            normalization.symmetry_classes.clone(),
        )
    }

    /// Visits every recorded entry in log order.
    ///
    /// A segmented log decodes one authenticated segment at a time.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a segment is absent
    /// or fails authentication, or the first error `visit` returns.
    pub fn try_for_each_entry(
        &self,
        mut visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), EngineError>,
    ) -> Result<(), EngineError> {
        self.entries.try_for_each(|entry| {
            visit(entry)?;
            Ok(ControlFlow::Continue(()))
        })
    }

    /// Visits raw entries with their log positions until `visit` breaks.
    pub(in crate::model) fn try_for_each_raw(
        &self,
        mut visit: impl FnMut(usize, &SchedulerEventLogEntry) -> Result<ControlFlow<()>, EngineError>,
    ) -> Result<(), EngineError> {
        let mut raw_index = 0_usize;
        self.entries.try_for_each(|entry| {
            let flow = visit(raw_index, entry)?;
            raw_index = raw_index.saturating_add(1);
            Ok(flow)
        })
    }

    /// Visits the renumbered causal projection until `visit` breaks.
    ///
    /// Each projected entry carries its raw position and its causal-index
    /// renumbering, exactly as [`event_log_causal_projection`] builds them.
    pub(in crate::model) fn try_for_each_causal(
        &self,
        mut visit: impl FnMut(
            usize,
            &crate::scheduler::EventLogCausalProjectionEntry,
        ) -> Result<ControlFlow<()>, EngineError>,
    ) -> Result<(), EngineError> {
        let mut causal_index = 0_usize;
        self.try_for_each_raw(|raw_index, entry| {
            if !is_causal_event_log_entry(entry) {
                return Ok(ControlFlow::Continue(()));
            }
            let projected = crate::scheduler::EventLogCausalProjectionEntry {
                raw_index,
                entry: crate::scheduler::causal_projection_entry(causal_index as u64, entry),
            };
            let flow = visit(causal_index, &projected)?;
            causal_index = causal_index.saturating_add(1);
            Ok(flow)
        })
    }

    /// Returns the projected causal entries whose indices fall in `range`.
    pub(in crate::model) fn causal_window(
        &self,
        range: RangeInclusive<usize>,
    ) -> Result<Vec<crate::scheduler::EventLogCausalProjectionEntry>, EngineError> {
        let mut window = Vec::new();
        self.try_for_each_causal(|index, entry| {
            if range.contains(&index) {
                window.push(entry.clone());
            }
            Ok(if index >= *range.end() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            })
        })?;
        Ok(window)
    }

    /// Returns the projected causal entry at `index`, when it exists.
    pub(in crate::model) fn causal_entry(
        &self,
        index: usize,
    ) -> Result<Option<crate::scheduler::EventLogCausalProjectionEntry>, EngineError> {
        Ok(self.causal_window(index..=index)?.pop())
    }
}
