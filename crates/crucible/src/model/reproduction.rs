//! Finding reconstruction, minimization, and reproduction replay.

use super::*;

/// Error returned when rebuilding a finding reproduction artifact from storage.
#[derive(Debug)]
pub enum FindingReproductionArtifactError {
    /// Engine-spine decoding or replay validation failed.
    Engine {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying engine error.
        source: Box<EngineError>,
    },
    /// DAG-store retrieval failed.
    Store {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying store error.
        source: DagStoreError,
    },
    /// Stored artifact replay did not match retained corpus entry metadata.
    RetainedCorpusEntryMismatch {
        /// Retained-entry field whose value diverged.
        field: &'static str,
        /// Value recorded in the retained entry metadata.
        expected: ContentHash,
        /// Value recomputed from the stored self-contained artifact.
        actual: ContentHash,
    },
}

impl fmt::Display for FindingReproductionArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine { operation, .. } => {
                write!(
                    f,
                    "finding reproduction artifact operation {operation} failed"
                )
            }
            Self::Store { operation, .. } => {
                write!(
                    f,
                    "finding reproduction artifact store operation {operation} failed"
                )
            }
            Self::RetainedCorpusEntryMismatch { field, .. } => {
                write!(
                    f,
                    "finding reproduction artifact retained corpus entry {field} metadata did not match stored artifact"
                )
            }
        }
    }
}

impl Error for FindingReproductionArtifactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine { source, .. } => Some(source.as_ref()),
            Self::Store { source, .. } => Some(source),
            Self::RetainedCorpusEntryMismatch { .. } => None,
        }
    }
}

/// Configuration for deterministic finding minimization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinimizationConfig {
    /// Seed used to order candidate removals with content-address tie-breaks.
    pub seed: Seed,
}

impl MinimizationConfig {
    /// Builds a minimization configuration.
    #[must_use]
    pub const fn new(seed: Seed) -> Self {
        Self { seed }
    }
}

/// One replay-validated candidate considered by minimization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MinimizationAttempt {
    /// Deterministic attempt sequence number.
    pub sequence: u64,
    /// Original schedule decision indexes removed for this candidate.
    pub removed_indices: Vec<usize>,
    /// Original schedule decisions removed for this candidate.
    pub removed_decisions: Vec<Decision>,
    /// Candidate self-contained artifact id.
    pub candidate_artifact: ContentHash,
    /// Candidate schedule content address.
    pub candidate_schedule: ContentHash,
    /// State reached by replaying the candidate artifact.
    pub replayed_state: ContentHash,
    /// Failure fingerprint observed by the oracle for this candidate.
    pub observed_fingerprint: Option<ContentHash>,
    /// Whether the candidate preserved the target failure and was accepted.
    pub accepted: bool,
}

/// Result of deterministic failure-preserving minimization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MinimizationRun {
    /// Seed used for candidate ordering.
    pub seed: Seed,
    /// Failure fingerprint that every accepted candidate preserves.
    pub target_fingerprint: ContentHash,
    /// Original self-contained finding artifact.
    pub original: FindingReproductionArtifact,
    /// Stable minimized self-contained finding artifact.
    pub minimized: FindingReproductionArtifact,
    /// Replay-validated candidates considered in deterministic order.
    pub attempts: Vec<MinimizationAttempt>,
}

impl MinimizationRun {
    /// Returns the number of accepted shrink candidates.
    #[must_use]
    pub fn accepted_attempts(&self) -> usize {
        self.attempts
            .iter()
            .filter(|attempt| attempt.accepted)
            .count()
    }

    /// Returns whether minimization removed at least one recorded decision.
    #[must_use]
    pub fn shrank(&self) -> bool {
        self.minimized.artifact.schedule().len() < self.original.artifact.schedule().len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct MinimizationCandidate {
    pub(super) removed_indices: Vec<usize>,
    pub(super) removed_decisions: Vec<Decision>,
    pub(super) schedule: Schedule,
    pub(super) order_key: ContentHash,
}

/// Successful replay-oracle verification of a reproduction artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionReplay {
    /// The artifact whose replay was verified.
    pub artifact: ContentHash,
    /// The embedded scenario definition id used for replay.
    pub scenario: ContentHash,
    /// The embedded recorded-schedule id used for replay.
    pub schedule: ContentHash,
    /// The reduced state reached by replay.
    pub state: ContentHash,
}

/// Compact event-log debugging artifact attached to a reproduction artifact.
///
/// This record is the event-log fork-point index plus a digest of the original
/// causal subsequence and coverage projection. It deliberately omits the full
/// log bytes: replay recomputes the log from `(seed, scenario, schedule)` and
/// compares the recomputed projections to this metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionEventLogArtifact {
    pub(super) id: ContentHash,
    /// The reproduction artifact this log metadata belongs to.
    pub reproduction_artifact: ContentHash,
    /// Event-log offset used as the debugging fork-point index.
    pub fork_point: EventLogOffset,
    /// Content hash of the original run's canonical causal subsequence bytes.
    pub causal_subsequence: ContentHash,
    /// Byte length of the original run's canonical causal subsequence.
    pub causal_subsequence_bytes: usize,
    /// Number of causal entries retained by the original run's causal projection.
    pub causal_subsequence_events: usize,
    /// Content hash of the original run's coverage-observation projection.
    pub coverage_fingerprint: ContentHash,
    /// Shared-store event-log segment keys, when retained by content address.
    pub shared_store_segments: Vec<ContentHash>,
}

impl ReproductionEventLogArtifact {
    /// Builds event-log metadata from an already-computed causal projection.
    #[must_use]
    pub fn from_causal_projection<I>(
        reproduction_artifact: ContentHash,
        fork_point: EventLogOffset,
        causal_subsequence: ContentHash,
        causal_subsequence_bytes: usize,
        causal_subsequence_events: usize,
        coverage_fingerprint: ContentHash,
        shared_store_segments: I,
    ) -> Self
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let shared_store_segments =
            sorted_unique_hashes(shared_store_segments.into_iter().collect());
        let id = reproduction_event_log_artifact_id(
            reproduction_artifact,
            fork_point,
            causal_subsequence,
            causal_subsequence_bytes,
            causal_subsequence_events,
            coverage_fingerprint,
            &shared_store_segments,
        );
        Self {
            id,
            reproduction_artifact,
            fork_point,
            causal_subsequence,
            causal_subsequence_bytes,
            causal_subsequence_events,
            coverage_fingerprint,
            shared_store_segments,
        }
    }

    /// Returns the content address of this compact event-log metadata record.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }
}

/// Result of checking a recomputed event log against reproduction metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionEventLogReplay {
    /// Reduction replay for the reproduction artifact's scenario/schedule.
    pub reduction: ReproductionReplay,
    /// Event-log metadata record used for the comparison.
    pub event_log_artifact: ContentHash,
    /// Whether the metadata belongs to the replayed reproduction artifact.
    pub artifact_matches: bool,
    /// Event-log offset used as the debugging fork-point index.
    pub fork_point: EventLogOffset,
    /// Expected causal-subsequence digest from the original run.
    pub expected_causal_subsequence: ContentHash,
    /// Causal-subsequence digest recomputed by replay.
    pub reproduced_causal_subsequence: ContentHash,
    /// Expected canonical causal-subsequence byte length.
    pub expected_causal_bytes: usize,
    /// Recomputed canonical causal-subsequence byte length.
    pub reproduced_causal_bytes: usize,
    /// Expected causal event count.
    pub expected_causal_events: usize,
    /// Recomputed causal event count.
    pub reproduced_causal_events: usize,
    /// Expected coverage fingerprint from the original run.
    pub expected_coverage_fingerprint: ContentHash,
    /// Coverage fingerprint recomputed by replay.
    pub reproduced_coverage_fingerprint: ContentHash,
    /// Shared-store event-log segment keys named by the metadata.
    pub shared_store_segments: Vec<ContentHash>,
}

impl ReproductionEventLogReplay {
    /// Returns whether the recomputed replay log matches the original metadata.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.artifact_matches
            && self.expected_causal_subsequence == self.reproduced_causal_subsequence
            && self.expected_causal_bytes == self.reproduced_causal_bytes
            && self.expected_causal_events == self.reproduced_causal_events
            && self.expected_coverage_fingerprint == self.reproduced_coverage_fingerprint
    }
}
