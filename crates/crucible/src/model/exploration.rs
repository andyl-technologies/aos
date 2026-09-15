//! Search, fuzzing, guidance, fleet work stealing, and unified operations.

use super::*;

#[path = "adaptive_campaign.rs"]
mod adaptive_campaign;
#[path = "app_random_branching.rs"]
mod app_random_branching;
#[path = "guidance_search.rs"]
mod guidance_search;

pub use adaptive_campaign::*;
pub use app_random_branching::*;
pub use guidance_search::*;

#[path = "exploration/failure_oracle.rs"]
mod failure_oracle;
#[path = "exploration/graph_operations.rs"]
mod graph_operations;
#[path = "exploration/guidance.rs"]
mod guidance;

pub use failure_oracle::*;
pub use graph_operations::{
    CoverageGuidedFuzzingEvidence, StateSpaceSearchEvidence, TemporalGraphReplayEvidence,
    TemporalGraphResumeEvidence, TemporalGraphSampledSearchRun, TemporalGraphSave,
    TemporalGraphSaveEvidence, TemporalGraphSearchRun, UnifiedGraphOperationEvidence,
    UnifiedGraphOperationKind, UnifiedGraphOperationReport,
};
pub(super) use graph_operations::{expect_content_hash, unified_operation_evidence_mismatch};
pub use guidance::*;

/// Result of an on-demand replay-oracle check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayOracleCheck {
    /// Configuration whose fat and thin checkpoint identities were compared.
    pub configuration: ContentHash,
    /// Content address of the supplied fat checkpoint.
    pub fat_checkpoint: ContentHash,
    /// Content address of the checkpoint reconstructed by thin replay.
    pub thin_checkpoint: ContentHash,
}

/// Bisection requested after an active-search replay-oracle mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchReplayOracleBisectionRequest {
    /// Stable search materialization sequence where the mismatch was observed.
    pub sequence: u64,
    /// Fat checkpoint whose sampled replay-oracle comparison failed.
    pub checkpoint: ContentHash,
    /// Stable reason for the bisection request.
    pub reason: &'static str,
}

/// Deterministic sampling report for active graph-search replay-oracle checks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SearchReplayOracleSamplingReport {
    /// Number of fat search materializations considered.
    pub considered: usize,
    /// Number of fat search materializations replay-oracle checked.
    pub sampled: usize,
    /// Number of fat search materializations not sampled.
    pub skipped: usize,
    /// Checkpoints selected by the deterministic sampler.
    pub sampled_checkpoints: Vec<ContentHash>,
}

/// One unique child produced by frontier decision enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrontierChild {
    /// Decision applied to the frontier configuration.
    pub decision: Decision,
    /// Child configuration produced by `step`.
    pub configuration: Configuration,
    /// Whether the child was already present in the temporal graph.
    pub already_recorded: bool,
}

/// Proof-carrying policy for graph-level frontier reductions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrontierReductionPolicy {
    /// Interchangeable node classes used for canonical-relabeling symmetry.
    pub symmetry_classes: SymmetryReductionClasses,
    /// Explicit independent decision pairs used for partial-order reduction.
    pub partial_order: PartialOrderReductionPolicy,
}

impl FrontierReductionPolicy {
    /// Builds a policy that explores every candidate.
    #[must_use]
    pub fn none() -> Self {
        Self {
            symmetry_classes: SymmetryReductionClasses::new(),
            partial_order: PartialOrderReductionPolicy::new(),
        }
    }

    /// Replaces the symmetry classes used for canonical relabeling.
    #[must_use]
    pub fn with_symmetry_classes(mut self, classes: SymmetryReductionClasses) -> Self {
        self.symmetry_classes = classes;
        self
    }

    /// Replaces the partial-order independence proof set.
    #[must_use]
    pub fn with_partial_order(mut self, partial_order: PartialOrderReductionPolicy) -> Self {
        self.partial_order = partial_order;
        self
    }
}

/// Why a frontier candidate was covered by a representative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrontierReductionReason {
    /// A prior frontier child had the same canonical-relabeling fingerprint.
    Symmetry,
    /// The candidate is the non-canonical ordering of independent decisions.
    PartialOrder,
}

/// A frontier child skipped because a representative already covers it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrontierCoveredChild {
    /// Decision that would have produced the covered child.
    pub decision: Decision,
    /// Covered child configuration produced by `step`.
    pub configuration: Configuration,
    /// Configuration id of the representative explored instead.
    pub representative: ContentHash,
    /// Reduction that justified the skip.
    pub reason: FrontierReductionReason,
    /// Content-addressed proof key for the reduction decision.
    pub reduction_key: ContentHash,
}

/// Reduced frontier enumeration result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrontierReductionReport {
    /// Children the search should explore.
    pub explored: Vec<FrontierChild>,
    /// Children covered by explored representatives.
    pub covered: Vec<FrontierCoveredChild>,
}

/// How a graph search chooses the next frontier checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SearchStrategy {
    /// Expands the shallowest pending checkpoint first.
    BreadthFirst,
    /// Expands the deepest pending checkpoint first.
    DepthFirst,
    /// Expands by a seeded deterministic priority score.
    Priority {
        /// Strategy-local seed used only to order the frontier.
        seed: Seed,
    },
    /// Expands by deterministic coverage feedback stored on checkpoints.
    CoverageGuided,
}

/// A finite budget for a strategy-driven graph search.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SearchBudget {
    /// Maximum number of frontier checkpoints to expand.
    pub max_expansions: u64,
}

impl SearchBudget {
    /// Builds a budget capped at `max_expansions` frontier expansions.
    #[must_use]
    pub const fn new(max_expansions: u64) -> Self {
        Self { max_expansions }
    }
}

/// One runtime RESOLVE frontier captured before its explorer-owned choice.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchRuntimeFrontier {
    /// Configuration after deterministic boundary decisions and before the choice.
    pub configuration: Configuration,
    /// Virtual-time coordinate of the RESOLVE boundary.
    pub at: VirtualTime,
    /// Alternative causal decision sequences accepted at this frontier.
    pub choices: SearchFrontierChoices,
}

/// Deterministic configuration for the shared-worklist fleet search model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FleetWorkStealingConfig {
    /// Total frontier-expansion budget shared by every host.
    pub total_budget: SearchBudget,
    /// Requested number of logical hosts competing for claims.
    pub host_count: u64,
    /// Seed used only to order host claims and work stealing.
    pub seed: Seed,
}

impl FleetWorkStealingConfig {
    /// Builds a deterministic fleet work-stealing configuration.
    #[must_use]
    pub const fn new(total_budget: SearchBudget, host_count: u64, seed: Seed) -> Self {
        Self {
            total_budget,
            host_count,
            seed,
        }
    }

    /// Returns the effective host count.
    ///
    /// A zero-host configuration is normalized to one host so callers cannot
    /// accidentally make the check depend on an absent host set.
    #[must_use]
    pub const fn host_count(self) -> u64 {
        if self.host_count == 0 {
            1
        } else {
            self.host_count
        }
    }
}

/// Configuration for a single-host coverage-guided fuzzing pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedFuzzConfig {
    /// Root seed for sampling, mutation, and deterministic candidate ordering.
    pub meta_seed: Seed,
    /// Maximum number of fuzz iterations to generate.
    pub iterations: u64,
}

impl CoverageGuidedFuzzConfig {
    /// Builds a coverage-guided fuzzing configuration.
    #[must_use]
    pub const fn new(meta_seed: Seed, iterations: u64) -> Self {
        Self {
            meta_seed,
            iterations,
        }
    }
}

/// Result of a deterministic coverage-guided fuzzing pass.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedFuzzRun {
    /// Configuration used by the pass.
    pub config: CoverageGuidedFuzzConfig,
    /// Iterations in generation order.
    pub iterations: Vec<CoverageGuidedFuzzIteration>,
    /// Candidate configuration ids ordered by coverage-guided priority.
    ///
    /// This is not corpus admission or pruning; T-ADV-13 owns durable corpus
    /// management. The order records the single-host bias T-ADV-12 uses before a
    /// real corpus is stored.
    pub coverage_biased_order: Vec<ContentHash>,
}

/// One generated coverage-guided fuzzing candidate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedFuzzIteration {
    /// Zero-based deterministic iteration sequence.
    pub sequence: u64,
    /// Finite family-space sample index selected for this iteration.
    pub sample_index: u64,
    /// Concrete family parameter point pinned for this iteration.
    pub params: FamilyParams,
    /// Concrete pinned scenario; fuzzing never executes the family directly.
    pub scenario: PinnedScenario,
    /// Corpus entry selected as the mutation parent for this iteration.
    pub selected_corpus_entry: ContentHash,
    /// Deterministic energy assigned to the selected mutation.
    pub energy: u64,
    /// Candidate configuration after schedule mutation.
    pub configuration: Configuration,
    /// Schedule mutation appended by this iteration.
    pub mutation: Decision,
    /// Coverage feedback fingerprint read by the fuzzing consumer.
    pub coverage_fingerprint: ContentHash,
    /// Whether this iteration is the first one in the run to see this coverage.
    pub new_coverage: bool,
}

impl CoverageGuidedFuzzIteration {
    /// Returns the content-addressed candidate id.
    #[must_use]
    pub fn configuration_id(&self) -> ContentHash {
        self.configuration.id()
    }

    /// Returns the complete reproduction schedule for this candidate.
    #[must_use]
    pub fn schedule(&self) -> &Schedule {
        &self.configuration.schedule
    }

    /// Emits a self-contained reproduction artifact for this fuzz candidate.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when artifact capture or replay validation fails.
    pub fn reproduction_artifact(
        &self,
        finding_fingerprint: ContentHash,
    ) -> Result<FindingReproductionArtifact, EngineError> {
        FindingReproductionArtifact::capture(
            FindingDiscoveryPath::CoverageGuidedFuzzing,
            finding_fingerprint,
            self.scenario.form(),
            &self.configuration,
        )
    }
}

/// Default deterministic T-ADV-13 smoke target for a local corpus campaign.
pub const DEFAULT_COVERAGE_GUIDED_FUZZ_THROUGHPUT_TARGET: u64 = 25;

/// Configuration for durable coverage-guided corpus management.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedCorpusConfig {
    /// Seed used for deterministic parent selection, pruning, and energy.
    pub seed: Seed,
    /// Deterministic throughput target used by local gates and reports.
    pub throughput_target: CoverageGuidedFuzzThroughputTarget,
}

impl CoverageGuidedCorpusConfig {
    /// Builds a corpus-management configuration with the default local target.
    #[must_use]
    pub const fn new(seed: Seed) -> Self {
        Self {
            seed,
            throughput_target: CoverageGuidedFuzzThroughputTarget::new(
                DEFAULT_COVERAGE_GUIDED_FUZZ_THROUGHPUT_TARGET,
            ),
        }
    }
}

/// Deterministic throughput target for a corpus fuzzing campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedFuzzThroughputTarget {
    /// Minimum generated mutants required by the local deterministic gate.
    pub min_generated_mutants: u64,
}

impl CoverageGuidedFuzzThroughputTarget {
    /// Builds a deterministic throughput target.
    #[must_use]
    pub const fn new(min_generated_mutants: u64) -> Self {
        Self {
            min_generated_mutants,
        }
    }
}

/// Durable coverage-guided corpus keyed by reproduction-artifact id.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoverageGuidedCorpus {
    pub(super) entries: BTreeMap<ContentHash, CoverageGuidedCorpusEntry>,
    pub(super) coverage_index: BTreeMap<ContentHash, ContentHash>,
}

impl CoverageGuidedCorpus {
    /// Builds an empty durable corpus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of retained corpus entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no corpus entries are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns retained entries ordered by artifact content address.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<ContentHash, CoverageGuidedCorpusEntry> {
        &self.entries
    }

    /// Returns the retained entry that owns `coverage`, if any.
    #[must_use]
    pub fn coverage_owner(&self, coverage: ContentHash) -> Option<ContentHash> {
        self.coverage_index.get(&coverage).copied()
    }

    /// Returns a deterministic fingerprint over retained artifact ids and energy.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        let material = self
            .entries
            .values()
            .map(|entry| {
                format!(
                    "artifact={}\ndescriptor={}\ncoverage={}\nenergy={}\n",
                    entry.artifact.to_hex(),
                    entry.descriptor_key.to_hex(),
                    entry.coverage_fingerprint.to_hex(),
                    entry.energy
                )
            })
            .collect::<String>();
        ContentHash::from_canonical_material("crucible.coverage-guided-corpus.v1", &material)
    }

    pub(super) fn insert(&mut self, entry: CoverageGuidedCorpusEntry) {
        self.coverage_index
            .insert(entry.coverage_fingerprint, entry.artifact);
        self.entries.insert(entry.artifact, entry);
    }
}

/// Origin of a retained coverage-guided corpus entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoverageGuidedCorpusEntryOrigin {
    /// Initial seed input retained before generated mutations.
    Seed,
    /// Entry admitted from one fuzz iteration.
    FuzzIteration {
        /// Zero-based fuzz iteration sequence.
        sequence: u64,
    },
}

/// One retained content-addressed corpus input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedCorpusEntry {
    /// Reproduction artifact id, equal to the DAG-store key for its bytes.
    pub artifact: ContentHash,
    /// DAG-store key containing the artifact's compact canonical bytes.
    pub store_key: ContentHash,
    /// DAG-store key containing corpus membership, coverage, and energy metadata.
    pub descriptor_key: ContentHash,
    /// Concrete pinned scenario id carried by the artifact.
    pub scenario: ContentHash,
    /// Recorded schedule hash carried by the artifact.
    pub schedule: ContentHash,
    /// Reduced state reached by replaying the artifact.
    pub replayed_state: ContentHash,
    /// Coverage fingerprint uniquely owned by this retained entry.
    pub coverage_fingerprint: ContentHash,
    /// Persisted deterministic mutation energy for parent selection.
    pub energy: u64,
    /// Parent corpus artifact selected for this entry.
    pub parent: Option<ContentHash>,
    /// How this entry entered the corpus.
    pub origin: CoverageGuidedCorpusEntryOrigin,
}

impl CoverageGuidedCorpusEntry {
    /// Reloads this retained corpus entry as a self-contained finding artifact.
    ///
    /// # Errors
    ///
    /// Returns [`FindingReproductionArtifactError::Store`] when `store` cannot
    /// read this entry's artifact bytes. Returns
    /// [`FindingReproductionArtifactError::Engine`] when the stored artifact is
    /// malformed or fails replay validation. Returns
    /// [`FindingReproductionArtifactError::RetainedCorpusEntryMismatch`] when
    /// the retained-entry descriptor fields do not match the stored artifact.
    pub fn reproduction_artifact<S>(
        &self,
        store: &S,
    ) -> Result<FindingReproductionArtifact, FindingReproductionArtifactError>
    where
        S: DagStore + ?Sized,
    {
        let finding = FindingReproductionArtifact::load_from_store(
            FindingDiscoveryPath::RetainedCorpusEntry,
            self.coverage_fingerprint,
            store,
            self.store_key,
        )?;
        let artifact = finding.artifact.id();
        if artifact != self.artifact {
            return Err(
                FindingReproductionArtifactError::RetainedCorpusEntryMismatch {
                    field: "artifact",
                    expected: self.artifact,
                    actual: artifact,
                },
            );
        }
        if artifact != self.store_key {
            return Err(
                FindingReproductionArtifactError::RetainedCorpusEntryMismatch {
                    field: "store_key",
                    expected: self.store_key,
                    actual: artifact,
                },
            );
        }
        if finding.replay.scenario != self.scenario {
            return Err(
                FindingReproductionArtifactError::RetainedCorpusEntryMismatch {
                    field: "scenario",
                    expected: self.scenario,
                    actual: finding.replay.scenario,
                },
            );
        }
        if finding.replay.schedule != self.schedule {
            return Err(
                FindingReproductionArtifactError::RetainedCorpusEntryMismatch {
                    field: "schedule",
                    expected: self.schedule,
                    actual: finding.replay.schedule,
                },
            );
        }
        if finding.replay.state != self.replayed_state {
            return Err(
                FindingReproductionArtifactError::RetainedCorpusEntryMismatch {
                    field: "replayed_state",
                    expected: self.replayed_state,
                    actual: finding.replay.state,
                },
            );
        }
        Ok(finding)
    }
}

/// Admission result for one generated corpus candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedCorpusAdmission {
    /// Zero-based fuzz iteration sequence.
    pub sequence: u64,
    /// Candidate reproduction artifact id.
    pub artifact: ContentHash,
    /// Coverage fingerprint reached by the candidate.
    pub coverage_fingerprint: ContentHash,
    /// Corpus parent chosen by seeded weighted energy.
    pub selected_parent: ContentHash,
    /// Deterministic candidate energy.
    pub energy: u64,
    /// Admission or deterministic pruning decision.
    pub decision: CoverageGuidedCorpusAdmissionDecision,
}

/// Durable-corpus admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoverageGuidedCorpusAdmissionDecision {
    /// Candidate reached coverage not owned by any retained entry and was stored.
    AdmittedNewCoverage {
        /// DAG-store key containing the admitted artifact bytes.
        store_key: ContentHash,
    },
    /// Candidate artifact was already retained.
    DuplicateArtifact {
        /// Existing retained artifact id.
        retained: ContentHash,
    },
    /// Candidate reached coverage already owned by a retained entry.
    PrunedSubsumedCoverage {
        /// Retained artifact that already owns this coverage fingerprint.
        retained: ContentHash,
    },
}

impl CoverageGuidedCorpusAdmissionDecision {
    /// Returns whether the candidate became a retained corpus entry.
    #[must_use]
    pub fn is_admitted(self) -> bool {
        matches!(self, Self::AdmittedNewCoverage { .. })
    }
}

/// Deterministic throughput and validation report for a corpus fuzzing run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedFuzzThroughputReport {
    /// Target checked by [`Self::meets_target`].
    pub target: CoverageGuidedFuzzThroughputTarget,
    /// Generated fuzz mutants, excluding the initial seed entry.
    pub generated_mutants: u64,
    /// Deterministic work units consumed by mutant generation.
    pub deterministic_work_units: u64,
    /// Reproduction replays validated, including the seed entry.
    pub replay_oracle_validations: u64,
    /// Logical DAG-store put attempts for retained corpus artifacts.
    pub store_puts: u64,
    /// Entries retained after coverage-driven admission/pruning.
    pub retained_entries: u64,
}

impl CoverageGuidedFuzzThroughputReport {
    /// Returns whether every generated mutant had replay validation evidence.
    #[must_use]
    pub fn oracle_validated_all_mutants(self) -> bool {
        self.replay_oracle_validations >= self.generated_mutants.saturating_add(1)
    }

    /// Returns whether the deterministic local throughput target was met.
    #[must_use]
    pub fn meets_target(self) -> bool {
        self.generated_mutants >= self.target.min_generated_mutants
            && self.deterministic_work_units == self.generated_mutants
            && self.oracle_validated_all_mutants()
    }
}

/// Result of a durable coverage-guided corpus fuzzing campaign.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoverageGuidedCorpusRun {
    /// Coverage-guided fuzz candidates in generation order.
    pub fuzz: CoverageGuidedFuzzRun,
    /// Retained content-addressed corpus entries.
    pub corpus: CoverageGuidedCorpus,
    /// Admission/pruning decision for each generated mutant.
    pub admissions: Vec<CoverageGuidedCorpusAdmission>,
    /// Deterministic throughput and replay-validation evidence.
    pub throughput: CoverageGuidedFuzzThroughputReport,
}

/// Error returned by durable coverage-guided corpus management.
#[derive(Debug)]
pub enum CoverageGuidedCorpusError {
    /// Engine-spine sampling, mutation, or replay validation failed.
    Engine {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying engine error.
        source: Box<EngineError>,
    },
    /// DAG-store persistence failed.
    Store {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying store error.
        source: DagStoreError,
    },
    /// A stored artifact key did not match the artifact's own id.
    ArtifactStoreKeyMismatch {
        /// Artifact id computed from canonical artifact bytes.
        artifact: ContentHash,
        /// Key returned by the DAG store.
        store_key: ContentHash,
    },
}

impl fmt::Display for CoverageGuidedCorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine { operation, .. } => {
                write!(
                    f,
                    "coverage-guided corpus engine operation {operation} failed"
                )
            }
            Self::Store { operation, .. } => {
                write!(
                    f,
                    "coverage-guided corpus store operation {operation} failed"
                )
            }
            Self::ArtifactStoreKeyMismatch { .. } => {
                f.write_str("coverage-guided corpus artifact key did not match stored bytes")
            }
        }
    }
}

impl Error for CoverageGuidedCorpusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine { source, .. } => Some(source.as_ref()),
            Self::Store { source, .. } => Some(source),
            Self::ArtifactStoreKeyMismatch { .. } => None,
        }
    }
}
