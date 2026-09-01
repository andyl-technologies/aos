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

    /// Returns this configuration with an explicit deterministic throughput target.
    #[must_use]
    pub const fn with_throughput_target(
        mut self,
        throughput_target: CoverageGuidedFuzzThroughputTarget,
    ) -> Self {
        self.throughput_target = throughput_target;
        self
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

/// Built-in deterministic guidance signal identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuidanceSignalKind {
    /// Coverage projection feedback from the unified event log.
    Coverage,
    /// Inverse-frequency novelty over a deterministic rarity table.
    NoveltyRarity,
    /// Assertion-proximity progress from observational event-log entries.
    AssertionProximity,
}

/// Input material read by guidance signals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceSignalInput {
    /// Coverage projection fingerprint for the candidate checkpoint.
    pub coverage_fingerprint: ContentHash,
    /// Number of times the candidate's novelty key has already appeared.
    pub rarity_count: u64,
    /// Best remaining assertion-proximity distance, if known.
    pub assertion_proximity_distance: Option<u64>,
}

/// A deterministic fixed-point guidance score.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuidanceScore {
    /// Integer micro-units; guidance never uses floating-point scores.
    pub micros: u64,
}

/// Read-only scoring signal for guided exploration.
pub trait GuidanceSignal {
    /// Returns the stable built-in signal identity.
    fn kind(&self) -> GuidanceSignalKind;

    /// Returns the deterministic fixed-point score for `input`.
    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore;
}

/// Coverage-only guidance signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoverageGuidanceSignal;

impl GuidanceSignal for CoverageGuidanceSignal {
    fn kind(&self) -> GuidanceSignalKind {
        GuidanceSignalKind::Coverage
    }

    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        if input.coverage_fingerprint == ContentHash::default() {
            return GuidanceScore { micros: 0 };
        }

        GuidanceScore {
            micros: u64::MAX - content_hash_low_u64(input.coverage_fingerprint),
        }
    }
}

impl CoverageGuidanceSignal {
    /// Returns the exact ordering key used by existing coverage-guided search.
    #[must_use]
    pub fn search_order_key(&self, input: GuidanceSignalInput) -> (u8, ContentHash) {
        let unknown_coverage = u8::from(input.coverage_fingerprint == ContentHash::default());
        (unknown_coverage, input.coverage_fingerprint)
    }
}

/// Novelty/rarity guidance signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoveltyRarityGuidanceSignal;

impl GuidanceSignal for NoveltyRarityGuidanceSignal {
    fn kind(&self) -> GuidanceSignalKind {
        GuidanceSignalKind::NoveltyRarity
    }

    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        GuidanceScore {
            micros: GUIDANCE_SCORE_ONE_MICRO / input.rarity_count.saturating_add(1),
        }
    }
}

/// Assertion-proximity guidance signal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AssertionProximityGuidanceSignal;

impl GuidanceSignal for AssertionProximityGuidanceSignal {
    fn kind(&self) -> GuidanceSignalKind {
        GuidanceSignalKind::AssertionProximity
    }

    fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        let Some(distance) = input.assertion_proximity_distance else {
            return GuidanceScore { micros: 0 };
        };
        GuidanceScore {
            micros: GUIDANCE_SCORE_ONE_MICRO / distance.saturating_add(1),
        }
    }
}

/// Fixed-point weight for one built-in guidance signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuidanceSignalWeight {
    /// Signal receiving this weight.
    pub signal: GuidanceSignalKind,
    /// Integer micro-weight used in deterministic weighted sums.
    pub weight_micros: u64,
}

/// Deterministic fixed-order guidance signal composition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuidanceSignalComposition {
    pub(super) weights: Vec<GuidanceSignalWeight>,
}

impl GuidanceSignalComposition {
    /// Builds the default coverage-only guidance composition.
    #[must_use]
    pub fn coverage_only() -> Self {
        Self {
            weights: vec![GuidanceSignalWeight {
                signal: GuidanceSignalKind::Coverage,
                weight_micros: GUIDANCE_SCORE_ONE_MICRO,
            }],
        }
    }

    /// Builds a deterministic composition from `weights`.
    ///
    /// Weights are sorted by signal identity so authoring order cannot change the
    /// fixed-point accumulation order.
    #[must_use]
    pub fn new(weights: Vec<GuidanceSignalWeight>) -> Self {
        let mut weights = weights;
        weights.sort();
        Self { weights }
    }

    /// Returns the fixed ordered weights.
    #[must_use]
    pub fn weights(&self) -> &[GuidanceSignalWeight] {
        &self.weights
    }

    /// Scores `input` with a deterministic fixed-point weighted sum.
    #[must_use]
    pub fn score(&self, input: GuidanceSignalInput) -> GuidanceScore {
        let mut total = 0u128;
        for weight in &self.weights {
            let score = guidance_signal_score(weight.signal, input);
            total = total.saturating_add(
                u128::from(score.micros).saturating_mul(u128::from(weight.weight_micros)),
            );
        }
        GuidanceScore {
            micros: (total / u128::from(GUIDANCE_SCORE_ONE_MICRO)).min(u128::from(u64::MAX)) as u64,
        }
    }
}

/// One adaptive strategy arm in deterministic order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdaptiveStrategyArm {
    /// Breadth-first exploration floor.
    BreadthFirst,
    /// Coverage-guided frontier ordering.
    CoverageGuided,
    /// Seeded priority frontier ordering.
    Priority,
}

/// Optional deterministic adaptive strategy-selection configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyConfig {
    /// Root seed for deterministic UCB tie-breaking.
    pub seed: Seed,
    /// Fixed ordered expansion arms.
    pub arms: Vec<AdaptiveStrategyArm>,
    /// Every Nth expansion is forced to breadth-first when nonzero.
    pub breadth_first_floor_interval: u64,
    /// Fixed-point multiplier for the deterministic UCB exploration term.
    pub ucb_exploration_weight_micros: u64,
    /// Whether adaptive selection is enabled.
    pub enabled: bool,
}

impl AdaptiveStrategyConfig {
    /// Builds the off-by-default adaptive strategy configuration.
    #[must_use]
    pub fn disabled(seed: Seed) -> Self {
        Self {
            seed,
            arms: vec![AdaptiveStrategyArm::BreadthFirst],
            breadth_first_floor_interval: 1,
            ucb_exploration_weight_micros: DEFAULT_ADAPTIVE_UCB_EXPLORATION_WEIGHT_MICROS,
            enabled: false,
        }
    }

    /// Builds an enabled deterministic adaptive strategy configuration.
    #[must_use]
    pub fn enabled(
        seed: Seed,
        arms: Vec<AdaptiveStrategyArm>,
        breadth_first_floor_interval: u64,
    ) -> Self {
        let mut arms = arms;
        arms.sort();
        arms.dedup();
        if arms.is_empty() {
            arms.push(AdaptiveStrategyArm::BreadthFirst);
        }
        Self {
            seed,
            arms,
            breadth_first_floor_interval,
            ucb_exploration_weight_micros: DEFAULT_ADAPTIVE_UCB_EXPLORATION_WEIGHT_MICROS,
            enabled: true,
        }
    }

    /// Replaces the deterministic UCB exploration multiplier.
    #[must_use]
    pub fn with_ucb_exploration_weight_micros(mut self, weight_micros: u64) -> Self {
        self.ucb_exploration_weight_micros = weight_micros;
        self
    }

    /// Computes the content-addressed campaign identity component for this config.
    #[must_use]
    pub fn campaign_identity(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            "crucible.adaptive-strategy.config.v1",
            &adaptive_strategy_config_material(self),
        )
    }
}

/// Deterministic reward credited to an adaptive strategy arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyReward {
    /// Reward for new coverage.
    pub new_coverage: u64,
    /// Reward for rarity/novelty gain.
    pub novelty_gain: u64,
    /// Reward for assertion-proximity progress.
    pub assertion_proximity_progress: u64,
    /// Dominant reward for a confirmed failure.
    pub confirmed_failure: bool,
}

/// One deterministic adaptive reward credit from a realized graph node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyCredit {
    /// Arm that produced the credited node.
    pub arm: AdaptiveStrategyArm,
    /// Content-addressed node receiving the reward.
    pub configuration: ContentHash,
    /// Reward observed for the node.
    pub reward: AdaptiveStrategyReward,
}

/// One deterministic adaptive arm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategySelection {
    /// Zero-based selection sequence.
    pub sequence: u64,
    /// Selected arm.
    pub arm: AdaptiveStrategyArm,
    /// Integer score used for selection.
    pub score: u64,
}

/// Result of deterministic adaptive strategy selection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdaptiveStrategyRun {
    /// Campaign identity including the adaptive configuration.
    pub campaign_identity: ContentHash,
    /// Content-addressed graph fingerprint used as deterministic campaign input.
    pub graph_fingerprint: ContentHash,
    /// Ordered arm selections.
    pub selections: Vec<AdaptiveStrategySelection>,
}

/// Configuration for preemption branch generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreemptionBranchConfig {
    /// Node whose vCPU is preempted.
    pub node: NodeId,
    /// First eligible retired-instruction count.
    pub deadline: Icount,
    /// Last eligible retired-instruction count.
    pub horizon: Icount,
    /// Positive retired-instruction stride between branches.
    pub step: u64,
    /// vCPU currently running before a switch branch.
    pub switch_from_vcpu: VcpuId,
    /// vCPU selected by a switch branch.
    pub switch_to_vcpu: VcpuId,
    /// Target vCPU for the interrupt.
    pub target_vcpu: VcpuId,
    /// Interrupt vector to deliver.
    pub irq: IrqVector,
}

/// Result of preemption branch expansion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreemptionBranchRun {
    /// Decisions considered for branching.
    pub decisions: Vec<Decision>,
    /// Reduced frontier report for the generated children.
    pub report: FrontierReductionReport,
    /// Replay-oracle-validated checkpoints for explored children and covered representatives.
    pub materialized: Vec<Checkpoint>,
}

/// Result of the guidance determinism source lint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuidanceDeterminismLintReport {
    /// Forbidden floating-point ordering tokens found in the inspected source.
    pub forbidden_hits: Vec<String>,
}

impl GuidanceDeterminismLintReport {
    /// Returns whether the lint found no forbidden tokens.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.forbidden_hits.is_empty()
    }
}

/// One frontier expansion in a strategy-driven graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchExpansion {
    /// Zero-based deterministic expansion sequence number.
    pub sequence: u64,
    /// Checkpoint expanded at this sequence number.
    pub frontier: ContentHash,
    /// Number of recorded decisions in `frontier`.
    pub depth: usize,
    /// Single-frontier search result produced for `frontier`.
    pub search: TemporalGraphSearch,
}

/// A failure discovered by a strategy-driven graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchDiscoveredFailure {
    /// Configuration where the failure was observed.
    pub configuration: ContentHash,
    /// Stable failure fingerprint used for deterministic deduplication.
    pub fingerprint: ContentHash,
    /// Self-contained artifact captured when search discovered the failure.
    pub reproduction_artifact: FindingReproductionArtifact,
}

impl SearchDiscoveredFailure {
    /// Returns the self-contained artifact emitted by the search path.
    #[must_use]
    pub fn reproduction_artifact(&self) -> &FindingReproductionArtifact {
        &self.reproduction_artifact
    }
}

/// One fleet work claim from the shared frontier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetWorkClaim {
    /// Zero-based deterministic claim sequence.
    pub sequence: u64,
    /// Logical host that won this claim.
    pub host_index: u64,
    /// Checkpoint expanded by the claim.
    pub frontier: ContentHash,
    /// Number of recorded decisions in `frontier`.
    pub depth: usize,
    /// Single-frontier search result produced by this claim.
    pub search: TemporalGraphSearch,
}

/// Result of a deterministic shared-worklist fleet search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetWorkStealingSearchRun {
    /// Root checkpoint supplied to the fleet.
    pub root: ContentHash,
    /// Fleet configuration used to order claims.
    pub config: FleetWorkStealingConfig,
    /// Deduplicated content-addressed graph reached by the fleet.
    pub explored_graph: BTreeSet<ContentHash>,
    /// Work claims in exact deterministic claim order.
    pub claims: Vec<FleetWorkClaim>,
    /// Failures discovered by the fleet.
    pub discovered_failures: Vec<SearchDiscoveredFailure>,
    /// Whether the shared frontier was exhausted before the budget stopped the run.
    pub exhausted: bool,
}

/// Content-addressed finding entry compared by `gate:fleet-equivalence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FleetFindingSetEntry {
    /// Stable finding fingerprint.
    pub fingerprint: ContentHash,
    /// Configuration where the finding was observed.
    pub configuration: ContentHash,
    /// Self-contained reproduction artifact id.
    pub artifact: ContentHash,
    /// Reduced state reached by replaying the artifact.
    pub replayed_state: ContentHash,
}

impl FleetFindingSetEntry {
    fn from_failure(failure: &SearchDiscoveredFailure) -> Self {
        Self {
            fingerprint: failure.fingerprint,
            configuration: failure.configuration,
            artifact: failure.reproduction_artifact.artifact.id(),
            replayed_state: failure.reproduction_artifact.replay.state,
        }
    }
}

/// Localized fleet-equivalence mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetEquivalenceDivergence {
    /// Stable mismatch category.
    pub reason: &'static str,
    /// Finding fingerprint at the first sorted mismatch, if known.
    pub fingerprint: Option<ContentHash>,
    /// Configuration at the first sorted mismatch, if known.
    pub configuration: Option<ContentHash>,
    /// Single-host artifact at the mismatch, if any.
    pub single_artifact: Option<ContentHash>,
    /// Fleet artifact at the mismatch, if any.
    pub fleet_artifact: Option<ContentHash>,
    /// Replay-oracle bisection handoff for the mismatching artifact/configuration.
    pub bisection: SearchReplayOracleBisectionRequest,
}

/// Result of comparing a single-host search with a fleet search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FleetEquivalenceReport {
    /// Whether both runs started from the same content-addressed root.
    pub root_equal: bool,
    /// Whether both runs used the same total frontier-expansion budget.
    pub budget_equal: bool,
    /// Whether both runs reached the same deduplicated graph.
    pub explored_graph_equal: bool,
    /// Whether both runs exhausted the reachable frontier before the budget ended.
    pub both_exhausted: bool,
    /// Single-host content-addressed finding set.
    pub single_finding_set: BTreeSet<FleetFindingSetEntry>,
    /// Fleet content-addressed finding set.
    pub fleet_finding_set: BTreeSet<FleetFindingSetEntry>,
    /// Single-host discovery order, retained only for diagnostics.
    pub single_discovery_order: Vec<FleetFindingSetEntry>,
    /// Fleet discovery order, retained only for diagnostics.
    pub fleet_discovery_order: Vec<FleetFindingSetEntry>,
    /// Whether the finding sets match order-insensitively.
    pub finding_sets_equal: bool,
    /// Whether every shared finding carries byte-identical artifacts.
    pub artifacts_byte_identical: bool,
    /// Whether the diagnostic discovery order happened to match.
    pub discovery_order_equal: bool,
    /// First localized mismatch, if the equivalence proof failed.
    pub divergence: Option<FleetEquivalenceDivergence>,
}

impl FleetEquivalenceReport {
    /// Compares a single-host exhaustive search and a shared-worklist fleet run.
    #[must_use]
    pub fn compare(single: &TemporalGraphSearchRun, fleet: &FleetWorkStealingSearchRun) -> Self {
        let single_discovery_order = single
            .discovered_failures
            .iter()
            .map(FleetFindingSetEntry::from_failure)
            .collect::<Vec<_>>();
        let fleet_discovery_order = fleet
            .discovered_failures
            .iter()
            .map(FleetFindingSetEntry::from_failure)
            .collect::<Vec<_>>();
        let single_finding_set = single_discovery_order
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let fleet_finding_set = fleet_discovery_order
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let root_equal = single.root == fleet.root;
        let budget_equal = single.budget == fleet.config.total_budget;
        let explored_graph_equal = single.explored_graph == fleet.explored_graph;
        let both_exhausted = single.exhausted && fleet.exhausted;
        let finding_sets_equal = single_finding_set == fleet_finding_set;
        let artifacts_byte_identical = fleet_artifacts_are_byte_identical(
            single,
            fleet,
            &single_finding_set,
            &fleet_finding_set,
        );
        let discovery_order_equal = single_discovery_order == fleet_discovery_order;
        let divergence = (!root_equal
            || !budget_equal
            || !explored_graph_equal
            || !both_exhausted
            || !finding_sets_equal
            || !artifacts_byte_identical)
            .then(|| {
                fleet_equivalence_divergence(single, fleet, &single_finding_set, &fleet_finding_set)
            });

        Self {
            root_equal,
            budget_equal,
            explored_graph_equal,
            both_exhausted,
            single_finding_set,
            fleet_finding_set,
            single_discovery_order,
            fleet_discovery_order,
            finding_sets_equal,
            artifacts_byte_identical,
            discovery_order_equal,
            divergence,
        }
    }

    /// Returns whether the fleet-equivalence proof passed.
    #[must_use]
    pub const fn passes(&self) -> bool {
        self.root_equal
            && self.budget_equal
            && self.explored_graph_equal
            && self.both_exhausted
            && self.finding_sets_equal
            && self.artifacts_byte_identical
            && self.divergence.is_none()
    }
}

/// Host-resolution facts used by retained-log search assertion lowering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchRetainedLogPredicateResolutions {
    pub(super) code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    pub(super) mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

impl SearchRetainedLogPredicateResolutions {
    /// Builds an empty retained-log predicate resolution table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a host-resolved coverage code point for one node and predicate leaf.
    #[must_use]
    pub fn with_code_point(
        mut self,
        node: NodeId,
        point: CodePoint,
        resolved: ResolvedCodePoint,
    ) -> Self {
        self.code_points.insert((node, point), resolved);
        self
    }

    /// Adds a host-resolved memory place for one node and predicate leaf.
    #[must_use]
    pub fn with_mem_place(
        mut self,
        node: NodeId,
        place: MemPlace,
        resolved: ResolvedMemPlace,
    ) -> Self {
        self.mem_places.insert((node, place), resolved);
        self
    }

    pub(super) fn resolves_code_point(&self, node: &NodeId, point: &CodePoint) -> bool {
        self.code_points
            .contains_key(&(node.clone(), point.clone()))
    }

    pub(super) fn resolves_mem_place(&self, node: &NodeId, place: &MemPlace) -> bool {
        self.mem_places.contains_key(&(node.clone(), place.clone()))
    }
}

/// Configuration-bound retained-log assertion evidence for search lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRetainedLogAssertionEvidence {
    pub(super) recorded_log: RecordedAssertionLog,
    pub(super) resolutions: SearchRetainedLogPredicateResolutions,
    pub(super) terminal_quiescence: Option<SchedulerQuiescence>,
}

impl SearchRetainedLogAssertionEvidence {
    /// Builds retained-log evidence with no host-resolution table.
    #[must_use]
    pub fn new(recorded_log: RecordedAssertionLog) -> Self {
        Self {
            recorded_log,
            resolutions: SearchRetainedLogPredicateResolutions::new(),
            terminal_quiescence: None,
        }
    }

    /// Adds host-resolution facts to this retained-log evidence.
    #[must_use]
    pub fn with_resolutions(mut self, resolutions: SearchRetainedLogPredicateResolutions) -> Self {
        self.resolutions = resolutions;
        self
    }

    /// Adds terminal scheduler-quiescence evidence to this retained-log evidence.
    #[must_use]
    pub fn with_terminal_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.terminal_quiescence = Some(quiescence);
        self
    }

    /// Returns the retained assertion log bound to one configuration.
    #[must_use]
    pub const fn recorded_log(&self) -> &RecordedAssertionLog {
        &self.recorded_log
    }

    /// Returns host-resolution facts bound to the retained assertion log.
    #[must_use]
    pub const fn resolutions(&self) -> &SearchRetainedLogPredicateResolutions {
        &self.resolutions
    }

    /// Returns terminal scheduler-quiescence evidence, if supplied.
    #[must_use]
    pub const fn terminal_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.terminal_quiescence.as_ref()
    }
}

/// Read-only failure input for strategy-driven graph search.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SearchFailureOracle {
    pub(super) failures: BTreeMap<ContentHash, ContentHash>,
}

impl SearchFailureOracle {
    /// Builds an oracle that reports no failures.
    #[must_use]
    pub fn none() -> Self {
        Self {
            failures: BTreeMap::new(),
        }
    }

    /// Adds a deterministic failure fingerprint for one configuration id.
    #[must_use]
    pub fn with_failure(mut self, configuration: ContentHash, fingerprint: ContentHash) -> Self {
        self.failures.insert(configuration, fingerprint);
        self
    }

    /// Builds an oracle from prefix-safe assertion violations found by a search run.
    ///
    /// This constructor grades each reached configuration schedule against
    /// `scenario` with the offline assertion checker and lowers only assertion
    /// outcomes that are safe to treat as prefix failures from schedule-only
    /// evidence: host `always` and unreachable violations whose predicates are
    /// composed only from fault-active facts and boolean combinators. It
    /// deliberately does not lower absence-based existential/liveness failures,
    /// time/timer/quiescence predicates, observable-event predicates, guest
    /// marker predicates, or named host predicates, because this path does not
    /// replay a backend-retained event log or a harness oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when the retained assertion log
    /// cannot be reconstructed or checked.
    pub fn from_search_assertion_violations(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
    ) -> Result<Self, EngineError> {
        let mut oracle = BlackBoxHostOracle;
        Self::from_search_assertion_violations_internal(
            scenario,
            root,
            run,
            &mut oracle,
            SearchAssertionPredicateScope::ScheduleOnly,
        )
    }

    /// Builds an oracle from prefix-safe assertion violations using named truths.
    ///
    /// This opt-in path admits named assertion predicates only through a
    /// data-only [`SearchScheduleNamedPredicateTruths`] table keyed by the named
    /// leaf and schedule-derived active signal bindings. The retained log is still
    /// reconstructed from search schedules, so this constructor lowers only
    /// prefix-safe safety/unreachability outcomes whose predicates are composed
    /// from binding-active schedule facts, declared named truths, and boolean
    /// combinators.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when the retained assertion log
    /// cannot be reconstructed or checked.
    pub fn from_search_assertion_violations_with_named_predicates(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        named_predicates: &SearchScheduleNamedPredicateTruths,
    ) -> Result<Self, EngineError> {
        let mut oracle = SearchScheduleNamedPredicateHostOracle::new(named_predicates);
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let mut failure_oracle = Self::none();
        for configuration in search_run_reached_configurations(root, run) {
            if configuration.def.id != scenario_def.id {
                return Err(EngineError::ReproductionScenarioMismatch {
                    expected: scenario_def.id,
                    actual: configuration.def.id,
                });
            }
            if let Some(fingerprint) = search_assertion_failure_fingerprint_with_named_truths(
                scenario,
                &configuration,
                &mut oracle,
            )? {
                failure_oracle = failure_oracle.with_failure(configuration.id(), fingerprint);
            }
        }
        Ok(failure_oracle)
    }

    /// Builds an oracle from assertion violations backed by retained logs.
    ///
    /// `retained_log_for` is consulted for every configuration reached by
    /// `run`. Configurations without a retained log are skipped. This is a
    /// trusted internal boundary: the provider must return the retained log that
    /// belongs to the supplied configuration. Supplied logs are graded with the
    /// offline black-box assertion checker, so this constructor can lower
    /// prefix-safe safety/unreachability violations over retained-log predicates
    /// whose evidence is carried by scheduler event-log entries: time/timer
    /// facts, observable network/console/I/O/node/assertion-state facts, raw
    /// guest-address coverage, physical-address/register memory samples, guest
    /// markers, and schedule fault-active facts. Named host predicates still
    /// require a separate explicit oracle path; host-resolution-dependent
    /// coverage or memory predicates require
    /// [`Self::from_search_assertion_violations_with_retained_logs_and_resolutions`].
    /// For backend integrations that have both logs and host-resolution facts,
    /// prefer
    /// [`Self::from_search_assertion_violations_with_retained_log_evidence`]
    /// so each reached configuration carries its own evidence bundle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when a supplied retained assertion
    /// log cannot be checked.
    pub fn from_search_assertion_violations_with_retained_logs<F>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        mut retained_log_for: F,
    ) -> Result<Self, EngineError>
    where
        F: FnMut(&Configuration) -> Option<RecordedAssertionLog>,
    {
        Self::from_search_assertion_violations_with_retained_log_evidence(
            scenario,
            root,
            run,
            move |configuration| {
                retained_log_for(configuration).map(SearchRetainedLogAssertionEvidence::new)
            },
        )
    }

    /// Builds a retained-log assertion oracle using explicit host resolutions.
    ///
    /// This extends [`Self::from_search_assertion_violations_with_retained_logs`]
    /// by admitting symbolic coverage and virtual/symbolic memory predicates
    /// only when `resolutions` contains an exact leaf resolution for the
    /// predicate's node and host-side reference. Use
    /// [`Self::from_search_assertion_violations_with_retained_log_evidence`]
    /// when those resolutions differ by reached configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when a supplied retained assertion
    /// log cannot be checked.
    pub fn from_search_assertion_violations_with_retained_logs_and_resolutions<F>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        resolutions: &SearchRetainedLogPredicateResolutions,
        mut retained_log_for: F,
    ) -> Result<Self, EngineError>
    where
        F: FnMut(&Configuration) -> Option<RecordedAssertionLog>,
    {
        let resolutions = resolutions.clone();
        Self::from_search_assertion_violations_with_retained_log_evidence(
            scenario,
            root,
            run,
            move |configuration| {
                retained_log_for(configuration).map(|recorded_log| {
                    SearchRetainedLogAssertionEvidence::new(recorded_log)
                        .with_resolutions(resolutions.clone())
                })
            },
        )
    }

    /// Builds a retained-log assertion oracle from configuration-bound evidence.
    ///
    /// `evidence_for` is consulted for every configuration reached by `run`.
    /// Configurations without evidence are skipped. This is the backend-facing
    /// retained-log boundary: every returned [`SearchRetainedLogAssertionEvidence`]
    /// must contain the exact retained log for that configuration and any
    /// host-resolution facts that were valid when the log was captured.
    /// Terminal scheduler-quiescence evidence is used for retained
    /// `after-quiescence` assertions, terminal retained `sometimes`/
    /// `eventually` violations, terminal retained expected-reachable failures,
    /// and guest assertion marker outcomes only when their retained-log evidence
    /// is complete enough for the marker flavor; it does not make quiescence
    /// predicates admissible for prefix, reachability, or terminal
    /// `sometimes`/`eventually` properties.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when a supplied retained assertion
    /// log cannot be checked.
    pub fn from_search_assertion_violations_with_retained_log_evidence<F>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        mut evidence_for: F,
    ) -> Result<Self, EngineError>
    where
        F: FnMut(&Configuration) -> Option<SearchRetainedLogAssertionEvidence>,
    {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let mut failure_oracle = Self::none();
        for configuration in search_run_reached_configurations(root, run) {
            if configuration.def.id != scenario_def.id {
                return Err(EngineError::ReproductionScenarioMismatch {
                    expected: scenario_def.id,
                    actual: configuration.def.id,
                });
            }
            let Some(evidence) = evidence_for(&configuration) else {
                continue;
            };
            if let Some(fingerprint) = search_assertion_failure_fingerprint_from_retained_log(
                scenario,
                &configuration,
                evidence.recorded_log(),
                evidence.resolutions(),
                evidence.terminal_quiescence(),
            )? {
                failure_oracle = failure_oracle.with_failure(configuration.id(), fingerprint);
            }
        }
        Ok(failure_oracle)
    }

    fn from_search_assertion_violations_internal<O>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        oracle: &mut O,
        predicate_scope: SearchAssertionPredicateScope,
    ) -> Result<Self, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let mut failure_oracle = Self::none();
        for configuration in search_run_reached_configurations(root, run) {
            if configuration.def.id != scenario_def.id {
                return Err(EngineError::ReproductionScenarioMismatch {
                    expected: scenario_def.id,
                    actual: configuration.def.id,
                });
            }
            if let Some(fingerprint) = search_assertion_failure_fingerprint(
                scenario,
                &configuration,
                oracle,
                predicate_scope,
            )? {
                failure_oracle = failure_oracle.with_failure(configuration.id(), fingerprint);
            }
        }
        Ok(failure_oracle)
    }

    /// Returns the configured failure fingerprint for `configuration`, if any.
    #[must_use]
    pub fn failure_for(&self, configuration: ContentHash) -> Option<ContentHash> {
        self.failures.get(&configuration).copied()
    }

    /// Returns whether this oracle contains no failure entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Result of a deterministic strategy-driven graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphSearchRun {
    /// Root checkpoint supplied to the search.
    pub root: ContentHash,
    /// Strategy used to order frontier expansion.
    pub strategy: SearchStrategy,
    /// Finite expansion budget used by the run.
    pub budget: SearchBudget,
    /// Deduplicated content-addressed graph reached during the run.
    pub explored_graph: BTreeSet<ContentHash>,
    /// Frontier expansions in exact deterministic order.
    pub expansions: Vec<SearchExpansion>,
    /// Failures discovered by the run.
    pub discovered_failures: Vec<SearchDiscoveredFailure>,
    /// Whether the work-list was exhausted before the budget stopped the run.
    pub exhausted: bool,
}

/// Result of a strategy-driven graph search with replay-oracle sampling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphSampledSearchRun {
    /// Deterministic strategy-search result.
    pub run: TemporalGraphSearchRun,
    /// Aggregate replay-oracle sampling report across every expanded frontier.
    pub replay_oracle_sampling: SearchReplayOracleSamplingReport,
}

/// Result of a graph-level save operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphSave {
    /// Configuration saved by the operation.
    pub configuration: ContentHash,
    /// Checkpoint identity saved for the configuration.
    pub checkpoint: ContentHash,
    /// Storage shape of the saved checkpoint.
    pub checkpoint_kind: CheckpointKind,
    /// DAG-store keys persisted for the saved closure.
    pub store_keys: TemporalGraphStoreKeys,
}

/// Advanced operation admitted through the single temporal graph realization path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnifiedGraphOperationKind {
    /// User-facing resume of a graph tip.
    Resume,
    /// Interactive fork from an existing graph configuration.
    Fork,
    /// Save of a graph configuration to a checkpoint/store closure.
    Save,
    /// Replay-oracle validation of a graph configuration.
    Replay,
    /// State-space search reached this configuration.
    StateSpaceSearch,
    /// Coverage-guided fuzzing produced this configuration.
    CoverageGuidedFuzzing,
    /// A self-contained reproduction artifact names this configuration.
    ReproductionArtifact,
    /// Failure minimization produced this configuration.
    Minimization,
}

/// Typed evidence that an advanced feature produced a temporal-graph configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::large_enum_variant)]
pub enum UnifiedGraphOperationEvidence {
    /// User-facing resume output plus the configuration that was resumed.
    Resume {
        /// Configuration supplied to `resume`.
        configuration: Configuration,
        /// Runtime output returned by `resume`.
        runtime: TemporalGraphRuntime,
    },
    /// Interactive fork output.
    Fork(TemporalGraphFork),
    /// Save output plus the configuration that was saved.
    Save {
        /// Configuration supplied to `save`.
        configuration: Configuration,
        /// Save output returned by the temporal graph.
        save: TemporalGraphSave,
    },
    /// Replay-oracle output plus the configuration that was replayed.
    Replay {
        /// Configuration supplied to `replay`.
        configuration: Configuration,
        /// Replay-oracle output returned by the temporal graph.
        replay: ReplayOracleCheck,
    },
    /// Failure discovered by a state-space search run.
    StateSpaceSearch {
        /// Temporal graph snapshot supplied to the search operation.
        graph: TemporalGraph,
        /// Concrete scenario form used for reproduction artifacts.
        scenario: ScenarioDefForm,
        /// Root configuration supplied to the search operation.
        root: Configuration,
        /// Frontier ordering strategy used by the search operation.
        strategy: SearchStrategy,
        /// Expansion budget supplied to the search operation.
        budget: SearchBudget,
        /// Checkpoint materialization policy supplied to the search operation.
        materialization_policy: MaterializationPolicy,
        /// Materialization trigger supplied to the search operation.
        trigger: MaterializationTrigger,
        /// Read-only failure oracle supplied to the search operation.
        failure_oracle: SearchFailureOracle,
        /// Full deterministic search output.
        run: TemporalGraphSearchRun,
        /// Discovered failure admitted through the unified graph path.
        failure: SearchDiscoveredFailure,
    },
    /// Candidate generated by a coverage-guided fuzzing run.
    CoverageGuidedFuzzing {
        /// Scenario family sampled by the fuzzing run.
        family: ScenarioFamily,
        /// Full deterministic fuzzing run output.
        run: CoverageGuidedFuzzRun,
        /// Coverage feedback fingerprints consumed by the run.
        feedback_fingerprints: Vec<ContentHash>,
        /// Iteration admitted through the unified graph path.
        iteration: CoverageGuidedFuzzIteration,
    },
    /// Self-contained finding reproduction artifact.
    ReproductionArtifact(FindingReproductionArtifact),
    /// Failure-preserving minimization run.
    Minimization(MinimizationRun),
}

impl UnifiedGraphOperationEvidence {
    /// Returns the operation kind carried by this evidence.
    #[must_use]
    pub const fn kind(&self) -> UnifiedGraphOperationKind {
        match self {
            Self::Resume { .. } => UnifiedGraphOperationKind::Resume,
            Self::Fork(_) => UnifiedGraphOperationKind::Fork,
            Self::Save { .. } => UnifiedGraphOperationKind::Save,
            Self::Replay { .. } => UnifiedGraphOperationKind::Replay,
            Self::StateSpaceSearch { .. } => UnifiedGraphOperationKind::StateSpaceSearch,
            Self::CoverageGuidedFuzzing { .. } => UnifiedGraphOperationKind::CoverageGuidedFuzzing,
            Self::ReproductionArtifact(_) => UnifiedGraphOperationKind::ReproductionArtifact,
            Self::Minimization(_) => UnifiedGraphOperationKind::Minimization,
        }
    }

    /// Returns the configuration proven by this operation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`],
    /// [`EngineError::RuntimeConfigurationMismatch`],
    /// [`EngineError::CheckpointConfigurationMismatch`],
    /// [`EngineError::ReproductionArtifactReplayMismatch`], or
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when the supplied
    /// evidence does not internally identify one consistent operation output.
    pub fn configuration(&self) -> Result<Configuration, EngineError> {
        match self {
            Self::Resume {
                configuration,
                runtime,
            } => {
                expect_runtime_configuration(runtime, configuration)?;
                Ok(configuration.clone())
            }
            Self::Fork(fork) => configuration_from_fork(fork),
            Self::Save {
                configuration,
                save,
            } => {
                expect_content_hash(save.configuration, configuration.id(), "save-configuration")?;
                expect_content_hash(save.checkpoint, configuration.id(), "save-checkpoint")?;
                Ok(configuration.clone())
            }
            Self::Replay {
                configuration,
                replay,
            } => {
                expect_content_hash(
                    replay.configuration,
                    configuration.id(),
                    "replay-configuration",
                )?;
                expect_content_hash(
                    replay.fat_checkpoint,
                    configuration.id(),
                    "replay-fat-checkpoint",
                )?;
                expect_content_hash(
                    replay.thin_checkpoint,
                    configuration.id(),
                    "replay-thin-checkpoint",
                )?;
                Ok(configuration.clone())
            }
            Self::StateSpaceSearch {
                graph,
                scenario,
                root,
                strategy,
                budget,
                materialization_policy,
                trigger,
                failure_oracle,
                run,
                failure,
            } => configuration_from_state_space_search(
                graph,
                scenario,
                root,
                *strategy,
                *budget,
                *materialization_policy,
                *trigger,
                failure_oracle,
                run,
                failure,
            ),
            Self::CoverageGuidedFuzzing {
                family,
                run,
                feedback_fingerprints,
                iteration,
            } => configuration_from_coverage_guided_fuzzing(
                family,
                run,
                feedback_fingerprints,
                iteration,
            ),
            Self::ReproductionArtifact(finding) => configuration_from_validated_finding(finding),
            Self::Minimization(run) => configuration_from_minimization_run(run),
        }
    }

    pub(super) fn validate_report(
        &self,
        graph: &TemporalGraph,
        configuration: &Configuration,
        report: &UnifiedGraphOperationReport,
    ) -> Result<(), EngineError> {
        match self {
            Self::Resume { runtime, .. } => {
                expect_content_hash(runtime.runtime.id, report.runtime_state, "resume-runtime")?;
                expect_content_hash(runtime.checkpoint, report.checkpoint, "resume-checkpoint")
            }
            Self::Fork(fork) => {
                expect_content_hash(fork.branch.id(), report.configuration, "fork-branch")?;
                expect_content_hash(
                    fork.branch_checkpoint.id,
                    report.checkpoint,
                    "fork-branch-checkpoint",
                )
            }
            Self::Save { save, .. } => {
                expect_content_hash(save.configuration, report.configuration, "save-report")?;
                expect_content_hash(save.checkpoint, report.checkpoint, "save-checkpoint")?;
                if save.checkpoint_kind != CheckpointKind::Fat {
                    return Err(unified_operation_evidence_mismatch(
                        self.operation_label(),
                        "save-checkpoint-kind",
                    ));
                }
                let expected = temporal_graph_store_keys_for_configuration(graph, configuration)?;
                if save.store_keys != expected {
                    return Err(unified_operation_evidence_mismatch(
                        self.operation_label(),
                        "save-store-keys",
                    ));
                }
                Ok(())
            }
            Self::Replay { replay, .. } => {
                if replay != &report.replay_oracle {
                    return Err(unified_operation_evidence_mismatch(
                        self.operation_label(),
                        "replay-oracle-output",
                    ));
                }
                Ok(())
            }
            Self::StateSpaceSearch {
                graph: search_graph,
                failure,
                ..
            } => {
                if search_graph.id != graph.id {
                    return Err(unified_operation_evidence_mismatch(
                        self.operation_label(),
                        "search-graph",
                    ));
                }
                expect_content_hash(
                    failure.configuration,
                    report.configuration,
                    "search-report-configuration",
                )?;
                expect_content_hash(
                    failure.reproduction_artifact.finding_fingerprint,
                    failure.fingerprint,
                    "search-report-fingerprint",
                )
            }
            Self::CoverageGuidedFuzzing { iteration, .. } => expect_content_hash(
                iteration.configuration_id(),
                report.configuration,
                "fuzz-report-configuration",
            ),
            Self::ReproductionArtifact(finding) => {
                expect_content_hash(
                    finding.configuration,
                    report.configuration,
                    "reproduction-report-configuration",
                )?;
                expect_content_hash(
                    finding.replay.state,
                    report.reduced_state,
                    "reproduction-report-state",
                )
            }
            Self::Minimization(run) => {
                expect_content_hash(
                    run.minimized.configuration,
                    report.configuration,
                    "minimization-report-configuration",
                )?;
                expect_content_hash(
                    run.minimized.replay.state,
                    report.reduced_state,
                    "minimization-report-state",
                )
            }
        }
    }

    fn operation_label(&self) -> &'static str {
        operation_kind_label(self.kind())
    }
}

pub(super) fn operation_kind_label(kind: UnifiedGraphOperationKind) -> &'static str {
    match kind {
        UnifiedGraphOperationKind::Resume => "resume",
        UnifiedGraphOperationKind::Fork => "fork",
        UnifiedGraphOperationKind::Save => "save",
        UnifiedGraphOperationKind::Replay => "replay",
        UnifiedGraphOperationKind::StateSpaceSearch => "state-space-search",
        UnifiedGraphOperationKind::CoverageGuidedFuzzing => "coverage-guided-fuzzing",
        UnifiedGraphOperationKind::ReproductionArtifact => "reproduction-artifact",
        UnifiedGraphOperationKind::Minimization => "minimization",
    }
}

pub(super) fn unified_operation_evidence_mismatch(
    operation: &'static str,
    reason: &'static str,
) -> EngineError {
    EngineError::UnifiedOperationEvidenceMismatch { operation, reason }
}

pub(super) fn expect_content_hash(
    actual: ContentHash,
    expected: ContentHash,
    _field: &'static str,
) -> Result<(), EngineError> {
    if actual != expected {
        return Err(EngineError::ReplayTargetMismatch { expected, actual });
    }
    Ok(())
}

pub(super) fn expect_runtime_configuration(
    runtime: &TemporalGraphRuntime,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    if runtime.configuration != configuration.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.runtime.id,
            expected: configuration.id(),
            actual: runtime.configuration,
        });
    }
    if runtime.runtime.configuration != configuration.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.runtime.id,
            expected: configuration.id(),
            actual: runtime.runtime.configuration,
        });
    }
    expect_content_hash(runtime.checkpoint, configuration.id(), "runtime-checkpoint")?;
    let reduced = reduce(&configuration.def, &configuration.schedule)?;
    expect_content_hash(runtime.runtime.id, reduced.id, "runtime-state")
}

pub(super) fn expect_checkpoint_configuration(
    checkpoint: &Checkpoint,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    if checkpoint.configuration != configuration.id() {
        return Err(EngineError::CheckpointConfigurationMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.configuration,
        });
    }
    if checkpoint.id != configuration.id() {
        return Err(EngineError::CheckpointIdentityMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.id,
        });
    }
    Ok(())
}

pub(super) fn configuration_from_fork(
    fork: &TemporalGraphFork,
) -> Result<Configuration, EngineError> {
    let base = configuration_prefix_with_id(&fork.branch, fork.base.configuration)?;
    expect_runtime_configuration(&fork.base, &base)?;
    expect_checkpoint_configuration(&fork.branch_checkpoint, &fork.branch)?;
    Ok(fork.branch.clone())
}

pub(super) fn configuration_prefix_with_id(
    configuration: &Configuration,
    expected: ContentHash,
) -> Result<Configuration, EngineError> {
    for len in 0..=configuration.schedule.len() {
        let schedule = configuration
            .schedule
            .prefix(len)
            .map_err(EngineError::SchedulePrefix)?;
        let prefix = Configuration {
            def: configuration.def.clone(),
            schedule,
        };
        if prefix.id() == expected {
            return Ok(prefix);
        }
    }
    Err(EngineError::ReplayTargetMismatch {
        expected,
        actual: configuration.id(),
    })
}
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn configuration_from_state_space_search(
    graph: &TemporalGraph,
    scenario: &ScenarioDefForm,
    root: &Configuration,
    strategy: SearchStrategy,
    budget: SearchBudget,
    materialization_policy: MaterializationPolicy,
    trigger: MaterializationTrigger,
    failure_oracle: &SearchFailureOracle,
    run: &TemporalGraphSearchRun,
    failure: &SearchDiscoveredFailure,
) -> Result<Configuration, EngineError> {
    let mut replay_graph = graph.clone();
    let expected_run = replay_graph.search_with_strategy_and_failure_oracle(
        scenario,
        root,
        strategy,
        budget,
        materialization_policy,
        trigger,
        failure_oracle,
    )?;
    if &expected_run != run {
        return Err(unified_operation_evidence_mismatch(
            "state-space-search",
            "search-run-output",
        ));
    }
    if !run.discovered_failures.contains(failure) {
        return Err(unified_operation_evidence_mismatch(
            "state-space-search",
            "search-failure-output",
        ));
    }
    let configuration = configuration_from_validated_finding(&failure.reproduction_artifact)?;
    if failure.reproduction_artifact.discovery_path != FindingDiscoveryPath::StateSpaceSearch {
        return Err(unified_operation_evidence_mismatch(
            "state-space-search",
            "search-discovery-path",
        ));
    }
    expect_content_hash(
        failure.configuration,
        configuration.id(),
        "search-failure-configuration",
    )?;
    expect_content_hash(
        failure.fingerprint,
        failure.reproduction_artifact.finding_fingerprint,
        "search-failure-fingerprint",
    )?;
    Ok(configuration)
}

pub(super) fn configuration_from_coverage_guided_fuzzing(
    family: &ScenarioFamily,
    run: &CoverageGuidedFuzzRun,
    feedback_fingerprints: &[ContentHash],
    iteration: &CoverageGuidedFuzzIteration,
) -> Result<Configuration, EngineError> {
    let expected =
        coverage_guided_fuzz_run_from_fingerprints(family, run.config, feedback_fingerprints)?;
    if &expected != run {
        return Err(unified_operation_evidence_mismatch(
            "coverage-guided-fuzzing",
            "run-output",
        ));
    }
    let expected_iteration = run
        .iterations
        .get(iteration.sequence as usize)
        .ok_or_else(|| {
            unified_operation_evidence_mismatch("coverage-guided-fuzzing", "iteration-sequence")
        })?;
    if expected_iteration != iteration {
        return Err(unified_operation_evidence_mismatch(
            "coverage-guided-fuzzing",
            "iteration-output",
        ));
    }
    Ok(iteration.configuration.clone())
}

pub(super) fn coverage_guided_fuzz_run_from_fingerprints(
    family: &ScenarioFamily,
    config: CoverageGuidedFuzzConfig,
    feedback_fingerprints: &[ContentHash],
) -> Result<CoverageGuidedFuzzRun, EngineError> {
    let cardinality = family.space().cardinality()?;
    let mut iterations = Vec::new();
    let mut seen_coverage = BTreeSet::new();
    let mut corpus = vec![coverage_guided_fuzz_seed_corpus_entry(config, cardinality)];

    for sequence in 0..config.iterations {
        let coverage_fingerprint =
            coverage_guided_feedback_fingerprint_for_sequence(feedback_fingerprints, sequence);
        let selected_corpus_entry = coverage_guided_fuzz_select_corpus_entry(
            config,
            sequence,
            coverage_fingerprint,
            &corpus,
        );
        let energy = coverage_guided_fuzz_energy(config, sequence, coverage_fingerprint);
        let sample_index =
            coverage_guided_fuzz_sample_index(config, sequence, coverage_fingerprint, cardinality);
        let scenario = family.instantiate_sample(sample_index)?;
        let params = scenario.params();
        let root = scenario.genesis_configuration();
        let mutation =
            coverage_guided_fuzz_override_decision(config, sequence, sample_index, params);
        let configuration = try_step(root.configuration(), mutation.clone())?;
        let new_coverage = coverage_fingerprint != ContentHash::default()
            && seen_coverage.insert(coverage_fingerprint);
        if new_coverage {
            corpus.push(configuration.id());
        }
        iterations.push(CoverageGuidedFuzzIteration {
            sequence,
            sample_index,
            params,
            scenario,
            selected_corpus_entry,
            energy,
            configuration,
            mutation,
            coverage_fingerprint,
            new_coverage,
        });
    }

    let coverage_biased_order = coverage_guided_fuzz_order(&iterations);
    Ok(CoverageGuidedFuzzRun {
        config,
        iterations,
        coverage_biased_order,
    })
}

pub(super) fn coverage_guided_feedback_fingerprint_for_sequence(
    feedback_fingerprints: &[ContentHash],
    sequence: u64,
) -> ContentHash {
    if feedback_fingerprints.is_empty() {
        return ContentHash::default();
    }
    let index = (sequence % feedback_fingerprints.len() as u64) as usize;
    feedback_fingerprints[index]
}

pub(super) fn configuration_from_finding_artifact(
    finding: &FindingReproductionArtifact,
) -> Result<Configuration, EngineError> {
    let configuration = Configuration {
        def: finding.artifact.scenario_def(),
        schedule: finding.artifact.schedule().clone(),
    };
    expect_content_hash(
        finding.configuration,
        configuration.id(),
        "finding-configuration",
    )?;
    Ok(configuration)
}

pub(super) fn configuration_from_validated_finding(
    finding: &FindingReproductionArtifact,
) -> Result<Configuration, EngineError> {
    let replay = finding.artifact.replay()?;
    if replay != finding.replay {
        return Err(EngineError::ReproductionArtifactReplayMismatch {
            artifact: finding.artifact.id(),
            expected: finding.replay.state,
            actual: replay.state,
        });
    }
    configuration_from_finding_artifact(finding)
}

pub(super) fn configuration_from_minimization_run(
    run: &MinimizationRun,
) -> Result<Configuration, EngineError> {
    configuration_from_validated_finding(&run.original)?;
    expect_content_hash(
        run.original.finding_fingerprint,
        run.target_fingerprint,
        "minimization-original-fingerprint",
    )?;
    expect_content_hash(
        run.minimized.finding_fingerprint,
        run.target_fingerprint,
        "minimization-minimized-fingerprint",
    )?;
    if run.minimized.discovery_path != run.original.discovery_path {
        return Err(unified_operation_evidence_mismatch(
            "minimization",
            "discovery-path",
        ));
    }

    let minimized = configuration_from_validated_finding(&run.minimized)?;
    let candidates = minimization_candidates(
        run.seed,
        run.original.artifact.id(),
        run.original.artifact.schedule(),
    );
    if run.attempts.len() > candidates.len() {
        return Err(unified_operation_evidence_mismatch(
            "minimization",
            "attempt-count",
        ));
    }

    let mut accepted = None;
    for (index, attempt) in run.attempts.iter().enumerate() {
        let candidate = candidates
            .get(index)
            .ok_or_else(|| unified_operation_evidence_mismatch("minimization", "attempt-count"))?;
        if attempt.sequence != index as u64 {
            return Err(unified_operation_evidence_mismatch(
                "minimization",
                "attempt-sequence",
            ));
        }
        if attempt.removed_indices != candidate.removed_indices {
            return Err(unified_operation_evidence_mismatch(
                "minimization",
                "removed-indices",
            ));
        }
        if attempt.removed_decisions != candidate.removed_decisions {
            return Err(unified_operation_evidence_mismatch(
                "minimization",
                "removed-decisions",
            ));
        }
        expect_content_hash(
            attempt.candidate_schedule,
            candidate.schedule.content_hash(),
            "minimization-candidate-schedule",
        )?;

        let candidate_configuration = Configuration {
            def: run.original.artifact.scenario_def(),
            schedule: candidate.schedule.clone(),
        };
        let candidate_finding = FindingReproductionArtifact::capture(
            run.original.discovery_path,
            run.target_fingerprint,
            run.original.artifact.scenario_form(),
            &candidate_configuration,
        )?;
        expect_content_hash(
            attempt.candidate_artifact,
            candidate_finding.artifact.id(),
            "minimization-candidate-artifact",
        )?;
        expect_content_hash(
            attempt.replayed_state,
            candidate_finding.replay.state,
            "minimization-replayed-state",
        )?;
        if attempt.accepted != (attempt.observed_fingerprint == Some(run.target_fingerprint)) {
            return Err(unified_operation_evidence_mismatch(
                "minimization",
                "accepted-fingerprint",
            ));
        }
        if attempt.accepted {
            accepted = Some(candidate_finding);
            if index + 1 != run.attempts.len() {
                return Err(unified_operation_evidence_mismatch(
                    "minimization",
                    "attempts-after-accepted",
                ));
            }
            break;
        }
    }

    match accepted {
        Some(candidate) if candidate == run.minimized => {}
        Some(_) => {
            return Err(unified_operation_evidence_mismatch(
                "minimization",
                "minimized-candidate",
            ));
        }
        None if run.attempts.len() == candidates.len() && run.minimized == run.original => {}
        None => {
            return Err(unified_operation_evidence_mismatch(
                "minimization",
                "unaccepted-minimized",
            ));
        }
    }

    Ok(minimized)
}

pub(super) fn temporal_graph_store_keys_for_configuration(
    graph: &TemporalGraph,
    frontier: &Configuration,
) -> Result<TemporalGraphStoreKeys, EngineError> {
    let chain = graph.checkpoint_parent_chain(frontier.id())?;
    let genesis =
        graph
            .genesis_snapshot(&frontier.def)
            .ok_or(EngineError::MissingBakedGenesis {
                scenario: frontier.def.id,
            })?;

    let scenario_def = ContentHash::from_bytes(&scenario_def_store_bytes(&frontier.def));
    let genesis_snapshot = ContentHash::from_bytes(&checkpoint_store_bytes(&genesis.checkpoint));
    let mut checkpoint_nodes = BTreeMap::new();
    let mut cached_snapshots = BTreeMap::new();
    let mut cow_deltas = BTreeMap::new();
    let mut schedule_deltas = Vec::new();
    let mut event_log_segments = Vec::new();

    for checkpoint in &chain {
        checkpoint_nodes.insert(
            checkpoint.id,
            ContentHash::from_bytes(&checkpoint_store_bytes(checkpoint)),
        );
        insert_checkpoint_cow_delta_store_keys(
            checkpoint,
            &mut cow_deltas,
            &mut schedule_deltas,
            &mut event_log_segments,
        );
        if let Some(snapshot) = graph.cached_snapshots.get(&checkpoint.id) {
            cached_snapshots.insert(
                snapshot.id,
                ContentHash::from_bytes(&checkpoint_store_bytes(snapshot)),
            );
            insert_checkpoint_cow_delta_store_keys(
                snapshot,
                &mut cow_deltas,
                &mut schedule_deltas,
                &mut event_log_segments,
            );
        }
    }

    Ok(TemporalGraphStoreKeys {
        checkpoint_nodes,
        cached_snapshots,
        cow_deltas,
        reproduction_artifact: DagStoreReproductionArtifact::new(
            scenario_def,
            genesis_snapshot,
            schedule_deltas,
        )
        .with_event_log_segment_keys(event_log_segments),
    })
}

pub(super) fn insert_checkpoint_cow_delta_store_keys(
    checkpoint: &Checkpoint,
    cow_deltas: &mut BTreeMap<CowDeltaRef, ContentHash>,
    schedule_deltas: &mut Vec<ContentHash>,
    event_log_segments: &mut Vec<ContentHash>,
) {
    for cow_ref in checkpoint.cow_delta_refs() {
        if cow_deltas.contains_key(&cow_ref) {
            continue;
        }
        let delta_key = match cow_ref.kind {
            CowDeltaKind::ScheduleDelta => {
                let key = ContentHash::from_bytes(&schedule_delta_store_bytes(
                    &checkpoint.schedule_delta,
                ));
                schedule_deltas.push(key);
                key
            }
            CowDeltaKind::EventLogSegment => {
                event_log_segments.push(cow_ref.content);
                cow_ref.content
            }
            CowDeltaKind::VmMemory | CowDeltaKind::DeviceOverlay => {
                ContentHash::from_bytes(&cow_delta_store_bytes(cow_ref))
            }
        };
        cow_deltas.insert(cow_ref, delta_key);
    }
}

/// Replay-oracle and single-VM-fingerprint evidence for one graph operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnifiedGraphOperationReport {
    /// Operation being validated through the unified temporal graph path.
    pub operation: UnifiedGraphOperationKind,
    /// Temporal graph handle used for validation.
    pub graph: ContentHash,
    /// Configuration admitted by the operation.
    pub configuration: ContentHash,
    /// Recorded schedule content address for the configuration.
    pub schedule: ContentHash,
    /// Checkpoint materialized from the single realized runtime.
    pub checkpoint: ContentHash,
    /// Reduced state denoted by the configuration.
    pub reduced_state: ContentHash,
    /// Runtime state returned by [`instantiate`].
    pub runtime_state: ContentHash,
    /// Model-side single-VM fingerprint for the realized runtime.
    pub single_vm_fingerprint: ExecutionFingerprint,
    /// Replay-oracle check comparing the realized checkpoint with thin replay.
    pub replay_oracle: ReplayOracleCheck,
}
