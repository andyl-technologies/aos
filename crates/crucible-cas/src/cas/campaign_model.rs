/// Immutable manifest named by a persistent campaign head.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignManifest {
    /// Root of the retained campaign corpus set.
    pub corpus_root: ContentHash,
    /// Root of the accumulated coverage map.
    pub coverage_map_root: ContentHash,
    /// Root of the campaign findings ledger.
    pub findings_root: ContentHash,
    /// Baked genesis checkpoint pin for this lineage.
    pub genesis_pin: ContentHash,
    /// Provenance triple that owns this campaign lineage.
    pub provenance: CampaignProvenance,
}

impl CampaignManifest {
    /// Builds a campaign manifest from content-addressed roots.
    #[must_use]
    pub fn new(
        corpus_root: ContentHash,
        coverage_map_root: ContentHash,
        findings_root: ContentHash,
        genesis_pin: ContentHash,
        provenance: CampaignProvenance,
    ) -> Self {
        Self {
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
            provenance,
        }
    }
}

/// Provenance triple recorded in a campaign manifest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignProvenance {
    /// Crucible software version.
    pub crucible_version: String,
    /// QEMU build identity plus applied series hash.
    pub qemu_build: String,
    /// Combined shmem, guest-host channel, and RPC ABI versions.
    pub abi_versions: String,
}

impl CampaignProvenance {
    /// Builds a campaign provenance triple.
    #[must_use]
    pub fn new(
        crucible_version: impl Into<String>,
        qemu_build: impl Into<String>,
        abi_versions: impl Into<String>,
    ) -> Self {
        Self {
            crucible_version: crucible_version.into(),
            qemu_build: qemu_build.into(),
            abi_versions: abi_versions.into(),
        }
    }
}

/// Computes the content-addressed key for a campaign provenance triple.
///
/// # Errors
///
/// Returns [`CasError`] when any provenance field is empty or contains a
/// newline.
pub fn campaign_provenance_key(provenance: &CampaignProvenance) -> Result<ContentHash, CasError> {
    validate_campaign_provenance(provenance)?;
    Ok(ContentHash::from_bytes(
        campaign_provenance_material(provenance).as_bytes(),
    ))
}

/// Computes the deterministic lineage id for a campaign manifest.
///
/// The lineage id is keyed to the manifest's genesis pin and provenance key, not
/// to the mutable corpus, coverage, or findings roots that advance over time.
///
/// # Errors
///
/// Returns [`CasError`] when the manifest or provenance fields are invalid.
pub fn campaign_lineage_id(manifest: &CampaignManifest) -> Result<ContentHash, CasError> {
    validate_campaign_manifest(manifest)?;
    let provenance_key = campaign_provenance_key(&manifest.provenance)?;
    Ok(ContentHash::from_bytes(
        campaign_lineage_material(manifest, provenance_key).as_bytes(),
    ))
}

/// Current content-addressed campaign manifest head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignHead {
    /// Content hash of the manifest object.
    pub manifest_hash: ContentHash,
    /// Parsed immutable manifest object.
    pub manifest: CampaignManifest,
}

/// Result of a campaign manifest-head compare-and-swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignCasOutcome {
    /// The head was advanced to the supplied manifest.
    Advanced(CampaignHead),
    /// The head changed before the compare-and-swap could publish the proposal.
    LostUpdate {
        /// Head hash expected by the caller.
        expected: Option<ContentHash>,
        /// Current head hash observed during CAS.
        current: Option<ContentHash>,
        /// Content-addressed proposal retained in the store.
        proposed_manifest_hash: ContentHash,
    },
}

/// Report from read-merge-retry campaign-head advancement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignAdvanceReport {
    /// Number of CAS attempts made.
    pub attempts: usize,
    /// Final advanced campaign head.
    pub head: CampaignHead,
}

/// Self-contained campaign replay artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignReplayArtifact {
    definition: Vec<u8>,
    seed: Vec<u8>,
    schedule: Vec<u8>,
}

impl CampaignReplayArtifact {
    /// Builds a replay artifact from definition, seed, and schedule bytes.
    #[must_use]
    pub fn new(
        definition: impl Into<Vec<u8>>,
        seed: impl Into<Vec<u8>>,
        schedule: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            definition: definition.into(),
            seed: seed.into(),
            schedule: schedule.into(),
        }
    }

    /// Returns the scenario or workload definition bytes.
    #[must_use]
    pub fn definition(&self) -> &[u8] {
        &self.definition
    }

    /// Returns the deterministic seed bytes.
    #[must_use]
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// Returns the deterministic schedule bytes.
    #[must_use]
    pub fn schedule(&self) -> &[u8] {
        &self.schedule
    }

    /// Returns the canonical replay-input bytes produced from the artifact.
    #[must_use]
    pub fn replay_bytes(&self) -> Vec<u8> {
        campaign_replay_input_material(self).into_bytes()
    }

    /// Returns the content hash of the canonical replay input.
    #[must_use]
    pub fn replay_hash(&self) -> ContentHash {
        ContentHash::from_bytes(&self.replay_bytes())
    }
}

/// Corpus seed loaded for the next campaign run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCorpusSeed {
    /// Content hash of the self-contained replay artifact.
    pub artifact_hash: ContentHash,
    /// Replay hash recorded by the corpus root.
    pub replay_hash: ContentHash,
    /// Self-contained replay artifact bytes.
    pub artifact: CampaignReplayArtifact,
}

impl CampaignCorpusSeed {
    /// Returns whether the loaded artifact reproduces the recorded replay hash.
    #[must_use]
    pub fn reproduces_bit_identically(&self) -> bool {
        self.artifact.replay_hash() == self.replay_hash
    }
}

/// Provenance-aware decision for campaign run N+1 seeding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignContinuitySeedDecision {
    /// The prior campaign corpus may seed this run.
    SeedPriorCorpus {
        /// Self-contained corpus entries loaded from the prior manifest root.
        seeds: Vec<CampaignCorpusSeed>,
        /// Stable id of the existing campaign lineage.
        lineage_id: ContentHash,
        /// Provenance key shared by the prior corpus and this run.
        provenance_key: ContentHash,
    },
    /// The prior corpus was refused and a fresh lineage baseline was recorded.
    RefuseCrossProvenanceReuse(Box<CampaignFreshLineageBaselineEvent>),
}

impl CampaignContinuitySeedDecision {
    /// Returns whether this decision seeds the prior corpus.
    #[must_use]
    pub fn seeds_prior_corpus(&self) -> bool {
        matches!(self, Self::SeedPriorCorpus { .. })
    }

    /// Returns whether this decision refused cross-provenance reuse.
    #[must_use]
    pub fn refuses_cross_provenance_reuse(&self) -> bool {
        matches!(self, Self::RefuseCrossProvenanceReuse(_))
    }
}

/// Baseline event recorded when a campaign forks a fresh lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignFreshLineageBaselineEvent {
    /// Content-addressed event record persisted in the campaign object store.
    pub baseline_event_hash: ContentHash,
    /// Event schema identifier.
    pub schema_version: String,
    /// Loud refusal reason for operators and CI logs.
    pub reason: String,
    /// Prior corpus root refused as a seed.
    pub refused_corpus_root: ContentHash,
    /// Previous campaign lineage id.
    pub previous_lineage_id: ContentHash,
    /// Fresh campaign lineage id.
    pub fresh_lineage_id: ContentHash,
    /// Provenance key for the refused prior campaign.
    pub previous_provenance_key: ContentHash,
    /// Provenance key for the current run.
    pub run_provenance_key: ContentHash,
    /// Content-addressed manifest object for the fresh lineage.
    pub fresh_manifest_hash: ContentHash,
    /// Fresh immutable manifest persisted for the new lineage.
    pub fresh_manifest: CampaignManifest,
}

/// Novelty result for a candidate against accumulated campaign coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCoverageDelta {
    /// Accumulated coverage root used as the novelty baseline.
    pub coverage_map_root: ContentHash,
    /// Candidate edges absent from the accumulated map.
    pub new_edges: Vec<ContentHash>,
    /// Candidate edges already present in the accumulated map.
    pub known_edges: Vec<ContentHash>,
}

impl CampaignCoverageDelta {
    /// Returns whether the candidate adds campaign-lifetime coverage.
    #[must_use]
    pub fn is_novel(&self) -> bool {
        !self.new_edges.is_empty()
    }
}

/// A finding to add to a cross-run campaign ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignFinding {
    /// Content-addressed failure fingerprint.
    pub fingerprint: ContentHash,
    /// Self-contained reproduction artifact for the finding.
    pub artifact: CampaignReplayArtifact,
}

impl CampaignFinding {
    /// Builds a campaign finding from a fingerprint and replay artifact.
    #[must_use]
    pub fn new(fingerprint: ContentHash, artifact: CampaignReplayArtifact) -> Self {
        Self {
            fingerprint,
            artifact,
        }
    }
}

/// Finding entry loaded from a cross-run campaign ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedCampaignFinding {
    /// Content hash of the finding entry.
    pub finding_hash: ContentHash,
    /// Content-addressed failure fingerprint.
    pub fingerprint: ContentHash,
    /// Content hash of the self-contained replay artifact.
    pub artifact_hash: ContentHash,
    /// Replay hash recorded by the finding entry.
    pub replay_hash: ContentHash,
}

impl PersistedCampaignFinding {
    /// Returns whether `artifact` reproduces the recorded replay hash.
    #[must_use]
    pub fn reproduces_bit_identically(&self, artifact: &CampaignReplayArtifact) -> bool {
        artifact.replay_hash() == self.replay_hash
    }
}

/// Root set for campaign object garbage collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcRoots {
    /// Root of the retained campaign corpus.
    pub corpus_root: ContentHash,
    /// Root of the accumulated campaign coverage map.
    pub coverage_map_root: ContentHash,
    /// Root of the grow-only findings ledger.
    pub findings_root: ContentHash,
    /// Genesis checkpoint pin for this campaign lineage.
    pub genesis_pin: ContentHash,
}

impl CampaignGcRoots {
    /// Returns the manifest root hashes as a sorted set.
    #[must_use]
    pub fn root_set(&self) -> BTreeSet<ContentHash> {
        BTreeSet::from([
            self.corpus_root,
            self.coverage_map_root,
            self.findings_root,
            self.genesis_pin,
        ])
    }
}

/// New roots used when provenance drift forks a fresh campaign lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignFreshLineageRoots {
    /// Fresh retained corpus root for the new lineage.
    pub corpus_root: ContentHash,
    /// Fresh accumulated coverage root for the new lineage.
    pub coverage_map_root: ContentHash,
    /// Fresh findings ledger root for the new lineage.
    pub findings_root: ContentHash,
    /// Fresh genesis checkpoint pin for the new lineage.
    pub genesis_pin: ContentHash,
}

impl CampaignFreshLineageRoots {
    /// Builds a fresh-lineage root set.
    #[must_use]
    pub fn new(
        corpus_root: ContentHash,
        coverage_map_root: ContentHash,
        findings_root: ContentHash,
        genesis_pin: ContentHash,
    ) -> Self {
        Self {
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
        }
    }
}

/// Planned campaign garbage-collection result before deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcPlan {
    /// Manifest roots used for reachability.
    pub roots: CampaignGcRoots,
    /// Objects retained by root-to-object reachability.
    pub retained_objects: BTreeSet<ContentHash>,
    /// Candidate objects outside the retained closure.
    pub sweep_candidates: BTreeSet<ContentHash>,
}

/// Report from sweeping unpinned campaign object candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcReport {
    /// Reachability plan used by the sweep.
    pub plan: CampaignGcPlan,
    /// Candidate objects removed from the object store.
    pub swept_objects: BTreeSet<ContentHash>,
    /// Sweep candidates that were already absent.
    pub missing_objects: BTreeSet<ContentHash>,
}

/// Deterministic seeded retention policy for a campaign corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CampaignCorpusRetentionPolicy {
    /// Maximum number of replay artifacts to retain.
    pub cap: usize,
    /// Seed controlling the deterministic artifact ordering.
    pub seed: ContentHash,
}

impl CampaignCorpusRetentionPolicy {
    /// Builds a retention policy from a maximum retained artifact count and seed.
    #[must_use]
    pub fn new(cap: usize, seed: ContentHash) -> Self {
        Self { cap, seed }
    }
}

/// Result of applying deterministic seeded retention to a campaign corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCorpusRetentionReport {
    /// Source corpus root that was pruned.
    pub source_root: ContentHash,
    /// New retained corpus root containing source, cap, seed, and retained entries.
    pub retained_root: ContentHash,
    /// Maximum number of artifacts retained.
    pub cap: usize,
    /// Seed used for deterministic pruning.
    pub seed: ContentHash,
    /// Artifact hashes retained in the bounded corpus.
    pub retained_artifacts: Vec<ContentHash>,
    /// Artifact hashes evicted from the bounded corpus.
    pub evicted_artifacts: Vec<ContentHash>,
}

/// Campaign checkpoint cache state used to model fat-to-thin eviction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignCheckpointMaterialization {
    /// Content-addressed checkpoint identity and denoted state.
    pub checkpoint: ContentHash,
    /// Thin-source parent checkpoint.
    pub parent: ContentHash,
    /// Thin-source schedule delta from the parent.
    pub schedule_delta: ContentHash,
    /// Optional cache-only exact materialization for a fat checkpoint.
    pub materialization: Option<ContentHash>,
}

impl CampaignCheckpointMaterialization {
    /// Builds a fat checkpoint cache entry.
    #[must_use]
    pub fn fat(
        checkpoint: ContentHash,
        parent: ContentHash,
        schedule_delta: ContentHash,
        materialization: ContentHash,
    ) -> Self {
        Self {
            checkpoint,
            parent,
            schedule_delta,
            materialization: Some(materialization),
        }
    }

    /// Builds a thin checkpoint source entry.
    #[must_use]
    pub fn thin(checkpoint: ContentHash, parent: ContentHash, schedule_delta: ContentHash) -> Self {
        Self {
            checkpoint,
            parent,
            schedule_delta,
            materialization: None,
        }
    }

    /// Evicts a fat checkpoint cache entry to its thin source.
    ///
    /// The checkpoint identity, parent, and schedule delta are preserved. Only
    /// the optional materialization cache is removed.
    #[must_use]
    pub fn evict_to_thin(&self) -> CampaignCheckpointEviction {
        CampaignCheckpointEviction {
            before: self.clone(),
            after: Self::thin(self.checkpoint, self.parent, self.schedule_delta),
            evicted_materialization: self.materialization,
        }
    }
}

/// Before/after record for one campaign fat-to-thin eviction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignCheckpointEviction {
    /// Checkpoint cache entry before eviction.
    pub before: CampaignCheckpointMaterialization,
    /// Thin checkpoint source after eviction.
    pub after: CampaignCheckpointMaterialization,
    /// Cache-only materialization removed by eviction.
    pub evicted_materialization: Option<ContentHash>,
}

impl CampaignCheckpointEviction {
    /// Returns whether the eviction preserved checkpoint value and thin source.
    #[must_use]
    pub fn preserves_value(&self) -> bool {
        self.before.checkpoint == self.after.checkpoint
            && self.before.parent == self.after.parent
            && self.before.schedule_delta == self.after.schedule_delta
            && self.after.materialization.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CampaignCorpusRetentionRecord {
    source_root: ContentHash,
    policy: CampaignCorpusRetentionPolicy,
    entries: BTreeMap<ContentHash, ContentHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CampaignRootMerge {
    label: &'static str,
    left: ContentHash,
    right: ContentHash,
}
