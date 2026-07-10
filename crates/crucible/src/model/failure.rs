// Failure findings, signatures, clustering, reports, and triage artifacts.

/// Discovery path that produced an interesting finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingDiscoveryPath {
    /// Finding was produced by an interactive fork/session operation.
    InteractiveFork,
    /// Finding was produced by state-space search.
    StateSpaceSearch,
    /// Finding was produced by coverage-guided fuzzing.
    CoverageGuidedFuzzing,
    /// Finding is a retained coverage-guided corpus entry.
    RetainedCorpusEntry,
}

/// Self-contained reproduction artifact attached to one interesting finding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FindingReproductionArtifact {
    /// Discovery path that produced the finding.
    pub discovery_path: FindingDiscoveryPath,
    /// Stable finding fingerprint supplied by the discovering oracle.
    pub finding_fingerprint: ContentHash,
    /// Content-addressed execution configuration captured by the artifact.
    pub configuration: ContentHash,
    /// Self-contained `(seed, scenario, schedule)` artifact.
    pub artifact: ReproductionArtifact,
    /// Replay evidence proving the artifact reduces without snapshots.
    pub replay: ReproductionReplay,
}

impl FindingReproductionArtifact {
    /// Captures a finding artifact from a pinned scenario form and configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario` is
    /// not the concrete form for `configuration`. Returns other [`EngineError`]
    /// values when artifact capture or replay validation fails.
    pub fn capture(
        discovery_path: FindingDiscoveryPath,
        finding_fingerprint: ContentHash,
        scenario: &ScenarioDefForm,
        configuration: &Configuration,
    ) -> Result<Self, EngineError> {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != configuration.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: configuration.def.id,
                actual: scenario_def.id,
            });
        }
        let expected_state = reduce(&configuration.def, &configuration.schedule)?.id;
        let artifact = ReproductionArtifact::capture(scenario, &configuration.schedule)?;
        let replay = artifact.verify_replay(expected_state)?;
        Ok(Self {
            discovery_path,
            finding_fingerprint,
            configuration: configuration.id(),
            artifact,
            replay,
        })
    }

    /// Stores this finding's self-contained artifact bytes in `store`.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when `store` cannot persist the artifact bytes.
    pub fn store_artifact<S>(&self, store: &S) -> Result<ContentHash, DagStoreError>
    where
        S: DagStore + ?Sized,
    {
        store.put(&self.artifact.to_compact_binary())
    }

    /// Rebuilds a finding artifact from a stored self-contained artifact.
    ///
    /// # Errors
    ///
    /// Returns [`FindingReproductionArtifactError::Store`] when the store cannot
    /// read `artifact_key`. Returns [`FindingReproductionArtifactError::Engine`]
    /// when the stored artifact bytes are malformed or fail replay validation.
    pub fn load_from_store<S>(
        discovery_path: FindingDiscoveryPath,
        finding_fingerprint: ContentHash,
        store: &S,
        artifact_key: ContentHash,
    ) -> Result<Self, FindingReproductionArtifactError>
    where
        S: DagStore + ?Sized,
    {
        let bytes =
            store
                .get(&artifact_key)
                .map_err(|source| FindingReproductionArtifactError::Store {
                    operation: "get-finding-artifact",
                    source,
                })?;
        let artifact = ReproductionArtifact::from_compact_binary(&bytes).map_err(|source| {
            FindingReproductionArtifactError::Engine {
                operation: "decode-finding-artifact",
                source: Box::new(source),
            }
        })?;
        let replay =
            artifact
                .replay()
                .map_err(|source| FindingReproductionArtifactError::Engine {
                    operation: "replay-finding-artifact",
                    source: Box::new(source),
                })?;
        let configuration = Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        };
        Ok(Self {
            discovery_path,
            finding_fingerprint,
            configuration: configuration.id(),
            artifact,
            replay,
        })
    }

    /// Shrinks this finding while preserving its failure fingerprint.
    ///
    /// The minimizer enumerates every shorter recorded schedule subsequence in
    /// deterministic shortest-first order, with seeded content-address tie-breaks.
    /// Every candidate is replayed as a self-contained artifact before
    /// `failure_fingerprint` is consulted, and the first preserving candidate is
    /// therefore the stable shortest artifact under the supplied failure oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] or
    /// [`EngineError::ReproductionArtifactReplayMismatch`] when this public value
    /// does not match its embedded artifact/replay evidence, or when the starting
    /// artifact does not reproduce this finding's fingerprint. Returns other
    /// [`EngineError`] values when candidate capture, replay validation, or the
    /// caller-supplied failure oracle fails.
    pub fn minimize<F>(
        &self,
        config: MinimizationConfig,
        mut failure_fingerprint: F,
    ) -> Result<MinimizationRun, EngineError>
    where
        F: FnMut(&FindingReproductionArtifact) -> Result<Option<ContentHash>, EngineError>,
    {
        let original = self.validated()?;
        let target = original.finding_fingerprint;
        let initial = failure_fingerprint(&original)?;
        if initial != Some(target) {
            return Err(EngineError::ReplayTargetMismatch {
                expected: target,
                actual: initial.unwrap_or_default(),
            });
        }

        let mut attempts = Vec::new();
        let mut minimized = original.clone();
        let candidates = minimization_candidates(
            config.seed,
            original.artifact.id(),
            original.artifact.schedule(),
        );

        for (sequence, candidate) in candidates.into_iter().enumerate() {
            let configuration = Configuration {
                def: original.artifact.scenario_def(),
                schedule: candidate.schedule,
            };
            let finding = FindingReproductionArtifact::capture(
                original.discovery_path,
                target,
                original.artifact.scenario_form(),
                &configuration,
            )?;
            let observed_fingerprint = failure_fingerprint(&finding)?;
            let accepted_candidate = observed_fingerprint == Some(target);
            attempts.push(MinimizationAttempt {
                sequence: sequence as u64,
                removed_indices: candidate.removed_indices,
                removed_decisions: candidate.removed_decisions,
                candidate_artifact: finding.artifact.id(),
                candidate_schedule: finding.artifact.schedule().content_hash(),
                replayed_state: finding.replay.state,
                observed_fingerprint,
                accepted: accepted_candidate,
            });

            if accepted_candidate {
                minimized = finding;
                break;
            }
        }

        Ok(MinimizationRun {
            seed: config.seed,
            target_fingerprint: target,
            original,
            minimized,
            attempts,
        })
    }

    fn validated(&self) -> Result<Self, EngineError> {
        let replay = self.artifact.replay()?;
        if replay != self.replay {
            return Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: self.artifact.id(),
                expected: self.replay.state,
                actual: replay.state,
            });
        }
        let configuration = Configuration {
            def: self.artifact.scenario_def(),
            schedule: self.artifact.schedule().clone(),
        };
        let configuration_id = configuration.id();
        if configuration_id != self.configuration {
            return Err(EngineError::ReplayTargetMismatch {
                expected: self.configuration,
                actual: configuration_id,
            });
        }
        Ok(Self {
            discovery_path: self.discovery_path,
            finding_fingerprint: self.finding_fingerprint,
            configuration: configuration_id,
            artifact: self.artifact.clone(),
            replay,
        })
    }
}

/// Closed failure discriminant carried by a triage signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureKind {
    /// The recorded run contains a failed assertion or property violation.
    PropertyViolation,
    /// The recorded run diverged from deterministic replay and was localized by bisection.
    Divergence,
}

/// Stable property identity carried by a property-violation signature.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailurePropertyKey {
    /// Stable assertion or property identifier read from the violation record.
    pub id: AssertionId,
    /// Quantifier or guest marker flavor read from the violation record.
    pub quantifier: AssertionQuantifierKind,
}

/// First attributable point for one recorded failure.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureFirstFailingPoint {
    /// Open-set event kind attached to the violation site or bisection point.
    pub event_kind: String,
    /// Scenario node that owns the failure site, when the record is node-local.
    pub faulting_node: Option<NodeId>,
}

/// Bucketed coverage class used by the first failure-signature model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureCoverageClass {
    /// Versioned bucketing algorithm used for this class.
    pub algorithm: &'static str,
    /// Coarse deterministic bucket derived from the coverage fingerprint.
    pub bucket: u16,
}

impl FailureCoverageClass {
    /// Builds a bucketed class from a deterministic coverage fingerprint.
    #[must_use]
    pub fn from_coverage_fingerprint(coverage_fingerprint: ContentHash) -> Self {
        Self {
            algorithm: FAILURE_COVERAGE_CLASS_ALGORITHM,
            bucket: u16::from_be_bytes([
                coverage_fingerprint.bytes[0],
                coverage_fingerprint.bytes[1],
            ]),
        }
    }
}

/// Closed failure-signature policy levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignaturePolicyLevel {
    /// Clusters by failure kind and stable property id.
    Coarse,
    /// Clusters by the everyday failure key used by default triage.
    #[default]
    Default,
    /// Adds the cone-scoped causal slice hash to separate code paths.
    Fine,
    /// Adds absolute icount and full causal-cone material for forensic runs.
    Exact,
}

/// Versioned selector for failure-signature key fields.
///
/// The policy is closed over the four RFC0010 levels and records the schema
/// version plus coverage-class bucketing algorithm in every key projection and
/// triage result identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignaturePolicy {
    level: SignaturePolicyLevel,
}

impl SignaturePolicy {
    /// Returns the coarse clustering policy.
    #[must_use]
    pub fn coarse() -> Self {
        Self {
            level: SignaturePolicyLevel::Coarse,
        }
    }

    /// Returns the default clustering policy.
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            level: SignaturePolicyLevel::Default,
        }
    }

    /// Returns the fine-grained clustering policy.
    #[must_use]
    pub fn fine() -> Self {
        Self {
            level: SignaturePolicyLevel::Fine,
        }
    }

    /// Returns the exact forensic clustering policy.
    #[must_use]
    pub fn exact() -> Self {
        Self {
            level: SignaturePolicyLevel::Exact,
        }
    }

    /// Returns the closed policy level.
    #[must_use]
    pub fn level(&self) -> SignaturePolicyLevel {
        self.level
    }

    /// Returns the versioned policy schema identifier.
    #[must_use]
    pub fn schema_version(&self) -> u16 {
        SIGNATURE_POLICY_SCHEMA_VERSION
    }

    /// Returns the fixed coverage-class bucketing algorithm selected by policy.
    #[must_use]
    pub fn coverage_class_algorithm(&self) -> &'static str {
        FAILURE_COVERAGE_CLASS_ALGORITHM
    }

    /// Returns whether this policy allows minimization merges.
    ///
    /// `exact` is forensic and must not minimize-merge.
    #[must_use]
    pub fn allows_minimize_merge(&self) -> bool {
        !matches!(self.level, SignaturePolicyLevel::Exact)
    }

    /// Returns whether the causal slice hash is a key field.
    #[must_use]
    pub fn keys_causal_slice_hash(&self) -> bool {
        matches!(
            self.level,
            SignaturePolicyLevel::Fine | SignaturePolicyLevel::Exact
        )
    }

    /// Returns whether absolute icount is a key field.
    #[must_use]
    pub fn keys_absolute_icount(&self) -> bool {
        matches!(self.level, SignaturePolicyLevel::Exact)
    }

    /// Projects `signature` into this policy's deterministic key.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if the
    /// signature's coverage bucket was built by a different algorithm, or if the
    /// exact policy is requested for a signature that does not retain full
    /// causal-cone material.
    pub fn signature_key(
        &self,
        signature: &FailureSignature,
    ) -> Result<FailureSignatureKey, EngineError> {
        if signature.coverage_class.algorithm != self.coverage_class_algorithm() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.policy",
                reason: "signature coverage class algorithm does not match policy",
            });
        }
        if self.level == SignaturePolicyLevel::Exact && signature.causal_cone.is_none() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.policy",
                reason: "exact policy requires full causal cone material",
            });
        }
        Ok(FailureSignatureKey {
            policy: *self,
            canonical_material: failure_signature_key_material(signature, *self),
        })
    }

    /// Returns the canonical policy material included in result identities.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_signature_policy_material(*self)
    }

    /// Returns the content address of this policy selector.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_SIGNATURE_KEY_DOMAIN,
            &self.canonical_material(),
        )
    }
}

/// Deterministic projection of a signature under a [`SignaturePolicy`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureSignatureKey {
    policy: SignaturePolicy,
    canonical_material: String,
}

impl FailureSignatureKey {
    /// Returns the policy that selected this key's fields.
    #[must_use]
    pub fn policy(&self) -> SignaturePolicy {
        self.policy
    }

    /// Returns the canonical material hashed into the cluster id.
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the content-addressed cluster id for this key.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(FAILURE_SIGNATURE_KEY_DOMAIN, &self.canonical_material)
    }
}

/// Content-addressed identity of one triage result.
///
/// The findings ledger content address and active signature policy are both
/// included, so re-clustering the same ledger under the same policy resolves to
/// the same result identity while a policy change is a distinct artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureTriageResultIdentity {
    /// Content hash of the findings ledger being clustered.
    pub findings_ledger: ContentHash,
    /// Active policy used to project failure-signature keys.
    pub policy: SignaturePolicy,
}

impl FailureTriageResultIdentity {
    /// Builds a triage result identity from a findings ledger and policy.
    #[must_use]
    pub fn new(findings_ledger: ContentHash, policy: SignaturePolicy) -> Self {
        Self {
            findings_ledger,
            policy,
        }
    }

    /// Returns the canonical identity material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_triage_result_identity_material(*self)
    }

    /// Returns the content-addressed triage result id.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_TRIAGE_RESULT_IDENTITY_DOMAIN,
            &self.canonical_material(),
        )
    }
}

/// A content-addressed set of finding reproduction artifacts.
///
/// Artifact-only ledgers retain only reproduction-artifact content hashes and
/// require an external engine-owned evidence bundle before they can be triaged.
/// Signed ledgers additionally carry the discovery-time failure signature for
/// each finding, letting offline triage cluster by recorded evidence without
/// inventing signatures in the CLI.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureFindingsLedger {
    /// Artifact-only reproduction hashes in content-address order.
    pub artifacts: Vec<ContentHash>,
    /// Findings with discovery-time signatures in content-address order.
    pub findings: Vec<FailureClusterFinding>,
}

impl FailureFindingsLedger {
    /// Builds a deduplicated findings ledger from reproduction-artifact hashes.
    #[must_use]
    pub fn from_artifacts(artifacts: impl IntoIterator<Item = ContentHash>) -> Self {
        Self {
            artifacts: artifacts
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            findings: Vec::new(),
        }
    }

    /// Builds a signed findings ledger from discovery-time signatures.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if the same
    /// reproduction artifact is supplied with conflicting signature evidence.
    pub fn from_signed_findings(
        findings: impl IntoIterator<Item = FailureClusterFinding>,
    ) -> Result<Self, EngineError> {
        let mut ordered = BTreeMap::new();
        for finding in findings {
            match ordered.entry(finding.reproduction_artifact) {
                Entry::Vacant(entry) => {
                    entry.insert(finding);
                }
                Entry::Occupied(entry)
                    if entry.get().signature.report_material()
                        == finding.signature.report_material() => {}
                Entry::Occupied(_) => {
                    return Err(EngineError::UnifiedOperationEvidenceMismatch {
                        operation: "failure-findings-ledger",
                        reason: "same reproduction artifact has conflicting discovery signatures",
                    });
                }
            }
        }
        Ok(Self {
            artifacts: Vec::new(),
            findings: ordered.into_values().collect(),
        })
    }

    /// Returns the number of unique findings in this ledger.
    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len() + self.findings.len()
    }

    /// Returns signed findings consumable by the clustering engine.
    #[must_use]
    pub fn signed_findings(&self) -> &[FailureClusterFinding] {
        &self.findings
    }

    /// Returns canonical ledger material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_findings_ledger_material(self)
    }

    /// Returns the content address of this ledger.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_bytes(&self.artifact_bytes())
    }

    /// Returns the deterministic bytes stored in the `DagStore`.
    #[must_use]
    pub fn artifact_bytes(&self) -> Vec<u8> {
        failure_triage_artifact_bytes(FAILURE_FINDINGS_LEDGER_DOMAIN, &self.canonical_material())
    }

    /// Stores this ledger artifact and reports whether it was already present.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the store cannot query or persist the
    /// ledger bytes.
    pub fn store<S>(&self, store: &S) -> Result<FailureTriageStoredArtifact, DagStoreError>
    where
        S: DagStore + ?Sized,
    {
        store_failure_triage_artifact(store, &self.artifact_bytes())
    }
}

/// Result of storing a deterministic failure-triage artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageStoredArtifact {
    /// `DagStore` object key for the stored bytes.
    pub key: ContentHash,
    /// Whether the same object was present before this store operation.
    pub cache_hit: bool,
    /// Stored byte length.
    pub size_bytes: usize,
}

/// One signature recomputation pair checked by offline triage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageSignatureSelfCheckInput {
    /// Finding reproduction artifact whose signature was checked.
    pub reproduction_artifact: ContentHash,
    /// Signature recorded when the finding was discovered.
    pub discovery_signature: FailureSignature,
    /// Signature recomputed offline from stored evidence.
    pub recomputed_signature: FailureSignature,
}

impl FailureTriageSignatureSelfCheckInput {
    /// Builds one offline signature recomputation check input.
    #[must_use]
    pub fn new(
        reproduction_artifact: ContentHash,
        discovery_signature: FailureSignature,
        recomputed_signature: FailureSignature,
    ) -> Self {
        Self {
            reproduction_artifact,
            discovery_signature,
            recomputed_signature,
        }
    }
}

/// Byte-for-byte signature recomputation mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageSignatureMismatch {
    /// Finding reproduction artifact whose signature drifted.
    pub reproduction_artifact: ContentHash,
    /// Content hash of the discovery-time signature key material.
    pub discovery_signature_hash: ContentHash,
    /// Content hash of the recomputed signature key material.
    pub recomputed_signature_hash: ContentHash,
    /// Hash of the full discovery-time reportable signature bytes.
    pub discovery_signature_bytes: ContentHash,
    /// Hash of the full recomputed reportable signature bytes.
    pub recomputed_signature_bytes: ContentHash,
}

/// Per-finding signature bytes compared by an offline self-check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageSignatureCheckRecord {
    /// Finding reproduction artifact whose signature was checked.
    pub reproduction_artifact: ContentHash,
    /// Content hash of the discovery-time signature tuple.
    pub discovery_signature_hash: ContentHash,
    /// Content hash of the recomputed signature tuple.
    pub recomputed_signature_hash: ContentHash,
    /// Hash of the full discovery-time reportable signature bytes.
    pub discovery_signature_bytes: ContentHash,
    /// Hash of the full recomputed reportable signature bytes.
    pub recomputed_signature_bytes: ContentHash,
    /// Whether the full reportable signature bytes matched.
    pub matched: bool,
}

/// Offline `--recompute-signatures` result for a findings ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageSignatureSelfCheck {
    /// Number of finding signatures recomputed.
    pub checked_count: usize,
    /// Per-finding byte comparisons, ordered by reproduction artifact.
    pub checks: Vec<FailureTriageSignatureCheckRecord>,
    /// Byte-for-byte mismatches, ordered by reproduction artifact.
    pub mismatches: Vec<FailureTriageSignatureMismatch>,
}

impl FailureTriageSignatureSelfCheck {
    /// Builds an empty self-check for a run that did not request recomputation.
    #[must_use]
    pub const fn skipped() -> Self {
        Self {
            checked_count: 0,
            checks: Vec::new(),
            mismatches: Vec::new(),
        }
    }

    /// Recomputes the deterministic mismatch list from signature pairs.
    #[must_use]
    pub fn from_signature_pairs(
        pairs: impl IntoIterator<Item = FailureTriageSignatureSelfCheckInput>,
    ) -> Self {
        let mut checked_count = 0usize;
        let mut checks = BTreeMap::new();
        let mut mismatches = BTreeMap::new();
        for pair in pairs {
            checked_count = checked_count.saturating_add(1);
            let discovery_material = pair.discovery_signature.report_material();
            let recomputed_material = pair.recomputed_signature.report_material();
            let discovery_signature_hash = pair.discovery_signature.content_hash();
            let recomputed_signature_hash = pair.recomputed_signature.content_hash();
            let discovery_signature_bytes =
                failure_signature_report_bytes_hash(&discovery_material);
            let recomputed_signature_bytes =
                failure_signature_report_bytes_hash(&recomputed_material);
            let matched = discovery_material == recomputed_material;
            let record = FailureTriageSignatureCheckRecord {
                reproduction_artifact: pair.reproduction_artifact,
                discovery_signature_hash,
                recomputed_signature_hash,
                discovery_signature_bytes,
                recomputed_signature_bytes,
                matched,
            };
            if !matched {
                mismatches.insert(
                    pair.reproduction_artifact,
                    FailureTriageSignatureMismatch {
                        reproduction_artifact: pair.reproduction_artifact,
                        discovery_signature_hash,
                        recomputed_signature_hash,
                        discovery_signature_bytes,
                        recomputed_signature_bytes,
                    },
                );
            }
            checks.insert(pair.reproduction_artifact, record);
        }

        Self {
            checked_count,
            checks: checks.into_values().collect(),
            mismatches: mismatches.into_values().collect(),
        }
    }

    /// Returns whether every recomputed signature matched byte-for-byte.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty()
    }

    /// Fails if any recomputed signature differs from its discovery-time bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] when at least
    /// one recomputed signature differs from its discovery-time signature bytes.
    pub fn assert_clean(&self) -> Result<(), EngineError> {
        if self.is_clean() {
            Ok(())
        } else {
            Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-signature-self-check",
                reason: "recomputed signature does not match discovery-time signature",
            })
        }
    }

    /// Returns canonical self-check material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_triage_signature_self_check_material(self)
    }

    /// Returns the content hash of this self-check result.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_TRIAGE_SIGNATURE_SELF_CHECK_DOMAIN,
            &self.canonical_material(),
        )
    }
}

/// Complete content-addressed triage result for one findings ledger and policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureTriageResult {
    /// Content-addressed result identity.
    pub identity: FailureTriageResultIdentity,
    /// Deterministic clustering output.
    pub clustering: FailureClusteringResult,
    /// Signature-preserving minimized representatives.
    pub minimization: FailureSignaturePreservingMinimizationResult,
    /// Per-cluster reports emitted for the minimized representatives.
    pub report_set: FailureClusterReportSet,
    /// Offline signature recomputation result.
    pub signature_self_check: FailureTriageSignatureSelfCheck,
}

impl FailureTriageResult {
    /// Builds and validates a complete triage result.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] when the
    /// clustering, minimization, report set, or self-check do not describe the
    /// same `(findings ledger, policy)` triage result.
    pub fn from_parts(
        findings_ledger: ContentHash,
        clustering: FailureClusteringResult,
        minimization: FailureSignaturePreservingMinimizationResult,
        report_set: FailureClusterReportSet,
        signature_self_check: FailureTriageSignatureSelfCheck,
    ) -> Result<Self, EngineError> {
        if minimization.policy != clustering.policy {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "minimization policy does not match clustering policy",
            });
        }
        if report_set.policy != clustering.policy {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "report-set policy does not match clustering policy",
            });
        }
        let cluster_ids = clustering
            .clusters
            .iter()
            .map(|cluster| cluster.id)
            .collect::<BTreeSet<_>>();
        if cluster_ids.len() != clustering.clusters.len() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "duplicate cluster id",
            });
        }
        let minimization_ids = minimization
            .runs
            .iter()
            .map(|run| run.cluster_id)
            .collect::<BTreeSet<_>>();
        if minimization_ids.len() != minimization.runs.len() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "duplicate minimization run for cluster",
            });
        }
        let report_ids = report_set
            .reports
            .iter()
            .map(|report| report.cluster_id)
            .collect::<BTreeSet<_>>();
        if report_ids.len() != report_set.reports.len() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "duplicate report for cluster",
            });
        }
        let member_signature_hashes = clustering
            .clusters
            .iter()
            .flat_map(|cluster| cluster.members.iter())
            .map(|member| {
                (
                    member.reproduction_artifact,
                    member.signature.content_hash(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if member_signature_hashes.len() != clustering.member_count() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "duplicate finding artifact in clusters",
            });
        }
        if signature_self_check.checked_count != signature_self_check.checks.len() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "signature self-check count does not match checked records",
            });
        }
        let checked_artifacts = signature_self_check
            .checks
            .iter()
            .map(|check| check.reproduction_artifact)
            .collect::<BTreeSet<_>>();
        if checked_artifacts.len() != signature_self_check.checks.len() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "duplicate signature self-check record",
            });
        }
        if signature_self_check.checked_count != 0 {
            let clustered_artifacts = member_signature_hashes
                .keys()
                .copied()
                .collect::<BTreeSet<_>>();
            if signature_self_check.checked_count != clustering.member_count()
                || checked_artifacts != clustered_artifacts
            {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "signature self-check did not cover every finding",
                });
            }
        }
        if signature_self_check
            .checks
            .iter()
            .any(|check| !check.matched)
        {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "signature self-check contains an unmatched record",
            });
        }
        for check in &signature_self_check.checks {
            let expected_signature = member_signature_hashes
                .get(&check.reproduction_artifact)
                .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "signature self-check record is not in clustered findings",
                })?;
            if check.discovery_signature_hash != *expected_signature {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "signature self-check discovery hash does not match cluster member",
                });
            }
            if check.matched
                != (check.discovery_signature_bytes == check.recomputed_signature_bytes
                    && check.discovery_signature_hash == check.recomputed_signature_hash)
            {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "signature self-check matched flag contradicts signature bytes",
                });
            }
        }
        signature_self_check.assert_clean()?;
        if cluster_ids != minimization_ids || cluster_ids != report_ids {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "cluster, minimization, and report ids do not match",
            });
        }

        let reports_by_cluster = report_set
            .reports
            .iter()
            .map(|report| (report.cluster_id, report))
            .collect::<BTreeMap<_, _>>();
        let runs_by_cluster = minimization
            .runs
            .iter()
            .map(|run| (run.cluster_id, run))
            .collect::<BTreeMap<_, _>>();
        for cluster in &clustering.clusters {
            if cluster.id != cluster.signature_key.content_hash() {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "cluster id does not match signature key",
                });
            }
            let representative = cluster.representative_member().ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "cluster has no representative",
                },
            )?;
            let run = runs_by_cluster.get(&cluster.id).ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "missing minimization run for cluster",
                },
            )?;
            if run.representative_artifact != representative.reproduction_artifact {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "minimization run does not use cluster representative",
                });
            }
            if run.minimization.original.artifact.id() != representative.reproduction_artifact {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "minimization original does not match cluster representative",
                });
            }
            if run.target_signature_key != cluster.signature_key
                || run.minimized_signature_key != cluster.signature_key
                || !run.preserves_signature()
            {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "minimization signature key does not match cluster",
                });
            }
            let report = reports_by_cluster.get(&cluster.id).ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "missing report for cluster",
                },
            )?;
            if report.member_count != cluster.members.len()
                || report.member_hashes != cluster.member_hashes()
                || report.representative_artifact != representative.reproduction_artifact
            {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "report membership does not match cluster",
                });
            }
            if report.signature.signature_key(clustering.policy)? != cluster.signature_key {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "report signature key does not match cluster",
                });
            }
        }
        for run in &minimization.runs {
            let report = reports_by_cluster.get(&run.cluster_id).ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "missing report for minimized cluster",
                },
            )?;
            if report.minimal_representative != run.minimized_artifact() {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "report minimal representative does not match minimization",
                });
            }
        }

        Ok(Self {
            identity: FailureTriageResultIdentity::new(findings_ledger, clustering.policy),
            clustering,
            minimization,
            report_set,
            signature_self_check,
        })
    }

    /// Returns canonical result material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_triage_result_material(self)
    }

    /// Returns the logical content address of this result.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_bytes(&self.artifact_bytes())
    }

    /// Returns the deterministic bytes stored in the `DagStore`.
    #[must_use]
    pub fn artifact_bytes(&self) -> Vec<u8> {
        failure_triage_artifact_bytes(FAILURE_TRIAGE_RESULT_DOMAIN, &self.canonical_material())
    }

    /// Stores this triage result and reports whether it was already present.
    ///
    /// # Errors
    ///
    /// Returns [`DagStoreError`] when the store cannot query or persist the
    /// result bytes.
    pub fn store<S>(&self, store: &S) -> Result<FailureTriageStoredArtifact, DagStoreError>
    where
        S: DagStore + ?Sized,
    {
        store_failure_triage_artifact(store, &self.artifact_bytes())
    }

    /// Returns a content diff from `baseline` to this result.
    #[must_use]
    pub fn compare_to(&self, baseline: &Self) -> FailureTriageResultDiff {
        FailureTriageResultDiff::between(baseline, self)
    }
}

/// One cluster whose content changed between two triage results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageChangedCluster {
    /// Shared cluster id.
    pub cluster_id: ContentHash,
    /// Baseline report content hash.
    pub baseline_report: ContentHash,
    /// Candidate report content hash.
    pub candidate_report: ContentHash,
}

/// Content diff between two stored triage results.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureTriageResultDiff {
    /// Baseline triage result hash.
    pub baseline: ContentHash,
    /// Candidate triage result hash.
    pub candidate: ContentHash,
    /// Clusters present only in the candidate result.
    pub added_clusters: Vec<ContentHash>,
    /// Clusters present only in the baseline result.
    pub removed_clusters: Vec<ContentHash>,
    /// Clusters present in both results with changed report content.
    pub changed_clusters: Vec<FailureTriageChangedCluster>,
    /// Clusters present in both results with identical report content.
    pub unchanged_clusters: Vec<ContentHash>,
}

impl FailureTriageResultDiff {
    /// Builds a deterministic content diff from `baseline` to `candidate`.
    #[must_use]
    pub fn between(baseline: &FailureTriageResult, candidate: &FailureTriageResult) -> Self {
        let baseline_reports = triage_report_hashes_by_cluster(baseline);
        let candidate_reports = triage_report_hashes_by_cluster(candidate);
        let mut added_clusters = Vec::new();
        let mut removed_clusters = Vec::new();
        let mut changed_clusters = Vec::new();
        let mut unchanged_clusters = Vec::new();
        let all_clusters = baseline_reports
            .keys()
            .chain(candidate_reports.keys())
            .copied()
            .collect::<BTreeSet<_>>();

        for cluster_id in all_clusters {
            match (
                baseline_reports.get(&cluster_id),
                candidate_reports.get(&cluster_id),
            ) {
                (None, Some(_)) => added_clusters.push(cluster_id),
                (Some(_), None) => removed_clusters.push(cluster_id),
                (Some(baseline_report), Some(candidate_report))
                    if baseline_report == candidate_report =>
                {
                    unchanged_clusters.push(cluster_id);
                }
                (Some(baseline_report), Some(candidate_report)) => {
                    changed_clusters.push(FailureTriageChangedCluster {
                        cluster_id,
                        baseline_report: *baseline_report,
                        candidate_report: *candidate_report,
                    });
                }
                (None, None) => {}
            }
        }

        Self {
            baseline: baseline.content_hash(),
            candidate: candidate.content_hash(),
            added_clusters,
            removed_clusters,
            changed_clusters,
            unchanged_clusters,
        }
    }

    /// Returns whether the content diff contains any added, removed, or changed clusters.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !(self.added_clusters.is_empty()
            && self.removed_clusters.is_empty()
            && self.changed_clusters.is_empty())
    }

    /// Returns canonical diff material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_triage_result_diff_material(self)
    }

    /// Returns the content hash of this diff.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_TRIAGE_RESULT_DIFF_DOMAIN,
            &self.canonical_material(),
        )
    }

    /// Renders the deterministic content diff as text.
    #[must_use]
    pub fn content_diff(&self) -> String {
        let mut lines = vec![
            format!("baseline\t{}", format_content_hash_ref(self.baseline)),
            format!("candidate\t{}", format_content_hash_ref(self.candidate)),
        ];
        for cluster in &self.added_clusters {
            lines.push(format!("added\t{}", format_content_hash_ref(*cluster)));
        }
        for cluster in &self.removed_clusters {
            lines.push(format!("removed\t{}", format_content_hash_ref(*cluster)));
        }
        for changed in &self.changed_clusters {
            lines.push(format!(
                "changed\t{}\t{}\t{}",
                format_content_hash_ref(changed.cluster_id),
                format_content_hash_ref(changed.baseline_report),
                format_content_hash_ref(changed.candidate_report)
            ));
        }
        for cluster in &self.unchanged_clusters {
            lines.push(format!("unchanged\t{}", format_content_hash_ref(*cluster)));
        }
        lines.join("\n")
    }
}

/// One finding and its recorded failure signature as consumed by clustering.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureClusterFinding {
    /// Content hash of the reproduction artifact represented by this finding.
    pub reproduction_artifact: ContentHash,
    /// Recorded signature computed from the finding's stored run.
    pub signature: FailureSignature,
}

impl FailureClusterFinding {
    /// Builds one clustering input item.
    #[must_use]
    pub fn new(reproduction_artifact: ContentHash, signature: FailureSignature) -> Self {
        Self {
            reproduction_artifact,
            signature,
        }
    }
}

/// One deterministically ordered member of a failure cluster.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureClusterMember {
    /// Content hash of the member reproduction artifact.
    pub reproduction_artifact: ContentHash,
    /// Signature recorded for this member.
    pub signature: FailureSignature,
}

/// Deterministic equivalence class of findings sharing one signature key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureCluster {
    /// Cluster id, defined as the content hash of [`Self::signature_key`].
    pub id: ContentHash,
    /// Policy-projected key shared by every member.
    pub signature_key: FailureSignatureKey,
    /// Members ordered by reproduction-artifact content hash.
    pub members: Vec<FailureClusterMember>,
}

impl FailureCluster {
    /// Returns the content-address-least member for representative selection.
    #[must_use]
    pub fn representative_member(&self) -> Option<&FailureClusterMember> {
        self.members.first()
    }

    /// Returns member reproduction-artifact hashes in deterministic order.
    #[must_use]
    pub fn member_hashes(&self) -> Vec<ContentHash> {
        self.members
            .iter()
            .map(|member| member.reproduction_artifact)
            .collect()
    }
}

/// Deterministic clustering output for a findings ledger under one policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureClusteringResult {
    /// Policy used to project signature keys.
    pub policy: SignaturePolicy,
    /// Clusters ordered by cluster id.
    pub clusters: Vec<FailureCluster>,
}

impl FailureClusteringResult {
    /// Partitions findings into deterministic content-address ordered clusters.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if a signature
    /// cannot be projected under `policy`, two distinct keys collide to the same
    /// cluster id, or the same reproduction artifact is supplied with conflicting
    /// signature evidence.
    pub fn from_findings(
        policy: SignaturePolicy,
        findings: impl IntoIterator<Item = FailureClusterFinding>,
    ) -> Result<Self, EngineError> {
        let mut clusters = BTreeMap::new();
        let mut seen_artifacts = BTreeMap::new();

        for finding in findings {
            let signature_key = finding.signature.signature_key(policy)?;
            let cluster_id = signature_key.content_hash();
            let signature_report = finding.signature.report_material();
            if let Some((previous_key, previous_report)) = seen_artifacts.insert(
                finding.reproduction_artifact,
                (signature_key.clone(), signature_report.clone()),
            ) && (previous_key != signature_key || previous_report != signature_report)
            {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-clustering",
                    reason: "same reproduction artifact has conflicting failure signatures",
                });
            }

            let member = FailureClusterMember {
                reproduction_artifact: finding.reproduction_artifact,
                signature: finding.signature,
            };
            match clusters.entry(cluster_id) {
                Entry::Vacant(entry) => {
                    let mut members = BTreeMap::new();
                    members.insert(member.reproduction_artifact, member);
                    entry.insert(FailureClusterBuilder {
                        signature_key,
                        members,
                    });
                }
                Entry::Occupied(mut entry) => {
                    if entry.get().signature_key != signature_key {
                        return Err(EngineError::UnifiedOperationEvidenceMismatch {
                            operation: "failure-clustering",
                            reason: "distinct signature keys collided to one cluster id",
                        });
                    }
                    entry
                        .get_mut()
                        .members
                        .insert(member.reproduction_artifact, member);
                }
            }
        }

        let clusters = clusters
            .into_iter()
            .map(|(id, builder)| FailureCluster {
                id,
                signature_key: builder.signature_key,
                members: builder.members.into_values().collect(),
            })
            .collect();

        Ok(Self { policy, clusters })
    }

    /// Returns the number of clusters in the partition.
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Returns the total number of clustered members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.clusters
            .iter()
            .map(|cluster| cluster.members.len())
            .sum()
    }

    /// Returns canonical result material with clusters and members in content order.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_clustering_result_material(self)
    }

    /// Returns the content address of this deterministic clustering output.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_CLUSTERING_RESULT_DOMAIN,
            &self.canonical_material(),
        )
    }

    /// Minimizes the content-address-least representative from each cluster.
    ///
    /// This extends [`FindingReproductionArtifact::minimize`] by using
    /// `signature` as the failure oracle: a replay-validated candidate is
    /// accepted only when `signature(candidate, policy) ==
    /// signature(original, policy)` under this result's active policy.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] when cluster
    /// evidence is internally inconsistent, a representative cannot be loaded,
    /// or the minimized artifact does not preserve the original signature key.
    /// Returns other [`EngineError`] values from representative loading,
    /// candidate replay, or signature recomputation.
    pub fn minimize_representatives<L, F>(
        &self,
        config: MinimizationConfig,
        mut load_representative: L,
        mut signature: F,
    ) -> Result<FailureSignaturePreservingMinimizationResult, EngineError>
    where
        L: FnMut(ContentHash) -> Result<FindingReproductionArtifact, EngineError>,
        F: FnMut(&FindingReproductionArtifact) -> Result<Option<FailureSignature>, EngineError>,
    {
        let mut runs = Vec::new();
        for cluster in &self.clusters {
            if cluster.id != cluster.signature_key.content_hash() {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "signature-preserving-minimization",
                    reason: "cluster id does not match signature key",
                });
            }
            let representative = cluster.representative_member().ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "signature-preserving-minimization",
                    reason: "cluster has no representative",
                },
            )?;
            let target_signature_key = representative.signature.signature_key(self.policy)?;
            if target_signature_key != cluster.signature_key {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "signature-preserving-minimization",
                    reason: "representative signature key does not match cluster",
                });
            }

            let original = load_representative(representative.reproduction_artifact)?;
            expect_content_hash(
                original.artifact.id(),
                representative.reproduction_artifact,
                "signature-preserving-representative-artifact",
            )?;
            let target_fingerprint = original.finding_fingerprint;
            let policy = self.policy;
            let target_key_for_oracle = target_signature_key.clone();
            let minimization = original.minimize(config, |candidate| {
                let Some(candidate_signature) = signature(candidate)? else {
                    return Ok(None);
                };
                let candidate_key = candidate_signature.signature_key(policy)?;
                Ok((candidate_key == target_key_for_oracle).then_some(target_fingerprint))
            })?;

            let minimized_signature = signature(&minimization.minimized)?.ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "signature-preserving-minimization",
                    reason: "minimal representative has no failure signature",
                },
            )?;
            let minimized_signature_key = minimized_signature.signature_key(self.policy)?;
            if minimized_signature_key != target_signature_key {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "signature-preserving-minimization",
                    reason: "minimal representative signature changed",
                });
            }

            runs.push(FailureSignaturePreservingMinimizationRun {
                cluster_id: cluster.id,
                representative_artifact: representative.reproduction_artifact,
                target_signature_key,
                minimized_signature_key,
                minimization,
            });
        }

        Ok(FailureSignaturePreservingMinimizationResult {
            policy: self.policy,
            runs,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FailureClusterBuilder {
    signature_key: FailureSignatureKey,
    members: BTreeMap<ContentHash, FailureClusterMember>,
}

/// Signature-preserving minimization evidence for one failure cluster.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSignaturePreservingMinimizationRun {
    /// Cluster whose representative was minimized.
    pub cluster_id: ContentHash,
    /// Content-address-least reproduction artifact selected from the cluster.
    pub representative_artifact: ContentHash,
    /// Signature key that must be preserved by every accepted candidate.
    pub target_signature_key: FailureSignatureKey,
    /// Signature key observed for the emitted minimal representative.
    pub minimized_signature_key: FailureSignatureKey,
    /// Underlying replay-validated minimization run from the base shrink pass.
    pub minimization: MinimizationRun,
}

impl FailureSignaturePreservingMinimizationRun {
    /// Returns whether the emitted minimal representative preserves the target key.
    #[must_use]
    pub fn preserves_signature(&self) -> bool {
        self.target_signature_key == self.minimized_signature_key
    }

    /// Returns the content hash of the emitted minimal reproduction artifact.
    #[must_use]
    pub fn minimized_artifact(&self) -> ContentHash {
        self.minimization.minimized.artifact.id()
    }
}

/// Signature-preserving minimization output for a clustering result.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSignaturePreservingMinimizationResult {
    /// Active signature policy used as the candidate accept predicate.
    pub policy: SignaturePolicy,
    /// One minimized representative per cluster, ordered by cluster id.
    pub runs: Vec<FailureSignaturePreservingMinimizationRun>,
}

impl FailureSignaturePreservingMinimizationResult {
    /// Returns the number of clusters minimized.
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        self.runs.len()
    }

    /// Returns the number of minimal representatives emitted.
    #[must_use]
    pub fn minimized_count(&self) -> usize {
        self.runs.len()
    }

    /// Returns canonical result material with runs in cluster-id order.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_signature_preserving_minimization_result_material(self)
    }

    /// Returns the content address of the deterministic minimization result.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_SIGNATURE_MINIMIZATION_RESULT_DOMAIN,
            &self.canonical_material(),
        )
    }
}

/// Deterministic rendering formats for per-cluster triage reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureClusterReportFormat {
    /// Machine-readable JSON object rendering.
    Json,
    /// Machine-readable JSON Lines rendering with one report per line.
    JsonLines,
    /// Human-readable tabular key/value rendering.
    Table,
    /// Human-readable Markdown rendering.
    Markdown,
}

/// Divergence detail carried by a per-cluster report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureClusterReportDivergence {
    /// Raw unified-log index of the bisected first differing causal entry.
    pub raw_index: usize,
    /// Node attributed to the first difference, when node-local.
    pub node: Option<NodeId>,
    /// Node carried by the original icount stamp, when node-local.
    pub icount_node: Option<NodeId>,
    /// Retired-instruction coordinate of the first difference.
    pub icount: Icount,
    /// Closed source that emitted the first differing entry.
    pub source: EventSource,
    /// Open-set event kind of the first differing entry.
    pub kind: String,
    /// Deterministic summary of the expected-side state at the difference.
    pub expected_state_summary: String,
    /// Deterministic summary of the reproduced-side state at the difference.
    pub reproduced_state_summary: String,
}

impl FailureClusterReportDivergence {
    /// Builds reportable divergence detail from a replay-oracle bisection point.
    #[must_use]
    pub fn from_bisected_first_diff(
        point: &EventLogCausalDivergencePoint,
        expected_state_summary: impl Into<String>,
        reproduced_state_summary: impl Into<String>,
    ) -> Self {
        Self {
            raw_index: point.raw_index,
            node: divergence_faulting_node(point),
            icount_node: point.at.node.clone(),
            icount: point.at.icount,
            source: point.source.clone(),
            kind: point.kind.clone(),
            expected_state_summary: expected_state_summary.into(),
            reproduced_state_summary: reproduced_state_summary.into(),
        }
    }

    fn to_divergence_point(&self) -> EventLogCausalDivergencePoint {
        EventLogCausalDivergencePoint {
            raw_index: self.raw_index,
            at: EventLogIcountStamp {
                node: self.icount_node.clone(),
                icount: self.icount,
            },
            source: self.source.clone(),
            kind: self.kind.clone(),
        }
    }
}

/// Failure-specific detail carried by a per-cluster report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FailureClusterReportFailure {
    /// Property-violation record read from the stored assertion result.
    Property(FailurePropertyViolationRecord),
    /// Replay-oracle divergence localized by causal-log bisection.
    Divergence(FailureClusterReportDivergence),
}

impl FailureClusterReportFailure {
    /// Builds report detail for a failed property.
    #[must_use]
    pub fn property(record: FailurePropertyViolationRecord) -> Self {
        Self::Property(record)
    }

    /// Builds report detail for a determinism divergence.
    #[must_use]
    pub fn divergence(detail: FailureClusterReportDivergence) -> Self {
        Self::Divergence(detail)
    }
}

/// One causal-log step rendered in a per-cluster report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureClusterReportCausalStep {
    /// Index of this entry in the original unified log before causal filtering.
    pub raw_index: usize,
    /// Renumbered causal-log sequence after filtering observational noise.
    pub sequence: u64,
    /// Canonical node attributed to this step, when node-local.
    pub node: Option<NodeId>,
    /// Retired-instruction coordinate for the step.
    pub icount: Icount,
    /// Open-set event kind.
    pub kind: String,
    /// Closed source rendered under the report's canonical relabeling.
    pub source: String,
    /// Content address of the canonical event-log entry.
    pub entry: ContentHash,
}

/// Minimal reproduction tuple referenced by a per-cluster report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureClusterReportReproduction {
    /// Self-contained reproduction artifact content hash.
    pub artifact: ContentHash,
    /// Root seed embedded in the scenario form.
    pub seed: Seed,
    /// Scenario definition content hash.
    pub scenario: ContentHash,
    /// Schedule content hash.
    pub schedule: ContentHash,
}

/// Deterministic per-cluster triage report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureClusterReport {
    /// Active policy used for the cluster and minimized representative.
    pub policy: SignaturePolicy,
    /// Cluster id, the content hash of the policy-projected signature key.
    pub cluster_id: ContentHash,
    /// Full failure signature for the minimized representative.
    pub signature: FailureSignature,
    /// Member reproduction-artifact hashes in content-address order.
    pub member_hashes: Vec<ContentHash>,
    /// Count of member reproduction artifacts.
    pub member_count: usize,
    /// Original representative selected from the cluster.
    pub representative_artifact: ContentHash,
    /// Signature-preserving minimal representative artifact.
    pub minimal_representative: ContentHash,
    /// Minimal self-contained reproduction tuple.
    pub minimal_reproduction: FailureClusterReportReproduction,
    /// Property-violation or divergence detail for the report.
    pub failure: FailureClusterReportFailure,
    /// Last-N causal entries leading to the first failing point.
    pub event_log_excerpt: Vec<FailureClusterReportCausalStep>,
    /// Ordered causal-cone narrative leading to the failure.
    pub causal_chain: Vec<FailureClusterReportCausalStep>,
    /// Exact replay command for the minimized artifact.
    pub replay_command: String,
}

impl FailureClusterReport {
    /// Builds a deterministic report for one minimized cluster representative.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if the cluster,
    /// minimization run, failure detail, or event-log evidence are not all bound
    /// to the same minimized representative. Returns other [`EngineError`]
    /// values if the minimized representative's signature cannot be recomputed
    /// or projected under `policy`.
    pub fn from_cluster(
        policy: SignaturePolicy,
        cluster: &FailureCluster,
        minimization: &FailureSignaturePreservingMinimizationRun,
        failure: FailureClusterReportFailure,
        event_log: &FailureRecordedEventLog,
        normalization: &FailureSignatureNormalization,
        excerpt_len: usize,
    ) -> Result<Self, EngineError> {
        if cluster.id != cluster.signature_key.content_hash() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "cluster id does not match signature key",
            });
        }
        if minimization.cluster_id != cluster.id {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "minimization run does not belong to cluster",
            });
        }
        let representative = cluster.representative_member().ok_or(
            EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "cluster has no representative",
            },
        )?;
        if minimization.representative_artifact != representative.reproduction_artifact {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "minimization run does not use cluster representative",
            });
        }
        if minimization.minimization.original.artifact.id() != representative.reproduction_artifact
        {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "minimization original does not match cluster representative",
            });
        }
        if minimization.target_signature_key != cluster.signature_key {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "minimization target signature key does not match cluster",
            });
        }
        if !minimization.preserves_signature() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "minimization run did not preserve signature",
            });
        }

        let minimal_representative = minimization.minimized_artifact();
        if event_log.artifact() != minimal_representative {
            return Err(EngineError::ReplayTargetMismatch {
                expected: minimal_representative,
                actual: event_log.artifact(),
            });
        }
        let signature = failure_signature_for_report_failure(
            &minimization.minimization.minimized,
            event_log,
            &failure,
            normalization,
        )?;
        let signature_key = signature.signature_key(policy)?;
        if signature_key != cluster.signature_key
            || signature_key != minimization.minimized_signature_key
        {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-cluster-report",
                reason: "report signature key does not match cluster",
            });
        }

        let causal_index = failure_report_anchor_index(&failure, event_log)?;
        let canonicalizer = event_log.symmetry_canonicalizer(normalization);
        let event_log_excerpt =
            failure_report_excerpt(event_log, causal_index, excerpt_len, &canonicalizer);
        let causal_chain = failure_causal_cone_entries(event_log, causal_index, &canonicalizer)
            .into_iter()
            .map(|entry| failure_cluster_report_causal_step(entry, &canonicalizer))
            .collect::<Vec<_>>();

        let minimized = &minimization.minimization.minimized.artifact;
        let minimal_reproduction = FailureClusterReportReproduction {
            artifact: minimized.id(),
            seed: minimized.seed(),
            scenario: minimized.scenario_def().id,
            schedule: minimized.schedule().content_hash(),
        };
        let replay_command = format!(
            "crucible replay {}",
            format_content_hash_ref(minimized.id())
        );

        Ok(Self {
            policy,
            cluster_id: cluster.id,
            signature,
            member_hashes: cluster.member_hashes(),
            member_count: cluster.members.len(),
            representative_artifact: minimization.representative_artifact,
            minimal_representative,
            minimal_reproduction,
            failure,
            event_log_excerpt,
            causal_chain,
            replay_command,
        })
    }

    /// Returns canonical report material shared by every rendering.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_cluster_report_material(self)
    }

    /// Returns the content address of this per-cluster report.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_CLUSTER_REPORT_DOMAIN,
            &self.canonical_material(),
        )
    }

    /// Renders this report in one deterministic output format.
    #[must_use]
    pub fn render(&self, format: FailureClusterReportFormat) -> String {
        match format {
            FailureClusterReportFormat::Json => failure_cluster_report_json(self),
            FailureClusterReportFormat::JsonLines => {
                format!("{}\n", failure_cluster_report_json(self))
            }
            FailureClusterReportFormat::Table => failure_cluster_report_table(self),
            FailureClusterReportFormat::Markdown => failure_cluster_report_markdown(self),
        }
    }
}

/// Deterministically ordered per-cluster report collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureClusterReportSet {
    /// Active policy shared by every report.
    pub policy: SignaturePolicy,
    /// Reports ordered by cluster id.
    pub reports: Vec<FailureClusterReport>,
}

impl FailureClusterReportSet {
    /// Builds a content-address ordered report set.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if reports from
    /// different policies are mixed or two reports claim the same cluster id.
    pub fn from_reports(
        policy: SignaturePolicy,
        reports: impl IntoIterator<Item = FailureClusterReport>,
    ) -> Result<Self, EngineError> {
        let mut ordered = BTreeMap::new();
        for report in reports {
            if report.policy != policy {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-cluster-report-set",
                    reason: "report policy does not match report set",
                });
            }
            match ordered.entry(report.cluster_id) {
                Entry::Vacant(entry) => {
                    entry.insert(report);
                }
                Entry::Occupied(_) => {
                    return Err(EngineError::UnifiedOperationEvidenceMismatch {
                        operation: "failure-cluster-report-set",
                        reason: "duplicate cluster report",
                    });
                }
            }
        }

        Ok(Self {
            policy,
            reports: ordered.into_values().collect(),
        })
    }

    /// Returns canonical report-set material.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_cluster_report_set_material(self)
    }

    /// Returns the content address of this report set.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            FAILURE_CLUSTER_REPORT_SET_DOMAIN,
            &self.canonical_material(),
        )
    }

    /// Renders every report in one deterministic output format.
    #[must_use]
    pub fn render(&self, format: FailureClusterReportFormat) -> String {
        match format {
            FailureClusterReportFormat::Json => failure_cluster_report_set_json(self),
            FailureClusterReportFormat::JsonLines => {
                self.reports
                    .iter()
                    .map(failure_cluster_report_json)
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            }
            FailureClusterReportFormat::Table => self
                .reports
                .iter()
                .map(failure_cluster_report_table)
                .collect::<Vec<_>>()
                .join("\n\n"),
            FailureClusterReportFormat::Markdown => self
                .reports
                .iter()
                .map(failure_cluster_report_markdown)
                .collect::<Vec<_>>()
                .join("\n\n"),
        }
    }
}

/// Full canonical causal-cone material retained for exact policy keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureCausalCone {
    canonical_material: String,
}

impl FailureCausalCone {
    /// Builds full causal-cone material from an already-canonical representation.
    #[must_use]
    pub fn from_canonical_material(canonical_material: impl Into<String>) -> Self {
        Self {
            canonical_material: canonical_material.into(),
        }
    }

    /// Returns the full canonical causal-cone material.
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the hash used by non-exact policy levels when the causal slice is keyed.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(FAILURE_CAUSAL_SLICE_DOMAIN, &self.canonical_material)
    }
}

/// Signature-normalization inputs applied before failure fields are keyed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FailureSignatureNormalization {
    /// Interchangeable-node classes used to canonicalize `faulting_node`.
    pub symmetry_classes: SymmetryReductionClasses,
}

impl FailureSignatureNormalization {
    /// Builds identity normalization with no interchangeable-node classes.
    #[must_use]
    pub fn identity() -> Self {
        Self::default()
    }

    /// Replaces the interchangeable-node classes used by triage canonicalization.
    #[must_use]
    pub fn with_symmetry_classes(mut self, classes: SymmetryReductionClasses) -> Self {
        self.symmetry_classes = classes;
        self
    }
}

/// Deterministic triage-side node relabeling for failure signatures.
///
/// Nodes not assigned to an interchangeable class keep their scenario identity.
/// Nodes inside a class are rewritten to a stable class-local label so symmetric
/// findings on different replicas share one `faulting_node` key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSymmetryCanonicalizer {
    coverage_fingerprint: ContentHash,
    classes: SymmetryReductionClasses,
}

impl FailureSymmetryCanonicalizer {
    /// Builds a canonicalizer bound to the recorded coverage fingerprint.
    #[must_use]
    pub fn new(coverage_fingerprint: ContentHash, classes: SymmetryReductionClasses) -> Self {
        Self {
            coverage_fingerprint,
            classes,
        }
    }

    /// Builds an identity canonicalizer for records without symmetry classes.
    #[must_use]
    pub fn identity(coverage_fingerprint: ContentHash) -> Self {
        Self::new(coverage_fingerprint, SymmetryReductionClasses::new())
    }

    /// Returns the recorded coverage fingerprint this canonicalizer is bound to.
    #[must_use]
    pub fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
    }

    /// Returns `node` under the triage symmetry-canonical relabeling.
    #[must_use]
    pub fn canonical_node(&self, node: &NodeId) -> NodeId {
        match self.classes.classes.get(node) {
            Some(class) => NodeId {
                name: format!("symmetry-class:{}:{}", class.name.len(), class.name),
            },
            None => node.clone(),
        }
    }

    fn canonical_node_option(&self, node: &Option<NodeId>) -> Option<NodeId> {
        node.as_ref().map(|node| self.canonical_node(node))
    }
}

/// Checked event-log evidence for failure-signature construction.
///
/// This value binds the supplied event-log entries to the
/// [`ReproductionEventLogArtifact`] recorded for the same reproduction artifact,
/// and caches only deterministic projections used by signature construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureRecordedEventLog {
    artifact: ContentHash,
    event_log_artifact: ContentHash,
    causal_subsequence: ContentHash,
    causal_subsequence_events: usize,
    coverage_fingerprint: ContentHash,
    projection: EventLogCausalProjection,
}

impl FailureRecordedEventLog {
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

        let projection = event_log_causal_projection(event_log);
        if projection.content_hash() != event_log_artifact.causal_subsequence {
            return Err(EngineError::ReplayTargetMismatch {
                expected: event_log_artifact.causal_subsequence,
                actual: projection.content_hash(),
            });
        }
        if projection.canonical_bytes().len() != event_log_artifact.causal_subsequence_bytes {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-signature.event-log",
                reason: "causal subsequence byte length does not match recorded metadata",
            });
        }
        if projection.len() != event_log_artifact.causal_subsequence_events {
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
            causal_subsequence: projection.content_hash(),
            causal_subsequence_events: projection.len(),
            coverage_fingerprint: event_log_artifact.coverage_fingerprint,
            projection,
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

    /// Returns the recorded deterministic coverage fingerprint validated against the log.
    #[must_use]
    pub fn coverage_fingerprint(&self) -> ContentHash {
        self.coverage_fingerprint
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
}

/// Property-violation source record consumed by failure-signature construction.
///
/// This wraps the deterministic host assertion violation record. The signature
/// constructor reads the property id, quantifier, node, and site kind from this
/// value rather than replaying the guest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailurePropertyViolationRecord {
    /// Deterministic assertion violation produced from the retained assertion log.
    pub violation: HostAssertionViolation,
}

impl FailurePropertyViolationRecord {
    /// Builds a signature input record from an assertion violation.
    #[must_use]
    pub fn new(violation: HostAssertionViolation) -> Self {
        Self { violation }
    }

    /// Returns the property key read from the violation record.
    #[must_use]
    pub fn property_key(&self) -> FailurePropertyKey {
        FailurePropertyKey {
            id: self.violation.assertion.clone(),
            quantifier: self.violation.quantifier,
        }
    }

    /// Returns the first failing point read from the violation record.
    #[must_use]
    pub fn first_failing_point(&self) -> FailureFirstFailingPoint {
        self.first_failing_point_with(&FailureSymmetryCanonicalizer::identity(
            ContentHash::default(),
        ))
    }

    /// Returns the first failing point under the supplied symmetry relabeling.
    #[must_use]
    pub fn first_failing_point_with(
        &self,
        canonicalizer: &FailureSymmetryCanonicalizer,
    ) -> FailureFirstFailingPoint {
        FailureFirstFailingPoint {
            event_kind: self.violation.event_kind.clone(),
            faulting_node: canonicalizer.canonical_node_option(&self.violation.node),
        }
    }
}

/// Deterministic, content-addressed root-cause signature for one finding.
///
/// The tuple is computed from stored finding artifacts, violation records, and
/// recorded event-log projections only. It deliberately omits discovery path,
/// discovering campaign, finding fingerprint, wall-clock data, and raw
/// observational log entries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSignature {
    /// Closed failure kind for this finding.
    pub failure_kind: FailureKind,
    /// Violated property identity for property failures, or `None` for divergence.
    pub property: Option<FailurePropertyKey>,
    /// First attributable point read from the violation record or bisection point.
    pub first_failing_point: FailureFirstFailingPoint,
    /// Bucketed class derived from the deterministic coverage fingerprint.
    pub coverage_class: FailureCoverageClass,
    /// Optional digest of the cone-scoped recorded causal slice.
    ///
    /// This is computed over the causal prefix ending at the first failing
    /// causal entry, not the whole causal subsequence.
    pub causal_slice_hash: Option<ContentHash>,
    /// Full canonical causal cone retained for exact-policy forensic keys.
    ///
    /// Coarse/default/fine policies key only selected scalar fields and, for
    /// fine, the cone hash above. The exact policy uses this material directly.
    pub causal_cone: Option<FailureCausalCone>,
    /// Absolute instruction count of the first failing point for reports only.
    ///
    /// The current default content hash excludes this value so minimization that
    /// shifts absolute icounts does not perturb the clustering key.
    pub at_icount_report_only: Option<Icount>,
}

impl FailureSignature {
    /// Builds a property-violation signature from recorded artifacts only.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, violation record, replay metadata, and
    /// configuration id disagree before any signature field is read.
    pub fn from_recorded_property_violation(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        violation: &FailurePropertyViolationRecord,
    ) -> Result<Self, EngineError> {
        Self::from_recorded_property_violation_with_normalization(
            finding,
            event_log,
            violation,
            &FailureSignatureNormalization::identity(),
        )
    }

    /// Builds a property-violation signature with explicit normalizations.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, violation record, replay metadata, and
    /// configuration id disagree before any signature field is read. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when the violation site
    /// is absent from the checked recorded causal projection.
    pub fn from_recorded_property_violation_with_normalization(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        violation: &FailurePropertyViolationRecord,
        normalization: &FailureSignatureNormalization,
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        validate_recorded_event_log_for_finding(finding, event_log)?;
        validate_violation_for_finding(finding, violation)?;
        let canonicalizer = event_log.symmetry_canonicalizer(normalization);
        let causal_index = validate_violation_point(event_log, violation)?;
        let causal_cone =
            failure_causal_cone_through_index(event_log, causal_index, &canonicalizer);
        Ok(Self {
            failure_kind: FailureKind::PropertyViolation,
            property: Some(violation.property_key()),
            first_failing_point: violation.first_failing_point_with(&canonicalizer),
            coverage_class: event_log.coverage_class(),
            causal_slice_hash: Some(causal_cone.content_hash()),
            causal_cone: Some(causal_cone),
            at_icount_report_only: violation.violation.at_icount,
        })
    }

    /// Builds a divergence signature from a recorded bisection point.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, replay metadata, and configuration id
    /// disagree before any signature field is read. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when `divergence` is not
    /// present in the checked recorded causal projection.
    pub fn from_recorded_divergence(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        divergence: &EventLogCausalDivergencePoint,
    ) -> Result<Self, EngineError> {
        Self::from_recorded_divergence_with_normalization(
            finding,
            event_log,
            divergence,
            &FailureSignatureNormalization::identity(),
        )
    }

    /// Builds a divergence signature with explicit normalizations.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReplayTargetMismatch`] if the finding's embedded
    /// artifact, event-log metadata, replay metadata, and configuration id
    /// disagree before any signature field is read. Returns
    /// [`EngineError::UnifiedOperationEvidenceMismatch`] when `divergence` is not
    /// present in the checked recorded causal projection.
    pub fn from_recorded_divergence_with_normalization(
        finding: &FindingReproductionArtifact,
        event_log: &FailureRecordedEventLog,
        divergence: &EventLogCausalDivergencePoint,
        normalization: &FailureSignatureNormalization,
    ) -> Result<Self, EngineError> {
        validate_finding_static_identity(finding)?;
        validate_recorded_event_log_for_finding(finding, event_log)?;
        let canonicalizer = event_log.symmetry_canonicalizer(normalization);
        let causal_index = validate_divergence_point(event_log, divergence)?;
        let causal_cone =
            failure_causal_cone_through_index(event_log, causal_index, &canonicalizer);
        Ok(Self {
            failure_kind: FailureKind::Divergence,
            property: None,
            first_failing_point: FailureFirstFailingPoint {
                event_kind: divergence.kind.clone(),
                faulting_node: canonicalizer
                    .canonical_node_option(&divergence_faulting_node(divergence)),
            },
            coverage_class: event_log.coverage_class(),
            causal_slice_hash: Some(causal_cone.content_hash()),
            causal_cone: Some(causal_cone),
            at_icount_report_only: Some(divergence.at.icount),
        })
    }

    /// Returns the deterministic content address of this signature tuple.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(FAILURE_SIGNATURE_DOMAIN, &self.canonical_material())
    }

    /// Returns the canonical material hashed by [`Self::content_hash`].
    #[must_use]
    pub fn canonical_material(&self) -> String {
        failure_signature_material(self)
    }

    /// Returns canonical report material including non-key detail fields.
    #[must_use]
    pub fn report_material(&self) -> String {
        failure_signature_report_material(self)
    }

    /// Projects this signature into the key selected by `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnifiedOperationEvidenceMismatch`] if the
    /// signature's coverage bucket does not match the policy's fixed bucketing
    /// algorithm, or if the exact policy needs missing causal-cone material.
    pub fn signature_key(
        &self,
        policy: SignaturePolicy,
    ) -> Result<FailureSignatureKey, EngineError> {
        policy.signature_key(self)
    }
}

fn validate_finding_static_identity(
    finding: &FindingReproductionArtifact,
) -> Result<(), EngineError> {
    let artifact = finding.artifact.id();
    if finding.replay.artifact != artifact {
        return Err(EngineError::ReplayTargetMismatch {
            expected: artifact,
            actual: finding.replay.artifact,
        });
    }

    let scenario = finding.artifact.scenario_form().id();
    if finding.replay.scenario != scenario {
        return Err(EngineError::ReplayTargetMismatch {
            expected: scenario,
            actual: finding.replay.scenario,
        });
    }

    let schedule = finding.artifact.schedule().content_hash();
    if finding.replay.schedule != schedule {
        return Err(EngineError::ReplayTargetMismatch {
            expected: schedule,
            actual: finding.replay.schedule,
        });
    }

    let configuration = Configuration {
        def: finding.artifact.scenario_def(),
        schedule: finding.artifact.schedule().clone(),
    };
    let configuration_id = configuration.id();
    if finding.configuration != configuration_id {
        return Err(EngineError::ReplayTargetMismatch {
            expected: configuration_id,
            actual: finding.configuration,
        });
    }

    Ok(())
}

fn validate_recorded_event_log_for_finding(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
) -> Result<(), EngineError> {
    let artifact = finding.artifact.id();
    if event_log.artifact != artifact {
        return Err(EngineError::ReplayTargetMismatch {
            expected: artifact,
            actual: event_log.artifact,
        });
    }
    Ok(())
}

fn validate_violation_for_finding(
    finding: &FindingReproductionArtifact,
    violation: &FailurePropertyViolationRecord,
) -> Result<(), EngineError> {
    let artifact = finding.artifact.id();
    if violation.violation.reproduction_artifact != artifact {
        return Err(EngineError::ReplayTargetMismatch {
            expected: artifact,
            actual: violation.violation.reproduction_artifact,
        });
    }
    Ok(())
}

fn validate_divergence_point(
    event_log: &FailureRecordedEventLog,
    divergence: &EventLogCausalDivergencePoint,
) -> Result<usize, EngineError> {
    if let Some((index, _)) =
        event_log
            .projection
            .entries()
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.raw_index == divergence.raw_index
                    && entry.entry.time().icount == divergence.at
                    && entry.entry.source() == &divergence.source
                    && entry.entry.event_payload().kind() == divergence.kind
            })
    {
        return Ok(index);
    }

    Err(EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.divergence",
        reason: "divergence bisection point is absent from recorded causal projection",
    })
}

fn validate_violation_point(
    event_log: &FailureRecordedEventLog,
    violation: &FailurePropertyViolationRecord,
) -> Result<usize, EngineError> {
    if let Some((index, _)) =
        event_log
            .projection
            .entries()
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.entry.event_payload().kind() == violation.violation.event_kind
                    && entry.entry.at() == violation.violation.at_virtual_time
                    && violation_event_icount_matches(entry.entry.time(), &violation.violation)
                    && violation_event_assertion_matches(
                        entry.entry.event_payload(),
                        &violation.violation,
                    )
            })
    {
        return Ok(index);
    }

    Err(EngineError::UnifiedOperationEvidenceMismatch {
        operation: "failure-signature.violation",
        reason: "violation record is absent from recorded causal projection",
    })
}

fn violation_event_icount_matches(
    at: &crate::scheduler::EventLogTime,
    violation: &HostAssertionViolation,
) -> bool {
    violation
        .at_icount
        .map(|icount| at.icount.icount == icount)
        .unwrap_or(true)
}

fn violation_event_assertion_matches(
    payload: &crate::scheduler::EventPayload,
    violation: &HostAssertionViolation,
) -> bool {
    matches!(
        payload.attribute("id"),
        Some(EventAttributeValue::String(value)) if value == &violation.assertion.name
    )
}

fn divergence_faulting_node(divergence: &EventLogCausalDivergencePoint) -> Option<NodeId> {
    match &divergence.source {
        EventSource::Node { node } | EventSource::Guest { node } => Some(node.clone()),
        EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
            divergence.at.node.clone()
        }
    }
}

fn failure_causal_cone_through_index(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> FailureCausalCone {
    let cone = failure_causal_cone_entries(event_log, causal_index, canonicalizer);
    let mut lines = vec![format!("causal_cone_events={}", cone.len())];
    for (cone_index, entry) in cone.into_iter().enumerate() {
        push_failure_causal_slice_entry_lines(cone_index, entry, canonicalizer, &mut lines);
    }
    FailureCausalCone::from_canonical_material(lines.join("\n"))
}

fn failure_causal_cone_entries<'a>(
    event_log: &'a FailureRecordedEventLog,
    causal_index: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Vec<&'a crate::scheduler::EventLogCausalProjectionEntry> {
    let anchor = &event_log.projection.entries()[causal_index];
    let anchor_keys = failure_causal_dependency_keys(anchor, canonicalizer);
    event_log
        .projection
        .entries()
        .iter()
        .take(causal_index + 1)
        .filter(|entry| {
            entry.raw_index == anchor.raw_index
                || failure_causal_dependency_keys(entry, canonicalizer)
                    .iter()
                    .any(|key| anchor_keys.contains(key))
        })
        .collect()
}

fn failure_causal_dependency_keys(
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    match entry.entry.source() {
        EventSource::Scenario { event } => {
            keys.insert(format!("event:{}:{}", event.name.len(), event.name));
        }
        EventSource::Engine | EventSource::Command { .. } => {}
        EventSource::Node { node } | EventSource::Guest { node } => {
            keys.insert(format!(
                "node:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            ));
        }
    }
    if let Some(node) = &entry.entry.time().icount.node {
        keys.insert(format!(
            "node:{}",
            failure_node_value(&canonicalizer.canonical_node(node))
        ));
    }
    for value in entry.entry.event_payload().attributes().values() {
        push_failure_dependency_keys_for_attribute(value, canonicalizer, &mut keys);
    }
    keys
}

fn push_failure_dependency_keys_for_attribute(
    value: &EventAttributeValue,
    canonicalizer: &FailureSymmetryCanonicalizer,
    keys: &mut BTreeSet<String>,
) {
    match value {
        EventAttributeValue::String(value) => {
            keys.insert(format!("string:{}:{}", value.len(), value));
        }
        EventAttributeValue::Node(node) => {
            keys.insert(format!(
                "node:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            ));
        }
        EventAttributeValue::Event(event) => {
            keys.insert(format!("event:{}:{}", event.name.len(), event.name));
        }
        EventAttributeValue::Fault(fault) => {
            keys.insert(format!("fault:{}:{}", fault.name.len(), fault.name));
        }
        EventAttributeValue::Bool(_)
        | EventAttributeValue::U64(_)
        | EventAttributeValue::U128(_)
        | EventAttributeValue::Bytes(_)
        | EventAttributeValue::VirtualTime(_)
        | EventAttributeValue::Icount(_)
        | EventAttributeValue::Level(_) => {}
    }
}

fn push_failure_causal_slice_entry_lines(
    cone_index: usize,
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
    lines: &mut Vec<String>,
) {
    lines.push(format!("entry.cone_index={cone_index}"));
    match &entry.entry.time().icount.node {
        Some(node) => lines.push(failure_node_material(
            "entry.icount.node",
            &canonicalizer.canonical_node(node),
        )),
        None => lines.push(String::from("entry.icount.node=none")),
    }
    lines.push(failure_event_source_material(
        "entry.source",
        entry.entry.source(),
        canonicalizer,
    ));
    lines.push(format!(
        "entry.level={}",
        failure_event_level_label(entry.entry.level())
    ));
    lines.push(format!(
        "entry.class={}",
        failure_event_class_label(entry.entry.class())
    ));
    lines.push(format!("entry.kind={}", entry.entry.event_payload().kind()));
    for (name, value) in entry.entry.event_payload().attributes() {
        if let Some(material) = failure_event_attribute_material(value, canonicalizer) {
            lines.push(format!("entry.attr.{name}={material}"));
        }
    }
}

fn failure_event_source_material(
    prefix: &str,
    source: &EventSource,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> String {
    match source {
        EventSource::Scenario { event } => {
            format!("{prefix}=scenario:{}", event.name)
        }
        EventSource::Engine => format!("{prefix}=engine"),
        EventSource::Node { node } => {
            format!(
                "{prefix}=node:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            )
        }
        EventSource::Guest { node } => {
            format!(
                "{prefix}=guest:{}",
                failure_node_value(&canonicalizer.canonical_node(node))
            )
        }
        EventSource::Command { command_id } => format!("{prefix}=command:{command_id}"),
    }
}

fn failure_event_attribute_material(
    value: &EventAttributeValue,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Option<String> {
    match value {
        EventAttributeValue::Bool(value) => Some(format!("bool:{value}")),
        EventAttributeValue::U64(value) => Some(format!("u64:{value}")),
        EventAttributeValue::U128(value) => Some(format!("u128:{value}")),
        EventAttributeValue::String(value) => Some(format!("string:{}:{}", value.len(), value)),
        EventAttributeValue::Bytes(value) => {
            Some(format!("bytes:{}:{}", value.len(), bytes_hex(value)))
        }
        EventAttributeValue::Node(node) => Some(format!(
            "node:{}",
            failure_node_value(&canonicalizer.canonical_node(node))
        )),
        EventAttributeValue::Event(event) => {
            Some(format!("event:{}:{}", event.name.len(), event.name))
        }
        EventAttributeValue::Fault(fault) => {
            Some(format!("fault:{}:{}", fault.name.len(), fault.name))
        }
        EventAttributeValue::VirtualTime(_) | EventAttributeValue::Icount(_) => None,
        EventAttributeValue::Level(level) => {
            Some(format!("level:{}", failure_event_level_label(*level)))
        }
    }
}

fn failure_node_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}={}", failure_node_value(node))
}

fn failure_node_value(node: &NodeId) -> String {
    format!("{}:{}", node.name.len(), node.name)
}

fn failure_event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

fn failure_event_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

fn failure_signature_material(signature: &FailureSignature) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "failure_kind={}",
        failure_kind_label(signature.failure_kind)
    ));
    match &signature.property {
        Some(property) => {
            lines.push(String::from("property=some"));
            lines.push(assertion_id_material(&property.id));
            lines.push(format!(
                "property_quantifier={}",
                failure_assertion_quantifier_label(property.quantifier)
            ));
        }
        None => lines.push(String::from("property=none")),
    }
    lines.push(format!(
        "first_failing_event_kind_len={}",
        signature.first_failing_point.event_kind.len()
    ));
    lines.push(format!(
        "first_failing_event_kind={}",
        signature.first_failing_point.event_kind
    ));
    match &signature.first_failing_point.faulting_node {
        Some(node) => lines.push(node_ref_material("faulting_node", node)),
        None => lines.push(String::from("faulting_node=none")),
    }
    lines.push(format!(
        "coverage_class_algorithm={}",
        signature.coverage_class.algorithm
    ));
    lines.push(format!(
        "coverage_class_bucket={}",
        signature.coverage_class.bucket
    ));
    lines.push(
        signature
            .causal_slice_hash
            .map(|hash| format!("causal_slice_hash={}", hash.to_hex()))
            .unwrap_or_else(|| String::from("causal_slice_hash=none")),
    );
    lines.join("\n")
}

fn failure_signature_report_material(signature: &FailureSignature) -> String {
    let mut lines = vec![signature.canonical_material()];
    lines.push(
        signature
            .at_icount_report_only
            .map(|icount| format!("at_icount_report_only={}", icount.retired))
            .unwrap_or_else(|| String::from("at_icount_report_only=none")),
    );
    match &signature.causal_cone {
        Some(cone) => {
            lines.push(String::from("causal_cone=some"));
            lines.push(String::from("causal_cone_material_BEGIN"));
            lines.push(cone.canonical_material().to_owned());
            lines.push(String::from("causal_cone_material_END"));
        }
        None => lines.push(String::from("causal_cone=none")),
    }
    lines.join("\n")
}

fn failure_signature_key_material(signature: &FailureSignature, policy: SignaturePolicy) -> String {
    let mut lines = vec![failure_signature_policy_material(policy)];
    lines.push(String::from("key_fields_BEGIN"));
    lines.push(format!(
        "failure_kind={}",
        failure_kind_label(signature.failure_kind)
    ));
    match &signature.property {
        Some(property) => {
            lines.push(String::from("property=some"));
            lines.push(assertion_id_material(&property.id));
            if policy.level >= SignaturePolicyLevel::Default {
                lines.push(format!(
                    "property_quantifier={}",
                    failure_assertion_quantifier_label(property.quantifier)
                ));
            }
        }
        None => lines.push(String::from("property=none")),
    }
    if policy.level >= SignaturePolicyLevel::Default {
        lines.push(format!(
            "first_failing_event_kind_len={}",
            signature.first_failing_point.event_kind.len()
        ));
        lines.push(format!(
            "first_failing_event_kind={}",
            signature.first_failing_point.event_kind
        ));
        match &signature.first_failing_point.faulting_node {
            Some(node) => lines.push(node_ref_material("faulting_node", node)),
            None => lines.push(String::from("faulting_node=none")),
        }
        lines.push(format!(
            "coverage_class_algorithm={}",
            signature.coverage_class.algorithm
        ));
        lines.push(format!(
            "coverage_class_bucket={}",
            signature.coverage_class.bucket
        ));
    }
    if policy.keys_causal_slice_hash() {
        lines.push(
            signature
                .causal_slice_hash
                .map(|hash| format!("causal_slice_hash={}", hash.to_hex()))
                .unwrap_or_else(|| String::from("causal_slice_hash=none")),
        );
    }
    if policy.keys_absolute_icount() {
        lines.push(
            signature
                .at_icount_report_only
                .map(|icount| format!("at_icount_key={}", icount.retired))
                .unwrap_or_else(|| String::from("at_icount_key=none")),
        );
        match &signature.causal_cone {
            Some(cone) => {
                lines.push(String::from("exact_causal_cone=some"));
                lines.push(String::from("exact_causal_cone_material_BEGIN"));
                lines.push(cone.canonical_material().to_owned());
                lines.push(String::from("exact_causal_cone_material_END"));
            }
            None => lines.push(String::from("exact_causal_cone=none")),
        }
    }
    lines.push(String::from("key_fields_END"));
    lines.join("\n")
}

fn failure_signature_policy_material(policy: SignaturePolicy) -> String {
    [
        format!(
            "signature_policy_schema_version={}",
            policy.schema_version()
        ),
        format!(
            "signature_policy_level={}",
            signature_policy_level_label(policy.level())
        ),
        format!(
            "coverage_class_algorithm={}",
            policy.coverage_class_algorithm()
        ),
        format!("minimize_merge_allowed={}", policy.allows_minimize_merge()),
    ]
    .join("\n")
}

fn failure_findings_ledger_material(ledger: &FailureFindingsLedger) -> String {
    let mut lines = vec![
        format!("artifact_count={}", ledger.artifacts.len()),
        format!("signed_finding_count={}", ledger.findings.len()),
    ];
    for (index, artifact) in ledger.artifacts.iter().enumerate() {
        lines.push(format!("artifact.{index}={}", content_hash_hex(*artifact)));
    }
    for (index, finding) in ledger.findings.iter().enumerate() {
        lines.push(format!(
            "finding.{index}.reproduction_artifact={}",
            content_hash_hex(finding.reproduction_artifact)
        ));
        lines.push(format!("finding.{index}.signature_BEGIN"));
        lines.push(finding.signature.report_material());
        lines.push(format!("finding.{index}.signature_END"));
    }
    lines.join("\n")
}

fn failure_triage_result_identity_material(identity: FailureTriageResultIdentity) -> String {
    [
        format!(
            "triage_result_schema_version={}",
            SIGNATURE_POLICY_SCHEMA_VERSION
        ),
        format!(
            "findings_ledger={}",
            content_hash_hex(identity.findings_ledger)
        ),
        identity.policy.canonical_material(),
    ]
    .join("\n")
}

fn failure_triage_signature_self_check_material(check: &FailureTriageSignatureSelfCheck) -> String {
    let mut lines = vec![
        format!("checked_count={}", check.checked_count),
        format!("check_record_count={}", check.checks.len()),
        format!("mismatch_count={}", check.mismatches.len()),
    ];
    for (index, record) in check.checks.iter().enumerate() {
        let prefix = format!("check.{index}");
        lines.push(format!(
            "{prefix}.reproduction_artifact={}",
            content_hash_hex(record.reproduction_artifact)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_hash={}",
            content_hash_hex(record.discovery_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_hash={}",
            content_hash_hex(record.recomputed_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_bytes={}",
            content_hash_hex(record.discovery_signature_bytes)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_bytes={}",
            content_hash_hex(record.recomputed_signature_bytes)
        ));
        lines.push(format!("{prefix}.matched={}", record.matched));
    }
    for (index, mismatch) in check.mismatches.iter().enumerate() {
        let prefix = format!("mismatch.{index}");
        lines.push(format!(
            "{prefix}.reproduction_artifact={}",
            content_hash_hex(mismatch.reproduction_artifact)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_hash={}",
            content_hash_hex(mismatch.discovery_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_hash={}",
            content_hash_hex(mismatch.recomputed_signature_hash)
        ));
        lines.push(format!(
            "{prefix}.discovery_signature_bytes={}",
            content_hash_hex(mismatch.discovery_signature_bytes)
        ));
        lines.push(format!(
            "{prefix}.recomputed_signature_bytes={}",
            content_hash_hex(mismatch.recomputed_signature_bytes)
        ));
    }
    lines.join("\n")
}

fn failure_triage_result_material(result: &FailureTriageResult) -> String {
    let mut lines = vec![
        result.identity.canonical_material(),
        format!(
            "triage_result_identity={}",
            content_hash_hex(result.identity.content_hash())
        ),
        format!(
            "clustering_result={}",
            content_hash_hex(result.clustering.content_hash())
        ),
        format!(
            "minimization_result={}",
            content_hash_hex(result.minimization.content_hash())
        ),
        format!(
            "report_set={}",
            content_hash_hex(result.report_set.content_hash())
        ),
        format!(
            "signature_self_check={}",
            content_hash_hex(result.signature_self_check.content_hash())
        ),
        format!("cluster_count={}", result.clustering.cluster_count()),
        format!("member_count={}", result.clustering.member_count()),
    ];
    for (index, report) in result.report_set.reports.iter().enumerate() {
        lines.push(format!(
            "report.{index}.cluster_id={}",
            content_hash_hex(report.cluster_id)
        ));
        lines.push(format!(
            "report.{index}.content_hash={}",
            content_hash_hex(report.content_hash())
        ));
        lines.push(format!(
            "report.{index}.minimal_representative={}",
            content_hash_hex(report.minimal_representative)
        ));
    }
    lines.join("\n")
}

fn failure_triage_result_diff_material(diff: &FailureTriageResultDiff) -> String {
    let mut lines = vec![
        format!("baseline={}", content_hash_hex(diff.baseline)),
        format!("candidate={}", content_hash_hex(diff.candidate)),
        format!("added_count={}", diff.added_clusters.len()),
    ];
    for (index, cluster) in diff.added_clusters.iter().enumerate() {
        lines.push(format!("added.{index}={}", content_hash_hex(*cluster)));
    }
    lines.push(format!("removed_count={}", diff.removed_clusters.len()));
    for (index, cluster) in diff.removed_clusters.iter().enumerate() {
        lines.push(format!("removed.{index}={}", content_hash_hex(*cluster)));
    }
    lines.push(format!("changed_count={}", diff.changed_clusters.len()));
    for (index, changed) in diff.changed_clusters.iter().enumerate() {
        lines.push(format!(
            "changed.{index}.cluster_id={}",
            content_hash_hex(changed.cluster_id)
        ));
        lines.push(format!(
            "changed.{index}.baseline_report={}",
            content_hash_hex(changed.baseline_report)
        ));
        lines.push(format!(
            "changed.{index}.candidate_report={}",
            content_hash_hex(changed.candidate_report)
        ));
    }
    lines.push(format!("unchanged_count={}", diff.unchanged_clusters.len()));
    for (index, cluster) in diff.unchanged_clusters.iter().enumerate() {
        lines.push(format!("unchanged.{index}={}", content_hash_hex(*cluster)));
    }
    lines.join("\n")
}

fn failure_signature_report_bytes_hash(material: &str) -> ContentHash {
    ContentHash::from_canonical_material(FAILURE_TRIAGE_SIGNATURE_SELF_CHECK_DOMAIN, material)
}

fn failure_triage_artifact_bytes(domain: &str, material: &str) -> Vec<u8> {
    format!("{domain}\n{material}\n").into_bytes()
}

fn store_failure_triage_artifact<S>(
    store: &S,
    bytes: &[u8],
) -> Result<FailureTriageStoredArtifact, DagStoreError>
where
    S: DagStore + ?Sized,
{
    let key = ContentHash::from_bytes(bytes);
    let cache_hit = store.exists(&key)?;
    let stored_key = store.put(bytes)?;
    if stored_key != key {
        return Err(DagStoreError::ContentMismatch {
            expected: key,
            actual: stored_key,
        });
    }
    Ok(FailureTriageStoredArtifact {
        key: stored_key,
        cache_hit,
        size_bytes: bytes.len(),
    })
}

fn triage_report_hashes_by_cluster(
    result: &FailureTriageResult,
) -> BTreeMap<ContentHash, ContentHash> {
    result
        .report_set
        .reports
        .iter()
        .map(|report| (report.cluster_id, report.content_hash()))
        .collect()
}

fn failure_clustering_result_material(result: &FailureClusteringResult) -> String {
    let mut lines = vec![
        result.policy.canonical_material(),
        format!("cluster_count={}", result.clusters.len()),
        format!("member_count={}", result.member_count()),
    ];
    for (cluster_index, cluster) in result.clusters.iter().enumerate() {
        lines.push(format!("cluster.index={cluster_index}"));
        lines.push(format!("cluster.id={}", content_hash_hex(cluster.id)));
        lines.push(String::from("cluster.signature_key_BEGIN"));
        lines.push(cluster.signature_key.canonical_material().to_owned());
        lines.push(String::from("cluster.signature_key_END"));
        lines.push(format!("cluster.member_count={}", cluster.members.len()));
        for (member_index, member) in cluster.members.iter().enumerate() {
            lines.push(format!("cluster.member.index={member_index}"));
            lines.push(format!(
                "cluster.member.reproduction_artifact={}",
                content_hash_hex(member.reproduction_artifact)
            ));
            lines.push(format!(
                "cluster.member.signature={}",
                content_hash_hex(member.signature.content_hash())
            ));
        }
    }
    lines.join("\n")
}

fn failure_signature_preserving_minimization_result_material(
    result: &FailureSignaturePreservingMinimizationResult,
) -> String {
    let mut lines = vec![
        result.policy.canonical_material(),
        format!("cluster_count={}", result.cluster_count()),
        format!("minimized_count={}", result.minimized_count()),
    ];
    for (run_index, run) in result.runs.iter().enumerate() {
        lines.push(format!("minimization.index={run_index}"));
        lines.push(format!(
            "minimization.cluster_id={}",
            content_hash_hex(run.cluster_id)
        ));
        lines.push(format!(
            "minimization.representative_artifact={}",
            content_hash_hex(run.representative_artifact)
        ));
        lines.push(String::from("minimization.target_signature_key_BEGIN"));
        lines.push(run.target_signature_key.canonical_material().to_owned());
        lines.push(String::from("minimization.target_signature_key_END"));
        lines.push(String::from("minimization.minimized_signature_key_BEGIN"));
        lines.push(run.minimized_signature_key.canonical_material().to_owned());
        lines.push(String::from("minimization.minimized_signature_key_END"));
        lines.push(format!(
            "minimization.seed={}",
            run.minimization.seed.to_hex()
        ));
        lines.push(format!(
            "minimization.target_fingerprint={}",
            content_hash_hex(run.minimization.target_fingerprint)
        ));
        lines.push(format!(
            "minimization.original_artifact={}",
            content_hash_hex(run.minimization.original.artifact.id())
        ));
        lines.push(format!(
            "minimization.minimized_artifact={}",
            content_hash_hex(run.minimized_artifact())
        ));
        lines.push(format!(
            "minimization.attempt_count={}",
            run.minimization.attempts.len()
        ));
        lines.push(format!(
            "minimization.accepted_attempt_count={}",
            run.minimization.accepted_attempts()
        ));
        for (attempt_index, attempt) in run.minimization.attempts.iter().enumerate() {
            push_minimization_attempt_lines(run_index, attempt_index, attempt, &mut lines);
        }
        lines.push(format!(
            "minimization.signature_preserved={}",
            run.preserves_signature()
        ));
    }
    lines.join("\n")
}

fn push_minimization_attempt_lines(
    run_index: usize,
    attempt_index: usize,
    attempt: &MinimizationAttempt,
    lines: &mut Vec<String>,
) {
    let prefix = format!("minimization.{run_index}.attempt.{attempt_index}");
    lines.push(format!("{prefix}.sequence={}", attempt.sequence));
    lines.push(format!(
        "{prefix}.removed_index_count={}",
        attempt.removed_indices.len()
    ));
    for (removed_index_index, removed_index) in attempt.removed_indices.iter().enumerate() {
        lines.push(format!(
            "{prefix}.removed_index.{removed_index_index}={removed_index}"
        ));
    }
    lines.push(format!(
        "{prefix}.removed_decision_count={}",
        attempt.removed_decisions.len()
    ));
    for (decision_index, decision) in attempt.removed_decisions.iter().enumerate() {
        let mut decision_lines = Vec::new();
        push_decision_lines(decision_index, decision, &mut decision_lines);
        for decision_line in decision_lines {
            lines.push(format!("{prefix}.removed_{decision_line}"));
        }
    }
    lines.push(format!(
        "{prefix}.candidate_artifact={}",
        content_hash_hex(attempt.candidate_artifact)
    ));
    lines.push(format!(
        "{prefix}.candidate_schedule={}",
        content_hash_hex(attempt.candidate_schedule)
    ));
    lines.push(format!(
        "{prefix}.replayed_state={}",
        content_hash_hex(attempt.replayed_state)
    ));
    match attempt.observed_fingerprint {
        Some(observed_fingerprint) => lines.push(format!(
            "{prefix}.observed_fingerprint={}",
            content_hash_hex(observed_fingerprint)
        )),
        None => lines.push(format!("{prefix}.observed_fingerprint=none")),
    }
    lines.push(format!("{prefix}.accepted={}", attempt.accepted));
}

fn failure_report_anchor_index(
    failure: &FailureClusterReportFailure,
    event_log: &FailureRecordedEventLog,
) -> Result<usize, EngineError> {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            if record.violation.reproduction_artifact != event_log.artifact() {
                return Err(EngineError::ReplayTargetMismatch {
                    expected: event_log.artifact(),
                    actual: record.violation.reproduction_artifact,
                });
            }
            validate_violation_point(event_log, record)
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            validate_divergence_point(event_log, &divergence.to_divergence_point())
        }
    }
}

fn failure_signature_for_report_failure(
    finding: &FindingReproductionArtifact,
    event_log: &FailureRecordedEventLog,
    failure: &FailureClusterReportFailure,
    normalization: &FailureSignatureNormalization,
) -> Result<FailureSignature, EngineError> {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            FailureSignature::from_recorded_property_violation_with_normalization(
                finding,
                event_log,
                record,
                normalization,
            )
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            FailureSignature::from_recorded_divergence_with_normalization(
                finding,
                event_log,
                &divergence.to_divergence_point(),
                normalization,
            )
        }
    }
}

fn failure_report_excerpt(
    event_log: &FailureRecordedEventLog,
    causal_index: usize,
    excerpt_len: usize,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> Vec<FailureClusterReportCausalStep> {
    if excerpt_len == 0 {
        return Vec::new();
    }
    let start = causal_index.saturating_add(1).saturating_sub(excerpt_len);
    event_log.projection.entries()[start..=causal_index]
        .iter()
        .map(|entry| failure_cluster_report_causal_step(entry, canonicalizer))
        .collect()
}

fn failure_cluster_report_causal_step(
    entry: &crate::scheduler::EventLogCausalProjectionEntry,
    canonicalizer: &FailureSymmetryCanonicalizer,
) -> FailureClusterReportCausalStep {
    let node = entry
        .entry
        .time()
        .icount
        .node
        .as_ref()
        .map(|node| canonicalizer.canonical_node(node))
        .or_else(|| match entry.entry.source() {
            EventSource::Node { node } | EventSource::Guest { node } => {
                Some(canonicalizer.canonical_node(node))
            }
            EventSource::Scenario { .. } | EventSource::Engine | EventSource::Command { .. } => {
                None
            }
        });
    let source = failure_event_source_material("source", entry.entry.source(), canonicalizer)
        .strip_prefix("source=")
        .unwrap_or("unknown")
        .to_owned();
    FailureClusterReportCausalStep {
        raw_index: entry.raw_index,
        sequence: entry.entry.sequence(),
        node,
        icount: entry.entry.time().icount.icount,
        kind: entry.entry.event_payload().kind().to_owned(),
        source,
        entry: entry.entry.content_hash(),
    }
}

fn failure_cluster_report_material(report: &FailureClusterReport) -> String {
    let mut lines = vec![
        report.policy.canonical_material(),
        format!("cluster_id={}", content_hash_hex(report.cluster_id)),
        String::from("signature_BEGIN"),
        report.signature.report_material(),
        String::from("signature_END"),
        format!("member_count={}", report.member_count),
    ];
    for (index, member) in report.member_hashes.iter().enumerate() {
        lines.push(format!(
            "member.{index}.reproduction_artifact={}",
            content_hash_hex(*member)
        ));
    }
    lines.push(format!(
        "representative_artifact={}",
        content_hash_hex(report.representative_artifact)
    ));
    lines.push(format!(
        "minimal_representative={}",
        content_hash_hex(report.minimal_representative)
    ));
    push_failure_report_reproduction_lines(
        "minimal_reproduction",
        &report.minimal_reproduction,
        &mut lines,
    );
    push_failure_report_failure_lines("failure", &report.failure, &mut lines);
    lines.push(format!(
        "event_log_excerpt_count={}",
        report.event_log_excerpt.len()
    ));
    for (index, step) in report.event_log_excerpt.iter().enumerate() {
        push_failure_report_step_lines(&format!("event_log_excerpt.{index}"), step, &mut lines);
    }
    lines.push(format!("causal_chain_count={}", report.causal_chain.len()));
    for (index, step) in report.causal_chain.iter().enumerate() {
        push_failure_report_step_lines(&format!("causal_chain.{index}"), step, &mut lines);
    }
    lines.push(format!(
        "replay_command_len={}",
        report.replay_command.len()
    ));
    lines.push(format!("replay_command={}", report.replay_command));
    lines.join("\n")
}

fn push_failure_report_reproduction_lines(
    prefix: &str,
    reproduction: &FailureClusterReportReproduction,
    lines: &mut Vec<String>,
) {
    lines.push(format!(
        "{prefix}.artifact={}",
        content_hash_hex(reproduction.artifact)
    ));
    lines.push(format!("{prefix}.seed={}", reproduction.seed.to_hex()));
    lines.push(format!(
        "{prefix}.scenario={}",
        content_hash_hex(reproduction.scenario)
    ));
    lines.push(format!(
        "{prefix}.schedule={}",
        content_hash_hex(reproduction.schedule)
    ));
}

fn push_failure_report_failure_lines(
    prefix: &str,
    failure: &FailureClusterReportFailure,
    lines: &mut Vec<String>,
) {
    match failure {
        FailureClusterReportFailure::Property(record) => {
            lines.push(format!("{prefix}.kind=property-violation"));
            lines.push(assertion_id_material(&record.violation.assertion));
            lines.push(format!(
                "{prefix}.property_message_len={}",
                record.violation.message.len()
            ));
            lines.push(format!(
                "{prefix}.property_message={}",
                record.violation.message
            ));
            lines.push(format!(
                "{prefix}.property_quantifier={}",
                failure_assertion_quantifier_label(record.violation.quantifier)
            ));
            lines.push(format!(
                "{prefix}.event_kind_len={}",
                record.violation.event_kind.len()
            ));
            lines.push(format!(
                "{prefix}.event_kind={}",
                record.violation.event_kind
            ));
            lines.push(
                record
                    .violation
                    .at_icount
                    .map(|icount| format!("{prefix}.at_icount={}", icount.retired))
                    .unwrap_or_else(|| format!("{prefix}.at_icount=none")),
            );
            match &record.violation.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            lines.push(format!(
                "{prefix}.detail_len={}",
                record.violation.detail.len()
            ));
            lines.push(format!("{prefix}.detail={}", record.violation.detail));
            lines.push(format!(
                "{prefix}.reproduction_artifact={}",
                content_hash_hex(record.violation.reproduction_artifact)
            ));
        }
        FailureClusterReportFailure::Divergence(divergence) => {
            lines.push(format!("{prefix}.kind=divergence"));
            lines.push(format!("{prefix}.raw_index={}", divergence.raw_index));
            match &divergence.node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
                None => lines.push(format!("{prefix}.node=none")),
            }
            match &divergence.icount_node {
                Some(node) => lines.push(node_ref_material(&format!("{prefix}.icount_node"), node)),
                None => lines.push(format!("{prefix}.icount_node=none")),
            }
            lines.push(format!("{prefix}.icount={}", divergence.icount.retired));
            lines.push(failure_event_source_material(
                &format!("{prefix}.source"),
                &divergence.source,
                &FailureSymmetryCanonicalizer::identity(ContentHash::default()),
            ));
            lines.push(format!("{prefix}.kind_len={}", divergence.kind.len()));
            lines.push(format!("{prefix}.event_kind={}", divergence.kind));
            lines.push(format!(
                "{prefix}.expected_state_summary_len={}",
                divergence.expected_state_summary.len()
            ));
            lines.push(format!(
                "{prefix}.expected_state_summary={}",
                divergence.expected_state_summary
            ));
            lines.push(format!(
                "{prefix}.reproduced_state_summary_len={}",
                divergence.reproduced_state_summary.len()
            ));
            lines.push(format!(
                "{prefix}.reproduced_state_summary={}",
                divergence.reproduced_state_summary
            ));
        }
    }
}

fn push_failure_report_step_lines(
    prefix: &str,
    step: &FailureClusterReportCausalStep,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.raw_index={}", step.raw_index));
    lines.push(format!("{prefix}.sequence={}", step.sequence));
    match &step.node {
        Some(node) => lines.push(node_ref_material(&format!("{prefix}.node"), node)),
        None => lines.push(format!("{prefix}.node=none")),
    }
    lines.push(format!("{prefix}.icount={}", step.icount.retired));
    lines.push(format!("{prefix}.kind_len={}", step.kind.len()));
    lines.push(format!("{prefix}.kind={}", step.kind));
    lines.push(format!("{prefix}.source_len={}", step.source.len()));
    lines.push(format!("{prefix}.source={}", step.source));
    lines.push(format!("{prefix}.entry={}", content_hash_hex(step.entry)));
}

fn failure_cluster_report_set_material(report_set: &FailureClusterReportSet) -> String {
    let mut lines = vec![
        report_set.policy.canonical_material(),
        format!("report_count={}", report_set.reports.len()),
    ];
    for (index, report) in report_set.reports.iter().enumerate() {
        lines.push(format!("report.index={index}"));
        lines.push(format!(
            "report.cluster_id={}",
            content_hash_hex(report.cluster_id)
        ));
        lines.push(format!(
            "report.content_hash={}",
            content_hash_hex(report.content_hash())
        ));
    }
    lines.join("\n")
}

fn failure_cluster_report_json(report: &FailureClusterReport) -> String {
    let members = report
        .member_hashes
        .iter()
        .map(|hash| json_string(&format_content_hash_ref(*hash)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":{},\"cluster_id\":{},\"policy\":{},\"report_hash\":{},\"signature_hash\":{},\"member_count\":{},\"member_hashes\":[{}],\"minimal_representative\":{},\"replay_command\":{},\"canonical_material\":{}}}",
        json_string(FAILURE_CLUSTER_REPORT_DOMAIN),
        json_string(&format_content_hash_ref(report.cluster_id)),
        json_string(signature_policy_level_label(report.policy.level())),
        json_string(&format_content_hash_ref(report.content_hash())),
        json_string(&format_content_hash_ref(report.signature.content_hash())),
        report.member_count,
        members,
        json_string(&format_content_hash_ref(report.minimal_representative)),
        json_string(&report.replay_command),
        json_string(&report.canonical_material()),
    )
}

fn failure_cluster_report_set_json(report_set: &FailureClusterReportSet) -> String {
    let reports = report_set
        .reports
        .iter()
        .map(failure_cluster_report_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":{},\"policy\":{},\"report_set_hash\":{},\"report_count\":{},\"reports\":[{}],\"canonical_material\":{}}}",
        json_string(FAILURE_CLUSTER_REPORT_SET_DOMAIN),
        json_string(signature_policy_level_label(report_set.policy.level())),
        json_string(&format_content_hash_ref(report_set.content_hash())),
        report_set.reports.len(),
        reports,
        json_string(&report_set.canonical_material()),
    )
}

fn failure_cluster_report_table(report: &FailureClusterReport) -> String {
    let mut lines = vec![
        String::from("field\tvalue"),
        format!("cluster_id\t{}", format_content_hash_ref(report.cluster_id)),
        format!(
            "minimal_representative\t{}",
            format_content_hash_ref(report.minimal_representative)
        ),
        format!("member_count\t{}", report.member_count),
        format!("replay_command\t{}", report.replay_command),
    ];
    for line in report.canonical_material().lines() {
        let (field, value) = line.split_once('=').unwrap_or((line, ""));
        lines.push(format!("canonical.{field}\t{value}"));
    }
    lines.join("\n")
}

fn failure_cluster_report_markdown(report: &FailureClusterReport) -> String {
    format!(
        "# Crucible Triage Cluster {}\n\n- Policy: {}\n- Members: {}\n- Minimal representative: {}\n- Replay: `{}`\n\n## Canonical Report\n\n```text\n{}\n```",
        format_content_hash_ref(report.cluster_id),
        signature_policy_level_label(report.policy.level()),
        report.member_count,
        format_content_hash_ref(report.minimal_representative),
        report.replay_command,
        report.canonical_material(),
    )
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(ch)));
            }
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn signature_policy_level_label(level: SignaturePolicyLevel) -> &'static str {
    match level {
        SignaturePolicyLevel::Coarse => "coarse",
        SignaturePolicyLevel::Default => "default",
        SignaturePolicyLevel::Fine => "fine",
        SignaturePolicyLevel::Exact => "exact",
    }
}

fn failure_kind_label(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::PropertyViolation => "property-violation",
        FailureKind::Divergence => "divergence",
    }
}

fn failure_assertion_quantifier_label(quantifier: AssertionQuantifierKind) -> &'static str {
    match quantifier {
        AssertionQuantifierKind::Always => "always",
        AssertionQuantifierKind::Sometimes => "sometimes",
        AssertionQuantifierKind::Eventually => "eventually",
        AssertionQuantifierKind::AfterQuiescence => "after-quiescence",
        AssertionQuantifierKind::Reachable => "reachable",
        AssertionQuantifierKind::GuestAlways => "guest-always",
        AssertionQuantifierKind::GuestSometimes => "guest-sometimes",
        AssertionQuantifierKind::GuestReachable => "guest-reachable",
        AssertionQuantifierKind::GuestUnreachable => "guest-unreachable",
    }
}
