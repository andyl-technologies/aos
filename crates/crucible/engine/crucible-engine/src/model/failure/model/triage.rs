//! Content-addressed finding ledgers, triage results, and result diffs.

use super::*;

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
        let minimized_members = minimization
            .runs
            .iter()
            .map(|run| (run.cluster_id, run.representative_artifact))
            .collect::<BTreeSet<_>>();
        if minimized_members.len() != minimization.runs.len() {
            return Err(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-triage-result",
                reason: "duplicate minimization run for cluster member",
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
            let run = minimization
                .runs
                .iter()
                .find(|run| {
                    run.cluster_id == cluster.id
                        && run.representative_artifact == representative.reproduction_artifact
                })
                .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "missing minimization run for cluster representative",
                })?;
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
            let cluster = clustering
                .clusters
                .iter()
                .find(|cluster| cluster.id == run.cluster_id)
                .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "minimization run does not belong to a cluster",
                })?;
            if !cluster
                .members
                .iter()
                .any(|member| member.reproduction_artifact == run.representative_artifact)
                || run.minimization.original.artifact.id() != run.representative_artifact
                || run.target_signature_key != cluster.signature_key
                || run.minimized_signature_key != cluster.signature_key
                || !run.preserves_signature()
            {
                return Err(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "minimization run does not match its cluster member",
                });
            }
            let representative = cluster.representative_member().ok_or(
                EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "failure-triage-result",
                    reason: "minimized cluster has no representative",
                },
            )?;
            if run.representative_artifact != representative.reproduction_artifact {
                continue;
            }
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
