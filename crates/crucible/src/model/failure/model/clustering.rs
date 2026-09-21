//! Deterministic failure clustering and signature-preserving minimization.

use super::*;

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
                disposition: FailureMinimizationDisposition::Minimized,
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
pub(in crate::model) struct FailureClusterBuilder {
    pub(in crate::model) signature_key: FailureSignatureKey,
    pub(in crate::model) members: BTreeMap<ContentHash, FailureClusterMember>,
}

/// Signature-preserving minimization evidence for one failure-cluster member.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailureSignaturePreservingMinimizationRun {
    /// Cluster whose selected member was minimized.
    pub cluster_id: ContentHash,
    /// Reproduction artifact selected from the cluster.
    pub representative_artifact: ContentHash,
    /// Signature key that must be preserved by every accepted candidate.
    pub target_signature_key: FailureSignatureKey,
    /// Signature key observed for the emitted minimal representative.
    pub minimized_signature_key: FailureSignatureKey,
    /// Whether a shrink pass ran or the failure kind is not safely minimizable.
    pub disposition: FailureMinimizationDisposition,
    /// Underlying replay-validated minimization run from the base shrink pass.
    pub minimization: MinimizationRun,
}

/// Closed outcome of a signature-preserving minimization request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureMinimizationDisposition {
    /// The deterministic candidate shrink pass was executed.
    Minimized,
    /// The caller requested clustering and reports without minimization.
    NotRequested,
    /// Timeout evidence retained the original representative without replaying candidates.
    NotApplicableTimeout,
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
    /// Minimized members ordered by cluster id and original artifact.
    ///
    /// The default path contains one content-address-least representative per
    /// cluster. Forensic all-member minimization adds one run for every other
    /// member while retaining the representative run used by the report.
    pub runs: Vec<FailureSignaturePreservingMinimizationRun>,
}

impl FailureSignaturePreservingMinimizationResult {
    /// Returns the number of distinct clusters represented by the runs.
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        self.runs
            .iter()
            .map(|run| run.cluster_id)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Returns the number of minimal member reproductions emitted.
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
