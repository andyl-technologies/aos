//! Deterministic per-cluster reports and report collections.

use super::*;

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

    pub(in crate::model) fn to_divergence_point(&self) -> EventLogCausalDivergencePoint {
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
    /// Deterministic execution-budget exhaustion.
    Timeout(FailureTimeoutRecord),
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

    /// Builds report detail for an execution timeout.
    #[must_use]
    pub fn timeout(record: FailureTimeoutRecord) -> Self {
        Self::Timeout(record)
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
