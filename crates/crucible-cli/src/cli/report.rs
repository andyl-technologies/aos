//! User-facing reports, debug plans, selftest reports, and CLI errors.

use super::*;

type OptionalHashPair = (Option<crucible::ContentHash>, Option<crucible::ContentHash>);

impl Cli {
    pub(super) fn output_format(&self) -> OutputFormat {
        resolve_output_format(self.format, io::stdout().is_terminal())
    }
}

/// Selects the explicit format or a terminal-appropriate default.
pub(super) fn resolve_output_format(
    explicit: Option<OutputFormat>,
    stdout_is_terminal: bool,
) -> OutputFormat {
    match explicit {
        Some(format) => format,
        None if stdout_is_terminal => OutputFormat::Table,
        None => OutputFormat::Jsonl,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageRunReport {
    pub(super) plan: TriageInvocationPlan,
    pub(super) ledger: crucible::FailureFindingsLedger,
    pub(super) stored_ledger: crucible::FailureTriageStoredArtifact,
    pub(super) result: crucible::FailureTriageResult,
    pub(super) stored_result: crucible::FailureTriageStoredArtifact,
    pub(super) report_path: PathBuf,
    pub(super) compare: Option<TriageSummaryDiff>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LoadedTriageFindings {
    pub(super) ledger: crucible::FailureFindingsLedger,
    pub(super) evidence: BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
    pub(super) artifact_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageFindingEvidence {
    pub(super) finding: crucible::FindingReproductionArtifact,
    pub(super) recorded_event_log: crucible_model::FailureRecordedEventLog,
    pub(super) failure: crucible_model::FailureClusterReportFailure,
    pub(super) discovery_signature: crucible_model::FailureSignature,
    pub(super) recorded_event_frames: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageInvocationPlan {
    pub(super) findings: TriageFindingsSource,
    pub(super) policy: crucible::SignaturePolicy,
    pub(super) minimize: TriageMinimizeArg,
    pub(super) report_dir: PathBuf,
    pub(super) format: crucible::FailureClusterReportFormat,
    pub(super) recompute_signatures: bool,
    pub(super) compare: Option<TriageCompareTarget>,
    pub(super) store_root: PathBuf,
    pub(super) pipeline: Vec<TriagePipelineStep>,
    pub(super) failure_exit_code: i32,
    pub(super) thin_driver: bool,
    pub(super) owns_run_state: bool,
    pub(super) offline: bool,
    pub(super) scheduler_started: bool,
}

impl TriageInvocationPlan {
    pub(super) fn policy_label(&self) -> &'static str {
        match self.policy.level() {
            crucible::SignaturePolicyLevel::Coarse => "coarse",
            crucible::SignaturePolicyLevel::Default => "default",
            crucible::SignaturePolicyLevel::Fine => "fine",
            crucible::SignaturePolicyLevel::Exact => "exact",
        }
    }

    pub(super) fn minimize_label(&self) -> &'static str {
        match self.minimize {
            TriageMinimizeArg::None => "none",
            TriageMinimizeArg::Representative => "representative",
            TriageMinimizeArg::All => "all",
        }
    }

    pub(super) fn format_label(&self) -> &'static str {
        match self.format {
            crucible::FailureClusterReportFormat::JsonLines => "jsonl",
            crucible::FailureClusterReportFormat::Json => "json",
            crucible::FailureClusterReportFormat::Table => "table",
            crucible::FailureClusterReportFormat::Markdown => "markdown",
        }
    }

    pub(super) fn proves_t_tri_7(&self) -> bool {
        self.thin_driver
            && !self.owns_run_state
            && self.offline
            && !self.scheduler_started
            && self
                .pipeline
                .contains(&TriagePipelineStep::LoadFindingsLedger)
            && self.pipeline.contains(&TriagePipelineStep::Cluster)
            && self.pipeline.contains(&TriagePipelineStep::EmitReports)
            && self
                .pipeline
                .contains(&TriagePipelineStep::StoreTriageResult)
            && self.failure_exit_code == 1
            && match self.minimize {
                TriageMinimizeArg::None => self
                    .pipeline
                    .contains(&TriagePipelineStep::SkipMinimization),
                TriageMinimizeArg::Representative => self
                    .pipeline
                    .contains(&TriagePipelineStep::MinimizeRepresentative),
                TriageMinimizeArg::All => self.pipeline.contains(&TriagePipelineStep::MinimizeAll),
            }
            && (!self.recompute_signatures
                || self
                    .pipeline
                    .contains(&TriagePipelineStep::RecomputeSignatureSelfCheck))
            && (self.compare.is_none()
                || self
                    .pipeline
                    .contains(&TriagePipelineStep::CompareContentDiff))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TriageFindingsSource {
    Path(PathBuf),
    StoredLedger(crucible::ContentHash),
}

impl TriageFindingsSource {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Path(_) => "path",
            Self::StoredLedger(_) => "dag-store",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TriageCompareTarget {
    Path(PathBuf),
    StoredResult(crucible::ContentHash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum TriagePipelineStep {
    LoadFindingsLedger,
    RecomputeSignatureSelfCheck,
    Cluster,
    SkipMinimization,
    MinimizeRepresentative,
    MinimizeAll,
    EmitReports,
    StoreTriageResult,
    CompareContentDiff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageResultSummary {
    pub(super) result: crucible::ContentHash,
    pub(super) report_hashes: BTreeMap<crucible::ContentHash, crucible::ContentHash>,
}

impl TriageResultSummary {
    pub(super) fn from_result(result: &crucible::FailureTriageResult) -> Self {
        Self {
            result: result.content_hash(),
            report_hashes: result
                .report_set
                .reports
                .iter()
                .map(|report| (report.cluster_id, report.content_hash()))
                .collect(),
        }
    }

    pub(super) fn from_artifact_bytes(bytes: &[u8]) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| artifact_error(format!("triage result is not UTF-8: {error}")))?;
        if text.lines().next() != Some("crucible.failure-triage.result.v1") {
            return Err(artifact_error("unsupported triage result artifact schema"));
        }
        let mut by_index = BTreeMap::<usize, OptionalHashPair>::new();
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("report.") else {
                continue;
            };
            let Some((index, field_value)) = rest.split_once('.') else {
                return Err(artifact_error("malformed triage result report line"));
            };
            let index = index
                .parse::<usize>()
                .map_err(|_| artifact_error("malformed triage result report index"))?;
            let Some((field, value)) = field_value.split_once('=') else {
                return Err(artifact_error("malformed triage result report field"));
            };
            let entry = by_index.entry(index).or_insert((None, None));
            match field {
                "cluster_id" => {
                    entry.0 = Some(parse_hex_content_hash("triage result cluster id", value)?);
                }
                "content_hash" => {
                    entry.1 = Some(parse_hex_content_hash("triage result report hash", value)?);
                }
                "minimal_representative" => {}
                _ => {}
            }
        }
        let mut report_hashes = BTreeMap::new();
        for (index, (cluster_id, report_hash)) in by_index {
            let cluster_id = cluster_id.ok_or_else(|| {
                artifact_error(format!(
                    "triage result report {index} is missing cluster_id"
                ))
            })?;
            let report_hash = report_hash.ok_or_else(|| {
                artifact_error(format!(
                    "triage result report {index} is missing content_hash"
                ))
            })?;
            report_hashes.insert(cluster_id, report_hash);
        }
        Ok(Self {
            result: crucible::ContentHash::from_bytes(bytes),
            report_hashes,
        })
    }

    pub(super) fn diff_from(&self, baseline: &Self) -> TriageSummaryDiff {
        let all_clusters = self
            .report_hashes
            .keys()
            .chain(baseline.report_hashes.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();
        for cluster in all_clusters {
            match (
                baseline.report_hashes.get(&cluster),
                self.report_hashes.get(&cluster),
            ) {
                (None, Some(_)) => added.push(cluster),
                (Some(_), None) => removed.push(cluster),
                (Some(left), Some(right)) if left == right => unchanged.push(cluster),
                (Some(left), Some(right)) => changed.push(TriageSummaryChangedCluster {
                    cluster,
                    baseline_report: *left,
                    candidate_report: *right,
                }),
                (None, None) => {}
            }
        }
        TriageSummaryDiff {
            baseline: baseline.result,
            candidate: self.result,
            added,
            removed,
            changed,
            unchanged,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TriageSummaryChangedCluster {
    pub(super) cluster: crucible::ContentHash,
    pub(super) baseline_report: crucible::ContentHash,
    pub(super) candidate_report: crucible::ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageSummaryDiff {
    pub(super) baseline: crucible::ContentHash,
    pub(super) candidate: crucible::ContentHash,
    pub(super) added: Vec<crucible::ContentHash>,
    pub(super) removed: Vec<crucible::ContentHash>,
    pub(super) changed: Vec<TriageSummaryChangedCluster>,
    pub(super) unchanged: Vec<crucible::ContentHash>,
}

impl TriageSummaryDiff {
    pub(super) fn status_label(&self) -> &'static str {
        if self.baseline == self.candidate
            && self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
        {
            "unchanged"
        } else {
            "changed"
        }
    }

    pub(super) fn content_diff(&self) -> String {
        let mut lines = vec![
            format!("baseline\t{}", format_content_hash_ref(self.baseline)),
            format!("candidate\t{}", format_content_hash_ref(self.candidate)),
        ];
        for cluster in &self.added {
            lines.push(format!("added\t{}", format_content_hash_ref(*cluster)));
        }
        for cluster in &self.removed {
            lines.push(format!("removed\t{}", format_content_hash_ref(*cluster)));
        }
        for changed in &self.changed {
            lines.push(format!(
                "changed\t{}\t{}\t{}",
                format_content_hash_ref(changed.cluster),
                format_content_hash_ref(changed.baseline_report),
                format_content_hash_ref(changed.candidate_report)
            ));
        }
        for cluster in &self.unchanged {
            lines.push(format!("unchanged\t{}", format_content_hash_ref(*cluster)));
        }
        lines.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DebugInvocationPlan {
    pub(super) target: DebugPlanTarget,
    pub(super) coordinate: DebugPlanCoordinate,
    pub(super) node: Option<String>,
    pub(super) gdb_listen: String,
    pub(super) read_only: bool,
    pub(super) allow_mutate: bool,
    pub(super) checkpoint_stride: Option<u64>,
    pub(super) record_transcript: Option<PathBuf>,
    pub(super) guest_idle_timeout: Duration,
    pub(super) verb: DebugInteractiveVerbPlan,
    pub(super) session_commands: Vec<SessionCommand>,
    pub(super) engine_operations: Vec<DebugEngineOperation>,
    pub(super) surface_contract: crucible::DebugCliSurfaceContract,
    pub(super) owns_debug_state: bool,
    pub(super) raw_gdb_single_step_allowed: bool,
    pub(super) non_canonical_branch_label: Option<String>,
}

impl DebugInvocationPlan {
    fn proves_thin_wrapper(&self) -> bool {
        !self.owns_debug_state
            && self.surface_contract.delegates_to_session_commands
            && self.surface_contract.delegates_to_gdbstub_proxy
            && self
                .engine_operations
                .contains(&DebugEngineOperation::ResolveTarget)
            && self
                .engine_operations
                .contains(&DebugEngineOperation::AttachGdbProxy)
            && self
                .engine_operations
                .contains(&DebugEngineOperation::OpenGdbstub)
            && self.engine_operations.contains(&DebugEngineOperation::Goto)
            && self
                .engine_operations
                .contains(&DebugEngineOperation::RestoreNearestCheckpointReplay)
            && self.session_commands.iter().all(|command| {
                matches!(
                    command,
                    SessionCommand::Query { .. } | SessionCommand::Fork { .. }
                )
            })
    }

    fn proves_read_mutate_boundary(&self) -> bool {
        if matches!(self.verb, DebugInteractiveVerbPlan::ForkDebug) {
            self.allow_mutate
                && !self.read_only
                && self.non_canonical_branch_label.as_deref() == Some("NON-CANONICAL debug branch")
                && self
                    .session_commands
                    .contains(&SessionCommand::fork_current())
                && self
                    .engine_operations
                    .contains(&DebugEngineOperation::NonCanonicalBranchFork)
        } else if matches!(
            self.verb,
            DebugInteractiveVerbPlan::Exec { .. }
                | DebugInteractiveVerbPlan::Pty { .. }
                | DebugInteractiveVerbPlan::Ssh
        ) {
            self.allow_mutate
                && !self.read_only
                && self.non_canonical_branch_label.as_deref() == Some("NON-CANONICAL debug branch")
                && !self
                    .session_commands
                    .contains(&SessionCommand::fork_current())
                && self
                    .engine_operations
                    .contains(&DebugEngineOperation::GuestIntrospection)
        } else {
            self.read_only
                && self.non_canonical_branch_label.is_none()
                && !self
                    .session_commands
                    .contains(&SessionCommand::fork_current())
                && !self
                    .engine_operations
                    .contains(&DebugEngineOperation::NonCanonicalBranchFork)
        }
    }

    pub(super) fn proves_t_dbg_8(&self) -> bool {
        self.surface_contract.proves_t_dbg_8()
            && self.proves_thin_wrapper()
            && self.proves_read_mutate_boundary()
            && !self.raw_gdb_single_step_allowed
            && self
                .engine_operations
                .contains(&DebugEngineOperation::DisableRawGdbSingleStep)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DebugPlanTarget {
    Artifact(PathBuf),
    Savepoint(crucible::ContentHash),
    Session(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DebugPlanCoordinate {
    Current,
    At(crucible::DebugCoordinate),
    AtEvent(u64),
    AtFailure,
    AtCheckpoint(crucible::ContentHash),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DebugInteractiveVerbPlan {
    AttachGdb,
    ForkDebug,
    Goto(crucible::DebugCoordinate),
    ReverseStep {
        grain: crucible::DebugReverseStepGrain,
    },
    ReverseContinue {
        condition: String,
    },
    Exec {
        argv: Vec<String>,
    },
    Pty {
        argv: Vec<String>,
        columns: u16,
        rows: u16,
    },
    Ssh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum DebugEngineOperation {
    ResolveTarget,
    Instantiate,
    AttachGdbProxy,
    OpenGdbstub,
    Goto,
    RestoreNearestCheckpointReplay,
    ReverseStep,
    ReverseContinue,
    ReadOnlyInspection,
    NonCanonicalBranchFork,
    CheckpointCadence,
    NoSymbolServer,
    MultiVcpuThreadEnumeration,
    DisableRawGdbSingleStep,
    GuestIntrospection,
}

#[derive(Debug)]
pub(super) struct SelftestReport {
    pub(super) gates: Vec<SelftestGateReport>,
    pub(super) verified: Vec<crucible::ExampleScenarioVerifyReport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelftestGateStatus {
    Passed,
}

impl SelftestGateStatus {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Passed => "PASS",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelftestGateRunner {
    #[cfg(any(test, feature = "test-double"))]
    DoubleBackedCorpus,
    RealQemu,
}

impl SelftestGateRunner {
    pub(super) fn label(self) -> &'static str {
        match self {
            #[cfg(any(test, feature = "test-double"))]
            Self::DoubleBackedCorpus => "double",
            Self::RealQemu => "qemu",
        }
    }
}

#[path = "report/error.rs"]
mod error;

pub(super) use error::*;
