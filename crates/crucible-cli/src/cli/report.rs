// User-facing reports, debug plans, selftest reports, and CLI errors.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageRunReport {
    plan: TriageInvocationPlan,
    ledger: crucible::FailureFindingsLedger,
    stored_ledger: crucible::FailureTriageStoredArtifact,
    result: crucible::FailureTriageResult,
    stored_result: crucible::FailureTriageStoredArtifact,
    report_path: PathBuf,
    compare: Option<TriageSummaryDiff>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LoadedTriageFindings {
    ledger: crucible::FailureFindingsLedger,
    evidence: BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
    artifact_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageFindingEvidence {
    finding: crucible::FindingReproductionArtifact,
    recorded_event_log: crucible_model::FailureRecordedEventLog,
    failure: crucible_model::FailureClusterReportFailure,
    discovery_signature: crucible_model::FailureSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageInvocationPlan {
    findings: TriageFindingsSource,
    policy: crucible::SignaturePolicy,
    minimize: TriageMinimizeArg,
    report_dir: PathBuf,
    format: crucible::FailureClusterReportFormat,
    recompute_signatures: bool,
    compare: Option<TriageCompareTarget>,
    store_root: PathBuf,
    pipeline: Vec<TriagePipelineStep>,
    failure_exit_code: i32,
    thin_driver: bool,
    owns_run_state: bool,
    offline: bool,
    scheduler_started: bool,
}

impl TriageInvocationPlan {
    fn policy_label(&self) -> &'static str {
        match self.policy.level() {
            crucible::SignaturePolicyLevel::Coarse => "coarse",
            crucible::SignaturePolicyLevel::Default => "default",
            crucible::SignaturePolicyLevel::Fine => "fine",
            crucible::SignaturePolicyLevel::Exact => "exact",
        }
    }

    fn minimize_label(&self) -> &'static str {
        match self.minimize {
            TriageMinimizeArg::None => "none",
            TriageMinimizeArg::Representative => "representative",
            TriageMinimizeArg::All => "all",
        }
    }

    fn format_label(&self) -> &'static str {
        match self.format {
            crucible::FailureClusterReportFormat::JsonLines => "jsonl",
            crucible::FailureClusterReportFormat::Json => "json",
            crucible::FailureClusterReportFormat::Table => "table",
            crucible::FailureClusterReportFormat::Markdown => "markdown",
        }
    }

    fn proves_t_tri_7(&self) -> bool {
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
enum TriageFindingsSource {
    Path(PathBuf),
    StoredLedger(crucible::ContentHash),
}

impl TriageFindingsSource {
    fn label(&self) -> &'static str {
        match self {
            Self::Path(_) => "path",
            Self::StoredLedger(_) => "dag-store",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TriageCompareTarget {
    Path(PathBuf),
    StoredResult(crucible::ContentHash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TriagePipelineStep {
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
struct TriageResultSummary {
    result: crucible::ContentHash,
    report_hashes: BTreeMap<crucible::ContentHash, crucible::ContentHash>,
}

impl TriageResultSummary {
    fn from_result(result: &crucible::FailureTriageResult) -> Self {
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

    fn from_artifact_bytes(bytes: &[u8]) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| artifact_error(format!("triage result is not UTF-8: {error}")))?;
        if text.lines().next() != Some("crucible.failure-triage.result.v1") {
            return Err(artifact_error("unsupported triage result artifact schema"));
        }
        let mut by_index =
            BTreeMap::<usize, (Option<crucible::ContentHash>, Option<crucible::ContentHash>)>::new(
            );
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

    fn diff_from(&self, baseline: &Self) -> TriageSummaryDiff {
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
struct TriageSummaryChangedCluster {
    cluster: crucible::ContentHash,
    baseline_report: crucible::ContentHash,
    candidate_report: crucible::ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TriageSummaryDiff {
    baseline: crucible::ContentHash,
    candidate: crucible::ContentHash,
    added: Vec<crucible::ContentHash>,
    removed: Vec<crucible::ContentHash>,
    changed: Vec<TriageSummaryChangedCluster>,
    unchanged: Vec<crucible::ContentHash>,
}

impl TriageSummaryDiff {
    fn status_label(&self) -> &'static str {
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

    fn content_diff(&self) -> String {
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
struct DebugInvocationPlan {
    target: DebugPlanTarget,
    coordinate: DebugPlanCoordinate,
    node: Option<String>,
    gdb_listen: String,
    read_only: bool,
    allow_mutate: bool,
    checkpoint_stride: Option<u64>,
    verb: DebugInteractiveVerbPlan,
    session_commands: Vec<SessionCommand>,
    engine_operations: Vec<DebugEngineOperation>,
    surface_contract: crucible::DebugCliSurfaceContract,
    owns_debug_state: bool,
    raw_gdb_single_step_allowed: bool,
    non_canonical_branch_label: Option<String>,
}

impl DebugInvocationPlan {
    fn mode_label(&self) -> &'static str {
        if self.allow_mutate {
            "allow-mutate"
        } else {
            "read-only"
        }
    }

    fn proves_read_only_default(&self) -> bool {
        !self.allow_mutate
            && self.read_only
            && self.non_canonical_branch_label.is_none()
            && !self
                .engine_operations
                .contains(&DebugEngineOperation::NonCanonicalBranchFork)
    }

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
                    SessionCommand::Query { .. }
                        | SessionCommand::Snapshot
                        | SessionCommand::Fork { .. }
                )
            })
    }

    fn proves_read_mutate_boundary(&self) -> bool {
        if self.allow_mutate {
            !self.read_only
                && self.non_canonical_branch_label.as_deref() == Some("NON-CANONICAL debug branch")
                && self
                    .session_commands
                    .contains(&SessionCommand::fork_current())
                && self
                    .engine_operations
                    .contains(&DebugEngineOperation::NonCanonicalBranchFork)
        } else {
            self.proves_read_only_default()
        }
    }

    fn proves_t_dbg_8(&self) -> bool {
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
enum DebugPlanTarget {
    Artifact(PathBuf),
    Savepoint(crucible::ContentHash),
    Session(String),
}

impl DebugPlanTarget {
    fn label(&self) -> &'static str {
        match self {
            Self::Artifact(_) => "artifact",
            Self::Savepoint(_) => "savepoint",
            Self::Session(_) => "session",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DebugPlanCoordinate {
    Current,
    At(crucible::DebugCoordinate),
    AtEvent(u64),
    AtFailure,
    AtCheckpoint(crucible::ContentHash),
}

impl DebugPlanCoordinate {
    fn label(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::At(_) => "at",
            Self::AtEvent(_) => "at-event",
            Self::AtFailure => "at-failure",
            Self::AtCheckpoint(_) => "at-checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DebugInteractiveVerbPlan {
    AttachGdb,
    Goto(crucible::DebugCoordinate),
    ReverseStep {
        grain: crucible::DebugReverseStepGrain,
    },
    ReverseContinue {
        condition: String,
    },
}

impl DebugInteractiveVerbPlan {
    fn label(&self) -> &'static str {
        match self {
            Self::AttachGdb => "attach-gdb",
            Self::Goto(_) => "goto",
            Self::ReverseStep { .. } => "reverse-step",
            Self::ReverseContinue { .. } => "reverse-continue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum DebugEngineOperation {
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
}

#[derive(Debug)]
struct SelftestReport {
    gates: Vec<SelftestGateReport>,
    verified: Vec<crucible::ExampleScenarioVerifyReport>,
}

#[derive(Debug)]
struct SelftestGateReport {
    name: String,
    status: SelftestGateStatus,
    corpus_entries: usize,
    runs_per_entry: usize,
    runner: SelftestGateRunner,
    qemu_build_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelftestGateStatus {
    Passed,
}

impl SelftestGateStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Passed => "PASS",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelftestGateRunner {
    DoubleBackedCorpus,
    RealQemu,
}

impl SelftestGateRunner {
    fn label(self) -> &'static str {
        match self {
            Self::DoubleBackedCorpus => "double",
            Self::RealQemu => "qemu",
        }
    }
}

#[derive(Debug)]
enum CliError {
    Io(io::Error),
    Store(crucible::DagStoreError),
    Artifact(String),
    Usage(String),
    Serve(String),
    Backend(String),
    Identity(String),
    Outcome(BackendCommandStatus),
    ReplayCheck(String),
    InvalidScenario(String),
    Triage(String),
    Selftest(crucible::ExampleCorpusError),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 5,
            Self::Store(_) => 5,
            Self::Artifact(_) => 5,
            Self::Usage(_) => 64,
            Self::Serve(_) => 3,
            Self::Backend(_) => 4,
            Self::Identity(_) => 3,
            Self::Outcome(BackendCommandStatus::Passed) => 0,
            Self::Outcome(BackendCommandStatus::Failed) => 1,
            Self::Outcome(BackendCommandStatus::Timeout) => 2,
            Self::Outcome(BackendCommandStatus::Crashed) => 3,
            Self::ReplayCheck(_) => 1,
            Self::InvalidScenario(_) => 5,
            Self::Triage(_) => 1,
            Self::Selftest(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::Usage(error) => write!(formatter, "{error}"),
            Self::Serve(error) => write!(formatter, "{error}"),
            Self::Backend(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Outcome(status) => write!(formatter, "run ended with {status:?}"),
            Self::ReplayCheck(error) => write!(formatter, "{error}"),
            Self::InvalidScenario(error) => write!(formatter, "{error}"),
            Self::Triage(error) => write!(formatter, "{error}"),
            Self::Selftest(error) => write!(formatter, "selftest failed: {error}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Artifact(_) => None,
            Self::Usage(_) => None,
            Self::Serve(_) => None,
            Self::Backend(_) => None,
            Self::Identity(_) => None,
            Self::Outcome(_) => None,
            Self::ReplayCheck(_) => None,
            Self::InvalidScenario(_) => None,
            Self::Triage(_) => None,
            Self::Selftest(error) => Some(error),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn usage_error(reason: impl Into<String>) -> CliError {
    CliError::Usage(reason.into())
}

fn serve_error(reason: impl Into<String>) -> CliError {
    CliError::Serve(reason.into())
}

fn backend_error(reason: impl Into<String>) -> CliError {
    CliError::Backend(reason.into())
}
