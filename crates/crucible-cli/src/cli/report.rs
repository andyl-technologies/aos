//! User-facing reports, debug plans, selftest reports, and CLI errors.

use super::*;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LoadedTriageFindings {
    pub(super) ledger: crucible::FailureFindingsLedger,
    pub(super) evidence: BTreeMap<crucible::ContentHash, TriageFindingEvidence>,
    pub(super) campaign_evidence: Vec<CampaignTriageFindingEvidence>,
    pub(super) artifact_bytes: Vec<u8>,
}

/// Authenticated campaign records retained beside one report projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignTriageFindingEvidence {
    pub(super) campaign: crucible_campaign::CampaignName,
    pub(super) snapshot: crucible_campaign::CampaignSnapshotId,
    pub(super) membership: CampaignFindingsMembershipProof,
    pub(super) observation_proof: CampaignFindingObjectProof,
    pub(super) reproduction_proof: CampaignFindingObjectProof,
    pub(super) minimized_reproduction_proof: Option<CampaignFindingObjectProof>,
    pub(super) occurrence_proofs: Vec<CampaignFindingOccurrenceProof>,
    pub(super) finding: crucible_campaign::Finding,
    pub(super) observation: crucible_campaign::Observation,
    pub(super) reproduction: crucible_campaign::ReproductionArtifact,
    pub(super) minimized_reproduction: Option<crucible_campaign::ReproductionArtifact>,
    pub(super) report: TriageFindingEvidence,
}

/// Exact checked service exchange proving final-snapshot Finding membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingsMembershipProof {
    pub(super) request: crucible_campaign::QueryCampaignFindingsRequest,
    pub(super) response: crucible_campaign::QueryCampaignFindingsResponse,
}

/// Exact checked service exchange resolving one Finding-owned dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingObjectProof {
    pub(super) request: crucible_campaign::GetCampaignFindingObjectRequest,
    pub(super) response: crucible_campaign::GetCampaignFindingObjectResponse,
}

/// Exact checked service exchange for one page of retained candidate occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingOccurrencesProof {
    pub(super) request: crucible_campaign::QueryCampaignFindingOccurrencesRequest,
    pub(super) response: crucible_campaign::QueryCampaignFindingOccurrencesResponse,
}

/// Exact checked exchanges resolving one retained candidate occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingOccurrenceProof {
    pub(super) page: CampaignFindingOccurrencesProof,
    pub(super) observation: CampaignFindingOccurrenceObjectProof,
    pub(super) reproduction: CampaignFindingOccurrenceObjectProof,
    pub(super) minimized_reproduction: CampaignFindingOccurrenceObjectProof,
    pub(super) triage_evidence: Option<CampaignFindingOccurrenceTriageProof>,
}

/// Four independently replayed native signatures retained by a rich candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingOccurrenceTriageProof {
    pub(super) minimization_original: CampaignFindingTriageReplayProof,
    pub(super) minimization_selected: CampaignFindingTriageReplayProof,
    pub(super) verification_original: CampaignFindingTriageReplayProof,
    pub(super) verification_selected: CampaignFindingTriageReplayProof,
}

/// Complete ordered segment transcript for one candidate triage replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingTriageReplayProof {
    pub(super) segments: Vec<CampaignFindingTriageReplaySegmentProof>,
}

/// One exact checked exchange resolving a stored replay-envelope segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingTriageReplaySegmentProof {
    pub(super) request: crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest,
    pub(super) response: crucible_campaign::GetCampaignFindingTriageReplaySegmentResponse,
}

/// Exact checked service exchange resolving one candidate-owned dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CampaignFindingOccurrenceObjectProof {
    pub(super) request: crucible_campaign::GetCampaignFindingOccurrenceObjectRequest,
    pub(super) response: crucible_campaign::GetCampaignFindingOccurrenceObjectResponse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageFindingEvidence {
    pub(super) finding: crucible::FindingReproductionArtifact,
    pub(super) causal_entries: Vec<crucible::SchedulerEventLogEntry>,
    pub(super) recorded_event_log: crucible_model::FailureRecordedEventLog,
    pub(super) failure: crucible_model::FailureClusterReportFailure,
    pub(super) discovery_signature: crucible_model::FailureSignature,
    pub(super) recorded_event_frames: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TriageInvocationPlan {
    pub(super) policy: crucible::SignaturePolicy,
    pub(super) minimize: TriageMinimizeArg,
    pub(super) report_dir: PathBuf,
    pub(super) format: crucible::FailureClusterReportFormat,
    pub(super) recompute_signatures: bool,
    pub(super) store_root: PathBuf,
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
