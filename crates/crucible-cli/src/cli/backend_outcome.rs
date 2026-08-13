//! Backend-neutral command outcomes and process status mapping.

use super::*;

pub(crate) trait BackendRouteRecorder {
    fn record_remote_daemon(&mut self, daemon: &str);

    fn record_local_backend(&mut self, backend: &ResolvedLocalBackend);

    fn record_backend_announcement(&mut self, message: &str);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BackendCommandOutcome {
    pub(crate) subcommand: CliSubcommand,
    pub(crate) status: BackendCommandStatus,
    pub(crate) exit_code: i32,
    pub(crate) stdout: Vec<String>,
    pub(crate) stderr: Vec<String>,
    pub(crate) canonical_log: Vec<CanonicalLogEntry>,
    pub(crate) canonical_log_digest: String,
    pub(crate) artifact_digest: String,
    pub(crate) terminal_savepoint: Option<crucible::ContentHash>,
    pub(crate) savepoint_oracle: Option<SavepointOracleProof>,
    pub(crate) save_boundary_evidence: Option<SaveBoundaryEvidence>,
    pub(crate) reproduction_artifact: Option<Vec<u8>>,
    pub(crate) side_reproduction_artifacts: Vec<(String, Vec<u8>)>,
}

impl BackendCommandOutcome {
    #[cfg(test)]
    pub(crate) fn normalized(&self) -> BackendCommandOutcomeProjection {
        BackendCommandOutcomeProjection {
            subcommand: self.subcommand,
            status: self.status,
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            canonical_log_digest: self.canonical_log_digest.clone(),
            artifact_digest: self.artifact_digest.clone(),
            terminal_savepoint: self.terminal_savepoint,
            savepoint_oracle: self.savepoint_oracle.clone(),
            save_boundary_evidence: self.save_boundary_evidence.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum BackendCommandStatus {
    Passed,
    Failed,
    Crashed,
    Timeout,
}

impl BackendCommandStatus {
    pub(crate) fn exit_code(self) -> i32 {
        CliError::Outcome(self).exit_code()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::Timeout => "timeout",
        }
    }

    pub(crate) fn non_passing_variants() -> [Self; 3] {
        [Self::Failed, Self::Crashed, Self::Timeout]
    }

    pub(crate) fn is_non_passing(self) -> bool {
        !matches!(self, Self::Passed)
    }

    pub(crate) fn failure_slug(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::Timeout => "timeout",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BackendCommandOutcomeProjection {
    pub(crate) subcommand: CliSubcommand,
    pub(crate) status: BackendCommandStatus,
    pub(crate) exit_code: i32,
    pub(crate) stdout: Vec<String>,
    pub(crate) stderr: Vec<String>,
    pub(crate) canonical_log_digest: String,
    pub(crate) artifact_digest: String,
    pub(crate) terminal_savepoint: Option<crucible::ContentHash>,
    pub(crate) savepoint_oracle: Option<SavepointOracleProof>,
    pub(crate) save_boundary_evidence: Option<SaveBoundaryEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BackendExecutionEvidence {
    #[cfg(any(test, feature = "test-double"))]
    LocalDouble,
    LocalProduction {
        build_id: String,
        plugin_abi: String,
    },
    RemoteDaemon {
        daemon: String,
    },
}

impl BackendExecutionEvidence {
    pub(crate) fn proves_t_cli_3(&self, plan: &BackendSelectionPlan) -> bool {
        plan.expected_execution_evidence().as_ref() == Some(self)
    }
}

pub(crate) struct BackendCommandExecution {
    pub(crate) outcome: BackendCommandOutcome,
    pub(crate) evidence: BackendExecutionEvidence,
}

pub(crate) trait BackendCommandRunner {
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    fn run_local(
        &mut self,
        backend: &ResolvedLocalBackend,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
        save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandExecution, CliError>;

    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::too_many_arguments)]
    fn run_remote(
        &mut self,
        daemon: &str,
        thin_plan: &CliThinWrapperPlan,
        backend_plan: &BackendSelectionPlan,
        ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
        run_plan: Option<&RunInvocationPlan>,
        verify_plan: Option<&VerifyInvocationPlan>,
        save_plan: Option<&SaveInvocationPlan>,
    ) -> Result<BackendCommandExecution, CliError>;
}
