//! Typed Crucible execution boundary for repository-resolved campaign attempts.
//!
//! This adapter consumes the language-neutral campaign contract, strictly
//! translates its nested artifacts through [`crate::crucible_artifact`], and
//! gives a concrete runner only authenticated Crucible values. Placement,
//! hot-fork, exact-restore, and thin-replay selection remain operational runner
//! policy and cannot alter the canonical attempt.

use crucible::{Configuration, ScenarioDefForm};
use crucible_campaign::{
    Attempt, BranchPath, CampaignExecutorStore, CampaignLineage, ExecutorRejection,
    ObservationCandidate, ResolvedSelection,
};

use crate::{
    AttemptExecutionContext, AttemptExecutionInput, AttemptExecutionModel, AttemptWorkerFailure,
    CrucibleArtifactError, ResolvedAttemptStart,
    decode_crucible_configuration_artifact_with_selections, decode_crucible_scenario_artifact,
};

/// Authenticated Crucible discovery or one-selection branch start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrucibleResolvedAttemptStart {
    /// Continues one exact existing Crucible configuration.
    Discover {
        /// Decoded and identity-verified starting configuration.
        configuration: Configuration,
    },
    /// Applies one campaign selection at an exact parent configuration.
    Branch {
        /// Decoded and identity-verified parent configuration.
        parent: Configuration,
        /// Campaign selection, opportunity, and effective domain authenticated together.
        selection: Box<ResolvedSelection>,
    },
}

/// Fully decoded input supplied to a concrete Crucible execution runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptExecution {
    lineage: CampaignLineage,
    scenario: ScenarioDefForm,
    attempt: Attempt,
    path: BranchPath,
    start: CrucibleResolvedAttemptStart,
}

impl CrucibleAttemptExecution {
    /// Returns the exact compatibility lineage admitted for this execution.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }

    /// Returns the decoded canonical Crucible scenario form.
    #[must_use]
    pub const fn scenario(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the authenticated semantic edge path.
    #[must_use]
    pub const fn path(&self) -> &BranchPath {
        &self.path
    }

    /// Returns the decoded discovery or one-selection branch start.
    #[must_use]
    pub const fn start(&self) -> &CrucibleResolvedAttemptStart {
        &self.start
    }
}

/// Concrete Crucible lifecycle runner behind the campaign execution contract.
pub trait CrucibleExecutionRunner {
    /// Runner-specific process, materialization, or modeled-execution failure.
    type Error;

    /// Executes one strictly decoded Crucible attempt.
    ///
    /// Implementations choose hot fork, exact restore, or thin replay without
    /// changing the returned canonical candidate.
    ///
    /// # Errors
    ///
    /// Returns a classified runner error for retryable infrastructure failure,
    /// observed cancellation, or stable incompatibility.
    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>>;
}

/// Execution-model adapter that authenticates artifacts before invoking a runner.
pub struct CrucibleExecutionModel<R> {
    store: CampaignExecutorStore,
    runner: R,
}

impl<R> CrucibleExecutionModel<R> {
    /// Creates the strict Crucible adapter over one concrete runner.
    #[must_use]
    pub const fn new(store: CampaignExecutorStore, runner: R) -> Self {
        Self { store, runner }
    }

    /// Returns the concrete runner for diagnostics and configuration.
    #[must_use]
    pub const fn runner(&self) -> &R {
        &self.runner
    }

    /// Returns mutable access to the concrete runner.
    #[must_use]
    pub const fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }

    /// Returns the owned runner after worker shutdown.
    #[must_use]
    pub fn into_runner(self) -> R {
        self.runner
    }
}

/// Failure from artifact authentication or the concrete Crucible runner.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleExecutionModelError<E> {
    /// Nested execution-model bytes failed strict authentication.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The concrete Crucible runner failed after authentication.
    #[error("Crucible execution runner failed")]
    Runner(E),
}

impl<R> AttemptExecutionModel for CrucibleExecutionModel<R>
where
    R: CrucibleExecutionRunner,
{
    type Error = CrucibleExecutionModelError<R::Error>;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>> {
        let scenario = decode_crucible_scenario_artifact(input.scenario()).map_err(|error| {
            AttemptWorkerFailure::Terminal(CrucibleExecutionModelError::Artifact(error))
        })?;
        let start = match input.start() {
            ResolvedAttemptStart::Discover { configuration } => {
                let configuration = decode_crucible_configuration_artifact_with_selections(
                    &scenario,
                    input.scenario(),
                    configuration,
                    &self.store,
                )
                .map_err(map_artifact_failure)?;
                CrucibleResolvedAttemptStart::Discover { configuration }
            }
            ResolvedAttemptStart::Branch { parent, selection } => {
                let parent = decode_crucible_configuration_artifact_with_selections(
                    &scenario,
                    input.scenario(),
                    parent,
                    &self.store,
                )
                .map_err(map_artifact_failure)?;
                CrucibleResolvedAttemptStart::Branch {
                    parent,
                    selection: selection.clone(),
                }
            }
        };
        let decoded = CrucibleAttemptExecution {
            lineage: input.lineage().clone(),
            scenario,
            attempt: input.attempt().clone(),
            path: input.path().clone(),
            start,
        };
        self.runner
            .execute(&decoded, context)
            .map_err(map_runner_failure)
    }
}

fn map_artifact_failure<E>(
    error: CrucibleArtifactError,
) -> AttemptWorkerFailure<CrucibleExecutionModelError<E>> {
    let retryable = matches!(
        &error,
        CrucibleArtifactError::SelectionRepository(repository)
            if repository.executor_rejection() == ExecutorRejection::UnavailableInput
    );
    let error = CrucibleExecutionModelError::Artifact(error);
    if retryable {
        AttemptWorkerFailure::Retryable(error)
    } else {
        AttemptWorkerFailure::Terminal(error)
    }
}

fn map_runner_failure<E>(
    failure: AttemptWorkerFailure<E>,
) -> AttemptWorkerFailure<CrucibleExecutionModelError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(CrucibleExecutionModelError::Runner(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(CrucibleExecutionModelError::Runner(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(CrucibleExecutionModelError::Runner(error))
        }
    }
}
