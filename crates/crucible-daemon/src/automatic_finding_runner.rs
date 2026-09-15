//! Automatic signature-preserving finding reduction around production runners.
//!
//! The outer runner executes the admitted attempt through its complete
//! production router first. Property failures and execution-quanta timeouts are
//! reduced directly. An explicitly enabled determinism policy privately runs
//! an ordinary candidate twice before originating a divergence finding.
//! Candidate execution shares cancellation and the physical quantum budget
//! with the admitted attempt, but it cannot recursively invoke this wrapper.

use std::collections::BTreeSet;
use std::sync::Arc;

use crucible::{EngineError, FailureClusterReportFailure, FindingReproductionArtifact};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, ConfigurationArtifact, FindingKind,
    FindingSignature, FindingTarget, ObservationCandidate,
};
use thiserror::Error;

use crate::crucible_artifact::{
    AutomaticFindingPreparation, decode_crucible_configuration_artifact_with_owned_candidate,
    prepare_automatic_signature_preserving_finding_with_outcomes,
};
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, AttemptWorkerFailure, AutomaticFindingPreparationError,
    AutomaticFindingReplayOutcome, CrucibleArtifactError, CrucibleAttemptExecution,
    CrucibleExecutionOutcome, CrucibleExecutionRunner, FindingReplayIncompatibility,
    QemuFreshExecutionRunner, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
};

const ASSERTION_FAILURE_CLASS: &str = "qemu.assertion-violation";
const EXECUTION_QUANTA_TIMEOUT_CLASS: &str = "qemu.execution-quanta-timeout";
const DIVERGENCE_FAILURE_CLASS: &str = "qemu.causal-log-divergence";
mod exact_retention;
use exact_retention::prepare_finding_exact_retention;
pub(crate) use exact_retention::{
    CampaignRunFindingExactRetentionSource, FindingExactCandidateInventoryError,
    FindingExactRetentionSource,
};

#[cfg(test)]
pub(crate) fn test_finding_exact_retention_source() -> Arc<dyn FindingExactRetentionSource> {
    let repository = Arc::new(crucible_campaign::CampaignRepository::new(
        Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
            "automatic-finding-exact-retention-test",
            u64::MAX,
        )),
        Arc::new(crucible_cas::content_store::MemoryRefBackend::new()),
    ));
    let checkpoint_directory = match tempfile::tempdir() {
        Ok(directory) => directory.keep(),
        Err(error) => panic!("create test exact checkpoint directory: {error}"),
    };
    let checkpoints = match crate::ExactCheckpointStore::new(
        Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "automatic-finding-exact-checkpoint-test",
            checkpoint_directory,
        )),
        u64::MAX,
    ) {
        Ok(checkpoints) => checkpoints,
        Err(error) => panic!("test exact checkpoint store: {error}"),
    };
    Arc::new(CampaignRunFindingExactRetentionSource::new(
        CampaignExecutorStore::new(repository),
        Arc::new(checkpoints),
    ))
}

mod divergence_signature;
pub(crate) use divergence_signature::divergence_fingerprint_for_scenario;

mod finding_signature;
pub(crate) use finding_signature::automatic_finding_signature;
use finding_signature::{
    bind_qemu_triage_evidence, minimization_seed, original_finding, replay_finding_signature,
};

mod private {
    pub trait Sealed {}
}

/// Fresh runner allowed to execute private finding-reduction candidates.
///
/// Implementations return only after all attempt-scoped process and resource
/// authority has been shut down or quarantined. The production implementation
/// is deliberately limited to `QemuFreshExecutionRunner` with
/// [`crate::QemuFreshModeledDriver`]; hot-fork, exact-resume, and routing runners can
/// retain authority after success and therefore cannot satisfy this contract.
pub trait PrivateFindingReplayRunner: CrucibleExecutionRunner + private::Sealed {
    /// Executes one explicitly requested paired determinism probe.
    ///
    /// Both executions consume the assignment's shared physical work budget.
    /// An incomplete probe is returned as evidence absence rather than a
    /// modeled timeout or divergence.
    ///
    /// # Errors
    ///
    /// Returns a worker failure when either private probe execution cannot
    /// produce a valid lifecycle result.
    fn probe_finding_candidate_determinism(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _candidate: &ConfigurationArtifact,
        _context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingDeterminismProbe, AttemptWorkerFailure<Self::Error>> {
        Ok(AutomaticFindingDeterminismProbe::Incomplete)
    }

    /// Returns whether a private replay failure only exhausted physical work.
    ///
    /// The automatic wrapper preserves the admitted observation when a
    /// divergence probe succeeded but its required reduction transcript could
    /// not complete inside the same finite reservation.
    fn is_incomplete_physical_work_failure(
        &self,
        _failure: &AttemptWorkerFailure<Self::Error>,
    ) -> bool {
        false
    }

    /// Reconstructs and evaluates one exact minimization-candidate boundary.
    ///
    /// # Errors
    ///
    /// Returns a worker failure for operational launch, replay, cancellation,
    /// resource, evaluation, or cleanup failures. Deterministic prefix
    /// incompatibility is returned as a typed successful outcome.
    fn replay_finding_candidate_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        candidate: &ConfigurationArtifact,
        finding: &FindingReproductionArtifact,
        target_signature: &FindingSignature,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>>;
}

/// Result of one explicitly enabled paired determinism verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutomaticFindingDeterminismProbe {
    /// Both complete causal projections were identical.
    Stable,
    /// A replay exposed a property failure or timeout with higher priority.
    HigherPriorityFailure,
    /// A mismatch was localized from two complete executions.
    Diverged {
        /// Actual first causal mismatch reconstructed from the paired executions.
        divergence: Box<crucible::FailureClusterReportDivergence>,
        /// Coverage produced by the second private replay for diagnostics only.
        reproduced_coverage: crucible_campaign::CoverageProjection,
    },
    /// The pair could not complete within compatibility or physical-work bounds.
    Incomplete,
}

/// Last paired-probe disposition observed by an automatic finding runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutomaticFindingDeterminismProbeDisposition {
    /// The deployment did not request paired verification.
    NotRequested,
    /// A property or timeout finding took precedence.
    HigherPriorityFinding,
    /// A private replay observed a higher-priority source, suppressing divergence.
    HigherPriorityProbeFailure,
    /// Both causal projections matched.
    Stable,
    /// A complete paired mismatch originated a divergence finding.
    Diverged,
    /// Compatibility or remaining physical work prevented a complete pair.
    Incomplete,
}

impl<F, D> private::Sealed for QemuFreshExecutionRunner<F, D> where
    D: crate::qemu_campaign_driver::QemuFindingReplayDriver
{
}

impl<F, D> PrivateFindingReplayRunner for QemuFreshExecutionRunner<F, D>
where
    F: crate::QemuFreshAttemptLifecycleFactory,
    D: crate::qemu_campaign_driver::QemuFindingReplayDriver,
{
    fn probe_finding_candidate_determinism(
        &mut self,
        input: &CrucibleAttemptExecution,
        candidate: &ConfigurationArtifact,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingDeterminismProbe, AttemptWorkerFailure<Self::Error>> {
        if !context.has_remaining_execution_quanta() {
            return Ok(AutomaticFindingDeterminismProbe::Incomplete);
        }
        let first = match QemuFreshExecutionRunner::replay_finding_candidate_boundary(
            self, input, candidate, None, context,
        ) {
            Ok(first) => first,
            Err(failure) if probe_exhausted_physical_work(&failure) => {
                return Ok(AutomaticFindingDeterminismProbe::Incomplete);
            }
            Err(failure) => return Err(failure),
        };
        let crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(first) =
            first
        else {
            return Ok(AutomaticFindingDeterminismProbe::Incomplete);
        };
        if first.has_higher_priority_failure_source() {
            return Ok(AutomaticFindingDeterminismProbe::HigherPriorityFailure);
        }
        if !context.has_remaining_execution_quanta() {
            return Ok(AutomaticFindingDeterminismProbe::Incomplete);
        }

        let second = match QemuFreshExecutionRunner::replay_finding_candidate_boundary(
            self,
            input,
            candidate,
            Some(&first),
            context,
        ) {
            Ok(second) => second,
            Err(failure) if probe_exhausted_physical_work(&failure) => {
                return Ok(AutomaticFindingDeterminismProbe::Incomplete);
            }
            Err(failure) => return Err(failure),
        };
        let crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(second) =
            second
        else {
            return Ok(AutomaticFindingDeterminismProbe::Incomplete);
        };
        if second.has_higher_priority_failure_source() {
            return Ok(AutomaticFindingDeterminismProbe::HigherPriorityFailure);
        }

        let reproduced_coverage = second.paired_reproduced_coverage().cloned();
        let (_, _, _, triage) = second.into_parts();
        let (failures, _, _, _, paired_logs) = triage.into_parts();
        let Some((_, _)) = paired_logs else {
            return Ok(AutomaticFindingDeterminismProbe::Stable);
        };
        let Some(reproduced_coverage) = reproduced_coverage else {
            return Ok(AutomaticFindingDeterminismProbe::Incomplete);
        };
        let [FailureClusterReportFailure::Divergence(divergence)] = failures.as_slice() else {
            return Ok(AutomaticFindingDeterminismProbe::Incomplete);
        };
        Ok(AutomaticFindingDeterminismProbe::Diverged {
            divergence: Box::new(divergence.clone()),
            reproduced_coverage,
        })
    }

    fn is_incomplete_physical_work_failure(
        &self,
        failure: &AttemptWorkerFailure<Self::Error>,
    ) -> bool {
        probe_exhausted_physical_work(failure)
    }

    fn replay_finding_candidate_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        candidate: &ConfigurationArtifact,
        finding: &FindingReproductionArtifact,
        target_signature: &FindingSignature,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
        let first = QemuFreshExecutionRunner::replay_finding_candidate_boundary(
            self, input, candidate, None, context,
        )?;
        let outcome = if target_signature.kind() == FindingKind::Divergence {
            match first {
                crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(
                    evidence,
                ) => {
                    if evidence.has_higher_priority_failure_source() {
                        return finish_qemu_finding_replay(
                            *evidence,
                            candidate,
                            finding,
                            target_signature,
                        )
                        .map_err(|failure| *failure);
                    }
                    if !context.has_remaining_execution_quanta() {
                        return Err(AttemptWorkerFailure::Terminal(
                            crate::QemuFreshExecutionRunnerError::StartReplay(
                                crate::QemuFreshStartReplayError::QuantumLimit,
                            ),
                        ));
                    }
                    QemuFreshExecutionRunner::replay_finding_candidate_boundary(
                        self,
                        input,
                        candidate,
                        Some(&evidence),
                        context,
                    )?
                }
                incompatible => incompatible,
            }
        } else {
            first
        };
        match outcome {
            crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(
                evidence,
            ) => finish_qemu_finding_replay(*evidence, candidate, finding, target_signature)
                .map_err(|failure| *failure),
            crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
                reason,
            ) => Ok(AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                configuration: candidate.clone(),
                reason: match reason {
                    crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::PrefixDiverged => FindingReplayIncompatibility::PrefixDiverged,
                    crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::PrefixTerminated => FindingReplayIncompatibility::PrefixTerminated,
                    crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::SelectionMismatch => FindingReplayIncompatibility::SelectionMismatch,
                },
            }),
        }
    }
}

fn probe_exhausted_physical_work<F>(
    failure: &AttemptWorkerFailure<
        crate::QemuFreshExecutionRunnerError<F, crate::QemuFreshModeledDriverError>,
    >,
) -> bool {
    matches!(
        failure,
        AttemptWorkerFailure::Terminal(crate::QemuFreshExecutionRunnerError::StartReplay(
            crate::qemu_campaign_lifecycle::QemuFreshStartReplayError::QuantumLimit
                | crate::qemu_campaign_lifecycle::QemuFreshStartReplayError::ResourceRefusal(_)
        )) | AttemptWorkerFailure::Terminal(crate::QemuFreshExecutionRunnerError::Driver(
            crate::QemuFreshModeledDriverError::ResourceRefusal(_)
        ))
    )
}

fn finish_qemu_finding_replay<F>(
    evidence: crate::qemu_campaign_driver::QemuFindingCandidateBoundaryEvidence,
    _candidate: &ConfigurationArtifact,
    finding: &FindingReproductionArtifact,
    target_signature: &FindingSignature,
) -> Result<
    AutomaticFindingReplayOutcome,
    Box<
        AttemptWorkerFailure<
            crate::QemuFreshExecutionRunnerError<F, crate::QemuFreshModeledDriverError>,
        >,
    >,
> {
    let (replay, measurement_replay_evidence, _final_events, triage) = evidence.into_parts();
    let triage = bind_qemu_triage_evidence(
        finding,
        target_signature.kind(),
        target_signature.property(),
        triage,
    )
    .map_err(|error| {
        Box::new(AttemptWorkerFailure::Terminal(
            crate::QemuFreshExecutionRunnerError::Driver(
                crate::QemuFreshModeledDriverError::Triage(Box::new(error)),
            ),
        ))
    })?;
    match triage {
        Some(triage) => Ok(AutomaticFindingReplayOutcome::observed_with_triage(
            replay,
            measurement_replay_evidence,
            triage,
        )),
        None => Ok(AutomaticFindingReplayOutcome::observed(
            replay,
            measurement_replay_evidence,
        )),
    }
}

fn divergence_fingerprint(
    input: &CrucibleAttemptExecution,
    divergence: &crucible::FailureClusterReportDivergence,
) -> CampaignHash {
    divergence_fingerprint_for_scenario(input.lineage().scenario(), divergence)
}

/// Adds automatic finding reduction to one complete production execution runner.
///
/// `main` owns admitted fresh, resume, and hot-fork execution. `replay` is an
/// independent raw fresh runner used only for private reduction candidates.
pub struct AutomaticFindingExecutionRunner<M, R> {
    store: CampaignExecutorStore,
    exact_retention: Arc<dyn FindingExactRetentionSource>,
    main: M,
    replay: R,
    verify_determinism_findings: bool,
    last_determinism_probe: AutomaticFindingDeterminismProbeDisposition,
}

impl<M, R> AutomaticFindingExecutionRunner<M, R> {
    /// Wraps one main runner and a separate fresh candidate runner.
    #[must_use]
    pub(crate) fn new(
        store: CampaignExecutorStore,
        exact_retention: Arc<dyn FindingExactRetentionSource>,
        main: M,
        replay: R,
    ) -> Self {
        Self {
            store,
            exact_retention,
            main,
            replay,
            verify_determinism_findings: false,
            last_determinism_probe: AutomaticFindingDeterminismProbeDisposition::NotRequested,
        }
    }

    /// Enables a bounded two-replay determinism check after ordinary attempts.
    #[must_use]
    pub const fn with_determinism_finding_verification(mut self) -> Self {
        self.verify_determinism_findings = true;
        self
    }

    /// Returns the explicit outcome of the most recent paired probe decision.
    #[must_use]
    pub const fn last_determinism_probe(&self) -> AutomaticFindingDeterminismProbeDisposition {
        self.last_determinism_probe
    }

    /// Returns the admitted-attempt runner.
    #[must_use]
    pub const fn main(&self) -> &M {
        &self.main
    }

    /// Returns the private candidate runner.
    #[must_use]
    pub const fn replay(&self) -> &R {
        &self.replay
    }
}

/// Failure from admitted execution or automatic private finding replay.
#[derive(Debug, Error)]
pub enum AutomaticFindingExecutionRunnerError<M, R>
where
    M: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
    /// The admitted production runner failed.
    #[error("automatic finding main execution failed: {0}")]
    Main(#[source] M),
    /// A private fresh candidate runner failed.
    #[error("automatic finding private replay failed: {0}")]
    Replay(#[source] R),
    /// A campaign value needed for private replay was invalid.
    #[error("automatic finding campaign record failed: {0}")]
    Campaign(#[source] CampaignCodecError),
    /// A Crucible candidate or its typed replay closure was invalid.
    #[error("automatic finding artifact failed: {0}")]
    Artifact(#[source] CrucibleArtifactError),
    /// The deterministic minimization or final finding attachment failed.
    #[error("automatic finding preparation failed: {0}")]
    Preparation(#[source] AutomaticFindingPreparationError),
    /// A runner returned a result shape outside the private replay contract.
    #[error("automatic finding result is inconsistent: {reason}")]
    Inconsistent {
        /// Stable description of the violated result invariant.
        reason: &'static str,
    },
}

impl<M, R> CrucibleExecutionRunner for AutomaticFindingExecutionRunner<M, R>
where
    M: CrucibleExecutionRunner,
    M::Error: std::error::Error + 'static,
    R: PrivateFindingReplayRunner,
    R::Error: std::error::Error + 'static,
{
    type Error = AutomaticFindingExecutionRunnerError<M::Error, R::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.last_determinism_probe = AutomaticFindingDeterminismProbeDisposition::NotRequested;
        let main = self
            .main
            .execute(input, context)
            .map_err(map_main_failure)?;
        let (product, materialization) = main.into_parts();
        let AttemptExecutionProduct::PreparedSemantic(result) = product else {
            return Ok(CrucibleExecutionOutcome::new(product, materialization));
        };
        if result.finding().is_some() {
            return Ok(CrucibleExecutionOutcome::new(
                AttemptExecutionProduct::PreparedSemantic(result),
                materialization,
            ));
        }

        let result = *result;
        let preparation = (|| {
            let mut probe_originated_divergence = false;
            let signature = automatic_finding_signature(input, result.observation())
                .map_err(terminal_campaign_error)?;
            let signature = if let Some(signature) = signature {
                if self.verify_determinism_findings {
                    self.last_determinism_probe =
                        AutomaticFindingDeterminismProbeDisposition::HigherPriorityFinding;
                }
                Some(signature)
            } else if self.verify_determinism_findings {
                let probe = self
                    .replay
                    .probe_finding_candidate_determinism(
                        input,
                        result.observation().child(),
                        context,
                    )
                    .map_err(map_replay_failure)?;
                match probe {
                    AutomaticFindingDeterminismProbe::Stable => {
                        self.last_determinism_probe =
                            AutomaticFindingDeterminismProbeDisposition::Stable;
                        None
                    }
                    AutomaticFindingDeterminismProbe::HigherPriorityFailure => {
                        self.last_determinism_probe =
                            AutomaticFindingDeterminismProbeDisposition::HigherPriorityProbeFailure;
                        None
                    }
                    AutomaticFindingDeterminismProbe::Incomplete => {
                        self.last_determinism_probe =
                            AutomaticFindingDeterminismProbeDisposition::Incomplete;
                        None
                    }
                    AutomaticFindingDeterminismProbe::Diverged {
                        divergence,
                        reproduced_coverage: _,
                    } => {
                        self.last_determinism_probe =
                            AutomaticFindingDeterminismProbeDisposition::Diverged;
                        probe_originated_divergence = true;
                        let fingerprint = divergence_fingerprint(input, &divergence);
                        Some(
                            FindingSignature::new(
                                FindingKind::Divergence,
                                fingerprint,
                                None,
                                String::from(DIVERGENCE_FAILURE_CLASS),
                                Some(FindingTarget::Configuration(
                                    result
                                        .observation()
                                        .child()
                                        .id()
                                        .map_err(terminal_campaign_error)?,
                                )),
                                BTreeSet::from([result
                                    .observation()
                                    .coverage()
                                    .id()
                                    .map_err(terminal_campaign_error)?
                                    .content_id()]),
                            )
                            .map_err(terminal_campaign_error)?,
                        )
                    }
                }
            } else {
                None
            };
            let Some(signature) = signature else {
                return Ok(result);
            };
            let preserved_result = probe_originated_divergence.then(|| result.clone());
            let finding = original_finding(input, &self.store, result.observation(), &signature)
                .map_err(terminal_artifact_error)?;
            let seed = minimization_seed(input, &signature).map_err(terminal_campaign_error)?;
            let owned_choices = result.observation().clone();
            let (exact_pins, exact_retention) = prepare_finding_exact_retention(
                &self.store,
                self.exact_retention.as_ref(),
                input,
                context,
                result.observation(),
            )
            .map_err(terminal_campaign_error)?;

            let mut candidate_failure = None;
            let target_signature = signature.clone();
            let prepared = prepare_automatic_signature_preserving_finding_with_outcomes(
                result,
                AutomaticFindingPreparation {
                    signature,
                    finding: &finding,
                    exact_pins,
                    exact_retention,
                    seed,
                },
                |candidate| match replay_candidate(
                    &self.store,
                    &mut self.replay,
                    input,
                    candidate,
                    &owned_choices,
                    &target_signature,
                    context,
                ) {
                    Ok(replay) => Ok(replay),
                    Err(failure) => {
                        candidate_failure = Some(failure);
                        Err(private_replay_unwind_error())
                    }
                },
            );
            if let Some(failure) = candidate_failure {
                if let (Some(preserved_result), CandidateReplayFailure::Operational(operational)) =
                    (preserved_result.as_ref(), &failure)
                    && self.replay.is_incomplete_physical_work_failure(operational)
                {
                    self.last_determinism_probe =
                        AutomaticFindingDeterminismProbeDisposition::Incomplete;
                    return Ok(preserved_result.clone());
                }
                return Err(map_candidate_failure(failure));
            }
            match (prepared, preserved_result) {
                (Ok(prepared), _) => Ok(prepared),
                (
                    Err(AutomaticFindingPreparationError::Artifact(
                        CrucibleArtifactError::FindingRequiredReproductionMismatch { .. },
                    )),
                    Some(preserved_result),
                ) => {
                    self.last_determinism_probe =
                        AutomaticFindingDeterminismProbeDisposition::Incomplete;
                    Ok(preserved_result)
                }
                (Err(error), _) => Err(error),
            }
            .map_err(AutomaticFindingExecutionRunnerError::Preparation)
            .map_err(AttemptWorkerFailure::Terminal)
        })();
        let prepared = match preparation {
            Ok(prepared) => prepared,
            Err(failure) => {
                self.main.quarantine_pending_execution();
                return Err(failure);
            }
        };

        Ok(CrucibleExecutionOutcome::new(
            AttemptExecutionProduct::prepared_semantic(prepared),
            materialization,
        ))
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.main
            .reconcile_execution(disposition)
            .map_err(map_main_failure)
    }

    fn quarantine_pending_execution(&mut self) {
        self.main.quarantine_pending_execution();
        self.replay.quarantine_pending_execution();
    }
}

pub(crate) fn replay_candidate<R>(
    store: &CampaignExecutorStore,
    replay: &mut R,
    original_input: &CrucibleAttemptExecution,
    candidate: &crucible::FindingReproductionArtifact,
    owned_choices: &ObservationCandidate,
    target_signature: &FindingSignature,
    context: &AttemptExecutionContext,
) -> Result<AutomaticFindingReplayOutcome, CandidateReplayFailure<R::Error>>
where
    R: PrivateFindingReplayRunner,
    R::Error: std::error::Error + 'static,
{
    if candidate.artifact.scenario_form() != original_input.scenario() {
        return Err(CandidateReplayFailure::Artifact(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "automatic finding candidate scenario",
            },
        ));
    }
    let scenario = encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
        .map_err(CandidateReplayFailure::Artifact)?;
    if scenario.id().map_err(CandidateReplayFailure::Campaign)?
        != original_input.lineage().scenario_content()
    {
        return Err(CandidateReplayFailure::Artifact(
            CrucibleArtifactError::SemanticIdentityMismatch {
                artifact: "automatic finding replay scenario",
            },
        ));
    }
    let configuration =
        encode_crucible_configuration_artifact(&scenario, candidate.artifact.schedule())
            .map_err(CandidateReplayFailure::Artifact)?;
    let (decoded, signal_fault_replay, starting_selections) =
        decode_crucible_configuration_artifact_with_owned_candidate(
            candidate.artifact.scenario_form(),
            &scenario,
            &configuration,
            store,
            // Every unpublished choice referenced by a candidate came from the
            // admitted observation whose child the minimizer is reducing.
            owned_choices,
        )
        .map_err(CandidateReplayFailure::Artifact)?;
    let replay_input = original_input
        .for_finding_replay(
            candidate.artifact.scenario_form().clone(),
            configuration
                .id()
                .map_err(CandidateReplayFailure::Campaign)?,
            decoded,
            signal_fault_replay,
        )
        .map_err(CandidateReplayFailure::Campaign)?;
    let replay_context = context.for_origin_replay();
    let outcome = replay
        .replay_finding_candidate_boundary(
            &replay_input,
            &configuration,
            candidate,
            target_signature,
            &replay_context,
        )
        .map_err(CandidateReplayFailure::Operational)?;
    match outcome {
        AutomaticFindingReplayOutcome::Observed {
            evidence,
            measurement_replay_evidence,
            triage_evidence,
        } => {
            let evidence = (*evidence)
                .with_resolved_starting_selections(&starting_selections)
                .map_err(CandidateReplayFailure::Artifact)?;
            let signature = replay_finding_signature(
                &replay_input,
                evidence.configuration(),
                evidence.properties(),
                evidence.coverage(),
                target_signature,
                triage_evidence.as_deref(),
            )
            .map_err(CandidateReplayFailure::Campaign)?;
            let evidence = match signature {
                Some(signature) => evidence
                    .with_signature(signature)
                    .map_err(CandidateReplayFailure::Artifact)?,
                None => evidence,
            };
            match triage_evidence {
                Some(triage_evidence) => Ok(AutomaticFindingReplayOutcome::observed_with_triage(
                    evidence,
                    measurement_replay_evidence,
                    *triage_evidence,
                )),
                None => Ok(AutomaticFindingReplayOutcome::observed(
                    evidence,
                    measurement_replay_evidence,
                )),
            }
        }
        incompatible @ AutomaticFindingReplayOutcome::DeterministicallyIncompatible { .. } => {
            Ok(incompatible)
        }
    }
}

#[derive(Debug)]
pub(crate) enum CandidateReplayFailure<R> {
    Operational(AttemptWorkerFailure<R>),
    Campaign(CampaignCodecError),
    Artifact(CrucibleArtifactError),
}

fn private_replay_unwind_error() -> EngineError {
    EngineError::UnifiedOperationEvidenceMismatch {
        operation: "automatic finding private replay",
        reason: "private replay failed before minimization could continue",
    }
}

fn map_main_failure<M, R>(
    failure: AttemptWorkerFailure<M>,
) -> AttemptWorkerFailure<AutomaticFindingExecutionRunnerError<M, R>>
where
    M: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(AutomaticFindingExecutionRunnerError::Main(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(AutomaticFindingExecutionRunnerError::Main(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Main(error))
        }
    }
}

fn map_replay_failure<M, R>(
    failure: AttemptWorkerFailure<R>,
) -> AttemptWorkerFailure<AutomaticFindingExecutionRunnerError<M, R>>
where
    M: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(AutomaticFindingExecutionRunnerError::Replay(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(AutomaticFindingExecutionRunnerError::Replay(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Replay(error))
        }
    }
}

fn map_candidate_failure<M, R>(
    failure: CandidateReplayFailure<R>,
) -> AttemptWorkerFailure<AutomaticFindingExecutionRunnerError<M, R>>
where
    M: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
    match failure {
        CandidateReplayFailure::Operational(AttemptWorkerFailure::Retryable(error)) => {
            AttemptWorkerFailure::Retryable(AutomaticFindingExecutionRunnerError::Replay(error))
        }
        CandidateReplayFailure::Operational(AttemptWorkerFailure::Canceled(error)) => {
            AttemptWorkerFailure::Canceled(AutomaticFindingExecutionRunnerError::Replay(error))
        }
        CandidateReplayFailure::Operational(AttemptWorkerFailure::Terminal(error)) => {
            AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Replay(error))
        }
        CandidateReplayFailure::Campaign(error) => {
            AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Campaign(error))
        }
        CandidateReplayFailure::Artifact(error) => {
            AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Artifact(error))
        }
    }
}

fn terminal_campaign_error<M, R>(
    error: CampaignCodecError,
) -> AttemptWorkerFailure<AutomaticFindingExecutionRunnerError<M, R>>
where
    M: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
    AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Campaign(error))
}

fn terminal_artifact_error<M, R>(
    error: CrucibleArtifactError,
) -> AttemptWorkerFailure<AutomaticFindingExecutionRunnerError<M, R>>
where
    M: std::error::Error + 'static,
    R: std::error::Error + 'static,
{
    AttemptWorkerFailure::Terminal(AutomaticFindingExecutionRunnerError::Artifact(error))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture construction failures stop the focused runner test.
#[allow(clippy::expect_used)]
#[path = "automatic_finding_runner/tests.rs"]
mod tests;
