//! Automatic signature-preserving finding reduction around production runners.
//!
//! The outer runner executes the admitted attempt through its complete
//! production router first. Property failures and execution-quanta timeouts are
//! reduced directly. An explicitly enabled determinism policy privately runs
//! an ordinary candidate twice before originating a divergence finding.
//! Candidate execution shares cancellation and the physical quantum budget
//! with the admitted attempt, but it cannot recursively invoke this wrapper.

use std::{collections::BTreeSet, sync::Arc};

use crucible::{
    ContentHash, EngineError, FailureClusterReportFailure, FailureKind,
    FailureTriageReplayEvidence, FindingDiscoveryPath, FindingReproductionArtifact,
};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CampaignHash, ConfigurationArtifact,
    FindingExactPins, FindingKind, FindingSignature, FindingTarget, ObservationCandidate,
    ObservationStopSatisfaction, PropertyVerdict, PropertyVerdictSet, ScenarioDefId, StopOutcome,
};
use thiserror::Error;

use crate::crucible_artifact::decode_crucible_configuration_artifact_with_owned_candidate;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, AttemptWorkerFailure, AutomaticFindingPreparationError,
    AutomaticFindingReplayOutcome, CapturedAttemptCheckpoint, CrucibleArtifactError,
    CrucibleAttemptExecution, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    FindingReplayIncompatibility, PreparedFindingExactRetention, PreparedSemanticAttemptResult,
    QemuFreshExecutionRunner, encode_crucible_configuration_artifact,
    encode_crucible_scenario_artifact,
    prepare_automatic_signature_preserving_finding_with_outcomes,
};

const ASSERTION_FAILURE_CLASS: &str = "qemu.assertion-violation";
const EXECUTION_QUANTA_TIMEOUT_CLASS: &str = "qemu.execution-quanta-timeout";
const DIVERGENCE_FAILURE_CLASS: &str = "qemu.causal-log-divergence";

mod private {
    pub trait Sealed {}
}

/// Owns immutable deployment inputs and process-local evidence for private replay capture.
pub(crate) struct QemuFindingReplayCaptureProducer {
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
    evidence: crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidence,
    static_byte_limit: u64,
    shared_context: OneEntryCache<
        QemuFindingReplaySharedContextScope,
        crate::FindingProductionReplayCaptureOutcome<
            Arc<crate::FindingProductionReplaySharedContext>,
        >,
    >,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QemuFindingReplaySharedContextScope {
    scenario: ContentHash,
    max_lifecycle_objects: usize,
    max_lifecycle_bytes: u64,
    max_guest_asset_bytes: u64,
    static_byte_limit: u64,
}

impl QemuFindingReplaySharedContextScope {
    fn new(
        finding: &FindingReproductionArtifact,
        limits: crate::FindingProductionReplayCaptureLimits,
        static_byte_limit: u64,
    ) -> Self {
        Self {
            scenario: finding.artifact.scenario_def().id(),
            max_lifecycle_objects: limits.max_lifecycle_objects,
            max_lifecycle_bytes: limits.max_lifecycle_bytes,
            max_guest_asset_bytes: limits.max_guest_asset_bytes,
            static_byte_limit,
        }
    }
}

struct OneEntryCache<K, V> {
    entry: Option<(K, V)>,
}

impl<K, V> OneEntryCache<K, V> {
    const fn new() -> Self {
        Self { entry: None }
    }
}

impl<K: PartialEq, V: Clone> OneEntryCache<K, V> {
    fn get_or_try_replace<E>(
        &mut self,
        key: K,
        capture: impl FnOnce() -> Result<V, E>,
    ) -> Result<V, E> {
        if let Some((cached_key, value)) = &self.entry
            && cached_key == &key
        {
            return Ok(value.clone());
        }

        let value = capture()?;
        self.entry = Some((key, value.clone()));
        Ok(value)
    }
}

impl QemuFindingReplayCaptureProducer {
    /// Creates a capture owner before the production replay runner takes lifecycle authority.
    pub(crate) const fn new(
        lifecycle: crucible_api::ProductionVmLifecycleConfig,
        evidence: crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidence,
        static_byte_limit: u64,
    ) -> Self {
        Self {
            lifecycle,
            evidence,
            static_byte_limit,
            shared_context: OneEntryCache::new(),
        }
    }

    /// Captures immutable replay inputs once per scenario-and-limits scope.
    ///
    /// Candidate executions in the same scope share one retained context. A
    /// worker moving to another scenario replaces that single cached entry.
    ///
    /// # Errors
    ///
    /// Returns [`crate::FindingProductionReplayCaptureError`] when marker
    /// authentication, lifecycle projection, or bounded content capture fails.
    pub(crate) fn shared_context(
        &mut self,
        finding: &FindingReproductionArtifact,
    ) -> Result<
        crate::FindingProductionReplayCaptureOutcome<
            Arc<crate::FindingProductionReplaySharedContext>,
        >,
        crate::FindingProductionReplayCaptureError,
    > {
        let limits = crate::FindingProductionReplayCaptureLimits::for_finding(finding);
        let scope =
            QemuFindingReplaySharedContextScope::new(finding, limits, self.static_byte_limit);
        self.shared_context.get_or_try_replace(scope, || {
            crate::capture_finding_replay_shared_context(
                finding,
                &self.lifecycle,
                self.static_byte_limit,
                limits,
            )
        })
    }

    /// Reads the evidence completed by the most recent private lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`crucible::SchedulerError`] when the process-local evidence lock is poisoned.
    pub(crate) fn execution_snapshot(
        &self,
    ) -> Result<
        crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot,
        crucible::SchedulerError,
    > {
        self.evidence.snapshot()
    }
}

/// Fresh runner allowed to execute private finding-reduction candidates.
///
/// Implementations return only after all attempt-scoped process and resource
/// authority has been shut down or quarantined. The production implementation
/// is deliberately limited to [`QemuFreshExecutionRunner`] with
/// [`crate::QemuFreshModeledDriver`]. Hot-fork, exact-resume, and routing
/// runners can retain authority after success and therefore cannot satisfy
/// this contract.
pub trait PrivateFindingReplayRunner: CrucibleExecutionRunner + private::Sealed {
    /// Executes one explicitly requested paired determinism probe.
    ///
    /// Both executions consume the assignment's shared physical work budget.
    /// An incomplete probe is returned as evidence absence rather than a
    /// modeled timeout or divergence.
    ///
    /// # Errors
    ///
    /// Returns a worker failure when either probe execution or its required
    /// cleanup cannot complete within the admitted work budget.
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
        replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
        target_signature: &FindingSignature,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>>;

    /// Reconstructs one candidate and captures its canonical safe-stop checkpoint.
    ///
    /// Implementations without exact capture support return the semantic replay
    /// with no checkpoint. Automatic retention then records a localized
    /// incomplete disposition while preserving thin finding publication.
    ///
    /// # Errors
    ///
    /// Returns the same operational failures as
    /// [`Self::replay_finding_candidate_boundary`].
    fn replay_and_capture_finding_candidate_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        candidate: &ConfigurationArtifact,
        finding: &FindingReproductionArtifact,
        replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
        target_signature: &FindingSignature,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingExactCheckpointReplay, AttemptWorkerFailure<Self::Error>> {
        self.replay_finding_candidate_boundary(
            input,
            candidate,
            finding,
            replay_closure,
            target_signature,
            context,
        )
        .map(|outcome| AutomaticFindingExactCheckpointReplay::new(outcome, None))
    }

    /// Transfers an unusable checkpoint to the runner's outer cleanup owner.
    ///
    /// The default accepts compatibility captures that own no native catalog.
    /// Production runners must override this method and preserve the native
    /// retirement authority for their worker pool.
    fn retain_abandoned_exact_checkpoint(&mut self, checkpoint: CapturedAttemptCheckpoint) {
        let _quarantine = crate::executor_worker::NativeCheckpointUnwindGuard::new(&checkpoint);
    }
}

/// One authenticated semantic replay paired with its unpublished exact capture.
#[derive(Debug)]
pub struct AutomaticFindingExactCheckpointReplay {
    outcome: AutomaticFindingReplayOutcome,
    checkpoint: Option<crate::CapturedAttemptCheckpoint>,
    native_guard: crate::executor_worker::NativeCheckpointUnwindGuard,
}

impl AutomaticFindingExactCheckpointReplay {
    fn new(
        outcome: AutomaticFindingReplayOutcome,
        checkpoint: Option<crate::CapturedAttemptCheckpoint>,
    ) -> Self {
        let native_guard = checkpoint.as_ref().map_or_else(
            crate::executor_worker::NativeCheckpointUnwindGuard::new_empty,
            crate::executor_worker::NativeCheckpointUnwindGuard::new,
        );
        Self {
            outcome,
            checkpoint,
            native_guard,
        }
    }

    /// Consumes the replay into semantic evidence and linear capture ownership.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AutomaticFindingReplayOutcome,
        Option<crate::CapturedAttemptCheckpoint>,
    ) {
        let Self {
            outcome,
            checkpoint,
            mut native_guard,
        } = self;
        native_guard.disarm();
        (outcome, checkpoint)
    }
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
        replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
        target_signature: &FindingSignature,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
        let shared_context = self
            .finding_replay_capture_mut()
            .map(|producer| producer.shared_context(finding))
            .transpose()
            .map_err(crate::QemuFreshExecutionRunnerError::FindingReplayCapture)
            .map_err(AttemptWorkerFailure::Terminal)?;
        let first = QemuFreshExecutionRunner::replay_finding_candidate_boundary(
            self, input, candidate, None, context,
        )?;
        let first_snapshot = qemu_finding_replay_snapshot(self)
            .map_err(crate::QemuFreshExecutionRunnerError::FindingReplayEvidence)
            .map_err(AttemptWorkerFailure::Terminal)?;
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
                            None,
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
                    let second = QemuFreshExecutionRunner::replay_finding_candidate_boundary(
                        self,
                        input,
                        candidate,
                        Some(&evidence),
                        context,
                    )?;
                    let second_snapshot = qemu_finding_replay_snapshot(self)
                        .map_err(crate::QemuFreshExecutionRunnerError::FindingReplayEvidence)
                        .map_err(AttemptWorkerFailure::Terminal)?;
                    (second, Some((first_snapshot, second_snapshot)))
                }
                incompatible => (incompatible, None),
            }
        } else {
            (first, Some((first_snapshot, None)))
        };
        let (outcome, snapshots) = outcome;
        match outcome {
            crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(
                evidence,
            ) => {
                let production_replay = capture_qemu_finding_replay_material(
                    &evidence,
                    snapshots,
                    shared_context,
                    finding,
                    target_signature.kind(),
                    replay_closure,
                )
                .map_err(crate::QemuFreshExecutionRunnerError::FindingReplayCapture)
                .map_err(AttemptWorkerFailure::Terminal)?;
                finish_qemu_finding_replay(
                    *evidence,
                    candidate,
                    finding,
                    target_signature,
                    production_replay,
                )
                .map_err(|failure| *failure)
            }
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

    fn replay_and_capture_finding_candidate_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        candidate: &ConfigurationArtifact,
        finding: &FindingReproductionArtifact,
        _replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
        target_signature: &FindingSignature,
        context: &AttemptExecutionContext,
    ) -> Result<AutomaticFindingExactCheckpointReplay, AttemptWorkerFailure<Self::Error>> {
        let (raw, mut checkpoint) = if target_signature.kind() == FindingKind::Divergence {
            let first = QemuFreshExecutionRunner::replay_finding_candidate_boundary(
                self, input, candidate, None, context,
            )?;
            let first = match first {
                crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(
                    first,
                ) => first,
                crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(reason) => {
                    let reason = match reason {
                        crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::PrefixDiverged => FindingReplayIncompatibility::PrefixDiverged,
                        crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::PrefixTerminated => FindingReplayIncompatibility::PrefixTerminated,
                        crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::SelectionMismatch => FindingReplayIncompatibility::SelectionMismatch,
                    };
                    return Ok(AutomaticFindingExactCheckpointReplay::new(
                        AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                            configuration: candidate.clone(),
                            reason,
                        },
                        None,
                    ));
                }
            };
            if first.has_higher_priority_failure_source()
                || !context.has_remaining_execution_quanta()
            {
                let outcome =
                    finish_qemu_finding_replay(*first, candidate, finding, target_signature, None)
                        .map_err(|failure| *failure)?;
                return Ok(AutomaticFindingExactCheckpointReplay::new(outcome, None));
            }

            QemuFreshExecutionRunner::replay_and_capture_finding_candidate_boundary(
                self,
                input,
                candidate,
                Some(&first),
                context,
            )?
            .into_parts()
        } else {
            QemuFreshExecutionRunner::replay_and_capture_finding_candidate_boundary(
                self, input, candidate, None, context,
            )?
            .into_parts()
        };
        let mut native_guard = checkpoint.as_ref().map_or_else(
            crate::executor_worker::NativeCheckpointUnwindGuard::new_empty,
            crate::executor_worker::NativeCheckpointUnwindGuard::new,
        );

        let outcome = match raw {
            crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::Observed(
                evidence,
            ) => match finish_qemu_finding_replay(
                *evidence,
                candidate,
                finding,
                target_signature,
                None,
            ) {
                Ok(outcome) => outcome,
                Err(failure) => {
                    if let Some(checkpoint) = checkpoint.take() {
                        self.retain_abandoned_checkpoint(checkpoint, false);
                        native_guard.disarm();
                    }
                    return Err(*failure);
                }
            },
            crate::qemu_campaign_lifecycle::QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
                reason,
            ) => AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                configuration: candidate.clone(),
                reason: match reason {
                    crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::PrefixDiverged => FindingReplayIncompatibility::PrefixDiverged,
                    crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::PrefixTerminated => FindingReplayIncompatibility::PrefixTerminated,
                    crate::qemu_campaign_lifecycle::QemuFindingCandidateIncompatibility::SelectionMismatch => FindingReplayIncompatibility::SelectionMismatch,
                },
            },
        };
        let replay = AutomaticFindingExactCheckpointReplay::new(outcome, checkpoint);
        native_guard.disarm();
        Ok(replay)
    }

    fn retain_abandoned_exact_checkpoint(&mut self, checkpoint: CapturedAttemptCheckpoint) {
        self.retain_abandoned_checkpoint(checkpoint, false);
    }
}

type QemuFindingReplaySnapshots = Option<(
    Option<crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot>,
    Option<crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot>,
)>;

fn qemu_finding_replay_snapshot<F, D>(
    runner: &mut QemuFreshExecutionRunner<F, D>,
) -> Result<
    Option<crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot>,
    crucible::SchedulerError,
> {
    runner
        .finding_replay_capture_mut()
        .map(|producer| producer.execution_snapshot())
        .transpose()
}

fn capture_qemu_finding_replay_material(
    evidence: &crate::qemu_campaign_driver::QemuFindingCandidateBoundaryEvidence,
    snapshots: QemuFindingReplaySnapshots,
    shared_context: Option<
        crate::FindingProductionReplayCaptureOutcome<
            Arc<crate::FindingProductionReplaySharedContext>,
        >,
    >,
    finding: &FindingReproductionArtifact,
    finding_kind: FindingKind,
    replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
) -> Result<
    Option<crate::FindingProductionReplayMaterialOutcome>,
    crate::FindingProductionReplayCaptureError,
> {
    let Some(shared_context) = shared_context else {
        return Ok(None);
    };
    let shared_context = match shared_context {
        crate::FindingProductionReplayCaptureOutcome::Complete(shared_context) => shared_context,
        crate::FindingProductionReplayCaptureOutcome::Incomplete(reason) => {
            return Ok(Some(
                crate::FindingProductionReplayCaptureOutcome::Incomplete(reason),
            ));
        }
    };
    let Some((first, second)) = snapshots else {
        return Ok(None);
    };
    let Some(first) = first.as_ref() else {
        return Ok(None);
    };
    let limits = crate::FindingProductionReplayCaptureLimits::for_finding(finding);
    let mut sides = Vec::with_capacity(2);
    match finding_kind {
        FindingKind::PropertyViolation | FindingKind::Timeout => {
            let terminal = if finding_kind == FindingKind::Timeout {
                crate::FindingProductionReplayTerminalOutcome::Timeout
            } else {
                crate::FindingProductionReplayTerminalOutcome::Failed
            };
            let side = capture_qemu_finding_replay_side(
                terminal,
                evidence.causal_entries(),
                first,
                limits,
            )?;
            match side {
                crate::FindingProductionReplayCaptureOutcome::Complete(side) => sides.push(side),
                crate::FindingProductionReplayCaptureOutcome::Incomplete(reason) => {
                    return Ok(Some(
                        crate::FindingProductionReplayCaptureOutcome::Incomplete(reason),
                    ));
                }
            }
        }
        FindingKind::Divergence => {
            let (Some(second), Some((expected_log, reproduced_log))) =
                (second.as_ref(), evidence.paired_divergence_logs())
            else {
                return Ok(None);
            };
            for (log, snapshot) in [(expected_log, first), (reproduced_log, second)] {
                match capture_qemu_finding_replay_side(
                    crate::FindingProductionReplayTerminalOutcome::Passed,
                    log,
                    snapshot,
                    limits,
                )? {
                    crate::FindingProductionReplayCaptureOutcome::Complete(side) => {
                        sides.push(side);
                    }
                    crate::FindingProductionReplayCaptureOutcome::Incomplete(reason) => {
                        return Ok(Some(
                            crate::FindingProductionReplayCaptureOutcome::Incomplete(reason),
                        ));
                    }
                }
            }
        }
    }
    let material = crate::FindingProductionReplayCaptureMaterial::from_shared_context(
        finding,
        finding_kind,
        shared_context,
        sides,
        replay_closure,
        limits,
    )?;
    Ok(Some(
        crate::FindingProductionReplayCaptureOutcome::Complete(Arc::new(material)),
    ))
}

fn capture_qemu_finding_replay_side(
    outcome: crate::FindingProductionReplayTerminalOutcome,
    complete_log: &[crucible::SchedulerEventLogEntry],
    snapshot: &crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot,
    limits: crate::FindingProductionReplayCaptureLimits,
) -> Result<
    crate::FindingProductionReplayCaptureOutcome<crate::FindingProductionReplayExecutionSide>,
    crate::FindingProductionReplayCaptureError,
> {
    let suffix = snapshot.event_log_entries();
    let prefix_len = suffix.first().map_or(complete_log.len(), |entry| {
        usize::try_from(entry.sequence()).unwrap_or(usize::MAX)
    });
    if prefix_len > complete_log.len()
        || complete_log.len().saturating_sub(prefix_len) != suffix.len()
        || complete_log[prefix_len..] != *suffix
    {
        return Err(crate::FindingProductionReplayCaptureError::InvalidEventLog);
    }
    crate::FindingProductionReplayExecutionSide::from_snapshot(
        outcome,
        &complete_log[..prefix_len],
        snapshot,
        limits,
    )
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
    production_replay: Option<crate::FindingProductionReplayMaterialOutcome>,
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
    let outcome = match triage {
        Some(triage) => AutomaticFindingReplayOutcome::observed_with_triage(
            replay,
            measurement_replay_evidence,
            triage,
        ),
        None => AutomaticFindingReplayOutcome::observed(replay, measurement_replay_evidence),
    };
    Ok(match production_replay {
        Some(production_replay) => outcome.with_production_replay(production_replay),
        None => outcome,
    })
}

fn divergence_fingerprint(
    input: &CrucibleAttemptExecution,
    divergence: &crucible::FailureClusterReportDivergence,
) -> CampaignHash {
    divergence_fingerprint_for_scenario(input.lineage().scenario(), divergence)
}

/// Derives the normalized campaign fingerprint for one native divergence source.
pub(crate) fn divergence_fingerprint_for_scenario(
    scenario: ScenarioDefId,
    divergence: &crucible::FailureClusterReportDivergence,
) -> CampaignHash {
    let node = divergence
        .node
        .as_ref()
        .map_or("", |node| node.name.as_str());
    let kind = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-kind.v1",
        divergence.kind.as_bytes(),
    );
    let node = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-node.v1",
        node.as_bytes(),
    );
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(&scenario.as_hash().as_bytes());
    material.extend_from_slice(&kind.as_bytes());
    material.extend_from_slice(&node.as_bytes());
    CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-fingerprint.v1",
        &material,
    )
}

/// Adds automatic finding reduction to one complete production execution runner.
///
/// `main` owns admitted fresh, resume, and hot-fork execution. `replay` is an
/// independent raw fresh runner used only for private reduction candidates.
pub struct AutomaticFindingExecutionRunner<M, R> {
    store: CampaignExecutorStore,
    main: M,
    replay: R,
    verify_determinism_findings: bool,
    last_determinism_probe: AutomaticFindingDeterminismProbeDisposition,
}

impl<M, R> AutomaticFindingExecutionRunner<M, R> {
    /// Wraps one main runner and a separate fresh candidate runner.
    #[must_use]
    pub const fn new(store: CampaignExecutorStore, main: M, replay: R) -> Self {
        Self {
            store,
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
    /// A candidate's authenticated campaign choice closure was invalid.
    #[error("automatic finding replay closure failed: {0}")]
    ReplayClosure(#[source] crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosureError),
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

    fn take_abandoned_native_checkpoint(&mut self) -> Option<crate::NativeCheckpointCleanup> {
        let mut cleanup = None;
        if let Some(replay) = self.replay.take_abandoned_native_checkpoint() {
            crate::NativeCheckpointCleanup::retain(&mut cleanup, replay);
        }
        if let Some(main) = self.main.take_abandoned_native_checkpoint() {
            crate::NativeCheckpointCleanup::retain(&mut cleanup, main);
        }
        cleanup
    }

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
        let result = match product {
            AttemptExecutionProduct::PreparedSemantic(result) => result,
            AttemptExecutionProduct::ObservationWithFinding {
                observation,
                finding,
            } => match PreparedSemanticAttemptResult::new(*observation, Some(*finding)) {
                Ok(result) => Box::new(result),
                Err(error) => {
                    self.main.quarantine_pending_execution();
                    return Err(AttemptWorkerFailure::Terminal(
                        AutomaticFindingExecutionRunnerError::Preparation(
                            AutomaticFindingPreparationError::PreparedResult(error),
                        ),
                    ));
                }
            },
            product => return Ok(CrucibleExecutionOutcome::new(product, materialization)),
        };
        if let Some(finding) = result.finding() {
            if finding.bundle().exact_retention().is_some() {
                self.main.quarantine_pending_execution();
                return Err(AttemptWorkerFailure::Terminal(
                    AutomaticFindingExecutionRunnerError::Inconsistent {
                        reason: "producer finding already carries automatic exact-retention evidence",
                    },
                ));
            }
            let retention = prepare_existing_finding_exact_retention(context);
            let product = match retention {
                Some(retention) => AttemptExecutionProduct::prepared_semantic_with_exact_retention(
                    *result, retention,
                ),
                None => AttemptExecutionProduct::PreparedSemantic(result),
            };
            return Ok(CrucibleExecutionOutcome::new(product, materialization));
        }

        let result = *result;
        let mut finding_exact_retention = None;
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

            let mut candidate_failure = None;
            let target_signature = signature.clone();
            let prepared = prepare_automatic_signature_preserving_finding_with_outcomes(
                result,
                signature,
                &finding,
                FindingExactPins::default(),
                seed,
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
            let prepared = match (prepared, preserved_result) {
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
            .map_err(AttemptWorkerFailure::Terminal)?;
            if prepared.finding().is_some() {
                finding_exact_retention = prepare_finding_exact_retention(
                    &self.store,
                    &mut self.replay,
                    input,
                    &finding,
                    &owned_choices,
                    &target_signature,
                    context,
                );
            }
            Ok(prepared)
        })();
        let prepared = match preparation {
            Ok(prepared) => prepared,
            Err(failure) => {
                self.main.quarantine_pending_execution();
                return Err(failure);
            }
        };

        let product = match finding_exact_retention {
            Some(retention) => {
                AttemptExecutionProduct::prepared_semantic_with_exact_retention(prepared, retention)
            }
            None => AttemptExecutionProduct::prepared_semantic(prepared),
        };
        Ok(CrucibleExecutionOutcome::new(product, materialization))
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

fn prepare_existing_finding_exact_retention(
    context: &AttemptExecutionContext,
) -> Option<PreparedFindingExactRetention> {
    let policy = context.finding_retention_policy()?;
    let basis = policy.basis();
    match policy.retention() {
        None => Some(PreparedFindingExactRetention::Incomplete {
            basis,
            reason:
                crucible_campaign::FindingExactRetentionIncomplete::MissingAuthenticatedPolicyBasis,
            discarded_checkpoint: None,
        }),
        Some(retention) if retention.exact_findings() => {
            Some(PreparedFindingExactRetention::Incomplete {
                basis,
                reason:
                    crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
                discarded_checkpoint: None,
            })
        }
        Some(_) => Some(PreparedFindingExactRetention::Disabled { basis }),
    }
}

/// Selects the highest-priority authenticated failure represented by an observation.
///
/// Property failures take precedence over an execution-quanta timeout reached
/// at the same boundary.
///
/// # Errors
///
/// Returns [`CampaignCodecError`] when the selected signature or one of its
/// content-addressed dependencies is invalid.
pub(crate) fn automatic_finding_signature(
    input: &CrucibleAttemptExecution,
    candidate: &ObservationCandidate,
) -> Result<Option<FindingSignature>, CampaignCodecError> {
    if let Some(signature) = property_violation_signature(input, candidate)? {
        return Ok(Some(signature));
    }
    if !observation_exhausted_execution_quanta(candidate.observation().stop()) {
        return Ok(None);
    }

    let fingerprint = execution_quanta_timeout_fingerprint(input)?;
    let coverage = candidate.coverage().id()?.content_id();
    FindingSignature::new(
        FindingKind::Timeout,
        fingerprint,
        None,
        String::from(EXECUTION_QUANTA_TIMEOUT_CLASS),
        Some(FindingTarget::Configuration(candidate.child().id()?)),
        BTreeSet::from([coverage]),
    )
    .map(Some)
}

fn observation_exhausted_execution_quanta(stop: &StopOutcome) -> bool {
    match stop {
        StopOutcome::Reached(crucible_campaign::StopCondition::ExecutionQuanta(_)) => true,
        StopOutcome::ObservationReached(proof) => {
            proof.satisfaction() == ObservationStopSatisfaction::ExecutionQuanta
        }
        StopOutcome::Reached(_)
        | StopOutcome::TerminalSuccess
        | StopOutcome::ModeledTimeout(_)
        | StopOutcome::GuestCrash(_)
        | StopOutcome::AssertionFailure(_)
        | StopOutcome::ScenarioFailure(_) => false,
    }
}

fn execution_quanta_timeout_fingerprint(
    input: &CrucibleAttemptExecution,
) -> Result<CampaignHash, CampaignCodecError> {
    let failure_class_bytes = u64::try_from(EXECUTION_QUANTA_TIMEOUT_CLASS.len())
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "automatic-finding-failure-class-bytes",
        })?
        .to_be_bytes();
    let mut material = Vec::with_capacity(
        input.lineage().scenario().as_hash().as_bytes().len()
            + failure_class_bytes.len()
            + EXECUTION_QUANTA_TIMEOUT_CLASS.len(),
    );
    material.extend_from_slice(&input.lineage().scenario().as_hash().as_bytes());
    material.extend_from_slice(&failure_class_bytes);
    material.extend_from_slice(EXECUTION_QUANTA_TIMEOUT_CLASS.as_bytes());
    Ok(CampaignHash::derive(
        "crucible.daemon.qemu-execution-quanta-timeout-fingerprint.v1",
        &material,
    ))
}

fn property_violation_signature(
    input: &CrucibleAttemptExecution,
    candidate: &ObservationCandidate,
) -> Result<Option<FindingSignature>, CampaignCodecError> {
    let property = match candidate.observation().stop() {
        StopOutcome::AssertionFailure(property) => property.as_str(),
        StopOutcome::ObservationReached(proof)
            if proof.satisfaction()
                == ObservationStopSatisfaction::AssertionViolationTransition =>
        {
            proof
                .assertion_witness()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "assertion observation stop has no violation witness",
                })?
                .assertion()
        }
        _ => return Ok(None),
    };
    signature_for_failed_property(input, candidate.child(), candidate.properties(), property)
        .map(Some)
}

fn replay_finding_signature(
    input: &CrucibleAttemptExecution,
    configuration: &ConfigurationArtifact,
    properties: &PropertyVerdictSet,
    coverage: &crucible_campaign::CoverageProjection,
    target_signature: &FindingSignature,
    triage: Option<&FailureTriageReplayEvidence>,
) -> Result<Option<FindingSignature>, CampaignCodecError> {
    if target_signature.kind() == FindingKind::PropertyViolation {
        let Some(preferred_property) = target_signature.property() else {
            return Ok(None);
        };
        let property = replayed_failed_property(input, properties, preferred_property);
        return property
            .as_deref()
            .map(|property| {
                signature_for_failed_property(input, configuration, properties, property)
            })
            .transpose();
    }

    let expected_native_kind = match target_signature.kind() {
        FindingKind::PropertyViolation => unreachable!("property finding returned above"),
        FindingKind::Divergence => FailureKind::Divergence,
        FindingKind::Timeout => FailureKind::Timeout,
    };
    let Some(triage) = triage else {
        return Ok(None);
    };
    if triage.signature().failure_kind != expected_native_kind {
        return Ok(None);
    }
    let fingerprint = match (target_signature.kind(), triage.failure()) {
        (FindingKind::Divergence, FailureClusterReportFailure::Divergence(divergence)) => {
            divergence_fingerprint(input, divergence)
        }
        (FindingKind::Timeout, FailureClusterReportFailure::Timeout(_)) => {
            execution_quanta_timeout_fingerprint(input)?
        }
        _ => return Ok(None),
    };
    FindingSignature::new(
        target_signature.kind(),
        fingerprint,
        None,
        target_signature.failure_class().to_owned(),
        Some(FindingTarget::Configuration(configuration.id()?)),
        BTreeSet::from([coverage.id()?.content_id()]),
    )
    .map(Some)
}

fn replayed_failed_property(
    input: &CrucibleAttemptExecution,
    properties: &PropertyVerdictSet,
    preferred_property: &str,
) -> Option<String> {
    let preferred_failed = properties
        .properties()
        .get(preferred_property)
        .is_some_and(|evidence| evidence.verdict() == PropertyVerdict::Failed);
    if preferred_failed {
        return Some(preferred_property.to_owned());
    }

    input
        .scenario()
        .properties()
        .assertions()
        .iter()
        .map(|assertion| assertion.id.name.as_str())
        .find(|property| {
            properties
                .properties()
                .get(*property)
                .is_some_and(|evidence| evidence.verdict() == PropertyVerdict::Failed)
        })
        .map(ToOwned::to_owned)
}

/// Binds one selected actual QEMU failure source to its exact reproduction.
///
/// # Errors
///
/// Returns [`EngineError`] when multiple sources match the selected kind or
/// native replay evidence cannot be reconstructed from the retained inputs.
pub(crate) fn bind_qemu_triage_evidence(
    finding: &FindingReproductionArtifact,
    kind: FindingKind,
    property: Option<&str>,
    triage: crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs,
) -> Result<Option<FailureTriageReplayEvidence>, EngineError> {
    let (
        failures,
        causal_entries,
        coverage_fingerprint,
        recorded_event_frames,
        paired_divergence_logs,
    ) = triage.into_parts();
    let mut matching = failures
        .into_iter()
        .filter(|failure| failure_matches_finding(failure, kind, property));
    let Some(mut failure) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "automatic-finding-triage-evidence",
            reason: "multiple replay failure sources match the selected finding",
        });
    }
    match &mut failure {
        FailureClusterReportFailure::Property(record) => {
            record.violation.reproduction_artifact = finding.artifact.id();
        }
        FailureClusterReportFailure::Timeout(record) => {
            record.reproduction_artifact = finding.artifact.id();
        }
        FailureClusterReportFailure::Divergence(_) => {}
    }

    if let Some((expected, reproduced)) = paired_divergence_logs {
        return FailureTriageReplayEvidence::new_paired_divergence(
            finding.clone(),
            expected,
            reproduced,
            coverage_fingerprint,
            recorded_event_frames,
        )
        .map(Some);
    }

    FailureTriageReplayEvidence::new(
        finding.clone(),
        failure,
        causal_entries,
        coverage_fingerprint,
        recorded_event_frames,
    )
    .map(Some)
}

fn failure_matches_finding(
    failure: &FailureClusterReportFailure,
    kind: FindingKind,
    property: Option<&str>,
) -> bool {
    match (kind, failure) {
        (FindingKind::PropertyViolation, FailureClusterReportFailure::Property(record)) => {
            property.is_some_and(|property| record.violation.assertion.name == property)
        }
        (FindingKind::Divergence, FailureClusterReportFailure::Divergence(_))
        | (FindingKind::Timeout, FailureClusterReportFailure::Timeout(_)) => true,
        _ => false,
    }
}

fn signature_for_failed_property(
    input: &CrucibleAttemptExecution,
    configuration: &ConfigurationArtifact,
    properties: &PropertyVerdictSet,
    property: &str,
) -> Result<FindingSignature, CampaignCodecError> {
    if !input
        .scenario()
        .properties()
        .assertions()
        .iter()
        .any(|assertion| assertion.id.name == property)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "assertion finding does not name a declared scenario property",
        });
    }
    if properties
        .properties()
        .get(property)
        .is_none_or(|evidence| evidence.verdict() != PropertyVerdict::Failed)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "assertion finding does not name an actual failed property verdict",
        });
    }

    let fingerprint = assertion_failure_fingerprint(input, property)?;
    let properties = properties.id()?.content_id();
    FindingSignature::new(
        FindingKind::PropertyViolation,
        fingerprint,
        Some(property.to_owned()),
        String::from(ASSERTION_FAILURE_CLASS),
        Some(FindingTarget::Configuration(configuration.id()?)),
        BTreeSet::from([properties]),
    )
}

fn assertion_failure_fingerprint(
    input: &CrucibleAttemptExecution,
    property: &str,
) -> Result<CampaignHash, CampaignCodecError> {
    let property_bytes = u64::try_from(property.len())
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "automatic-finding-property-bytes",
        })?
        .to_be_bytes();
    let failure_class_bytes = u64::try_from(ASSERTION_FAILURE_CLASS.len())
        .map_err(|_| CampaignCodecError::LimitExceeded {
            limit: "automatic-finding-failure-class-bytes",
        })?
        .to_be_bytes();
    let mut material = Vec::with_capacity(
        32 + property_bytes.len()
            + property.len()
            + failure_class_bytes.len()
            + ASSERTION_FAILURE_CLASS.len(),
    );
    material.extend_from_slice(&input.lineage().scenario().as_hash().as_bytes());
    material.extend_from_slice(&property_bytes);
    material.extend_from_slice(property.as_bytes());
    material.extend_from_slice(&failure_class_bytes);
    material.extend_from_slice(ASSERTION_FAILURE_CLASS.as_bytes());
    Ok(CampaignHash::derive(
        "crucible.daemon.qemu-assertion-finding-fingerprint.v1",
        &material,
    ))
}

fn minimization_seed(
    input: &CrucibleAttemptExecution,
    signature: &FindingSignature,
) -> Result<crucible::Seed, CampaignCodecError> {
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(&input.attempt().id()?.content_id().digest());
    material.extend_from_slice(&signature.cluster_key().as_bytes());
    Ok(crucible::Seed::from_bytes(
        CampaignHash::derive(
            "crucible.daemon.automatic-finding-minimization-seed.v1",
            &material,
        )
        .as_bytes(),
    ))
}

fn original_finding(
    input: &CrucibleAttemptExecution,
    store: &CampaignExecutorStore,
    candidate: &ObservationCandidate,
    signature: &FindingSignature,
) -> Result<crucible::FindingReproductionArtifact, CrucibleArtifactError> {
    let scenario = encode_crucible_scenario_artifact(input.scenario())?;
    if scenario.id()? != input.lineage().scenario_content() {
        return Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "automatic finding scenario",
        });
    }
    let (configuration, _, _) = decode_crucible_configuration_artifact_with_owned_candidate(
        input.scenario(),
        &scenario,
        candidate.child(),
        store,
        candidate,
    )?;
    crucible::FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        ContentHash {
            bytes: signature.fingerprint().as_bytes(),
        },
        input.scenario(),
        &configuration,
    )
    .map_err(|source| CrucibleArtifactError::InvalidPayload {
        artifact: "automatic finding reproduction",
        source: Box::new(source),
    })
}

fn prepare_finding_exact_retention<R>(
    store: &CampaignExecutorStore,
    replay: &mut R,
    input: &CrucibleAttemptExecution,
    finding: &crucible::FindingReproductionArtifact,
    owned_choices: &ObservationCandidate,
    target_signature: &FindingSignature,
    context: &AttemptExecutionContext,
) -> Option<PreparedFindingExactRetention>
where
    R: PrivateFindingReplayRunner,
    R::Error: std::error::Error + 'static,
{
    let policy = context.finding_retention_policy()?;
    let basis = policy.basis();
    let Some(retention) = policy.retention() else {
        return Some(PreparedFindingExactRetention::Incomplete {
            basis,
            reason:
                crucible_campaign::FindingExactRetentionIncomplete::MissingAuthenticatedPolicyBasis,
            discarded_checkpoint: None,
        });
    };
    if !retention.exact_findings() {
        return Some(PreparedFindingExactRetention::Disabled { basis });
    }

    let replayed = match replay_candidate_with_exact_capture(
        store,
        replay,
        input,
        finding,
        owned_choices,
        target_signature,
        context,
    ) {
        Ok(replayed) => replayed,
        Err(_) => {
            return Some(PreparedFindingExactRetention::Incomplete {
                basis,
                reason:
                    crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
                discarded_checkpoint: None,
            });
        }
    };
    let (outcome, checkpoint) = replayed.into_parts();
    let Some(checkpoint) = checkpoint else {
        return Some(PreparedFindingExactRetention::Incomplete {
            basis,
            reason: crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
            discarded_checkpoint: None,
        });
    };
    let mut native_guard = crate::executor_worker::NativeCheckpointUnwindGuard::new(&checkpoint);

    let capture_matches = outcome.signature() == Some(target_signature)
        && checkpoint.scenario() == finding.artifact.scenario_def().id()
        && checkpoint.configuration() == finding.configuration;
    if !capture_matches {
        native_guard.disarm();
        return Some(PreparedFindingExactRetention::Incomplete {
            basis,
            reason:
                crucible_campaign::FindingExactRetentionIncomplete::CandidateAuthenticationFailed,
            discarded_checkpoint: Some(checkpoint),
        });
    }
    native_guard.disarm();
    Some(PreparedFindingExactRetention::Captured { basis, checkpoint })
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
    replay_candidate_inner(
        store,
        replay,
        original_input,
        candidate,
        owned_choices,
        target_signature,
        context,
        false,
    )
    .map(|replay| replay.into_parts().0)
}

fn replay_candidate_with_exact_capture<R>(
    store: &CampaignExecutorStore,
    replay: &mut R,
    original_input: &CrucibleAttemptExecution,
    candidate: &crucible::FindingReproductionArtifact,
    owned_choices: &ObservationCandidate,
    target_signature: &FindingSignature,
    context: &AttemptExecutionContext,
) -> Result<AutomaticFindingExactCheckpointReplay, CandidateReplayFailure<R::Error>>
where
    R: PrivateFindingReplayRunner,
    R::Error: std::error::Error + 'static,
{
    replay_candidate_inner(
        store,
        replay,
        original_input,
        candidate,
        owned_choices,
        target_signature,
        context,
        true,
    )
}

// crucible-lint: allow rust-allow -- the shared replay path keeps capture and ordinary authentication identical.
#[allow(clippy::too_many_arguments)]
fn replay_candidate_inner<R>(
    store: &CampaignExecutorStore,
    replay: &mut R,
    original_input: &CrucibleAttemptExecution,
    candidate: &crucible::FindingReproductionArtifact,
    owned_choices: &ObservationCandidate,
    target_signature: &FindingSignature,
    context: &AttemptExecutionContext,
    capture_exact_checkpoint: bool,
) -> Result<AutomaticFindingExactCheckpointReplay, CandidateReplayFailure<R::Error>>
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
    let replay_closure =
        crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_resolved_selections(
            candidate.artifact.scenario_form(),
            candidate.artifact.schedule(),
            &starting_selections,
        )
        .map_err(CandidateReplayFailure::ReplayClosure)?;
    let replay_context = context.for_origin_replay();
    let replayed = if capture_exact_checkpoint {
        replay.replay_and_capture_finding_candidate_boundary(
            &replay_input,
            &configuration,
            candidate,
            &replay_closure,
            target_signature,
            &replay_context,
        )
    } else {
        replay
            .replay_finding_candidate_boundary(
                &replay_input,
                &configuration,
                candidate,
                &replay_closure,
                target_signature,
                &replay_context,
            )
            .map(|outcome| AutomaticFindingExactCheckpointReplay::new(outcome, None))
    }
    .map_err(CandidateReplayFailure::Operational)?;
    let (outcome, mut checkpoint) = replayed.into_parts();
    let mut native_guard = checkpoint.as_ref().map_or_else(
        crate::executor_worker::NativeCheckpointUnwindGuard::new_empty,
        crate::executor_worker::NativeCheckpointUnwindGuard::new,
    );
    let transformed = (|| match outcome {
        AutomaticFindingReplayOutcome::Observed {
            evidence,
            measurement_replay_evidence,
            triage_evidence,
            production_replay,
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
            let outcome = match triage_evidence {
                Some(triage_evidence) => Ok(AutomaticFindingReplayOutcome::observed_with_triage(
                    evidence,
                    measurement_replay_evidence,
                    *triage_evidence,
                )),
                None => Ok(AutomaticFindingReplayOutcome::observed(
                    evidence,
                    measurement_replay_evidence,
                )),
            }?;
            let outcome = match production_replay {
                Some(production_replay) => outcome.with_production_replay(production_replay),
                None => outcome,
            };
            Ok(outcome)
        }
        incompatible @ AutomaticFindingReplayOutcome::DeterministicallyIncompatible { .. } => {
            Ok(incompatible)
        }
    })();
    match transformed {
        Ok(outcome) => {
            let replay = AutomaticFindingExactCheckpointReplay::new(outcome, checkpoint);
            native_guard.disarm();
            Ok(replay)
        }
        Err(failure) => {
            if let Some(checkpoint) = checkpoint.take() {
                replay.retain_abandoned_exact_checkpoint(checkpoint);
                native_guard.disarm();
            }
            Err(failure)
        }
    }
}

#[derive(Debug)]
pub(crate) enum CandidateReplayFailure<R> {
    Operational(AttemptWorkerFailure<R>),
    Campaign(CampaignCodecError),
    Artifact(CrucibleArtifactError),
    ReplayClosure(crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosureError),
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
        CandidateReplayFailure::ReplayClosure(error) => AttemptWorkerFailure::Terminal(
            AutomaticFindingExecutionRunnerError::ReplayClosure(error),
        ),
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
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    #[cfg(target_os = "linux")]
    use crucible::NodeId;
    use crucible::{
        Checkpoint, CheckpointKind, Configuration, Decision, DeliveryOrderDecision, EventLogTime,
        Icount, Schedule, SchedulerEventLogEntry, VirtualTime,
    };
    #[cfg(target_os = "linux")]
    use crucible_api::ProductionVmNodeGeneration;
    #[cfg(target_os = "linux")]
    use crucible_campaign::FindingReplaySignature;
    use crucible_campaign::{
        AssertionViolationWitness, AssignmentId, Attempt, AttemptAdmissionId,
        AttemptContinuationInput, AttemptResourceLimits, AttemptRetentionPolicyBasis, AttemptStart,
        BooleanDomain, BranchEdgeId, BranchPath, BranchPathSegment, BranchPointId, BudgetGrant,
        CampaignCommandId, CampaignControlAction, CampaignFact, CampaignLineage, CampaignMode,
        CampaignPolicy, CampaignPolicyId, CampaignRepository, CampaignSeed, CampaignSnapshotId,
        ChoiceClassContext, ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain, ChoiceSource,
        ChoiceValue, ConfigurationId, ControlRequest, CoverageProjection, DaemonEpoch,
        DiscoveryRequest, ExactCheckpointId, ExecutionId, ExecutionRetentionIntent, ExplorerPolicy,
        FairnessPolicy, FindingExactPins, FindingExactRetention, FindingExactRetentionDisposition,
        GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
        MeasurementSet, Observation, ObservationCondition, ObservationEventLogProof, ObservationId,
        ObservationQuantumBoundary, ObservationStopProof, ProgressiveWideningPolicy,
        PropertyEvidence, PropertyVerdictSet, PuctPolicy, RetentionPolicy, SavepointCaptureOutcome,
        SavepointCaptureRequest, SavepointCaptureResolution, SavepointContinuationSelection,
        ScenarioDefId, SelectableDeclaration, Selection, StopCondition, SubmitAttemptRequest,
    };
    use crucible_cas::content_store::{
        BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend,
        MemoryBlobBackend, MemoryRefBackend, MutableRefBackend, ObjectKind, PlacementReceipt,
        PutReceipt, RefStoreAdmin, StoreError,
    };
    #[cfg(target_os = "linux")]
    use crucible_qemu::{
        QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
        QemuPreparedRunDirectory, QemuReplayOracleValidation, QemuVmRealizationError,
        QemuVmSnapshot,
    };

    use super::*;
    use crate::crucible_execution::{CrucibleAttemptOrigin, CrucibleAttemptOrigins};
    use crate::{
        AttemptFindingRetentionPolicy, CapturedAttemptCheckpoint, CrucibleMaterializationTier,
        CrucibleResolvedAttemptStart, ExecutionCancellation, ExecutionCheckpointRequest,
        PreparedSemanticAttemptResult, StagedAttemptResult,
    };
    #[cfg(target_os = "linux")]
    use crate::{
        QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
        QemuAttemptResourceGuardFactory, QemuExecutionQuantumCounter,
        QemuHotForkWorldAuxiliaryResourceBroker, QemuHotForkWorldAuxiliaryResourceFactory,
        QemuHotForkWorldAuxiliaryResourceGuard, QemuHotForkWorldResourceOwner,
    };

    struct MainRunner {
        result: PreparedSemanticAttemptResult,
        calls: Arc<AtomicUsize>,
        quarantines: Arc<AtomicUsize>,
    }

    struct CleanupOnlyRunner {
        cleanup: Option<crate::NativeCheckpointCleanup>,
    }

    impl private::Sealed for CleanupOnlyRunner {}

    impl PrivateFindingReplayRunner for CleanupOnlyRunner {
        fn replay_finding_candidate_boundary(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _candidate: &ConfigurationArtifact,
            _finding: &FindingReproductionArtifact,
            _replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            _target_signature: &FindingSignature,
            _context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            unreachable!("cleanup-only runner does not execute")
        }
    }

    impl CrucibleExecutionRunner for CleanupOnlyRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            unreachable!("cleanup-only runner does not execute")
        }

        fn take_abandoned_native_checkpoint(&mut self) -> Option<crate::NativeCheckpointCleanup> {
            self.cleanup.take()
        }
    }

    struct BlockingDurableBackend {
        memory: MemoryBlobBackend,
        first_put: Mutex<Option<mpsc::Sender<()>>>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ImmutableBlobBackend for BlockingDurableBackend {
        fn name(&self) -> &str {
            self.memory.name()
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                durable: true,
                deferred_write: false,
                range_read: true,
                streaming_read: true,
                conditional_create: true,
                streaming_put: true,
                repair_inventory: false,
                planned_delete: false,
            }
        }

        fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
            self.memory.contains(id)
        }

        fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
            self.memory.read(id, range)
        }

        fn put_if_absent(
            &self,
            id: ContentId,
            source: &BlobHandle,
        ) -> Result<PutReceipt, StoreError> {
            if let Some(entered) = self.first_put.lock().expect("first put signal").take() {
                entered.send(()).expect("publication observer");
                let (released, changed) = self.release.as_ref();
                let mut released = released.lock().expect("publication release");
                while !*released {
                    released = changed.wait(released).expect("publication release wake");
                }
            }
            self.memory.put_if_absent(id, source)?;
            Ok(PutReceipt {
                id,
                placements: vec![PlacementReceipt {
                    backend: String::from(self.name()),
                    durable: true,
                    logical_length: source.logical_length(),
                }],
            })
        }
    }

    impl CrucibleExecutionRunner for MainRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            _input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            charge_quantum(context)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CrucibleExecutionOutcome::new(
                AttemptExecutionProduct::prepared_semantic(self.result.clone()),
                CrucibleMaterializationTier::ThinReplay,
            ))
        }

        fn quarantine_pending_execution(&mut self) {
            self.quarantines.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct ReplayRunner {
        calls: Arc<AtomicUsize>,
        observed: Arc<Mutex<Vec<(BranchPath, usize)>>>,
        property: String,
        expected_controls: Option<Vec<(u64, ObservationId)>>,
        controlled_calls: Option<Arc<AtomicUsize>>,
    }

    impl private::Sealed for ReplayRunner {}

    impl PrivateFindingReplayRunner for ReplayRunner {
        fn replay_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            _finding: &FindingReproductionArtifact,
            _replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            _target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            let outcome = CrucibleExecutionRunner::execute(self, input, context)?;
            let (product, _) = outcome.into_parts();
            let AttemptExecutionProduct::PreparedSemantic(result) = product else {
                return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                    "test replay did not produce a semantic result",
                )));
            };
            if result.observation().child() != candidate {
                return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                    "test replay did not reach the exact candidate",
                )));
            }
            let observation = result.observation();
            let evidence = crate::CrucibleFindingReplayEvidence::new(
                None,
                candidate.clone(),
                observation.measurements().clone(),
                observation.properties().clone(),
                observation.coverage().clone(),
                observation.discovered_choices().to_vec(),
                observation.produced_selections().to_vec(),
            )
            .map_err(|error| AttemptWorkerFailure::Terminal(io::Error::other(error)))?;
            Ok(AutomaticFindingReplayOutcome::observed(
                evidence,
                result.measurement_replay_evidence().to_vec(),
            ))
        }
    }

    impl CrucibleExecutionRunner for ReplayRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            charge_quantum(context)?;
            if let Some(expected) = &self.expected_controls {
                let actual = replay_continuation_controls(input)?;
                if &actual != expected {
                    return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                        "private replay lost or reordered descendant continuation controls",
                    )));
                }
                self.controlled_calls
                    .as_ref()
                    .ok_or_else(|| {
                        AttemptWorkerFailure::Terminal(io::Error::other(
                            "controlled replay has no verification counter",
                        ))
                    })?
                    .fetch_add(1, Ordering::SeqCst);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observed.lock().expect("replay observations").push((
                input.path().clone(),
                input.start().configuration().schedule.decisions().len(),
            ));
            let result = failed_result(input, &self.property);
            Ok(CrucibleExecutionOutcome::new(
                AttemptExecutionProduct::prepared_semantic(result),
                CrucibleMaterializationTier::ThinReplay,
            ))
        }
    }

    #[cfg(target_os = "linux")]
    struct ExactCaptureReplayRunner {
        inner: ReplayRunner,
        captures: Arc<Mutex<Vec<(ConfigurationId, usize)>>>,
    }

    #[cfg(target_os = "linux")]
    struct FailingTransformCaptureReplayRunner {
        inner: ReplayRunner,
        checkpoint: Option<CapturedAttemptCheckpoint>,
    }

    #[cfg(target_os = "linux")]
    impl private::Sealed for ExactCaptureReplayRunner {}

    #[cfg(target_os = "linux")]
    impl CrucibleExecutionRunner for ExactCaptureReplayRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            self.inner.execute(input, context)
        }
    }

    #[cfg(target_os = "linux")]
    impl PrivateFindingReplayRunner for ExactCaptureReplayRunner {
        fn replay_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            self.inner.replay_finding_candidate_boundary(
                input,
                candidate,
                finding,
                replay_closure,
                target_signature,
                context,
            )
        }

        fn replay_and_capture_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingExactCheckpointReplay, AttemptWorkerFailure<Self::Error>>
        {
            let outcome = self.inner.replay_finding_candidate_boundary(
                input,
                candidate,
                finding,
                replay_closure,
                target_signature,
                context,
            )?;
            self.captures
                .lock()
                .expect("exact capture observations")
                .push((
                    candidate.configuration(),
                    finding.artifact.schedule().decisions().len(),
                ));

            let configuration = Configuration {
                def: finding.artifact.scenario_def().clone(),
                schedule: finding.artifact.schedule().clone(),
            };
            let parent = Configuration::genesis(configuration.def.clone());
            let checkpoint = Checkpoint::from_recorded_configuration(
                &configuration,
                Some(&parent),
                VirtualTime::default(),
                BTreeMap::new(),
                CheckpointKind::Fat,
                BTreeMap::new(),
            )
            .expect("exact finding test checkpoint");
            let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
                .expect("exact finding test snapshot");
            let checkpoint = crate::CapturedExactCheckpoint::new(
                snapshot,
                BlobHandle::from_bytes(vec![0x5a; 512]),
            );

            Ok(AutomaticFindingExactCheckpointReplay::new(
                outcome,
                Some(checkpoint.into()),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    impl private::Sealed for FailingTransformCaptureReplayRunner {}

    #[cfg(target_os = "linux")]
    impl CrucibleExecutionRunner for FailingTransformCaptureReplayRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            self.inner.execute(input, context)
        }
    }

    #[cfg(target_os = "linux")]
    impl PrivateFindingReplayRunner for FailingTransformCaptureReplayRunner {
        fn replay_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            self.inner.replay_finding_candidate_boundary(
                input,
                candidate,
                finding,
                replay_closure,
                target_signature,
                context,
            )
        }

        fn replay_and_capture_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingExactCheckpointReplay, AttemptWorkerFailure<Self::Error>>
        {
            let outcome = self.inner.replay_finding_candidate_boundary(
                input,
                candidate,
                finding,
                replay_closure,
                target_signature,
                context,
            )?;
            let AutomaticFindingReplayOutcome::Observed {
                evidence,
                measurement_replay_evidence,
                ..
            } = outcome
            else {
                return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                    "test capture replay was unexpectedly incompatible",
                )));
            };
            let evidence = evidence
                .with_signature(target_signature.clone())
                .map_err(|error| AttemptWorkerFailure::Terminal(io::Error::other(error)))?;
            let checkpoint = self.checkpoint.take().ok_or_else(|| {
                AttemptWorkerFailure::Terminal(io::Error::other(
                    "test capture checkpoint was already consumed",
                ))
            })?;

            Ok(AutomaticFindingExactCheckpointReplay::new(
                AutomaticFindingReplayOutcome::observed(evidence, measurement_replay_evidence),
                Some(checkpoint),
            ))
        }
    }

    struct ClosureRecordingReplayRunner {
        inner: ReplayRunner,
        closures: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl private::Sealed for ClosureRecordingReplayRunner {}

    impl CrucibleExecutionRunner for ClosureRecordingReplayRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            self.inner.execute(input, context)
        }
    }

    impl PrivateFindingReplayRunner for ClosureRecordingReplayRunner {
        fn replay_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            let bytes = replay_closure
                .to_canonical_bytes()
                .map_err(|error| AttemptWorkerFailure::Terminal(io::Error::other(error)))?;
            self.closures
                .lock()
                .expect("record replay closure")
                .push(bytes);
            self.inner.replay_finding_candidate_boundary(
                input,
                candidate,
                finding,
                replay_closure,
                target_signature,
                context,
            )
        }
    }

    struct DivergenceReplayRunner {
        calls: Arc<AtomicUsize>,
        property: String,
        candidate_replays: usize,
        incompatible_replay_indices: BTreeSet<usize>,
        mismatched_replay_indices: BTreeSet<usize>,
    }

    fn divergence_replay_logs() -> (Vec<SchedulerEventLogEntry>, Vec<SchedulerEventLogEntry>) {
        divergence_replay_logs_for_node("paired-probe-node")
    }

    fn divergence_replay_logs_for_node(
        node: &str,
    ) -> (Vec<SchedulerEventLogEntry>, Vec<SchedulerEventLogEntry>) {
        let node = NodeId {
            name: String::from(node),
        };
        let at = EventLogTime::from_virtual_time(VirtualTime { ticks: 9 })
            .with_icount(node, Icount { retired: 37 });
        let expected = SchedulerEventLogEntry::execution_budget_exhausted_with_time(
            0,
            at.clone(),
            "execution-quanta",
        );
        let reproduced =
            SchedulerEventLogEntry::execution_budget_exhausted_with_time(0, at, "virtual-time");
        (vec![expected], vec![reproduced])
    }

    fn divergence_probe_coverage() -> CoverageProjection {
        CoverageProjection::new(
            BTreeSet::from([CampaignHash::derive(
                "crucible.test.probe-coverage.v1",
                b"private-replay-only",
            )]),
            BTreeSet::new(),
        )
        .expect("divergence probe coverage")
    }

    impl private::Sealed for DivergenceReplayRunner {}

    impl CrucibleExecutionRunner for DivergenceReplayRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            Err(AttemptWorkerFailure::Terminal(io::Error::other(
                "divergence fixture uses only private replay entry points",
            )))
        }
    }

    impl PrivateFindingReplayRunner for DivergenceReplayRunner {
        fn probe_finding_candidate_determinism(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingDeterminismProbe, AttemptWorkerFailure<Self::Error>> {
            charge_quantum(context)?;
            charge_quantum(context)?;
            self.calls.fetch_add(2, Ordering::SeqCst);
            let result = failed_result_for_schedule_with_stop(
                input,
                &self.property,
                &input.start().configuration().schedule,
                StopOutcome::TerminalSuccess,
            );
            if result.observation().child() != candidate {
                return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                    "divergence probe changed the candidate",
                )));
            }
            let (expected, reproduced) = divergence_replay_logs();
            let comparison = crucible::compare_event_log_determinism(&expected, &reproduced);
            let mismatch = comparison.mismatch().ok_or_else(|| {
                AttemptWorkerFailure::Terminal(io::Error::other(
                    "divergence probe fixture did not diverge",
                ))
            })?;
            let divergence = crucible::FailureClusterReportDivergence::from_bisected_first_diff(
                mismatch.first_location().ok_or_else(|| {
                    AttemptWorkerFailure::Terminal(io::Error::other(
                        "divergence probe fixture has no mismatch location",
                    ))
                })?,
                "expected fixture state",
                "reproduced fixture state",
            );
            Ok(AutomaticFindingDeterminismProbe::Diverged {
                divergence: Box::new(divergence),
                reproduced_coverage: divergence_probe_coverage(),
            })
        }

        fn is_incomplete_physical_work_failure(
            &self,
            failure: &AttemptWorkerFailure<Self::Error>,
        ) -> bool {
            matches!(
                failure,
                AttemptWorkerFailure::Terminal(error)
                    if error.to_string() == "test execution budget exhausted"
            )
        }

        fn replay_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            _replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            _target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            charge_quantum(context)?;
            charge_quantum(context)?;
            self.calls.fetch_add(2, Ordering::SeqCst);
            let replay_index = self.candidate_replays;
            self.candidate_replays += 1;
            if self.incompatible_replay_indices.contains(&replay_index) {
                return Ok(
                    AutomaticFindingReplayOutcome::DeterministicallyIncompatible {
                        configuration: candidate.clone(),
                        reason: FindingReplayIncompatibility::PrefixDiverged,
                    },
                );
            }
            let result = failed_result_for_schedule_with_stop(
                input,
                &self.property,
                &input.start().configuration().schedule,
                StopOutcome::TerminalSuccess,
            );
            let observation = result.observation();
            let evidence = crate::CrucibleFindingReplayEvidence::new(
                None,
                candidate.clone(),
                observation.measurements().clone(),
                observation.properties().clone(),
                observation.coverage().clone(),
                observation.discovered_choices().to_vec(),
                observation.produced_selections().to_vec(),
            )
            .map_err(|error| AttemptWorkerFailure::Terminal(io::Error::other(error)))?;
            let (expected, reproduced) = if self.mismatched_replay_indices.contains(&replay_index) {
                divergence_replay_logs_for_node("different-paired-probe-node")
            } else {
                divergence_replay_logs()
            };
            let coverage = crucible::coverage_fingerprint_from_event_log(&expected);
            let triage = FailureTriageReplayEvidence::new_paired_divergence(
                finding.clone(),
                expected,
                reproduced,
                coverage,
                Vec::new(),
            )
            .map_err(|error| AttemptWorkerFailure::Terminal(io::Error::other(error)))?;
            Ok(AutomaticFindingReplayOutcome::observed_with_triage(
                evidence,
                result.measurement_replay_evidence().to_vec(),
                triage,
            ))
        }
    }

    fn replay_continuation_controls(
        input: &CrucibleAttemptExecution,
    ) -> Result<Vec<(u64, ObservationId)>, AttemptWorkerFailure<io::Error>> {
        let (origins, terminal) = input.continuation_replay_basis().ok_or_else(|| {
            AttemptWorkerFailure::Terminal(io::Error::other(
                "private replay has no descendant continuation basis",
            ))
        })?;
        Ok(origins
            .iter()
            .filter_map(|origin| origin.attempt().continuation_input())
            .chain(terminal)
            .map(|control| {
                (
                    control.source_frontier_ticks(),
                    control.source_observation(),
                )
            })
            .collect())
    }

    #[cfg(target_os = "linux")]
    struct TestProcessGuard {
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        quanta: QemuExecutionQuantumCounter,
        process_contract: QemuChildProcessContract,
        active: Arc<AtomicUsize>,
        finishes: Arc<AtomicUsize>,
        quarantines: Arc<AtomicUsize>,
        terminal: bool,
    }

    #[cfg(target_os = "linux")]
    impl TestProcessGuard {
        fn new(
            resources: AttemptResourceLimits,
            cancellation: ExecutionCancellation,
            active: Arc<AtomicUsize>,
            finishes: Arc<AtomicUsize>,
            quarantines: Arc<AtomicUsize>,
        ) -> Self {
            let (cgroup_procs, _cgroup_peer) =
                UnixStream::pair().expect("test cgroup descriptor pair");
            let (cancellation_event, _cancellation_peer) =
                UnixStream::pair().expect("test cancellation descriptor pair");
            Self {
                resources,
                cancellation,
                quanta: QemuExecutionQuantumCounter::new(resources),
                process_contract: QemuChildProcessContract::from_unvalidated_test_descriptors(
                    cgroup_procs.into(),
                    cancellation_event.into(),
                    resources.maximum_vcpus(),
                    resources.maximum_resident_bytes(),
                    resources.maximum_disk_bytes(),
                ),
                active,
                finishes,
                quarantines,
                terminal: false,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl QemuAttemptOperationalBoundary for TestProcessGuard {
        fn resource_limits(&self) -> AttemptResourceLimits {
            self.resources
        }

        fn cancellation(&self) -> &ExecutionCancellation {
            &self.cancellation
        }

        fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
            if self.cancellation.is_canceled() {
                Err(QemuVmRealizationError::Canceled {
                    operation: "check retained finding fixture resources",
                })
            } else {
                Ok(())
            }
        }

        fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
            self.check_operational_boundary()?;
            self.quanta.charge()
        }
    }

    #[cfg(target_os = "linux")]
    impl QemuAttemptResourceGuard for TestProcessGuard {
        fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
            if !self.terminal {
                self.finishes.fetch_add(1, Ordering::SeqCst);
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.terminal = true;
            }
            Ok(())
        }

        fn quarantine(&mut self) {
            if !self.terminal {
                self.quarantines.fetch_add(1, Ordering::SeqCst);
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.terminal = true;
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl QemuAttemptProcessResourceGuard for TestProcessGuard {
        fn child_process_contract(
            &self,
        ) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
            Ok(&self.process_contract)
        }

        fn prepare_generation_run_directory(
            &mut self,
            _requirements: QemuLaunchResourceRequirements,
        ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
            Err(QemuVmRealizationError::Executor {
                operation: "prepare retained finding fixture run directory",
                message: String::from("the focused fixture never launches a process"),
            })
        }

        fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {
            self.quarantine();
        }
    }

    #[cfg(target_os = "linux")]
    struct RejectingFreshFactory {
        begins: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl QemuAttemptResourceGuardFactory for RejectingFreshFactory {
        type Guard = TestProcessGuard;

        fn begin(
            &mut self,
            _resources: AttemptResourceLimits,
            _cancellation: ExecutionCancellation,
        ) -> Result<Self::Guard, QemuVmRealizationError> {
            self.begins.fetch_add(1, Ordering::SeqCst);
            Err(QemuVmRealizationError::Executor {
                operation: "allocate fresh finding fixture resources",
                message: String::from("retained World resources must satisfy every replay"),
            })
        }
    }

    #[cfg(target_os = "linux")]
    struct RetainedWorldMainRunner {
        result: PreparedSemanticAttemptResult,
        owner: Option<QemuHotForkWorldResourceOwner<TestProcessGuard>>,
        binding: Option<
            crate::qemu_hot_fork_world_resource::QemuHotForkWorldAuxiliaryResourceBinding<
                TestProcessGuard,
            >,
        >,
        broker: QemuHotForkWorldAuxiliaryResourceBroker<TestProcessGuard>,
    }

    #[cfg(target_os = "linux")]
    impl CrucibleExecutionRunner for RetainedWorldMainRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            _input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            charge_quantum(context)?;
            let mut owner = self.owner.take().ok_or_else(|| {
                AttemptWorkerFailure::Terminal(io::Error::other(
                    "retained World main runner was executed twice",
                ))
            })?;
            let identity = ProductionVmNodeGeneration::new(
                NodeId {
                    name: String::from("finding-main"),
                },
                1,
            )
            .map_err(test_resource_failure)?;
            let mut target = owner
                .reserve_node(identity)
                .map_err(test_resource_failure)?;
            target
                .charge_execution_quantum()
                .map_err(test_resource_failure)?;
            target.finish().map_err(test_resource_failure)?;

            let mut lifecycle = owner.lifecycle_guard().map_err(test_resource_failure)?;
            lifecycle.finish().map_err(test_resource_failure)?;
            let binding = self.broker.bind(&owner).map_err(test_resource_failure)?;
            self.owner = Some(owner);
            self.binding = Some(binding);

            Ok(CrucibleExecutionOutcome::new(
                AttemptExecutionProduct::prepared_semantic(self.result.clone()),
                CrucibleMaterializationTier::HotFork,
            ))
        }

        fn reconcile_execution(
            &mut self,
            disposition: AttemptExecutionDisposition,
        ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
            if !matches!(disposition, AttemptExecutionDisposition::Observation(_)) {
                return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                    "retained finding fixture expected an observation disposition",
                )));
            }
            self.binding.take();
            let mut owner = self.owner.take().ok_or_else(|| {
                AttemptWorkerFailure::Terminal(io::Error::other(
                    "retained finding fixture has no World owner to reconcile",
                ))
            })?;
            owner.finish().map_err(test_resource_failure)?;
            Ok(AttemptExecutionReconciliationStep::Complete)
        }

        fn quarantine_pending_execution(&mut self) {
            self.binding.take();
            if let Some(owner) = &mut self.owner {
                owner.quarantine();
            }
        }
    }

    #[cfg(target_os = "linux")]
    struct RetainedReplayRunner {
        inner: ReplayRunner,
        resources: QemuHotForkWorldAuxiliaryResourceFactory<RejectingFreshFactory>,
        retained_calls: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl private::Sealed for RetainedReplayRunner {}

    #[cfg(target_os = "linux")]
    impl CrucibleExecutionRunner for RetainedReplayRunner {
        type Error = io::Error;

        fn execute(
            &mut self,
            input: &CrucibleAttemptExecution,
            context: &AttemptExecutionContext,
        ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
            self.inner.execute(input, context)
        }
    }

    #[cfg(target_os = "linux")]
    impl PrivateFindingReplayRunner for RetainedReplayRunner {
        fn replay_finding_candidate_boundary(
            &mut self,
            input: &CrucibleAttemptExecution,
            candidate: &ConfigurationArtifact,
            finding: &FindingReproductionArtifact,
            replay_closure: &crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
            target_signature: &FindingSignature,
            context: &AttemptExecutionContext,
        ) -> Result<AutomaticFindingReplayOutcome, AttemptWorkerFailure<Self::Error>> {
            let mut guard = self
                .resources
                .begin(context.resources(), context.cancellation().clone())
                .map_err(test_resource_failure)?;
            if !matches!(guard, QemuHotForkWorldAuxiliaryResourceGuard::Retained(_)) {
                return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                    "private finding replay allocated fresh physical capacity",
                )));
            }
            self.retained_calls.fetch_add(1, Ordering::SeqCst);
            guard
                .charge_execution_quantum()
                .map_err(test_resource_failure)?;
            let outcome = self.inner.replay_finding_candidate_boundary(
                input,
                candidate,
                finding,
                replay_closure,
                target_signature,
                context,
            );
            guard.finish().map_err(test_resource_failure)?;
            outcome
        }
    }

    #[cfg(target_os = "linux")]
    fn test_resource_failure(error: impl std::fmt::Display) -> AttemptWorkerFailure<io::Error> {
        AttemptWorkerFailure::Terminal(io::Error::other(error.to_string()))
    }

    fn charge_quantum(
        context: &AttemptExecutionContext,
    ) -> Result<(), AttemptWorkerFailure<io::Error>> {
        context.charge_execution_quantum().map_err(|_| {
            AttemptWorkerFailure::Terminal(io::Error::other("test execution budget exhausted"))
        })
    }

    fn failed_result(
        input: &CrucibleAttemptExecution,
        property: &str,
    ) -> PreparedSemanticAttemptResult {
        failed_result_for_schedule_with_stop(
            input,
            property,
            &input.start().configuration().schedule,
            StopOutcome::AssertionFailure(property.to_owned()),
        )
    }

    fn failed_result_for_schedule(
        input: &CrucibleAttemptExecution,
        property: &str,
        schedule: &Schedule,
    ) -> PreparedSemanticAttemptResult {
        failed_result_for_schedule_with_stop(
            input,
            property,
            schedule,
            StopOutcome::AssertionFailure(property.to_owned()),
        )
    }

    fn failed_result_with_stop(
        input: &CrucibleAttemptExecution,
        property: &str,
        stop: StopOutcome,
    ) -> PreparedSemanticAttemptResult {
        failed_result_for_schedule_with_stop(
            input,
            property,
            &input.start().configuration().schedule,
            stop,
        )
    }

    fn failed_result_for_schedule_with_stop(
        input: &CrucibleAttemptExecution,
        property: &str,
        schedule: &Schedule,
        stop: StopOutcome,
    ) -> PreparedSemanticAttemptResult {
        let scenario = encode_crucible_scenario_artifact(input.scenario()).expect("scenario");
        let child =
            encode_crucible_configuration_artifact(&scenario, schedule).expect("configuration");
        let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
        let properties = PropertyVerdictSet::new(BTreeMap::from([(
            property.to_owned(),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())
                .expect("failed property"),
        )]))
        .expect("properties");
        let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
        let observation = Observation::new(
            input.attempt().id().expect("attempt"),
            child.configuration(),
            child.id().expect("configuration ID"),
            input.path().id().expect("path ID"),
            stop,
            measurements.id().expect("measurement ID"),
            properties.id().expect("property ID"),
            coverage.id().expect("coverage ID"),
            BTreeSet::new(),
        )
        .expect("observation");
        let candidate = ObservationCandidate::new(
            child,
            measurements,
            properties,
            coverage,
            Vec::new(),
            observation,
        )
        .expect("candidate");
        PreparedSemanticAttemptResult::new(candidate, None).expect("prepared result")
    }

    fn failed_result_with_unpublished_branch_selection(
        input: &CrucibleAttemptExecution,
        property: &str,
    ) -> (PreparedSemanticAttemptResult, Selection) {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let declaration = SelectableDeclaration::new(
            "automatic-finding.unpublished-choice",
            ChoiceSource::Workload {
                producer: String::from("automatic-finding-test"),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("selectable declaration");
        let opportunity = crucible_campaign::ChoiceOpportunity::new(
            input.lineage().scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive(
                    "automatic-finding-test.choice-coordinate",
                    b"scheduler",
                ),
                producer: CampaignHash::derive(
                    "automatic-finding-test.choice-coordinate",
                    b"producer",
                ),
            },
            "unpublished-branch-selection",
            None,
        )
        .expect("choice opportunity");
        let parent = input.start().configuration();
        let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
        let selection = Selection::new_campaign_branch(
            &opportunity,
            &domain,
            ChoiceValue::Boolean(true),
            opportunity.branch_point_id(parent_id),
        )
        .expect("branch selection");
        let schedule = parent.schedule.clone().appended(Decision::Selection(
            crucible::SelectionDecision::new(&selection),
        ));

        let scenario = encode_crucible_scenario_artifact(input.scenario()).expect("scenario");
        let child =
            encode_crucible_configuration_artifact(&scenario, &schedule).expect("configuration");
        let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
        let properties = PropertyVerdictSet::new(BTreeMap::from([(
            property.to_owned(),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())
                .expect("failed property"),
        )]))
        .expect("properties");
        let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
        let discovery = ChoiceDiscovery::new(declaration, domain, opportunity)
            .expect("self-contained choice discovery");
        let observation = Observation::new(
            input.attempt().id().expect("attempt"),
            child.configuration(),
            child.id().expect("configuration ID"),
            input.path().id().expect("path ID"),
            StopOutcome::AssertionFailure(property.to_owned()),
            measurements.id().expect("measurement ID"),
            properties.id().expect("property ID"),
            coverage.id().expect("coverage ID"),
            BTreeSet::from([discovery.opportunity().id().expect("choice opportunity ID")]),
        )
        .expect("observation");
        let candidate = ObservationCandidate::new(
            child,
            measurements,
            properties,
            coverage,
            vec![discovery],
            observation,
        )
        .expect("candidate")
        .with_produced_selections(vec![selection.clone()])
        .expect("attach unpublished selection");

        (
            PreparedSemanticAttemptResult::new(candidate, None).expect("prepared result"),
            selection,
        )
    }

    fn cache_scope_finding(
        scenario: &crucible::ScenarioDefForm,
        schedule: Schedule,
        fingerprint: &[u8],
    ) -> FindingReproductionArtifact {
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule,
        };
        FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            ContentHash::from_bytes(fingerprint),
            scenario,
            &configuration,
        )
        .expect("cache-scope finding")
    }

    #[test]
    fn shared_context_cache_replaces_scenarios_and_reuses_same_scenario_arc() {
        let crash = crucible::crash_restart_scenario()
            .expect("crash-restart scenario")
            .scenario;
        let first = cache_scope_finding(&crash, Schedule::empty(), b"first-cache-scope");
        let happy = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let second = cache_scope_finding(&happy, Schedule::empty(), b"second-cache-scope");
        let minimized = cache_scope_finding(
            &happy,
            Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            })),
            b"second-cache-scope",
        );
        assert_ne!(second.artifact.id(), minimized.artifact.id());

        let scope = |finding: &FindingReproductionArtifact| {
            QemuFindingReplaySharedContextScope::new(
                finding,
                crate::FindingProductionReplayCaptureLimits::for_finding(finding),
                1024,
            )
        };
        let mut cache = OneEntryCache::new();
        let incomplete = cache
            .get_or_try_replace(scope(&first), || {
                Ok::<_, std::convert::Infallible>(crate::FindingProductionReplayCaptureOutcome::<
                    Arc<u8>,
                >::Incomplete(
                    crate::FindingProductionReplayIncomplete::MissingWorldArtifactStore,
                ))
            })
            .expect("cache incomplete scenario");
        assert!(matches!(
            incomplete,
            crate::FindingProductionReplayCaptureOutcome::Incomplete(
                crate::FindingProductionReplayIncomplete::MissingWorldArtifactStore
            )
        ));

        let complete = cache
            .get_or_try_replace(scope(&second), || {
                Ok::<_, std::convert::Infallible>(
                    crate::FindingProductionReplayCaptureOutcome::Complete(Arc::new(7_u8)),
                )
            })
            .expect("replace cache for second scenario");
        let reused = cache
            .get_or_try_replace(
                scope(&minimized),
                || -> Result<_, std::convert::Infallible> {
                    panic!("same-scenario candidate must reuse shared capture")
                },
            )
            .expect("reuse second-scenario context");
        let (
            crate::FindingProductionReplayCaptureOutcome::Complete(complete),
            crate::FindingProductionReplayCaptureOutcome::Complete(reused),
        ) = (complete, reused)
        else {
            panic!("second scenario must retain complete shared context")
        };
        assert!(Arc::ptr_eq(&complete, &reused));
    }

    fn input_fixture() -> (CrucibleAttemptExecution, String) {
        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let property = scenario
            .properties()
            .assertions()
            .first()
            .expect("declared assertion")
            .id
            .name
            .clone();
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 1 },
            order: Vec::new(),
        }));
        let configuration = Configuration {
            def: scenario.scenario_def(),
            schedule,
        };
        let scenario_artifact =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let configuration_artifact =
            encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
                .expect("configuration artifact");
        let scenario_id =
            ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.scenario_def().id().bytes));
        let lineage = CampaignLineage::new(
            scenario_id,
            scenario_artifact.id().expect("scenario ID"),
            configuration_artifact.configuration(),
            configuration_artifact.id().expect("configuration ID"),
            "automatic-finding-test",
            "qemu-test",
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )
        .expect("lineage");
        let path = BranchPath::new(vec![BranchPathSegment::new(
            BranchPointId::from_hash(CampaignHash::derive("test.branch", b"original")),
            BranchEdgeId::from_hash(CampaignHash::derive("test.edge", b"original")),
        )])
        .expect("nonempty path");
        let attempt = Attempt::new(
            AttemptStart::Discover {
                configuration: configuration_artifact.id().expect("configuration ID"),
            },
            path.id().expect("path ID"),
            StopCondition::Terminal,
        )
        .expect("attempt");
        let input = CrucibleAttemptExecution::from_test_parts(
            lineage,
            scenario,
            attempt,
            path,
            CrucibleResolvedAttemptStart::Discover { configuration },
        );
        (input, property)
    }

    fn executor_store() -> CampaignExecutorStore {
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "automatic-finding-runner-test",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        CampaignExecutorStore::new(repository)
    }

    fn exact_finding_retention_policy() -> AttemptFindingRetentionPolicy {
        let snapshot = CampaignSnapshotId::parse(&format!(
            "crucible.campaign.snapshot@{}",
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, 3, b"exact-finding-snapshot")
                .encode()
        ))
        .expect("campaign snapshot ID");
        let admission = AttemptAdmissionId::parse(&format!(
            "crucible.campaign.attempt-admission@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 3, b"exact-finding-admission").encode()
        ))
        .expect("attempt admission ID");
        let policy = CampaignPolicyId::parse(&format!(
            "crucible.campaign.policy@{}",
            ContentId::for_bytes(ObjectKind::Policy, 1, b"exact-finding-policy").encode()
        ))
        .expect("campaign policy ID");
        AttemptFindingRetentionPolicy::new(
            AttemptRetentionPolicyBasis::new(snapshot, admission, Some(policy)),
            Some(RetentionPolicy::new(true, 1, true, false)),
        )
    }

    fn campaign_command(label: &str) -> CampaignCommandId {
        CampaignCommandId::from_hash(CampaignHash::derive(
            "automatic-finding-runner-test.command",
            label.as_bytes(),
        ))
    }

    fn finding_campaign_policy(lineage: &CampaignLineage) -> CampaignPolicy {
        let widening = ProgressiveWideningPolicy::new(
            crucible_campaign::ExactRational::new(1, 1).expect("widening numerator"),
            crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
            1,
            100,
            1,
        )
        .expect("widening policy");
        CampaignPolicy::new(
            lineage.scenario(),
            CampaignSeed::from_bytes([0x51; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("campaign policy")
    }

    struct ControlledContinuationRequest<'a> {
        repository: &'a CampaignRepository,
        lineage: &'a CampaignLineage,
        campaign: &'a str,
        origin: &'a Attempt,
        source_observation: ObservationId,
        source_frontier_ticks: u64,
        stop: StopCondition,
        marker: u8,
    }

    fn select_controlled_continuation(request: ControlledContinuationRequest<'_>) -> Attempt {
        let head = request
            .repository
            .head(request.campaign)
            .expect("capture parent head");
        let capture_request = SavepointCaptureRequest::new(
            campaign_command(&format!("capture-{:02x}", request.marker)),
            head.snapshot_id(),
            request.origin.id().expect("capture origin ID"),
            request.lineage.genesis_content(),
            request.lineage.genesis(),
            request.origin.stop().clone(),
            format!("automatic finding source {:02x}", request.marker),
        )
        .expect("capture request");
        let capture = request
            .repository
            .request_savepoint_capture(request.campaign, &capture_request)
            .expect("request source savepoint");
        let resources = finding_fixture_resources();
        let assignment = SubmitAttemptRequest::new_savepoint_capture(
            AssignmentId::from_bytes([request.marker; 16]).expect("capture assignment"),
            DaemonEpoch::from_bytes([request.marker.wrapping_add(1); 16])
                .expect("capture daemon epoch"),
            request.lineage.id().expect("lineage ID"),
            capture.attempt,
            resources,
            ExecutionRetentionIntent::RetainAlways,
            capture.request,
            capture.configuration,
        )
        .expect("capture assignment request");
        let status_request = GetAttemptExecutionRequest::new(
            &assignment,
            ExecutionId::from_bytes([request.marker.wrapping_add(2); 16])
                .expect("capture execution"),
        )
        .expect("capture status request");
        let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            2,
            &[request.marker; 32],
        ))
        .expect("capture checkpoint");
        let status = GetAttemptExecutionResponse::new(
            &status_request,
            GetAttemptExecutionDisposition::Paused { checkpoint },
        )
        .expect("paused capture status");
        let ready = SavepointCaptureResolution {
            command: campaign_command(&format!("ready-{:02x}", request.marker)),
            expected_snapshot: capture.new_snapshot,
            request: capture.request,
            outcome: SavepointCaptureOutcome::Ready,
        };
        let resolved = request
            .repository
            .resolve_savepoint_capture(request.campaign, &ready, &assignment, &status)
            .expect("resolve source savepoint");

        let continuation = Attempt::new_with_continuation_input(
            AttemptStart::AfterAttempt {
                origin: request.origin.id().expect("continuation origin ID"),
                reached: request.lineage.genesis_content(),
            },
            request.origin.path(),
            request.stop,
            AttemptContinuationInput::scheduler_reseed(
                request.source_observation,
                request.source_frontier_ticks,
                [request.marker; 32],
            ),
        )
        .expect("controlled continuation");
        let selection = SavepointContinuationSelection {
            command: campaign_command(&format!("select-{:02x}", request.marker)),
            expected_snapshot: resolved.new_snapshot,
            request: capture.request,
            ready: CampaignFact::SavepointCaptureResolved(ready)
                .id()
                .expect("Ready fact ID"),
            continuation: continuation.id().expect("continuation ID"),
        };
        request
            .repository
            .select_savepoint_continuation(request.campaign, &selection, &continuation)
            .expect("select controlled continuation");
        continuation
    }

    fn finding_fixture_resources() -> AttemptResourceLimits {
        AttemptResourceLimits::new(1, 1024 * 1024, 1024 * 1024, 5)
            .expect("finding fixture resources")
    }

    struct DescendantInputFixture {
        repository: Arc<CampaignRepository>,
        store: CampaignExecutorStore,
        input: CrucibleAttemptExecution,
        property: String,
        schedule: Schedule,
        controls: Vec<(u64, ObservationId)>,
    }

    fn descendant_input_fixture() -> DescendantInputFixture {
        descendant_input_fixture_with_storage(
            Arc::new(MemoryBlobBackend::new(
                "automatic-finding-descendant-test",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        )
    }

    fn descendant_input_fixture_with_storage(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> DescendantInputFixture {
        const CAMPAIGN: &str = "automatic-finding-descendant";

        let scenario = crucible::happy_path_scenario()
            .expect("happy-path scenario")
            .scenario;
        let property = scenario
            .properties()
            .assertions()
            .first()
            .expect("declared assertion")
            .id
            .name
            .clone();
        let scenario_record =
            encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
        let genesis = Configuration::genesis(scenario.scenario_def());
        let genesis_record =
            encode_crucible_configuration_artifact(&scenario_record, &genesis.schedule)
                .expect("genesis artifact");
        let lineage = CampaignLineage::new(
            scenario_record.scenario(),
            scenario_record.id().expect("scenario ID"),
            genesis_record.configuration(),
            genesis_record.id().expect("genesis ID"),
            "automatic-finding-descendant-test",
            "qemu-test",
            BTreeMap::from([(String::from("control"), 1)]),
            scenario_record.payload_schema(),
            1,
        )
        .expect("campaign lineage");
        let repository = Arc::new(CampaignRepository::new(blobs, refs));
        repository
            .publish_scenario_artifact(
                scenario_record.scenario(),
                scenario_record.payload_schema(),
                scenario_record.payload().to_vec(),
            )
            .expect("publish scenario");
        repository
            .publish_configuration_artifact(
                genesis_record.scenario(),
                genesis_record.scenario_artifact(),
                genesis_record.configuration(),
                genesis_record.payload_schema(),
                genesis_record.payload().to_vec(),
            )
            .expect("publish genesis");
        let policy = finding_campaign_policy(&lineage);
        let created = repository
            .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
            .expect("create finding fixture campaign");
        let funded = repository
            .apply_control(
                CAMPAIGN,
                &ControlRequest {
                    command: campaign_command("fund"),
                    expected_snapshot: created.snapshot_id(),
                    action: CampaignControlAction::GrantBudget(
                        BudgetGrant::new(0, 3).expect("attempt budget"),
                    ),
                },
            )
            .expect("fund finding fixture campaign");
        let running = repository
            .apply_control(
                CAMPAIGN,
                &ControlRequest {
                    command: campaign_command("resume"),
                    expected_snapshot: funded.new_snapshot,
                    action: CampaignControlAction::Resume,
                },
            )
            .expect("run finding fixture campaign");
        let discovery = DiscoveryRequest::new(
            campaign_command("discover"),
            running.new_snapshot,
            lineage.genesis_content(),
            StopCondition::VirtualTimeNanoseconds(1),
        )
        .expect("discovery request");
        let first_admission = repository
            .submit_discovery_request(CAMPAIGN, &discovery)
            .expect("admit first source attempt");
        let first = repository
            .load_attempt(first_admission.attempt)
            .expect("load first source attempt");
        let store = CampaignExecutorStore::new(Arc::clone(&repository));
        let path = store
            .load_branch_path(first.path())
            .expect("load source path");
        let first_input = CrucibleAttemptExecution::from_test_parts(
            lineage.clone(),
            scenario.clone(),
            first.clone(),
            path.clone(),
            CrucibleResolvedAttemptStart::Discover {
                configuration: genesis.clone(),
            },
        );
        let first_source_result = failed_result_with_stop(
            &first_input,
            &property,
            StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(1)),
        );
        let first_source_observation = store
            .publish_observation_candidate(first_source_result.observation())
            .expect("publish first source observation");

        let second = select_controlled_continuation(ControlledContinuationRequest {
            repository: &repository,
            lineage: &lineage,
            campaign: CAMPAIGN,
            origin: &first,
            source_observation: first_source_observation,
            source_frontier_ticks: 1,
            stop: StopCondition::VirtualTimeNanoseconds(2),
            marker: 0x29,
        });
        let first_origin = CrucibleAttemptOrigin::new_with_source_stop(
            first.clone(),
            genesis.clone(),
            crucible::SignalFaultCampaignReplayPlan::empty(genesis.clone()),
            StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(1)),
        );
        let second_input = CrucibleAttemptExecution::from_test_parts(
            lineage.clone(),
            scenario.clone(),
            second.clone(),
            path.clone(),
            CrucibleResolvedAttemptStart::AfterAttempt {
                base: Box::new(CrucibleResolvedAttemptStart::Discover {
                    configuration: genesis.clone(),
                }),
                base_signal_fault_replay: crucible::SignalFaultCampaignReplayPlan::empty(
                    genesis.clone(),
                ),
                origins: Box::new(CrucibleAttemptOrigins::new(
                    first_origin.clone(),
                    Vec::new(),
                )),
            },
        );
        let second_source_result = failed_result_with_stop(
            &second_input,
            &property,
            StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2)),
        );
        let second_source_observation = store
            .publish_observation_candidate(second_source_result.observation())
            .expect("publish second source observation");

        let current = select_controlled_continuation(ControlledContinuationRequest {
            repository: &repository,
            lineage: &lineage,
            campaign: CAMPAIGN,
            origin: &second,
            source_observation: second_source_observation,
            source_frontier_ticks: 2,
            stop: StopCondition::Terminal,
            marker: 0x47,
        });
        let second_origin = CrucibleAttemptOrigin::new_with_source_stop(
            second,
            genesis.clone(),
            crucible::SignalFaultCampaignReplayPlan::empty(genesis.clone()),
            StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2)),
        );
        let input = CrucibleAttemptExecution::from_test_parts(
            lineage,
            scenario,
            current,
            path,
            CrucibleResolvedAttemptStart::AfterAttempt {
                base: Box::new(CrucibleResolvedAttemptStart::Discover {
                    configuration: genesis.clone(),
                }),
                base_signal_fault_replay: crucible::SignalFaultCampaignReplayPlan::empty(genesis),
                origins: Box::new(CrucibleAttemptOrigins::new(
                    first_origin,
                    vec![second_origin],
                )),
            },
        );
        let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 3 },
            order: Vec::new(),
        }));
        let controls = vec![
            (1, first_source_observation),
            (2, second_source_observation),
        ];

        DescendantInputFixture {
            repository,
            store,
            input,
            property,
            schedule,
            controls,
        }
    }

    #[test]
    fn authenticated_assertion_observation_stop_produces_a_finding_signature() {
        let (input, property) = input_fixture();
        let scenario = encode_crucible_scenario_artifact(input.scenario()).expect("scenario");
        let child = encode_crucible_configuration_artifact(
            &scenario,
            &input.start().configuration().schedule,
        )
        .expect("configuration");
        let boundary = ObservationQuantumBoundary::new(1, 0, 1, 0).expect("quantum boundary");
        let entry = CampaignHash::derive("test.observation-entry", property.as_bytes());
        let proof = ObservationStopProof::new(
            ObservationCondition::AssertionViolationTransition(property.clone()),
            ObservationStopSatisfaction::AssertionViolationTransition,
            child.configuration(),
            boundary,
            ObservationEventLogProof::new(
                CampaignHash::derive("test.event-prefix", b"empty"),
                Some(CampaignHash::derive("test.event-segment", b"assertion")),
                1,
                1,
                CampaignHash::derive("test.event-digest", b"assertion"),
            ),
            Some(
                AssertionViolationWitness::new(property.clone(), 0, entry)
                    .expect("assertion witness"),
            ),
        )
        .expect("observation stop proof");
        let result = failed_result_with_stop(
            &input,
            &property,
            StopOutcome::ObservationReached(Box::new(proof)),
        );

        let signature = property_violation_signature(&input, result.observation())
            .expect("valid observation signature")
            .expect("assertion finding signature");
        assert_eq!(signature.property(), Some(property.as_str()));
        assert_eq!(signature.failure_class(), ASSERTION_FAILURE_CLASS);
    }

    #[test]
    fn private_replay_carries_an_authenticated_unpublished_choice_closure() {
        let (input, property) = input_fixture();
        let (main_result, selection) =
            failed_result_with_unpublished_branch_selection(&input, &property);
        let store = executor_store();
        assert!(
            store
                .resolve_selection(selection.id().expect("selection ID"))
                .is_err(),
            "the regression requires a choice absent from repository storage"
        );
        let signature = property_violation_signature(&input, main_result.observation())
            .expect("property signature")
            .expect("failed property finding");
        let finding = original_finding(&input, &store, main_result.observation(), &signature)
            .expect("original finding with owned unpublished choice");
        let closures = Arc::new(Mutex::new(Vec::new()));
        let mut replay = ClosureRecordingReplayRunner {
            inner: ReplayRunner {
                calls: Arc::new(AtomicUsize::new(0)),
                observed: Arc::new(Mutex::new(Vec::new())),
                property,
                expected_controls: None,
                controlled_calls: None,
            },
            closures: Arc::clone(&closures),
        };
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 1).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        replay_candidate(
            &store,
            &mut replay,
            &input,
            &finding,
            main_result.observation(),
            &signature,
            &context,
        )
        .expect("private replay from owned choice closure");

        let recorded = closures.lock().expect("recorded closure");
        assert_eq!(recorded.len(), 1);
        let closure =
            crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
                &recorded[0],
            )
            .expect("canonical replay closure");
        closure
            .validate_for_schedule(
                finding.artifact.scenario_form(),
                finding.artifact.schedule(),
            )
            .expect("closure authenticates the candidate schedule");
        assert!(
            store
                .resolve_selection(selection.id().expect("selection ID"))
                .is_err(),
            "private replay must not depend on ambient choice publication"
        );
    }

    #[test]
    fn automatic_finding_replays_both_passes_under_the_original_budget_and_path() {
        let (input, property) = input_fixture();
        let main_calls = Arc::new(AtomicUsize::new(0));
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let main = MainRunner {
            result: failed_result(&input, &property),
            calls: Arc::clone(&main_calls),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = ReplayRunner {
            calls: Arc::clone(&replay_calls),
            observed: Arc::clone(&observed),
            property,
            expected_controls: None,
            controlled_calls: None,
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay);
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 5).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("automatic finding execution");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("automatic finding returned a nonsemantic result")
        };
        let finding = result.finding().expect("automatic finding");
        let minimized =
            crucible::ReproductionArtifact::from_compact_binary(finding.minimized().payload())
                .expect("minimized reproduction");
        assert!(minimized.schedule().decisions().is_empty());
        assert_eq!(main_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replay_calls.load(Ordering::SeqCst), 4);
        assert_eq!(quarantines.load(Ordering::SeqCst), 0);
        assert_eq!(context.consumed_execution_quanta(), 5);

        let observed = observed.lock().expect("replay observations");
        assert_eq!(
            observed
                .iter()
                .map(|(_, decisions)| *decisions)
                .collect::<Vec<_>>(),
            [1, 0, 1, 0]
        );
        assert!(observed.iter().all(|(path, _)| path == input.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn automatic_exact_retention_captures_the_original_after_minimization() {
        let (input, property) = input_fixture();
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let capture_observations = Arc::new(Mutex::new(Vec::new()));
        let main = MainRunner {
            result: failed_result(&input, &property),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let replay = ExactCaptureReplayRunner {
            inner: ReplayRunner {
                calls: Arc::clone(&replay_calls),
                observed: Arc::new(Mutex::new(Vec::new())),
                property,
                expected_controls: None,
                controlled_calls: None,
            },
            captures: Arc::clone(&capture_observations),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay);
        let finding_retention = exact_finding_retention_policy();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 6).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        )
        .with_finding_retention_policy(Some(finding_retention));

        let outcome = runner
            .execute(&input, &context)
            .expect("automatic finding exact capture");
        let AttemptExecutionProduct::PreparedSemanticWithExactRetention { result, retention } =
            outcome.product()
        else {
            panic!("automatic finding exact capture returned no retention handoff")
        };
        let finding = result.finding().expect("automatic finding");
        let original = finding.original_configuration().configuration();
        let minimized = finding.minimized_configuration().configuration();
        assert_ne!(original, minimized);

        let PreparedFindingExactRetention::Captured { basis, checkpoint } = retention.as_ref()
        else {
            panic!(
                "automatic finding exact capture was not retained: {retention:?}; captures={:?}; quanta={}",
                capture_observations
                    .lock()
                    .expect("exact capture observations"),
                context.consumed_execution_quanta(),
            )
        };
        assert_eq!(*basis, finding_retention.basis());
        assert_eq!(
            checkpoint.configuration().bytes,
            original.as_hash().as_bytes()
        );
        assert_eq!(
            capture_observations
                .lock()
                .expect("exact capture observations")
                .as_slice(),
            &[(original, 1)]
        );
        assert_eq!(replay_calls.load(Ordering::SeqCst), 5);
        assert_eq!(context.consumed_execution_quanta(), 6);
    }

    #[test]
    fn producer_supplied_finding_cannot_bypass_exact_retention_policy() {
        let (input, property) = input_fixture();
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let replay = || ReplayRunner {
            calls: Arc::clone(&replay_calls),
            observed: Arc::new(Mutex::new(Vec::new())),
            property: property.clone(),
            expected_controls: None,
            controlled_calls: None,
        };
        let main = MainRunner {
            result: failed_result(&input, &property),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let mut first = AutomaticFindingExecutionRunner::new(executor_store(), main, replay());
        let legacy_context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 5).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );
        let first_outcome = first
            .execute(&input, &legacy_context)
            .expect("prepare producer finding");
        let (first_product, _materialization) = first_outcome.into_parts();
        let AttemptExecutionProduct::PreparedSemantic(producer_result) = first_product else {
            panic!("producer fixture did not create a prepared finding")
        };

        replay_calls.store(0, Ordering::SeqCst);
        let main = MainRunner {
            result: *producer_result,
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay());
        let policy = exact_finding_retention_policy();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 1).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        )
        .with_finding_retention_policy(Some(policy));

        let outcome = runner
            .execute(&input, &context)
            .expect("policy-bound producer finding");
        let AttemptExecutionProduct::PreparedSemanticWithExactRetention { result, retention } =
            outcome.product()
        else {
            panic!("producer finding escaped without retention handoff")
        };
        assert!(result.finding().is_some());
        assert!(matches!(
            retention.as_ref(),
            PreparedFindingExactRetention::Incomplete {
                basis,
                reason:
                    crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
                discarded_checkpoint: None,
            } if *basis == policy.basis()
        ));
        assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn automatic_runner_drains_main_and_replay_native_cleanup_together() {
        let main_state = tempfile::tempdir().expect("main cleanup run state");
        let main_fixture = crucible_api::build_authenticated_production_checkpoint_codec_fixture(
            main_state.path(),
        )
        .expect("main cleanup fixture");
        let main_retirement = main_fixture.closure().native_retirement();
        let replay_state = tempfile::tempdir().expect("replay cleanup run state");
        let replay_fixture = crucible_api::build_authenticated_production_checkpoint_codec_fixture(
            replay_state.path(),
        )
        .expect("replay cleanup fixture");
        let replay_retirement = replay_fixture.closure().native_retirement();
        let mut runner = AutomaticFindingExecutionRunner::new(
            executor_store(),
            CleanupOnlyRunner {
                cleanup: Some(crate::NativeCheckpointCleanup::Retire(
                    main_retirement.clone(),
                )),
            },
            CleanupOnlyRunner {
                cleanup: Some(crate::NativeCheckpointCleanup::Retire(
                    replay_retirement.clone(),
                )),
            },
        );

        let Some(crate::NativeCheckpointCleanup::Batch(cleanups)) =
            runner.take_abandoned_native_checkpoint()
        else {
            panic!("both runner cleanups must be returned in one batch")
        };

        assert_eq!(cleanups.len(), 2);
        for cleanup in cleanups {
            let crate::NativeCheckpointCleanup::Retire(retirement) = cleanup else {
                panic!("safe cleanup fixture must remain retireable")
            };
            crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
                .expect("retire aggregated checkpoint catalog");
        }
        let repeated_main =
            crucible_api::retire_production_exact_checkpoint_catalog(&main_retirement)
                .expect("repeat main retirement");
        let repeated_replay =
            crucible_api::retire_production_exact_checkpoint_catalog(&replay_retirement)
                .expect("repeat replay retirement");
        assert!(!repeated_main.retired());
        assert!(!repeated_replay.retired());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_post_capture_transformation_quarantines_the_native_checkpoint() {
        let run_state = tempfile::tempdir().expect("production checkpoint run state");
        let fixture =
            crucible_api::build_authenticated_production_checkpoint_codec_fixture(run_state.path())
                .expect("authenticated production checkpoint fixture");
        let retirement = fixture.closure().native_retirement();
        let checkpoint = CapturedAttemptCheckpoint::from(fixture.closure().clone());
        let quarantine_before =
            crate::executor_worker::native_checkpoint_process_quarantine_len_for_test();

        let (input, property) = input_fixture();
        let main = MainRunner {
            result: failed_result(&input, &property),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let replay = FailingTransformCaptureReplayRunner {
            inner: ReplayRunner {
                calls: Arc::new(AtomicUsize::new(0)),
                observed: Arc::new(Mutex::new(Vec::new())),
                property,
                expected_controls: None,
                controlled_calls: None,
            },
            checkpoint: Some(checkpoint),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay);
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 6).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        )
        .with_finding_retention_policy(Some(exact_finding_retention_policy()));

        let outcome = runner
            .execute(&input, &context)
            .expect("automatic finding preserves thin evidence");
        let AttemptExecutionProduct::PreparedSemanticWithExactRetention { retention, .. } =
            outcome.product()
        else {
            panic!("automatic finding lost exact-retention diagnostic")
        };
        assert!(matches!(
            retention.as_ref(),
            PreparedFindingExactRetention::Incomplete {
                reason:
                    crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
                discarded_checkpoint: None,
                ..
            }
        ));

        let quarantine_after =
            crate::executor_worker::native_checkpoint_process_quarantine_len_for_test();
        assert!(quarantine_after > quarantine_before);

        let active = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
            .expect("test owner releases transformation quarantine");
        assert!(active.retired());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_only_finding_publication_excludes_destructive_gc_until_root_publication() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let blobs = Arc::new(BlockingDurableBackend {
            memory: MemoryBlobBackend::new("exact-only-publication-guard", u64::MAX),
            first_put: Mutex::new(None),
            release: Arc::clone(&release),
        });
        let refs = Arc::new(MemoryRefBackend::new());
        let fixture = descendant_input_fixture_with_storage(blobs.clone(), refs.clone());
        let DescendantInputFixture {
            repository,
            store,
            input,
            property,
            ..
        } = fixture;
        let main = MainRunner {
            result: failed_result(&input, &property),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let replay = ReplayRunner {
            calls: Arc::new(AtomicUsize::new(0)),
            observed: Arc::new(Mutex::new(Vec::new())),
            property,
            expected_controls: None,
            controlled_calls: None,
        };
        let mut runner = AutomaticFindingExecutionRunner::new(store.clone(), main, replay);
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 5).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );
        let outcome = runner
            .execute(&input, &context)
            .expect("automatic finding execution");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("automatic finding returned a nonsemantic result")
        };
        let mut result = result.as_ref().clone();

        let source_snapshot = repository
            .head("automatic-finding-descendant")
            .expect("source campaign head")
            .snapshot_id();
        let retention_basis = repository
            .attempt_retention_policy_basis_at(
                source_snapshot,
                input.attempt().id().expect("attempt ID"),
            )
            .expect("source retention basis");
        let exact_retention = FindingExactRetention::new(
            retention_basis.snapshot(),
            retention_basis.policy(),
            retention_basis.admission(),
            0,
            FindingExactRetentionDisposition::Incomplete(
                crucible_campaign::FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
            ),
        )
        .expect("finding exact retention");
        let finding = result
            .prepare_bound_finding_exact_retention(
                FindingExactPins::default(),
                exact_retention,
                None,
            )
            .expect("bind exact-only finding");
        result.commit_bound_production_replay_finding(finding);
        assert!(
            result
                .finding()
                .expect("bound finding")
                .bundle()
                .replay_captures()
                .is_none()
        );

        let epoch = DaemonEpoch::from_bytes([0xd1; 16]).expect("daemon epoch");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0xd2; 16]).expect("assignment"),
            epoch,
            input.lineage().id().expect("lineage ID"),
            input.attempt().id().expect("attempt ID"),
            AttemptResourceLimits::new(1, 1, 0, 1).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
        )
        .expect("submit request");
        let queued = crate::QueuedAttempt::from_test_parts(
            ExecutionId::from_bytes([0xd3; 16]).expect("execution ID"),
            request,
        );
        let staged = StagedAttemptResult::from_test_parts(queued, result);

        *blobs.first_put.lock().expect("arm first put") = Some(entered_tx);
        let publication = thread::spawn(move || {
            crate::publish_prepared_attempt_result(&store, Box::new(staged))
                .expect("publish exact-only finding")
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("finding publication reached immutable storage");

        let (inventory_tx, inventory_rx) = mpsc::channel();
        let inventory = thread::spawn(move || {
            let _fence = refs
                .acquire_ref_inventory_fence()
                .expect("acquire destructive GC inventory fence");
            inventory_tx.send(()).expect("inventory completion");
        });
        assert!(matches!(
            inventory_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        let (released, changed) = release.as_ref();
        *released.lock().expect("publication release") = true;
        changed.notify_all();
        publication.join().expect("finding publication thread");
        inventory_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("GC inventory proceeds after finding publication");
        inventory.join().expect("GC inventory thread");
    }

    #[test]
    fn default_runner_does_not_probe_an_ordinary_success() {
        let (input, property) = input_fixture();
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let main = MainRunner {
            result: failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let replay = ReplayRunner {
            calls: Arc::clone(&replay_calls),
            observed: Arc::new(Mutex::new(Vec::new())),
            property,
            expected_controls: None,
            controlled_calls: None,
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay);
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 2).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("default automatic finding execution");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("default automatic finding execution returned a nonsemantic result")
        };

        assert!(result.finding().is_none());
        assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            runner.last_determinism_probe(),
            AutomaticFindingDeterminismProbeDisposition::NotRequested
        );
        assert_eq!(context.consumed_execution_quanta(), 1);
    }

    #[test]
    fn paired_probe_derives_fingerprint_from_actual_divergence_kind_and_node() {
        let (input, property) = input_fixture();
        let main_calls = Arc::new(AtomicUsize::new(0));
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let main = MainRunner {
            result: failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess),
            calls: Arc::clone(&main_calls),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = DivergenceReplayRunner {
            calls: Arc::clone(&replay_calls),
            property,
            candidate_replays: 0,
            incompatible_replay_indices: BTreeSet::new(),
            mismatched_replay_indices: BTreeSet::new(),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay)
            .with_determinism_finding_verification();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("paired divergence finding execution");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("paired divergence finding returned a nonsemantic result")
        };
        let finding = result.finding().expect("paired divergence finding");
        let kind = CampaignHash::derive(
            "crucible.daemon.qemu-causal-divergence-kind.v1",
            b"execution_budget_exhausted",
        );
        let node = CampaignHash::derive(
            "crucible.daemon.qemu-causal-divergence-node.v1",
            b"paired-probe-node",
        );
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(&input.lineage().scenario().as_hash().as_bytes());
        material.extend_from_slice(&kind.as_bytes());
        material.extend_from_slice(&node.as_bytes());
        let expected_fingerprint = CampaignHash::derive(
            "crucible.daemon.qemu-causal-divergence-fingerprint.v1",
            &material,
        );

        assert_eq!(finding.bundle().signature().kind(), FindingKind::Divergence);
        assert_eq!(
            finding.bundle().signature().fingerprint(),
            expected_fingerprint
        );
        assert!(finding.bundle().triage_evidence().is_some());
        assert_eq!(
            runner.last_determinism_probe(),
            AutomaticFindingDeterminismProbeDisposition::Diverged
        );
        assert_eq!(main_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replay_calls.load(Ordering::SeqCst), 10);
        assert_eq!(context.consumed_execution_quanta(), 11);
        assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn paired_probe_binds_main_coverage_when_reproduced_coverage_differs() {
        let (input, property) = input_fixture();
        let main_result = failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
        let main_coverage = main_result
            .observation()
            .coverage()
            .id()
            .expect("main observation coverage ID")
            .content_id();
        let reproduced_coverage = divergence_probe_coverage()
            .id()
            .expect("reproduced coverage ID")
            .content_id();
        assert_ne!(main_coverage, reproduced_coverage);

        let main = MainRunner {
            result: main_result,
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::new(AtomicUsize::new(0)),
        };
        let replay = DivergenceReplayRunner {
            calls: Arc::new(AtomicUsize::new(0)),
            property,
            candidate_replays: 0,
            incompatible_replay_indices: BTreeSet::new(),
            mismatched_replay_indices: BTreeSet::new(),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay)
            .with_determinism_finding_verification();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("paired divergence finding execution");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("paired divergence finding returned a nonsemantic result")
        };
        let signature = result
            .finding()
            .expect("paired divergence finding")
            .bundle()
            .signature();

        assert_eq!(
            signature.causal_evidence(),
            &BTreeSet::from([main_coverage])
        );
        assert!(!signature.causal_evidence().contains(&reproduced_coverage));
    }

    #[test]
    fn divergence_reduction_budget_exhaustion_preserves_the_original_result() {
        let (input, property) = input_fixture();
        let original_result =
            failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let main = MainRunner {
            result: original_result.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = DivergenceReplayRunner {
            calls: Arc::clone(&replay_calls),
            property,
            candidate_replays: 0,
            incompatible_replay_indices: BTreeSet::new(),
            mismatched_replay_indices: BTreeSet::new(),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay)
            .with_determinism_finding_verification();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 3).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("incomplete divergence reduction preserves the attempt");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("incomplete divergence reduction returned a nonsemantic result")
        };

        assert_eq!(result.as_ref(), &original_result);
        assert_eq!(
            runner.last_determinism_probe(),
            AutomaticFindingDeterminismProbeDisposition::Incomplete
        );
        assert_eq!(replay_calls.load(Ordering::SeqCst), 2);
        assert_eq!(context.consumed_execution_quanta(), 3);
        assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn incompatible_reduction_trial_does_not_discard_a_later_reproduced_finding() {
        let (input, property) = input_fixture();
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let main = MainRunner {
            result: failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = DivergenceReplayRunner {
            calls: Arc::clone(&replay_calls),
            property,
            candidate_replays: 0,
            incompatible_replay_indices: BTreeSet::from([1, 3]),
            mismatched_replay_indices: BTreeSet::new(),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay)
            .with_determinism_finding_verification();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("later reproduced divergence remains a finding");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("reproduced divergence returned a nonsemantic result")
        };

        assert!(result.finding().is_some());
        assert_eq!(
            runner.last_determinism_probe(),
            AutomaticFindingDeterminismProbeDisposition::Diverged
        );
        assert!(replay_calls.load(Ordering::SeqCst) > 2);
        assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn probe_divergence_that_does_not_reproduce_preserves_the_successful_main_result() {
        let (input, property) = input_fixture();
        let original_result =
            failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let main = MainRunner {
            result: original_result.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = DivergenceReplayRunner {
            calls: Arc::clone(&replay_calls),
            property,
            candidate_replays: 0,
            incompatible_replay_indices: BTreeSet::from([0]),
            mismatched_replay_indices: BTreeSet::new(),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay)
            .with_determinism_finding_verification();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("nonreproducing optional divergence preserves the attempt");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("nonreproducing divergence returned a nonsemantic result")
        };

        assert_eq!(result.as_ref(), &original_result);
        assert!(result.finding().is_none());
        assert_eq!(
            runner.last_determinism_probe(),
            AutomaticFindingDeterminismProbeDisposition::Incomplete
        );
        assert!(replay_calls.load(Ordering::SeqCst) > 2);
        assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn probe_divergence_with_a_different_original_signature_preserves_the_main_result() {
        let (input, property) = input_fixture();
        let original_result =
            failed_result_with_stop(&input, &property, StopOutcome::TerminalSuccess);
        let quarantines = Arc::new(AtomicUsize::new(0));
        let main = MainRunner {
            result: original_result.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = DivergenceReplayRunner {
            calls: Arc::new(AtomicUsize::new(0)),
            property,
            candidate_replays: 0,
            incompatible_replay_indices: BTreeSet::new(),
            mismatched_replay_indices: BTreeSet::from([0]),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay)
            .with_determinism_finding_verification();
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 16).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("signature-mismatched optional divergence preserves the attempt");
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("signature-mismatched divergence returned a nonsemantic result")
        };

        assert_eq!(result.as_ref(), &original_result);
        assert!(result.finding().is_none());
        assert_eq!(
            runner.last_determinism_probe(),
            AutomaticFindingDeterminismProbeDisposition::Incomplete
        );
        assert_eq!(quarantines.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descendant_finding_replay_preserves_controls_signature_and_retained_world() {
        let fixture = descendant_input_fixture();
        let DescendantInputFixture {
            repository,
            store,
            input,
            property,
            schedule: original_schedule,
            controls: expected_controls,
        } = fixture;
        let resources = finding_fixture_resources();
        let cancellation = ExecutionCancellation::default();
        let physical_active = Arc::new(AtomicUsize::new(1));
        let physical_finishes = Arc::new(AtomicUsize::new(0));
        let physical_quarantines = Arc::new(AtomicUsize::new(0));
        let underlying = TestProcessGuard::new(
            resources,
            cancellation.clone(),
            Arc::clone(&physical_active),
            Arc::clone(&physical_finishes),
            Arc::clone(&physical_quarantines),
        );
        let owner = QemuHotForkWorldResourceOwner::new(underlying, 1)
            .expect("retained World resource owner");
        let broker = QemuHotForkWorldAuxiliaryResourceBroker::new();
        let fallback_begins = Arc::new(AtomicUsize::new(0));
        let retained_calls = Arc::new(AtomicUsize::new(0));
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let controlled_calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let main = RetainedWorldMainRunner {
            result: failed_result_for_schedule(&input, &property, &original_schedule),
            owner: Some(owner),
            binding: None,
            broker: broker.clone(),
        };
        let replay = RetainedReplayRunner {
            inner: ReplayRunner {
                calls: Arc::clone(&replay_calls),
                observed: Arc::clone(&observed),
                property,
                expected_controls: Some(expected_controls),
                controlled_calls: Some(Arc::clone(&controlled_calls)),
            },
            resources: QemuHotForkWorldAuxiliaryResourceFactory::new(
                broker,
                RejectingFreshFactory {
                    begins: Arc::clone(&fallback_begins),
                },
            ),
            retained_calls: Arc::clone(&retained_calls),
        };
        let mut runner = AutomaticFindingExecutionRunner::new(store.clone(), main, replay);
        let context = AttemptExecutionContext::new(
            resources,
            ExecutionRetentionIntent::RetainOnFailure,
            cancellation,
            ExecutionCheckpointRequest::default(),
        );

        let outcome = runner
            .execute(&input, &context)
            .expect("descendant automatic finding execution");
        assert_eq!(
            outcome.materialization(),
            CrucibleMaterializationTier::HotFork
        );
        let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
            panic!("descendant automatic finding returned a nonsemantic result")
        };
        let observation_candidate = result.observation().clone();
        let finding = result
            .finding()
            .expect("descendant automatic finding")
            .clone();
        let minimized =
            crucible::ReproductionArtifact::from_compact_binary(finding.minimized().payload())
                .expect("minimized descendant reproduction");
        assert!(minimized.schedule().decisions().is_empty());
        assert_eq!(replay_calls.load(Ordering::SeqCst), 4);
        assert_eq!(controlled_calls.load(Ordering::SeqCst), 4);
        assert_eq!(retained_calls.load(Ordering::SeqCst), 4);
        assert_eq!(fallback_begins.load(Ordering::SeqCst), 0);
        assert_eq!(context.consumed_execution_quanta(), 5);
        assert_eq!(physical_active.load(Ordering::SeqCst), 1);

        let observation = store
            .publish_observation_candidate(&observation_candidate)
            .expect("publish descendant finding observation");
        assert_eq!(physical_active.load(Ordering::SeqCst), 1);
        let candidate = finding
            .publish_for_executor(&store)
            .expect("publish descendant finding closure");
        assert_eq!(physical_active.load(Ordering::SeqCst), 1);
        let durable = repository
            .load_finding_candidate_bundle(candidate)
            .expect("reload durable descendant finding closure");
        assert_eq!(physical_active.load(Ordering::SeqCst), 1);
        assert_eq!(durable.observation(), observation);

        let original_target = FindingTarget::Configuration(
            finding
                .original_configuration()
                .id()
                .expect("original configuration ID"),
        );
        let minimized_target = FindingTarget::Configuration(
            finding
                .minimized_configuration()
                .id()
                .expect("minimized configuration ID"),
        );
        assert_ne!(original_target, minimized_target);
        assert_eq!(durable.signature().target(), Some(original_target));
        let signatures = durable.signature_minimization();
        assert_eq!(
            signatures.minimization_pass(),
            signatures.verification_pass()
        );
        let minimized_signature = signatures
            .minimization_pass()
            .iter()
            .flatten()
            .find(|signature| signature.target() == Some(minimized_target))
            .expect("minimization pass observed minimized descendant signature");
        let verified_signature = signatures
            .verification_pass()
            .iter()
            .flatten()
            .find(|signature| signature.target() == Some(minimized_target))
            .expect("verification pass observed minimized descendant signature");
        assert_eq!(minimized_signature, verified_signature);
        assert_ne!(durable.signature(), minimized_signature);
        assert_eq!(
            FindingReplaySignature::from_observed(durable.signature()),
            FindingReplaySignature::from_observed(minimized_signature),
        );

        assert_eq!(
            runner
                .reconcile_execution(AttemptExecutionDisposition::Observation(observation))
                .expect("reconcile retained descendant World"),
            AttemptExecutionReconciliationStep::Complete,
        );
        assert_eq!(physical_active.load(Ordering::SeqCst), 0);
        assert_eq!(physical_finishes.load(Ordering::SeqCst), 1);
        assert_eq!(physical_quarantines.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn post_execution_validation_failure_quarantines_main_authority() {
        let (input, _) = input_fixture();
        let main_calls = Arc::new(AtomicUsize::new(0));
        let replay_calls = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let main = MainRunner {
            result: failed_result(&input, "undeclared-property"),
            calls: Arc::clone(&main_calls),
            quarantines: Arc::clone(&quarantines),
        };
        let replay = ReplayRunner {
            calls: Arc::clone(&replay_calls),
            observed,
            property: String::from("undeclared-property"),
            expected_controls: None,
            controlled_calls: None,
        };
        let mut runner = AutomaticFindingExecutionRunner::new(executor_store(), main, replay);
        let context = AttemptExecutionContext::new(
            AttemptResourceLimits::new(1, 1, 0, 5).expect("attempt limits"),
            ExecutionRetentionIntent::Discard,
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );

        assert!(matches!(
            runner.execute(&input, &context),
            Err(AttemptWorkerFailure::Terminal(
                AutomaticFindingExecutionRunnerError::Campaign(_)
            ))
        ));
        assert_eq!(main_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
        assert_eq!(quarantines.load(Ordering::SeqCst), 1);
    }
}
