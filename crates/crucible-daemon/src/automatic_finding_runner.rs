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
mod tests;
