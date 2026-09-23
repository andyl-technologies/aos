//! Tests for automatic finding execution and reduction.

use std::collections::BTreeMap;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use crucible::NodeId;
use crucible::{
    Configuration, Decision, DeliveryOrderDecision, EventLogTime, FailureTriageReplayEvidence,
    Icount, Schedule, SchedulerEventLogEntry, VirtualTime,
};
#[cfg(target_os = "linux")]
use crucible_api::ProductionVmNodeGeneration;
#[cfg(target_os = "linux")]
use crucible_campaign::FindingReplaySignature;
use crucible_campaign::{
    AssertionViolationWitness, AssignmentId, Attempt, AttemptContinuationInput,
    AttemptResourceLimits, AttemptRetentionPolicyBasis, AttemptStart, BranchPath, BudgetGrant,
    CampaignCommandId, CampaignControlAction, CampaignFact, CampaignLineage, CampaignMode,
    CampaignPolicy, CampaignRepository, CampaignSeed, ControlRequest, CoverageProjection,
    DaemonEpoch, DiscoveryRequest, ExactCheckpointId, ExecutionId, ExecutionRetentionIntent,
    ExplorerPolicy, FairnessPolicy, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, MeasurementSet, Observation, ObservationCondition,
    ObservationEventLogProof, ObservationId, ObservationQuantumBoundary, ObservationStopProof,
    ObservationStopSatisfaction, ProgressiveWideningPolicy, PropertyEvidence, PropertyVerdict,
    PropertyVerdictSet, PuctPolicy, RetentionPolicy, SavepointCaptureOutcome,
    SavepointCaptureRequest, SavepointCaptureResolution, SavepointContinuationSelection,
    ScenarioDefId, StopCondition, StopOutcome, SubmitAttemptRequest,
};
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory, QemuVmRealizationError,
};

use super::*;
use crate::crucible_execution::{CrucibleAttemptOrigin, CrucibleAttemptOrigins};
#[cfg(target_os = "linux")]
use crate::qemu_hot_fork_world_resource::QemuHotForkWorldAuxiliaryResourceGuard;
use crate::{
    CrucibleMaterializationTier, CrucibleResolvedAttemptStart, ExecutionCancellation,
    ExecutionCheckpointRequest, PreparedSemanticAttemptResult,
};

fn replay_capture_limits() -> crate::FindingProductionReplayCaptureLimits {
    crate::FindingProductionReplayCaptureLimits {
        max_events_per_side: 16,
        max_event_bytes_per_side: 16 * 1024,
        max_lifecycle_objects: 0,
        max_lifecycle_bytes: 0,
        max_guest_asset_bytes: 0,
        max_encoded_bytes: 16 * 1024,
    }
}

#[test]
fn policy_timeout_capture_authenticates_host_marker_after_native_qemu_log() {
    use crucible::{FailureTimeoutBudgetKind, FailureTimeoutRecord};
    use crucible_campaign::{BoundedStopProof, PolicyTimeoutKind};

    let frontier = VirtualTime { ticks: 2_000_000 };
    let native =
        SchedulerEventLogEntry::execution_budget_exhausted(0, frontier, "execution-quanta");
    let marker = SchedulerEventLogEntry::execution_budget_exhausted(1, frontier, "virtual-time");
    let snapshot = crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot::for_replay_capture_test(
        1,
        frontier,
        vec![native.clone()],
    );
    let record = FailureTimeoutRecord::new(
        FailureTimeoutBudgetKind::VirtualTime,
        Some(frontier.ticks),
        1,
        frontier,
        None,
        None,
        ContentHash::default(),
    );
    let policy = (
        StopCondition::Bounded {
            primary: Box::new(StopCondition::NextChoice),
            virtual_time_nanoseconds: Some(frontier.ticks),
            execution_quanta: None,
        },
        PolicyTimeoutKind::VirtualTime,
        BoundedStopProof::new(frontier.ticks, 1),
    );
    let timeout = crate::FindingProductionReplayTerminalOutcome::Timeout;
    let complete_log = [native.clone(), marker.clone()];
    let mut forged_material = serde_json::to_value(&marker).expect("encode marker fixture");
    forged_material["content_hash"] =
        serde_json::to_value(ContentHash::default()).expect("encode mismatched hash");
    let forged_hash: SchedulerEventLogEntry =
        serde_json::from_value(forged_material).expect("decode forged marker fixture");
    assert!(!forged_hash.has_valid_content_hash());

    let captured = capture_qemu_finding_replay_side(
        timeout,
        &complete_log,
        &snapshot,
        Some(&record),
        Some(&policy),
        replay_capture_limits(),
    )
    .expect("authenticated timeout capture");
    assert!(matches!(
        captured,
        crate::FindingProductionReplayCaptureOutcome::Complete(side)
            if side.event_log() == complete_log
    ));

    for forged in [
        SchedulerEventLogEntry::execution_budget_exhausted(1, frontier, "execution-quanta"),
        SchedulerEventLogEntry::execution_budget_exhausted(
            1,
            VirtualTime { ticks: 1 },
            "virtual-time",
        ),
        SchedulerEventLogEntry::execution_budget_exhausted(2, frontier, "virtual-time"),
        forged_hash,
    ] {
        assert!(matches!(
            capture_qemu_finding_replay_side(
                timeout,
                &[native.clone(), forged],
                &snapshot,
                Some(&record),
                Some(&policy),
                replay_capture_limits(),
            ),
            Err(crate::FindingProductionReplayCaptureError::InvalidEventLog)
        ));
    }
    assert!(matches!(
        capture_qemu_finding_replay_side(
            timeout,
            std::slice::from_ref(&native),
            &snapshot,
            Some(&record),
            Some(&policy),
            replay_capture_limits(),
        ),
        Err(crate::FindingProductionReplayCaptureError::InvalidEventLog)
    ));
}

#[test]
fn ordinary_replay_capture_preserves_exact_native_snapshot_suffix() {
    let frontier = VirtualTime { ticks: 7 };
    let native =
        SchedulerEventLogEntry::execution_budget_exhausted(0, frontier, "execution-quanta");
    let snapshot = crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot::for_replay_capture_test(
        1,
        frontier,
        vec![native.clone()],
    );
    let passed = crate::FindingProductionReplayTerminalOutcome::Passed;

    assert!(matches!(
        capture_qemu_finding_replay_side(
            passed,
            std::slice::from_ref(&native),
            &snapshot,
            None,
            None,
            replay_capture_limits(),
        ),
        Ok(crate::FindingProductionReplayCaptureOutcome::Complete(side))
            if side.event_log() == [native]
    ));
    let changed_native =
        SchedulerEventLogEntry::execution_budget_exhausted(0, frontier, "virtual-time");
    assert!(matches!(
        capture_qemu_finding_replay_side(
            passed,
            std::slice::from_ref(&changed_native),
            &snapshot,
            None,
            None,
            replay_capture_limits(),
        ),
        Err(crate::FindingProductionReplayCaptureError::InvalidEventLog)
    ));
}
#[cfg(target_os = "linux")]
use crate::{
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory, QemuExecutionQuantumCounter,
    QemuHotForkWorldAuxiliaryResourceBroker, QemuHotForkWorldAuxiliaryResourceFactory,
    QemuHotForkWorldResourceOwner,
};

struct MainRunner {
    result: PreparedSemanticAttemptResult,
    calls: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
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
        let (cgroup_procs, _cgroup_peer) = UnixStream::pair().expect("test cgroup descriptor pair");
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
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
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
        _selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        self.begins.fetch_add(1, Ordering::SeqCst);
        Err(QemuVmRealizationError::Executor {
            operation: "allocate fresh finding fixture resources",
            message: String::from("retained World resources must satisfy every replay"),
        }
        .into())
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
            .begin(context.resources(), context.cancellation().clone(), None)
            .map_err(|failure| test_resource_failure(failure.into_parts().0))?;
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
    let child = encode_crucible_configuration_artifact(&scenario, schedule).expect("configuration");
    let measurements = MeasurementSet::from_evaluation(
        CampaignHash::derive(
            "crucible.test.measurement-definitions.v1",
            b"finding reduction",
        ),
        1,
        CampaignHash::derive(
            "crucible.test.measurement-evaluation.v1",
            b"finding reduction",
        ),
        b"finding reduction".to_vec(),
        BTreeSet::new(),
    )
    .expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        property.to_owned(),
        PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new()).expect("failed property"),
    )]))
    .expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        input.attempt().id().expect("attempt"),
        Observation::outcome(
            child.configuration(),
            child.id().expect("configuration ID"),
            input.path().id().expect("path ID"),
            stop,
            measurements.id().expect("measurement ID"),
            properties.id().expect("property ID"),
            coverage.id().expect("coverage ID"),
        ),
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
    PreparedSemanticAttemptResult::new(candidate, Vec::new(), None).expect("prepared result")
}

fn input_fixture() -> (
    CrucibleAttemptExecution,
    String,
    CampaignExecutorStore,
    AttemptRetentionPolicyBasis,
) {
    const CAMPAIGN: &str = "automatic-finding-runner";

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
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("lineage");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "automatic-finding-runner-test",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish scenario");
    repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            configuration_artifact.scenario_artifact(),
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish configuration");
    let policy = finding_campaign_policy(&lineage);
    let created = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create automatic finding campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: campaign_command("fund-input"),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("attempt budget"),
                ),
            },
        )
        .expect("fund automatic finding campaign");
    let running = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: campaign_command("resume-input"),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("run automatic finding campaign");
    let discovery = DiscoveryRequest::new(
        campaign_command("discover-input"),
        running.new_snapshot,
        lineage.genesis_content(),
        StopCondition::Terminal,
    )
    .expect("discovery request");
    let admitted = repository
        .submit_discovery_request(CAMPAIGN, &discovery)
        .expect("admit automatic finding attempt");
    let attempt = repository
        .load_attempt(admitted.attempt)
        .expect("load automatic finding attempt");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let path = store
        .load_branch_path(attempt.path())
        .expect("load automatic finding path");
    let retention_basis = repository
        .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
        .expect("automatic finding retention basis");
    let input = CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    );
    (input, property, store, retention_basis)
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
        CampaignPolicy::identity(
            lineage.scenario(),
            CampaignSeed::from_bytes([0x51; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
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
    let assignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([request.marker; 16]).expect("capture assignment"),
        DaemonEpoch::from_bytes([request.marker.wrapping_add(1); 16])
            .expect("capture daemon epoch"),
        request.lineage.id().expect("lineage ID"),
        capture.attempt,
        resources,
        ExecutionRetentionIntent::RetainAlways,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .and_then(|assignment| {
        SubmitAttemptRequest::new_savepoint_capture(
            assignment,
            capture.request,
            capture.configuration,
        )
    })
    .expect("capture assignment request");
    let status_request = GetAttemptExecutionRequest::new(
        &assignment,
        ExecutionId::from_bytes([request.marker.wrapping_add(2); 16]).expect("capture execution"),
    )
    .expect("capture status request");
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
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
    AttemptResourceLimits::new(1, 1024 * 1024, 1024 * 1024, 5).expect("finding fixture resources")
}

mod outcomes;
