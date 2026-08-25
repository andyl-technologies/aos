//! QEMU campaign exact-resume request and runtime-binding tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ScenarioDef, SchedulerEventLogEntry,
    SchedulerQuiescence, VirtualTime,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmLifecycleResumeState};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BranchPath, CampaignHash, CampaignLineage,
    ConfigurationArtifact, ConfigurationId, ExactCheckpointId, ExecutionRetentionIntent,
    ScenarioArtifact, ScenarioDefId, StopCondition,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, ObjectKind,
};
use crucible_qemu::{QemuReplayOracleValidation, QemuVmSnapshot};

use super::*;
use crate::{
    CapturedAttemptCheckpoint, CrucibleResolvedAttemptStart, ExecutionCancellation,
    ExecutionCheckpointRequest,
};

#[derive(Default)]
struct ResumeCalls {
    starts: AtomicUsize,
    drives: AtomicUsize,
    shutdowns: AtomicUsize,
    seals: AtomicUsize,
}

struct FakeResumeLifecycle {
    calls: Arc<ResumeCalls>,
    state: ProductionVmLifecycleResumeState,
    final_events: Vec<SchedulerEventLogEntry>,
}

impl QemuFreshAttemptLifecycleOwner for FakeResumeLifecycle {
    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("resume test driver does not advance a quantum"),
        })
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("resume test did not request another checkpoint"),
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("resume test has no production fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.calls.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(self.final_events.clone())
    }
}

impl QemuProductionExactResumeLifecycleOwner for FakeResumeLifecycle {
    fn resume_state(&self) -> Result<ProductionVmLifecycleResumeState, SchedulerError> {
        Ok(self.state.clone())
    }
}

struct FakeResumeFactory {
    calls: Arc<ResumeCalls>,
    state: Option<ProductionVmLifecycleResumeState>,
    final_events: Vec<SchedulerEventLogEntry>,
}

impl QemuProductionExactResumeLifecycleFactory for FakeResumeFactory {
    type Lifecycle = FakeResumeLifecycle;
    type Error = &'static str;

    fn start_resume_lifecycle(
        &mut self,
        _checkpoints: &ExactCheckpointStore,
        _checkpoint: ExactCheckpointId,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _initial: &Configuration,
        _post_selection: Option<&Configuration>,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.calls.starts.fetch_add(1, Ordering::SeqCst);
        let state = self.state.take().ok_or(AttemptWorkerFailure::Terminal(
            "resume factory was invoked more than once",
        ))?;
        Ok(FakeResumeLifecycle {
            calls: Arc::clone(&self.calls),
            state,
            final_events: self.final_events.clone(),
        })
    }
}

struct FakeResumeDriver {
    calls: Arc<ResumeCalls>,
    observed: Arc<Mutex<Option<ObservedResume>>>,
}

struct ObservedResume {
    events: Vec<SchedulerEventLogEntry>,
    bytes: usize,
    quiescence: Option<SchedulerQuiescence>,
    final_events: Vec<SchedulerEventLogEntry>,
}

impl QemuFreshAttemptDriver for FakeResumeDriver {
    type Pending = ();
    type Error = &'static str;

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        self.calls.drives.fetch_add(1, Ordering::SeqCst);
        let (events, bytes, quiescence, _terminal) = materialization.into_parts();
        *self.observed.lock().expect("resume observation") = Some(ObservedResume {
            events,
            bytes,
            quiescence,
            final_events: Vec::new(),
        });
        Ok(QemuFreshDriveOutcome::Observation(()))
    }

    fn seal(
        &mut self,
        _pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.calls.seals.fetch_add(1, Ordering::SeqCst);
        self.observed
            .lock()
            .expect("resume observation")
            .as_mut()
            .expect("driver must observe materialization before sealing")
            .final_events = final_events;
        Ok(test_checkpoint_product())
    }
}

#[test]
fn resume_runner_rejects_missing_root_before_factory_invocation() {
    let calls = Arc::new(ResumeCalls::default());
    let observed = Arc::new(Mutex::new(None));
    let mut runner = resume_runner(
        Arc::clone(&calls),
        Arc::clone(&observed),
        ProductionVmLifecycleResumeState::new(Vec::new(), 0, SchedulerQuiescence::default(), None),
        Vec::new(),
    );

    let error = runner
        .execute(&test_input(), &test_context(None))
        .expect_err("resume-only runner must require an exact root");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::MissingCheckpoint
        )
    ));
    assert_eq!(calls.starts.load(Ordering::SeqCst), 0);
    assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 0);
}

#[test]
fn resume_runner_preserves_exact_event_prefix_and_final_drain() {
    let calls = Arc::new(ResumeCalls::default());
    let observed = Arc::new(Mutex::new(None));
    let prefix = vec![event(0, 11, "restored-prefix")];
    let final_events = vec![event(1, 12, "final-drain")];
    let expected_bytes: usize = prefix
        .iter()
        .map(SchedulerEventLogEntry::canonical_material_len)
        .sum();
    let mut runner = resume_runner(
        Arc::clone(&calls),
        Arc::clone(&observed),
        ProductionVmLifecycleResumeState::new(
            prefix.clone(),
            0,
            SchedulerQuiescence::default(),
            None,
        ),
        final_events.clone(),
    );
    let checkpoint = checkpoint_id("resume-runner-preserves-prefix");

    let outcome = runner
        .execute(&test_input(), &test_context(Some(checkpoint)))
        .expect("promoted exact resume should reach the modeled driver");

    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::ExactRestore
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    let observed = observed
        .lock()
        .expect("resume observation")
        .take()
        .expect("driver should retain resume evidence");
    assert_eq!(observed.events, prefix);
    assert_eq!(observed.bytes, expected_bytes);
    assert_eq!(observed.quiescence, Some(SchedulerQuiescence::default()));
    assert_eq!(observed.final_events, final_events);
    assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
    assert_eq!(calls.drives.load(Ordering::SeqCst), 1);
    assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(calls.seals.load(Ordering::SeqCst), 1);
}

#[test]
fn resume_runner_rejects_suffix_only_evidence_and_still_cleans_up() {
    let calls = Arc::new(ResumeCalls::default());
    let observed = Arc::new(Mutex::new(None));
    let mut runner = resume_runner(
        Arc::clone(&calls),
        Arc::clone(&observed),
        ProductionVmLifecycleResumeState::new(
            vec![event(7, 21, "retained-suffix")],
            7,
            SchedulerQuiescence::default(),
            None,
        ),
        Vec::new(),
    );
    let checkpoint = checkpoint_id("resume-runner-incomplete-evidence");

    let error = runner
        .execute(&test_input(), &test_context(Some(checkpoint)))
        .expect_err("suffix-only evidence must not become a cumulative result");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::IncompleteEventLog(7)
        )
    ));
    assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
    assert_eq!(calls.drives.load(Ordering::SeqCst), 0);
    assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(calls.seals.load(Ordering::SeqCst), 0);
    assert!(observed.lock().expect("resume observation").is_none());
}

fn resume_runner(
    calls: Arc<ResumeCalls>,
    observed: Arc<Mutex<Option<ObservedResume>>>,
    state: ProductionVmLifecycleResumeState,
    final_events: Vec<SchedulerEventLogEntry>,
) -> QemuProductionExactResumeExecutionRunner<FakeResumeFactory, FakeResumeDriver> {
    QemuProductionExactResumeExecutionRunner::new(
        test_checkpoint_store(),
        FakeResumeFactory {
            calls: Arc::clone(&calls),
            state: Some(state),
            final_events,
        },
        FakeResumeDriver { calls, observed },
    )
}

fn test_checkpoint_store() -> Arc<ExactCheckpointStore> {
    let directory = tempfile::tempdir().expect("resume checkpoint directory");
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "resume-runner-checkpoints",
        directory.keep(),
    ));
    Arc::new(ExactCheckpointStore::new(backend, 1024 * 1024).expect("resume checkpoint store"))
}

fn checkpoint_id(label: &str) -> ExactCheckpointId {
    ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        label.as_bytes(),
    ))
    .expect("exact checkpoint fixture")
}

fn test_context(checkpoint: Option<ExactCheckpointId>) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
            .expect("attempt resource fixture"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    )
    .with_resume_checkpoint(checkpoint)
}

fn event(sequence: u64, ticks: u64, kind: &str) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::execution_budget_exhausted(sequence, VirtualTime { ticks }, kind)
}

fn test_input() -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let definition = scenario.scenario_def();
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(definition.id().bytes));
    let scenario_artifact =
        ScenarioArtifact::new(scenario_id, 1, b"scenario".to_vec()).expect("scenario artifact");
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        StopCondition::Terminal,
    )
    .expect("discovery attempt");

    CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn test_checkpoint_product() -> AttemptExecutionProduct {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.resume-campaign-runner",
        "sealed-product",
    ));
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("resume runner checkpoint boundary");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("resume runner QEMU snapshot");
    AttemptExecutionProduct::exact_checkpoint(crate::CapturedExactCheckpoint::new(
        snapshot,
        BlobHandle::from_bytes(vec![0x5a; 512]),
    ))
}
