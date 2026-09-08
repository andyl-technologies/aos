//! QEMU campaign exact-resume request and runtime-binding tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::{
    Checkpoint, CheckpointKind, Configuration, Decision, ScenarioDef, SchedulerEventLogEntry,
    SchedulerQuiescence, SelectionDecision, VirtualTime,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmLifecycleResumeState};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BooleanDomain, BranchPath, BranchPathSegment,
    CampaignFactId, CampaignHash, CampaignLineage, CampaignRepository, ChoiceClassContext,
    ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue,
    ConfigurationArtifact, ConfigurationId, ExactCheckpointId, ExecutionId,
    ExecutionRetentionIntent, ScenarioArtifact, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, ObjectKind,
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
    fn enable_signal_fault_campaign_promotion(&mut self) {
        panic!("exact resume tests must not use the fresh-attempt promotion gate");
    }

    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("resume test driver does not advance a quantum"),
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.state.scheduler_quanta()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("resume lifecycle fixture has no selectable transport"),
        })
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

    fn authenticate_resume_boundary(
        &mut self,
        _checkpoints: &ExactCheckpointStore,
        _checkpoint: ExactCheckpointId,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _initial: &Configuration,
        _post_selection: Option<&Configuration>,
        _context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        Err(AttemptWorkerFailure::Terminal(
            "ordinary resume fixture has no selected boundary",
        ))
    }

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
    completed_quanta: u64,
    frontier: VirtualTime,
    quiescence: Option<SchedulerQuiescence>,
    final_events: Vec<SchedulerEventLogEntry>,
    attempt_event_count: usize,
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
        let attempt_event_count = materialization.attempt_event_count();
        let (events, bytes, completed_quanta, frontier, quiescence, _terminal) =
            materialization.into_parts();
        *self.observed.lock().expect("resume observation") = Some(ObservedResume {
            events,
            bytes,
            completed_quanta,
            frontier,
            quiescence,
            final_events: Vec::new(),
            attempt_event_count,
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
        ProductionVmLifecycleResumeState::new(
            test_configuration(),
            Vec::new(),
            0,
            0,
            VirtualTime::default(),
            SchedulerQuiescence::default(),
            None,
        ),
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
fn event_count_resume_rejects_a_missing_start_proof_before_factory_invocation() {
    let calls = Arc::new(ResumeCalls::default());
    let observed = Arc::new(Mutex::new(None));
    let mut runner = resume_runner(
        Arc::clone(&calls),
        observed,
        ProductionVmLifecycleResumeState::new(
            test_configuration(),
            Vec::new(),
            0,
            0,
            VirtualTime::default(),
            SchedulerQuiescence::default(),
            None,
        ),
        Vec::new(),
    );

    let error = runner
        .execute(
            &test_input_with_stop(StopCondition::EventCount(1)),
            &test_context(Some(checkpoint_id("missing-attempt-start-proof"))),
        )
        .expect_err("EventCount resume must require a start-prefix proof");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::MissingAttemptStartProof
        )
    ));
    assert_eq!(calls.starts.load(Ordering::SeqCst), 0);
}

#[test]
fn cold_fallback_distinguishes_an_absent_selected_root_from_a_missing_child() {
    let checkpoint = checkpoint_id("selected-source-root");
    let context = selected_source_context(checkpoint);
    let absent_root = crate::QemuAttemptProductionVmLifecycleError::CheckpointRestore(
        crate::ProductionAttemptCheckpointRestoreError::Checkpoint(
            crate::ExactCheckpointStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound {
                    id: checkpoint.content_id(),
                },
            ),
        ),
    );
    let missing_child = crate::QemuAttemptProductionVmLifecycleError::CheckpointRestore(
        crate::ProductionAttemptCheckpointRestoreError::Checkpoint(
            crate::ExactCheckpointStoreError::Store(
                crucible_cas::content_store::StoreError::NotFound {
                    id: ContentId::for_bytes(ObjectKind::DeviceState, 1, b"missing-child"),
                },
            ),
        ),
    );

    assert!(initial_selected_source_is_absent(
        &absent_root,
        checkpoint,
        &context
    ));
    assert!(!initial_selected_source_is_absent(
        &missing_child,
        checkpoint,
        &context
    ));
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
            test_configuration(),
            prefix.clone(),
            0,
            4,
            VirtualTime { ticks: 17 },
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
    assert_eq!(observed.completed_quanta, 4);
    assert_eq!(observed.frontier, VirtualTime { ticks: 17 });
    assert_eq!(observed.quiescence, Some(SchedulerQuiescence::default()));
    assert_eq!(observed.final_events, final_events);
    assert_eq!(observed.attempt_event_count, 0);
    assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
    assert_eq!(calls.drives.load(Ordering::SeqCst), 1);
    assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(calls.seals.load(Ordering::SeqCst), 1);
}

#[test]
fn event_count_resume_derives_same_attempt_progress_for_discovery_and_branch_starts() {
    let inherited = vec![event(0, 3, "inherited-a"), event(1, 5, "inherited-b")];
    let same_attempt = vec![
        event(2, 7, "attempt-a"),
        event(3, 11, "attempt-b"),
        event(4, 13, "attempt-c"),
    ];
    let final_events = vec![event(5, 17, "final-drain")];
    let inputs = [
        test_input_with_stop(StopCondition::EventCount(8)),
        test_branch_input(StopCondition::EventCount(8)),
    ];

    for input in inputs {
        let calls = Arc::new(ResumeCalls::default());
        let observed = Arc::new(Mutex::new(None));
        let mut restored = inherited.clone();
        restored.extend(same_attempt.clone());
        let proof = QemuAttemptStartReplayProof::from_reached_boundary(
            input.start().configuration(),
            &inherited,
        )
        .expect("authenticated attempt-start prefix");
        let mut runner = resume_runner(
            Arc::clone(&calls),
            Arc::clone(&observed),
            ProductionVmLifecycleResumeState::new(
                input.start().configuration().clone(),
                restored.clone(),
                0,
                5,
                VirtualTime { ticks: 13 },
                SchedulerQuiescence::default(),
                None,
            ),
            final_events.clone(),
        );

        runner
            .execute_verified_attempt_start(
                &input,
                &test_context(Some(checkpoint_id("event-count-resume"))),
                proof,
            )
            .expect("verified ordinary resume");

        let observed = observed
            .lock()
            .expect("resume observation")
            .take()
            .expect("driver observation");
        assert_eq!(observed.events, restored);
        assert_eq!(observed.attempt_event_count, same_attempt.len());
        assert_eq!(observed.final_events, final_events);
        assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
        assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn event_count_resume_keeps_quiet_and_repeated_same_attempt_progress_exact() {
    let input = test_input_with_stop(StopCondition::EventCount(8));
    let inherited = vec![event(0, 3, "inherited")];
    let proof = QemuAttemptStartReplayProof::from_reached_boundary(
        input.start().configuration(),
        &inherited,
    )
    .expect("authenticated attempt-start prefix");

    for (same_attempt_events, expected) in [(0, 0), (2, 2), (4, 4)] {
        let calls = Arc::new(ResumeCalls::default());
        let observed = Arc::new(Mutex::new(None));
        let mut restored = inherited.clone();
        restored.extend((0..same_attempt_events).map(|index| {
            let sequence = u64::try_from(index + inherited.len()).expect("event sequence");
            event(sequence, sequence + 5, "same-attempt")
        }));
        let mut runner = resume_runner(
            calls,
            Arc::clone(&observed),
            ProductionVmLifecycleResumeState::new(
                input.start().configuration().clone(),
                restored,
                0,
                8,
                VirtualTime { ticks: 21 },
                SchedulerQuiescence::default(),
                None,
            ),
            Vec::new(),
        );

        runner
            .execute_verified_attempt_start(
                &input,
                &test_context(Some(checkpoint_id("repeated-event-count-resume"))),
                proof,
            )
            .expect("verified repeated resume");

        assert_eq!(
            observed
                .lock()
                .expect("resume observation")
                .as_ref()
                .expect("driver observation")
                .attempt_event_count,
            expected
        );
    }
}

#[test]
fn event_count_resume_rejects_foreign_or_short_inherited_prefixes() {
    let input = test_input_with_stop(StopCondition::EventCount(8));
    let inherited = vec![event(0, 3, "inherited-a"), event(1, 5, "inherited-b")];
    let proof = QemuAttemptStartReplayProof::from_reached_boundary(
        input.start().configuration(),
        &inherited,
    )
    .expect("authenticated attempt-start prefix");
    let cases = [
        vec![event(0, 3, "foreign"), event(1, 5, "inherited-b")],
        vec![event(0, 3, "inherited-a")],
    ];

    for restored in cases {
        let calls = Arc::new(ResumeCalls::default());
        let observed = Arc::new(Mutex::new(None));
        let mut runner = resume_runner(
            Arc::clone(&calls),
            Arc::clone(&observed),
            ProductionVmLifecycleResumeState::new(
                input.start().configuration().clone(),
                restored,
                0,
                2,
                VirtualTime { ticks: 5 },
                SchedulerQuiescence::default(),
                None,
            ),
            Vec::new(),
        );

        let error = runner
            .execute_verified_attempt_start(
                &input,
                &test_context(Some(checkpoint_id("mismatched-event-count-resume"))),
                proof,
            )
            .expect_err("foreign or short attempt-start evidence must fail closed");
        assert!(matches!(
            error,
            AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::AttemptStartMismatch
            )
        ));
        assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
        assert_eq!(calls.drives.load(Ordering::SeqCst), 0);
        assert_eq!(calls.shutdowns.load(Ordering::SeqCst), 1);
        assert!(observed.lock().expect("resume observation").is_none());
    }
}

#[test]
fn selected_resume_materialization_carries_cold_derived_attempt_event_progress() {
    let calls = Arc::new(ResumeCalls::default());
    let configuration = test_configuration();
    let events = (0..5)
        .map(|sequence| event(sequence, sequence + 1, "selected-resume-prefix"))
        .collect::<Vec<_>>();
    let proof = QemuSavepointReplayProof::from_reached_boundary(
        &configuration,
        5,
        VirtualTime { ticks: 5 },
        &events,
    )
    .and_then(|proof| proof.with_attempt_event_count(2))
    .expect("cold-derived selected proof");
    let lifecycle = FakeResumeLifecycle {
        calls,
        state: ProductionVmLifecycleResumeState::new(
            configuration.clone(),
            events,
            0,
            5,
            VirtualTime { ticks: 5 },
            SchedulerQuiescence::default(),
            None,
        ),
        final_events: Vec::new(),
    };

    let materialization = resume_start_materialization::<&'static str, &'static str>(
        &lifecycle,
        &configuration,
        QemuResumeReplayProof::SelectedOrigin(proof),
    )
    .expect("selected resume materialization");

    assert_eq!(materialization.attempt_event_count(), 2);
}

#[test]
fn resume_runner_rejects_suffix_only_evidence_and_still_cleans_up() {
    let calls = Arc::new(ResumeCalls::default());
    let observed = Arc::new(Mutex::new(None));
    let mut runner = resume_runner(
        Arc::clone(&calls),
        Arc::clone(&observed),
        ProductionVmLifecycleResumeState::new(
            test_configuration(),
            vec![event(7, 21, "retained-suffix")],
            7,
            9,
            VirtualTime { ticks: 21 },
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

fn selected_source_context(checkpoint: ExactCheckpointId) -> AttemptExecutionContext {
    let source_attempt = test_input().attempt().id().expect("source attempt");
    let certificate = CampaignFactId::parse(&format!(
        "crucible.campaign.fact@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 10, b"selected-source-certificate")
    ))
    .expect("selection certificate");
    let request = CampaignFactId::parse(&format!(
        "crucible.campaign.fact@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 10, b"selected-source-request")
    ))
    .expect("capture request");
    test_context(None).with_execution_origin(crate::AttemptExecutionOrigin::SelectedSavepoint {
        certificate,
        request,
        source_attempt,
        source_execution: ExecutionId::from_bytes([0x71; 16]).expect("source execution"),
        source_checkpoint: checkpoint,
        resume: None,
    })
}

fn event(sequence: u64, ticks: u64, kind: &str) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::execution_budget_exhausted(sequence, VirtualTime { ticks }, kind)
}

fn test_configuration() -> Configuration {
    Configuration::genesis(
        crucible::crash_restart_scenario()
            .expect("built-in scenario")
            .scenario
            .scenario_def(),
    )
}

fn test_input() -> CrucibleAttemptExecution {
    test_input_with_stop(StopCondition::Terminal)
}

fn test_input_with_stop(stop: StopCondition) -> CrucibleAttemptExecution {
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
        stop,
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

fn test_branch_input(stop: StopCondition) -> CrucibleAttemptExecution {
    let base = test_input();
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("branch domain"));
    let declaration = SelectableDeclaration::new(
        "scheduler.test-branch",
        ChoiceSource::Scheduler {
            producer: String::from("resume-test"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("branch choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("branch selectable declaration");
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "resume-branch-selection",
            1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(&domain)
        .expect("publish branch domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish branch declaration");
    let opportunity = ChoiceOpportunity::new(
        base.lineage().scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("resume-test-branch", b"scheduler"),
            producer: CampaignHash::derive("resume-test-branch", b"producer"),
        },
        "resume-test",
        None,
    )
    .expect("branch opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish branch opportunity");

    let CrucibleResolvedAttemptStart::Discover {
        configuration: parent,
    } = base.start()
    else {
        panic!("branch base must be a discovery start")
    };
    let parent = parent.clone();
    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let branch_point = opportunity.branch_point_id(parent_id);
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        ChoiceValue::Boolean(true),
        branch_point,
    )
    .expect("branch selection");
    repository
        .publish_selection(&selection)
        .expect("publish branch selection");
    let resolved = repository
        .resolve_selection(selection.id().expect("branch selection ID"))
        .expect("resolve branch selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("branch selection has the wrong origin")
    };
    let selected = crucible::step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let path =
        BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)]).expect("branch path");
    let AttemptStart::Discover {
        configuration: parent_artifact,
    } = base.attempt().start()
    else {
        panic!("branch base attempt must discover")
    };
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: parent_artifact,
            selection: selection.id().expect("branch selection ID"),
        },
        path.id().expect("branch path ID"),
        stop,
    )
    .expect("branch attempt");

    CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        attempt,
        path,
        CrucibleResolvedAttemptStart::Branch {
            parent,
            selection: Box::new(resolved),
            selected,
        },
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
