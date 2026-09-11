//! QEMU campaign lifecycle restart, promotion, and recovery tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible::model::{BindingSearchChoice, SearchChoiceId};
use crucible::test_support::{
    condition_observation_entry_for_test, condition_open_payload_entry_for_test,
};
use crucible::{
    AppRandomDecision, AppRandomSelectable, AssertionDef, AssertionId, AssertionPhase, Checkpoint,
    CheckpointKind, Configuration, Decision, EventAttributeValue, EventDiagnosticPayload,
    EventLevel, EventLog, EventPayload, FindingDiscoveryPath, FindingReproductionArtifact, Icount,
    MarkerId, NodeId, NodeTemplate, ObservableEvent, Plan, Predicate, Properties, Property,
    ReadyPoint, RngDecision, RngStreamId, ScenarioDef, ScenarioDefForm, ScenarioSelectableLimits,
    ScenarioSelectables, SchedulerEvaluationBoundaryKind, SchedulerEventLogClass,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SearchFrontierChoices, SearchRuntimeFrontier,
    SearchScheduleNamedPredicateKey, SearchScheduleNamedPredicateTruths, Seed, SelectionDecision,
    SignalFaultSelectable, VirtualTime, WhiteBoxPolicy, World, WorldNode, step,
};
use crucible_api::vm_lifecycle::production_permanently_failed_loop_for_test;
use crucible_api::{
    LifecycleApiError, ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig,
    ProductionVmNodeLauncher, build_authenticated_production_checkpoint_codec_fixture,
};
use crucible_campaign::{
    AssignmentId, Attempt, AttemptContinuationInput, AttemptResourceLimits, AttemptStart,
    AttemptStartMode, BooleanDomain, BranchPath, BranchPathSegment, BudgetGrant, CampaignCommandId,
    CampaignControlAction, CampaignExecutorStore, CampaignFactId, CampaignHash, CampaignLineage,
    CampaignMode, CampaignPolicy, CampaignRepository, CampaignSeed, ChoiceClassContext,
    ChoiceDiscovery, ChoiceDomain, ChoiceSource, ChoiceValue, ConfigurationArtifact,
    ConfigurationId, ControlRequest, CoverageProjection, DaemonEpoch, DiscoveryRequest,
    ExecutionId, ExecutionRetentionIntent, ExecutorRejection, ExecutorService, ExplorerPolicy,
    FairnessPolicy, FindingCandidateBundleId, FindingExactPins, MeasurementSet, Observation,
    ObservationCandidate, ObservationCondition, ObservationEventLogProof, ObservationId,
    ObservationQuantumBoundary, ObservationStopProof, ObservationStopSatisfaction,
    PropertyEvidence, PropertyVerdict, PropertyVerdictSet, RetentionPolicy, ScenarioArtifact,
    ScenarioDefId, SelectableDeclaration, Selection, SelectionOrigin, SelectionReplayMismatchKind,
    StopCondition, StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
};
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MemoryBlobBackend, MemoryRefBackend, ObjectKind, StoreGraph, StoreGraphConfig, StoreNodeId,
    StoreNodeSpec,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuLiveNodeStepGateConfig,
    QemuNodeChild, QemuPreparedRunDirectory, QemuReplayOracleValidation, QemuVmRealizationError,
    QemuVmSnapshot,
};

use super::*;
use crate::crucible_execution::{CrucibleAttemptOrigin, CrucibleAttemptOrigins};
use crate::exact_checkpoint_store::AttemptCheckpointResultState;
use crate::executor_supervisor::{AttemptCheckpointHandoff, ExecutionCheckpointHandoff};
use crate::qemu_campaign_driver::QemuFreshSupplementalModeledDriver;
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionDisposition,
    AttemptExecutionOrigin, AttemptExecutionProduct, AttemptExecutionReconciliationStep,
    AttemptResultRecoveryFailure, AttemptResultStageOutcome, AttemptRuntimeState, AttemptStateCas,
    AutomaticFindingReplayOutcome, CapturedAttemptCheckpoint, CheckpointHandoffFailure,
    CompletionValidationFailure, CrucibleAttemptExecution, CrucibleExecutionOutcome,
    CrucibleExecutionRunner, CrucibleFindingReplayTranscript, CrucibleMaterializationTier,
    CrucibleResolvedAttemptStart, DirectoryAssignmentLedger, DirectoryCampaignGcJournal,
    DirectoryPreparedResultJournal, ExactCheckpointStore, ExecutionCancellation,
    ExecutionCheckpointRequest, ExecutorCapacity, FindingReplayCaptureStore,
    LocalExecutorSupervisor, MAX_PREPARED_SEMANTIC_RESULT_BYTES, ObservationPublicationOutcome,
    PreparedAttemptCheckpoint, PreparedAttemptRecoveryOutcome, PreparedSemanticAttemptResult,
    QemuAttemptExecutionRouter, QemuAttemptExecutionRouterError, QemuAttemptOperationalBoundary,
    QemuAttemptResourceGuard, QemuFreshModeledDriver, QemuSavepointReplayProof,
    QemuSelectedOriginResumeRunner, apply_single_host_campaign_gc, plan_single_host_campaign_gc,
};

mod support;

use support::*;

#[derive(Debug)]
struct OversizedFailure<E> {
    source: E,
}

impl<E: fmt::Display> fmt::Display for OversizedFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} trailing=", self.source)?;
        for _ in 0..10_000 {
            formatter.write_str("x")?;
        }
        Ok(())
    }
}

impl<E: Error + 'static> Error for OversizedFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[test]
fn genesis_start_error_retains_worker_class_and_underlying_cause() {
    let error = QemuFreshGenesisCheckpointError::Start(AttemptWorkerFailure::Terminal(
        std::io::Error::other("guarded launch rejected"),
    ));
    assert!(
        error
            .to_string()
            .contains("terminal execution failure: guarded launch rejected")
    );
    let worker = std::error::Error::source(&error).expect("worker classification source");
    assert_eq!(
        worker.source().expect("original cause").to_string(),
        "guarded launch rejected"
    );
}

#[test]
fn selected_start_derives_matching_scheduler_and_plugin_branch_plans() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.campaign.branch-plan",
        "scenario=branch-plan",
        Seed::from_u64(0x51ec_7100),
    );
    let genesis = Configuration::genesis(scenario.clone());
    let stream = RngStreamId::from_name("app-random/node:6:node-a/stream:6:branch");
    let mut seeded = scenario
        .seed()
        .decision_rng()
        .fork_in_domain(&stream.domain, &stream.name);
    let raw = seeded.next_u64();
    let selected = raw ^ 1;
    let live = AppRandomDecision {
        node: NodeId {
            name: String::from("node-a"),
        },
        stream: stream.clone(),
        request_id: 11,
        width: 64,
        value: selected,
    };
    let parent = step(
        &genesis,
        Decision::RngDraw(RngDecision { stream, value: raw }),
    );
    let selection = AppRandomSelectable::from_decision(&scenario, &live)
        .expect("app-random request should reconstruct")
        .branch_selection(&parent, selected)
        .expect("exact parent should admit branch selection");
    let target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );

    let (scheduler, plugins) =
        app_random_branch_replay(&target).expect("selected target should derive plans");

    assert_eq!(
        scheduler.get(&parent.id()),
        Some(&SelectionDecision::new(&selection))
    );
    let plugin = plugins
        .get(&NodeId {
            name: String::from("node-a"),
        })
        .expect("node plan should exist");
    assert!(matches!(
        plugin.entries(),
        [entry]
            if entry.draw_index() == 0
                && entry.expected_raw_value() == raw
                && entry.selected_value() == selected
                && entry.selection_id()
                    == selection.id().expect("selection id").content_id().digest()
    ));
}

#[test]
fn promoted_signal_fault_branch_is_admitted_only_by_its_typed_plan() {
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.campaign.signal-fault-branch",
        "signal fault branch",
    );
    let parent = Configuration::genesis(scenario);
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(b"choice")),
        candidates_digest: crucible::ContentHash::from_bytes(b"candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let frontier = SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime { ticks: 91 },
        choices: SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    };
    let selectable = SignalFaultSelectable::from_frontier(&frontier)
        .expect("signal-fault frontier should normalize");
    let selection = selectable
        .branch_selection(&parent, 1)
        .expect("candidate should select");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("candidate should reconstruct");

    let empty = crucible::SignalFaultCampaignReplayPlan::empty(branch.selected().clone());
    assert_eq!(
        unsupported_fresh_replay_decision(branch.selected(), &empty),
        Some(1)
    );
    let plan = crucible::SignalFaultCampaignReplayPlan::new(
        branch.selected().clone(),
        vec![branch.clone()],
    )
    .expect("typed replay plan");
    assert_eq!(
        unsupported_fresh_replay_decision(branch.selected(), &plan),
        None
    );
}

#[test]
fn app_random_projection_ignores_a_campaign_selection_outside_its_owned_stream() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.campaign.branch-plan",
        "scenario=foreign-stream-domain",
        Seed::from_u64(0x51ec_7101),
    );
    let genesis = Configuration::genesis(scenario.clone());
    let stream = RngStreamId::for_node("app-random/node:6:node-a/stream:6:branch");
    let raw = 17;
    let selected = 23;
    let live = AppRandomDecision {
        node: NodeId {
            name: String::from("node-a"),
        },
        stream: stream.clone(),
        request_id: 11,
        width: 64,
        value: selected,
    };
    let parent = step(
        &genesis,
        Decision::RngDraw(RngDecision { stream, value: raw }),
    );
    let selection = AppRandomSelectable::from_decision(&scenario, &live)
        .expect("foreign-domain selectable should remain structurally valid")
        .branch_selection(&parent, selected)
        .expect("exact parent should admit a structural branch selection");
    let target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );

    let (selections, plans) =
        app_random_branch_replay(&target).expect("foreign producer stays outside this adapter");
    assert!(selections.is_empty());
    assert!(plans.is_empty());
}

#[test]
fn exact_guard_is_transferred_to_lifecycle_launcher_hooks() {
    let limits = resources(2);
    let counters = Arc::new(GuardCounters::default());
    let cancellation = ExecutionCancellation::default();
    let context = context(limits, cancellation);
    let mut factory = factory(limits, false, Arc::clone(&counters));

    factory
        .with_attempt_launcher(&context, 1, |mut launcher| {
            launcher.begin_execution_quantum()?;
            launcher.check_operational_boundary()?;
            launcher.finish()
        })
        .expect("exact guard should back lifecycle launcher hooks");

    assert_eq!(counters.begins.load(Ordering::SeqCst), 1);
    assert_eq!(counters.charges.load(Ordering::SeqCst), 1);
    assert_eq!(counters.checks.load(Ordering::SeqCst), 1);
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_resume_is_rejected_before_resource_installation() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"fresh-lifecycle-resume-rejection",
    ))
    .expect("exact checkpoint fixture");
    let context =
        context(limits, ExecutionCancellation::default()).with_resume_checkpoint(Some(checkpoint));
    let mut factory = factory(limits, false, Arc::clone(&counters));
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario fixture")
        .scenario;

    let error = factory
        .begin_fresh(&source.scenario_def(), &source, &context)
        .err()
        .expect("resume root must fail closed on the fresh path");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(actual)
            if actual == checkpoint
    ));
    assert_eq!(counters.begins.load(Ordering::SeqCst), 0);
}

#[test]
fn drifted_scenario_identity_fields_are_rejected_before_resource_installation() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let context = context(limits, ExecutionCancellation::default());
    let mut factory = factory(limits, false, Arc::clone(&counters));
    let source = crucible::crash_restart_scenario()
        .expect("built-in scenario fixture")
        .scenario;
    let reconstructed = source.scenario_def();
    let drifted = crucible::ScenarioDef::from_trusted_identity(
        reconstructed.id(),
        crucible::Seed::from_u64(0xabad_1dea),
        reconstructed.app_random_draw_cap(),
    );

    let error = factory
        .begin_fresh(&drifted, &source, &context)
        .err()
        .expect("drifted scenario fields must fail closed");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch
    ));
    assert_eq!(counters.begins.load(Ordering::SeqCst), 0);
}

#[test]
fn mismatched_guard_contract_is_released_before_rejection() {
    let requested = resources(1);
    let installed = AttemptResourceLimits::new(
        requested.maximum_vcpus() + 1,
        requested.maximum_resident_bytes(),
        requested.maximum_disk_bytes(),
        requested.maximum_execution_quanta(),
    )
    .expect("mismatched limits fixture");
    let counters = Arc::new(GuardCounters::default());
    let context = context(requested, ExecutionCancellation::default());
    let mut factory = factory(installed, false, Arc::clone(&counters));

    let error = factory
        .with_attempt_launcher(&context, 1, |_launcher| Ok(()))
        .expect_err("mismatched limits must fail closed");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn mismatched_cancellation_incarnation_is_released_before_rejection() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let context = context(limits, ExecutionCancellation::default());
    let mut factory = factory(limits, true, Arc::clone(&counters));

    let error = factory
        .with_attempt_launcher(&context, 1, |_launcher| Ok(()))
        .expect_err("mismatched cancellation must fail closed");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::ResourceContractMismatch
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
}

#[test]
fn lifecycle_construction_failure_quarantines_installed_guard() {
    let limits = resources(1);
    let counters = Arc::new(GuardCounters::default());
    let context = context(limits, ExecutionCancellation::default());
    let mut factory = factory(limits, false, Arc::clone(&counters));

    let error = factory
        .with_attempt_launcher(&context, 1, |_launcher| {
            Err::<(), _>(LifecycleApiError::LoopFactory {
                message: String::from("injected lifecycle construction failure"),
            })
        })
        .expect_err("construction failure must remain observable");

    assert!(matches!(
        error,
        QemuAttemptProductionVmLifecycleError::Lifecycle(_)
    ));
    assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
    assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
}

#[test]
fn observed_lifecycle_retains_only_successful_execution_evidence() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.standalone-campaign-lifecycle",
        "scenario=standalone-campaign-lifecycle",
        Seed::from_u64(0x5a11_da10),
    );
    let genesis = Configuration::genesis(scenario);
    let order = Arc::new(Mutex::new(Vec::new()));
    let lifecycle = FakeFreshLifecycle {
        order: Arc::clone(&order),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed = QemuObservedFreshAttemptLifecycle::new(
        lifecycle,
        vec![crucible::NodeId {
            name: String::from("node"),
        }],
        evidence.clone(),
    );

    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis.clone(),
            control: Vec::new(),
        })
        .expect("first admitted quantum");
    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("second admitted quantum");
    observed
        .prepare_terminal_fingerprints()
        .expect("terminal fingerprints");
    observed.shutdown().expect("cleanup remains available");
    let snapshot = evidence.snapshot().expect("observed execution evidence");
    assert_eq!(snapshot.quanta(), 2);
    assert_eq!(snapshot.frontier(), VirtualTime { ticks: 2 });
    assert_eq!(snapshot.event_log_entries().len(), 1);
    assert_eq!(snapshot.execution_fingerprints().len(), 2);
    assert_eq!(snapshot.execution_fingerprints()[0].at.ticks, 0);
    assert_eq!(snapshot.execution_fingerprints()[1].at.ticks, 1);
    let terminal = snapshot
        .terminal_fingerprints()
        .expect("published terminal fingerprints");
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].at.ticks, 2);
    assert_ne!(
        terminal[0].fingerprint,
        snapshot.execution_fingerprints()[1].fingerprint
    );
    assert_eq!(
        snapshot.resolved_effect_trace(),
        Some(b"resolved-effect-test".as_slice())
    );
    assert_eq!(
        *order.lock().expect("standalone lifecycle order"),
        ["replay", "replay", "shutdown"]
    );
}

#[test]
fn observed_production_lifecycle_projects_retained_failed_node_terminal_fingerprints()
-> Result<(), Box<dyn Error>> {
    let (source, mut lifecycle) = production_permanently_failed_loop_for_test()?;
    let nodes = source
        .world()
        .vm_nodes()
        .iter()
        .map(|vm| vm.id.clone())
        .collect::<Vec<_>>();
    let expected = nodes
        .iter()
        .map(|node| QuantumLoop::sample_fingerprint(&mut lifecycle, node.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed = QemuObservedFreshAttemptLifecycle::new(lifecycle, nodes, evidence.clone());

    observed.prepare_terminal_fingerprints()?;
    observed.shutdown()?;

    let snapshot = evidence.snapshot()?;
    assert_eq!(snapshot.terminal_fingerprints(), Some(expected.as_slice()));
    Ok(())
}

#[test]
fn observed_lifecycle_rejects_a_mismatched_terminal_fingerprint_atomically() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.terminal-fingerprint-mismatch",
        "scenario=terminal-fingerprint-mismatch",
        Seed::from_u64(0x5a11_da11),
    );
    let genesis = Configuration::genesis(scenario);
    let expected = crucible::NodeId {
        name: String::from("expected-node"),
    };
    let fingerprint_node_override = Arc::new(Mutex::new(None));
    let lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::clone(&fingerprint_node_override),
    };
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed =
        QemuObservedFreshAttemptLifecycle::new(lifecycle, vec![expected], evidence.clone());
    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("admitted quantum");
    *fingerprint_node_override
        .lock()
        .expect("fingerprint node override") = Some(crucible::NodeId {
        name: String::from("wrong-node"),
    });

    let error = observed
        .prepare_terminal_fingerprints()
        .expect_err("a mismatched terminal sample must fail closed");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    observed.shutdown().expect("cleanup remains available");
    let snapshot = evidence.snapshot().expect("evidence after refusal");
    assert_eq!(snapshot.execution_fingerprints().len(), 2);
    assert_eq!(snapshot.terminal_fingerprints(), None);
}

#[test]
fn observed_lifecycle_does_not_publish_staged_fingerprints_when_cleanup_fails() {
    let scenario = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.terminal-fingerprint-cleanup",
        "scenario=terminal-fingerprint-cleanup",
        Seed::from_u64(0x5a11_da12),
    );
    let genesis = Configuration::genesis(scenario);
    let node = crucible::NodeId {
        name: String::from("cleanup-node"),
    };
    let lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: true,
        pending: Vec::new(),
        replies: Arc::new(Mutex::new(Vec::new())),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let evidence = QemuAttemptExecutionEvidence::default();
    let mut observed =
        QemuObservedFreshAttemptLifecycle::new(lifecycle, vec![node], evidence.clone());
    observed
        .drive_quantum(QuantumRequest {
            configuration: genesis,
            control: Vec::new(),
        })
        .expect("admitted quantum");
    observed
        .prepare_terminal_fingerprints()
        .expect("stage terminal fingerprints");

    observed
        .shutdown()
        .expect_err("injected cleanup failure must remain observable");

    let snapshot = evidence.snapshot().expect("evidence after cleanup failure");
    assert_eq!(snapshot.execution_fingerprints().len(), 2);
    assert_eq!(snapshot.terminal_fingerprints(), None);
}

#[test]
fn router_cold_executes_an_initial_selected_origin_when_its_source_is_absent() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: None,
        },
    );
    let (input, source_attempt, source_checkpoint) = selected_after_genesis_input();
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xa1),
        request: campaign_fact_id(0xa2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xa3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let outcome = router
        .execute(&input, &context)
        .expect("absent initial selected source should cold execute");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Failed)
            .expect("reconcile the initial selected cold route"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert!(matches!(
        router.reconcile_execution(AttemptExecutionDisposition::Failed),
        Err(AttemptWorkerFailure::Terminal(
            QemuAttemptExecutionRouterError::NoPendingReconciliation
        ))
    ));
}

#[test]
fn router_cold_executes_continuation_control_after_authenticating_exact_source() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let continuations = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::clone(&continuations),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: None,
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, source_attempt, source_checkpoint) =
        selected_after_genesis_input_with_continuation(Some(continuation));
    let source = input.start().configuration().id();
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xa1),
        request: campaign_fact_id(0xa2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xa3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let outcome = router
        .execute(&input, &context)
        .expect("controlled continuation should cold execute");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert_eq!(
        continuations
            .lock()
            .expect("accepted continuation trace")
            .as_slice(),
        [(1, source)]
    );
    assert_eq!(
        router
            .reconcile_execution(AttemptExecutionDisposition::Failed)
            .expect("reconcile the controlled cold route"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn router_cold_replays_each_control_in_a_two_generation_continuation_chain() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let continuations = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::clone(&continuations),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: None,
        },
    );
    let (input, source_attempt, source_checkpoint, expected_controls) =
        selected_after_two_controlled_generations();
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xb1),
        request: campaign_fact_id(0xb2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xb3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let outcome = router
        .execute(&input, &context)
        .expect("two controlled generations should cold replay in order");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert_eq!(
        continuations
            .lock()
            .expect("accepted continuation trace")
            .as_slice(),
        expected_controls
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn private_fresh_replay_can_preserve_descendant_continuation_controls() {
    let (source, _, _, expected_controls) = selected_after_two_controlled_generations();
    let candidate = source.start().configuration().clone();
    let candidate_artifact =
        test_reached_configuration_artifact(&source, &candidate, b"finding-replay-candidate");
    let replay = source
        .for_finding_replay(
            source.scenario().clone(),
            candidate_artifact,
            candidate.clone(),
            crucible::SignalFaultCampaignReplayPlan::empty(candidate),
        )
        .unwrap_or_else(|error| panic!("private finding candidate should replay: {error}"));

    let controls = validated_attempt_continuations(&replay)
        .unwrap_or_else(|()| panic!("private replay continuation controls should validate"));
    let actual = controls
        .iter()
        .map(|control| {
            (
                control.input().source_frontier_ticks(),
                control.source().id(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(actual, expected_controls);
}

#[test]
fn private_fresh_replay_rejects_a_candidate_shorter_than_its_descendant_controls() {
    let (source, _, _, _) = selected_after_two_controlled_generations();
    let full = source.start().configuration();
    let shortened = Configuration {
        def: full.def.clone(),
        schedule: full
            .schedule
            .prefix(1)
            .unwrap_or_else(|error| panic!("first controlled prefix should exist: {error}")),
    };
    let candidate_artifact =
        test_reached_configuration_artifact(&source, &shortened, b"short-finding-replay-candidate");
    let replay = source.for_finding_replay(
        source.scenario().clone(),
        candidate_artifact,
        shortened.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(shortened),
    );

    assert!(matches!(
        replay,
        Err(crucible_campaign::CampaignCodecError::InvalidValue {
            reason: "finding replay candidate ends before a controlled source boundary"
        })
    ));
}

#[test]
fn router_rejects_invalid_exact_source_before_cold_continuation_allocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let authentications = Arc::new(AtomicUsize::new(0));
    let fresh = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::new(Mutex::new(Vec::new())),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let mut router = QemuAttemptExecutionRouter::new(
        fresh,
        AbsentSelectedSourceResume {
            authentications: Arc::clone(&authentications),
            authentication_failure: Some("invalid exact continuation source"),
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, source_attempt, source_checkpoint) =
        selected_after_genesis_input_with_continuation(Some(continuation));
    let origin = AttemptExecutionOrigin::SelectedSavepoint {
        certificate: campaign_fact_id(0xa1),
        request: campaign_fact_id(0xa2),
        source_attempt,
        source_execution: crucible_campaign::ExecutionId::from_bytes([0xa3; 16])
            .expect("source execution"),
        source_checkpoint,
        resume: None,
    };
    let context = fresh_runner_context().with_execution_origin(origin);

    let error = router
        .execute(&input, &context)
        .expect_err("invalid exact source must reject cold continuation");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuAttemptExecutionRouterError::Resume(
            "invalid exact continuation source"
        ))
    ));
    assert_eq!(authentications.load(Ordering::SeqCst), 1);
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_captures_a_sticky_checkpoint_before_shutdown_and_seal() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint handoff directory");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "fresh-runner-checkpoint-handoff",
        checkpoint_directory.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
        .expect("checkpoint handoff store");
    let checkpoint_scenario = test_checkpoint_capture()
        .snapshot()
        .checkpoint()
        .scenario_ref;
    let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
        order: Arc::clone(&order),
        checkpoints,
    }));
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_checkpoint_handoff(checkpoint_scenario, Some(handoff));

    let outcome = runner
        .execute(&fresh_runner_input(), &context)
        .expect("fresh execution should capture the requested checkpoint");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "capture", "stage", "shutdown"]
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn savepoint_captures_same_start_at_q100_and_q200_as_distinct_physical_prefixes() {
    fn capture_at(
        quanta: u64,
        label: &[u8],
        captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    ) -> ExactCheckpointId {
        let input = fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(quanta));
        let AttemptStart::Discover { configuration } = input.attempt().start() else {
            panic!("savepoint fixture must begin with discovery")
        };
        let request = CampaignFactId::parse(&format!(
            "crucible.campaign.fact@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 11, label)
        ))
        .expect("capture request ID");
        let mut runner = QemuFreshExecutionRunner::new(
            BoundaryCaptureLifecycleFactory {
                captured,
                final_events: Vec::new(),
                replay_decisions: VecDeque::new(),
            },
            QemuFreshModeledDriver::new(),
        );
        let checkpoint_directory = tempfile::tempdir().expect("savepoint checkpoint directory");
        let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(
            DirectoryBlobBackend::new("savepoint-checkpoint-handoff", checkpoint_directory.path()),
        );
        let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
            .expect("savepoint checkpoint store");
        let order = Arc::new(Mutex::new(Vec::new()));
        let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
            order,
            checkpoints,
        }));
        let checkpoint_request = ExecutionCheckpointRequest::default();
        checkpoint_request.request_for_test();
        let context = AttemptExecutionContext::new(
            resources(250),
            ExecutionRetentionIntent::RetainAlways,
            ExecutionCancellation::default(),
            checkpoint_request,
        )
        .with_start_mode(AttemptStartMode::SavepointCapture {
            request,
            configuration,
        })
        .with_checkpoint_handoff(input.scenario().scenario_def().id(), Some(handoff));

        let outcome = runner
            .execute(&input, &context)
            .expect("savepoint capture reaches exact quanta boundary");
        let (product, _) = outcome.into_parts();
        let AttemptExecutionProduct::ExactCheckpoint(checkpoint) = product else {
            panic!("savepoint capture must return an exact checkpoint")
        };
        let AttemptCheckpointResultState::Prepared(checkpoint) = checkpoint.into_state() else {
            panic!("runner handoff must prepare the exact root before return")
        };
        checkpoint.root()
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let q100 = capture_at(100, b"savepoint-q100", Arc::clone(&captured));
    let q200 = capture_at(200, b"savepoint-q200", Arc::clone(&captured));
    let captured = captured.lock().expect("captured boundary records");

    assert_ne!(q100, q200);
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].quanta, 100);
    assert_eq!(captured[1].quanta, 200);
    assert_eq!(captured[0].configuration, captured[1].configuration);
    assert_eq!(captured[0].events.len(), 100);
    assert_eq!(captured[1].events.len(), 200);
    assert_eq!(captured[0].events, captured[1].events[..100]);
    assert_ne!(captured[0].events, captured[1].events);
}

#[test]
fn fresh_runner_capture_mode_returns_the_materialized_start_without_driving() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint handoff directory");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "materialized-start-checkpoint-handoff",
        checkpoint_directory.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
        .expect("checkpoint handoff store");
    let checkpoint_scenario = test_checkpoint_capture()
        .snapshot()
        .checkpoint()
        .scenario_ref;
    let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
        order: Arc::clone(&order),
        checkpoints,
    }));
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let input = fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration })
    .with_checkpoint_handoff(checkpoint_scenario, Some(handoff));

    let outcome = runner
        .execute(&input, &context)
        .expect("capture mode should return the exact materialized start");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "capture", "stage", "shutdown"]
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn fresh_runner_capture_mode_preserves_a_terminal_property_boundary() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint handoff directory");
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "terminal-materialized-start-checkpoint-handoff",
        checkpoint_directory.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(checkpoint_backend, 1024 * 1024)
        .expect("checkpoint handoff store");
    let checkpoint_scenario = test_checkpoint_capture()
        .snapshot()
        .checkpoint()
        .scenario_ref;
    let handoff = ExecutionCheckpointHandoff::new(Arc::new(OrderingCheckpointHandoff {
        order: Arc::clone(&order),
        checkpoints,
    }));
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let input = non_genesis_fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration })
    .with_checkpoint_handoff(checkpoint_scenario, Some(handoff));

    let outcome = runner
        .execute(&input, &context)
        .expect("checkpoint-ready property boundary must remain capturable");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        [
            "begin",
            "replay",
            "terminal-cause",
            "capture",
            "stage",
            "shutdown"
        ]
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn fresh_runner_capture_mode_rejects_a_terminal_boundary_that_is_not_checkpoint_ready() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: false,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let input = non_genesis_fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration });

    let error = runner
        .execute(&input, &context)
        .expect_err("unsafe terminal materialization must not be captured");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::CaptureStartNotCheckpointReady
        )
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_capture_mode_requires_a_prelatched_checkpoint_request() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = fresh_runner_input();
    let AttemptStart::Discover { configuration } = input.attempt().start() else {
        panic!("capture fixture must be a discovery attempt")
    };
    let context = fresh_runner_context()
        .with_start_mode(AttemptStartMode::CaptureMaterializedStart { configuration });

    let error = runner
        .execute(&input, &context)
        .expect_err("capture mode without a prelatched request must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::CaptureCheckpointNotRequested
        )
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_opts_only_next_choice_attempts_into_live_signal_promotion() {
    for (stop, expected) in [
        (StopCondition::Terminal, false),
        (StopCondition::NextChoice, true),
    ] {
        let order = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut runner = QemuFreshExecutionRunner::new(
            PromotionRecordingFreshLifecycleFactory {
                order: Arc::clone(&order),
                observed: Arc::clone(&observed),
            },
            FakeFreshDriver {
                order,
                failure: None,
            },
        );

        runner
            .execute(&fresh_runner_input_for_stop(stop), &fresh_runner_context())
            .expect("fresh runner promotion admission");

        let observed = observed.lock().expect("promotion observations");
        if expected {
            assert_eq!(observed.as_slice(), [true]);
        } else {
            assert!(observed.is_empty());
        }
    }
}

#[test]
fn fresh_runner_enables_live_signal_promotion_after_start_materialization() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        PromotionRecordingFreshLifecycleFactory {
            order: Arc::clone(&order),
            observed: Arc::clone(&observed),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input_with_decisions_for_stop(
        vec![Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        })],
        StopCondition::NextChoice,
    );

    runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh runner should activate promotion after replay");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "promotion", "drive", "shutdown", "seal"]
    );
    assert_eq!(
        observed.lock().expect("promotion observations").as_slice(),
        [true]
    );
}

#[test]
fn fresh_genesis_checkpoint_capture_uses_no_modeled_quantum_and_tears_down() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: false,
        checkpoint_ready: true,
        cleanup_error: false,
    };

    let capture = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect("fresh genesis capture should succeed");

    assert_eq!(
        capture.configuration(),
        Configuration::genesis(input.scenario().scenario_def()).id()
    );
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "profiles", "shutdown"]
    );
}

#[test]
fn fresh_genesis_checkpoint_capture_rejects_foreign_basis_after_teardown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: true,
        checkpoint_ready: true,
        cleanup_error: false,
    };

    let error = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect_err("foreign genesis capture must fail closed");

    assert!(matches!(
        error,
        QemuFreshGenesisCheckpointError::Capture(
            QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch
        )
    ));
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "shutdown"]
    );
}

#[test]
fn fresh_genesis_checkpoint_capture_preserves_cleanup_precedence() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: true,
        checkpoint_ready: true,
        cleanup_error: true,
    };

    let error = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect_err("cleanup failure must retain precedence");

    assert!(matches!(
        error,
        QemuFreshGenesisCheckpointError::Cleanup {
            prior: Some(prior),
            ..
        } if matches!(
            prior.as_ref(),
            QemuFreshGenesisCheckpointCaptureFailure::BasisMismatch
        )
    ));
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "shutdown"]
    );
}

#[test]
fn production_genesis_capture_quarantines_native_catalog_after_shutdown_error() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let run_state = tempfile::tempdir().expect("production genesis run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production genesis fixture");
    let retirement = fixture.closure().native_retirement();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: Some(CapturedAttemptCheckpoint::from(fixture.closure().clone())),
        foreign_capture: false,
        checkpoint_ready: true,
        cleanup_error: true,
    };

    let error = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        fixture.source(),
        &fresh_runner_context(),
    )
    .expect_err("shutdown failure must quarantine the native catalog");

    assert!(matches!(
        error,
        QemuFreshGenesisCheckpointError::Cleanup {
            retirement: Some(_),
            ..
        }
    ));
    let report = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .expect("catalog remains available to its quarantine owner");
    assert!(report.retired());
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "profiles", "shutdown"]
    );
}

#[test]
fn fresh_runner_quarantines_failed_production_handoff_after_shutdown_error() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let run_state = tempfile::tempdir().expect("production fresh run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production fresh fixture");
    let retirement = fixture.closure().native_retirement();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeGenesisCheckpointLifecycleFactory {
            order: Arc::clone(&order),
            capture: Some(CapturedAttemptCheckpoint::from(fixture.closure().clone())),
            foreign_capture: false,
            checkpoint_ready: true,
            cleanup_error: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = fresh_runner_input();
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_checkpoint_handoff(input.scenario().scenario_def().id(), None);

    let failure = runner
        .execute(&input, &context)
        .expect_err("foreign production capture and failed shutdown must fail closed");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner { .. })
    ));
    let Some(crate::NativeCheckpointCleanup::Quarantine(cleanup)) =
        runner.take_abandoned_native_checkpoint()
    else {
        panic!("failed shutdown must quarantine the captured native catalog")
    };
    let report = crucible_api::retire_production_exact_checkpoint_catalog(&cleanup)
        .expect("test owner releases quarantined production capture");
    assert!(report.retired());
    let repeated = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .expect("repeat shutdown quarantine retirement");
    assert!(!repeated.retired());
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "drive", "ready", "capture", "shutdown"]
    );
}

#[test]
fn fresh_runner_retains_production_quarantine_when_handoff_panics_after_capture() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let run_state = tempfile::tempdir().expect("production panic run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production panic fixture");
    let retirement = fixture.closure().native_retirement();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeGenesisCheckpointLifecycleFactory {
            order: Arc::clone(&order),
            capture: Some(CapturedAttemptCheckpoint::from(fixture.closure().clone())),
            foreign_capture: false,
            checkpoint_ready: true,
            cleanup_error: false,
        },
        FakeFreshDriver {
            order,
            failure: None,
        },
    );
    let input = fresh_runner_input();
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        resources(4),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    )
    .with_checkpoint_handoff(
        fixture.closure().scenario(),
        Some(ExecutionCheckpointHandoff::new(Arc::new(
            PanickingCheckpointHandoff,
        ))),
    );

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _outcome = runner.execute(&input, &context);
    }));

    assert!(panicked.is_err());
    let Some(crate::NativeCheckpointCleanup::Quarantine(cleanup)) =
        runner.take_abandoned_native_checkpoint()
    else {
        panic!("unwinding capture must remain in the runner quarantine slot")
    };
    let report = crucible_api::retire_production_exact_checkpoint_catalog(&cleanup)
        .expect("test owner releases panic quarantine");
    assert!(report.retired());
    let repeated = crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .expect("repeat panic quarantine retirement");
    assert!(!repeated.retired());
}

#[test]
fn dropping_fresh_runner_moves_in_flight_capture_to_process_quarantine() {
    let run_state = tempfile::tempdir().expect("production drop run state");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(run_state.path())
        .expect("production drop fixture");
    let capture = CapturedAttemptCheckpoint::from(fixture.closure().clone());
    let before = crate::executor_worker::native_checkpoint_process_quarantine_len_for_test();
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeGenesisCheckpointLifecycleFactory {
            order: Arc::clone(&order),
            capture: None,
            foreign_capture: false,
            checkpoint_ready: true,
            cleanup_error: false,
        },
        FakeFreshDriver {
            order,
            failure: None,
        },
    );
    runner.register_native_checkpoint_capture(&capture);

    drop(runner);

    let after = crate::executor_worker::native_checkpoint_process_quarantine_len_for_test();
    assert!(after > before);
}

#[test]
fn production_baked_genesis_rejects_legacy_capture_after_guarded_teardown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = fresh_runner_input();
    let mut factory = FakeGenesisCheckpointLifecycleFactory {
        order: Arc::clone(&order),
        capture: None,
        foreign_capture: false,
        checkpoint_ready: true,
        cleanup_error: false,
    };

    let error = crate::capture_production_baked_genesis(
        &mut factory,
        input.scenario(),
        &fresh_runner_context(),
    )
    .expect_err("production baked genesis must require a version-four closure");

    assert!(matches!(
        error,
        crate::ProductionBakedGenesisCaptureError::Admission(
            crate::ProductionBakedGenesisCheckpointError::CompatibilityCapture
        )
    ));
    assert_eq!(
        order.lock().expect("genesis capture order").as_slice(),
        ["begin", "ready", "capture", "profiles", "shutdown"]
    );
}

#[test]
fn fresh_runner_rejects_an_unsolicited_checkpoint_before_capture() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        UnsolicitedCheckpointDriver,
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("unsolicited checkpoint capture must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::UnsolicitedCheckpoint)
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}

#[test]
fn fresh_runner_seals_only_after_runner_owned_shutdown() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let outcome = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect("fresh execution should seal after cleanup");

    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown", "seal"]
    );
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
}

#[test]
fn terminal_evidence_runner_attaches_the_fresh_terminal_world_set_after_shutdown() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(1));
    let factory = BoundaryCaptureLifecycleFactory {
        captured: Arc::new(Mutex::new(Vec::new())),
        final_events: Vec::new(),
        replay_decisions: VecDeque::new(),
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver::new());
    let mut runner = QemuTerminalEvidenceExecutionRunner::new(runner, evidence);

    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh modeled execution with terminal evidence");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("fresh absolute stop must produce a prepared semantic result")
    };
    let terminal = result
        .terminal_fingerprints()
        .expect("prepared fresh terminal fingerprints");
    let expected_nodes = input
        .scenario()
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let retained_nodes = terminal
        .iter()
        .map(|sample| sample.node.clone())
        .collect::<BTreeSet<_>>();

    assert!(!terminal.is_empty());
    assert_eq!(retained_nodes, expected_nodes);
    assert!(terminal.iter().all(|sample| sample.at.ticks == 1));
    result
        .verify_terminal_fingerprints(input.scenario())
        .expect("fresh terminal set must match the authenticated World");
    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
}

#[test]
fn automatic_wrapper_retains_supplemental_violation_when_offline_source_also_fails() {
    const PROPERTY: &str = "supplemental-collision";
    const NAMED_PREDICATE: &str = "supplemental-truth";

    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name(PROPERTY),
            message: String::from("supplemental collision failed"),
            property: Property::Always {
                predicate: Predicate::named(NAMED_PREDICATE),
            },
        }],
    )
    .expect("supplemental collision properties");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0x005a_771e),
    )
    .expect("supplemental collision scenario");
    let input = modeled_fresh_runner_input_for_scenario(
        scenario.clone(),
        StopCondition::ExecutionQuanta(1),
    );
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("supplemental-collision"),
        value: 1,
    });
    let finding_configuration = step(input.start().configuration(), decision.clone());
    let source = GuardedCampaignFindingOracleSource::new(
        ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes)),
        "application/vnd.crucible.test-named-truth+binary",
        b"supplemental-truth=false".to_vec(),
    )
    .expect("supplemental source");
    let source_id = source.content_id();
    let oracle = Arc::new(NamedSupplementalFindingOracle {
        scenario: scenario.clone(),
        source,
        truths: SearchScheduleNamedPredicateTruths::new().with_truth(
            SearchScheduleNamedPredicateKey::new(NAMED_PREDICATE, Vec::new()),
            false,
        ),
    });
    let expected_finding = oracle
        .evaluate(&finding_configuration)
        .expect("evaluate supplemental collision")
        .expect("supplemental collision must fail");
    let oracle: Arc<dyn GuardedCampaignFindingOracle> = oracle;

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("supplemental-wrapper", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let artifacts = crate::CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    artifacts
        .import_scenario(&scenario)
        .expect("publish supplemental scenario");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    store
        .publish_executor_trace_leaf(source_id, 1, oracle.source().canonical_bytes().as_slice())
        .expect("publish supplemental source");
    let configuration = artifacts
        .import_configuration(&scenario, &input.start().configuration().schedule)
        .expect("publish supplemental start configuration");
    let policy = CampaignPolicy::new(
        input.lineage().scenario(),
        CampaignSeed::from_bytes([0x5a; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("supplemental fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("supplemental campaign policy");
    let created = repository
        .create(
            "supplemental-wrapper",
            input.lineage(),
            &policy,
            &BTreeMap::new(),
        )
        .expect("create supplemental campaign");
    let resumed = repository
        .apply_control(
            "supplemental-wrapper",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"resume-supplemental-wrapper",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume supplemental campaign");
    let funded = repository
        .apply_control(
            "supplemental-wrapper",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"fund-supplemental-wrapper",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("supplemental attempt grant"),
                ),
            },
        )
        .expect("fund supplemental campaign");
    let admitted = repository
        .submit_discovery_request(
            "supplemental-wrapper",
            &DiscoveryRequest::new(
                CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"discover-supplemental-wrapper",
                )),
                funded.new_snapshot,
                configuration,
                StopCondition::ExecutionQuanta(1),
            )
            .expect("supplemental discovery request"),
        )
        .expect("admit supplemental discovery");
    assert_eq!(
        admitted.attempt,
        input.attempt().id().expect("supplemental input attempt ID")
    );

    let replay_decisions = VecDeque::from([decision]);
    let main = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: vec![SchedulerEventLogEntry::assertion_state_observation(
                1,
                VirtualTime { ticks: 1 },
                AssertionId::from_name(PROPERTY),
                AssertionPhase::Violated,
            )],
            replay_decisions: replay_decisions.clone(),
        },
        QemuFreshSupplementalModeledDriver::new(Some(Arc::clone(&oracle))),
    );
    // Each pass replays the one-decision original and then the empty selected
    // schedule, so the retained assertion follows prefixes of length one and zero.
    let replay_final_events = [1, 0, 1, 0]
        .into_iter()
        .map(|sequence| {
            vec![SchedulerEventLogEntry::assertion_state_observation(
                sequence,
                VirtualTime { ticks: sequence },
                AssertionId::from_name(PROPERTY),
                AssertionPhase::Violated,
            )]
        })
        .collect::<VecDeque<_>>();
    let replay = QemuFreshExecutionRunner::new(
        SequencedBoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: replay_final_events,
            replay_decisions,
        },
        QemuFreshSupplementalModeledDriver::new(Some(oracle)),
    );
    let mut runner = crate::AutomaticFindingExecutionRunner::new(store.clone(), main, replay);

    let outcome = runner
        .execute(
            &input,
            &context(resources(64), ExecutionCancellation::default()),
        )
        .expect("automatic supplemental finding wrapper");
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("supplemental finding must produce a prepared semantic result")
    };
    let property = result
        .observation()
        .properties()
        .properties()
        .get(PROPERTY)
        .expect("supplemental property verdict");
    assert_eq!(property.verdict(), PropertyVerdict::Failed);
    assert_eq!(property.evidence(), &BTreeSet::from([source_id]));

    let finding = result
        .finding()
        .expect("supplemental finding must survive private minimization");
    assert_eq!(finding.bundle().schema_version(), 2);
    crate::executor_worker::publish_prepared_semantic_attempt_result(&store, result)
        .expect("publish supplemental prepared result");
    let triage = finding
        .bundle()
        .triage_evidence()
        .expect("supplemental finding triage set");
    let retained = repository
        .load_finding_triage_replay_evidence(triage.minimization_original())
        .expect("load supplemental triage evidence");
    let reproduction = finding.original();
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .expect("decode supplemental reproduction");
    let native_finding = FindingReproductionArtifact {
        discovery_path: FindingDiscoveryPath::StateSpaceSearch,
        finding_fingerprint: crucible::ContentHash {
            bytes: reproduction.finding_fingerprint().as_bytes(),
        },
        configuration: crucible::ContentHash {
            bytes: reproduction.configuration().as_hash().as_bytes(),
        },
        replay: artifact.replay().expect("replay supplemental reproduction"),
        artifact,
    };
    let replay = crucible::FailureTriageReplayEvidence::from_compact_binary(
        native_finding,
        retained.payload(),
    )
    .expect("decode supplemental triage payload");
    let crucible::FailureClusterReportFailure::Property(actual) = replay.failure() else {
        panic!("supplemental replay must retain a property violation")
    };
    let mut expected = expected_finding.violation().clone();
    expected.reproduction_artifact = replay.finding().artifact.id();
    assert_eq!(actual.violation, expected);
}

#[test]
fn finding_candidate_replay_evaluates_the_exact_materialized_boundary() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(4));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("candidate boundary replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("genesis candidate must be observable")
    };

    assert_eq!(evidence.replay().configuration(), &candidate);
    assert_eq!(evidence.measurement_replay_evidence().len(), 1);
    assert!(evidence.final_events().is_empty());
    let (replay, measurements, final_events, _) = (*evidence).into_parts();
    assert_eq!(replay.configuration(), &candidate);
    assert_eq!(measurements.len(), 1);
    assert!(final_events.is_empty());
}

#[test]
fn finding_candidate_replay_stops_after_reaching_a_nonempty_schedule() {
    let input = modeled_non_genesis_fresh_runner_input();
    let candidate = finding_candidate_artifact(&input);
    let context = fresh_runner_context();
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::from([Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            })]),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("nonempty candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("matching nonempty candidate must be observable")
    };

    assert_eq!(evidence.replay().configuration(), &candidate);
    assert_eq!(
        context.consumed_execution_quanta(),
        1,
        "candidate evaluation must not run a continuation quantum"
    );
}

#[test]
fn finding_candidate_replay_retains_authenticated_execution_quanta_timeout() {
    let input = modeled_non_genesis_fresh_runner_input_for_stop(StopCondition::Observation(
        ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
            execution_quanta: 1,
        },
    ));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: Vec::new(),
            replay_decisions: VecDeque::from([Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            })]),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("execution-bound candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("execution-bound candidate must be observable")
    };
    let (_, _, _, triage) = evidence.into_parts();
    let (failures, causal_entries, _, _, _) = triage.into_parts();
    let timeouts = failures
        .iter()
        .filter_map(|failure| match failure {
            crucible::FailureClusterReportFailure::Timeout(timeout) => Some(timeout),
            crucible::FailureClusterReportFailure::Property(_)
            | crucible::FailureClusterReportFailure::Divergence(_) => None,
        })
        .collect::<Vec<_>>();
    let [timeout] = timeouts.as_slice() else {
        panic!("execution-bound replay must retain exactly one timeout source")
    };

    assert_eq!(
        timeout.budget_kind,
        crucible::FailureTimeoutBudgetKind::ExecutionQuanta
    );
    assert_eq!(timeout.configured_limit, Some(1));
    assert_eq!(timeout.observed_quanta, 1);
    assert!(causal_entries.iter().any(|entry| {
        entry.event_payload().kind() == "execution_budget_exhausted"
            && entry.event_payload().string("budget_kind") == Some("execution-quanta")
    }));
}

#[test]
fn property_failure_precedes_a_coincident_execution_quanta_timeout() {
    let assertion = AssertionId::from_name("coincident-timeout-safety");
    let base = modeled_assertion_candidate_input(assertion.clone(), 2);
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let configuration = step(base.start().configuration(), decision.clone());
    let input = finding_candidate_input_with_configuration_and_stop(
        &base,
        configuration,
        StopCondition::ExecutionQuanta(1),
    );
    let candidate = finding_candidate_artifact(&input);
    let final_event = SchedulerEventLogEntry::assertion_state_observation(
        1,
        VirtualTime { ticks: 1 },
        assertion,
        AssertionPhase::Violated,
    );
    let mut runner = QemuFreshExecutionRunner::new(
        BoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: vec![final_event],
            replay_decisions: VecDeque::from([decision]),
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("coincident property and timeout candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
        panic!("coincident property and timeout candidate must be observable")
    };
    let (_, _, _, triage) = evidence.into_parts();
    let (failures, _, _, _, _) = triage.into_parts();

    assert!(matches!(
        failures.as_slice(),
        [
            crucible::FailureClusterReportFailure::Property(_),
            crucible::FailureClusterReportFailure::Timeout(_)
        ]
    ));
}

#[test]
fn fresh_paired_replay_keeps_selected_evidence_and_both_distinct_coverages_coherent() {
    let fork_entry = |sequence, label: &'static [u8]| {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            String::from("from_checkpoint_id"),
            EventAttributeValue::String(crucible::ContentHash::from_bytes(label).to_hex()),
        );
        attributes.insert(
            String::from("schedule_delta"),
            EventAttributeValue::String(
                crucible::ContentHash::from_bytes(&[label, b"-schedule"].concat()).to_hex(),
            ),
        );
        condition_open_payload_entry_for_test(
            sequence,
            VirtualTime { ticks: 1 },
            SchedulerEventLogClass::Causal,
            EventPayload::new("fork", attributes.clone()),
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "paired-fork",
                EventLevel::Info,
                attributes,
            )),
        )
    };
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    let properties =
        Properties::from_assertions_for_world(&world, Vec::new()).expect("empty property set");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0xa2b0_c0d0),
    )
    .expect("paired replay scenario");
    let input = modeled_fresh_runner_input_for_scenario(scenario, StopCondition::NextChoice);
    let candidate = finding_candidate_artifact(&input);
    let expected_event = condition_observation_entry_for_test(
        0,
        &ObservableEvent::coverage_marker(
            Icount { retired: 1 },
            NodeId {
                name: String::from("paired-node"),
            },
            MarkerId::from_name("expected-path"),
        ),
    );
    let reproduced_event = condition_observation_entry_for_test(
        0,
        &ObservableEvent::coverage_marker(
            Icount { retired: 1 },
            NodeId {
                name: String::from("paired-node"),
            },
            MarkerId::from_name("reproduced-path"),
        ),
    );
    let expected_boundary = fork_entry(1, b"expected-fork");
    let reproduced_boundary = fork_entry(1, b"reproduced-fork");
    let mut runner = QemuFreshExecutionRunner::new(
        SequencedBoundaryCaptureLifecycleFactory {
            captured: Arc::new(Mutex::new(Vec::new())),
            final_events: VecDeque::from([
                vec![expected_event, expected_boundary],
                vec![reproduced_event, reproduced_boundary],
            ]),
            replay_decisions: VecDeque::new(),
        },
        QemuFreshModeledDriver::new(),
    );
    let context = fresh_runner_context();

    let expected = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("expected candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(expected) = expected else {
        panic!("expected replay must reach the candidate boundary")
    };
    let expected_coverage = expected.replay().coverage().clone();
    let reproduced = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &context)
        .expect("reproduced candidate replay");
    let QemuFindingCandidateReplayOutcome::Observed(reproduced) = reproduced else {
        panic!("reproduced replay must reach the candidate boundary")
    };
    let (_, _, _, expected_triage) = (*expected).clone().into_parts();
    let (_, _, _, reproduced_triage) = (*reproduced).clone().into_parts();
    let (_, expected_causal, _, _, _) = expected_triage.into_parts();
    let (_, reproduced_causal, _, _, _) = reproduced_triage.into_parts();
    assert_ne!(expected_causal, reproduced_causal);
    let reproduced = Box::new((*reproduced).compare_against_expected_replay(&expected));
    let reproduced_coverage = reproduced
        .paired_reproduced_coverage()
        .expect("paired replay retains reproduced coverage")
        .clone();
    let (selected_replay, _, selected_events, triage) = (*reproduced).into_parts();
    let (failures, causal_entries, coverage_fingerprint, _, paired_logs) = triage.into_parts();

    assert_ne!(expected_coverage, reproduced_coverage);
    assert_eq!(selected_replay.coverage(), &expected_coverage);
    assert_eq!(selected_events.len(), 2);
    assert_eq!(causal_entries, selected_events);
    assert_eq!(
        coverage_fingerprint,
        crucible::coverage_fingerprint_from_event_log(&selected_events)
    );
    assert!(matches!(
        failures.as_slice(),
        [crucible::FailureClusterReportFailure::Divergence(_)]
    ));
    assert!(paired_logs.is_some());
}

#[test]
fn replay_divergence_uses_the_actual_first_causal_log_mismatch() {
    let expected = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "execution-quanta",
    )];
    let reproduced = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "virtual-time",
    )];
    let comparison = crucible::compare_event_log_determinism(&expected, &reproduced);
    let mismatch = comparison.mismatch().expect("actual causal mismatch");
    let expected_point = mismatch.first_location().expect("mismatch coordinate");
    let expected_coverage = ContentHash::from_bytes(b"expected-replay-coverage");
    let reproduced_coverage = ContentHash::from_bytes(b"reproduced-replay-coverage");
    let expected_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            expected.clone(),
            expected_coverage,
            vec![b"expected-frame".to_vec()],
        );
    let reproduced_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            reproduced.clone(),
            reproduced_coverage,
            vec![b"reproduced-frame".to_vec()],
        );

    let (triage, selected_expected) = crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
        &expected_inputs,
        &reproduced_inputs,
    )
    .expect("divergence triage inputs");
    let (failures, causal_entries, coverage_fingerprint, frames, paired_logs) = triage.into_parts();
    let [crucible::FailureClusterReportFailure::Divergence(divergence)] = failures.as_slice()
    else {
        panic!("mismatched causal logs must retain one divergence source")
    };

    assert!(selected_expected);
    assert_eq!(divergence.raw_index, expected_point.raw_index);
    assert_eq!(divergence.kind, expected_point.kind);
    assert!(
        divergence.expected_state_summary.contains(
            &mismatch
                .expected_entry
                .as_ref()
                .expect("expected mismatch entry")
                .content_hash()
                .to_hex()
        )
    );
    assert!(
        divergence.reproduced_state_summary.contains(
            &mismatch
                .reproduced_entry
                .as_ref()
                .expect("reproduced mismatch entry")
                .content_hash()
                .to_hex()
        )
    );
    assert_eq!(causal_entries, expected);
    assert_eq!(coverage_fingerprint, expected_coverage);
    assert_eq!(frames, [b"expected-frame".to_vec()]);
    assert_eq!(paired_logs, Some((expected, reproduced)));
}

#[test]
fn replay_divergence_uses_reproduced_evidence_when_expected_entry_is_absent() {
    let expected = Vec::new();
    let reproduced = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 9 },
        "execution-quanta",
    )];
    let expected_coverage = ContentHash::from_bytes(b"empty-expected-replay-coverage");
    let reproduced_coverage = ContentHash::from_bytes(b"present-reproduced-replay-coverage");
    let expected_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            expected.clone(),
            expected_coverage,
            vec![b"empty-expected-frame".to_vec()],
        );
    let reproduced_inputs =
        crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::replay_for_test(
            reproduced.clone(),
            reproduced_coverage,
            vec![b"present-reproduced-frame".to_vec()],
        );

    let (triage, selected_expected) = crate::qemu_campaign_driver::QemuFindingCandidateTriageInputs::from_replay_determinism_mismatch(
        &expected_inputs,
        &reproduced_inputs,
    )
    .expect("divergence triage inputs");
    let (_, causal_entries, coverage_fingerprint, frames, paired_logs) = triage.into_parts();

    assert!(!selected_expected);
    assert_eq!(causal_entries, reproduced);
    assert_eq!(coverage_fingerprint, reproduced_coverage);
    assert_eq!(frames, [b"present-reproduced-frame".to_vec()]);
    assert_eq!(paired_logs, Some((expected, reproduced)));
}

#[test]
fn composed_candidate_replay_retains_app_random_choice_and_measurement_leaf() {
    let assertion = AssertionId::from_name("app-random-candidate-safety");
    let base = modeled_assertion_candidate_input_with_vm(assertion.clone(), 2);
    let selectable = AppRandomSelectable::new(
        &base.scenario().scenario_def(),
        NodeId {
            name: String::from("node-a"),
        },
        RngStreamId::for_node("finding-replay-app-random"),
        11,
        16,
    )
    .expect("app-random selectable");
    let selection = selectable
        .sampled_selection(0x1234_5678_9abc_def0)
        .expect("app-random sampled selection");
    let discovery = selectable.into_discovery().expect("app-random discovery");
    let configuration = Configuration {
        def: base.scenario().scenario_def(),
        schedule: Schedule::empty()
            .appended(Decision::Selection(SelectionDecision::new(&selection))),
    };
    let input = finding_candidate_input_with_configuration(&base, configuration);

    assert_composed_candidate_replay_retains_choice_and_measurement(
        input, discovery, selection, &assertion,
    );
}

#[test]
fn composed_candidate_replay_retains_signal_fault_choice_and_measurement_leaf() {
    let assertion = AssertionId::from_name("signal-fault-candidate-safety");
    let base = modeled_assertion_candidate_input_with_vm(assertion.clone(), 2);
    let parent = Configuration::genesis(base.scenario().scenario_def());
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"finding-replay-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"finding-replay-signal-candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let frontier = SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime { ticks: 17 },
        choices: SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    };
    let selectable =
        SignalFaultSelectable::from_frontier(&frontier).expect("signal-fault selectable");
    let selection = selectable
        .branch_selection(&parent, 2)
        .expect("signal-fault selection");
    let discovery = selectable.discovery().expect("signal-fault discovery");
    let configuration = selectable
        .resolve_branch(&selection)
        .expect("signal-fault branch")
        .selected()
        .clone();
    let input = finding_candidate_input_with_configuration(&base, configuration);

    assert_composed_candidate_replay_retains_choice_and_measurement(
        input, discovery, selection, &assertion,
    );
}

#[test]
fn finding_candidate_replay_reports_preserving_and_nonpreserving_verdicts() {
    let assertion = AssertionId::from_name("candidate-safety");

    for (predicate_at, expected) in [(1, PropertyVerdict::Passed), (2, PropertyVerdict::Failed)] {
        let input = modeled_assertion_candidate_input(assertion.clone(), predicate_at);
        let candidate = finding_candidate_artifact(&input);
        let final_event = SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            assertion.clone(),
            AssertionPhase::Satisfied,
        );
        let mut runner = QemuFreshExecutionRunner::new(
            BoundaryCaptureLifecycleFactory {
                captured: Arc::new(Mutex::new(Vec::new())),
                final_events: vec![final_event],
                replay_decisions: VecDeque::new(),
            },
            QemuFreshModeledDriver::new(),
        );

        let outcome = runner
            .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
            .expect("candidate assertion replay");
        let QemuFindingCandidateReplayOutcome::Observed(evidence) = outcome else {
            panic!("materializable candidate must produce semantic evidence")
        };
        let actual = evidence
            .replay()
            .properties()
            .properties()
            .get(assertion.name.as_str())
            .expect("candidate assertion verdict")
            .verdict();

        assert_eq!(actual, expected);
        assert_eq!(evidence.final_events().len(), 1);
    }
}

#[test]
fn finding_candidate_replay_reports_prefix_divergence_after_cleanup() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("incompatible replay is a modeled outcome");

    assert_eq!(
        outcome,
        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
            QemuFindingCandidateIncompatibility::PrefixDiverged,
        )
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_reports_terminal_prefix_after_cleanup() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let input = non_genesis_fresh_runner_input_with_decisions(vec![decision.clone(), decision]);
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: true,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let outcome = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect("terminal prefix is a modeled incompatibility");

    assert_eq!(
        outcome,
        QemuFindingCandidateReplayOutcome::DeterministicallyIncompatible(
            QemuFindingCandidateIncompatibility::PrefixTerminated,
        )
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_preserves_cleanup_failure_over_incompatibility() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));
    let candidate = finding_candidate_artifact(&input);
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let error = runner
        .replay_finding_candidate_boundary(&input, &candidate, None, &fresh_runner_context())
        .expect_err("cleanup failure overrides deterministic incompatibility");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner { .. })
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn finding_candidate_replay_shares_cancellation_and_still_cleans_up() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let input = non_genesis_fresh_runner_input();
    let candidate = finding_candidate_artifact(&input);
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        QemuFreshModeledDriver::new(),
    );

    let error = runner
        .replay_finding_candidate_boundary(
            &input,
            &candidate,
            None,
            &context(resources(4), cancellation),
        )
        .expect_err("canceled candidate replay remains operational failure");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Canceled
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}

struct PreparedSemanticResultRunner {
    result: Option<PreparedSemanticAttemptResult>,
}

impl CrucibleExecutionRunner for PreparedSemanticResultRunner {
    type Error = Infallible;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let result = self
            .result
            .take()
            .expect("prepared semantic fixture executes once");
        Ok(CrucibleExecutionOutcome::new(
            AttemptExecutionProduct::PreparedSemantic(Box::new(result)),
            CrucibleMaterializationTier::ThinReplay,
        ))
    }
}

#[test]
fn terminal_evidence_runner_rejects_previous_attempt_samples_after_a_factory_reset() {
    let input = modeled_fresh_runner_input_for_stop(StopCondition::ExecutionQuanta(1));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let factory = BoundaryCaptureLifecycleFactory {
        captured: Arc::clone(&captured),
        final_events: Vec::new(),
        replay_decisions: VecDeque::new(),
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(factory);
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver::new());
    let mut first = QemuTerminalEvidenceExecutionRunner::new(runner, evidence.clone());
    let first_outcome = first
        .execute(&input, &fresh_runner_context())
        .expect("first attempt publishes terminal evidence");
    let AttemptExecutionProduct::PreparedSemantic(first_result) = first_outcome.product() else {
        panic!("first attempt must produce a prepared semantic result")
    };
    assert!(first_result.terminal_fingerprints().is_some());

    let next_result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
        first_result.observation().clone(),
        first_result.measurement_replay_evidence().to_vec(),
        first_result.finding().cloned(),
    )
    .expect("next prepared result without terminal evidence");
    let resetting_factory = QemuObservedFreshAttemptLifecycleFactory::with_shared_evidence(
        BoundaryCaptureLifecycleFactory {
            captured,
            final_events: Vec::new(),
            replay_decisions: VecDeque::new(),
        },
        evidence.clone(),
    );
    resetting_factory
        .prepare_observation(input.scenario())
        .expect("new fast-tier attempt resets per-worker evidence");
    assert_eq!(
        evidence
            .snapshot()
            .expect("reset evidence snapshot")
            .terminal_fingerprints(),
        None
    );

    let inner = PreparedSemanticResultRunner {
        result: Some(next_result),
    };
    let mut next = QemuTerminalEvidenceExecutionRunner::new(inner, evidence);
    let error = next
        .execute(&input, &fresh_runner_context())
        .expect_err("the next attempt cannot reuse the previous terminal set");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuTerminalEvidenceExecutionRunnerError::MissingTerminalFingerprints
        )
    ));
}

#[test]
fn fresh_runner_rejects_resume_origin_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        3,
        b"fresh-runner-resume-origin",
    ))
    .expect("exact checkpoint fixture");
    let resumed = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let error = runner
        .execute(&fresh_runner_input(), &resumed)
        .expect_err("fresh runner must reject a resume origin");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::ResumeCheckpointUnsupported(actual)
        ) if actual == checkpoint
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_rejects_unconsumed_continuation_input_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let continuation_input = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation(Some(continuation_input));

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("default factory must reject modeled continuation input");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::ContinuationInputUnsupported)
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_rejects_continuation_without_exact_virtual_time_source() {
    assert_invalid_continuation_source(StopCondition::ExecutionQuanta(1));
}

#[test]
fn fresh_runner_rejects_continuation_at_a_different_virtual_time() {
    assert_invalid_continuation_source(StopCondition::VirtualTimeNanoseconds(2));
}

#[test]
fn continuation_accepts_an_authenticated_observation_source_frontier() {
    let condition = ObservationCondition::SchedulerQuiescent;
    let proof = ObservationStopProof::new(
        condition.clone(),
        ObservationStopSatisfaction::SchedulerQuiescent,
        ConfigurationId::from_hash(CampaignHash::derive(
            "continuation-observation-source",
            b"child",
        )),
        ObservationQuantumBoundary::new(1, 0, 1, 0).expect("observation source boundary"),
        ObservationEventLogProof::new(
            CampaignHash::derive("continuation-observation-source", b"prefix"),
            None,
            0,
            0,
            CampaignHash::derive("continuation-observation-source", b"digest"),
        ),
        None,
    )
    .expect("quiescent source proof");
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation_source_evidence(
        continuation,
        StopCondition::Observation(condition),
        StopOutcome::ObservationReached(Box::new(proof)),
    );

    let controls = validated_attempt_continuations(&input)
        .unwrap_or_else(|()| panic!("authenticated observation source should validate"));

    assert_eq!(controls.len(), 1);
    assert_eq!(controls[0].input().source_frontier_ticks(), 1);
}

#[test]
fn continuation_rejects_a_terminally_preempted_source_stop() {
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) = selected_after_genesis_input_with_continuation_source_evidence(
        continuation,
        StopCondition::VirtualTimeNanoseconds(1),
        StopOutcome::TerminalSuccess,
    );

    assert!(validated_attempt_continuations(&input).is_err());
}

fn assert_invalid_continuation_source(source_stop: StopCondition) {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        ContinuationAcceptingFreshLifecycleFactory {
            inner: FakeFreshLifecycleFactory {
                order: Arc::clone(&order),
                cleanup_error: false,
                terminal_after_replay: false,
                checkpoint_ready: true,
            },
            continuations: Arc::new(Mutex::new(Vec::new())),
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let continuation = AttemptContinuationInput::scheduler_reseed(
        test_continuation_source_observation(),
        1,
        [0x5a; 32],
    );
    let (input, _, _) =
        selected_after_genesis_input_with_continuation_source_stop(continuation, source_stop);

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("invalid source must not admit continuation control");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::InvalidContinuationInput)
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_replays_supported_non_genesis_start_before_driver() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input();
    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("fresh runner must replay a supported non-genesis start");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn fresh_runner_replays_authenticated_signal_fault_plan_before_driver() {
    let base = fresh_runner_input();
    let CrucibleResolvedAttemptStart::Discover {
        configuration: parent,
    } = base.start()
    else {
        panic!("fresh runner fixture should discover genesis");
    };
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"fresh-runner-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"fresh-runner-signal-candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let selectable = SignalFaultSelectable::from_frontier(&SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime::default(),
        choices: SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(Decision::Override),
        ),
    })
    .expect("fresh runner signal selectable");
    let selection = selectable
        .branch_selection(parent, 1)
        .expect("fresh runner signal selection");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("fresh runner signal branch");
    let replay = crucible::SignalFaultCampaignReplayPlan::new(
        branch.selected().clone(),
        vec![branch.clone()],
    )
    .expect("fresh runner signal replay plan");
    let input = non_genesis_fresh_runner_input_with_decisions(branch.decisions().to_vec())
        .with_test_signal_fault_replay(replay);
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let outcome = runner
        .execute(&input, &fresh_runner_context())
        .expect("typed signal-fault replay should reach the modeled driver");

    assert!(matches!(
        outcome.product(),
        AttemptExecutionProduct::ExactCheckpoint(_)
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "drive", "shutdown", "seal"]
    );
}

#[test]
fn fresh_replay_applies_campaign_selection_at_exact_guest_request() {
    let node = NodeId {
        name: String::from("router-a"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guest-selectable-replay-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("guest selectable replay World");
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .expect("guest selectable declaration");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32).expect("selectable limits"),
        vec![declaration.clone()],
    )
    .expect("scenario selectables");
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(17),
    )
    .expect("guest selectable replay scenario")
    .with_selectables(selectables)
    .expect("attach guest selectables");
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let parent = Configuration::genesis(source.scenario_def());
    let request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("guest request");
    let pending = SelectablePlanPendingRequest::new(request, 41, 0, 0x1000);
    let discovery =
        crate::guest_selectable::resolve_guest_selectable(scenario, &source, &node, &pending)
            .expect("runtime opportunity");
    let default_selection = Selection::new(
        discovery.opportunity(),
        discovery.domain(),
        discovery.opportunity().default().clone(),
        crucible_campaign::SelectionOrigin::Default,
    )
    .expect("default guest selection");
    let default_target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&default_selection)),
    );
    assert_eq!(
        unsupported_fresh_replay_decision(
            &default_target,
            &crucible::SignalFaultCampaignReplayPlan::empty(default_target.clone()),
        ),
        None,
        "the runner prefilter must admit default guest replay"
    );
    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let selection = Selection::new_campaign_branch(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Boolean(true),
        discovery.opportunity().branch_point_id(parent_id),
    )
    .expect("campaign selection");
    let target = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "guest-selectable-replay-diagnostic",
            1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(discovery.domain())
        .expect("publish guest choice domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish guest selectable declaration");
    repository
        .publish_choice_opportunity(discovery.opportunity())
        .expect("publish guest choice opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish guest selection");
    let resolved_selection = repository
        .resolve_selection(selection.id().expect("guest selection ID"))
        .expect("resolve guest selection");
    let replay_start = CrucibleResolvedAttemptStart::Branch {
        parent: parent.clone(),
        selection: Box::new(resolved_selection),
        selected: target.clone(),
    };
    assert!(
        replay_start.replay_selection(1).is_none(),
        "expected context must not attach to an unrelated decision index"
    );
    let base_attempt = fresh_runner_input();
    let AttemptStart::Discover {
        configuration: parent_artifact,
    } = base_attempt.attempt().start()
    else {
        panic!("guest branch fixture must start from discovery")
    };
    let SelectionOrigin::CampaignBranch { branch_point, edge } = selection.origin() else {
        panic!("guest replay selection must be a campaign branch")
    };
    let replay_path = BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)])
        .expect("guest replay branch path");
    let replay_attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: parent_artifact,
            selection: selection.id().expect("guest replay selection ID"),
        },
        replay_path.id().expect("guest replay branch path ID"),
        StopCondition::Terminal,
    )
    .expect("guest replay branch attempt");
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(node, pending),
        ],
        replies: Arc::clone(&replies),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let mut current = parent.clone();
    let diagnostic_config = crate::GuestSelectableBoundaryDiagnosticConfig::new(4)
        .expect("guest-selectable diagnostic policy");
    let (diagnostics, diagnostic_lines) =
        crate::guest_selectable::GuestSelectableBoundaryDiagnosticRecorder::capture(
            diagnostic_config,
        );
    let execution_context =
        fresh_runner_context().with_guest_selectable_boundary_diagnostics(diagnostics);
    let mut materialization = QemuFreshStartMaterialization::genesis();
    apply_replayed_guest_selectables::<(), ()>(
        &mut lifecycle,
        &execution_context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: &replay_attempt,
            start: &replay_start,
        },
        scenario,
        &source,
        &target,
        &mut current,
        &mut materialization,
    )
    .expect("exact guest branch replay");

    assert_eq!(current, target);
    let replies = replies.lock().expect("fresh lifecycle replies");
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].selected_value(),
        Some(ChoiceValue::Boolean(true).canonical_bytes().as_slice())
    );
    {
        let diagnostic_lines = diagnostic_lines.lock().expect("boundary diagnostics");
        assert_eq!(diagnostic_lines.len(), 1);
        assert!(diagnostic_lines[0].contains("stage=replay"));
        assert!(diagnostic_lines[0].contains("decision_index=0"));
        assert!(diagnostic_lines[0].contains("trap_icount=41 stopped_icount=42 vcpu=0"));
        assert!(
            diagnostic_lines[0]
                .contains("expected_opportunity=crucible.campaign.choice-opportunity@")
        );
    }

    let drift_request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("drifted guest request");
    let drift_pending = SelectablePlanPendingRequest::new(drift_request, 42, 0, 0x1000);
    let drift_replies = Arc::new(Mutex::new(Vec::new()));
    let mut drift_lifecycle = FakeFreshLifecycle {
        order: Arc::new(Mutex::new(Vec::new())),
        completed_quanta: 0,
        promotion_observations: None,
        cleanup_error: false,
        pending: vec![
            crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
                NodeId {
                    name: String::from("router-a"),
                },
                drift_pending,
            ),
        ],
        replies: Arc::clone(&drift_replies),
        signal_fault_branches: VecDeque::new(),
        terminal_after_replay: false,
        checkpoint_ready: true,
        fingerprint_error: false,
        fingerprint_node_override: Arc::new(Mutex::new(None)),
    };
    let mut drift_current = parent.clone();
    let mut drift_materialization = QemuFreshStartMaterialization::genesis();

    let failure = apply_replayed_guest_selectables::<std::io::Error, std::io::Error>(
        &mut drift_lifecycle,
        &execution_context,
        GuestSelectableReplayContext {
            phase: GuestSelectableReplayPhase::FreshStart,
            attempt_role: GuestSelectableReplayAttemptRole::ExecutingAttempt,
            attempt: &replay_attempt,
            start: &replay_start,
        },
        scenario,
        &source,
        &target,
        &mut drift_current,
        &mut drift_materialization,
    )
    .expect_err("drifted runtime opportunity must fail replay");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::GuestSelectable(GuestSelectableError::ReplayMismatch(mismatch)),
    )) = &failure
    else {
        panic!("replay mismatch must retain its typed production error chain")
    };
    assert_eq!(
        finding_candidate_incompatibility(&failure),
        Some(QemuFindingCandidateIncompatibility::SelectionMismatch)
    );
    assert_eq!(
        mismatch.mismatch().kind(),
        SelectionReplayMismatchKind::OpportunityIdentity
    );
    assert_eq!(mismatch.phase(), GuestSelectableReplayPhase::FreshStart);
    assert_eq!(
        mismatch.attempt_role(),
        GuestSelectableReplayAttemptRole::ExecutingAttempt
    );
    assert_eq!(
        mismatch.attempt(),
        replay_attempt.id().expect("replay attempt identity")
    );
    assert_eq!(
        mismatch.replayed_configuration(),
        ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes))
    );
    assert_eq!(mismatch.decision_index(), 0);
    assert_eq!(mismatch.node(), "router-a");
    assert_eq!(mismatch.selectable(), "product.recovery");
    assert_eq!(mismatch.request_instance(), "routing-epoch-7");
    assert_eq!(mismatch.request_sequence(), 9);
    assert_eq!(mismatch.request_icount(), 42);
    assert_eq!(mismatch.request_vcpu_index(), 0);
    let expected_opportunity = mismatch
        .expected_opportunity()
        .expect("branch start retains expected opportunity context");
    assert_eq!(
        expected_opportunity.declaration(),
        discovery.opportunity().declaration()
    );
    assert_eq!(
        expected_opportunity.coordinate(),
        discovery.opportunity().coordinate()
    );
    assert_eq!(expected_opportunity.instance(), "routing-epoch-7");
    assert_eq!(
        mismatch.replayed_opportunity().instance(),
        "routing-epoch-7"
    );
    assert_eq!(drift_current, parent);
    assert!(drift_replies.lock().expect("drift replies").is_empty());

    let execution = ExecutionId::from_bytes([0x39; 16]).expect("execution identity");
    let diagnostic =
        crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(execution, &failure);
    assert!(diagnostic.contains("phase=fresh-start"));
    assert!(diagnostic.contains("attempt-role=executing-attempt"));
    assert!(diagnostic.contains("failed-predicate=selection-opportunity-identity"));
    assert!(diagnostic.contains("decision-index=0"));
    assert!(diagnostic.contains("request-sequence=9"));
    assert!(diagnostic.contains("request-icount=42"));
    assert!(diagnostic.contains("request-vcpu=0"));
    assert!(diagnostic.contains("expected-declaration="));
    assert!(diagnostic.contains("expected-choice-scheduler-coordinate="));

    let oversized = crate::packaged_qemu_executor::packaged_attempt_failure_diagnostic(
        execution,
        &OversizedFailure { source: failure },
    );
    assert!(oversized.contains("phase=fresh-start"));
    assert!(oversized.contains("attempt-role=executing-attempt"));
    assert!(oversized.contains("failed-predicate=selection-opportunity-identity"));
    assert!(oversized.ends_with("\n  ... diagnostic truncated"));
    assert!(
        oversized.len()
            <= crate::packaged_qemu_executor::MAX_PACKAGED_ATTEMPT_FAILURE_DIAGNOSTIC_BYTES
    );
}

#[test]
fn fresh_runner_replay_divergence_cleans_up_without_calling_driver() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 8,
    }));

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("drifted replay prefix must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Diverged
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_replay_honors_cancellation_before_first_quantum() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let cancellation = ExecutionCancellation::default();
    cancellation.cancel_for_test();

    let error = runner
        .execute(
            &non_genesis_fresh_runner_input(),
            &context(resources(4), cancellation),
        )
        .expect_err("canceled replay must fail before a scheduler quantum");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Canceled(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::Canceled
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "shutdown"]
    );
}

#[test]
fn fresh_runner_replay_is_bounded_by_admitted_quanta() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    });
    let input = non_genesis_fresh_runner_input_with_decisions(vec![decision.clone(), decision]);

    let error = runner
        .execute(
            &input,
            &context(resources(1), ExecutionCancellation::default()),
        )
        .expect_err("replay must not exceed the attempt quantum ceiling");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
            QemuFreshStartReplayError::ResourceRefusal(_)
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn fresh_runner_rejects_producer_override_before_factory_invocation() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input =
        non_genesis_fresh_runner_input_with_decision(Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::from_name("fresh-runner-override"),
            request_id: 1,
            width: 8,
            value: 7,
        }));
    let expected = match input.start() {
        CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
        CrucibleResolvedAttemptStart::Branch { .. }
        | CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
            panic!("expected discovery fixture")
        }
    };

    let error = runner
        .execute(&input, &fresh_runner_context())
        .expect_err("producer override must fail before fresh lifecycle construction");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                configuration,
                decision: 0,
            }
        ) if configuration == expected
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn attempt_start_verifier_seals_the_prefix_before_final_drain() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input();
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"ordinary-attempt-start-proof",
    ))
    .expect("resume checkpoint");
    let resume_context = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let proof = runner
        .verify_attempt_start(&input, &resume_context)
        .expect("cold-replayed attempt-start prefix");

    assert_eq!(
        proof.attempt_event_count(input.start().configuration(), &[]),
        Some(0)
    );
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "replay", "shutdown"]
    );
}

#[test]
fn attempt_start_verifier_rejects_unsupported_event_count_start_before_factory() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );
    let input = non_genesis_fresh_runner_input_with_decisions_for_stop(
        vec![Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::from_name("event-count-resume-override"),
            request_id: 1,
            width: 8,
            value: 7,
        })],
        StopCondition::EventCount(4),
    );
    let expected = input.start().configuration().id();
    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"unsupported-event-count-start",
    ))
    .expect("resume checkpoint");
    let resume_context = fresh_runner_context().with_resume_checkpoint(Some(checkpoint));

    let error = runner
        .verify_attempt_start(&input, &resume_context)
        .expect_err("unsupported EventCount start must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshExecutionRunnerError::StartDecisionUnsupported {
                configuration,
                decision: 0,
            }
        ) if configuration == expected
    ));
    assert!(order.lock().expect("fresh lifecycle order").is_empty());
}

#[test]
fn fresh_runner_cleans_up_and_preserves_driver_failure_classification() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: Some(FakeFreshDriverFailure::Retryable),
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("driver retry should remain classified");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Retryable(QemuFreshExecutionRunnerError::Driver("driver retry"))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
}

#[test]
fn fresh_runner_cleans_up_after_terminal_fingerprint_capture_failure() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let failing = FingerprintFailingFreshLifecycleFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: false,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(failing);
    let mut runner = QemuFreshExecutionRunner::new(
        factory,
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("missing terminal fingerprint authority must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::TerminalFingerprintCapture(
            SchedulerError::BoundaryViolation { .. }
        ))
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
    assert_eq!(
        evidence
            .snapshot()
            .expect("evidence after capture failure")
            .terminal_fingerprints(),
        None
    );
}

#[test]
fn cleanup_failure_overrides_terminal_fingerprint_capture_failure() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let failing = FingerprintFailingFreshLifecycleFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
    };
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(failing);
    let mut runner = QemuFreshExecutionRunner::new(
        factory,
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: None,
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("cleanup failure must retain precedence");

    let AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterRunner {
        failure,
        ..
    }) = error
    else {
        panic!("cleanup failure must retain the prior capture failure");
    };
    assert!(matches!(
        *failure,
        QemuFreshExecutionRunnerError::TerminalFingerprintCapture(
            SchedulerError::BoundaryViolation { .. }
        )
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
    assert_eq!(
        evidence
            .snapshot()
            .expect("evidence after cleanup failure")
            .terminal_fingerprints(),
        None
    );
}

#[test]
fn fresh_cleanup_failure_overrides_driver_retry_and_retains_diagnostics() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = QemuFreshExecutionRunner::new(
        FakeFreshLifecycleFactory {
            order: Arc::clone(&order),
            cleanup_error: true,
            terminal_after_replay: false,
            checkpoint_ready: true,
        },
        FakeFreshDriver {
            order: Arc::clone(&order),
            failure: Some(FakeFreshDriverFailure::Retryable),
        },
    );

    let error = runner
        .execute(&fresh_runner_input(), &fresh_runner_context())
        .expect_err("cleanup failure must take precedence");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::CleanupAfterDriver {
            driver: "driver retry",
            ..
        })
    ));
    assert_eq!(
        order.lock().expect("fresh lifecycle order").as_slice(),
        ["begin", "drive", "shutdown"]
    );
}

#[test]
fn production_lifecycle_resource_admission_keeps_retry_and_cancel_classes() {
    let unavailable = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::ExecutorUnavailable {
                operation: "install test resources",
                message: String::from("temporarily unavailable"),
            },
        ),
    );
    assert!(matches!(unavailable, AttemptWorkerFailure::Retryable(_)));

    let canceled = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ResourceInstallation(
            QemuVmRealizationError::Canceled {
                operation: "install test resources",
            },
        ),
    );
    assert!(matches!(canceled, AttemptWorkerFailure::Canceled(_)));

    let terminal = classify_production_lifecycle_failure(
        QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch,
    );
    assert!(matches!(terminal, AttemptWorkerFailure::Terminal(_)));
}

#[test]
fn production_continuation_plan_consumes_the_authenticated_reseed() {
    let input = fresh_runner_input();
    let source = step(
        input.start().configuration(),
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("continuation-plan-source"),
            value: 7,
        }),
    );
    let frontier = VirtualTime { ticks: 37 };
    let seed = Seed::from_u64(0x51ec_7ed0);
    let continuation = OwnedQemuAttemptContinuation {
        input: AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation(),
            frontier.ticks,
            seed.bytes(),
        ),
        source: source.clone(),
    };

    let plan = production_continuation_plan(input.scenario(), Some(&continuation))
        .expect("production continuation plan");

    assert_eq!(
        plan,
        ProductionContinuationPlan::Reseed {
            base: source,
            frontier,
            seed,
        }
    );
}
