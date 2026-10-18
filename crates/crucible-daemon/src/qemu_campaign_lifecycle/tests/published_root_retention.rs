//! Thin-attempt world retention at published next-choice boundaries.
//!
//! These tests drive the fresh runner with a scripted lifecycle, factory,
//! and driver so each retention decision is observable: whether the final
//! boundary is drained, which final entries sealing receives, whether a
//! world is prepared, and when a pending root reaches the pool sink.

use crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld;
use crucible_campaign::{ChoiceCoordinate, ChoiceOpportunity};

use super::super::test_support::{Order, RetentionFactory, Script, entry, retention_trace};
use super::*;
use crate::managed_qemu_hot_fork_source_world_pool::test_support::advanced_published_root_source_for_test;
use crate::qemu_hot_fork_source_capture::AuthenticatedPublishedRootQemuHotForkSource;
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, QemuFinalBoundaryDrain,
    QemuHotForkSourceWorldBoundary, QemuHotForkSourceWorldKey, QemuPublishedRootAdmission,
    QemuPublishedRootRetirementError, QemuPublishedRootSink,
};

/// Final entries and effect trace one seal received.
type SealRecord = (Vec<u64>, Option<crucible::model::ResolvedEffectTrace>);

struct RetentionDriver {
    order: Order,
    sealed: Arc<Mutex<Vec<SealRecord>>>,
    boundary: Option<(Configuration, QemuSavepointReplayProof)>,
    product: Option<AttemptExecutionProduct>,
}

impl QemuFreshAttemptDriver for RetentionDriver {
    type Pending = ();
    type Error = &'static str;

    fn retention_boundary(
        &self,
        _pending: &Self::Pending,
    ) -> Result<(Configuration, QemuSavepointReplayProof), &'static str> {
        self.boundary.clone().ok_or("stop-not-next-choice")
    }

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        self.order.lock().expect("retention order").push("drive");
        Ok(QemuFreshDriveOutcome::Observation(()))
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.seal_with_trace(pending, final_events, None)
    }

    fn seal_with_trace(
        &mut self,
        _pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
        resolved_effect_trace: Option<crucible::model::ResolvedEffectTrace>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.order.lock().expect("retention order").push("seal");
        let sequences = final_events.iter().map(|entry| entry.sequence()).collect();
        self.sealed
            .lock()
            .expect("sealed inputs")
            .push((sequences, resolved_effect_trace));
        self.product.take().ok_or(AttemptWorkerFailure::Terminal(
            "retention fixture seals once",
        ))
    }
}

/// Pool sink that records admitted keys and then retires the root.
#[derive(Default)]
struct RecordingRootSink {
    full: bool,
    admitted: Mutex<Vec<QemuHotForkSourceWorldKey>>,
}

impl RecordingRootSink {
    fn admitted(&self) -> Vec<QemuHotForkSourceWorldKey> {
        self.admitted.lock().expect("admitted roots").clone()
    }
}

impl QemuPublishedRootSink for RecordingRootSink {
    fn may_admit(&self) -> bool {
        !self.full
    }

    fn admit(
        &self,
        root: AuthenticatedPublishedRootQemuHotForkSource,
    ) -> Result<QemuPublishedRootAdmission, QemuPublishedRootRetirementError> {
        let (key, _published, source) = root.into_parts();
        self.admitted.lock().expect("admitted roots").push(key);
        source
            .retire()
            .map_err(|error| QemuPublishedRootRetirementError::new(error.to_string()))?;
        Ok(QemuPublishedRootAdmission::Admitted)
    }
}

/// One scripted runner and the handles its assertions read.
struct Fixture {
    runner: QemuFreshExecutionRunner<RetentionFactory, RetentionDriver>,
    order: Order,
    sealed: Arc<Mutex<Vec<SealRecord>>>,
}

impl Fixture {
    fn new(
        script: Script,
        boundary: Option<(Configuration, QemuSavepointReplayProof)>,
        product: AttemptExecutionProduct,
        sink: Option<Arc<RecordingRootSink>>,
    ) -> Self {
        let order = Arc::new(Mutex::new(Vec::new()));
        let sealed = Arc::new(Mutex::new(Vec::new()));
        let runner = QemuFreshExecutionRunner::new(
            RetentionFactory::new(Arc::clone(&order), script),
            RetentionDriver {
                order: Arc::clone(&order),
                sealed: Arc::clone(&sealed),
                boundary,
                product: Some(product),
            },
        );
        let runner = match sink {
            Some(sink) => runner.with_published_root_retention(sink),
            None => runner,
        };
        Self {
            runner,
            order,
            sealed,
        }
    }

    fn order(&self) -> Vec<&'static str> {
        self.order.lock().expect("retention order").clone()
    }

    fn sealed(&self) -> Vec<SealRecord> {
        self.sealed.lock().expect("sealed inputs").clone()
    }
}

fn retention_input() -> CrucibleAttemptExecution {
    fresh_runner_input_for_stop(StopCondition::NextChoice)
}

/// Binds the execution to the input's own lineage, as the executor does.
fn retention_context(input: &CrucibleAttemptExecution) -> AttemptExecutionContext {
    fresh_runner_context().with_runtime_basis(AttemptExecutionRuntimeBasis::new(
        AttemptExecutionKey::new(
            input.lineage().id().expect("lineage id"),
            input.attempt().id().expect("attempt id"),
        ),
        ExecutionId::from_bytes([0x67; 16]).expect("execution id"),
    ))
}

/// Seals the replay proof a prepared world must match at its own boundary.
fn world_boundary(
    world: &ProductionVmHotForkSourceWorld,
) -> (Configuration, QemuSavepointReplayProof) {
    let continuation = world.continuation();
    let proof = QemuSavepointReplayProof::from_checkpoint(
        continuation.configuration(),
        continuation.scheduler(),
        continuation.event_log_segments(),
    )
    .expect("world boundary proof");
    (continuation.configuration().clone(), proof)
}

/// Builds a semantic observation whose child is `boundary` with one discovered choice.
fn published_observation(
    input: &CrucibleAttemptExecution,
    boundary: &Configuration,
) -> AttemptExecutionProduct {
    let name = "published.next-choice";
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(
        input.scenario().scenario_def().id().bytes,
    ));
    let configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(boundary.id().bytes));
    let child = ConfigurationArtifact::new(
        scenario,
        input.lineage().scenario_content(),
        configuration,
        1,
        boundary.id().bytes.to_vec(),
    )
    .expect("published child artifact");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        name,
        ChoiceSource::Scheduler {
            producer: String::from("published-root-next"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("next-choice declaration");
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("published-next-scheduler", name.as_bytes()),
            producer: CampaignHash::derive("published-next-producer", name.as_bytes()),
        },
        name,
        None,
    )
    .expect("next-choice opportunity");
    let opportunity_id = opportunity.id().expect("opportunity id");
    let discovery =
        ChoiceDiscovery::new(declaration, domain, opportunity).expect("next-choice discovery");

    let measurements = MeasurementSet::from_evaluation(
        CampaignHash::derive("crucible.test.measurement-definitions.v1", name.as_bytes()),
        1,
        CampaignHash::derive("crucible.test.measurement-evaluation.v1", name.as_bytes()),
        name.as_bytes().to_vec(),
        BTreeSet::new(),
    )
    .expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        input.attempt().id().expect("attempt id"),
        Observation::outcome(
            child.configuration(),
            child.id().expect("child id"),
            input.path().id().expect("path id"),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements.id().expect("measurement id"),
            properties.id().expect("property id"),
            coverage.id().expect("coverage id"),
        ),
        BTreeSet::from([opportunity_id]),
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
    .expect("observation candidate");

    AttemptExecutionProduct::prepared_semantic(
        PreparedSemanticAttemptResult::new(
            candidate,
            Vec::new(),
            crate::MemorySegmentStore::default(),
            None,
        )
        .expect("prepared observation"),
    )
}

fn observation_disposition(outcome: &CrucibleExecutionOutcome) -> AttemptExecutionDisposition {
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("retention fixtures seal semantic observations")
    };
    AttemptExecutionDisposition::Observation(
        result
            .observation()
            .observation()
            .id()
            .expect("observation id"),
    )
}

#[test]
fn retainable_boundary_seals_what_ordinary_teardown_seals() {
    let input = retention_input();
    let context = retention_context(&input);
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.equivalence",
    ));
    let product = || published_observation(&input, &boundary.0);

    // Without a sink the runner never settles the boundary for retention.
    let mut ordinary = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable),
        Some(boundary.clone()),
        product(),
        None,
    );
    let ordinary_outcome = ordinary
        .runner
        .execute(&input, &context)
        .expect("ordinary thin execution");

    // Preparation declines, so the drained world is shut down unretained.
    let sink = Arc::new(RecordingRootSink::default());
    let mut retained = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable),
        Some(boundary.clone()),
        product(),
        Some(Arc::clone(&sink)),
    );
    let retained_outcome = retained
        .runner
        .execute(&input, &context)
        .expect("thin execution on the retention path");

    assert_eq!(ordinary.order(), ["begin", "drive", "shutdown", "seal"]);
    assert_eq!(
        retained.order(),
        ["begin", "drive", "drain", "seal", "prepare", "shutdown"]
    );
    // CCOMP-21: sealing receives identical inputs on both paths.
    assert_eq!(ordinary.sealed(), retained.sealed());
    assert_eq!(retained.sealed(), [(Vec::new(), Some(retention_trace()))]);
    assert_eq!(
        observation_disposition(&ordinary_outcome),
        observation_disposition(&retained_outcome)
    );
    assert_eq!(
        retained_outcome.materialization(),
        CrucibleMaterializationTier::ThinReplay
    );
    assert!(retained.runner.pending_retention.is_none());
    assert!(sink.admitted().is_empty());
}

#[test]
fn nonempty_final_drain_precedes_shutdown_entries_when_sealing() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.drained",
    ));
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Drained(vec![entry(3), entry(4)]))
            .with_shutdown_events(&[5]),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::new(RecordingRootSink::default())),
    );

    fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect("drained thin execution");

    assert_eq!(
        fixture.order(),
        ["begin", "drive", "drain", "shutdown", "seal"]
    );
    assert_eq!(fixture.sealed(), [(vec![3, 4, 5], Some(retention_trace()))]);
}

#[test]
fn ineligible_final_drain_keeps_ordinary_teardown() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.ineligible",
    ));
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Ineligible(
            "held-guest-selectable-stop",
        ))
        .with_shutdown_events(&[9]),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::new(RecordingRootSink::default())),
    );

    fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect("ineligible thin execution");

    assert_eq!(
        fixture.order(),
        ["begin", "drive", "drain", "shutdown", "seal"]
    );
    assert_eq!(fixture.sealed(), [(vec![9], Some(retention_trace()))]);
}

#[test]
fn unretainable_stops_and_full_pools_never_settle_the_boundary() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.unretainable",
    ));
    let full = Arc::new(RecordingRootSink {
        full: true,
        ..RecordingRootSink::default()
    });

    // The driver reports no retainable stop boundary.
    let mut no_boundary = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).with_shutdown_events(&[2]),
        None,
        published_observation(&input, &boundary.0),
        Some(Arc::new(RecordingRootSink::default())),
    );
    no_boundary
        .runner
        .execute(&input, &retention_context(&input))
        .expect("thin execution without a retainable stop");

    // The pool has no free template slot.
    let mut full_pool = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).with_shutdown_events(&[2]),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(full),
    );
    full_pool
        .runner
        .execute(&input, &retention_context(&input))
        .expect("thin execution with a full pool");

    // An execution bound to no runtime lineage never retains its world.
    let mut unbound = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).with_shutdown_events(&[2]),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::new(RecordingRootSink::default())),
    );
    unbound
        .runner
        .execute(&input, &fresh_runner_context())
        .expect("thin execution without a runtime basis");

    for fixture in [&no_boundary, &full_pool, &unbound] {
        assert_eq!(fixture.order(), ["begin", "drive", "shutdown", "seal"]);
        assert_eq!(fixture.sealed(), [(vec![2], Some(retention_trace()))]);
    }
}

#[test]
fn retention_drain_failure_still_shuts_down_and_fails_cleanup() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.drain-failure",
    ));
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable)
            .failing_drain("injected final drain failure"),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::new(RecordingRootSink::default())),
    );

    let failure = fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect_err("a failed final drain fails the attempt");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Cleanup(
            SchedulerError::BoundaryViolation { .. }
        ))
    ));
    assert_eq!(fixture.order(), ["begin", "drive", "drain", "shutdown"]);
    assert!(fixture.sealed().is_empty());
}

#[test]
fn shutdown_entries_after_an_empty_drain_fail_closed() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.late-entries",
    ));
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).with_shutdown_events(&[6]),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::new(RecordingRootSink::default())),
    );

    let failure = fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect_err("entries after an empty drain could change the sealed product");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::Cleanup(
            SchedulerError::BoundaryViolation { .. }
        ))
    ));
    assert_eq!(
        fixture.order(),
        ["begin", "drive", "drain", "seal", "prepare", "shutdown"]
    );
}

#[test]
fn observation_naming_another_child_is_not_retained() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.child-boundary",
    ));
    let other = world_boundary(&advanced_published_root_source_for_test(
        "retention.other-child",
    ));
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable),
        Some(boundary),
        published_observation(&input, &other.0),
        Some(Arc::new(RecordingRootSink::default())),
    );

    fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect("the sealed product survives a declined retention");

    // Sealing happened before the mismatch was found; no world is prepared.
    assert_eq!(
        fixture.order(),
        ["begin", "drive", "drain", "seal", "shutdown"]
    );
    assert!(fixture.runner.pending_retention.is_none());
}

#[test]
fn prepared_world_at_another_boundary_is_retired() {
    let input = retention_input();
    let boundary = world_boundary(&advanced_published_root_source_for_test(
        "retention.expected-world",
    ));
    let sink = Arc::new(RecordingRootSink::default());
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).preparing(
            advanced_published_root_source_for_test("retention.unexpected-world"),
        ),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::clone(&sink)),
    );

    let outcome = fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect("a mismatched world is retired without failing the attempt");

    assert_eq!(
        fixture.order(),
        ["begin", "drive", "drain", "seal", "prepare"]
    );
    assert!(fixture.runner.pending_retention.is_none());
    assert_eq!(
        fixture
            .runner
            .reconcile_execution(observation_disposition(&outcome))
            .expect("nothing is pending"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert!(sink.admitted().is_empty());
}

#[test]
fn retained_root_reaches_the_pool_only_after_an_observation_disposition() {
    let input = retention_input();
    let world = advanced_published_root_source_for_test("retention.admitted");
    let boundary = world_boundary(&world);
    let sink = Arc::new(RecordingRootSink::default());
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).preparing(world),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::clone(&sink)),
    );

    let outcome = fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect("thin execution keeps its world");
    assert_eq!(
        fixture.order(),
        ["begin", "drive", "drain", "seal", "prepare"]
    );
    assert!(fixture.runner.pending_retention.is_some());
    assert!(sink.admitted().is_empty());

    // The worker reconciles before it accepts another attempt.
    let refused = fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect_err("a pending root blocks the next attempt");
    assert!(matches!(
        refused,
        AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::PriorRetentionPending)
    ));

    assert_eq!(
        fixture
            .runner
            .reconcile_execution(observation_disposition(&outcome))
            .expect("admit the pending root"),
        AttemptExecutionReconciliationStep::Complete
    );
    let admitted = sink.admitted();
    assert_eq!(admitted.len(), 1);
    assert_eq!(
        admitted[0].boundary(),
        QemuHotForkSourceWorldBoundary::PublishedBoundary
    );
    assert_eq!(admitted[0].configuration(), boundary.0.id());
    assert!(fixture.runner.pending_retention.is_none());
}

#[test]
fn rejected_disposition_retires_the_pending_root() {
    let input = retention_input();
    let world = advanced_published_root_source_for_test("retention.failed");
    let boundary = world_boundary(&world);
    let sink = Arc::new(RecordingRootSink::default());
    let mut fixture = Fixture::new(
        Script::new(QemuFinalBoundaryDrain::Retainable).preparing(world),
        Some(boundary.clone()),
        published_observation(&input, &boundary.0),
        Some(Arc::clone(&sink)),
    );
    fixture
        .runner
        .execute(&input, &retention_context(&input))
        .expect("thin execution keeps its world");

    assert_eq!(
        fixture
            .runner
            .reconcile_execution(AttemptExecutionDisposition::Failed)
            .expect("retire the pending root"),
        AttemptExecutionReconciliationStep::Complete
    );
    assert!(sink.admitted().is_empty());
    assert!(fixture.runner.pending_retention.is_none());
}
