//! Hot children forked from an ancestor root replay the recorded suffix.
//!
//! A scripted world advances along a fixed successor map, appending real
//! quantum-boundary entries, so the same attempt can be realized by thin
//! replay from genesis and by a hot child started at an ancestor boundary.

use crucible::{RngDecision, RngStreamId};

use super::*;
use crate::qemu_hot_fork_source_capture::{QemuPublishedRootOrigin, QemuPublishedRootProvenance};
use crate::{QemuFreshAttemptLifecycleFactory, QemuFreshExecutionRunner};

pub(super) fn step(parent: &Configuration, decision: Decision) -> Configuration {
    match crucible::try_step(parent, decision) {
        Ok(configuration) => configuration,
        Err(error) => panic!("test configuration step should be accepted: {error}"),
    }
}

pub(super) fn rng_step(parent: &Configuration, stream: &str, value: u64) -> Configuration {
    step(
        parent,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(stream),
            value,
        }),
    )
}

/// What the attempt's own branch edge selects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Edge {
    Scheduler,
    Guest,
}

/// One branch attempt at `parent`, two quanta past genesis.
pub(super) struct SuffixCase {
    pub(super) input: CrucibleAttemptExecution,
    /// The ancestor root boundary, one quantum past genesis.
    pub(super) anchor: Configuration,
    pub(super) parent: Configuration,
    pub(super) selected: Configuration,
}

pub(super) fn suffix_case(edge: Edge) -> SuffixCase {
    let base = match edge {
        Edge::Guest => execution_input_for_scenario(guest_selectable_scenario()),
        Edge::Scheduler => execution_input(),
    };
    let genesis = Configuration::genesis(base.scenario().scenario_def());
    let anchor = rng_step(&genesis, "ancestor-suffix-first", 3);
    let parent = rng_step(&anchor, "ancestor-suffix-second", 5);

    let (declaration, value) = match edge {
        Edge::Guest => (guest_selectable_declaration(), ChoiceValue::Boolean(true)),
        Edge::Scheduler => (
            SelectableDeclaration::new(
                "scheduler.ancestor-edge",
                ChoiceSource::Scheduler {
                    producer: String::from("ancestor-edge"),
                },
                ChoiceDomain::Boolean(BooleanDomain::new(1).expect("edge domain")),
                ChoiceValue::Boolean(false),
                ChoiceClassContext::new(BTreeSet::new()).expect("edge choice class"),
                BTreeSet::new(),
                true,
            )
            .expect("edge declaration"),
            ChoiceValue::Boolean(true),
        ),
    };
    let domain = declaration.domain().clone();
    let opportunity = match edge {
        Edge::Guest => {
            let pending = branch_replay_guest_pending(&declaration, "publication");
            crate::guest_selectable::resolve_guest_selectable(
                base.lineage().scenario(),
                base.scenario(),
                pending.node(),
                pending.pending(),
            )
            .expect("resolve guest edge opportunity")
            .opportunity()
            .clone()
        }
        Edge::Scheduler => crucible_campaign::ChoiceOpportunity::new(
            base.lineage().scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("ancestor-edge-scheduler", b"edge"),
                producer: CampaignHash::derive("ancestor-edge-producer", b"edge"),
            },
            declaration.name(),
            None,
        )
        .expect("edge opportunity"),
    };

    let parent_id = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
    let branch_point = opportunity.branch_point_id(parent_id);
    let selection = Selection::new_campaign_branch(&opportunity, &domain, value, branch_point)
        .expect("edge selection");
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "ancestor-suffix-edge",
            8 * 1024 * 1024,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    repository
        .publish_choice_domain(&domain)
        .expect("publish edge domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish edge selectable");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish edge opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish edge selection");
    let resolved = repository
        .resolve_selection(selection.id().expect("edge selection id"))
        .expect("resolve edge selection");

    let selected = step(
        &parent,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let SelectionOrigin::CampaignBranch { edge: edge_id, .. } = selection.origin() else {
        panic!("edge selection must be a campaign branch")
    };
    let path =
        BranchPath::new(vec![BranchPathSegment::new(branch_point, edge_id)]).expect("edge path");
    // Replay reaches the selection after two quanta; the driver runs one more.
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge: edge_id,
            parent: base.lineage().genesis_content(),
            selection: selection.id().expect("edge selection id"),
        },
        path.id().expect("edge path id"),
        StopCondition::ExecutionQuanta(3),
    )
    .expect("edge attempt");
    let input = CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        attempt,
        path,
        crate::CrucibleResolvedAttemptStart::Branch {
            parent: parent.clone(),
            selection: Box::new(resolved),
            selected: selected.clone(),
        },
    );
    SuffixCase {
        input,
        anchor,
        parent,
        selected,
    }
}

/// Effects shared by every scripted suffix lifecycle of one run.
#[derive(Clone, Default)]
pub(super) struct SuffixObservations {
    requests: Arc<Mutex<Vec<Configuration>>>,
    replies: Arc<Mutex<Vec<crucible_protocol::SelectionReply>>>,
    pub(super) quarantines: Arc<AtomicUsize>,
    pub(super) recoveries: Arc<AtomicUsize>,
}

/// The scripted world: each quantum moves to a fixed successor, if any.
#[derive(Clone)]
pub(super) struct SuffixWorld {
    genesis: Configuration,
    pub(super) successors: BTreeMap<ContentHash, Configuration>,
    /// A guest request published once the world reaches this configuration.
    pub(super) guest: Option<(Configuration, QemuNodeSelectablePendingRequest)>,
    /// Where an attempt's driven quantum fails like the scheduler would.
    pub(super) drive_failure_at: Option<Configuration>,
    /// Where the world reports a terminal verdict.
    pub(super) terminal_at: Option<Configuration>,
    /// Whether applying a guest reply fails.
    pub(super) reply_failure: bool,
}

impl SuffixWorld {
    pub(super) fn for_case(case: &SuffixCase, edge: Edge) -> Self {
        let genesis = Configuration::genesis(case.input.scenario().scenario_def());
        let mut successors = BTreeMap::from([
            (genesis.id(), case.anchor.clone()),
            (case.anchor.id(), case.parent.clone()),
        ]);
        let guest = match edge {
            Edge::Scheduler => {
                successors.insert(case.parent.id(), case.selected.clone());
                None
            }
            Edge::Guest => {
                let crate::CrucibleResolvedAttemptStart::Branch { selection, .. } =
                    case.input.start()
                else {
                    panic!("suffix case is a branch")
                };
                let pending = branch_replay_guest_pending(
                    selection.declaration(),
                    selection.opportunity().instance(),
                );
                Some((case.parent.clone(), pending))
            }
        };
        Self {
            genesis,
            successors,
            guest,
            drive_failure_at: None,
            terminal_at: None,
            reply_failure: false,
        }
    }

    /// Starts a lifecycle after `quanta` quanta, as a retained root would be.
    pub(super) fn lifecycle_at(
        &self,
        quanta: u64,
        origin: QemuHotForkStartOrigin,
        runtime_basis: Option<AttemptExecutionRuntimeBasis>,
        observations: &SuffixObservations,
    ) -> SuffixLifecycle {
        let mut lifecycle = SuffixLifecycle {
            world: self.clone(),
            configuration: self.genesis.clone(),
            quanta: 0,
            event_log: EventLog::new(),
            events: Vec::new(),
            origin,
            runtime_basis,
            observations: observations.clone(),
            record: false,
        };
        for _ in 0..quanta {
            let request = crucible::QuantumRequest {
                configuration: lifecycle.configuration.clone(),
                control: Vec::new(),
            };
            lifecycle.drive_quantum(request).expect("advance to root");
        }
        lifecycle.record = true;
        lifecycle
    }
}

pub(super) struct SuffixLifecycle {
    world: SuffixWorld,
    configuration: Configuration,
    quanta: u64,
    event_log: EventLog,
    events: Vec<SchedulerEventLogEntry>,
    origin: QemuHotForkStartOrigin,
    runtime_basis: Option<AttemptExecutionRuntimeBasis>,
    observations: SuffixObservations,
    /// Whether driven quanta are attempt work rather than root preparation.
    record: bool,
}

impl QemuFreshAttemptLifecycleOwner for SuffixLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("quantum request is not the scripted frontier"),
            });
        }
        if self.record {
            self.observations
                .requests
                .lock()
                .expect("suffix requests")
                .push(request.configuration.clone());
            if self.world.drive_failure_at.as_ref() == Some(&self.configuration) {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("scripted suffix quantum failure"),
                });
            }
        }
        let at = crucible::VirtualTime {
            ticks: self.quanta + 1,
        };
        let append = self.event_log.append_observations_at_boundary(
            None,
            at,
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        )?;
        self.quanta += 1;
        self.events.extend(append.entries.iter().cloned());
        if let Some(next) = self.world.successors.get(&self.configuration.id()) {
            self.configuration = next.clone();
        }

        Ok(crucible::QuantumOutcome {
            configuration: self.configuration.clone(),
            frontier: at,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: append.entries,
            event_log_segment_bytes: append.segment_bytes,
            event_log_segment_text: append.segment_text,
            event_log_segment_hash: append.segment_hash,
            event_log_offset: append.offset,
            scheduler_quiescence: None,
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        (self.world.terminal_at.as_ref() == Some(&self.configuration)).then(|| {
            crucible::QuantumTerminalVerdict::Failed(vec![String::from(
                "scripted suffix terminal verdict",
            )])
        })
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        _cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("suffix fixture retains no terminal checkpoint"),
        })
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(false)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        let published = self
            .world
            .guest
            .as_ref()
            .is_some_and(|(at, _pending)| *at == self.configuration);
        Ok(if published {
            self.world
                .guest
                .take()
                .map(|(_at, pending)| pending)
                .into_iter()
                .collect()
        } else {
            Vec::new()
        })
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        _decision: SelectionDecision,
        selected: &Configuration,
        _pending: &QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        assert_eq!(parent, &self.configuration);
        if self.world.reply_failure {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("scripted guest reply failure"),
            });
        }
        self.configuration = selected.clone();
        self.observations
            .replies
            .lock()
            .expect("suffix replies")
            .push(reply.clone());
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("suffix fixture has no checkpoint authority"),
        })
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("suffix fixture has no replay launch profiles"),
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("suffix fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        // Fingerprints depend only on absolute progress, never on the tier.
        let hash = ContentHash::from_bytes(format!("{}@{}", node.name, self.quanta).as_bytes());
        Ok(FingerprintSample {
            node,
            at: crucible::VirtualTime { ticks: self.quanta },
            fingerprint: ExecutionFingerprint { hash },
        })
    }

    fn resolved_effect_trace(
        &self,
    ) -> Result<Option<crucible::model::ResolvedEffectTrace>, SchedulerError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }
}

impl QemuHotForkWorldLifecycleOwner for SuffixLifecycle {
    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.runtime_basis
            .expect("hot suffix lifecycle runtime basis")
    }

    fn start_materialization(
        &self,
    ) -> Result<crate::QemuFreshStartMaterialization, SchedulerError> {
        Ok(crate::QemuFreshStartMaterialization::from_resume_parts(
            self.configuration.clone(),
            crate::qemu_campaign_driver::RetainedAttemptLog::from_entries(
                crate::DEFAULT_MAXIMUM_EVENT_LOG_BYTES,
                self.events.clone(),
            )
            .expect("dense suffix start log"),
            self.quanta,
            crucible::VirtualTime { ticks: self.quanta },
            SchedulerQuiescence::default(),
            None,
        ))
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crucible_api::LifecycleApiError> {
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    fn start_origin(&self) -> QemuHotForkStartOrigin {
        self.origin.clone()
    }
}

/// Hot factory whose single child starts at the ancestor root.
pub(super) struct AncestorFactory {
    world: SuffixWorld,
    root_quanta: u64,
    origin: QemuHotForkStartOrigin,
    observations: SuffixObservations,
}

impl QemuHotForkWorldLifecycleFactory for AncestorFactory {
    type Lifecycle = SuffixLifecycle;
    type Error = Infallible;

    fn try_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        Ok(QemuHotForkWorldLifecycleStart::Started(
            self.world.lifecycle_at(
                self.root_quanta,
                self.origin.clone(),
                context.runtime_basis(),
                &self.observations,
            ),
        ))
    }

    fn recover(&mut self, _lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        self.observations.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {
        self.observations.quarantines.fetch_add(1, Ordering::SeqCst);
    }
}

/// Thin factory whose lifecycle replays the whole path from genesis.
struct ThinFactory {
    world: SuffixWorld,
    observations: SuffixObservations,
}

impl QemuFreshAttemptLifecycleFactory for ThinFactory {
    type Lifecycle = SuffixLifecycle;
    type Error = Infallible;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        Ok(self
            .world
            .lifecycle_at(0, QemuHotForkStartOrigin::Exact, None, &self.observations))
    }
}

pub(super) fn ancestor_origin(anchor: &Configuration) -> QemuHotForkStartOrigin {
    QemuHotForkStartOrigin::Ancestor {
        anchor: Arc::new(anchor.clone()),
        root: QemuPublishedRootOrigin::BranchParentAnchor,
    }
}

pub(super) type AncestorRunner = QemuHotForkWorldExecutionRunner<
    QemuObservedFreshAttemptLifecycleFactory<AncestorFactory>,
    QemuFreshModeledDriver,
>;

/// Builds an observed hot runner whose child starts after `root_quanta`.
pub(super) fn ancestor_runner(
    world: SuffixWorld,
    root_quanta: u64,
    origin: QemuHotForkStartOrigin,
    observations: &SuffixObservations,
) -> (AncestorRunner, QemuAttemptExecutionEvidence) {
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(AncestorFactory {
            world,
            root_quanta,
            origin,
            observations: observations.clone(),
        });
    (
        QemuHotForkWorldExecutionRunner::new(factory, QemuFreshModeledDriver::new()),
        evidence,
    )
}

fn prepared(outcome: &CrucibleExecutionOutcome) -> crate::PreparedSemanticAttemptResult {
    let AttemptExecutionProduct::PreparedSemantic(result) = outcome.product() else {
        panic!("suffix attempts produce prepared semantic results")
    };
    result.as_ref().clone()
}

/// The same branch realized hot from an ancestor and by thin replay seals
/// byte-identical semantic results (CCOMP-21).
#[test]
fn ancestor_hot_and_thin_realizations_prepare_identical_results() {
    for edge in [Edge::Scheduler, Edge::Guest] {
        let case = suffix_case(edge);
        let world = SuffixWorld::for_case(&case, edge);

        let thin_observations = SuffixObservations::default();
        let (factory, thin_evidence) =
            QemuObservedFreshAttemptLifecycleFactory::with_evidence(ThinFactory {
                world: world.clone(),
                observations: thin_observations.clone(),
            });
        let thin = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver::new());
        let mut thin = QemuTerminalEvidenceExecutionRunner::new(thin, thin_evidence);
        let thin_outcome = thin
            .execute(&case.input, &execution_context(&case.input, 0x91))
            .expect("thin realization");

        let hot_observations = SuffixObservations::default();
        let (hot, hot_evidence) =
            ancestor_runner(world, 1, ancestor_origin(&case.anchor), &hot_observations);
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let hot = QemuHotFirstExecutionRouter::new(
            hot,
            NeverFallbackRunner {
                calls: Arc::clone(&fallback_calls),
            },
        );
        let mut hot = QemuTerminalEvidenceExecutionRunner::new(hot, hot_evidence);
        let hot_outcome = hot
            .execute(&case.input, &execution_context(&case.input, 0x92))
            .expect("ancestor hot realization");

        assert_eq!(
            thin_outcome.materialization(),
            CrucibleMaterializationTier::ThinReplay
        );
        assert_eq!(
            hot_outcome.materialization(),
            CrucibleMaterializationTier::HotFork
        );
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
        assert_eq!(prepared(&hot_outcome), prepared(&thin_outcome));
        // The hot child replayed only the suffix below the parent.
        let hot_requests = hot_observations
            .requests
            .lock()
            .expect("hot requests")
            .clone();
        assert_eq!(hot_requests.first(), Some(&case.anchor));
        assert!(!hot_requests.contains(&Configuration::genesis(
            case.input.scenario().scenario_def()
        )));
        let replies =
            |observations: &SuffixObservations| observations.replies.lock().expect("replies").len();
        assert_eq!(replies(&hot_observations), usize::from(edge == Edge::Guest));
        assert_eq!(replies(&thin_observations), replies(&hot_observations));
        assert_eq!(
            hot.reconcile_execution(AttemptExecutionDisposition::Canceled)
                .expect("reconcile the ancestor child"),
            AttemptExecutionReconciliationStep::Complete
        );
        assert_eq!(hot_observations.recoveries.load(Ordering::SeqCst), 1);
    }
}

/// A suffix that diverges before the parent is operational: the child is
/// quarantined, which abandons the root, and the attempt may retry thin.
#[test]
fn ancestor_suffix_divergence_is_retryable_and_quarantines_the_child() {
    let case = suffix_case(Edge::Scheduler);
    let mut world = SuffixWorld::for_case(&case, Edge::Scheduler);
    let diverged = rng_step(&case.anchor, "ancestor-suffix-second", 6);
    world.successors.insert(case.anchor.id(), diverged);
    let observations = SuffixObservations::default();
    let (mut runner, _evidence) =
        ancestor_runner(world, 1, ancestor_origin(&case.anchor), &observations);

    let failure = runner
        .try_execute(&case.input, &execution_context(&case.input, 0x93))
        .err()
        .expect("a diverged suffix fails the hot attempt");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Retryable(
            QemuHotForkWorldExecutionRunnerError::AncestorSuffixDiverged(_)
        )
    ));
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
}

/// Divergence at or after the parent belongs to the attempt, as for any
/// exact root, and keeps its terminal class.
#[test]
fn divergence_on_the_attempt_edge_stays_terminal_for_an_ancestor_child() {
    let case = suffix_case(Edge::Scheduler);
    let mut world = SuffixWorld::for_case(&case, Edge::Scheduler);
    let wrong_edge = rng_step(&case.parent, "ancestor-wrong-edge", 1);
    world.successors.insert(case.parent.id(), wrong_edge);
    let observations = SuffixObservations::default();
    let (mut runner, _evidence) =
        ancestor_runner(world, 1, ancestor_origin(&case.anchor), &observations);

    let failure = runner
        .try_execute(&case.input, &execution_context(&case.input, 0x94))
        .err()
        .expect("a diverged edge fails the hot attempt");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuHotForkWorldExecutionRunnerError::StartReplay(_))
    ));
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
}

/// An ancestor origin that is not a strict prefix of the parent contradicts
/// the lease and is quarantined before any replay.
#[test]
fn ancestor_origin_outside_the_parent_prefix_is_a_source_recovery_failure() {
    let case = suffix_case(Edge::Scheduler);
    let world = SuffixWorld::for_case(&case, Edge::Scheduler);
    let genesis = Configuration::genesis(case.input.scenario().scenario_def());
    let unrelated = rng_step(&genesis, "ancestor-unrelated", 9);
    let observations = SuffixObservations::default();
    let (mut runner, _evidence) =
        ancestor_runner(world, 1, ancestor_origin(&unrelated), &observations);

    let failure = runner
        .try_execute(&case.input, &execution_context(&case.input, 0x95))
        .err()
        .expect("an unrelated ancestor is refused");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuHotForkWorldExecutionRunnerError::SourceRecovery)
    ));
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
    assert!(observations.requests.lock().expect("requests").is_empty());
}

pub(super) fn provenance(
    anchor: &Configuration,
    pause: Option<bool>,
) -> QemuPublishedRootProvenance {
    QemuPublishedRootProvenance::new(
        QemuPublishedRootOrigin::BranchParentAnchor,
        anchor.clone(),
        pause,
    )
}

pub(super) fn override_decision(name: &str) -> Decision {
    Decision::Override(crucible::OverrideDecision {
        point: crucible::SchedulingPoint {
            key: format!("ancestor-{name}"),
        },
        choice: crucible::ChoiceTag {
            name: String::from(name),
        },
    })
}

/// Provider with no exact roots that records every ancestor lookup.
#[derive(Default)]
struct RecordingAncestorProvider {
    exact_checkouts: Arc<AtomicUsize>,
    lookups: Arc<Mutex<Vec<(QemuHotForkSourceWorldKey, Configuration, bool)>>>,
    candidate: Option<QemuPublishedRootProvenance>,
}

impl super::super::source_world_provider_sealed::Sealed for RecordingAncestorProvider {}

impl QemuHotForkSourceWorldProvider for RecordingAncestorProvider {
    type Error = Infallible;

    fn checkout(
        &mut self,
        _key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        self.exact_checkouts.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn checkout_ancestor(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
        parent: &Configuration,
        eligible: &dyn Fn(&QemuPublishedRootProvenance) -> bool,
    ) -> Result<
        Option<crate::managed_qemu_hot_fork_source_world_pool::QemuHotForkAncestorCheckout>,
        Self::Error,
    > {
        // The candidate is offered to the suffix policy but never leased.
        let accepted = self.candidate.as_ref().is_some_and(eligible);
        self.lookups.lock().expect("ancestor lookups").push((
            key.clone(),
            parent.clone(),
            accepted,
        ));
        Ok(None)
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        let _retained_for_process_lifetime = Box::leak(Box::new(source));
    }

    fn abandon(&mut self) {}
}

fn recording_factory(
    provider: RecordingAncestorProvider,
    run_state: &std::path::Path,
) -> QemuProductionHotForkWorldLifecycleFactory<RecordingAncestorProvider, ScriptedWorldGuardFactory>
{
    QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ScriptedWorldGuardFactory {
            observations: ScriptedWorldObservations::new(),
        },
        run_state,
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
    )
}

/// A published-boundary miss asks for an ancestor of the attempt's parent,
/// offering candidates to the suffix policy, and declines when none leases.
#[test]
fn published_root_miss_looks_up_an_eligible_ancestor_of_the_parent() {
    let case = suffix_case(Edge::Guest);
    let pause =
        crate::qemu_campaign_lifecycle::replay_pauses_before_live_network_choice(&case.selected);
    let provider = RecordingAncestorProvider {
        candidate: Some(provenance(&case.anchor, Some(pause))),
        ..RecordingAncestorProvider::default()
    };
    let lookups = Arc::clone(&provider.lookups);
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = recording_factory(provider, run_state.path());

    let started = factory
        .try_start(&case.input, &execution_context(&case.input, 0x96))
        .expect("a miss is a decline");

    assert!(matches!(started, QemuHotForkWorldLifecycleStart::Declined));
    let lookups = lookups.lock().expect("ancestor lookups");
    let [(key, parent, accepted)] = lookups.as_slice() else {
        panic!("exactly one ancestor lookup")
    };
    assert_eq!(
        key.boundary(),
        QemuHotForkSourceWorldBoundary::PublishedBoundary
    );
    assert_eq!(key.configuration(), case.parent.id());
    assert_eq!(parent, &case.parent);
    assert!(accepted);
}

/// A child of any published root inherits its configuration, so an edge
/// that only lifecycle configuration serves never checks a root out.
#[test]
fn configuration_carried_edge_declines_before_any_published_checkout() {
    let case = suffix_case(Edge::Scheduler);
    let overridden = step(&case.parent, override_decision("edge"));
    let crate::CrucibleResolvedAttemptStart::Branch { selection, .. } = case.input.start() else {
        panic!("suffix case is a branch")
    };
    let input = CrucibleAttemptExecution::from_test_parts(
        case.input.lineage().clone(),
        case.input.scenario().clone(),
        case.input.attempt().clone(),
        case.input.path().clone(),
        crate::CrucibleResolvedAttemptStart::Branch {
            parent: case.parent.clone(),
            selection: selection.clone(),
            selected: overridden,
        },
    );
    let provider = RecordingAncestorProvider::default();
    let exact_checkouts = Arc::clone(&provider.exact_checkouts);
    let lookups = Arc::clone(&provider.lookups);
    let run_state = tempfile::tempdir().expect("run state");
    let mut factory = recording_factory(provider, run_state.path());

    let started = factory
        .try_start(&input, &execution_context(&input, 0x97))
        .expect("a configuration-carried edge is a decline");

    assert!(matches!(started, QemuHotForkWorldLifecycleStart::Declined));
    assert_eq!(exact_checkouts.load(Ordering::SeqCst), 0);
    assert!(lookups.lock().expect("ancestor lookups").is_empty());
}
