//! Focused shared-owner regressions for guarded scenario-default runs.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use crucible::{
    Configuration, ContentHash, EventLog, ExecutionFingerprint, FingerprintSample, Icount,
    MarkerId, NodeId, NodeTemplate, ObservableEvent, Plan, Properties, QuantumOutcome,
    QuantumRequest, QuantumTerminalVerdict, ReadyPoint, ScenarioDef, ScenarioDefForm,
    ScenarioSelectableLimits, ScenarioSelectables, SchedulerError, SchedulerEventLogEntry, Seed,
    VirtualTime, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig};
use crucible_campaign::{
    AttemptResourceLimits, BooleanDomain, CampaignState, ChoiceClassContext, ChoiceDomain,
    ChoiceSource, ChoiceValue, SelectableDeclaration, StopOutcome,
};
use crucible_cas::content_store::{
    BlobHandle, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, ObjectKind,
    StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;

use super::*;
use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    DirectoryAssignmentLedger, DirectoryCampaignGcJournal, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner, apply_single_host_campaign_gc,
    decode_crucible_scenario_artifact, plan_single_host_campaign_gc,
};

const TEST_EFFECT_TRACE: &[u8] = b"guarded-default-run-effect-trace";

struct TerminalLifecycle {
    node: NodeId,
    event_log: EventLog,
    mode: TerminalLifecycleMode,
    frontier: VirtualTime,
}

#[derive(Clone, Copy)]
enum TerminalLifecycleMode {
    Terminal,
    VirtualTime { quantum_nanoseconds: u64 },
}

impl QemuFreshAttemptLifecycleOwner for TerminalLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.frontier.ticks = match self.mode {
            TerminalLifecycleMode::Terminal => 7,
            TerminalLifecycleMode::VirtualTime {
                quantum_nanoseconds,
            } => self.frontier.ticks.saturating_add(quantum_nanoseconds),
        };
        let append = self
            .event_log
            .append_observable_events([ObservableEvent::guest_marker(
                Icount {
                    retired: self.frontier.ticks,
                },
                self.node.clone(),
                MarkerId::from_name("guarded-default-run-quantum"),
            )])?;
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: self.frontier,
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

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        matches!(self.mode, TerminalLifecycleMode::Terminal)
            .then_some(QuantumTerminalVerdict::Passed)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(false)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::NotImplemented {
            operation: "guarded default-run checkpoint fixture",
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::NotImplemented {
            operation: "guarded default-run fault-evidence fixture",
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        assert_eq!(node, self.node);
        Ok(FingerprintSample {
            node,
            at: self.frontier,
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"guarded-default-run-fingerprint"),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        Ok(Some(TEST_EFFECT_TRACE.to_vec()))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if matches!(self.mode, TerminalLifecycleMode::VirtualTime { .. }) {
            return Ok(Vec::new());
        }
        self.event_log
            .append_observable_events([ObservableEvent::guest_marker(
                Icount { retired: 8 },
                self.node.clone(),
                MarkerId::from_name("guarded-default-run-final-drain"),
            )])
            .map(|append| append.entries)
    }
}

struct TerminalLifecycleFactory {
    node: NodeId,
    fail_start: bool,
    mode: TerminalLifecycleMode,
}

struct SelectableLifecycle {
    node: NodeId,
    event_log: EventLog,
    pending: Vec<crucible_qemu::QemuNodeSelectablePendingRequest>,
    selection_received: bool,
    terminal_driven: bool,
    frontier: VirtualTime,
}

impl QemuFreshAttemptLifecycleOwner for SelectableLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.terminal_driven = self.selection_received;
        self.frontier = VirtualTime {
            ticks: if self.terminal_driven { 7 } else { 1 },
        };
        let marker = if self.terminal_driven {
            "guarded-selected-terminal"
        } else {
            "guarded-selectable-offered"
        };
        let append = self
            .event_log
            .append_observable_events([ObservableEvent::guest_marker(
                Icount {
                    retired: self.frontier.ticks,
                },
                self.node.clone(),
                MarkerId::from_name(marker),
            )])?;

        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: self.frontier,
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

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_driven
            .then_some(QuantumTerminalVerdict::Passed)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(false)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(std::mem::take(&mut self.pending))
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), SchedulerError> {
        if reply.selected_value().is_none() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("selectable fixture received a non-selected reply"),
            });
        }
        self.selection_received = true;
        Ok(())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::NotImplemented {
            operation: "guarded selectable checkpoint fixture",
        })
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::NotImplemented {
            operation: "guarded selectable fault-evidence fixture",
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        assert_eq!(node, self.node);
        Ok(FingerprintSample {
            node,
            at: self.frontier,
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"guarded-selectable-fingerprint"),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }
}

struct SelectableLifecycleFactory {
    node: NodeId,
    starts: Arc<AtomicUsize>,
}

impl QemuFreshAttemptLifecycleFactory for SelectableLifecycleFactory {
    type Lifecycle = SelectableLifecycle;
    type Error = io::Error;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.starts.fetch_add(1, Ordering::Relaxed);
        Ok(SelectableLifecycle {
            node: self.node.clone(),
            event_log: EventLog::new(),
            pending: vec![pending_guest_request(self.node.clone())],
            selection_received: false,
            terminal_driven: false,
            frontier: VirtualTime::default(),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for TerminalLifecycleFactory {
    type Lifecycle = TerminalLifecycle;
    type Error = io::Error;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        if self.fail_start {
            return Err(AttemptWorkerFailure::Terminal(io::Error::other(
                "injected guarded lifecycle start failure",
            )));
        }
        Ok(TerminalLifecycle {
            node: self.node.clone(),
            event_log: EventLog::new(),
            mode: self.mode,
            frontier: VirtualTime::default(),
        })
    }
}

#[test]
fn shared_owner_authenticates_completion_and_retains_terminal_evidence() {
    let (request, node) = request();
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(TerminalLifecycleFactory {
            node: node.clone(),
            fail_start: false,
            mode: TerminalLifecycleMode::Terminal,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("shared owner should complete the authenticated attempt");

    assert_eq!(
        completed.state_updates(),
        [
            CampaignState::Created,
            CampaignState::Running,
            CampaignState::Completed,
        ]
    );
    assert_eq!(completed.observations().len(), 1);
    assert_eq!(completed.observations()[0].virtual_time_ticks(), 7);
    assert_eq!(completed.branch_request_count(), 0);
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::TerminalSuccess
    );
    assert_eq!(
        completed
            .terminal()
            .observation()
            .child()
            .as_hash()
            .as_bytes(),
        completed.terminal_configuration().id().bytes,
    );

    let evidence = completed.evidence();
    assert_eq!(evidence.quanta(), 1);
    assert_eq!(evidence.frontier(), VirtualTime { ticks: 7 });
    assert_eq!(evidence.event_log_entries().len(), 2);
    assert_eq!(
        evidence
            .event_log_entries()
            .iter()
            .map(SchedulerEventLogEntry::sequence)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(evidence.execution_fingerprints().len(), 2);
    assert!(
        evidence
            .execution_fingerprints()
            .iter()
            .all(|sample| sample.node == node)
    );
    assert_eq!(evidence.resolved_effect_trace(), Some(TEST_EFFECT_TRACE));
}

#[test]
fn selected_schedule_replays_through_a_fresh_authenticated_repository() {
    let (request, node) = selectable_request();
    let scenario = request.scenario.clone();
    let first_starts = Arc::new(AtomicUsize::new(0));
    let first = run_selectable_campaign(request, node.clone(), Arc::clone(&first_starts));

    assert_eq!(first.branch_request_count(), 1);
    assert_eq!(first.terminal_configuration().schedule.len(), 1);
    assert!(matches!(
        first.terminal_configuration().schedule.decisions(),
        [crucible::Decision::Selection(_)]
    ));
    assert_eq!(first_starts.load(Ordering::Relaxed), 2);

    let closure_bytes = first
        .replay_closure()
        .to_canonical_bytes()
        .expect("selected replay closure");
    let closure = GuardedCampaignReplayClosure::from_canonical_bytes(&closure_bytes)
        .expect("decode selected replay closure");
    closure
        .validate_for_schedule(&scenario, &first.terminal_configuration().schedule)
        .expect("closure must cover the exact selected schedule");

    let (replay_request, replay_node) = selectable_request();
    let replay_request = replay_request
        .with_initial_replay(first.terminal_configuration().schedule.clone(), closure);
    let replay_starts = Arc::new(AtomicUsize::new(0));
    let replayed = run_selectable_campaign(replay_request, replay_node, Arc::clone(&replay_starts));

    assert_eq!(replayed.branch_request_count(), 0);
    assert_eq!(
        replayed.terminal_configuration(),
        first.terminal_configuration()
    );
    assert_eq!(
        replayed
            .replay_closure()
            .to_canonical_bytes()
            .expect("replayed closure"),
        closure_bytes
    );
    assert_eq!(replay_starts.load(Ordering::Relaxed), 1);
}

#[test]
fn explicit_terminal_discovery_precedes_supervisor_automatic_discovery() {
    let (request, node) = selectable_request();
    let request = request.with_discovery_stop(StopCondition::Terminal);
    let starts = Arc::new(AtomicUsize::new(0));

    let completed = run_selectable_campaign(request, node, Arc::clone(&starts));

    assert_eq!(starts.load(Ordering::Relaxed), 1);
    assert_eq!(completed.branch_request_count(), 0);
    assert_eq!(completed.terminal_configuration().schedule.len(), 1);
    assert!(matches!(
        completed.terminal_configuration().schedule.decisions(),
        [crucible::Decision::Selection(_)]
    ));
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::TerminalSuccess
    );
}

#[test]
fn explicit_virtual_time_discovery_retains_the_first_frontier_crossing_the_deadline() {
    let deadline = 2_000_000;
    let quantum_nanoseconds = 1_100_000;
    let completed_frontier = quantum_nanoseconds * 2;
    let (request, node) = request();
    let request = request.with_discovery_stop(StopCondition::VirtualTimeNanoseconds(deadline));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(TerminalLifecycleFactory {
            node,
            fail_start: false,
            mode: TerminalLifecycleMode::VirtualTime {
                quantum_nanoseconds,
            },
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("virtual-time campaign should reach the requested deadline");

    assert_eq!(completed.observations().len(), 1);
    assert_eq!(completed.branch_request_count(), 0);
    assert_eq!(completed.evidence().quanta(), 2);
    assert_eq!(completed.evidence().frontier().ticks, completed_frontier);
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(deadline))
    );
}

#[test]
fn terminal_discovery_selection_survives_gc_restart_and_replay() {
    let temp = tempfile::TempDir::new().expect("temporary campaign store");
    let blob_root = temp.path().join("blobs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("gc-journal");
    let store_node = StoreNodeId::new("legacy-run-directory").expect("store node");
    let graph_config = || StoreGraphConfig {
        root: store_node.clone(),
        admitted_kinds: campaign_object_kinds(),
        nodes: BTreeMap::from([(
            store_node.clone(),
            StoreNodeSpec::Directory {
                root: blob_root.clone(),
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("campaign graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let (request, node) = selectable_request();
    let scenario = request.scenario.clone();
    let request = request.with_discovery_stop(StopCondition::Terminal);
    let starts = Arc::new(AtomicUsize::new(0));
    let completed = try_selectable_campaign_with_store(
        request,
        node,
        Arc::clone(&starts),
        graph.clone(),
        refs.clone(),
    )
    .expect("terminal discovery campaign");

    assert_eq!(starts.load(Ordering::Relaxed), 1);
    let campaign = completed.campaign().clone();
    let observation_id = completed.terminal().id();
    let selection_id = completed
        .terminal()
        .observation()
        .produced_selections()
        .iter()
        .next()
        .copied()
        .expect("terminal observation selection");
    let expected_configuration = completed.terminal_configuration().clone();
    let orphan_bytes = b"legacy-run-unreachable-after-terminal";
    let orphan =
        crucible_cas::content_store::ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.to_vec()))
        .expect("publish GC control object");
    drop(completed);

    let (repository, _) = default_run_repository(graph.clone(), refs.clone())
        .expect("reopen campaign repository for GC planning");
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open assignment ledger");
    let prepared =
        plan_single_host_campaign_gc(&repository, refs.as_ref(), &mut ledger, None, None, &admin)
            .expect("plan campaign GC");
    assert!(
        prepared
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == orphan)
    );
    assert!(
        prepared
            .candidates()
            .iter()
            .all(|candidate| candidate.id() != selection_id.content_id())
    );
    let planned_candidates =
        u64::try_from(prepared.candidates().len()).expect("planned candidate count");
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("persist campaign GC plan");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("reopen campaign graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let (repository, _) = default_run_repository(graph.clone(), refs.clone())
        .expect("reopen campaign repository for GC apply");
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen assignment ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen campaign GC journal");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply campaign GC after restart");
    assert_eq!(report.candidates(), planned_candidates);
    assert!(!graph.contains(orphan).expect("orphan placement"));
    assert!(
        graph
            .contains(selection_id.content_id())
            .expect("selection placement")
    );
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, _admin) =
        StoreGraph::build_with_admin(graph_config()).expect("reopen collected campaign graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let (repository, _) = default_run_repository(graph.clone(), refs.clone())
        .expect("reopen collected campaign repository");
    let observation = repository
        .load_observation(observation_id)
        .expect("load terminal observation after GC");
    let head = repository
        .head(campaign.as_str())
        .expect("load campaign head after GC");
    let lineage = repository
        .load_lineage(head.snapshot().lineage())
        .expect("load campaign lineage after GC");
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .expect("load campaign scenario after GC");
    let authenticated_scenario = decode_crucible_scenario_artifact(&scenario_artifact)
        .expect("decode campaign scenario after GC");
    let configuration_artifact = repository
        .load_configuration_artifact(observation.child_content())
        .expect("load terminal configuration after GC");
    let store = CampaignExecutorStore::new(Arc::new(repository));
    let decoded = decode_crucible_configuration_artifact_with_selections(
        &authenticated_scenario,
        &scenario_artifact,
        &configuration_artifact,
        &store,
    )
    .expect("resolve terminal configuration after GC");
    assert_eq!(decoded, expected_configuration);

    let closure = GuardedCampaignReplayClosure::collect(&store, &scenario, &decoded.schedule)
        .expect("collect replay closure after GC");
    let (mut replay_request, replay_node) = selectable_request();
    replay_request.seed = Seed::from_u64(0x7265_706c_6179_6564);
    let replay_request = replay_request
        .with_initial_replay(decoded.schedule.clone(), closure)
        .with_discovery_stop(StopCondition::Terminal);
    let replay_starts = Arc::new(AtomicUsize::new(0));
    let replayed = try_selectable_campaign_with_store(
        replay_request,
        replay_node,
        Arc::clone(&replay_starts),
        graph,
        refs,
    )
    .expect("replay terminal configuration after GC");
    assert_eq!(replay_starts.load(Ordering::Relaxed), 1);
    assert_eq!(replayed.terminal_configuration(), &expected_configuration);
}

#[test]
fn replay_closure_rejects_missing_extra_duplicate_and_tampered_records_before_start() {
    let (request, node) = selectable_request();
    let starts = Arc::new(AtomicUsize::new(0));
    let completed = run_selectable_campaign(request, node, starts);
    let schedule = completed.terminal_configuration().schedule.clone();
    let closure = completed.replay_closure().clone();
    let closure_bytes = closure
        .to_canonical_bytes()
        .expect("selected replay closure");

    let (mut missing_request, missing_node) = selectable_request();
    missing_request.initial_schedule = schedule.clone();
    let missing_starts = Arc::new(AtomicUsize::new(0));
    let missing =
        try_selectable_campaign(missing_request, missing_node, Arc::clone(&missing_starts))
            .expect_err("selected schedule without closure must fail");
    assert!(matches!(
        missing,
        GuardedDefaultCampaignRunError::ReplayClosure(
            GuardedCampaignReplayClosureError::Invalid { .. }
        )
    ));
    assert_eq!(missing_starts.load(Ordering::Relaxed), 0);

    let (extra_request, extra_node) = selectable_request();
    let extra_request = extra_request.with_initial_replay(Schedule::empty(), closure);
    let extra_starts = Arc::new(AtomicUsize::new(0));
    let extra = try_selectable_campaign(extra_request, extra_node, Arc::clone(&extra_starts))
        .expect_err("unused closure selection must fail");
    assert!(matches!(
        extra,
        GuardedDefaultCampaignRunError::ReplayClosure(
            GuardedCampaignReplayClosureError::Invalid { .. }
        )
    ));
    assert_eq!(extra_starts.load(Ordering::Relaxed), 0);

    let wrong_selection = completed
        .replay_closure()
        .with_alternate_boolean_branch_selection()
        .expect("canonical closure with another legal branch selection");
    let (wrong_request, wrong_node) = selectable_request();
    let wrong_request = wrong_request.with_initial_replay(schedule, wrong_selection);
    let wrong_starts = Arc::new(AtomicUsize::new(0));
    let wrong = try_selectable_campaign(wrong_request, wrong_node, Arc::clone(&wrong_starts))
        .expect_err("closure for another legal selection must fail exact replay");
    assert!(matches!(
        wrong,
        GuardedDefaultCampaignRunError::ReplayClosure(
            GuardedCampaignReplayClosureError::Invalid { .. }
        )
    ));
    assert_eq!(wrong_starts.load(Ordering::Relaxed), 0);

    let mut duplicate = Vec::from(&closure_bytes[..8]);
    duplicate.extend_from_slice(&2_u32.to_le_bytes());
    duplicate.extend_from_slice(&closure_bytes[12..]);
    duplicate.extend_from_slice(&closure_bytes[12..]);
    assert!(matches!(
        GuardedCampaignReplayClosure::from_canonical_bytes(&duplicate),
        Err(GuardedCampaignReplayClosureError::Invalid { .. })
    ));

    let mut tampered = closure_bytes;
    let domain_length = u32::from_le_bytes(
        tampered[12..16]
            .try_into()
            .expect("selected closure domain length"),
    );
    tampered[12..16].copy_from_slice(&domain_length.saturating_add(1).to_le_bytes());
    assert!(GuardedCampaignReplayClosure::from_canonical_bytes(&tampered).is_err());
}

#[test]
fn shared_owner_preserves_the_terminal_lifecycle_error_source() {
    let (request, node) = request();
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(TerminalLifecycleFactory {
            node,
            fail_start: true,
            mode: TerminalLifecycleMode::Terminal,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let error = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect_err("injected lifecycle failure must reach the daemon caller");
    let mut source = Some(&error as &(dyn Error + 'static));
    let mut messages = Vec::new();
    while let Some(current) = source {
        messages.push(current.to_string());
        source = current.source();
    }

    assert!(
        messages
            .iter()
            .any(|message| { message.contains("injected guarded lifecycle start failure") }),
        "error sources: {messages:?}"
    );
}

fn request() -> (GuardedDefaultCampaignRunRequest, NodeId) {
    let node = NodeId {
        name: String::from("guarded-node"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: 128,
        cmdline: String::from("guarded-default-run-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("guarded test world");
    let seed = Seed::from_u64(0x6c65_6761_6379_7275);
    let scenario =
        ScenarioDefForm::from_components(&world, &Plan::empty(), &Properties::empty(), seed)
            .expect("guarded test scenario");
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-guarded-test",
        "/tmp/crucible-guarded-test",
        "guarded-test",
        1,
        1,
        65_533,
        65_533,
        16,
        1_024,
        Duration::from_secs(1),
    )
    .expect("guarded host configuration");
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024 * 1024, 10_000)
        .expect("guarded attempt resources");
    let lifecycle =
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state");

    (
        GuardedDefaultCampaignRunRequest::new(
            scenario,
            seed,
            "guarded-engine-test",
            "guarded-qemu-test",
            lifecycle,
            host,
            resources,
        ),
        node,
    )
}

fn selectable_request() -> (GuardedDefaultCampaignRunRequest, NodeId) {
    let node = NodeId {
        name: String::from("guarded-choice-node"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: 128,
        cmdline: String::from("guarded-selectable-run-test"),
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
    .expect("guarded selectable world");
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .expect("guarded selectable declaration");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32).expect("selectable limits"),
        vec![declaration],
    )
    .expect("guarded scenario selectables");
    let seed = Seed::from_u64(0x7365_6c65_6374_6564);
    let scenario =
        ScenarioDefForm::from_components(&world, &Plan::empty(), &Properties::empty(), seed)
            .expect("guarded selectable scenario")
            .with_selectables(selectables)
            .expect("attach guarded selectables");
    let host = LinuxQemuAttemptHostConfig::new(
        "/sys/fs/cgroup/crucible-guarded-selectable-test",
        "/tmp/crucible-guarded-selectable-test",
        "guarded-selectable-test",
        1,
        1,
        65_531,
        65_531,
        16,
        1_024,
        Duration::from_secs(1),
    )
    .expect("guarded selectable host configuration");
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024 * 1024, 10_000)
        .expect("guarded selectable resources");
    let lifecycle =
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state");

    (
        GuardedDefaultCampaignRunRequest::new(
            scenario,
            seed,
            "guarded-selectable-engine-test",
            "guarded-selectable-qemu-test",
            lifecycle,
            host,
            resources,
        ),
        node,
    )
}

fn campaign_object_kinds() -> BTreeSet<ObjectKind> {
    BTreeSet::from([
        ObjectKind::CampaignFact,
        ObjectKind::CampaignSnapshot,
        ObjectKind::MerkleNode,
        ObjectKind::Scenario,
        ObjectKind::Configuration,
        ObjectKind::Policy,
        ObjectKind::ExactManifest,
        ObjectKind::RamExtent,
        ObjectKind::DiskExtent,
        ObjectKind::DeviceState,
        ObjectKind::Observation,
        ObjectKind::Finding,
        ObjectKind::Projection,
        ObjectKind::Trace,
    ])
}

fn pending_guest_request(node: NodeId) -> crucible_qemu::QemuNodeSelectablePendingRequest {
    let request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", None, 256)
        .expect("guest selection request");
    crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
        node,
        SelectablePlanPendingRequest::new(request, 41, 0, 0x1000),
    )
}

fn run_selectable_campaign(
    request: GuardedDefaultCampaignRunRequest,
    node: NodeId,
    starts: Arc<AtomicUsize>,
) -> GuardedDefaultCampaignRun {
    try_selectable_campaign(request, node, starts)
        .expect("guarded selectable campaign should complete")
}

fn try_selectable_campaign(
    request: GuardedDefaultCampaignRunRequest,
    node: NodeId,
    starts: Arc<AtomicUsize>,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError> {
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(SelectableLifecycleFactory {
            node,
            starts,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);
    run_guarded_default_campaign_with_runner(request, runner, evidence)
}

fn try_selectable_campaign_with_store(
    request: GuardedDefaultCampaignRunRequest,
    node: NodeId,
    starts: Arc<AtomicUsize>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
) -> Result<GuardedDefaultCampaignRun, GuardedDefaultCampaignRunError> {
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(SelectableLifecycleFactory {
            node,
            starts,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);
    run_guarded_default_campaign_with_store(request, runner, evidence, blobs, refs)
}
