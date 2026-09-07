//! Focused shared-owner regressions for guarded scenario-default runs.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
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
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;

use super::*;
use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    QemuFreshAttemptLifecycleFactory, QemuFreshAttemptLifecycleOwner,
};

const TEST_EFFECT_TRACE: &[u8] = b"guarded-default-run-effect-trace";

struct TerminalLifecycle {
    node: NodeId,
    event_log: EventLog,
}

impl QemuFreshAttemptLifecycleOwner for TerminalLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        let append = self
            .event_log
            .append_observable_events([ObservableEvent::guest_marker(
                Icount { retired: 7 },
                self.node.clone(),
                MarkerId::from_name("guarded-default-run-quantum"),
            )])?;
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: 7 },
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
        Some(QuantumTerminalVerdict::Passed)
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
            at: VirtualTime { ticks: 7 },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"guarded-default-run-fingerprint"),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        Ok(Some(TEST_EFFECT_TRACE.to_vec()))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
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
