//! Focused shared-owner regressions for guarded scenario-default runs.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::error::Error;
use std::io;
use std::time::Duration;

use crucible::{
    Configuration, ContentHash, EventLog, ExecutionFingerprint, FingerprintSample, Icount,
    MarkerId, NodeId, NodeTemplate, ObservableEvent, Plan, Properties, QuantumOutcome,
    QuantumRequest, QuantumTerminalVerdict, ReadyPoint, ScenarioDef, ScenarioDefForm,
    SchedulerError, SchedulerEventLogEntry, Seed, VirtualTime, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig};
use crucible_campaign::{AttemptResourceLimits, CampaignState, StopOutcome};

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
