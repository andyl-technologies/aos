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
    Checkpoint, CheckpointKind, Configuration, ContentHash, EventLog, ExecutionFingerprint,
    FingerprintSample, Icount, MarkerId, NodeId, NodeTemplate, ObservableEvent, Plan, Properties,
    QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, ReadyPoint, ScenarioDef,
    ScenarioDefForm, ScenarioSelectableLimits, ScenarioSelectables, SchedulerError,
    SchedulerEventLogEntry, Seed, VirtualTime, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmLifecycleConfig};
use crucible_campaign::{
    AttemptResourceLimits, BooleanDomain, CampaignState, ChoiceClassContext, ChoiceDomain,
    ChoiceSource, ChoiceValue, SelectableDeclaration, StopOutcome,
};
use crucible_cas::content_store::{
    BlobHandle, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
    ObjectKind, StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_qemu::{QemuReplayOracleValidation, QemuVmSnapshot};

use super::*;
use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    DirectoryAssignmentLedger, DirectoryCampaignGcJournal, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner, apply_single_host_campaign_gc,
    decode_crucible_scenario_artifact, plan_single_host_campaign_gc,
};

const TEST_EFFECT_TRACE: &[u8] = b"guarded-default-run-effect-trace";

type TestGuardedDefaultCampaignRunError = GuardedDefaultCampaignRunError<
    QemuFreshExecutionRunnerError<
        QemuObservedFreshAttemptLifecycleFactoryError<io::Error>,
        QemuFreshModeledDriverError,
    >,
>;

struct TerminalLifecycle {
    node: NodeId,
    event_log: EventLog,
    mode: TerminalLifecycleMode,
    replay_target: Option<Schedule>,
    pending: Vec<crucible_qemu::QemuNodeSelectablePendingRequest>,
    pending_after_frontier: Option<u64>,
    frontier: VirtualTime,
    completed_quanta: u64,
    configuration: Option<Configuration>,
}

#[derive(Clone, Copy)]
enum TerminalLifecycleMode {
    Terminal,
    VirtualTime {
        quantum_nanoseconds: u64,
    },
    Resume {
        source_frontier: u64,
        terminal_frontier: u64,
    },
}

impl QemuFreshAttemptLifecycleOwner for TerminalLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.completed_quanta = self.completed_quanta.saturating_add(1);
        self.frontier.ticks = match self.mode {
            TerminalLifecycleMode::Terminal => 7,
            TerminalLifecycleMode::VirtualTime {
                quantum_nanoseconds,
            } => self.frontier.ticks.saturating_add(quantum_nanoseconds),
            TerminalLifecycleMode::Resume {
                source_frontier,
                terminal_frontier,
            } => {
                if self.frontier.ticks < source_frontier {
                    source_frontier
                } else if self.frontier.ticks == source_frontier {
                    source_frontier.saturating_add(1)
                } else {
                    terminal_frontier
                }
            }
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
        let mut configuration = request.configuration;
        if let Some(target) = &self.replay_target
            && configuration.schedule.len() < target.len()
        {
            configuration.schedule =
                target
                    .prefix(configuration.schedule.len() + 1)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: error.to_string(),
                    })?;
        }
        self.configuration = Some(configuration.clone());
        Ok(QuantumOutcome {
            configuration,
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

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        match self.mode {
            TerminalLifecycleMode::Terminal => Some(QuantumTerminalVerdict::Passed),
            TerminalLifecycleMode::VirtualTime { .. } => None,
            TerminalLifecycleMode::Resume {
                terminal_frontier, ..
            } => {
                (self.frontier.ticks >= terminal_frontier).then_some(QuantumTerminalVerdict::Passed)
            }
        }
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        if self
            .pending_after_frontier
            .is_some_and(|frontier| self.frontier.ticks < frontier)
        {
            return Ok(Vec::new());
        }
        Ok(std::mem::take(&mut self.pending))
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        let configuration =
            self.configuration
                .as_ref()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("checkpoint requested before a completed quantum"),
                })?;
        let parent = if configuration.schedule.is_empty() {
            None
        } else {
            Some(Configuration {
                def: configuration.def.clone(),
                schedule: configuration
                    .schedule
                    .prefix(configuration.schedule.len() - 1)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: error.to_string(),
                    })?,
            })
        };
        let checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            parent.as_ref(),
            self.frontier,
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: error.to_string(),
        })?;
        let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: error.to_string(),
            })?;
        Ok(
            crate::CapturedExactCheckpoint::new(snapshot, BlobHandle::from_bytes(vec![0x5a; 512]))
                .into(),
        )
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
        let terminal = match self.mode {
            TerminalLifecycleMode::Terminal => true,
            TerminalLifecycleMode::VirtualTime { .. } => false,
            TerminalLifecycleMode::Resume {
                terminal_frontier, ..
            } => self.frontier.ticks >= terminal_frontier,
        };
        if !terminal {
            return Ok(Vec::new());
        }
        self.event_log
            .append_observable_events([ObservableEvent::guest_marker(
                Icount {
                    retired: self.frontier.ticks.saturating_add(1),
                },
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
    completed_quanta: u64,
}

impl QemuFreshAttemptLifecycleOwner for SelectableLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.completed_quanta = self.completed_quanta.saturating_add(1);
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

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
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

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, SchedulerError> {
        if reply.selected_value().is_none() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("selectable fixture received a non-selected reply"),
            });
        }
        self.selection_received = true;
        Ok(Vec::new())
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
            completed_quanta: 0,
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
            replay_target: None,
            pending: Vec::new(),
            pending_after_frontier: None,
            frontier: VirtualTime::default(),
            completed_quanta: 0,
            configuration: None,
        })
    }
}

struct ReplayLifecycleFactory {
    node: NodeId,
    starts: Arc<AtomicUsize>,
    replay_quantum_nanoseconds: u64,
}

impl QemuFreshAttemptLifecycleFactory for ReplayLifecycleFactory {
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
        let start = self.starts.fetch_add(1, Ordering::Relaxed);
        Ok(TerminalLifecycle {
            node: self.node.clone(),
            event_log: EventLog::new(),
            mode: TerminalLifecycleMode::VirtualTime {
                quantum_nanoseconds: if start == 0 {
                    1_100_000
                } else {
                    self.replay_quantum_nanoseconds
                },
            },
            replay_target: None,
            pending: Vec::new(),
            pending_after_frontier: None,
            frontier: VirtualTime::default(),
            completed_quanta: 0,
            configuration: None,
        })
    }
}

struct ResumeLifecycleFactory {
    node: NodeId,
    starts: Arc<AtomicUsize>,
    mode: TerminalLifecycleMode,
    offer_continuation_choice: bool,
}

impl QemuFreshAttemptLifecycleFactory for ResumeLifecycleFactory {
    type Lifecycle = TerminalLifecycle;
    type Error = io::Error;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        start_configuration: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let incarnation = self.starts.fetch_add(1, Ordering::Relaxed);
        Ok(TerminalLifecycle {
            node: self.node.clone(),
            event_log: EventLog::new(),
            mode: self.mode,
            replay_target: Some(start_configuration.schedule.clone()),
            pending: if self.offer_continuation_choice && incarnation >= 2 {
                vec![pending_guest_request(self.node.clone())]
            } else {
                Vec::new()
            },
            pending_after_frontier: (self.offer_continuation_choice && incarnation >= 2).then_some(
                match self.mode {
                    TerminalLifecycleMode::Resume {
                        source_frontier, ..
                    } => source_frontier.saturating_add(1),
                    TerminalLifecycleMode::Terminal | TerminalLifecycleMode::VirtualTime { .. } => {
                        0
                    }
                },
            ),
            frontier: VirtualTime::default(),
            completed_quanta: 0,
            configuration: None,
        })
    }
}

#[test]
fn shared_owner_authenticates_completion_and_retains_terminal_evidence() {
    let (request, node) = request();
    let request = request.with_watch_frames();
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
    let watch_frames = completed.watch_frames();
    assert_eq!(watch_frames.len(), 4);
    assert_eq!(
        watch_frames
            .iter()
            .map(GuardedDefaultCampaignWatchFrame::state)
            .collect::<Vec<_>>(),
        [
            CampaignState::Created,
            CampaignState::Running,
            CampaignState::Running,
            CampaignState::Completed,
        ]
    );
    assert!(
        watch_frames
            .iter()
            .all(|frame| frame.campaign() == completed.campaign())
    );
    assert_eq!(watch_frames[0].frontier(), VirtualTime::default());
    assert_eq!(watch_frames[0].quanta(), 0);
    assert_eq!(watch_frames[1].frontier(), VirtualTime::default());
    assert_eq!(watch_frames[1].quanta(), 0);
    assert_eq!(watch_frames[2].frontier(), VirtualTime { ticks: 7 });
    assert_eq!(watch_frames[2].quanta(), 1);
    assert_eq!(
        watch_frames[2].observation(),
        Some(completed.terminal().id())
    );
    assert_eq!(watch_frames[3].snapshot(), completed.final_snapshot());
    assert_eq!(watch_frames[3].frontier(), VirtualTime { ticks: 7 });
    assert_eq!(watch_frames[3].quanta(), 1);
    assert_eq!(watch_frames[3].observation(), None);
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
fn virtual_time_savepoint_capture_replays_and_authenticates_the_same_boundary() {
    let deadline = 2_000_000;
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let request = request
        .with_discovery_stop(StopCondition::VirtualTimeNanoseconds(deadline))
        .with_reached_stop_savepoint_capture(Arc::clone(&checkpoints));
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ReplayLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            replay_quantum_nanoseconds: 1_100_000,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("stable replay should capture the requested savepoint");
    let savepoint = completed.savepoint().expect("authenticated savepoint");
    let loaded = checkpoints
        .load_attempt_checkpoint(savepoint.checkpoint())
        .expect("published exact checkpoint closure");

    assert_eq!(starts.load(Ordering::Relaxed), 2);
    assert_eq!(
        savepoint.attempt(),
        completed.terminal().observation().attempt()
    );
    assert_eq!(
        savepoint.configuration(),
        completed.terminal().observation().child()
    );
    assert_eq!(
        savepoint.stop(),
        &StopCondition::VirtualTimeNanoseconds(deadline)
    );
    assert_eq!(savepoint.evidence(), completed.evidence());
    assert_eq!(savepoint.evidence().frontier().ticks, 2_200_000);
    assert_eq!(loaded.root(), savepoint.checkpoint());
    assert_eq!(
        loaded.configuration().bytes,
        completed
            .terminal()
            .observation()
            .child()
            .as_hash()
            .as_bytes()
    );
}

#[test]
fn selection_free_resume_authenticates_the_exact_source_before_continuing() {
    let source_frontier = VirtualTime { ticks: 5 };
    let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 10 },
            order: Vec::new(),
        },
    )]);
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let checkpoint = legacy_resume_checkpoint(&request, &schedule, source_frontier);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .expect("selection-free replay closure");
    let request = request
        .with_selection_free_resume_source(
            schedule,
            closure,
            checkpoint.clone(),
            StopCondition::Terminal,
            Arc::clone(&checkpoints),
        )
        .with_watch_frames();
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ResumeLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            mode: TerminalLifecycleMode::Resume {
                source_frontier: source_frontier.ticks,
                terminal_frontier: 9,
            },
            offer_continuation_choice: false,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("selection-free legacy resume should complete");
    let resume = completed.resume().expect("authenticated resume proof");
    let source_savepoint = resume
        .source_savepoint()
        .expect("resume source exact savepoint");

    assert_eq!(starts.load(Ordering::Relaxed), 3);
    assert_eq!(resume.source_checkpoint(), checkpoint.id);
    assert_eq!(resume.source_frontier(), source_frontier);
    assert_eq!(
        resume.source_configuration(),
        completed.observations()[0].observation().child()
    );
    assert_eq!(
        resume.source_observation(),
        completed.observations()[0].id()
    );
    assert!(resume.ready().is_some());
    assert!(resume.selection().is_some());
    assert!(resume.continuation().is_some());
    assert_eq!(completed.observations().len(), 2);
    assert_eq!(
        completed.observations()[0].observation().stop(),
        &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(source_frontier.ticks))
    );
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::TerminalSuccess
    );
    assert_eq!(completed.evidence().frontier(), VirtualTime { ticks: 9 });
    assert_eq!(source_savepoint.evidence().frontier(), source_frontier);
    assert_eq!(
        source_savepoint.configuration(),
        resume.source_configuration()
    );
    assert_eq!(
        checkpoints
            .load_attempt_checkpoint(source_savepoint.checkpoint())
            .expect("load resume source checkpoint")
            .root(),
        source_savepoint.checkpoint()
    );

    let watched_observations = completed
        .watch_frames()
        .iter()
        .filter_map(GuardedDefaultCampaignWatchFrame::observation)
        .collect::<Vec<_>>();
    assert_eq!(
        watched_observations,
        vec![resume.source_observation(), completed.terminal().id()]
    );
}

#[test]
fn selection_free_resume_terminal_at_source_needs_no_continuation() {
    let source_frontier = VirtualTime { ticks: 7 };
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let schedule = Schedule::empty();
    let checkpoint = legacy_resume_checkpoint(&request, &schedule, source_frontier);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .expect("selection-free replay closure");
    let request = request.with_selection_free_resume_source(
        schedule,
        closure,
        checkpoint,
        StopCondition::Terminal,
        checkpoints,
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ResumeLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            mode: TerminalLifecycleMode::Terminal,
            offer_continuation_choice: false,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("terminal source should complete without fabrication");
    let resume = completed.resume().expect("authenticated terminal source");

    assert_eq!(starts.load(Ordering::Relaxed), 1);
    assert!(resume.source_savepoint().is_none());
    assert!(resume.ready().is_none());
    assert!(resume.selection().is_none());
    assert!(resume.continuation().is_none());
    assert_eq!(completed.observations().len(), 1);
    assert_eq!(completed.terminal().id(), resume.source_observation());
}

#[test]
fn selection_free_resume_rejects_terminal_before_the_source_boundary() {
    let source_frontier = VirtualTime { ticks: 8 };
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let schedule = Schedule::empty();
    let checkpoint = legacy_resume_checkpoint(&request, &schedule, source_frontier);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .expect("selection-free replay closure");
    let request = request.with_selection_free_resume_source(
        schedule,
        closure,
        checkpoint,
        StopCondition::Terminal,
        checkpoints,
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ResumeLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            mode: TerminalLifecycleMode::Terminal,
            offer_continuation_choice: false,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let error = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect_err("terminal before the source frontier must fail closed");

    assert_eq!(starts.load(Ordering::Relaxed), 1);
    assert!(matches!(
        error,
        GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::ResumeSourceBoundaryMismatch
        )
    ));
}

#[test]
fn selection_free_resume_rejects_a_checkpoint_for_another_configuration() {
    let source_frontier = VirtualTime { ticks: 5 };
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let checkpoint = legacy_resume_checkpoint(&request, &Schedule::empty(), source_frontier);
    let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: VirtualTime { ticks: 10 },
            order: Vec::new(),
        },
    )]);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .expect("selection-free replay closure");
    let request = request.with_selection_free_resume_source(
        schedule,
        closure,
        checkpoint,
        StopCondition::Terminal,
        checkpoints,
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ResumeLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            mode: TerminalLifecycleMode::Resume {
                source_frontier: source_frontier.ticks,
                terminal_frontier: 9,
            },
            offer_continuation_choice: false,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let error = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect_err("a checkpoint for another configuration must fail before execution");

    assert_eq!(starts.load(Ordering::Relaxed), 0);
    assert!(matches!(
        error,
        GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::ResumeSourceCheckpointMismatch
        )
    ));
}

#[test]
fn selection_free_resume_applies_an_earlier_final_stop_after_source_admission() {
    let source_frontier = VirtualTime { ticks: 5 };
    let final_stop = StopCondition::VirtualTimeNanoseconds(3);
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let schedule = Schedule::empty();
    let checkpoint = legacy_resume_checkpoint(&request, &schedule, source_frontier);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .expect("selection-free replay closure");
    let request = request.with_selection_free_resume_source(
        schedule,
        closure,
        checkpoint,
        final_stop.clone(),
        checkpoints,
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ResumeLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            mode: TerminalLifecycleMode::Resume {
                source_frontier: source_frontier.ticks,
                terminal_frontier: 9,
            },
            offer_continuation_choice: false,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("earlier final stop should apply only to the continuation");
    let resume = completed.resume().expect("authenticated resume proof");

    assert_eq!(starts.load(Ordering::Relaxed), 3);
    assert!(resume.source_savepoint().is_some());
    assert!(resume.continuation().is_some());
    assert_eq!(completed.observations().len(), 2);
    assert_eq!(
        completed.observations()[0].virtual_time_ticks(),
        source_frontier.ticks
    );
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::Reached(final_stop)
    );
    assert_eq!(completed.evidence().frontier(), source_frontier);
}

#[test]
fn selection_free_resume_completes_at_the_requested_next_choice() {
    let source_frontier = VirtualTime { ticks: 5 };
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = selectable_request();
    let schedule = Schedule::empty();
    let checkpoint = legacy_resume_checkpoint(&request, &schedule, source_frontier);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
        .expect("selection-free replay closure");
    let request = request.with_selection_free_resume_source(
        schedule,
        closure,
        checkpoint,
        StopCondition::NextChoice,
        checkpoints,
    );
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ResumeLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            mode: TerminalLifecycleMode::Resume {
                source_frontier: source_frontier.ticks,
                terminal_frontier: 9,
            },
            offer_continuation_choice: true,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let completed = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect("resume should stop at the first continuation choice");
    let resume = completed.resume().expect("authenticated resume proof");

    assert_eq!(starts.load(Ordering::Relaxed), 3);
    assert!(resume.source_savepoint().is_some());
    assert!(resume.continuation().is_some());
    assert_eq!(completed.observations().len(), 2);
    assert_eq!(completed.branch_request_count(), 0);
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::Reached(StopCondition::NextChoice)
    );
}

#[test]
fn savepoint_capture_rejects_a_terminal_outcome_before_the_requested_deadline() {
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let request = request
        .with_discovery_stop(StopCondition::VirtualTimeNanoseconds(2_000_000))
        .with_reached_stop_savepoint_capture(checkpoints);
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(TerminalLifecycleFactory {
            node,
            fail_start: false,
            mode: TerminalLifecycleMode::Terminal,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let error = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect_err("early terminal outcome must not become a successful savepoint");

    assert!(matches!(
        error,
        GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::SavepointStopNotReached
        )
    ));
    assert_eq!(
        std::fs::read_dir(checkpoint_directory.path())
            .expect("inspect checkpoint directory")
            .count(),
        0
    );
}

#[test]
fn savepoint_capture_rejects_mismatched_replay_evidence() {
    let checkpoint_directory = tempfile::TempDir::new().expect("checkpoint directory");
    let checkpoints = exact_checkpoint_store(&checkpoint_directory);
    let (request, node) = request();
    let request = request
        .with_discovery_stop(StopCondition::VirtualTimeNanoseconds(2_000_000))
        .with_reached_stop_savepoint_capture(checkpoints);
    let starts = Arc::new(AtomicUsize::new(0));
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(ReplayLifecycleFactory {
            node,
            starts: Arc::clone(&starts),
            replay_quantum_nanoseconds: 1_200_000,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);

    let error = run_guarded_default_campaign_with_runner(request, runner, evidence)
        .expect_err("a different capture replay must fail closed");

    assert_eq!(starts.load(Ordering::Relaxed), 2);
    assert!(matches!(
        error,
        GuardedDefaultCampaignRunError::Invariant(
            GuardedDefaultCampaignInvariantError::SavepointEvidenceMismatch
        )
    ));
}

#[test]
fn savepoint_default_choice_preserves_the_requested_continuation_stop() {
    let marker = StopCondition::NamedBoundary(String::from("checkpoint-ready"));
    assert_eq!(default_choice_continuation_stop(true, &marker), marker);

    let virtual_time = StopCondition::VirtualTimeNanoseconds(2_000_000);
    assert_eq!(
        default_choice_continuation_stop(true, &virtual_time),
        virtual_time
    );
    assert_eq!(
        default_choice_continuation_stop(false, &StopCondition::Terminal),
        StopCondition::NextChoice
    );
}

#[test]
fn explicit_execution_quanta_discovery_stops_at_the_absolute_coordinate() {
    let execution_quanta = 3;
    let quantum_nanoseconds = 11;
    let (request, node) = request();
    let request = request.with_discovery_stop(StopCondition::ExecutionQuanta(execution_quanta));
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
        .expect("execution-quanta campaign should reach the requested coordinate");

    assert_eq!(completed.observations().len(), 1);
    assert_eq!(completed.branch_request_count(), 0);
    assert_eq!(completed.evidence().quanta(), execution_quanta);
    assert_eq!(
        completed.evidence().frontier().ticks,
        execution_quanta * quantum_nanoseconds
    );
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::Reached(StopCondition::ExecutionQuanta(execution_quanta))
    );
}

#[test]
fn explicit_combined_discovery_stops_at_the_first_reached_bound() {
    let virtual_time_nanoseconds = 15;
    let execution_quanta = 3;
    let quantum_nanoseconds = 10;
    let stop = StopCondition::VirtualTimeOrExecutionQuanta {
        virtual_time_nanoseconds,
        execution_quanta,
    };
    let (request, node) = request();
    let request = request.with_discovery_stop(stop.clone());
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
        .expect("combined campaign should reach its virtual-time member first");

    assert_eq!(completed.observations().len(), 1);
    assert_eq!(completed.branch_request_count(), 0);
    assert_eq!(completed.evidence().quanta(), 2);
    assert_eq!(completed.evidence().frontier().ticks, 20);
    assert_eq!(
        completed.terminal().observation().stop(),
        &StopOutcome::Reached(stop)
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

    let (repository, _) = default_run_repository::<io::Error>(graph.clone(), refs.clone())
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
    let (repository, _) = default_run_repository::<io::Error>(graph.clone(), refs.clone())
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
    let (repository, _) = default_run_repository::<io::Error>(graph.clone(), refs.clone())
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
    let empty = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&Schedule::empty())
        .expect("selection-free schedule should admit the exact empty closure");
    assert_eq!(
        empty
            .to_canonical_bytes()
            .expect("canonical empty replay closure"),
        b"CCRC\0\0\0\x01\0\0\0\0",
    );

    let (request, node) = selectable_request();
    let starts = Arc::new(AtomicUsize::new(0));
    let completed = run_selectable_campaign(request, node, starts);
    let schedule = completed.terminal_configuration().schedule.clone();
    assert!(
        GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule).is_err(),
        "a selected schedule must require its authenticated record closure",
    );
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
    assert!(matches!(
        &error,
        GuardedDefaultCampaignRunError::Supervisor(_)
    ));

    let mut source = Some(&error as &(dyn Error + 'static));
    let mut injected = None;
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<io::Error>() {
            injected = Some((error.kind(), error.to_string()));
        }
        source = current.source();
    }

    assert_eq!(
        injected,
        Some((
            io::ErrorKind::Other,
            String::from("injected guarded lifecycle start failure"),
        ))
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

fn exact_checkpoint_store(directory: &tempfile::TempDir) -> Arc<ExactCheckpointStore> {
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "legacy-run-savepoint-tests",
        directory.path(),
    ));
    Arc::new(
        ExactCheckpointStore::new(backend, 1024 * 1024).expect("durable exact checkpoint store"),
    )
}

fn legacy_resume_checkpoint(
    request: &GuardedDefaultCampaignRunRequest,
    schedule: &Schedule,
    frontier: VirtualTime,
) -> Checkpoint {
    let configuration = Configuration {
        def: request.scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let parent = if schedule.is_empty() {
        None
    } else {
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: schedule
                .prefix(schedule.len() - 1)
                .expect("legacy resume parent schedule"),
        })
    };

    Checkpoint::from_recorded_configuration(
        &configuration,
        parent.as_ref(),
        frontier,
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("legacy resume logical checkpoint")
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
) -> Result<GuardedDefaultCampaignRun, TestGuardedDefaultCampaignRunError> {
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
) -> Result<GuardedDefaultCampaignRun, TestGuardedDefaultCampaignRunError> {
    let (factory, evidence) =
        QemuObservedFreshAttemptLifecycleFactory::with_evidence(SelectableLifecycleFactory {
            node,
            starts,
        });
    let runner = QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver);
    run_guarded_default_campaign_with_store(request, runner, evidence, blobs, refs)
}
