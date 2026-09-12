//! Shared lifecycle fakes, replay inputs, and finding fixtures.

use super::*;

#[derive(Default)]
pub(super) struct GuardCounters {
    pub(super) begins: AtomicUsize,
    pub(super) checks: AtomicUsize,
    pub(super) charges: AtomicUsize,
    pub(super) finishes: AtomicUsize,
    pub(super) quarantines: AtomicUsize,
}

pub(super) struct FakeResourceFactory {
    pub(super) installed_resources: AttemptResourceLimits,
    pub(super) replace_cancellation: bool,
    pub(super) counters: Arc<GuardCounters>,
}

impl QemuAttemptResourceGuardFactory for FakeResourceFactory {
    type Guard = FakeResourceGuard;

    fn begin(
        &mut self,
        _resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        self.counters.begins.fetch_add(1, Ordering::SeqCst);
        Ok(FakeResourceGuard {
            resources: self.installed_resources,
            cancellation: if self.replace_cancellation {
                ExecutionCancellation::default()
            } else {
                cancellation
            },
            counters: Arc::clone(&self.counters),
            terminal: false,
        })
    }
}

pub(super) struct FakeResourceGuard {
    pub(super) resources: AttemptResourceLimits,
    pub(super) cancellation: ExecutionCancellation,
    pub(super) counters: Arc<GuardCounters>,
    pub(super) terminal: bool,
}

impl QemuAttemptOperationalBoundary for FakeResourceGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counters.checks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.counters.charges.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl QemuAttemptResourceGuard for FakeResourceGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if !self.terminal {
            self.counters.finishes.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.counters.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuAttemptProcessResourceGuard for FakeResourceGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Err(fake_guard_error(
            "fake guard does not launch child processes",
        ))
    }

    fn prepare_generation_run_directory(
        &mut self,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        Err(fake_guard_error(
            "fake guard does not provision generation directories",
        ))
    }

    fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}
}

pub(super) fn fake_guard_error(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "test production lifecycle guard",
        message: message.into(),
    }
}

pub(super) fn resources(quanta: u64) -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 64 * 1024 * 1024, 128 * 1024 * 1024, quanta)
        .expect("attempt resource fixture")
}

pub(super) fn context(
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        resources,
        ExecutionRetentionIntent::Discard,
        cancellation,
        ExecutionCheckpointRequest::default(),
    )
}

pub(super) fn factory(
    installed_resources: AttemptResourceLimits,
    replace_cancellation: bool,
    counters: Arc<GuardCounters>,
) -> QemuAttemptProductionVmLifecycleFactory<FakeResourceFactory> {
    QemuAttemptProductionVmLifecycleFactory::new(
        ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
        FakeResourceFactory {
            installed_resources,
            replace_cancellation,
            counters,
        },
    )
}

pub(super) struct FakeFreshLifecycle {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) completed_quanta: u64,
    pub(super) promotion_observations: Option<Arc<Mutex<Vec<bool>>>>,
    pub(super) cleanup_error: bool,
    pub(super) pending: Vec<crucible_qemu::QemuNodeSelectablePendingRequest>,
    pub(super) replies: Arc<Mutex<Vec<crucible_protocol::SelectionReply>>>,
    pub(super) signal_fault_branches: VecDeque<crucible::SignalFaultCampaignBranch>,
    pub(super) terminal_after_replay: bool,
    pub(super) checkpoint_ready: bool,
    pub(super) fingerprint_error: bool,
    pub(super) fingerprint_node_override: Arc<Mutex<Option<crucible::NodeId>>>,
}

impl FakeFreshLifecycle {
    fn complete_quantum(
        &mut self,
        outcome: crucible::QuantumOutcome,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.completed_quanta = self.completed_quanta.checked_add(1).ok_or_else(|| {
            crucible::SchedulerError::BoundaryViolation {
                message: String::from("fake lifecycle quantum coordinate overflowed"),
            }
        })?;
        Ok(outcome)
    }
}

impl QemuFreshAttemptLifecycleOwner for FakeFreshLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("promotion");
        if let Some(observations) = &self.promotion_observations {
            observations
                .lock()
                .expect("promotion observations")
                .push(true);
        }
    }

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("replay");
        if let Some(branch) = self.signal_fault_branches.front().cloned()
            && branch.parent() == &request.configuration
        {
            self.signal_fault_branches.pop_front();
            return self.complete_quantum(crucible::QuantumOutcome {
                configuration: branch.selected().clone(),
                frontier: branch.frontier(),
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: branch.decisions().to_vec(),
                discovered_choices: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible::EventLogOffset::default(),
                scheduler_quiescence: None,
            });
        }
        let configuration = step(
            &request.configuration,
            Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("fresh-runner-non-genesis"),
                value: 7,
            }),
        );
        let next_frontier = self.completed_quanta.saturating_add(1);
        self.complete_quantum(crucible::QuantumOutcome {
            configuration,
            frontier: VirtualTime {
                ticks: next_frontier,
            },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            discovered_choices: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        (self.terminal_after_replay && self.completed_quanta > 0).then(|| {
            crucible::QuantumTerminalVerdict::Failed(vec![String::from(
                "selected property was violated",
            )])
        })
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), crucible::SchedulerError> {
        assert_eq!(
            cause,
            crucible::CheckpointTerminalCause::Failed(vec![String::from(
                "selected property was violated",
            )])
        );
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("terminal-cause");
        Ok(())
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(self.checkpoint_ready)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(std::mem::take(&mut self.pending))
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.replies
            .lock()
            .expect("fresh lifecycle replies")
            .push(reply.clone());
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("capture");
        Ok(test_checkpoint_capture().into())
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("fake lifecycle has no production fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        if self.fingerprint_error {
            return Err(crucible::SchedulerError::BoundaryViolation {
                message: format!("injected missing fingerprint node `{}`", node.name),
            });
        }
        Ok(crucible::FingerprintSample {
            node: self
                .fingerprint_node_override
                .lock()
                .expect("fingerprint node override")
                .clone()
                .unwrap_or(node),
            at: VirtualTime {
                ticks: self.completed_quanta,
            },
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_bytes(&self.completed_quanta.to_le_bytes()),
            },
        })
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, crucible::SchedulerError> {
        Ok(Some(b"resolved-effect-test".to_vec()))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("shutdown");
        if self.cleanup_error {
            Err(crucible::SchedulerError::BoundaryViolation {
                message: String::from("injected fresh lifecycle cleanup failure"),
            })
        } else {
            Ok(vec![SchedulerEventLogEntry::execution_budget_exhausted(
                7,
                VirtualTime { ticks: 11 },
                "final-drain-test",
            )])
        }
    }
}

pub(super) struct FakeFreshLifecycleFactory {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) cleanup_error: bool,
    pub(super) terminal_after_replay: bool,
    pub(super) checkpoint_ready: bool,
}

pub(super) struct ContinuationAcceptingFreshLifecycleFactory {
    pub(super) inner: FakeFreshLifecycleFactory,
    pub(super) continuations: Arc<Mutex<Vec<(u64, crucible::ContentHash)>>>,
}

pub(super) struct FingerprintFailingFreshLifecycleFactory {
    pub(super) inner: FakeFreshLifecycleFactory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CapturedBoundary {
    pub(super) quanta: u64,
    pub(super) configuration: crucible::ContentHash,
    pub(super) events: Vec<SchedulerEventLogEntry>,
}

pub(super) struct BoundaryCaptureLifecycle {
    pub(super) configuration: Configuration,
    pub(super) quanta: u64,
    pub(super) event_log: EventLog,
    pub(super) events: Vec<SchedulerEventLogEntry>,
    pub(super) captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    pub(super) final_events: Vec<SchedulerEventLogEntry>,
    pub(super) replay_decisions: VecDeque<Decision>,
}

impl QemuFreshAttemptLifecycleOwner for BoundaryCaptureLifecycle {
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
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        let at = VirtualTime {
            ticks: self.quanta + 1,
        };
        let append = self.event_log.append_observations_at_boundary(
            std::iter::empty(),
            at,
            SchedulerEvaluationBoundaryKind::Quantum,
        )?;
        self.quanta += 1;
        self.events.extend(append.entries.iter().cloned());
        let configuration = self
            .replay_decisions
            .pop_front()
            .map_or(request.configuration.clone(), |decision| {
                step(&request.configuration, decision)
            });
        Ok(crucible::QuantumOutcome {
            configuration,
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
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: SelectionDecision,
        _selected: &Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("boundary capture fixture has no selectable requests"),
        })
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, crucible::SchedulerError> {
        self.captured
            .lock()
            .expect("captured boundaries")
            .push(CapturedBoundary {
                quanta: self.quanta,
                configuration: self.configuration.id(),
                events: self.events.clone(),
            });
        let checkpoint = Checkpoint::from_recorded_configuration(
            &self.configuration,
            None,
            VirtualTime { ticks: self.quanta },
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| crucible::SchedulerError::BoundaryViolation {
            message: error.to_string(),
        })?;
        let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
            .map_err(|error| crucible::SchedulerError::BoundaryViolation {
                message: error.to_string(),
            })?;
        let byte = u8::try_from(self.quanta).unwrap_or(0xff);
        Ok(
            crate::CapturedExactCheckpoint::new(snapshot, BlobHandle::from_bytes(vec![byte; 512]))
                .into(),
        )
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("boundary capture fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(
        &mut self,
        node: NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        Ok(crucible::FingerprintSample {
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_bytes(node.name.as_bytes()),
            },
            node,
            at: VirtualTime { ticks: self.quanta },
        })
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        Ok(std::mem::take(&mut self.final_events))
    }
}

pub(super) struct BoundaryCaptureLifecycleFactory {
    pub(super) captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    pub(super) final_events: Vec<SchedulerEventLogEntry>,
    pub(super) replay_decisions: VecDeque<Decision>,
}

pub(super) struct SequencedBoundaryCaptureLifecycleFactory {
    pub(super) captured: Arc<Mutex<Vec<CapturedBoundary>>>,
    pub(super) final_events: VecDeque<Vec<SchedulerEventLogEntry>>,
    pub(super) replay_decisions: VecDeque<Decision>,
}

impl QemuFreshAttemptLifecycleFactory for BoundaryCaptureLifecycleFactory {
    type Lifecycle = BoundaryCaptureLifecycle;
    type Error = Infallible;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        Ok(BoundaryCaptureLifecycle {
            configuration: start.clone(),
            quanta: 0,
            event_log: EventLog::new(),
            events: Vec::new(),
            captured: Arc::clone(&self.captured),
            final_events: self.final_events.clone(),
            replay_decisions: self.replay_decisions.clone(),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for SequencedBoundaryCaptureLifecycleFactory {
    type Lifecycle = BoundaryCaptureLifecycle;
    type Error = Infallible;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let final_events = self
            .final_events
            .pop_front()
            .expect("sequenced boundary fixture has one event log per replay");
        Ok(BoundaryCaptureLifecycle {
            configuration: start.clone(),
            quanta: 0,
            event_log: EventLog::new(),
            events: Vec::new(),
            captured: Arc::clone(&self.captured),
            final_events,
            replay_decisions: self.replay_decisions.clone(),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for FakeFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("begin");
        Ok(FakeFreshLifecycle {
            order: Arc::clone(&self.order),
            completed_quanta: 0,
            promotion_observations: None,
            cleanup_error: self.cleanup_error,
            pending: Vec::new(),
            replies: Arc::new(Mutex::new(Vec::new())),
            signal_fault_branches: signal_fault_replay.branches().iter().cloned().collect(),
            terminal_after_replay: self.terminal_after_replay,
            checkpoint_ready: self.checkpoint_ready,
            fingerprint_error: false,
            fingerprint_node_override: Arc::new(Mutex::new(None)),
        })
    }
}

impl QemuFreshAttemptLifecycleFactory for ContinuationAcceptingFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn configure_attempt_continuations(
        &mut self,
        continuations: &[crate::QemuAttemptContinuation<'_>],
    ) -> bool {
        self.continuations
            .lock()
            .expect("accepted continuation trace")
            .extend(continuations.iter().map(|continuation| {
                (
                    continuation.input().source_frontier_ticks(),
                    continuation.source().id(),
                )
            }));
        true
    }

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.inner
            .start_fresh_lifecycle(scenario, source, start, signal_fault_replay, context)
    }
}

impl QemuFreshAttemptLifecycleFactory for FingerprintFailingFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let mut lifecycle = self.inner.start_fresh_lifecycle(
            scenario,
            source,
            start,
            signal_fault_replay,
            context,
        )?;
        lifecycle.fingerprint_error = true;
        Ok(lifecycle)
    }
}

pub(super) struct PromotionRecordingFreshLifecycleFactory {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) observed: Arc<Mutex<Vec<bool>>>,
}

impl QemuFreshAttemptLifecycleFactory for PromotionRecordingFreshLifecycleFactory {
    type Lifecycle = FakeFreshLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &crucible::ScenarioDefForm,
        _start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("begin");
        Ok(FakeFreshLifecycle {
            order: Arc::clone(&self.order),
            completed_quanta: 0,
            promotion_observations: Some(Arc::clone(&self.observed)),
            cleanup_error: false,
            pending: Vec::new(),
            replies: Arc::new(Mutex::new(Vec::new())),
            signal_fault_branches: signal_fault_replay.branches().iter().cloned().collect(),
            terminal_after_replay: false,
            checkpoint_ready: true,
            fingerprint_error: false,
            fingerprint_node_override: Arc::new(Mutex::new(None)),
        })
    }
}

pub(super) struct FakeGenesisCheckpointLifecycle {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) capture: Option<CapturedAttemptCheckpoint>,
    pub(super) launch_profiles: Vec<ProductionVmNodeReplayLaunchProfile>,
    pub(super) checkpoint_ready: bool,
    pub(super) cleanup_error: bool,
}

impl QemuFreshAttemptLifecycleOwner for FakeGenesisCheckpointLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        panic!("fresh genesis capture must not enable signal-fault promotion");
    }

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<crucible::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, crucible::SchedulerError> {
        unreachable!("fresh genesis capture performs no modeled quantum")
    }

    fn completed_quanta(&self) -> u64 {
        0
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("ready");
        Ok(self.checkpoint_ready)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, crucible::SchedulerError>
    {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible::Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &crucible::Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("genesis checkpoint fixture has no selectable transport"),
        })
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("capture");
        self.capture
            .take()
            .ok_or_else(|| crucible::SchedulerError::BoundaryViolation {
                message: String::from("genesis checkpoint fixture was already consumed"),
            })
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("profiles");
        Ok(self.launch_profiles.clone())
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible::SchedulerError> {
        Err(crucible::SchedulerError::BoundaryViolation {
            message: String::from("genesis capture fixture has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible::SchedulerError> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("shutdown");
        if self.cleanup_error {
            Err(crucible::SchedulerError::BoundaryViolation {
                message: String::from("injected genesis capture cleanup failure"),
            })
        } else {
            Ok(Vec::new())
        }
    }
}

pub(super) struct FakeGenesisCheckpointLifecycleFactory {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) capture: Option<CapturedAttemptCheckpoint>,
    pub(super) foreign_capture: bool,
    pub(super) checkpoint_ready: bool,
    pub(super) cleanup_error: bool,
}

impl QemuFreshAttemptLifecycleFactory for FakeGenesisCheckpointLifecycleFactory {
    type Lifecycle = FakeGenesisCheckpointLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        source: &crucible::ScenarioDefForm,
        start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("genesis capture order")
            .push("begin");
        let configuration = if self.foreign_capture {
            Configuration::genesis(ScenarioDef::from_canonical_material(
                "crucible.test.foreign-genesis-capture",
                "foreign",
            ))
        } else {
            start.clone()
        };
        let launch_profiles = source
            .world()
            .vm_nodes()
            .iter()
            .map(|node| {
                ProductionVmNodeReplayLaunchProfile::new(
                    node.id.clone(),
                    QemuLiveNodeStepGateConfig::new(
                        "qemu",
                        "plugin",
                        "kernel",
                        "firmware",
                        format!("run-{}", node.id.name),
                    ),
                )
            })
            .collect();
        let capture = self
            .capture
            .take()
            .unwrap_or_else(|| test_checkpoint_capture_for_configuration(&configuration).into());
        Ok(FakeGenesisCheckpointLifecycle {
            order: Arc::clone(&self.order),
            capture: Some(capture),
            launch_profiles,
            checkpoint_ready: self.checkpoint_ready,
            cleanup_error: self.cleanup_error,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum FakeFreshDriverFailure {
    Retryable,
}

pub(super) struct FakeFreshDriver {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) failure: Option<FakeFreshDriverFailure>,
}

pub(super) struct UnsolicitedCheckpointDriver;

pub(super) struct OrderingCheckpointHandoff {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) checkpoints: ExactCheckpointStore,
}

pub(super) struct PanickingCheckpointHandoff;

impl std::fmt::Debug for PanickingCheckpointHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PanickingCheckpointHandoff")
    }
}

impl AttemptCheckpointHandoff for PanickingCheckpointHandoff {
    fn prepare_and_stage(
        &self,
        _capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        panic!("injected panic after production capture")
    }
}

impl std::fmt::Debug for OrderingCheckpointHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrderingCheckpointHandoff")
            .finish_non_exhaustive()
    }
}

impl AttemptCheckpointHandoff for OrderingCheckpointHandoff {
    fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        let prepared = self
            .checkpoints
            .prepare_attempt_checkpoint(capture.reopenable_copy())
            .map_err(|_| CheckpointHandoffFailure::Terminal)?;
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("stage");
        Ok(prepared)
    }
}

impl QemuFreshAttemptDriver for UnsolicitedCheckpointDriver {
    type Pending = ();
    type Error = &'static str;

    fn drive(
        &mut self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        Ok(QemuFreshDriveOutcome::CheckpointRequested)
    }

    fn seal(
        &mut self,
        _pending: Self::Pending,
        _final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        unreachable!("an unsolicited checkpoint never reaches result sealing")
    }
}

impl QemuFreshAttemptDriver for FakeFreshDriver {
    type Pending = &'static str;
    type Error = &'static str;

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        _materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("drive");
        assert_eq!(lifecycle.pending_network_output_count(), 0);
        assert!(
            lifecycle
                .exact_checkpoint_ready()
                .expect("checkpoint ready")
        );
        if context.checkpoint_request().is_requested() {
            return Ok(QemuFreshDriveOutcome::CheckpointRequested);
        }
        match self.failure {
            None => Ok(QemuFreshDriveOutcome::Observation("pending modeled result")),
            Some(FakeFreshDriverFailure::Retryable) => {
                Err(AttemptWorkerFailure::Retryable("driver retry"))
            }
        }
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        final_events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert_eq!(pending, "pending modeled result");
        assert_eq!(final_events.len(), 1);
        assert_eq!(final_events[0].sequence(), 7);
        let mut order = self.order.lock().expect("fresh lifecycle order");
        assert_eq!(order.last(), Some(&"shutdown"));
        order.push("seal");
        Ok(test_checkpoint_product())
    }
}

pub(super) struct AbsentSelectedSourceResume {
    pub(super) authentications: Arc<AtomicUsize>,
    pub(super) authentication_failure: Option<&'static str>,
}

impl CrucibleExecutionRunner for AbsentSelectedSourceResume {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("selected source absence must route to cold execution")
    }
}

impl QemuSelectedOriginResumeRunner for AbsentSelectedSourceResume {
    fn authenticate_selected_resume_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        assert!(matches!(
            input.start(),
            CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ));
        assert!(context.resume_checkpoint().is_some());
        self.authentications.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.authentication_failure {
            return Err(AttemptWorkerFailure::Terminal(error));
        }
        Ok(None)
    }

    fn execute_verified_selected_origin(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _proof: QemuSavepointReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("an absent selected source has no physical execution path")
    }
}

impl crate::QemuOrdinaryResumeRunner for AbsentSelectedSourceResume {
    fn execute_verified_attempt_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _proof: crate::QemuAttemptStartReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        panic!("absent selected-source fixture must not resume an ordinary attempt")
    }
}

pub(super) fn finding_candidate_artifact(
    input: &CrucibleAttemptExecution,
) -> ConfigurationArtifact {
    let scenario = crate::encode_crucible_scenario_artifact(input.scenario())
        .expect("candidate scenario artifact");
    crate::encode_crucible_configuration_artifact(
        &scenario,
        &input.start().configuration().schedule,
    )
    .expect("candidate configuration artifact")
}

pub(super) fn finding_candidate_input_with_configuration(
    base: &CrucibleAttemptExecution,
    configuration: Configuration,
) -> CrucibleAttemptExecution {
    finding_candidate_input_with_configuration_and_stop(
        base,
        configuration,
        StopCondition::Terminal,
    )
}

pub(super) fn finding_candidate_input_with_configuration_and_stop(
    base: &CrucibleAttemptExecution,
    configuration: Configuration,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let scenario = crate::encode_crucible_scenario_artifact(base.scenario())
        .expect("candidate scenario artifact");
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario, &configuration.schedule)
            .expect("candidate configuration artifact");
    let lineage = CampaignLineage::new(
        scenario.scenario(),
        scenario.id().expect("candidate scenario content ID"),
        configuration_artifact.configuration(),
        configuration_artifact
            .id()
            .expect("candidate configuration content ID"),
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario.payload_schema(),
        1,
    )
    .expect("candidate campaign lineage");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact
                .id()
                .expect("candidate configuration ID"),
        },
        base.path().id().expect("candidate path ID"),
        stop,
    )
    .expect("candidate attempt");
    CrucibleAttemptExecution::from_test_parts(
        lineage,
        base.scenario().clone(),
        attempt,
        base.path().clone(),
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

pub(super) fn owned_finding_candidate(
    input: &CrucibleAttemptExecution,
    discovery: ChoiceDiscovery,
    selection: Selection,
    property: &str,
) -> ObservationCandidate {
    let child = finding_candidate_artifact(input);
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("owned measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        property.to_owned(),
        PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())
            .expect("owned failed property"),
    )]))
    .expect("owned properties");
    let coverage =
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("owned coverage");
    let opportunity = discovery.opportunity().id().expect("opportunity ID");
    let observation = Observation::new(
        input.attempt().id().expect("candidate attempt ID"),
        child.configuration(),
        child.id().expect("candidate child ID"),
        input.path().id().expect("candidate path ID"),
        StopOutcome::AssertionFailure(property.to_owned()),
        measurements.id().expect("owned measurement ID"),
        properties.id().expect("owned property ID"),
        coverage.id().expect("owned coverage ID"),
        BTreeSet::from([opportunity]),
    )
    .expect("owned observation");
    ObservationCandidate::new(
        child,
        measurements,
        properties,
        coverage,
        vec![discovery],
        observation,
    )
    .expect("owned observation candidate")
    .with_produced_selections(vec![selection])
    .expect("owned produced selection")
}

pub(super) fn assert_composed_candidate_replay_retains_choice_and_measurement(
    input: CrucibleAttemptExecution,
    discovery: ChoiceDiscovery,
    selection: Selection,
    assertion: &AssertionId,
) {
    let (lifecycle_artifacts, lifecycle) = finding_replay_lifecycle_fixture();
    let provisional_candidate = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        crucible::ContentHash::from_bytes(b"composed-exact-candidate"),
        input.scenario(),
        input.start().configuration(),
    )
    .expect("candidate reproduction");
    let owned = owned_finding_candidate(
        &input,
        discovery.clone(),
        selection.clone(),
        assertion.name.as_str(),
    );
    let object_root = lifecycle_artifacts.path().join("objects");
    let graph_root = StoreNodeId::new("composed-exact-candidate").expect("store graph node");
    let (blob_backend, blob_admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: graph_root.clone(),
        admitted_kinds: BTreeSet::from([
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
        ]),
        nodes: BTreeMap::from([(
            graph_root,
            StoreNodeSpec::Directory {
                root: object_root.clone(),
            },
        )]),
    })
    .expect("build composed recovery store graph");
    let blob_backend = Arc::new(blob_backend);
    let ref_backend = Arc::new(DirectoryRefBackend::new(
        lifecycle_artifacts.path().join("refs"),
    ));
    let repository = Arc::new(CampaignRepository::new(
        blob_backend.clone(),
        ref_backend.clone(),
    ));
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let request =
        publish_composed_candidate_input(&repository, &store, &input, &discovery, &selection);
    let final_event = SchedulerEventLogEntry::assertion_state_observation(
        1,
        VirtualTime { ticks: 1 },
        assertion.clone(),
        AssertionPhase::Violated,
    );
    let decisions = input
        .start()
        .configuration()
        .schedule
        .decisions()
        .iter()
        .cloned()
        .collect();
    let production_boundaries = Arc::new(Mutex::new(Vec::new()));
    let mut runner = crate::packaged_qemu_executor::packaged_finding_replay_runner(
        lifecycle.clone(),
        BoundaryCaptureLifecycleFactory {
            captured: Arc::clone(&production_boundaries),
            final_events: vec![final_event],
            replay_decisions: decisions,
        },
    );
    let context = fresh_runner_context();
    let target_signature =
        crate::automatic_finding_runner::automatic_finding_signature(&input, &owned)
            .expect("candidate target signature")
            .expect("failed-property target signature");

    let outcome = crate::automatic_finding_runner::replay_candidate(
        &store,
        &mut runner,
        &input,
        &provisional_candidate,
        &owned,
        &target_signature,
        &context,
    )
    .expect("composed exact candidate replay");
    let AutomaticFindingReplayOutcome::Observed {
        evidence,
        measurement_replay_evidence,
        ..
    } = &outcome
    else {
        panic!("exact candidate must reach its semantic boundary")
    };
    assert!(evidence.signature().is_some());
    assert_eq!(evidence.opportunities(), &[discovery.opportunity().clone()]);
    assert_eq!(evidence.selections(), &[selection]);
    assert_eq!(measurement_replay_evidence.len(), 1);
    assert_eq!(
        measurement_replay_evidence[0].configuration(),
        evidence.configuration().configuration()
    );
    let triage = outcome
        .triage_evidence()
        .expect("exact property replay must retain full triage evidence");
    assert_eq!(triage.finding(), &provisional_candidate);
    assert!(matches!(
        triage.failure(),
        crucible::FailureClusterReportFailure::Property(_)
    ));
    assert!(!triage.causal_entries().is_empty());
    assert!(triage.recorded_event_frames().is_empty());

    let signature = outcome
        .signature()
        .expect("exact property replay signature")
        .clone();
    let candidate = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        crucible::ContentHash {
            bytes: signature.fingerprint().as_bytes(),
        },
        input.scenario(),
        input.start().configuration(),
    )
    .expect("signature-bound candidate reproduction");

    let mut transcript = CrucibleFindingReplayTranscript::new();
    transcript
        .record_minimization_outcome(&provisional_candidate, outcome.clone())
        .expect("journal composed minimization replay");
    transcript
        .record_verification_outcome(&provisional_candidate, outcome)
        .expect("journal composed verification replay");

    let minimization_target = signature.clone();
    let prepared = crate::prepare_automatic_signature_preserving_finding_with_outcomes(
        PreparedSemanticAttemptResult::new(owned.clone(), None)
            .expect("prepared composed observation"),
        signature,
        &candidate,
        FindingExactPins::default(),
        Seed::from_bytes([0x75; 32]),
        |replay_candidate| {
            let decisions = replay_candidate
                .artifact
                .schedule()
                .decisions()
                .iter()
                .cloned()
                .collect::<VecDeque<_>>();
            let boundary = u64::try_from(decisions.len()).expect("candidate event sequence");
            let final_event = SchedulerEventLogEntry::assertion_state_observation(
                boundary,
                VirtualTime { ticks: boundary },
                assertion.clone(),
                AssertionPhase::Violated,
            );
            let mut replay_runner = crate::packaged_qemu_executor::packaged_finding_replay_runner(
                lifecycle.clone(),
                BoundaryCaptureLifecycleFactory {
                    captured: Arc::clone(&production_boundaries),
                    final_events: vec![final_event],
                    replay_decisions: decisions,
                },
            );
            Ok(crate::automatic_finding_runner::replay_candidate(
                &store,
                &mut replay_runner,
                &input,
                replay_candidate,
                &owned,
                &minimization_target,
                &context,
            )
            .expect("production candidate replay during automatic minimization"))
        },
    )
    .expect("prepare production rich finding closure");
    let capture_inputs = prepared
        .production_replay_capture_inputs()
        .expect("encode production replay captures")
        .expect("packaged runner must retain production replay captures");
    assert!(matches!(
        prepared.canonical_bytes(),
        Err(crate::PreparedSemanticResultCodecError::Inconsistent {
            component: "unbound finding production replay captures"
        })
    ));
    assert!(
        capture_inputs
            .iter()
            .all(|capture| matches!(capture, crate::FindingReplayCaptureInput::Complete { .. }))
    );
    let durable_captures = FindingReplayCaptureStore::prepare_set(capture_inputs)
        .expect("prepare production replay capture closure");
    let capture_references = durable_captures.references();
    let guard = store
        .acquire_finding_replay_publication_guard()
        .expect("exclude GC while publishing production replay captures");
    FindingReplayCaptureStore::publish_set(&guard, &durable_captures)
        .expect("publish production replay capture closure");

    let bound_finding = prepared
        .prepare_bound_production_replay_finding(capture_references)
        .expect("bind production replay manifests to finding");
    let mut prepared = prepared;
    prepared.commit_bound_production_replay_finding(bound_finding);

    let durable_bytes = prepared
        .canonical_bytes()
        .expect("encode rich prepared result");
    assert_eq!(
        crate::crucible_artifact::PreparedSemanticResultVersion::from_payload(&durable_bytes),
        Some(crate::crucible_artifact::PreparedSemanticResultVersion::V6)
    );
    let expected_observation = prepared
        .observation()
        .observation()
        .id()
        .expect("prepared observation ID");
    let expected_finding = prepared
        .finding()
        .expect("prepared V6 finding")
        .id()
        .expect("prepared V6 finding ID");
    let key = crate::AttemptExecutionKey::new(
        input.lineage().id().expect("candidate lineage ID"),
        input.attempt().id().expect("candidate attempt ID"),
    );
    let producer_execution = ExecutionId::from_bytes([0x77; 16]).expect("producer execution ID");
    let ledger_root = lifecycle_artifacts.path().join("ledger");
    fs::create_dir(&ledger_root).expect("create assignment ledger directory");
    let mut producer_ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("open producer assignment ledger");
    assert_eq!(
        producer_ledger
            .compare_exchange_attempt(
                key,
                None,
                Some(AttemptRuntimeState::Publishing {
                    execution_basis: request.execution_basis_digest(),
                    origin: AttemptExecutionOrigin::Initial,
                    daemon_epoch: DaemonEpoch::from_bytes([0x78; 16])
                        .expect("producer daemon epoch"),
                    execution: producer_execution,
                    observation: expected_observation,
                    finding_candidate: Some(expected_finding),
                    finding_replay_captures: Some(capture_references),
                    finding_exact_retention_roots: [None; 3],
                    prepared_result_digest: None,
                }),
            )
            .expect("stage production replay capture roots before journaling"),
        AttemptStateCas::Advanced
    );
    drop(guard);
    drop(producer_ledger);

    let journal_namespace = lifecycle_artifacts.path().join("journals");
    fs::create_dir(&journal_namespace).expect("create prepared-result journal namespace");
    let (journal, disposition) = DirectoryPreparedResultJournal::create(
        &journal_namespace,
        key,
        producer_execution,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        prepared,
    )
    .expect("create V6 prepared-result journal");
    assert_eq!(
        disposition,
        crate::PreparedResultJournalCreateDisposition::Created
    );
    drop(journal);
    let production_boundaries_before_restart = production_boundaries
        .lock()
        .expect("production replay boundaries")
        .len();
    let capture_manifest = capture_references
        .minimization_original()
        .evidence()
        .expect("complete minimization-original manifest")
        .content_id();
    let manifest_bytes = blob_backend
        .read(capture_manifest, None)
        .expect("load persisted production replay manifest")
        .read_all(64 * 1024)
        .expect("read persisted production replay manifest");
    let manifest = ContentEnvelope::from_canonical_bytes(&manifest_bytes)
        .expect("decode persisted production replay manifest");
    let capture_roots = capture_references
        .references()
        .into_iter()
        .filter_map(crucible_campaign::FindingReplayCaptureReference::evidence)
        .map(|evidence| evidence.content_id());
    let persisted_capture_closure = repository
        .authenticated_closure_ids(capture_roots)
        .expect("authenticate every persisted production replay capture closure");

    let mut restarted_ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen assignment ledger");
    let gc_plan = plan_single_host_campaign_gc(
        &repository,
        ref_backend.as_ref(),
        &mut restarted_ledger,
        blob_backend.as_ref(),
        None,
        &blob_admin,
    )
    .expect("plan GC between V6 journal durability and candidate publication");
    assert!(
        gc_plan
            .candidates()
            .iter()
            .all(|candidate| !persisted_capture_closure.contains(&candidate.id()))
    );
    let (mut gc_journal, _) =
        DirectoryCampaignGcJournal::create(lifecycle_artifacts.path().join("gc-journal"), &gc_plan)
            .expect("journal pre-publication GC plan");
    apply_single_host_campaign_gc(
        &mut gc_journal,
        &repository,
        ref_backend.as_ref(),
        &mut restarted_ledger,
        blob_backend.as_ref(),
        None,
        &blob_admin,
    )
    .expect("apply GC between V6 journal durability and candidate publication");
    let retained_capture_closure = repository
        .authenticated_closure_ids(
            capture_references
                .references()
                .into_iter()
                .filter_map(crucible_campaign::FindingReplayCaptureReference::evidence)
                .map(|evidence| evidence.content_id()),
        )
        .expect("reauthenticate every capture closure after pre-publication GC");
    assert_eq!(retained_capture_closure, persisted_capture_closure);

    let mut supervisor = LocalExecutorSupervisor::new(
        restarted_ledger,
        UnavailableCompletionAdmission,
        request.daemon_epoch(),
        ExecutorCapacity::new(1, 2, 64 * 1024 * 1024, 128 * 1024 * 1024, 64)
            .expect("recovery executor capacity"),
    );
    let response = supervisor
        .submit_attempt(&request)
        .expect("admit restarted V6 attempt");
    let SubmitAttemptDisposition::Accepted {
        execution: recovery_execution,
    } = response.disposition()
    else {
        panic!("restarted V6 attempt must be accepted: {response:?}");
    };
    assert_ne!(recovery_execution, producer_execution);
    let queued = supervisor.next_queued().expect("queued V6 recovery");

    let missing_chunk = manifest
        .children()
        .first()
        .expect("production replay manifest has one chunk")
        .id();
    fs::remove_file(directory_blob_object_path(
        &lifecycle_artifacts.path().join("objects"),
        missing_chunk,
    ))
    .expect("remove one persisted production replay chunk");
    let failed_recovery = crate::recover_prepared_attempt_result(
        &store,
        &journal_namespace,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        queued,
    )
    .expect_err("missing capture chunk must fail V6 recovery");
    assert!(matches!(
        failed_recovery.source,
        AttemptResultRecoveryFailure::CaptureStore(_)
    ));
    assert!(
        repository
            .load_finding_candidate_bundle(expected_finding)
            .is_err()
    );

    let guard = store
        .acquire_finding_replay_publication_guard()
        .expect("exclude GC while restoring missing capture chunk");
    FindingReplayCaptureStore::publish_set(&guard, &durable_captures)
        .expect("restore production replay capture closure");
    drop(guard);

    let capture_chunk_path =
        directory_blob_object_path(&lifecycle_artifacts.path().join("objects"), missing_chunk);
    let mut corrupt_chunk_bytes =
        fs::read(&capture_chunk_path).expect("read restored production replay chunk");
    *corrupt_chunk_bytes
        .first_mut()
        .expect("production replay chunk must not be empty") ^= 0xff;
    fs::write(&capture_chunk_path, corrupt_chunk_bytes)
        .expect("corrupt one persisted production replay chunk");
    let failed_recovery = crate::recover_prepared_attempt_result(
        &store,
        &journal_namespace,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        *failed_recovery.queued,
    )
    .expect_err("corrupt capture chunk must fail V6 recovery");
    assert!(matches!(
        failed_recovery.source,
        AttemptResultRecoveryFailure::CaptureStore(_)
    ));
    assert!(
        repository
            .load_finding_candidate_bundle(expected_finding)
            .is_err()
    );
    assert_eq!(
        production_boundaries
            .lock()
            .expect("production replay boundaries after corrupt recovery")
            .len(),
        production_boundaries_before_restart,
        "corrupt journal recovery must not execute another production lifecycle"
    );

    fs::remove_file(&capture_chunk_path).expect("remove corrupt production replay chunk");
    let guard = store
        .acquire_finding_replay_publication_guard()
        .expect("exclude GC while replacing corrupt capture chunk");
    FindingReplayCaptureStore::publish_set(&guard, &durable_captures)
        .expect("replace corrupt production replay capture closure");
    drop(guard);

    let recovered = crate::recover_prepared_attempt_result(
        &store,
        &journal_namespace,
        MAX_PREPARED_SEMANTIC_RESULT_BYTES,
        *failed_recovery.queued,
    )
    .expect("recover authenticated V6 prepared result after restart");
    let PreparedAttemptRecoveryOutcome::Prepared(prepared) = recovered else {
        panic!("complete V6 journal must recover without guest execution");
    };
    assert_eq!(
        production_boundaries
            .lock()
            .expect("production replay boundaries after restart")
            .len(),
        production_boundaries_before_restart,
        "journal recovery must not execute another production lifecycle"
    );
    let finding = prepared.result().finding().expect("recovered rich finding");
    let triage_ids = finding
        .bundle()
        .triage_evidence()
        .expect("candidate bundle v3 triage evidence");
    assert_eq!(finding.bundle().schema_version(), 3);
    assert_eq!(
        triage_ids.minimization_original(),
        triage_ids.verification_original(),
        "independent original replays must retain identical native evidence",
    );
    assert_eq!(
        triage_ids.minimization_selected(),
        triage_ids.verification_selected(),
        "independent selected replays must retain identical native evidence",
    );

    let replay_captures = finding
        .bundle()
        .replay_captures()
        .expect("recovered V6 finding owns production replay manifests");
    assert_eq!(replay_captures, capture_references);
    assert_eq!(
        supervisor
            .stage_observation_finding_and_replay_capture_publication(
                prepared.queued(),
                expected_observation,
                expected_finding,
                capture_references,
            )
            .expect("restage recovered V6 publication roots"),
        ObservationPublicationOutcome::AlreadyStaged
    );

    let staged = crate::stage_prepared_attempt_result(&mut supervisor, *prepared)
        .expect("stage recovered V6 candidate publication");
    let AttemptResultStageOutcome::Publish(staged) = staged else {
        panic!("recovered V6 candidate must require immutable publication");
    };
    assert!(
        repository
            .load_finding_candidate_bundle(expected_finding)
            .is_err()
    );
    let published = crate::publish_prepared_attempt_result(&store, staged)
        .expect("publish recovered V6 candidate");
    assert_eq!(published.finding_candidate(), Some(expected_finding));
    assert!(repository.load_observation(expected_observation).is_ok());
    let durable_bundle = repository
        .load_finding_candidate_bundle(expected_finding)
        .expect("load published V6 finding candidate");
    assert_eq!(durable_bundle.schema_version(), 3);
    assert_eq!(durable_bundle.replay_captures(), Some(capture_references));
}

pub(super) struct UnavailableCompletionAdmission;

impl AttemptAdmissionValidator for UnavailableCompletionAdmission {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        Ok(())
    }

    fn validate_completion_artifacts(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
        _finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        Err(CompletionValidationFailure::UnavailableInput)
    }
}

pub(super) fn publish_composed_candidate_input(
    repository: &CampaignRepository,
    store: &CampaignExecutorStore,
    input: &CrucibleAttemptExecution,
    discovery: &ChoiceDiscovery,
    selection: &Selection,
) -> SubmitAttemptRequest {
    const CAMPAIGN: &str = "composed-production-recovery";

    let scenario = crate::encode_crucible_scenario_artifact(input.scenario())
        .expect("encode composed recovery scenario");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .expect("publish composed recovery scenario");
    assert_eq!(
        scenario_content,
        input.lineage().scenario_content(),
        "published scenario must match the execution lineage"
    );

    let configuration = crate::encode_crucible_configuration_artifact(
        &scenario,
        &input.start().configuration().schedule,
    )
    .expect("encode composed recovery configuration");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration.scenario(),
            scenario_content,
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .expect("publish composed recovery configuration");
    assert_eq!(configuration_content, input.lineage().genesis_content());

    store
        .publish_executor_choice_domain(discovery.domain())
        .expect("publish composed recovery choice domain");
    store
        .publish_executor_selectable(discovery.declaration())
        .expect("publish composed recovery selectable");
    store
        .publish_executor_choice_opportunity(discovery.opportunity())
        .expect("publish composed recovery choice opportunity");
    store
        .publish_executor_selection(selection)
        .expect("publish composed recovery selection");

    let policy = CampaignPolicy::new(
        input.lineage().scenario(),
        CampaignSeed::from_bytes([0x74; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("composed recovery fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("composed recovery campaign policy");
    let created = repository
        .create(CAMPAIGN, input.lineage(), &policy, &BTreeMap::new())
        .expect("create composed recovery campaign");
    let resumed = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"resume-composed-production-recovery",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume composed recovery campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"fund-composed-production-recovery",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("composed recovery attempt grant"),
                ),
            },
        )
        .expect("fund composed recovery campaign");
    let admitted = repository
        .submit_discovery_request(
            CAMPAIGN,
            &DiscoveryRequest::new(
                CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"discover-composed-production-recovery",
                )),
                funded.new_snapshot,
                configuration_content,
                input.attempt().stop().clone(),
            )
            .expect("composed recovery discovery request"),
        )
        .expect("admit composed recovery attempt");
    let attempt = input.attempt().id().expect("composed recovery attempt ID");
    assert_eq!(admitted.attempt, attempt);

    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x75; 16]).expect("composed recovery assignment"),
        DaemonEpoch::from_bytes([0x76; 16]).expect("composed recovery daemon epoch"),
        input.lineage().id().expect("composed recovery lineage ID"),
        attempt,
        resources(64),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("composed recovery submit request")
}

pub(super) fn directory_blob_object_path(
    root: &std::path::Path,
    id: ContentId,
) -> std::path::PathBuf {
    let encoded = id.encode();
    let digest = encoded
        .rsplit_once('.')
        .expect("content digest separator")
        .1;
    root.join(id.kind().as_str())
        .join(id.schema_version().to_string())
        .join(&digest[..2])
        .join(digest)
}

pub(super) fn finding_replay_lifecycle_fixture() -> (tempfile::TempDir, ProductionVmLifecycleConfig)
{
    let directory = tempfile::tempdir().expect("finding replay lifecycle fixture");
    let root = directory.path();
    let qemu = root.join("bin/qemu-system-x86_64");
    let plugin = root.join("lib/libcrucible-qemu-plugin.so");
    let kernel = root.join("guest/kernel");
    let root_image = root.join("guest/root.qcow2");
    let qemu_marker = root.join("share/aos/crucible/qemu-build-identity.env");
    let plugin_marker = root.join("nix-support/crucible-qemu-plugin-build-info");

    for path in [
        &qemu,
        &plugin,
        &kernel,
        &root_image,
        &qemu_marker,
        &plugin_marker,
    ] {
        fs::create_dir_all(path.parent().expect("fixture artifact parent"))
            .expect("create finding replay fixture directory");
    }
    fs::write(&qemu, b"authenticated qemu fixture").expect("write QEMU fixture");
    fs::write(&plugin, b"authenticated plugin fixture").expect("write plugin fixture");
    fs::write(&kernel, b"guest kernel fixture").expect("write guest kernel fixture");
    fs::write(&root_image, b"guest root fixture").expect("write guest root fixture");

    let abi_version = crucible::SHMEM_ABI_VERSION;
    let abi = format!("crucible-shmem-abi-v{abi_version}");
    fs::write(
        &qemu_marker,
        format!(
            "qemu_sim_capability=qemu-crucible\n\
             qemu_crucible_patches_applied=true\n\
             qemu_plugins_enabled=true\n\
             qemu_build_id=qemu-build-v1\n\
             qemu_patch_series_hash=sha256:patch\n\
             qemu_shmem_abi_version={abi_version}\n\
             qemu_shmem_abi={abi}\n\
             qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n\
             qemu_shmem_header_hash=sha256:header\n"
        ),
    )
    .expect("write QEMU identity marker");
    fs::write(
        &plugin_marker,
        format!(
            "plugin_abi={abi}\n\
             qemu_build_id=qemu-build-v1\n\
             shmem_abi_version={abi_version}\n\
             shmem_abi={abi}\n\
             shmem_generated_header_hash=sha256:header\n"
        ),
    )
    .expect("write plugin identity marker");

    let lifecycle =
        ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image, root.join("run-state"));
    (directory, lifecycle)
}

pub(super) struct NamedSupplementalFindingOracle {
    pub(super) scenario: ScenarioDefForm,
    pub(super) source: GuardedCampaignFindingOracleSource,
    pub(super) truths: SearchScheduleNamedPredicateTruths,
}

impl GuardedCampaignFindingOracle for NamedSupplementalFindingOracle {
    fn source(&self) -> &GuardedCampaignFindingOracleSource {
        &self.source
    }

    fn evaluate(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<GuardedCampaignFindingOracleEvaluation>, GuardedCampaignFindingOracleError>
    {
        crucible::SearchFailureOracle::evaluate_configuration_with_named_predicates(
            &self.scenario,
            configuration,
            &self.truths,
        )
        .map(|finding| finding.map(GuardedCampaignFindingOracleEvaluation::new))
        .map_err(|error| GuardedCampaignFindingOracleError::new(error.to_string()))
    }
}

pub(super) fn fresh_runner_input() -> CrucibleAttemptExecution {
    fresh_runner_input_for_stop(StopCondition::Terminal)
}

pub(super) fn fresh_runner_input_for_stop(stop: StopCondition) -> CrucibleAttemptExecution {
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

pub(super) fn modeled_fresh_runner_input_for_stop(stop: StopCondition) -> CrucibleAttemptExecution {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    modeled_fresh_runner_input_for_scenario(scenario, stop)
}

pub(super) fn modeled_assertion_candidate_input(
    assertion: AssertionId,
    predicate_at: u64,
) -> CrucibleAttemptExecution {
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty World");
    modeled_assertion_candidate_input_for_world(world, assertion, predicate_at)
}

pub(super) fn modeled_assertion_candidate_input_with_vm(
    assertion: AssertionId,
    predicate_at: u64,
) -> CrucibleAttemptExecution {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("node-a"),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("finding-replay-production-capture"),
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
    .expect("finding replay production capture World");
    modeled_assertion_candidate_input_for_world(world, assertion, predicate_at)
}

pub(super) fn modeled_assertion_candidate_input_for_world(
    world: World,
    assertion: AssertionId,
    predicate_at: u64,
) -> CrucibleAttemptExecution {
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion,
            message: String::from("candidate safety failed"),
            property: Property::Always {
                predicate: Predicate::At {
                    at: VirtualTime {
                        ticks: predicate_at,
                    },
                },
            },
        }],
    )
    .expect("candidate properties");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &properties,
        Seed::from_u64(0x51a7_5afe),
    )
    .expect("candidate assertion scenario");
    modeled_fresh_runner_input_for_scenario(scenario, StopCondition::Terminal)
}

pub(super) fn modeled_fresh_runner_input_for_scenario(
    scenario: ScenarioDefForm,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let definition = scenario.scenario_def();
    let scenario_artifact =
        crate::encode_crucible_scenario_artifact(&scenario).expect("encoded scenario artifact");
    let scenario_id = scenario_artifact.scenario();
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(definition);
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encoded configuration artifact");
    let configuration_id = configuration_artifact.configuration();
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
        scenario_artifact.payload_schema(),
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

pub(super) fn selected_after_genesis_input() -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    selected_after_genesis_input_with_continuation(None)
}

pub(super) fn selected_after_genesis_input_with_continuation(
    continuation_input: Option<AttemptContinuationInput>,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    let source_stop = continuation_input
        .as_ref()
        .map(|input| StopCondition::VirtualTimeNanoseconds(input.source_frontier_ticks()))
        .unwrap_or(StopCondition::ExecutionQuanta(1));
    selected_after_genesis_input_with_optional_continuation_source_stop(
        continuation_input,
        source_stop.clone(),
        StopOutcome::Reached(source_stop),
    )
}

pub(super) fn selected_after_genesis_input_with_continuation_source_stop(
    continuation_input: AttemptContinuationInput,
    source_stop: StopCondition,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    selected_after_genesis_input_with_continuation_source_evidence(
        continuation_input,
        source_stop.clone(),
        StopOutcome::Reached(source_stop),
    )
}

pub(super) fn selected_after_genesis_input_with_continuation_source_evidence(
    continuation_input: AttemptContinuationInput,
    source_stop: StopCondition,
    source_outcome: StopOutcome,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    selected_after_genesis_input_with_optional_continuation_source_stop(
        Some(continuation_input),
        source_stop,
        source_outcome,
    )
}

pub(super) fn selected_after_genesis_input_with_optional_continuation_source_stop(
    continuation_input: Option<AttemptContinuationInput>,
    source_stop: StopCondition,
    source_outcome: StopOutcome,
) -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
) {
    let base = fresh_runner_input();
    let configuration = base.start().configuration().clone();
    let reached = step(
        &configuration,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let AttemptStart::Discover {
        configuration: configuration_artifact,
    } = base.attempt().start()
    else {
        panic!("fresh fixture must discover from genesis");
    };
    let origin = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact,
        },
        base.attempt().path(),
        source_stop.clone(),
    )
    .expect("selected origin attempt");
    let source_attempt = origin.id().expect("selected origin attempt ID");
    let reached_id = ConfigurationId::from_hash(CampaignHash::from_bytes(reached.id().bytes));
    let reached_artifact = ConfigurationArtifact::new(
        base.lineage().scenario(),
        base.lineage().scenario_content(),
        reached_id,
        1,
        b"selected-origin-reached".to_vec(),
    )
    .expect("selected reached configuration artifact")
    .id()
    .expect("selected reached configuration artifact ID");
    let continuation_start = AttemptStart::AfterAttempt {
        origin: source_attempt,
        reached: reached_artifact,
    };
    let continuation = match continuation_input {
        Some(input) => Attempt::new_with_continuation_input(
            continuation_start,
            base.attempt().path(),
            StopCondition::Terminal,
            input,
        ),
        None => Attempt::new(
            continuation_start,
            base.attempt().path(),
            StopCondition::Terminal,
        ),
    }
    .expect("selected continuation attempt");
    let base_replay = crucible::SignalFaultCampaignReplayPlan::empty(configuration.clone());
    let reached_replay = crucible::SignalFaultCampaignReplayPlan::empty(reached.clone());
    let origins = CrucibleAttemptOrigins::new(
        CrucibleAttemptOrigin::new_with_source_stop(
            origin,
            reached,
            reached_replay,
            source_outcome,
        ),
        Vec::new(),
    );
    let input = CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        continuation,
        base.path().clone(),
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(CrucibleResolvedAttemptStart::Discover {
                configuration: configuration.clone(),
            }),
            base_signal_fault_replay: base_replay,
            origins: Box::new(origins),
        },
    );
    let source_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"absent-selected-source-checkpoint",
    ))
    .expect("selected source checkpoint");

    (input, source_attempt, source_checkpoint)
}

pub(super) fn selected_after_two_controlled_generations() -> (
    CrucibleAttemptExecution,
    crucible_campaign::AttemptId,
    ExactCheckpointId,
    [(u64, crucible::ContentHash); 2],
) {
    let base = fresh_runner_input();
    let configuration = base.start().configuration().clone();
    let reached_first = step(
        &configuration,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let reached_second = step(
        &reached_first,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let AttemptStart::Discover {
        configuration: configuration_artifact,
    } = base.attempt().start()
    else {
        panic!("fresh fixture must discover from genesis");
    };
    let first = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact,
        },
        base.attempt().path(),
        StopCondition::VirtualTimeNanoseconds(1),
    )
    .expect("first source attempt");
    let first_id = first.id().expect("first source attempt ID");
    let reached_first_artifact =
        test_reached_configuration_artifact(&base, &reached_first, b"two-control-first-reached");
    let second = Attempt::new_with_continuation_input(
        AttemptStart::AfterAttempt {
            origin: first_id,
            reached: reached_first_artifact,
        },
        base.attempt().path(),
        StopCondition::VirtualTimeNanoseconds(2),
        AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation_for(b"two-control-first-observation"),
            1,
            [0x29; 32],
        ),
    )
    .expect("first controlled continuation");
    let second_id = second.id().expect("first controlled continuation ID");
    let reached_second_artifact =
        test_reached_configuration_artifact(&base, &reached_second, b"two-control-second-reached");
    let current = Attempt::new_with_continuation_input(
        AttemptStart::AfterAttempt {
            origin: second_id,
            reached: reached_second_artifact,
        },
        base.attempt().path(),
        StopCondition::Terminal,
        AttemptContinuationInput::scheduler_reseed(
            test_continuation_source_observation_for(b"two-control-second-observation"),
            2,
            [0x47; 32],
        ),
    )
    .expect("second controlled continuation");
    let first_origin = CrucibleAttemptOrigin::new_with_source_stop(
        first,
        reached_first.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(reached_first.clone()),
        crucible_campaign::StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(1)),
    );
    let second_origin = CrucibleAttemptOrigin::new_with_source_stop(
        second,
        reached_second.clone(),
        crucible::SignalFaultCampaignReplayPlan::empty(reached_second.clone()),
        crucible_campaign::StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2)),
    );
    let expected_controls = [(1, reached_first.id()), (2, reached_second.id())];
    let input = CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        base.scenario().clone(),
        current,
        base.path().clone(),
        CrucibleResolvedAttemptStart::AfterAttempt {
            base: Box::new(CrucibleResolvedAttemptStart::Discover {
                configuration: configuration.clone(),
            }),
            base_signal_fault_replay: crucible::SignalFaultCampaignReplayPlan::empty(configuration),
            origins: Box::new(CrucibleAttemptOrigins::new(
                first_origin,
                vec![second_origin],
            )),
        },
    );
    let source_checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        2,
        b"two-control-selected-source-checkpoint",
    ))
    .expect("selected source checkpoint");

    (input, second_id, source_checkpoint, expected_controls)
}

pub(super) fn test_reached_configuration_artifact(
    base: &CrucibleAttemptExecution,
    reached: &Configuration,
    bytes: &[u8],
) -> crucible_campaign::ConfigurationArtifactId {
    let reached_id = ConfigurationId::from_hash(CampaignHash::from_bytes(reached.id().bytes));
    ConfigurationArtifact::new(
        base.lineage().scenario(),
        base.lineage().scenario_content(),
        reached_id,
        1,
        bytes.to_vec(),
    )
    .expect("selected reached configuration artifact")
    .id()
    .expect("selected reached configuration artifact ID")
}

pub(super) fn campaign_fact_id(byte: u8) -> CampaignFactId {
    let content = ContentId::for_bytes(ObjectKind::CampaignFact, 10, &[byte; 32]);
    CampaignFactId::parse(&format!("crucible.campaign.fact@{}", content.encode()))
        .expect("campaign fact")
}

pub(super) fn test_continuation_source_observation() -> crucible_campaign::ObservationId {
    test_continuation_source_observation_for(b"controlled-continuation-source-observation")
}

pub(super) fn test_continuation_source_observation_for(
    bytes: &[u8],
) -> crucible_campaign::ObservationId {
    let content = ContentId::for_bytes(ObjectKind::Observation, 6, bytes);
    crucible_campaign::ObservationId::parse(&format!(
        "crucible.campaign.observation@{}",
        content.encode()
    ))
    .expect("controlled continuation source observation")
}

pub(super) fn non_genesis_fresh_runner_input() -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("fresh-runner-non-genesis"),
        value: 7,
    }))
}

pub(super) fn modeled_non_genesis_fresh_runner_input() -> CrucibleAttemptExecution {
    modeled_non_genesis_fresh_runner_input_for_stop(StopCondition::Terminal)
}

pub(super) fn modeled_non_genesis_fresh_runner_input_for_stop(
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let base = modeled_fresh_runner_input_for_stop(StopCondition::Terminal);
    let scenario = base.scenario().clone();
    let configuration = step(
        &Configuration::genesis(scenario.scenario_def()),
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("fresh-runner-non-genesis"),
            value: 7,
        }),
    );
    let scenario_artifact =
        crate::encode_crucible_scenario_artifact(&scenario).expect("modeled scenario artifact");
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("modeled non-genesis configuration artifact");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_artifact
                .id()
                .expect("modeled non-genesis artifact ID"),
        },
        path.id().expect("branch path ID"),
        stop,
    )
    .expect("modeled non-genesis attempt");

    CrucibleAttemptExecution::from_test_parts(
        base.lineage().clone(),
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

pub(super) fn non_genesis_fresh_runner_input_with_decision(
    decision: Decision,
) -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decisions(vec![decision])
}

pub(super) fn non_genesis_fresh_runner_input_with_decisions(
    decisions: Vec<Decision>,
) -> CrucibleAttemptExecution {
    non_genesis_fresh_runner_input_with_decisions_for_stop(decisions, StopCondition::Terminal)
}

pub(super) fn non_genesis_fresh_runner_input_with_decisions_for_stop(
    decisions: Vec<Decision>,
    stop: StopCondition,
) -> CrucibleAttemptExecution {
    let input = fresh_runner_input();
    let scenario = input.scenario().clone();
    let definition = scenario.scenario_def();
    let configuration = decisions.into_iter().fold(
        Configuration::genesis(definition.clone()),
        |parent, decision| step(&parent, decision),
    );
    let scenario_id = input.lineage().scenario();
    let scenario_content = input.lineage().scenario_content();
    let configuration_id =
        ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes));
    let configuration_artifact = ConfigurationArtifact::new(
        scenario_id,
        scenario_content,
        configuration_id,
        1,
        b"non-genesis-configuration".to_vec(),
    )
    .expect("non-genesis configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("non-genesis configuration artifact id");
    let path = BranchPath::new(Vec::new()).expect("genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path id"),
        stop,
    )
    .expect("non-genesis discovery attempt");

    CrucibleAttemptExecution::from_test_parts(
        input.lineage().clone(),
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

pub(super) fn fresh_runner_context() -> AttemptExecutionContext {
    context(resources(4), ExecutionCancellation::default())
}

pub(super) fn test_checkpoint_capture() -> crate::CapturedExactCheckpoint {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.fresh-campaign-runner",
        "sealed-product",
    ));
    test_checkpoint_capture_for_configuration(&configuration)
}

pub(super) fn test_checkpoint_capture_for_configuration(
    configuration: &Configuration,
) -> crate::CapturedExactCheckpoint {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("fresh runner checkpoint boundary");
    let snapshot = QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("fresh runner QEMU snapshot");
    crate::CapturedExactCheckpoint::new(snapshot, BlobHandle::from_bytes(vec![0x5a; 512]))
}

pub(super) fn test_checkpoint_product() -> AttemptExecutionProduct {
    AttemptExecutionProduct::exact_checkpoint(test_checkpoint_capture())
}
