//! Fresh-lifecycle owner fake shared by the campaign lifecycle tests.

use super::*;

pub(super) struct FakeFreshLifecycle {
    pub(super) order: Arc<Mutex<Vec<&'static str>>>,
    pub(super) completed_quanta: u64,
    pub(super) promotion_observations: Option<Arc<Mutex<Vec<bool>>>>,
    pub(super) cleanup_error: bool,
    pub(super) pending: Vec<crucible_qemu_host::QemuNodeSelectablePendingRequest>,
    pub(super) replies: Arc<Mutex<Vec<crucible_qemu_protocol::SelectionReply>>>,
    pub(super) signal_fault_branches: VecDeque<crucible_engine::SignalFaultCampaignBranch>,
    pub(super) terminal_after_replay: bool,
    pub(super) released_host_outcome: Option<(u64, crucible_engine::QuantumOutcome, bool)>,
    pub(super) checkpoint_ready: bool,
    pub(super) fingerprint_error: bool,
    pub(super) fingerprint_node_override: Arc<Mutex<Option<crucible_engine::NodeId>>>,
    pub(super) network_park: Option<super::network_fault_replay::FakeNetworkPark>,
}

impl FakeFreshLifecycle {
    fn complete_quantum(
        &mut self,
        outcome: crucible_engine::QuantumOutcome,
    ) -> Result<crucible_engine::QuantumOutcome, crucible_engine::SchedulerError> {
        self.completed_quanta = self.completed_quanta.checked_add(1).ok_or_else(|| {
            crucible_engine::SchedulerError::BoundaryViolation {
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
        _frontier: Option<crucible_engine::VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        request: crucible_engine::QuantumRequest,
    ) -> Result<crucible_engine::QuantumOutcome, crucible_engine::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("replay");
        if let Some(branch) = self.signal_fault_branches.front().cloned()
            && branch.parent().matches(&request.configuration)
        {
            self.signal_fault_branches.pop_front();
            return self.complete_quantum(crucible_engine::QuantumOutcome {
                configuration: branch.selected().to_configuration(),
                frontier: branch.frontier(),
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: branch.decisions().to_vec(),
                discovered_choices: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: crucible_engine::EventLogOffset::default(),
                scheduler_quiescence: None,
            });
        }
        let configuration = accepted_step(
            &request.configuration,
            Decision::RngDraw(RngDecision::ordinal(
                RngStreamId::from_name("fresh-runner-non-genesis"),
                0,
                7,
            )),
        );
        let next_frontier = self.completed_quanta.saturating_add(1);
        self.complete_quantum(crucible_engine::QuantumOutcome {
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
            event_log_offset: crucible_engine::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }

    fn park_held_campaign_markers(
        &mut self,
        markers: &[&str],
        outcome: &mut crucible_engine::QuantumOutcome,
    ) -> Result<usize, SchedulerError> {
        if markers != crate::qemu_campaign_driver::NETWORK_FAULT_PHASE_MARKERS {
            return Err(SchedulerError::BoundaryViolation {
                message: format!("unexpected parked campaign markers: {markers:?}"),
            });
        }
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("park");
        if let Some(park) = &mut self.network_park {
            park.observe_quantum(self.completed_quanta);
            outcome
                .event_log_entries
                .extend(std::mem::take(&mut park.published));
        }
        Ok(1)
    }

    fn parked_campaign_marker(
        &mut self,
        node: &crucible_engine::NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        Ok(self
            .network_park
            .as_ref()
            .and_then(|park| park.parked_marker(node)))
    }

    fn join_campaign_parks_to_frontier(&mut self) -> Result<Option<VirtualTime>, SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("join");
        Ok(self.network_park.as_ref().and_then(|park| park.joined_at()))
    }

    fn append_network_fault_campaign_branch(
        &mut self,
        branch: &crucible_engine::NetworkFaultCampaignBranch,
    ) -> Result<(Configuration, Vec<SchedulerEventLogEntry>), SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("append");
        // Like the production scheduler, the branch append is one quantum.
        self.completed_quanta += 1;
        let entries = self
            .network_park
            .as_mut()
            .map(|park| std::mem::take(&mut park.branch_entries))
            .unwrap_or_default();
        Ok((branch.selected().clone(), entries))
    }

    fn release_parked_campaign_marker(
        &mut self,
        node: &crucible_engine::NodeId,
        marker: &str,
        _selected: crucible_engine::ContentHash,
    ) -> Result<(), SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("release");
        self.network_park
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("fake lifecycle has no network park"),
            })?
            .release(node, marker)
    }

    fn publish_released_host_outcomes(
        &mut self,
        _configuration: &Configuration,
    ) -> Result<Option<crucible_engine::QuantumOutcome>, SchedulerError> {
        if self
            .released_host_outcome
            .as_ref()
            .is_none_or(|(after, _, _)| self.completed_quanta < *after)
        {
            return Ok(None);
        }
        let (_, outcome, terminal) = self
            .released_host_outcome
            .take()
            .expect("eligible retained fixture outcome");
        self.terminal_after_replay = terminal;
        self.complete_quantum(outcome).map(Some)
    }

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn event_log_offset(&self) -> Result<crucible_engine::EventLogOffset, SchedulerError> {
        Ok(crucible_engine::EventLogOffset::default())
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible_engine::QuantumTerminalVerdict> {
        (self.terminal_after_replay && self.completed_quanta > 0).then(|| {
            crucible_engine::QuantumTerminalVerdict::Failed(vec![String::from(
                "selected property was violated",
            )])
        })
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible_engine::CheckpointTerminalCause,
    ) -> Result<(), crucible_engine::SchedulerError> {
        assert_eq!(
            cause,
            crucible_engine::CheckpointTerminalCause::Failed(vec![String::from(
                "selected property was violated",
            )])
        );
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("terminal-cause");
        Ok(())
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, crucible_engine::SchedulerError> {
        Ok(self.checkpoint_ready)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<
        Vec<crucible_qemu_host::QemuNodeSelectablePendingRequest>,
        crucible_engine::SchedulerError,
    > {
        Ok(std::mem::take(&mut self.pending))
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &crucible_engine::Configuration,
        _decision: crucible_engine::SelectionDecision,
        _selected: &crucible_engine::Configuration,
        _pending: &crucible_qemu_host::QemuNodeSelectablePendingRequest,
        reply: &crucible_qemu_protocol::SelectionReply,
    ) -> Result<Vec<crucible_engine::SchedulerEventLogEntry>, crucible_engine::SchedulerError> {
        self.replies
            .lock()
            .expect("fresh lifecycle replies")
            .push(reply.clone());
        Ok(Vec::new())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, crucible_engine::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("capture");
        Ok(test_checkpoint_capture())
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, crucible_engine::SchedulerError> {
        Err(crucible_engine::SchedulerError::BoundaryViolation {
            message: String::from("fake fresh lifecycle has no replay launch profiles"),
        })
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<ProductionFaultEvidenceSnapshot, crucible_engine::SchedulerError> {
        Err(crucible_engine::SchedulerError::BoundaryViolation {
            message: String::from("fake lifecycle has no production fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(
        &mut self,
        node: crucible_engine::NodeId,
    ) -> Result<crucible_engine::FingerprintSample, crucible_engine::SchedulerError> {
        if self.fingerprint_error {
            return Err(crucible_engine::SchedulerError::BoundaryViolation {
                message: format!("injected missing fingerprint node `{}`", node.name),
            });
        }
        Ok(crucible_engine::FingerprintSample {
            node: self
                .fingerprint_node_override
                .lock()
                .expect("fingerprint node override")
                .clone()
                .unwrap_or(node),
            at: VirtualTime {
                ticks: self.completed_quanta,
            },
            fingerprint: crucible_engine::ExecutionFingerprint {
                hash: crucible_engine::ContentHash::from_bytes(
                    &self.completed_quanta.to_le_bytes(),
                ),
            },
        })
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), crucible_engine::SchedulerError> {
        Ok(())
    }

    fn resolved_effect_trace(
        &self,
    ) -> Result<Option<crucible_engine::model::ResolvedEffectTrace>, crucible_engine::SchedulerError>
    {
        Ok(Some(
            crucible_engine::model::ResolvedEffectTrace::empty(
                crucible_engine::model::FaultReplayMode::RecomputedCause,
            )
            .map_err(|error| crucible_engine::SchedulerError::BoundaryViolation {
                message: format!("fixture effect trace did not build: {error}"),
            })?,
        ))
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, crucible_engine::SchedulerError> {
        self.order
            .lock()
            .expect("fresh lifecycle order")
            .push("shutdown");
        if self.cleanup_error {
            Err(crucible_engine::SchedulerError::BoundaryViolation {
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
