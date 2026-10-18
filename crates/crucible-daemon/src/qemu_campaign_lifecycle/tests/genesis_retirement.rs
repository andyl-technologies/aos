//! Exercises the real generic genesis return algorithm with a resource-free owner.
//!
//! Placeholder checkpoint codec material supplies semantic capture identity; it
//! cannot launch QEMU and supplies no Main, Source or native admission grant.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum ComponentFailure {
    #[error("component start refused")]
    Start,
    #[error("component owner return refused")]
    Return,
}

struct CapturingOwner {
    inner: FakeFreshLifecycle,
    capture: Option<CapturedAttemptCheckpoint>,
    identity: Arc<()>,
}

impl QemuFreshAttemptLifecycleOwner for CapturingOwner {
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.inner.enable_signal_fault_campaign_promotion();
    }

    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        self.inner.set_attempt_stop_frontier(frontier)
    }

    fn drive_quantum(
        &mut self,
        request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        self.inner.drive_quantum(request)
    }

    fn completed_quanta(&self) -> u64 {
        self.inner.completed_quanta()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        self.inner.terminal_verdict_for_stop()
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        self.inner.prepare_terminal_checkpoint(cause)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.inner.exact_checkpoint_ready()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.inner.drain_pending_selectable_requests()
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.inner
            .apply_selectable_reply(parent, decision, selected, pending, reply)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.inner
            .order
            .lock()
            .expect("component order")
            .push("capture");
        Ok(self.capture.take().expect("exactly one capture"))
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Ok(Vec::new())
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.inner.fault_evidence_snapshot()
    }

    fn pending_network_output_count(&self) -> usize {
        self.inner.pending_network_output_count()
    }

    fn sample_fingerprint(
        &mut self,
        node: NodeId,
    ) -> Result<crucible::FingerprintSample, SchedulerError> {
        self.inner.sample_fingerprint(node)
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        self.inner.prepare_terminal_fingerprints()
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        self.inner.resolved_effect_trace()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.inner.shutdown()
    }
}

struct ReturningFactory {
    inner: FakeFreshLifecycleFactory,
    capture: Option<CapturedAttemptCheckpoint>,
    identity: Arc<()>,
    returned: Option<CapturingOwner>,
    reject_start: bool,
    reject_return: bool,
}

impl QemuFreshAttemptLifecycleFactory for ReturningFactory {
    type Lifecycle = CapturingOwner;
    type Error = ComponentFailure;

    fn start_fresh_lifecycle(
        &mut self,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        start: &Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<CapturingOwner, AttemptWorkerFailure<ComponentFailure>> {
        if self.reject_start {
            return Err(AttemptWorkerFailure::Terminal(ComponentFailure::Start));
        }
        // This existing component producer has no admission effects or grant.
        let inner = self
            .inner
            .start_fresh_lifecycle(scenario, source, start, signal_fault_replay, context)
            .expect("resource-free producer");
        Ok(CapturingOwner {
            inner,
            capture: self.capture.take(),
            identity: self.identity.clone(),
        })
    }

    fn retire_lifecycle(&mut self, owner: CapturingOwner) -> Result<(), ComponentFailure> {
        assert!(Arc::ptr_eq(&owner.identity, &self.identity));
        assert!(self.returned.is_none(), "exact owner returns once");
        owner
            .inner
            .order
            .lock()
            .expect("component order")
            .push("return");
        self.returned = Some(owner);
        if self.reject_return {
            Err(ComponentFailure::Return)
        } else {
            Ok(())
        }
    }
}

fn factory(
    capture: CapturedAttemptCheckpoint,
    ready: bool,
    cleanup_error: bool,
    reject_return: bool,
) -> ReturningFactory {
    ReturningFactory {
        inner: FakeFreshLifecycleFactory {
            order: Arc::new(Mutex::new(Vec::new())),
            cleanup_error,
            terminal_after_replay: false,
            checkpoint_ready: ready,
        },
        capture: Some(capture),
        identity: Arc::new(()),
        returned: None,
        reject_start: false,
        reject_return,
    }
}

#[test]
fn every_genesis_outcome_returns_the_same_owner_once_after_shutdown() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let directory = tempfile::tempdir().expect("codec fixture directory");
    let fixture = crate::build_exact_ram_production_checkpoint_codec_fixture(directory.path())
        .expect("nonlaunchable checkpoint fixture");

    for ready in [false, true] {
        for cleanup_error in [false, true] {
            for reject_return in [false, true] {
                let mut factory = factory(
                    CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone()),
                    ready,
                    cleanup_error,
                    reject_return,
                );
                let result = capture_fresh_genesis_checkpoint_candidate(
                    &mut factory,
                    fixture.source(),
                    &fresh_runner_context(),
                );
                let expected = if ready {
                    vec!["begin", "capture", "shutdown", "return"]
                } else {
                    vec!["begin", "shutdown", "return"]
                };
                assert_eq!(
                    *factory.inner.order.lock().expect("component order"),
                    expected
                );
                let returned = factory
                    .returned
                    .as_ref()
                    .expect("same owner retained even after negative return");
                assert!(Arc::ptr_eq(&returned.identity, &factory.identity));

                if reject_return {
                    let error = result.expect_err("actual owner return refusal");
                    assert_eq!(
                        error.source().expect("raw return leaf").to_string(),
                        ComponentFailure::Return.to_string()
                    );
                    let QemuFreshGenesisCheckpointError::Retirement {
                        capture,
                        cleanup,
                        retirement,
                    } = error
                    else {
                        panic!("independent raw causes were replaced")
                    };
                    assert_eq!(retirement, ComponentFailure::Return);
                    assert_eq!(capture.is_some(), !ready);
                    assert_eq!(cleanup.is_some(), cleanup_error);
                } else if cleanup_error {
                    let QemuFreshGenesisCheckpointError::Cleanup { prior, cleanup } =
                        result.expect_err("shutdown keeps original precedence")
                    else {
                        panic!("shutdown classification changed")
                    };
                    assert_eq!(prior.is_some(), !ready);
                    assert!(
                        cleanup
                            .to_string()
                            .contains("injected fresh lifecycle cleanup failure")
                    );
                } else if ready {
                    assert!(
                        result.is_ok(),
                        "valid candidate survives accepted actual return"
                    );
                } else {
                    assert!(matches!(
                        result,
                        Err(QemuFreshGenesisCheckpointError::Capture(
                            QemuFreshGenesisCheckpointCaptureFailure::NotCheckpointReady
                        ))
                    ));
                }
            }
        }
    }
}

#[test]
fn refused_genesis_start_never_calls_shutdown_or_returns_an_unborn_owner() {
    let _metadata = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let directory = tempfile::tempdir().expect("codec fixture directory");
    let fixture = crate::build_exact_ram_production_checkpoint_codec_fixture(directory.path())
        .expect("nonlaunchable checkpoint fixture");
    let mut factory = factory(
        CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone()),
        true,
        false,
        false,
    );
    factory.reject_start = true;

    let result = capture_fresh_genesis_checkpoint_candidate(
        &mut factory,
        fixture.source(),
        &fresh_runner_context(),
    );

    assert!(matches!(
        result,
        Err(QemuFreshGenesisCheckpointError::Start(
            AttemptWorkerFailure::Terminal(ComponentFailure::Start)
        ))
    ));
    assert!(factory.returned.is_none());
    assert!(
        factory
            .inner
            .order
            .lock()
            .expect("component order")
            .is_empty()
    );
}
