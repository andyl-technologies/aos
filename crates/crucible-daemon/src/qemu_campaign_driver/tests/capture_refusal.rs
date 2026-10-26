//! A savepoint capture whose reached stop is not exact-checkpoint ready.
//!
//! The capture fails closed at its stop, and the refusal names the
//! lifecycle's readiness reason in both the failure and the diagnostic row.

use super::super::savepoint_refusal::savepoint_capture_refusal_row;
use super::*;
use crucible_api::ProductionExactCheckpointNotReady;

/// Reaches its single-quantum stop at a boundary the lifecycle refuses.
struct RefusingStopLifecycle {
    configuration: Configuration,
    completed_quanta: u64,
    refusal: QemuExactCheckpointRefusal,
}

impl QemuModeledAttemptLifecycle for RefusingStopLifecycle {
    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("refusing-stop fixture received another configuration"),
            });
        }
        self.completed_quanta += 1;
        Ok(outcome(
            self.configuration.clone(),
            Vec::new(),
            EventLogOffset::default(),
            self.completed_quanta,
        ))
    }

    fn completed_quanta(&self) -> u64 {
        self.completed_quanta
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(false)
    }

    fn exact_checkpoint_refusal(
        &mut self,
    ) -> Result<Option<QemuExactCheckpointRefusal>, SchedulerError> {
        Ok(Some(self.refusal.clone()))
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: crucible::SelectionDecision,
        _selected: &Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("refusing-stop fixture has no selectable transport"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("refusing-stop fixture has no execution fingerprint"),
        })
    }
}

fn savepoint_capture_context() -> AttemptExecutionContext {
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 1).expect("capture resources"),
        ExecutionRetentionIntent::RetainAlways,
        ExecutionCancellation::default(),
        checkpoint_request,
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_start_mode(AttemptStartMode::SavepointCapture {
        request: CampaignFactId::parse(&format!(
            "crucible.campaign.fact@{}",
            ContentId::for_bytes(
                ObjectKind::CampaignFact,
                crucible_campaign::CampaignRecordKind::Fact.schema_version(),
                b"refused-capture-request",
            )
        ))
        .expect("capture request ID"),
        configuration: ConfigurationArtifactId::parse(&format!(
            "crucible.campaign.configuration-artifact@{}",
            ContentId::for_bytes(
                ObjectKind::Configuration,
                1,
                b"refused-capture-configuration"
            )
        ))
        .expect("configuration artifact ID"),
    })
}

#[test]
fn savepoint_capture_at_a_held_stop_fails_closed_with_the_named_reason() {
    let input = input(StopCondition::ExecutionQuanta(1));
    let mut lifecycle = RefusingStopLifecycle {
        configuration: starting_configuration(&input),
        completed_quanta: 0,
        refusal: QemuExactCheckpointRefusal::Named(
            ProductionExactCheckpointNotReady::UnsettledHostContinuation,
        ),
    };

    let Err(failure) = drive_modeled_attempt(
        &mut lifecycle,
        &input,
        &savepoint_capture_context(),
        QemuFreshStartMaterialization::genesis(),
    ) else {
        panic!("a held stop must not hand a checkpoint request to the runner");
    };

    let rendered = format!("{failure:?}");
    assert!(
        rendered.contains("savepoint capture stop is not checkpoint ready")
            && rendered.contains(
                "physical checkpoint cannot retain held or unpublished host RUN outcomes"
            ),
        "unexpected refusal: {rendered}"
    );
    assert_eq!(lifecycle.completed_quanta, 1);
}

#[test]
fn savepoint_capture_refusal_row_names_the_attempt_and_reason() {
    let held = QemuExactCheckpointRefusal::Named(
        ProductionExactCheckpointNotReady::UnsettledHostContinuation,
    );
    let device = QemuExactCheckpointRefusal::Named(ProductionExactCheckpointNotReady::DeviceIo {
        node: NodeId {
            name: String::from("router-a"),
        },
    });

    assert_eq!(
        savepoint_capture_refusal_row("attempt-7", &held),
        "CRUCIBLE-SAVEPOINT-CAPTURE-REFUSAL-V1 attempt=attempt-7 \
         reason=unsettled-host-continuation node=none \
         detail=physical checkpoint cannot retain held or unpublished host RUN outcomes"
    );
    assert_eq!(
        savepoint_capture_refusal_row("attempt-7", &device),
        "CRUCIBLE-SAVEPOINT-CAPTURE-REFUSAL-V1 attempt=attempt-7 reason=device-io \
         node=router-a detail=device I/O on node router-a is not quiescent"
    );
    assert_eq!(
        savepoint_capture_refusal_row("attempt-7", &QemuExactCheckpointRefusal::Unnamed),
        "CRUCIBLE-SAVEPOINT-CAPTURE-REFUSAL-V1 attempt=attempt-7 reason=unnamed node=none \
         detail=the lifecycle named no readiness reason"
    );
}
