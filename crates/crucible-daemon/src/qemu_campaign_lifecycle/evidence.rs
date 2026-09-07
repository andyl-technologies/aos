//! Bounded process-local evidence capture for fresh QEMU attempts.
//!
//! This observer decorates a resource-owned lifecycle without acquiring any
//! launch or shutdown authority of its own. It retains exact event,
//! fingerprint, frontier, and resolved-effect material for compatibility
//! callers that need to build a reproduction artifact after the campaign
//! repository accepts the observation.

use crucible::{
    FingerprintSample, NodeId, QuantumTerminalVerdict, SchedulerError, SchedulerEventLogEntry,
};

// crucible-lint: allow host-nondeterminism-state -- the observer forwards scheduler-owned quantum requests and records successful outcomes without selecting modeled state.
use crucible::{QuantumOutcome, QuantumRequest};
// crucible-lint: allow host-nondeterminism-state -- replay and fault snapshots remain typed evidence forwarded from the guarded lifecycle.
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmNodeReplayLaunchProfile};
use crucible_protocol::SelectionReply;
use crucible_qemu::QemuNodeSelectablePendingRequest;
use thiserror::Error;

use super::{
    AttemptExecutionContext, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    MAX_QEMU_ATTEMPT_GENERATION_NODES, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner,
};

const MAX_EXECUTION_FINGERPRINT_SAMPLES: usize = MAX_QEMU_ATTEMPT_GENERATION_NODES * 2;

/// Fresh lifecycle wrapper that records exact process-local execution evidence.
///
/// Resource enforcement remains wholly owned by the wrapped lifecycle. This
/// observer records only successfully completed scheduler operations and never
/// substitutes for the attempt's process or storage guard.
pub struct QemuObservedFreshAttemptLifecycle<L> {
    lifecycle: L,
    driven_quanta: u64,
    fingerprint_nodes: Vec<NodeId>,
    evidence: QemuAttemptExecutionEvidence,
}

impl<L> QemuObservedFreshAttemptLifecycle<L> {
    pub(super) fn new(
        lifecycle: L,
        fingerprint_nodes: Vec<NodeId>,
        evidence: QemuAttemptExecutionEvidence,
    ) -> Self {
        Self {
            lifecycle,
            driven_quanta: 0,
            fingerprint_nodes,
            evidence,
        }
    }
}

impl<L> QemuFreshAttemptLifecycleOwner for QemuObservedFreshAttemptLifecycle<L>
where
    L: QemuFreshAttemptLifecycleOwner,
{
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.lifecycle.enable_signal_fault_campaign_promotion();
    }

    // crucible-lint: allow host-nondeterminism-state -- quantum authority remains with the wrapped scheduler lifecycle; this wrapper retains its successful result.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        if self.driven_quanta == 0 {
            self.record_fingerprints()?;
        }

        // crucible-lint: allow host-nondeterminism-state -- the wrapped lifecycle remains the sole quantum driver.
        let outcome = self.lifecycle.drive_quantum(request)?;
        self.driven_quanta = self.driven_quanta.checked_add(1).ok_or_else(|| {
            evidence_limit("observed-qemu-quanta", self.driven_quanta, 1, u64::MAX)
        })?;
        self.evidence.record(
            self.driven_quanta,
            outcome.frontier,
            &outcome.event_log_entries,
        )?;
        if self.driven_quanta == 1 {
            self.record_fingerprints()?;
        }
        Ok(outcome)
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.lifecycle.terminal_verdict_for_stop()
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.lifecycle.exact_checkpoint_ready()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.lifecycle.drain_pending_selectable_requests()
    }

    fn enqueue_selectable_reply(
        &mut self,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.enqueue_selectable_reply(pending, reply)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.lifecycle.capture_attempt_checkpoint(context)
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        self.lifecycle.replay_launch_profiles()
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.lifecycle.fault_evidence_snapshot()
    }

    fn pending_network_output_count(&self) -> usize {
        self.lifecycle.pending_network_output_count()
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        self.lifecycle.sample_fingerprint(node)
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        self.lifecycle.resolved_effect_trace()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let resolved_effect_trace = self.lifecycle.resolved_effect_trace();
        let final_events = self.lifecycle.shutdown()?;
        self.evidence
            .complete(&final_events, resolved_effect_trace?)?;
        Ok(final_events)
    }
}

impl<L> QemuObservedFreshAttemptLifecycle<L>
where
    L: QemuFreshAttemptLifecycleOwner,
{
    fn record_fingerprints(&mut self) -> Result<(), SchedulerError> {
        let samples = self
            .fingerprint_nodes
            .iter()
            .cloned()
            .map(|node| self.lifecycle.sample_fingerprint(node))
            .collect::<Result<Vec<_>, _>>()?;
        self.evidence.record_fingerprints(samples)
    }
}

mod store;
use store::evidence_limit;
pub use store::{QemuAttemptExecutionEvidence, QemuAttemptExecutionEvidenceSnapshot};

/// Adds bounded process-local evidence capture to any fresh lifecycle factory.
pub struct QemuObservedFreshAttemptLifecycleFactory<F> {
    inner: F,
    evidence: QemuAttemptExecutionEvidence,
}

impl<F> QemuObservedFreshAttemptLifecycleFactory<F> {
    /// Wraps a fresh factory and returns its read-only evidence handle.
    #[must_use]
    pub fn with_evidence(inner: F) -> (Self, QemuAttemptExecutionEvidence) {
        let evidence = QemuAttemptExecutionEvidence::default();
        (
            Self {
                inner,
                evidence: evidence.clone(),
            },
            evidence,
        )
    }
}

/// Failure to construct an evidence-observed fresh QEMU lifecycle.
#[derive(Debug, Error)]
pub enum QemuObservedFreshAttemptLifecycleFactoryError<E> {
    /// The wrapped guarded lifecycle factory rejected construction.
    #[error("construct guarded QEMU lifecycle: {0}")]
    Inner(#[source] E),
    /// The process-local evidence recorder could not be reset.
    #[error("reset QEMU attempt execution evidence: {0}")]
    Evidence(#[source] SchedulerError),
}

impl<F> QemuFreshAttemptLifecycleFactory for QemuObservedFreshAttemptLifecycleFactory<F>
where
    F: QemuFreshAttemptLifecycleFactory,
{
    type Lifecycle = QemuObservedFreshAttemptLifecycle<F::Lifecycle>;
    type Error = QemuObservedFreshAttemptLifecycleFactoryError<F::Error>;

    fn start_fresh_lifecycle(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- the authenticated scenario is forwarded unchanged to the guarded lifecycle factory.
        scenario: &crucible::ScenarioDef,
        source: &crucible::ScenarioDefForm,
        // crucible-lint: allow host-nondeterminism-state -- the authenticated start configuration is forwarded unchanged to the guarded lifecycle factory.
        start: &crucible::Configuration,
        signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.evidence
            .reset()
            .map_err(QemuObservedFreshAttemptLifecycleFactoryError::Evidence)
            .map_err(AttemptWorkerFailure::Retryable)?;
        let lifecycle = self
            .inner
            .start_fresh_lifecycle(scenario, source, start, signal_fault_replay, context)
            .map_err(map_factory_failure)?;
        let mut fingerprint_nodes = source
            .world()
            .vm_nodes()
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        fingerprint_nodes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(QemuObservedFreshAttemptLifecycle::new(
            lifecycle,
            fingerprint_nodes,
            self.evidence.clone(),
        ))
    }
}

fn map_factory_failure<E>(
    failure: AttemptWorkerFailure<E>,
) -> AttemptWorkerFailure<QemuObservedFreshAttemptLifecycleFactoryError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuObservedFreshAttemptLifecycleFactoryError::Inner(error),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuObservedFreshAttemptLifecycleFactoryError::Inner(error),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuObservedFreshAttemptLifecycleFactoryError::Inner(error),
        ),
    }
}
