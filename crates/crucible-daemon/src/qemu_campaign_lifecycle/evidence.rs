//! Bounded process-local evidence capture for QEMU attempts.
//!
//! This observer decorates a resource-owned lifecycle without acquiring any
//! launch or shutdown authority of its own. It retains exact event,
//! fingerprint, frontier, and resolved-effect material for compatibility
//! callers that need to build a reproduction artifact after the campaign
//! repository accepts the observation.
//!
//! The guarded portable-report owner attaches this observer to fresh production
//! lifecycles. Exact-resume and hot-fork factory adapters preserve the same
//! capture contract for owners that retain and consume the evidence handle.

use crucible::{
    Configuration, FingerprintSample, NodeId, QuantumTerminalVerdict, SchedulerError,
    SchedulerEventLogEntry, SelectionDecision, VirtualTime,
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
    MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES, QemuAttemptContinuation, QemuFreshAttemptLifecycleFactory,
    QemuFreshAttemptLifecycleOwner,
};

const MAX_EXECUTION_FINGERPRINT_SAMPLES: usize = MAX_QEMU_ATTEMPT_GENERATION_NODES * 2;
const MAX_TERMINAL_FINGERPRINT_SAMPLES: usize = MAX_QEMU_ATTEMPT_GENERATION_NODES;

/// Lifecycle wrapper that records exact process-local execution evidence.
///
/// Resource enforcement remains wholly owned by the wrapped lifecycle. This
/// observer records only successfully completed scheduler operations and never
/// substitutes for the attempt's process or storage guard.
pub struct QemuObservedFreshAttemptLifecycle<L> {
    lifecycle: L,
    initial_fingerprints_recorded: bool,
    post_first_quantum_fingerprints_recorded: bool,
    fingerprint_nodes: Vec<NodeId>,
    staged_terminal_fingerprints: Option<Vec<FingerprintSample>>,
    evidence: QemuAttemptExecutionEvidence,
}

impl<L> QemuObservedFreshAttemptLifecycle<L> {
    pub(crate) fn new(
        lifecycle: L,
        fingerprint_nodes: Vec<NodeId>,
        evidence: QemuAttemptExecutionEvidence,
    ) -> Self {
        Self {
            lifecycle,
            initial_fingerprints_recorded: false,
            post_first_quantum_fingerprints_recorded: false,
            fingerprint_nodes,
            staged_terminal_fingerprints: None,
            evidence,
        }
    }

    pub(crate) fn lifecycle(&self) -> &L {
        &self.lifecycle
    }

    pub(crate) fn lifecycle_mut(&mut self) -> &mut L {
        &mut self.lifecycle
    }

    pub(crate) fn into_recovery_parts(self) -> (L, Vec<NodeId>, QemuAttemptExecutionEvidence) {
        (self.lifecycle, self.fingerprint_nodes, self.evidence)
    }
}

impl<L> QemuFreshAttemptLifecycleOwner for QemuObservedFreshAttemptLifecycle<L>
where
    L: QemuFreshAttemptLifecycleOwner,
{
    fn enable_signal_fault_campaign_promotion(&mut self) {
        self.lifecycle.enable_signal_fault_campaign_promotion();
    }

    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.set_attempt_stop_frontier(frontier)
    }

    // crucible-lint: allow host-nondeterminism-state -- quantum authority remains with the wrapped scheduler lifecycle; this wrapper retains its successful result.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        if !self.initial_fingerprints_recorded {
            self.record_fingerprints()?;
            self.initial_fingerprints_recorded = true;
        }

        let prior_quanta = self.lifecycle.completed_quanta();
        // crucible-lint: allow host-nondeterminism-state -- the wrapped lifecycle remains the sole quantum driver.
        let outcome = self.lifecycle.drive_quantum(request)?;
        let completed_quanta = self.lifecycle.completed_quanta();
        if completed_quanta < prior_quanta {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "observed scheduler quantum coordinate regressed from {prior_quanta} to {completed_quanta}"
                ),
            });
        }
        self.evidence.record(
            completed_quanta,
            outcome.frontier,
            &outcome.event_log_entries,
        )?;
        if completed_quanta > prior_quanta && !self.post_first_quantum_fingerprints_recorded {
            self.record_fingerprints()?;
            self.post_first_quantum_fingerprints_recorded = true;
        }
        Ok(outcome)
    }

    fn completed_quanta(&self) -> u64 {
        self.lifecycle.completed_quanta()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.lifecycle.terminal_verdict_for_stop()
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        self.lifecycle.prepare_terminal_checkpoint(cause)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.lifecycle.exact_checkpoint_ready()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.lifecycle.drain_pending_selectable_requests()
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.lifecycle
            .apply_selectable_reply(parent, decision, selected, pending, reply)
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

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        self.lifecycle.prepare_terminal_fingerprints()?;
        if self.staged_terminal_fingerprints.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("terminal fingerprints were already prepared"),
            });
        }

        let samples = self.sample_fingerprints()?;
        self.staged_terminal_fingerprints = Some(samples);
        Ok(())
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        self.lifecycle.resolved_effect_trace()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let resolved_effect_trace = self.lifecycle.resolved_effect_trace();
        let final_events = self.lifecycle.shutdown()?;
        let terminal_fingerprints = self.staged_terminal_fingerprints.take();
        self.evidence
            .complete(&final_events, resolved_effect_trace?, terminal_fingerprints)?;
        Ok(final_events)
    }
}

impl<L> QemuObservedFreshAttemptLifecycle<L>
where
    L: QemuFreshAttemptLifecycleOwner,
{
    fn record_fingerprints(&mut self) -> Result<(), SchedulerError> {
        let samples = self.sample_fingerprints()?;
        self.evidence.record_fingerprints(samples)
    }

    fn sample_fingerprints(&mut self) -> Result<Vec<FingerprintSample>, SchedulerError> {
        let mut samples = Vec::new();
        samples
            .try_reserve(self.fingerprint_nodes.len())
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("reserve execution fingerprint samples: allocation failed"),
            })?;
        for expected in &self.fingerprint_nodes {
            let sample = self.lifecycle.sample_fingerprint(expected.clone())?;
            if sample.node != *expected {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "execution fingerprint sample named node `{}` while `{}` was requested",
                        sample.node.name, expected.name
                    ),
                });
            }
            samples.push(sample);
        }
        Ok(samples)
    }
}

mod store;
pub use store::{QemuAttemptExecutionEvidence, QemuAttemptExecutionEvidenceSnapshot};

/// Adds bounded process-local evidence capture to a QEMU lifecycle factory.
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

    pub(crate) fn inner_mut(&mut self) -> &mut F {
        &mut self.inner
    }

    pub(crate) fn prepare_observation(
        &self,
        source: &crucible::ScenarioDefForm,
    ) -> Result<Vec<NodeId>, AttemptWorkerFailure<SchedulerError>> {
        self.evidence
            .reset()
            .map_err(AttemptWorkerFailure::Retryable)?;
        let vm_nodes = source.world().vm_nodes();
        if vm_nodes.len() > MAX_TERMINAL_FINGERPRINT_SAMPLES {
            return Err(AttemptWorkerFailure::Terminal(store::evidence_limit(
                "qemu-terminal-fingerprint-node-count",
                0,
                vm_nodes.len() as u64,
                MAX_TERMINAL_FINGERPRINT_SAMPLES as u64,
            )));
        }
        let mut fingerprint_nodes = vm_nodes
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        fingerprint_nodes.sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(duplicate) = fingerprint_nodes
            .windows(2)
            .find(|pair| pair[0] == pair[1])
            .map(|pair| pair[0].name.clone())
        {
            return Err(AttemptWorkerFailure::Terminal(
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "authenticated World contains duplicate VM node `{duplicate}` for fingerprint capture"
                    ),
                },
            ));
        }
        Ok(fingerprint_nodes)
    }

    pub(crate) fn observe<L>(
        &self,
        lifecycle: L,
        fingerprint_nodes: Vec<NodeId>,
    ) -> QemuObservedFreshAttemptLifecycle<L> {
        QemuObservedFreshAttemptLifecycle::new(lifecycle, fingerprint_nodes, self.evidence.clone())
    }
}

/// Failure to construct an evidence-observed QEMU lifecycle.
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

    fn configure_attempt_continuation(
        &mut self,
        continuation: Option<QemuAttemptContinuation<'_>>,
    ) -> bool {
        self.inner.configure_attempt_continuation(continuation)
    }

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
        let fingerprint_nodes = self
            .prepare_observation(source)
            .map_err(map_observed_evidence_failure::<F::Error>)?;
        let lifecycle = self
            .inner
            .start_fresh_lifecycle(scenario, source, start, signal_fault_replay, context)
            .map_err(map_observed_inner_failure)?;
        Ok(self.observe(lifecycle, fingerprint_nodes))
    }
}

pub(crate) fn map_observed_inner_failure<E>(
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

pub(crate) fn map_observed_evidence_failure<E>(
    failure: AttemptWorkerFailure<SchedulerError>,
) -> AttemptWorkerFailure<QemuObservedFreshAttemptLifecycleFactoryError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuObservedFreshAttemptLifecycleFactoryError::Evidence(error),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuObservedFreshAttemptLifecycleFactoryError::Evidence(error),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuObservedFreshAttemptLifecycleFactoryError::Evidence(error),
        ),
    }
}
