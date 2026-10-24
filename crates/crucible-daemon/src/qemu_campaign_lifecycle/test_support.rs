//! Scripted fresh-lifecycle fakes for thin-attempt world retention.
//!
//! The lifecycle and factory here script the final-boundary drain, the
//! shutdown entries, and source preparation of one fresh attempt, and record
//! each effect in order. Runner tests and lifecycle-wrapper tests share them.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failures.
#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use crucible::{
    Configuration, NodeId, ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerEventLogEntry,
    SelectionDecision, VirtualTime,
};
use crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld;
use crucible_api::{ProductionFaultEvidenceSnapshot, ProductionVmNodeReplayLaunchProfile};

use super::{
    QemuFinalBoundaryDrain, QemuFreshAttemptLifecycleFactory, QemuFreshAttemptLifecycleOwner,
    QemuRetainedSourcePreparation,
};
use crate::{AttemptExecutionContext, AttemptWorkerFailure, CapturedAttemptCheckpoint};

/// Shared record of the lifecycle effects a fixture observed, in order.
pub(crate) type Order = Arc<Mutex<Vec<&'static str>>>;

/// Returns the resolved-effect trace every scripted lifecycle reports.
pub(crate) fn retention_trace() -> crucible::model::ResolvedEffectTrace {
    crucible::model::ResolvedEffectTrace::empty(crucible::model::FaultReplayMode::LockedEffect)
        .expect("empty locked-effect trace")
}

/// What source preparation does with a drained lifecycle.
pub(crate) enum Preparation {
    /// Preparation declines and returns the lifecycle.
    Recover,
    /// Preparation yields this prepared source world.
    Prepare(Box<ProductionVmHotForkSourceWorld>),
}

/// Scripted lifecycle effects for one attempt.
pub(crate) struct Script {
    drain: Result<QemuFinalBoundaryDrain, &'static str>,
    shutdown_events: Vec<SchedulerEventLogEntry>,
    preparation: Preparation,
}

impl Script {
    /// Scripts `drain` with no shutdown entries and a declining preparation.
    pub(crate) fn new(drain: QemuFinalBoundaryDrain) -> Self {
        Self {
            drain: Ok(drain),
            shutdown_events: Vec::new(),
            preparation: Preparation::Recover,
        }
    }

    /// Makes shutdown publish entries with these sequence numbers.
    pub(crate) fn with_shutdown_events(mut self, sequences: &[u64]) -> Self {
        self.shutdown_events = sequences.iter().copied().map(entry).collect();
        self
    }

    /// Makes source preparation yield `world`.
    pub(crate) fn preparing(mut self, world: ProductionVmHotForkSourceWorld) -> Self {
        self.preparation = Preparation::Prepare(Box::new(world));
        self
    }

    /// Makes the final-boundary drain fail with `message`.
    pub(crate) fn failing_drain(mut self, message: &'static str) -> Self {
        self.drain = Err(message);
        self
    }
}

/// Fresh lifecycle owner with scripted drain and shutdown effects.
pub(crate) struct RetentionLifecycle {
    order: Order,
    drain: Option<Result<QemuFinalBoundaryDrain, &'static str>>,
    shutdown_events: Vec<SchedulerEventLogEntry>,
}

impl QemuFreshAttemptLifecycleOwner for RetentionLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn set_attempt_stop_frontier(
        &mut self,
        _frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn drive_quantum(
        &mut self,
        _request: crucible::QuantumRequest,
    ) -> Result<crucible::QuantumOutcome, SchedulerError> {
        Err(boundary_violation("a genesis discovery replays no quanta"))
    }

    fn completed_quanta(&self) -> u64 {
        0
    }

    fn event_log_offset(&self) -> Result<crucible::EventLogOffset, SchedulerError> {
        crate::qemu_campaign_lifecycle::refuse_event_log_offset()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<crucible::QuantumTerminalVerdict> {
        None
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        _cause: crucible::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        Err(boundary_violation("retention never captures a checkpoint"))
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn apply_selectable_reply(
        &mut self,
        _parent: &Configuration,
        _decision: SelectionDecision,
        _selected: &Configuration,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Err(boundary_violation(
            "retention fixtures publish no guest requests",
        ))
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        Err(boundary_violation("retention never captures a checkpoint"))
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        Err(boundary_violation(
            "retention fixtures have no launch profiles",
        ))
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(boundary_violation(
            "retention fixtures have no fault evidence",
        ))
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn sample_fingerprint(
        &mut self,
        node: NodeId,
    ) -> Result<crucible::FingerprintSample, SchedulerError> {
        Ok(crucible::FingerprintSample {
            node,
            at: VirtualTime::default(),
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_bytes(b"retention-fingerprint"),
            },
        })
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        Ok(())
    }

    fn resolved_effect_trace(
        &self,
    ) -> Result<Option<crucible::model::ResolvedEffectTrace>, SchedulerError> {
        Ok(Some(retention_trace()))
    }

    fn drain_final_events_for_retention(
        &mut self,
    ) -> Result<QemuFinalBoundaryDrain, SchedulerError> {
        self.order.lock().expect("retention order").push("drain");
        match self.drain.take() {
            Some(Ok(drain)) => Ok(drain),
            Some(Err(message)) => Err(boundary_violation(message)),
            None => Err(boundary_violation("final boundary drained twice")),
        }
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.order.lock().expect("retention order").push("shutdown");
        Ok(std::mem::take(&mut self.shutdown_events))
    }
}

/// Fresh lifecycle factory that runs one scripted attempt.
pub(crate) struct RetentionFactory {
    order: Order,
    script: Option<Script>,
    preparation: Option<Preparation>,
}

impl RetentionFactory {
    /// Runs `script` once, recording effects into `order`.
    pub(crate) fn new(order: Order, script: Script) -> Self {
        Self {
            order,
            script: Some(script),
            preparation: None,
        }
    }
}

impl QemuFreshAttemptLifecycleFactory for RetentionFactory {
    type Lifecycle = RetentionLifecycle;
    type Error = &'static str;

    fn start_fresh_lifecycle(
        &mut self,
        _scenario: &ScenarioDef,
        _source: &ScenarioDefForm,
        _start: &Configuration,
        _signal_fault_replay: &crucible::SignalFaultCampaignReplayPlan,
        _context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.order.lock().expect("retention order").push("begin");
        let script = self.script.take().ok_or(AttemptWorkerFailure::Terminal(
            "retention fixture runs once",
        ))?;
        self.preparation = Some(script.preparation);
        Ok(RetentionLifecycle {
            order: Arc::clone(&self.order),
            drain: Some(script.drain),
            shutdown_events: script.shutdown_events,
        })
    }

    fn prepare_retained_source(
        &mut self,
        lifecycle: Self::Lifecycle,
        _source: &ScenarioDefForm,
        _boundary: &Configuration,
    ) -> QemuRetainedSourcePreparation<Self::Lifecycle> {
        self.order.lock().expect("retention order").push("prepare");
        match self.preparation.take() {
            Some(Preparation::Prepare(world)) => QemuRetainedSourcePreparation::Prepared(world),
            Some(Preparation::Recover) | None => {
                QemuRetainedSourcePreparation::Recovered(lifecycle)
            }
        }
    }
}

pub(crate) fn boundary_violation(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}

/// Builds one final scheduler entry with `sequence`.
pub(crate) fn entry(sequence: u64) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::execution_budget_exhausted(
        sequence,
        VirtualTime { ticks: sequence },
        "retention-final-entry",
    )
}
