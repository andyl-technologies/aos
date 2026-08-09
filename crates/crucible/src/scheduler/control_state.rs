//! Trigger action state, verdicts, actor control, and scheduler observations.

use super::*;
/// Determinism class for a scheduler event-log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEventLogClass {
    /// Causal entries participate in deterministic replay comparison.
    Causal,
    /// Observational entries are descriptive and excluded from causal comparison.
    Observational,
}

/// Deterministic scheduler boundary that may trigger condition evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEvaluationBoundaryKind {
    /// A quantum boundary keyed by virtual time / icount.
    Quantum,
    /// A rendezvous boundary keyed by virtual time / icount.
    Rendezvous,
}

/// Observational diagnostic payload used as the open-set escape hatch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventDiagnosticPayload {
    /// Stable diagnostic name.
    pub name: String,
    /// Display level for this diagnostic.
    pub level: EventLevel,
    /// Typed diagnostic details keyed by stable field name.
    pub details: BTreeMap<String, EventAttributeValue>,
}

impl EventDiagnosticPayload {
    /// Builds a diagnostic payload.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        level: EventLevel,
        details: BTreeMap<String, EventAttributeValue>,
    ) -> Self {
        Self {
            name: name.into(),
            level,
            details,
        }
    }

    /// Returns this diagnostic as an open-set event payload.
    #[must_use]
    pub fn event_payload(&self) -> EventPayload {
        EventPayload::diagnostic(self.name.clone(), self.details.clone())
    }
}

/// Payload variants emitted by the scheduler EMIT phase.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerEventLogPayload {
    /// A resolved scheduler happening made visible this quantum.
    ResolvedHappening(ScheduledEvent),
    /// A decision taken and appended to the schedule this quantum.
    Decision(Decision),
    /// An observable condition fact appended to the event log.
    Observable(ObservableEventPayload),
    /// A deterministic evaluation boundary appended to the event log.
    EvaluationBoundary(SchedulerEvaluationBoundaryKind),
    /// A deterministic trigger firing computed from a checked condition prefix.
    TriggerFired(EventFiring),
    /// A deterministic trigger action effect applied at the firing boundary.
    TriggerActionApplied(TriggerActionApplication),
    /// Typed evidence from signal-driven fault evaluation and application.
    FaultObservation(crate::model::FaultObservation),
    /// An observational diagnostic escape-hatch entry.
    Diagnostic(EventDiagnosticPayload),
}

/// Scheduler-owned state produced by deterministic trigger action application.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TriggerActionState {
    /// Every non-group action applied by triggers in deterministic application order.
    pub applications: Vec<TriggerActionApplication>,
    /// Trigger timers armed by name with their absolute virtual-time fire point.
    pub armed_timers: BTreeMap<TimerId, VirtualTime>,
    /// Trigger-scheduled node lifecycle overrides keyed by declared node.
    pub node_states: BTreeMap<NodeId, NodeLifecycle>,
    /// Savepoint requests raised by trigger actions.
    pub savepoints: Vec<TriggerLabelRecord>,
    /// Fork requests raised by trigger actions.
    pub forks: Vec<TriggerLabelRecord>,
    /// Latest pass verdict or first sticky fail verdict raised by a trigger action.
    pub verdict: Option<TriggerVerdict>,
    /// Whether a trigger pass/fail action requested run termination.
    pub termination_requested: bool,
    /// Observational diagnostics raised by trigger log actions.
    pub diagnostics: Vec<TriggerDiagnosticRecord>,
}

impl TriggerActionState {
    /// Composes trigger pass/fail state with the final assertion-layer verdict.
    ///
    /// Assertion failures and explicit trigger failures both fail the run. An
    /// explicit trigger pass is retained only when the assertion layer passed and
    /// no trigger failure fired.
    #[must_use]
    pub fn compose_run_verdict(&self, assertions: AssertionRunVerdict) -> ComposedRunVerdict {
        let mut assertion_failures = assertions.failures().to_vec();
        assertion_failures.sort();
        let mut failures = assertion_failures
            .into_iter()
            .map(ComposedRunVerdictFailure::Assertion)
            .collect::<Vec<_>>();
        if let Some(trigger) = self
            .verdict
            .as_ref()
            .filter(|verdict| verdict.failed_reason.is_some())
        {
            failures.push(ComposedRunVerdictFailure::Trigger(trigger.clone()));
        }
        if failures.is_empty() {
            ComposedRunVerdict::Passed {
                trigger: self.verdict.clone(),
            }
        } else {
            ComposedRunVerdict::Failed { failures }
        }
    }

    /// Composes a run verdict by replaying trigger verdict actions from event-log entries.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when any supplied event-log
    /// entry has a content hash that does not match its canonical material.
    pub fn compose_run_verdict_from_event_log(
        entries: &[SchedulerEventLogEntry],
        assertions: AssertionRunVerdict,
    ) -> Result<ComposedRunVerdict, SchedulerError> {
        let mut state = Self::default();
        for entry in entries {
            if !entry.has_valid_content_hash() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "event-log entry {} has invalid content hash during trigger verdict replay",
                        entry.sequence()
                    ),
                });
            }
            if let SchedulerEventLogPayload::TriggerActionApplied(application) = entry.payload() {
                apply_trigger_verdict_effect(&mut state, application);
            }
        }
        Ok(state.compose_run_verdict(assertions))
    }
}

/// One deterministic non-group trigger action application.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerActionApplication {
    /// Monotone scheduler-local trigger action sequence.
    pub sequence: u64,
    /// Event whose firing produced this action.
    pub event: crate::EventId,
    /// Virtual time at which the action was applied.
    pub at: VirtualTime,
    /// Path through nested `Group` actions, in declared zero-based indexes.
    pub path: Vec<u64>,
    /// Non-group action applied at this path.
    pub action: Action,
}

impl TriggerActionApplication {
    /// Returns whether this action application is observational rather than causal.
    #[must_use]
    pub fn is_observational(&self) -> bool {
        matches!(self.action, Action::Log { .. })
    }
}

/// One trigger request to label a temporal graph boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerLabelRecord {
    /// Trigger action sequence that raised the request.
    pub sequence: u64,
    /// Event whose firing produced the request.
    pub event: crate::EventId,
    /// Virtual time at which the request was raised.
    pub at: VirtualTime,
    /// Optional stable author label.
    pub label: Option<String>,
}

/// A trigger-sourced pass/fail verdict request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerVerdict {
    /// Trigger action sequence that raised the verdict.
    pub sequence: u64,
    /// Event whose firing produced the verdict.
    pub event: crate::EventId,
    /// Virtual time at which the verdict was raised.
    pub at: VirtualTime,
    /// Failure reason when this is a fail verdict; absent for pass.
    pub failed_reason: Option<String>,
}

/// Final assertion-layer verdict supplied to trigger verdict composition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AssertionRunVerdict {
    /// The assertion layer finalized without failing properties.
    Passed,
    /// One or more assertion properties failed.
    Failed {
        /// Assertion failures supplied by the assertion layer.
        ///
        /// [`Self::failed`] sorts this list when constructing the verdict, and
        /// final run-verdict composition normalizes it before emitting failure
        /// causes.
        failures: Vec<AssertionVerdictFailure>,
    },
}

impl AssertionRunVerdict {
    /// Builds a passed assertion verdict.
    #[must_use]
    pub const fn passed() -> Self {
        Self::Passed
    }

    /// Builds a failed assertion verdict with deterministic failure ordering.
    ///
    /// Empty failure lists normalize to [`Self::Passed`].
    #[must_use]
    pub fn failed(mut failures: Vec<AssertionVerdictFailure>) -> Self {
        if failures.is_empty() {
            return Self::Passed;
        }
        failures.sort();
        Self::Failed { failures }
    }

    /// Returns true when the assertion layer failed the run.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns the assertion failures stored in this verdict.
    ///
    /// Use [`Self::failed`] or final run-verdict composition when deterministic
    /// failure ordering is required.
    #[must_use]
    pub fn failures(&self) -> &[AssertionVerdictFailure] {
        match self {
            Self::Passed => &[],
            Self::Failed { failures } => failures,
        }
    }
}

/// One assertion failure participating in final run-verdict composition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssertionVerdictFailure {
    /// Assertion that failed.
    pub assertion: AssertionId,
    /// Deterministic virtual time where the failure was observed.
    pub at: VirtualTime,
    /// Stable failure detail from the assertion layer.
    pub reason: String,
}

impl AssertionVerdictFailure {
    /// Builds an assertion-failure record.
    #[must_use]
    pub fn new(assertion: AssertionId, at: VirtualTime, reason: impl Into<String>) -> Self {
        Self {
            assertion,
            at,
            reason: reason.into(),
        }
    }
}

/// Final run verdict after composing trigger and assertion outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComposedRunVerdict {
    /// No trigger or assertion failure occurred.
    Passed {
        /// Optional explicit trigger pass request.
        trigger: Option<TriggerVerdict>,
    },
    /// At least one trigger or assertion failure occurred.
    Failed {
        /// Deterministically ordered failure causes.
        failures: Vec<ComposedRunVerdictFailure>,
    },
}

impl ComposedRunVerdict {
    /// Returns true when the composed verdict failed the run.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns the composed failure causes.
    #[must_use]
    pub fn failures(&self) -> &[ComposedRunVerdictFailure] {
        match self {
            Self::Passed { .. } => &[],
            Self::Failed { failures } => failures,
        }
    }
}

/// One failure cause in the composed run verdict.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComposedRunVerdictFailure {
    /// Failure from the assertion layer.
    Assertion(AssertionVerdictFailure),
    /// Failure from an explicit trigger `Fail` action.
    Trigger(TriggerVerdict),
}

/// One observational diagnostic emitted by a trigger log action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TriggerDiagnosticRecord {
    /// Trigger action sequence that emitted the diagnostic.
    pub sequence: u64,
    /// Event whose firing produced the diagnostic.
    pub event: crate::EventId,
    /// Virtual time at which the diagnostic was emitted.
    pub at: VirtualTime,
    /// Diagnostic severity level.
    pub level: LogLevel,
    /// Stable diagnostic message.
    pub message: String,
}

/// Result of appending one scheduler quantum to the event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerEventLogAppend {
    /// Entries appended for this quantum.
    pub entries: Vec<SchedulerEventLogEntry>,
    /// Canonical bytes appended for this quantum's event-log segment.
    pub segment_bytes: Vec<u8>,
    /// Human-readable text projection derived from `segment_bytes`.
    pub segment_text: String,
    /// Content address of `segment_bytes`, when a segment was appended.
    pub segment_hash: Option<ContentHash>,
    /// Offset reached after appending this quantum's segment.
    pub offset: EventLogOffset,
}

/// The single max-advance ceiling published for one RUN phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerRunCeilingPublication {
    /// Monotone index of this publication in the scheduler's publication log.
    pub sequence: u64,
    /// The quantum that published this ceiling.
    pub quantum: u64,
    /// The node selected by PICK for the RUN.
    pub node: SchedulerNodeId,
    /// The node counter observed before publishing the ceiling.
    pub current_icount: NodeCounter,
    /// The scheduler-published `max_advance_icount` ABI field value.
    pub max_advance_icount: u64,
    /// The fixed icount shift used to convert `target_time` into the ceiling.
    pub icount_shift: Shift,
    /// The virtual-time horizon that produced `max_advance_icount`.
    pub target_time: SimInstant,
}

/// Deterministic vCPU RR policy for one scheduler node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerRunSubdivisionPolicy {
    /// Scheduler node whose RUN budget is subdivided internally.
    pub node: SchedulerNodeId,
    /// Number of vCPUs hosted by the node.
    pub vcpu_count: u32,
    /// Fixed retired-instruction quantum used before rotating to the next vCPU.
    pub rr_switch_quantum: u64,
}

impl SchedulerRunSubdivisionPolicy {
    /// Builds a validated RR subdivision policy.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `vcpu_count` or
    /// `rr_switch_quantum` is zero.
    pub fn new(
        node: SchedulerNodeId,
        vcpu_count: u32,
        rr_switch_quantum: u64,
    ) -> Result<Self, SchedulerError> {
        validate_scheduler_rr_policy(vcpu_count, rr_switch_quantum)?;
        Ok(Self {
            node,
            vcpu_count,
            rr_switch_quantum,
        })
    }
}

/// One plugin-internal vCPU slice inside a node-level RUN.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerRunSubdivisionSlice {
    /// vCPU selected for this slice.
    pub vcpu: VcpuId,
    /// Node-local counter at which the slice starts.
    pub start_icount: NodeCounter,
    /// Node-local counter at which the slice ends.
    pub end_icount: NodeCounter,
}

/// Evidence that a node-level RUN used deterministic RR subdivision internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerRunSubdivisionRecord {
    /// Monotone scheduler-local subdivision record sequence.
    pub sequence: u64,
    /// Scheduler quantum whose RUN was subdivided.
    pub quantum: u64,
    /// Policy used to subdivide this RUN.
    pub policy: SchedulerRunSubdivisionPolicy,
    /// The single scheduler-published node ceiling for this RUN.
    pub ceiling: SchedulerRunCeilingPublication,
    /// Per-vCPU slices in plugin execution order.
    pub slices: Vec<SchedulerRunSubdivisionSlice>,
}

/// Evidence that an explorer-supplied preemption was applied by RESOLVE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerPreemptionApplication {
    /// Monotone scheduler-local preemption application sequence.
    pub sequence: u64,
    /// Scheduler quantum whose RUN admitted this preemption.
    pub quantum: u64,
    /// Scheduler node selected for the RUN that admitted the preemption.
    pub node: SchedulerNodeId,
    /// Explorer-supplied preemption decision recorded in the schedule.
    pub decision: PreemptionDecision,
    /// Scheduler-axis virtual time at the preemption's retired-instruction point.
    pub virtual_time: SimInstant,
    /// Inclusive lower icount bound for this RUN's authorized window.
    pub deadline_icount: Icount,
    /// Inclusive upper icount bound for this RUN's authorized window.
    pub horizon_icount: Icount,
    /// The single scheduler-published node ceiling for this RUN.
    pub ceiling: SchedulerRunCeilingPublication,
}

/// One vCPU's scheduler-visible idle snapshot inside an N-vCPU VM node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerVcpuIdleState {
    /// The vCPU described by this snapshot.
    pub vcpu: VcpuId,
    /// Whether the vCPU is halted at the scheduler boundary.
    pub halted: bool,
    /// The vCPU's next exact timer deadline, when one is armed.
    pub next_deadline: Option<SimInstant>,
    /// Whether input is already pending for this vCPU.
    pub pending_input: bool,
}

/// Per-vCPU idle evidence for one scheduler VM node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerNodeVcpuIdleSnapshot {
    /// Scheduler node whose vCPU idle state is reported.
    pub node: SchedulerNodeId,
    /// Total number of vCPUs hosted by the node.
    pub vcpu_count: u32,
    /// Per-vCPU states in canonical vCPU-index order.
    pub vcpus: Vec<SchedulerVcpuIdleState>,
}

impl SchedulerNodeVcpuIdleSnapshot {
    /// Builds a validated per-node vCPU idle snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the snapshot declares
    /// zero vCPUs, does not cover every vCPU exactly once, or targets a non-VM
    /// scheduler node.
    pub fn new(
        node: SchedulerNodeId,
        vcpu_count: u32,
        mut vcpus: Vec<SchedulerVcpuIdleState>,
    ) -> Result<Self, SchedulerError> {
        validate_vcpu_idle_snapshot(&node, vcpu_count, &mut vcpus)?;
        Ok(Self {
            node,
            vcpu_count,
            vcpus,
        })
    }
}

/// The virtual-time clock value used for scheduler lookahead decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerEffectiveClock {
    /// The scheduler graph node whose clock was projected.
    pub node: SchedulerNodeId,
    /// The node's currently published virtual time.
    pub current_time: SimInstant,
    /// The effective clock used by the scheduler for lookahead and PICK.
    pub effective_time: SimInstant,
    /// The reason the effective clock has this value.
    pub source: SchedulerEffectiveClockSource,
}

/// The source of a scheduler effective-clock projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerEffectiveClockSource {
    /// The node's effective clock is its current virtual time.
    Current,
    /// An idle node's effective clock is its exact wake time.
    IdleWake,
}

/// The scheduler-side cause for a boundary topology recompute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulerTopologyChangeTrigger {
    /// Directed edges were removed from the effective topology.
    EdgeRemoval,
    /// Directed edges were restored to the effective topology.
    EdgeRestore,
    /// A latency mutation changed the conservative lookahead bound.
    LatencyChange,
}

/// The topology effect applied at a scheduler quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SchedulerTopologyChangeEffect {
    /// Replaces the complete effective edge set.
    ReplaceEffectiveEdges(Vec<SchedulerLookaheadEdge>),
    /// Updates matching directed edges without restoring absent edges.
    UpdateEffectiveEdges(Vec<SchedulerLookaheadEdge>),
    /// Removes effective edges matching the listed directed endpoints.
    RemoveEffectiveEdges(Vec<SchedulerLookaheadEdgeEndpoint>),
    /// Restores effective edges into the current edge set.
    RestoreEffectiveEdges(Vec<SchedulerLookaheadEdge>),
}

/// A boundary-applied effective-topology mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerTopologyChange {
    /// Session-local sequence number used to order same-boundary changes.
    pub sequence: u64,
    /// The reason this change requires a lookahead recompute.
    pub trigger: SchedulerTopologyChangeTrigger,
    /// Exact virtual time at which a fault-timed topology change takes effect.
    pub activation_time: Option<SimInstant>,
    /// The effective-topology effect to apply at the boundary.
    pub effect: SchedulerTopologyChangeEffect,
}

impl SchedulerTopologyChange {
    /// Builds a topology change from a complete effective edge-set replacement.
    #[must_use]
    pub fn new(
        sequence: u64,
        trigger: SchedulerTopologyChangeTrigger,
        effective_edges: Vec<SchedulerLookaheadEdge>,
    ) -> Self {
        Self {
            sequence,
            trigger,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(effective_edges),
        }
    }

    /// Builds a partition change that removes directed effective edges.
    #[must_use]
    pub fn partition(sequence: u64, removed_edges: Vec<SchedulerLookaheadEdgeEndpoint>) -> Self {
        Self {
            sequence,
            trigger: SchedulerTopologyChangeTrigger::EdgeRemoval,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::RemoveEffectiveEdges(removed_edges),
        }
    }

    /// Builds a heal change that restores directed effective edges.
    #[must_use]
    pub fn heal(sequence: u64, restored_edges: Vec<SchedulerLookaheadEdge>) -> Self {
        Self {
            sequence,
            trigger: SchedulerTopologyChangeTrigger::EdgeRestore,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges),
        }
    }

    /// Builds a latency change that updates existing directed effective edges.
    ///
    /// The updated edges replace only matching endpoints that are still present in
    /// the current effective topology. This preserves pending partition effects:
    /// a latency refresh cannot re-add an edge that a partition removed.
    #[must_use]
    pub fn update_effective_edges(
        sequence: u64,
        trigger: SchedulerTopologyChangeTrigger,
        updated_edges: Vec<SchedulerLookaheadEdge>,
    ) -> Self {
        Self {
            sequence,
            trigger,
            activation_time: None,
            effect: SchedulerTopologyChangeEffect::UpdateEffectiveEdges(updated_edges),
        }
    }

    /// Sets the exact activation virtual time for a fault-timed topology change.
    #[must_use]
    pub fn with_activation_time(mut self, activation_time: SimInstant) -> Self {
        self.activation_time = Some(activation_time);
        self
    }
}

pub(super) fn topology_change_order(
    left: &SchedulerTopologyChange,
    right: &SchedulerTopologyChange,
) -> std::cmp::Ordering {
    left.sequence
        .cmp(&right.sequence)
        .then_with(|| left.trigger.cmp(&right.trigger))
        .then_with(|| left.activation_time.cmp(&right.activation_time))
}

/// One node lookahead value recomputed by a topology change.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerTopologyLookaheadUpdate {
    /// The scheduler node whose network lookahead was recomputed.
    pub node: SchedulerNodeId,
    /// The lookahead value used before the boundary change.
    pub previous_lookahead: NetworkLookahead,
    /// The lookahead value derived from the new effective edge set.
    pub recomputed_lookahead: NetworkLookahead,
}

/// Evidence that a topology change was applied at a quantum boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerTopologyChangeApplication {
    /// Monotone scheduler topology epoch after this application.
    pub topology_epoch: u64,
    /// Session-local sequence number of the applied topology change.
    pub sequence: u64,
    /// The reason this change required a lookahead recompute.
    pub trigger: SchedulerTopologyChangeTrigger,
    /// Exact activation rendezvous time, when the change was fault-timed.
    pub activation_time: Option<SimInstant>,
    /// Per-node lookahead updates in canonical scheduler-node order.
    pub updates: Vec<SchedulerTopologyLookaheadUpdate>,
}

/// Scheduler-side checkpoint anchor for one VM node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerNodeCheckpoint {
    /// The checkpointed VM node.
    pub node: NodeId,
    /// The VM counter captured by the checkpoint.
    pub counter: NodeCounter,
    /// Scheduler-time projection of `counter` when the checkpoint was recorded.
    pub at: SimInstant,
}

/// Authorization for emitting one cross-node frame under the current topology.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SchedulerSendAuthorization {
    /// The producer scheduler node.
    pub producer: SchedulerNodeId,
    /// The consumer scheduler node.
    pub consumer: SchedulerNodeId,
    /// The topology epoch under which this send was authorized.
    pub topology_epoch: u64,
}

/// Authorizes cross-node frame emission against scheduler topology state.
pub trait SchedulerSendAuthorizer: Send + Sync {
    /// Authorizes one producer-to-consumer frame under the current topology.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when sends are frozen by a pending topology
    /// change or the effective edge set does not contain the requested edge.
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError>;
}

#[cfg(feature = "test-double")]
impl SchedulerRunCeilingPublication {
    /// Converts this scheduler publication to the shared-memory ABI ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_shmem::LookaheadGateError`] when the publication is not
    /// a valid max-advance ceiling under the shared-memory lookahead gate.
    pub fn to_shmem_ceiling(
        &self,
    ) -> Result<crucible_shmem::AdvanceCeiling, crucible_shmem::LookaheadGateError> {
        crucible_shmem::authorize_advance_ceiling(
            self.current_icount.ticks,
            self.max_advance_icount,
            None,
        )
    }

    /// Publishes pending inputs, this ceiling, and the wake through shmem.
    ///
    /// Pending inputs are appended to their directed inboxes before the node
    /// slot ceiling is release-stored and its futex word is incremented.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerRunCeilingHandoffError`] when the publication cannot
    /// be authorized as a shared-memory ceiling, or when the shared-memory
    /// region rejects an inbox, ceiling, or wake publication.
    pub fn publish_to_shmem_after_inputs(
        &self,
        region: &mut crucible_shmem::RegionAllocation,
        dst_slot: u32,
        pending_inputs: &[crucible_shmem::PendingInputPublication],
    ) -> Result<crucible_shmem::SchedulerWakePublication, SchedulerRunCeilingHandoffError> {
        let ceiling = self.to_shmem_ceiling()?;
        Ok(region.publish_scheduler_inputs_and_ceiling(dst_slot, pending_inputs, ceiling)?)
    }
}

/// An error produced while handing a scheduler RUN ceiling to shmem.
#[cfg(feature = "test-double")]
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerRunCeilingHandoffError {
    /// The scheduler publication did not authorize as an ABI ceiling.
    #[error("scheduler RUN ceiling could not be authorized for shared memory")]
    Authorization {
        /// Underlying lookahead-gate error.
        #[from]
        source: crucible_shmem::LookaheadGateError,
    },
    /// The shared-memory region rejected the ordered publication.
    #[error("scheduler RUN ceiling shared-memory publication failed")]
    Publication {
        /// Underlying shared-memory publication error.
        #[from]
        source: crucible_shmem::SchedulerWakePublicationError,
    },
}

/// A read-only copy of the state owned by the scheduler actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerActorStateSnapshot {
    /// The current frontier configuration.
    pub configuration: Configuration,
    /// Per-node counters in canonical scheduler-node order.
    pub node_counters: Vec<(SchedulerNodeId, NodeCounter)>,
    /// Number of cross-node events still owned by the scheduler.
    pub pending_event_count: usize,
    /// Number of control operations waiting for the next quantum boundary.
    pub pending_control_count: usize,
    /// Decision-RNG cursor positions owned by the scheduler.
    pub decision_rng_cursor: DecisionRngState,
    /// Boundary-applied control operations in scheduler application order.
    pub control_applications: Vec<SchedulerControlApplication>,
    /// Explorer-supplied preemptions applied by completed RESOLVE phases.
    pub preemption_applications: Vec<SchedulerPreemptionApplication>,
    /// Number of quantum boundaries at which the scheduler yielded to control.
    pub boundary_yields: u64,
}

/// A message-only scheduler actor that owns the authoritative scheduler state.
#[derive(Debug)]
pub struct SchedulerActor {
    pub(super) scheduler: SingleScheduler,
    pub(super) inbox: Receiver<SchedulerActorMessage>,
    pub(super) deferred: VecDeque<SchedulerActorMessage>,
}

/// A clonable sender for scheduler actor messages.
#[derive(Clone, Debug)]
pub struct SchedulerActorHandle {
    pub(super) inbox: Sender<SchedulerActorMessage>,
}

/// A typed reply receiver for scheduler actor requests.
#[derive(Debug)]
pub struct SchedulerActorReply<T> {
    pub(super) receiver: Receiver<T>,
}

pub(super) enum SchedulerActorMessage {
    QueueControl(ControlOperation),
    QueueTopologyChange(SchedulerTopologyChange),
    DriveQuantum {
        request: QuantumRequest,
        reply: Sender<Result<QuantumOutcome, SchedulerError>>,
    },
    Snapshot {
        reply: Sender<SchedulerActorStateSnapshot>,
    },
}

impl fmt::Debug for SchedulerActorMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueControl(operation) => formatter
                .debug_tuple("QueueControl")
                .field(operation)
                .finish(),
            Self::QueueTopologyChange(change) => formatter
                .debug_tuple("QueueTopologyChange")
                .field(change)
                .finish(),
            Self::DriveQuantum { request, .. } => formatter
                .debug_struct("DriveQuantum")
                .field("request", request)
                .finish_non_exhaustive(),
            Self::Snapshot { .. } => formatter.debug_struct("Snapshot").finish_non_exhaustive(),
        }
    }
}

impl SchedulerActor {
    /// Builds a scheduler actor and the handle used to send it messages.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the scheduler cannot be built from
    /// `scenario`.
    pub fn new(
        scenario: SchedulerLivenessScenario,
    ) -> Result<(SchedulerActorHandle, Self), SchedulerError> {
        let (sender, receiver) = mpsc::channel();
        Ok((
            SchedulerActorHandle { inbox: sender },
            Self {
                scheduler: SingleScheduler::new(scenario)?,
                inbox: receiver,
                deferred: VecDeque::new(),
            },
        ))
    }

    /// Processes one queued actor message, if one is available.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError`] when the actor mailbox is closed or when
    /// a caller drops a reply receiver before the actor sends the result.
    pub fn run_once(&mut self) -> Result<bool, SchedulerActorError> {
        if let Some(message) = self.deferred.pop_front() {
            self.apply_message(message)?;
            return Ok(true);
        }

        match self.inbox.try_recv() {
            Ok(message) => {
                self.apply_message(message)?;
                Ok(true)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(SchedulerActorError::MailboxClosed),
        }
    }

    /// Processes queued actor messages until the mailbox is temporarily empty.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError`] when the actor mailbox is closed or when
    /// a caller drops a reply receiver before the actor sends the result.
    pub fn run_until_idle(&mut self) -> Result<usize, SchedulerActorError> {
        let mut processed = 0usize;
        while self.run_once()? {
            processed += 1;
        }
        Ok(processed)
    }

    fn apply_message(&mut self, message: SchedulerActorMessage) -> Result<(), SchedulerActorError> {
        match message {
            SchedulerActorMessage::QueueControl(operation) => {
                self.scheduler.queue_control(operation);
                Ok(())
            }
            SchedulerActorMessage::QueueTopologyChange(change) => {
                self.scheduler.queue_topology_change(change);
                Ok(())
            }
            SchedulerActorMessage::DriveQuantum { request, reply } => {
                self.drain_boundary_messages_before_quantum();
                reply
                    .send(self.scheduler.drive_quantum(request))
                    .map_err(|_| SchedulerActorError::ReplyDropped)
            }
            SchedulerActorMessage::Snapshot { reply } => reply
                .send(self.scheduler.actor_state_snapshot())
                .map_err(|_| SchedulerActorError::ReplyDropped),
        }
    }

    fn drain_boundary_messages_before_quantum(&mut self) {
        loop {
            match self.inbox.try_recv() {
                Ok(SchedulerActorMessage::QueueControl(operation)) => {
                    self.scheduler.queue_control(operation);
                }
                Ok(SchedulerActorMessage::QueueTopologyChange(change)) => {
                    self.scheduler.queue_topology_change(change);
                }
                Ok(message) => {
                    self.deferred.push_back(message);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
    }
}

impl SchedulerActorHandle {
    /// Queues a control operation for the scheduler actor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn queue_control(&self, operation: ControlOperation) -> Result<(), SchedulerActorError> {
        self.send(SchedulerActorMessage::QueueControl(operation))
    }

    /// Queues a topology change for the next scheduler quantum boundary.
    ///
    /// Fault, heal, and latency-control paths use this message to freeze
    /// cross-node sends until the actor applies the new effective edge set and
    /// recomputes lookahead before the next PICK.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn queue_topology_change(
        &self,
        change: SchedulerTopologyChange,
    ) -> Result<(), SchedulerActorError> {
        self.send(SchedulerActorMessage::QueueTopologyChange(change))
    }

    /// Requests one scheduler quantum through the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn drive_quantum(
        &self,
        request: QuantumRequest,
    ) -> Result<SchedulerActorReply<Result<QuantumOutcome, SchedulerError>>, SchedulerActorError>
    {
        let (sender, receiver) = mpsc::channel();
        self.send(SchedulerActorMessage::DriveQuantum {
            request,
            reply: sender,
        })?;
        Ok(SchedulerActorReply { receiver })
    }

    /// Requests a read-only scheduler state snapshot through the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::MailboxClosed`] when the actor has already
    /// stopped receiving messages.
    pub fn snapshot(
        &self,
    ) -> Result<SchedulerActorReply<SchedulerActorStateSnapshot>, SchedulerActorError> {
        let (sender, receiver) = mpsc::channel();
        self.send(SchedulerActorMessage::Snapshot { reply: sender })?;
        Ok(SchedulerActorReply { receiver })
    }

    fn send(&self, message: SchedulerActorMessage) -> Result<(), SchedulerActorError> {
        self.inbox
            .send(message)
            .map_err(|_| SchedulerActorError::MailboxClosed)
    }
}

impl<T> SchedulerActorReply<T> {
    /// Receives a scheduler actor reply.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerActorError::ReplyDropped`] when the actor drops before
    /// replying to the request.
    pub fn recv(self) -> Result<T, SchedulerActorError> {
        self.receiver
            .recv()
            .map_err(|_| SchedulerActorError::ReplyDropped)
    }
}

/// An error produced by the scheduler actor mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerActorError {
    /// The actor mailbox is closed.
    MailboxClosed,
    /// A request reply was dropped before delivery.
    ReplyDropped,
}

impl fmt::Display for SchedulerActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxClosed => formatter.write_str("scheduler actor mailbox is closed"),
            Self::ReplyDropped => formatter.write_str("scheduler actor reply was dropped"),
        }
    }
}

impl Error for SchedulerActorError {}
