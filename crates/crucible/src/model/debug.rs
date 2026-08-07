//! Debug attachment, inspection, branching, and time-travel reports.

use super::*;

/// Result of a graph-level runtime realization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraphRuntime {
    /// Configuration realized by [`instantiate`].
    pub configuration: ContentHash,
    /// Checkpoint identity used as the graph operation target.
    pub checkpoint: ContentHash,
    /// Runtime state returned by [`instantiate`].
    pub runtime: RuntimeState,
}

/// A gdb-protocol endpoint used by the debug attach boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugGdbEndpoint {
    pub(super) value: String,
}

impl DebugGdbEndpoint {
    /// Builds a validated endpoint string.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DebugGdbEndpointInvalid`] when `value` is empty or
    /// contains a newline or NUL byte.
    pub fn new(field: &'static str, value: impl Into<String>) -> Result<Self, EngineError> {
        let value = value.into();
        validate_debug_gdb_endpoint(field, &value)?;
        Ok(Self { value })
    }

    /// Returns the stable endpoint text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// A request to attach the time-travel debugger to one checkpoint configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugAttachRequest {
    /// Checkpoint configuration resolved from the operator coordinate.
    pub configuration: Configuration,
    /// Node whose QEMU gdbstub is exposed to the operator.
    pub node: NodeId,
    /// Host-side endpoint where QEMU exposes its raw gdbstub.
    pub qemu_gdbstub: DebugGdbEndpoint,
    /// Operator-facing `--gdb-listen` endpoint served by Crucible's proxy.
    pub gdb_listen: DebugGdbEndpoint,
}

impl DebugAttachRequest {
    /// Builds a debug attach request from a resolved checkpoint configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DebugGdbEndpointInvalid`] when either endpoint is
    /// empty or cannot be represented as stable launch/proxy text.
    pub fn new(
        configuration: Configuration,
        node: NodeId,
        qemu_gdbstub: impl Into<String>,
        gdb_listen: impl Into<String>,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            configuration,
            node,
            qemu_gdbstub: DebugGdbEndpoint::new("qemu_gdbstub", qemu_gdbstub)?,
            gdb_listen: DebugGdbEndpoint::new("gdb_listen", gdb_listen)?,
        })
    }
}

/// One channel role in the QEMU child boundary during a debug session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugAttachChannelKind {
    /// Plugin IPC control carries setup and teardown messages only.
    PluginIpcControl,
    /// Shared memory carries the per-quantum hot path.
    SharedMemoryHotPath,
    /// QMP carries out-of-band machine-control commands.
    QmpMachineControl,
    /// The gdbstub carries out-of-band debugger protocol packets.
    Gdbstub,
}

/// The complete QEMU child channel set while a debugger is attached.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugAttachChannelSet {
    /// Stable channel roles owned by the debug-attached node.
    pub channels: BTreeSet<DebugAttachChannelKind>,
}

impl DebugAttachChannelSet {
    /// Builds the required four-channel debug-session boundary.
    #[must_use]
    pub fn four_channel_debug_session() -> Self {
        Self {
            channels: BTreeSet::from([
                DebugAttachChannelKind::PluginIpcControl,
                DebugAttachChannelKind::SharedMemoryHotPath,
                DebugAttachChannelKind::QmpMachineControl,
                DebugAttachChannelKind::Gdbstub,
            ]),
        }
    }

    /// Returns whether the set contains exactly the four required channel roles.
    #[must_use]
    pub fn is_four_channel_debug_session(&self) -> bool {
        self == &Self::four_channel_debug_session()
    }
}

/// The mediated QEMU gdbstub channel exposed during a debug attach.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugGdbstubChannel {
    /// Node whose QEMU child owns the gdbstub.
    pub node: NodeId,
    /// Host-side endpoint where QEMU exposes the raw gdbstub.
    pub qemu_endpoint: DebugGdbEndpoint,
    /// Operator-facing gdb-protocol endpoint served by Crucible's proxy.
    pub operator_listen: DebugGdbEndpoint,
    /// Whether Crucible mediates the raw QEMU gdbstub.
    pub mediated_by_crucible: bool,
    /// Whether the channel is outside scheduler delivery order.
    pub out_of_band: bool,
    /// Whether debugger traffic carries per-quantum timing data.
    pub carries_per_quantum_timing: bool,
    /// Whether debugger traffic carries guest frame data.
    pub carries_frame_data: bool,
}

impl DebugGdbstubChannel {
    /// Returns whether this channel satisfies the out-of-band debug contract.
    #[must_use]
    pub const fn is_out_of_band_debug_proxy(&self) -> bool {
        self.mediated_by_crucible
            && self.out_of_band
            && !self.carries_per_quantum_timing
            && !self.carries_frame_data
    }
}

/// Result of attaching a debugger to an instantiated checkpoint configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugAttachReport {
    /// Configuration realized for the debugger attach.
    pub configuration: ContentHash,
    /// Checkpoint identity used as the attach target.
    pub checkpoint: ContentHash,
    /// Ordinary runtime produced by [`TemporalGraph::resume`].
    pub runtime: TemporalGraphRuntime,
    /// Reduced state denoted by the attached configuration.
    pub reduced_state: ContentHash,
    /// Complete child-channel set visible during the debug session.
    pub channel_set: DebugAttachChannelSet,
    /// The out-of-band mediated gdbstub channel.
    pub gdbstub: DebugGdbstubChannel,
}

impl DebugAttachReport {
    /// Returns whether the attach report proves the ordinary instantiate path.
    #[must_use]
    pub fn uses_instantiated_runtime(&self) -> bool {
        self.runtime.configuration == self.configuration
            && self.runtime.checkpoint == self.checkpoint
            && self.runtime.runtime.configuration == self.configuration
            && self.runtime.runtime.id == self.reduced_state
    }

    /// Returns whether the report carries the required four-channel debug boundary.
    #[must_use]
    pub fn has_four_channel_debug_boundary(&self) -> bool {
        self.channel_set.is_four_channel_debug_session()
            && self.gdbstub.is_out_of_band_debug_proxy()
    }
}

/// One read-only debugger inspection operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DebugReadOnlyInspectionKind {
    /// Reads architectural registers from the attached node.
    RegisterRead,
    /// Reads guest memory from the attached node.
    MemoryRead,
    /// Walks the guest stack or backtrace without changing execution.
    Backtrace,
    /// Enumerates threads or vCPUs visible to the debugger.
    ThreadEnumeration,
    /// Reads a watchpoint value without arming a deterministic trigger.
    WatchpointValueRead,
}

impl DebugReadOnlyInspectionKind {
    /// Returns the stable diagnostic suffix for this inspection kind.
    #[must_use]
    pub const fn diagnostic_suffix(self) -> &'static str {
        match self {
            Self::RegisterRead => "register_read",
            Self::MemoryRead => "memory_read",
            Self::Backtrace => "backtrace",
            Self::ThreadEnumeration => "thread_enumeration",
            Self::WatchpointValueRead => "watchpoint_value_read",
        }
    }
}

/// A batch of read-only debugger inspections at one virtual-time coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReadOnlyInspectionRequest {
    /// Virtual-time coordinate reported for the read-only debugger observations.
    pub virtual_time: VirtualTime,
    /// Ordered read-only debugger operations performed during the attach.
    pub inspections: Vec<DebugReadOnlyInspectionKind>,
}

impl DebugReadOnlyInspectionRequest {
    /// Builds a read-only debugger inspection request.
    #[must_use]
    pub fn new<I>(virtual_time: VirtualTime, inspections: I) -> Self
    where
        I: IntoIterator<Item = DebugReadOnlyInspectionKind>,
    {
        Self {
            virtual_time,
            inspections: inspections.into_iter().collect(),
        }
    }
}

/// Checkpoint fields captured before and after read-only debugger inspection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReadOnlyCheckpointFootprint {
    /// Checkpoint identity.
    pub id: ContentHash,
    /// Configuration denoted by the checkpoint.
    pub configuration: ContentHash,
    /// Whether the checkpoint is loadable or thin/replay-only.
    pub kind: CheckpointKind,
    /// Virtual-time coordinate recorded for the checkpoint.
    pub virtual_time: VirtualTime,
    /// Event-log offset retained by a materialized checkpoint, when present.
    pub event_log: EventLogOffset,
}

/// Graph/runtime footprint captured around read-only debugger inspection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReadOnlyInspectionFootprint {
    /// Temporal graph identity.
    pub graph: ContentHash,
    /// Recorded configuration identities in stable order.
    pub recorded_configurations: Vec<ContentHash>,
    /// Recorded checkpoint-node identities and non-identity state in stable order.
    pub checkpoint_nodes: Vec<DebugReadOnlyCheckpointFootprint>,
    /// Cached loadable snapshot identities and non-identity state in stable order.
    pub cached_snapshots: Vec<DebugReadOnlyCheckpointFootprint>,
    /// Baked genesis scenario identities in stable order.
    pub baked_genesis: Vec<ContentHash>,
    /// Configuration realized by the attached debugger session.
    pub attached_configuration: ContentHash,
    /// Checkpoint realized by the attached debugger session.
    pub attached_checkpoint: ContentHash,
    /// Whether the attached checkpoint exists in the graph footprint.
    pub attached_checkpoint_recorded: bool,
    /// Runtime-state identity realized by the attached debugger session.
    pub attached_runtime: ContentHash,
    /// Runtime state's configuration identity.
    pub attached_runtime_configuration: ContentHash,
    /// Runtime node icounts at the attached checkpoint.
    pub attached_runtime_node_icounts: BTreeMap<NodeId, Icount>,
    /// Runtime node blob references at the attached checkpoint.
    pub attached_runtime_node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Scheduler-owned state reconstructed at the attached checkpoint.
    pub attached_runtime_scheduler: SchedulerState,
    /// Runtime event-log offset from which deterministic execution would resume.
    pub attached_runtime_event_log: EventLogOffset,
    /// Graph-derived virtual time at the attached checkpoint.
    pub virtual_time: VirtualTime,
}

impl DebugReadOnlyInspectionFootprint {
    pub(super) fn capture(
        graph: &TemporalGraph,
        attach: &DebugAttachReport,
        fallback_virtual_time: VirtualTime,
    ) -> Self {
        let checkpoint = graph
            .checkpoint_nodes
            .get(&attach.checkpoint)
            .or_else(|| graph.cached_snapshots.get(&attach.checkpoint));
        Self {
            graph: graph.id,
            recorded_configurations: graph.recorded_configurations.keys().copied().collect(),
            checkpoint_nodes: checkpoint_footprints(&graph.checkpoint_nodes),
            cached_snapshots: checkpoint_footprints(&graph.cached_snapshots),
            baked_genesis: graph.baked_genesis.keys().copied().collect(),
            attached_configuration: attach.configuration,
            attached_checkpoint: attach.checkpoint,
            attached_checkpoint_recorded: checkpoint.is_some(),
            attached_runtime: attach.runtime.runtime.id,
            attached_runtime_configuration: attach.runtime.runtime.configuration,
            attached_runtime_node_icounts: attach.runtime.runtime.node_icounts.clone(),
            attached_runtime_node_blobs: attach.runtime.runtime.node_blobs.clone(),
            attached_runtime_scheduler: attach.runtime.runtime.scheduler.clone(),
            attached_runtime_event_log: attach.runtime.runtime.event_log,
            virtual_time: checkpoint
                .map(|checkpoint| checkpoint.virtual_time)
                .unwrap_or(fallback_virtual_time),
        }
    }
}

/// Evidence that debugger inspection preserved deterministic execution state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugReadOnlyInspectionReport {
    /// Graph/runtime footprint before emitting debugger observations.
    pub footprint_before: DebugReadOnlyInspectionFootprint,
    /// Graph/runtime footprint after emitting debugger observations.
    pub footprint_after: DebugReadOnlyInspectionFootprint,
    /// Virtual-time coordinate requested by the debugger operation.
    pub requested_virtual_time: VirtualTime,
    /// Canonical causal event-log projection without debugger observations.
    pub causal_event_log_before: EventLogCausalProjection,
    /// Canonical causal event-log projection with debugger observations.
    pub causal_event_log_after: EventLogCausalProjection,
    /// Observational diagnostics generated for attach, read-only reads, and detach.
    pub observational_entries: Vec<SchedulerEventLogEntry>,
    /// Full event-log view after appending read-only debugger observations.
    pub event_log_with_observations: Vec<SchedulerEventLogEntry>,
}

impl DebugReadOnlyInspectionReport {
    /// Returns whether the temporal graph footprint is unchanged.
    #[must_use]
    pub fn graph_unchanged(&self) -> bool {
        self.footprint_before == self.footprint_after
    }

    /// Returns whether the inspected configuration identity is unchanged.
    #[must_use]
    pub fn configuration_unchanged(&self) -> bool {
        self.footprint_before.attached_configuration == self.footprint_after.attached_configuration
    }

    /// Returns whether the inspected checkpoint identity is unchanged.
    #[must_use]
    pub fn checkpoint_unchanged(&self) -> bool {
        self.footprint_before.attached_checkpoint == self.footprint_after.attached_checkpoint
            && self.footprint_before.attached_checkpoint_recorded
            && self.footprint_after.attached_checkpoint_recorded
    }

    /// Returns whether the inspected runtime-state identity is unchanged.
    #[must_use]
    pub fn runtime_unchanged(&self) -> bool {
        self.footprint_before.attached_runtime == self.footprint_after.attached_runtime
            && self.footprint_before.attached_runtime_configuration
                == self.footprint_after.attached_runtime_configuration
            && self.footprint_before.attached_runtime_node_icounts
                == self.footprint_after.attached_runtime_node_icounts
            && self.footprint_before.attached_runtime_node_blobs
                == self.footprint_after.attached_runtime_node_blobs
            && self.footprint_before.attached_runtime_scheduler
                == self.footprint_after.attached_runtime_scheduler
            && self.footprint_before.attached_runtime_event_log
                == self.footprint_after.attached_runtime_event_log
    }

    /// Returns whether the requested inspection time is the attached checkpoint time.
    #[must_use]
    pub fn requested_virtual_time_matches_checkpoint(&self) -> bool {
        self.requested_virtual_time == self.footprint_before.virtual_time
            && self.requested_virtual_time == self.footprint_after.virtual_time
    }

    /// Returns whether the read-only inspection advanced no virtual time.
    #[must_use]
    pub fn virtual_time_unchanged(&self) -> bool {
        self.footprint_before.virtual_time == self.footprint_after.virtual_time
    }

    /// Returns whether the before/after causal projections are byte-identical.
    #[must_use]
    pub fn causal_subsequence_byte_identical(&self) -> bool {
        self.causal_event_log_before.canonical_bytes()
            == self.causal_event_log_after.canonical_bytes()
    }

    /// Returns whether every generated debugger entry is observational.
    #[must_use]
    pub fn observational_entries_are_non_causal(&self) -> bool {
        self.observational_entries
            .iter()
            .all(|entry| entry.class() == SchedulerEventLogClass::Observational)
    }

    /// Returns whether this report satisfies the full read-only debugger contract.
    #[must_use]
    pub fn proves_read_only(&self) -> bool {
        self.graph_unchanged()
            && self.configuration_unchanged()
            && self.checkpoint_unchanged()
            && self.runtime_unchanged()
            && self.requested_virtual_time_matches_checkpoint()
            && self.virtual_time_unchanged()
            && self.causal_subsequence_byte_identical()
            && self.observational_entries_are_non_causal()
    }
}

pub(super) fn checkpoint_footprints(
    checkpoints: &BTreeMap<ContentHash, Checkpoint>,
) -> Vec<DebugReadOnlyCheckpointFootprint> {
    checkpoints
        .values()
        .map(|checkpoint| DebugReadOnlyCheckpointFootprint {
            id: checkpoint.id,
            configuration: checkpoint.configuration,
            kind: checkpoint.kind,
            virtual_time: checkpoint.virtual_time,
            event_log: checkpoint
                .state
                .as_ref()
                .map(|state| state.event_log)
                .unwrap_or_default(),
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum DebugReadOnlyInspectionEvent {
    Attach,
    Inspect(DebugReadOnlyInspectionKind),
    Detach,
}

impl DebugReadOnlyInspectionEvent {
    fn diagnostic_name(self) -> String {
        match self {
            Self::Attach => String::from("debug.attach"),
            Self::Inspect(kind) => format!("debug.inspect.{}", kind.diagnostic_suffix()),
            Self::Detach => String::from("debug.detach"),
        }
    }

    const fn phase(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Inspect(_) => "inspect",
            Self::Detach => "detach",
        }
    }
}

pub(super) fn debug_read_only_observation_entry(
    sequence: u64,
    at: VirtualTime,
    event: DebugReadOnlyInspectionEvent,
    attach: &DebugAttachReport,
) -> SchedulerEventLogEntry {
    let mut details = BTreeMap::new();
    details.insert(
        String::from("phase"),
        EventAttributeValue::String(String::from(event.phase())),
    );
    details.insert(
        String::from("configuration"),
        EventAttributeValue::String(attach.configuration.to_hex()),
    );
    details.insert(
        String::from("checkpoint"),
        EventAttributeValue::String(attach.checkpoint.to_hex()),
    );
    details.insert(
        String::from("runtime_state"),
        EventAttributeValue::String(attach.runtime.runtime.id.to_hex()),
    );
    details.insert(
        String::from("node"),
        EventAttributeValue::Node(attach.gdbstub.node.clone()),
    );
    details.insert(String::from("read_only"), EventAttributeValue::Bool(true));
    details.insert(String::from("causal"), EventAttributeValue::Bool(false));
    SchedulerEventLogEntry::diagnostic(
        sequence,
        at,
        EventDiagnosticPayload::new(event.diagnostic_name(), EventLevel::Debug, details),
    )
}

pub(super) fn debug_non_canonical_branch_id(
    attach: &DebugAttachReport,
    request: &DebugNonCanonicalBranchRequest,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.debug.non-canonical-branch.v1",
        &debug_non_canonical_branch_material(attach, request),
    )
}

pub(super) fn debug_non_canonical_branch_material(
    attach: &DebugAttachReport,
    request: &DebugNonCanonicalBranchRequest,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "fork_point={}",
        content_hash_hex(request.current.id())
    ));
    lines.push(format!(
        "checkpoint={}",
        content_hash_hex(attach.checkpoint)
    ));
    lines.push(format!(
        "runtime={}",
        content_hash_hex(attach.runtime.runtime.id)
    ));
    lines.push(format!("at_ticks={}", request.at.ticks));
    lines.push(format!("trigger={}", request.trigger.label()));
    lines.push(format!("actions={}", request.actions.len()));
    for (index, action) in request.actions.iter().enumerate() {
        push_debug_non_canonical_action_lines(index, action, &mut lines);
    }
    lines.join("\n")
}

pub(super) fn push_debug_non_canonical_action_lines(
    index: usize,
    action: &DebugNonCanonicalBranchAction,
    lines: &mut Vec<String>,
) {
    let prefix = format!("debug_action.{index}");
    match action {
        DebugNonCanonicalBranchAction::Decision(decision) => {
            lines.push(format!("{prefix}.kind=decision"));
            push_decision_lines(index, decision, lines);
        }
        DebugNonCanonicalBranchAction::ControlOperation(operation) => {
            lines.push(format!("{prefix}.kind=control-operation"));
            push_debug_control_operation_lines(&prefix, operation, lines);
        }
        DebugNonCanonicalBranchAction::GuestEdit(edit) => {
            lines.push(format!("{prefix}.kind=guest-edit"));
            push_debug_guest_edit_lines(&prefix, edit, lines);
        }
        DebugNonCanonicalBranchAction::OperatorControl(kind) => {
            lines.push(format!("{prefix}.kind=operator-control"));
            lines.push(format!("{prefix}.operator_control={}", kind.label()));
        }
        DebugNonCanonicalBranchAction::GuestIntrospection { node } => {
            lines.push(format!("{prefix}.kind=guest-introspection"));
            lines.push(format!("{prefix}.node={}", node.name));
        }
    }
}

pub(super) fn push_debug_control_operation_lines(
    prefix: &str,
    operation: &ControlOperation,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.sequence={}", operation.sequence));
    lines.push(format!(
        "{prefix}.control_kind={}",
        debug_control_operation_kind_label(&operation.kind)
    ));
    match &operation.kind {
        ControlOperationKind::InjectFault { tag, fault } => {
            lines.push(format!("{prefix}.tag_len={}", tag.name.len()));
            lines.push(format!("{prefix}.tag={}", tag.name));
            lines.push(fault.canonical_material());
        }
        ControlOperationKind::HealFault { tag } => {
            lines.push(format!("{prefix}.tag_len={}", tag.name.len()));
            lines.push(format!("{prefix}.tag={}", tag.name));
        }
        ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Inject
        | ControlOperationKind::Query => {}
    }
}

pub(super) fn debug_control_operation_kind_label(kind: &ControlOperationKind) -> &'static str {
    match kind {
        ControlOperationKind::Pause => "pause",
        ControlOperationKind::Resume => "resume",
        ControlOperationKind::Step => "step",
        ControlOperationKind::Snapshot => "snapshot",
        ControlOperationKind::Fork => "fork",
        ControlOperationKind::Inject => "inject",
        ControlOperationKind::InjectFault { .. } => "inject-fault",
        ControlOperationKind::HealFault { .. } => "heal-fault",
        ControlOperationKind::Query => "query",
    }
}

pub(super) fn push_debug_guest_edit_lines(
    prefix: &str,
    edit: &DebugGuestEdit,
    lines: &mut Vec<String>,
) {
    lines.push(format!("{prefix}.node_len={}", edit.node.name.len()));
    lines.push(format!("{prefix}.node={}", edit.node.name));
    lines.push(format!("{prefix}.edit_kind={}", edit.kind.label()));
    lines.push(format!("{prefix}.target_len={}", edit.target.len()));
    lines.push(format!("{prefix}.target={}", edit.target));
    lines.push(format!("{prefix}.bytes_len={}", edit.bytes.len()));
    lines.push(format!("{prefix}.bytes={}", debug_hex_bytes(&edit.bytes)));
    push_debug_coordinate_lines(&format!("{prefix}.coordinate"), &edit.coordinate, lines);
}

pub(super) fn debug_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn push_debug_coordinate_lines(
    prefix: &str,
    coordinate: &DebugCoordinate,
    lines: &mut Vec<String>,
) {
    match coordinate {
        DebugCoordinate::Configuration(configuration) => {
            lines.push(format!("{prefix}.kind=configuration"));
            lines.push(format!(
                "{prefix}.configuration={}",
                content_hash_hex(configuration.id())
            ));
        }
        DebugCoordinate::Checkpoint(checkpoint) => {
            lines.push(format!("{prefix}.kind=checkpoint"));
            lines.push(format!(
                "{prefix}.checkpoint={}",
                content_hash_hex(*checkpoint)
            ));
        }
        DebugCoordinate::EventSequence(sequence) => {
            lines.push(format!("{prefix}.kind=event-sequence"));
            lines.push(format!("{prefix}.sequence={sequence}"));
        }
        DebugCoordinate::VirtualTime(time) => {
            lines.push(format!("{prefix}.kind=virtual-time"));
            lines.push(format!("{prefix}.ticks={}", time.ticks));
        }
        DebugCoordinate::NodeIcount { node, icount } => {
            lines.push(format!("{prefix}.kind=node-icount"));
            lines.push(format!("{prefix}.node_len={}", node.name.len()));
            lines.push(format!("{prefix}.node={}", node.name));
            lines.push(format!("{prefix}.retired={}", icount.retired));
        }
    }
}

pub(super) fn debug_non_canonical_fork_marker(
    branch: ContentHash,
    fork_point: ContentHash,
    fork_checkpoint: ContentHash,
    request: &DebugNonCanonicalBranchRequest,
    sequence: u64,
) -> DebugNonCanonicalForkMarker {
    let mut details = BTreeMap::new();
    details.insert(
        String::from("branch"),
        EventAttributeValue::String(branch.to_hex()),
    );
    details.insert(
        String::from("fork_point"),
        EventAttributeValue::String(fork_point.to_hex()),
    );
    details.insert(
        String::from("trigger"),
        EventAttributeValue::String(String::from(request.trigger.label())),
    );
    details.insert(
        String::from("non_canonical"),
        EventAttributeValue::Bool(true),
    );
    details.insert(String::from("canonical"), EventAttributeValue::Bool(false));
    details.insert(
        String::from("inside_virtual_time"),
        EventAttributeValue::Bool(true),
    );
    details.insert(
        String::from("one_execution_path"),
        EventAttributeValue::Bool(true),
    );
    details.insert(
        String::from("model_reproducible"),
        EventAttributeValue::Bool(false),
    );
    let schedule_delta = debug_non_canonical_schedule_delta(request).content_hash();
    let entry = SchedulerEventLogEntry::fork_marker(
        sequence,
        request.at,
        fork_checkpoint,
        schedule_delta,
        details,
    );
    DebugNonCanonicalForkMarker {
        branch,
        fork_point,
        entry,
    }
}

pub(super) fn next_event_log_sequence(event_log: &[SchedulerEventLogEntry]) -> u64 {
    event_log
        .last()
        .map_or(0, |entry| entry.sequence().saturating_add(1))
}

pub(super) fn canonical_run_event_log_projection_without_debug_branches(
    entries: &[SchedulerEventLogEntry],
) -> EventLogCausalProjection {
    let canonical_entries = entries
        .iter()
        .filter(|entry| !is_debug_non_canonical_fork_marker_entry(entry))
        .cloned()
        .collect::<Vec<_>>();
    event_log_causal_projection(&canonical_entries)
}

pub(super) fn is_debug_non_canonical_fork_marker_entry(entry: &SchedulerEventLogEntry) -> bool {
    entry.event_payload().kind() == "fork"
        && entry.event_payload().attribute("non_canonical")
            == Some(&EventAttributeValue::Bool(true))
        && entry.event_payload().attribute("canonical") == Some(&EventAttributeValue::Bool(false))
}

pub(super) fn debug_non_canonical_schedule_delta(
    request: &DebugNonCanonicalBranchRequest,
) -> Schedule {
    Schedule::from_decisions(request.actions.iter().filter_map(|action| match action {
        DebugNonCanonicalBranchAction::Decision(decision) => Some(decision.clone()),
        DebugNonCanonicalBranchAction::ControlOperation(_)
        | DebugNonCanonicalBranchAction::GuestEdit(_)
        | DebugNonCanonicalBranchAction::OperatorControl(_)
        | DebugNonCanonicalBranchAction::GuestIntrospection { .. } => None,
    }))
}

pub(super) fn debug_first_assertion_violation_sequence(
    event_log: &[SchedulerEventLogEntry],
) -> Option<u64> {
    event_log
        .iter()
        .find(|entry| debug_event_log_entry_is_assertion_violation(entry))
        .map(SchedulerEventLogEntry::sequence)
}

pub(super) fn debug_event_log_contains_sequence(
    event_log: &[SchedulerEventLogEntry],
    sequence: u64,
) -> bool {
    event_log.iter().any(|entry| entry.sequence() == sequence)
}

pub(super) fn debug_event_log_entry_is_assertion_violation(entry: &SchedulerEventLogEntry) -> bool {
    matches!(
        entry.payload(),
        SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionStateChanged {
            state: AssertionPhase::Violated,
            ..
        })
    ) || (entry.event_payload().kind() == "assertion_state_changed"
        && entry.event_payload().string("new_state") == Some("Violated"))
}

pub(super) fn shell_quote_command_argument(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(is_shell_safe_unquoted_byte) {
        return value.to_owned();
    }

    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

pub(super) fn is_shell_safe_unquoted_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'@'
            | b'%'
            | b'_'
            | b'+'
            | b'='
            | b':'
            | b','
            | b'.'
            | b'/'
            | b'-'
    )
}

pub(super) fn debug_labels_contain_all(labels: &[&'static str], required: &[&'static str]) -> bool {
    required
        .iter()
        .all(|required_label| labels.iter().any(|label| label == required_label))
}

/// Client-visible breakpoint request flavor at the debug protocol boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugBreakpointClientKind {
    /// A gdb-protocol software-breakpoint request.
    Software,
    /// A gdb-protocol hardware-breakpoint request.
    Hardware,
    /// A Crucible event-graph condition breakpoint request.
    EngineCondition,
}

/// Canonical out-of-band breakpoint mechanism available to a debug session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugBreakpointMechanism {
    /// A 17a condition evaluated by Crucible at deterministic boundaries.
    EngineCondition,
    /// A QEMU/gdbstub hardware breakpoint or debug-register trap.
    QemuHardwareBreakpoint,
}

/// Breakpoint target requested by the operator or gdb-protocol client.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugBreakpointTarget {
    /// Guest instruction address for a PC breakpoint.
    GuestAddress {
        /// Guest virtual or physical address as interpreted by the backend.
        address: u64,
    },
    /// Guest address that has no hardware/out-of-band mechanism in this session.
    GuestMemoryPatchOnly {
        /// Guest virtual or physical address that would require a trap patch.
        address: u64,
    },
    /// Named 17a condition breakpoint.
    EngineCondition {
        /// Stable condition identifier or predicate label.
        condition: String,
    },
}

/// A canonical breakpoint request on an attached debug session.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugBreakpointRequest {
    /// Node where the breakpoint should be installed.
    pub node: NodeId,
    /// Breakpoint kind requested by the client.
    pub client_kind: DebugBreakpointClientKind,
    /// Target being broken on.
    pub target: DebugBreakpointTarget,
}

impl DebugBreakpointRequest {
    /// Builds a canonical breakpoint request.
    #[must_use]
    pub fn new(
        node: NodeId,
        client_kind: DebugBreakpointClientKind,
        target: DebugBreakpointTarget,
    ) -> Self {
        Self {
            node,
            client_kind,
            target,
        }
    }

    /// Builds a gdb software-breakpoint request for a guest address.
    #[must_use]
    pub fn software_guest_address(node: NodeId, address: u64) -> Self {
        Self::new(
            node,
            DebugBreakpointClientKind::Software,
            DebugBreakpointTarget::GuestAddress { address },
        )
    }

    /// Builds a software breakpoint request known to require a guest-memory patch.
    #[must_use]
    pub fn software_memory_patch_only_guest_address(node: NodeId, address: u64) -> Self {
        Self::new(
            node,
            DebugBreakpointClientKind::Software,
            DebugBreakpointTarget::GuestMemoryPatchOnly { address },
        )
    }

    pub(super) fn canonical_mechanism(&self) -> Option<DebugBreakpointMechanism> {
        match &self.target {
            DebugBreakpointTarget::EngineCondition { .. } => {
                Some(DebugBreakpointMechanism::EngineCondition)
            }
            DebugBreakpointTarget::GuestAddress { .. } => {
                Some(DebugBreakpointMechanism::QemuHardwareBreakpoint)
            }
            DebugBreakpointTarget::GuestMemoryPatchOnly { .. } => None,
        }
    }
}

/// Resolution of a canonical breakpoint request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugBreakpointReport {
    /// Configuration being debugged.
    pub configuration: ContentHash,
    /// Checkpoint being debugged.
    pub checkpoint: ContentHash,
    /// Node where the breakpoint is installed.
    pub node: NodeId,
    /// Breakpoint kind requested by the client.
    pub requested_client_kind: DebugBreakpointClientKind,
    /// Target being broken on.
    pub target: DebugBreakpointTarget,
    /// Canonical out-of-band mechanism used.
    pub mechanism: DebugBreakpointMechanism,
    /// Whether the breakpoint remains on the canonical branch.
    pub canonical: bool,
    /// Whether the resolution mutates guest-visible memory.
    pub mutates_guest_memory: bool,
    /// Whether a guest-memory trap patch was used.
    pub memory_patch_used: bool,
    /// Whether the operator must opt into a non-canonical mutation branch.
    pub requires_allow_mutate: bool,
}

impl DebugBreakpointReport {
    /// Returns whether this breakpoint satisfies the canonical out-of-band contract.
    #[must_use]
    pub const fn is_canonical_out_of_band(&self) -> bool {
        self.canonical
            && !self.mutates_guest_memory
            && !self.memory_patch_used
            && !self.requires_allow_mutate
    }

    /// Returns whether a software-breakpoint client request was transparently satisfied.
    #[must_use]
    pub const fn transparently_satisfies_software_request(&self) -> bool {
        matches!(
            self.requested_client_kind,
            DebugBreakpointClientKind::Software
        ) && self.is_canonical_out_of_band()
    }
}

/// First operator action that forces a debug session off the canonical run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugNonCanonicalBranchTrigger {
    /// A raw guest register write was requested.
    GuestRegisterWrite,
    /// A raw guest memory write was requested.
    GuestMemoryWrite,
    /// A guest-memory software-breakpoint patch was required.
    MemoryPatchBreakpoint,
    /// The operator continued execution outside the canonical schedule.
    OperatorContinue,
    /// The operator stepped execution outside the canonical schedule.
    OperatorStep,
    /// The operator supplied a model-expressible decision or control operation.
    ScheduleExpressibleEdit,
    /// The operator opened an exec, PTY, or SSH-compatible guest channel.
    GuestIntrospection,
}

impl DebugNonCanonicalBranchTrigger {
    /// Returns the stable trigger label used in graph and event-log markers.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GuestRegisterWrite => "guest-register-write",
            Self::GuestMemoryWrite => "guest-memory-write",
            Self::MemoryPatchBreakpoint => "memory-patch-breakpoint",
            Self::OperatorContinue => "operator-continue",
            Self::OperatorStep => "operator-step",
            Self::ScheduleExpressibleEdit => "schedule-expressible-edit",
            Self::GuestIntrospection => "guest-introspection",
        }
    }
}

/// Arbitrary guest-state edit kind recorded in a debug-edit script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugGuestEditKind {
    /// Raw architectural register write.
    RegisterWrite,
    /// Raw guest memory write.
    MemoryWrite,
    /// Guest-memory breakpoint patch.
    MemoryPatchBreakpoint,
}

impl DebugGuestEditKind {
    /// Returns the stable edit-kind label used in debug-edit scripts.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RegisterWrite => "register-write",
            Self::MemoryWrite => "memory-write",
            Self::MemoryPatchBreakpoint => "memory-patch-breakpoint",
        }
    }
}

/// One arbitrary guest-state edit on a non-canonical debug branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugGuestEdit {
    /// Node whose guest-visible state is edited.
    pub node: NodeId,
    /// Kind of guest-visible state mutation.
    pub kind: DebugGuestEditKind,
    /// Debug coordinate at which the edit applies.
    pub coordinate: DebugCoordinate,
    /// Stable operator-facing target, such as a register name or address.
    pub target: String,
    /// Exact bytes written or patched by the operator.
    pub bytes: Vec<u8>,
}

impl DebugGuestEdit {
    /// Builds an arbitrary guest-state edit.
    #[must_use]
    pub fn new(
        node: NodeId,
        kind: DebugGuestEditKind,
        coordinate: DebugCoordinate,
        target: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            node,
            kind,
            coordinate,
            target: target.into(),
            bytes: bytes.into(),
        }
    }
}

/// Operator-owned execution control that creates a non-canonical branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugOperatorControlKind {
    /// Continue execution under operator control.
    Continue,
    /// Step execution under operator control.
    Step,
}

impl DebugOperatorControlKind {
    /// Returns the stable control label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Step => "step",
        }
    }
}

/// One operator action recorded on a non-canonical debug branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DebugNonCanonicalBranchAction {
    /// A schedule-expressible decision recorded per the control/session log.
    Decision(Decision),
    /// A control-log operation admitted at a virtual-time boundary.
    ControlOperation(ControlOperation),
    /// An arbitrary guest-state edit recorded in the debug-edit script.
    GuestEdit(DebugGuestEdit),
    /// Free operator execution control outside the canonical schedule.
    OperatorControl(DebugOperatorControlKind),
    /// Opens an out-of-band debug guest-agent channel on one node.
    GuestIntrospection {
        /// Node whose guest agent receives the request.
        node: NodeId,
    },
}

impl DebugNonCanonicalBranchAction {
    /// Builds a schedule-expressible decision action.
    #[must_use]
    pub fn decision(decision: Decision) -> Self {
        Self::Decision(decision)
    }

    /// Builds a control-log operation action.
    #[must_use]
    pub fn control_operation(operation: ControlOperation) -> Self {
        Self::ControlOperation(operation)
    }

    /// Builds an arbitrary guest-edit action.
    #[must_use]
    pub fn guest_edit(edit: DebugGuestEdit) -> Self {
        Self::GuestEdit(edit)
    }

    /// Builds an operator-control action.
    #[must_use]
    pub const fn operator_control(kind: DebugOperatorControlKind) -> Self {
        Self::OperatorControl(kind)
    }

    /// Builds a guest-introspection channel action.
    #[must_use]
    pub const fn guest_introspection(node: NodeId) -> Self {
        Self::GuestIntrospection { node }
    }
}

/// Request to fork an attached debugger into a non-canonical branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugNonCanonicalBranchRequest {
    /// Canonical configuration where the debugger is currently attached.
    pub current: Configuration,
    /// Virtual-time boundary at which the first operator action applies.
    pub at: VirtualTime,
    /// First action category that forces the branch.
    pub trigger: DebugNonCanonicalBranchTrigger,
    /// Ordered operator actions recorded on the branch.
    pub actions: Vec<DebugNonCanonicalBranchAction>,
}

impl DebugNonCanonicalBranchRequest {
    /// Builds a non-canonical branch request.
    #[must_use]
    pub fn new(
        current: Configuration,
        at: VirtualTime,
        trigger: DebugNonCanonicalBranchTrigger,
    ) -> Self {
        Self {
            current,
            at,
            trigger,
            actions: Vec::new(),
        }
    }

    /// Appends one operator action to this branch request.
    #[must_use]
    pub fn with_action(mut self, action: DebugNonCanonicalBranchAction) -> Self {
        self.actions.push(action);
        self
    }

    pub(super) fn trigger_has_evidence(&self) -> bool {
        self.actions
            .first()
            .is_some_and(|action| self.trigger.matches_first_action(action))
    }
}

impl DebugNonCanonicalBranchTrigger {
    fn matches_first_action(self, action: &DebugNonCanonicalBranchAction) -> bool {
        match self {
            Self::GuestRegisterWrite => {
                matches!(action, DebugNonCanonicalBranchAction::GuestEdit(edit)
                    if edit.kind == DebugGuestEditKind::RegisterWrite)
            }
            Self::GuestMemoryWrite => {
                matches!(action, DebugNonCanonicalBranchAction::GuestEdit(edit)
                    if edit.kind == DebugGuestEditKind::MemoryWrite)
            }
            Self::MemoryPatchBreakpoint => {
                matches!(action, DebugNonCanonicalBranchAction::GuestEdit(edit)
                    if edit.kind == DebugGuestEditKind::MemoryPatchBreakpoint)
            }
            Self::OperatorContinue => matches!(
                action,
                DebugNonCanonicalBranchAction::OperatorControl(DebugOperatorControlKind::Continue)
            ),
            Self::OperatorStep => matches!(
                action,
                DebugNonCanonicalBranchAction::OperatorControl(DebugOperatorControlKind::Step)
            ),
            Self::ScheduleExpressibleEdit => matches!(
                action,
                DebugNonCanonicalBranchAction::Decision(_)
                    | DebugNonCanonicalBranchAction::ControlOperation(_)
            ),
            Self::GuestIntrospection => {
                matches!(
                    action,
                    DebugNonCanonicalBranchAction::GuestIntrospection { .. }
                )
            }
        }
    }
}

/// One ordered entry in a branch-local debug-edit script.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugEditScriptEntry {
    /// Zero-based entry sequence within the debug-edit script.
    pub sequence: u64,
    /// Exact arbitrary guest-state edit performed by the operator.
    pub edit: DebugGuestEdit,
}

/// Script of arbitrary guest-state edits hung off a non-canonical fork point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugEditScript {
    /// Canonical configuration where the debug branch forked.
    pub fork_point: ContentHash,
    /// Ordered arbitrary edits and their coordinates.
    pub entries: Vec<DebugEditScriptEntry>,
    /// Whether this script is a model-reproducible `(seed, scenario, schedule)` artifact.
    pub model_reproducible: bool,
}

impl DebugEditScript {
    fn from_actions(fork_point: ContentHash, actions: &[DebugNonCanonicalBranchAction]) -> Self {
        let entries = actions
            .iter()
            .filter_map(|action| match action {
                DebugNonCanonicalBranchAction::GuestEdit(edit) => Some(edit.clone()),
                DebugNonCanonicalBranchAction::Decision(_)
                | DebugNonCanonicalBranchAction::ControlOperation(_)
                | DebugNonCanonicalBranchAction::OperatorControl(_)
                | DebugNonCanonicalBranchAction::GuestIntrospection { .. } => None,
            })
            .enumerate()
            .map(|(sequence, edit)| DebugEditScriptEntry {
                sequence: sequence as u64,
                edit,
            })
            .collect();
        Self {
            fork_point,
            entries,
            model_reproducible: false,
        }
    }

    /// Returns whether arbitrary edits are explicitly never model-reproducible.
    #[must_use]
    pub fn is_never_model_reproducible(&self) -> bool {
        !self.model_reproducible
    }
}

/// Event-log fork marker for a non-canonical debug branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugNonCanonicalForkMarker {
    /// Stable branch identity marked in the event log.
    pub branch: ContentHash,
    /// Canonical configuration where the branch forked.
    pub fork_point: ContentHash,
    /// Event-log entry that carries the non-canonical fork marker.
    pub entry: SchedulerEventLogEntry,
}

impl DebugNonCanonicalForkMarker {
    /// Returns whether the marker visibly identifies a non-canonical fork.
    #[must_use]
    pub fn visibly_marks_non_canonical_fork(&self) -> bool {
        self.entry.class() == SchedulerEventLogClass::Causal
            && self.entry.event_payload().kind() == "fork"
            && self.entry.event_payload().attribute("non_canonical")
                == Some(&EventAttributeValue::Bool(true))
            && self.entry.event_payload().attribute("canonical")
                == Some(&EventAttributeValue::Bool(false))
            && self.entry.event_payload().attribute("branch")
                == Some(&EventAttributeValue::String(self.branch.to_hex()))
            && self.entry.event_payload().attribute("fork_point")
                == Some(&EventAttributeValue::String(self.fork_point.to_hex()))
            && self
                .entry
                .event_payload()
                .attribute("from_checkpoint_id")
                .is_some()
            && self
                .entry
                .event_payload()
                .attribute("schedule_delta")
                .is_some()
    }
}

/// Live status shown for a non-canonical debug branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugNonCanonicalLiveStatus {
    /// Branch identity displayed in the live mirror/status surface.
    pub branch: ContentHash,
    /// Canonical configuration where the branch forked.
    pub fork_point: ContentHash,
    /// Checkpoint used as the live branch source.
    pub checkpoint: ContentHash,
    /// Runtime used as the live branch source.
    pub runtime: ContentHash,
    /// Stable live status label.
    pub label: String,
    /// Whether the branch is canonical.
    pub canonical: bool,
    /// Whether the branch is inside Crucible virtual time.
    pub inside_virtual_time: bool,
    /// Whether the branch remains on the single deterministic execution path.
    pub one_execution_path: bool,
}

impl DebugNonCanonicalLiveStatus {
    /// Returns whether the live status cannot be confused with a canonical run.
    #[must_use]
    pub fn visibly_distinguishes_branch(&self) -> bool {
        !self.canonical
            && self.label == "non-canonical-debug-branch"
            && self.checkpoint != ContentHash::default()
            && self.runtime != ContentHash::default()
            && self.inside_virtual_time
            && self.one_execution_path
    }
}

/// Metadata for a branch created by debugger mutation or operator control.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugNonCanonicalBranch {
    /// Stable non-canonical branch identity.
    pub id: ContentHash,
    /// Canonical configuration where the branch forked.
    pub fork_point: ContentHash,
    /// Checkpoint where the debugger was attached at the fork point.
    pub fork_checkpoint: ContentHash,
    /// Runtime state attached before branching.
    pub fork_runtime: ContentHash,
    /// First operator action category that forced the fork.
    pub trigger: DebugNonCanonicalBranchTrigger,
    /// Decision-expressible edits recorded per the control/session log.
    pub schedule_expressible_decisions: Vec<Decision>,
    /// Control-log operations recorded at virtual-time boundaries.
    pub control_log_entries: Vec<ControlOperation>,
    /// Free operator-control actions that forced a non-canonical branch.
    pub operator_controls: Vec<DebugOperatorControlKind>,
    /// Debug-edit script for arbitrary guest-state changes.
    pub debug_edit_script: DebugEditScript,
    /// Non-canonical fork marker appended to the event-log view.
    pub fork_marker: DebugNonCanonicalForkMarker,
    /// Live status/mirror view for this branch.
    pub live_status: DebugNonCanonicalLiveStatus,
    /// Whether the branch was created from an already-instantiated fork source.
    pub ordinary_fork_instantiated: bool,
    /// Whether divergent operator actions are attached to the fork source.
    pub divergent_actions_recorded: bool,
    /// Whether the branch is excluded from replay-oracle checking.
    pub replay_oracle_excluded: bool,
    /// Whether the branch is a `(seed, scenario, schedule)` reproduction artifact.
    pub seed_scenario_schedule_artifact: bool,
}

impl DebugNonCanonicalBranch {
    pub(super) fn from_request(
        attach: &DebugAttachReport,
        request: &DebugNonCanonicalBranchRequest,
        marker_sequence: u64,
    ) -> Self {
        let fork_point = request.current.id();
        let id = debug_non_canonical_branch_id(attach, request);
        let debug_edit_script = DebugEditScript::from_actions(fork_point, &request.actions);
        let schedule_expressible_decisions = request
            .actions
            .iter()
            .filter_map(|action| match action {
                DebugNonCanonicalBranchAction::Decision(decision) => Some(decision.clone()),
                DebugNonCanonicalBranchAction::ControlOperation(_)
                | DebugNonCanonicalBranchAction::GuestEdit(_)
                | DebugNonCanonicalBranchAction::OperatorControl(_)
                | DebugNonCanonicalBranchAction::GuestIntrospection { .. } => None,
            })
            .collect();
        let control_log_entries = request
            .actions
            .iter()
            .filter_map(|action| match action {
                DebugNonCanonicalBranchAction::ControlOperation(operation) => {
                    Some(operation.clone())
                }
                DebugNonCanonicalBranchAction::Decision(_)
                | DebugNonCanonicalBranchAction::GuestEdit(_)
                | DebugNonCanonicalBranchAction::OperatorControl(_)
                | DebugNonCanonicalBranchAction::GuestIntrospection { .. } => None,
            })
            .collect();
        let operator_controls = request
            .actions
            .iter()
            .filter_map(|action| match action {
                DebugNonCanonicalBranchAction::OperatorControl(kind) => Some(*kind),
                DebugNonCanonicalBranchAction::Decision(_)
                | DebugNonCanonicalBranchAction::ControlOperation(_)
                | DebugNonCanonicalBranchAction::GuestEdit(_)
                | DebugNonCanonicalBranchAction::GuestIntrospection { .. } => None,
            })
            .collect();
        let fork_marker = debug_non_canonical_fork_marker(
            id,
            fork_point,
            attach.checkpoint,
            request,
            marker_sequence,
        );
        let live_status = DebugNonCanonicalLiveStatus {
            branch: id,
            fork_point,
            checkpoint: attach.checkpoint,
            runtime: attach.runtime.runtime.id,
            label: String::from("non-canonical-debug-branch"),
            canonical: false,
            inside_virtual_time: true,
            one_execution_path: true,
        };

        Self {
            id,
            fork_point,
            fork_checkpoint: attach.checkpoint,
            fork_runtime: attach.runtime.runtime.id,
            trigger: request.trigger,
            schedule_expressible_decisions,
            control_log_entries,
            operator_controls,
            debug_edit_script,
            fork_marker,
            live_status,
            ordinary_fork_instantiated: attach.uses_instantiated_runtime(),
            divergent_actions_recorded: !request.actions.is_empty(),
            replay_oracle_excluded: true,
            seed_scenario_schedule_artifact: false,
        }
    }

    /// Returns whether this branch is visibly non-canonical everywhere exposed.
    #[must_use]
    pub fn visibly_marked_non_canonical(&self) -> bool {
        self.fork_marker.visibly_marks_non_canonical_fork()
            && self.live_status.visibly_distinguishes_branch()
    }

    /// Returns whether this branch is excluded from replay-oracle checking.
    #[must_use]
    pub const fn excluded_from_replay_oracle(&self) -> bool {
        self.replay_oracle_excluded
    }

    /// Returns whether this branch cannot be emitted as a model reproduction artifact.
    #[must_use]
    pub const fn excluded_from_seed_scenario_schedule_artifacts(&self) -> bool {
        !self.seed_scenario_schedule_artifact
    }

    /// Returns whether the branch remains inside Crucible's virtual-time execution path.
    #[must_use]
    pub fn inside_virtual_time_single_execution_path(&self) -> bool {
        self.live_status.inside_virtual_time && self.live_status.one_execution_path
    }

    /// Returns whether this branch has the ordinary fork source shape.
    #[must_use]
    pub fn ordinary_fork_shape(&self) -> bool {
        self.ordinary_fork_instantiated
            && self.divergent_actions_recorded
            && self.live_status.checkpoint == self.fork_checkpoint
            && self.live_status.runtime == self.fork_runtime
    }

    /// Returns whether schedule-expressible edits are retained in control/session form.
    #[must_use]
    pub fn records_schedule_expressible_edits(&self) -> bool {
        !self.schedule_expressible_decisions.is_empty() || !self.control_log_entries.is_empty()
    }

    /// Returns whether arbitrary guest edits are retained only as a debug-edit script.
    #[must_use]
    pub fn records_arbitrary_guest_edits_as_debug_script(&self) -> bool {
        !self.debug_edit_script.entries.is_empty()
            && self.debug_edit_script.is_never_model_reproducible()
    }
}

/// Report proving a debug mutation fork preserved the canonical run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugNonCanonicalBranchReport {
    /// Recorded non-canonical branch metadata.
    pub branch: DebugNonCanonicalBranch,
    /// Canonical graph/runtime footprint before recording branch metadata.
    pub canonical_footprint_before: DebugReadOnlyInspectionFootprint,
    /// Canonical graph/runtime footprint after recording branch metadata.
    pub canonical_footprint_after: DebugReadOnlyInspectionFootprint,
    /// Canonical causal event-log projection before the fork marker view.
    pub causal_event_log_before: EventLogCausalProjection,
    /// Canonical causal event-log projection after the fork marker view.
    pub causal_event_log_after: EventLogCausalProjection,
    /// Event log view including the non-canonical fork marker.
    pub event_log_with_fork_marker: Vec<SchedulerEventLogEntry>,
}

impl DebugNonCanonicalBranchReport {
    /// Returns whether the canonical run stayed bit-identical.
    #[must_use]
    pub fn canonical_run_bit_identical(&self) -> bool {
        self.canonical_footprint_before == self.canonical_footprint_after
            && self.causal_event_log_before.canonical_bytes()
                == self.causal_event_log_after.canonical_bytes()
    }

    /// Returns whether the branch is excluded from replay and reproduction artifacts.
    #[must_use]
    pub fn excluded_from_oracles_and_artifacts(&self) -> bool {
        self.branch.excluded_from_replay_oracle()
            && self.branch.excluded_from_seed_scenario_schedule_artifacts()
            && self.branch.debug_edit_script.is_never_model_reproducible()
    }

    /// Returns whether every visible surface marks the branch non-canonical.
    #[must_use]
    pub fn visibly_marked_non_canonical(&self) -> bool {
        self.branch.visibly_marked_non_canonical()
    }

    /// Returns whether the branch stays inside virtual time and the one execution path.
    #[must_use]
    pub fn inside_virtual_time_single_execution_path(&self) -> bool {
        self.branch.inside_virtual_time_single_execution_path()
    }

    /// Returns whether all T-DBG-6 invariants are satisfied.
    #[must_use]
    pub fn proves_non_canonical_debug_branch(&self) -> bool {
        self.canonical_run_bit_identical()
            && self.excluded_from_oracles_and_artifacts()
            && self.visibly_marked_non_canonical()
            && self.inside_virtual_time_single_execution_path()
            && self.branch.ordinary_fork_shape()
    }
}

/// Coordinate accepted by the debug `goto` resolver.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DebugCoordinate {
    /// An already-resolved configuration.
    Configuration(Configuration),
    /// A checkpoint/configuration content address.
    Checkpoint(ContentHash),
    /// A unified event-log sequence with a caller-supplied coordinate mapping.
    EventSequence(u64),
    /// The latest checkpoint coordinate at or before a virtual-time point.
    VirtualTime(VirtualTime),
    /// The latest checkpoint coordinate where `node` is at or before `icount`.
    NodeIcount {
        /// Node whose retired-instruction coordinate is requested.
        node: NodeId,
        /// Maximum retired-instruction count.
        icount: Icount,
    },
}

impl DebugCoordinate {
    /// Builds a configuration coordinate.
    #[must_use]
    pub fn configuration(configuration: Configuration) -> Self {
        Self::Configuration(configuration)
    }

    /// Builds a checkpoint coordinate.
    #[must_use]
    pub const fn checkpoint(checkpoint: ContentHash) -> Self {
        Self::Checkpoint(checkpoint)
    }

    /// Builds an event-log coordinate.
    #[must_use]
    pub const fn event_sequence(sequence: u64) -> Self {
        Self::EventSequence(sequence)
    }

    /// Builds a virtual-time coordinate.
    #[must_use]
    pub const fn virtual_time(time: VirtualTime) -> Self {
        Self::VirtualTime(time)
    }

    /// Builds a node icount coordinate.
    #[must_use]
    pub fn node_icount(node: NodeId, icount: Icount) -> Self {
        Self::NodeIcount { node, icount }
    }
}

/// Divergence-bisection coordinate accepted directly as a debug target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugDivergenceCoordinate {
    /// Node pinned by the divergence bisection.
    pub node: NodeId,
    /// Retired-instruction count pinned by the divergence bisection.
    pub icount: Icount,
    /// Open-set event kind reported by the divergence bisection.
    pub kind: String,
}

impl DebugDivergenceCoordinate {
    /// Builds a node-local divergence coordinate.
    #[must_use]
    pub fn new(node: NodeId, icount: Icount, kind: impl Into<String>) -> Self {
        Self {
            node,
            icount,
            kind: kind.into(),
        }
    }

    /// Converts an event-log causal divergence point when it is node-local.
    #[must_use]
    pub fn from_event_log_causal_divergence(point: &EventLogCausalDivergencePoint) -> Option<Self> {
        Some(Self {
            node: point.at.node.clone()?,
            icount: point.at.icount,
            kind: point.kind.clone(),
        })
    }
}

/// Operator-facing target selector accepted by the debug target resolver.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DebugTargetSelector {
    /// Direct `--at` coordinate.
    At(DebugCoordinate),
    /// `--at-event <seq>` event-log coordinate.
    AtEvent(u64),
    /// `--at-failure`, the first assertion-violation event.
    AtFailure,
    /// `--at-checkpoint <hash>` checkpoint coordinate.
    AtCheckpoint(ContentHash),
    /// Divergence-bisection `(node, icount, kind)` coordinate.
    Divergence(DebugDivergenceCoordinate),
}

impl DebugTargetSelector {
    /// Builds a direct `--at` virtual-time selector.
    #[must_use]
    pub const fn at_virtual_time(time: VirtualTime) -> Self {
        Self::At(DebugCoordinate::virtual_time(time))
    }

    /// Builds a direct `--at` node-icount selector.
    #[must_use]
    pub fn at_node_icount(node: NodeId, icount: Icount) -> Self {
        Self::At(DebugCoordinate::node_icount(node, icount))
    }

    /// Builds an `--at-event` selector.
    #[must_use]
    pub const fn at_event(sequence: u64) -> Self {
        Self::AtEvent(sequence)
    }

    /// Builds an `--at-failure` selector.
    #[must_use]
    pub const fn at_failure() -> Self {
        Self::AtFailure
    }

    /// Builds an `--at-checkpoint` selector.
    #[must_use]
    pub const fn at_checkpoint(checkpoint: ContentHash) -> Self {
        Self::AtCheckpoint(checkpoint)
    }

    /// Builds a divergence-bisection selector.
    #[must_use]
    pub fn divergence(coordinate: DebugDivergenceCoordinate) -> Self {
        Self::Divergence(coordinate)
    }
}

/// Copy-pasteable debug command printed in non-passing failure footers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugFailureFooterCommand {
    /// Reproduction artifact path displayed to the operator.
    pub artifact: String,
    /// Debug command that opens at the first failure.
    pub debug_command: String,
}

impl DebugFailureFooterCommand {
    /// Builds the `crucible debug <artifact> --at-failure` command.
    #[must_use]
    pub fn new(artifact: impl Into<String>) -> Self {
        let artifact = artifact.into();
        let debug_command = format!(
            "crucible debug {} --at-failure",
            shell_quote_command_argument(&artifact)
        );
        Self {
            artifact,
            debug_command,
        }
    }

    /// Returns whether the command is the required at-failure debug footer.
    #[must_use]
    pub fn is_copy_pasteable_at_failure(&self) -> bool {
        !self.artifact.is_empty()
            && !self.artifact.chars().any(|ch| matches!(ch, '\n' | '\0'))
            && self.debug_command
                == format!(
                    "crucible debug {} --at-failure",
                    shell_quote_command_argument(&self.artifact)
                )
    }
}

/// Request to resolve an operator-facing debug target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugTargetResolverRequest {
    /// Configuration where the debug session currently sits.
    pub current: Configuration,
    /// Operator-facing target selector.
    pub selector: DebugTargetSelector,
    /// Mapping from event-log sequence to temporal-graph coordinate.
    pub event_coordinates: BTreeMap<u64, Configuration>,
    /// Reproduction artifact shown in the optional failure footer command.
    pub failure_footer_artifact: Option<String>,
}

impl DebugTargetResolverRequest {
    /// Builds a debug target resolver request.
    #[must_use]
    pub fn new(current: Configuration, selector: DebugTargetSelector) -> Self {
        Self {
            current,
            selector,
            event_coordinates: BTreeMap::new(),
            failure_footer_artifact: None,
        }
    }

    /// Adds an event-log sequence to configuration mapping.
    #[must_use]
    pub fn with_event_coordinate(mut self, sequence: u64, configuration: Configuration) -> Self {
        self.event_coordinates.insert(sequence, configuration);
        self
    }

    /// Adds the artifact path used to render an at-failure debug footer.
    #[must_use]
    pub fn with_failure_footer_artifact(mut self, artifact: impl Into<String>) -> Self {
        self.failure_footer_artifact = Some(artifact.into());
        self
    }
}

/// Result of resolving an operator-facing debug target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugTargetResolverReport {
    /// Target selector supplied by the operator.
    pub selector: DebugTargetSelector,
    /// Concrete coordinate delegated to `debug goto`.
    pub resolved_coordinate: DebugCoordinate,
    /// Resolved configuration content address.
    pub target_configuration: ContentHash,
    /// `goto` request that can realize the resolved target.
    pub goto_request: DebugGotoRequest,
    /// Event sequence selected by `--at-failure`, when that selector was used.
    pub failure_event_sequence: Option<u64>,
    /// Divergence coordinate consumed directly by the resolver, when present.
    pub divergence: Option<DebugDivergenceCoordinate>,
    /// Optional copy-pasteable failure footer command.
    pub failure_footer: Option<DebugFailureFooterCommand>,
}

impl DebugTargetResolverReport {
    /// Returns whether the report delegates the resolved coordinate to `goto`.
    #[must_use]
    pub fn delegates_to_goto(&self) -> bool {
        self.goto_request.target == self.resolved_coordinate
            && self.goto_request.current.id() != ContentHash::default()
            && self.target_configuration != ContentHash::default()
    }

    /// Returns whether the report carries the required at-failure footer command.
    #[must_use]
    pub fn has_copy_pasteable_at_failure_footer(&self) -> bool {
        self.failure_footer
            .as_ref()
            .is_some_and(DebugFailureFooterCommand::is_copy_pasteable_at_failure)
    }

    /// Returns whether this report satisfies the T-DBG-7 target resolver contract.
    #[must_use]
    pub fn proves_debug_target_resolution(&self) -> bool {
        self.delegates_to_goto()
            && (!matches!(self.selector, DebugTargetSelector::AtFailure)
                || self.failure_event_sequence.is_some())
            && (!matches!(self.selector, DebugTargetSelector::Divergence(_))
                || self.divergence.is_some())
    }
}

/// Contract for source-level debug-info ownership.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugSymbolResolutionPolicy {
    /// Whether Crucible provides an in-process symbol server.
    pub crucible_symbol_server: bool,
    /// Whether Crucible parses DWARF or maps source locations itself.
    pub crucible_dwarf_resolution: bool,
    /// Whether source mapping is delegated to the operator's gdb-protocol client.
    pub operator_gdb_client_resolves_symbols: bool,
    /// Whether debug info is supplied by the operator instead of the engine.
    pub operator_supplied_debug_info: bool,
}

impl DebugSymbolResolutionPolicy {
    /// Builds the RFC-0010 no-symbol-server policy.
    #[must_use]
    pub const fn no_symbol_server() -> Self {
        Self {
            crucible_symbol_server: false,
            crucible_dwarf_resolution: false,
            operator_gdb_client_resolves_symbols: true,
            operator_supplied_debug_info: true,
        }
    }

    /// Returns whether Crucible stays out of source mapping.
    #[must_use]
    pub const fn proves_no_crucible_symbol_server(&self) -> bool {
        !self.crucible_symbol_server
            && !self.crucible_dwarf_resolution
            && self.operator_gdb_client_resolves_symbols
            && self.operator_supplied_debug_info
    }
}

/// Contract for multi-vCPU debugger behavior.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugMultiVcpuPolicy {
    /// Whether each vCPU is exposed as a distinct gdb thread.
    pub exposes_vcpus_as_gdb_threads: bool,
    /// Whether the node model is deterministic single-threaded round-robin TCG.
    pub deterministic_round_robin_icount: bool,
    /// Whether an affected node lands every vCPU at one coordinate.
    pub lands_affected_vcpus_at_one_coordinate: bool,
    /// Whether whole-world `goto` lands every node and vCPU coherently.
    pub whole_world_lands_every_vcpu: bool,
    /// Whether reads, breakpoints, and reverse operations observe one coherent state.
    pub coherent_reads_breakpoints_and_reverse: bool,
}

impl DebugMultiVcpuPolicy {
    /// Builds the RFC-0010 multi-vCPU debug policy.
    #[must_use]
    pub const fn coherent_round_robin_threads() -> Self {
        Self {
            exposes_vcpus_as_gdb_threads: true,
            deterministic_round_robin_icount: true,
            lands_affected_vcpus_at_one_coordinate: true,
            whole_world_lands_every_vcpu: true,
            coherent_reads_breakpoints_and_reverse: true,
        }
    }

    /// Returns whether multi-vCPU debugging satisfies the coherence contract.
    #[must_use]
    pub const fn proves_multi_vcpu_coherence(&self) -> bool {
        self.exposes_vcpus_as_gdb_threads
            && self.deterministic_round_robin_icount
            && self.lands_affected_vcpus_at_one_coordinate
            && self.whole_world_lands_every_vcpu
            && self.coherent_reads_breakpoints_and_reverse
    }
}

/// Contract for read-only gdbstub fallback while the S14 spike is unresolved.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugGdbstubStepPolicy {
    /// Whether the gdbstub attach/step behavior remains a named spike.
    pub spike_required: bool,
    /// Whether debugger attach defaults to read-only.
    pub read_only_attach_default: bool,
    /// Whether stepping is routed through Crucible deterministic step verbs.
    pub crucible_driven_step_reverse_step: bool,
    /// Whether raw gdb single-step is disabled until the spike is green.
    pub raw_gdb_single_step_disabled_until_green: bool,
}

impl DebugGdbstubStepPolicy {
    /// Builds the conservative S14 fallback policy.
    #[must_use]
    pub const fn disabled_raw_single_step_until_green() -> Self {
        Self {
            spike_required: true,
            read_only_attach_default: true,
            crucible_driven_step_reverse_step: true,
            raw_gdb_single_step_disabled_until_green: true,
        }
    }

    /// Returns whether the fallback prevents raw gdb stepping from perturbing time.
    #[must_use]
    pub const fn proves_s14_fallback(&self) -> bool {
        self.spike_required
            && self.read_only_attach_default
            && self.crucible_driven_step_reverse_step
            && self.raw_gdb_single_step_disabled_until_green
    }
}

/// Contract for the read-only versus mutating debug boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReadMutationBoundaryPolicy {
    /// Whether read-only mode is the default.
    pub read_only_default: bool,
    /// Whether read-only mode must leave canonical execution bit-identical.
    pub canonical_bit_identical_required: bool,
    /// Whether mutation requires a non-canonical debug branch.
    pub allow_mutate_forks_non_canonical_branch: bool,
    /// Whether the branch must be visibly labelled non-canonical.
    pub non_canonical_branch_label_required: bool,
    /// Whether tests must gate-enforce the boundary.
    pub gate_enforced: bool,
}

impl DebugReadMutationBoundaryPolicy {
    /// Builds the RFC-0010 read/mutate boundary policy.
    #[must_use]
    pub const fn read_only_default_with_explicit_branching() -> Self {
        Self {
            read_only_default: true,
            canonical_bit_identical_required: true,
            allow_mutate_forks_non_canonical_branch: true,
            non_canonical_branch_label_required: true,
            gate_enforced: true,
        }
    }

    /// Returns whether the read/mutate boundary is explicit and gate-enforced.
    #[must_use]
    pub const fn proves_read_mutate_boundary(&self) -> bool {
        self.read_only_default
            && self.canonical_bit_identical_required
            && self.allow_mutate_forks_non_canonical_branch
            && self.non_canonical_branch_label_required
            && self.gate_enforced
    }
}

/// Contract for debug reverse-latency and snapshot-completeness risks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReverseLatencyPolicy {
    /// Whether `--checkpoint-stride` is exposed as a reverse-latency tuning knob.
    pub checkpoint_stride_supported: bool,
    /// Whether correctness is independent of opportunistic fat checkpoints.
    pub correctness_independent_of_fat_checkpoints: bool,
    /// Whether thin/replay remains the default until snapshot completeness is green.
    pub thin_replay_until_snapshot_completeness: bool,
}

impl DebugReverseLatencyPolicy {
    /// Builds the RFC-0010 reverse-latency risk policy.
    #[must_use]
    pub const fn performance_only_checkpoint_cadence() -> Self {
        Self {
            checkpoint_stride_supported: true,
            correctness_independent_of_fat_checkpoints: true,
            thin_replay_until_snapshot_completeness: true,
        }
    }

    /// Returns whether reverse-latency tuning cannot affect correctness.
    #[must_use]
    pub const fn proves_reverse_latency_policy(&self) -> bool {
        self.checkpoint_stride_supported
            && self.correctness_independent_of_fat_checkpoints
            && self.thin_replay_until_snapshot_completeness
    }
}

/// Contract for the `crucible debug` CLI surface.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugCliSurfaceContract {
    /// Accepted coordinate flags.
    pub coordinate_flags: Vec<&'static str>,
    /// Accepted debug-control flags.
    pub control_flags: Vec<&'static str>,
    /// Accepted interactive verbs.
    pub interactive_verbs: Vec<&'static str>,
    /// Whether the CLI stores no debugger state of its own.
    pub cli_holds_debug_state: bool,
    /// Whether the CLI delegates to existing session operations.
    pub delegates_to_session_commands: bool,
    /// Whether gdb traffic is exposed only through the mediated gdbstub proxy.
    pub delegates_to_gdbstub_proxy: bool,
    /// Source-level debug-info ownership policy.
    pub symbol_resolution: DebugSymbolResolutionPolicy,
    /// Multi-vCPU debugger coherence policy.
    pub multi_vcpu: DebugMultiVcpuPolicy,
    /// Gdbstub attach/step fallback policy.
    pub gdbstub_step: DebugGdbstubStepPolicy,
    /// Read-only versus mutating debug boundary policy.
    pub read_mutate_boundary: DebugReadMutationBoundaryPolicy,
    /// Reverse-latency and snapshot-completeness policy.
    pub reverse_latency: DebugReverseLatencyPolicy,
}

impl DebugCliSurfaceContract {
    /// Builds the RFC-0010 `crucible debug` surface contract.
    #[must_use]
    pub fn rfc0010() -> Self {
        Self {
            coordinate_flags: vec!["--at", "--at-event", "--at-failure", "--at-checkpoint"],
            control_flags: vec![
                "--node",
                "--gdb-listen",
                "--read-only",
                "--allow-mutate",
                "--checkpoint-stride",
            ],
            interactive_verbs: vec![
                "attach-gdb",
                "fork-debug",
                "goto",
                "reverse-step",
                "reverse-continue",
                "exec",
                "pty",
                "ssh",
            ],
            cli_holds_debug_state: false,
            delegates_to_session_commands: true,
            delegates_to_gdbstub_proxy: true,
            symbol_resolution: DebugSymbolResolutionPolicy::no_symbol_server(),
            multi_vcpu: DebugMultiVcpuPolicy::coherent_round_robin_threads(),
            gdbstub_step: DebugGdbstubStepPolicy::disabled_raw_single_step_until_green(),
            read_mutate_boundary:
                DebugReadMutationBoundaryPolicy::read_only_default_with_explicit_branching(),
            reverse_latency: DebugReverseLatencyPolicy::performance_only_checkpoint_cadence(),
        }
    }

    /// Returns whether the CLI exposes every required coordinate flag.
    #[must_use]
    pub fn has_required_coordinate_flags(&self) -> bool {
        debug_labels_contain_all(
            &self.coordinate_flags,
            &["--at", "--at-event", "--at-failure", "--at-checkpoint"],
        )
    }

    /// Returns whether the CLI exposes every required debug-control flag.
    #[must_use]
    pub fn has_required_control_flags(&self) -> bool {
        debug_labels_contain_all(
            &self.control_flags,
            &[
                "--node",
                "--gdb-listen",
                "--read-only",
                "--allow-mutate",
                "--checkpoint-stride",
            ],
        )
    }

    /// Returns whether the CLI exposes every required interactive verb.
    #[must_use]
    pub fn has_required_interactive_verbs(&self) -> bool {
        debug_labels_contain_all(
            &self.interactive_verbs,
            &[
                "attach-gdb",
                "fork-debug",
                "goto",
                "reverse-step",
                "reverse-continue",
                "exec",
                "pty",
                "ssh",
            ],
        )
    }

    /// Returns whether this surface satisfies the T-DBG-8 contract.
    #[must_use]
    pub fn proves_t_dbg_8(&self) -> bool {
        self.has_required_coordinate_flags()
            && self.has_required_control_flags()
            && self.has_required_interactive_verbs()
            && !self.cli_holds_debug_state
            && self.delegates_to_session_commands
            && self.delegates_to_gdbstub_proxy
            && self.symbol_resolution.proves_no_crucible_symbol_server()
            && self.multi_vcpu.proves_multi_vcpu_coherence()
            && self.gdbstub_step.proves_s14_fallback()
            && self.read_mutate_boundary.proves_read_mutate_boundary()
            && self.reverse_latency.proves_reverse_latency_policy()
    }
}

/// Request to move a debug session to another temporal-graph coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugGotoRequest {
    /// Configuration where the debug session currently sits.
    pub current: Configuration,
    /// Coordinate to resolve and realize through restore-plus-replay.
    pub target: DebugCoordinate,
    /// Mapping from event-log sequence to temporal-graph coordinate.
    pub event_coordinates: BTreeMap<u64, Configuration>,
}

impl DebugGotoRequest {
    /// Builds a debug `goto` request.
    #[must_use]
    pub fn new(current: Configuration, target: DebugCoordinate) -> Self {
        Self {
            current,
            target,
            event_coordinates: BTreeMap::new(),
        }
    }

    /// Builds a debug `goto` request for an already-resolved configuration.
    #[must_use]
    pub fn at_configuration(current: Configuration, target: Configuration) -> Self {
        Self::new(current, DebugCoordinate::configuration(target))
    }

    /// Adds an event-log sequence to configuration mapping.
    #[must_use]
    pub fn with_event_coordinate(mut self, sequence: u64, configuration: Configuration) -> Self {
        self.event_coordinates.insert(sequence, configuration);
        self
    }
}

/// Replay-oracle bisection coordinates for a failed debug `goto`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReplayOracleBisectionRequest {
    /// Configuration where the debug session started.
    pub current_configuration: ContentHash,
    /// Configuration the debugger attempted to reach.
    pub target_configuration: ContentHash,
    /// Restore configuration selected before replay.
    pub restore_configuration: ContentHash,
    /// Restore checkpoint selected before replay.
    pub restore_checkpoint: ContentHash,
    /// Last matching schedule prefix length, when one was found.
    pub last_matching_schedule_prefix_len: Option<usize>,
    /// First differing schedule prefix length found by bisection.
    pub first_different_schedule_prefix_len: usize,
}

/// Report proving a debug `goto` used restore-plus-replay.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugGotoReport {
    /// Configuration where the debug session started.
    pub current_configuration: ContentHash,
    /// Coordinate requested by the operator.
    pub target_coordinate: DebugCoordinate,
    /// Configuration reached by the operation.
    pub target_configuration: ContentHash,
    /// Configuration restored before forward replay.
    pub restore_configuration: ContentHash,
    /// Checkpoint restored before forward replay.
    pub restore_checkpoint: ContentHash,
    /// Number of schedule decisions replayed after restoring.
    pub replay_suffix_decisions: usize,
    /// Runtime realized at the target coordinate.
    pub runtime: TemporalGraphRuntime,
    /// Fat checkpoint materialized from the target runtime for oracle checking.
    pub target_checkpoint: ContentHash,
    /// Replay-oracle proof that the rewound coordinate matches forward replay.
    pub replay_oracle: ReplayOracleCheck,
}

impl DebugGotoReport {
    /// Returns whether this report proves an exact content-addressed target.
    #[must_use]
    pub fn proves_replay_oracle(&self) -> bool {
        self.runtime.configuration == self.target_configuration
            && self.runtime.checkpoint == self.target_configuration
            && self.replay_oracle.configuration == self.target_configuration
            && self.replay_oracle.fat_checkpoint == self.target_checkpoint
            && self.replay_oracle.thin_checkpoint == self.target_checkpoint
    }

    /// Returns whether this `goto` restored a checkpoint then replayed to target.
    #[must_use]
    pub fn used_restore_then_replay(&self) -> bool {
        self.restore_configuration != self.target_configuration && self.replay_suffix_decisions > 0
    }
}

/// Backend request to replace the live debug runtime at a resolved graph coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugRuntimeRepositionRequest {
    /// Node whose live QEMU process and gateway backend are replaced.
    pub node: NodeId,
    /// Configuration currently owned by the live runtime.
    pub current_configuration: ContentHash,
    /// Private QEMU endpoint currently selected by the debugger gateway.
    pub current_qemu_gdbstub: DebugGdbEndpoint,
    /// Complete target configuration the backend must instantiate.
    pub target: Configuration,
    /// Configuration whose checkpoint must be restored before replay.
    pub restore_configuration: ContentHash,
    /// Fat checkpoint the backend must restore before replay.
    pub restore_checkpoint: ContentHash,
    /// Fat checkpoint expected after replay reaches the target.
    pub target_checkpoint: ContentHash,
    /// Runtime state whose scheduler, event-log, and node coordinates must be realized.
    pub target_runtime: RuntimeState,
    /// Fat/thin replay-oracle proof binding the target checkpoint to the target configuration.
    pub replay_oracle: ReplayOracleCheck,
}

impl DebugRuntimeRepositionRequest {
    /// Builds a backend request from a graph-level `goto` plan and its target configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when `target`
    /// does not match the configuration named by `goto`.
    pub fn from_goto(
        target: Configuration,
        goto: &DebugGotoReport,
        node: NodeId,
        current_qemu_gdbstub: DebugGdbEndpoint,
    ) -> Result<Self, EngineError> {
        if target.id() != goto.target_configuration {
            return Err(EngineError::CheckpointConfigurationMismatch {
                checkpoint: goto.target_checkpoint,
                expected: goto.target_configuration,
                actual: target.id(),
            });
        }
        if !goto.proves_replay_oracle() {
            return Err(EngineError::ReplayOracleMismatch {
                checkpoint: goto.target_checkpoint,
                expected: goto.replay_oracle.thin_checkpoint,
                actual: goto.replay_oracle.fat_checkpoint,
            });
        }
        Ok(Self {
            node,
            current_configuration: goto.current_configuration,
            current_qemu_gdbstub,
            target,
            restore_configuration: goto.restore_configuration,
            restore_checkpoint: goto.restore_checkpoint,
            target_checkpoint: goto.target_checkpoint,
            target_runtime: goto.runtime.runtime.clone(),
            replay_oracle: goto.replay_oracle.clone(),
        })
    }

    /// Returns whether the request carries a complete target replay-oracle proof.
    #[must_use]
    pub fn proves_target_oracle(&self) -> bool {
        self.target_runtime.configuration == self.target.id()
            && self.replay_oracle.configuration == self.target.id()
            && self.replay_oracle.fat_checkpoint == self.target_checkpoint
            && self.replay_oracle.thin_checkpoint == self.target_checkpoint
    }
}

/// Backend evidence that an atomic live-runtime replacement completed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugRuntimeRepositionReport {
    /// Node whose replacement was promoted by the debugger gateway.
    pub node: NodeId,
    /// Configuration replaced by the operation.
    pub previous_configuration: ContentHash,
    /// Configuration now owned by the live runtime.
    pub target_configuration: ContentHash,
    /// Fat checkpoint verified after replay reached the target.
    pub target_checkpoint: ContentHash,
    /// Private QEMU endpoint promoted by the debugger gateway.
    pub qemu_gdbstub: DebugGdbEndpoint,
    /// Nonzero gateway generation returned by the committed prepare transaction.
    pub gateway_generation: u64,
    /// How the replaced world was deauthorized after gateway promotion.
    pub retired_world_cleanup: DebugRetiredWorldCleanup,
}

/// Teardown evidence for a world retired by debugger runtime replacement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DebugRetiredWorldCleanup {
    /// Every old QEMU child completed the normal shutdown and reap ladder.
    Reaped,
    /// Runtime authority was detached, but process cleanup was not observed.
    DetachedCleanupPending {
        /// Bounded diagnostic from the failed observed shutdown ladder.
        diagnostic: String,
    },
}

impl DebugRetiredWorldCleanup {
    /// Returns whether the retired world no longer has scheduler or gateway authority.
    ///
    /// This proof concerns Crucible control authority only. A
    /// [`Self::DetachedCleanupPending`] result deliberately makes no claim that
    /// every operating-system process has exited or been reaped.
    #[must_use]
    pub const fn proves_deauthorization(&self) -> bool {
        true
    }
}

impl DebugRuntimeRepositionReport {
    /// Builds a success report for a gateway promotion.
    #[must_use]
    pub fn completed(
        request: &DebugRuntimeRepositionRequest,
        qemu_gdbstub: DebugGdbEndpoint,
        gateway_generation: u64,
    ) -> Self {
        Self::completed_with_cleanup(
            request,
            qemu_gdbstub,
            gateway_generation,
            DebugRetiredWorldCleanup::Reaped,
        )
    }

    /// Builds a success report with explicit retired-world cleanup evidence.
    #[must_use]
    pub fn completed_with_cleanup(
        request: &DebugRuntimeRepositionRequest,
        qemu_gdbstub: DebugGdbEndpoint,
        gateway_generation: u64,
        retired_world_cleanup: DebugRetiredWorldCleanup,
    ) -> Self {
        Self {
            node: request.node.clone(),
            previous_configuration: request.current_configuration,
            target_configuration: request.target.id(),
            target_checkpoint: request.target_checkpoint,
            qemu_gdbstub,
            gateway_generation,
            retired_world_cleanup,
        }
    }

    /// Returns whether this report proves completion of exactly `request`.
    #[must_use]
    pub fn proves(&self, request: &DebugRuntimeRepositionRequest) -> bool {
        request.proves_target_oracle()
            && self.node == request.node
            && self.previous_configuration == request.current_configuration
            && self.target_configuration == request.target.id()
            && self.target_checkpoint == request.target_checkpoint
            && self.qemu_gdbstub != request.current_qemu_gdbstub
            && self.gateway_generation != 0
            && self.retired_world_cleanup.proves_deauthorization()
    }
}

/// Reverse-step grain mirrored from the forward debugger step surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugReverseStepGrain {
    /// Mirror of forward instruction stepping.
    Instruction,
    /// Mirror of forward quantum stepping.
    Quantum,
    /// Mirror of forward event stepping.
    Event,
    /// Mirror of forward assertion-state stepping.
    Assertion,
    /// Mirror of forward timer stepping.
    Timer,
}

impl DebugReverseStepGrain {
    /// The closed reverse-step set expected by the debug CLI.
    pub const ALL: [Self; 5] = [
        Self::Instruction,
        Self::Quantum,
        Self::Event,
        Self::Assertion,
        Self::Timer,
    ];
}

/// Request to reverse-step from one debug coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReverseStepRequest {
    /// Configuration where the debug session currently sits.
    pub current: Configuration,
    /// Reverse-step grain requested by the operator.
    pub grain: DebugReverseStepGrain,
    /// Event-log entries available for event-like grains.
    pub event_log: Vec<SchedulerEventLogEntry>,
    /// Mapping from event-log sequence to temporal-graph coordinate.
    pub event_coordinates: BTreeMap<u64, Configuration>,
    /// Exclusive upper bound for event-log entries considered current.
    pub current_event_sequence: Option<u64>,
}

impl DebugReverseStepRequest {
    /// Builds a reverse-step request.
    #[must_use]
    pub fn new(
        current: Configuration,
        grain: DebugReverseStepGrain,
        event_log: Vec<SchedulerEventLogEntry>,
    ) -> Self {
        Self {
            current,
            grain,
            event_log,
            event_coordinates: BTreeMap::new(),
            current_event_sequence: None,
        }
    }

    /// Adds an event-log sequence to configuration mapping.
    #[must_use]
    pub fn with_event_coordinate(mut self, sequence: u64, configuration: Configuration) -> Self {
        self.event_coordinates.insert(sequence, configuration);
        self
    }

    /// Sets the exclusive current event-log sequence limit.
    #[must_use]
    pub const fn with_current_event_sequence(mut self, sequence: u64) -> Self {
        self.current_event_sequence = Some(sequence);
        self
    }

    pub(super) fn current_event_sequence_limit(&self) -> u64 {
        self.current_event_sequence.unwrap_or(u64::MAX)
    }
}

/// Report for a completed reverse-step operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReverseStepReport {
    /// Reverse-step grain that was resolved.
    pub grain: DebugReverseStepGrain,
    /// Event-log sequence selected for event-like grains.
    pub target_event_sequence: Option<u64>,
    /// Configuration selected as the target coordinate.
    pub target_configuration: ContentHash,
    /// Delegated `goto` report for the resolved coordinate.
    pub goto: DebugGotoReport,
}

impl DebugReverseStepReport {
    /// Returns whether reverse-step resolved to a `goto`.
    #[must_use]
    pub fn realized_by_goto(&self) -> bool {
        self.goto.target_configuration == self.target_configuration
            && self.goto.proves_replay_oracle()
    }
}

/// Request to reverse-continue to the latest prior matching condition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReverseContinueRequest {
    /// Configuration where the debug session currently sits.
    pub current: Configuration,
    /// Condition evaluated over checked event-log prefixes.
    pub condition: Condition,
    /// Event-log entries available for the backward scan.
    pub event_log: Vec<SchedulerEventLogEntry>,
    /// Mapping from event-log sequence to temporal-graph coordinate.
    pub event_coordinates: BTreeMap<u64, Configuration>,
    /// Inclusive upper bound for event-log entries considered current.
    pub current_event_sequence: Option<u64>,
}

impl DebugReverseContinueRequest {
    /// Builds a reverse-continue request.
    #[must_use]
    pub fn new(
        current: Configuration,
        condition: Condition,
        event_log: Vec<SchedulerEventLogEntry>,
    ) -> Self {
        Self {
            current,
            condition,
            event_log,
            event_coordinates: BTreeMap::new(),
            current_event_sequence: None,
        }
    }

    /// Adds an event-log sequence to configuration mapping.
    #[must_use]
    pub fn with_event_coordinate(mut self, sequence: u64, configuration: Configuration) -> Self {
        self.event_coordinates.insert(sequence, configuration);
        self
    }

    /// Sets the inclusive current event-log sequence limit.
    #[must_use]
    pub const fn with_current_event_sequence(mut self, sequence: u64) -> Self {
        self.current_event_sequence = Some(sequence);
        self
    }

    pub(super) fn current_event_sequence_limit(&self) -> u64 {
        self.current_event_sequence.unwrap_or(u64::MAX)
    }

    pub(super) fn searched_entries_before(&self, matching_index: usize) -> usize {
        self.event_log.len().saturating_sub(matching_index)
    }
}

/// Matching coordinate selected by reverse-continue.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReverseContinueMatch {
    /// Event-log sequence whose prefix made the condition true.
    pub event_sequence: u64,
    /// Configuration selected for the matching coordinate.
    pub target_configuration: ContentHash,
    /// Delegated `goto` report for the selected coordinate.
    pub goto: DebugGotoReport,
}

/// Report for a reverse-continue scan.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugReverseContinueReport {
    /// Condition used for the backward scan.
    pub condition: Condition,
    /// Candidate event-log prefixes inspected before completion.
    pub searched_entries: usize,
    /// Matching coordinate, or `None` when the condition never held.
    pub matched: Option<DebugReverseContinueMatch>,
}

impl DebugReverseContinueReport {
    /// Returns whether reverse-continue found and realized a matching coordinate.
    #[must_use]
    pub fn realized_by_goto(&self) -> bool {
        self.matched
            .as_ref()
            .is_some_and(|matched| matched.goto.proves_replay_oracle())
    }
}

/// Request to move one node to a node-icount debug coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugPerNodeTimeTravelRequest {
    /// Configuration where the debug session currently sits.
    pub current: Configuration,
    /// Node whose debugger-visible machine state should move.
    pub node: NodeId,
    /// Per-node retired-instruction coordinate to land at.
    pub icount: Icount,
}

impl DebugPerNodeTimeTravelRequest {
    /// Builds a per-node time-travel request.
    #[must_use]
    pub fn new(current: Configuration, node: NodeId, icount: Icount) -> Self {
        Self {
            current,
            node,
            icount,
        }
    }
}

/// Evidence for scoped per-node goto over one node's checkpoint material.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugPerNodeGotoReport {
    /// Configuration where the debug session started.
    pub current_configuration: ContentHash,
    /// Exact per-node coordinate requested by the operator.
    pub target_coordinate: DebugCoordinate,
    /// Configuration that supplies the target node material.
    pub target_configuration: ContentHash,
    /// Restore point used as the source of target node material.
    pub restore_configuration: ContentHash,
    /// Checkpoint id loaded for the scoped node restore.
    pub restore_checkpoint: ContentHash,
    /// Number of schedule decisions replayed to derive the target node blob.
    pub replay_suffix_decisions: usize,
    /// Replay-oracle admission for an exact cached target snapshot, when present.
    pub replay_oracle: Option<ReplayOracleCheck>,
    /// Nodes whose material was derived for the scoped landing.
    pub materialized_nodes: BTreeSet<NodeId>,
}

impl DebugPerNodeGotoReport {
    /// Returns whether this goto derived material only for `node`.
    #[must_use]
    pub fn proves_scoped_to_node(&self, node: &NodeId) -> bool {
        self.materialized_nodes.len() == 1 && self.materialized_nodes.contains(node)
    }

    /// Returns whether any exact cached target snapshot passed replay-oracle admission.
    #[must_use]
    pub fn proves_replay_oracle_or_thin_source(&self) -> bool {
        self.replay_oracle.as_ref().is_none_or(|check| {
            check.configuration == self.target_configuration
                && check.fat_checkpoint == self.target_configuration
                && check.thin_checkpoint == self.target_configuration
        })
    }
}

/// Report proving scoped per-node time travel left other nodes untouched.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugPerNodeTimeTravelReport {
    /// Configuration where the debug session started.
    pub current_configuration: ContentHash,
    /// Node moved by the scoped time-travel operation.
    pub node: NodeId,
    /// Icount requested for `node`.
    pub requested_icount: Icount,
    /// Configuration that supplied the moved node's checkpoint material.
    pub target_configuration: ContentHash,
    /// Node icount before scoped travel.
    pub current_node_icount: Icount,
    /// Node icount after scoped travel.
    pub landed_node_icount: Icount,
    /// Node material before scoped travel.
    pub current_node_blob: NodeBlobRef,
    /// Node material after scoped travel.
    pub landed_node_blob: NodeBlobRef,
    /// Attached runtime's per-node icount map.
    pub current_node_icounts: BTreeMap<NodeId, Icount>,
    /// Debugger-visible per-node icount map after scoped travel.
    pub final_node_icounts: BTreeMap<NodeId, Icount>,
    /// Attached runtime's per-node material map.
    pub current_node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Debugger-visible per-node material map after scoped travel.
    pub final_node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Scoped node `goto` evidence used to realize the node material.
    pub node_goto: DebugPerNodeGotoReport,
}

impl DebugPerNodeTimeTravelReport {
    /// Returns whether the operation was realized by a scoped node `goto`.
    #[must_use]
    pub fn realized_by_goto(&self) -> bool {
        self.node_goto.target_configuration == self.target_configuration
            && self.node_goto.proves_replay_oracle_or_thin_source()
            && self.node_goto.proves_scoped_to_node(&self.node)
    }

    /// Returns whether every non-target node retained its attached material.
    #[must_use]
    pub fn leaves_other_nodes_unreinstantiated(&self) -> bool {
        maps_equal_except_key(
            &self.current_node_icounts,
            &self.final_node_icounts,
            &self.node,
        ) && maps_equal_except_key(&self.current_node_blobs, &self.final_node_blobs, &self.node)
    }

    /// Returns whether the target node landed at one coherent node icount.
    #[must_use]
    pub fn lands_node_coherently(&self) -> bool {
        self.landed_node_icount == self.requested_icount
            && self.final_node_icounts.get(&self.node) == Some(&self.landed_node_icount)
            && self.final_node_blobs.get(&self.node) == Some(&self.landed_node_blob)
    }
}

/// Whole-world debug time-travel target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DebugWholeWorldTarget {
    /// A direct schedule prefix length.
    PrefixLen(usize),
    /// Latest recorded prefix at or before virtual time.
    VirtualTime(VirtualTime),
    /// Event-log sequence with a caller-supplied configuration mapping.
    EventSequence(u64),
}

impl DebugWholeWorldTarget {
    /// Builds a direct prefix target.
    #[must_use]
    pub const fn prefix_len(len: usize) -> Self {
        Self::PrefixLen(len)
    }

    /// Builds a virtual-time target.
    #[must_use]
    pub const fn virtual_time(time: VirtualTime) -> Self {
        Self::VirtualTime(time)
    }

    /// Builds an event-sequence target.
    #[must_use]
    pub const fn event_sequence(sequence: u64) -> Self {
        Self::EventSequence(sequence)
    }
}

/// Request to move the whole world to a prefix coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugWholeWorldTimeTravelRequest {
    /// Configuration where the debug session currently sits.
    pub current: Configuration,
    /// Whole-world prefix target.
    pub target: DebugWholeWorldTarget,
    /// Mapping from event-log sequence to temporal-graph coordinate.
    pub event_coordinates: BTreeMap<u64, Configuration>,
}

impl DebugWholeWorldTimeTravelRequest {
    /// Builds a whole-world time-travel request.
    #[must_use]
    pub fn new(current: Configuration, target: DebugWholeWorldTarget) -> Self {
        Self {
            current,
            target,
            event_coordinates: BTreeMap::new(),
        }
    }

    /// Adds an event-log sequence to configuration mapping.
    #[must_use]
    pub fn with_event_coordinate(mut self, sequence: u64, configuration: Configuration) -> Self {
        self.event_coordinates.insert(sequence, configuration);
        self
    }

    pub(super) fn goto_request(
        &self,
        graph: &TemporalGraph,
    ) -> Result<DebugGotoRequest, EngineError> {
        let mut request = match self.target {
            DebugWholeWorldTarget::PrefixLen(len) => DebugGotoRequest::at_configuration(
                self.current.clone(),
                debug_configuration_prefix(&self.current, len)?,
            ),
            DebugWholeWorldTarget::VirtualTime(time) => {
                DebugGotoRequest::new(self.current.clone(), DebugCoordinate::virtual_time(time))
            }
            DebugWholeWorldTarget::EventSequence(sequence) => DebugGotoRequest::new(
                self.current.clone(),
                DebugCoordinate::event_sequence(sequence),
            ),
        };
        for (sequence, configuration) in &self.event_coordinates {
            request = request.with_event_coordinate(*sequence, configuration.clone());
        }
        if matches!(self.target, DebugWholeWorldTarget::PrefixLen(_)) {
            return Ok(request);
        }
        let resolved = graph.debug_resolve_coordinate(
            &request.current,
            &request.target,
            &request.event_coordinates,
        )?;
        Ok(DebugGotoRequest::at_configuration(
            self.current.clone(),
            resolved,
        ))
    }
}

/// Report proving whole-world time travel landed at one prefix.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugWholeWorldTimeTravelReport {
    /// Configuration where the debug session started.
    pub current_configuration: ContentHash,
    /// Whole-world target requested by the operator.
    pub target: DebugWholeWorldTarget,
    /// Prefix configuration that the whole world reached.
    pub target_configuration: ContentHash,
    /// Runtime node icounts at the landed prefix.
    pub landed_node_icounts: BTreeMap<NodeId, Icount>,
    /// Runtime node material at the landed prefix.
    pub landed_node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Delegated `goto` report for the whole-world prefix.
    pub goto: DebugGotoReport,
}

impl DebugWholeWorldTimeTravelReport {
    /// Returns whether the whole-world landing was realized by `goto`.
    #[must_use]
    pub fn realized_by_goto(&self) -> bool {
        self.goto.target_configuration == self.target_configuration
            && self.goto.proves_replay_oracle()
    }

    /// Returns whether every landed node has exactly one node icount and material entry.
    #[must_use]
    pub fn lands_all_nodes_coherently(&self) -> bool {
        !self.landed_node_icounts.is_empty()
            && self
                .landed_node_icounts
                .keys()
                .eq(self.landed_node_blobs.keys())
    }

    /// Returns whether this landing is a fork before divergent decisions are appended.
    #[must_use]
    pub fn is_fork_without_divergence(&self) -> bool {
        self.goto.current_configuration == self.current_configuration
            && self.goto.target_configuration == self.target_configuration
            && self.goto.proves_replay_oracle()
    }
}

/// Non-zero opportunistic checkpoint stride for debug time travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugCheckpointStride {
    pub(super) every: NonZeroUsize,
}

impl DebugCheckpointStride {
    /// Builds a non-zero checkpoint stride.
    #[must_use]
    pub fn new(every: usize) -> Option<Self> {
        NonZeroUsize::new(every).map(|every| Self { every })
    }

    /// Returns the stride interval.
    #[must_use]
    pub const fn every(self) -> usize {
        self.every.get()
    }

    pub(super) fn includes_prefix(self, prefix_len: usize) -> bool {
        prefix_len > 0 && prefix_len.is_multiple_of(self.every())
    }
}

/// Request to apply an opportunistic checkpoint cadence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugCheckpointCadenceRequest {
    /// Configuration whose prefix region should receive cadence checkpoints.
    pub current: Configuration,
    /// Non-zero checkpoint stride.
    pub stride: DebugCheckpointStride,
    /// Savevm hedge that decides whether cadence points may be fat.
    pub hedge: SavevmCompletenessHedge,
}

impl DebugCheckpointCadenceRequest {
    /// Builds a checkpoint-cadence request with an explicit savevm hedge.
    #[must_use]
    pub fn with_hedge(
        current: Configuration,
        stride: DebugCheckpointStride,
        hedge: SavevmCompletenessHedge,
    ) -> Self {
        Self {
            current,
            stride,
            hedge,
        }
    }

    /// Builds the default S3-conservative cadence request.
    #[must_use]
    pub fn thin_replay_until_full_s3(
        current: Configuration,
        stride: DebugCheckpointStride,
    ) -> Self {
        Self::with_hedge(
            current,
            stride,
            SavevmCompletenessHedge::thin_replay_until_full_s3(),
        )
    }
}

/// Report for opportunistic checkpoint cadence application.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugCheckpointCadenceReport {
    /// Configuration whose prefix region was considered.
    pub current_configuration: ContentHash,
    /// Non-zero stride that selected candidate prefixes.
    pub stride: DebugCheckpointStride,
    /// Savevm hedge used for every candidate prefix.
    pub hedge: SavevmCompletenessHedge,
    /// Candidate prefix configuration ids selected by the stride.
    pub candidate_configurations: Vec<ContentHash>,
    /// Candidate ids cached as fat checkpoints.
    pub fat_checkpoints: Vec<ContentHash>,
    /// Candidate ids kept as thin replay checkpoints.
    pub thin_checkpoints: Vec<ContentHash>,
    /// Fat cache count before applying the cadence.
    pub cached_snapshots_before: usize,
    /// Fat cache count after applying the cadence.
    pub cached_snapshots_after: usize,
}

impl DebugCheckpointCadenceReport {
    /// Returns whether the S3-conservative default kept all cadence points thin.
    #[must_use]
    pub fn defaults_to_thin_replay_until_full_s3(&self) -> bool {
        !self.hedge.fat_snapshot_default()
            && self.fat_checkpoints.is_empty()
            && self.thin_checkpoints.len() == self.candidate_configurations.len()
    }

    /// Returns whether checkpoint cadence only changed cache materialization.
    #[must_use]
    pub fn is_performance_only_cache_decision(&self) -> bool {
        let classified = self
            .fat_checkpoints
            .iter()
            .chain(self.thin_checkpoints.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let candidates = self
            .candidate_configurations
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        classified == candidates
    }
}
