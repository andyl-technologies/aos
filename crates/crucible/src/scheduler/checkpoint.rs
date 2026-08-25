//! Canonical, process-independent continuation for [`SingleScheduler`].

use serde::{Deserialize, Serialize};

use super::*;

const MAGIC: &[u8] = b"crucible.single-scheduler-continuation.v2\0";
/// Maximum canonical byte length of one complete single-scheduler continuation.
pub const MAX_SINGLE_SCHEDULER_CHECKPOINT_BYTES: usize =
    MAX_SINGLE_SCHEDULER_CHECKPOINT_PAYLOAD_BYTES + MAGIC.len();
const MAX_SINGLE_SCHEDULER_CHECKPOINT_PAYLOAD_BYTES: usize = 1_610_612_736;

/// Complete mutable continuation of one admitted scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleSchedulerCheckpoint {
    wire: SingleSchedulerWire,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleSchedulerWire {
    scenario: ContentHash,
    schedule: Vec<u8>,
    quantum_budget: u64,
    time_limit: u64,
    branch_frontier_cap: Option<u64>,
    rendezvous_interval: Option<u64>,
    nodes: Vec<RuntimeNodeWire>,
    scheduler_state: Vec<u8>,
    network_state: Vec<u8>,
    device_state: Vec<(String, Vec<Vec<u8>>)>,
    pending_events: Vec<ScheduledEvent>,
    run_subdivision_policies: Vec<SchedulerRunSubdivisionPolicy>,
    run_subdivision_records: Vec<SchedulerRunSubdivisionRecord>,
    preemption_requests: Vec<PreemptionDecision>,
    preemption_applications: Vec<SchedulerPreemptionApplication>,
    control_admissions: Vec<SchedulerControlAdmission>,
    control_applications: Vec<SchedulerControlApplication>,
    control_inbox: Vec<ControlOperation>,
    decision_seed: [u8; 32],
    decision_rng_cursor: DecisionRngState,
    branch_network_choices: Vec<OverrideDecision>,
    search_frontiers: Vec<SearchRuntimeFrontierWire>,
    event_log: EventLogWire,
    trigger_actions: TriggerActionState,
    frontier: u64,
    quanta: u64,
    topology_change_applications: Vec<SchedulerTopologyChangeApplication>,
    rendezvous_records: Vec<SchedulerRendezvousRecord>,
    boundary_yields: u64,
    ceiling_publications: Vec<SchedulerRunCeilingPublication>,
    last_advance: Option<NodeAdvance>,
    last_topology_recompute: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeNodeWire {
    id: SchedulerNodeId,
    counter: u64,
    time_mapping: NodeTimeMapping,
    last_checkpoint: Option<SchedulerNodeCheckpoint>,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
    vcpu_idle_states: Vec<SchedulerVcpuIdleState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventLogWire {
    prefix: ContentHash,
    appended_segment: Option<ContentHash>,
    segment_dependencies: Vec<ContentHash>,
    bytes: u64,
    events: u64,
    condition_entries: Vec<SchedulerEventLogEntry>,
    condition_base_events: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRuntimeFrontierWire {
    scenario: ContentHash,
    schedule: Vec<u8>,
    at: u64,
    choices: Vec<Vec<u8>>,
}

impl SingleScheduler {
    /// Captures every mutable field that can affect future scheduler behavior or evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError`] if a device or network owner
    /// cannot encode its independently validated continuation.
    pub fn checkpoint(&self) -> Result<SingleSchedulerCheckpoint, SingleSchedulerCheckpointError> {
        if self.lock_held || !self.app_random_branch_selections.is_empty() {
            return Err(SingleSchedulerCheckpointError::Transient);
        }
        let device_state = self
            .device_sub_nodes
            .iter()
            .map(|(node, devices)| {
                let devices = devices
                    .iter()
                    .map(|device| device.checkpoint().canonical_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SingleSchedulerCheckpointError::Device)?;
                Ok((node.name.clone(), devices))
            })
            .collect::<Result<Vec<_>, SingleSchedulerCheckpointError>>()?;
        let network_state = self
            .network_checkpoint()
            .canonical_bytes()
            .map_err(|_| SingleSchedulerCheckpointError::Network)?;
        Ok(SingleSchedulerCheckpoint {
            wire: SingleSchedulerWire {
                scenario: self.configuration.def.id(),
                schedule: self.configuration.schedule.to_compact_binary(),
                quantum_budget: self.quantum_budget,
                time_limit: self.time_limit.nanos,
                branch_frontier_cap: self.branch_frontier_cap.map(|cap| cap.nanos),
                rendezvous_interval: self.rendezvous.interval().map(|value| value.nanos),
                nodes: self.nodes.iter().map(RuntimeNodeWire::from).collect(),
                scheduler_state: self.materialized_scheduler_state().to_compact_binary(),
                network_state,
                device_state,
                pending_events: self.pending_events.clone(),
                run_subdivision_policies: self.run_subdivision_policies.clone(),
                run_subdivision_records: self.run_subdivision_records.clone(),
                preemption_requests: self.preemption_requests.clone(),
                preemption_applications: self.preemption_applications.clone(),
                control_admissions: self.control_admissions.clone(),
                control_applications: self.control_applications.clone(),
                control_inbox: self.control_inbox.clone(),
                decision_seed: self.decision_seed.bytes(),
                decision_rng_cursor: self.decision_rng_cursor.clone(),
                branch_network_choices: self.branch_network_choices.clone(),
                search_frontiers: self
                    .search_frontiers
                    .iter()
                    .map(SearchRuntimeFrontierWire::from)
                    .collect(),
                event_log: EventLogWire::from(&self.event_log),
                trigger_actions: self.trigger_actions.clone(),
                frontier: self.frontier.ticks,
                quanta: self.quanta,
                topology_change_applications: self.topology_change_applications.clone(),
                rendezvous_records: self.rendezvous_records.clone(),
                boundary_yields: self.boundary_yields,
                ceiling_publications: self.ceiling_publications.clone(),
                last_advance: self.last_advance.clone(),
                last_topology_recompute: self.last_topology_recompute,
            },
        })
    }

    /// Reads and authenticates every event-log segment required by the current prefix.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError::EventLog`] when a retained
    /// segment is missing or its bytes no longer match its content identity.
    pub fn event_log_dependency_objects(
        &self,
    ) -> Result<Vec<(ContentHash, Vec<u8>)>, SingleSchedulerCheckpointError> {
        self.event_log
            .segment_dependencies
            .iter()
            .map(|identity| {
                let bytes = self
                    .event_log
                    .segment_store
                    .store
                    .get(identity)
                    .map_err(|_| SingleSchedulerCheckpointError::EventLog)?;
                if ContentHash::from_bytes(&bytes) != *identity {
                    return Err(SingleSchedulerCheckpointError::EventLog);
                }
                Ok((*identity, bytes))
            })
            .collect()
    }
}

impl From<&RuntimeSchedulerNode> for RuntimeNodeWire {
    fn from(node: &RuntimeSchedulerNode) -> Self {
        Self {
            id: node.id.clone(),
            counter: node.counter.ticks,
            time_mapping: node.time_mapping,
            last_checkpoint: node.last_checkpoint.clone(),
            activity: node.activity,
            network_lookahead: node.network_lookahead,
            exact_local_event: node.exact_local_event.clone(),
            vcpu_idle_states: node.vcpu_idle_states.clone(),
        }
    }
}

impl From<&EventLog> for EventLogWire {
    fn from(log: &EventLog) -> Self {
        Self {
            prefix: log.offset.prefix,
            appended_segment: log.offset.appended_segment,
            segment_dependencies: log.segment_dependencies.clone(),
            bytes: log.offset.bytes,
            events: log.offset.events,
            condition_entries: log.condition_entries.clone(),
            condition_base_events: log.condition_base_events,
        }
    }
}

impl From<&SearchRuntimeFrontier> for SearchRuntimeFrontierWire {
    fn from(frontier: &SearchRuntimeFrontier) -> Self {
        Self {
            scenario: frontier.configuration.def.id(),
            schedule: frontier.configuration.schedule.to_compact_binary(),
            at: frontier.at.ticks,
            choices: frontier
                .choices
                .choices()
                .iter()
                .map(|choice| {
                    Schedule::from_decisions(choice.decisions().to_vec()).to_compact_binary()
                })
                .collect(),
        }
    }
}

impl SingleSchedulerCheckpoint {
    /// Returns the immutable scenario identity owning this continuation.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.wire.scenario
    }

    /// Reconstructs the checkpoint configuration against an authenticated scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError::Configuration`] when `scenario`
    /// has another identity or the recorded schedule is malformed.
    pub fn configuration_for(
        &self,
        scenario: &ScenarioDef,
    ) -> Result<Configuration, SingleSchedulerCheckpointError> {
        if self.wire.scenario != scenario.id() || self.future_decision_seed() != scenario.seed() {
            return Err(SingleSchedulerCheckpointError::Configuration);
        }
        let schedule = Schedule::from_compact_binary(&self.wire.schedule)
            .map_err(|_| SingleSchedulerCheckpointError::Configuration)?;
        Ok(Configuration {
            def: scenario.clone(),
            schedule,
        })
    }

    /// Returns the exact restored scheduler frontier.
    #[must_use]
    pub const fn frontier(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.wire.frontier,
        }
    }

    /// Returns the scheduler-state projection retained at this boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError::State`] if the internally
    /// retained scheduler projection is malformed. Canonically decoded and
    /// locally captured checkpoints have already passed this validation.
    pub fn scheduler_state(&self) -> Result<SchedulerState, SingleSchedulerCheckpointError> {
        SchedulerState::from_compact_binary(&self.wire.scheduler_state)
            .map_err(|_| SingleSchedulerCheckpointError::State)
    }

    /// Returns the exact unified event-log boundary retained by this continuation.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        EventLogOffset {
            prefix: self.wire.event_log.prefix,
            appended_segment: self.wire.event_log.appended_segment,
            bytes: self.wire.event_log.bytes,
            events: self.wire.event_log.events,
        }
    }

    /// Returns the active branch frontier cap, if branch admission is pending.
    #[must_use]
    pub const fn branch_frontier_cap(&self) -> Option<VirtualTime> {
        match self.wire.branch_frontier_cap {
            Some(ticks) => Some(VirtualTime { ticks }),
            None => None,
        }
    }

    /// Returns the seed owning all future scheduler decision streams.
    #[must_use]
    pub fn future_decision_seed(&self) -> Seed {
        Seed::from_bytes(self.wire.decision_seed)
    }

    /// Returns the future decision-stream cursor map.
    #[must_use]
    pub const fn future_decision_rng_state(&self) -> &DecisionRngState {
        &self.wire.decision_rng_cursor
    }

    /// Returns the ordered event-log segment identities retained by this continuation.
    #[must_use]
    pub fn event_log_segment_dependencies(&self) -> &[ContentHash] {
        &self.wire.event_log.segment_dependencies
    }

    /// Returns the exact event entries retained for condition and evidence replay.
    ///
    /// A scheduler created at run genesis retains a zero-based complete prefix.
    /// A continuation reconstructed from an offset-only source may instead
    /// retain a suffix whose first sequence is reported by
    /// [`Self::retained_event_log_base_events`]. Callers that require complete
    /// run evidence must reject a nonzero base or load the authenticated prior
    /// segment closure before interpreting this slice as the whole run.
    #[must_use]
    pub fn retained_event_log_entries(&self) -> &[SchedulerEventLogEntry] {
        &self.wire.event_log.condition_entries
    }

    /// Returns the dense sequence preceding the retained event-entry suffix.
    ///
    /// Zero means [`Self::retained_event_log_entries`] starts at run genesis.
    #[must_use]
    pub const fn retained_event_log_base_events(&self) -> u64 {
        self.wire.event_log.condition_base_events
    }

    /// Encodes the complete scheduler continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError`] if serialization fails or the
    /// checkpoint exceeds the compiled byte ceiling.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SingleSchedulerCheckpointError> {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&self.wire, &mut payload)
            .map_err(|_| SingleSchedulerCheckpointError::Malformed)?;
        if payload.len() > MAX_SINGLE_SCHEDULER_CHECKPOINT_PAYLOAD_BYTES {
            return Err(SingleSchedulerCheckpointError::Limit);
        }
        let mut bytes = Vec::with_capacity(MAGIC.len() + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes a byte-canonical scheduler continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError`] for unsupported, malformed,
    /// over-limit, nested-invalid, or noncanonical state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SingleSchedulerCheckpointError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(SingleSchedulerCheckpointError::Version)?;
        if payload.len() > MAX_SINGLE_SCHEDULER_CHECKPOINT_PAYLOAD_BYTES {
            return Err(SingleSchedulerCheckpointError::Limit);
        }
        let wire: SingleSchedulerWire = ciborium::de::from_reader(payload)
            .map_err(|_| SingleSchedulerCheckpointError::Malformed)?;
        Schedule::from_compact_binary(&wire.schedule)
            .map_err(|_| SingleSchedulerCheckpointError::Configuration)?;
        SchedulerState::from_compact_binary(&wire.scheduler_state)
            .map_err(|_| SingleSchedulerCheckpointError::State)?;
        SchedulerNetworkCheckpoint::from_canonical_bytes(&wire.network_state)
            .map_err(|_| SingleSchedulerCheckpointError::Network)?;
        for (_, devices) in &wire.device_state {
            for device in devices {
                crate::DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(device)
                    .map_err(|_| SingleSchedulerCheckpointError::Device)?;
            }
        }
        validate_wire(&wire)?;
        let checkpoint = Self { wire };
        if checkpoint.canonical_bytes()?.as_slice() != bytes {
            return Err(SingleSchedulerCheckpointError::Noncanonical);
        }
        Ok(checkpoint)
    }

    /// Restores this continuation into a freshly admitted scheduler atomically.
    ///
    /// The destination supplies immutable World artifacts, topology, and any
    /// event-log segment store. The checkpoint must name exactly the same
    /// scenario, scheduler nodes, network links, and I/O sub-nodes.
    ///
    /// # Errors
    ///
    /// Returns [`SingleSchedulerCheckpointError`] if any identity, nested state,
    /// event-log prefix, or cross-owner projection is inconsistent.
    pub fn restore_into(
        &self,
        scheduler: &mut SingleScheduler,
    ) -> Result<(), SingleSchedulerCheckpointError> {
        validate_wire(&self.wire)?;
        if scheduler.configuration.def.id() != self.wire.scenario {
            return Err(SingleSchedulerCheckpointError::Configuration);
        }
        let schedule = Schedule::from_compact_binary(&self.wire.schedule)
            .map_err(|_| SingleSchedulerCheckpointError::Configuration)?;
        let configuration = Configuration {
            def: scheduler.configuration.def.clone(),
            schedule,
        };
        let state = SchedulerState::from_compact_binary(&self.wire.scheduler_state)
            .map_err(|_| SingleSchedulerCheckpointError::State)?;
        let network = SchedulerNetworkCheckpoint::from_canonical_bytes(&self.wire.network_state)
            .map_err(|_| SingleSchedulerCheckpointError::Network)?;

        let mut staged = scheduler.clone();
        restore_devices(&mut staged, &self.wire.device_state)?;
        staged
            .restore_network_checkpoint(&network)
            .map_err(|_| SingleSchedulerCheckpointError::Network)?;
        restore_nodes(&mut staged, &self.wire.nodes)?;
        restore_event_log(&mut staged.event_log, &self.wire.event_log)?;
        let search_frontiers =
            restore_search_frontiers(&configuration.def, &self.wire.search_frontiers)?;

        staged.configuration = configuration;
        staged.quantum_budget = self.wire.quantum_budget;
        staged.time_limit = SimInstant {
            nanos: self.wire.time_limit,
        };
        staged.branch_frontier_cap = self
            .wire
            .branch_frontier_cap
            .map(|nanos| SimInstant { nanos });
        staged.rendezvous = match self.wire.rendezvous_interval {
            Some(nanos) => SchedulerRendezvous::every(SimDuration { nanos })
                .map_err(|_| SingleSchedulerCheckpointError::State)?,
            None => SchedulerRendezvous::disabled(),
        };
        staged.effective_topology =
            SchedulerLookaheadGraph::from_edges(state.effective_topology_edges.clone());
        staged.topology_changes = state.pending_topology_changes;
        staged.run_subdivision_policies = self.wire.run_subdivision_policies.clone();
        staged.run_subdivision_records = self.wire.run_subdivision_records.clone();
        staged.preemption_requests = self.wire.preemption_requests.clone();
        staged.preemption_applications = self.wire.preemption_applications.clone();
        staged.control_admissions = self.wire.control_admissions.clone();
        staged.control_applications = self.wire.control_applications.clone();
        staged.pending_events = self.wire.pending_events.clone();
        staged.event_sequences = state.event_sequences;
        staged.world_network_decisions = state.pending_device_decisions;
        staged.device_horizons = state
            .horizons
            .into_iter()
            .map(|(node, time)| (node, SimInstant { nanos: time.ticks }))
            .collect();
        staged.control_inbox = self.wire.control_inbox.clone();
        staged.decision_seed = Seed::from_bytes(self.wire.decision_seed);
        staged.decision_rng_cursor = self.wire.decision_rng_cursor.clone();
        staged.branch_network_choices = self.wire.branch_network_choices.clone();
        staged.app_random_branch_selections.clear();
        staged.search_frontiers = search_frontiers;
        staged.trigger_actions = self.wire.trigger_actions.clone();
        staged.frontier = VirtualTime {
            ticks: self.wire.frontier,
        };
        staged.quanta = self.wire.quanta;
        staged.topology_epoch = state.topology_epoch;
        staged.topology_change_applications = self.wire.topology_change_applications.clone();
        staged.rendezvous_records = self.wire.rendezvous_records.clone();
        staged.boundary_yields = self.wire.boundary_yields;
        staged.ceiling_publications = self.wire.ceiling_publications.clone();
        staged.lock_held = false;
        staged.last_advance = self.wire.last_advance.clone();
        staged.last_topology_recompute = self.wire.last_topology_recompute;

        let projected = staged.materialized_scheduler_state();
        if projected
            != SchedulerState::from_compact_binary(&self.wire.scheduler_state)
                .map_err(|_| SingleSchedulerCheckpointError::State)?
        {
            return Err(SingleSchedulerCheckpointError::State);
        }
        *scheduler = staged;
        Ok(())
    }
}

fn validate_wire(wire: &SingleSchedulerWire) -> Result<(), SingleSchedulerCheckpointError> {
    if wire.quantum_budget == 0
        || wire.nodes.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || wire
            .device_state
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
        || wire
            .pending_events
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
    {
        return Err(SingleSchedulerCheckpointError::State);
    }
    if wire.event_log.events < wire.event_log.condition_base_events {
        return Err(SingleSchedulerCheckpointError::EventLog);
    }
    let condition_entry_count =
        usize::try_from(wire.event_log.events - wire.event_log.condition_base_events)
            .map_err(|_| SingleSchedulerCheckpointError::EventLog)?;
    if condition_entry_count != wire.event_log.condition_entries.len() {
        return Err(SingleSchedulerCheckpointError::EventLog);
    }
    for frontier in &wire.search_frontiers {
        Schedule::from_compact_binary(&frontier.schedule)
            .map_err(|_| SingleSchedulerCheckpointError::State)?;
        for choice in &frontier.choices {
            Schedule::from_compact_binary(choice)
                .map_err(|_| SingleSchedulerCheckpointError::State)?;
        }
    }
    Ok(())
}

fn restore_devices(
    scheduler: &mut SingleScheduler,
    checkpoint: &[(String, Vec<Vec<u8>>)],
) -> Result<(), SingleSchedulerCheckpointError> {
    if scheduler.device_sub_nodes.len() != checkpoint.len() {
        return Err(SingleSchedulerCheckpointError::Device);
    }
    for ((node, devices), (checkpoint_node, checkpoints)) in
        scheduler.device_sub_nodes.iter_mut().zip(checkpoint)
    {
        if node.name != *checkpoint_node || devices.len() != checkpoints.len() {
            return Err(SingleSchedulerCheckpointError::Device);
        }
        for (device, encoded) in devices.iter_mut().zip(checkpoints) {
            let checkpoint =
                crate::DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(encoded)
                    .map_err(|_| SingleSchedulerCheckpointError::Device)?;
            device
                .restore_checkpoint(&checkpoint)
                .map_err(|_| SingleSchedulerCheckpointError::Device)?;
        }
    }
    Ok(())
}

fn restore_nodes(
    scheduler: &mut SingleScheduler,
    checkpoint: &[RuntimeNodeWire],
) -> Result<(), SingleSchedulerCheckpointError> {
    if scheduler.nodes.len() != checkpoint.len() {
        return Err(SingleSchedulerCheckpointError::Node);
    }
    for (node, restored) in scheduler.nodes.iter_mut().zip(checkpoint) {
        if node.id != restored.id {
            return Err(SingleSchedulerCheckpointError::Node);
        }
        node.counter = NodeCounter {
            ticks: restored.counter,
        };
        node.time_mapping = restored.time_mapping;
        node.last_checkpoint = restored.last_checkpoint.clone();
        node.activity = restored.activity;
        node.network_lookahead = restored.network_lookahead;
        node.exact_local_event = restored.exact_local_event.clone();
        node.vcpu_idle_states = restored.vcpu_idle_states.clone();
    }
    Ok(())
}

fn restore_event_log(
    log: &mut EventLog,
    checkpoint: &EventLogWire,
) -> Result<(), SingleSchedulerCheckpointError> {
    let offset = EventLogOffset {
        prefix: checkpoint.prefix,
        appended_segment: checkpoint.appended_segment,
        bytes: checkpoint.bytes,
        events: checkpoint.events,
    };
    if checkpoint.appended_segment != checkpoint.segment_dependencies.last().copied()
        && !(checkpoint.appended_segment.is_none() && checkpoint.segment_dependencies.is_empty())
    {
        return Err(SingleSchedulerCheckpointError::EventLog);
    }
    let condition_prefix = if checkpoint.condition_entries.is_empty() {
        ConditionEventLogPrefix::genesis().with_event_log_offset(offset)
    } else {
        ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base_sequence(
            checkpoint.condition_entries.clone(),
            checkpoint.condition_base_events,
        )
        .map_err(|_| SingleSchedulerCheckpointError::EventLog)?
        .with_event_log_offset(offset)
    };
    log.prefix = scheduler_event_log_prefix_for_resume(offset);
    log.segment_dependencies = checkpoint.segment_dependencies.clone();
    log.offset = offset;
    log.bytes = offset.bytes;
    log.events = offset.events;
    log.condition_entries = checkpoint.condition_entries.clone();
    log.condition_base_events = checkpoint.condition_base_events;
    log.condition_prefix = condition_prefix;
    Ok(())
}

fn restore_search_frontiers(
    scenario: &ScenarioDef,
    checkpoints: &[SearchRuntimeFrontierWire],
) -> Result<Vec<SearchRuntimeFrontier>, SingleSchedulerCheckpointError> {
    checkpoints
        .iter()
        .map(|checkpoint| {
            if checkpoint.scenario != scenario.id() {
                return Err(SingleSchedulerCheckpointError::Configuration);
            }
            let schedule = Schedule::from_compact_binary(&checkpoint.schedule)
                .map_err(|_| SingleSchedulerCheckpointError::State)?;
            let choices = checkpoint
                .choices
                .iter()
                .map(|bytes| {
                    Schedule::from_compact_binary(bytes)
                        .map(|schedule| schedule.decisions().to_vec())
                        .map_err(|_| SingleSchedulerCheckpointError::State)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SearchRuntimeFrontier {
                configuration: Configuration {
                    def: scenario.clone(),
                    schedule,
                },
                at: VirtualTime {
                    ticks: checkpoint.at,
                },
                choices: SearchFrontierChoices::from_decision_sequences(choices),
            })
        })
        .collect()
}

/// Failure to encode, decode, validate, or restore an exact scheduler continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SingleSchedulerCheckpointError {
    /// The envelope version is unsupported.
    #[error("unsupported single-scheduler checkpoint version")]
    Version,
    /// The envelope or a primitive field is malformed.
    #[error("malformed single-scheduler checkpoint")]
    Malformed,
    /// The configuration is malformed or invalid.
    #[error("invalid scheduler checkpoint configuration")]
    Configuration,
    /// The materialized scheduler projection is invalid.
    #[error("invalid scheduler checkpoint state projection")]
    State,
    /// A network continuation is invalid.
    #[error("invalid scheduler network continuation")]
    Network,
    /// An I/O sub-node continuation is invalid.
    #[error("invalid scheduler device continuation")]
    Device,
    /// The checkpoint's scheduler-node set or node-local state is invalid.
    #[error("invalid scheduler node continuation")]
    Node,
    /// The checkpoint's retained event-log state is invalid.
    #[error("invalid scheduler event-log continuation")]
    EventLog,
    /// Capture was attempted while the scheduler held its internal quantum lock.
    #[error("cannot checkpoint a scheduler during a transient quantum phase")]
    Transient,
    /// The checkpoint exceeds its compiled byte ceiling.
    #[error("single-scheduler checkpoint exceeds its size limit")]
    Limit,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical single-scheduler checkpoint")]
    Noncanonical,
}
