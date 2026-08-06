//! Liveness scenario identity and canonical scheduler material.

use super::*;
/// One generated node consumed by the scheduler liveness gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerScenarioNode {
    /// The scheduler graph node to advance.
    pub id: SchedulerNodeId,
    /// The node-local counter at the start of the run.
    pub counter: NodeCounter,
    /// The node's effective scheduling state at the start of the run.
    pub activity: SchedulerNodeActivity,
    /// The conservative cross-node lookahead for this node.
    pub network_lookahead: NetworkLookahead,
    /// The exact local timer, I/O completion, fault, or idle report for this node.
    pub exact_local_event: ExactLocalEvent,
}

/// The generated liveness activity state for one scheduler node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerNodeActivity {
    /// The node has work and may be selected by PICK.
    Runnable,
    /// The node is idle, has no local timer or I/O work, and cannot advance.
    Idle,
    /// The node is halted and contributes an infinite effective horizon.
    Halted,
    /// The node is complete and is never selected by PICK.
    Done,
}

/// A finite scheduler scenario for checking quantum-loop liveness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerLivenessScenario {
    /// Author-supplied scenario material that names this generated scenario.
    pub authored_material: String,
    /// Canonical logical World identity installed by [`Self::with_world`].
    pub world_ref: Option<ContentHash>,
    /// The configuration whose schedule records scheduler decisions.
    pub configuration: Configuration,
    /// The fixed icount-to-virtual-time shift for every node in the scenario.
    pub shift: Shift,
    /// The maximum number of quanta allowed before the scenario time-limits.
    pub quantum_budget: u64,
    /// The virtual-time limit that also terminates the scenario.
    pub time_limit: SimInstant,
    /// The exact shared rendezvous cap policy.
    pub rendezvous: SchedulerRendezvous,
    /// The current effective scheduler edge set, when known to this scenario.
    pub effective_topology: SchedulerLookaheadGraph,
    /// The generated nodes driven by the authoritative scheduler.
    ///
    /// A runnable generated node becomes [`SchedulerNodeActivity::Idle`] once it
    /// reaches the horizon selected from its exact local event and network
    /// lookahead.
    pub nodes: Vec<SchedulerScenarioNode>,
    /// Baked ready-point counters that differ from the default zero boundary.
    ///
    /// Production backends use this runtime-only projection when boot-barrier
    /// priming retires instructions before the scheduler admits a VM.
    pub(super) ready_point_counters: BTreeMap<SchedulerNodeId, NodeCounter>,
    /// Boundary-applied topology changes waiting for the scheduler.
    pub topology_changes: Vec<SchedulerTopologyChange>,
    /// Optional deterministic RR subdivision policies keyed by scheduler node.
    pub run_subdivision_policies: Vec<SchedulerRunSubdivisionPolicy>,
    /// Explorer-supplied preemption decisions waiting for the owning node RUN.
    pub preemption_requests: Vec<PreemptionDecision>,
    /// Per-vCPU idle snapshots keyed by scheduler VM node.
    pub vcpu_idle_snapshots: Vec<SchedulerNodeVcpuIdleSnapshot>,
    /// Cross-node, I/O, fault, and control events waiting for scheduler delivery.
    pub pending_events: Vec<ScheduledEvent>,
    /// Saved per-producer/consumer sequence counters for newly emitted events.
    pub event_sequences: EventSequenceState,
    /// Static world products used to validate trigger node scheduling actions.
    pub trigger_static_topology: Option<WorldStaticTopology>,
    /// Submitted scenario identity retained at a production lifecycle boundary.
    bound_scenario_def: Option<ScenarioDef>,
}

impl SchedulerLivenessScenario {
    /// Builds a scheduler scenario with a deterministic synthetic configuration.
    #[must_use]
    pub fn from_canonical_material(
        material: &str,
        shift: Shift,
        quantum_budget: u64,
        time_limit: SimInstant,
        nodes: Vec<SchedulerScenarioNode>,
        pending_events: Vec<ScheduledEvent>,
    ) -> Self {
        let mut scenario = Self {
            authored_material: material.to_owned(),
            world_ref: None,
            configuration: Configuration::genesis(ScenarioDef::from_canonical_material_with_seed(
                "crucible.scheduler-liveness.authored",
                material,
                crate::Seed::default(),
            )),
            shift,
            quantum_budget,
            time_limit,
            rendezvous: SchedulerRendezvous::disabled(),
            effective_topology: SchedulerLookaheadGraph::default(),
            nodes,
            topology_changes: Vec::new(),
            run_subdivision_policies: Vec::new(),
            preemption_requests: Vec::new(),
            vcpu_idle_snapshots: Vec::new(),
            pending_events,
            event_sequences: EventSequenceState::empty(),
            trigger_static_topology: None,
            ready_point_counters: BTreeMap::new(),
            bound_scenario_def: None,
        };
        scenario.refresh_configuration();
        scenario
    }

    /// Builds the effective scheduler configuration from scenario-owned state.
    #[must_use]
    pub fn canonical_configuration(&self) -> Configuration {
        if let Some(scenario) = &self.bound_scenario_def {
            return Configuration {
                def: scenario.clone(),
                schedule: self.configuration.schedule.clone(),
            };
        }
        Configuration {
            def: ScenarioDef::from_canonical_material_with_seed(
                "crucible.scheduler-liveness.scenario.v1",
                &scheduler_liveness_scenario_material(self),
                self.configuration.def.seed(),
            ),
            schedule: self.configuration.schedule.clone(),
        }
    }

    /// Sets the world-derived static topology used to validate trigger actions.
    #[must_use]
    pub fn with_trigger_world(mut self, world: &World) -> Self {
        self.trigger_static_topology = Some(world.static_topology());
        self.refresh_configuration();
        self
    }

    /// Applies the complete production scheduler projection of `world`.
    ///
    /// Unlike [`SchedulerLivenessScenario::with_trigger_world`], this also
    /// installs the World's conservative network lookahead graph. Concrete
    /// block/9p devices are resolved by [`SingleScheduler::from_world`].
    #[must_use]
    pub fn with_world(mut self, world: &World) -> Self {
        let topology = world.static_topology();
        self.world_ref = Some(world.id());
        self.effective_topology =
            SchedulerLookaheadGraph::from_world_edges(&topology.lookahead_graph);
        recompute_scenario_node_lookahead(&mut self.nodes, &self.effective_topology);
        self.trigger_static_topology = Some(topology);
        self.refresh_configuration();
        self
    }

    /// Records the baked counter restored by ready-point node restarts.
    ///
    /// Scenarios default to counter zero. Live backends call this after
    /// admitting a VM at a nonzero boot-barrier boundary.
    #[must_use]
    pub fn with_ready_point_counter(mut self, node: SchedulerNodeId, counter: NodeCounter) -> Self {
        self.ready_point_counters.insert(node, counter);
        self.refresh_configuration();
        self
    }

    /// Enables fixed-interval rendezvous caps for this scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `interval` is zero.
    pub fn with_rendezvous_interval(
        mut self,
        interval: SimDuration,
    ) -> Result<Self, SchedulerError> {
        self.rendezvous = SchedulerRendezvous::every(interval)?;
        self.refresh_configuration();
        Ok(self)
    }

    /// Replaces the scenario's effective topology and recomputes node lookahead.
    #[must_use]
    pub fn with_effective_topology_edges(mut self, edges: Vec<SchedulerLookaheadEdge>) -> Self {
        self.effective_topology = SchedulerLookaheadGraph::from_edges(edges);
        recompute_scenario_node_lookahead(&mut self.nodes, &self.effective_topology);
        self.refresh_configuration();
        self
    }

    /// Queues a topology change for the next quantum boundary.
    #[must_use]
    pub fn with_topology_change(mut self, change: SchedulerTopologyChange) -> Self {
        self.topology_changes.push(change);
        self.topology_changes.sort_by(topology_change_order);
        self.refresh_configuration();
        self
    }

    /// Sets the deterministic RR subdivision policy for one scheduler node.
    #[must_use]
    pub fn with_run_subdivision_policy(mut self, policy: SchedulerRunSubdivisionPolicy) -> Self {
        self.run_subdivision_policies
            .retain(|existing| existing.node != policy.node);
        self.run_subdivision_policies.push(policy);
        self.run_subdivision_policies.sort();
        self.refresh_configuration();
        self
    }

    /// Adds an explorer-supplied preemption request to the scheduler queue.
    #[must_use]
    pub fn with_preemption_request(mut self, decision: PreemptionDecision) -> Self {
        self.preemption_requests.push(decision);
        self.preemption_requests.sort_by(preemption_decision_order);
        self.refresh_configuration();
        self
    }

    /// Sets per-vCPU idle evidence for one scheduler VM node.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the snapshot is
    /// internally invalid.
    pub fn with_vcpu_idle_snapshot(
        mut self,
        mut snapshot: SchedulerNodeVcpuIdleSnapshot,
    ) -> Result<Self, SchedulerError> {
        validate_vcpu_idle_snapshot(&snapshot.node, snapshot.vcpu_count, &mut snapshot.vcpus)?;
        self.vcpu_idle_snapshots
            .retain(|existing| existing.node != snapshot.node);
        self.vcpu_idle_snapshots.push(snapshot);
        self.vcpu_idle_snapshots.sort();
        self.refresh_configuration();
        Ok(self)
    }

    fn refresh_configuration(&mut self) {
        self.configuration = self.canonical_configuration();
    }
}

pub(super) fn scheduler_liveness_scenario_material(scenario: &SchedulerLivenessScenario) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "authored_material_len={}",
        scenario.authored_material.len()
    ));
    lines.push(format!("authored_material={}", scenario.authored_material));
    match scenario.world_ref {
        Some(world) => lines.push(format!("world_ref=blake3:{}", world.to_hex())),
        None => lines.push(String::from("world_ref=absent")),
    }
    lines.push(format!("shift_bits={}", scenario.shift.bits));
    lines.push(format!("quantum_budget={}", scenario.quantum_budget));
    lines.push(format!("time_limit_ns={}", scenario.time_limit.nanos));
    lines.push(format!(
        "effective_topology_edges={}",
        scenario.effective_topology.edges().len()
    ));
    lines.extend(
        scenario
            .effective_topology
            .edges()
            .iter()
            .map(scheduler_lookahead_edge_material),
    );
    match &scenario.trigger_static_topology {
        Some(topology) => {
            lines.push(String::from("trigger_static_topology=present"));
            lines.push(world_static_topology_material(topology));
        }
        None => lines.push(String::from("trigger_static_topology=absent")),
    }
    let mut nodes = scenario.nodes.clone();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    lines.push(format!("nodes={}", nodes.len()));
    lines.extend(nodes.iter().map(scheduler_scenario_node_material));
    lines.push(format!(
        "ready_point_counters={}",
        scenario.ready_point_counters.len()
    ));
    for (node, counter) in &scenario.ready_point_counters {
        lines.push(format!(
            "ready_point_node:\n{}\nready_point_counter_ticks={}",
            scheduler_node_material(node),
            counter.ticks,
        ));
    }

    let mut topology_changes = scenario.topology_changes.clone();
    topology_changes.sort_by(topology_change_order);
    lines.push(format!("topology_changes={}", topology_changes.len()));
    lines.extend(topology_changes.iter().map(topology_change_material));

    let mut run_subdivision_policies = scenario.run_subdivision_policies.clone();
    run_subdivision_policies.sort();
    lines.push(format!(
        "run_subdivision_policies={}",
        run_subdivision_policies.len()
    ));
    lines.extend(
        run_subdivision_policies
            .iter()
            .map(run_subdivision_policy_material),
    );

    let mut preemption_requests = scenario.preemption_requests.clone();
    preemption_requests.sort_by(preemption_decision_order);
    lines.push(format!("preemption_requests={}", preemption_requests.len()));
    lines.extend(preemption_requests.iter().map(preemption_decision_material));

    let mut vcpu_idle_snapshots = scenario.vcpu_idle_snapshots.clone();
    vcpu_idle_snapshots.sort();
    lines.push(format!("vcpu_idle_snapshots={}", vcpu_idle_snapshots.len()));
    lines.extend(vcpu_idle_snapshots.iter().map(vcpu_idle_snapshot_material));

    let pending = ordered_scheduled_events(&scenario.pending_events);
    lines.push(format!("pending_events={}", pending.len()));
    lines.extend(pending.into_iter().map(scheduled_event_material));

    lines.push(format!(
        "event_sequences={}",
        scenario.event_sequences.next.len()
    ));
    for (key, next) in &scenario.event_sequences.next {
        lines.push(format!(
            "sequence_producer:\n{}\nsequence_consumer:\n{}\nsequence_next={next}",
            scheduler_node_material(&key.producer),
            scheduler_node_material(&key.consumer),
        ));
    }

    lines.join("\n")
}

pub(super) fn recompute_scenario_node_lookahead(
    nodes: &mut [SchedulerScenarioNode],
    topology: &SchedulerLookaheadGraph,
) {
    for node in nodes {
        node.network_lookahead = topology.lookahead(&node.id);
    }
}

pub(super) fn scheduler_scenario_node_material(node: &SchedulerScenarioNode) -> String {
    format!(
        "node:\n{}\ncounter_ticks={}\nactivity={}\n{}\n{}",
        scheduler_node_material(&node.id),
        node.counter.ticks,
        scheduler_node_activity_label(node.activity),
        network_lookahead_material(node.network_lookahead),
        exact_local_event_material(&node.exact_local_event),
    )
}

pub(super) fn run_subdivision_policy_material(policy: &SchedulerRunSubdivisionPolicy) -> String {
    format!(
        "run_subdivision_policy:\n{}\nvcpu_count={}\nrr_switch_quantum={}",
        scheduler_node_material(&policy.node),
        policy.vcpu_count,
        policy.rr_switch_quantum,
    )
}

pub(super) fn preemption_decision_order(
    left: &PreemptionDecision,
    right: &PreemptionDecision,
) -> std::cmp::Ordering {
    left.at
        .cmp(&right.at)
        .then_with(|| left.node.name.cmp(&right.node.name))
        .then_with(|| preemption_kind_order(&left.kind).cmp(&preemption_kind_order(&right.kind)))
}

pub(super) fn preemption_kind_order(kind: &PreemptionKind) -> (u8, u32, u32, u32) {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => (0, from_vcpu.index, to_vcpu.index, 0),
        PreemptionKind::InterruptAt { target_vcpu, irq } => (1, target_vcpu.index, irq.vector, 0),
    }
}

pub(super) fn preemption_decision_material(preemption: &PreemptionDecision) -> String {
    let mut lines = Vec::new();
    lines.push(String::from("preemption_request:"));
    lines.push(format!("node_len={}", preemption.node.name.len()));
    lines.push(format!("node={}", preemption.node.name));
    lines.push(format!("at_retired={}", preemption.at.retired));
    match &preemption.kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
            lines.push(String::from("preemption_kind=vcpu-switch"));
            lines.push(format!("from_vcpu={}", from_vcpu.index));
            lines.push(format!("to_vcpu={}", to_vcpu.index));
        }
        PreemptionKind::InterruptAt { target_vcpu, irq } => {
            lines.push(String::from("preemption_kind=interrupt-at"));
            lines.push(format!("target_vcpu={}", target_vcpu.index));
            lines.push(format!("irq={}", irq.vector));
        }
    }
    lines.join("\n")
}

pub(super) fn vcpu_idle_snapshot_material(snapshot: &SchedulerNodeVcpuIdleSnapshot) -> String {
    let mut vcpus = snapshot.vcpus.clone();
    vcpus.sort();
    let mut lines = Vec::new();
    lines.push(String::from("vcpu_idle_snapshot:"));
    lines.push(scheduler_node_material(&snapshot.node));
    lines.push(format!("vcpu_count={}", snapshot.vcpu_count));
    lines.push(format!("vcpu_idle_states={}", vcpus.len()));
    for state in vcpus {
        lines.push(format!("vcpu={}", state.vcpu.index));
        lines.push(format!("halted={}", state.halted));
        match state.next_deadline {
            Some(deadline) => lines.push(format!("next_deadline_ns={}", deadline.nanos)),
            None => lines.push(String::from("next_deadline_ns=none")),
        }
        lines.push(format!("pending_input={}", state.pending_input));
    }
    lines.join("\n")
}

pub(super) fn scheduler_lookahead_edge_material(edge: &SchedulerLookaheadEdge) -> String {
    format!(
        "edge:\nedge_from:\n{}\nedge_to:\n{}\nedge_minimum_latency_ns={}",
        scheduler_node_material(&edge.from),
        scheduler_node_material(&edge.to),
        edge.minimum_latency.nanos,
    )
}

pub(super) fn world_static_topology_material(topology: &WorldStaticTopology) -> String {
    let mut participants = topology.participants.clone();
    participants.sort();
    let mut scheduling_nodes = topology.scheduling_nodes.clone();
    scheduling_nodes.sort();
    let mut rng_streams = topology.rng_streams.clone();
    rng_streams.sort();
    let mut lookahead_graph = topology.lookahead_graph.clone();
    lookahead_graph.sort();
    let mut bake_nodes = topology.bake_nodes.clone();
    bake_nodes.sort();

    let mut lines = Vec::new();
    lines.push(format!("participants={}", participants.len()));
    for node in participants {
        lines.push(trigger_node_material("participant", &node));
    }
    lines.push(format!("scheduling_nodes={}", scheduling_nodes.len()));
    for node in scheduling_nodes {
        lines.push(String::from("scheduling_node:"));
        lines.push(scheduler_node_material(&node));
    }
    lines.push(format!("rng_streams={}", rng_streams.len()));
    for stream in rng_streams {
        lines.push(format!("rng_stream_domain_len={}", stream.domain.len()));
        lines.push(format!("rng_stream_domain={}", stream.domain));
        lines.push(format!("rng_stream_name_len={}", stream.name.len()));
        lines.push(format!("rng_stream_name={}", stream.name));
    }
    lines.push(format!("world_lookahead_edges={}", lookahead_graph.len()));
    for edge in lookahead_graph {
        lines.push(world_lookahead_edge_material(&edge));
    }
    lines.push(format!("bake_nodes={}", bake_nodes.len()));
    for node in bake_nodes {
        lines.push(trigger_node_material("bake_node", &node));
    }
    lines.join("\n")
}

pub(super) fn world_lookahead_edge_material(edge: &WorldLookaheadEdge) -> String {
    format!(
        "world_edge_from_len={}\nworld_edge_from={}\nworld_edge_to_len={}\nworld_edge_to={}\nworld_edge_minimum_latency_ns={}",
        edge.from.name.len(),
        edge.from.name,
        edge.to.name.len(),
        edge.to.name,
        edge.minimum_latency.nanos,
    )
}

pub(super) fn topology_change_material(change: &SchedulerTopologyChange) -> String {
    let mut lines = Vec::new();
    lines.push(format!("topology_change_sequence={}", change.sequence));
    lines.push(format!(
        "topology_change_trigger={}",
        topology_change_trigger_label(change.trigger)
    ));
    lines.push(match change.activation_time {
        Some(activation_time) => format!(
            "topology_change_activation_time_ns={}",
            activation_time.nanos
        ),
        None => String::from("topology_change_activation_time_ns=none"),
    });
    match &change.effect {
        SchedulerTopologyChangeEffect::ReplaceEffectiveEdges(effective_edges) => {
            let graph = SchedulerLookaheadGraph::from_edges(effective_edges.clone());
            lines.push(String::from(
                "topology_change_effect=replace-effective-edges",
            ));
            lines.push(format!(
                "topology_change_effective_edges={}",
                graph.edges().len()
            ));
            lines.extend(graph.edges().iter().map(scheduler_lookahead_edge_material));
        }
        SchedulerTopologyChangeEffect::UpdateEffectiveEdges(updated_edges) => {
            let graph = SchedulerLookaheadGraph::from_edges(updated_edges.clone());
            lines.push(String::from(
                "topology_change_effect=update-effective-edges",
            ));
            lines.push(format!(
                "topology_change_updated_edges={}",
                graph.edges().len()
            ));
            lines.extend(graph.edges().iter().map(scheduler_lookahead_edge_material));
        }
        SchedulerTopologyChangeEffect::RemoveEffectiveEdges(endpoints) => {
            let mut endpoints = endpoints.clone();
            endpoints.sort();
            endpoints.dedup();
            lines.push(String::from(
                "topology_change_effect=remove-effective-edges",
            ));
            lines.push(format!("topology_change_removed_edges={}", endpoints.len()));
            lines.extend(
                endpoints
                    .iter()
                    .map(scheduler_lookahead_edge_endpoint_material),
            );
        }
        SchedulerTopologyChangeEffect::RestoreEffectiveEdges(restored_edges) => {
            let graph = SchedulerLookaheadGraph::from_edges(restored_edges.clone());
            lines.push(String::from(
                "topology_change_effect=restore-effective-edges",
            ));
            lines.push(format!(
                "topology_change_restored_edges={}",
                graph.edges().len()
            ));
            lines.extend(graph.edges().iter().map(scheduler_lookahead_edge_material));
        }
    }
    lines.join("\n")
}

pub(super) fn topology_change_trigger_label(
    trigger: SchedulerTopologyChangeTrigger,
) -> &'static str {
    match trigger {
        SchedulerTopologyChangeTrigger::FaultActivation => "fault-activation",
        SchedulerTopologyChangeTrigger::Heal => "heal",
        SchedulerTopologyChangeTrigger::LatencyChange => "latency-change",
    }
}

pub(super) fn scheduler_node_material(node: &SchedulerNodeId) -> String {
    format!(
        "node_name_len={}\nnode_name={}\nnode_kind={}",
        node.node.name.len(),
        node.node.name,
        scheduling_node_kind_label(node.kind),
    )
}

pub(super) fn scheduler_lookahead_edge_endpoint_material(
    endpoint: &SchedulerLookaheadEdgeEndpoint,
) -> String {
    format!(
        "edge_endpoint:\nedge_from:\n{}\nedge_to:\n{}",
        scheduler_node_material(&endpoint.from),
        scheduler_node_material(&endpoint.to),
    )
}

pub(super) fn scheduler_node_activity_label(activity: SchedulerNodeActivity) -> &'static str {
    match activity {
        SchedulerNodeActivity::Runnable => "runnable",
        SchedulerNodeActivity::Idle => "idle",
        SchedulerNodeActivity::Halted => "halted",
        SchedulerNodeActivity::Done => "done",
    }
}

pub(super) fn scheduling_node_kind_label(kind: SchedulingNodeKind) -> &'static str {
    match kind {
        SchedulingNodeKind::Vm => "vm",
        SchedulingNodeKind::Disk => "disk",
        SchedulingNodeKind::NineP => "9p",
        SchedulingNodeKind::Network => "network",
        SchedulingNodeKind::ControlPlane => "control-plane",
    }
}

pub(super) fn network_lookahead_material(lookahead: NetworkLookahead) -> String {
    match lookahead {
        NetworkLookahead::Finite(duration) => {
            format!(
                "network_lookahead=finite\nnetwork_lookahead_ns={}",
                duration.nanos
            )
        }
        NetworkLookahead::Infinite => String::from("network_lookahead=infinite"),
    }
}

pub(super) fn exact_local_event_material(event: &ExactLocalEvent) -> String {
    match event {
        ExactLocalEvent::NoArmedTimer => String::from("exact_local_event=none"),
        ExactLocalEvent::TimerDeadline { virtual_time } => {
            format!(
                "exact_local_event=timer\nexact_local_event_ns={}",
                virtual_time.nanos
            )
        }
        ExactLocalEvent::IoCompletion {
            virtual_time,
            sub_node,
        } => format!(
            "exact_local_event=io\nexact_local_event_ns={}\nexact_local_sub_node:\n{}",
            virtual_time.nanos,
            scheduler_node_material(sub_node),
        ),
        ExactLocalEvent::FaultActivation {
            virtual_time,
            fault,
        } => format!(
            "exact_local_event=fault\nexact_local_event_ns={}\nfault_name_len={}\nfault_name={}",
            virtual_time.nanos,
            fault.name.len(),
            fault.name,
        ),
    }
}

pub(super) fn scheduled_event_material(event: &ScheduledEvent) -> String {
    format!(
        "event:\n{}\n{}",
        scheduled_event_key_material(&event.key),
        scheduled_event_payload_material(&event.payload),
    )
}

pub(super) fn scheduled_event_key_material(key: &ScheduledEventKey) -> String {
    format!(
        "event_time={}\nevent_consumer:\n{}\nevent_producer:\n{}\nevent_sequence={}",
        key.virtual_time().ticks,
        scheduler_node_material(key.consumer()),
        scheduler_node_material(key.producer()),
        key.sequence(),
    )
}

pub(super) fn scheduled_event_payload_material(payload: &ScheduledEventPayload) -> String {
    match payload {
        ScheduledEventPayload::BackendInput(input) => format!(
            "payload=backend-input\npayload_node_len={}\npayload_node={}\npayload_bytes={}",
            input.node.name.len(),
            input.node.name,
            hex_bytes(&input.payload),
        ),
        ScheduledEventPayload::IoCompletion(completion) => format!(
            "payload=io-completion\npayload_sub_node:\n{}\npayload_target_len={}\npayload_target={}\npayload_delivery_icount={}\npayload_bytes={}",
            scheduler_node_material(&completion.sub_node),
            completion.target.name.len(),
            completion.target.name,
            completion.delivery_icount.retired,
            hex_bytes(&completion.payload),
        ),
        ScheduledEventPayload::FaultActivation(fault) => format!(
            "payload=fault-activation\npayload_fault_len={}\npayload_fault={}",
            fault.name.len(),
            fault.name,
        ),
        ScheduledEventPayload::ProbabilisticFault(choice) => format!(
            "payload=probabilistic-fault\npayload_fault_len={}\npayload_fault={}\npayload_stream_domain_len={}\npayload_stream_domain={}\npayload_stream_name_len={}\npayload_stream_name={}\npayload_rate_basis_points={}",
            choice.fault.name.len(),
            choice.fault.name,
            choice.stream.domain.len(),
            choice.stream.domain,
            choice.stream.name.len(),
            choice.stream.name,
            choice.rate.basis_points(),
        ),
        ScheduledEventPayload::Control(operation) => {
            format!("payload=control\n{}", control_operation_material(operation))
        }
    }
}

pub(super) fn control_operation_material(operation: &ControlOperation) -> String {
    let mut lines = Vec::new();
    lines.push(format!("control_sequence={}", operation.sequence));
    lines.push(format!(
        "control_kind={}",
        control_operation_kind_label(&operation.kind)
    ));
    match &operation.kind {
        ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Inject
        | ControlOperationKind::Query => {}
    }
    lines.join("\n")
}

pub(super) fn control_operation_kind_label(kind: &ControlOperationKind) -> &'static str {
    match kind {
        ControlOperationKind::Pause => "pause",
        ControlOperationKind::Resume => "resume",
        ControlOperationKind::Step => "step",
        ControlOperationKind::Snapshot => "snapshot",
        ControlOperationKind::Fork => "fork",
        ControlOperationKind::Inject => "inject",
        ControlOperationKind::Query => "query",
    }
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
mod production;
