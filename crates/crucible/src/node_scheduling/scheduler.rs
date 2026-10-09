//! Activated-world owner reservations and conservative input-bound arithmetic.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    time::Duration,
};

use crucible_node_contract::{
    ConnectionDescriptor, Endpoint, Id, OperatingMode, Phase, Position, QuantumGrid, U64,
};

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{
        ExactBoundaryPolicy, OperationRequest, ProgressEvidence, StopReason, WorldActivation,
    },
};

use super::grant::ExactPermission;
use super::{
    ExactCeiling, ExactGrant, ExecutionAdmission, ExecutionPolicy, QuantizedGrant,
    SchedulingCommit, SchedulingError, SchedulingReceipt, event::Delivery,
};

#[derive(Clone, Debug)]
pub(super) struct ExternalRootPolicy {
    maximum_payload_bytes: U64,
    maximum_pending_bytes: U64,
    grid: Option<QuantumGrid>,
}

#[derive(Clone, Debug)]
pub(super) struct RoutingConnection {
    pub(super) descriptor: ConnectionDescriptor,
    pub(super) policy: crate::node_admission::ConnectionPolicy,
}

#[derive(Clone, Debug)]
struct InputPath {
    producer: Id,
    latency_ps: U64,
    external: bool,
    external_endpoint: Option<Endpoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputBound {
    Unknown,
    At(Position),
    AfterInstant(U64),
}

#[derive(Clone, Debug)]
struct OwnerSchedule {
    grid: QuantumGrid,
    policy: ExecutionPolicy,
    cursor: Position,
    inputs: Vec<InputPath>,
    reserved: Option<Id>,
}

#[derive(Debug)]
struct InputBatchState {
    batch: super::RuntimeInputBatch,
    acknowledgement: Option<super::NativeInputAcknowledgement>,
    activated_by: Option<Id>,
    consumed: Vec<super::InputIdentity>,
}

#[derive(Clone, Debug)]
struct Reservation {
    node: Id,
    owner: Id,
    request: OperationRequest,
    input_batch: Option<Id>,
}

/// Derives half-open exact grants and fully closed quantized start windows.
///
/// Construction requires both a sealed admitted graph and runtime-minted full
/// world activation. All causal paths of a shared execution owner constrain its
/// grant, including inputs exposed through another public node facet. Dropping
/// an issued grant does not erase its retained reservation.
pub struct CausalScheduler {
    activation: WorldActivation,
    node_owners: BTreeMap<Id, Id>,
    node_routes: BTreeMap<Id, Vec<crate::node_contract::OwnerIdentity>>,
    input_batches: BTreeMap<Id, InputBatchState>,
    used_input_batches: BTreeSet<Id>,
    owners: BTreeMap<Id, OwnerSchedule>,
    bounds: BTreeMap<Id, OutputBound>,
    pending: BTreeMap<crucible_node_contract::EventKey, Delivery>,
    operations: BTreeMap<Id, Reservation>,
    used_operations: BTreeSet<Id>,
    sequences: super::event::ProducerSequences,
    routing: BTreeMap<Id, RoutingConnection>,
    output_endpoints: BTreeMap<Endpoint, U64>,
    external_roots: BTreeMap<Endpoint, ExternalRootPolicy>,
    external_closed_prefixes: BTreeMap<Endpoint, Position>,
    closed_prefixes: BTreeMap<Id, Position>,
    native_sequences: BTreeMap<Endpoint, U64>,
    payloads: BTreeMap<crucible_node_contract::ContentRef, Vec<u8>>,
    maximum_pending_payload_bytes: U64,
    maximum_microsteps: U64,
}

#[path = "terminal.rs"]
mod terminal;

impl CausalScheduler {
    pub(crate) fn activation(&self) -> &WorldActivation {
        &self.activation
    }

    /// Constructs a conservative scheduler for one durably activated graph.
    ///
    /// Producer bounds initially remain unknown. Current adapters must provide
    /// authenticated complete output observations before connected progression;
    /// native providers are not enabled merely by constructing this scheduler.
    ///
    /// # Errors
    /// Refuses mismatched activation, unsupported nonuniform boundaries, and
    /// different execution policies assigned to one indivisible owner.
    pub(crate) fn new(
        graph: &AdmittedGraph,
        activation: WorldActivation,
    ) -> Result<Self, SchedulingError> {
        if graph.world_binding_hash() != &activation.record().world_binding_hash {
            return Err(SchedulingError::ForeignActivation);
        }

        let mut node_owners = BTreeMap::new();
        let mut node_routes = BTreeMap::new();
        let mut owners: BTreeMap<Id, OwnerSchedule> = BTreeMap::new();
        let mut bounds = BTreeMap::new();
        let mut output_endpoints = BTreeMap::new();
        for node in graph.node_ids() {
            let binding = graph.binding(node).ok_or(SchedulingError::UnknownNode)?;
            let owner = &binding.compatibility.execution_owner.id;
            let live = activation
                .record()
                .owners
                .iter()
                .find(|live| &live.owner == owner)
                .ok_or(SchedulingError::ForeignActivation)?;
            if live.incarnation != binding.authority.incarnation_id
                || live.generation != binding.authority.owner_generation
            {
                return Err(SchedulingError::ForeignActivation);
            }
            let policy = graph
                .operating_policy(node)
                .ok_or(SchedulingError::UnsupportedMode)?
                .clone();
            let contract = &binding.compatibility.operating_contract;
            let grid = match (&policy, contract.mode) {
                (ExecutionPolicy::Exact { .. }, OperatingMode::Exact) => QuantumGrid::new(
                    contract
                        .resolution_ps
                        .ok_or(SchedulingError::UnsupportedMode)?,
                    contract.phase_ps.ok_or(SchedulingError::UnsupportedMode)?,
                )?,
                (
                    ExecutionPolicy::Quantized {
                        quantum_ps,
                        phase_ps,
                        ..
                    },
                    OperatingMode::Quantized,
                ) => QuantumGrid::new(*quantum_ps, *phase_ps)?,
                _ => return Err(SchedulingError::UnsupportedMode),
            };
            if let Some(existing) = owners.get(owner) {
                if existing.grid != grid || existing.policy != policy {
                    return Err(SchedulingError::UnsupportedMode);
                }
            } else {
                owners.insert(
                    owner.clone(),
                    OwnerSchedule {
                        grid,
                        policy,
                        cursor: activation.record().boundary,
                        inputs: Vec::new(),
                        reserved: None,
                    },
                );
            }
            let mut route_ids = BTreeSet::from([
                owner.clone(),
                binding.compatibility.capture_owner.id.clone(),
            ]);
            let route = activation
                .record()
                .owners
                .iter()
                .filter(|identity| route_ids.remove(&identity.owner))
                .cloned()
                .collect::<Vec<_>>();
            if !route_ids.is_empty() {
                return Err(SchedulingError::ForeignActivation);
            }
            node_routes.insert(node.clone(), route);
            node_owners.insert(node.clone(), owner.clone());
            bounds.insert(node.clone(), OutputBound::Unknown);
            let descriptor = graph.descriptor(node).ok_or(SchedulingError::UnknownNode)?;
            for port in &descriptor.ports {
                for lane in &port.lanes {
                    if lane.direction == crucible_node_contract::Direction::Output {
                        output_endpoints.insert(
                            Endpoint {
                                node_id: node.clone(),
                                port_id: port.id.clone(),
                                lane_id: lane.id.clone(),
                            },
                            lane.maximum_payload_bytes,
                        );
                    }
                }
            }
        }

        // The initial allocation roster is explicit. Snapshot restoration must
        // not turn an implicit default into a newly materialized producer entry.
        let mut sequences = super::event::ProducerSequences::default();
        for node in bounds.keys() {
            sequences.restore_next(node.clone(), Some(U64::new(0)));
        }
        let closed_prefixes = bounds
            .keys()
            .map(|node| (node.clone(), activation.record().boundary))
            .collect();
        let routing = graph
            .world()
            .connections
            .iter()
            .map(|connection| {
                let policy = graph
                    .connection_policy(&connection.id)
                    .ok_or(SchedulingError::UnsupportedMode)?
                    .clone();
                Ok((
                    connection.id.clone(),
                    RoutingConnection {
                        descriptor: connection.clone(),
                        policy,
                    },
                ))
            })
            .collect::<Result<_, SchedulingError>>()?;
        let mut maximum_pending_payload_bytes =
            graph
                .world()
                .connections
                .iter()
                .try_fold(U64::new(0), |total, connection| {
                    total
                        .checked_add(
                            graph
                                .connection_policy(&connection.id)
                                .ok_or(SchedulingError::UnsupportedMode)?
                                .maximum_pending_bytes,
                        )
                        .map_err(SchedulingError::from)
                })?;
        let mut external_roots = BTreeMap::new();
        for endpoint in &graph.coordinator_policy().external_inputs {
            let descriptor = graph
                .descriptor(&endpoint.node_id)
                .ok_or(SchedulingError::UnknownNode)?;
            let port = descriptor
                .ports
                .iter()
                .find(|port| port.id == endpoint.port_id)
                .ok_or(SchedulingError::UnknownNode)?;
            let lane = port
                .lanes
                .iter()
                .find(|lane| lane.id == endpoint.lane_id)
                .ok_or(SchedulingError::UnknownNode)?;
            let lane_policy = graph
                .port_policy(&endpoint.node_id, &endpoint.port_id)
                .and_then(|port| {
                    port.lanes
                        .iter()
                        .find(|lane| lane.lane_id == endpoint.lane_id)
                })
                .ok_or(SchedulingError::UnsupportedMode)?;
            let grid = match lane_policy.visibility {
                crate::node_admission::LaneVisibility::Exact => None,
                crate::node_admission::LaneVisibility::Quantized {
                    quantum_ps,
                    phase_ps,
                    ..
                } => Some(QuantumGrid::new(quantum_ps, phase_ps)?),
            };
            maximum_pending_payload_bytes =
                maximum_pending_payload_bytes.checked_add(lane_policy.maximum_pending_bytes)?;
            external_roots.insert(
                endpoint.clone(),
                ExternalRootPolicy {
                    maximum_payload_bytes: lane.maximum_payload_bytes,
                    maximum_pending_bytes: lane_policy.maximum_pending_bytes,
                    grid,
                },
            );
        }
        let mut scheduler = Self {
            activation,
            node_owners,
            node_routes,
            input_batches: BTreeMap::new(),
            used_input_batches: BTreeSet::new(),
            owners,
            bounds,
            pending: BTreeMap::new(),
            operations: BTreeMap::new(),
            used_operations: BTreeSet::new(),
            sequences,
            routing,
            output_endpoints,
            external_roots,
            external_closed_prefixes: BTreeMap::new(),
            closed_prefixes,
            native_sequences: BTreeMap::new(),
            payloads: BTreeMap::new(),
            maximum_pending_payload_bytes,
            maximum_microsteps: graph.coordinator_policy().maximum_microsteps_per_instant,
        };
        for connection in &graph.world().connections {
            let policy = graph
                .connection_policy(&connection.id)
                .ok_or(SchedulingError::UnsupportedMode)?;
            let crate::node_admission::ConnectionDelivery::Fixed { latency_ps } = policy.delivery;
            scheduler.add_path(
                &connection.producer.node_id,
                &connection.consumer.node_id,
                latency_ps,
                false,
            )?;
        }
        for dependency in &graph.ownership_policy().internal_dependencies {
            scheduler.add_path(
                &dependency.producer_node_id,
                &dependency.consumer_node_id,
                dependency.minimum_latency_ps,
                false,
            )?;
        }
        for endpoint in &graph.coordinator_policy().external_inputs {
            scheduler.add_path(&endpoint.node_id, &endpoint.node_id, U64::new(0), true)?;
            let owner = scheduler.owner_id(&endpoint.node_id)?.clone();
            let path = scheduler
                .owners
                .get_mut(&owner)
                .and_then(|owner| owner.inputs.last_mut())
                .ok_or(SchedulingError::UnknownNode)?;
            path.external_endpoint = Some(endpoint.clone());
        }
        Ok(scheduler)
    }

    fn add_path(
        &mut self,
        producer: &Id,
        consumer: &Id,
        latency_ps: U64,
        external: bool,
    ) -> Result<(), SchedulingError> {
        let source_owner = self
            .node_owners
            .get(producer)
            .ok_or(SchedulingError::UnknownNode)?;
        let owner = self
            .node_owners
            .get(consumer)
            .ok_or(SchedulingError::UnknownNode)?;
        if source_owner == owner && !external {
            return Ok(());
        }
        self.owners
            .get_mut(owner)
            .ok_or(SchedulingError::UnknownNode)?
            .inputs
            .push(InputPath {
                producer: producer.clone(),
                latency_ps,
                external,
                external_endpoint: None,
            });
        Ok(())
    }

    /// Returns the greatest authenticated cursor of a node's shared owner.
    ///
    /// # Errors
    /// Refuses a node not present in the admitted graph.
    pub fn position(&self, node: &Id) -> Result<Position, SchedulingError> {
        Ok(self.schedule(node)?.cursor)
    }

    /// Previews a closed exact input prefix without staging or consuming it.
    ///
    /// Authentic future producer bounds limit the cut; already published pending
    /// deliveries remain eligible for inclusion. The native staging path checks
    /// the returned cut again before issuing immutable custody.
    ///
    /// # Errors
    /// Refuses unknown producers, unsupported modes and cuts at or before the
    /// current cursor. This preview never reserves an execution operation.
    pub fn preview_exact_input_cut(
        &self,
        node: &Id,
        horizon: U64,
    ) -> Result<Position, SchedulingError> {
        let schedule = self.schedule(node)?;
        if !matches!(schedule.policy, ExecutionPolicy::Exact { .. }) {
            return Err(SchedulingError::UnsupportedMode);
        }
        let mut cutoff = Position::new(horizon, U64::new(0), Phase::BoundaryControl);
        for path in &schedule.inputs {
            if let Some(arrival) = self.earliest_delivery(path)? {
                cutoff = cutoff.min(arrival);
            }
        }
        if cutoff <= schedule.cursor {
            return Err(SchedulingError::NoSafeProgress);
        }
        Ok(cutoff)
    }

    /// Previews the conservative exact ceiling without reserving execution.
    ///
    /// The returned position permits only input-cut preparation. Native execution
    /// still requires `admit_exact`, which revalidates all authentic producer,
    /// pending-delivery and immutable staged-input state before issuing a grant.
    ///
    /// # Errors
    /// Refuses unsupported modes, incomplete closure and intervals without safe
    /// representable progress under the same checks as exact grant admission.
    pub fn preview_exact_limit(
        &self,
        node: &Id,
        horizon: U64,
    ) -> Result<Position, SchedulingError> {
        Ok(self.exact_limit(node, horizon)?.0)
    }

    fn exact_limit(
        &self,
        node: &Id,
        horizon: U64,
    ) -> Result<(Position, ExactBoundaryPolicy), SchedulingError> {
        let owner = self.owner_id(node)?.clone();
        let schedule = self.schedule(node)?;
        let ceiling = match &schedule.policy {
            ExecutionPolicy::Exact { ceiling, .. } => ceiling,
            _ => return Err(SchedulingError::UnsupportedMode),
        };
        let mut safe = horizon;
        let mut earliest_input: Option<U64> = None;
        for path in &schedule.inputs {
            let Some(arrival) = self.earliest_arrival(path)? else {
                continue;
            };
            earliest_input = Some(earliest_input.map_or(arrival, |previous| previous.min(arrival)));
            let stop = match ceiling {
                ExactCeiling::StrictPredecessor => {
                    let before = arrival
                        .get()
                        .checked_sub(1)
                        .ok_or(SchedulingError::NoSafeProgress)?;
                    schedule.grid.predecessor(U64::new(before))?
                }
                ExactCeiling::InputBlocked { .. } => schedule.grid.predecessor(arrival)?,
            };
            safe = safe.min(stop);
        }
        for delivery in self
            .pending
            .values()
            .filter(|delivery| self.node_owners.get(&delivery.consumer) == Some(&owner))
        {
            if self.input_captured(&owner, delivery) {
                continue;
            }
            let arrival = delivery.delivery.time_ps;
            earliest_input = Some(earliest_input.map_or(arrival, |previous| previous.min(arrival)));
            let stop = match ceiling {
                ExactCeiling::StrictPredecessor => {
                    let before = arrival
                        .get()
                        .checked_sub(1)
                        .ok_or(SchedulingError::NoSafeProgress)?;
                    schedule.grid.predecessor(U64::new(before))?
                }
                ExactCeiling::InputBlocked { .. } => schedule.grid.predecessor(arrival)?,
            };
            safe = safe.min(stop);
        }
        let limit = Position::new(
            schedule.grid.predecessor(safe)?,
            U64::new(0),
            Phase::BoundaryControl,
        );
        if limit <= schedule.cursor {
            return Err(SchedulingError::NoSafeProgress);
        }
        let boundary_policy = if matches!(ceiling, ExactCeiling::InputBlocked { .. })
            && earliest_input == Some(limit.time_ps)
        {
            ExactBoundaryPolicy::InputBlockedPark
        } else {
            ExactBoundaryPolicy::HorizonPark
        };
        Ok((limit, boundary_policy))
    }

    /// Admits exact execution up to a safe representable exclusive ceiling.
    ///
    /// Requested horizons cannot bypass any unknown input path, pending delivery
    /// or shared-owner reservation. Ordinary ceilings exclude every semantic
    /// position at their physical tick, irrespective of endpoint lexical order.
    ///
    /// # Errors
    /// Refuses unknown or stale input closure, duplicate identities, busy owners,
    /// incompatible mode and requests with no representable safe progress.
    pub fn admit_exact(
        &mut self,
        node: &Id,
        operation: Id,
        horizon: U64,
    ) -> Result<ExecutionAdmission, SchedulingError> {
        let owner = self.owner_id(node)?.clone();
        let (limit, boundary_policy) = self.exact_limit(node, horizon)?;
        let input_batch = match self.input_batches.get(&owner) {
            Some(state) => {
                self.staged_batch(&owner)?;
                if state.batch.node != *node {
                    return Err(SchedulingError::MissingObservation);
                }
                Some(state.batch.batch.clone())
            }
            None => None,
        };
        let request = OperationRequest::ExactRun {
            start: self.schedule(node)?.cursor,
            limit,
            boundary_policy,
        };
        self.reserve(node, operation.clone(), request.clone())?;
        if let Some(batch) = &input_batch {
            self.activate_input_batch(&owner, &operation, batch)?;
        }
        Ok(ExecutionAdmission::Exact(ExactGrant {
            activation: self.activation.clone(),
            node: node.clone(),
            operation,
            input_batch,
            permission: ExactPermission::Run {
                start: self.schedule(node)?.cursor,
                limit,
                boundary_policy,
            },
        }))
    }

    /// Admits one quantized window after every equal-boundary input is closed.
    ///
    /// The input batch is fixed before activation. An unresolved producer at the
    /// start boundary blocks the next window even after an earlier window's
    /// physical stop. The original end is retained until its close receipt.
    ///
    /// # Errors
    /// Refuses incomplete boundary closure, unstaged pending inputs, busy owners,
    /// incompatible mode, repeated identities and checked boundary overflow.
    pub fn admit_quantum(
        &mut self,
        node: &Id,
        operation: Id,
        window: Id,
        input_batch: Id,
    ) -> Result<ExecutionAdmission, SchedulingError> {
        let owner = self.owner_id(node)?.clone();
        let schedule = self.schedule(node)?;
        let host_budget_ns = match &schedule.policy {
            ExecutionPolicy::Quantized { host_budget_ns, .. } => *host_budget_ns,
            _ => return Err(SchedulingError::UnsupportedMode),
        };
        let start = schedule.cursor.time_ps;
        if !schedule.grid.contains(start) {
            return Err(SchedulingError::NoSafeProgress);
        }
        self.require_boundary_closed(&owner, start)?;
        let staged = self.staged_batch(&owner)?;
        if staged.batch.node != *node
            || staged.batch.batch != input_batch
            || staged.batch.cutoff
                != Position::new(
                    start.checked_add(U64::new(1))?,
                    U64::new(0),
                    Phase::BoundaryControl,
                )
        {
            return Err(SchedulingError::MissingObservation);
        }
        if self.pending.values().any(|delivery| {
            self.node_owners.get(&delivery.consumer) == Some(&owner)
                && delivery.delivery.time_ps <= start
                && !self.input_captured(&owner, delivery)
        }) {
            return Err(SchedulingError::MissingObservation);
        }
        let end = start.checked_add(schedule.grid.quantum())?;
        let start = Position::new(start, U64::new(0), Phase::BoundaryControl);
        let end = Position::new(end, U64::new(0), Phase::Publication);
        let host_budget = Duration::from_nanos(host_budget_ns.get());
        let request = OperationRequest::QuantumBegin {
            window: window.clone(),
            start,
            end,
            input_batch: input_batch.clone(),
            host_budget,
        };
        self.reserve(node, operation.clone(), request.clone())?;
        self.activate_input_batch(&owner, &operation, &input_batch)?;
        Ok(ExecutionAdmission::Quantized(QuantizedGrant {
            activation: self.activation.clone(),
            node: node.clone(),
            operation,
            window,
            start,
            end,
            input_batch,
            host_budget,
        }))
    }

    /// Admits a finite half-open range of qualified same-instant reactions.
    ///
    /// Settlement never authorizes a later physical tick. An unresolved delivery
    /// inside its position range prevents activation; native input staging is a
    /// separate obligation which cannot be inferred from the absence of output.
    ///
    /// # Errors
    /// Refuses unqualified settlement, unknown closure, exhausted microsteps,
    /// pending input in the range, incompatible coordinates and busy owners.
    pub fn admit_boundary_settlement(
        &mut self,
        node: &Id,
        operation: Id,
        limit: Position,
    ) -> Result<ExecutionAdmission, SchedulingError> {
        let owner = self.owner_id(node)?.clone();
        let schedule = self.schedule(node)?;
        match &schedule.policy {
            ExecutionPolicy::Exact {
                boundary_settlement_ref: Some(_),
                ..
            } => {}
            _ => return Err(SchedulingError::UnsupportedMode),
        }
        if limit.time_ps != schedule.cursor.time_ps || limit <= schedule.cursor {
            return Err(SchedulingError::NoSafeProgress);
        }
        if limit.microstep >= self.maximum_microsteps {
            return Err(SchedulingError::SameTimeNonconvergence);
        }
        for path in &schedule.inputs {
            if self
                .earliest_delivery(path)?
                .is_some_and(|arrival| arrival < limit)
            {
                return Err(SchedulingError::InputBlocked(path.producer.clone()));
            }
        }
        if self.pending.values().any(|delivery| {
            self.node_owners.get(&delivery.consumer) == Some(&owner)
                && delivery.delivery < limit
                && !self.input_captured(&owner, delivery)
        }) {
            return Err(SchedulingError::MissingObservation);
        }
        let input_batch = match self.input_batches.get(&owner) {
            Some(state) => {
                self.staged_batch(&owner)?;
                if state.batch.node != *node {
                    return Err(SchedulingError::MissingObservation);
                }
                Some(state.batch.batch.clone())
            }
            None => None,
        };
        let request = OperationRequest::BoundarySettle {
            start: schedule.cursor,
            limit,
        };
        self.reserve(node, operation.clone(), request.clone())?;
        if let Some(batch) = &input_batch {
            self.activate_input_batch(&owner, &operation, batch)?;
        }
        Ok(ExecutionAdmission::Exact(ExactGrant {
            activation: self.activation.clone(),
            node: node.clone(),
            operation,
            input_batch,
            permission: ExactPermission::Settlement {
                start: self.schedule(node)?.cursor,
                limit,
            },
        }))
    }

    /// Applies authentic native progress while retaining uncertain obligations.
    ///
    /// ID-only outputs are deliberately refused until an adapter supplies their
    /// authenticated coordinates and complete production closure. An invalid
    /// receipt leaves the original owner reservation intact.
    ///
    /// # Errors
    /// Refuses foreign authority, repeated/mismatched receipts, unauthorized
    /// progress and outputs lacking qualified causal publication information.
    pub(crate) fn accept_receipt(
        &mut self,
        receipt: SchedulingReceipt,
    ) -> Result<SchedulingCommit, SchedulingError> {
        if !Rc::ptr_eq(&self.activation.authority, &receipt.activation.authority)
            || self.activation.record() != receipt.activation.record()
        {
            return Err(SchedulingError::ForeignActivation);
        }
        let reservation = self
            .operations
            .get(&receipt.operation)
            .ok_or(SchedulingError::InvalidReceipt)?;
        if reservation.node != receipt.node {
            return Err(SchedulingError::InvalidReceipt);
        }
        if reservation.input_batch.is_some() && receipt.observation.is_none() {
            return Err(SchedulingError::MissingObservation);
        }
        if !receipt.retained_outputs.is_empty() && receipt.observation.is_none() {
            return Err(SchedulingError::MissingOutputCoordinates);
        }
        let input_blocked_park = matches!(
            reservation.request,
            OperationRequest::ExactRun {
                boundary_policy: ExactBoundaryPolicy::InputBlockedPark,
                ..
            }
        );
        let reached = match (&reservation.request, &receipt.progress) {
            (
                OperationRequest::ExactRun { start, limit, .. }
                | OperationRequest::BoundarySettle { start, limit },
                ProgressEvidence::Exact { reached, stop },
            ) if reached >= start
                && reached <= limit
                && *stop != StopReason::Unclassified
                && (*stop != StopReason::HorizonPark || reached == limit)
                && (*reached != *limit
                    || *stop == StopReason::HorizonPark
                    || (input_blocked_park && *stop == StopReason::InputBlocked)) =>
            {
                *reached
            }
            (
                OperationRequest::QuantumBegin {
                    window,
                    end,
                    input_batch,
                    ..
                },
                ProgressEvidence::Quantized {
                    window: actual,
                    publication,
                    closure,
                    ..
                },
            ) if window == actual && end == publication && input_batch == &closure.input_batch => {
                Position::new(end.time_ps, U64::new(0), Phase::BoundaryControl)
            }
            _ => return Err(SchedulingError::InvalidReceipt),
        };
        let owner = reservation.owner.clone();
        if reached.microstep >= self.maximum_microsteps
            && !(self.maximum_microsteps.get() == 0 && reached.microstep.get() == 0)
        {
            return Err(SchedulingError::SameTimeNonconvergence);
        }
        let update = if let Some(observation) = &receipt.observation {
            if observation.node != receipt.node || observation.reached != reached {
                return Err(SchedulingError::InvalidReceipt);
            }
            if observation
                .publications
                .iter()
                .map(|publication| publication.publication_id.clone())
                .collect::<Vec<_>>()
                != receipt.retained_outputs
            {
                return Err(SchedulingError::InvalidReceipt);
            }
            Some(self.prepare_observation(observation, Some(reservation))?)
        } else {
            None
        };
        if let Some(update) = update {
            self.apply_observation(update);
        }
        let schedule = self
            .owners
            .get_mut(&owner)
            .ok_or(SchedulingError::InvalidReceipt)?;
        schedule.cursor = reached;
        schedule.reserved = None;
        self.operations.remove(&receipt.operation);
        self.release_input_activation(&owner, &receipt.operation);
        self.retire_consumed_batch(&owner);
        Ok(SchedulingCommit {
            activation: receipt.activation,
            node: receipt.node,
            operation: receipt.operation,
            retained_outputs: receipt.retained_outputs,
        })
    }

    // Only the owning runtime calls this after positively establishing that no
    // native effect began. A timeout, cancellation or dropped token is not proof.
    pub(crate) fn reconcile_no_effect(
        &mut self,
        admission: &ExecutionAdmission,
    ) -> Result<(), SchedulingError> {
        if !Rc::ptr_eq(
            &self.activation.authority,
            &admission.activation().authority,
        ) {
            return Err(SchedulingError::ForeignActivation);
        }
        let reservation = self
            .operations
            .get(admission.operation())
            .ok_or(SchedulingError::InvalidReceipt)?;
        if &reservation.node != admission.node() || reservation.request != admission.request() {
            return Err(SchedulingError::InvalidReceipt);
        }
        let owner = reservation.owner.clone();
        self.operations.remove(admission.operation());
        self.release_input_activation(&owner, admission.operation());
        self.owners
            .get_mut(&owner)
            .ok_or(SchedulingError::InvalidReceipt)?
            .reserved = None;
        Ok(())
    }

    /// Releases an issued grant which has never been handed to the runtime.
    ///
    /// Consuming the unique opaque grant makes this unavailable after dispatch.
    /// Its identity remains used and cannot be reused for a different request.
    ///
    /// # Errors
    /// Refuses a foreign grant or one whose retained reservation is absent.
    pub fn abandon_undispatched(
        &mut self,
        admission: ExecutionAdmission,
    ) -> Result<(), SchedulingError> {
        if !Rc::ptr_eq(
            &self.activation.authority,
            &admission.activation().authority,
        ) {
            return Err(SchedulingError::ForeignActivation);
        }
        let reservation = self
            .operations
            .remove(admission.operation())
            .ok_or(SchedulingError::InvalidReceipt)?;
        self.release_input_activation(&reservation.owner, admission.operation());
        self.owners
            .get_mut(&reservation.owner)
            .ok_or(SchedulingError::InvalidReceipt)?
            .reserved = None;
        Ok(())
    }

    fn owner_id(&self, node: &Id) -> Result<&Id, SchedulingError> {
        self.node_owners
            .get(node)
            .ok_or(SchedulingError::UnknownNode)
    }

    fn schedule(&self, node: &Id) -> Result<&OwnerSchedule, SchedulingError> {
        self.owners
            .get(self.owner_id(node)?)
            .ok_or(SchedulingError::UnknownNode)
    }

    fn reserve(
        &mut self,
        node: &Id,
        operation: Id,
        request: OperationRequest,
    ) -> Result<(), SchedulingError> {
        if self.used_operations.contains(&operation) {
            return Err(SchedulingError::DuplicateOperation);
        }
        if self.used_operations.len() >= crucible_node_contract::MAX_ARRAY_ELEMENTS {
            return Err(SchedulingError::CapacityExceeded);
        }
        let owner = self.owner_id(node)?.clone();
        let schedule = self
            .owners
            .get_mut(&owner)
            .ok_or(SchedulingError::UnknownNode)?;
        if schedule.reserved.is_some() {
            return Err(SchedulingError::OwnerBusy);
        }
        schedule.reserved = Some(operation.clone());
        self.used_operations.insert(operation.clone());
        self.operations.insert(
            operation,
            Reservation {
                node: node.clone(),
                owner,
                request,
                input_batch: None,
            },
        );
        Ok(())
    }

    // None is mathematical top only for an authenticated all-instant closure.
    // Finite coordinates retain checked transport arithmetic and cannot become top.
    fn earliest_arrival(&self, path: &InputPath) -> Result<Option<U64>, SchedulingError> {
        if path.external {
            return path
                .external_endpoint
                .as_ref()
                .and_then(|endpoint| self.external_closed_prefixes.get(endpoint))
                .map(|position| Some(position.time_ps))
                .ok_or_else(|| SchedulingError::InputBlocked(path.producer.clone()));
        }
        let earliest = match self.bounds.get(&path.producer) {
            Some(OutputBound::At(position)) => position.time_ps,
            Some(OutputBound::AfterInstant(time)) if time.get() == u64::MAX => return Ok(None),
            Some(OutputBound::AfterInstant(time)) => time.checked_add(U64::new(1))?,
            _ => return Err(SchedulingError::InputBlocked(path.producer.clone())),
        };
        Ok(Some(earliest.checked_add(path.latency_ps)?))
    }

    fn earliest_delivery(&self, path: &InputPath) -> Result<Option<Position>, SchedulingError> {
        if path.external {
            return path
                .external_endpoint
                .as_ref()
                .and_then(|endpoint| self.external_closed_prefixes.get(endpoint))
                .copied()
                .map(Some)
                .ok_or_else(|| SchedulingError::InputBlocked(path.producer.clone()));
        }
        match self.bounds.get(&path.producer) {
            Some(OutputBound::At(position)) => {
                super::event::direct_delivery(*position, path.latency_ps, None).map(Some)
            }
            Some(OutputBound::AfterInstant(time)) if time.get() == u64::MAX => Ok(None),
            Some(OutputBound::AfterInstant(time)) => {
                let arrival = time
                    .checked_add(U64::new(1))?
                    .checked_add(path.latency_ps)?;
                Ok(Some(Position::new(arrival, U64::new(0), Phase::Delivery)))
            }
            _ => Err(SchedulingError::InputBlocked(path.producer.clone())),
        }
    }

    fn require_boundary_closed(&self, owner: &Id, boundary: U64) -> Result<(), SchedulingError> {
        let schedule = self.owners.get(owner).ok_or(SchedulingError::UnknownNode)?;
        for path in &schedule.inputs {
            if self
                .earliest_arrival(path)?
                .is_some_and(|arrival| arrival <= boundary)
            {
                return Err(SchedulingError::InputBlocked(path.producer.clone()));
            }
        }
        Ok(())
    }

    // Native adapters must authenticate a complete all-output-lane observation
    // before calling this. Portable bound records never invoke it themselves.
    #[cfg(test)]
    pub(crate) fn observe_bound(
        &mut self,
        activation: &WorldActivation,
        producer: &Id,
        bound: OutputBound,
    ) -> Result<(), SchedulingError> {
        if !Rc::ptr_eq(&self.activation.authority, &activation.authority)
            || self.activation.record() != activation.record()
        {
            return Err(SchedulingError::ForeignActivation);
        }
        if matches!(bound, OutputBound::At(position) if position.phase != Phase::Publication) {
            return Err(SchedulingError::InvalidPublication);
        }
        if matches!(bound, OutputBound::At(position) if position.microstep >= self.maximum_microsteps
            && !(self.maximum_microsteps.get() == 0 && position.microstep.get() == 0))
        {
            return Err(SchedulingError::SameTimeNonconvergence);
        }
        let slot = self
            .bounds
            .get_mut(producer)
            .ok_or(SchedulingError::UnknownNode)?;
        let advances = match (*slot, bound) {
            (OutputBound::Unknown, _) => true,
            (OutputBound::At(old), OutputBound::At(new)) => new >= old,
            (OutputBound::At(old), OutputBound::AfterInstant(new)) => new >= old.time_ps,
            (OutputBound::AfterInstant(old), OutputBound::AfterInstant(new)) => new >= old,
            (OutputBound::AfterInstant(old), OutputBound::At(new)) => new.time_ps > old,
            (_, OutputBound::Unknown) => false,
        };
        if !advances {
            return Err(SchedulingError::CausalRegression);
        }
        *slot = bound;
        Ok(())
    }

    /// Returns the finite admitted same-time closure count.
    pub fn maximum_microsteps(&self) -> U64 {
        self.maximum_microsteps
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[path = "snapshot_impl.rs"]
mod snapshot_impl;

pub use snapshot_impl::PreparedSchedulingRestore;
pub use snapshot_impl::validate_saved_source;

#[path = "observed_impl.rs"]
mod observed_impl;

#[path = "inputs_impl.rs"]
mod inputs_impl;

#[path = "preflight_impl.rs"]
mod preflight;
