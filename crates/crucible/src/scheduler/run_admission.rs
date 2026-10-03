//! Immutable scheduler RUN ownership and fully enumerated input boundaries.
//!
//! Only finalized scheduler preparation constructs these records. Their opaque
//! context binds modeled authority; native process identity and execution
//! permission remain independently authenticated by the operational backend.

use std::num::NonZeroU64;

use super::*;
use crate::ExecutionHorizon;

#[path = "run_admission/input_replan.rs"]
mod input_replan;

/// Complete scheduler-owned input inventory frozen for one dispatch revision.
#[derive(Clone, Debug)]
pub struct PreparedRunInputInventory {
    generation: NonZeroU64,
    next_input: Option<NodeCounter>,
    // Retains every actual queue, device/link state, control record and cap,
    // including sources that presently have no queued delivery.
    _source: Arc<SingleScheduler>,
}

impl PreparedRunInputInventory {
    pub(super) fn complete_source(
        source: Arc<SingleScheduler>,
        generation: NonZeroU64,
        next_input: Option<NodeCounter>,
    ) -> Self {
        Self {
            generation,
            next_input,
            _source: source,
        }
    }

    pub(super) fn fixed_input(
        source: Arc<SingleScheduler>,
        generation: NonZeroU64,
        at: NodeCounter,
    ) -> Self {
        Self {
            generation,
            next_input: Some(at),
            _source: source,
        }
    }

    /// Returns the checked publication revision that owns this enumeration.
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    /// Returns the immutable World owner retained by this input enumeration.
    ///
    /// An uninstantiated scheduler has no World owner. This identity binds
    /// modeled inputs; it does not authenticate native Source or RUN permission.
    #[must_use]
    pub fn world(&self) -> Option<ContentHash> {
        self._source
            .inventory_world
            .as_ref()
            .map(|world| world.id())
    }

    /// Returns the earliest known input in the backend's node-local logical ticks.
    ///
    /// This is projected through the actual node time mapping. It is neither a
    /// shared timeline cast nor a raw retired-instruction count. Absence is
    /// derived by enumerating the retained scheduler's complete input sources.
    #[must_use]
    pub const fn next_input(&self) -> Option<NodeCounter> {
        self.next_input
    }
}

#[derive(Clone, Debug)]
struct PreparedRunOwner {
    plan: AdvancePlan,
    semantic_horizon: u64,
    command: Option<PreemptionDecision>,
    control_token: NonZeroU64,
    context: [u64; 4],
    // Keeps the original Configuration, authored Plan, effective topology,
    // event-log prefix and complete planner state alive across internal waves.
    _source: Arc<SingleScheduler>,
}

/// Sealed semantic RUN authority and its current scheduler dispatch bounds.
///
/// There is no public constructor. A backend receives this record only after
/// the scheduler finalizes PICK, preemption clipping and ceiling publication.
/// Physical continuations retain the original owner while refreshing their
/// actual input inventory and dispatch cap.
#[derive(Clone, Debug)]
pub struct PreparedRunAdmission {
    owner: Arc<PreparedRunOwner>,
    input_inventory: PreparedRunInputInventory,
    dispatch_horizon: ExecutionHorizon,
}

impl PreparedRunAdmission {
    pub(super) fn shares_semantic_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }

    /// Returns the logical node selected by the finalized scheduler RUN.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.owner.plan.node.node
    }

    /// Returns the checked scheduler token retained by this semantic RUN.
    #[must_use]
    pub fn control_token(&self) -> NonZeroU64 {
        self.owner.control_token
    }

    /// Returns the opaque binding of the original immutable RUN authority.
    #[must_use]
    pub fn context(&self) -> [u64; 4] {
        self.owner.context
    }

    /// Returns the complete input enumeration for the current dispatch revision.
    #[must_use]
    pub const fn input_inventory(&self) -> &PreparedRunInputInventory {
        &self.input_inventory
    }

    /// Validates a shared delivery key against this RUN's node-local coordinate.
    ///
    /// The retained inventory supplies the actual selected node time mapping.
    /// This coordinate check does not authorize publication or prove that the
    /// backend's independently held physical input owner remains current.
    ///
    /// # Errors
    ///
    /// Returns an error for a different consumer, an inexact or overflowing
    /// mapping, or a node-local coordinate that differs from the mapped key.
    pub fn validate_input_delivery_coordinate(
        &self,
        key: &ScheduledEventKey,
        at: NodeCounter,
    ) -> Result<(), crate::BackendError> {
        if key.consumer() != &self.owner.plan.node {
            return Err(crate::BackendError::Rejected {
                message: String::from("input delivery key targets a different RUN consumer"),
            });
        }

        let mapped = self
            .input_inventory
            ._source
            .backend_effect_time(self.node(), key.virtual_time())
            .map_err(|error| crate::BackendError::Rejected {
                message: format!("input delivery coordinate cannot be projected: {error}"),
            })?;
        if mapped.ticks != at.ticks {
            return Err(crate::BackendError::Rejected {
                message: String::from(
                    "input delivery coordinate differs from the retained mapping",
                ),
            });
        }

        Ok(())
    }

    /// Returns the original semantic horizon in node-local logical ticks.
    ///
    /// The historical `Icount.retired` wrapper carries logical T here, as does
    /// [`NodeCounter`]. It must not be multiplied into time or used as native
    /// raw retirement. Native raw/B/C and physical identity are separate facts.
    #[must_use]
    pub fn semantic_horizon(&self) -> ExecutionHorizon {
        ExecutionHorizon {
            icount: Icount {
                retired: self.owner.semantic_horizon,
            },
        }
    }

    /// Returns the current finalized dispatch cap in node-local logical ticks.
    ///
    /// The scheduler can replan this physical cap after authenticated input
    /// settlement. Fresh planner bounds and the original semantic horizon
    /// constrain every wave; a backend cannot widen a previously issued cap.
    #[must_use]
    pub const fn dispatch_horizon(&self) -> ExecutionHorizon {
        self.dispatch_horizon
    }
}

impl PartialEq for PreparedRunAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.control_token() == other.control_token()
            && self.context() == other.context()
            && self.input_inventory.generation == other.input_inventory.generation
            && self.input_inventory.next_input == other.input_inventory.next_input
            && self.dispatch_horizon == other.dispatch_horizon
    }
}

impl Eq for PreparedRunAdmission {}

impl SingleScheduler {
    /// Prepares genuine scheduler admissions for an explicitly modeled fixture.
    ///
    /// This runs the ordinary scheduler preparation without dispatching a
    /// backend. Its records do not grant native Source or execution permission.
    ///
    /// # Errors
    ///
    /// Returns the scheduler's ordinary planning or inventory validation error.
    #[cfg(any(test, feature = "test-double"))]
    pub fn prepare_run_admissions_for_test(
        &self,
        maximum_runs: usize,
    ) -> Result<Vec<PreparedRunAdmission>, SchedulerError> {
        let prepared = self.prepare_host_concurrent_quantum_limited(
            QuantumRequest {
                configuration: self.configuration().clone(),
                control: Vec::new(),
            },
            maximum_runs,
        )?;
        Ok(prepared.runs.into_iter().map(|run| run.admission).collect())
    }

    pub(super) fn seal_prepared_run(
        &self,
        plan: &AdvancePlan,
        natural_horizon: u64,
        command: Option<&PreemptionDecision>,
        previous: Option<&PreparedRunAdmission>,
    ) -> Result<PreparedRunAdmission, SchedulerError> {
        let index = usize::try_from(plan.ceiling.sequence).map_err(|_| {
            admission_error("RUN publication sequence exceeds the actual table width")
        })?;
        let publication = self
            .ceiling_publications
            .get(index)
            .ok_or_else(|| admission_error("RUN admission has no actual published ceiling"))?;
        let node = self
            .nodes
            .get(plan.index)
            .ok_or_else(|| admission_error("RUN admission has no actual selected node"))?;
        if publication != &plan.ceiling
            || node.id != plan.node
            || node.counter != plan.before
            || plan.ceiling.node != plan.node
            || plan.ceiling.current_icount != plan.before
            || plan.ceiling.max_advance_icount != plan.target_counter
            || plan.target_counter <= plan.before.ticks
        {
            return Err(admission_error(
                "RUN admission differs from finalized planner state",
            ));
        }
        let revision = plan
            .ceiling
            .sequence
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| admission_error("RUN admission revision is exhausted"))?;
        let source = Arc::new(self.clone());
        let next_input = self.prepared_run_next_input(node)?;
        if next_input.is_some_and(|input| input <= plan.before) {
            return Err(admission_error(
                "RUN PICK has unresolved current or past input",
            ));
        }
        let semantic_horizon = command.map_or(natural_horizon, |command| {
            natural_horizon.min(command.at.ticks)
        });
        if semantic_horizon < plan.target_counter {
            return Err(admission_error(
                "RUN dispatch exceeds its natural or command horizon",
            ));
        }
        let retained = previous.filter(|previous| {
            let original = &previous.owner._source;
            previous.owner.plan.node == plan.node
                && previous.owner.command.as_ref() == command
                && plan.before >= previous.owner.plan.before
                && plan.before.ticks < previous.owner.semantic_horizon
                && plan.target_counter <= previous.owner.semantic_horizon
                && original.configuration == self.configuration
                && original.effective_topology == self.effective_topology
                && original.topology_epoch == self.topology_epoch
                && original.event_log.offset() == self.event_log.offset()
        });
        let owner = if let Some(previous) = retained {
            Arc::clone(&previous.owner)
        } else {
            // A changed immutable context is a new admitted RUN, never a
            // mutation of the previous owner or an equality-by-counter reuse.
            let edges = self
                .effective_topology
                .edges()
                .iter()
                .map(|edge| (&edge.from, &edge.to, edge.minimum_latency.ticks))
                .collect::<Vec<_>>();
            let material = serde_json::to_vec(&(
                self.configuration.id(),
                self.configuration.def.id(),
                edges,
                self.topology_epoch,
                self.event_log.offset(),
                &plan.ceiling,
                plan.quiescent_horizon,
                semantic_horizon,
                command,
                revision.get(),
            ))
            .map_err(|error| admission_error(&format!("RUN context encoding failed: {error}")))?;
            let hash = ContentHash::from_bytes(&material);
            let mut context = [0; 4];
            for (word, bytes) in context.iter_mut().zip(hash.bytes.as_chunks::<8>().0) {
                *word = u64::from_be_bytes(*bytes);
            }
            Arc::new(PreparedRunOwner {
                plan: plan.clone(),
                semantic_horizon,
                command: command.cloned(),
                control_token: revision,
                context,
                _source: Arc::clone(&source),
            })
        };
        Ok(PreparedRunAdmission {
            owner,
            input_inventory: PreparedRunInputInventory {
                generation: revision,
                next_input,
                _source: source,
            },
            dispatch_horizon: ExecutionHorizon {
                icount: Icount {
                    retired: plan.target_counter,
                },
            },
        })
    }

    pub(super) fn tighten_cap_boundary_admission(
        &mut self,
        run: &mut PreparedHostRun,
        tighter_cap: NodeCounter,
    ) -> Result<(), SchedulerError> {
        let node = self
            .nodes
            .get(run.plan.index)
            .ok_or_else(|| admission_error("cap readmission lost its actual scheduler node"))?;
        if node.id != run.plan.node || node.counter != run.plan.before {
            return Err(admission_error(
                "cap readmission changed its stopped scheduler owner",
            ));
        }
        let candidate = self
            .advance_candidate(
                run.plan.index,
                node,
                self.shared_rendezvous_cap()?,
                self.pending_topology_activation_cap()?,
            )?
            .ok_or_else(|| {
                admission_error("cap readmission has no current planner authorization")
            })?;
        let fresh = self.advance_plan_draft(&candidate)?;
        let target = tighter_cap.ticks.min(fresh.target_counter);
        if target <= run.plan.before.ticks || target >= run.plan.target_counter {
            return Err(admission_error(
                "cap readmission is not a strictly tighter future bound",
            ));
        }
        let next_input = self.prepared_run_next_input(node)?;
        if next_input.is_some_and(|input| input <= run.plan.before) {
            return Err(admission_error(
                "cap readmission has unresolved stopped input",
            ));
        }
        let time = self.node_time_for_counter(node, NodeCounter { ticks: target })?;
        let subdivision = self.planned_run_subdivision(&run.plan.node, run.plan.before, target)?;
        let publication =
            self.publish_run_ceiling(run.plan.node.clone(), run.plan.before, target, time)?;
        let revision = publication
            .sequence
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| admission_error("cap readmission revision exhausted"))?;
        let admission = PreparedRunAdmission {
            owner: Arc::clone(&run.admission.owner),
            input_inventory: PreparedRunInputInventory {
                generation: revision,
                next_input,
                _source: Arc::new(self.clone()),
            },
            dispatch_horizon: ExecutionHorizon {
                icount: Icount { retired: target },
            },
        };

        run.plan.target_counter = target;
        run.plan.projected_target_time = time;
        run.plan.ceiling = publication;
        run.plan.subdivision = subdivision;
        if target == fresh.target_counter {
            run.plan.quiescent_horizon = fresh.quiescent_horizon;
        }
        run.admission = admission;
        Ok(())
    }

    pub(super) fn prepared_run_next_input(
        &self,
        node: &RuntimeSchedulerNode,
    ) -> Result<Option<NodeCounter>, SchedulerError> {
        let mut times = Vec::new();
        for event in &self.pending_events {
            if event.key.consumer() == &node.id
                && matches!(
                    event.payload,
                    ScheduledEventPayload::BackendInput(_) | ScheduledEventPayload::IoCompletion(_)
                )
            {
                times.push(SimInstant {
                    ticks: event.key.virtual_time().ticks,
                });
            }
        }
        if !self.control_inbox.is_empty() {
            return Err(admission_error(
                "RUN input inventory has unadmitted control operations",
            ));
        }
        if let ExactLocalEvent::IoCompletion { virtual_time, .. } = node.exact_local_event {
            times.push(virtual_time);
        }
        if let Some(devices) = self.device_sub_nodes.get(&node.id.node) {
            for device in devices {
                if let Some(tick) = device.next_exact_local_event() {
                    times.push(
                        self.vm_delivery_time_for_tick(&node.id.node, SimInstant { ticks: tick })?,
                    );
                }
            }
        }
        // The planner's device horizon must still match the actual complete
        // device/link enumeration. A stale cache cannot mint known absence.
        let mut checked = self.clone();
        checked.refresh_device_horizons()?;
        if checked.device_horizons != self.device_horizons {
            return Err(admission_error(
                "RUN input inventory has stale device horizons",
            ));
        }
        // Link responses remain in the actual model queue until RESOLVE emits
        // their backend input; enumerate them before that materialization too.
        for runtime in self.world_network_links.values() {
            let destination = match runtime.direction {
                NetworkLinkDirection::EndpointAToEndpointB => &runtime.endpoint_b,
                NetworkLinkDirection::EndpointBToEndpointA => &runtime.endpoint_a,
            };
            if destination == &node.id.node {
                for pending in &runtime.link.snapshot().inflight {
                    times.push(self.network_time_for_tick(pending.key.delivery_icount));
                }
            }
        }
        times
            .into_iter()
            .map(|time| self.node_counter_for_time_floor(node, time))
            .collect::<Result<Vec<_>, _>>()
            .map(|values| values.into_iter().min())
    }
}

fn admission_error(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}
