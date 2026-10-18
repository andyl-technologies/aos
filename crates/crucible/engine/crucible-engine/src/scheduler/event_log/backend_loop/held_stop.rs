//! Explicit settlement of committed guest stops and their held peer evidence.
//!
//! The opaque witness binds a canonical committed stop to its controller epoch
//! and offered configuration/log prefix. It is host metadata, not permission to
//! reply to a guest: the backend's complete token and paused grid must also be
//! authenticated before an external transition or marker release.

use super::host_concurrent::{HeldHostContinuation, validate_host_run_outcome};
use super::*;
use crate::BackendPhysicalStop;

/// The guest authority that must explicitly release one committed physical stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldHostStopKind {
    /// A retained guest selectable requires an authenticated host reply.
    GuestSelectable,
    /// A retained campaign marker requires its committed atomic choice release.
    CampaignMarker,
}

impl HeldHostStopKind {
    pub(super) const fn from_physical_stop(stop: BackendPhysicalStop) -> Option<Self> {
        match stop {
            BackendPhysicalStop::GuestSelectable => Some(Self::GuestSelectable),
            BackendPhysicalStop::CampaignMarker => Some(Self::CampaignMarker),
            _ => None,
        }
    }
}

// This private capability belongs to one live host controller. It never enters
// a checkpoint, canonical event log, serialized payload, or process protocol.
// Witness ownership retains the allocation, preventing identity reuse after
// whole-world teardown while an old witness can still be presented.
#[derive(Clone, Debug)]
pub(super) struct HeldHostStopController(std::sync::Arc<()>);

impl HeldHostStopController {
    pub(super) fn new() -> Self {
        Self(std::sync::Arc::new(()))
    }
}

impl PartialEq for HeldHostStopController {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HeldHostStopController {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommittedHostStop {
    pub(super) node: SchedulerNodeId,
    pub(super) node_index: usize,
    pub(super) run_generation: u64,
    pub(super) controller_generation: u64,
    pub(super) physical_pause: VirtualTime,
    pub(super) kind: HeldHostStopKind,
}

/// An opaque witness for the single canonical guest stop already committed.
///
/// Later physically completed peer stops remain private until this source is
/// explicitly released. This witness neither synthesizes a pause coordinate
/// nor authorizes a backend reply or an application receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldHostStopWitness {
    controller: HeldHostStopController,
    stop: CommittedHostStop,
    offer_configuration: Configuration,
    offer_log_offset: EventLogOffset,
}

impl HeldHostStopWitness {
    /// Returns the exact scheduler node that owns the committed stop.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.stop.node.node
    }

    /// Returns the independently observed physical pause coordinate.
    #[must_use]
    pub const fn physical_pause(&self) -> VirtualTime {
        self.stop.physical_pause
    }

    /// Returns the explicit guest authority required for settlement.
    #[must_use]
    pub const fn kind(&self) -> HeldHostStopKind {
        self.stop.kind
    }
}

fn rejected(message: impl Into<String>) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.into(),
    }
}

fn validate_held_peers(
    scheduler: &SingleScheduler,
    state: &HeldHostContinuation,
) -> Result<(), SchedulerError> {
    if scheduler.effective_topology != state.topology
        || state.runs.len() + state.boundary_runs.len() > scheduler.nodes.len()
    {
        return Err(rejected(
            "held physical RUN topology or peer cardinality changed",
        ));
    }
    for (node, held) in &state.runs {
        let runtime = scheduler.nodes.get(held.run.plan.index).ok_or_else(|| {
            rejected(format!("held peer `{}` lost its scheduler node", node.name))
        })?;
        if held.run.plan.node.node != *node
            || held.completed.node != *node
            || runtime.id != held.run.plan.node
            || runtime.counter != held.run.plan.before
            || state.generations.get(node) != Some(&held.generation)
        {
            return Err(rejected(format!(
                "held peer `{}` changed node, generation, or before counter",
                node.name
            )));
        }
        validate_host_run_outcome(&held.run, &held.completed)?;
    }
    for (node, held) in &state.boundary_runs {
        let runtime = scheduler
            .nodes
            .get(held.run.plan.index)
            .ok_or_else(|| rejected("held input lost its actual scheduler node"))?;
        if held.run.plan.node.node != *node
            || runtime.id != held.run.plan.node
            || runtime.counter != held.run.plan.before
            || state.generations.get(node) != Some(&held.generation)
        {
            return Err(rejected("held input node/generation changed"));
        }
        held.boundary.validate(&held.run)?;
    }
    Ok(())
}

impl<B, I> BackendQuantumLoop<SingleScheduler, B, I> {
    /// Reports whether physical evidence still awaits an explicit settlement.
    ///
    /// This remains true for a zero-peer guest stop and for a poisoned hold.
    #[must_use]
    pub fn has_unsettled_host_continuation(&self) -> bool {
        self.continuation_poisoned || self.held_host_continuation.is_some()
    }

    /// Poisons a failed logical settlement before another RUN or checkpoint.
    ///
    /// Held evidence remains retained for whole-world teardown and diagnostics;
    /// this operation never replies, resumes, drains peers, or creates receipts.
    pub fn abort_host_stop_settlement(&mut self) {
        self.continuation_poisoned = true;
    }

    /// Returns the committed canonical guest stop, when it can be offered.
    ///
    /// A same-source network preselection must settle first. Physically held
    /// later peers never become candidates through this query.
    #[must_use]
    pub fn held_host_stop_witness(&self) -> Option<HeldHostStopWitness> {
        if self.continuation_poisoned || self.preselection.is_some() {
            return None;
        }
        let state = self.held_host_continuation.as_ref()?;
        Some(HeldHostStopWitness {
            controller: self.held_stop_controller.clone(),
            stop: state.source_stop.clone()?,
            offer_configuration: state.offer_configuration.clone(),
            offer_log_offset: state.offer_log_offset,
        })
    }

    fn validate_stop_identity(&self, witness: &HeldHostStopWitness) -> Result<(), SchedulerError> {
        if self.continuation_poisoned || self.preselection.is_some() {
            return Err(rejected(
                "guest stop cannot cross a poisoned or unresolved network continuation",
            ));
        }
        let state = self
            .held_host_continuation
            .as_ref()
            .ok_or_else(|| rejected("no committed guest stop is held"))?;
        if self.held_stop_controller != witness.controller
            || state.source_stop.as_ref() != Some(&witness.stop)
            || self.held_stop_generation != witness.stop.controller_generation
            || state.offer_configuration != witness.offer_configuration
            || state.offer_log_offset != witness.offer_log_offset
            || state.generations.get(witness.node()) != Some(&witness.stop.run_generation)
            || (state.runs.contains_key(witness.node())
                || state.boundary_runs.contains_key(witness.node()))
        {
            return Err(rejected(
                "guest stop witness differs from its controller generation or offer prefix",
            ));
        }
        let runtime = self
            .loop_impl
            .nodes
            .get(witness.stop.node_index)
            .ok_or_else(|| rejected("committed guest stop lost its scheduler node"))?;
        if runtime.id != witness.stop.node
            || runtime.counter.ticks != witness.physical_pause().ticks
        {
            return Err(rejected(
                "committed guest stop changed node identity or physical counter",
            ));
        }
        validate_held_peers(&self.loop_impl, state)
    }

    /// Validates a source witness before any external selection or release.
    ///
    /// # Errors
    ///
    /// Rejects an absent, poisoned, changed-generation, changed-prefix, or moved
    /// source, unresolved network preselection, or changed held peer evidence.
    pub fn validate_held_host_stop(
        &self,
        witness: &HeldHostStopWitness,
    ) -> Result<(), SchedulerError> {
        self.validate_stop_identity(witness)?;
        if self.loop_impl.configuration() != &witness.offer_configuration
            || self.loop_impl.event_log_offset() != witness.offer_log_offset
        {
            return Err(rejected(
                "scheduler prefix differs from the offered guest stop",
            ));
        }
        Ok(())
    }

    /// Rebinds the hold after a successfully committed external transition.
    ///
    /// The caller first validates this exact witness and authenticates the full
    /// backend token/grid. This method changes no backend control or receipt and
    /// does not release the guest or publish its peers.
    ///
    /// # Errors
    ///
    /// Rejects a changed source, controller, prior offer, or peer, a replaced
    /// scenario definition, or an event-log/schedule prefix rollback.
    pub fn refresh_held_host_stop_prefix_after_transition(
        &mut self,
        witness: &HeldHostStopWitness,
    ) -> Result<(), SchedulerError> {
        self.validate_stop_identity(witness)?;
        let current = self.loop_impl.configuration();
        let offset = self.loop_impl.event_log_offset();
        if current.def != witness.offer_configuration.def
            || !current
                .schedule
                .decisions()
                .starts_with(witness.offer_configuration.schedule.decisions())
            || offset.events < witness.offer_log_offset.events
            || offset.bytes < witness.offer_log_offset.bytes
        {
            return Err(rejected(
                "external guest transition replaced or rolled back its offered prefix",
            ));
        }
        let configuration = current.clone();
        let state = self
            .held_host_continuation
            .as_mut()
            .ok_or_else(|| rejected("guest stop vanished after its external transition"))?;
        state.offer_configuration = configuration;
        state.offer_log_offset = offset;
        Ok(())
    }
}

impl<B, I> BackendQuantumLoop<SingleScheduler, B, I>
where
    B: ConcurrentSimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
{
    /// Explicitly releases one authenticated source and settles its causal peers.
    ///
    /// The release callback authenticates the complete backend token/grid and
    /// performs its atomic selection/reply or verified marker release. A failed
    /// callback retains all held evidence. Successful release permits necessary
    /// causal catch-up; a new guest stop retains the remaining peers again.
    /// Returned outcomes must be published once through the lifecycle pipeline
    /// before another guest offer, checkpoint, or physical RUN is admitted.
    ///
    /// # Errors
    ///
    /// Rejects a stale witness or peer, failed release, invalid committed prefix,
    /// or failed subsequent causal publication. A prefix mutation on a failed
    /// release or failure after successful release poisons the continuation.
    pub fn settle_held_host_stop<T>(
        &mut self,
        witness: &HeldHostStopWitness,
        release: impl FnOnce(&mut SingleScheduler, &mut B, &mut I) -> Result<T, SchedulerError>,
    ) -> Result<(T, Vec<QuantumOutcome>), SchedulerError> {
        self.validate_held_host_stop(witness)?;
        let frozen_outputs = self.pending_network_output_times_for_node(witness.node())?;
        let released = release(
            &mut self.loop_impl,
            &mut self.backend,
            &mut self.network_output_interceptor,
        );
        let released = match released {
            Ok(released) => released,
            Err(error) => {
                if self.loop_impl.configuration() != &witness.offer_configuration
                    || self.loop_impl.event_log_offset() != witness.offer_log_offset
                {
                    self.continuation_poisoned = true;
                }
                return Err(error);
            }
        };
        self.retain_pending_network_output_times(witness.node(), frozen_outputs);
        if let Err(error) = self.refresh_held_host_stop_prefix_after_transition(witness) {
            return Err(self.poison_continuation(error));
        }

        let mut state = self.held_host_continuation.take().ok_or_else(|| {
            self.poison_continuation(rejected("released guest stop lost its held evidence"))
        })?;
        state.source_stop = None;
        let backup = state.clone();
        let scheduler = self.loop_impl.clone();
        match self.publish_held_host_continuation(scheduler, state) {
            Ok(outcomes) => Ok((released, outcomes)),
            Err(error) => {
                self.held_host_continuation = Some(backup);
                Err(self.poison_continuation(error))
            }
        }
    }
}
