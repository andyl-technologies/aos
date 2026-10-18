//! Nonexecution ownership for exact current-time input settlement.
//!
//! The actor selects an original due batch under complete queue observation.
//! The backend independently retains the actual Setup, Loaded or Stopped Source;
//! neither this modeled owner nor a backend result manufactures native authority.

use std::num::NonZeroU64;

use super::*;

#[derive(Clone, Debug)]
struct FixedInputOwner {
    node: SchedulerNodeId,
    at: NodeCounter,
    control_token: NonZeroU64,
    context: [u64; 4],
    events: Vec<ScheduledEvent>,
    source: Arc<SingleScheduler>,
}

/// Original scheduler-issued batch awaiting a stopped input consumer.
///
/// There is no public constructor. The record keeps the actual Configuration,
/// authored Plan, effective topology, event prefix and complete inventory alive.
/// It does not authorize RUN, retirement, clock movement or native publication.
#[derive(Clone, Debug)]
pub struct PreparedHostFixedInput {
    owner: Arc<FixedInputOwner>,
    inventory: PreparedRunInputInventory,
}

impl PreparedHostFixedInput {
    /// Returns the exact selected logical input consumer.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.owner.node.node
    }

    /// Returns the original stopped node-local logical coordinate.
    #[must_use]
    pub fn at(&self) -> NodeCounter {
        self.owner.at
    }

    /// Returns the checked actor token for this nonexecution owner.
    #[must_use]
    pub fn control_token(&self) -> NonZeroU64 {
        self.owner.control_token
    }

    /// Returns the immutable equality binding of the original due batch.
    #[must_use]
    pub fn context(&self) -> [u64; 4] {
        self.owner.context
    }

    /// Returns the exact canonical batch, including retained physical origins.
    #[must_use]
    pub fn events(&self) -> &[ScheduledEvent] {
        &self.owner.events
    }

    /// Returns the complete original inventory that selected this due batch.
    #[must_use]
    pub fn input_inventory(&self) -> &PreparedRunInputInventory {
        &self.inventory
    }
}

impl PartialEq for PreparedHostFixedInput {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }
}

impl Eq for PreparedHostFixedInput {}

/// Factual progress of a retained stopped input consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendFixedInputState {
    /// No completed publication has been acknowledged.
    Pending,
    /// An exact prefix has been consumed and the unread suffix remains owned.
    Partial,
    /// The native Source has resealed but publication remains owed.
    Resealed,
    /// The actual source-bound publication witness is complete.
    Published,
}

/// Observation returned by the independently authenticated fixed-input backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendFixedInputResult {
    /// Exact original borrowed scheduler owner, never a reconstructed scalar.
    pub prepared: PreparedHostFixedInput,
    /// Number of fully consumed canonical events in the original prefix.
    ///
    /// The backend maps actual directed-inbox frontiers to event boundaries;
    /// this count is not a native entry index or decoder-produced generation.
    pub consumed: usize,
    /// Factual native consumer disposition, without execution completion.
    pub state: BackendFixedInputState,
}

impl SingleScheduler {
    pub(super) fn prepare_current_fixed_input(
        &mut self,
        published_consumers: &BTreeSet<NodeId>,
    ) -> Result<Option<PreparedHostFixedInput>, SchedulerError> {
        if self.fixed_input_in_progress {
            return Err(fixed_input_error("fixed input owner is already retained"));
        }
        let mut selected = Vec::new();
        for event in &self.pending_events {
            let index = self.vm_node_index(&event.key.consumer().node)?;
            let node = &self.nodes[index];
            if event.key.consumer() != &node.id {
                return Err(fixed_input_error(
                    "fixed input targets a different scheduler node kind",
                ));
            }
            let now = self.node_time_for_counter(node, node.counter)?;
            if event.key.virtual_time().ticks < now.ticks {
                return Err(fixed_input_error(
                    "fixed input contains a past unresolved delivery",
                ));
            }
            if event.key.virtual_time().ticks == now.ticks {
                if matches!(event.payload, ScheduledEventPayload::Control(_)) {
                    return Err(fixed_input_error(
                        "fixed input cannot consume a control command",
                    ));
                }
                selected.push(event.clone());
            }
        }
        selected.sort_by(|left, right| left.key.cmp(&right.key));
        let Some(first) = selected.first() else {
            return Ok(None);
        };
        if !self.control_inbox.is_empty() {
            return Err(fixed_input_error(
                "fixed input requires the admitted control boundary to drain",
            ));
        }
        let consumer = first.key.consumer().clone();
        // Refusal must precede generation reservation and owner creation. The
        // caller cannot retain a newly minted owner after this repeated batch.
        if published_consumers.contains(&consumer.node) {
            return Err(fixed_input_error(
                "current-T consumer repeated before a new scheduler call",
            ));
        }
        selected.retain(|event| event.key.consumer() == &consumer);
        let index = self.vm_node_index(&consumer.node)?;
        let at = self.nodes[index].counter;
        if !self.imported_io.contains_key(&consumer.node) {
            return Err(fixed_input_error(
                "fixed input lacks the complete current physical inventory",
            ));
        }
        let generation = self
            .fixed_input_generation
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| fixed_input_error("fixed input actor generation exhausted"))?;
        let edges = self
            .effective_topology
            .edges()
            .iter()
            .map(|edge| (&edge.from, &edge.to, edge.minimum_latency.ticks))
            .collect::<Vec<_>>();
        let material = serde_json::to_vec(&(
            "crucible.scheduler.fixed-input.v1",
            self.configuration.id(),
            self.configuration.def.id(),
            edges,
            self.topology_epoch,
            self.event_log.offset(),
            &consumer,
            at,
            generation,
            &selected,
        ))
        .map_err(|error| {
            fixed_input_error(&format!("fixed input context encoding failed: {error}"))
        })?;
        let digest = ContentHash::from_bytes(&material);
        let mut context = [0; 4];
        for (word, bytes) in context.iter_mut().zip(digest.bytes.as_chunks::<8>().0) {
            *word = u64::from_be_bytes(*bytes);
        }
        self.fixed_input_generation = generation.get();
        let source = Arc::new(self.clone());
        let inventory = PreparedRunInputInventory::fixed_input(Arc::clone(&source), generation, at);
        let owner = Arc::new(FixedInputOwner {
            node: consumer,
            at,
            control_token: generation,
            context,
            events: selected,
            source,
        });
        self.fixed_input_in_progress = true;
        Ok(Some(PreparedHostFixedInput { owner, inventory }))
    }

    pub(super) fn validate_current_fixed_input(
        &self,
        prepared: &PreparedHostFixedInput,
    ) -> Result<(), SchedulerError> {
        let source = &prepared.owner.source;
        if !self.fixed_input_in_progress
            || self.fixed_input_generation != prepared.control_token().get()
        {
            return Err(fixed_input_error("fixed input owner is not registered"));
        }
        let mut current = self.clone();
        current.fixed_input_in_progress = false;
        let checkpoint = current
            .checkpoint()
            .and_then(|checkpoint| checkpoint.canonical_bytes())
            .map_err(|error| {
                fixed_input_error(&format!(
                    "fixed input actor state cannot be checked: {error}"
                ))
            })?;
        let original = source
            .checkpoint()
            .and_then(|checkpoint| checkpoint.canonical_bytes())
            .map_err(|error| {
                fixed_input_error(&format!(
                    "fixed input original state cannot be checked: {error}"
                ))
            })?;
        if checkpoint != original
            || self.attempt_stop_frontier_cap != source.attempt_stop_frontier_cap
            || self.inventory_world.as_ref().map(|world| world.id())
                != source.inventory_world.as_ref().map(|world| world.id())
        {
            return Err(fixed_input_error(
                "fixed input owner no longer matches its original actor source",
            ));
        }
        Ok(())
    }

    pub(super) fn finish_current_fixed_input(
        &mut self,
        prepared: &PreparedHostFixedInput,
    ) -> Result<(), SchedulerError> {
        self.validate_current_fixed_input(prepared)?;
        let mut staged = self.clone();
        for event in prepared.events() {
            staged.record_imported_io_publication(event)?;
        }
        let keys = prepared
            .events()
            .iter()
            .map(|event| &event.key)
            .collect::<BTreeSet<_>>();
        staged
            .pending_events
            .retain(|event| !keys.contains(&event.key));
        staged
            .settled_fixed_input_events
            .extend_from_slice(prepared.events());
        staged
            .settled_fixed_input_events
            .sort_by(|left, right| left.key.cmp(&right.key));
        staged.fixed_input_in_progress = false;
        *self = staged;
        Ok(())
    }
}

pub(super) fn fixed_input_error(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}
