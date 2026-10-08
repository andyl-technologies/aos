//! Construction, inspection, and initial admission of resolved block-fault state.
//!
//! Child modules own request-phase opportunities and continuations, array rebuild,
//! transport recovery, and complete checkpoint validation. Observation wrappers
//! retain the revision boundary around those mutations.

use super::*;

mod execution_services;
mod resource_usage;

pub use execution_services::BlockExecutionServiceSummary;

mod array_rebuild;
mod request_continuations;
mod request_opportunities;
mod restore_validation;
mod transport_recovery;

impl BlockFaultState {
    /// Creates fault-free write-through state for a device.
    #[must_use]
    pub fn write_through(length_bytes: u64) -> Self {
        Self {
            observation_revision: std::num::NonZeroU64::MIN,
            observation_mutation_active: false,
            observation_external_effect: false,
            observation_changed: false,
            config: BlockDurabilityConfig::write_through(length_bytes),
            transport_epoch: None,
            retired_transport_epochs: BTreeMap::new(),
            retry_preserve_authorizations: BTreeSet::new(),
            recovery_until_ticks: None,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            service: BlockServiceState::default(),
            service_pending: BTreeMap::new(),
            service_pending_bytes: 0,
            service_outcomes: Vec::new(),
            storage_outcome_order: Vec::new(),
            execution_opportunities_required: false,
            execution_pending: BTreeMap::new(),
            execution_pending_bytes: 0,
            request_persistence_pending: BTreeMap::new(),
            request_persistence_pending_bytes: 0,
            delivery_pending: BTreeMap::new(),
            delivery_pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            media_queue: BTreeMap::new(),
            media_queue_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            media: BlockMediaState::default(),
            flash: BlockFlashState::default(),
            persistence_execution_required: false,
            pending_persistence_media: BTreeMap::new(),
            persistence_media_outcomes: Vec::new(),
            persistence: BlockPersistenceGraph::new(),
            pending_barrier_frontier: None,
            pending_honest_flush_frontier: None,
            next_cache_sequence: 0,
            next_cache_access_sequence: 0,
            next_version_sequence: 0,
            first_lost_sequence: None,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
            array_dirty_ranges: BTreeMap::new(),
            array_rebuild: BlockArrayRebuildCursor::default(),
        }
    }

    /// Reports whether accepted storage mutation remains outside durable media.
    ///
    /// This excludes request-phase and delivery queues: callers can combine it
    /// with transport quiescence to identify a checkpoint boundary at which the
    /// guest-visible operation has completed but controller, cache, or media
    /// work must still survive in the host continuation.
    #[must_use]
    pub fn has_pending_durability_continuation(&self) -> bool {
        !self.controller.is_empty()
            || !self.media_queue.is_empty()
            || !self.volatile.is_empty()
            || !self.pending_persistence_media.is_empty()
            || self.pending_barrier_frontier.is_some()
            || self.pending_honest_flush_frontier.is_some()
    }

    /// Creates a validated fault-free write-through state.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when `config` violates geometry or hard bounds.
    pub fn new(config: BlockDurabilityConfig) -> Result<Self, DeviceError> {
        config.validate()?;
        let persistence = BlockPersistenceGraph::with_edge_limit(
            usize::try_from(config.persistence_dependencies).unwrap_or(usize::MAX),
        )?;
        Ok(Self {
            observation_revision: std::num::NonZeroU64::MIN,
            observation_mutation_active: false,
            observation_external_effect: false,
            observation_changed: false,
            config,
            transport_epoch: None,
            retired_transport_epochs: BTreeMap::new(),
            retry_preserve_authorizations: BTreeSet::new(),
            recovery_until_ticks: None,
            execution_required: false,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            service: BlockServiceState::default(),
            service_pending: BTreeMap::new(),
            service_pending_bytes: 0,
            service_outcomes: Vec::new(),
            storage_outcome_order: Vec::new(),
            execution_opportunities_required: false,
            execution_pending: BTreeMap::new(),
            execution_pending_bytes: 0,
            request_persistence_pending: BTreeMap::new(),
            request_persistence_pending_bytes: 0,
            delivery_pending: BTreeMap::new(),
            delivery_pending_bytes: 0,
            controller: BTreeMap::new(),
            controller_bytes: 0,
            media_queue: BTreeMap::new(),
            media_queue_bytes: 0,
            volatile: BTreeMap::new(),
            volatile_bytes: 0,
            retained: BTreeMap::new(),
            media: BlockMediaState::default(),
            flash: BlockFlashState::default(),
            persistence_execution_required: false,
            pending_persistence_media: BTreeMap::new(),
            persistence_media_outcomes: Vec::new(),
            persistence,
            pending_barrier_frontier: None,
            pending_honest_flush_frontier: None,
            next_cache_sequence: 0,
            next_cache_access_sequence: 0,
            next_version_sequence: 0,
            first_lost_sequence: None,
            actual_durable_frontier: 0,
            reported_durable_frontier: 0,
            retained_completions: BTreeMap::new(),
            array_dirty_ranges: BTreeMap::new(),
            array_rebuild: BlockArrayRebuildCursor::default(),
        })
    }

    /// Enables or disables the fail-closed requirement for exact directives.
    pub(super) fn require_directives_untracked(&mut self, required: bool) {
        observed_set!(self, execution_required, required);
    }

    /// Returns whether no request, mutation, or sequence has entered this state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.transport_epoch.is_none()
            && self.retired_transport_epochs.is_empty()
            && self.retry_preserve_authorizations.is_empty()
            && self.recovery_until_ticks.is_none()
            && self.pending.is_empty()
            && self.pending_bytes == 0
            && self.service.continuations().is_empty()
            && self.service_pending.is_empty()
            && self.service_pending_bytes == 0
            && self.service_outcomes.is_empty()
            && self.storage_outcome_order.is_empty()
            && self.execution_pending.is_empty()
            && self.execution_pending_bytes == 0
            && self.request_persistence_pending.is_empty()
            && self.request_persistence_pending_bytes == 0
            && self.delivery_pending.is_empty()
            && self.delivery_pending_bytes == 0
            && self.controller.is_empty()
            && self.controller_bytes == 0
            && self.media_queue.is_empty()
            && self.media_queue_bytes == 0
            && self.volatile.is_empty()
            && self.volatile_bytes == 0
            && self.retained.is_empty()
            && self.media.rules().is_empty()
            && self.flash.continuations().is_empty()
            && self.pending_persistence_media.is_empty()
            && self.persistence_media_outcomes.is_empty()
            && self.persistence.nodes().is_empty()
            && self.pending_barrier_frontier.is_none()
            && self.pending_honest_flush_frontier.is_none()
            && self.retained_completions.is_empty()
            && self.array_dirty_ranges.is_empty()
            && self.array_rebuild == BlockArrayRebuildCursor::default()
            && self.next_cache_sequence == 0
            && self.next_cache_access_sequence == 0
            && self.next_version_sequence == 0
            && self.first_lost_sequence.is_none()
            && self.actual_durable_frontier == 0
            && self.reported_durable_frontier == 0
    }

    /// Returns the epoch authenticated by the live block transport, if any.
    #[must_use]
    pub const fn transport_epoch(&self) -> Option<u64> {
        self.transport_epoch
    }

    /// Returns the exclusive simulation-tick recovery deadline, if active.
    #[must_use]
    pub const fn recovery_until_ticks(&self) -> Option<u64> {
        self.recovery_until_ticks
    }

    /// Enables fail-closed resolution at each physical persistence opportunity.
    pub(super) fn require_persistence_media_directives_untracked(&mut self, required: bool) {
        observed_set!(self, persistence_execution_required, required);
    }

    /// Returns the first ready physical persistence opportunity in canonical order.
    #[must_use]
    pub fn next_persistence_opportunity(
        &self,
        now_ticks: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        self.media_queue
            .keys()
            .filter(|sequence| self.persistence.is_ready_at(**sequence, now_ticks))
            .filter(|sequence| !self.pending_persistence_media.contains_key(sequence))
            .filter_map(|sequence| {
                self.persistence
                    .writeback_key(*sequence)
                    .map(|key| (key, *sequence))
            })
            .min_by_key(|(key, _sequence)| *key)
            .and_then(|(_key, sequence)| self.persistence_opportunity(sequence))
    }

    /// Installs the exact media directive for one ready persistence opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for stale/mismatched opportunity identity,
    /// duplicate installation, invalid flash rules, or bounded-state exhaustion.
    pub(super) fn install_persistence_media_directive_untracked(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        self.validate_persistence_media_directive(&directive)?;
        if self.pending_persistence_media.len() == HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_persistence_media",
                hard: HARD_BLOCK_PERSISTENCE_MEDIA_EVENTS,
            });
        }
        let sequence = directive.opportunity.sequence;
        if self.pending_persistence_media.contains_key(&sequence) {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "duplicate persistence-media directive",
            });
        }
        let mut next = self.clone();
        next.flash
            .register_rules(self.config.length_bytes, &directive.flash_rules)?;
        observed_insert!(next, pending_persistence_media, sequence, directive);
        *self = next;
        Ok(())
    }

    /// Returns checkpointed sparse flash counters and changed-cell state.
    #[must_use]
    pub const fn flash_state(&self) -> &BlockFlashState {
        &self.flash
    }

    /// Drains completed persistence-media evidence after durable event recording.
    pub(super) fn drain_persistence_media_outcomes_untracked(
        &mut self,
    ) -> Vec<BlockPersistenceMediaOutcome> {
        observed_retain!(self, storage_outcome_order, |outcome| matches!(
            outcome,
            BlockStorageOutcomeRef::Service(_)
        ));
        observed_take!(self, persistence_media_outcomes)
    }

    /// Borrows completed physical-media outcomes without acknowledging them.
    #[must_use]
    pub fn persistence_media_outcomes(&self) -> &[BlockPersistenceMediaOutcome] {
        &self.persistence_media_outcomes
    }

    /// Returns every pending storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when checkpointed outcome-order state contains
    /// an invalid reference.
    pub fn storage_outcomes(&self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_outcome_order
            .iter()
            .map(|outcome| match *outcome {
                BlockStorageOutcomeRef::Service(index) => self
                    .service_outcomes
                    .get(index)
                    .copied()
                    .map(BlockStorageOutcome::Service),
                BlockStorageOutcomeRef::Persistence(index) => self
                    .persistence_media_outcomes
                    .get(index)
                    .cloned()
                    .map(BlockStorageOutcome::Persistence),
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "storage outcome order contains an invalid index",
            })
    }

    /// Drains every storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutation when checkpointed outcome-order
    /// state contains an invalid reference.
    pub(super) fn drain_storage_outcomes_untracked(
        &mut self,
    ) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        let outcomes = self.storage_outcomes()?;
        observed_clear!(self, storage_outcome_order);
        observed_clear!(self, service_outcomes);
        observed_clear!(self, persistence_media_outcomes);
        Ok(outcomes)
    }

    /// Installs one directive, keyed by the exact guest request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate IDs or a hard pending-state limit.
    pub(super) fn install_untracked(
        &mut self,
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        directive.validate_static(identity.request_id, &self.config)?;
        if directive.request_epoch != identity.epoch {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block fault directive epoch differs from its installation identity",
            });
        }
        if self.pending.len() == HARD_PENDING_BLOCK_FAULT_DIRECTIVES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directives",
                hard: HARD_PENDING_BLOCK_FAULT_DIRECTIVES,
            });
        }
        if self.pending.contains_key(&identity) {
            return Err(DeviceError::DuplicateBlockFaultDirective {
                request_id: identity.request_id,
            });
        }
        let bytes = directive_owned_bytes(&directive)?;
        let next_bytes =
            self.pending_bytes
                .checked_add(bytes)
                .ok_or(DeviceError::BlockFaultStateLimit {
                    field: "pending_directive_bytes",
                    hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
                })?;
        if next_bytes > HARD_PENDING_BLOCK_FAULT_BYTES {
            return Err(DeviceError::BlockFaultStateLimit {
                field: "pending_directive_bytes",
                hard: usize::try_from(HARD_PENDING_BLOCK_FAULT_BYTES).unwrap_or(usize::MAX),
            });
        }
        observed_insert!(self, pending, identity, directive);
        observed_set!(self, pending_bytes, next_bytes);
        Ok(())
    }

    /// Returns the immutable durability configuration.
    #[must_use]
    pub const fn config(&self) -> &BlockDurabilityConfig {
        &self.config
    }

    /// Returns volatile entries in cache sequence order.
    #[must_use]
    pub const fn volatile_entries(&self) -> &BTreeMap<u64, BlockVolatileEntry> {
        &self.volatile
    }

    /// Returns canonical cache-loss candidates for the requested protection scope.
    ///
    /// When `include_protected` is false, entries admitted under a
    /// power-loss-protected policy are excluded. A protection-failure impulse
    /// passes true and receives every live sequence.
    #[must_use]
    pub fn volatile_loss_candidates(&self, include_protected: bool) -> Vec<u64> {
        self.volatile
            .iter()
            .filter_map(|(sequence, entry)| {
                (include_protected || !entry.power_loss_protected).then_some(*sequence)
            })
            .collect()
    }

    /// Returns the canonical digest of the complete live volatile-cache entry set.
    #[must_use]
    pub fn volatile_entries_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-volatile-entry-set.v2\0");
        for (sequence, entry) in &self.volatile {
            hasher.update(&sequence.to_be_bytes());
            hasher.update(&entry.request_id.to_be_bytes());
            hasher.update(&[entry.media_identity.operation.to_wire()]);
            hasher.update(&entry.media_identity.operation_sequence.to_be_bytes());
            hasher.update(&entry.media_identity.request_digest);
            hasher.update(&entry.media_identity.request_offset.to_be_bytes());
            hasher.update(&entry.media_identity.request_count.to_be_bytes());
            hasher.update(&entry.offset.to_be_bytes());
            hasher.update(
                &u64::try_from(entry.bytes.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(blake3::hash(&entry.bytes).as_bytes());
            hasher.update(&entry.last_access_sequence.to_be_bytes());
            hasher.update(&[u8::from(entry.power_loss_protected)]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Returns controller-accepted writes in global sequence order.
    #[must_use]
    pub const fn controller_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.controller
    }

    /// Returns writes admitted to the durable-media service queue.
    #[must_use]
    pub const fn media_queue_entries(&self) -> &BTreeMap<u64, BlockControllerEntry> {
        &self.media_queue
    }

    /// Returns the complete live persistence dependency graph.
    #[must_use]
    pub const fn persistence_graph(&self) -> &BlockPersistenceGraph {
        &self.persistence
    }

    /// Drains persistence graph mutations after canonical event recording.
    pub(super) fn drain_persistence_transformation_evidence_untracked(
        &mut self,
    ) -> Vec<crate::block::persistence::BlockPersistenceTransformationEvidence> {
        observed_drain!(self, self.persistence.drain_transformation_evidence())
    }

    /// Returns retained versions in version sequence order.
    #[must_use]
    pub const fn retained_versions(&self) -> &BTreeMap<u64, BlockRetainedVersion> {
        &self.retained
    }

    /// Returns checkpointed media overlays and activation counters.
    #[must_use]
    pub const fn media_state(&self) -> &BlockMediaState {
        &self.media
    }
}
