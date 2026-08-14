//! Block construction, configuration, opportunities, and storage outcomes.

use super::*;

impl BlockDevice {
    /// Builds a block device over `base` with the given core and latency model.
    ///
    /// The base image is held read-only and never mutated ([IO-5]); the overlay
    /// starts empty so every read falls through to the base.
    #[must_use]
    pub fn new(core: IoCore, base: BaseImage, latency: BlockLatency) -> Self {
        let mut storage_faults = BlockFaultState::write_through(base.len());
        storage_faults.set_icount_shift(core.shift_bits());
        Self {
            core,
            base,
            overlay: CowOverlay::new(),
            storage_faults,
            latency,
        }
    }

    /// Returns the device length in bytes (the base image size, [IO-6]).
    #[must_use]
    pub fn length(&self) -> u64 {
        self.base.len()
    }

    /// Returns the BLAKE3 content hash of the read-only base image.
    #[must_use]
    pub fn base_hash(&self) -> [u8; 32] {
        self.base.hash()
    }

    /// Returns a shared reference to the composed [`IoCore`].
    #[must_use]
    pub fn core(&self) -> &IoCore {
        &self.core
    }

    /// Returns a mutable reference to the composed [`IoCore`].
    ///
    /// Use this to reach the full uniform lifecycle (`enqueue_request`,
    /// `process_inbox`, `advance_to`, `pop_response`, `next_exact_local_event`)
    /// when the convenience wrappers are not enough.
    pub fn core_mut(&mut self) -> &mut IoCore {
        &mut self.core
    }

    /// Returns the deterministic completion-latency model.
    #[must_use]
    pub const fn latency_model(&self) -> &BlockLatency {
        &self.latency
    }

    /// Replaces the deterministic latency model for future request admissions.
    ///
    /// Responses already in flight retain their computed delivery coordinates;
    /// the replacement applies when subsequent requests are admitted. The active
    /// model is included in [`Self::snapshot`] and therefore survives restore.
    pub fn set_latency_model(&mut self, latency: BlockLatency) {
        self.latency = latency;
    }

    /// Returns a read-only view of the copy-on-write overlay.
    #[must_use]
    pub fn overlay(&self) -> &CowOverlay {
        &self.overlay
    }

    /// Returns checkpointed durability and resolved fault state.
    #[must_use]
    pub const fn storage_fault_state(&self) -> &BlockFaultState {
        &self.storage_faults
    }

    /// Restores an exact trusted storage-fault state during host transaction rollback.
    pub fn restore_storage_fault_state(&mut self, state: BlockFaultState) {
        self.storage_faults = state;
    }

    /// Replaces durability configuration before request execution begins.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the configuration is invalid or does not
    /// describe the exact bound base image.
    pub fn configure_storage_faults(
        &mut self,
        config: BlockDurabilityConfig,
        require_directives: bool,
    ) -> Result<(), DeviceError> {
        if config.length_bytes != self.base.len()
            || !self.storage_faults.is_pristine()
            || self.overlay.page_count() != 0
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "storage durability must be configured before device mutation",
            });
        }
        let mut state = BlockFaultState::new(config)?;
        state.set_icount_shift(self.core.shift_bits());
        state.require_directives(require_directives);
        self.storage_faults = state;
        Ok(())
    }

    /// Enables fail-closed staged resolve/persist opportunities.
    ///
    /// This must be selected before any request or storage mutation enters the
    /// device so checkpoints never mix direct and staged request semantics.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] unless the block and durability state are pristine.
    pub fn require_storage_execution_opportunities(&mut self) -> Result<(), DeviceError> {
        if !self.storage_faults.is_pristine() || self.overlay.page_count() != 0 {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "staged storage execution must be configured before device mutation",
            });
        }
        self.storage_faults.require_execution_opportunities(true);
        Ok(())
    }

    /// Enables fail-closed physical-media opportunities before device mutation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] unless the block and durability state are pristine.
    pub fn require_storage_persistence_media_opportunities(&mut self) -> Result<(), DeviceError> {
        if !self.storage_faults.is_pristine() || self.overlay.page_count() != 0 {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "staged physical persistence must be configured before device mutation",
            });
        }
        self.storage_faults
            .require_persistence_media_directives(true);
        Ok(())
    }

    /// Installs one fully resolved directive for an exact pending request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate identity or bounded-state failure.
    pub fn install_storage_fault_directive(
        &mut self,
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install(identity, directive)
    }

    /// Returns the first request ready for resolve/persist evaluation.
    #[must_use]
    pub fn next_storage_execution_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockExecutionOpportunity> {
        self.storage_faults.next_execution_opportunity(now_nanos)
    }

    /// Installs one complete resolve/persist decision for a staged request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the decision does not authenticate the live
    /// opportunity, repeats queue service, or violates storage bounds.
    pub fn install_storage_execution_directive(
        &mut self,
        directive: ResolvedBlockExecutionDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install_execution_directive(directive)
    }

    /// Returns the next write/discard/flush ready for persist-phase evaluation.
    #[must_use]
    pub fn next_storage_request_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockRequestPersistenceOpportunity> {
        self.storage_faults
            .next_request_persistence_opportunity(now_nanos)
    }

    /// Installs one exact persist-phase decision for a staged request mutation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the decision is stale, repeated, malformed,
    /// or changes an earlier phase.
    pub fn install_storage_request_persistence_directive(
        &mut self,
        directive: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults
            .install_request_persistence_directive(directive)
    }

    /// Returns the next computed completion ready for deliver-phase evaluation.
    #[must_use]
    pub fn next_storage_delivery_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockDeliveryOpportunity> {
        self.storage_faults.next_delivery_opportunity(now_nanos)
    }

    /// Installs one exact deliver-phase decision for a computed completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the decision is stale, repeated, malformed,
    /// or changes an earlier phase.
    pub fn install_storage_delivery_directive(
        &mut self,
        directive: ResolvedBlockDeliveryDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults.install_delivery_directive(directive)
    }

    /// Returns the next physical persistence opportunity ready at `now_nanos`.
    #[must_use]
    pub fn next_storage_persistence_opportunity(
        &self,
        now_nanos: u64,
    ) -> Option<BlockPersistenceOpportunity> {
        self.storage_faults.next_persistence_opportunity(now_nanos)
    }

    /// Installs one exact resolved physical-media directive.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the directive does not authenticate the
    /// live persistence opportunity, repeats an installed decision, or exceeds
    /// flash/persistence state bounds.
    pub fn install_storage_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        self.storage_faults
            .install_persistence_media_directive(directive)
    }

    /// Drains completed physical-media outcomes for event recording.
    pub fn drain_storage_persistence_media_outcomes(
        &mut self,
    ) -> Vec<BlockPersistenceMediaOutcome> {
        self.storage_faults.drain_persistence_media_outcomes()
    }

    /// Borrows completed physical-media outcomes without acknowledging them.
    #[must_use]
    pub fn storage_persistence_media_outcomes(&self) -> &[BlockPersistenceMediaOutcome] {
        self.storage_faults.persistence_media_outcomes()
    }

    /// Drains integrated-service completion evidence in canonical order.
    pub fn drain_storage_service_outcomes(&mut self) -> Vec<BlockServiceCompletion> {
        self.storage_faults.drain_service_outcomes()
    }

    /// Borrows integrated-service completion evidence without acknowledging it.
    #[must_use]
    pub fn storage_service_outcomes(&self) -> &[BlockServiceCompletion] {
        self.storage_faults.service_outcomes()
    }

    /// Returns all pending storage outcomes in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when checkpointed outcome-order state is invalid.
    pub fn storage_outcomes(&self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_faults.storage_outcomes()
    }

    /// Drains all storage outcomes in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutation when checkpointed outcome-order
    /// state is invalid.
    pub fn drain_storage_outcomes(&mut self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.storage_faults.drain_storage_outcomes()
    }

    /// Returns the earliest response, service, or persistence event coordinate.
    pub fn next_exact_local_event(&self) -> Option<u64> {
        let service = self
            .storage_faults
            .next_service_completion_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let persistence = self
            .storage_faults
            .next_persistence_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let execution = self
            .storage_faults
            .next_execution_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let request_persistence = self
            .storage_faults
            .next_request_persistence_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let delivery = self
            .storage_faults
            .next_delivery_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let retained_timeout = self
            .storage_faults
            .next_retained_timeout_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        let array_rebuild = self
            .storage_faults
            .next_array_rebuild_deadline_nanos()
            .map(|nanos| ceil_nanos_to_valid_icount(nanos, self.core.shift_bits()));
        self.core
            .next_exact_local_event()
            .into_iter()
            .chain(service)
            .chain(execution)
            .chain(request_persistence)
            .chain(delivery)
            .chain(persistence)
            .chain(retained_timeout)
            .chain(array_rebuild)
            .min()
    }

    /// Drops exact volatile-cache entries selected by their global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any selected sequence is absent or repeated.
    pub fn lose_storage_volatile(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        self.storage_faults.lose_volatile(sequences)
    }

    /// Drops exact controller-buffer entries selected by their global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any selected sequence is absent or repeated.
    pub fn lose_storage_controller(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        self.storage_faults.lose_controller(sequences)
    }

    /// Applies an asynchronous controller transition at an authorized host boundary.
    ///
    /// Unlike a duplicate-completion reset, this transition is not caused by
    /// delivery of one distinguished guest response. It atomically updates the
    /// complete host-owned request lifecycle and rewrites every already-resolved
    /// but undelivered response according to the declared transition policy.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if the recovery coordinate is outside QEMU's
    /// virtual-clock range, an epoch cannot advance, a lifecycle disposition
    /// cannot be encoded, or the resulting responses exceed device bounds.
    pub fn apply_storage_controller_transition(
        &mut self,
        transition: &ResolvedBlockControllerTransition,
        boundary_nanos: u64,
    ) -> Result<(), DeviceError> {
        let qemu_virtual_limit = i64::MAX as u64;
        if boundary_nanos > qemu_virtual_limit
            || transition.recovery_nanos > qemu_virtual_limit
            || boundary_nanos
                .checked_add(transition.recovery_nanos)
                .is_none_or(|deadline| deadline > qemu_virtual_limit)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block transport recovery exceeds QEMU virtual-clock range",
            });
        }
        let current_epoch = self.storage_faults.transport_epoch().unwrap_or(0);
        let reset = transition.transport_reset(current_epoch)?;
        let mut next_faults = self.storage_faults.clone();
        let immediate = next_faults.apply_transport_reset(reset, boundary_nanos)?;
        let mut next_core = self.core.clone();
        next_core.check_response_sequence_capacity(immediate.len())?;
        let mut inflight = next_core.take_inflight_from_snapshot();
        if reset.completed_undelivered != BlockTransportUndelivered::Complete {
            for pending in &mut inflight {
                let response =
                    BlockResponse::decode(&pending.response.payload).map_err(DeviceError::Codec)?;
                if matches!(response.status, BlockStatus::Ok | BlockStatus::Error) {
                    let replacement = match reset.completed_undelivered {
                        BlockTransportUndelivered::Complete => response,
                        BlockTransportUndelivered::Fail => {
                            BlockResponse::error_for(response.identity(), reset.failure_result)
                        }
                        BlockTransportUndelivered::RetryPreserveId => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::RetryPreserveId,
                            )
                        }
                        BlockTransportUndelivered::RetryNewId => BlockResponse::reset_disposition(
                            response.identity(),
                            BlockStatus::RetryNewId,
                        ),
                        BlockTransportUndelivered::DropCompletion => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::DropCompletion,
                            )
                        }
                    };
                    pending.response = block_response_to_uniform_device(&replacement)?;
                }
            }
        }
        next_core.replace_inflight(inflight);
        for response in immediate {
            next_core.schedule_response_now(response)?;
        }
        self.storage_faults = next_faults;
        self.core = next_core;
        Ok(())
    }

    /// Releases a stalled storage completion at the current scheduler icount.
    ///
    /// The response remains retained if the delivery core cannot reserve its
    /// canonical ordering sequence, so retrying cannot lose the completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when `identity` is
    /// not retained, or propagates the delivery core's scheduling error.
    pub fn release_storage_completion(
        &mut self,
        identity: super::super::codec::BlockRequestIdentity,
        release: BlockRetainedRelease,
    ) -> Result<BlockRetainedReleaseOutcome, DeviceError> {
        let outcomes = self.release_storage_completions(&[(identity, release)])?;
        outcomes
            .into_iter()
            .next()
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "single retained-completion release produced no outcome",
            })
    }

    /// Atomically releases retained storage completions at the current icount.
    ///
    /// Every durability mutation and response reservation is applied to a clone
    /// of the complete device. The device changes only after all releases have
    /// succeeded, so a full response queue or invalid identity cannot expose a
    /// prefix of the requested batch.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when any identity is absent, a recovery cannot
    /// satisfy its durability frontier, or any response cannot be scheduled.
    pub fn release_storage_completions(
        &mut self,
        releases: &[(
            super::super::codec::BlockRequestIdentity,
            BlockRetainedRelease,
        )],
    ) -> Result<Vec<BlockRetainedReleaseOutcome>, DeviceError> {
        let mut next = self.clone();
        let now_nanos = icount_to_virtual_ns(next.core.current_icount(), next.core.shift_bits())?;
        let mut outcomes = Vec::with_capacity(releases.len());
        for (identity, release) in releases {
            let response = next.storage_faults.resolve_retained_completion(
                &next.base,
                &mut next.overlay,
                *identity,
                *release,
                now_nanos,
            )?;
            match response {
                Some(response) => {
                    next.core.schedule_response_now(response)?;
                    outcomes.push(BlockRetainedReleaseOutcome::Released);
                }
                None => outcomes.push(BlockRetainedReleaseOutcome::PendingPersistence),
            }
        }
        *self = next;
        Ok(outcomes)
    }

    /// Predicts retained-completion release outcomes without changing the device.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::release_storage_completions`].
    pub fn preview_storage_completion_releases(
        &self,
        releases: &[(
            super::super::codec::BlockRequestIdentity,
            BlockRetainedRelease,
        )],
    ) -> Result<Vec<BlockRetainedReleaseOutcome>, DeviceError> {
        let mut preview = self.clone();
        preview.release_storage_completions(releases)
    }

    /// Returns a read-only view of the base image.
    #[must_use]
    pub fn base(&self) -> &BaseImage {
        &self.base
    }
}
