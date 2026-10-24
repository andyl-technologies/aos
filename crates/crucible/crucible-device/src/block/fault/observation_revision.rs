//! Persistent revision of every mutable storage-phase owner entry.
//!
//! Revision advancement precedes payload and phase effects. Nested internal
//! transitions share their outer entry. The reserved revision remains only
//! when explicit retained mutations or payload effects occur; probes do not make
//! checkpoint identity depend on how often the host polls a pipeline.
//! The counter never authenticates a native Source, receipt or consumer.

use super::*;
use std::num::NonZeroU64;

impl BlockFaultState {
    /// Returns the actual retained revision of this storage-phase owner.
    ///
    /// This is a read-only observation. Source/runtime exclusion and complete
    /// phase classification remain independently required by the observer.
    ///
    /// # Errors
    ///
    /// Refuses an active or interrupted mutable entry whose effects are not
    /// available as an immutable observation.
    pub fn observation_revision(&self) -> Result<NonZeroU64, DeviceError> {
        if self.observation_mutation_active {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "storage observation overlaps an active mutation",
            });
        }
        Ok(self.observation_revision)
    }

    pub(in crate::block) fn replace_retained_state(
        &mut self,
        mut replacement: Self,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            replacement.observation_revision = state.observation_revision;
            replacement.observation_mutation_active = true;
            replacement.observation_external_effect = state.observation_external_effect;
            replacement.observation_changed = state.observation_changed;
            // Replacement touches the whole owner; comparing its supplied
            // state is proportional to that explicit replacement operation.
            replacement.observation_changed |= replacement != *state;
            *state = replacement;
            Ok(())
        })
    }

    // The IoCore checkpoint belongs to this already-entered COMPUTE attempt.
    // Rollback restores its bytes, while retaining the entry's actual revision;
    // it cannot resurrect a prior queue observation or require a post-effect mint.
    pub(in crate::block) fn restore_compute_transaction(&mut self, mut checkpoint: Self) {
        checkpoint.observation_revision = self.observation_revision;
        checkpoint.observation_mutation_active = self.observation_mutation_active;
        checkpoint.observation_external_effect = self.observation_external_effect;
        checkpoint.observation_changed = self.observation_changed;
        *self = checkpoint;
    }

    fn with_observation_mutation<T>(
        &mut self,
        mutate: impl FnOnce(&mut Self) -> Result<T, DeviceError>,
    ) -> Result<T, DeviceError> {
        if self.observation_mutation_active {
            return mutate(self);
        }
        let revision = self
            .observation_revision
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "storage observation revision exhausted",
            })?;
        let previous_revision = self.observation_revision;
        self.observation_revision = revision;
        self.observation_mutation_active = true;
        let result = mutate(self);
        let changed = self.observation_changed || self.observation_external_effect;
        self.observation_changed = false;
        self.observation_external_effect = false;
        self.observation_mutation_active = false;

        // Actual field/effect sites record the entry's changes. A probe that
        // changes nothing returns its unexposed reservation without cloning
        // or comparing the rest of the retained owner.
        if !changed {
            self.observation_revision = previous_revision;
        }
        result
    }

    /// Enables or disables the fail-closed requirement for exact directives.
    ///
    /// # Errors
    ///
    /// Refuses before mutation when the retained observation revision is exhausted.
    pub fn require_directives(&mut self, required: bool) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.require_directives_untracked(required);
            Ok(())
        })
    }

    /// Records one exact physical mutation absent from an array member.
    ///
    /// Overlapping and adjacent ranges for a member are coalesced immediately,
    /// retaining the earliest dirty coordinate and newest mutation generation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for an empty/overflowing range or when the
    /// checkpointed dirty-range hard bound would be exceeded.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn record_array_dirty_range(
        &mut self,
        member: u16,
        start_byte: u64,
        bytes: Vec<u8>,
        dirty_ticks: u64,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.record_array_dirty_range_untracked(member, start_byte, bytes, dirty_ticks)
        })
    }

    /// Schedules or returns the next exact bounded rebuild chunk.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for zero policy values or arithmetic overflow.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn next_array_rebuild_opportunity(
        &mut self,
        now_ticks: u64,
        chunk_bytes: u64,
        bytes_per_second: u64,
        operations_per_second: Option<u64>,
    ) -> Result<Option<BlockArrayRebuildOpportunity>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.next_array_rebuild_opportunity_untracked(
                now_ticks,
                chunk_bytes,
                bytes_per_second,
                operations_per_second,
            )
        })
    }

    /// Commits one exact previously offered rebuild chunk.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn complete_array_rebuild(
        &mut self,
        opportunity: &BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| state.complete_array_rebuild_untracked(opportunity))
    }

    /// Retires one failed rebuild attempt without repairing its dirty bytes.
    ///
    /// The next scheduler call charges the complete chunk service duration
    /// again, preventing a persistent failure from spinning at one coordinate.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn defer_array_rebuild(
        &mut self,
        opportunity: &BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| state.defer_array_rebuild_untracked(opportunity))
    }

    /// Pauses a scheduled rebuild while its destination is unavailable.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn pause_array_rebuild(
        &mut self,
        _now_ticks: u64,
        opportunity: &BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.pause_array_rebuild_untracked(_now_ticks, opportunity)
        })
    }

    /// Enables fail-closed resolve/persist opportunities after queue service.
    ///
    /// # Errors
    ///
    /// Refuses before mutation when the retained observation revision is exhausted.
    pub fn require_execution_opportunities(&mut self, required: bool) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.require_execution_opportunities_untracked(required);
            Ok(())
        })
    }

    /// Installs the complete resolve/persist directive for one ready request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, the directive
    /// aliases another request, queue service is repeated, or a decision was
    /// already installed.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn install_execution_directive(
        &mut self,
        resolved: ResolvedBlockExecutionDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.install_execution_directive_untracked(resolved)
        })
    }

    /// Installs the complete persist decision for one exact mutation opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, repeated, or the
    /// directive alters fields already fixed by admit/queue/resolve.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn install_request_persistence_directive(
        &mut self,
        resolved: ResolvedBlockRequestPersistenceDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.install_request_persistence_directive_untracked(resolved)
        })
    }

    /// Installs the complete deliver-phase decision for one computed completion.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale, repeated, or the
    /// directive changes fields fixed by an earlier request phase.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn install_delivery_directive(
        &mut self,
        resolved: ResolvedBlockDeliveryDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| state.install_delivery_directive_untracked(resolved))
    }

    /// Enables fail-closed resolution at each physical persistence opportunity.
    ///
    /// # Errors
    ///
    /// Refuses before mutation when the retained observation revision is exhausted.
    pub fn require_persistence_media_directives(
        &mut self,
        required: bool,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.require_persistence_media_directives_untracked(required);
            Ok(())
        })
    }

    /// Installs the exact media directive for one ready persistence opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for stale/mismatched opportunity identity,
    /// duplicate installation, invalid flash rules, or bounded-state exhaustion.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn install_persistence_media_directive(
        &mut self,
        directive: ResolvedBlockPersistenceMediaDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.install_persistence_media_directive_untracked(directive)
        })
    }

    /// Drains completed persistence-media evidence after durable event recording.
    ///
    /// # Errors
    ///
    /// Refuses before mutation when the retained observation revision is exhausted.
    pub fn drain_persistence_media_outcomes(
        &mut self,
    ) -> Result<Vec<BlockPersistenceMediaOutcome>, DeviceError> {
        self.with_observation_mutation(|state| {
            Ok(state.drain_persistence_media_outcomes_untracked())
        })
    }

    /// Drains every storage outcome in exact causal generation order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutation when checkpointed outcome-order
    /// state contains an invalid reference.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn drain_storage_outcomes(&mut self) -> Result<Vec<BlockStorageOutcome>, DeviceError> {
        self.with_observation_mutation(|state| state.drain_storage_outcomes_untracked())
    }

    /// Installs one directive, keyed by the exact guest request ID.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate IDs or a hard pending-state limit.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn install(
        &mut self,
        identity: BlockRequestIdentity,
        directive: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| state.install_untracked(identity, directive))
    }

    /// Drains persistence graph mutations after canonical event recording.
    ///
    /// # Errors
    ///
    /// Refuses before mutation when the retained observation revision is exhausted.
    pub fn drain_persistence_transformation_evidence(
        &mut self,
    ) -> Result<Vec<crate::block::persistence::BlockPersistenceTransformationEvidence>, DeviceError>
    {
        self.with_observation_mutation(|state| {
            Ok(state.drain_persistence_transformation_evidence_untracked())
        })
    }

    /// Resolves a retained completion and applies its recovery-only durability.
    ///
    /// Callers must execute this method on cloned state and commit the clone
    /// only after the response scheduler accepts the returned response.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the request is not retained or persistence
    /// of the captured flush frontier fails.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn resolve_retained_completion(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        identity: BlockRequestIdentity,
        release: BlockRetainedRelease,
        now_ticks: u64,
    ) -> Result<Option<Response>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.resolve_retained_completion_untracked(base, durable, identity, release, now_ticks)
        })
    }

    /// Drops exact volatile entries selected by cache sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a selected sequence is not currently live.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn lose_volatile(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| state.lose_volatile_untracked(sequences))
    }

    /// Drops exact controller-accepted entries selected by global sequence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a selected sequence is not currently in the
    /// controller-accepted layer.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn lose_controller(&mut self, sequences: &[u64]) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| state.lose_controller_untracked(sequences))
    }

    /// Applies the host-side portion of a controller reset.
    ///
    /// For a response-triggered reset, the caller invokes this after the reset
    /// response crosses the delivery boundary. An asynchronous controller effect
    /// invokes it directly at its scheduler-authorized boundary. Requests removed
    /// from a host-owned lifecycle stage receive one explicit terminal or retry
    /// disposition; returned responses are ordered by request sequence within
    /// each stage and by queued, executing, resolved, then completed stage order.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if a generated response cannot be encoded or if
    /// losing controller/cache state violates persistence accounting.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub fn apply_transport_reset(
        &mut self,
        reset: BlockTransportReset,
        delivered_ticks: u64,
    ) -> Result<Vec<Response>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.apply_transport_reset_untracked(reset, delivered_ticks)
        })
    }

    /// Drains contributor-level service evidence in canonical completion order.
    ///
    /// # Errors
    ///
    /// Refuses before mutation when the retained observation revision is exhausted.
    pub fn drain_service_outcomes(&mut self) -> Result<Vec<BlockServiceCompletion>, DeviceError> {
        self.with_observation_mutation(|state| Ok(state.drain_service_outcomes_untracked()))
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn defer_execution(
        &mut self,
        request: &BlockRequest,
        request_icount: u64,
        ready_ticks: u64,
        admission: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.defer_execution_untracked(request, request_icount, ready_ticks, admission)
        })
    }

    /// Executes every ready request whose resolve/persist decision is installed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when a decision is malformed, execution fails,
    /// or the resulting completion cannot be represented exactly.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn resume_execution_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.resume_execution_to_untracked(base, durable, now_ticks)
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn defer_request_persistence(
        &mut self,
        request: BlockRequest,
        request_icount: u64,
        ready_ticks: u64,
        resolved: ResolvedBlockFaultDirective,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.defer_request_persistence_untracked(
                request,
                request_icount,
                ready_ticks,
                resolved,
            )
        })
    }

    /// Executes every request whose exact persist decision is installed and ready.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn resume_request_persistence_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.resume_request_persistence_to_untracked(base, durable, now_ticks)
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn execute_to_delivery(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
        directive: ResolvedBlockFaultDirective,
        mutation_ticks: u64,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.execute_to_delivery_untracked(
                base,
                durable,
                request,
                request_icount,
                directive,
                mutation_ticks,
            )
        })
    }

    /// Releases every computed completion with an installed deliver decision.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn resume_delivery_to(
        &mut self,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        self.with_observation_mutation(|state| state.resume_delivery_to_untracked(now_ticks))
    }

    /// Advances service and executes every request released by all constraints.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when service state is malformed, persistence at
    /// an intervening boundary fails, or released device execution fails.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn advance_service_to(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<Vec<BlockDeferredResponse>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.advance_service_to_untracked(base, durable, now_ticks)
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn execute(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request: &BlockRequest,
        request_icount: u64,
    ) -> Result<ComputedResponse, DeviceError> {
        self.with_observation_mutation(|state| {
            state.execute_untracked(base, durable, request, request_icount)
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn dispose_retired_transport_request_if_needed(
        &mut self,
        identity: BlockRequestIdentity,
    ) -> Result<Option<Response>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.dispose_retired_transport_request_if_needed_untracked(identity)
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    #[expect(
        clippy::too_many_arguments,
        reason = "the atomic cross-device write carries independent request identity, time, range, and bytes"
    )]
    pub(in crate::block) fn apply_external_write(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_id: u32,
        request_sequence: u64,
        admitted_ticks: u64,
        destination_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        self.with_observation_mutation(|state| {
            state.apply_external_write_untracked(
                base,
                durable,
                request_id,
                request_sequence,
                admitted_ticks,
                destination_offset,
                bytes,
            )
        })
    }

    /// Applies one externally owned array mutation without a guest completion.
    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn apply_external_mutation(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        request_sequence: u64,
        admitted_ticks: u64,
        request: BlockRequest,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        self.with_observation_mutation(|state| {
            state.apply_external_mutation_untracked(
                base,
                durable,
                request_sequence,
                admitted_ticks,
                request,
            )
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn read_visible(
        &mut self,
        base: &BaseImage,
        durable: &CowOverlay,
        offset: u64,
        count: u32,
        record_cache_access: bool,
    ) -> Result<Vec<u8>, DeviceError> {
        self.with_observation_mutation(|state| {
            state.read_visible_untracked(base, durable, offset, count, record_cache_access)
        })
    }

    ///
    /// The retained observation revision advances before this outer mutation
    /// entry; exhaustion refuses before any phase or external payload effect.
    pub(in crate::block) fn persist_due(
        &mut self,
        base: &BaseImage,
        durable: &mut CowOverlay,
        now_ticks: u64,
    ) -> Result<(), DeviceError> {
        self.with_observation_mutation(|state| {
            state.persist_due_untracked(base, durable, now_ticks)
        })
    }
}

#[cfg(test)]
#[path = "observation_revision_tests.rs"]
mod tests;
