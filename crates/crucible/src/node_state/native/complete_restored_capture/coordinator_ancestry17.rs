//! Authenticates every signed coordinator parent before current17 admission.
//!
//! Each decoded ancestor remains in this actual validation attempt, including a
//! later refusal. Content closure ownership and the typed parent bank are
//! independent. A matching current prefix alone cannot reset inherited lifetime
//! counters or prove that an activation followed its real imported safe point.

use super::*;
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA;

impl NativeArchiveRecord {
    pub(super) fn authenticate_coordinator_ancestry17_data(
        &self,
        attempt: &mut CompleteRestoredSettledArchiveValidationAttempt,
        additional_retained_bytes: usize,
    ) -> Result<(), StateError> {
        attempt.authenticate(self)?;
        if !attempt.coordinator_ancestry.is_empty() || attempt.coordinator_ancestry.capacity() != 0
        {
            return Err(refused(
                "settled17 coordinator ancestry validation is spent",
            ));
        }
        let maximum = self
            .limits
            .state
            .maximum_total_content_bytes
            .min(self.limits.native.maximum_total_record_bytes);
        let maximum_record = self
            .limits
            .state
            .maximum_record_bytes
            .min(self.limits.native.maximum_record_bytes);
        // Every parent is a separately verified full-reference object in this
        // finite signed closure. Its population supplies a bank bound, not a
        // new coordinator record budget or a guessed maximum ancestry depth.
        let maximum_ancestors = self.index.objects.len();
        let bank = maximum_ancestors
            .checked_mul(std::mem::size_of::<CoordinatorCommitmentCheckpoint17>())
            .ok_or_else(|| refused("settled17 coordinator parent bank overflow"))?;
        validation::admit(
            self,
            attempt,
            additional_retained_bytes,
            bank.checked_add(counter_scratch_data())
                .ok_or_else(|| refused("settled17 coordinator parent preparation overflow"))?,
        )?;
        attempt
            .coordinator_ancestry
            .try_reserve_exact(maximum_ancestors)
            .map_err(|_| refused("settled17 coordinator parent bank unavailable"))?;
        if attempt.coordinator_ancestry.capacity() > maximum_ancestors {
            return Err(refused(
                "settled17 coordinator parent bank exceeds admission",
            ));
        }

        loop {
            let child = current_child(attempt)?;
            let Some(reference) = child.parent.as_ref() else {
                // The defining closed grammar requires actual original genesis,
                // zero inherited counters and both committed genesis rows here.
                child
                    .authenticate_prefix_data()
                    .map_err(crate::node_state::schema)?;
                break;
            };
            if attempt.coordinator_ancestry.len() >= maximum_ancestors
                || reference.media_type != COORDINATOR_CHECKPOINT17_MEDIA
                || reference == &self.manifest().coordinator_state_ref
                || !self
                    .index
                    .objects
                    .iter()
                    .any(|row| &row.reference == reference)
            {
                return Err(refused(
                    "settled17 coordinator parent is cyclic or outside signed closure",
                ));
            }
            let content = attempt
                .content
                .as_ref()
                .ok_or_else(|| refused("settled17 coordinator parent content absent"))?;
            let bytes = content
                .get(reference)
                .ok_or_else(|| refused("settled17 coordinator parent body absent"))?;
            reference.verify(bytes).map_err(crate::node_state::schema)?;
            if bytes.len() > maximum_record {
                return Err(refused(
                    "settled17 coordinator parent exceeds record admission",
                ));
            }
            let row =
                CoordinatorCommitmentCheckpoint17::prospective_storage_data(bytes.len(), maximum)
                    .map_err(crate::node_state::schema)?;
            validation::admit(
                self,
                attempt,
                additional_retained_bytes,
                row.requested_bytes_data()
                    .checked_add(counter_scratch_data())
                    .ok_or_else(|| refused("settled17 coordinator parent parse overflow"))?,
            )?;
            let parent = decode_record(bytes, maximum_record)?;
            // Install before prefix, lifetime and activation checks. Failure
            // preserves this exact initialized typed parent in its once owner.
            attempt.coordinator_ancestry.push(parent);
            let parent_index = attempt.coordinator_ancestry.len() - 1;
            let parent = &attempt.coordinator_ancestry[parent_index];
            let child = if parent_index == 0 {
                attempt
                    .coordinator
                    .as_ref()
                    .ok_or_else(|| refused("settled17 current coordinator absent"))?
            } else {
                &attempt.coordinator_ancestry[parent_index - 1]
            };
            let reference = child
                .parent
                .as_ref()
                .ok_or_else(|| refused("settled17 coordinator parent edge absent"))?;
            parent
                .authenticate_structure_data(
                    &parent.safe_point.runtime,
                    parent.safe_point.position,
                    parent.safe_point.event_ordinal,
                )
                .map_err(crate::node_state::schema)?;
            parent
                .authenticate_prefix_data()
                .map_err(crate::node_state::schema)?;
            child
                .authenticate_parent_counters_data(reference, parent)
                .map_err(crate::node_state::schema)?;
            attempt.authenticate(self)?;
        }
        validation::admit(
            self,
            attempt,
            additional_retained_bytes,
            counter_scratch_data(),
        )?;
        attempt.authenticate(self)
    }
}

fn current_child(
    attempt: &CompleteRestoredSettledArchiveValidationAttempt,
) -> Result<&CoordinatorCommitmentCheckpoint17, StateError> {
    attempt
        .coordinator_ancestry
        .last()
        .or(attempt.coordinator.as_ref())
        .ok_or_else(|| refused("settled17 coordinator chain has no current child"))
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&NativeArchiveRecord>()
        + size_of::<&CompleteRestoredSettledArchiveValidationAttempt>()
        + size_of::<&mut CompleteRestoredSettledArchiveValidationAttempt>()
        + size_of::<&CoordinatorCommitmentCheckpoint17>()
        + size_of::<Result<&CoordinatorCommitmentCheckpoint17, StateError>>()
        + size_of::<CoordinatorCommitmentCheckpoint17>()
        + size_of::<Option<&ContentRef>>()
        + size_of::<&ContentRef>()
        + size_of::<&[u8]>()
        + size_of::<Result<CoordinatorCommitmentCheckpoint17, StateError>>()
        + size_of::<Result<(), StateError>>()
        + size_of::<crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCheckpointStorageData17>()
        + size_of::<[usize; 7]>()
}
