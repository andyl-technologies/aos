//! Corroborates actual Park closure before returning Host-owned memberships.
//!
//! Source owns the real loan slots and registered publisher identities. Native
//! closes its received resources; the same retained QMP transport authenticates
//! that factual closure. Neither pair-view bits nor a reply alone unlink Host
//! subscribers, retire the standing Source, or complete producing operations.

use super::*;
use crucible_qemu_protocol::boundary_action::ActionBinding;
use crucible_qemu_protocol::parent_park_return::ParentParkReturn;

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use crate::qmp::parent_park_drain::QmpParentParkClosedRequest;

/// Retains exact corroborated evidence across partial Host membership cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VerifiedParkReturn {
    journal: ParentParkReturn,
    completed_requests: u64,
}

impl action::PendingAction {
    fn retain_park_return(
        &mut self,
        verified: VerifiedParkReturn,
        previous_completed: u64,
    ) -> Result<(), HostSupervisionError> {
        let journal = verified.journal;
        journal
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        if journal.binding != self.observation.binding
            || self.observation.binding.park_request.is_none()
            || self.verified_return.is_some()
            || !(2..=4).contains(&self.observation.row_count)
            || (journal.publication_count != 0
                && journal.publication_count != self.observation.row_count)
            || journal.pair_view_return_mask & !self.observation.projected_mask != 0
        {
            return Err(HostSupervisionError::Unavailable);
        }
        if let Some(retained) = self.verified_park_return {
            // An identical completed ordinal is required while retrying a
            // partially unlinked cohort. It is not a fresh closure admission.
            return if retained == verified && self.returning {
                Ok(())
            } else {
                Err(HostSupervisionError::Unavailable)
            };
        }
        if self.returning || verified.completed_requests <= previous_completed {
            return Err(HostSupervisionError::Unavailable);
        }
        self.verified_park_return = Some(verified);
        self.returning = true;
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl OriginalSourceSupervision {
    /// Returns this request's Host subscribers only after authenticated closure.
    ///
    /// The proof comes from the same retained QMP owner, not a deserialized
    /// reply. Independent semantic failures survive factual resource return.
    /// Every still-born loan remains in its original paid slot on refusal.
    ///
    /// # Errors
    /// Refuses foreign mapping/request/proof, changed evidence, uncertain
    /// cleanup or final publication. A missing/concurrent journal yields None.
    pub(crate) fn settle_parent_park_from_mapping(
        &self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        closed: &QmpParentParkClosedRequest,
    ) -> Result<Option<ParentParkReturn>, HostSupervisionError> {
        let assigned = *self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if assigned != Some((mapping.backing_identity(), slot)) {
            return Err(HostSupervisionError::Unavailable);
        }
        let node = mapping
            .node_slot(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let Some(journal) = node
            .observe_parent_park_return()
            .map_err(|_| HostSupervisionError::InvalidBudget)?
        else {
            return Ok(None);
        };
        closed
            .corroborate_return(journal.binding, &journal)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let verified = VerifiedParkReturn {
            journal,
            completed_requests: closed.completed_requests(),
        };
        let count = {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let previous = state.last_parent_park_return;
            let Some(action) = state.action.as_mut() else {
                return if previous == Some(verified) {
                    Ok(Some(journal))
                } else {
                    Err(HostSupervisionError::Unavailable)
                };
            };
            action.retain_park_return(
                verified,
                previous.map_or(0, |closed| closed.completed_requests),
            )?;
            action.observation.row_count
        };

        for index in 0..count as usize {
            let mut slot = self.publisher.action_loans[index]
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let bit = 1 << index;
            {
                let state = self
                    .publisher
                    .state
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?;
                let action = state
                    .action
                    .as_ref()
                    .ok_or(HostSupervisionError::Unavailable)?;
                if action.verified_park_return != Some(verified) || !action.returning {
                    return Err(HostSupervisionError::Unavailable);
                }
                if slot.is_none() {
                    if action.observation.borrowed_mask & bit != 0
                        && action.park_members_returned_mask & bit == 0
                    {
                        // Missing local storage is not evidence that its actual
                        // registered Host subscriber physically returned.
                        return Err(HostSupervisionError::Unavailable);
                    }
                    continue;
                }
                if action.observation.borrowed_mask & bit == 0
                    || action.park_members_returned_mask & bit != 0
                {
                    return Err(HostSupervisionError::Unavailable);
                }
            }
            let loan = slot.as_mut().ok_or(HostSupervisionError::Unavailable)?;
            // The loan finds its registered publisher and real row. Its
            // selector is never constructed from the pair-view mask.
            let receipt = loan.observe_parent_park_return()?;
            loan.return_parent_park_physical(&receipt)?;
            {
                let mut state = self
                    .publisher
                    .state
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?;
                let action = state
                    .action
                    .as_mut()
                    .ok_or(HostSupervisionError::Unavailable)?;
                if action.verified_park_return != Some(verified) || !action.returning {
                    return Err(HostSupervisionError::Unavailable);
                }
                // This internal bit records an actual Host unlink, separately
                // from the immutable Native received-view mask.
                action.park_members_returned_mask |= bit;
            }
            *slot = None;
        }

        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let Some(action) = state.action.as_mut() else {
            return if state.last_parent_park_return == Some(verified) {
                Ok(Some(journal))
            } else {
                Err(HostSupervisionError::Unavailable)
            };
        };
        if action.observation.binding != journal.binding
            || !action.returning
            || action.verified_park_return != Some(verified)
            || action.park_members_returned_mask != action.observation.borrowed_mask
        {
            return Err(HostSupervisionError::Unavailable);
        }
        // Physical unlink is final. Keep the evidence and frontier if clearing
        // the containing publication subsequently fails.
        action.clearing = true;
        state.last_parent_park_return = Some(verified);
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        if let Err(error) = self.publisher.publish_locked(&mut state, latest) {
            if let Some(action) = state.action.as_mut() {
                action.refused = true;
            }
            self.publisher.invalidate();
            return Err(error);
        }
        node.release_action_frontier(journal.binding.loan_sequence)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.action = None;
        Ok(Some(journal))
    }
}

impl SourcePublisher {
    pub(super) fn verified_parent_park_member_return(
        &self,
        binding: ActionBinding,
        row: u32,
    ) -> Result<ParentParkReturn, HostSupervisionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        let verified = action
            .verified_park_return
            .ok_or(HostSupervisionError::Unavailable)?;
        if !action.returning
            || action.observation.binding != binding
            || verified.journal.binding != binding
            || row >= action.observation.row_count
            || action.observation.borrowed_mask & (1 << row) == 0
        {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(verified.journal)
    }
}

#[cfg(test)]
mod tests;
