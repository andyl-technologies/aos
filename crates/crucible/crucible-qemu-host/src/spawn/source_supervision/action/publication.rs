//! Owns the unique mapped Source producer and its unpublished return cut.
//!
//! The producer replaces an existing Source handle without another allocation.
//! Each action's privilege stays in the already paid publisher until its actual
//! request mutation is attempted or its real subscribers return locally.

use super::*;

/// Owns the once-bound host producer without cloning its issuance privilege.
///
/// Shared dereferencing preserves the existing nonissuing Source operations.
/// Original Source clones cannot issue or locally retire actions; their attempt
/// to bind another producer refuses the occupied actual mapping.
#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct ActionSourceProducer {
    pub(super) source: OriginalSourceSupervision,
}

impl std::ops::Deref for ActionSourceProducer {
    type Target = OriginalSourceSupervision;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

// The enclosing runtime's existing optional field must not grow, including its
// niche and alignment. Its separately erased body pricing is not proved here.
const _: () = {
    assert!(
        std::mem::size_of::<Option<ActionSourceProducer>>()
            == std::mem::size_of::<Option<OriginalSourceSupervision>>()
    );
    assert!(
        std::mem::align_of::<Option<ActionSourceProducer>>()
            == std::mem::align_of::<Option<OriginalSourceSupervision>>()
    );
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PublicationPhase {
    Unpublished,
    Publishing,
    Published,
    LocallyClosed,
}

pub(super) fn retained_action(
    action: &mut Option<PendingAction>,
) -> Result<&mut PendingAction, HostSupervisionError> {
    action.as_mut().ok_or(HostSupervisionError::Unavailable)
}

impl PendingAction {
    pub(super) fn begin_pause_publication(
        &mut self,
        binding: ActionBinding,
    ) -> Result<(), HostSupervisionError> {
        if binding.park_request.is_some()
            || binding.capture.is_some()
            || self.observation.binding != binding
            || self.observation.primary_count != 2
            || self.observation.parents[..2]
                .iter()
                .any(|parent| parent.class != 6)
        {
            return Err(HostSupervisionError::Unavailable);
        }
        self.begin_publication()
    }

    pub(super) fn begin_publication(&mut self) -> Result<(), HostSupervisionError> {
        if self.publication == PublicationPhase::LocallyClosed
            || self.returning
            || self.refused
            || !self.observation.cohort_current
            || !(1..=4).contains(&self.observation.row_count)
            || self.observation.borrowed_mask != (1 << self.observation.row_count) - 1
            || self.observation.projected_mask != self.observation.borrowed_mask
            || self.observation.parents[..self.observation.row_count as usize]
                .iter()
                .any(|parent| parent.state != 0)
        {
            return Err(HostSupervisionError::Unavailable);
        }
        if self.publication == PublicationPhase::Unpublished {
            // This store precedes the caller's first shared mutation. A failed
            // wake or unwind can never restore the unpublished privilege.
            self.publication = PublicationPhase::Publishing;
        }
        Ok(())
    }

    pub(super) fn close_unpublished(&mut self) -> Result<bool, HostSupervisionError> {
        if self.observation.binding.park_request.is_some() || self.returning {
            return Err(HostSupervisionError::Unavailable);
        }
        match self.publication {
            PublicationPhase::Unpublished | PublicationPhase::LocallyClosed => {
                self.publication = PublicationPhase::LocallyClosed;
                self.refused = true;
                self.observation.cohort_current = false;
                Ok(true)
            }
            PublicationPhase::Publishing | PublicationPhase::Published => Ok(false),
        }
    }

    pub(super) fn record_publication(&mut self) -> Result<(), HostSupervisionError> {
        if self.observation.binding.park_request.is_some()
            || !matches!(
                self.publication,
                PublicationPhase::Publishing | PublicationPhase::Published
            )
        {
            return Err(HostSupervisionError::Unavailable);
        }
        self.publication = PublicationPhase::Published;
        Ok(())
    }
}

impl ActionSourceProducer {
    /// Seals this actual producer before the first request mutation.
    ///
    /// All fallible validation precedes the phase transition. The binding
    /// corroborates the nominal producer and cannot construct another one.
    pub(crate) fn begin_control_publication(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        token: u32,
        frontier: u64,
        capture: Option<u32>,
    ) -> Result<(), HostSupervisionError> {
        let expected = *self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if expected != Some((mapping.backing_identity(), slot)) {
            return Err(HostSupervisionError::Unavailable);
        }
        // Recollect the same Originals before this request's first effect.
        // A clean but old publication cannot authorize an expired lender.
        self.refresh_action()?;
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = retained_action(&mut state.action)?;
        let binding = action.observation.binding;
        if binding.park_request.is_some()
            || binding.token != token
            || binding.frontier != frontier
            || binding.capture != capture
        {
            return Err(HostSupervisionError::Unavailable);
        }
        action.begin_publication()
    }

    /// Seals the exact two-lender Pause action before its header or ceiling write.
    ///
    /// # Errors
    /// Refuses changed mapping/selector, missing admission, or any terminal lender.
    pub(crate) fn begin_pause_publication(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        binding: ActionBinding,
    ) -> Result<(), HostSupervisionError> {
        if binding.park_request.is_some() || binding.capture.is_some() {
            return Err(HostSupervisionError::Unavailable);
        }
        let expected = *self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if expected != Some((mapping.backing_identity(), slot)) {
            return Err(HostSupervisionError::Unavailable);
        }
        self.refresh_action()?;
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = retained_action(&mut state.action)?;
        action.begin_pause_publication(binding)
    }

    /// Seals the same privilege before the sampler generation becomes visible.
    pub(crate) fn begin_capture_publication(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        capture: u32,
    ) -> Result<(), HostSupervisionError> {
        let binding = {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            retained_action(&mut state.action)?.observation.binding
        };
        self.begin_control_publication(
            mapping,
            slot,
            binding.token,
            binding.frontier,
            Some(capture),
        )
    }

    /// Records known token publication, independently of the later eventfd wake.
    pub(crate) fn control_publication_returned(&mut self) -> Result<(), HostSupervisionError> {
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = retained_action(&mut state.action)?;
        action.record_publication()
    }

    /// Returns this producer's actual locally sealed unpublished subscriptions.
    ///
    /// This never polls an Original or constructs a native journal. Actual loan
    /// fields select partial births and unprojected rows, not copied born bits.
    pub(crate) fn return_unpublished_action(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
    ) -> Result<bool, HostSupervisionError> {
        let expected = *self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if expected != Some((mapping.backing_identity(), slot)) {
            return Err(HostSupervisionError::Unavailable);
        }
        let binding = {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let Some(action) = state.action.as_mut() else {
                return Ok(true);
            };
            if action.observation.binding.park_request.is_some() {
                return Ok(false);
            }
            if !action.close_unpublished()? {
                return Ok(false);
            }
            action.observation.binding
        };
        for output in &self.publisher.action_loans {
            let mut output = output
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            if let Some(loan) = output.as_mut() {
                let receipt = loan.observe_unpublished_return()?;
                loan.return_unpublished(&receipt)?;
                *output = None;
            }
        }
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding
            || action.publication != PublicationPhase::LocallyClosed
        {
            return Err(HostSupervisionError::Unavailable);
        }
        if action.frontier_held {
            mapping
                .node_slot(slot)
                .map_err(|_| HostSupervisionError::Unavailable)?
                .release_action_frontier(binding.loan_sequence)
                .map_err(|_| HostSupervisionError::Unavailable)?;
            action.frontier_held = false;
        }
        // No token or capture was attempted. The protocol requires an actual
        // pending token before Native may acquire an operational action loan.
        action.clearing = true;
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        self.publisher.publish_locked(&mut state, latest)?;
        state.action = None;
        Ok(true)
    }
}
