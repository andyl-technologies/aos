//! Owns the Source's actual action lenders and coherent publication cuts.
//!
//! Slot locks precede lender state/outer locks and publication state. No path
//! holding publication state acquires a slot or lender lock. A changed lender
//! publishes a dirty cohort; only the full locked collector makes it current.

use super::*;
use crucible_host_resources::host_supervision::{
    HostActionLoan, HostActionPublisher, HostOperationGuard,
};
use crucible_qemu_protocol::boundary_action::{
    ActionBinding, ActionObservation, ActionParent, ActionReturn,
};

mod publication;
mod quantum;
pub(crate) use publication::ActionSourceProducer;
use publication::PublicationPhase;

enum RequestIdentity {
    Quantum {
        command: crucible_qemu_protocol::publisher_subscription::PublisherCommand,
    },
    Control {
        token: u32,
        capture: Option<u32>,
    },
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    Park {
        correlation: u64,
    },
}

impl RequestIdentity {
    // Matching bytes in a pending untyped request cannot create a producing
    // membership retrospectively. The real producer invokes this before birth.
    fn require_unpublished_request(
        &self,
        node: &crucible_qemu_shmem::NodeSlot,
    ) -> Result<(), HostSupervisionError> {
        let acknowledged = node.control_boundary_token();
        let token_matches = match self {
            Self::Quantum { .. } => true,
            Self::Control { token, .. } => acknowledged.checked_add(1) == Some(*token),
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::Park { .. } => true,
        };
        if acknowledged & 1 == 0 || !token_matches || node.action_frontier_is_retained() {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct PendingAction {
    pub(super) observation: ActionObservation,
    pub(super) returning: bool,
    pub(super) clearing: bool,
    pub(super) refused: bool,
    pub(super) verified_return: Option<ActionReturn>,
    pub(super) verified_park_return: Option<parent_park_return::VerifiedParkReturn>,
    pub(super) park_members_returned_mask: u32,
    publication: PublicationPhase,
    frontier_held: bool,
    pub(super) quantum: Option<quantum::PendingQuantumCommand>,
}

impl PendingAction {
    #[cfg(test)]
    pub(super) fn from_observation_for_test(observation: ActionObservation) -> Self {
        Self {
            observation,
            returning: false,
            clearing: false,
            refused: false,
            verified_return: None,
            verified_park_return: None,
            park_members_returned_mask: 0,
            publication: PublicationPhase::Unpublished,
            frontier_held: false,
            quantum: None,
        }
    }

    // This comparison consumes a fresh full collector result. It never turns
    // an independently updated dirty row into an accepted cohort.
    fn matches_current_cohort(
        &self,
        binding: ActionBinding,
        parents: &[ActionParent; 4],
        count: u32,
    ) -> bool {
        self.observation.binding == binding
            && self.observation.row_count == count
            && self.observation.cohort_current
            && !self.returning
            && !self.refused
            && self.observation.parents == *parents
    }
}

impl OriginalSourceSupervision {
    /// Binds the actual hosted setup mapping before any action publication.
    pub(crate) fn bind_action_mapping(
        self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        wake: Arc<std::fs::File>,
    ) -> Result<ActionSourceProducer, HostSupervisionError> {
        self.publisher
            ._admission
            .check()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        mapping
            .node_slot(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if !rustix::fs::fcntl_getfl(wake.as_ref())
            .map_err(|_| HostSupervisionError::Unavailable)?
            .contains(OFlags::NONBLOCK)
            || super::super::plugin_startup::event_identity(wake.as_raw_fd()).is_err()
        {
            return Err(HostSupervisionError::Unavailable);
        }
        let identity = mapping.backing_identity();
        let mut held = self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if held.is_some() {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        let mut action_wake = self
            .publisher
            .action_wake
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if action_wake.is_some() {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        *action_wake = Some(wake);
        *held = Some((identity, slot));
        drop(action_wake);
        drop(held);
        Ok(ActionSourceProducer { source: self })
    }

    /// Reads return only from the assigned live mapping and actual peer slot.
    pub(crate) fn observe_action_return(
        &self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
    ) -> Result<Option<ActionReturn>, HostSupervisionError> {
        let expected = *self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if expected != Some((mapping.backing_identity(), slot)) {
            return Err(HostSupervisionError::Unavailable);
        }
        let state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let binding = state
            .action
            .as_ref()
            .map(|action| action.observation.binding)
            .ok_or(HostSupervisionError::Unavailable)?;
        let slot = mapping
            .node_slot(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if binding.park_request.is_some()
            || state
                .action
                .as_ref()
                .is_some_and(|action| action.quantum.is_some())
        {
            // The Park record returns local received views, not these standing
            // memberships. Keep them until a real same-owner settlement exists.
            return Err(HostSupervisionError::Unavailable);
        }
        let journal = slot
            .observe_action_return()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        // A journal from another request cannot retire this retained cohort.
        Ok(journal.filter(|journal| journal.binding == binding))
    }

    /// Settles only return from the actual assigned peer mapping.
    pub(crate) fn settle_action_from_mapping(
        &self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
    ) -> Result<Option<ActionReturn>, HostSupervisionError> {
        let Some(journal) = self.observe_action_return(mapping, slot)? else {
            return Ok(None);
        };
        if !self.return_action(&journal)? {
            return Ok(None);
        }
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if !state
            .action
            .as_ref()
            .is_some_and(|action| action.returning && action.observation.binding == journal.binding)
        {
            return Err(HostSupervisionError::Unavailable);
        }
        // Known physical consumption stays consumed. The admission latch and
        // exact frontier remain held until their final publication is known.
        state.last_action_return = Some(journal);
        state
            .action
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?
            .clearing = true;
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        if let Err(error) = self.publisher.publish_locked(&mut state, latest) {
            if let Some(action) = state.action.as_mut() {
                action.refused = true;
            }
            self.publisher.invalidate();
            return Err(error);
        }
        mapping
            .node_slot(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?
            .release_action_frontier(journal.binding.loan_sequence)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.action = None;
        Ok(Some(journal))
    }

    /// Retains the exact owned mapping when its runtime leaves physical debt.
    pub(crate) fn retain_uncertain_mapping(&self, mapping: crucible_qemu_shmem::MappedSetupRegion) {
        let mut held = self
            .publisher
            .retained_mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.is_none() {
            *held = Some(mapping);
        } else {
            // Duplicate ownership is uncertain. Both paid mappings remain
            // retained; neither a close nor a replacement is assumed safe.
            std::mem::forget(mapping);
        }
    }

    /// Checks the actual containing Source without entering another operation.
    ///
    /// # Errors
    /// Refuses another supervisor, invalidated publication, terminal original
    /// cap or retired admission. No pointer or scalar grants continuation.
    pub(crate) fn verify_live_control_source(
        &self,
        supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Result<(), HostSupervisionError> {
        self.publisher
            ._admission
            .host_purpose()
            .verify_supervisor(supervisor)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if supervisor.cap_id() != self.publisher.subject.containing_cap {
            return Err(HostSupervisionError::Unavailable);
        }
        if let Err(error) = supervisor.verify_original_live() {
            self.publisher.invalidate();
            return Err(error);
        }
        self.publisher
            ._admission
            .check()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let sequence = u64::from_be(self.publisher.mapping.words()[0].load(Ordering::SeqCst));
        if sequence == 0
            || sequence & 1 != 0
            || sequence == u64::MAX
            || sequence != state.sequence
            || state
                .latest
                .is_none_or(|snapshot| snapshot.outer.state != HostOperationState::Running)
        {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(())
    }

    /// Reports retained physical debt without admitting semantic continuation.
    pub(crate) fn action_is_pending(&self) -> bool {
        self.publisher
            .state
            .lock()
            .map_or(true, |state| state.action.is_some())
    }
}

impl ActionSourceProducer {
    /// Retains genuine producer loans before any request publication.
    ///
    /// No guard is cloned or reclassified. Born-negative memberships remain in
    /// the inline paid slots, independently of the caller's stack lifetime.
    pub(crate) fn begin_action(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        token: u32,
        frontier: u64,
        capture: Option<u32>,
        primary: [Option<&HostOperationGuard>; 2],
    ) -> Result<ActionBinding, HostSupervisionError> {
        self.begin_request(
            mapping,
            slot,
            frontier,
            RequestIdentity::Control { token, capture },
            primary,
        )
    }

    /// Enrolls the actual Park pair without publishing a control token or wake.
    ///
    /// The caller has already finished every Pause action physically. The same
    /// Source then owns both real lender memberships through Park disposition.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn begin_parent_park_action(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        correlation: u64,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<ActionBinding, HostSupervisionError> {
        if correlation == 0 || correlation == u64::MAX {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let actor_before = actor.check_original_quiescence_cancellation();
        let family_before = family.check_original_quiescence_cancellation();
        actor_before.and(family_before)?;
        let frontier = mapping
            .fault_command_write_index(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        self.begin_request(
            mapping,
            slot,
            frontier,
            RequestIdentity::Park { correlation },
            [Some(actor), Some(family)],
        )
    }
}

impl OriginalSourceSupervision {
    /// Refreshes only this still-owned typed pair before another Park action.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn check_parent_park_action(
        &self,
        binding: ActionBinding,
    ) -> Result<(), HostSupervisionError> {
        {
            let state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            if !state.action.as_ref().is_some_and(|action| {
                binding.park_request.is_some() && action.observation.binding == binding
            }) {
                return Err(HostSupervisionError::BorrowedOperation);
            }
        }
        self.refresh_action()?;
        let state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        if binding.park_request.is_none()
            || action.observation.binding != binding
            || action.observation.primary_count != 2
            || !action.observation.cohort_current
            || action.returning
            || action.refused
        {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        Ok(())
    }
}

impl ActionSourceProducer {
    fn begin_request(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        frontier: u64,
        request: RequestIdentity,
        primary: [Option<&HostOperationGuard>; 2],
    ) -> Result<ActionBinding, HostSupervisionError> {
        let quantum = match request {
            RequestIdentity::Quantum { command } => {
                Some(quantum::PendingQuantumCommand::new(command))
            }
            _ => None,
        };
        let (token, capture, park_request) = match request {
            RequestIdentity::Quantum { .. } => (0, None, None),
            RequestIdentity::Control { token, capture } => (token, capture, None),
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            RequestIdentity::Park { correlation } => (0, None, Some(correlation)),
        };
        self.publisher
            ._admission
            .check()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let primary_count = if primary[1].is_some() { 2 } else { 1 };
        if primary[0].is_none() || (park_request.is_some() && primary_count != 2) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let mut lenders: [Option<&HostOperationGuard>; 4] = [primary[0], primary[1], None, None];
        let mut links = [0; 4];
        let mut count = primary_count;
        for index in 0..primary_count {
            let guard = primary[index].ok_or(HostSupervisionError::Unavailable)?;
            if let Some(preparation) = guard.action_preparation() {
                if preparation.action_preparation().is_some() {
                    return Err(HostSupervisionError::InvalidBudget);
                }
                preparation.verify_operation_class(
                    crucible_host_resources::host_supervision::HostOperationClass::Preparation,
                )?;
                lenders[count] = Some(preparation);
                links[index] = count as u32 + 1;
                count += 1;
            }
        }
        let expected = *self
            .publisher
            .action_mapping
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if expected != Some((mapping.backing_identity(), slot)) {
            return Err(HostSupervisionError::Unavailable);
        }
        let node = mapping
            .node_slot(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        request.require_unpublished_request(node)?;
        if mapping
            .fault_command_write_index(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?
            != frontier
        {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        let binding = {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            if state.action.is_some() {
                return Err(HostSupervisionError::BorrowedOperation);
            }
            let binding = ActionBinding {
                cap: self.publisher.subject.containing_cap,
                reservation: self.publisher.subject.reservation,
                account_generation: self.publisher.subject.account_generation,
                process_generation: self.publisher.subject.process_generation,
                loan_sequence: state
                    .sequence
                    .checked_add(2)
                    .filter(|value| *value < u64::MAX)
                    .ok_or(HostSupervisionError::IdentityExhausted)?,
                token,
                frontier,
                capture,
                park_request,
            };
            state.action = Some(PendingAction {
                observation: ActionObservation {
                    binding,
                    primary_count: primary_count as u32,
                    row_count: count as u32,
                    borrowed_mask: 0,
                    projected_mask: 0,
                    cohort_current: false,
                    parents: [ActionParent::default(); 4],
                },
                returning: false,
                clearing: false,
                refused: false,
                verified_return: None,
                verified_park_return: None,
                park_members_returned_mask: 0,
                publication: if park_request.is_some() {
                    PublicationPhase::Published
                } else {
                    PublicationPhase::Unpublished
                },
                frontier_held: false,
                quantum,
            });
            binding
        };
        let retained = {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let action = state
                .action
                .as_mut()
                .ok_or(HostSupervisionError::Unavailable)?;
            let retained = node.retain_action_frontier(binding.loan_sequence);
            if retained.is_ok() {
                // The same held state receives the factual result before any
                // later lock, projection or post can refuse.
                action.frontier_held = true;
            }
            retained
        };
        if retained.is_err() {
            if park_request.is_some() {
                let _ = self.clear_unborn_park_action(mapping, slot, binding, false);
            }
            return Err(HostSupervisionError::BorrowedOperation);
        }
        // The producer ordinal is checked after exclusion. No later command
        // enqueue can mutate the actual frontier until physical return.
        if mapping
            .fault_command_write_index(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?
            != frontier
        {
            if park_request.is_some() {
                let _ = self.clear_unborn_park_action(mapping, slot, binding, true);
            }
            return Err(HostSupervisionError::Unavailable);
        }
        let callback = self.publisher.action();
        for index in 0..count {
            let mut output = self.publisher.action_loans[index]
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let result = lenders[index]
                .ok_or(HostSupervisionError::Unavailable)?
                .lend_action(
                    self.publisher._admission.host_purpose(),
                    callback.clone(),
                    binding,
                    index as u32,
                    links[index],
                    u32::from(index >= primary_count),
                    &mut output,
                );
            // The actual loan field is already populated when a post refuses.
            drop(output);
            if let Err(error) = result {
                if park_request.is_some() {
                    let _ = self.clear_unborn_park_action(mapping, slot, binding, true);
                }
                return Err(error);
            }
        }
        self.refresh_action()?;
        Ok(binding)
    }

    /// Closes only Park's existing no-reader cut before any actual loan birth.
    ///
    /// The canonical publisher emits no action tail while the born mask is
    /// zero, and this caller has not published a control request or wake. Every
    /// actual output slot must also be empty; an unprojectable born owner is
    /// retained rather than mistaken for an unpublished operation.
    fn clear_unborn_park_action(
        &self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        binding: ActionBinding,
        frontier_held: bool,
    ) -> Result<(), HostSupervisionError> {
        if binding.park_request.is_none() {
            return Err(HostSupervisionError::Unavailable);
        }
        let mut outputs = std::array::from_fn::<_, 4, _>(|_| None);
        for (index, output) in outputs.iter_mut().enumerate() {
            *output = Some(
                self.publisher.action_loans[index]
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?,
            );
            if output.as_ref().is_some_and(|output| output.is_some()) {
                return Err(HostSupervisionError::BorrowedOperation);
            }
        }
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding || action.observation.borrowed_mask != 0 {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        if frontier_held {
            mapping
                .node_slot(slot)
                .map_err(|_| HostSupervisionError::Unavailable)?
                .release_action_frontier(binding.loan_sequence)
                .map_err(|_| HostSupervisionError::Unavailable)?;
        }
        state.action = None;
        Ok(())
    }
}

impl OriginalSourceSupervision {
    /// Revalidates every actual lender outside publication guards.
    pub(crate) fn refresh_action(&self) -> Result<(), HostSupervisionError> {
        let count = {
            let state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let action = state
                .action
                .as_ref()
                .ok_or(HostSupervisionError::Unavailable)?;
            if action.returning || action.refused {
                return Err(HostSupervisionError::Unavailable);
            }
            action.observation.row_count
        };
        let mut held = std::array::from_fn::<_, 4, _>(|_| None);
        for index in 0..count as usize {
            held[index] = Some(
                self.publisher.action_loans[index]
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?,
            );
        }
        let loans =
            std::array::from_fn(|index| held[index].as_ref().and_then(|slot| slot.as_ref()));
        HostActionLoan::refresh_cohort(loans, count)
    }

    /// Consumes only a full journal read from the actual mapped peer slot.
    ///
    /// Syntax remains distinct from authority: the caller must observe this
    /// journal through the retained Source's exact validated setup mapping.
    /// Pending/uncertain, partial-mask and changed-binding records retain debt.
    fn return_action(&self, journal: &ActionReturn) -> Result<bool, HostSupervisionError> {
        journal
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let count = {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let action = state
                .action
                .as_mut()
                .ok_or(HostSupervisionError::Unavailable)?;
            if action.quantum.is_some()
                || journal.binding != action.observation.binding
                || journal.row_count != action.observation.row_count
                || journal.borrowed_mask != action.observation.borrowed_mask
                || !matches!(
                    action.publication,
                    PublicationPhase::Publishing | PublicationPhase::Published
                )
            {
                return Err(HostSupervisionError::Unavailable);
            }
            if journal.physical_state != 1 {
                return Ok(false);
            }
            action.verified_return = Some(*journal);
            action.returning = true;
            action.observation.row_count
        };
        for index in 0..count as usize {
            let mut slot = self.publisher.action_loans[index]
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            if let Some(loan) = slot.as_mut() {
                let receipt = loan.observe_physical_return()?;
                loan.return_physical(&receipt)?;
                // The actual physical selector is consumed before projection.
                *slot = None;
            }
        }
        let state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != journal.binding || !action.returning {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(true)
    }
}

impl HostActionPublisher for SourcePublisher {
    fn unpublished_return(&self, binding: ActionBinding) -> Result<(), HostSupervisionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding == binding
            && binding.park_request.is_none()
            && action.publication == PublicationPhase::LocallyClosed
        {
            Ok(())
        } else {
            Err(HostSupervisionError::Unavailable)
        }
    }

    fn retain_parent(&self, binding: ActionBinding, row: u32) -> Result<(), HostSupervisionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding
            || row >= action.observation.row_count
            || action.returning
            || action.observation.borrowed_mask & (1 << row) != 0
        {
            return Err(HostSupervisionError::Unavailable);
        }
        // The actual output is already held. A refused projection never makes
        // this born member disappear from the independently returned mask.
        action.observation.borrowed_mask |= 1 << row;
        action.observation.cohort_current = false;
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        self.publish_locked(&mut state, latest)
    }

    fn publish_parent(
        &self,
        binding: ActionBinding,
        row: u32,
        parent: ActionParent,
    ) -> Result<(), HostSupervisionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding
            || row >= action.observation.row_count
            || action.returning
            || action.observation.borrowed_mask & (1 << row) == 0
        {
            return Err(HostSupervisionError::Unavailable);
        }
        let index = row as usize;
        if action.observation.projected_mask & (1 << row) != 0 {
            let previous = action.observation.parents[index];
            if parent.cap != previous.cap
                || parent.budget_owner != previous.budget_owner
                || parent.operation != previous.operation
                || parent.class != previous.class
                || parent.started_revision != previous.started_revision
                || parent.origin_ns != previous.origin_ns
                || parent.started_ns != previous.started_ns
                || parent.preparation != previous.preparation
                || parent.role != previous.role
                || parent.policy_revision < previous.policy_revision
                || parent.outer_revision < previous.outer_revision
                || parent.progress_ns < previous.progress_ns
                || parent.completed < previous.completed
                || (previous.state != 0 && parent.state != previous.state)
            {
                return Err(HostSupervisionError::Unavailable);
            }
            if parent == previous {
                return Ok(());
            }
        }
        action.observation.parents[index] = parent;
        action.observation.projected_mask |= 1 << row;
        action.observation.cohort_current = false;
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        self.publish_locked(&mut state, latest)
    }

    fn publish_outer(
        &self,
        binding: ActionBinding,
        cap: [u8; 32],
        outer: crucible_host_resources::host_supervision::HostOuterCapBinding,
    ) -> Result<(), HostSupervisionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding || action.returning {
            return Err(HostSupervisionError::Unavailable);
        }
        let mut changed = false;
        for (index, parent) in action.observation.parents.iter_mut().enumerate() {
            if action.observation.projected_mask & (1 << index) == 0 || parent.cap != cap {
                continue;
            }
            if parent.origin_ns != outer.original_monotonic_ns
                || outer.revision < parent.outer_revision
            {
                return Err(HostSupervisionError::Unavailable);
            }
            let end = if parent.class == 13 {
                0
            } else {
                outer
                    .allowance
                    .map(|span| {
                        u64::try_from(span.as_nanos())
                            .ok()
                            .and_then(|ns| parent.origin_ns.checked_add(ns))
                            .ok_or(HostSupervisionError::InvalidBudget)
                    })
                    .transpose()?
                    .unwrap_or(0)
            };
            let disposition = if parent.state != 0 || parent.class == 13 {
                parent.state
            } else {
                match outer.state {
                    HostOperationState::Running => 0,
                    HostOperationState::Completed => 1,
                    HostOperationState::Expired => 2,
                    HostOperationState::Canceled => 3,
                }
            };
            changed |= parent.outer_revision != outer.revision
                || parent.outer_end_ns != end
                || parent.state != disposition;
            parent.outer_revision = outer.revision;
            parent.outer_end_ns = end;
            parent.state = disposition;
        }
        if !changed {
            return Ok(());
        }
        action.observation.cohort_current = false;
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        self.publish_locked(&mut state, latest)
    }

    fn publish_cohort(
        &self,
        binding: ActionBinding,
        parents: [ActionParent; 4],
        count: u32,
    ) -> Result<(), HostSupervisionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding
            || action.observation.row_count != count
            || action.observation.borrowed_mask != (1 << count) - 1
            || action.observation.projected_mask != action.observation.borrowed_mask
            || action.returning
            || action.refused
        {
            return Err(HostSupervisionError::Unavailable);
        }
        if action.matches_current_cohort(binding, &parents, count) {
            let published = u64::from_be(self.mapping.words()[0].load(Ordering::SeqCst));
            return if published == state.sequence && published != u64::MAX {
                self.publish_ready_quantum(&mut state)
            } else {
                Err(HostSupervisionError::Unavailable)
            };
        }
        if action
            .quantum
            .as_ref()
            .is_some_and(|quantum| quantum.has_publication_attempt())
        {
            // An issued command is immutable. A fresh full collector can deny
            // it, but cannot rebind the existing offer to changed parent facts.
            action.observation.parents = parents;
            action.observation.cohort_current = false;
            action.refused = true;
            let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
            self.publish_locked(&mut state, latest)?;
            return Err(HostSupervisionError::Unavailable);
        }
        // These values come from the collector while every real lender lock
        // remains held. An individual row callback never enters this branch.
        action.observation.parents = parents;
        action.observation.cohort_current = true;
        action
            .observation
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let latest = state.latest.ok_or(HostSupervisionError::Unavailable)?;
        self.publish_locked(&mut state, latest)?;
        self.publish_ready_quantum(&mut state)
    }

    fn action_return(&self, binding: ActionBinding) -> Result<ActionReturn, HostSupervisionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = state
            .action
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding || !action.returning {
            return Err(HostSupervisionError::Unavailable);
        }
        action
            .verified_return
            .ok_or(HostSupervisionError::Unavailable)
    }

    fn parent_park_return(
        &self,
        binding: ActionBinding,
        row: u32,
    ) -> Result<crucible_qemu_protocol::parent_park_return::ParentParkReturn, HostSupervisionError>
    {
        self.verified_parent_park_member_return(binding, row)
    }

    fn invalidate_action(&self, binding: ActionBinding) {
        if let Ok(mut state) = self.state.lock()
            && let Some(action) = state.action.as_mut()
            && action.observation.binding == binding
        {
            action.refused = true;
            action.observation.cohort_current = false;
        }
        if let Ok(mut session) = self.publisher_session.lock() {
            let _ = session.revoke_born_command();
        }
        // Publication poison denies semantics but retains descriptors and all
        // exact lender slots for the separate identity-only return path.
        self.mapping.invalidate();
    }
}

#[cfg(test)]
mod tests;
