//! Retains real Quantum lenders across scheduler commit and command publication.
//!
//! Command coordinates corroborate the actual reserved scheduler writer. They
//! grant no operation: only the unique Source producer borrowing its caller's
//! existing Quantum Original can create the retained cohort.

use super::*;
use crucible_qemu_protocol::publisher_subscription::{
    PublisherCommand, PublisherLoanIdentity, PublisherPermission, PublisherPublication,
    PublisherStopMode,
};
use crucible_qemu_shmem::{CommittedSchedulerAdvance, PreparedSchedulerAdvance};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OfferPhase {
    Retaining,
    Ready,
    Attempted,
    Offered(PublisherLoanIdentity),
}

#[derive(Debug)]
pub(in super::super) struct PendingQuantumCommand {
    command: PublisherCommand,
    phase: OfferPhase,
    original_post: Option<HostSupervisionError>,
    cohort_post: Option<HostSupervisionError>,
    notification_attempted: bool,
    notification_first: Option<HostSupervisionError>,
}

impl PendingQuantumCommand {
    pub(in super::super) fn has_publication_attempt(&self) -> bool {
        matches!(self.phase, OfferPhase::Attempted | OfferPhase::Offered(_))
    }

    pub(super) fn new(command: PublisherCommand) -> Self {
        Self {
            command,
            phase: OfferPhase::Retaining,
            original_post: None,
            cohort_post: None,
            notification_attempted: false,
            notification_first: None,
        }
    }
}

impl ActionSourceProducer {
    /// Retains the actual Quantum and Preparation lenders before tuple commit.
    ///
    /// The caller authenticates the prepared writer against its actual mapped
    /// channel before borrowing this producer. The independently mapped runtime
    /// is bound to the same backing and slot; address equality between those
    /// two mappings would incorrectly reject genuine aliases.
    ///
    /// # Errors
    /// Refuses a different operation class, invalid calibration or ceiling,
    /// changed mapping/frontier, occupied Source, or any real lender refusal.
    pub(crate) fn begin_quantum_action(
        &mut self,
        mapping: &crucible_qemu_shmem::MappedSetupRegion,
        slot: u32,
        original: &HostOperationGuard,
        prepared: &PreparedSchedulerAdvance<'_>,
        logical_ceiling: u64,
        stop: crate::QemuQuantumStopCondition,
    ) -> Result<ActionBinding, HostSupervisionError> {
        original.verify_operation_class(
            crucible_host_resources::host_supervision::HostOperationClass::Quantum,
        )?;
        let frontier = mapping
            .fault_command_write_index(slot)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let command = command_coordinates(prepared, logical_ceiling, stop, frontier)?;
        self.begin_request(
            mapping,
            slot,
            frontier,
            RequestIdentity::Quantum { command },
            [Some(original), None],
        )
    }

    /// Seals the retained cohort before the caller's first scheduler mutation.
    ///
    /// # Errors
    /// Refuses a changed request or a dirty, partial, terminal or returned cohort.
    pub(crate) fn begin_quantum_publication(
        &mut self,
        binding: ActionBinding,
    ) -> Result<(), HostSupervisionError> {
        self.refresh_action()?;
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = publication::retained_action(&mut state.action)?;
        if action.observation.binding != binding
            || !action
                .quantum
                .as_ref()
                .is_some_and(|quantum| quantum.phase == OfferPhase::Retaining)
        {
            return Err(HostSupervisionError::Unavailable);
        }
        action.begin_publication()
    }

    /// Publishes only after the actual reserved writer committed its tuple.
    ///
    /// The actual committed receipt remains borrowed through the complete real
    /// lender collector. No callback runs while the session mutex is held.
    ///
    /// # Errors
    /// Refuses another slot/generation, a changed request, an earlier attempt,
    /// or any independent lender, mapped publisher or final collector failure.
    pub(crate) fn commit_quantum_publication(
        &mut self,
        binding: ActionBinding,
        actual_node: &crucible_qemu_shmem::NodeSlot,
        committed: &CommittedSchedulerAdvance<'_>,
    ) -> Result<(), HostSupervisionError> {
        if !committed.belongs_to(actual_node) {
            return Err(HostSupervisionError::Unavailable);
        }
        {
            let mut state = self
                .publisher
                .state
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let action = publication::retained_action(&mut state.action)?;
            let quantum = action
                .quantum
                .as_mut()
                .ok_or(HostSupervisionError::Unavailable)?;
            if action.observation.binding != binding
                || action.publication != PublicationPhase::Publishing
                || quantum.phase != OfferPhase::Retaining
                || quantum.command.scheduler_generation != committed.generation()
            {
                return Err(HostSupervisionError::Unavailable);
            }
            quantum.phase = OfferPhase::Ready;
        }
        self.refresh_action()
    }

    /// Retains both actual independent posts without replacing the offer.
    pub(crate) fn record_quantum_publication_posts(
        &mut self,
        binding: ActionBinding,
        original_post: Option<HostSupervisionError>,
        cohort_post: Option<HostSupervisionError>,
    ) -> Result<(), HostSupervisionError> {
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = publication::retained_action(&mut state.action)?;
        if action.observation.binding != binding {
            return Err(HostSupervisionError::Unavailable);
        }
        let quantum = action
            .quantum
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if let Some(first) = original_post {
            quantum.original_post.get_or_insert(first);
        }
        if let Some(first) = cohort_post {
            quantum.cohort_post.get_or_insert(first);
        }
        Ok(())
    }

    pub(crate) fn deny_quantum_publication(&mut self, binding: ActionBinding) {
        self.publisher.invalidate_action(binding);
    }

    /// Notifies the actual node only after independent Original/cohort posts.
    ///
    /// # Errors
    /// Refuses an unpublished offer, changed action or failed actual event write.
    pub(crate) fn notify_quantum_publication(
        &mut self,
        binding: ActionBinding,
    ) -> Result<(), HostSupervisionError> {
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let action = publication::retained_action(&mut state.action)?;
        let quantum = action
            .quantum
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)?;
        if action.observation.binding != binding
            || action.refused
            || !action.observation.cohort_current
            || !matches!(quantum.phase, OfferPhase::Offered(_))
            || quantum.original_post.is_some()
            || quantum.cohort_post.is_some()
            || quantum.notification_attempted
        {
            return Err(HostSupervisionError::Unavailable);
        }
        quantum.notification_attempted = true;
        let result = (|| {
            let wake = self
                .publisher
                .action_wake
                .lock()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            let wake = wake.as_ref().ok_or(HostSupervisionError::Unavailable)?;
            match rustix::io::write(wake.as_ref(), &1_u64.to_ne_bytes()) {
                Ok(8) | Err(rustix::io::Errno::AGAIN) => Ok(()),
                _ => Err(HostSupervisionError::Unavailable),
            }
        })();
        if let Err(first) = result {
            quantum.notification_first.get_or_insert(first);
        }
        result
    }
}

impl SourcePublisher {
    /// Runs only from the collector while all real lender state locks are held.
    pub(super) fn publish_ready_quantum(
        &self,
        state: &mut PublicationState,
    ) -> Result<(), HostSupervisionError> {
        let action = publication::retained_action(&mut state.action)?;
        let Some(quantum) = action.quantum.as_mut() else {
            return Ok(());
        };
        match quantum.phase {
            OfferPhase::Retaining => return Ok(()),
            OfferPhase::Offered(_) => {
                // The exact session retains peer metadata independently of
                // real Source consumption. Seeing ReturnRequested cannot
                // retire a lender or authorize terminal publication here.
                self.publisher_session
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?
                    .observe_born_command_return()?;
                return Ok(());
            }
            OfferPhase::Attempted => return Err(HostSupervisionError::Unavailable),
            OfferPhase::Ready => {}
        }
        if action.publication != PublicationPhase::Publishing
            || !action.observation.cohort_current
            || action.refused
            || action.returning
        {
            return Err(HostSupervisionError::Unavailable);
        }
        quantum.command.native_monotonic_ns_ceiling = native_ceiling(&action.observation)?;
        let publication = PublisherPublication {
            sequence: 2,
            standing_sequence: state.sequence,
            offer_generation: 1,
            ticket_serial: 1,
            permission: PublisherPermission::Borrowable,
            cohort: action.observation,
            command: Some(quantum.command),
        };
        quantum.phase = OfferPhase::Attempted;
        let identity = self
            .publisher_session
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?
            .publish_command_offer(publication)?;
        quantum.phase = OfferPhase::Offered(identity);
        action.publication = PublicationPhase::Published;
        Ok(())
    }
}

fn command_coordinates(
    prepared: &PreparedSchedulerAdvance<'_>,
    logical_ceiling: u64,
    stop: crate::QemuQuantumStopCondition,
    frontier: u64,
) -> Result<PublisherCommand, HostSupervisionError> {
    let snapshot = prepared.snapshot();
    let raw_ticks = snapshot
        .logical_time_raw_icount
        .checked_mul(crucible_engine::SIM_TICKS_PER_INSTRUCTION)
        .ok_or(HostSupervisionError::InvalidBudget)?;
    let offset = snapshot
        .current_icount
        .checked_sub(raw_ticks)
        .ok_or(HostSupervisionError::InvalidBudget)?;
    let maximum_raw_icount = logical_ceiling
        .checked_sub(offset)
        .ok_or(HostSupervisionError::InvalidBudget)?
        / crucible_engine::SIM_TICKS_PER_INSTRUCTION;
    if logical_ceiling < snapshot.current_icount
        || maximum_raw_icount < snapshot.logical_time_raw_icount
    {
        return Err(HostSupervisionError::InvalidBudget);
    }
    Ok(PublisherCommand {
        scheduler_generation: prepared.generation(),
        initial_raw_icount: snapshot.logical_time_raw_icount,
        maximum_raw_icount,
        logical_tick_ceiling: logical_ceiling,
        native_monotonic_ns_ceiling: 0,
        stop: match stop {
            crate::QemuQuantumStopCondition::Ceiling => PublisherStopMode::RetiredCeiling,
            crate::QemuQuantumStopCondition::NextAuthenticatedIdle => PublisherStopMode::NextIdle {
                target_generation: prepared.generation(),
            },
        },
        frontier,
    })
}

fn native_ceiling(cohort: &ActionObservation) -> Result<u64, HostSupervisionError> {
    if !cohort.cohort_current || !(1..=4).contains(&cohort.row_count) {
        return Err(HostSupervisionError::Unavailable);
    }
    Ok(cohort.parents[..cohort.row_count as usize]
        .iter()
        .flat_map(|parent| {
            [
                parent.total_end_ns,
                parent.progress_end_ns,
                parent.outer_end_ns,
                parent.private_end_ns,
            ]
        })
        .filter(|end| *end != 0)
        .min()
        .unwrap_or(0))
}

#[cfg(test)]
mod tests;
