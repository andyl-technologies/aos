//! Funds the initial append bank before any World publication effect.
//!
//! The first semantic event is the explicitly declared initial-world-ready
//! control. It is committed only after the same barrier returns genuine World
//! authority and complete currentness checks succeed. Its evidence is the exact
//! coordinator object already acknowledged by that actual World publication.

use super::*;
use crate::node_contract::PublicationStatus;

/// Prices the original fixed bank independently of native ingress storage.
///
/// The original initial constructor retains this row before whole admission.
/// It does not authorize native activity, replace a Source declaration or turn
/// a decoded checkpoint into a fresh coordinator issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalCoordinator17ConstructionData {
    maximum_records: usize,
    retained_requested_bytes: usize,
    declared_counter_scratch_bytes: usize,
}

impl OriginalCoordinator17ConstructionData {
    /// Quotes the complete fixed bank and defining current-constructor views.
    ///
    /// # Errors
    /// Refuses a zero/unrepresentable lifetime ceiling, checked layout overflow
    /// or requested storage above the independently supplied admission maximum.
    pub fn quote(maximum_records: usize, maximum: usize) -> Result<Self, RuntimeError> {
        if maximum_records < 2 {
            return Err(RuntimeError::ResourceLimit);
        }
        let policy = CoordinatorCommitmentPolicy17::new(maximum_records)?;
        let retained_requested_bytes = policy.requested_bytes_data()?;
        let declared_counter_scratch_bytes = counter_scratch_data()
            .checked_add(size_of::<Self>())
            .and_then(|n| n.checked_add(size_of::<&Self>()))
            .and_then(|n| n.checked_add(size_of::<Option<&Self>>()))
            .and_then(|n| n.checked_add(size_of::<Result<Self, RuntimeError>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        retained_requested_bytes
            .checked_add(declared_counter_scratch_bytes)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(Self {
            maximum_records,
            retained_requested_bytes,
            declared_counter_scratch_bytes,
        })
    }

    /// Returns the complete original prospective retained bank demand.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained_requested_bytes
    }

    /// Returns the defining independently admitted counter/constructor views.
    pub const fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.declared_counter_scratch_bytes
    }

    /// Sums the independently simultaneous axes without granting allocation.
    ///
    /// # Errors
    /// Refuses checked requested-byte overflow.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.retained_requested_bytes
            .checked_add(self.declared_counter_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl NodeRuntime {
    pub(crate) fn initialize_original_coordinator17_data(
        &self,
        row: &OriginalCoordinator17ConstructionData,
    ) -> Result<(), RuntimeError> {
        if self.activated
            || !self.barrier.can_arm()
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || self.scheduling_origin()?.initialized()?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let expected = OriginalCoordinator17ConstructionData::quote(
            row.maximum_records,
            row.requested_bytes_data()?,
        )?;
        if expected != *row {
            return Err(RuntimeError::ForeignAuthority);
        }
        let policy = CoordinatorCommitmentPolicy17::new(row.maximum_records)?;
        self.scheduling_origin()?
            .initialize_initial_coordinator17_data(
                CoordinatorCommitments17::unallocated(policy),
                row.retained_requested_bytes,
            )
    }
}

impl CoordinatorCommitments17 {
    /// Spends the original activation attempt before the publisher callback.
    pub(super) fn prepare_activation_data(
        &mut self,
        position: Position,
    ) -> Result<(), RuntimeError> {
        if !self.initialized || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        if let Some(attempt) = self.activation_attempt {
            let entry = self.entry_data(attempt)?;
            if entry.kind != CoordinatorCommitmentKind17::Activation
                || entry.position != Some(position)
                || !matches!(
                    entry.state,
                    CoordinatorCommitmentState17::Reserved
                        | CoordinatorCommitmentState17::Uncertain
                        | CoordinatorCommitmentState17::Committed
                )
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            if entry.state == CoordinatorCommitmentState17::Committed {
                self.authenticate_completed_activation_data()?;
                return Ok(());
            }
            // Reconciliation concerns the same original publication identity.
            entry.state = CoordinatorCommitmentState17::Uncertain;
            return Ok(());
        }
        let semantic = usize::from(self.parent.is_none());
        let attempt = self.reserve_data(
            CoordinatorCommitmentKind17::Activation,
            None,
            None,
            Some(position),
            semantic,
        )?;
        self.activation_attempt = Some(attempt);
        self.entries[attempt.index].state = CoordinatorCommitmentState17::Uncertain;
        Ok(())
    }

    fn authenticate_completed_activation_data(&self) -> Result<(), RuntimeError> {
        if !self.initialized || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let attempt = self
            .activation_attempt
            .ok_or(RuntimeError::ForeignAuthority)?;
        let activation = self
            .entries
            .get(attempt.index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if activation.sequence != attempt.sequence
            || activation.kind != CoordinatorCommitmentKind17::Activation
            || activation.state != CoordinatorCommitmentState17::Committed
            || activation.evidence.is_none()
            || activation.event_ordinal.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.parent.is_none() {
            let ready = self
                .entries
                .get(
                    attempt
                        .index
                        .checked_add(1)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ForeignAuthority)?;
            if ready.kind != CoordinatorCommitmentKind17::Control
                || ready.state != CoordinatorCommitmentState17::Committed
                || ready.operation.is_some()
                || ready.node.is_some()
                || ready.position != activation.position
                || ready.evidence != activation.evidence
                || ready.event_ordinal != Some(U64::new(0))
                || self.next_event_ordinal.get() == 0
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }

    fn settle_activation_data(
        &mut self,
        status: Option<PublicationStatus>,
        world: Option<&WorldActivation>,
    ) -> Result<(), RuntimeError> {
        if !self.initialized || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let attempt = self
            .activation_attempt
            .ok_or(RuntimeError::ForeignAuthority)?;
        if self
            .entries
            .get(attempt.index)
            .is_some_and(|entry| entry.state == CoordinatorCommitmentState17::Committed)
        {
            self.authenticate_completed_activation_data()?;
        }
        let entry = self.entry_data(attempt)?;
        if entry.state == CoordinatorCommitmentState17::Committed {
            let world = world.ok_or(RuntimeError::ForeignAuthority)?;
            let coordinator = world
                .coordinator_snapshot()
                .ok_or(RuntimeError::InvalidReceipt)?;
            if status != Some(PublicationStatus::Committed)
                || entry.position != Some(world.record().boundary)
                || entry.evidence.as_ref() != Some(&coordinator.reference)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            return Ok(());
        }
        if !matches!(
            entry.state,
            CoordinatorCommitmentState17::Reserved | CoordinatorCommitmentState17::Uncertain
        ) {
            return Err(RuntimeError::ForeignAuthority);
        }
        match (status, world) {
            (Some(PublicationStatus::NotCommitted), None) => {
                entry.state = CoordinatorCommitmentState17::Refused;
                self.release_future_data(attempt)
            }
            (Some(PublicationStatus::Committed), Some(world)) => {
                let coordinator = world
                    .coordinator_snapshot()
                    .ok_or(RuntimeError::InvalidReceipt)?;
                coordinator
                    .reference
                    .verify(&coordinator.bytes)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                if entry.position != Some(world.record().boundary) {
                    return Err(RuntimeError::ForeignAuthority);
                }
                // Both future evidence clones were included in the original
                // bounded ContentRef bank. A partial clone failure poisons the
                // same retained owner and cannot be retried as a fresh effect.
                self.failed = true;
                self.entries[attempt.index].evidence =
                    Some(clone_reference(&coordinator.reference)?);
                self.entries[attempt.index].state = CoordinatorCommitmentState17::Committed;
                if self.parent.is_none() {
                    if self.first_sequence.get() != 0
                        || self.first_event_ordinal.get() != 0
                        || self.next_event_ordinal.get() != 0
                        || self.future_semantic[attempt.index] != 1
                        || self.entries.len() == self.entries.capacity()
                        || self.future_semantic.len() == self.future_semantic.capacity()
                    {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    let sequence = self.next_sequence;
                    let next = sequence
                        .checked_add(U64::new(1))
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                    self.entries.push(CoordinatorCommitmentEntry17 {
                        sequence,
                        kind: CoordinatorCommitmentKind17::Control,
                        operation: None,
                        node: None,
                        position: Some(world.record().boundary),
                        evidence: None,
                        state: CoordinatorCommitmentState17::Reserved,
                        event_ordinal: None,
                    });
                    self.future_semantic.push(0);
                    self.next_sequence = next;
                    self.future_semantic[attempt.index] = 0;
                    self.reserved_semantic = self
                        .reserved_semantic
                        .checked_sub(1)
                        .ok_or(RuntimeError::ForeignAuthority)?;
                    let control = self
                        .entries
                        .last_mut()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    control.evidence = Some(clone_reference(&coordinator.reference)?);
                    control.state = CoordinatorCommitmentState17::Committed;
                    control.event_ordinal = Some(U64::new(0));
                    self.next_event_ordinal = U64::new(1);
                }
                self.failed = false;
                Ok(())
            }
            _ => {
                entry.state = CoordinatorCommitmentState17::Uncertain;
                Ok(())
            }
        }
    }
}

impl NodeRuntime {
    pub(crate) fn prepare_coordinator17_activation_data(&self) -> Result<(), RuntimeError> {
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .with_coordinator17_data(|log| {
                if let Some(log) = log {
                    log.prepare_activation_data(self.barrier.record().boundary)?;
                }
                Ok(())
            })
    }

    pub(crate) fn settle_coordinator17_activation_data(
        &self,
        world: Option<&WorldActivation>,
    ) -> Result<(), RuntimeError> {
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?
            .with_coordinator17_data(|log| {
                if let Some(log) = log {
                    log.settle_activation_data(
                        self.barrier.publication_status_or_not_attempted(),
                        world,
                    )?;
                }
                Ok(())
            })
    }

    /// Borrows immutable limits from this actual Runtime without minting credit.
    pub(crate) fn host_restored17_runtime_limits_data(&self) -> RuntimeLimits {
        self.limits
    }
}

impl NodeRuntime {
    /// Prices the actual future Runtime7 typed/DOM/canonical owner before copy.
    pub(crate) fn host_restored17_runtime_snapshot_construction_data(
        &self,
        cut: Position,
        ordinal: U64,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let view = super::super::original_input_lineage::snapshot_credit::SnapshotView {
            runtime: self,
            cut,
            ordinal,
        };
        Self::original_restoration_coordinator_serialization_geometry_data(
            &view,
            Self::capture_closed_inline_storage(),
            maximum,
        )
        .map(|(requested, _)| requested)
    }

    /// Prices the same current Scheduler1 owner without creating a snapshot.
    pub(crate) fn host_restored17_scheduler_snapshot_construction_data(
        &self,
        cut: Position,
        ordinal: U64,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.scheduling_origin()?
            .retained()?
            .restored17_snapshot_construction_data(cut, ordinal, maximum)
    }
}

#[cfg(test)]
mod activation_failure_tests {
    use super::*;

    #[test]
    fn partial_genesis_poison_cannot_be_bypassed_by_a_committed_activation_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = CoordinatorCommitmentPolicy17::new(3)?;
        let mut log = CoordinatorCommitments17::unallocated(policy);
        log.initialize_data(policy.requested_bytes_data()?)?;
        let position = Position::new(
            U64::new(0),
            U64::new(0),
            crucible_node_contract::Phase::BoundaryControl,
        );
        log.prepare_activation_data(position)?;
        let attempt = log
            .activation_attempt
            .ok_or(RuntimeError::ForeignAuthority)?;
        // This is the actual retained disposition after a later evidence clone
        // or genesis-control construction fails, before Runtime activation.
        log.entries[attempt.index].state = CoordinatorCommitmentState17::Committed;
        log.failed = true;
        assert!(log.prepare_activation_data(position).is_err());
        assert!(
            log.settle_activation_data(Some(PublicationStatus::Committed), None)
                .is_err()
        );
        assert!(log.require_settled_data().is_err());
        assert_eq!(log.next_event_ordinal, U64::new(0));
        assert_eq!(log.next_sequence, U64::new(1));
        Ok(())
    }
}
