//! Frozen complete input-prefix custody and original native staging evidence.

use super::*;
use crate::node_scheduling::{
    InputCustodyCommit, InputIdentity, InputPayload, RuntimeInputBatch,
    ValidatedInputAcknowledgement,
};
use crucible_node_contract::{MAX_ARRAY_ELEMENTS, Validate, canonical};

impl CausalScheduler {
    /// Freezes a complete canonical input prefix before native staging.
    ///
    /// Exact cuts exclude the cutoff position. Quantized cuts must be the next
    /// physical tick after the start, thereby including every phase and microstep
    /// at the start boundary. This operation does not deliver modeled input.
    /// Dropping the returned handle leaves the immutable original cut retained.
    ///
    /// # Errors
    /// Refuses incomplete production closure, busy owners, prior unconsumed cuts,
    /// reused identities, invalid coordinates, and unavailable immutable bytes.
    pub fn prepare_input_batch(
        &mut self,
        node: &Id,
        stage_operation: Id,
        batch: Id,
        cutoff: Position,
    ) -> Result<RuntimeInputBatch, SchedulingError> {
        stage_operation.validate()?;
        batch.validate()?;
        let owner = self.owner_id(node)?.clone();
        let schedule = self.schedule(node)?;
        if schedule.reserved.is_some() || self.input_batches.contains_key(&owner) {
            return Err(SchedulingError::OwnerBusy);
        }
        if self.used_operations.contains(&stage_operation)
            || self.used_input_batches.contains(&batch)
        {
            return Err(SchedulingError::DuplicateOperation);
        }
        if self.used_operations.len() >= MAX_ARRAY_ELEMENTS
            || self.used_input_batches.len() >= MAX_ARRAY_ELEMENTS
        {
            return Err(SchedulingError::CapacityExceeded);
        }
        if cutoff <= schedule.cursor
            || cutoff.microstep >= self.maximum_microsteps
                && !(self.maximum_microsteps.get() == 0 && cutoff.microstep.get() == 0)
        {
            return Err(SchedulingError::NoSafeProgress);
        }
        match schedule.policy {
            ExecutionPolicy::Exact { .. } => {
                for path in &schedule.inputs {
                    if self.earliest_delivery(path)? < cutoff {
                        return Err(SchedulingError::InputBlocked(path.producer.clone()));
                    }
                }
            }
            ExecutionPolicy::Quantized { .. } => {
                let after_start = schedule.cursor.time_ps.checked_add(U64::new(1))?;
                if cutoff != Position::new(after_start, U64::new(0), Phase::BoundaryControl) {
                    return Err(SchedulingError::NoSafeProgress);
                }
                self.require_boundary_closed(&owner, schedule.cursor.time_ps)?;
            }
        }
        let deliveries: Vec<_> = self
            .pending
            .values()
            .filter(|delivery| {
                self.node_owners.get(&delivery.consumer) == Some(&owner)
                    && delivery.delivery < cutoff
            })
            .cloned()
            .collect();
        if deliveries.len() > MAX_ARRAY_ELEMENTS {
            return Err(SchedulingError::CapacityExceeded);
        }
        let references: BTreeSet<_> = deliveries
            .iter()
            .map(|delivery| delivery.payload.clone())
            .collect();
        let payloads = references
            .into_iter()
            .map(|reference| {
                let bytes = self
                    .payloads
                    .get(&reference)
                    .ok_or(SchedulingError::MissingObservation)?
                    .clone();
                Ok(InputPayload { reference, bytes })
            })
            .collect::<Result<Vec<_>, SchedulingError>>()?;
        let value = serde_json::to_value(&deliveries)
            .map_err(crucible_node_contract::ContractError::from)?;
        let canonical_inventory = canonical::canonical_json(&value)?;
        let inventory = canonical::content_ref(
            &canonical_inventory,
            "application/vnd.crucible.input-inventory+json",
        )?;
        let prepared = RuntimeInputBatch {
            activation: self.activation.clone(),
            node: node.clone(),
            stage_operation: stage_operation.clone(),
            batch: batch.clone(),
            owners: self
                .node_routes
                .get(node)
                .ok_or(SchedulingError::UnknownNode)?
                .clone(),
            cutoff,
            inventory,
            deliveries,
            payloads,
        };
        self.used_operations.insert(stage_operation);
        self.used_input_batches.insert(batch);
        self.input_batches.insert(
            owner,
            InputBatchState {
                batch: prepared.retained_copy(),
                acknowledgement: None,
                activated_by: None,
                consumed: Vec::new(),
            },
        );
        Ok(prepared)
    }

    // Runtime publication retains this commitment before exposing it, so lost
    // caller handles cannot erase native staging acknowledgement authority.
    pub(crate) fn accept_input_acknowledgement(
        &mut self,
        validated: ValidatedInputAcknowledgement,
    ) -> Result<InputCustodyCommit, SchedulingError> {
        if !Rc::ptr_eq(&self.activation.authority, &validated.activation.authority)
            || self.activation.record() != validated.activation.record()
        {
            return Err(SchedulingError::ForeignActivation);
        }
        let ack = validated.acknowledgement;
        ack.proof_ref.validate()?;
        let owner = self.owner_id(&ack.node)?.clone();
        let state = self
            .input_batches
            .get_mut(&owner)
            .ok_or(SchedulingError::InvalidReceipt)?;
        let batch = &state.batch;
        if ack.node != batch.node
            || ack.stage_operation != batch.stage_operation
            || ack.batch != batch.batch
            || ack.cutoff != batch.cutoff
            || ack.inventory != batch.inventory
            || ack.owners != batch.owners
            || state
                .acknowledgement
                .as_ref()
                .is_some_and(|original| original != &ack)
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        let commit = InputCustodyCommit {
            activation: self.activation.clone(),
            node: ack.node.clone(),
            stage_operation: ack.stage_operation.clone(),
            batch: ack.batch.clone(),
            inventory: ack.inventory.clone(),
            cutoff: ack.cutoff,
        };
        state.acknowledgement = Some(ack);
        Ok(commit)
    }

    /// Abandons an original immutable cut that was never handed to native staging.
    ///
    /// # Errors
    /// Refuses foreign authority, changed original inventory, or staging that has
    /// already acquired authenticated native custody or execution effects.
    pub fn abandon_input_undispatched(
        &mut self,
        batch: RuntimeInputBatch,
    ) -> Result<(), SchedulingError> {
        self.reconcile_input_no_effect(&batch)
    }

    pub(crate) fn reconcile_input_no_effect(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<(), SchedulingError> {
        if !Rc::ptr_eq(&self.activation.authority, &batch.activation.authority)
            || self.activation.record() != batch.activation.record()
        {
            return Err(SchedulingError::ForeignActivation);
        }
        let owner = self.owner_id(&batch.node)?.clone();
        let state = self
            .input_batches
            .get(&owner)
            .ok_or(SchedulingError::InvalidReceipt)?;
        if state.batch.batch != batch.batch
            || state.batch.stage_operation != batch.stage_operation
            || state.batch.inventory != batch.inventory
            || state.acknowledgement.is_some()
            || state.activated_by.is_some()
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        self.input_batches.remove(&owner);
        Ok(())
    }

    pub(super) fn staged_batch(&self, owner: &Id) -> Result<&InputBatchState, SchedulingError> {
        let state = self
            .input_batches
            .get(owner)
            .ok_or(SchedulingError::MissingObservation)?;
        if state.acknowledgement.is_none() || state.activated_by.is_some() {
            return Err(SchedulingError::MissingObservation);
        }
        Ok(state)
    }

    pub(super) fn input_captured(&self, owner: &Id, delivery: &Delivery) -> bool {
        self.input_batches.get(owner).is_some_and(|state| {
            state.acknowledgement.is_some()
                && state
                    .batch
                    .deliveries
                    .iter()
                    .any(|original| original == delivery)
                && !state.consumed.contains(&input_identity(delivery))
        })
    }

    pub(super) fn activate_input_batch(
        &mut self,
        owner: &Id,
        operation: &Id,
        batch: &Id,
    ) -> Result<(), SchedulingError> {
        let state = self
            .input_batches
            .get_mut(owner)
            .ok_or(SchedulingError::MissingObservation)?;
        if state.acknowledgement.is_none()
            || state.batch.batch != *batch
            || state.activated_by.is_some()
        {
            return Err(SchedulingError::MissingObservation);
        }
        state.activated_by = Some(operation.clone());
        self.operations
            .get_mut(operation)
            .ok_or(SchedulingError::InvalidReceipt)?
            .input_batch = Some(batch.clone());
        Ok(())
    }

    pub(super) fn release_input_activation(&mut self, owner: &Id, operation: &Id) {
        if let Some(state) = self.input_batches.get_mut(owner)
            && state.activated_by.as_ref() == Some(operation)
        {
            state.activated_by = None;
        }
    }

    pub(super) fn retire_consumed_batch(&mut self, owner: &Id) {
        if self
            .input_batches
            .get(owner)
            .is_some_and(|state| state.batch.deliveries.len() == state.consumed.len())
        {
            self.input_batches.remove(owner);
        }
        let needed: BTreeSet<_> = self
            .pending
            .values()
            .map(|delivery| delivery.payload.clone())
            .collect();
        self.payloads
            .retain(|reference, _| needed.contains(reference));
    }
}

pub(super) fn input_identity(delivery: &Delivery) -> InputIdentity {
    InputIdentity {
        producer: delivery.producer.clone(),
        source_sequence: delivery.source_sequence,
    }
}
