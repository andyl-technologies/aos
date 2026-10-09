//! Authentic external root-prefix observations and retained original input bytes.

use super::*;

impl CausalScheduler {
    pub(super) fn prepare_external_inputs(
        &self,
        observation: &NativeSchedulingObservation,
        original: Option<&Reservation>,
        update: &mut ObservationUpdate,
    ) -> Result<(), SchedulingError> {
        if observation.external_inputs.len() > MAX_ARRAY_ELEMENTS {
            return Err(SchedulingError::CapacityExceeded);
        }
        let owner = self.owner_id(&observation.node)?;
        let mut seen = BTreeSet::new();
        let mut retained_bytes = self
            .payloads
            .values()
            .chain(update.payloads.iter().map(|(_, bytes)| bytes))
            .try_fold(0u64, |total, bytes| {
                total
                    .checked_add(bytes.len() as u64)
                    .ok_or(SchedulingError::CapacityExceeded)
            })?;
        for inventory in &observation.external_inputs {
            let policy = self
                .external_roots
                .get(&inventory.endpoint)
                .ok_or(SchedulingError::InvalidReceipt)?;
            inventory.proof_ref.validate()?;
            check_position(inventory.closed_before, self.maximum_microsteps)?;
            if self.node_owners.get(&inventory.endpoint.node_id) != Some(owner)
                || !seen.insert(inventory.endpoint.clone())
                || inventory.inputs.len() > MAX_ARRAY_ELEMENTS
                || inventory.closed_before < self.schedule(&inventory.endpoint.node_id)?.cursor
                || self
                    .external_closed_prefixes
                    .get(&inventory.endpoint)
                    .is_some_and(|old| *old > inventory.closed_before)
            {
                return Err(SchedulingError::CausalRegression);
            }
            // A refreshed full native inventory cannot forget an arrival that
            // still has coordinator custody. Only actual consumption in the
            // original semantic operation may retire that FIFO membership.
            let retained_native_sequences: BTreeSet<_> = inventory
                .inputs
                .iter()
                .map(|input| input.native_sequence)
                .collect();
            for prior in self
                .pending
                .values()
                .filter(|delivery| delivery.external_root.as_ref() == Some(&inventory.endpoint))
            {
                let consumed = update.consumed.as_ref().is_some_and(|(_, identities)| {
                    identities.contains(&super::super::inputs_impl::input_identity(prior))
                });
                if !consumed && !retained_native_sequences.contains(&prior.native_sequence) {
                    return Err(SchedulingError::InvalidReceipt);
                }
            }
            let mut previous = None;
            for input in &inventory.inputs {
                input.event_id.validate()?;
                input.payload.validate()?;
                input.provenance_ref.validate()?;
                if input.publication.phase != Phase::Publication
                    || input.publication.microstep.get() != 0
                    || previous.is_some_and(|last| last >= input.native_sequence)
                    || input.payload.length > policy.maximum_payload_bytes
                    || input.payload_bytes.len() as u64 != input.payload.length.get()
                    || canonical::content_ref(&input.payload_bytes, &input.payload.media_type)?
                        != input.payload
                {
                    return Err(SchedulingError::InvalidPublication);
                }
                previous = Some(input.native_sequence);
                let delivery = crate::node_scheduling::event::direct_delivery(
                    input.publication,
                    U64::new(0),
                    policy.grid,
                )?;
                if let Some(last) = update.native_sequences.get(&inventory.endpoint) {
                    if input.native_sequence <= *last {
                        let prior = self
                            .pending
                            .values()
                            .chain(update.deliveries.iter())
                            .find(|event| {
                                event.external_root.as_ref() == Some(&inventory.endpoint)
                                    && event.native_sequence == input.native_sequence
                            })
                            .ok_or(SchedulingError::CausalRegression)?;
                        if prior.publication_id != input.event_id
                            || prior.publication != input.publication
                            || prior.delivery != delivery
                            || prior.payload != input.payload
                            || prior.provenance_ref != input.provenance_ref
                        {
                            return Err(SchedulingError::InvalidReceipt);
                        }
                        continue;
                    }
                }
                if self
                    .external_closed_prefixes
                    .get(&inventory.endpoint)
                    .is_some_and(|closed| delivery < *closed)
                {
                    return Err(SchedulingError::CausalRegression);
                }
                let cursor = self.schedule(&inventory.endpoint.node_id)?.cursor;
                let blocked = self
                    .schedule(&inventory.endpoint.node_id)?
                    .reserved
                    .as_ref()
                    .and_then(|id| self.operations.get(id));
                let outruns = blocked.is_some_and(|active| {
                    if original.is_some_and(|operation| operation.owner == active.owner) {
                        return delivery < observation.reached;
                    }
                    match active.request {
                        OperationRequest::ExactRun { limit, .. }
                        | OperationRequest::BoundarySettle { limit, .. } => delivery < limit,
                        OperationRequest::QuantumBegin { start, .. } => {
                            delivery.time_ps <= start.time_ps
                        }
                        _ => true,
                    }
                });
                if delivery < cursor || outruns {
                    return Err(SchedulingError::CausalRegression);
                }
                let pending_bytes = self
                    .pending
                    .values()
                    .chain(update.deliveries.iter())
                    .filter(|event| event.external_root.as_ref() == Some(&inventory.endpoint))
                    .try_fold(0u64, |total, event| {
                        total
                            .checked_add(event.payload.length.get())
                            .ok_or(SchedulingError::CapacityExceeded)
                    })?;
                if pending_bytes
                    .checked_add(input.payload.length.get())
                    .is_none_or(|total| total > policy.maximum_pending_bytes.get())
                {
                    return Err(SchedulingError::CapacityExceeded);
                }
                if self
                    .pending
                    .len()
                    .checked_add(update.deliveries.len())
                    .is_none_or(|count| count >= MAX_ARRAY_ELEMENTS)
                {
                    return Err(SchedulingError::CapacityExceeded);
                }
                let sequence = update.sequences.allocate(&inventory.endpoint.node_id)?;
                update.deliveries.push(Delivery {
                    connection_id: None,
                    connection_policy_ref: None,
                    external_root: Some(inventory.endpoint.clone()),
                    provenance_ref: input.provenance_ref.clone(),
                    publication_id: input.event_id.clone(),
                    producer: inventory.endpoint.node_id.clone(),
                    consumer: inventory.endpoint.node_id.clone(),
                    producer_endpoint: inventory.endpoint.clone(),
                    consumer_endpoint: inventory.endpoint.clone(),
                    source_sequence: sequence,
                    native_sequence: input.native_sequence,
                    evaluation: None,
                    causal_parents: Vec::new(),
                    publication: input.publication,
                    delivery,
                    payload: input.payload.clone(),
                });
                update
                    .native_sequences
                    .insert(inventory.endpoint.clone(), input.native_sequence);
                if !self.payloads.contains_key(&input.payload)
                    && !update
                        .payloads
                        .iter()
                        .any(|(reference, _)| reference == &input.payload)
                {
                    retained_bytes = retained_bytes
                        .checked_add(input.payload.length.get())
                        .ok_or(SchedulingError::CapacityExceeded)?;
                    if retained_bytes > self.maximum_pending_payload_bytes.get() {
                        return Err(SchedulingError::CapacityExceeded);
                    }
                    update
                        .payloads
                        .push((input.payload.clone(), input.payload_bytes.clone()));
                }
            }
            update
                .external_prefixes
                .insert(inventory.endpoint.clone(), inventory.closed_before);
        }
        Ok(())
    }
}
