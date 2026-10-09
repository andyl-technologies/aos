//! Atomic application of runtime-authenticated producer observations and output.

use super::*;
use crate::node_admission::{ConnectionDelivery, VisibilityConversion};
use crate::node_scheduling::{
    NativeOutputBound, NativeSchedulingObservation, ValidatedSchedulingObservation,
};
use crucible_node_contract::{ContentRef, MAX_ARRAY_ELEMENTS, Validate, canonical};

pub(super) struct ObservationUpdate {
    bounds: BTreeMap<Id, OutputBound>,
    prefixes: BTreeMap<Id, Position>,
    sequences: super::super::event::ProducerSequences,
    native_sequences: BTreeMap<Endpoint, U64>,
    external_prefixes: BTreeMap<Endpoint, Position>,
    deliveries: Vec<Delivery>,
    payloads: Vec<(ContentRef, Vec<u8>)>,
    consumed: Option<(Id, Vec<crate::node_scheduling::InputIdentity>)>,
}

impl CausalScheduler {
    /// Incorporates authentic complete stopped-owner closure without executing it.
    ///
    /// The observation supplies qualified future-output evidence even when the
    /// coordinator queue is empty. Ordinary portable bound records cannot call
    /// this path. Unowned original output is refused rather than acknowledged.
    ///
    /// # Errors
    /// Refuses foreign authority, incomplete producer coverage, regressing bounds,
    /// invalid closure or publications without original operation custody.
    pub fn accept_boundary_observation(
        &mut self,
        receipt: ValidatedSchedulingObservation,
    ) -> Result<(), SchedulingError> {
        if !Rc::ptr_eq(&self.activation.authority, &receipt.activation.authority)
            || self.activation.record() != receipt.activation.record()
        {
            return Err(SchedulingError::ForeignActivation);
        }
        if !receipt.observation.publications.is_empty() {
            return Err(SchedulingError::MissingOutputCoordinates);
        }
        let update = self.prepare_observation(&receipt.observation, None)?;
        self.apply_observation(update);
        Ok(())
    }

    pub(super) fn prepare_observation(
        &self,
        observation: &NativeSchedulingObservation,
        original: Option<&Reservation>,
    ) -> Result<ObservationUpdate, SchedulingError> {
        observation.proof_ref.validate()?;
        check_position(observation.reached, self.maximum_microsteps)?;
        check_position(observation.closed_prefix, self.maximum_microsteps)?;
        let owner = self.owner_id(&observation.node)?;
        if self.node_routes.get(&observation.node) != Some(&observation.owners)
            || (original.is_none() && self.schedule(&observation.node)?.reserved.is_some())
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        let members: Vec<_> = self
            .node_owners
            .iter()
            .filter(|(_, member_owner)| *member_owner == owner)
            .map(|(node, _)| node.clone())
            .collect();
        if observation.bounds.len() > MAX_ARRAY_ELEMENTS
            || observation.publications.len() > MAX_ARRAY_ELEMENTS
            || observation
                .bounds
                .iter()
                .map(|bound| bound.producer.clone())
                .collect::<Vec<_>>()
                != members
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        if original.is_none() && observation.reached != self.schedule(&observation.node)?.cursor {
            return Err(SchedulingError::InvalidReceipt);
        }
        let mut bounds = self.bounds.clone();
        let mut prefixes = self.closed_prefixes.clone();
        for claimed in &observation.bounds {
            claimed.proof_ref.validate()?;
            let bound = match claimed.bound {
                NativeOutputBound::Unknown => OutputBound::Unknown,
                NativeOutputBound::At(position) => {
                    check_position(position, self.maximum_microsteps)?;
                    if position.phase != Phase::Publication {
                        return Err(SchedulingError::InvalidPublication);
                    }
                    OutputBound::At(position)
                }
                NativeOutputBound::AfterInstant(time) => OutputBound::AfterInstant(time),
            };
            let old = self
                .bounds
                .get(&claimed.producer)
                .ok_or(SchedulingError::UnknownNode)?;
            if !strengthens(*old, bound)
                || prefixes
                    .get(&claimed.producer)
                    .is_some_and(|old| *old > observation.closed_prefix)
            {
                return Err(SchedulingError::CausalRegression);
            }
            bounds.insert(claimed.producer.clone(), bound);
            prefixes.insert(claimed.producer.clone(), observation.closed_prefix);
        }
        let mut update = ObservationUpdate {
            bounds,
            prefixes,
            sequences: self.sequences.clone(),
            native_sequences: self.native_sequences.clone(),
            external_prefixes: self.external_closed_prefixes.clone(),
            deliveries: Vec::new(),
            payloads: Vec::new(),
            consumed: self.prepare_input_progress(observation, original)?,
        };
        let mut publication_ids = BTreeSet::new();
        let mut retained_payload_bytes =
            self.payloads.values().try_fold(0u64, |total, bytes| {
                total
                    .checked_add(bytes.len() as u64)
                    .ok_or(SchedulingError::CapacityExceeded)
            })?;
        for publication in &observation.publications {
            let original = original.ok_or(SchedulingError::MissingOutputCoordinates)?;
            if !publication_ids.insert(publication.publication_id.clone())
                || self.node_owners.get(&publication.endpoint.node_id) != Some(owner)
                || publication.causal_parents.len() > MAX_ARRAY_ELEMENTS
            {
                return Err(SchedulingError::InvalidReceipt);
            }
            let maximum_payload = self
                .output_endpoints
                .get(&publication.endpoint)
                .ok_or(SchedulingError::InvalidPublication)?;
            if publication.payload.length > *maximum_payload
                || publication.payload_bytes.len() as u64 != publication.payload.length.get()
            {
                return Err(SchedulingError::CapacityExceeded);
            }
            publication.payload.validate()?;
            if canonical::content_ref(&publication.payload_bytes, &publication.payload.media_type)?
                != publication.payload
            {
                return Err(SchedulingError::InvalidPublication);
            }
            check_position(publication.publication, self.maximum_microsteps)?;
            if publication.publication.phase != Phase::Publication {
                return Err(SchedulingError::InvalidPublication);
            }
            match &original.request {
                OperationRequest::ExactRun { start, limit, .. }
                | OperationRequest::BoundarySettle { start, limit } => {
                    let evaluation = publication
                        .evaluation
                        .ok_or(SchedulingError::InvalidPublication)?;
                    if evaluation < *start
                        || evaluation >= *limit
                        || super::super::event::reaction_publication(
                            &publication.causal_parents,
                            evaluation,
                            publication.publication.time_ps,
                            self.maximum_microsteps,
                        )? != publication.publication
                    {
                        return Err(SchedulingError::InvalidPublication);
                    }
                }
                OperationRequest::QuantumBegin { end, .. } => {
                    if publication.publication != *end || publication.evaluation.is_some() {
                        return Err(SchedulingError::InvalidPublication);
                    }
                    // Quantized execution preserves original input provenance
                    // without claiming an instruction-level evaluation instant.
                    // Parents can name only deliveries in the authentic consumed
                    // prefix of this original immutable window input cut.
                    if !publication.causal_parents.is_empty() {
                        let batch = self
                            .input_batches
                            .get(owner)
                            .ok_or(SchedulingError::MissingObservation)?;
                        let progress = observation
                            .input_progress
                            .as_ref()
                            .ok_or(SchedulingError::MissingObservation)?;
                        let parents = batch
                            .batch
                            .deliveries()
                            .iter()
                            .take(progress.consumed.len())
                            .map(|delivery| delivery.delivery)
                            .collect::<BTreeSet<_>>();
                        if publication
                            .causal_parents
                            .windows(2)
                            .any(|pair| pair[0] >= pair[1])
                            || publication
                                .causal_parents
                                .iter()
                                .any(|parent| !parents.contains(parent))
                        {
                            return Err(SchedulingError::InvalidPublication);
                        }
                    }
                }
                _ => return Err(SchedulingError::UnsupportedMode),
            }
            match self.bounds.get(&publication.endpoint.node_id) {
                Some(OutputBound::At(bound)) if publication.publication < *bound => {
                    return Err(SchedulingError::CausalRegression);
                }
                Some(OutputBound::AfterInstant(bound))
                    if publication.publication.time_ps <= *bound =>
                {
                    return Err(SchedulingError::CausalRegression);
                }
                _ => {}
            }
            if update
                .native_sequences
                .get(&publication.endpoint)
                .is_some_and(|last| *last >= publication.native_sequence)
            {
                return Err(SchedulingError::CausalRegression);
            }
            update
                .native_sequences
                .insert(publication.endpoint.clone(), publication.native_sequence);
            let routes: Vec<_> = self
                .routing
                .values()
                .filter(|route| route.descriptor.producer == publication.endpoint)
                .collect();
            let allocated = update
                .sequences
                .allocate_fanout(&publication.endpoint.node_id, routes.len().max(1))?;
            for (route, sequence) in routes.into_iter().zip(allocated) {
                let latency_ps = match route.policy.delivery {
                    ConnectionDelivery::Fixed { latency_ps } => latency_ps,
                };
                let destination = self.schedule(&route.descriptor.consumer.node_id)?;
                let destination_grid = match &route.policy.visibility {
                    VisibilityConversion::Direct
                    | VisibilityConversion::PublicationPreserving { .. } => None,
                    VisibilityConversion::BoundarySampling { .. } => Some(destination.grid),
                    VisibilityConversion::Adapter { .. } => {
                        return Err(SchedulingError::UnsupportedMode);
                    }
                };
                let delivery = super::super::event::direct_delivery(
                    publication.publication,
                    latency_ps,
                    destination_grid,
                )?;
                if matches!(destination.policy, ExecutionPolicy::Quantized { .. })
                    && !destination.grid.contains(delivery.time_ps)
                {
                    return Err(SchedulingError::InvalidPublication);
                }
                let outruns_active = destination
                    .reserved
                    .as_ref()
                    .and_then(|operation| self.operations.get(operation))
                    .is_some_and(|reservation| {
                        if original.owner == reservation.owner {
                            return delivery < observation.reached;
                        }
                        match reservation.request {
                            OperationRequest::QuantumBegin { start, .. } => {
                                delivery.time_ps <= start.time_ps
                            }
                            OperationRequest::ExactRun { limit, .. }
                            | OperationRequest::BoundarySettle { limit, .. } => delivery < limit,
                            _ => true,
                        }
                    });
                if delivery < destination.cursor || outruns_active {
                    return Err(SchedulingError::CausalRegression);
                }
                if publication.payload.length > route.policy.maximum_payload_bytes {
                    return Err(SchedulingError::CapacityExceeded);
                }
                let mut queued = self
                    .pending
                    .values()
                    .filter(|pending| pending.connection_id.as_ref() == Some(&route.descriptor.id));
                let (count, bytes) = queued.try_fold((0u64, 0u64), |(count, bytes), pending| {
                    Ok::<_, SchedulingError>((
                        count
                            .checked_add(1)
                            .ok_or(SchedulingError::CapacityExceeded)?,
                        bytes
                            .checked_add(pending.payload.length.get())
                            .ok_or(SchedulingError::CapacityExceeded)?,
                    ))
                })?;
                let staged: Vec<_> = update
                    .deliveries
                    .iter()
                    .filter(|pending| pending.connection_id.as_ref() == Some(&route.descriptor.id))
                    .collect();
                let staged_bytes = staged.iter().try_fold(0u64, |bytes, pending| {
                    bytes
                        .checked_add(pending.payload.length.get())
                        .ok_or(SchedulingError::CapacityExceeded)
                })?;
                if count + staged.len() as u64 >= route.policy.maximum_pending_events.get()
                    || bytes
                        .checked_add(staged_bytes)
                        .and_then(|bytes| bytes.checked_add(publication.payload.length.get()))
                        .is_none_or(|total| total > route.policy.maximum_pending_bytes.get())
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
                update.deliveries.push(Delivery {
                    connection_id: Some(route.descriptor.id.clone()),
                    connection_policy_ref: Some(route.descriptor.policy_ref.clone()),
                    external_root: None,
                    provenance_ref: observation.proof_ref.clone(),
                    publication_id: publication.publication_id.clone(),
                    producer: publication.endpoint.node_id.clone(),
                    consumer: route.descriptor.consumer.node_id.clone(),
                    producer_endpoint: route.descriptor.producer.clone(),
                    consumer_endpoint: route.descriptor.consumer.clone(),
                    source_sequence: sequence,
                    publication: publication.publication,
                    delivery,
                    payload: publication.payload.clone(),
                    native_sequence: publication.native_sequence,
                    evaluation: publication.evaluation,
                    causal_parents: publication.causal_parents.clone(),
                });
            }
            if update
                .deliveries
                .iter()
                .any(|delivery| delivery.payload == publication.payload)
                && !self.payloads.contains_key(&publication.payload)
                && !update
                    .payloads
                    .iter()
                    .any(|(reference, _)| reference == &publication.payload)
            {
                retained_payload_bytes = retained_payload_bytes
                    .checked_add(publication.payload.length.get())
                    .ok_or(SchedulingError::CapacityExceeded)?;
                if retained_payload_bytes > self.maximum_pending_payload_bytes.get() {
                    return Err(SchedulingError::CapacityExceeded);
                }
                update.payloads.push((
                    publication.payload.clone(),
                    publication.payload_bytes.clone(),
                ));
            }
        }
        self.prepare_external_inputs(observation, original, &mut update)?;
        if self
            .pending
            .len()
            .checked_add(update.deliveries.len())
            .is_none_or(|count| count > MAX_ARRAY_ELEMENTS)
        {
            return Err(SchedulingError::CapacityExceeded);
        }
        Ok(update)
    }

    fn prepare_input_progress(
        &self,
        observation: &NativeSchedulingObservation,
        original: Option<&Reservation>,
    ) -> Result<Option<(Id, Vec<crate::node_scheduling::InputIdentity>)>, SchedulingError> {
        let expected = original.and_then(|reservation| reservation.input_batch.as_ref());
        let Some(batch_id) = expected else {
            return if observation.input_progress.is_none() {
                Ok(None)
            } else {
                Err(SchedulingError::InvalidReceipt)
            };
        };
        let original = original.ok_or(SchedulingError::InvalidReceipt)?;
        let state = self
            .input_batches
            .get(&original.owner)
            .ok_or(SchedulingError::InvalidReceipt)?;
        let progress = observation
            .input_progress
            .as_ref()
            .ok_or(SchedulingError::MissingObservation)?;
        progress.proof_ref.validate()?;
        if &progress.batch != batch_id
            || &state.batch.batch != batch_id
            || state.activated_by.as_ref()
                != self
                    .owners
                    .get(&original.owner)
                    .and_then(|owner| owner.reserved.as_ref())
            || progress.consumed.len() > MAX_ARRAY_ELEMENTS
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        if progress.consumed.len() < state.consumed.len()
            || progress.consumed.len() > state.batch.deliveries.len()
            || progress.consumed[..state.consumed.len()] != state.consumed
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        for (identity, delivery) in progress.consumed.iter().zip(&state.batch.deliveries) {
            if *identity != super::inputs_impl::input_identity(delivery)
                || delivery.delivery > observation.reached
            {
                return Err(SchedulingError::InvalidReceipt);
            }
        }
        let remaining = &state.batch.deliveries[progress.consumed.len()..];
        if matches!(original.request, OperationRequest::QuantumBegin { .. })
            && !remaining.is_empty()
            || remaining
                .first()
                .is_some_and(|delivery| delivery.delivery < observation.reached)
        {
            return Err(SchedulingError::InvalidReceipt);
        }
        Ok(Some((
            original.owner.clone(),
            progress.consumed[state.consumed.len()..].to_vec(),
        )))
    }

    pub(super) fn apply_observation(&mut self, update: ObservationUpdate) {
        if let Some((owner, consumed)) = update.consumed
            && let Some(state) = self.input_batches.get_mut(&owner)
        {
            for identity in &consumed {
                if let Some(delivery) = state
                    .batch
                    .deliveries
                    .iter()
                    .find(|delivery| super::inputs_impl::input_identity(delivery) == *identity)
                {
                    self.pending.remove(&delivery.key());
                }
            }
            state.consumed.extend(consumed);
        }
        self.bounds = update.bounds;
        self.closed_prefixes = update.prefixes;
        self.sequences = update.sequences;
        self.native_sequences = update.native_sequences;
        self.external_closed_prefixes = update.external_prefixes;
        for delivery in update.deliveries {
            self.pending.insert(delivery.key(), delivery);
        }
        for (reference, payload) in update.payloads {
            self.payloads.insert(reference, payload);
        }
    }

    /// Reports conservative public output-credit backpressure for a native node.
    ///
    /// Pending transferred input custody retains the connection credit until
    /// authentic native consumption commits. A controller can use this read-only
    /// check to defer work that may emit its admitted maximum-size publication;
    /// it never removes pending input or reserves permission.
    ///
    /// # Errors
    /// Refuses an unknown producer or invalid checked capacity arithmetic.
    pub fn output_backpressure(&self, node: &Id) -> Result<bool, SchedulingError> {
        self.schedule(node)?;
        for route in self
            .routing
            .values()
            .filter(|route| &route.descriptor.producer.node_id == node)
        {
            let mut events = 0u64;
            let mut bytes = 0u64;
            for delivery in self
                .pending
                .values()
                .filter(|delivery| delivery.connection_id.as_ref() == Some(&route.descriptor.id))
            {
                events = events
                    .checked_add(1)
                    .ok_or(SchedulingError::CapacityExceeded)?;
                bytes = bytes
                    .checked_add(delivery.payload.length.get())
                    .ok_or(SchedulingError::CapacityExceeded)?;
            }
            if events >= route.policy.maximum_pending_events.get()
                || bytes
                    .checked_add(route.policy.maximum_payload_bytes.get())
                    .is_none_or(|total| total > route.policy.maximum_pending_bytes.get())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns pending inputs in their canonical delivery order without consuming them.
    ///
    /// # Errors
    /// Refuses a node outside the admitted realization.
    pub fn pending_inputs(&self, node: &Id) -> Result<Vec<&Delivery>, SchedulingError> {
        let owner = self.owner_id(node)?;
        Ok(self
            .pending
            .values()
            .filter(|delivery| self.node_owners.get(&delivery.consumer) == Some(owner))
            .collect())
    }
}

fn check_position(position: Position, maximum_microsteps: U64) -> Result<(), SchedulingError> {
    if position.microstep >= maximum_microsteps
        && !(maximum_microsteps.get() == 0 && position.microstep.get() == 0)
    {
        return Err(SchedulingError::SameTimeNonconvergence);
    }
    Ok(())
}

fn strengthens(old: OutputBound, new: OutputBound) -> bool {
    match (old, new) {
        (OutputBound::Unknown, _) => true,
        (OutputBound::At(old), OutputBound::At(new)) => new >= old,
        (OutputBound::At(old), OutputBound::AfterInstant(new)) => new >= old.time_ps,
        (OutputBound::AfterInstant(old), OutputBound::AfterInstant(new)) => new >= old,
        (OutputBound::AfterInstant(old), OutputBound::At(new)) => new.time_ps > old,
        (_, OutputBound::Unknown) => false,
    }
}

#[path = "external_impl.rs"]
mod external;
