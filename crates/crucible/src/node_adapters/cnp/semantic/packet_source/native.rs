//! Source-native original journal and complete packet inventory authentication.

use super::*;

impl PacketSemanticSource {
    pub(super) fn owner(&self) -> OwnerIdentity {
        OwnerIdentity {
            owner: self.installation.owner.owner.id.clone(),
            incarnation: self.installation.binding.authority.incarnation_id.clone(),
            generation: self.installation.binding.authority.owner_generation,
        }
    }

    pub(super) fn native_record(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketNativeRecord, OperationFailure> {
        self.authenticate_provider(scope.native)?;
        let bytes = scope.controller.content(root).map_err(unknown)?;
        root.verify(bytes).map_err(unknown)?;
        let value =
            canonical::parse_json(bytes, self.installation.maximum_result_bytes.min(65_536))
                .map_err(unknown)?;
        let mut allocation = None;
        let record = if let Some(world) = self
            .world_scope
            .as_ref()
            .filter(|world| world.is_complete())
        {
            let decoded = super::super::packet_complete_source::capture_allocation_receipt::decode_complete_receipt_data(
                scope, bytes, value, self.complete_capture_allocation_selection,
            )?;
            allocation = decoded.allocation;
            let wrapper = decoded.receipt;
            let native_bytes = match allocation.as_ref() {
                Some(allocation) => crucible_node_provider::reference_packet::service::capture_allocation::original_capture_allocation_native_bytes_data(bytes, allocation.reference()).map_err(unknown)?,
                None => bytes,
            };
            if canonical::canonical_json(&serde_json::to_value(&wrapper).map_err(unknown)?)
                .map_err(unknown)?
                != native_bytes
            {
                return Err(refused("complete producer wrapper noncanonical"));
            }
            let request_id = wrapper
                .original
                .request_id
                .0
                .as_ref()
                .ok_or_else(|| refused("complete producer original request absent"))?;
            let original = scope
                .controller
                .original(request_id)
                .ok_or_else(|| refused("complete producer original controller request absent"))?;
            let expected = self
                .complete_storage
                .as_ref()
                .ok_or_else(|| refused("complete source selected storage absent"))?;
            if wrapper.capture_profile != *self.complete_capture_profile.as_ref().unwrap_or(
                &crucible_node_provider::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
            )
                || wrapper.confirmation_selection != self.complete_confirmation_selection.flatten()
                || wrapper.storage_selection != *expected
                || wrapper.storage_selection.limits != scope.controller.authority().limits()
            {
                return Err(refused(
                    "complete source original storage/negotiated limits changed",
                ));
            }
            let raw = scope
                .controller
                .content(&wrapper.native_record)
                .map_err(unknown)?;
            match wrapper.verify_original_record_data(world.selection(),scope.native.provider_pid(),&original.request,raw).map_err(unknown)? {
                crucible_node_provider::reference_packet::control::PacketNative5UnderlyingRecord::Producer(record)=>*record,
                _=>return Err(refused("complete producer cannot consume reactive record")),
            }
        } else {
            serde_json::from_value::<PacketNativeRecord>(value).map_err(unknown)?
        };
        let request = record
            .original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("packet native original request absent"))?;
        let retained = scope
            .controller
            .original(request)
            .ok_or_else(|| refused("packet native proof has no original controller request"))?;
        let response = retained
            .response
            .as_ref()
            .ok_or_else(|| refused("packet native proof has no authentic original response"))?;
        let decoded_request =
            decode_request(retained.request.method, &retained.request.body).map_err(unknown)?;
        let decoded = decode_response(&decoded_request, &response.body).map_err(unknown)?;
        let referenced = match decoded.result {
            Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) => {
                result.stop_receipt == *root
                    && result.pending_inventory == *root
                    && result.observation_batch == *root
            }
            Some(MethodResult::Realize(result)) => result.closed_gate_receipt == *root,
            Some(MethodResult::Activate(result)) => result.activation_receipt == *root,
            Some(MethodResult::WorldActivate(result)) => result.activation_receipt == *root,
            Some(MethodResult::Observe(result)) => result
                .observations
                .iter()
                .any(|row| row.measurement_ref == *root),
            Some(MethodResult::Poll(result)) => {
                let operation = retained
                    .request
                    .operation_id
                    .0
                    .as_ref()
                    .ok_or_else(|| refused("packet original Poll operation absent"))?;
                let begin = scope
                    .controller
                    .originals()
                    .find_map(|original| {
                        if original.request.method != Method::Begin
                            || original.request.operation_id.0.as_ref() != Some(operation)
                        {
                            return None;
                        }
                        match decode_request(Method::Begin, &original.request.body).ok()? {
                            RequestBody::Begin(begin) => Some(begin),
                            _ => None,
                        }
                    })
                    .ok_or_else(|| refused("packet original Poll has no retained Begin"))?;
                let outcome = result
                    .validated_outcome(&begin)
                    .map_err(unknown)?
                    .ok_or_else(|| refused("packet original Poll is not completed"))?;
                match outcome.result {
                    Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) => {
                        result.stop_receipt == *root
                            && result.pending_inventory == *root
                            && result.observation_batch == *root
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        if !referenced
            || record.original != retained.request
            || record.schema != "source-owned.packet-native/2"
            || record.native_pid.get() != u64::from(scope.native.provider_pid())
        {
            return Err(refused(
                "packet native proof differs from authentic original response",
            ));
        }
        self.inventory(&record)?;
        if allocation.is_some() {
            super::super::packet_complete_source::capture_allocation_receipt::authenticate_allocation_cursor(
                allocation.as_ref(), record.inventory.reached,
            )?;
            self.authenticate_provider(scope.native)?;
        }
        Ok(record)
    }

    pub(super) fn authenticate_record_evidence(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        reference: &ContentRef,
    ) -> Result<(), OperationFailure> {
        if !self
            .world_scope
            .as_ref()
            .is_some_and(|world| world.is_complete())
        {
            return self.native_record(scope, reference).map(|_| ());
        }
        self.authenticate_provider(scope.native)?;
        let bytes = scope.controller.content(reference).map_err(unknown)?;
        reference.verify(bytes).map_err(unknown)?;
        let value = canonical::parse_json(bytes, 65_536).map_err(unknown)?;
        if value.get("schema").and_then(serde_json::Value::as_str) == Some("source-owned.packet-receipt/5")
            || (self.complete_capture_allocation_selection.is_some()
                && value.get("schema").and_then(serde_json::Value::as_str) == Some(crucible_node_provider::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD))
        {
            return self.native_record(scope, reference).map(|_| ());
        }
        let record: PacketNativeRecord = serde_json::from_value(value).map_err(unknown)?;
        let request = record
            .original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("complete producer raw original id absent"))?;
        let original = scope
            .controller
            .original(request)
            .ok_or_else(|| refused("complete producer raw original request absent"))?;
        let response = original
            .response
            .as_ref()
            .ok_or_else(|| refused("complete producer raw original response absent"))?;
        let request =
            decode_request(original.request.method, &original.request.body).map_err(unknown)?;
        let root = super::super::packet_connected_source::native_result_root(
            decode_response(&request, &response.body)
                .map_err(unknown)?
                .result
                .as_ref(),
        )?
        .ok_or_else(|| refused("complete producer raw original root absent"))?;
        let wrapper_bytes = scope.controller.content(&root).map_err(unknown)?;
        let wrapper = super::super::packet_complete_source::capture_allocation_receipt::decode_complete_receipt_data(
            scope, wrapper_bytes, canonical::parse_json(wrapper_bytes, 65_536).map_err(unknown)?, self.complete_capture_allocation_selection,
        )?.receipt;
        if wrapper.native_record != *reference || self.native_record(scope, &root)? != record {
            return Err(refused(
                "complete producer raw differs from original wrapper",
            ));
        }
        self.authenticate_provider(scope.native)
    }

    pub(super) fn inventory(&self, record: &PacketNativeRecord) -> Result<(), OperationFailure> {
        Self::original_restored_producer_historical_inventory_data(&self.program, record)
    }

    /// Checks immutable Producer inventory without constructing a live Source.
    ///
    /// The exact same algorithm protects the live caller and historical DATA
    /// mapping. Original native receipts and Source authority remain separate.
    pub(in crate::node_adapters::cnp::semantic) fn original_restored_producer_historical_inventory_data(
        program: &crucible_node_provider::reference_packet::PacketProgramDefinition,
        record: &PacketNativeRecord,
    ) -> Result<(), OperationFailure> {
        let inventory = &record.inventory;
        let completed = program
            .events
            .len()
            .checked_sub(inventory.pending.len())
            .ok_or_else(|| refused("packet pending source population exceeds complete program"))?;
        if program.events[completed..] != inventory.pending {
            return Err(refused(
                "packet pending callbacks differ from immutable source program",
            ));
        }
        let prefix = &program.events[..completed];
        let packets = prefix
            .iter()
            .filter(|event| event.payload.is_some())
            .count();
        if inventory.packet_effects.get() != packets as u64
            || inventory.private_mutations.get() != (completed - packets) as u64
            || inventory.retained_outputs.len() > packets
        {
            return Err(refused(
                "packet source callback counters or output population changed",
            ));
        }
        inventory.reached.validate().map_err(unknown)?;
        let mut sequence = 0;
        for output in &inventory.retained_outputs {
            let (index, event) = program
                .events
                .iter()
                .enumerate()
                .find(|(_, event)| event.id == output.event)
                .ok_or_else(|| refused("packet output has no source-native event"))?;
            let expected_sequence = program.events[..=index]
                .iter()
                .filter(|event| event.payload.is_some())
                .count() as u64;
            if index >= completed
                || output.sequence.get() != expected_sequence
                || output.sequence.get() <= sequence
                || event.payload.as_ref() != Some(&output.payload)
                || event.evaluation != output.evaluation
                || event.completion != output.publication
            {
                return Err(refused(
                    "packet output payload/birth/FIFO differs from native source",
                ));
            }
            sequence = output.sequence.get();
        }
        if let Some(grant) = &record.grant
            && (!grant.complete
                || grant.inventory != *inventory
                || record.original.operation_id.0.as_ref() != Some(&grant.operation)
                || grant.start > inventory.reached
                || inventory.reached > grant.limit
                || grant.newborn != inventory.retained_outputs
                || grant
                    .newborn
                    .iter()
                    .any(|output| output.operation != grant.operation))
        {
            return Err(refused(
                "packet native completed original grant population changed",
            ));
        }
        Ok(())
    }

    pub(super) fn latest(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<PacketNativeRecord, OperationFailure> {
        let root = self.latest_root(scope)?;
        self.native_record(scope, &root)
    }

    pub(super) fn latest_root(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<ContentRef, OperationFailure> {
        let mut roots = Vec::new();
        for original in scope.controller.originals() {
            let Some(response) = original.response.as_ref() else {
                continue;
            };
            let request =
                decode_request(original.request.method, &original.request.body).map_err(unknown)?;
            let response = decode_response(&request, &response.body).map_err(unknown)?;
            let root = match response.result {
                Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) => {
                    Some(result.stop_receipt)
                }
                Some(MethodResult::Realize(result)) => Some(result.closed_gate_receipt),
                Some(MethodResult::Activate(result)) => Some(result.activation_receipt),
                Some(MethodResult::WorldActivate(result)) => Some(result.activation_receipt),
                Some(MethodResult::Observe(result)) => result
                    .observations
                    .first()
                    .map(|row| row.measurement_ref.clone()),
                Some(MethodResult::Poll(result)) => {
                    let Some(outcome) = result.outcome.0 else {
                        continue;
                    };
                    let shape = native_shape(outcome)?;
                    match shape {
                        ResponseShape::Completed { result, .. } => result
                            .get("stop_receipt")
                            .cloned()
                            .map(serde_json::from_value)
                            .transpose()
                            .map_err(unknown)?,
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(root) = root {
                roots.push((original.request.sequence, root));
            }
        }
        let (_, root) = roots
            .into_iter()
            .max_by_key(|(sequence, _)| *sequence)
            .ok_or_else(|| refused("packet authentic native state observation absent"))?;
        Ok(root)
    }

    pub(in crate::node_adapters::cnp::semantic) fn observation(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        record: &PacketNativeRecord,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.authenticate_activation_record(activation.record())?;
        Self::historical_scheduling17_data(
            &self.installation.descriptor,
            || self.owner(),
            root,
            record,
        )
    }

    /// Maps an authenticated historical Producer without constructing a World.
    ///
    /// Its caller separately verifies the model, original native proof and
    /// complete owner correspondence. The result is inert scheduling DATA.
    ///
    /// # Errors
    /// Refuses a closed gate or invalid full output payload reference.
    pub(in crate::node_adapters::cnp::semantic) fn historical_scheduling17_data(
        descriptor: &NodeDescriptor,
        owner: impl FnOnce() -> OwnerIdentity,
        root: &ContentRef,
        record: &PacketNativeRecord,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if record.inventory.gate_closed {
            return Err(refused(
                "packet scheduling has foreign or unopened original activation",
            ));
        }
        let publications = record
            .inventory
            .retained_outputs
            .iter()
            .map(|output| {
                let bytes = output.payload.as_slice();
                let port = descriptor
                    .ports
                    .first()
                    .ok_or_else(|| refused("packet historical publication port absent"))?;
                let lane = port
                    .lanes
                    .first()
                    .ok_or_else(|| refused("packet historical publication lane absent"))?;
                Ok(NativePublication {
                    publication_id: output.event.clone(),
                    endpoint: Endpoint {
                        node_id: descriptor.id.clone(),
                        port_id: port.id.clone(),
                        lane_id: lane.id.clone(),
                    },
                    native_sequence: output.sequence,
                    publication: output.publication,
                    evaluation: Some(output.evaluation),
                    causal_parents: Vec::new(),
                    payload: canonical::content_ref(bytes, "application/octet-stream")
                        .map_err(unknown)?,
                    payload_bytes: bytes.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        let bound = output_bound(&record.inventory);
        Ok(NativeSchedulingObservation {
            node: descriptor.id.clone(),
            owners: vec![owner()],
            reached: record.inventory.reached,
            closed_prefix: record.inventory.reached,
            bounds: vec![NativeProducerBound {
                producer: descriptor.id.clone(),
                bound,
                proof_ref: root.clone(),
            }],
            publications,
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: root.clone(),
        })
    }
}

/// Uses the complete source-authenticated future callback roster, never cursor phase.
fn output_bound(
    inventory: &crucible_node_provider::reference_packet::PacketInventory,
) -> NativeOutputBound {
    match inventory
        .pending
        .iter()
        .filter(|event| event.payload.is_some())
        .map(|event| event.completion)
        .min()
    {
        Some(publication) => NativeOutputBound::At(publication),
        // This fixed output-only program cannot create an unlisted callback or
        // accept new inputs. An exhausted public roster closes the entire
        // reached instant, including when its cursor is BoundaryControl or
        // a private Reaction. Retained original output is acknowledged separately.
        None => NativeOutputBound::AfterInstant(inventory.reached.time_ps),
    }
}

// crucible-lint: allow panic-shortcut -- These output-closure controls assert independent expected bounds.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_provider::reference_packet::{PacketEvent, PacketInventory};

    fn inventory(reached: Position, pending: Vec<PacketEvent>) -> PacketInventory {
        PacketInventory {
            reached,
            gate_closed: false,
            pending,
            retained_outputs: Vec::new(),
            private_mutations: U64::new(0),
            packet_effects: U64::new(0),
        }
    }

    #[test]
    fn exhausted_output_roster_closes_boundary_and_private_reaction_instants() {
        for phase in [Phase::BoundaryControl, Phase::Reaction] {
            let reached = Position::new(U64::new(10), U64::new(0), phase);
            assert_eq!(
                output_bound(&inventory(reached, Vec::new())),
                NativeOutputBound::AfterInstant(U64::new(10))
            );
        }
    }

    #[test]
    fn only_public_callbacks_determine_the_earliest_future_publication() {
        let reached = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
        let private = PacketEvent {
            id: Id::new("private").unwrap(),
            evaluation: Position::new(U64::new(11), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(11), U64::new(0), Phase::Reaction),
            payload: None,
        };
        assert_eq!(
            output_bound(&inventory(reached, vec![private.clone()])),
            NativeOutputBound::AfterInstant(U64::new(10))
        );
        let publication = Position::new(U64::new(12), U64::new(1), Phase::Publication);
        let public = PacketEvent {
            id: Id::new("public").unwrap(),
            evaluation: Position::new(U64::new(12), U64::new(0), Phase::Reaction),
            completion: publication,
            payload: Some(Bytes::new(vec![1])),
        };
        assert_eq!(
            output_bound(&inventory(reached, vec![private, public])),
            NativeOutputBound::At(publication)
        );
    }
}
