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
        let record: PacketNativeRecord = serde_json::from_value(
            canonical::parse_json(bytes, self.installation.maximum_result_bytes.min(65_536))
                .map_err(unknown)?,
        )
        .map_err(unknown)?;
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
        Ok(record)
    }

    fn inventory(&self, record: &PacketNativeRecord) -> Result<(), OperationFailure> {
        let inventory = &record.inventory;
        let completed = self
            .program
            .events
            .len()
            .checked_sub(inventory.pending.len())
            .ok_or_else(|| refused("packet pending source population exceeds complete program"))?;
        if self.program.events[completed..] != inventory.pending {
            return Err(refused(
                "packet pending callbacks differ from immutable source program",
            ));
        }
        let prefix = &self.program.events[..completed];
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
            let (index, event) = self
                .program
                .events
                .iter()
                .enumerate()
                .find(|(_, event)| event.id == output.event)
                .ok_or_else(|| refused("packet output has no source-native event"))?;
            let expected_sequence = self.program.events[..=index]
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

    pub(super) fn observation(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        record: &PacketNativeRecord,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if activation.record().world_binding_hash != self.installation.world_binding_hash
            || activation.record().owners != [self.owner()]
            || record.inventory.gate_closed
        {
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
                Ok(NativePublication {
                    publication_id: output.event.clone(),
                    endpoint: Endpoint {
                        node_id: self.installation.descriptor.id.clone(),
                        port_id: self.installation.descriptor.ports[0].id.clone(),
                        lane_id: self.installation.descriptor.ports[0].lanes[0].id.clone(),
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
        let bound = record
            .inventory
            .pending
            .iter()
            .filter(|event| event.payload.is_some())
            .map(|event| event.completion)
            .min()
            .unwrap_or(record.inventory.reached);
        Ok(NativeSchedulingObservation {
            node: self.installation.descriptor.id.clone(),
            owners: vec![self.owner()],
            reached: record.inventory.reached,
            closed_prefix: record.inventory.reached,
            bounds: vec![NativeProducerBound {
                producer: self.installation.descriptor.id.clone(),
                bound: NativeOutputBound::At(bound),
                proof_ref: root.clone(),
            }],
            publications,
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: root.clone(),
        })
    }
}
