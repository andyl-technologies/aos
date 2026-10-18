//! Maps full captured native histories to archived common outcomes and scheduling.

use super::*;
use crate::node_contract::StopReason as CommonStopReason;
use crucible_node_provider::reference_packet::{
    continuation_models::{PacketModelCaptureBoundaryData, PacketModelRecordExpectation},
    control::{
        PacketDecodedControlSnapshot, PacketNative5Record, PacketNative5UnderlyingRecord,
        decode_packet_control_snapshot, packet_control_snapshot_validation_layouts,
    },
};

impl PacketCompleteSemanticSource {
    /// Checks archived input custody, full native outcomes and latest scheduling.
    ///
    /// The actual captured Control body supplies the complete original model
    /// history. Each proof remains tied to its unchanged host request/reply and
    /// original native PID. Historical model data creates no active native
    /// owner, physical restore gate, operation token or fresh registration.
    ///
    /// The factory also calls the independent common Runtime7/ancestry and full
    /// literal Capture/after/confirmation predicates. This method does not replace
    /// them or claim physical allocator/stack admission from requested layouts.
    ///
    /// # Errors
    /// Refuses foreign/incomplete owners, changed historical grants, unproved
    /// observation cuts, altered outcomes/publications/consumed prefixes,
    /// quarantined or reclaimed custody, and exhausted simultaneous scratch.
    pub fn authenticate_archived_native_semantics_data(
        &self,
        cold: &PacketCompleteArchivedOwnerData<'_>,
        semantics: &PacketCompleteArchivedSemantics,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.authenticate_archived_native_input_data(
            cold,
            semantics,
            additional_retained_bytes,
            maximum_total_bytes,
        )?;
        let content = cold.source_content_data(self)?;
        let retained = additional_retained_bytes
            .checked_add(cold.known_requested_bytes()?)
            .and_then(|n| n.checked_add(20 + 256))
            .filter(|n| *n <= maximum_total_bytes)
            .ok_or_else(|| refused("cold native projection aggregate storage exhausted"))?;
        let data = NativeInputData {
            selection: NativeInputSelection::Live(self),
            host: cold.host()?,
            native: cold.native_after()?,
            content: ArchivedContentData::Verified(content),
            retained,
            maximum: maximum_total_bytes,
            scratch: Cell::new(0),
            construction: None,
        };
        self.authenticate_original_native_semantic_history_data(&data, cold.journal()?, semantics)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_native_semantic_history_data(
        &self,
        data: &NativeInputData<'_>,
        journal: &PacketCompleteSettledJournal,
        semantics: &PacketCompleteArchivedSemantics,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        data.selection.authenticate_same_source_data(self)?;
        data.authenticate_semantic_history_data(journal, semantics)?;
        data.selection.authenticate_same_source_data(self)?;
        self.ensure_origin()
    }
}

impl NativeInputData<'_> {
    /// Checks original outcomes, model history and scheduling without live grants.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_semantic_history_data(
        &self,
        journal: &PacketCompleteSettledJournal,
        semantics: &PacketCompleteArchivedSemantics,
    ) -> Result<(), OperationFailure> {
        self.selection.authenticate_origin_data()?;
        let state = semantics.source_common_data();
        // A complete live cut requires the original current native owner. A
        // reclaimed or quarantined common node cannot acquire Ready through a
        // historical decoder, even when all its old fields remain preserved.
        if state.quarantined || state.reclaimed.is_some() || self.host.fenced {
            return Err(refused(
                "cold complete source has unresolved or reclaimed custody",
            ));
        }
        self.observation_population(state)?;
        let control = self.control(&journal.native_control)?;
        if control.administrative_cut() != journal.cut {
            return Err(refused("cold native model uses another administrative cut"));
        }
        let capture = self
            .host
            .custody
            .controller
            .get(&journal.confirmation.capture.capture_request_id)
            .ok_or_else(|| refused("cold original Capture request absent"))?;
        self.operation_population(state, &capture.request)?;
        for operation in state.operations.values() {
            settled_operation(operation)?;
            self.retirement(operation)?;
            if let Some(outcome) = &operation.outcome {
                let observation = outcome
                    .scheduling
                    .as_ref()
                    .ok_or_else(|| refused("cold completed operation scheduling absent"))?;
                let record = self.native_record(
                    &observation.proof_ref,
                    &control,
                    PacketModelRecordExpectation::CompletedGrant,
                    capture.request.sequence,
                )?;
                self.outcome(operation, outcome, &record, &observation.proof_ref, state)?;
            }
        }
        if let Some((activation, observation)) = &state.observation {
            if state.active.as_ref() != Some(activation) {
                return Err(refused("cold latest observation uses another activation"));
            }
            let record = self.native_record(
                &observation.proof_ref,
                &control,
                PacketModelRecordExpectation::FinalObservation,
                capture.request.sequence,
            )?;
            self.observation(observation, &record, &observation.proof_ref, false)?;
        }
        self.selection.authenticate_origin_data()
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capture_boundary_data(
        &self,
        journal: &PacketCompleteSettledJournal,
    ) -> Result<PacketModelCaptureBoundaryData, OperationFailure> {
        // The same full-Control lease covers its bounded model projection,
        // inventory DOM and canonical banks while the returned hash is built.
        // The three returned hash strings are independent of the Control's
        // parsed fields, even though their logical identity is derived there.
        let hash_bytes = "blake3-256".len()
            + 64
            + "source-owned.packet-connected-inventory/4"
                .len()
                .max("source-owned.packet-inventory.v1".len());
        let scratch = self
            .scratch
            .get()
            .checked_add(hash_bytes)
            .ok_or_else(|| refused("cold model boundary hash storage overflow"))?;
        self.retained
            .checked_add(scratch)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or_else(|| refused("cold model boundary hash storage exhausted"))?;
        self.observe_construction(scratch)?;
        self.scratch.set(scratch);
        let _hash_charge = NativeScratch {
            total: &self.scratch,
            bytes: hash_bytes,
        };
        let control = self.control(&journal.native_control)?;
        let maximum = usize::try_from(
            self.selection
                .storage_data()?
                .storage
                .control_snapshot_bytes
                .get(),
        )
        .map_err(|_| refused("cold model selected bound is not representable"))?
        .min(packet_control_snapshot_validation_layouts().maximum_model_bytes);
        control
            .model()
            .capture_boundary_data(maximum)
            .map_err(unknown)
    }

    fn control(
        &self,
        reference: &ContentRef,
    ) -> Result<NativeObject<'_, PacketDecodedControlSnapshot>, OperationFailure> {
        let bytes = self
            .content
            .get(reference)
            .ok_or_else(|| refused("cold complete Control body absent"))?;
        reference.verify(bytes).map_err(unknown)?;
        let selected = self.selection.storage_data()?;
        let layouts = packet_control_snapshot_validation_layouts();
        let maximum = usize::try_from(selected.storage.control_snapshot_bytes.get())
            .map_err(|_| refused("cold Control selected bound is not representable"))?
            .min(layouts.maximum_control_bytes);
        if bytes.len() > maximum {
            return Err(refused(
                "cold complete Control exceeds original selected bound",
            ));
        }
        // One conservative pinned node for every possible typed entry/container
        // covers the actual private map K/V layouts and alignments. The scanner
        // counts the actual raw syntax, including empty containers, before DOM.
        let node = NodeRuntime::capture_protocol_tree_storage(
            1,
            0,
            layouts.maximum_tree_key_value_bytes,
            layouts.maximum_tree_entry_alignment,
            self.maximum,
        )
        .map_err(unknown)?;
        let one = NodeRuntime::capture_selected_json_decode_storage(
            bytes,
            layouts.maximum_typed_slot_bytes,
            node,
            self.maximum,
        )
        .map_err(unknown)?;
        let projections = layouts
            .maximum_simultaneous_control_dom_views
            .checked_add(layouts.maximum_simultaneous_typed_model_views)
            .ok_or_else(|| refused("cold model projection count overflow"))?;
        let encoded = bytes
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_mul(layouts.maximum_simultaneous_control_encoded_banks))
            .ok_or_else(|| refused("cold model canonical bank extent overflow"))?;
        let demand = one
            .checked_mul(projections)
            .and_then(|n| n.checked_add(encoded))
            .and_then(|n| n.checked_add(layouts.control_record_bytes))
            .and_then(|n| n.checked_add(layouts.model_record_bytes))
            .and_then(|n| {
                n.checked_add(
                    layouts
                        .producer_state_bytes
                        .max(layouts.reactive_state_bytes),
                )
            })
            .ok_or_else(|| refused("cold model decoder storage overflow"))?;
        let scratch = self
            .scratch
            .get()
            .checked_add(demand)
            .ok_or_else(|| refused("cold model simultaneous storage overflow"))?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("cold model decoder storage exhausted"))?;
        self.observe_construction(scratch)?;
        self.scratch.set(scratch);
        let charge = NativeScratch {
            total: &self.scratch,
            bytes: demand,
        };
        let value = decode_packet_control_snapshot(bytes, reference, maximum).map_err(unknown)?;
        Ok(NativeObject {
            value,
            _charge: charge,
        })
    }

    fn native_record(
        &self,
        root: &ContentRef,
        control: &PacketDecodedControlSnapshot,
        expectation: PacketModelRecordExpectation,
        before: U64,
    ) -> Result<NativeObject<'_, PacketNative5UnderlyingRecord>, OperationFailure> {
        let wrapper: NativeObject<'_, PacketNative5Record> = self.object(root)?;
        let original = self.original(&wrapper.original)?;
        let policy = &self.native.connection.policy;
        if wrapper.original.sequence >= before
            || wrapper.capture_profile != policy.capture_profile
            || wrapper.confirmation_selection != policy.confirmation_selection
            || wrapper.ack_emitter_selection != policy.ack_emitter_selection
            || wrapper.protocol_metadata_limits != policy.protocol_metadata_limits
            || wrapper.complete_restore_selection != policy.complete_restore_selection
            || wrapper.restore_input_emitter_selection != policy.restore_input_emitter_selection
            || wrapper.storage_selection != *self.selection.storage_data()?
        {
            return Err(refused(
                "cold native receipt differs from original installed tuple",
            ));
        }
        self.references_root(original, root)?;
        // Keep the typed/raw decode lease through all model-history checks. The
        // raw Value is discarded only after the separately decoded record exists.
        let raw: NativeObject<'_, serde_json::Value> = self.object(&wrapper.native_record)?;
        let value = wrapper
            .verify_original_record_data(
                self.selection(),
                self.pid(),
                &original.request,
                self.body(&wrapper.native_record)?,
            )
            .map_err(unknown)?;
        strict_native_record_data(&value, &raw)?;
        let NativeObject {
            value: raw_value,
            _charge,
        } = raw;
        drop(raw_value);
        let record = NativeObject { value, _charge };
        let maximum = usize::try_from(
            self.selection
                .storage_data()?
                .storage
                .control_snapshot_bytes
                .get(),
        )
        .map_err(|_| refused("cold model selected bound is not representable"))?
        .min(packet_control_snapshot_validation_layouts().maximum_model_bytes);
        control
            .model()
            .authenticate_original_record_history_data(
                &record,
                &original.request,
                expectation,
                maximum,
            )
            .map_err(unknown)?;
        Ok(record)
    }

    fn observation_population(
        &self,
        common: &ArchivedSemanticCustody,
    ) -> Result<(), OperationFailure> {
        let actual = self
            .host
            .custody
            .controller
            .values()
            .filter(|one| one.request.method == Method::Observe)
            .count();
        require_observation_population(common, actual)
    }

    fn retirement(&self, operation: &ArchivedOperation) -> Result<(), OperationFailure> {
        let Some(consumption) = &operation.retirement else {
            return Ok(());
        };
        let id = super::super::super::preparation::request_id("retire", &operation.operation)?;
        let original = self
            .host
            .custody
            .controller
            .get(&id)
            .ok_or_else(|| refused("cold acknowledged retirement original absent"))?;
        let _request_charge = self.charge_envelope(&original.request)?;
        let RequestBody::Retire(request) =
            decode_request(original.request.method, &original.request.body).map_err(unknown)?
        else {
            return Err(refused("cold retirement original method differs"));
        };
        let response = original
            .response
            .as_ref()
            .ok_or_else(|| refused("cold acknowledged retirement response absent"))?;
        let _reply_charge = self.charge_envelope(response)?;
        let Some(MethodResult::Retire(result)) =
            decode_response(&RequestBody::Retire(request.clone()), &response.body)
                .map_err(unknown)?
                .result
        else {
            return Err(refused(
                "cold acknowledged retirement completed result absent",
            ));
        };
        let begin_id = super::super::super::preparation::request_id("begin", &operation.operation)?;
        if request.disposition != RetirementDisposition::Consumed
            || request.custody_receipt.0.as_ref() != Some(&consumption.reference)
            || request.request_ids.as_slice() != std::slice::from_ref(&begin_id)
            || request.operation_ids.as_slice() != std::slice::from_ref(&operation.operation)
            || !request.extensions.is_empty()
            || result.retired_request_ids != request.request_ids
            || result.retired_operation_ids != request.operation_ids
        {
            return Err(refused(
                "cold retirement changes actual consumed population",
            ));
        }
        consumption
            .reference
            .verify(&consumption.bytes)
            .map_err(unknown)?;
        if self.content.get(&consumption.reference) != Some(consumption.bytes.as_slice()) {
            return Err(refused(
                "cold retirement bytes differ from authenticated archive closure",
            ));
        }
        let expected = ConsumptionProjection {
            schema: if self.selection.reactive_definition_data()?.is_some() {
                "source-owned.packet-consumption.v4"
            } else {
                "source-owned.packet-consumption.v1"
            },
            operation: &operation.operation,
            outputs: &operation
                .outcome
                .as_ref()
                .ok_or_else(|| refused("cold retirement outcome absent"))?
                .retained_outputs,
        };
        let value_bytes =
            NodeRuntime::capture_serialization_storage(&expected, self.maximum).map_err(unknown)?;
        let encoded_extent = super::super::super::budget::serialized_size(
            &expected,
            self.selection.maximum_authorization_bytes_data()?.min(8192),
        )?;
        // This is the same conservative growing byte-bank bound as the pinned
        // Core decoder. The DOM and encoded bank coexist; neither displaces the
        // archived consumption or the retained full input/result owners.
        let encoded_capacity = encoded_extent
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| refused("cold consumption encoded bank extent overflow"))?;
        let bytes = value_bytes
            .checked_add(encoded_capacity)
            .ok_or_else(|| refused("cold consumption simultaneous storage overflow"))?;
        let scratch = self
            .scratch
            .get()
            .checked_add(bytes)
            .ok_or_else(|| refused("cold consumption serialization extent overflow"))?;
        self.retained
            .checked_add(scratch)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| refused("cold consumption serialization storage exhausted"))?;
        self.observe_construction(scratch)?;
        self.scratch.set(scratch);
        let _charge = NativeScratch {
            total: &self.scratch,
            bytes,
        };
        let value = serde_json::to_value(expected).map_err(unknown)?;
        let encoded = canonical::canonical_json(&value).map_err(unknown)?;
        if encoded.len() != encoded_extent || encoded.capacity() > encoded_capacity {
            return Err(refused(
                "cold consumption actual encoded bank exceeds precharge",
            ));
        }
        if encoded != consumption.bytes {
            return Err(refused(
                "cold retirement complete consumed output projection differs",
            ));
        }
        Ok(())
    }

    fn operation_population(
        &self,
        common: &ArchivedSemanticCustody,
        capture: &Envelope,
    ) -> Result<(), OperationFailure> {
        for original in self.host.custody.controller.values() {
            if matches!(original.request.method, Method::Retire | Method::Cancel) {
                let _charge = self.charge_envelope(&original.request)?;
                let (operation_id, prefix) = if original.request.method == Method::Retire {
                    let RequestBody::Retire(retire) =
                        decode_request(Method::Retire, &original.request.body).map_err(unknown)?
                    else {
                        return Err(refused("cold original Retire method differs"));
                    };
                    if retire.operation_ids.len() != 1 {
                        return Err(refused("cold Retire has no single common operation"));
                    }
                    (retire.operation_ids[0].clone(), "retire")
                } else {
                    (
                        original
                            .request
                            .operation_id
                            .0
                            .clone()
                            .ok_or_else(|| refused("cold Cancel operation absent"))?,
                        "cancel",
                    )
                };
                let operation = common.operations.get(&operation_id).ok_or_else(|| {
                    refused("cold common custody omits original Retire or Cancel")
                })?;
                let expected = super::super::super::preparation::request_id(prefix, &operation_id)?;
                if original.request.request_id.0.as_ref() != Some(&expected)
                    || (prefix == "retire"
                        && (!operation.acknowledged || operation.retirement.is_none()))
                    || (prefix == "cancel" && operation.cancellation.0 == "not-attempted")
                {
                    return Err(refused(
                        "cold original Retire or Cancel loses common custody",
                    ));
                }
                continue;
            }
            if original.request.method != Method::Begin {
                continue;
            }
            let _charge = self.charge_envelope(&original.request)?;
            let RequestBody::Begin(begin) =
                decode_request(Method::Begin, &original.request.body).map_err(unknown)?
            else {
                return Err(refused("cold original Begin method differs"));
            };
            match begin.decoded_arguments().map_err(unknown)? {
                BeginArguments::ExactRun(_) | BeginArguments::BoundarySettle(_) => {
                    let operation = original
                        .request
                        .operation_id
                        .0
                        .as_ref()
                        .and_then(|id| common.operations.get(id))
                        .ok_or_else(|| {
                            refused("cold common custody omits a native grant operation")
                        })?;
                    if operation.begin != begin {
                        return Err(refused("cold common grant Begin differs from original"));
                    }
                }
                BeginArguments::Capture(_) if original.request == *capture => {}
                _ => return Err(refused("cold native Begin has no complete common owner")),
            }
        }
        Ok(())
    }

    fn references_root(
        &self,
        original: &ClientOriginal,
        root: &ContentRef,
    ) -> Result<(), OperationFailure> {
        let _original_charge = self.charge_envelope(&original.request)?;
        let request =
            decode_request(original.request.method, &original.request.body).map_err(unknown)?;
        let mut found = false;
        for reply in self.host.custody.controller.values() {
            let same_original = reply.request == original.request;
            let same_poll = reply.request.method == Method::Poll
                && original.request.operation_id.0.is_some()
                && reply.request.operation_id == original.request.operation_id;
            if !same_original && !same_poll {
                continue;
            }
            let Some(response) = &reply.response else {
                continue;
            };
            let _reply_charge = self.charge_envelope(response)?;
            let _request_charge = self.charge_envelope(&reply.request)?;
            let decoded_request =
                decode_request(reply.request.method, &reply.request.body).map_err(unknown)?;
            let decoded = decode_response(&decoded_request, &response.body).map_err(unknown)?;
            let result = match decoded.result {
                Some(MethodResult::Poll(poll)) => {
                    let RequestBody::Begin(begin) = &request else {
                        return Err(refused("cold native Poll has no original Begin"));
                    };
                    poll.validated_outcome(begin)
                        .map_err(unknown)?
                        .and_then(|outcome| outcome.result)
                }
                result => result,
            };
            let referenced = match result {
                Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) => {
                    result.stop_receipt == *root
                        && result.pending_inventory == *root
                        && result.observation_batch == *root
                }
                Some(MethodResult::Observe(result)) => {
                    result.complete
                        && result.observations.len() == 1
                        && result.observations[0].measurement_ref == *root
                }
                _ => false,
            };
            found |= referenced;
        }
        if !found {
            return Err(refused(
                "cold native proof not named by original completed reply",
            ));
        }
        Ok(())
    }

    fn observation(
        &self,
        observation: &NativeSchedulingObservation,
        record: &PacketNative5UnderlyingRecord,
        root: &ContentRef,
        input_progress: bool,
    ) -> Result<(), OperationFailure> {
        let owner = self
            .selection()
            .realization
            .owner_bindings
            .first()
            .ok_or_else(|| refused("cold native observation owner absent"))?;
        let binding = self
            .selection()
            .realization
            .bindings
            .first()
            .ok_or_else(|| refused("cold native observation binding absent"))?;
        let reached = match record {
            PacketNative5UnderlyingRecord::Producer(record) => record.inventory.reached,
            PacketNative5UnderlyingRecord::Reactive(record) => record.inventory.reached,
        };
        if observation.node != self.host.node
            || observation.owners.len() != 1
            || observation.owners[0].owner != owner.owner.id
            || observation.owners[0].incarnation != binding.authority.incarnation_id
            || observation.owners[0].generation != binding.authority.owner_generation
            || observation.reached != reached
            || observation.closed_prefix != reached
            || observation.proof_ref != *root
            || observation.bounds.len() != 1
            || observation.bounds[0].producer != self.host.node
            || observation.bounds[0].proof_ref != *root
            || !observation.external_inputs.is_empty()
            || (!input_progress && observation.input_progress.is_some())
        {
            return Err(refused(
                "cold native scheduling owner, cut or evidence differs",
            ));
        }
        match record {
            PacketNative5UnderlyingRecord::Producer(record) => {
                let descriptor = self
                    .selection()
                    .realization
                    .descriptors
                    .first()
                    .ok_or_else(|| refused("cold producer descriptor absent"))?;
                let port = descriptor
                    .ports
                    .first()
                    .ok_or_else(|| refused("cold producer port absent"))?;
                let lane = port
                    .lanes
                    .first()
                    .ok_or_else(|| refused("cold producer lane absent"))?;
                let bound = record
                    .inventory
                    .pending
                    .iter()
                    .filter(|event| event.payload.is_some())
                    .map(|event| event.completion)
                    .min()
                    .map_or(
                        NativeOutputBound::AfterInstant(reached.time_ps),
                        NativeOutputBound::At,
                    );
                if record.inventory.gate_closed
                    || observation.bounds[0].bound != bound
                    || observation.publications.len() != record.inventory.retained_outputs.len()
                {
                    return Err(refused(
                        "cold producer callback bound or output population differs",
                    ));
                }
                for (actual, output) in observation
                    .publications
                    .iter()
                    .zip(&record.inventory.retained_outputs)
                {
                    if actual.endpoint.node_id != self.host.node
                        || actual.endpoint.port_id != port.id
                        || actual.endpoint.lane_id != lane.id
                        || !actual.causal_parents.is_empty()
                    {
                        return Err(refused(
                            "cold producer publication endpoint or parents differ",
                        ));
                    }
                    publication(actual, output)?;
                }
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                let definition = self
                    .selection
                    .reactive_definition_data()?
                    .ok_or_else(|| refused("cold reactive definition absent"))?;
                let bound = super::super::super::packet_connected_source::output_bound(
                    &record.inventory,
                    definition.output.is_some(),
                )?;
                if record.inventory.gate_closed
                    || observation.bounds[0].bound != bound
                    || observation.publications.len() != record.inventory.retained_outputs.len()
                {
                    return Err(refused(
                        "cold reactive callback bound or output population differs",
                    ));
                }
                for (actual, retained) in observation
                    .publications
                    .iter()
                    .zip(&record.inventory.retained_outputs)
                {
                    if definition.output.as_ref() != Some(&actual.endpoint)
                        || actual.causal_parents.as_slice() != [retained.pending.reaction.parent]
                    {
                        return Err(refused(
                            "cold reactive publication endpoint or parent differs",
                        ));
                    }
                    publication(actual, &retained.output)?;
                }
            }
        }
        Ok(())
    }

    fn outcome(
        &self,
        operation: &ArchivedOperation,
        outcome: &OperationOutcome,
        record: &PacketNative5UnderlyingRecord,
        root: &ContentRef,
        common: &ArchivedSemanticCustody,
    ) -> Result<(), OperationFailure> {
        let request: &OperationRequest = &operation.request;
        let (start, limit) = match request {
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy: ExactBoundaryPolicy::HorizonPark,
            }
            | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
            _ => return Err(refused("cold native outcome interval is unsupported")),
        };
        let (id, grant_start, grant_limit, complete) = match record {
            PacketNative5UnderlyingRecord::Producer(record) => {
                let grant = record
                    .grant
                    .as_ref()
                    .ok_or_else(|| refused("cold producer grant absent"))?;
                (&grant.operation, grant.start, grant.limit, grant.complete)
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                let grant = record
                    .grant
                    .as_ref()
                    .ok_or_else(|| refused("cold reactive grant absent"))?;
                (&grant.operation, grant.start, grant.limit, grant.complete)
            }
        };
        if id != &operation.operation
            || grant_start != start
            || grant_limit != limit
            || !complete
            || outcome.operation != operation.operation
            || outcome.node != operation.route.node
            || outcome.owners != operation.route.owners
            || outcome.progress
                != (ProgressEvidence::Exact {
                    reached: limit,
                    stop: CommonStopReason::HorizonPark,
                })
        {
            return Err(refused(
                "cold common outcome differs from exact native grant",
            ));
        }
        let observation = outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refused("cold outcome scheduling absent"))?;
        self.observation(
            observation,
            record,
            root,
            matches!(record, PacketNative5UnderlyingRecord::Reactive(_)),
        )?;
        match record {
            PacketNative5UnderlyingRecord::Producer(record) => {
                let grant = record
                    .grant
                    .as_ref()
                    .ok_or_else(|| refused("cold producer grant absent"))?;
                if outcome.retained_outputs.len() != grant.newborn.len()
                    || outcome
                        .retained_outputs
                        .iter()
                        .zip(&grant.newborn)
                        .any(|(id, row)| id != &row.event)
                {
                    return Err(refused("cold producer outcome changes newborn outputs"));
                }
            }
            PacketNative5UnderlyingRecord::Reactive(record) => {
                let grant = record
                    .grant
                    .as_ref()
                    .ok_or_else(|| refused("cold reactive grant absent"))?;
                if outcome.retained_outputs.len() != grant.newborn.len()
                    || outcome
                        .retained_outputs
                        .iter()
                        .zip(&grant.newborn)
                        .any(|(id, row)| id != &row.output.event)
                {
                    return Err(refused("cold reactive outcome changes newborn outputs"));
                }
                let batch = operation
                    .inputs
                    .as_ref()
                    .ok_or_else(|| refused("cold reactive outcome input cut absent"))?;
                let input = common
                    .inputs
                    .get(&batch.stage_operation)
                    .ok_or_else(|| refused("cold reactive outcome staged custody absent"))?;
                let committed = input
                    .commitment
                    .as_ref()
                    .and_then(|one| one.response.as_ref())
                    .ok_or_else(|| refused("cold reactive outcome consumed custody absent"))?;
                let (_, commit) = self.input_root(committed)?;
                if commit.sequence >= record.original.sequence {
                    return Err(refused("cold reactive grant precedes consumed input"));
                }
                let progress = observation
                    .input_progress
                    .as_ref()
                    .ok_or_else(|| refused("cold reactive consumed prefix absent"))?;
                if progress.batch != batch.batch || progress.proof_ref != *root {
                    return Err(refused("cold reactive consumed prefix changes batch"));
                }
                let mut consumed = 0;
                let mut pending = false;
                for delivery in &batch.deliveries {
                    let found = record.inventory.delivered_inputs.iter().any(|actual| {
                        actual.reaction.stage_operation == batch.stage_operation
                            && Some(&actual.reaction.commit_request) == commit.request_id.0.as_ref()
                            && actual.reaction.input_event == delivery.publication_id
                            && actual.reaction.input_producer == delivery.producer
                            && actual.reaction.input_sequence == delivery.source_sequence
                            && actual.reaction.parent == delivery.delivery
                    });
                    if found {
                        let identity = progress
                            .consumed
                            .get(consumed)
                            .ok_or_else(|| refused("cold consumed prefix loses an input"))?;
                        if pending
                            || identity.producer != delivery.producer
                            || identity.source_sequence != delivery.source_sequence
                        {
                            return Err(refused(
                                "cold delivered inputs are not the original canonical prefix",
                            ));
                        }
                        consumed += 1;
                    } else {
                        pending = true;
                    }
                }
                if consumed != progress.consumed.len() {
                    return Err(refused("cold consumed prefix adds an input"));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn strict_native_record_data(
    value: &PacketNative5UnderlyingRecord,
    raw: &serde_json::Value,
) -> Result<(), OperationFailure> {
    let typed_value = match value {
        PacketNative5UnderlyingRecord::Producer(record) => serde_json::to_value(record),
        PacketNative5UnderlyingRecord::Reactive(record) => serde_json::to_value(record),
    }
    .map_err(unknown)?;
    if typed_value != *raw {
        return Err(refused(
            "cold native underlying typed record loses original fields",
        ));
    }
    Ok(())
}

pub(super) fn require_observation_population(
    common: &ArchivedSemanticCustody,
    actual: usize,
) -> Result<(), OperationFailure> {
    if u64::try_from(actual).map_err(unknown)? != common.observe_sequence.get()
        || (actual != 0) != common.observation.is_some()
    {
        return Err(refused(
            "cold common latest observation or actual population is omitted",
        ));
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ConsumptionProjection<'a> {
    schema: &'static str,
    operation: &'a Id,
    outputs: &'a [Id],
}

pub(super) fn settled_operation(operation: &ArchivedOperation) -> Result<(), OperationFailure> {
    if operation.outcome.is_none()
        || operation.failure.is_some()
        || (operation.retirement.is_some() && !operation.acknowledged)
        || (operation.acknowledged && operation.retirement.is_none())
        || operation.cancellation.1.is_some()
        || !matches!(
            operation.cancellation.0.as_str(),
            "not-attempted" | "requested" | "unsupported"
        )
    {
        return Err(refused(
            "cold complete source has failed or unresolved operation custody",
        ));
    }
    Ok(())
}

fn publication(
    actual: &NativePublication,
    output: &crucible_node_provider::reference_packet::PacketPublication,
) -> Result<(), OperationFailure> {
    if actual.publication_id != output.event
        || actual.native_sequence != output.sequence
        || actual.publication != output.publication
        || actual.evaluation != Some(output.evaluation)
        || actual.payload_bytes != output.payload.as_slice()
        || actual.payload
            != canonical::content_ref(output.payload.as_slice(), "application/octet-stream")
                .map_err(unknown)?
    {
        return Err(refused("cold native full publication projection differs"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn full_publication_accepts_but_changed_payload_or_evaluation_refuses() {
        let output = crucible_node_provider::reference_packet::PacketPublication {
            event: Id::new("event").unwrap(),
            operation: Id::new("operation").unwrap(),
            sequence: U64::new(3),
            evaluation: Position::new(U64::new(2), U64::new(0), Phase::Reaction),
            publication: Position::new(U64::new(2), U64::new(1), Phase::Publication),
            payload: Bytes::new(vec![7, 8]),
        };
        let mut actual = NativePublication {
            publication_id: output.event.clone(),
            endpoint: Endpoint {
                node_id: Id::new("producer").unwrap(),
                port_id: Id::new("port").unwrap(),
                lane_id: Id::new("lane").unwrap(),
            },
            native_sequence: output.sequence,
            publication: output.publication,
            evaluation: Some(output.evaluation),
            causal_parents: Vec::new(),
            payload: canonical::content_ref(output.payload.as_slice(), "application/octet-stream")
                .unwrap(),
            payload_bytes: output.payload.as_slice().to_vec(),
        };
        publication(&actual, &output).unwrap();
        actual.payload_bytes[0] ^= 1;
        assert!(publication(&actual, &output).is_err());
        actual.payload_bytes = output.payload.as_slice().to_vec();
        actual.evaluation = Some(output.publication);
        assert!(publication(&actual, &output).is_err());
    }
}
