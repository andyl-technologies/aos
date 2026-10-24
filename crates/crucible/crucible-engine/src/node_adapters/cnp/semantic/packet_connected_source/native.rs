//! Original bounded journal reconstruction through each historical native cut.
//!
//! Future control requests cannot change an earlier completed proof. This pure
//! projection checks original source records; it neither sends datagrams nor
//! supplies the independent effect oracle or class acceptance.

use super::*;
use crate::node_scheduling::event::Delivery;
use crucible_node_transport::{
    envelope::Envelope,
    reference_packet::connected::{
        PacketConnectedGrant, PacketConnectedPublication, PacketDeliveredInput,
        PacketPendingPublication,
    },
};

pub(super) fn initial_inventory() -> PacketConnectedInventory {
    PacketConnectedInventory {
        reached: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        gate_closed: true,
        reactions: Vec::new(),
        delivered_inputs: Vec::new(),
        publications: Vec::new(),
        retained_outputs: Vec::new(),
        reactions_completed: U64::new(0),
        packet_effects: U64::new(0),
        stages: Vec::new(),
        commits: Vec::new(),
    }
}

impl PacketConnectedSemanticSource {
    fn envelope_current(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        envelope: &Envelope,
    ) -> Result<(), OperationFailure> {
        envelope.validate().map_err(unknown)?;
        let id = envelope
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("connected source original id absent"))?;
        let original = scope
            .controller
            .original(id)
            .ok_or_else(|| refused("connected source original journal absent"))?;
        let authority = &self.installation.binding.authority;
        let scoped = matches!(
            envelope.method,
            Method::Input | Method::Begin | Method::Observe | Method::Retire | Method::Poll
        );
        if original.request != *envelope
            || envelope.session_id.0.as_ref() != Some(&authority.session_id)
            || envelope.incarnation_id.0.as_ref() != Some(&authority.incarnation_id)
            || envelope.node_id.0.as_ref() != scoped.then_some(&self.installation.descriptor.id)
            || envelope.execution_owner_id.0.as_ref()
                != scoped.then_some(&self.installation.owner.owner.id)
        {
            return Err(refused("connected source foreign original envelope"));
        }
        Ok(())
    }

    fn response_for_input(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &Envelope,
        root: &ContentRef,
    ) -> Result<InputResult, OperationFailure> {
        self.envelope_current(scope, original)?;
        let request = decode_request(original.method, &original.body).map_err(unknown)?;
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("connected input id absent"))?;
        let retained = scope
            .controller
            .original(id)
            .ok_or_else(|| refused("connected input journal absent"))?;
        let response = retained
            .response
            .as_ref()
            .ok_or_else(|| refused("connected input response absent"))?;
        let Some(MethodResult::Input(result)) = decode_response(&request, &response.body)
            .map_err(unknown)?
            .result
        else {
            return Err(refused("connected input result absent"));
        };
        if self.input_root(scope, &result)?.0 != *root {
            return Err(refused(
                "connected input body not referenced by original response",
            ));
        }
        Ok(result)
    }

    pub(super) fn stage_record(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketStageRecord, OperationFailure> {
        self.guard(scope)?;
        let record: PacketStageRecord = self.object(scope, root)?;
        self.response_for_input(scope, &record.original, root)?;
        let PacketInputContext::Stage { cut } =
            PacketInputContext::decode(&record.original.extensions).map_err(unknown)?
        else {
            return Err(refused("connected native stage context changed"));
        };
        let RequestBody::Input(request) =
            decode_request(record.original.method, &record.original.body).map_err(unknown)?
        else {
            return Err(refused("connected stage original method"));
        };
        self.authenticate_cut(&cut)?;
        let active = self.active_request(scope, record.original.sequence)?;
        PacketInputContext::Stage { cut: cut.clone() }
            .authenticate(&record.original, &request, self.world.selection(), &active)
            .map_err(unknown)?;
        if record.schema != "source-owned.packet-staged-bytes/4"
            || record.native_pid.get() != u64::from(scope.native.provider_pid())
            || record.cut != cut
            || record.batch
                != request
                    .verified_batch(&self.owner().owner)
                    .map_err(unknown)?
            || record.batch.identity().map_err(unknown)? != cut.batch_hash
            || record.batch.events.len() > 4
            || record.deliveries.len() != record.batch.events.len()
            || record.payloads.len() != record.batch.events.len()
        {
            return Err(refused("connected complete original staged bytes changed"));
        }
        let inventory_bytes = scope
            .controller
            .content(&cut.delivery_inventory)
            .map_err(unknown)?;
        cut.delivery_inventory
            .verify(inventory_bytes)
            .map_err(unknown)?;
        let deliveries: Vec<Delivery> = serde_json::from_value(
            canonical::parse_json(inventory_bytes, 65_536).map_err(unknown)?,
        )
        .map_err(unknown)?;
        if serde_json::to_value(&deliveries).map_err(unknown)?
            != serde_json::to_value(&record.deliveries).map_err(unknown)?
        {
            return Err(refused(
                "connected stage replaces original complete delivery inventory",
            ));
        }
        let mut previous = None;
        for ((delivery, event), bytes) in deliveries
            .iter()
            .zip(&record.batch.events)
            .zip(&record.payloads)
        {
            self.check_staged_delivery(delivery, event, bytes, &cut)?;
            let key = delivery.key();
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(refused("connected stage canonical order changed"));
            }
            previous = Some(key);
        }
        self.guard(scope)?;
        Ok(record)
    }

    fn check_staged_delivery(
        &self,
        delivery: &Delivery,
        event: &Event,
        bytes: &Bytes,
        cut: &PacketInputCut,
    ) -> Result<(), OperationFailure> {
        // The same route checks are applied before staging and to original source evidence.
        self.validate_delivery(delivery, cut.cutoff)?;
        if bytes.as_slice().len() > 32
            || delivery.delivery < record_position_zero()
            || event.id != delivery.publication_id
            || event.source != delivery.producer_endpoint
            || event.destination != delivery.consumer_endpoint
            || event.source_sequence != delivery.native_sequence
            || event.provenance_ref != delivery.provenance_ref
            || event.position != delivery.delivery
            || event.publication_position != delivery.publication
            || event.delivery_position != Some(delivery.delivery)
            || event.payload != delivery.payload
            || event.stage != EventStage::Delivery
            || !event.extensions.is_empty()
            || event.causal_parent_ids
                != crucible_node_transport::reference_packet::connected::causal_parent_ids(
                    &delivery.causal_parents,
                )
                .map_err(unknown)?
        {
            return Err(refused(
                "connected staged complete event/payload lineage changed",
            ));
        }
        delivery.payload.verify(bytes.as_slice()).map_err(unknown)
    }

    fn active_request(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        before: U64,
    ) -> Result<WorldActivateRequest, OperationFailure> {
        let mut selected = None;
        for original in controller_originals(scope.controller) {
            if original.request.sequence >= before
                || original.request.method != Method::WorldActivate
            {
                continue;
            }
            if let RequestBody::WorldActivate(active) =
                decode_request(original.request.method, &original.request.body).map_err(unknown)?
            {
                if selected.is_some() {
                    return Err(refused("connected source activation renewed"));
                }
                selected = Some(active);
            }
        }
        selected
            .ok_or_else(|| refused("connected original input precedes authentic world activation"))
    }

    fn authenticate_cut(&self, cut: &PacketInputCut) -> Result<(), OperationFailure> {
        cut.validate().map_err(unknown)?;
        let authority = &self.installation.binding.authority;
        let world = self.world.coordinator();
        let saved: SavedRuntimeActivation =
            serde_json::from_value(world.template["activation"].clone()).map_err(unknown)?;
        if cut.session_id != authority.session_id
            || cut.incarnation_id != authority.incarnation_id
            || cut.node_id != self.installation.descriptor.id
            || cut.execution_owner_id != self.owner().owner
            || cut.owner_generation != authority.owner_generation
            || cut.input_epoch != authority.input_epoch
            || cut.world_binding_hash != self.installation.world_binding_hash
            || cut.activation_id != saved.activation_id
            || cut.world_generation != saved.generation
        {
            return Err(refused("connected native original input cut changed"));
        }
        Ok(())
    }

    pub(super) fn commit_record(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketCommitRecord, OperationFailure> {
        self.guard(scope)?;
        let record: PacketCommitRecord = self.object(scope, root)?;
        self.response_for_input(scope, &record.original, root)?;
        let PacketInputContext::Commit {
            cut,
            input_request_id,
            staging_receipt,
        } = PacketInputContext::decode(&record.original.extensions).map_err(unknown)?
        else {
            return Err(refused("connected original commit action changed"));
        };
        let stage = self.stage_record(scope, &record.staged_record)?;
        let RequestBody::Input(request) =
            decode_request(record.original.method, &record.original.body).map_err(unknown)?
        else {
            return Err(refused("connected commit original method"));
        };
        PacketInputContext::Commit {
            cut: cut.clone(),
            input_request_id: input_request_id.clone(),
            staging_receipt: staging_receipt.clone(),
        }
        .authenticate(
            &record.original,
            &request,
            self.world.selection(),
            &self.active_request(scope, record.original.sequence)?,
        )
        .map_err(unknown)?;
        let expected = input::expected_reactions(
            &stage,
            record
                .original
                .request_id
                .0
                .as_ref()
                .ok_or_else(|| refused("connected commit request id absent"))?,
        );
        if record.schema != "source-owned.packet-consumed-input/4"
            || record.native_pid.get() != u64::from(scope.native.provider_pid())
            || record.cut != cut
            || cut != stage.cut
            || record.staging_receipt != staging_receipt
            || stage.original.request_id.0.as_ref() != Some(&input_request_id)
            || stage.original.sequence >= record.original.sequence
            || record.reactions != expected
            || stage.batch
                != request
                    .verified_batch(&self.owner().owner)
                    .map_err(unknown)?
            || self
                .response_for_input(scope, &stage.original, &record.staged_record)?
                .custody_receipt
                != staging_receipt
        {
            return Err(refused(
                "connected native complete original consumed lineage changed",
            ));
        }
        self.guard(scope)?;
        Ok(record)
    }

    pub(super) fn completed_root(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &Envelope,
    ) -> Result<Option<ContentRef>, OperationFailure> {
        let request = decode_request(original.method, &original.body).map_err(unknown)?;
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("connected original id absent"))?;
        let row = scope
            .controller
            .original(id)
            .ok_or_else(|| refused("connected original journal absent"))?;
        if let Some(response) = &row.response {
            let decoded = decode_response(&request, &response.body).map_err(unknown)?;
            if let Some(root) = result_root(decoded.result.as_ref())? {
                return Ok(Some(root));
            }
        }
        let RequestBody::Begin(begin) = request else {
            return Ok(None);
        };
        for poll in controller_originals(scope.controller) {
            if poll.request.method != Method::Poll
                || poll.request.operation_id != original.operation_id
            {
                continue;
            }
            let Some(response) = &poll.response else {
                continue;
            };
            let request =
                decode_request(poll.request.method, &poll.request.body).map_err(unknown)?;
            if let Some(MethodResult::Poll(result)) = decode_response(&request, &response.body)
                .map_err(unknown)?
                .result
                && let Some(response) = result.validated_outcome(&begin).map_err(unknown)?
                && let Some(root) = result_root(response.result.as_ref())?
            {
                return Ok(Some(root));
            }
        }
        Ok(None)
    }

    // Edition five retains a live wrapper and the unchanged model record as
    // separate objects. Both are joined to the same original controller request;
    // parsing the wrapper cannot authenticate a foreign or restored capsule.
    fn original_record_data(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketConnectedNativeRecord, OperationFailure> {
        if !self.world.is_complete() {
            return self.object(scope, root);
        }
        self.guard(scope)?;
        let decoded = if self.complete_capture_allocation_selection.is_some() {
            super::super::packet_complete_source::capture_allocation_receipt::decode_complete_receipt_data(
                scope, scope.controller.content(root).map_err(unknown)?, self.object(scope, root)?, self.complete_capture_allocation_selection,
            )?
        } else {
            super::super::packet_complete_source::capture_allocation_receipt::CompleteReceiptData {
                receipt: self.object(scope, root)?,
                allocation: None,
            }
        };
        let wrapper = decoded.receipt;
        let request_id = wrapper
            .original
            .request_id
            .0
            .as_ref()
            .ok_or_else(|| refused("complete native original request id absent"))?;
        let original = scope
            .controller
            .original(request_id)
            .ok_or_else(|| refused("complete native original controller request absent"))?;
        if self.completed_root(scope, &original.request)?.as_ref() != Some(root) {
            return Err(refused(
                "complete native wrapper is not the original response",
            ));
        }
        let expected = self
            .complete_storage
            .as_ref()
            .ok_or_else(|| refused("complete source selected storage absent"))?;
        if wrapper.capture_profile != *self.complete_capture_profile.as_ref().unwrap_or(
                &crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
            )
                || wrapper.confirmation_selection != self.complete_confirmation_selection.flatten()
                || wrapper.storage_selection != *expected
            || wrapper.storage_selection.limits != scope.controller.authority().limits()
        {
            return Err(refused(
                "complete source original storage/negotiated limits changed",
            ));
        }
        let bytes = scope
            .controller
            .content(&wrapper.native_record)
            .map_err(unknown)?;
        let record = wrapper
            .verify_original_record_data(
                self.world.selection(),
                scope.native.provider_pid(),
                &original.request,
                bytes,
            )
            .map_err(unknown)?;
        self.guard(scope)?;
        match record {
            crucible_node_transport::reference_packet::control::PacketNative5UnderlyingRecord::Reactive(record) => {
                super::super::packet_complete_source::capture_allocation_receipt::authenticate_allocation_cursor(decoded.allocation.as_ref(), record.inventory.reached)?;
                Ok(*record)
            },
            _=>Err(refused("complete reactive source cannot read a producer record")),
        }
    }

    pub(super) fn authenticate_record_evidence(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        reference: &ContentRef,
    ) -> Result<(), OperationFailure> {
        if !self.world.is_complete() {
            return self.native_record(scope, reference).map(|_| ());
        }
        self.guard(scope)?;
        let value: serde_json::Value = self.object(scope, reference)?;
        if value.get("schema").and_then(serde_json::Value::as_str) == Some("source-owned.packet-receipt/5")
            || (self.complete_capture_allocation_selection.is_some()
                && value.get("schema").and_then(serde_json::Value::as_str) == Some(crucible_node_transport::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD))
        {
            return self.native_record(scope, reference).map(|_| ());
        }
        let record: PacketConnectedNativeRecord = serde_json::from_value(value).map_err(unknown)?;
        let root = self
            .completed_root(scope, &record.original)?
            .ok_or_else(|| refused("complete underlying record original response absent"))?;
        let wrapper = if self.complete_capture_allocation_selection.is_some() {
            super::super::packet_complete_source::capture_allocation_receipt::decode_complete_receipt_data(
                scope, scope.controller.content(&root).map_err(unknown)?, self.object(scope, &root)?, self.complete_capture_allocation_selection,
            )?.receipt
        } else {
            self.object(scope, &root)?
        };
        if wrapper.native_record != *reference || self.native_record(scope, &root)? != record {
            return Err(refused(
                "complete underlying record differs from original wrapper",
            ));
        }
        self.guard(scope)
    }

    pub(super) fn native_record(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketConnectedNativeRecord, OperationFailure> {
        self.guard(scope)?;
        let record = self.original_record_data(scope, root)?;
        self.envelope_current(scope, &record.original)?;
        if record.schema != "source-owned.packet-native/4"
            || record.native_pid.get() != u64::from(scope.native.provider_pid())
            || self.completed_root(scope, &record.original)?.as_ref() != Some(root)
        {
            return Err(refused(
                "connected native proof not original current response",
            ));
        }
        let projected = self.project(scope, record.original.sequence)?;
        if record.inventory != projected {
            return Err(refused(
                "connected full historical source inventory changed",
            ));
        }
        self.guard(scope)?;
        Ok(record)
    }

    fn project(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        through: U64,
    ) -> Result<PacketConnectedInventory, OperationFailure> {
        let mut inventory = initial_inventory();
        let mut staged = Vec::new();
        let mut committed = Vec::new();
        let mut operations = Vec::new();
        let mut originals = scope
            .controller
            .originals()
            .filter(|row| row.request.sequence <= through)
            .collect::<Vec<_>>();
        originals.sort_by_key(|row| row.request.sequence);
        for original in originals {
            let envelope = &original.request;
            let request = decode_request(envelope.method, &envelope.body).map_err(unknown)?;
            match request {
                RequestBody::Input(_) => {
                    let Some(response) = &original.response else {
                        return Err(refused("connected historical Input has no final answer"));
                    };
                    let decoded = decode_response(
                        &decode_request(envelope.method, &envelope.body).map_err(unknown)?,
                        &response.body,
                    )
                    .map_err(unknown)?;
                    let Some(MethodResult::Input(result)) = decoded.result else {
                        continue;
                    };
                    let root = self.input_root(scope, &result)?.0;
                    match PacketInputContext::decode(&envelope.extensions).map_err(unknown)? {
                        PacketInputContext::Stage { .. } => {
                            let record = self.stage_record(scope, &root)?;
                            if inventory.gate_closed
                                || !inventory.retained_outputs.is_empty()
                                || record.inventory != inventory
                                || record.cut.batch_sequence.get() != staged.len() as u64 + 1
                                || staged.len() >= 16
                                || staged.len() != committed.len()
                                || record.cut.cutoff <= inventory.reached
                                || record
                                    .deliveries
                                    .iter()
                                    .any(|delivery| delivery.delivery < inventory.reached)
                                || staged.iter().any(|old: &PacketStageRecord| {
                                    old.cut.batch_id == record.cut.batch_id
                                        || old.cut.stage_operation_id
                                            == record.cut.stage_operation_id
                                        || old.batch.events.iter().any(|event| {
                                            record.batch.events.iter().any(|new| new.id == event.id)
                                        })
                                })
                            {
                                return Err(refused(
                                    "connected historical staging source state changed",
                                ));
                            }
                            inventory.stages.push(root);
                            staged.push(record);
                        }
                        PacketInputContext::Commit { .. } => {
                            let record = self.commit_record(scope, &root)?;
                            let last = staged
                                .last()
                                .ok_or_else(|| refused("connected commit precedes stage"))?;
                            if inventory.gate_closed
                                || !inventory.retained_outputs.is_empty()
                                || staged.len() != committed.len() + 1
                                || record.cut != last.cut
                                || record.staged_record
                                    != *inventory
                                        .stages
                                        .last()
                                        .ok_or_else(|| refused("connected stage root absent"))?
                                || record.reached != inventory.reached
                            {
                                return Err(refused(
                                    "connected historical commit source state changed",
                                ));
                            }
                            inventory.reactions.extend(record.reactions.clone());
                            inventory.reactions.sort_by(|a, b| {
                                (a.evaluation, &a.input_producer, a.input_sequence).cmp(&(
                                    b.evaluation,
                                    &b.input_producer,
                                    b.input_sequence,
                                ))
                            });
                            if staged
                                .iter()
                                .map(|stage| stage.batch.events.len())
                                .sum::<usize>()
                                > 32
                            {
                                return Err(refused("connected source event lifetime credit"));
                            }
                            inventory.commits.push(root);
                            committed.push(record);
                        }
                    }
                }
                RequestBody::Begin(begin) => {
                    let Some(root) = self.completed_root(scope, envelope)? else {
                        return Err(refused("connected historical original Begin is incomplete"));
                    };
                    let record = self.original_record_data(scope, &root)?;
                    if record.original != *envelope
                        || record.schema != "source-owned.packet-native/4"
                        || record.native_pid.get() != u64::from(scope.native.provider_pid())
                    {
                        return Err(refused("connected historical original grant changed"));
                    }
                    let actual = record
                        .grant
                        .as_ref()
                        .ok_or_else(|| refused("connected actual completed grant absent"))?;
                    let selected_common = self.validate_original_grant(scope, envelope, &begin)?;
                    let common = selected_common.view()?;
                    let consumed = committed
                        .last()
                        .ok_or_else(|| refused("connected grant has no actual consumed cut"))?;
                    if common.input_batch.cut != consumed.cut
                        || common.input_batch.commit_record
                            != *inventory
                                .commits
                                .last()
                                .ok_or_else(|| refused("connected consumed root absent"))?
                        || consumed.original.request_id.0.as_ref()
                            != Some(&common.input_batch.commit_request_id)
                        || actual.start != inventory.reached
                        || actual.limit > consumed.cut.cutoff
                        || operations.len() >= 64
                    {
                        return Err(refused(
                            "connected grant lost original finite consumed input",
                        ));
                    }
                    let (common_start, common_limit) = match common.request {
                        crucible_node_transport::reference_packet::common::PacketCommonRequest::ExactRun { start, limit, .. }
                        | crucible_node_transport::reference_packet::common::PacketCommonRequest::BoundarySettle { start, limit } => (*start, *limit),
                    };
                    if &actual.operation != common.operation
                        || actual.start != common_start
                        || actual.limit != common_limit
                    {
                        return Err(refused(
                            "connected native grant changes original common interval",
                        ));
                    }
                    let projected = project_grant(
                        &inventory,
                        &actual.operation,
                        actual.start,
                        actual.limit,
                        self.definition.output.is_some(),
                    )?;
                    if *actual != projected || record.inventory != projected.inventory {
                        return Err(refused(
                            "connected actual Delivery/Reaction/Publication grant changed",
                        ));
                    }
                    inventory = projected.inventory;
                    operations.push(actual.operation.clone());
                }
                RequestBody::WorldActivate(_) => {
                    let Some(root) = self.completed_root(scope, envelope)? else {
                        continue;
                    };
                    let record = self.original_record_data(scope, &root)?;
                    if !inventory.gate_closed {
                        return Err(refused("connected original gate renewed"));
                    }
                    inventory.gate_closed = false;
                    if record.original != *envelope
                        || record.schema != "source-owned.packet-native/4"
                        || record.native_pid.get() != u64::from(scope.native.provider_pid())
                        || record.inventory != inventory
                        || record.grant.is_some()
                    {
                        return Err(refused("connected original activation inventory changed"));
                    }
                }
                RequestBody::Retire(request) => {
                    let Some(response) = &original.response else {
                        continue;
                    };
                    let decoded =
                        decode_response(&RequestBody::Retire(request.clone()), &response.body)
                            .map_err(unknown)?;
                    let Some(MethodResult::Retire(result)) = decoded.result else {
                        continue;
                    };
                    if result.retired_operation_ids != request.operation_ids {
                        return Err(refused("connected original retirement changed"));
                    }
                    let receipt = request.custody_receipt.0.as_ref().ok_or_else(|| {
                        refused("connected native retirement lacks consumed bytes")
                    })?;
                    let value: serde_json::Value = self.object(scope, receipt)?;
                    validate_retirement_consumption(
                        &request.operation_ids,
                        &operations,
                        &inventory,
                        &value,
                    )?;
                    inventory.retained_outputs.clear();
                }
                RequestBody::Realize(_) | RequestBody::Activate(_) | RequestBody::Observe(_) => {
                    if let Some(root) = self.completed_root(scope, envelope)? {
                        let record = self.original_record_data(scope, &root)?;
                        if record.original != *envelope
                            || record.schema != "source-owned.packet-native/4"
                            || record.native_pid.get() != u64::from(scope.native.provider_pid())
                            || record.inventory != inventory
                            || record.grant.is_some()
                        {
                            return Err(refused(
                                "connected original read-only source inventory changed",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(inventory)
    }

    pub(super) fn latest_root(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<ContentRef, OperationFailure> {
        self.guard(scope)?;
        let mut latest = None;
        for original in controller_originals(scope.controller) {
            if let Some(root) = self.completed_root(scope, &original.request)?
                && latest
                    .as_ref()
                    .is_none_or(|(sequence, _)| *sequence < original.request.sequence)
            {
                latest = Some((original.request.sequence, root));
            }
        }
        latest
            .map(|(_, root)| root)
            .ok_or_else(|| refused("connected authentic source observation absent"))
    }

    pub(super) fn latest(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<PacketConnectedNativeRecord, OperationFailure> {
        self.native_record(scope, &self.latest_root(scope)?)
    }
}

pub(super) fn result_root(
    result: Option<&MethodResult>,
) -> Result<Option<ContentRef>, OperationFailure> {
    let Some(result) = result else {
        return Ok(None);
    };
    let root = match result {
        MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result) => {
            if result.stop_receipt != result.pending_inventory
                || result.stop_receipt != result.observation_batch
                || result.stop_reason != crucible_node_transport::bodies::StopReason::Ceiling
            {
                return Err(refused(
                    "connected completed stop does not join one full original source proof",
                ));
            }
            Some(result.stop_receipt.clone())
        }
        MethodResult::Realize(result) => Some(result.closed_gate_receipt.clone()),
        MethodResult::Activate(result) => Some(result.activation_receipt.clone()),
        MethodResult::WorldActivate(result) => Some(result.activation_receipt.clone()),
        MethodResult::Observe(result) => {
            if !result.complete || result.observations.len() != 1 {
                return Err(refused(
                    "connected complete original source observation absent",
                ));
            }
            result
                .observations
                .first()
                .map(|row| row.measurement_ref.clone())
        }
        _ => None,
    };
    Ok(root)
}

fn record_position_zero() -> Position {
    Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
}

pub(super) fn project_grant(
    initial: &PacketConnectedInventory,
    operation: &Id,
    start: Position,
    limit: Position,
    output: bool,
) -> Result<PacketConnectedGrant, OperationFailure> {
    if initial.gate_closed
        || !initial.retained_outputs.is_empty()
        || start != initial.reached
        || start > limit
        || limit.microstep.get() >= 16
    {
        return Err(refused("connected original source grant preconditions"));
    }
    let mut inventory = initial.clone();
    let mut newborn = Vec::new();
    loop {
        let reaction = inventory.reactions.first().map(|reaction| {
            if inventory
                .delivered_inputs
                .iter()
                .any(|row| row.reaction == *reaction)
            {
                reaction.evaluation
            } else {
                reaction.parent
            }
        });
        let publication = inventory.publications.first().map(|row| row.publication);
        let next = match (reaction, publication) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => break,
        };
        if next >= limit {
            break;
        }
        if publication == Some(next) {
            let pending = inventory.publications.remove(0);
            let sequence = inventory
                .packet_effects
                .checked_add(U64::new(1))
                .map_err(unknown)?;
            let row = PacketConnectedPublication {
                output: crucible_node_transport::reference_packet::PacketPublication {
                    event: pending.event.clone(),
                    operation: operation.clone(),
                    sequence,
                    evaluation: pending.reaction.evaluation,
                    publication: pending.publication,
                    payload: pending.reaction.payload.clone(),
                },
                pending,
            };
            inventory.packet_effects = sequence;
            inventory.retained_outputs.push(row.clone());
            newborn.push(row);
        } else {
            let first = inventory
                .reactions
                .first()
                .ok_or_else(|| refused("connected original input step absent"))?;
            if next == first.parent {
                inventory.delivered_inputs.push(PacketDeliveredInput {
                    reaction: first.clone(),
                    delivery_operation: operation.clone(),
                });
            } else {
                let reaction = inventory.reactions.remove(0);
                if output {
                    inventory.publications.push(PacketPendingPublication {
                        event: Id::new(format!(
                            "packet-reaction-{}",
                            reaction.input_event.as_str()
                        ))
                        .map_err(unknown)?,
                        publication: reaction
                            .evaluation
                            .reaction_publication(U64::new(16))
                            .map_err(unknown)?,
                        reaction,
                        reaction_operation: operation.clone(),
                    });
                    inventory
                        .publications
                        .sort_by(|a, b| (a.publication, &a.event).cmp(&(b.publication, &b.event)));
                }
                inventory.reactions_completed = inventory
                    .reactions_completed
                    .checked_add(U64::new(1))
                    .map_err(unknown)?;
            }
        }
    }
    inventory.reached = limit;
    Ok(PacketConnectedGrant {
        operation: operation.clone(),
        start,
        limit,
        inventory,
        newborn,
        complete: true,
    })
}

// Source4 consumes the complete v4 output roster before replay releases it.
// Legacy packet sources own their separate v1 retirement codec.
fn validate_retirement_consumption(
    operation_ids: &[Id],
    completed_operations: &[Id],
    inventory: &PacketConnectedInventory,
    value: &serde_json::Value,
) -> Result<(), OperationFailure> {
    let operation = operation_ids
        .first()
        .ok_or_else(|| refused("connected retirement operation absent"))?;
    let outputs = inventory
        .retained_outputs
        .iter()
        .map(|row| row.output.event.clone())
        .collect::<Vec<_>>();
    if operation_ids.len() != 1
        || !completed_operations.contains(operation)
        || value
            != &serde_json::json!({
                "schema": "source-owned.packet-consumption.v4",
                "operation": operation,
                "outputs": outputs
            })
        || inventory
            .retained_outputs
            .iter()
            .any(|row| &row.output.operation != operation)
    {
        return Err(refused(
            "connected whole original retirement consumption changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod retirement_tests;
