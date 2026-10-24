//! Conjoins full common snapshots with Runtime7 and first-sealed input ancestry.

use super::super::archive_owner::ArchivedContentData;
use super::{PacketCompleteArchivedSemantics, data::*, refused};
use crate::{
    node_contract::{
        EffectKnowledge, OperationFailure, OriginalLineageInputRecord,
        OriginalLineageRuntimeRecord, SavedRuntimeResult,
    },
    node_state::VerifiedStateContent,
};
use crucible_node_format::{EventStage, Id, Validate, canonical};

impl PacketCompleteArchivedSemantics {
    /// Correlates complete historical common custody with the exact signed runtime.
    ///
    /// This validates data only. Protocol, model, backend, source and fresh-world
    /// checks remain independent requirements before any restoration is installed.
    ///
    /// # Errors
    /// Refuses missing or extra native admissions, different payloads/ACKs,
    /// changed activation, unsupported failure closure or altered first ancestry.
    pub fn authenticate_runtime_data(
        &self,
        node: &Id,
        runtime: &OriginalLineageRuntimeRecord,
        content: &VerifiedStateContent,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.authenticate_runtime_with_construction_data(
            node,
            runtime,
            content,
            maximum_record_bytes,
            additional_retained_bytes,
            maximum_total_bytes,
            None,
        )
    }

    pub(super) fn authenticate_runtime_with_construction_data(
        &self,
        node: &Id,
        runtime: &OriginalLineageRuntimeRecord,
        content: &VerifiedStateContent,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
        construction: Option<&super::construction_storage::ValidationConstructionCounter>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_runtime_from_content_data(
            node,
            runtime,
            ArchivedContentData::Verified(content),
            maximum_record_bytes,
            additional_retained_bytes,
            maximum_total_bytes,
            construction,
        )
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_runtime_from_content_data(
        &self,
        node: &Id,
        runtime: &OriginalLineageRuntimeRecord,
        content: ArchivedContentData<'_>,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
        construction: Option<&super::construction_storage::ValidationConstructionCounter>,
    ) -> Result<(), OperationFailure> {
        let semantic = &self.semantic;
        let retained = additional_retained_bytes
            .checked_add(self.reserved_decoder_bytes)
            .and_then(|n| n.checked_add(20 + 256))
            .filter(|n| *n <= maximum_total_bytes)
            .ok_or_else(|| refused("archived common runtime storage exhausted"))?;
        super::construction_storage::observe(construction, retained, 0)?;
        if semantic.schema != "source-owned.packet-semantic-custody/5"
            || !matches!(
                self.ancestry.schema(),
                "source-owned.packet-original-ancestry/5"
                    | "source-owned.packet-original-ancestry/12"
            )
            || semantic.active.as_ref() != Some(&runtime.source_activation)
            || semantic.arm_attempt.as_ref() != Some(&runtime.source_activation)
            || semantic.activation_attempt.as_ref() != Some(&runtime.source_activation)
        {
            return Err(refused("archived common activation or schema differs"));
        }
        let ready = semantic
            .ready
            .as_ref()
            .ok_or_else(|| refused("archived common Ready absent"))?;
        let prepared = semantic
            .prepared_owner
            .as_ref()
            .ok_or_else(|| refused("archived common prepared owner absent"))?;
        if ready.owners.len() != 1
            || !runtime.source_activation.owners.contains(&ready.owners[0])
            || prepared.owner_id != ready.owners[0].owner
            || prepared.incarnation_id != ready.owners[0].incarnation
            || prepared.owner_generation != ready.owners[0].generation
            || prepared.ready_receipt != ready.ready_receipt
            || semantic.activate_response.is_none()
        {
            return Err(refused("archived common prepared/Ready owner differs"));
        }
        ready.boundary.validate().map_err(super::unknown)?;
        admit_scratch(
            retained,
            crate::node_contract::NodeRuntime::capture_serialization_storage(
                prepared,
                maximum_total_bytes,
            )
            .map_err(super::unknown)?,
            maximum_total_bytes,
            construction,
        )?;
        prepared.validate().map_err(super::unknown)?;

        for (identity, input) in &semantic.inputs {
            let saved = runtime
                .inputs
                .iter()
                .find(|one| &one.node == node && &one.stage_operation == identity)
                .ok_or_else(|| refused("archived common input is absent from Runtime7"))?;
            authenticate_batch(&input.original, saved, runtime, content)?;
            if input.acknowledgement != saved.acknowledgement
                || input.request.events.len() != saved.deliveries.len()
                || input.request.batch_id != saved.batch
                || input.watermark != input.request.batch_sequence
                || input.response.is_some() != input.acknowledgement.is_some()
            {
                return Err(refused("archived common input response/ACK differs"));
            }
            let input_validation = input
                .request
                .events
                .len()
                .checked_mul(
                    crate::node_contract::NodeRuntime::capture_map_node_storage::<
                        (&Id, crucible_node_format::U64),
                        (),
                    >(),
                )
                .ok_or_else(|| refused("archived common input validation extent overflow"))?;
            admit_scratch(
                retained,
                input_validation,
                maximum_total_bytes,
                construction,
            )?;
            input.request.validate().map_err(super::unknown)?;
            if let Some(response) = &input.response {
                authenticate_input_result(&input.request, response)?;
            }
            if let Some(commitment) = &input.commitment {
                let original = &commitment.original;
                if original.activation != input.original.activation
                    || original.node != saved.node
                    || original.stage_operation != saved.stage_operation
                    || original.batch != saved.batch
                    || original.inventory != saved.inventory
                    || original.cutoff != saved.cutoff
                    || input.acknowledgement.is_none()
                {
                    return Err(refused(
                        "archived consumed-input commitment changed original stage",
                    ));
                }
                for payload in &commitment.context {
                    authenticate_payload(payload, content)?;
                }
                if let Some(response) = &commitment.response {
                    authenticate_input_result(&input.request, response)?;
                }
            }
            if saved.coordinator_committed
                && input
                    .commitment
                    .as_ref()
                    .is_none_or(|one| one.response.is_none())
            {
                return Err(refused("archived common consumed-input response absent"));
            }
        }
        for input in runtime.inputs.iter().filter(|one| &one.node == node) {
            if !semantic.inputs.contains_key(&input.stage_operation)
                && !(input
                    .failure
                    .as_ref()
                    .is_some_and(|failure| failure.effects == EffectKnowledge::None)
                    && input.acknowledgement.is_none()
                    && !input.committed
                    && !input.coordinator_committed)
            {
                return Err(refused("Runtime7 input omits original common custody"));
            }
        }

        for (identity, operation) in &semantic.operations {
            let saved = runtime
                .operations
                .iter()
                .find(|one| &one.route.node == node && &one.operation == identity)
                .ok_or_else(|| refused("archived common operation absent from Runtime7"))?;
            if operation.operation != *identity
                || operation.route != saved.route
                || operation.request != saved.request
                || operation.activation != runtime.source_activation
                || operation.inputs.as_ref().map(|batch| &batch.batch) != saved.input_batch.as_ref()
            {
                return Err(refused(
                    "archived common admission or input association differs",
                ));
            }
            if let Some(batch) = &operation.inputs {
                let original = semantic
                    .inputs
                    .get(&batch.stage_operation)
                    .ok_or_else(|| refused("archived operation input stage absent"))?;
                if batch != &original.original {
                    return Err(refused("archived operation changed original input bytes"));
                }
            }
            let result_matches = match &saved.result {
                SavedRuntimeResult::Pending => {
                    operation.outcome.is_none()
                        && operation.failure.is_none()
                        && !operation.acknowledged
                }
                SavedRuntimeResult::Complete(outcome) => {
                    operation.outcome.as_ref() == Some(outcome)
                        && operation.failure.is_none()
                        && !operation.acknowledged
                }
                SavedRuntimeResult::Acknowledged(outcome) => {
                    operation.outcome.as_ref() == Some(outcome)
                        && operation.failure.is_none()
                        && operation.acknowledged
                        && operation.retirement.is_some()
                }
                SavedRuntimeResult::Failed(failure) => operation.failure.as_ref() == Some(failure),
            };
            if !result_matches {
                return Err(refused("archived common operation completion differs"));
            }
            admit_begin_validation(
                &operation.begin,
                retained,
                maximum_total_bytes,
                construction,
            )?;
            operation.begin.validate().map_err(super::unknown)?;
            if let Some(payload) = &operation.retirement {
                authenticate_payload(payload, content)?;
            }
        }
        for operation in runtime
            .operations
            .iter()
            .filter(|one| &one.route.node == node)
        {
            if !semantic.operations.contains_key(&operation.operation)
                && !matches!(&operation.result, SavedRuntimeResult::Failed(failure) if failure.effects == EffectKnowledge::None)
            {
                return Err(refused("Runtime7 operation omits original common custody"));
            }
        }
        self.authenticate_ancestry_data(
            node,
            runtime,
            content,
            maximum_record_bytes,
            additional_retained_bytes,
            maximum_total_bytes,
            construction,
        )
    }

    fn authenticate_ancestry_data(
        &self,
        node: &Id,
        runtime: &OriginalLineageRuntimeRecord,
        content: ArchivedContentData<'_>,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
        construction: Option<&super::construction_storage::ValidationConstructionCounter>,
    ) -> Result<(), OperationFailure> {
        let validation = AncestryValidation {
            node,
            runtime,
            content,
            maximum_record_bytes,
            retained_decoder_bytes: self.reserved_decoder_bytes,
            additional_retained_bytes,
            maximum_total_bytes,
            construction,
        };
        match &self.ancestry {
            ArchivedAncestry::Inline(record) => validation.authenticate(record),
            ArchivedAncestry::References(record) => validation.authenticate(record),
        }
    }
}

struct AncestryValidation<'a> {
    node: &'a Id,
    runtime: &'a OriginalLineageRuntimeRecord,
    content: ArchivedContentData<'a>,
    maximum_record_bytes: usize,
    retained_decoder_bytes: usize,
    additional_retained_bytes: usize,
    maximum_total_bytes: usize,
    construction: Option<&'a super::construction_storage::ValidationConstructionCounter>,
}

trait ArchivedObjectData {
    fn reference(&self) -> &crucible_node_format::ContentRef;

    fn authenticate(&self, content: ArchivedContentData<'_>) -> Result<(), OperationFailure>;
}

impl ArchivedObjectData for crate::node_scheduling::InputPayload {
    fn reference(&self) -> &crucible_node_format::ContentRef {
        &self.reference
    }

    fn authenticate(&self, content: ArchivedContentData<'_>) -> Result<(), OperationFailure> {
        authenticate_payload(self, content)
    }
}

impl ArchivedObjectData for crucible_node_format::ContentRef {
    fn reference(&self) -> &crucible_node_format::ContentRef {
        self
    }

    fn authenticate(&self, content: ArchivedContentData<'_>) -> Result<(), OperationFailure> {
        let bytes = content
            .get(self)
            .ok_or_else(|| refused("reference ancestry body absent"))?;
        self.verify(bytes).map_err(super::unknown)
    }
}

impl AncestryValidation<'_> {
    fn authenticate<Object: ArchivedObjectData>(
        &self,
        ancestry: &ArchivedAncestryRecord<Object>,
    ) -> Result<(), OperationFailure> {
        let Self {
            node,
            runtime,
            content,
            maximum_record_bytes,
            additional_retained_bytes,
            maximum_total_bytes,
            ..
        } = *self;
        let selected = runtime
            .inputs
            .iter()
            .filter(|one| &one.node == node && one.lineage.is_some());
        if selected.clone().count() != ancestry.lineages.len() {
            return Err(refused("archived first-sealed ancestry roster differs"));
        }
        for (offset, original) in ancestry.lineages.iter().enumerate() {
            if ancestry.lineages[..offset].iter().any(|one| {
                one.source_scope.stage_operation == original.source_scope.stage_operation
            }) {
                return Err(refused("archived first-sealed ancestry repeats a stage"));
            }
            let saved = selected
                .clone()
                .find(|one| {
                    one.lineage
                        .as_ref()
                        .is_some_and(|lineage| lineage.source == original.source_scope)
                })
                .ok_or_else(|| refused("archived first-sealed scope differs"))?;
            let lineage = saved
                .lineage
                .as_ref()
                .ok_or_else(|| refused("archived first-sealed scope absent"))?;
            let batch = &original.original;
            let source = &lineage.source;
            if batch.activation != source.source_activation
                || batch.node != source.node
                || batch.stage_operation != source.stage_operation
                || batch.batch != source.batch
                || batch.owners != source.owners
                || batch.cutoff != source.cutoff
                || batch.inventory != source.inventory
                || batch.deliveries != saved.deliveries
                || !batch
                    .payloads
                    .iter()
                    .map(|payload| &payload.reference)
                    .eq(saved.payloads.iter())
                || original.publications.len() != lineage.publications.len()
                || original.publications.len() != batch.deliveries.len()
            {
                return Err(refused("archived immutable ancestry batch differs"));
            }
            for payload in &batch.payloads {
                authenticate_payload(payload, content)?;
            }
            for ((publication, recorded), delivery) in original
                .publications
                .iter()
                .zip(&lineage.publications)
                .zip(&batch.deliveries)
            {
                if publication.origin != recorded.origin
                    || publication.published != recorded.published
                    || publication.rows != recorded.rows
                    || !publication
                        .objects
                        .iter()
                        .map(ArchivedObjectData::reference)
                        .eq(recorded.objects.iter())
                    || publication.origin.measurement != delivery.provenance_ref
                    || publication.event.id != delivery.publication_id
                    || publication.event.source != delivery.producer_endpoint
                    || publication.event.source_sequence != delivery.native_sequence
                    || publication.event.payload != delivery.payload
                    || publication.event.provenance_ref != delivery.provenance_ref
                    || publication.event.publication_position != delivery.publication
                    || publication.event.position != delivery.publication
                    || publication.event.stage != EventStage::Publication
                    || publication.event.delivery_position.is_some()
                    || !publication.event.extensions.is_empty()
                {
                    return Err(refused("archived original publication ancestry differs"));
                }
                let bytes = content
                    .get(&publication.published)
                    .ok_or_else(|| refused("original publication body absent"))?;
                if bytes.len() > maximum_record_bytes {
                    return Err(refused(
                        "archived publication exceeds selected record ceiling",
                    ));
                }
                let scratch =
                    super::decode_storage(bytes, maximum_total_bytes).map_err(super::unknown)?;
                additional_retained_bytes
                    .checked_add(self.retained_decoder_bytes)
                    .and_then(|n| n.checked_add(scratch))
                    .filter(|n| *n <= maximum_total_bytes)
                    .ok_or_else(|| refused("archived publication comparison storage exhausted"))?;
                super::construction_storage::observe(
                    self.construction,
                    additional_retained_bytes
                        .checked_add(self.retained_decoder_bytes)
                        .ok_or_else(|| refused("archived publication construction overflow"))?,
                    scratch,
                )?;
                publication
                    .published
                    .verify(bytes)
                    .map_err(super::unknown)?;
                let event: crucible_node_format::Event =
                    canonical::decode(bytes, bytes.len()).map_err(super::unknown)?;
                event.validate().map_err(super::unknown)?;
                if event != publication.event {
                    return Err(refused("archived original publication Event changed"));
                }
                for object in &publication.objects {
                    object.authenticate(content)?;
                }
            }
        }
        Ok(())
    }
}

fn admit_scratch(
    retained: usize,
    scratch: usize,
    maximum: usize,
    construction: Option<&super::construction_storage::ValidationConstructionCounter>,
) -> Result<(), OperationFailure> {
    retained
        .checked_add(scratch)
        .filter(|n| *n <= maximum)
        .ok_or_else(|| refused("archived common validation scratch exhausted"))?;
    super::construction_storage::observe(construction, retained, scratch)?;
    Ok(())
}

fn admit_begin_validation(
    begin: &crucible_node_transport::bodies::BeginRequest,
    retained: usize,
    maximum: usize,
    construction: Option<&super::construction_storage::ValidationConstructionCounter>,
) -> Result<(), OperationFailure> {
    use crate::node_contract::NodeRuntime;

    if std::mem::size_of::<crucible_node_transport::bodies::BeginArguments>()
        > NodeRuntime::capture_closed_inline_storage()
    {
        return Err(refused(
            "archived Begin argument layout exceeds selected decoder",
        ));
    }
    // The public validator clones arguments for canonicalization, retains the
    // encoded Vec, then clones them again for its closed typed argument decode.
    let first = NodeRuntime::capture_serialization_storage(&begin.arguments, maximum)
        .map_err(super::unknown)?;
    let encoded = NodeRuntime::capture_encoded_output_storage(&begin.arguments, maximum)
        .map_err(super::unknown)?;
    let decoded = NodeRuntime::capture_future_decode_storage(&begin.arguments, maximum)
        .map_err(super::unknown)?;
    let scratch = first
        .checked_add(encoded)
        .and_then(|n| n.checked_add(decoded))
        .ok_or_else(|| refused("archived Begin validation extent overflow"))?;
    admit_scratch(retained, scratch, maximum, construction)
}

fn authenticate_input_result(
    request: &crucible_node_transport::bodies::InputRequest,
    response: &crucible_node_transport::bodies::InputResult,
) -> Result<(), OperationFailure> {
    // The caller's fixed clone scratch covers the public sorted-ID validator.
    response.validate().map_err(super::unknown)?;
    if response.input_watermark != request.batch_sequence
        || response.accepted_event_ids.len() != request.events.len()
        || request
            .events
            .iter()
            .any(|event| !response.accepted_event_ids.contains(&event.id))
    {
        return Err(refused(
            "archived common input result changed sequence or accepted events",
        ));
    }
    Ok(())
}

fn authenticate_batch(
    batch: &ArchivedBatch,
    input: &OriginalLineageInputRecord,
    runtime: &OriginalLineageRuntimeRecord,
    content: ArchivedContentData<'_>,
) -> Result<(), OperationFailure> {
    if batch.activation != runtime.source_activation
        || batch.node != input.node
        || batch.stage_operation != input.stage_operation
        || batch.batch != input.batch
        || batch.owners != input.owners
        || batch.cutoff != input.cutoff
        || batch.inventory != input.inventory
        || batch.deliveries != input.deliveries
        || !batch
            .payloads
            .iter()
            .map(|payload| &payload.reference)
            .eq(input.payloads.iter())
    {
        return Err(refused("archived common input batch differs"));
    }
    for payload in &batch.payloads {
        authenticate_payload(payload, content)?;
    }
    Ok(())
}

pub(super) fn authenticate_payload(
    payload: &crate::node_scheduling::InputPayload,
    content: ArchivedContentData<'_>,
) -> Result<(), OperationFailure> {
    payload
        .reference
        .verify(&payload.bytes)
        .map_err(super::unknown)?;
    if content.get(&payload.reference) != Some(payload.bytes.as_slice()) {
        return Err(refused("archived common referenced bytes differ"));
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<AncestryValidation<'_>>()
        + size_of::<crucible_node_format::Event>()
        + size_of::<Result<crucible_node_format::Event, crucible_node_format::ContractError>>()
        + size_of::<[usize; 4]>()
}
