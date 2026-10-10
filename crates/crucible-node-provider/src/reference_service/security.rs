//! Installed native verification for public controller requests and receipts.

use crucible_node_contract::*;

use crate::ProviderError;
use crate::blob::BlobSchemaVerifier;
use crate::bodies::{
    self, BeginArguments, BeginKind, BeginRequest, InputRequest, InputResult, MethodResult,
};
use crate::connection::{BodySchemaVerifier, ReceivedBody};
use crate::envelope::Envelope;
use crate::handshake::ConnectionAuthority;
use crate::native_journal::*;
use crate::reference_device::DeviceStatus;

use super::resources::Resources;

pub(super) struct SchemaVerifier {
    pub(super) reader: Option<crate::reference_lineage::InputLineageDefinition>,
}

impl BodySchemaVerifier for SchemaVerifier {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty() {
            return Err(ProviderError::Frame(
                "reference envelope extensions unsupported",
            ));
        }
        if let Some(definition) = &self.reader
            && definition
                .declaration()
                .required_features
                .iter()
                .any(|feature| feature.as_str() == crate::handshake::EXTENSION_NEGOTIATION_V1)
            && authority.selected_extensions() != Some(std::slice::from_ref(definition.selection()))
        {
            return Err(ProviderError::Correlation(
                "typed reader original peer selection differs",
            ));
        }
        let extensions = match body {
            ReceivedBody::Request(request) => match request.as_ref() {
                bodies::RequestBody::Hello(value) => &value.extensions,
                bodies::RequestBody::Discover(value) => &value.extensions,
                bodies::RequestBody::Realize(value) => &value.extensions,
                bodies::RequestBody::Admit(value) => &value.extensions,
                bodies::RequestBody::Activate(value) => &value.extensions,
                bodies::RequestBody::Input(value) => &value.extensions,
                bodies::RequestBody::Observe(value) => &value.extensions,
                bodies::RequestBody::Begin(value) => &value.extensions,
                bodies::RequestBody::Poll(value) => &value.extensions,
                bodies::RequestBody::Cancel(value) => &value.extensions,
                bodies::RequestBody::QuantumClose(value) => &value.extensions,
                bodies::RequestBody::WorldActivate(value) => &value.extensions,
                bodies::RequestBody::Abort(value) => &value.extensions,
                bodies::RequestBody::Retire(value) => &value.extensions,
                bodies::RequestBody::BlobBegin(value) => &value.extensions,
                bodies::RequestBody::BlobChunk(value) => &value.extensions,
                bodies::RequestBody::BlobFinish(value) => &value.extensions,
                bodies::RequestBody::Release(value) => &value.extensions,
            },
            ReceivedBody::Response(response) => match &response.shape {
                bodies::ResponseShape::Accepted { extensions, .. }
                | bodies::ResponseShape::Completed { extensions, .. }
                | bodies::ResponseShape::Error { extensions, .. } => extensions,
            },
            ReceivedBody::Notification(notification) => &notification.extensions,
        };
        if let (Some(definition), ReceivedBody::Request(request)) = (&self.reader, body)
            && let bodies::RequestBody::Input(_) = request.as_ref()
        {
            if !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == crate::reference_lineage::INPUT_LINEAGE_FEATURE)
            {
                return Err(ProviderError::Correlation(
                    "lineage input reader feature was not negotiated",
                ));
            }
            super::input_reader::inventory_reference(definition, extensions)?;
            return Ok(());
        }
        if !extensions.is_empty() {
            return Err(ProviderError::Frame(
                "reference body extensions unsupported",
            ));
        }
        Ok(())
    }
}

pub(super) struct NativeVerifier {
    pub(super) request_id: Id,
}

impl NativeScopeVerifier<Resources> for NativeVerifier {
    fn verify_begin(
        &self,
        resources: &Resources,
        envelope: &Envelope,
        original: &BeginRequest,
    ) -> Result<NativeScope, ProviderError> {
        resources.check_owner(envelope, original.owner_generation, &original.binding_hash)?;
        if !resources.admitted {
            return Err(ProviderError::Correlation(
                "reference owner is not admitted",
            ));
        }
        match original.decoded_arguments()? {
            BeginArguments::QuantumBegin(grant) => {
                if !resources.active
                    || original.activation_id.0.as_ref() != Some(&resources.bootstrap.activation_id)
                    || original.world_generation != resources.bootstrap.world_generation
                    || grant.realization_id != resources.bootstrap.authority.realization_id
                    || grant.activation_id != resources.bootstrap.activation_id
                    || grant.world_generation != resources.bootstrap.world_generation
                    || grant.owner_generation != resources.bootstrap.authority.owner_generation
                    || grant.input_epoch != resources.bootstrap.authority.input_epoch
                    || grant.quantum_index != resources.next_quantum
                    || grant.policy_hash != resources.profile.operating_contract.policy_ref.hash
                    || grant.wall_budget_ns != resources.bootstrap.host_budget_ns
                    || grant.from_ps
                        != resources
                            .bootstrap
                            .quantum_ps
                            .checked_mul(grant.quantum_index)?
                    || grant.until_ps
                        != grant.from_ps.checked_add(resources.bootstrap.quantum_ps)?
                    || resources
                        .window
                        .as_ref()
                        .is_some_and(|window| !window.publication_acknowledged)
                {
                    return Err(ProviderError::Correlation(
                        "reference quantum differs from admitted native window",
                    ));
                }
                let input = resources.input.as_ref().ok_or(ProviderError::Correlation(
                    "reference quantum lacks original input custody",
                ))?;
                let supplied: InputBatch = resources.resolve(&grant.input_batch)?;
                if &supplied != input
                    || input.batch_sequence != grant.input_watermark
                    || input.execution_owner_id != resources.bootstrap.owner_id
                    || input.input_epoch != resources.bootstrap.authority.input_epoch
                    || input
                        .events
                        .iter()
                        .any(|event| event.position.time_ps > grant.from_ps)
                {
                    return Err(ProviderError::Correlation(
                        "reference quantum input cut lacks complete native custody",
                    ));
                }
                if resources
                    .child
                    .as_ref()
                    .is_none_or(|child| child.status() != DeviceStatus::Parked)
                {
                    return Err(ProviderError::Conflict(
                        "reference child is not natively parked",
                    ));
                }
            }
            BeginArguments::Shutdown(_) => {
                if resources
                    .window
                    .as_ref()
                    .is_some_and(|window| !window.publication_acknowledged)
                {
                    return Err(ProviderError::Conflict(
                        "unpublished reference output remains in custody",
                    ));
                }
            }
            _ => {
                return Err(ProviderError::Frame(
                    "reference profile does not support this operation facet",
                ));
            }
        }
        Ok(NativeScope {
            execution_owner: resources.bootstrap.owner_id.clone(),
            capture_owner: None,
            owner_generation: original.owner_generation,
            binding_hash: original.binding_hash.clone(),
            participants: resources.profile.owner.participant_ids.clone(),
            state_domains: resources.profile.owner.state_domain_ids.clone(),
        })
    }
}

impl NativeOutcomeVerifier<Resources> for NativeVerifier {
    fn verify_terminal(
        &self,
        resources: &Resources,
        original: &OperationSnapshot,
        response: &bodies::ResponseBody,
    ) -> Result<NativeDisposition, ProviderError> {
        match &response.result {
            Some(MethodResult::QuantumBegin(result)) => {
                let window = resources.window.as_ref().ok_or(ProviderError::Correlation(
                    "native window proof unavailable",
                ))?;
                let child = resources
                    .child
                    .as_ref()
                    .ok_or(ProviderError::Correlation("native child proof unavailable"))?;
                child.validate_receipt(&window.native)?;
                if window.operation != original.operation_id
                    || result.grant_id != window.grant.window_id
                    || result.quantum_index != window.grant.quantum
                    || result.stop_receipt != window.stop
                    || result.observation_batch != window.observation_ref
                    || result.pending_inventory != window.pending
                    || result.physical_measurement_ref != window.measurement
                    || !window.native.application_parked
                {
                    return Err(ProviderError::Correlation(
                        "terminal result differs from original native window",
                    ));
                }
                Ok(NativeDisposition::Released)
            }
            Some(MethodResult::Shutdown(result))
                if result.stopped
                    && result.reaped
                    && resources
                        .child
                        .as_ref()
                        .is_some_and(|child| child.status() == DeviceStatus::Reaped) =>
            {
                Ok(NativeDisposition::Released)
            }
            None => Ok(NativeDisposition::Held),
            _ => Err(ProviderError::Correlation(
                "reference native terminal evidence is unavailable",
            )),
        }
    }
}

impl NativeInputVerifier<Resources> for NativeVerifier {
    fn verify_input(
        &self,
        resources: &Resources,
        envelope: &Envelope,
        original: &InputRequest,
        batch: &InputBatch,
    ) -> Result<(), ProviderError> {
        resources.check_owner(envelope, original.owner_generation, &original.binding_hash)?;
        if !resources.active
            || resources
                .window
                .as_ref()
                .is_some_and(|window| !window.publication_acknowledged)
            || resources.input.is_some()
            || batch.input_epoch != resources.bootstrap.authority.input_epoch
            || resources
                .child
                .as_ref()
                .is_none_or(|child| child.status() != DeviceStatus::Parked)
        {
            return Err(ProviderError::Conflict(
                "reference input cannot replace occupied native custody",
            ));
        }
        if !batch.events.is_empty()
            && !resources
                .profile
                .descriptor
                .ports
                .iter()
                .flat_map(|port| &port.lanes)
                .any(|lane| lane.direction == Direction::Input)
        {
            return Err(ProviderError::Correlation(
                "closed reference source cannot accept nonempty input",
            ));
        }
        if resources.profile.is_lineage() && batch.events.len() > 64 {
            return Err(ProviderError::ResourceExhausted(
                "lineage original input event slots",
            ));
        }
        if resources.profile.input_lineage_definition().is_some() {
            super::input_reader::validate_original_input(
                resources,
                batch,
                original.owner_generation,
            )?;
        } else if resources.profile.is_lineage() {
            let original_parents: Vec<_> = batch
                .events
                .iter()
                .map(|event| event.provenance_ref.clone())
                .collect();
            super::transfer::verify_lineage_input_closure(resources, &original_parents)?;
        }
        let mut total = 0usize;
        for event in &batch.events {
            if resources.profile.is_lineage()
                && event.payload.media_type != "application/octet-stream"
            {
                return Err(ProviderError::Correlation(
                    "selected lineage byte role differs",
                ));
            }
            if event.destination.node_id != resources.bootstrap.node_id
                || event.destination.port_id.as_str() != "data"
                || event.destination.lane_id.as_str() != "input"
            {
                return Err(ProviderError::Correlation(
                    "reference input targets another node or lane",
                ));
            }
            let length = usize::try_from(event.payload.length.get())
                .map_err(|_| ProviderError::ResourceExhausted("reference payload length"))?;
            total = total
                .checked_add(length)
                .ok_or(ProviderError::ResourceExhausted("reference input bytes"))?;
            if total > crate::reference_device::MAX_INPUT_BYTES {
                return Err(ProviderError::ResourceExhausted("reference input bytes"));
            }
            if resources.content(&event.payload).is_err()
                && !resources.verified.contains_key(&event.payload.hash.digest)
            {
                return Err(ProviderError::Correlation(
                    "reference payload is not verified local content",
                ));
            }
        }
        Ok(())
    }

    fn accept_input(
        &self,
        resources: &mut Resources,
        batch: &InputBatch,
    ) -> Result<InputResult, ProviderError> {
        let inventory = if resources.profile.input_lineage_definition().is_some() {
            Some(super::input_reader::validate_original_input(
                resources,
                batch,
                resources.bootstrap.authority.owner_generation,
            )?)
        } else {
            None
        };
        let schema = resources
            .profile
            .descriptor
            .ports
            .iter()
            .find(|port| port.id.as_str() == "data")
            .and_then(|port| port.lanes.iter().find(|lane| lane.id.as_str() == "input"))
            .map(|lane| lane.payload_schema.definition.clone());
        let mut bytes = Vec::new();
        for event in &batch.events {
            let schema = schema.as_ref().ok_or(ProviderError::Frame(
                "installed reference input schema unavailable",
            ))?;
            if let Some(verified) = resources.verified.get(&event.payload.hash.digest) {
                let pin = resources.blobs.pin_operation(
                    verified,
                    batch.batch_id.clone(),
                    schema.clone(),
                    &PayloadSchema {
                        expected: schema.clone(),
                    },
                )?;
                pin.with_bytes(|payload| bytes.extend_from_slice(payload))?;
                resources.pins.push(pin);
            } else {
                bytes.extend_from_slice(resources.content(&event.payload)?);
            }
        }
        if let Some((reference, inventory)) = inventory {
            resources
                .lineage_input_rows
                .as_mut()
                .ok_or(ProviderError::Correlation(
                    "selected lineage row custody absent",
                ))?
                .retain(reference, &inventory)?;
        }
        resources.input = Some(batch.clone());
        resources.input_bytes = bytes;
        let pending = resources.pending()?;
        let record = InputCustodyRecord {
            schema_version: 1,
            execution_owner_id: resources.bootstrap.owner_id.clone(),
            owner_generation: resources.bootstrap.authority.owner_generation,
            input_epoch: batch.input_epoch.clone(),
            input_watermark: batch.batch_sequence,
            batch_hashes: vec![batch.identity()?],
            pending_inventory: pending.clone(),
            evidence_refs: Vec::new(),
            extensions: Extensions::new(),
        };
        let record_ref = resources.store_json(record)?;
        let receipt = resources.control_receipt(
            ControlReceiptKind::InputCustody,
            record_ref,
            &self.request_id,
            None,
        )?;
        resources.input_custody = Some(receipt.clone());
        let mut accepted_event_ids: Vec<_> =
            batch.events.iter().map(|event| event.id.clone()).collect();
        accepted_event_ids.sort();
        accepted_event_ids.dedup();
        Ok(InputResult {
            accepted_event_ids,
            input_watermark: batch.batch_sequence,
            custody_receipt: receipt,
            inventory_hash: pending.hash,
        })
    }
}

impl NativeObservationVerifier<Resources> for NativeVerifier {
    fn verify_observation(
        &self,
        resources: &Resources,
        original: &OperationSnapshot,
        batch: &ObservationBatch,
    ) -> Result<(), ProviderError> {
        let window = resources.window.as_ref().ok_or(ProviderError::Correlation(
            "original native observation unavailable",
        ))?;
        resources
            .child
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native observation child unavailable",
            ))?
            .validate_receipt(&window.native)?;
        if window.operation != original.operation_id || &window.observation != batch {
            return Err(ProviderError::Correlation(
                "observation differs from actual original native output",
            ));
        }
        Ok(())
    }
}

impl NativeConsumptionVerifier<Resources> for NativeVerifier {
    fn verify_operation(
        &self,
        resources: &Resources,
        original: &OperationSnapshot,
        receipt: &ContentRef,
    ) -> Result<(), ProviderError> {
        if !resources.consumed.contains(&receipt.hash.digest) {
            return Err(ProviderError::Correlation(
                "original semantic consumption was not authenticated",
            ));
        }
        let consumed: super::resources::PublicationConsumption = resources.resolve(receipt)?;
        if consumed.operation_id != original.operation_id {
            return Err(ProviderError::Correlation(
                "semantic receipt belongs to another original operation",
            ));
        }
        if original.original.kind == BeginKind::QuantumBegin
            && resources
                .window
                .as_ref()
                .is_some_and(|window| !window.publication_acknowledged)
        {
            return Err(ProviderError::Conflict("native output remains unpublished"));
        }
        Ok(())
    }
}

pub(super) struct PayloadSchema {
    pub(super) expected: ContentRef,
}

impl BlobSchemaVerifier for PayloadSchema {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        _: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if schema != &self.expected || bytes.len() > crate::reference_device::MAX_INPUT_BYTES {
            return Err(ProviderError::Frame(
                "reference bytes payload violates installed schema",
            ));
        }
        Ok(())
    }
}

impl Resources {
    pub(super) fn check_observation_scope(
        &self,
        envelope: &Envelope,
        generation: U64,
        binding: &HashRef,
    ) -> Result<(), ProviderError> {
        if envelope.execution_owner_id.0.is_some() {
            return self.check_owner(envelope, generation, binding);
        }
        if envelope.node_id.0.as_ref() != Some(&self.bootstrap.node_id)
            || envelope.capture_owner_id.0.is_some()
            || generation != self.bootstrap.authority.owner_generation
            || binding != &self.binding.identity()?
        {
            return Err(ProviderError::Correlation(
                "node observation differs from installed complete binding",
            ));
        }
        Ok(())
    }

    pub(super) fn check_owner(
        &self,
        envelope: &Envelope,
        generation: U64,
        binding: &HashRef,
    ) -> Result<(), ProviderError> {
        if envelope.execution_owner_id.0.as_ref() != Some(&self.bootstrap.owner_id)
            || envelope
                .node_id
                .0
                .as_ref()
                .is_some_and(|node| node != &self.bootstrap.node_id)
            || envelope.capture_owner_id.0.is_some()
            || generation != self.bootstrap.authority.owner_generation
            || binding != &self.owner_binding.identity()?
        {
            return Err(ProviderError::Correlation(
                "reference owner scope differs from installed native authority",
            ));
        }
        Ok(())
    }
}
