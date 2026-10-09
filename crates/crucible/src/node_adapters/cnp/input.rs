//! Exact original host inputs staged through authenticated public byte custody.

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError, bodies::*, envelope::Method, reference_device::MAX_INPUT_BYTES,
};

use crate::{
    node_contract::OperationFailure,
    node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch},
};

use super::{
    control::{CnpControlledReference, StagedInput, content, original_id},
    readiness::{after_native_effect, refused, unknown},
};

impl CnpControlledReference {
    pub(super) fn stage_inputs(
        &mut self,
        original: &RuntimeInputBatch,
        provenance: Option<&crate::node_contract::InputProvenanceClosure>,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        if !original.deliveries().is_empty() && provenance.is_none() {
            return Err(refused(
                "public input requires runtime-owned original provenance",
            ));
        }
        if let Some(provenance) = provenance {
            let mut roots = original
                .deliveries()
                .iter()
                .map(|delivery| delivery.provenance_ref.clone())
                .collect::<Vec<_>>();
            roots.sort();
            roots.dedup();
            if provenance.version() != 1
                || provenance.node() != original.node()
                || provenance.stage_operation() != original.stage_operation()
                || provenance.batch() != original.batch()
                || provenance.inventory() != original.inventory()
                || provenance.activation().record() != original.activation().record()
                || !std::rc::Rc::ptr_eq(
                    &provenance.activation().authority,
                    &original.activation().authority,
                )
                || provenance.roots() != roots
                || roots.iter().any(|root| {
                    !provenance
                        .objects()
                        .iter()
                        .any(|object| object.reference == *root)
                })
            {
                return Err(refused(
                    "runtime-owned public input provenance scope changed",
                ));
            }
            for object in provenance.objects() {
                object
                    .reference
                    .verify(&object.bytes)
                    .map_err(|error| unknown(error.into()))?;
            }
        }
        if let Some(staged) = &self.input {
            if staged.original.stage_operation() != original.stage_operation()
                || staged.original.batch() != original.batch()
                || staged.original.deliveries() != original.deliveries()
                || staged.original.payloads() != original.payloads()
                || staged.original.inventory() != original.inventory()
                || staged.original.cutoff() != original.cutoff()
                || staged.original.activation().record() != original.activation().record()
            {
                return Err(refused("public input retry changed original custody"));
            }
            if match (&staged.provenance, provenance) {
                (None, None) => false,
                (Some(old), Some(new)) => {
                    old.roots() != new.roots() || old.objects() != new.objects()
                }
                _ => true,
            } {
                return Err(refused(
                    "public input retry changed original provenance custody",
                ));
            }
            return staged.acknowledgement.clone().ok_or_else(|| {
                unknown(ProviderError::Correlation(
                    "original public input remains unresolved",
                ))
            });
        }
        let bootstrap = self.controller().map_err(unknown)?.bootstrap.clone();
        let mut events = Vec::with_capacity(original.deliveries().len());
        let mut bytes = Vec::new();
        for delivery in original.deliveries() {
            // Position-only lineage cannot be replaced by fabricated public IDs.
            if !delivery.causal_parents.is_empty() {
                return Err(refused(
                    "public input requires original causal parent identities",
                ));
            }
            let payload = original
                .payloads()
                .iter()
                .find(|payload| payload.reference == delivery.payload)
                .ok_or_else(|| refused("original public input payload unavailable"))?;
            if bytes
                .len()
                .checked_add(payload.bytes.len())
                .is_none_or(|size| size > MAX_INPUT_BYTES)
            {
                return Err(refused(
                    "public checksum input exceeds installed native bound",
                ));
            }
            bytes.extend_from_slice(&payload.bytes);
            events.push(Event {
                schema_version: 1,
                id: delivery.publication_id.clone(),
                source: delivery.producer_endpoint.clone(),
                destination: delivery.consumer_endpoint.clone(),
                position: delivery.delivery,
                stage: EventStage::Delivery,
                publication_position: delivery.publication,
                delivery_position: Some(delivery.delivery),
                // The coordinator allocates its own delivery sequence. Public
                // provider events retain the source's original native FIFO.
                source_sequence: delivery.native_sequence,
                causal_parent_ids: Vec::new(),
                payload: delivery.payload.clone(),
                provenance_ref: delivery.provenance_ref.clone(),
                extensions: Extensions::new(),
            });
        }
        let sequence = self.next_input_sequence;
        let successor = sequence
            .checked_add(U64::new(1))
            .map_err(|error| unknown(error.into()))?;
        let public = InputBatch {
            schema_version: 1,
            execution_owner_id: bootstrap.owner_id.clone(),
            input_epoch: bootstrap.authority.input_epoch.clone(),
            batch_id: original.batch().clone(),
            batch_sequence: sequence,
            events,
            extensions: Extensions::new(),
        };
        public.validate().map_err(|error| unknown(error.into()))?;
        let identity = public.identity().map_err(|error| unknown(error.into()))?;
        let (reference, canonical) = content(&public).map_err(unknown)?;
        let binding_hash = self
            .owner_binding
            .identity()
            .map_err(|error| unknown(error.into()))?;
        let request = original_id("input", original.stage_operation()).map_err(unknown)?;
        // Retain the opaque original before the first remote effect. A failed
        // transfer or receipt check leaves this exact input unresolved; retries
        // cannot allocate another sequence or silently resubmit accepted work.
        self.input = Some(StagedInput {
            original: original.retained_copy(),
            public: public.clone(),
            reference: reference.clone(),
            provenance: provenance.map(|closure| closure.retained_copy()),
            acknowledgement: None,
            bytes,
        });
        self.next_input_sequence = successor;
        self.activate_world(original.activation())?;
        let controller = self.controller_mut().map_err(unknown)?;
        if let Some(provenance) = provenance {
            for object in provenance.objects() {
                controller
                    .upload(&object.reference, &object.bytes)
                    .map_err(unknown)?;
            }
        }
        for payload in original.payloads() {
            controller
                .upload(&payload.reference, &payload.bytes)
                .map_err(unknown)?;
        }
        controller.upload(&reference, &canonical).map_err(unknown)?;
        let response = controller
            .call(
                request.clone(),
                None,
                Method::Input,
                true,
                InputRequest {
                    binding_hash,
                    owner_generation: bootstrap.authority.owner_generation,
                    batch_id: public.batch_id.clone(),
                    batch_sequence: sequence,
                    input_epoch: public.input_epoch.clone(),
                    events: public.events.clone(),
                    batch_hash: identity.clone(),
                    extensions: Extensions::new(),
                },
            )
            .map_err(unknown)?;
        let Some(MethodResult::Input(result)) = response.result else {
            return Err(unknown(ProviderError::Correlation(
                "original public input custody did not complete",
            )));
        };
        let mut expected_ids = public
            .events
            .iter()
            .map(|event| event.id.clone())
            .collect::<Vec<_>>();
        expected_ids.sort();
        expected_ids.dedup();
        let receipt: ControlReceipt = self
            .controller()
            .map_err(unknown)?
            .record(&result.custody_receipt)
            .map_err(unknown)?;
        let custody: InputCustodyRecord = self
            .controller()
            .map_err(unknown)?
            .record(&receipt.record_ref)
            .map_err(unknown)?;
        if result.accepted_event_ids != expected_ids
            || result.input_watermark != sequence
            || receipt.kind != ControlReceiptKind::InputCustody
            || receipt.issuer != ReceiptIssuer::Provider
            || receipt.session_id != bootstrap.authority.session_id
            || receipt.incarnation_id != bootstrap.authority.incarnation_id
            || receipt.request_id != request
            || receipt.operation_id.is_some()
            || receipt.owner_ids != [bootstrap.owner_id.clone()]
            || receipt.world_generation != bootstrap.world_generation
            || !receipt.extensions.is_empty()
            || custody.execution_owner_id != bootstrap.owner_id
            || custody.owner_generation != bootstrap.authority.owner_generation
            || custody.input_epoch != public.input_epoch
            || custody.input_watermark != sequence
            || custody.batch_hashes != [identity]
            || custody.pending_inventory.hash != result.inventory_hash
            || !custody.extensions.is_empty()
        {
            return Err(unknown(ProviderError::Correlation(
                "public input receipt changed original batch custody",
            )));
        }
        self.verify_native_custody().map_err(unknown)?;
        let previous = self
            .windows
            .values()
            .filter(|window| window.consumed)
            .max_by_key(|window| window.grant.quantum);
        self.verify_pending(
            &custody.pending_inventory,
            super::pending::ExpectedPending {
                operation: previous.map(|window| window.original.token().operation()),
                grant: previous.map(|window| &window.grant.window_id),
                revision: U64::new(sequence.get() - 1),
                input: &reference,
                output: None,
                watermark: sequence,
            },
        )
        .map_err(unknown)?;
        for payload in original.payloads() {
            self.retain_boundary_record(&payload.reference, Vec::new())
                .map_err(after_native_effect)?;
        }
        if let Some(provenance) = provenance {
            for object in provenance.objects() {
                self.retain_inherited_boundary_record(&object.reference)
                    .map_err(after_native_effect)?;
            }
        }
        let dependencies = public
            .events
            .iter()
            .flat_map(|event| [event.payload.clone(), event.provenance_ref.clone()])
            .collect();
        self.retain_boundary_record(&reference, dependencies)
            .map_err(after_native_effect)?;
        self.retain_boundary_record(&custody.pending_inventory, vec![reference.clone()])
            .map_err(after_native_effect)?;
        self.retain_boundary_record(&receipt.record_ref, vec![custody.pending_inventory])
            .map_err(after_native_effect)?;
        self.retain_boundary_record(&result.custody_receipt, vec![receipt.record_ref])
            .map_err(after_native_effect)?;
        let acknowledgement = NativeInputAcknowledgement {
            stage_operation: original.stage_operation().clone(),
            batch: original.batch().clone(),
            node: original.node().clone(),
            owners: original.owners().to_vec(),
            cutoff: original.cutoff(),
            inventory: original.inventory().clone(),
            proof_ref: result.custody_receipt,
        };
        let staged = self
            .input
            .as_mut()
            .ok_or_else(|| unknown(ProviderError::Correlation("original input custody lost")))?;
        staged.acknowledgement = Some(acknowledgement.clone());
        Ok(acknowledgement)
    }
}
