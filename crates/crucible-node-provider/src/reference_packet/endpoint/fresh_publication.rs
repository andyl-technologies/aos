//! Publishes one genuine inactive Fresh report and retains every partial owner.
//!
//! The Source-admitted startup purpose and separate fixed Prepare scope precede
//! this path. The actual query/current census is already held by the endpoint.
//! No parsed report, ceiling or incomplete publication creates the completed
//! owner needed by the next Prepare.

use super::fresh_restore::NativeFreshCurrentCensus;
use super::*;
use crate::client::DeadlineStream;
use crate::reference_packet::serialization_storage::encode_original_precharged_serialization_into;
use crate::reference_packet::service::fresh_restore_allocation::*;
use crate::reference_packet::service::report_startup::{
    PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY, PacketNativeReportStartupAllocationRow,
};

mod metadata;
mod startup;
mod storage;
pub(crate) use startup::{
    original_fresh_report_startup_publication_counter_scratch_data,
    original_fresh_report_startup_publication_data,
};

#[cfg(test)]
mod tests;

/// Owns construction, caches and the successful response commitment in one slot.
pub(super) struct NativeFreshReportPublication {
    schema: Option<String>,
    data: Option<PacketNativeFreshRestoreAllocationData>,
    proof: Option<PacketNativeFreshRestoreAllocationProof>,
    report: Option<PacketNativeFreshRestoreAllocationReport>,
    raw: Vec<u8>,
    reference: Option<ContentRef>,
    inventory_raw: Vec<u8>,
    inventory_hash: Option<crucible_node_contract::HashRef>,
    result: Option<ObserveResult>,
    receipt: Option<PacketNativeFreshRestoreAllocationReceipt>,
    reply: Option<super::super::control::PacketControlReply>,
    completed_response: Option<[u8; 32]>,
    completed_record: Option<usize>,
}

impl NativeFreshReportPublication {
    pub(super) const fn new() -> Self {
        Self {
            schema: None,
            data: None,
            proof: None,
            report: None,
            raw: Vec::new(),
            reference: None,
            inventory_raw: Vec::new(),
            inventory_hash: None,
            result: None,
            receipt: None,
            reply: None,
            completed_response: None,
            completed_record: None,
        }
    }

    pub(super) fn is_unstarted(&self) -> bool {
        self.schema.is_none()
            && self.data.is_none()
            && self.proof.is_none()
            && self.report.is_none()
            && self.raw.is_empty()
            && self.raw.capacity() == 0
            && self.reference.is_none()
            && self.inventory_raw.is_empty()
            && self.inventory_raw.capacity() == 0
            && self.inventory_hash.is_none()
            && self.result.is_none()
            && self.receipt.is_none()
            && self.reply.is_none()
            && self.completed_response.is_none()
            && self.completed_record.is_none()
    }

    /// Lends only a publication completed by the actual transport path.
    /// Typed/raw correspondence is the private publisher's construction
    /// invariant; this loan never deserializes a portable completion owner.
    pub(super) fn completed_parts_data(
        &self,
    ) -> Result<(&ContentRef, &[u8; 32], usize), ProviderError> {
        let reference = self.reference.as_ref().ok_or_else(refused)?;
        let receipt = self.receipt.as_ref().ok_or_else(refused)?;
        if self.schema.is_some()
            || self.data.is_some()
            || self.proof.is_some()
            || self.report.is_none()
            || self.result.is_none()
            || self.reply.is_none()
            || self.raw.is_empty()
            || self.raw.capacity() != PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY
            || reference.length.get() != u64::try_from(self.raw.len()).map_err(|_| refused())?
            || receipt.allocation != *reference
        {
            return Err(refused());
        }
        Ok((
            reference,
            self.completed_response.as_ref().ok_or_else(refused)?,
            self.completed_record.ok_or_else(refused)?,
        ))
    }

    fn assemble_report(&mut self) -> Result<(), ProviderError> {
        if self.report.is_some() {
            return Err(refused());
        }
        // This transition contains no callback, serializer or fallible owner
        // construction. On a phase mismatch, put every original part back.
        match (self.schema.take(), self.data.take(), self.proof.take()) {
            (Some(schema), Some(data), Some(proof)) => {
                self.report = Some(PacketNativeFreshRestoreAllocationReport {
                    schema,
                    data,
                    proof,
                });
                Ok(())
            }
            (schema, data, proof) => {
                self.schema = schema;
                self.data = data;
                self.proof = proof;
                Err(refused())
            }
        }
    }
}

/// Names actual fixed publication/counter work before taking any producer loan.
pub(crate) fn original_fresh_report_publication_counter_scratch_data() -> usize {
    [
        super::fresh_restore::original_fresh_current_counter_scratch_data(),
        PacketControl::original_fresh_report_view_counter_scratch_data(),
        fresh_restore_allocation_startup_counter_scratch_data(),
        crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data(),
        Connection::<DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data(),
        std::mem::size_of::<NativeFreshReportPublication>(),
        std::mem::size_of::<storage::NativeFreshPublicationPlan>(),
        std::mem::size_of::<blake3::Hasher>(),
        std::mem::size_of::<[usize; 20]>(),
    ].into_iter().try_fold(0usize, usize::checked_add).unwrap_or(usize::MAX)
}

impl PacketEndpoint<DeadlineStream> {
    pub(super) fn publish_original_fresh_report(
        &mut self,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        let plan = storage::quote(self)?;
        let Self {
            transport,
            native,
            authority,
            next_sequence,
            transport_credit,
            fresh_restore_attempt,
            ..
        } = self;
        let Some(Transport::Connected(connection)) = transport.as_ref() else {
            return Err(refused());
        };
        let mut attempt_guard = fresh_restore_attempt
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        let attempt = &mut *attempt_guard;
        attempt.authenticate_current(connection)?;
        attempt
            .startup
            .authenticate_complete_native_baseline(connection)?;
        attempt
            .startup
            .authenticate_actual_data(connection, &plan.row)?;
        let current = attempt.current.as_ref().ok_or_else(refused)?;
        let commitments = attempt.input.commitments.as_ref().ok_or_else(refused)?;
        let frame = attempt.input.frame.as_ref().ok_or_else(refused)?;
        let ReceivedBody::Request(body) = &frame.body else {
            return Err(refused());
        };
        let RequestBody::Observe(observed) = body.as_ref() else {
            return Err(refused());
        };
        let view = native.borrow_original_fresh_report_data(
            &connection.original_native_owned11_admission()?.policy,
        )?;
        let selection = view.selection_data();
        let [binding] = selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let [owner] = selection.realization.owner_bindings.as_slice() else {
            return Err(refused());
        };
        if owner.owner != binding.compatibility.execution_owner {
            return Err(refused());
        }
        let publication = &mut attempt.publication;
        if !publication.is_unstarted() {
            return Err(refused());
        }
        publication
            .raw
            .try_reserve_exact(PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY)
            .map_err(|_| exhausted())?;
        publication
            .inventory_raw
            .try_reserve_exact(plan.inventory.maximum_encoded_bytes)
            .map_err(|_| exhausted())?;
        if publication.raw.capacity() != PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY
            || publication.inventory_raw.capacity() != plan.inventory.maximum_encoded_bytes
        {
            return Err(exhausted());
        }
        encode_original_precharged_serialization_into(
            &view.inventory_data(),
            &plan.inventory,
            &mut publication.inventory_raw,
        )?;
        publication.inventory_hash = Some(crucible_node_contract::canonical::hash(
            view.inventory_domain_data(),
            &publication.inventory_raw,
        )?);
        let prepare = attempt
            .prepare
            .original_fixed_prepare_storage_data(connection)?;
        let current_bytes = quantity(current.retained_requested_bytes)?;
        let prepare_growth = quantity(prepare.retained_growth_bytes())?;
        let prepare_transient = quantity(prepare.maximum_simultaneous_transient_bytes())?;
        let full_scratch = quantity(plan.declared_full_scratch)?;
        publication.schema = Some(PACKET_FRESH_RESTORE_ALLOCATION_REPORT.into());
        publication.data = Some(PacketNativeFreshRestoreAllocationData {
            scope: PacketNativeFreshRestoreAllocationScope {
                native_pid: U64::new(u64::from(std::process::id())),
                session: binding.authority.session_id.clone(),
                incarnation: binding.authority.incarnation_id.clone(),
                node: binding.compatibility.node_id.clone(),
                owner: binding.compatibility.execution_owner.id.clone(),
                owner_generation: binding.authority.owner_generation,
                owner_binding: observed.binding_hash.clone(),
                world: selection.world.clone(),
                prepared_token: selection.prepared_token.clone(),
                admission: selection.admission.clone(),
                closed_gate_receipt: view.gate_receipt_data().clone(),
                nonce: crucible_node_contract::Bytes::new(commitments[0].to_vec()),
                ack_context: crucible_node_contract::Bytes::new(commitments[1].to_vec()),
                assigned_query: crucible_node_contract::Bytes::new(commitments[2].to_vec()),
                completed_admit_request: crucible_node_contract::Bytes::new(
                    commitments[3].to_vec(),
                ),
                completed_admit_response: crucible_node_contract::Bytes::new(
                    commitments[4].to_vec(),
                ),
            },
            storage: PacketNativeFreshRestoreAllocationStorage {
                current_retained_bytes: current_bytes,
                query_retained_growth_bytes: plan.row.retained_growth_bytes,
                prepare_retained_growth_bytes: prepare_growth,
                query_transient_bytes: plan.row.maximum_simultaneous_transient_bytes,
                prepare_transient_bytes: prepare_transient,
                declared_counter_scratch_bytes: full_scratch,
            },
        });
        let data = publication.data.as_ref().ok_or_else(refused)?;
        publication.proof = Some(
            attempt
                .startup
                .fresh_restore_report_proof_data(connection, data)?,
        );
        publication.assemble_report()?;
        let report = publication.report.as_ref().ok_or_else(refused)?;
        report.validate_data()?;
        encode_original_precharged_serialization_into(
            report,
            &plan.shapes.report,
            &mut publication.raw,
        )?;
        publication.reference = Some(crucible_node_contract::canonical::content_ref(
            &publication.raw,
            PACKET_FRESH_RESTORE_ALLOCATION_MEDIA,
        )?);
        let reference = publication.reference.as_ref().ok_or_else(refused)?;
        publication.result = Some(ObserveResult {
            observations: Vec::new(),
            next_sequence: U64::new(0),
            complete: true,
            inventory_hash: publication
                .inventory_hash
                .as_ref()
                .ok_or_else(refused)?
                .clone(),
        });
        publication.receipt = Some(PacketNativeFreshRestoreAllocationReceipt {
            schema: PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT.into(),
            allocation: reference.clone(),
        });
        // Retain all native result owners before DOM construction or transport.
        publication.reply = Some(super::super::control::PacketControlReply {
            body: serde_json::Map::new(),
            evidence: Vec::new(),
        });
        {
            let reply = publication.reply.as_mut().ok_or_else(refused)?;
            reply.body = prefix::completed(publication.result.as_ref().ok_or_else(refused)?)?;
            let receipt = serde_json::to_value(publication.receipt.as_ref().ok_or_else(refused)?)
                .map_err(crucible_node_contract::ContractError::from)?;
            reply
                .body
                .get_mut("extensions")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(refused)?
                .insert(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT.into(), receipt);
            reply
                .evidence
                .try_reserve_exact(1)
                .map_err(|_| exhausted())?;
            reply
                .evidence
                .push((reference.clone(), publication.raw.clone()));
        }
        // Reconcile the actual independently retained typed/raw/cache owners
        // before the prefix builder allocates any original transport frames.
        let mut observed = crate::retained_metadata::MetadataObserver::new();
        publication.observe_retained_metadata(&mut observed)?;
        let actual_backing =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observed.finish())?;
        if u64::try_from(actual_backing).map_err(|_| exhausted())?
            > plan.row.retained_growth_bytes.get()
        {
            return Err(exhausted());
        }
        attempt.startup.authenticate_current(connection)?;
        drop(view);
        prefix::prepare_with_projection_storage_data(
            transport,
            next_sequence,
            transport_credit,
            authority,
            &frame.envelope,
            publication.reply.as_ref().ok_or_else(refused)?,
            &plan.prefix,
        )?;
        drop(attempt_guard);
        // The step reserved this exact outer slot before the query. Check it
        // again before I/O so completing the retained record cannot grow Vec.
        if self.records.len() >= EXCHANGES || self.records.len() >= self.records.capacity() {
            return Err(exhausted());
        }
        let Some(Transport::Prepared(exchange, acknowledgements)) = transport.as_mut() else {
            return Err(refused());
        };
        exchange.publish(&mut |request, reply| acknowledgements.validate(request, reply))?;
        let Some(Transport::Prepared(exchange, _)) = transport.take() else {
            return Err(refused());
        };
        let (connection, record) = exchange.into_parts();
        let completed_record = self.records.len();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        self.finish_original_fresh_report_publication(service, completed_record)
    }

    fn finish_original_fresh_report_publication(
        &mut self,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
        record_index: usize,
    ) -> Result<(), ProviderError> {
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let mut attempt = self
            .fresh_restore_attempt
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| refused())?;
        attempt.authenticate_current(connection)?;
        attempt
            .startup
            .authenticate_complete_native_baseline(connection)?;
        let frame = attempt.input.frame.as_ref().ok_or_else(refused)?;
        let record = self.records.get(record_index).ok_or_else(refused)?;
        let terminal = record.original_sent_frame(connection, 0)?;
        frame.envelope.matches_response(terminal.original())?;
        let response = PacketNativeFreshRestoreOriginalRole::QueryResponse
            .verified_canonical_body_digest(terminal.canonical_body());
        // The selected service and original closed gate remain current after
        // every proof ACK. No numeric census or complete flag replaces them.
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let context = service.with_original_endpoint_roots(boot, &self.policy);
        {
            let _current =
                context.borrow_current_original_protocol_data(connection, &self.uploads)?;
        }
        if !self.native.original_fresh_report_window_data()? {
            return Err(refused());
        }
        // Recheck after releasing the service loan; no callback, allocation or
        // transport operation separates this fence from the completion stamp.
        context.authenticate_original(connection, &self.uploads)?;
        attempt.authenticate_current(connection)?;
        attempt.publication.completed_response = Some(response);
        attempt.publication.completed_record = Some(record_index);
        self.held = false;
        Ok(())
    }
}

fn quantity(bytes: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(bytes).map_err(|_| exhausted())?))
}
fn refused() -> ProviderError {
    ProviderError::Correlation("native fresh report publication differs")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native fresh report publication storage")
}

mod settled17;
pub(crate) use settled17::HistoricalFreshReportPublication17;
