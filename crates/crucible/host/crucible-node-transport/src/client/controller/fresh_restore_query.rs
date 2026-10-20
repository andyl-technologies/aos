//! Retains the source's one-shot query before dispatch and all post-call fences.
//!
//! This owner supplies data correspondence only. The actual Source must consume
//! its separately issued host query ticket before this call, authenticate the
//! keyed report and real native/kernel/source custody afterward, and perform a
//! distinct whole restoration admission before assigning Prepare.

use super::*;
use crate::{
    protocol_snapshot::{OriginalProtocolStorageFacts, ProtocolCaptureOwner},
    reference_packet::service::fresh_restore_allocation::*,
    retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts},
};
use std::rc::Rc;
mod storage;

/// Counts future host query owners on one actual completed-Admit controller.
///
/// This is nonportable requested-storage data. It grants no allocation or query
/// right; the installed Source/Core policy must separately admit the row.
pub struct OriginalFreshRestoreQueryStorageData {
    controller: Rc<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    planned_id: blake3::Hash,
    admit_sequence: U64,
    retained_growth_bytes: usize,
    maximum_simultaneous_transient_bytes: usize,
    declared_counter_scratch_bytes: usize,
    query_typed_bytes: usize,
}

impl OriginalFreshRestoreQueryStorageData {
    /// Returns new retained owner/cache/content requested backing.
    pub fn retained_growth_bytes(&self) -> usize {
        self.retained_growth_bytes
    }
    /// Returns a conservative complete transient bound, summing proof phases.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.maximum_simultaneous_transient_bytes
    }
    /// Returns declared observer/counter headers, excluding compiler stack.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.declared_counter_scratch_bytes
    }

    /// Reports retained quote-association child fields as data.
    ///
    /// The caller separately counts this quote's inline header. No serialized
    /// or current permission follows from the original actor handle.
    ///
    /// # Errors
    /// Refuses a foreign original process/thread or checked traversal overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(self.controller.as_ref())?;
        Ok(observer.finish())
    }

    fn authenticate(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        planned_id: &Id,
    ) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        emitter.authenticate_original(controller)?;
        let completed = controller.original_completed_canonical_ack_admit(emitter)?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner)
            || self.frontier != controller.original_native5_storage_facts()?
            || self.planned_id != blake3::hash(planned_id.as_str().as_bytes())
            || self.admit_sequence != completed.original().sequence
            || controller.original(planned_id).is_some()
        {
            return Err(refused());
        }
        controller.session.fresh_restore_query_selection()?;
        Ok(())
    }
}

/// Owns the original query, partial terminal and independently decoded report.
///
/// The controller retains literal bytes and content banks throughout failures.
/// No decoder, clone, caller constructor or portable serialization exists. An
/// incomplete owner remains in the caller's slot after any error or unwind.
pub struct OriginalFreshRestoreQuery {
    controller: Rc<ProtocolCaptureOwner>,
    query: PacketNativeFreshRestoreAllocationQuery,
    original: Option<Envelope>,
    terminal: Option<Envelope>,
    response: Option<ResponseBody>,
    receipt: Option<PacketNativeFreshRestoreAllocationReceipt>,
    report: Option<PacketNativeFreshRestoreAllocationReport>,
    completed_frontier: Option<OriginalProtocolStorageFacts>,
}

impl OriginalFreshRestoreQuery {
    /// Borrows the actual initialized query, including after failed dispatch.
    pub fn query_data(&self) -> &PacketNativeFreshRestoreAllocationQuery {
        &self.query
    }
    /// Borrows its assigned full original when assignment reached custody.
    pub fn original_data(&self) -> Option<&Envelope> {
        self.original.as_ref()
    }
    /// Borrows its full session reply retained before Source post-call checks.
    pub fn terminal_data(&self) -> Option<&Envelope> {
        self.terminal.as_ref()
    }
    /// Borrows its independently decoded selected Observe response.
    pub fn response_data(&self) -> Option<&ResponseBody> {
        self.response.as_ref()
    }
    /// Borrows the decoded report only when that stage completed.
    pub fn report_data(&self) -> Option<&PacketNativeFreshRestoreAllocationReport> {
        self.report.as_ref()
    }
    /// Borrows the exact received full report reference when present.
    pub fn allocation_reference_data(&self) -> Option<&ContentRef> {
        self.receipt.as_ref().map(|r| &r.allocation)
    }

    /// Rechecks the exact completed pair, original actor and no-intervening frontier.
    ///
    /// # Errors
    /// Refuses partial owners, another controller/emitter, changed cache/literals,
    /// revoked registration, unavailable content or subsequent protocol traffic.
    pub fn authenticate_current(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        emitter.authenticate_original(controller)?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner)
            || self.completed_frontier != Some(controller.original_native5_storage_facts()?)
        {
            return Err(refused());
        }
        let original = self.original.as_ref().ok_or_else(refused)?;
        let terminal = self.terminal.as_ref().ok_or_else(refused)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let cached = controller.original(id).ok_or_else(refused)?;
        if &cached.request != original
            || cached.response.as_ref() != Some(terminal)
            || self.report.is_none()
        {
            return Err(refused());
        }
        controller.content(self.allocation_reference_data().ok_or_else(refused)?)?;
        controller.session.fresh_restore_query_selection()?;
        Ok(())
    }

    /// Compares Source expectations to this completed query's actual originals.
    ///
    /// The expected complete owner must equal the immutable installed SDK owner.
    /// Its report binding is then compared to the SDK's actual query body hash;
    /// the ACK context is compared to the SAME completed Admit's original proof.
    /// This uses borrowed fields and one fixed32-byte decode bank, without
    /// hashing, DOM, formatting, serialization, allocation or I/O. Source still
    /// authenticates its installation, kernel, report MAC and whole admission.
    ///
    /// # Errors
    /// Refuses partial/stale/foreign query ownership, a different expected owner,
    /// mismatched full owner hash or original ACK context, malformed proof data,
    /// revoked registration or any intervening protocol traffic.
    pub fn authenticate_original_source_context_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        expected_owner: &crucible_node_format::OwnerBinding,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(controller, emitter)?;
        let selection = controller.session.fresh_restore_query_selection()?;
        let [actual_owner] = selection.realization.owner_bindings.as_slice() else {
            return Err(refused());
        };
        if actual_owner != expected_owner {
            return Err(refused());
        }
        let report = self.report.as_ref().ok_or_else(refused)?;
        let original = self.original.as_ref().ok_or_else(refused)?;
        let admitted = controller.original_completed_canonical_ack_admit(emitter)?;
        authenticate_source_hashes(
            &report.data.scope.owner_binding,
            &report.data.scope.ack_context,
            original,
            admitted.original(),
        )?;
        self.authenticate_current(controller, emitter)
    }

    /// Borrows the actual controller-owned, hash-verified report byte bank.
    ///
    /// # Errors
    /// Refuses an incomplete or stale query association or absent original bytes.
    pub fn report_bytes_data<'a>(
        &self,
        controller: &'a CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<&'a [u8], ProviderError> {
        self.authenticate_current(controller, emitter)?;
        controller.content(self.allocation_reference_data().ok_or_else(refused)?)
    }

    /// Reports all initialized owning fields even after partial failure.
    ///
    /// The raw content bank belongs to the controller and is counted there.
    /// Source must count this separate typed report/response/original backing.
    /// Outer inline owner storage is excluded from these child facts.
    ///
    /// # Errors
    /// Refuses foreign original process/thread or checked traversal exhaustion.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.controller.ensure_current()?;
        let Self {
            controller,
            query,
            original,
            terminal,
            response,
            receipt,
            report,
            completed_frontier: _,
        } = self;
        let mut observer = MetadataObserver::new();
        observer.shared_value(controller.as_ref())?;
        observer.observe(query)?;
        observer.observe(original)?;
        observer.observe(terminal)?;
        if let Some(response) = response {
            storage::observe_response(response, &mut observer)?;
        }
        observer.observe(receipt)?;
        observer.observe(report)?;
        Ok(observer.finish())
    }
}

impl CnpController {
    /// Returns fixed observation/counter headers before the query quote runs.
    ///
    /// This excludes recursive serde/compiler frames and allocator overhead.
    pub const fn original_fresh_restore_query_counter_scratch_data() -> usize {
        storage::counter_scratch_data()
    }

    /// Quotes the selected host call before a query/nonce/report is constructed.
    ///
    /// The planned ID is already owned by the same installed Source holder. No
    /// query, canonical original digest, report or body is allocated by this
    /// constructor. It reads actual private layouts/current owner facts and
    /// closed future field counts. It issues no Core or native permission.
    ///
    /// # Errors
    /// Refuses absent completed Admit/fresh selection, old/pending originals,
    /// nonoriginal actors, exhausted baseline banks or checked layout overflow.
    pub fn quote_original_fresh_restore_query_storage_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        planned_id: &Id,
    ) -> Result<OriginalFreshRestoreQueryStorageData, ProviderError> {
        emitter.authenticate_original(self)?;
        self.ensure_no_pending_original_complete_restore()?;
        self.session.preflight_original_fresh_query_data()?;
        let completed = self.original_completed_canonical_ack_admit(emitter)?;
        let frontier = self.original_native5_storage_facts()?;
        if !frontier.all_io_complete
            || self.original(planned_id).is_some()
            || self.custody.has_original_fresh_query_data()
        {
            return Err(refused());
        }
        let selection = self.session.fresh_restore_query_selection()?;
        let parts = storage::quote(self, selection, completed.original(), completed.response())?;
        Ok(OriginalFreshRestoreQueryStorageData {
            controller: self.protocol_owner.clone(),
            frontier,
            planned_id: blake3::hash(planned_id.as_str().as_bytes()),
            admit_sequence: completed.original().sequence,
            retained_growth_bytes: parts.retained,
            maximum_simultaneous_transient_bytes: parts.transient,
            declared_counter_scratch_bytes: Self::original_fresh_restore_query_counter_scratch_data(
            ),
            query_typed_bytes: parts.query_typed,
        })
    }

    /// Dispatches one admitted query and retains every result before postchecks.
    ///
    /// The installed caller must hold its genuine one-shot host query ticket.
    /// This method authenticates data/transport ownership only; Source separately
    /// verifies the keyed report and native physical gate. The output slot is
    /// populated before query validation, body/digest construction or I/O.
    ///
    /// # Errors
    /// Refuses a changed quote/planned ID/controller, occupied slot, malformed
    /// query, mismatched completed Admit, exhausted original custody, uncertain
    /// transport or invalid report. Partial results remain in `result`.
    pub fn call_original_fresh_restore_allocation_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        quote: &OriginalFreshRestoreQueryStorageData,
        planned_id: &Id,
        query: PacketNativeFreshRestoreAllocationQuery,
        result: &mut Option<OriginalFreshRestoreQuery>,
    ) -> Result<(), ProviderError> {
        quote.authenticate(self, emitter, planned_id)?;
        if result.is_some() {
            return Err(refused());
        }
        *result = Some(OriginalFreshRestoreQuery {
            controller: self.protocol_owner.clone(),
            query,
            original: None,
            terminal: None,
            response: None,
            receipt: None,
            report: None,
            completed_frontier: None,
        });
        let owner = result.as_mut().ok_or_else(refused)?;
        owner.query.validate_data()?;
        storage::authenticate_query_capacity(&owner.query, quote.query_typed_bytes)?;
        let actual = self.quote_original_fresh_restore_query_storage_data(emitter, planned_id)?;
        if actual.retained_growth_bytes > quote.retained_growth_bytes
            || actual.maximum_simultaneous_transient_bytes
                > quote.maximum_simultaneous_transient_bytes
            || actual.declared_counter_scratch_bytes > quote.declared_counter_scratch_bytes
        {
            return Err(refused());
        }
        let admit = self.original_completed_canonical_ack_admit(emitter)?;
        let request_digest = fresh_restore_allocation_envelope_digest_data(
            admit.original(),
            PacketNativeFreshRestoreOriginalRole::AdmitRequest,
            self.maximum_frame()?,
        )?;
        let response_digest = fresh_restore_allocation_envelope_digest_data(
            admit.response(),
            PacketNativeFreshRestoreOriginalRole::AdmitResponse,
            self.maximum_frame()?,
        )?;
        if owner.query.completed_admit_request.as_slice() != request_digest
            || owner.query.completed_admit_response.as_slice() != response_digest
        {
            return Err(refused());
        }
        let selection = self.session.fresh_restore_query_selection()?;
        let [binding] = selection.realization.owner_bindings.as_slice() else {
            return Err(refused());
        };
        let body = ObserveRequest {
            binding_hash: binding.identity()?,
            owner_generation: selection.realization.bindings[0].authority.owner_generation,
            after_observation_sequence: U64::new(0),
            maximum_items: U64::new(1),
            extensions: Extensions::new(),
        };
        let body = super::super::session::object(body)?;
        let mut extensions = Extensions::new();
        extensions.insert(
            PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
            serde_json::to_value(&owner.query)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        owner.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(planned_id.clone())),
            operation_id: Nullable(None),
            sequence: self.session.fresh_restore_query_sequence()?,
            method: Method::Observe,
            body,
            extensions,
        });
        let original = owner.original.as_ref().ok_or_else(refused)?;
        owner.terminal = Some(self.session.exchange_original_fresh_restore_query(
            &mut self.custody,
            original,
            self.budget,
        )?);
        let terminal = owner.terminal.as_ref().ok_or_else(refused)?;
        let request = decode_request(Method::Observe, &original.body)?;
        owner.response = Some(decode_response(&request, &terminal.body)?);
        let response = owner.response.as_ref().ok_or_else(refused)?;
        let ResponseShape::Completed { extensions, .. } = &response.shape else {
            return Err(refused());
        };
        let value = extensions
            .get(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT)
            .ok_or_else(refused)?;
        owner.receipt = Some(
            serde_json::from_value(value.clone())
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let receipt = owner.receipt.as_ref().ok_or_else(refused)?;
        receipt.validate_data()?;
        self.session.receive_original_fresh_restore_report(
            &mut self.custody,
            original,
            &receipt.allocation,
            self.budget,
        )?;
        let raw = self.content(&receipt.allocation)?;
        owner.report =
            Some(serde_json::from_slice(raw).map_err(crucible_node_format::ContractError::from)?);
        let report = owner.report.as_ref().ok_or_else(refused)?;
        report.validate_data()?;
        let scope = &report.data.scope;
        let assigned = fresh_restore_allocation_envelope_digest_data(
            original,
            PacketNativeFreshRestoreOriginalRole::Query,
            self.maximum_frame()?,
        )?;
        if scope.assigned_query.as_slice() != assigned
            || scope.nonce != owner.query.nonce
            || scope.completed_admit_request != owner.query.completed_admit_request
            || scope.completed_admit_response != owner.query.completed_admit_response
            || Some(&scope.session) != original.session_id.0.as_ref()
            || Some(&scope.incarnation) != original.incarnation_id.0.as_ref()
            || Some(&scope.node) != original.node_id.0.as_ref()
            || Some(&scope.owner) != original.execution_owner_id.0.as_ref()
        {
            return Err(refused());
        }
        // Canonical correspondence is checked under the preadmitted report
        // authentication phase; raw bytes stay in original ClientContent.
        let value =
            serde_json::to_value(report).map_err(crucible_node_format::ContractError::from)?;
        if crucible_node_format::canonical::canonical_json(&value)?.as_slice() != raw {
            return Err(refused());
        }
        owner.completed_frontier = Some(self.original_native5_storage_facts()?);
        owner.authenticate_current(self, emitter)
    }

    /// Reads the actual explicitly installed fresh query selection.
    ///
    /// # Errors
    /// Refuses another actor, replaced codec or revoked original negotiation.
    pub fn original_native5_fresh_restore_allocation_selection(
        &self,
    ) -> Result<Option<PacketNative5FreshRestoreAllocationSelection>, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.session
            .original_native5_codec_owner()
            .ok_or_else(refused)?
            .fresh_restore_selection_data(self.authority())
    }

    /// Installs the complete fresh13 host grammar once on the unused source actor.
    ///
    /// # Errors
    /// Refuses used custody/banks, a different route, missing full definitions,
    /// unselected feature/keys or exceeded finite metadata extent.
    pub fn install_native5_source_fresh_restore_allocation_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: crate::connection::CanonicalAckCodecMetadataExtent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced
            || self.originals().next().is_some()
            || selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || self.route.node != selection.realization.bindings[0].compatibility.node_id
            || self.route.execution_owner != selection.realization.owner_bindings[0].owner.id
        {
            return Err(refused());
        }
        self.session
            .install_native5_source_fresh_restore_allocation_codec_with_metadata_extent(
                bank,
                selection,
                coordinator,
                profile,
                metadata_extent,
            )
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original fresh restore query ownership or result differs")
}

#[cfg(test)]
mod tests {
    //! Checks actual partial custody data; no native query positive is claimed.
    // crucible-lint: panic-shortcut: fixture assertions stop on mismatched custody.
    use super::*;
    use std::mem::size_of;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn partial(capacity: usize) -> OriginalFreshRestoreQuery {
        let mut nonce = Vec::with_capacity(capacity);
        nonce.extend_from_slice(&[7; 32]);
        OriginalFreshRestoreQuery {
            controller: Rc::new(ProtocolCaptureOwner::new()),
            query: PacketNativeFreshRestoreAllocationQuery {
                schema: PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
                nonce: Bytes::new(nonce),
                completed_admit_request: Bytes::new(vec![3; 32]),
                completed_admit_response: Bytes::new(vec![5; 32]),
            },
            original: None,
            terminal: None,
            response: None,
            receipt: None,
            report: None,
            completed_frontier: None,
        }
    }

    #[test]
    fn partial_query_owner_counts_spare_digest_capacity_before_any_terminal() -> TestResult {
        let compact = partial(32);
        let spare = partial(4096);
        compact.query_data().validate_data()?;
        spare.query_data().validate_data()?;
        assert_eq!(compact.query_data(), spare.query_data());

        let left = compact.original_retained_metadata_facts()?;
        let right = spare.original_retained_metadata_facts()?;
        assert_eq!(left.vector_banks, right.vector_banks);
        let delta = spare
            .query_data()
            .nonce
            .allocation_capacity()
            .checked_sub(compact.query_data().nonce.allocation_capacity())
            .ok_or_else(refused)?;
        assert!(delta > 0);
        assert_eq!(
            right.vector_capacity_bytes,
            left.vector_capacity_bytes + delta
        );
        assert!(spare.original_data().is_none());
        assert!(spare.terminal_data().is_none());
        assert!(spare.report_data().is_none());
        let mut observer = MetadataObserver::new();
        observer.observe(compact.query_data())?;
        let minimum = size_of::<PacketNativeFreshRestoreAllocationQuery>()
            .checked_add(
                crate::retained_metadata::requested_metadata_backing_storage_data(
                    &observer.finish(),
                )?,
            )
            .ok_or_else(refused)?;
        storage::authenticate_query_capacity(compact.query_data(), minimum)?;
        assert!(storage::authenticate_query_capacity(spare.query_data(), minimum).is_err());
        Ok(())
    }
}

fn authenticate_source_hashes(
    report_owner: &crucible_node_format::HashRef,
    report_ack_context: &Bytes,
    query: &Envelope,
    admitted: &Envelope,
) -> Result<(), ProviderError> {
    use base64::Engine;
    let binding = query
        .body
        .get("binding_hash")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    if binding.len() != 3
        || binding.get("algorithm").and_then(Value::as_str) != Some(report_owner.algorithm.as_str())
        || binding.get("domain").and_then(Value::as_str) != Some(report_owner.domain.as_str())
        || binding.get("digest").and_then(Value::as_str) != Some(report_owner.digest.as_str())
    {
        return Err(refused());
    }
    let proof = admitted
        .extensions
        .get(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
        .ok_or_else(refused)?;
    crate::reference_packet::service::ack_emitter::validate_proof_value(proof)?;
    let encoded = proof
        .get("context_digest")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let mut context = [0u8; 32];
    let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut context)
        .map_err(|_| refused())?;
    if written != context.len() || report_ack_context.as_slice() != context {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod source_context_data_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn originals() -> Result<
        (crucible_node_format::HashRef, Bytes, Envelope, Envelope),
        Box<dyn std::error::Error>,
    > {
        let hash = canonical::hash("cnp.owner-binding.v1", b"actual query owner binding DATA")?;
        let context = Bytes::new(vec![9; 32]);
        let mut query = Envelope {
            protocol: "CNP/1".to_owned(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("query-data")?)),
            operation_id: Nullable(None),
            sequence: U64::new(7),
            method: Method::Observe,
            body: serde_json::Map::new(),
            extensions: Extensions::new(),
        };
        query
            .body
            .insert("binding_hash".to_owned(), serde_json::to_value(&hash)?);
        let mut admitted = query.clone();
        admitted.method = Method::Admit;
        admitted.sequence = U64::new(4);
        let proof = crate::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionProof {
            schema: crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.to_owned(),
            algorithm: crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.to_owned(),
            context_digest: context.clone(), mac: Bytes::new(vec![5;32]),
        };
        admitted
            .extensions
            .insert(proof.schema.clone(), serde_json::to_value(proof)?);
        Ok((hash, context, query, admitted))
    }

    #[test]
    fn borrowed_full_hash_and_original_ack_context_match_without_reserializing() -> TestResult {
        let (hash, context, query, admitted) = originals()?;
        authenticate_source_hashes(&hash, &context, &query, &admitted)?;
        let changed = canonical::hash("cnp.owner-binding.v1", b"another owner DATA")?;
        assert!(authenticate_source_hashes(&changed, &context, &query, &admitted).is_err());
        assert!(
            authenticate_source_hashes(&hash, &Bytes::new(vec![8; 32]), &query, &admitted).is_err()
        );
        Ok(())
    }

    #[test]
    fn extra_hash_field_and_noncanonical_original_proof_refuse() -> TestResult {
        let (hash, context, mut query, mut admitted) = originals()?;
        query
            .body
            .get_mut("binding_hash")
            .and_then(Value::as_object_mut)
            .ok_or("hash object")?
            .insert("extra".to_owned(), Value::Null);
        assert!(authenticate_source_hashes(&hash, &context, &query, &admitted).is_err());
        let (_, _, query, _) = originals()?;
        admitted.extensions.get_mut(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
            .and_then(Value::as_object_mut).ok_or("proof object")?
            .insert("context_digest".to_owned(), Value::String("A".repeat(42)+"B"));
        assert!(authenticate_source_hashes(&hash, &context, &query, &admitted).is_err());
        Ok(())
    }
}
