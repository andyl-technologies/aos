//! Binds Prepare to the same actual completed query without issuing Source rights.
//!
//! Its quote includes only additional binding/query-digest work. Existing full
//! Prepare assignment and whole restoration ownership remain separately funded.

use super::*;
use crate::{
    protocol_snapshot::{OriginalProtocolStorageFacts, ProtocolCaptureOwner},
    reference_packet::service::fresh_restore_allocation::*,
    retained_metadata::{
        MetadataObserver, RetainedProtocolMetadataFacts, requested_metadata_backing_storage_data,
        serialization_storage::{
            OriginalSerializationStorageData as Data,
            OriginalSerializationStorageProjection as Projection,
            actual_serialization_storage_data, original_serialization_counter_scratch_data,
        },
    },
};
use std::{
    mem::size_of,
    rc::{Rc, Weak},
};

/// Owns the planned request inputs for one fresh-query Prepare assignment.
///
/// These fields are inert data. The controller independently authenticates the
/// original emitter, completed query, binding quote and archived mapping before
/// retaining an assigned original. This record supplies no Source permission.
pub struct OriginalFreshRestorePrepareInputs {
    /// Names the same unused request identity selected by the Source.
    pub request_id: Id,
    /// Retains the baseline Begin body for this same Prepare operation.
    pub baseline: BeginRequest,
    /// Retains the complete selected restoration request and mapping reference.
    pub request: PacketCompleteRestorePrepareRequest,
}

/// Quotes added binding work on one actual completed query frontier.
///
/// The nonconstructible association has no decoder or clone. Existing query,
/// controller, mapping and complete Prepare allocation are separate obligations;
/// this data neither authenticates the Source MAC nor grants allocation rights.
pub struct OriginalFreshRestorePrepareBindingStorageData {
    controller: Weak<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    query_sequence: U64,
    query_id: blake3::Hash,
    allocation: blake3::Hash,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalFreshRestorePrepareBindingStorageData {
    /// Returns added retained binding field and owned metadata bytes.
    pub fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns added typed binding and complete query-digest transient phases.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns fixed quote/counter headers admitted before observation.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Reports the actual shared association backing, excluding this inline quote.
    ///
    /// No external alias discount is inferred from the controller's other views.
    ///
    /// # Errors
    /// Refuses an expired association, foreign original process/thread or overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        owner.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(owner.as_ref())?;
        Ok(observer.finish())
    }

    fn authenticate(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
    ) -> Result<(), ProviderError> {
        query.authenticate_current(controller, emitter)?;
        let owner = self.controller.upgrade().ok_or_else(refused)?;
        let original = query.original_data().ok_or_else(refused)?;
        if !Rc::ptr_eq(&owner, &controller.protocol_owner)
            || self.frontier != controller.original_native5_storage_facts()?
            || self.query_sequence != original.sequence
            || self.query_id != query_identity(original)?
            || self.allocation
                != reference_identity(query.allocation_reference_data().ok_or_else(refused)?)
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl CnpController {
    /// Returns fixed quote/observer/formatter headers before the added data walk.
    ///
    /// Compiler/recursive frames and allocator overhead remain separate. This
    /// getter creates no query, callback, Source grant or native permission.
    pub fn original_fresh_restore_prepare_binding_counter_scratch_data() -> usize {
        size_of::<OriginalFreshRestorePrepareBindingStorageData>()
            // Charge both actual owning wrappers, including their compiled
            // enum representation and padding, before selected assignment.
            // Repeated payload/header views are conservatively conjoined.
            + size_of::<super::TransferExtensions>()
            + size_of::<super::TransferPreparation>()
            + 2 * size_of::<MetadataObserver<'static>>()
            + 2 * size_of::<RetainedProtocolMetadataFacts>()
            + 3 * size_of::<Data>() + size_of::<Projection>()
            + original_serialization_counter_scratch_data()
            + complete_restore_fresh_prepare_digest_counter_scratch_data()
            + size_of::<PacketNativeFreshRestoreAllocationPrepareBinding>()
            + size_of::<PacketNativeFreshRestoreOriginalRole>()
            // Actual bounded-canonical Writer fields and serialized-credit
            // Counter fields; neither owns another hidden allocation.
            + size_of::<(Vec<u8>, usize)>()
            + size_of::<(usize, usize)>()
            + size_of::<blake3::Hasher>() + 2 * size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>() + size_of::<[u8; 8]>()
            + size_of::<[usize; 4]>() + size_of::<std::array::IntoIter<usize, 4>>()
            + 6 * size_of::<usize>() + size_of::<Rc<ProtocolCaptureOwner>>()
            + size_of::<std::array::IntoIter<&Envelope, 2>>()
            + size_of::<std::array::IntoIter<&str, 2>>()
            + size_of::<std::array::IntoIter<&String, 4>>()
            + size_of::<(&CnpController, &OriginalFreshRestoreQuery, &ContentRef)>()
            // Full request backing remains in the separate Prepare row.
            // Add both new ownership headers beside the earlier controls.
            + 2 * size_of::<OriginalFreshRestorePrepareInputs>()
            + size_of::<usize>()
    }

    /// Quotes additional binding work on this actual completed query.
    ///
    /// The caller preadmits the static scratch, independently funds the existing
    /// complete Prepare construction, and verifies the Source's private report
    /// MAC. This method creates no binding DTO, digest bank or Source action.
    /// Existing Envelope Values contain encoded Bytes strings; visiting those
    /// values allocates no Bytes formatter. Future fixed digests are projected.
    ///
    /// # Errors
    /// Refuses a partial/stale/foreign query, missing report reference, absent
    /// actual selection, overflow or complete added demand above `maximum`.
    pub fn quote_original_fresh_restore_prepare_binding_storage_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        maximum: usize,
    ) -> Result<OriginalFreshRestorePrepareBindingStorageData, ProviderError> {
        query.authenticate_current(self, emitter)?;
        if self.original_native5_fresh_restore_allocation_selection()?
            != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
        {
            return Err(refused());
        }
        let original = query.original_data().ok_or_else(refused)?;
        let terminal = query.terminal_data().ok_or_else(refused)?;
        let reference = query.allocation_reference_data().ok_or_else(refused)?;
        let maximum_frame = self.maximum_frame()?;
        let binding = binding_projection(reference, maximum)?;
        let mut retained = add(
            binding.dom_and_canonical_scratch_bytes,
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.len(),
        )?;
        // Conservatively count the real Weak association's shared allocation
        // view; no new controller allocation or alias refund is inferred.
        let mut association = MetadataObserver::new();
        association.shared_value(self.protocol_owner.as_ref())?;
        retained = add(
            retained,
            requested_metadata_backing_storage_data(&association.finish())?,
        )?;
        let mut transient = binding.requested_total()?;
        for bytes in [
            size_of::<PacketNativeFreshRestoreAllocationPrepareBinding>(),
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.len(),
            2 * 32,
            2 * 44,
        ] {
            transient = add(transient, bytes)?;
        }
        let mut observer = MetadataObserver::new();
        observer.observe(reference)?;
        transient = add(
            transient,
            requested_metadata_backing_storage_data(&observer.finish())?,
        )?;
        for envelope in [original, terminal] {
            let mut observer = MetadataObserver::new();
            observer.observe(envelope)?;
            let data = actual_serialization_storage_data(envelope, observer.finish(), maximum)?;
            transient = add(transient, data.requested_total()?)?;
            // Existing digest writer reserves its actual whole frame bank.
            transient = add(transient, maximum_frame)?;
            transient = add(transient, size_of::<Value>())?;
        }
        let scratch = Self::original_fresh_restore_prepare_binding_counter_scratch_data();
        if add(add(retained, transient)?, scratch)? > maximum {
            return Err(credit());
        }
        let result = OriginalFreshRestorePrepareBindingStorageData {
            controller: Rc::downgrade(&self.protocol_owner),
            frontier: self.original_native5_storage_facts()?,
            query_sequence: original.sequence,
            query_id: query_identity(original)?,
            allocation: reference_identity(reference),
            retained,
            transient,
            scratch,
        };
        query.authenticate_current(self, emitter)?;
        Ok(result)
    }

    /// Assigns Prepare with the binding derived from this same opaque query.
    ///
    /// The Source separately authenticates its report MAC and whole construction
    /// action. This method authenticates the exact SDK frontier/emitter/mapping
    /// and supplies neither a key nor a controller extractor.
    ///
    /// # Errors
    /// Refuses foreign/stale quote/query/emitter/mapping, missing selection,
    /// reused phase/ID, invalid typed inputs or insufficient original credit.
    pub fn prepare_original_complete_restore_prepare_with_fresh_query<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        quote: &OriginalFreshRestorePrepareBindingStorageData,
        inputs: OriginalFreshRestorePrepareInputs,
        mapping: &PreparedArchivedProtocolMapping,
    ) -> Result<PreparedOriginalCompleteRestoreTransfer<'a>, ProviderError> {
        let OriginalFreshRestorePrepareInputs {
            request_id,
            baseline,
            request,
        } = inputs;

        quote.authenticate(self, emitter, query)?;
        request.validate_data()?;
        if &request.host_protocol != mapping.archive_protocol()
            || &request.native_protocol != mapping.native_protocol()
            || request.restoration.nonce.as_slice() != mapping.nonce()
        {
            return Err(refused());
        }
        authenticate_mapping_reference(&request.restoration.mapping, mapping)?;
        let maximum = self.maximum_frame()?;
        let binding = PacketNativeFreshRestoreAllocationPrepareBinding {
            schema: PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.to_owned(),
            assigned_query: Bytes::new(
                fresh_restore_allocation_envelope_digest_data(
                    query.original_data().ok_or_else(refused)?,
                    PacketNativeFreshRestoreOriginalRole::Query,
                    maximum,
                )?
                .to_vec(),
            ),
            completed_query_response: Bytes::new(
                fresh_restore_allocation_envelope_digest_data(
                    query.terminal_data().ok_or_else(refused)?,
                    PacketNativeFreshRestoreOriginalRole::QueryResponse,
                    maximum,
                )?
                .to_vec(),
            ),
            allocation: query
                .allocation_reference_data()
                .ok_or_else(refused)?
                .clone(),
        };
        binding.validate_data()?;
        let value =
            serde_json::to_value(&request).map_err(crucible_node_format::ContractError::from)?;
        quote.authenticate(self, emitter, query)?;
        self.prepare_transfer(
            emitter,
            mapping,
            TransferPreparation {
                request_id,
                baseline,
                value,
                phase: PacketCompleteRestoreTransferPhase::Prepare,
                reference: request.restoration.mapping,
                extensions: TransferExtensions::FreshPrepare(binding),
            },
        )
    }
}

pub(super) fn authenticate_unsigned_fresh_prepare(
    original: &Envelope,
) -> Result<(), ProviderError> {
    crate::reference_packet::service::complete_restore::transfer::authenticate_fresh_prepare_shape(
        original, false,
    )
}

fn binding_projection(reference: &ContentRef, maximum: usize) -> Result<Data, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)?;
    p.add_object()?;
    p.add_field("schema")?;
    p.add_string(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)?;
    for key in ["assigned_query", "completed_query_response"] {
        p.add_field(key)?;
        p.add_unescaped_ascii_extent(44)?;
    }
    p.add_field("allocation")?;
    p.add_value(reference)?;
    p.finish(maximum)
}

fn query_identity(original: &Envelope) -> Result<blake3::Hash, ProviderError> {
    Ok(blake3::hash(
        original
            .request_id
            .0
            .as_ref()
            .ok_or_else(refused)?
            .as_str()
            .as_bytes(),
    ))
}

fn reference_identity(reference: &ContentRef) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    for value in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        h.update(&(value.len() as u64).to_le_bytes());
        h.update(value.as_bytes());
    }
    h.update(&reference.length.get().to_le_bytes());
    h.finalize()
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(credit)
}

#[cfg(test)]
mod tests;
