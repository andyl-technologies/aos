//! Lends exact signed imported rows and their actual retained body geometry.
//!
//! The existing original ticket remains the live owner; no schema construction,
//! Blob fetch, allocator credit, future Source or readiness grant is issued.

use super::*;

impl PacketCompleteSemanticSource {
    /// Borrows only this Source's completed born or exact signed imported row.
    ///
    /// # Errors
    /// Refuses foreign/busy custody, incomplete or failed materialization,
    /// ambiguous rows, a failing sink or changed original custody after it.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn with_original_capture17_dependency_row_data<
        R,
    >(
        &self,
        reference: &ContentRef,
        inspect: impl FnOnce(Option<&[ContentRef]>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let capture = original
            .restored_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let copies = capture
            .materialization
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !copies.transferred || copies.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let ticket = original.original_capture_parent_ticket17_data()?;
        let archive = ticket.original_capture_parent_archive17_data()?;
        let row = match copies.born.find_data(reference)? {
            Some(row) => Some(row),
            None => archive
                .complete_original_index_row17_data(reference)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        };
        let result = inspect(row);
        ticket.owner()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }
}

impl PacketCompleteSemanticSource {
    /// Borrows an exact signed imported body from the real retained original ticket.
    ///
    /// No Blob call, clone, archive construction or currentness grant occurs.
    /// The writer separately admits any returned copy before invoking its sink.
    ///
    /// # Errors
    /// Refuses foreign Source/ticket custody, incomplete Capture, an unsigned
    /// body role, a missing original body or changed actor custody after the sink.
    pub(crate) fn with_original_capture17_imported_body_data<R>(
        &self,
        reference: &ContentRef,
        inspect: impl FnOnce(&[u8]) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_original_capture17_dependency_row_data(reference, |row| {
            if row.is_none() {
                return Err(RuntimeError::InvalidReceipt);
            }
            let association = self
                .ack_peer_association
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let ticket = original.original_capture_parent_ticket17_data()?;
            let archive = ticket.original_capture_parent_archive17_data()?;
            if archive
                .complete_original_index_row17_data(reference)
                .map_err(|_| RuntimeError::InvalidReceipt)?
                .is_none()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            let content = ticket.content()?;
            let bytes = content.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
            let result = inspect(bytes);
            ticket.owner()?;
            result
        })
    }
}

impl PacketCompleteSemanticSource {
    pub(super) fn authenticate_original_capture17_parent_archive_data(
        &self,
        archive: &CompleteOriginalRestorationSource,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let ticket = original.original_capture_parent_ticket17_data()?;
        ticket.authenticate_source(archive)?;
        self.storage_origin_with_error::<RuntimeError>()
    }
}

impl PacketCompleteSemanticSource {
    /// Counts the actual completed imported closure without allocating copies.
    ///
    /// The tuple contains typed object occurrences, complete body bytes, fullref
    /// clone backing, edge occurrences, edge Vec-plus-reference backing, and
    /// largest body, maximum returned-row copy and maximum row-plus-hash window.
    /// Repeated typed bodies remain independent copy occurrences.
    /// Actual destination owner/map headers and callback captures are additional
    /// defining writer costs. The current materializer must already have moved
    /// its output. This DATA funds neither SDK effects nor native actions.
    ///
    /// # Errors
    /// Refuses another Source policy, absent/foreign original ticket, a signed
    /// row without its retained verified body, checked overflow or changed actor.
    pub fn original_capture17_completed_imported_closure_storage_data(
        &self,
    ) -> Result<(usize, usize, usize, usize, usize, usize, usize, usize), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !crate::node_adapters::cnp::CnpSemanticSource::requires_restored_capture17_scope_data(
            self,
        )? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let ticket = original.original_capture_parent_ticket17_data()?;
        let archive = ticket.original_capture_parent_archive17_data()?;
        let content = ticket.content()?;
        let capture = original
            .restored_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let copies = capture
            .materialization
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !copies.transferred || copies.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut objects = 0usize;
        let mut bodies = 0usize;
        let mut references = 0usize;
        let mut edges = 0usize;
        let mut adjacency = 0usize;
        let mut largest = 0usize;
        let mut maximum_returned = 0usize;
        let mut maximum_lookup = 0usize;
        for (reference, dependencies) in archive
            .complete_original_index_rows17_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?
        {
            let bytes = content.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
            objects = objects.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            bodies = bodies
                .checked_add(bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            references = references
                .checked_add(NodeRuntime::capture_reference_storage(reference)?)
                .ok_or(RuntimeError::ResourceLimit)?;
            edges = edges
                .checked_add(dependencies.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            adjacency = adjacency
                .checked_add(
                    dependencies
                        .len()
                        .checked_mul(size_of::<ContentRef>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
            for dependency in dependencies {
                adjacency = adjacency
                    .checked_add(NodeRuntime::capture_reference_storage(dependency)?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            largest = largest.max(bytes.len());
            let row = PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
                reference,
                dependencies,
                usize::MAX,
            )?;
            maximum_returned = maximum_returned.max(row.returned_row_bytes());
            maximum_lookup = maximum_lookup.max(
                row.requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            );
        }
        ticket.owner()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        // The actual current owner retains the original Index payload after
        // transferring a separately funded copy into Core. Include that root
        // occurrence here; all other rows come directly from its signed body.
        let born = &copies.born;
        let index_reference = born
            .index_reference
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let index_dependencies = born.rows[INDEX_ROW].dependencies.as_slice();
        let index_row = PacketCompleteCaptureDependencyLookupData::from_borrowed_capture17_data(
            index_reference,
            index_dependencies,
            usize::MAX,
        )?;
        objects = objects.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        bodies = bodies
            .checked_add(born.index_bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        references = references
            .checked_add(NodeRuntime::capture_reference_storage(index_reference)?)
            .ok_or(RuntimeError::ResourceLimit)?;
        edges = edges
            .checked_add(index_dependencies.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        adjacency = adjacency
            .checked_add(index_row.returned_row_bytes())
            .ok_or(RuntimeError::ResourceLimit)?;
        largest = largest.max(born.index_bytes.len());
        maximum_returned = maximum_returned.max(index_row.returned_row_bytes());
        maximum_lookup = maximum_lookup.max(
            index_row
                .requested_bytes()
                .map_err(|_| RuntimeError::ResourceLimit)?,
        );
        ticket.owner()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok((
            objects,
            bodies,
            references,
            edges,
            adjacency,
            largest,
            maximum_returned,
            maximum_lookup,
        ))
    }

    /// Visits actual signed imported bodies after this current Capture moved.
    ///
    /// The owning writer independently admits and retains each initialized copy
    /// before invoking this visitor. Original and current Source custody remain
    /// borrowed throughout the sink, including its refusal path. The visitor
    /// reads no unspecified JSON fields and never classifies an unknown leaf.
    ///
    /// # Errors
    /// Refuses incomplete current materialization, unavailable original custody,
    /// a signed row without its verified body, a failing sink or changed actor.
    pub fn visit_original_capture17_imported_objects_data(
        &self,
        mut inspect: impl FnMut(&ContentRef, &[u8], &[ContentRef]) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let capture = original
            .restored_capture
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let copies = capture
            .materialization
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !copies.transferred || copies.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let ticket = original.original_capture_parent_ticket17_data()?;
        let archive = ticket.original_capture_parent_archive17_data()?;
        let content = ticket.content()?;
        let result = (|| {
            let born = &copies.born;
            let index_reference = born
                .index_reference
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let index_dependencies = born.rows[INDEX_ROW].dependencies.as_slice();
            inspect(index_reference, &born.index_bytes, index_dependencies)?;
            for (reference, dependencies) in archive
                .complete_original_index_rows17_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?
            {
                let bytes = content.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
                inspect(reference, bytes, dependencies)?;
            }
            Ok(())
        })();
        ticket.owner()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }

    /// Names fixed signed-row lenders; destination owner/callback costs are separate.
    pub fn original_capture17_imported_closure_counter_scratch_data() -> usize {
        use super::super::super::super::owner::CaptureOnceOwner;
        use crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association::OriginalAckPeerAssociation;
        use crate::node_state::{CompleteOriginalNativeTicket, VerifiedStateContent};
        size_of::<(usize, usize, usize, usize, usize, usize, usize, usize)>()
            + size_of::<
                Result<(usize, usize, usize, usize, usize, usize, usize, usize), RuntimeError>,
            >()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<(&ContentRef, &[u8], &[ContentRef])>()
            + size_of::<Option<&[ContentRef]>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<&NativeArchiveRecord>()
            + size_of::<Result<&NativeArchiveRecord, RuntimeError>>()
            + size_of::<Result<&CompleteOriginalNativeTicket, RuntimeError>>()
            + size_of::<Result<&crate::node_state::NativeOwnerState, RuntimeError>>()
            + size_of::<Result<&VerifiedStateContent, RuntimeError>>()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<&VerifiedStateContent>()
            + size_of::<Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Ref<'static, CaptureOnceOwner>>()
            + size_of::<Ref<'static, CaptureMaterializationOwner>>()
            + size_of::<
                Result<Ref<'static, Option<OriginalAckPeerAssociation>>, std::cell::BorrowError>,
            >()
            + size_of::<Result<Ref<'static, CaptureOnceOwner>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, CaptureMaterializationOwner>, std::cell::BorrowError>>()
            + size_of::<&mut dyn FnMut(&ContentRef, &[u8], &[ContentRef]) -> Result<(), RuntimeError>>(
            )
            + size_of::<std::slice::Iter<'static, ContentRef>>()
            + size_of::<std::slice::Iter<'static, BornRow>>()
            + size_of::<Vec<ContentRef>>()
            + size_of::<Result<Vec<ContentRef>, RuntimeError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<crucible_node_format::HashRef>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + returned_header(|| blake3::Hash::from_bytes([0; 32]).to_hex())
            + size_of::<PacketCompleteCaptureDependencyLookupData>()
            + size_of::<Result<PacketCompleteCaptureDependencyLookupData, RuntimeError>>()
            + NativeArchiveRecord::complete_original_index_body17_counter_scratch_data()
    }
}
