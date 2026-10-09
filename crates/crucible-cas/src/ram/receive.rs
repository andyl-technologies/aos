//! Receives a complete archive RAM closure with bounded discovery and credits.
//!
//! Discovery authenticates one object at a time. Validated catalogs and pages
//! share bounded publication batches; the complete root is published last.
//! Incomplete closure progress has no root lease or readiness claim. Unnamed
//! catalogs remain collectable after operation retention closes. Missing-content
//! requests follow authenticated parent metadata and a logical coordinate.

use crucible_protocol::ram_transfer::{
    MAX_TRANSFER_OBJECT_BYTES, RamTransferControl, RamTransferMessage, RamTransferNodeCoordinate,
    RamTransferOffer,
};
use std::sync::Arc;

use crucible_ram::{Limits, PageDigest, RegionDescriptor, RootRecord};

use crate::content_envelope::ContentEnvelope;
use crate::content_store::{ContentId, StoreError};

use super::codec::{TreeNode, TreeRef, decode_root_envelope, object_limits, validate_tree};
use super::codec_ownership::admission;
use super::{
    LeasedRamRoot, RamClosureStored, RamRetention, RamStore, RamStoreError, RamTransferReport,
    RamTransferResponse, Work, logical, valid_length,
};

/// Terminal outcome after active buffers have been disposed.
#[derive(Clone, Debug)]
pub enum RamTransferStep {
    /// A complete durable destination image has independent retention.
    ClosureStored(RamClosureStored),
    /// Peer cancellation was acknowledged after active work stopped.
    Canceled,
}

/// Receives an offered image while retaining the destination GC authority.
///
/// The archive coordinator authenticates the owning whole-world root and
/// destination identity before admission. `receive` runs through its existing
/// transport callback; this object does not create a new remote CAS service.
pub struct RamTransferReceiver<'a> {
    store: RamStore,
    retention: &'a dyn RamRetention,
    operation: [u8; 32],
    offer: RamTransferOffer,
    record: RootRecord,
    root: ContentId,
    report: RamTransferReport,
    requested: u64,
    received: u64,
    terminal: bool,
    metadata_resources: Arc<super::metadata::RootMetadataResources>,
    _offer_credit: Option<crate::owned_decode::DecodeScratch>,
}

impl<'a> RamTransferReceiver<'a> {
    #[cfg(test)]
    pub(super) fn original_for_test(
        &self,
    ) -> Result<crate::owned_decode::DecodeBudget, RamStoreError> {
        crate::owned_decode::DecodeBudget::for_store(self.store.backend.metadata_resources()?)
            .map_err(super::codec_ownership::admission)
    }

    /// Receives the offered image on an authenticated bounded archive channel.
    ///
    /// The caller first reads and authenticates the offer, then constructs this
    /// receiver with the corresponding retention owner. Transport timeouts and
    /// channel identity remain the caller's responsibility; this method keeps
    /// the same operation clocks and callbacks across all request round trips.
    ///
    /// # Errors
    ///
    /// Returns transport, integrity, cancellation, retention, and limit errors.
    pub fn receive_transport<T: std::io::Read + std::io::Write>(
        &mut self,
        transport: &mut T,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamTransferStep, RamStoreError> {
        let maximum = self.offer.limits.chunk_bytes as usize + 256;
        let boundary = std::cell::RefCell::new(boundary);
        self.receive(
            &mut |message| {
                let _credit = original
                    .reserve_scratch_bytes(super::response::message_peak(&message.control)?)
                    .map_err(admission)?;
                super::response::check(original, &mut || (boundary.borrow_mut())())?;
                message.write(transport)?;
                RamTransferResponse::read_bounded(
                    transport,
                    original,
                    &mut || (boundary.borrow_mut())(),
                    maximum,
                    false,
                )
            },
            original,
            &mut || (boundary.borrow_mut())(),
        )
    }

    /// Admits a bounded offer under an actual destination retention owner.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, topology limits, or a weaker
    /// destination durability floor than the source offer requires.
    pub fn new(
        store: RamStore,
        retention: &'a dyn RamRetention,
        response: RamTransferResponse,
    ) -> Result<Self, RamStoreError> {
        // The owning Offer frame retains separate credit for self.record's
        // decoder. This loan covers the independently authenticated stored root
        // and catalog references that outlive the receiver in its returned lease.
        let metadata_resources = store.reserve_root_metadata(1)?;
        let (message, offer_credit) = response.into_parts();
        let RamTransferControl::Offer(offer) = message.control else {
            return Err(RamStoreError::Invalid("transfer admission requires offer"));
        };
        let record = RootRecord::decode(&offer.root_record, Limits::default()).map_err(logical)?;
        store.admit_ram_publication(record.topology(), record.scope())?;
        if store.durability.minimum_durable_placements() < offer.durable_placements {
            return Err(RamStoreError::Invalid(
                "transfer destination durability floor",
            ));
        }
        let root = ContentId::parse(&offer.ram_root)?;
        Ok(Self {
            store,
            retention,
            operation: message.operation,
            offer,
            record,
            root,
            report: RamTransferReport::default(),
            requested: 0,
            received: 0,
            terminal: false,
            metadata_resources,
            _offer_credit: offer_credit,
        })
    }

    /// Authenticates and durably stores the closure through an archive transport.
    ///
    /// The callback exchanges one bounded control/data message. Its owner must
    /// enforce transport deadlines; the boundary callback services cancellation
    /// before every request and storage operation. Failure never yields a root
    /// lease or a stored acknowledgment. No process restore is attempted here.
    ///
    /// # Errors
    ///
    /// Returns an error for corruption, missing source bytes, invalid controls,
    /// insufficient durability, retention loss, cancellation, or resource caps.
    pub fn receive(
        &mut self,
        exchange: &mut dyn FnMut(RamTransferMessage) -> Result<RamTransferResponse, RamStoreError>,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamTransferStep, RamStoreError> {
        if self.terminal {
            return Err(RamStoreError::Invalid("terminal transfer receiver"));
        }
        let mut work = Work::new(self.store.limits, original, boundary)?;
        let result = self.receive_inner(exchange, &mut work);
        self.terminal = true;
        if result.is_err() {
            // Dispose unpublished batch bodies before asking the peer to stop.
            // Completed batches remain retained, without a complete root. The peer
            // acknowledgment concerns buffer disposition, never archive commit.
            drop(work.pending.take());
            let cancel = self.message(RamTransferControl::Cancel);
            let _ = exchange(cancel);
        }
        result
    }

    fn receive_inner(
        &mut self,
        exchange: &mut dyn FnMut(RamTransferMessage) -> Result<RamTransferResponse, RamStoreError>,
        work: &mut Work<'_>,
    ) -> Result<RamTransferStep, RamStoreError> {
        let request = RamTransferControl::WantNode {
            coordinate: RamTransferNodeCoordinate::Root,
            object: self.root.to_string(),
        };
        let (envelope, existing) = self.object(self.root, request, exchange, work)?;
        let (record, regions) = decode_root_envelope(&envelope)?;
        if record != self.record {
            return Err(RamStoreError::Invalid("transfer offered logical root"));
        }
        self.store.validate_root_catalogs(&record, &regions)?;
        self.store.begin_publication_batch(work)?;
        for (region, reference) in record
            .topology()
            .regions()
            .iter()
            .filter(|region| record.scope().includes(region.class()))
            .zip(&regions)
        {
            self.region(region, *reference, 0, exchange, work)?;
        }
        self.store.flush_publication_batch(work)?;
        work.pending = None;
        self.publish(self.root, &envelope, existing, work)?;
        let lease = super::metadata::retain_resources(
            self.retention.retain_root(self.root)?,
            Arc::clone(&self.metadata_resources),
        );
        if lease.root() != self.root {
            return Err(RamStoreError::Invalid("transfer retained root identity"));
        }
        let acknowledgment = self.message(RamTransferControl::ClosureStored {
            ram_root: self.root.to_string(),
        });
        let response = exchange(acknowledgment.clone())?;
        if response.message() != &acknowledgment {
            return Err(RamStoreError::Invalid("transfer stored acknowledgment"));
        }
        self.report.object_visits = work.visits;
        Ok(RamTransferStep::ClosureStored(RamClosureStored {
            root: LeasedRamRoot {
                record: Arc::new(record),
                regions: regions.into(),
                metadata_custody: Arc::clone(&lease),
                lease,
            },
            report: self.report,
        }))
    }

    fn region(
        &mut self,
        region: &RegionDescriptor,
        reference: TreeRef,
        first: u64,
        exchange: &mut dyn FnMut(RamTransferMessage) -> Result<RamTransferResponse, RamStoreError>,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        let request = RamTransferControl::WantNode {
            coordinate: RamTransferNodeCoordinate::Catalog {
                region_id: region.id().to_owned(),
                first_page: first,
                height: reference.height,
            },
            object: reference.id.to_string(),
        };
        let (envelope, existing) = self.object(reference.id, request, exchange, work)?;
        let node = validate_tree(&envelope, reference)?;
        // Authentication authorizes child discovery. Bounded pending bodies
        // retain their original credits; batches must be durable before root
        // publication.
        self.publish(reference.id, &envelope, existing, work)?;
        match node {
            TreeNode::Padding => {}
            TreeNode::Leaf { page, digest } => {
                let request = RamTransferControl::WantObject {
                    region_id: region.id().to_owned(),
                    page_index: first,
                    object: page.to_string(),
                };
                let (page_envelope, page_existing) = self.object(page, request, exchange, work)?;
                validate_page(&page_envelope, digest, valid_length(region, first)?)?;
                self.publish(page, &page_envelope, page_existing, work)?;
            }
            TreeNode::Branch { left, right } => {
                self.region(region, left, first, exchange, work)?;
                self.region(
                    region,
                    right,
                    first + (1_u64 << (reference.height - 1)),
                    exchange,
                    work,
                )?;
            }
        }
        Ok(())
    }

    fn object(
        &mut self,
        id: ContentId,
        request: RamTransferControl,
        exchange: &mut dyn FnMut(RamTransferMessage) -> Result<RamTransferResponse, RamStoreError>,
        work: &mut Work<'_>,
    ) -> Result<(super::codec_ownership::OwnedEnvelope, bool), RamStoreError> {
        if work
            .pending
            .as_ref()
            .is_some_and(|pending| pending.iter().any(|object| object.id == id))
        {
            // Repeated references authenticate actual durable destination bytes.
            // Flush the bounded batch before its ordinary read, preserving
            // missing-only requests and existing-object report semantics.
            self.store.flush_publication_batch(work)?;
        }
        let account = work
            .original()
            .child()
            .map_err(super::codec_ownership::admission)?;
        let _scope = account.enter();
        let (maximum_bytes, maximum_children) = object_limits(id)?;
        self.retention.retain_object(id)?;
        if let Some(bytes) =
            super::bounded_read::read_canonical(self.store.backend.as_ref(), id, &account, work)?
        {
            let envelope = super::codec::decode_envelope(id, &bytes, maximum_children, &account)?;
            return Ok((envelope, true));
        }
        self.requested = self
            .requested
            .checked_add(1)
            .ok_or(RamStoreError::Limit("transfer object requests"))?;
        if self.requested > self.offer.limits.objects {
            return Err(RamStoreError::Limit("transfer object requests"));
        }
        let _assembly_credit = account
            .reserve_scratch_bytes(maximum_bytes)
            .map_err(admission)?;
        (work.boundary)()?;
        let mut response = exchange(self.message(request))?;
        let mut object = Vec::new();
        let mut declared = None;
        loop {
            let _chunk_bytes = match &response.message().control {
                RamTransferControl::ObjectChunk { bytes, .. }
                    if bytes.len() <= self.offer.limits.chunk_bytes as usize =>
                {
                    bytes.len()
                }
                _ => {
                    return Err(RamStoreError::Invalid(
                        "transfer response requires object chunk",
                    ));
                }
            };
            response.with_encoded(&account, |_| Ok(()))?;
            let message = response.message();
            if message.operation != self.operation {
                return Err(RamStoreError::Invalid("transfer response operation"));
            }
            let RamTransferControl::ObjectChunk {
                object: identity,
                length,
                offset,
                bytes,
                last,
            } = &message.control
            else {
                return Err(RamStoreError::Invalid(
                    "transfer response requires object chunk",
                ));
            };
            let (length, offset, last) = (*length, *offset, *last);
            if !id.with_encoded_text(|id| id == identity.as_bytes())
                || offset != object.len() as u64
                || bytes.len() > self.offer.limits.chunk_bytes as usize
                || declared.is_some_and(|expected| expected != length)
                || length > MAX_TRANSFER_OBJECT_BYTES
                || length > maximum_bytes
            {
                return Err(RamStoreError::Invalid("transfer chunk identity or order"));
            }
            if declared.is_none() {
                self.received = self
                    .received
                    .checked_add(length)
                    .ok_or(RamStoreError::Limit("transfer received bytes"))?;
                if self.received > self.offer.limits.bytes {
                    return Err(RamStoreError::Limit("transfer received bytes"));
                }
                let length = usize::try_from(length)
                    .map_err(|_| RamStoreError::Limit("transfer object allocation"))?;
                object
                    .try_reserve_exact(length)
                    .map_err(|source| StoreError::Supervision {
                        source: Box::new(source),
                    })?;
                declared = Some(length as u64);
            }
            work.visit(bytes.len() as u64)?;
            object.extend_from_slice(bytes);
            if last {
                break;
            }
            (work.boundary)()?;
            response = exchange(self.message(RamTransferControl::Credit {
                object: id.to_string(),
                offset: object.len() as u64,
                bytes: self.offer.limits.chunk_bytes,
            }))?;
        }
        if !id.authenticates(&object) {
            return Err(StoreError::Corrupt { id }.into());
        }
        let envelope =
            ContentEnvelope::from_canonical_bytes_with_child_limit(&object, maximum_children)?;
        if envelope.schema_version() != 1 || envelope.content_id(id.kind()) != id {
            return Err(RamStoreError::Invalid("transfer canonical envelope"));
        }
        Ok((
            super::codec_ownership::OwnedEnvelope::new(envelope, &account),
            false,
        ))
    }

    fn publish(
        &mut self,
        id: ContentId,
        envelope: &ContentEnvelope,
        existing: bool,
        work: &mut Work<'_>,
    ) -> Result<(), RamStoreError> {
        if self
            .store
            .put_envelope(envelope, id.kind(), self.retention, work)?
            != id
        {
            return Err(RamStoreError::Invalid("transfer persisted identity"));
        }
        if existing {
            self.report.authenticated_existing_objects = self
                .report
                .authenticated_existing_objects
                .checked_add(1)
                .ok_or(RamStoreError::Limit("transfer report objects"))?;
        } else {
            self.report.copied_objects = self
                .report
                .copied_objects
                .checked_add(1)
                .ok_or(RamStoreError::Limit("transfer report objects"))?;
            self.report.copied_bytes = self
                .report
                .copied_bytes
                .checked_add(envelope.canonical_bytes().len() as u64)
                .ok_or(RamStoreError::Limit("transfer report bytes"))?;
        }
        Ok(())
    }

    fn message(&self, control: RamTransferControl) -> RamTransferMessage {
        RamTransferMessage {
            operation: self.operation,
            control,
        }
    }
}

fn validate_page(
    envelope: &ContentEnvelope,
    expected: PageDigest,
    valid: usize,
) -> Result<(), RamStoreError> {
    let body = envelope.body();
    if envelope.schema_name() != "crucible.ram.page"
        || !envelope.children().is_empty()
        || body.len() != 36 + valid
    {
        return Err(RamStoreError::Invalid("transfer page envelope"));
    }
    let recorded = body
        .get(..32)
        .ok_or(RamStoreError::Invalid("transfer page digest"))?;
    let length: [u8; 4] = body
        .get(32..36)
        .ok_or(RamStoreError::Invalid("transfer page length"))?
        .try_into()
        .map_err(|_| RamStoreError::Invalid("transfer page length"))?;
    if recorded != expected.as_bytes()
        || u32::from_be_bytes(length) as usize != valid
        || PageDigest::hash(&body[36..]).map_err(logical)? != expected
    {
        return Err(RamStoreError::Invalid("transfer logical page bytes"));
    }
    Ok(())
}
