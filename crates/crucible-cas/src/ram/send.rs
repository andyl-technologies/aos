//! Serves operation-bound RAM coordinates with one credited object buffer.

use crucible_protocol::ram_transfer::{
    RamTransferControl, RamTransferMessage, RamTransferNodeCoordinate, RamTransferOffer,
};

use super::{LeasedRamRoot, RamObjectCoordinate, RamObjectRecord, RamStore, RamStoreError, Work};

/// Serves a leased immutable RAM image without exposing arbitrary CAS reads.
///
/// The owning archive transport authenticates the whole-world-to-RAM binding
/// before constructing this sender. One bounded object is retained at a time;
/// credits name absolute offsets so retransmission cannot advance its cursor.
pub struct RamTransferSender {
    store: RamStore,
    root: LeasedRamRoot,
    operation: [u8; 32],
    offer: RamTransferOffer,
    active: Option<RamObjectRecord>,
    terminal: bool,
    requested: u64,
    bytes: u64,
    visits: u64,
    io_bytes: u64,
}

impl RamTransferSender {
    #[cfg(test)]
    pub(super) fn original_for_test(
        &self,
    ) -> Result<crate::owned_decode::DecodeBudget, RamStoreError> {
        crate::owned_decode::DecodeBudget::for_store(self.store.backend.metadata_resources()?)
            .map_err(super::codec_ownership::admission)
    }

    /// Serves framed controls on an already authenticated archive channel.
    ///
    /// The channel owner authenticates the destination and configures transport
    /// timeouts before entering this method. Terminal acknowledgments dispose
    /// only this sender's active buffer; whole-world transfer journals remain
    /// under the caller's separate publication and ownership protocol.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failures, malformed controls, source
    /// corruption, cancellation, or exhausted resource limits.
    pub fn serve_transport<T: std::io::Read + std::io::Write>(
        &mut self,
        transport: &mut T,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<(), RamStoreError> {
        self.offer().write(transport)?;
        while !self.terminal {
            boundary()?;
            let request = RamTransferMessage::read(transport)?;
            let response = self.respond(request, original, boundary)?;
            response.write(transport)?;
        }
        Ok(())
    }

    /// Binds a source capability to an authenticated archive offer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed offers or mismatched source identities.
    pub fn new(
        store: RamStore,
        root: LeasedRamRoot,
        operation: [u8; 32],
        offer: RamTransferOffer,
    ) -> Result<Self, RamStoreError> {
        RamTransferMessage {
            operation,
            control: RamTransferControl::Offer(offer.clone()),
        }
        .encode()?;
        if offer.ram_root != root.object_id().to_string()
            || offer.root_record != root.record().encode()
        {
            return Err(RamStoreError::Invalid("transfer offer source binding"));
        }
        store.admit_topology(root.record().topology())?;
        Ok(Self {
            store,
            root,
            operation,
            offer,
            active: None,
            terminal: false,
            requested: 0,
            bytes: 0,
            visits: 0,
            io_bytes: 0,
        })
    }

    /// Returns the immutable operation offer.
    pub fn offer(&self) -> RamTransferMessage {
        self.message(RamTransferControl::Offer(self.offer.clone()))
    }

    /// Handles one coordinate request, absolute credit, or terminal control.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, a foreign operation, unavailable or
    /// corrupt source bytes, cancellation, or exhausted source resource limits.
    pub fn respond(
        &mut self,
        message: RamTransferMessage,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamTransferMessage, RamStoreError> {
        message.encode()?;
        if message.operation != self.operation {
            return Err(RamStoreError::Invalid("transfer operation identity"));
        }
        if matches!(message.control, RamTransferControl::Cancel) {
            self.active = None;
            self.terminal = true;
            return Ok(self.message(RamTransferControl::Canceled));
        }
        if self.terminal {
            return Err(RamStoreError::Invalid("terminal transfer sender"));
        }
        boundary()?;
        let (coordinate, expected) = match message.control {
            RamTransferControl::WantNode { coordinate, object } => {
                let coordinate = match coordinate {
                    RamTransferNodeCoordinate::Root => RamObjectCoordinate::Root,
                    RamTransferNodeCoordinate::Catalog {
                        region_id,
                        first_page,
                        height,
                    } => RamObjectCoordinate::Catalog {
                        region_id,
                        first_page,
                        height,
                    },
                };
                (coordinate, object)
            }
            RamTransferControl::WantObject {
                region_id,
                page_index,
                object,
            } => (
                RamObjectCoordinate::Page {
                    region_id,
                    page_index,
                },
                object,
            ),
            RamTransferControl::Credit {
                object,
                offset,
                bytes,
            } => return self.chunk(&object, offset, bytes),
            RamTransferControl::ClosureStored { ram_root } => {
                if ram_root != self.offer.ram_root {
                    return Err(RamStoreError::Invalid("transfer stored root"));
                }
                self.active = None;
                self.terminal = true;
                return Ok(self.message(RamTransferControl::ClosureStored { ram_root }));
            }
            RamTransferControl::Fail { code } => {
                self.active = None;
                self.terminal = true;
                return Ok(self.message(RamTransferControl::Fail { code }));
            }
            _ => return Err(RamStoreError::Invalid("unexpected sender control")),
        };
        self.requested = self
            .requested
            .checked_add(1)
            .ok_or(RamStoreError::Limit("transfer requests"))?;
        if self.requested > self.offer.limits.objects {
            return Err(RamStoreError::Limit("transfer requests"));
        }
        let mut work = Work::new(self.store.limits, original, boundary)?;
        work.visits = self.visits;
        work.io_bytes = self.io_bytes;
        let result = self
            .store
            .read_transfer_object_with_work(&self.root, &coordinate, &mut work);
        self.visits = work.visits;
        self.io_bytes = work.io_bytes;
        let object = result?;
        if object.id().to_string() != expected {
            return Err(RamStoreError::Invalid(
                "transfer coordinate object identity",
            ));
        }
        self.bytes = self
            .bytes
            .checked_add(object.canonical_bytes().len() as u64)
            .ok_or(RamStoreError::Limit("transfer source bytes"))?;
        if self.bytes > self.offer.limits.bytes {
            return Err(RamStoreError::Limit("transfer source bytes"));
        }
        self.active = Some(object);
        self.chunk(&expected, 0, self.offer.limits.chunk_bytes)
    }

    fn chunk(
        &self,
        expected: &str,
        offset: u64,
        credit: u32,
    ) -> Result<RamTransferMessage, RamStoreError> {
        let active = self
            .active
            .as_ref()
            .ok_or(RamStoreError::Invalid("credit without active object"))?;
        let bytes = active.canonical_bytes();
        if expected != active.id().to_string()
            || offset >= bytes.len() as u64
            || credit > self.offer.limits.chunk_bytes
        {
            return Err(RamStoreError::Invalid("transfer credit object or offset"));
        }
        let begin = usize::try_from(offset).map_err(|_| RamStoreError::Limit("transfer offset"))?;
        let end = bytes.len().min(begin + credit as usize);
        Ok(self.message(RamTransferControl::ObjectChunk {
            object: expected.to_owned(),
            length: bytes.len() as u64,
            offset,
            bytes: bytes[begin..end].to_vec(),
            last: end == bytes.len(),
        }))
    }

    fn message(&self, control: RamTransferControl) -> RamTransferMessage {
        RamTransferMessage {
            operation: self.operation,
            control,
        }
    }
}
