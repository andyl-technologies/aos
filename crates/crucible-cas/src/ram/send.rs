//! Serves operation-bound RAM coordinates with one credited object buffer.

use crucible_protocol::ram_transfer::{
    RamTransferControl, RamTransferLimits, RamTransferMessage, RamTransferNodeCoordinate,
    RamTransferOffer,
};

use super::codec_ownership::admission;
use super::{
    LeasedRamRoot, RamObjectCoordinate, RamObjectRecord, RamStore, RamStoreError,
    RamTransferResponse, Work,
};
use crate::content_store::ContentId;
use crate::owned_decode::{DecodeBudget, DecodeScratch};

mod path;

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
    root_record: Option<RamObjectRecord>,
    path: Vec<path::PathEntry>,
    state: Option<super::store_boundary::RetainedReadState>,
    _offer_credit: DecodeScratch,
    _path_credit: DecodeScratch,
    _control_credit: DecodeScratch,
    initial_response_credit: Option<DecodeScratch>,
    original: DecodeBudget,
    terminal: bool,
    requested: u64,
    bytes: u64,
    visits: u64,
    io_bytes: u64,
}

impl RamTransferSender {
    #[cfg(test)]
    pub(super) fn state_for_test(&self) -> (u64, u64, u64, bool, bool, bool, bool) {
        (
            self.requested,
            self.visits,
            self.io_bytes,
            self.state.is_some(),
            self.terminal,
            self.path.is_empty(),
            self.active.is_none(),
        )
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
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<(), RamStoreError> {
        let result = (|| {
            self.offer()?.write(transport, &self.original, boundary)?;
            while !self.terminal {
                let request = RamTransferResponse::read_bounded(
                    transport,
                    &self.original,
                    boundary,
                    1024,
                    false,
                )?;
                let response = self.respond(request.message().clone(), boundary)?;
                response.write(transport, &self.original, boundary)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(self.seal_transport_error(error));
        }
        Ok(())
    }

    fn seal_transport_error(&mut self, error: RamStoreError) -> RamStoreError {
        self.terminal = true;
        self.active = None;
        self.root_record = None;
        self.path.clear();
        match self.state.take() {
            Some(state) => {
                let mut account =
                    super::store_boundary::WorkAccount::from_retained(&self.original, state);
                let error = if account.read_failure().is_none() {
                    account.fail_read(error).into()
                } else {
                    error
                };
                self.state = Some(account.into_retained());
                error
            }
            None => error,
        }
    }

    /// Binds a source capability to an authenticated archive offer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed offers or mismatched source identities.
    // crucible-lint: allow rust-allow -- source, archive binding, destination contract and original are independently authenticated inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: RamStore,
        root: LeasedRamRoot,
        operation: [u8; 32],
        whole_world_root: ContentId,
        destination: &str,
        durable_placements: u16,
        limits: RamTransferLimits,
        original: &DecodeBudget,
    ) -> Result<Self, RamStoreError> {
        original.verify_live().map_err(admission)?;
        store.admit_topology(root.record().topology())?;
        let account = super::store_boundary::WorkAccount::new(original)?;
        let world_length = whole_world_root.with_encoded_text(<[u8]>::len);
        let root_length = root.object_id().with_encoded_text(<[u8]>::len);
        let offer_length = 83_usize
            .checked_add(world_length)
            .and_then(|n| n.checked_add(root_length))
            .and_then(|n| n.checked_add(root.record().encoded_len()))
            .and_then(|n| n.checked_add(destination.len()))
            .ok_or(RamStoreError::Limit("transfer offer allocation"))?;
        let peak = super::response::frame_peak(offer_length, true)?;
        let offer_credit = original.reserve_scratch_bytes(peak).map_err(admission)?;
        let initial_response_credit = original.reserve_scratch_bytes(peak).map_err(admission)?;
        let path_count = root
            .record()
            .topology()
            .regions()
            .iter()
            .filter(|region| root.record().scope().includes(region.class()))
            .map(|region| region.geometry().height() as usize + 1)
            .max()
            .unwrap_or(0);
        let path_credit = original
            .reserve_scratch_array::<path::PathEntry>(path_count)
            .map_err(admission)?;
        let control_credit = original
            .reserve_scratch_bytes(super::response::frame_peak(1028, false)?)
            .map_err(admission)?;
        original.verify_live().map_err(admission)?;
        let offer = RamTransferOffer {
            whole_world_root: whole_world_root.to_string(),
            ram_root: root.object_id().to_string(),
            root_record: root.record().encode(),
            destination: destination.to_owned(),
            durable_placements,
            limits,
        };
        RamTransferMessage {
            operation,
            control: RamTransferControl::Offer(offer.clone()),
        }
        .encode()?;
        let mut path = Vec::new();
        path.try_reserve_exact(path_count).map_err(|source| {
            crate::content_store::StoreError::Allocation {
                source,
                custody: Some(original.custody()),
            }
        })?;
        Ok(Self {
            store,
            root,
            operation,
            offer,
            active: None,
            root_record: None,
            path,
            state: Some(account.into_retained()),
            _offer_credit: offer_credit,
            _path_credit: path_credit,
            _control_credit: control_credit,
            initial_response_credit: Some(initial_response_credit),
            original: original.clone(),
            terminal: false,
            requested: 0,
            bytes: 0,
            visits: 0,
            io_bytes: 0,
        })
    }

    /// Returns the immutable operation offer with its own retained frame credit.
    ///
    /// # Errors
    /// Refuses a failed operation or exhausted original frame resources.
    pub fn offer(&mut self) -> Result<RamTransferResponse, RamStoreError> {
        if let Err(error) = self.check_state() {
            return Err(self.seal_transport_error(error));
        }
        let credit = match self.initial_response_credit.take() {
            Some(credit) => credit,
            None => self
                .original
                .reserve_scratch_bytes(super::response::offer_peak(&self.offer)?)
                .map_err(admission)?,
        };
        self.original.verify_live().map_err(admission)?;
        Ok(RamTransferResponse::new(
            self.message(RamTransferControl::Offer(self.offer.clone())),
            credit,
        ))
    }

    fn check_state(&self) -> Result<(), RamStoreError> {
        if self.state.is_none() {
            return Err(RamStoreError::Invalid("terminal transfer sender"));
        }
        // Borrowed inspection cannot renew or consume the saved failure slots.
        if let Some(error) = self.state.as_ref().and_then(|state| state.read_failure()) {
            return Err(error.into());
        }
        if self.terminal {
            return Err(RamStoreError::Invalid("terminal transfer sender"));
        }
        self.original.verify_live().map_err(admission)
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
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<RamTransferResponse, RamStoreError> {
        if message.operation != self.operation {
            return Err(RamStoreError::Invalid("transfer operation identity"));
        }
        if matches!(message.control, RamTransferControl::Cancel) {
            self.active = None;
            self.root_record = None;
            self.path.clear();
            self.terminal = true;
            return Ok(RamTransferResponse::inline(
                self.message(RamTransferControl::Canceled),
            ));
        }
        if let Err(error) = self.check_state() {
            return Err(self.seal_transport_error(error));
        }
        let state = self
            .state
            .take()
            .ok_or(RamStoreError::Invalid("missing transfer operation"))?;
        let mut turn = Turn {
            work: Some(Work::from_retained(
                self.store.limits,
                &self.original,
                boundary,
                state,
                self.visits,
                self.io_bytes,
            )),
            state: &mut self.state,
            visits: &mut self.visits,
            io_bytes: &mut self.io_bytes,
            active: &mut self.active,
            root_record: &mut self.root_record,
            path: &mut self.path,
            terminal: &mut self.terminal,
        };
        let result = respond_inner(
            &self.store,
            &self.root,
            self.operation,
            &self.offer,
            &self.original,
            &mut self.requested,
            &mut self.bytes,
            message,
            &mut turn,
        );
        turn.finish(result)
    }

    fn message(&self, control: RamTransferControl) -> RamTransferMessage {
        RamTransferMessage {
            operation: self.operation,
            control,
        }
    }
}

struct Turn<'sender, 'work> {
    work: Option<Work<'work>>,
    state: &'sender mut Option<super::store_boundary::RetainedReadState>,
    visits: &'sender mut u64,
    io_bytes: &'sender mut u64,
    active: &'sender mut Option<RamObjectRecord>,
    root_record: &'sender mut Option<RamObjectRecord>,
    path: &'sender mut Vec<path::PathEntry>,
    terminal: &'sender mut bool,
}

impl Turn<'_, '_> {
    fn finish(
        mut self,
        result: Result<RamTransferResponse, RamStoreError>,
    ) -> Result<RamTransferResponse, RamStoreError> {
        let mut work = self
            .work
            .take()
            .ok_or(RamStoreError::Invalid("missing transfer operation"))?;
        let result = match result {
            Err(error) if work.account.read_failure().is_none() => {
                Err(work.account.fail_read(error).into())
            }
            result => result,
        };
        *self.visits = work.visits;
        *self.io_bytes = work.io_bytes;
        *self.state = Some(work.account.into_retained());
        result
    }
}

impl Drop for Turn<'_, '_> {
    fn drop(&mut self) {
        if self.work.is_some() {
            *self.terminal = true;
            *self.active = None;
            *self.root_record = None;
            self.path.clear();
        }
    }
}

// crucible-lint: allow rust-allow -- the split turn owns mutable operation custody while source bindings remain borrowed.
#[allow(clippy::too_many_arguments)]
fn respond_inner(
    store: &RamStore,
    root: &LeasedRamRoot,
    operation: [u8; 32],
    offer: &RamTransferOffer,
    original: &DecodeBudget,
    requested: &mut u64,
    source_bytes: &mut u64,
    message: RamTransferMessage,
    turn: &mut Turn<'_, '_>,
) -> Result<RamTransferResponse, RamStoreError> {
    message.encode()?;
    let work = turn
        .work
        .as_mut()
        .ok_or(RamStoreError::Invalid("missing transfer operation"))?;
    work.account.check_boundary(work.boundary)?;
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
        } => {
            return chunk(
                turn.active.as_ref(),
                operation,
                offer,
                original,
                &object,
                offset,
                bytes,
            );
        }
        RamTransferControl::ClosureStored { ram_root } => {
            if ram_root != offer.ram_root {
                return Err(RamStoreError::Invalid("transfer stored root"));
            }
            *turn.active = None;
            *turn.terminal = true;
            let credit = original
                .reserve_scratch_bytes(super::response::frame_peak(ram_root.len() + 49, false)?)
                .map_err(admission)?;
            return Ok(RamTransferResponse::new(
                RamTransferMessage {
                    operation,
                    control: RamTransferControl::ClosureStored { ram_root },
                },
                credit,
            ));
        }
        RamTransferControl::Fail { code } => {
            *turn.active = None;
            *turn.terminal = true;
            return Ok(RamTransferResponse::inline(RamTransferMessage {
                operation,
                control: RamTransferControl::Fail { code },
            }));
        }
        _ => return Err(RamStoreError::Invalid("unexpected sender control")),
    };
    *requested = requested
        .checked_add(1)
        .ok_or(RamStoreError::Limit("transfer requests"))?;
    if *requested > offer.limits.objects {
        return Err(RamStoreError::Limit("transfer requests"));
    }
    let work = turn
        .work
        .as_mut()
        .ok_or(RamStoreError::Invalid("missing transfer operation"))?;
    let object = path::read(store, root, turn.root_record, turn.path, &coordinate, work)?;
    if !object
        .id()
        .with_encoded_text(|id| id == expected.as_bytes())
    {
        return Err(RamStoreError::Invalid(
            "transfer coordinate object identity",
        ));
    }
    *source_bytes = source_bytes
        .checked_add(object.canonical_bytes().len() as u64)
        .ok_or(RamStoreError::Limit("transfer source bytes"))?;
    if *source_bytes > offer.limits.bytes {
        return Err(RamStoreError::Limit("transfer source bytes"));
    }
    *turn.active = Some(object);
    chunk(
        turn.active.as_ref(),
        operation,
        offer,
        original,
        &expected,
        0,
        offer.limits.chunk_bytes,
    )
}

fn chunk(
    active: Option<&RamObjectRecord>,
    operation: [u8; 32],
    offer: &RamTransferOffer,
    original: &DecodeBudget,
    expected: &str,
    offset: u64,
    credit: u32,
) -> Result<RamTransferResponse, RamStoreError> {
    let active = active.ok_or(RamStoreError::Invalid("credit without active object"))?;
    let bytes = active.canonical_bytes();
    if !active
        .id()
        .with_encoded_text(|id| id == expected.as_bytes())
        || offset >= bytes.len() as u64
        || credit > offer.limits.chunk_bytes
    {
        return Err(RamStoreError::Invalid("transfer credit object or offset"));
    }
    let begin = usize::try_from(offset).map_err(|_| RamStoreError::Limit("transfer offset"))?;
    let end = bytes.len().min(begin + credit as usize);
    let extent = super::response::frame_peak(70 + expected.len() + end - begin, false)?;
    let allocation = original.reserve_scratch_bytes(extent).map_err(admission)?;
    original.verify_live().map_err(admission)?;
    let message = RamTransferMessage {
        operation,
        control: RamTransferControl::ObjectChunk {
            object: expected.to_owned(),
            length: bytes.len() as u64,
            offset,
            bytes: bytes[begin..end].to_vec(),
            last: end == bytes.len(),
        },
    };
    Ok(RamTransferResponse::new(message, allocation))
}
