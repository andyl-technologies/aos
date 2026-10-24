//! Retains physical Bootstrap response receipt before closed preflight and parsing.

use super::*;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapEnvelopeProjectionData,
    PacketNativeImport18BootstrapRawResponseData as Raw,
    PacketNativeImport18BootstrapRawResponseRowData as Row,
    native_import18_bootstrap_envelope_projection_data,
    native_import18_bootstrap_raw_preflight_counter_scratch_data,
    native_import18_bootstrap_raw_preflight_data,
};
use crate::retained_metadata::MetadataObserver;
use crucible_node_format::canonical;
use std::{
    io::{self, Read},
    mem::{align_of, size_of},
};

impl<S: ProviderStream> Connection<S> {
    /// Quotes the concrete body bank, closed parser and containment windows.
    ///
    /// The complete holder separately funds its existing journal and actual
    /// supervisor callback. The body bound becomes a real retained allocation;
    /// it is not used to manufacture a generic JSON population allowance.
    ///
    /// # Errors
    /// Refuses invalid physical framing, checked overflow or a short restriction.
    pub(crate) fn original_bootstrap_raw_response_construction_data(
        maximum_body_bytes: usize,
        maximum_requested: usize,
    ) -> Result<Row, ProviderError> {
        if maximum_body_bytes == 0 || u32::try_from(maximum_body_bytes).is_err() {
            return Err(refused());
        }
        let projection = native_import18_bootstrap_envelope_projection_data(maximum_requested)?;
        let sdk = Self::original_bootstrap_sealing_construction_data(maximum_requested)?;
        let dom = projection.response_backing_storage_data(
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        )?;
        let forming_dom = projection.retained_value_backing_bytes_data()[1];
        let axes = [
            sum(&[size_of::<Raw>(), maximum_body_bytes, dom, sdk[0]])?,
            sum(&[
                sdk[1],
                // Parser intermediates and its independently forming Value
                // survive together until the complete tree moves into Raw.
                projection.serialization_requested_bytes_data()[1][1],
                forming_dom,
                size_of::<Raw>(),
                size_of::<Option<Raw>>(),
                size_of::<RetainedFrame>(),
                size_of::<serde_json::Value>(),
                size_of::<Vec<u8>>(),
                PacketNativeImport18BootstrapEnvelopeProjectionData::serialization_failure_requested_bytes_data(),
            ])?,
            sum(&[sdk[2], Self::original_bootstrap_raw_response_counter_scratch_data()])?,
        ];
        if sum(&axes)? > maximum_requested {
            return Err(refused());
        }
        Ok(Row {
            axes,
            maximum_body_bytes,
        })
    }

    /// Retains the actual raw body and strict tree before any terminal guard.
    ///
    /// The caller authenticates the already published original and independently
    /// admits the whole holder before entry. An occupied output refuses before
    /// guards or effects; every later refusal keeps initialized read prefixes.
    ///
    /// # Errors
    /// Refuses changed original custody, row, frame limit, partial I/O, closed
    /// raw grammar, strict parsing or actual retained backing beyond admission.
    pub(crate) fn receive_original_bootstrap_response_into_data(
        &mut self,
        original: &Envelope,
        row: &Row,
        maximum_requested: usize,
        output: &mut Option<Raw>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some(Raw {
            owner: ProtocolCaptureOwner::new(),
            row: *row,
            header: [0; 4],
            header_received: 0,
            body: Vec::new(),
            body_received: 0,
            slot: None,
            frame: None,
            complete: false,
            preflighted: false,
            parsed: false,
            failed: true,
        });
        let raw = output.as_mut().ok_or_else(refused)?;
        let result = (|| {
            self.original_bootstrap_transport_selection_data()?;
            self.authenticate_bootstrap_published_before_response(original)?;
            if Self::original_bootstrap_raw_response_construction_data(
                row.maximum_body_bytes,
                maximum_requested,
            )? != *row
                || row.maximum_body_bytes > allowance(self.authority.limits().frame_bytes.get())?
            {
                return Err(refused());
            }
            self.ensure_no_pending_native_restore_response()?;
            self.check_authority()?;
            self.read_bootstrap_response(raw)?;
            native_import18_bootstrap_raw_preflight_data(original, &raw.body)?;
            raw.preflighted = true;
            let value = canonical::parse_json_with_depth(
                &raw.body,
                row.maximum_body_bytes,
                allowance(self.authority.limits().nesting.get())?,
            )?;
            raw.frame = Some(RetainedFrame {
                value,
                bytes: std::mem::take(&mut raw.body),
            });
            raw.parsed = true;
            self.authenticate_native_import18_raw_data(
                original,
                raw.frame.as_ref().ok_or_else(refused)?,
            )
        })();
        // The same owner is observed after success or any read/parser refusal.
        let actual = raw.retained_requested_bytes_data();
        if result.is_err()
            || match &actual {
                Ok(bytes) => *bytes > row.axes[0],
                Err(_) => true,
            }
        {
            self.reader.fence_original_literal_data();
            self.contain(ConnectionFailure::Read);
        }
        result?;
        if actual? > row.axes[0] {
            return Err(refused());
        }
        raw.failed = false;
        Ok(())
    }

    fn authenticate_bootstrap_published_before_response(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_bootstrap_endpoint_data()?;
        self.guard.original_bootstrap_pending_data(original)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        let named = bank.original_outgoing_request_frame_data(
            original.request_id.0.as_ref().ok_or_else(refused)?,
        )?;
        let last = bank.frames().last().ok_or_else(refused)?;
        let length = named.bytes.len().checked_sub(4).ok_or_else(refused)?;
        let header = u32::try_from(length).map_err(|_| refused())?.to_be_bytes();
        if length == 0
            || !named.complete
            || named.transferred != named.bytes.len()
            || named.bytes.get(..4) != Some(header.as_slice())
            || last.direction != named.direction
            || last.bytes != named.bytes
            || last.transferred != named.transferred
            || last.complete != named.complete
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the same completed literal and pending original after strict parsing.
    ///
    /// # Errors
    /// Refuses foreign custody, incomplete/failed parser state or changed journal.
    pub(crate) fn authenticate_original_bootstrap_received_raw_data(
        &self,
        original: &Envelope,
        raw: &Raw,
    ) -> Result<(), ProviderError> {
        self.authenticate_bootstrap_response_literal_data(raw)?;
        self.guard.original_bootstrap_pending_data(original)
    }

    /// Checks settled SDK custody beside the same raw and decoded response.
    ///
    /// # Errors
    /// Refuses changed literal, typed correspondence, moved request or SDK state.
    pub(crate) fn authenticate_original_bootstrap_sdk_settlement_data(
        &self,
        original: &Envelope,
        raw: &Raw,
        moved: &Envelope,
        decoded: &PacketNativeImport18BootstrapResponseDecodeData,
    ) -> Result<(), ProviderError> {
        self.authenticate_bootstrap_response_literal_data(raw)?;
        decoded.authenticate_raw_data(original, &raw.frame.as_ref().ok_or_else(refused)?.value)?;
        if moved != original {
            return Err(refused());
        }
        self.guard.original_bootstrap_received_data(
            moved,
            decoded
                .borrowed_history_data()
                .envelope
                .ok_or_else(refused)?,
        )
    }

    fn authenticate_bootstrap_response_literal_data(&self, raw: &Raw) -> Result<(), ProviderError> {
        raw.owner.ensure_current()?;
        let frame = raw.frame.as_ref().ok_or_else(refused)?;
        if raw.failed
            || !raw.complete
            || !raw.preflighted
            || !raw.parsed
            || raw.header_received != 4
            || raw.body_received != frame.bytes.len()
            || raw.header
                != u32::try_from(frame.bytes.len())
                    .map_err(|_| refused())?
                    .to_be_bytes()
            || raw.slot != self.reader.original_slot()
            || !raw.body.is_empty()
        {
            return Err(refused());
        }
        self.authenticate_original_bootstrap_endpoint_data()?;
        self.native_import18_selection_data()?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        let (last, observed) = bank.frames().enumerate().last().ok_or_else(refused)?;
        if Some(last) != raw.slot
            || observed.direction != FrameDirection::Incoming
            || !observed.complete
            || observed.transferred != frame.bytes.len().checked_add(4).ok_or_else(refused)?
            || observed.bytes.get(..4) != Some(raw.header.as_slice())
            || observed.bytes.get(4..) != Some(frame.bytes.as_slice())
        {
            return Err(refused());
        }
        Ok(())
    }

    fn read_bootstrap_response(&mut self, raw: &mut Raw) -> Result<(), ProviderError> {
        raw.owner.ensure_current()?;
        // Request the admitted concrete capacity before the first public byte.
        raw.body
            .try_reserve_exact(raw.row.maximum_body_bytes)
            .map_err(|_| refused())?;
        if raw.body.capacity() != raw.row.maximum_body_bytes {
            return Err(refused());
        }
        let bank = self.original_frames.as_ref().ok_or_else(refused)?.clone();
        let slot = self
            .reader
            .begin_original_literal_data(raw.row.maximum_body_bytes, &bank)?;
        raw.slot = Some(slot);
        read_into(
            self.reader.stream_mut(),
            &bank,
            slot,
            &mut raw.header,
            &mut raw.header_received,
        )?;
        let length = usize::try_from(u32::from_be_bytes(raw.header)).map_err(|_| refused())?;
        if length == 0 || length > raw.row.maximum_body_bytes {
            return Err(refused());
        }
        raw.body.resize(length, 0);
        read_into(
            self.reader.stream_mut(),
            &bank,
            slot,
            &mut raw.body,
            &mut raw.body_received,
        )?;
        bank.try_borrow_mut().map_err(|_| refused())?.finish(slot)?;
        raw.complete = true;
        Ok(())
    }

    /// Names actual fixed parser, cursor, census and bank-borrow controls.
    pub(crate) fn original_bootstrap_raw_response_counter_scratch_data() -> usize {
        Self::original_bootstrap_sealing_counter_scratch_data()
            + native_import18_bootstrap_raw_preflight_counter_scratch_data()
            + canonical::json_parse_counter_scratch_bytes_data()
            + size_of::<Row>() * 2
            + size_of::<Result<Row, ProviderError>>()
            + size_of::<&mut Raw>()
            + size_of::<&mut Option<Raw>>()
            + size_of::<&mut Self>()
            + size_of::<&Envelope>()
            + size_of::<
                Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>,
            >()
            + size_of::<MetadataObserver<'static>>()
            + MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data() * 8
            + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<usize, io::Error>>()
            + size_of::<io::ErrorKind>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<[Result<(), ProviderError>; 3]>()
            + size_of::<&mut [u8]>()
            + size_of::<[usize; 8]>()
            + size_of::<crate::transport::original_frames::OriginalFrame<'static>>() * 2
            + crate::transport::original_frames::original_frames_iterator_counter_scratch_data()
            + size_of::<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        crate::transport::original_frames::OriginalFrameReservation,
                    >,
                    std::cell::BorrowError,
                >,
            >()
    }
}

fn read_into(
    stream: &mut impl Read,
    bank: &Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>,
    slot: usize,
    bytes: &mut [u8],
    received: &mut usize,
) -> Result<(), ProviderError> {
    while *received < bytes.len() {
        let count = match stream.read(&mut bytes[*received..]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let start = *received;
        let end = start
            .checked_add(count)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(refused)?;
        // Preserve physical progress even if journal retention itself refuses.
        *received = end;
        bank.try_borrow_mut()
            .map_err(|_| refused())?
            .append(slot, &bytes[start..*received])?;
    }
    Ok(())
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(refused)
    })
}

#[cfg(test)]
#[path = "raw_response/tests.rs"]
mod tests;
