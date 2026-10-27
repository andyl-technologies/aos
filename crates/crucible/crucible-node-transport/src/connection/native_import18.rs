//! Checks distinct Native18 assignments beneath the actual installed host codec.
//!
//! These transport guards accept only the new binding/proof/receipt family.
//! Existing Transfer12 assignment and projection methods remain unchanged.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::reference_packet::service::complete_restore::{
    import17::{
        PacketNativeImport17CommitReceipt, PacketNativeImport17PrepareReceipt,
        PacketNativeImport17Proof,
    },
    import18::*,
    transfer::*,
};
use crate::transport::original_frames::FrameDirection;
use crucible_node_format::SchemaRef;
use serde::Deserialize;

#[path = "native_import18/wire.rs"]
mod wire;
pub(super) use wire::verify_selected_wire_data;

/// Checks full installed contract rosters and negotiated Native18 extensions.
///
/// The caller admits the compiled schema-factory workspace before entry. This
/// authenticates immutable selection DATA, never a native phase or model grant.
///
/// # Errors
/// Refuses absent/duplicate/changed full schemas, unsupported features or a
/// revoked original registration.
pub(crate) fn authenticate_selection_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    let mut actual = None;
    for schema in &selection.provider.implementation.formats {
        if schema.id.as_str() == NATIVE_IMPORT18_EXTENSION && actual.replace(schema).is_some() {
            return Err(invalid());
        }
    }
    let actual = actual.ok_or_else(invalid)?;
    authenticate_native_import18_schema_data(actual)?;

    if selection.realization.bindings.is_empty()
        || !selection
            .provider
            .extensions_supported
            .iter()
            .any(|id| id.as_str() == NATIVE_IMPORT18_EXTENSION)
        || !authority
            .selected_features()
            .iter()
            .any(|id| id.as_str() == NATIVE_IMPORT18_EXTENSION)
    {
        return Err(invalid());
    }
    for binding in &selection.realization.bindings {
        let mut matches = binding
            .compatibility
            .implementation
            .formats
            .iter()
            .filter(|schema| schema.id.as_str() == NATIVE_IMPORT18_EXTENSION);
        if matches.next() != Some(actual) || matches.next().is_some() {
            return Err(invalid());
        }
    }
    for key in [
        NATIVE_IMPORT18_EXTENSION,
        PacketNativeImport18Phase::Prepare.request_extension(),
        PacketNativeImport18Phase::Prepare.proof_extension(),
        PacketNativeImport18Phase::Prepare.receipt_extension(),
        PacketNativeImport18Phase::Commit.request_extension(),
        PacketNativeImport18Phase::Commit.proof_extension(),
        PacketNativeImport18Phase::Commit.receipt_extension(),
    ] {
        if !authority.envelope_extensions().contains(key) {
            return Err(invalid());
        }
    }
    authority.ensure_live()
}

/// Checks only the selected new-family request vocabulary and header DATA.
///
/// The native defining caller separately authenticates its actual incoming
/// ProtocolGuard/literal owner and phase token. This helper grants no receive,
/// input custody, model installation or World publication permission.
///
/// # Errors
/// Refuses a foreign full selection, header, typed payload or proof grammar.
pub(crate) fn authenticate_request_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
    phase: PacketNativeImport18Phase,
    sealed: bool,
) -> Result<(), ProviderError> {
    authenticate_selection_data(selection, authority)?;
    wire::authenticate_request_data(selection, authority, original, phase, sealed)
}

impl<S: ProviderStream> Connection<S> {
    /// Borrows the actual installed host selection after full contract checks.
    ///
    /// # Errors
    /// Refuses another actor/endpoint/codec, full schema or current registration.
    pub(crate) fn native_import18_selection_data(
        &self,
    ) -> Result<&PacketControlSelection, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let Native5CodecOwner::ControllerPacket(policy) =
            self.native5_codec.as_deref().ok_or_else(invalid)?
        else {
            return Err(invalid());
        };
        let selection = policy.original_native_import18_selection_data(&self.authority)?;
        authenticate_selection_data(selection, &self.authority)?;
        if self.role != EndpointRole::Controller {
            return Err(invalid());
        }
        Ok(selection)
    }

    /// Reserves the exact unsigned new-family original in its literal bank.
    ///
    /// # Errors
    /// Refuses another selection/header/phase, a used ID/slot or insufficient
    /// original frame capacity. An initialized slot remains retained on refusal.
    pub(crate) fn reserve_native_import18_data(
        &mut self,
        original: &Envelope,
        phase: PacketNativeImport18Phase,
        maximum: usize,
        output: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        let selection = self.native_import18_selection_data()?;
        wire::authenticate_request_data(selection, &self.authority, original, phase, false)?;
        if output.is_some() || maximum > allowance(self.authority.limits().frame_bytes.get())? {
            return Err(invalid());
        }
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let mut bank = self
            .original_frames
            .as_ref()
            .ok_or_else(invalid)?
            .try_borrow_mut()
            .map_err(|_| invalid())?;
        if !bank.complete() || bank.contains_original_id(id.as_str()) {
            return Err(invalid());
        }
        let slot = bank.begin(
            FrameDirection::Outgoing,
            maximum.checked_add(4).ok_or_else(invalid)?,
        )?;
        *output = Some(slot);
        bank.retain_request(slot, id)
    }

    /// Writes the same sealed new-family original from its retained literal slot.
    ///
    /// # Errors
    /// Refuses changed scope/shape/bytes or authority, and contains write failure.
    pub(crate) fn publish_native_import18_data(
        &mut self,
        original: &Envelope,
        phase: PacketNativeImport18Phase,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        let selection = self.native_import18_selection_data()?;
        wire::authenticate_request_data(selection, &self.authority, original, phase, true)?;
        self.check_authority()?;
        let result = self.publish_original_send(bytes, slot);
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        }
        result
    }

    /// Receives exact strict raw bytes/Value while leaving DTO decoding pending.
    ///
    /// # Errors
    /// Refuses changed pending original, occupied output, selection or transport loss.
    pub(crate) fn receive_native_import18_raw_into_data(
        &mut self,
        original: &Envelope,
        raw: &mut Option<crate::transport::RetainedFrame>,
        profile: &mut crate::retained_metadata::NativeImport18JsonMetadataProfileData,
    ) -> Result<(), ProviderError> {
        self.native_import18_selection_data()?;
        if raw.is_some()
            || !self
                .guard
                .pending_requests()
                .any(|pending| pending == original)
        {
            return Err(invalid());
        }
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        let result = (|| {
            let frame = self.reader.read_retained()?.ok_or_else(invalid)?;
            // Store actual syntax geometry before the owning slot and every
            // later fallible literal/selection guard. No DTO parse runs here.
            profile.retain_strict_raw_population_data(frame.bytes.len());
            *raw = Some(frame);
            self.authenticate_native_import18_raw_data(original, raw.as_ref().ok_or_else(invalid)?)
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Read);
        }
        result
    }

    /// Checks the real current incoming literal and still-pending original DATA.
    ///
    /// # Errors
    /// Refuses changed literal/reader/selection or any intervening correlation.
    pub(crate) fn authenticate_native_import18_raw_data(
        &self,
        original: &Envelope,
        raw: &crate::transport::RetainedFrame,
    ) -> Result<(), ProviderError> {
        self.native_import18_selection_data()?;
        let mut pending = self.guard.pending_requests();
        if pending.next() != Some(original) || pending.next().is_some() {
            return Err(invalid());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(invalid)?
            .try_borrow()
            .map_err(|_| invalid())?;
        let slot = self.reader.original_slot().ok_or_else(invalid)?;
        let (last, frame) = bank.frames().enumerate().last().ok_or_else(invalid)?;
        if last != slot
            || frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.get(4..) != Some(raw.bytes.as_slice())
        {
            return Err(invalid());
        }
        let length = u32::try_from(raw.bytes.len())
            .map_err(|_| invalid())?
            .to_be_bytes();
        if frame.bytes.get(..4) != Some(length.as_slice()) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Constructs Envelope/typed output from the exact already-admitted raw frame.
    ///
    /// # Errors
    /// Retains each initialized slot and fences the actor on later refusal.
    pub(crate) fn decode_native_import18_raw_into_data(
        &mut self,
        original: &Envelope,
        raw: &crate::transport::RetainedFrame,
        response: &mut Option<Envelope>,
        received: &mut Option<ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native_import18_raw_data(original, raw)?;
        if response.is_some() || received.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            *response = Some(
                serde_json::from_value(raw.value.clone())
                    .map_err(crucible_node_format::ContractError::from)?,
            );
            let envelope = response.as_ref().ok_or_else(invalid)?;
            // Only the pending Prepare response reaches a baseline body decoder.
            // Wrong-message/route raw data remains retained without arbitrary
            // request-method DTO construction.
            original.matches_response(envelope)?;
            let body = self.validate_body(envelope, true)?;
            *received = Some(ReceivedFrame {
                envelope: envelope.clone(),
                body,
            });
            self.retain_original_request_id(envelope, self.reader.original_slot())?;
            self.authority.with_live(|| self.guard.receive(envelope))?;
            Ok(())
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("distinct Native18 SDK assignment changed")
}

/// Names the actual borrowed bank/current-literal controls, without walking it.
pub(crate) fn pending_assignment_counter_scratch_data() -> usize {
    use std::mem::size_of;
    type Bank = crate::transport::original_frames::OriginalFrameReservation;
    type BankRef = std::cell::Ref<'static, Bank>;
    type Frame = crate::transport::original_frames::OriginalFrame<'static>;

    size_of::<BankRef>()
        + size_of::<Result<BankRef, std::cell::BorrowError>>()
        + size_of::<Frame>() * 2
        + size_of::<Option<Frame>>()
        + size_of::<(usize, Frame)>()
        + size_of::<Option<(usize, Frame)>>()
        + size_of::<Result<Frame, ProviderError>>()
        + crate::transport::original_frames::original_frames_iterator_counter_scratch_data()
        + crate::transport::original_frames::original_history_guard_counter_scratch_data()
        + size_of::<usize>() * 2
        + size_of::<&Id>()
        + size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<[u8; 4]>()
        + size_of::<Result<u32, std::num::TryFromIntError>>()
        + size_of::<Option<usize>>()
        + size_of::<&Envelope>()
        + size_of::<&[u8]>()
        + size_of::<Result<(), ProviderError>>()
}

impl<S: ProviderStream> Connection<S> {
    /// Checks the original reserved literal before its first publication attempt.
    ///
    /// Selected-contract work is already performed by the capsule's same-current
    /// guard under its funded row. This helper checks actual bank/correlation
    /// state only; no wire DTO, historical query or new authority is constructed.
    ///
    /// # Errors
    /// Refuses absent/mismatched original custody, another pending original,
    /// advanced literal roster, changed bytes, or any attempted transmission.
    pub(crate) fn authenticate_pending_native_import18_data(
        &self,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
        sealed: bool,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authority.ensure_live()?;
        if self.fenced {
            return Err(invalid());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(invalid)?
            .try_borrow()
            .map_err(|_| invalid())?;
        let slot = slot.ok_or_else(invalid)?;
        // Assignment reserves the final original slot. No later literal may be
        // appended between that reservation and this pending signing loan.
        let (last, _) = bank.frames().enumerate().last().ok_or_else(invalid)?;
        if last != slot {
            return Err(invalid());
        }
        let frame = bank.frame(slot).ok_or_else(invalid)?;
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let named = bank.original_outgoing_request_frame_data(id)?;
        if frame.direction != FrameDirection::Outgoing
            || frame.complete
            || frame.transferred != 0
            || frame.bytes != named.bytes
            || frame.direction != named.direction
            || frame.complete != named.complete
            || frame.transferred != named.transferred
        {
            return Err(invalid());
        }
        let mut pending = self.guard.pending_requests();
        if sealed {
            let length = u32::try_from(bytes.len()).map_err(|_| invalid())?;
            if bytes.is_empty()
                || !bank.matches_send(slot, &length.to_be_bytes(), bytes)
                || pending.next() != Some(original)
                || pending.next().is_some()
            {
                return Err(invalid());
            }
        } else if !bytes.is_empty() || !frame.bytes.is_empty() || pending.next().is_some() {
            return Err(invalid());
        }
        Ok(())
    }
}

#[path = "native_import18_upload.rs"]
mod input_upload;
