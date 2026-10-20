//! Authenticates the actual fresh Realize receipt from the same literal history.
//!
//! The narrow pending-restore predicate borrows originals without weakening the
//! settled public history loan or decoding another owning envelope/result DOM.

use super::*;
use crate::bodies::{PrepareRestoreResult, RealizeRequest};
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, correspondence, original_owned11_invalid as invalid,
    original_owned11_plain_string as plain_string,
};
use crate::transport::original_frames::{FrameDirection, OriginalFrame};

struct OriginalRealizeHeader<'a> {
    body: &'a [u8],
    message: &'a str,
    method: &'a str,
    scope: [&'a [u8]; 7],
}

fn complete(frame: OriginalFrame<'_>) -> Result<&[u8], ProviderError> {
    if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
        return Err(invalid());
    }
    let header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| invalid())?;
    if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
        return Err(invalid());
    }
    Ok(&frame.bytes[4..])
}

fn header(bytes: &[u8]) -> Result<OriginalRealizeHeader<'_>, ProviderError> {
    let mut f = Fields::object(bytes)?;
    let body = f.named("body")?;
    let capture = f.named("capture_owner_id")?;
    let execution = f.named("execution_owner_id")?;
    let extensions = f.named("extensions")?;
    let incarnation = f.named("incarnation_id")?;
    let message = plain_string(f.named("message")?)?;
    let method = plain_string(f.named("method")?)?;
    let node = f.named("node_id")?;
    let operation = f.named("operation_id")?;
    if plain_string(f.named("protocol")?)? != "CNP/1" {
        return Err(invalid());
    }
    let id = f.named("request_id")?;
    f.named("sequence")?;
    let session = f.named("session_id")?;
    f.finish()?;
    if method == "realize" && (extensions != b"{}" || id == b"null") {
        return Err(invalid());
    }
    Ok(OriginalRealizeHeader {
        body,
        message,
        method,
        scope: [
            capture,
            execution,
            incarnation,
            node,
            operation,
            id,
            session,
        ],
    })
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn authenticate_original_native_realize_receipt_data(
        &self,
        expected_realize: &RealizeRequest,
        expected_result: &PrepareRestoreResult,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authority.ensure_live()?;
        if self.role != EndpointRole::Provider || self.fenced
            || self.original_native5_complete_restore_selection()?
                != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            return Err(invalid());
        }
        let unsigned_slot = self.original_unsigned_restore_response_slot()?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(invalid)?
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original Realize history borrowed"))?;
        let mut original = None;
        let mut replied = false;
        for (index, frame) in bank.frames().enumerate() {
            // The sole unsigned original response is already retained before
            // the native issuer signs it. It is the only allowed empty slot.
            if unsigned_slot == Some(index) {
                if frame.direction != FrameDirection::Outgoing
                    || frame.complete
                    || frame.transferred != 0
                    || !frame.bytes.is_empty()
                {
                    return Err(invalid());
                }
                continue;
            }
            let direction = frame.direction;
            let value = header(complete(frame)?)?;
            if value.method != "realize" {
                continue;
            }
            if plain_string(value.scope[2])? != self.authority.incarnation_id().as_str()
                || plain_string(value.scope[6])? != self.authority.session_id().as_str()
            {
                return Err(invalid());
            }
            match direction {
                FrameDirection::Incoming => {
                    if original.is_some() || value.message != "request" {
                        return Err(invalid());
                    }
                    correspondence::realize_request(expected_realize, value.body)?;
                    original = Some(value);
                }
                FrameDirection::Outgoing => {
                    let request = original.as_ref().ok_or_else(invalid)?;
                    if replied || value.message != "response" || value.scope != request.scope {
                        return Err(invalid());
                    }
                    let mut body = Fields::object(value.body)?;
                    if body.named("extensions")? != b"{}"
                        || plain_string(body.named("operation_state")?)? != "completed"
                    {
                        return Err(invalid());
                    }
                    let mut result = Fields::object(body.named("result")?)?;
                    correspondence::content_reference(
                        &expected_result.closed_gate_receipt,
                        result.named("closed_gate_receipt")?,
                    )?;
                    if plain_string(result.named("prepared_token")?)?
                        != expected_result.prepared_token.as_str()
                    {
                        return Err(invalid());
                    }
                    result.named("realization_manifest")?;
                    result.finish()?;
                    if plain_string(body.named("status")?)? != "completed" {
                        return Err(invalid());
                    }
                    body.finish()?;
                    replied = true;
                }
            }
        }
        if original.is_none() || !replied {
            return Err(invalid());
        }
        Ok(())
    }
}
