//! Decodes a selectable trap before its native read buffer is returned.
//!
//! Preparation retains the complete owned declaration or request and immutable
//! callback coordinates. Service starts after the encoded snapshot is released,
//! so a pending boundary cannot retain a native guest-read allocation.

use super::*;

/// Retains a validated selectable message without borrowing its encoded bytes.
pub(crate) struct PreparedSelectableTrap {
    doorbell: PluginWhiteboxDoorbell,
    event: WhiteboxDoorbellTrapEvent,
    coordinate: SelectableCallbackCoordinate,
    message: Message,
}

enum Message {
    Register(SelectableRegister),
    Request(SelectionRequest),
}

impl PreparedSelectableTrap {
    /// Validates the snapshot and exact callback coordinate before service.
    ///
    /// # Errors
    ///
    /// Refuses disabled mode, invalid ranges or snapshot lengths, mismatched
    /// coordinates, malformed protocol bytes, and guest-supplied replies.
    pub(crate) fn decode(
        doorbell: &PluginWhiteboxDoorbell,
        event: WhiteboxDoorbellTrapEvent,
        coordinate: SelectableCallbackCoordinate,
        payload: &[u8],
    ) -> Result<Self, SelectableDoorbellError> {
        doorbell
            .validate_snapshot(event, payload)
            .map_err(SelectableDoorbellError::Doorbell)?;
        if coordinate.raw_icount() != event.current_icount()
            || coordinate.vcpu_index() != event.vcpu_index()
        {
            return Err(SelectableDoorbellError::CoordinateMismatch);
        }
        let message = match decode_selectable_message_kind(payload)? {
            SelectableMessageKind::Register => {
                Message::Register(SelectableRegister::decode(payload)?)
            }
            SelectableMessageKind::Request => Message::Request(SelectionRequest::decode(payload)?),
            SelectableMessageKind::Reply => {
                return Err(SelectableDoorbellError::GuestSuppliedReply);
            }
        };
        Ok(Self {
            doorbell: *doorbell,
            event,
            coordinate,
            message,
        })
    }

    /// Services the retained message after its encoded snapshot has returned.
    ///
    /// # Errors
    ///
    /// Preserves catalog or decision refusals, reply binding and reservation
    /// failures, and the original same-icount guest-delivery error.
    pub(crate) fn serve<S, W>(
        self,
        capability: &WhiteboxGuestInputCapability,
        service: &mut S,
        writer: &mut W,
    ) -> Result<SelectableDoorbellOutcome, SelectableDoorbellError>
    where
        S: SelectableDoorbellService + ?Sized,
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        let Self {
            doorbell,
            event,
            coordinate,
            message,
        } = self;

        match message {
            Message::Register(registration) => {
                service.register_selectable(&registration, coordinate)?;
                Ok(SelectableDoorbellOutcome::Registered {
                    registration,
                    coordinate,
                })
            }
            Message::Request(request) => {
                let disposition =
                    service.serve_selection(&request, coordinate, event.payload_range())?;
                let SelectableReplyDisposition::Reply(reply) = disposition else {
                    return Ok(SelectableDoorbellOutcome::Pending {
                        request,
                        coordinate,
                    });
                };
                if reply.sequence() != request.sequence() {
                    return Err(SelectableDoorbellError::ReplySequenceMismatch {
                        expected: request.sequence(),
                        actual: reply.sequence(),
                    });
                }
                let reply_bytes = reply.encode()?;
                if reply_bytes.len() > request.reply_capacity() {
                    return Err(SelectableDoorbellError::ReplyExceedsReservation {
                        reply_len: reply_bytes.len(),
                        capacity: request.reply_capacity(),
                    });
                }
                let mut full_buffer = vec![0; request.reply_capacity()];
                full_buffer[..reply_bytes.len()].copy_from_slice(&reply_bytes);
                let input = WhiteboxGuestInput::new(
                    event.current_icount(),
                    event.payload_range(),
                    full_buffer,
                );
                let injection = match doorbell
                    .inject_guest_input(capability, writer, event.current_icount(), &input)
                    .map_err(SelectableDoorbellError::Doorbell)?
                {
                    WhiteboxGuestInputOutcome::Delivered(injection) => injection,
                    WhiteboxGuestInputOutcome::NotReady { delivery_icount } => {
                        return Err(SelectableDoorbellError::ReplyNotDelivered { delivery_icount });
                    }
                };
                Ok(SelectableDoorbellOutcome::Replied {
                    request,
                    reply,
                    coordinate,
                    injection,
                })
            }
        }
    }
}
