//! Decodes a selectable trap before its native read buffer is returned.
//!
//! Preparation retains the complete owned declaration or request and immutable
//! callback coordinates. Service starts after the encoded snapshot is released,
//! so a pending boundary cannot retain a native guest-read allocation.

use crucible_qemu_protocol::SELECTABLE_MESSAGE_MAX_BYTES;

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
        self.serve_with_storage(capability, service, writer, None)
    }

    /// Services a trap using the containing runtime's fixed reply workspace.
    ///
    /// The exact protocol maximum makes every valid guest reservation fit.
    /// Pending and registration paths leave the workspace unchanged. Replies
    /// clear their full reservation and preserve all bytes outside that prefix.
    ///
    /// # Errors
    /// Preserves the same service, protocol and delivery refusals as `serve`.
    pub(crate) fn serve_with_reply_buffer<S, W>(
        self,
        capability: &WhiteboxGuestInputCapability,
        service: &mut S,
        writer: &mut W,
        buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<SelectableDoorbellOutcome, SelectableDoorbellError>
    where
        S: SelectableDoorbellService + ?Sized,
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        self.serve_with_storage(capability, service, writer, Some(buffer))
    }

    fn serve_with_storage<S, W>(
        self,
        capability: &WhiteboxGuestInputCapability,
        service: &mut S,
        writer: &mut W,
        buffer: Option<&mut [u8; SELECTABLE_MESSAGE_MAX_BYTES]>,
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
                let reply_len = reply.encoded_len()?;
                if reply_len > request.reply_capacity() {
                    return Err(SelectableDoorbellError::ReplyExceedsReservation {
                        reply_len,
                        capacity: request.reply_capacity(),
                    });
                }
                let mut owned_buffer;
                let full_buffer = match buffer {
                    Some(buffer) => {
                        let full_buffer = buffer.get_mut(..request.reply_capacity()).ok_or(
                            SelectableProtocolError::ReplyCapacityTooSmall {
                                capacity: SELECTABLE_MESSAGE_MAX_BYTES,
                                minimum: request.reply_capacity(),
                            },
                        )?;
                        full_buffer.fill(0);
                        full_buffer
                    }
                    None => {
                        owned_buffer = vec![0; request.reply_capacity()];
                        owned_buffer.as_mut_slice()
                    }
                };
                reply.encode_into(full_buffer)?;
                let injection = match doorbell
                    .inject_guest_input_slice(
                        capability,
                        writer,
                        event.current_icount(),
                        event.current_icount(),
                        event.payload_range(),
                        full_buffer,
                    )
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
