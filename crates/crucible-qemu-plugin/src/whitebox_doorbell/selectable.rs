//! Safe callback core for guest selectable registration and choice replies.
//!
//! This module owns no campaign policy. It decodes the permissive process ABI,
//! delegates catalog and decision authority to a typed service, and routes one
//! exact request-sized reply through the existing same-icount guest-input gate.

use crucible_protocol::{
    SelectableMessageKind, SelectableProtocolError, SelectableRegister, SelectionReply,
    SelectionRequest, decode_selectable_message_kind,
};
use thiserror::Error;

use super::{
    GuestMemoryRange, GuestMemoryReader, PluginWhiteboxDoorbell, WhiteboxDoorbellError,
    WhiteboxDoorbellTrapEvent, WhiteboxGuestInput, WhiteboxGuestInputCapability,
    WhiteboxGuestInputInjection, WhiteboxGuestInputOutcome, WhiteboxGuestInputWriter,
    read_doorbell_payload,
};

mod catalog;
pub use catalog::{
    CatalogedSelectableService, SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS,
    SELECTABLE_CATALOG_HARD_MAX_REQUESTS, SelectableCatalog, SelectableCatalogError,
    SelectableCatalogExpectation, SelectableCatalogFreeze, SelectableCatalogLimits,
    SelectableCatalogPhase, SelectableDecisionAuthority, SelectableExpectedDeclaration,
    SelectableExpectedPresence, SelectablePendingRequest,
};

/// Exact execution coordinate attached to one selectable callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectableCallbackCoordinate {
    icount: u64,
    vcpu_index: u32,
}

impl SelectableCallbackCoordinate {
    /// Builds one exact callback coordinate for authenticated continuation state.
    #[must_use]
    pub const fn new(icount: u64, vcpu_index: u32) -> Self {
        Self { icount, vcpu_index }
    }

    /// Returns the aggregate instruction count at the guest doorbell.
    #[must_use]
    pub const fn icount(self) -> u64 {
        self.icount
    }

    /// Returns the vCPU that executed the guest doorbell.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }
}

impl From<WhiteboxDoorbellTrapEvent> for SelectableCallbackCoordinate {
    fn from(event: WhiteboxDoorbellTrapEvent) -> Self {
        Self::new(event.current_icount(), event.vcpu_index())
    }
}

/// Authority that admits setup-time selectable registrations.
pub trait SelectableRegistrationService {
    /// Validates and records one guest declaration before catalog freeze.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableDoorbellServiceError`] when the registration is
    /// late, duplicated, outside scenario bounds, or conflicts with the
    /// launch-authenticated expected catalog.
    fn register_selectable(
        &mut self,
        registration: &SelectableRegister,
        coordinate: SelectableCallbackCoordinate,
    ) -> Result<(), SelectableDoorbellServiceError>;
}

/// Authority that resolves one runtime selectable request.
pub trait SelectableReplyService {
    /// Validates one frozen-catalog request and either replies or retains it.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableDoorbellServiceError`] when catalog, narrowing,
    /// instance, selection, or continuation authority cannot serve the request.
    fn serve_selection(
        &mut self,
        request: &SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
        reply_range: GuestMemoryRange,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError>;
}

/// Whether choice authority completed or retained one admitted request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectableReplyDisposition {
    /// The exact sequence-bound reply is ready for same-icount delivery.
    Reply(SelectionReply),
    /// The authority retained the request at a VM-stop/checkpoint boundary.
    Pending,
}

impl From<SelectionReply> for SelectableReplyDisposition {
    fn from(reply: SelectionReply) -> Self {
        Self::Reply(reply)
    }
}

/// Complete selectable callback authority.
pub trait SelectableDoorbellService:
    SelectableRegistrationService + SelectableReplyService
{
}

impl<T> SelectableDoorbellService for T where
    T: SelectableRegistrationService + SelectableReplyService + ?Sized
{
}

/// Handles one register or request message at the exact doorbell coordinate.
///
/// Registration bytes are observational and remain unchanged. A request is
/// decoded with its complete zero-filled reply reservation, delegated to the
/// supplied authority, and either retained untouched at a pending boundary or
/// replaced by one canonical reply followed by zeros. Guest-supplied reply
/// messages are rejected.
///
/// # Errors
///
/// Returns [`SelectableDoorbellError`] when guest-memory access, message
/// decoding, catalog/decision service, reply binding, or same-icount delivery
/// fails.
pub fn handle_whitebox_selectable_callback<R, S, W>(
    doorbell: &PluginWhiteboxDoorbell,
    capability: &WhiteboxGuestInputCapability,
    reader: &mut R,
    service: &mut S,
    writer: &mut W,
    event: WhiteboxDoorbellTrapEvent,
) -> Result<SelectableDoorbellOutcome, SelectableDoorbellError>
where
    R: GuestMemoryReader + ?Sized,
    S: SelectableDoorbellService + ?Sized,
    W: WhiteboxGuestInputWriter + ?Sized,
{
    let payload = read_doorbell_payload(doorbell, reader, event)
        .map_err(SelectableDoorbellError::Doorbell)?;
    let coordinate = SelectableCallbackCoordinate::from(event);
    match decode_selectable_message_kind(&payload)? {
        SelectableMessageKind::Register => {
            let registration = SelectableRegister::decode(&payload)?;
            service.register_selectable(&registration, coordinate)?;
            Ok(SelectableDoorbellOutcome::Registered {
                registration,
                coordinate,
            })
        }
        SelectableMessageKind::Request => {
            let request = SelectionRequest::decode(&payload)?;
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
            let input =
                WhiteboxGuestInput::new(event.current_icount(), event.payload_range(), full_buffer);
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
        SelectableMessageKind::Reply => Err(SelectableDoorbellError::GuestSuppliedReply),
    }
}

/// Result of one successfully serviced selectable doorbell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectableDoorbellOutcome {
    /// A setup-time declaration was admitted without mutating guest memory.
    Registered {
        /// Exact decoded registration.
        registration: SelectableRegister,
        /// Trap coordinate attached to the registration.
        coordinate: SelectableCallbackCoordinate,
    },
    /// A request was retained without making its reply reservation visible.
    Pending {
        /// Exact decoded request and zero-filled reply reservation.
        request: SelectionRequest,
        /// Trap coordinate at which the guest is stopped.
        coordinate: SelectableCallbackCoordinate,
    },
    /// A runtime request received one exact same-icount reply.
    Replied {
        /// Exact decoded request and reply reservation.
        request: SelectionRequest,
        /// Exact authority-produced reply.
        reply: SelectionReply,
        /// Trap coordinate attached to the opportunity.
        coordinate: SelectableCallbackCoordinate,
        /// Guest-memory write evidence.
        injection: WhiteboxGuestInputInjection,
    },
}

/// Stable failure from the catalog or decision authority.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("selectable service failed: {message}")]
pub struct SelectableDoorbellServiceError {
    message: String,
}

impl SelectableDoorbellServiceError {
    /// Builds one service failure without exposing host-private state.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the stable service diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Failure while dispatching one selectable doorbell message.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectableDoorbellError {
    /// The shared doorbell read or same-icount injection contract failed.
    #[error("white-box doorbell failed while serving a selectable: {0}")]
    Doorbell(WhiteboxDoorbellError),
    /// The standalone selectable message was not canonical.
    #[error("guest selectable message failed validation: {0}")]
    Protocol(#[from] SelectableProtocolError),
    /// The scenario/catalog/decision authority rejected the operation.
    #[error(transparent)]
    Service(#[from] SelectableDoorbellServiceError),
    /// A guest attempted to send the host-owned reply kind.
    #[error("guest supplied host-owned selectable reply message kind")]
    GuestSuppliedReply,
    /// The authority returned a reply for another request sequence.
    #[error("selectable reply sequence {actual} does not match request sequence {expected}")]
    ReplySequenceMismatch {
        /// Request sequence.
        expected: u64,
        /// Reply sequence.
        actual: u64,
    },
    /// The canonical reply does not fit the exact lent reservation.
    #[error("selectable reply length {reply_len} exceeds reservation {capacity}")]
    ReplyExceedsReservation {
        /// Encoded reply bytes.
        reply_len: usize,
        /// Request-lent bytes.
        capacity: usize,
    },
    /// The existing delivery gate did not write at the trap icount.
    #[error("selectable reply was not delivered at icount {delivery_icount}")]
    ReplyNotDelivered {
        /// Still-pending delivery coordinate.
        delivery_icount: u64,
    },
}

#[cfg(test)]
mod tests;
