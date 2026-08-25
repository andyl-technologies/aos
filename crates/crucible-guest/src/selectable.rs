//! Typed guest helpers for the selectable register/request/reply ABI.
//!
//! These helpers reuse the native doorbell transport while keeping all byte
//! ownership and protocol validation in `crucible-protocol`. A request lends
//! one fixed zero-filled buffer to the host; a conforming host replaces that
//! buffer with one exact sequence-bound reply and clears the unused tail.

use crucible_protocol::{
    SELECTION_REPLY_HEADER_BYTES, SelectableProtocolError, SelectableRegister, SelectionReply,
    SelectionReplyStatus, SelectionRequest,
};
use thiserror::Error;

use crucible_campaign::{CampaignCodecError, ChoiceDomain, ChoiceValue};

use crate::{DoorbellTransport, GuestEmitterError};

/// Result of emitting one setup-time selectable registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestSelectableRegistration {
    bytes: Vec<u8>,
}

impl GuestSelectableRegistration {
    /// Returns the exact canonical registration bytes observed by the host.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Result of one reply-bearing guest selection request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestSelection {
    request_bytes: Vec<u8>,
    reply: SelectionReply,
}

impl GuestSelection {
    /// Returns the exact request buffer before host reply delivery.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    /// Returns the fully decoded sequence-bound selection or typed rejection.
    #[must_use]
    pub const fn reply(&self) -> &SelectionReply {
        &self.reply
    }
}

/// One successful typed selection validated against the guest's declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestTypedSelection {
    exchange: GuestSelection,
    value: ChoiceValue,
}

impl GuestTypedSelection {
    /// Returns the exact request/reply exchange that carried this value.
    #[must_use]
    pub const fn exchange(&self) -> &GuestSelection {
        &self.exchange
    }

    /// Returns the decoded value after declaration-domain validation.
    #[must_use]
    pub const fn value(&self) -> &ChoiceValue {
        &self.value
    }
}

/// Builds one protocol registration from the shared typed choice model.
///
/// This is the product-facing declaration boundary. It keeps the guest and
/// coordinator on the same canonical domain/value representation instead of
/// asking applications to construct opaque protocol bytes.
///
/// # Errors
///
/// Returns [`GuestSelectableError::DefaultOutsideDomain`] when `default` is
/// not legal in `domain`, or [`GuestSelectableError::Protocol`] when the
/// resulting bounded registration is not representable by the guest ABI.
pub fn build_selectable_registration(
    sequence: u64,
    selectable_id: impl Into<String>,
    domain: &ChoiceDomain,
    default: &ChoiceValue,
    semantic_tags: Vec<String>,
) -> Result<SelectableRegister, GuestSelectableError> {
    if !domain.contains(default) {
        return Err(GuestSelectableError::DefaultOutsideDomain);
    }
    SelectableRegister::new(
        sequence,
        selectable_id,
        domain.canonical_bytes(),
        default.canonical_bytes(),
        semantic_tags,
    )
    .map_err(GuestSelectableError::from)
}

/// Emits one setup-time selectable registration through a doorbell transport.
///
/// Registration is observational at the trap boundary: the host must leave the
/// complete registration bytes unchanged. Catalog comparison and setup freeze
/// remain host-owned operations.
///
/// # Errors
///
/// Returns [`GuestSelectableError`] when canonical encoding or the doorbell
/// transport fails, or when a host incorrectly mutates registration bytes.
pub fn emit_selectable_registration<T>(
    registration: &SelectableRegister,
    transport: &mut T,
) -> Result<GuestSelectableRegistration, GuestSelectableError>
where
    T: DoorbellTransport + ?Sized,
{
    let mut bytes = registration.encode()?;
    let canonical = bytes.clone();
    transport
        .ring(&mut bytes)
        .map_err(GuestSelectableError::Transport)?;
    if bytes != canonical {
        return Err(GuestSelectableError::RegistrationMutated);
    }
    Ok(GuestSelectableRegistration { bytes: canonical })
}

/// Emits one choice request and validates the exact host reply.
///
/// The host must overwrite the beginning of the reserved request buffer with a
/// canonical [`SelectionReply`] and clear every unused byte in the reservation.
/// The reply sequence must equal the request sequence.
///
/// # Errors
///
/// Returns [`GuestSelectableError`] when request encoding or transport fails,
/// the reply header/length/tail is invalid, reply decoding fails, or the host
/// replies for a different sequence.
pub fn request_selection<T>(
    request: &SelectionRequest,
    transport: &mut T,
) -> Result<GuestSelection, GuestSelectableError>
where
    T: DoorbellTransport + ?Sized,
{
    let mut buffer = request.encode()?;
    let request_bytes = buffer.clone();
    transport
        .ring(&mut buffer)
        .map_err(GuestSelectableError::Transport)?;

    if buffer.len() < 12 {
        return Err(GuestSelectableError::ReplyHeaderTruncated {
            actual_len: buffer.len(),
        });
    }
    let total_len = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as usize;
    if total_len < SELECTION_REPLY_HEADER_BYTES || total_len > buffer.len() {
        return Err(GuestSelectableError::ReplyLengthOutOfRange {
            declared_len: total_len,
            capacity: buffer.len(),
        });
    }
    if buffer[total_len..].iter().any(|byte| *byte != 0) {
        return Err(GuestSelectableError::ReplyTailNotCleared);
    }
    let reply = SelectionReply::decode(&buffer[..total_len])?;
    if reply.sequence() != request.sequence() {
        return Err(GuestSelectableError::ReplySequenceMismatch {
            expected: request.sequence(),
            actual: reply.sequence(),
        });
    }
    Ok(GuestSelection {
        request_bytes,
        reply,
    })
}

/// Emits one selection request and validates a successful typed value.
///
/// Typed rejection replies remain explicit errors rather than being silently
/// converted to the declaration default. The guest may choose a fallback only
/// through its own application policy.
///
/// # Errors
///
/// Returns the errors documented by [`request_selection`],
/// [`GuestSelectableError::SelectionRejected`] for a host rejection,
/// [`GuestSelectableError::CampaignCodec`] for malformed canonical value
/// bytes, or [`GuestSelectableError::SelectedValueOutsideDomain`] when the
/// decoded value does not belong to `domain`.
pub fn request_typed_selection<T>(
    request: &SelectionRequest,
    domain: &ChoiceDomain,
    transport: &mut T,
) -> Result<GuestTypedSelection, GuestSelectableError>
where
    T: DoorbellTransport + ?Sized,
{
    let exchange = request_selection(request, transport)?;
    let reply = exchange.reply();
    if reply.status() != SelectionReplyStatus::Selected {
        return Err(GuestSelectableError::SelectionRejected {
            status: reply.status(),
        });
    }
    let selected = reply
        .selected_value()
        .ok_or(GuestSelectableError::SelectedValueMissing)?;
    let value = ChoiceValue::from_canonical_bytes(selected)?;
    if !domain.contains(&value) {
        return Err(GuestSelectableError::SelectedValueOutsideDomain);
    }
    Ok(GuestTypedSelection { exchange, value })
}

/// Error returned by typed guest selectable helpers.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GuestSelectableError {
    /// Canonical selectable message construction or reply decoding failed.
    #[error("guest selectable protocol failed: {source}")]
    Protocol {
        /// Underlying protocol error.
        #[from]
        source: SelectableProtocolError,
    },
    /// Campaign choice-domain or selected-value decoding failed.
    #[error("guest selectable value failed canonical validation: {source}")]
    CampaignCodec {
        /// Underlying typed choice codec error.
        #[from]
        source: CampaignCodecError,
    },
    /// The architecture-specific doorbell transport failed.
    #[error("guest selectable transport failed: {0}")]
    Transport(GuestEmitterError),
    /// An observational registration was incorrectly overwritten.
    #[error("host mutated observational selectable registration bytes")]
    RegistrationMutated,
    /// The declared default is not legal in the declared domain.
    #[error("guest selectable default is outside its declared domain")]
    DefaultOutsideDomain,
    /// The reply buffer cannot contain the common fixed header.
    #[error("selection reply buffer length {actual_len} is shorter than 12-byte common header")]
    ReplyHeaderTruncated {
        /// Available bytes.
        actual_len: usize,
    },
    /// The reply-declared message length is outside the lent buffer.
    #[error("selection reply length {declared_len} is outside reserved capacity {capacity}")]
    ReplyLengthOutOfRange {
        /// Reply-declared bytes.
        declared_len: usize,
        /// Lent mutable bytes.
        capacity: usize,
    },
    /// The host did not clear the unused tail of its reply-owned range.
    #[error("selection reply left nonzero bytes after its canonical body")]
    ReplyTailNotCleared,
    /// The reply belongs to another request sequence.
    #[error("selection reply sequence {actual} does not match request sequence {expected}")]
    ReplySequenceMismatch {
        /// Request sequence.
        expected: u64,
        /// Reply sequence.
        actual: u64,
    },
    /// The host rejected a typed selection request.
    #[error("host rejected guest selection with status {status:?}")]
    SelectionRejected {
        /// Exact stable protocol rejection.
        status: SelectionReplyStatus,
    },
    /// A selected reply omitted the canonical value body.
    #[error("selected guest reply omitted its canonical value")]
    SelectedValueMissing,
    /// The selected value is not legal in the guest's declared domain.
    #[error("host selected a value outside the guest declaration domain")]
    SelectedValueOutsideDomain,
}

#[cfg(test)]
mod tests;
