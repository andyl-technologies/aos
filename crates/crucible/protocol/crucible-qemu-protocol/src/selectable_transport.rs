//! Process-neutral selectable catalog delta transport.
//!
//! This is not the guest ABI. The guest sends a standalone
//! [`SelectionRequest`]; after retaining it and requesting VMStop, the plugin
//! publishes this process-neutral record through the plugin-to-host white-box
//! marker ring:
//!
//! ```text
//! offset  size  field
//! 0       8     magic `CRUCSPQ2`
//! 8       2     version, little-endian (`2`)
//! 10      2     header length, little-endian (`40`)
//! 12      4     total record length, little-endian
//! 16      8     guest virtual reply address, little-endian
//! 24      4     SelectionRequestV1 byte length, little-endian
//! 28      4     reserved, zero
//! 32      8     raw pre-instruction retirement count, little-endian
//! 40      N     canonical SelectionRequestV1 bytes
//! ```
//!
//! The outer shared-memory marker supplies the pre-instruction simulation tick
//! in picoseconds and vCPU index. The distinct raw retirement count retains
//! replay identity. The nested request retains its complete zero-filled reply
//! reservation. Consequently this transport admits request bodies up to 4,568
//! bytes, slightly below the standalone guest ABI's 4,608-byte ceiling.
//!
//! Two additional internal marker kinds carry an already-canonical
//! [`crate::SelectableRegister`] after plugin admission and the exact
//! [`crate::SelectionReply`] after same-icount guest delivery. Together with
//! the pending record and ordinary setup-complete marker, these deltas maintain
//! the host-owned checkpoint mirror without defining another aggregate codec.

use thiserror::Error;

use crate::{SELECTABLE_MESSAGE_MAX_BYTES, SelectableProtocolError, SelectionRequest};

/// Internal SPSC entry kind for one deferred selectable request.
///
/// The value is outside the frozen guest marker-kind registry and therefore
/// cannot be confused with a guest-originated observational marker.
pub const WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING: u16 = 0xff06;

/// Internal SPSC entry kind for one host-authorized selectable reply.
///
/// The reply travels through the directionally separate current-ABI ring and its
/// payload is one canonical [`crate::SelectionReply`].
pub const WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY: u16 = 0xff07;

/// Internal SPSC entry kind for one catalog registration admitted by the plugin.
///
/// The payload is one canonical [`crate::SelectableRegister`]. The host uses
/// it to mirror the exact plugin catalog before checkpointing.
pub const WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED: u16 = 0xff08;

/// Internal SPSC entry kind for one selectable reply consumed by the plugin.
///
/// The payload is the canonical [`crate::SelectionReply`] that was written to
/// guest memory and charged to the plugin catalog.
pub const WHITEBOX_SHMEM_KIND_SELECTABLE_COMPLETED: u16 = 0xff09;

/// Magic prefix for the deferred selectable request transport.
pub const SELECTABLE_PENDING_TRANSPORT_MAGIC: [u8; 8] = *b"CRUCSPQ2";

/// Current deferred selectable request transport version.
pub const SELECTABLE_PENDING_TRANSPORT_VERSION: u16 = 2;

/// Required golden-vector maintenance rule for this transport.
pub const SELECTABLE_PENDING_TRANSPORT_REGENERATION_RULE: &str = "changing SELECTABLE_PENDING_TRANSPORT_VERSION requires regenerating the deferred-request ABI vector";

/// Fixed header bytes preceding the nested request.
pub const SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES: usize = 40;

/// Maximum nested request bytes that fit one white-box marker payload.
pub const SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES: usize =
    SELECTABLE_MESSAGE_MAX_BYTES - SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES;

/// One exact deferred request and its process-neutral reply target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectablePendingTransportRecord {
    request: SelectionRequest,
    guest_virtual_address: u64,
    raw_icount: u64,
}

impl SelectablePendingTransportRecord {
    /// Builds one bounded deferred-request transport record.
    ///
    /// # Errors
    ///
    /// Returns [`SelectablePendingTransportError`] when the canonical nested
    /// request exceeds the marker transport profile.
    pub fn new(
        request: SelectionRequest,
        guest_virtual_address: u64,
        raw_icount: u64,
    ) -> Result<Self, SelectablePendingTransportError> {
        SelectablePendingTransportView::new(&request, guest_virtual_address, raw_icount)?;
        Ok(Self {
            request,
            guest_virtual_address,
            raw_icount,
        })
    }

    /// Decodes one complete plugin-to-host deferred-request record.
    ///
    /// # Errors
    ///
    /// Returns [`SelectablePendingTransportError`] for malformed fixed fields,
    /// unsupported versions, noncanonical lengths, nonzero reserved bytes, or
    /// an invalid nested request.
    pub fn decode(bytes: &[u8]) -> Result<Self, SelectablePendingTransportError> {
        if bytes.len() < SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES {
            return Err(SelectablePendingTransportError::Truncated {
                len: bytes.len(),
                minimum: SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES,
            });
        }
        if bytes[..8] != SELECTABLE_PENDING_TRANSPORT_MAGIC {
            return Err(SelectablePendingTransportError::InvalidMagic);
        }
        let version = read_u16(bytes, 8);
        if version != SELECTABLE_PENDING_TRANSPORT_VERSION {
            return Err(SelectablePendingTransportError::UnsupportedVersion {
                expected: SELECTABLE_PENDING_TRANSPORT_VERSION,
                actual: version,
            });
        }
        let header_len = usize::from(read_u16(bytes, 10));
        if header_len != SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES {
            return Err(SelectablePendingTransportError::HeaderLengthMismatch {
                expected: SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES,
                actual: header_len,
            });
        }
        let declared_len = read_u32(bytes, 12) as usize;
        if declared_len != bytes.len() {
            return Err(SelectablePendingTransportError::LengthMismatch {
                declared: declared_len,
                actual: bytes.len(),
            });
        }
        let guest_virtual_address = read_u64(bytes, 16);
        let request_len = read_u32(bytes, 24) as usize;
        if read_u32(bytes, 28) != 0 {
            return Err(SelectablePendingTransportError::NonzeroReserved);
        }
        if request_len > SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES {
            return Err(SelectablePendingTransportError::RequestTooLarge {
                len: request_len,
                maximum: SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES,
            });
        }
        let expected_len = SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES
            .checked_add(request_len)
            .ok_or(SelectablePendingTransportError::LengthOverflow)?;
        if expected_len != bytes.len() {
            return Err(SelectablePendingTransportError::NestedLengthMismatch {
                request_len,
                actual_payload_len: bytes
                    .len()
                    .saturating_sub(SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES),
            });
        }
        let request =
            SelectionRequest::decode(&bytes[SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES..])?;
        let raw_icount = read_u64(bytes, 32);
        Self::new(request, guest_virtual_address, raw_icount)
    }

    /// Encodes this record for one shared-memory marker payload.
    ///
    /// # Errors
    ///
    /// Returns [`SelectablePendingTransportError`] when the nested request no
    /// longer satisfies its canonical bounds or a fixed-width length overflows.
    pub fn encode(&self) -> Result<Vec<u8>, SelectablePendingTransportError> {
        let mut bytes = vec![0; self.encoded_len()?];
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Borrows this record's request and exact reply target without copying them.
    #[must_use]
    pub const fn as_view(&self) -> SelectablePendingTransportView<'_> {
        SelectablePendingTransportView {
            request: &self.request,
            guest_virtual_address: self.guest_virtual_address,
            raw_icount: self.raw_icount,
        }
    }

    /// Returns the canonical record length without serializing the request.
    ///
    /// # Errors
    /// Returns the same validation and transport-bound refusals as
    /// [`SelectablePendingTransportView::encoded_len`].
    pub fn encoded_len(&self) -> Result<usize, SelectablePendingTransportError> {
        self.as_view().encoded_len()
    }

    /// Encodes the record and nested reservation into caller-owned storage.
    ///
    /// Returns the written prefix length and preserves the remaining suffix.
    /// All validation and capacity checks precede writes. This method allocates
    /// no storage and leaves the destination unchanged on refusal.
    ///
    /// # Errors
    /// Returns the same validation and capacity refusals as
    /// [`SelectablePendingTransportView::encode_into`].
    pub fn encode_into(
        &self,
        destination: &mut [u8],
    ) -> Result<usize, SelectablePendingTransportError> {
        self.as_view().encode_into(destination)
    }

    /// Returns the complete guest request and zero-filled reply reservation.
    #[must_use]
    pub const fn request(&self) -> &SelectionRequest {
        &self.request
    }

    /// Returns the exact guest virtual address of the reply reservation.
    #[must_use]
    pub const fn guest_virtual_address(&self) -> u64 {
        self.guest_virtual_address
    }

    /// Returns the raw retirement count before the guest doorbell instruction.
    #[must_use]
    pub const fn raw_icount(&self) -> u64 {
        self.raw_icount
    }
}

/// Borrows one deferred request and its process-neutral reply target.
///
/// The request remains owned by its caller, for example the live selectable
/// catalog. Encoding writes the same canonical bytes as
/// [`SelectablePendingTransportRecord`] without cloning the request's strings,
/// domains or tag. The borrow prevents mutation during validation and encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectablePendingTransportView<'request> {
    request: &'request SelectionRequest,
    guest_virtual_address: u64,
    raw_icount: u64,
}

impl<'request> SelectablePendingTransportView<'request> {
    /// Borrows one request after checking the deferred transport's bounds.
    ///
    /// This constructor neither copies nor serializes the request.
    ///
    /// # Errors
    /// Returns [`SelectablePendingTransportError`] when the nested request is
    /// invalid or exceeds the marker transport profile.
    pub fn new(
        request: &'request SelectionRequest,
        guest_virtual_address: u64,
        raw_icount: u64,
    ) -> Result<Self, SelectablePendingTransportError> {
        let view = Self {
            request,
            guest_virtual_address,
            raw_icount,
        };
        view.encoded_len()?;
        Ok(view)
    }

    /// Returns the canonical record length without serializing the request.
    ///
    /// # Errors
    /// Returns [`SelectablePendingTransportError`] when the nested request is
    /// invalid or exceeds this transport's stricter message bound.
    pub fn encoded_len(&self) -> Result<usize, SelectablePendingTransportError> {
        let request_len = self.request.encoded_len()?;
        if request_len > SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES {
            return Err(SelectablePendingTransportError::RequestTooLarge {
                len: request_len,
                maximum: SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES,
            });
        }
        SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES
            .checked_add(request_len)
            .ok_or(SelectablePendingTransportError::LengthOverflow)
    }

    /// Encodes the record and nested reservation into caller-owned storage.
    ///
    /// Returns the written prefix length and preserves the remaining suffix.
    /// All validation and capacity checks precede writes. This method allocates
    /// no storage and leaves the destination unchanged on refusal.
    ///
    /// # Errors
    /// Returns [`SelectablePendingTransportError`] for an invalid nested request,
    /// exceeded transport bounds or insufficient destination capacity.
    pub fn encode_into(
        &self,
        destination: &mut [u8],
    ) -> Result<usize, SelectablePendingTransportError> {
        let total_len = self.encoded_len()?;
        if destination.len() < total_len {
            return Err(SelectablePendingTransportError::Selectable(
                SelectableProtocolError::ReplyCapacityTooSmall {
                    capacity: destination.len(),
                    minimum: total_len,
                },
            ));
        }

        let bytes = &mut destination[..total_len];
        let (header, request) = bytes.split_at_mut(SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES);
        // The same immutable request and exact capacity were validated above;
        // nested encoding cannot fail after any destination byte is changed.
        self.request.encode_into(request)?;
        header.fill(0);
        header[..8].copy_from_slice(&SELECTABLE_PENDING_TRANSPORT_MAGIC);
        header[8..10].copy_from_slice(&SELECTABLE_PENDING_TRANSPORT_VERSION.to_le_bytes());
        header[10..12]
            .copy_from_slice(&(SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES as u16).to_le_bytes());
        header[12..16].copy_from_slice(&(total_len as u32).to_le_bytes());
        header[16..24].copy_from_slice(&self.guest_virtual_address.to_le_bytes());
        header[24..28].copy_from_slice(&(request.len() as u32).to_le_bytes());
        header[32..40].copy_from_slice(&self.raw_icount.to_le_bytes());
        Ok(total_len)
    }

    /// Returns the caller-owned request and zero-filled reply reservation.
    #[must_use]
    pub const fn request(&self) -> &'request SelectionRequest {
        self.request
    }

    /// Returns the exact guest virtual address of the reply reservation.
    #[must_use]
    pub const fn guest_virtual_address(&self) -> u64 {
        self.guest_virtual_address
    }

    /// Returns the raw retirement count before the guest doorbell instruction.
    #[must_use]
    pub const fn raw_icount(&self) -> u64 {
        self.raw_icount
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Invalid deferred selectable request transport bytes.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectablePendingTransportError {
    /// The fixed transport header was missing.
    #[error("selectable pending record has {len} bytes, expected at least {minimum}")]
    Truncated {
        /// Actual record bytes.
        len: usize,
        /// Minimum fixed-header bytes.
        minimum: usize,
    },
    /// The transport magic did not match the v2 namespace.
    #[error("selectable pending record magic is invalid")]
    InvalidMagic,
    /// The record used an unsupported transport version.
    #[error("selectable pending transport version {actual} does not match expected {expected}")]
    UnsupportedVersion {
        /// Supported version.
        expected: u16,
        /// Observed version.
        actual: u16,
    },
    /// The fixed header length was noncanonical.
    #[error("selectable pending header length {actual} does not match expected {expected}")]
    HeaderLengthMismatch {
        /// Canonical header bytes.
        expected: usize,
        /// Observed header bytes.
        actual: usize,
    },
    /// The outer total length did not consume the complete record.
    #[error("selectable pending record length {declared} does not match actual {actual}")]
    LengthMismatch {
        /// Header-declared record bytes.
        declared: usize,
        /// Supplied record bytes.
        actual: usize,
    },
    /// The nested length did not consume the complete payload.
    #[error(
        "selectable pending request length {request_len} does not match payload {actual_payload_len}"
    )]
    NestedLengthMismatch {
        /// Header-declared request bytes.
        request_len: usize,
        /// Supplied bytes following the fixed header.
        actual_payload_len: usize,
    },
    /// A reserved field was nonzero.
    #[error("selectable pending reserved field is nonzero")]
    NonzeroReserved,
    /// The nested request cannot fit the shared-memory marker profile.
    #[error("selectable pending request length {len} exceeds maximum {maximum}")]
    RequestTooLarge {
        /// Canonical nested request bytes.
        len: usize,
        /// Maximum nested request bytes.
        maximum: usize,
    },
    /// Length arithmetic or fixed-width conversion overflowed.
    #[error("selectable pending transport length arithmetic overflowed")]
    LengthOverflow,
    /// The nested request was not canonical selectable-v1 bytes.
    #[error("selectable pending request is invalid: {0}")]
    Selectable(#[from] SelectableProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(capacity: usize) -> Result<SelectionRequest, SelectableProtocolError> {
        SelectionRequest::new(71, "network.policy", "epoch/9", Some(vec![2, 3]), capacity)
    }

    #[test]
    fn pending_request_round_trips_with_exact_reply_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = SelectablePendingTransportRecord::new(request(256)?, 0xfeed_2000, 17)?;
        let encoded = record.encode()?;
        assert_eq!(SelectablePendingTransportRecord::decode(&encoded)?, record);
        assert_eq!(&encoded[..8], &SELECTABLE_PENDING_TRANSPORT_MAGIC);
        assert_eq!(record.encoded_len()?, encoded.len());
        let view = SelectablePendingTransportView::new(
            record.request(),
            record.guest_virtual_address(),
            record.raw_icount(),
        )?;
        assert!(std::ptr::eq(view.request(), record.request()));
        assert_eq!(view, record.as_view());
        assert_eq!(view.encoded_len()?, encoded.len());
        assert_eq!(view.guest_virtual_address(), 0xfeed_2000);
        assert_eq!(view.raw_icount(), 17);

        let mut destination = [0xa5; 320];
        let written = record.encode_into(&mut destination)?;
        assert_eq!(written, encoded.len());
        assert_eq!(&destination[..written], encoded);
        assert!(destination[written..].iter().all(|byte| *byte == 0xa5));
        destination.fill(0xa5);
        assert_eq!(view.encode_into(&mut destination)?, written);
        assert_eq!(&destination[..written], encoded);
        assert!(destination[written..].iter().all(|byte| *byte == 0xa5));

        let mut insufficient = [0xa5; 295];
        assert_eq!(
            record.encode_into(&mut insufficient),
            Err(SelectablePendingTransportError::Selectable(
                SelectableProtocolError::ReplyCapacityTooSmall {
                    capacity: 295,
                    minimum: 296,
                }
            ))
        );
        assert_eq!(insufficient, [0xa5; 295]);
        assert_eq!(
            view.encode_into(&mut insufficient),
            record.encode_into(&mut insufficient)
        );
        assert_eq!(insufficient, [0xa5; 295]);
        assert_eq!(record.guest_virtual_address(), 0xfeed_2000);
        assert_eq!(record.request().sequence(), 71);
        assert_eq!(record.raw_icount(), 17);
        let mut legacy = encoded.clone();
        legacy[..8].copy_from_slice(b"CRUCSPQ1");
        assert_eq!(
            SelectablePendingTransportRecord::decode(&legacy),
            Err(SelectablePendingTransportError::InvalidMagic)
        );
        Ok(())
    }

    #[test]
    fn transport_bound_is_stricter_than_standalone_guest_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let boundary = SelectablePendingTransportRecord::new(
            request(SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES)?,
            0x1000,
            17,
        )?;
        assert_eq!(boundary.encode()?.len(), SELECTABLE_MESSAGE_MAX_BYTES);
        let mut destination = [0xa5; SELECTABLE_MESSAGE_MAX_BYTES];
        assert_eq!(boundary.encode_into(&mut destination)?, destination.len());
        assert_eq!(destination.as_slice(), boundary.encode()?);
        let view = SelectablePendingTransportView::new(boundary.request(), 0x1000, 17)?;
        destination.fill(0xa5);
        assert_eq!(view.encode_into(&mut destination)?, destination.len());
        assert_eq!(destination.as_slice(), boundary.encode()?);

        let oversized = SelectablePendingTransportRecord {
            request: request(SELECTABLE_MESSAGE_MAX_BYTES)?,
            guest_virtual_address: 0x1000,
            raw_icount: 17,
        };
        let before = destination;
        assert_eq!(
            oversized.encode().unwrap_err(),
            oversized.encoded_len().unwrap_err()
        );
        assert_eq!(
            oversized.encode_into(&mut destination).unwrap_err(),
            oversized.encoded_len().unwrap_err()
        );
        assert_eq!(destination, before);
        assert_eq!(
            oversized
                .as_view()
                .encode_into(&mut destination)
                .unwrap_err(),
            oversized.encoded_len().unwrap_err()
        );
        assert_eq!(destination, before);
        assert_eq!(
            SelectablePendingTransportView::new(oversized.request(), 0x1000, 17).unwrap_err(),
            oversized.encoded_len().unwrap_err()
        );

        let request = request(SELECTABLE_MESSAGE_MAX_BYTES)?;
        assert_eq!(request.encode()?.len(), SELECTABLE_MESSAGE_MAX_BYTES);
        assert!(matches!(
            SelectablePendingTransportRecord::new(request, 0x1000, 17),
            Err(SelectablePendingTransportError::RequestTooLarge {
                len: SELECTABLE_MESSAGE_MAX_BYTES,
                maximum: SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES,
            })
        ));
        Ok(())
    }

    #[test]
    fn decoder_rejects_reserved_and_nested_length_mutations()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = SelectablePendingTransportRecord::new(request(256)?, 0x4000, 17)?;
        let mut reserved = record.encode()?;
        reserved[28] = 1;
        assert_eq!(
            SelectablePendingTransportRecord::decode(&reserved),
            Err(SelectablePendingTransportError::NonzeroReserved)
        );

        let mut nested = record.encode()?;
        nested[24..28].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            SelectablePendingTransportRecord::decode(&nested),
            Err(SelectablePendingTransportError::NestedLengthMismatch { .. })
        ));
        Ok(())
    }
}
