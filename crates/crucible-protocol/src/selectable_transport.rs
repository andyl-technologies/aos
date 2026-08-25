//! Plugin-to-host transport for one deferred selectable request.
//!
//! This is not the guest ABI. The guest sends a standalone
//! [`SelectionRequest`]; after retaining it and requesting VMStop, the plugin
//! publishes this process-neutral record through the plugin-to-host white-box
//! marker ring:
//!
//! ```text
//! offset  size  field
//! 0       8     magic `CRUCSPQ1`
//! 8       2     version, little-endian (`1`)
//! 10      2     header length, little-endian (`32`)
//! 12      4     total record length, little-endian
//! 16      8     guest virtual reply address, little-endian
//! 24      4     SelectionRequestV1 byte length, little-endian
//! 28      4     reserved, zero
//! 32      N     canonical SelectionRequestV1 bytes
//! ```
//!
//! The outer shared-memory marker supplies the exact retired-instruction count
//! and vCPU index. The nested request retains its complete zero-filled reply
//! reservation. Consequently this transport admits request bodies up to 4,576
//! bytes, slightly below the standalone guest ABI's 4,608-byte ceiling.

use thiserror::Error;

use crate::{SELECTABLE_MESSAGE_MAX_BYTES, SelectableProtocolError, SelectionRequest};

/// Internal SPSC entry kind for one deferred selectable request.
///
/// The value is outside the frozen guest marker-kind registry and therefore
/// cannot be confused with a guest-originated observational marker.
pub const WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING: u16 = 0xff06;

/// Magic prefix for the deferred selectable request transport.
pub const SELECTABLE_PENDING_TRANSPORT_MAGIC: [u8; 8] = *b"CRUCSPQ1";

/// Current deferred selectable request transport version.
pub const SELECTABLE_PENDING_TRANSPORT_VERSION: u16 = 1;

/// Required golden-vector maintenance rule for this transport.
pub const SELECTABLE_PENDING_TRANSPORT_REGENERATION_RULE: &str = "changing SELECTABLE_PENDING_TRANSPORT_VERSION requires regenerating the deferred-request ABI vector";

/// Fixed header bytes preceding the nested request.
pub const SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES: usize = 32;

/// Maximum nested request bytes that fit one white-box marker payload.
pub const SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES: usize =
    SELECTABLE_MESSAGE_MAX_BYTES - SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES;

/// One exact deferred request and its process-neutral reply target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectablePendingTransportRecord {
    request: SelectionRequest,
    guest_virtual_address: u64,
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
    ) -> Result<Self, SelectablePendingTransportError> {
        let request_len = request.encode()?.len();
        if request_len > SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES {
            return Err(SelectablePendingTransportError::RequestTooLarge {
                len: request_len,
                maximum: SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES,
            });
        }
        Ok(Self {
            request,
            guest_virtual_address,
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
        Self::new(request, guest_virtual_address)
    }

    /// Encodes this record for one shared-memory marker payload.
    ///
    /// # Errors
    ///
    /// Returns [`SelectablePendingTransportError`] when the nested request no
    /// longer satisfies its canonical bounds or a fixed-width length overflows.
    pub fn encode(&self) -> Result<Vec<u8>, SelectablePendingTransportError> {
        let request = self.request.encode()?;
        if request.len() > SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES {
            return Err(SelectablePendingTransportError::RequestTooLarge {
                len: request.len(),
                maximum: SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES,
            });
        }
        let total_len = SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES
            .checked_add(request.len())
            .ok_or(SelectablePendingTransportError::LengthOverflow)?;
        let total_len = u32::try_from(total_len)
            .map_err(|_source| SelectablePendingTransportError::LengthOverflow)?;
        let request_len = u32::try_from(request.len())
            .map_err(|_source| SelectablePendingTransportError::LengthOverflow)?;

        let mut bytes = vec![0; SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES];
        bytes[..8].copy_from_slice(&SELECTABLE_PENDING_TRANSPORT_MAGIC);
        bytes[8..10].copy_from_slice(&SELECTABLE_PENDING_TRANSPORT_VERSION.to_le_bytes());
        bytes[10..12]
            .copy_from_slice(&(SELECTABLE_PENDING_TRANSPORT_HEADER_BYTES as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&total_len.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.guest_virtual_address.to_le_bytes());
        bytes[24..28].copy_from_slice(&request_len.to_le_bytes());
        bytes.extend_from_slice(&request);
        Ok(bytes)
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
    /// The transport magic did not match the v1 namespace.
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
        let record = SelectablePendingTransportRecord::new(request(256)?, 0xfeed_2000)?;
        let encoded = record.encode()?;
        assert_eq!(SelectablePendingTransportRecord::decode(&encoded)?, record);
        assert_eq!(&encoded[..8], &SELECTABLE_PENDING_TRANSPORT_MAGIC);
        assert_eq!(record.guest_virtual_address(), 0xfeed_2000);
        assert_eq!(record.request().sequence(), 71);
        Ok(())
    }

    #[test]
    fn transport_bound_is_stricter_than_standalone_guest_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let boundary = SelectablePendingTransportRecord::new(
            request(SELECTABLE_PENDING_TRANSPORT_MAX_REQUEST_BYTES)?,
            0x1000,
        )?;
        assert_eq!(boundary.encode()?.len(), SELECTABLE_MESSAGE_MAX_BYTES);

        let request = request(SELECTABLE_MESSAGE_MAX_BYTES)?;
        assert_eq!(request.encode()?.len(), SELECTABLE_MESSAGE_MAX_BYTES);
        assert!(matches!(
            SelectablePendingTransportRecord::new(request, 0x1000),
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
        let record = SelectablePendingTransportRecord::new(request(256)?, 0x4000)?;
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
