//! Shared white-box doorbell frame ABI.
//!
//! The doorbell frame sits above the architecture-specific trap instruction and
//! is the same for every guest architecture:
//!
//! ```text
//! offset  size  field
//! 0       4     magic: u32 little-endian (`CRBL`)
//! 4       2     version: u16 little-endian
//! 6       2     kind: u16 little-endian
//! 8       4     payload_len: u32 little-endian
//! 12      N     payload bytes, where N == payload_len
//! ```

use thiserror::Error;

/// Fixed little-endian doorbell frame magic (`CRBL`).
pub const WHITEBOX_DOORBELL_FRAME_MAGIC: u32 = 0x4c42_5243;
/// Current architecture-independent white-box doorbell frame version.
pub const WHITEBOX_DOORBELL_PROTOCOL_VERSION: u16 = 2;
/// Fixed byte length of the architecture-independent doorbell frame header.
pub const WHITEBOX_DOORBELL_FRAME_HEADER_LEN: usize = 12;
/// Rule for regenerating the doorbell frame golden-vector corpus.
pub const WHITEBOX_DOORBELL_FRAME_REGENERATION_RULE: &str = "Regenerate every white-box doorbell frame golden vector whenever WHITEBOX_DOORBELL_PROTOCOL_VERSION changes.";

/// A decoded architecture-independent white-box doorbell frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellFrame {
    kind: u16,
    payload: Vec<u8>,
}

impl WhiteboxDoorbellFrame {
    /// Builds a doorbell frame from a marker kind and body bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellFrameEncodeError::PayloadTooLarge`] when the
    /// payload cannot fit in the fixed `u32` payload-length field.
    pub fn new(kind: u16, payload: &[u8]) -> Result<Self, WhiteboxDoorbellFrameEncodeError> {
        validate_payload_len(payload.len())?;
        Ok(Self {
            kind,
            payload: payload.to_vec(),
        })
    }

    /// Decodes one fixed-header little-endian doorbell frame.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellFrameDecodeError`] when the frame has a bad
    /// magic, unsupported version, mismatched payload length, or truncated header.
    pub fn decode(bytes: &[u8]) -> Result<Self, WhiteboxDoorbellFrameDecodeError> {
        Self::decode_bounded(bytes, u32::MAX as usize)
    }

    /// Decodes one doorbell frame with an explicit payload allocation bound.
    ///
    /// The bound is checked against the header-declared payload length before
    /// copying the payload into the decoded frame, so malformed guest input
    /// cannot request an allocation larger than the caller's trap-time read
    /// budget.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellFrameDecodeError`] when the frame has a bad
    /// magic, unsupported version, payload length above `max_payload_len`,
    /// mismatched payload length, or truncated header.
    pub fn decode_bounded(
        bytes: &[u8],
        max_payload_len: usize,
    ) -> Result<Self, WhiteboxDoorbellFrameDecodeError> {
        if bytes.len() < WHITEBOX_DOORBELL_FRAME_HEADER_LEN {
            return Err(WhiteboxDoorbellFrameDecodeError::TruncatedFrame {
                len: bytes.len(),
                minimum_len: WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
            });
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != WHITEBOX_DOORBELL_FRAME_MAGIC {
            return Err(WhiteboxDoorbellFrameDecodeError::BadMagic {
                expected: WHITEBOX_DOORBELL_FRAME_MAGIC,
                actual: magic,
            });
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != WHITEBOX_DOORBELL_PROTOCOL_VERSION {
            return Err(WhiteboxDoorbellFrameDecodeError::UnsupportedVersion {
                expected: WHITEBOX_DOORBELL_PROTOCOL_VERSION,
                actual: version,
            });
        }

        let kind = u16::from_le_bytes([bytes[6], bytes[7]]);
        let payload_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        if payload_len > max_payload_len {
            return Err(
                WhiteboxDoorbellFrameDecodeError::PayloadLengthExceedsBound {
                    declared_len: payload_len,
                    max_payload_len,
                },
            );
        }
        let actual_payload_len = bytes.len() - WHITEBOX_DOORBELL_FRAME_HEADER_LEN;
        if payload_len != actual_payload_len {
            return Err(WhiteboxDoorbellFrameDecodeError::PayloadLengthMismatch {
                declared_len: payload_len,
                actual_len: actual_payload_len,
            });
        }

        Ok(Self {
            kind,
            payload: bytes[WHITEBOX_DOORBELL_FRAME_HEADER_LEN..].to_vec(),
        })
    }

    /// Encodes this frame into its canonical fixed-header byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellFrameEncodeError::PayloadTooLarge`] when the
    /// payload cannot fit in the fixed `u32` payload-length field.
    pub fn encode(&self) -> Result<Vec<u8>, WhiteboxDoorbellFrameEncodeError> {
        encode_whitebox_doorbell_frame(self.kind, &self.payload)
    }

    /// Returns the marker kind carried by the frame.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Returns the kind-specific payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Encodes a white-box doorbell frame with the current protocol version.
///
/// # Errors
///
/// Returns [`WhiteboxDoorbellFrameEncodeError::PayloadTooLarge`] when the
/// payload cannot fit in the fixed `u32` payload-length field.
pub fn encode_whitebox_doorbell_frame(
    kind: u16,
    payload: &[u8],
) -> Result<Vec<u8>, WhiteboxDoorbellFrameEncodeError> {
    validate_payload_len(payload.len())?;
    let mut frame = Vec::with_capacity(WHITEBOX_DOORBELL_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&WHITEBOX_DOORBELL_FRAME_MAGIC.to_le_bytes());
    frame.extend_from_slice(&WHITEBOX_DOORBELL_PROTOCOL_VERSION.to_le_bytes());
    frame.extend_from_slice(&kind.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn validate_payload_len(len: usize) -> Result<(), WhiteboxDoorbellFrameEncodeError> {
    if len > u32::MAX as usize {
        Err(WhiteboxDoorbellFrameEncodeError::PayloadTooLarge {
            len,
            max_len: u32::MAX as usize,
        })
    } else {
        Ok(())
    }
}

/// Error returned while encoding a white-box doorbell frame.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WhiteboxDoorbellFrameEncodeError {
    /// The payload cannot fit in the fixed `u32` payload-length field.
    #[error("white-box doorbell payload length {len} exceeds maximum {max_len}")]
    PayloadTooLarge {
        /// Observed payload length.
        len: usize,
        /// Maximum encodable payload length.
        max_len: usize,
    },
}

/// Error returned while decoding a white-box doorbell frame.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WhiteboxDoorbellFrameDecodeError {
    /// The frame was shorter than the fixed header.
    #[error("white-box doorbell frame length {len} is shorter than header {minimum_len}")]
    TruncatedFrame {
        /// Observed byte length.
        len: usize,
        /// Minimum valid byte length.
        minimum_len: usize,
    },
    /// The fixed channel magic was not recognized.
    #[error("white-box doorbell magic {actual:#x} does not match expected {expected:#x}")]
    BadMagic {
        /// Expected fixed magic.
        expected: u32,
        /// Observed magic.
        actual: u32,
    },
    /// The protocol version was not recognized.
    #[error("white-box doorbell version {actual} does not match expected {expected}")]
    UnsupportedVersion {
        /// Expected protocol version.
        expected: u16,
        /// Observed protocol version.
        actual: u16,
    },
    /// The header-declared payload length exceeded the caller's allocation bound.
    #[error("white-box doorbell payload length {declared_len} exceeds bound {max_payload_len}")]
    PayloadLengthExceedsBound {
        /// Header-declared payload length.
        declared_len: usize,
        /// Caller-supplied maximum payload length.
        max_payload_len: usize,
    },
    /// The header payload length did not match the received payload bytes.
    #[error("white-box doorbell payload length {declared_len} does not match actual {actual_len}")]
    PayloadLengthMismatch {
        /// Header-declared payload length.
        declared_len: usize,
        /// Actual payload length after the header.
        actual_len: usize,
    },
}

/// One frozen white-box doorbell frame golden vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxDoorbellFrameGoldenVector {
    /// Stable corpus name.
    pub name: &'static str,
    /// Doorbell protocol version the vector belongs to.
    pub protocol_version: u16,
    /// Doorbell marker kind carried by the vector.
    pub kind: u16,
    /// Kind-specific body bytes.
    pub payload: &'static [u8],
    /// Complete frame bytes, including the fixed header.
    pub frame: &'static [u8],
}

/// Frozen white-box doorbell frame golden-vector corpus.
pub const GOLDEN_WHITEBOX_DOORBELL_FRAME_VECTORS: [WhiteboxDoorbellFrameGoldenVector; 2] = [
    WhiteboxDoorbellFrameGoldenVector {
        name: "marker-kind-1-empty",
        protocol_version: 2,
        kind: 1,
        payload: &[],
        frame: &[0x43, 0x52, 0x42, 0x4c, 2, 0, 1, 0, 0, 0, 0, 0],
    },
    WhiteboxDoorbellFrameGoldenVector {
        name: "random-request-kind-5",
        protocol_version: 2,
        kind: 5,
        payload: &[0x04, 0x03, 0x02, 0x01, 4, 3, 0, 0x72, 0x6e, 0x67],
        frame: &[
            0x43, 0x52, 0x42, 0x4c, 2, 0, 5, 0, 10, 0, 0, 0, 0x04, 0x03, 0x02, 0x01, 4, 3, 0, 0x72,
            0x6e, 0x67,
        ],
    },
];
