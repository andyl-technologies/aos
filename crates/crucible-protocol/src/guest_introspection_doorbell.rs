//! Fixed guest-buffer exchange for the guest-introspection agent.
//!
//! A guest agent rings the existing architecture-specific white-box doorbell
//! with one fixed-size mutable buffer. The QEMU-side adapter consumes an
//! optional response from that buffer, dequeues at most one host request from
//! shared memory, and overwrites the same buffer with a request or idle frame.
//! The format is independently implementable and contains no pointers:
//!
//! ```text
//! offset  size  field
//! 0       4     magic (`CRGX`)
//! 4       2     protocol version, little-endian
//! 6       1     exchange kind
//! 7       1     flags (zero)
//! 8       4     embedded `CRGI` record length, little-endian
//! 12      4     reserved (zero)
//! 16      N     complete `CRGI` record
//! 16+N    ...   zero padding to 4608 bytes
//! ```

use thiserror::Error;

use crate::guest_introspection::{
    GUEST_INTROSPECTION_MAX_RECORD_BYTES, GuestIntrospectionError, GuestIntrospectionRecord,
};

/// Four-byte magic identifying a guest-agent exchange buffer.
pub const GUEST_INTROSPECTION_DOORBELL_MAGIC: [u8; 4] = *b"CRGX";
/// Current guest-agent exchange protocol version.
pub const GUEST_INTROSPECTION_DOORBELL_VERSION: u16 = 1;
/// Fixed exchange header length in bytes.
pub const GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES: usize = 16;
/// Exact mutable guest-buffer length used by every exchange.
pub const GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES: usize = 4608;

const KIND_POLL: u8 = 1;
const KIND_RESPONSE: u8 = 2;
const KIND_IDLE: u8 = 3;
const KIND_REQUEST: u8 = 4;
const KIND_RETRY: u8 = 5;

const _: () = assert!(
    GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES + GUEST_INTROSPECTION_MAX_RECORD_BYTES
        == GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES
);

/// Closed direction and payload state of one guest-agent exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestIntrospectionDoorbellKind {
    /// Guest has no response and is polling for host work.
    Poll,
    /// Guest is returning one response and polling for more work.
    Response,
    /// Plugin found no host request to deliver.
    Idle,
    /// Plugin is delivering one host request to the guest.
    Request,
    /// Plugin could not publish the response and asks the guest to retry it.
    Retry,
}

impl GuestIntrospectionDoorbellKind {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Poll => KIND_POLL,
            Self::Response => KIND_RESPONSE,
            Self::Idle => KIND_IDLE,
            Self::Request => KIND_REQUEST,
            Self::Retry => KIND_RETRY,
        }
    }

    const fn from_wire_value(value: u8) -> Option<Self> {
        match value {
            KIND_POLL => Some(Self::Poll),
            KIND_RESPONSE => Some(Self::Response),
            KIND_IDLE => Some(Self::Idle),
            KIND_REQUEST => Some(Self::Request),
            KIND_RETRY => Some(Self::Retry),
            _ => None,
        }
    }

    const fn carries_record(self) -> bool {
        matches!(self, Self::Response | Self::Request)
    }
}

/// One validated fixed-size guest-agent exchange frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIntrospectionDoorbellFrame {
    kind: GuestIntrospectionDoorbellKind,
    record: Option<GuestIntrospectionRecord>,
}

impl GuestIntrospectionDoorbellFrame {
    /// Builds an empty guest poll frame.
    #[must_use]
    pub const fn poll() -> Self {
        Self {
            kind: GuestIntrospectionDoorbellKind::Poll,
            record: None,
        }
    }

    /// Builds a guest response frame.
    #[must_use]
    pub const fn response(record: GuestIntrospectionRecord) -> Self {
        Self {
            kind: GuestIntrospectionDoorbellKind::Response,
            record: Some(record),
        }
    }

    /// Builds an idle plugin reply.
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            kind: GuestIntrospectionDoorbellKind::Idle,
            record: None,
        }
    }

    /// Builds a plugin request delivery.
    #[must_use]
    pub const fn request(record: GuestIntrospectionRecord) -> Self {
        Self {
            kind: GuestIntrospectionDoorbellKind::Request,
            record: Some(record),
        }
    }

    /// Builds a plugin backpressure reply.
    #[must_use]
    pub const fn retry() -> Self {
        Self {
            kind: GuestIntrospectionDoorbellKind::Retry,
            record: None,
        }
    }

    /// Returns the closed exchange kind.
    #[must_use]
    pub const fn kind(&self) -> GuestIntrospectionDoorbellKind {
        self.kind
    }

    /// Returns the embedded complete `CRGI` record, when present.
    #[must_use]
    pub const fn record(&self) -> Option<&GuestIntrospectionRecord> {
        self.record.as_ref()
    }

    /// Encodes the exchange into its exact fixed-size guest buffer.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionDoorbellError`] when an embedded record
    /// cannot be encoded within the public record bound.
    pub fn encode(
        &self,
    ) -> Result<[u8; GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES], GuestIntrospectionDoorbellError>
    {
        let record = self
            .record
            .as_ref()
            .map(GuestIntrospectionRecord::encode)
            .transpose()
            .map_err(GuestIntrospectionDoorbellError::Record)?;
        if self.kind.carries_record() != record.is_some() {
            return Err(GuestIntrospectionDoorbellError::KindRecordMismatch { kind: self.kind });
        }
        let record_len = record.as_ref().map_or(0, Vec::len);
        if record_len > GUEST_INTROSPECTION_MAX_RECORD_BYTES {
            return Err(GuestIntrospectionDoorbellError::RecordTooLarge { len: record_len });
        }
        let record_len = u32::try_from(record_len).map_err(|_error| {
            GuestIntrospectionDoorbellError::RecordTooLarge { len: record_len }
        })?;
        let mut output = [0_u8; GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES];
        output[..4].copy_from_slice(&GUEST_INTROSPECTION_DOORBELL_MAGIC);
        output[4..6].copy_from_slice(&GUEST_INTROSPECTION_DOORBELL_VERSION.to_le_bytes());
        output[6] = self.kind.wire_value();
        output[8..12].copy_from_slice(&record_len.to_le_bytes());
        if let Some(record) = record {
            let end = GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES + record.len();
            output[GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES..end].copy_from_slice(&record);
        }
        Ok(output)
    }

    /// Decodes and validates one exact fixed-size guest buffer.
    ///
    /// # Errors
    ///
    /// Returns [`GuestIntrospectionDoorbellError`] for a bad length, magic,
    /// version, kind, reserved field, record shape, or nonzero padding.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestIntrospectionDoorbellError> {
        if bytes.len() != GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES {
            return Err(GuestIntrospectionDoorbellError::FrameLength {
                actual: bytes.len(),
            });
        }
        if bytes[..4] != GUEST_INTROSPECTION_DOORBELL_MAGIC {
            return Err(GuestIntrospectionDoorbellError::Magic);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != GUEST_INTROSPECTION_DOORBELL_VERSION {
            return Err(GuestIntrospectionDoorbellError::Version { actual: version });
        }
        let kind = GuestIntrospectionDoorbellKind::from_wire_value(bytes[6])
            .ok_or(GuestIntrospectionDoorbellError::Kind { actual: bytes[6] })?;
        if bytes[7] != 0 || bytes[12..16].iter().any(|byte| *byte != 0) {
            return Err(GuestIntrospectionDoorbellError::Reserved);
        }
        let record_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        if record_len > GUEST_INTROSPECTION_MAX_RECORD_BYTES {
            return Err(GuestIntrospectionDoorbellError::RecordTooLarge { len: record_len });
        }
        if kind.carries_record() != (record_len != 0) {
            return Err(GuestIntrospectionDoorbellError::KindRecordMismatch { kind });
        }
        let record_end = GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES + record_len;
        if bytes[record_end..].iter().any(|byte| *byte != 0) {
            return Err(GuestIntrospectionDoorbellError::NonzeroPadding);
        }
        let record = if record_len == 0 {
            None
        } else {
            Some(
                GuestIntrospectionRecord::decode(
                    &bytes[GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES..record_end],
                )
                .map_err(GuestIntrospectionDoorbellError::Record)?,
            )
        };
        Ok(Self { kind, record })
    }
}

/// Invalid guest-agent exchange buffer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GuestIntrospectionDoorbellError {
    /// The mutable guest buffer did not have the exact public size.
    #[error("guest-introspection doorbell frame length {actual} is not 4608")]
    FrameLength {
        /// Observed byte length.
        actual: usize,
    },
    /// The frame magic was not `CRGX`.
    #[error("guest-introspection doorbell magic is invalid")]
    Magic,
    /// The exchange protocol version is unsupported.
    #[error("guest-introspection doorbell version {actual} is unsupported")]
    Version {
        /// Observed version.
        actual: u16,
    },
    /// The exchange kind is unknown.
    #[error("guest-introspection doorbell kind {actual} is unknown")]
    Kind {
        /// Observed kind.
        actual: u8,
    },
    /// Flags or reserved bytes were nonzero.
    #[error("guest-introspection doorbell reserved bytes must be zero")]
    Reserved,
    /// The exchange kind and record presence disagree.
    #[error("guest-introspection doorbell kind {kind:?} has the wrong record presence")]
    KindRecordMismatch {
        /// Decoded exchange kind.
        kind: GuestIntrospectionDoorbellKind,
    },
    /// The embedded record exceeds the public bound.
    #[error("guest-introspection doorbell record length {len} exceeds the maximum")]
    RecordTooLarge {
        /// Observed record length.
        len: usize,
    },
    /// The embedded record is malformed.
    #[error("guest-introspection doorbell record is malformed: {0}")]
    Record(GuestIntrospectionError),
    /// Bytes after the embedded record were nonzero.
    #[error("guest-introspection doorbell padding must be zero")]
    NonzeroPadding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_introspection::GuestIntrospectionMessage;

    fn close_record() -> GuestIntrospectionRecord {
        match GuestIntrospectionRecord::new(7, GuestIntrospectionMessage::Close) {
            Ok(record) => record,
            Err(error) => panic!("valid close record failed: {error}"),
        }
    }

    #[test]
    fn all_exchange_kinds_round_trip() {
        let frames = [
            GuestIntrospectionDoorbellFrame::poll(),
            GuestIntrospectionDoorbellFrame::response(close_record()),
            GuestIntrospectionDoorbellFrame::idle(),
            GuestIntrospectionDoorbellFrame::request(close_record()),
            GuestIntrospectionDoorbellFrame::retry(),
        ];
        for frame in frames {
            let encoded = match frame.encode() {
                Ok(encoded) => encoded,
                Err(error) => panic!("valid exchange failed to encode: {error}"),
            };
            assert_eq!(GuestIntrospectionDoorbellFrame::decode(&encoded), Ok(frame));
        }
    }

    #[test]
    fn malformed_envelopes_fail_closed() {
        let encoded = match GuestIntrospectionDoorbellFrame::poll().encode() {
            Ok(encoded) => encoded,
            Err(error) => panic!("poll failed to encode: {error}"),
        };
        assert!(matches!(
            GuestIntrospectionDoorbellFrame::decode(&encoded[..encoded.len() - 1]),
            Err(GuestIntrospectionDoorbellError::FrameLength { .. })
        ));

        let mut bad_reserved = encoded;
        bad_reserved[12] = 1;
        assert_eq!(
            GuestIntrospectionDoorbellFrame::decode(&bad_reserved),
            Err(GuestIntrospectionDoorbellError::Reserved)
        );

        let mut bad_padding = encoded;
        bad_padding[GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES - 1] = 1;
        assert_eq!(
            GuestIntrospectionDoorbellFrame::decode(&bad_padding),
            Err(GuestIntrospectionDoorbellError::NonzeroPadding)
        );
    }
}
