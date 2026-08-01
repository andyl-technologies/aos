//! Closed white-box doorbell marker vocabulary and body codecs.
//!
//! This module owns the architecture-independent marker `kind` registry carried
//! inside [`crate::WhiteboxDoorbellFrame`] and the fixed or length-prefixed body
//! layout for each kind:
//!
//! ```text
//! kind=1 assertion       flavor:u8, condition:u8, must_hit:u8,
//!                        lp_str id, lp_str message, lp_str location, lp_kv[] details
//! kind=2 lifecycle       event:u16
//! kind=3 event           lp_str name, lp_kv[] details
//! kind=4 coverage        lp_str point
//! kind=5 random_request  request_id:u32, width:u8, lp_str stream_tag
//! ```

use thiserror::Error;

use crate::{
    WhiteboxDoorbellFrame, WhiteboxDoorbellFrameEncodeError, encode_whitebox_doorbell_frame,
};

/// Wire value for assertion marker bodies.
pub const WHITEBOX_DOORBELL_KIND_ASSERTION: u16 = 1;
/// Wire value for lifecycle marker bodies.
pub const WHITEBOX_DOORBELL_KIND_LIFECYCLE: u16 = 2;
/// Wire value for diagnostic event marker bodies.
pub const WHITEBOX_DOORBELL_KIND_EVENT: u16 = 3;
/// Wire value for named coverage marker bodies.
pub const WHITEBOX_DOORBELL_KIND_COVERAGE: u16 = 4;
/// Wire value for app-controlled random request marker bodies.
pub const WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST: u16 = 5;
/// Number of entries in the closed marker-kind vocabulary.
pub const WHITEBOX_DOORBELL_MARKER_KIND_COUNT: usize = 5;
/// Maximum app-controlled random-request reply width.
pub const WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES: u8 = 8;
/// Number of assertion marker flavor entries.
pub const WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT: usize = 4;
/// Number of lifecycle marker event entries.
pub const WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT: usize = 2;

/// Wire value for the `setup_complete` lifecycle marker.
pub const WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE: u16 = 1;
/// Wire value for the `test_done` lifecycle marker.
pub const WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE: u16 = 2;

/// Closed marker-kind vocabulary carried by the doorbell frame `kind` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WhiteboxDoorbellMarkerKind {
    /// Guest assertion marker with assertion-finalization fields.
    Assertion,
    /// Guest lifecycle marker.
    Lifecycle,
    /// Free-form diagnostic marker.
    Event,
    /// Named semantic coverage marker.
    Coverage,
    /// App-controlled randomness request.
    RandomRequest,
}

impl WhiteboxDoorbellMarkerKind {
    /// Stable marker-kind order used by ABI-conformance tests.
    pub const ALL: [Self; WHITEBOX_DOORBELL_MARKER_KIND_COUNT] = [
        Self::Assertion,
        Self::Lifecycle,
        Self::Event,
        Self::Coverage,
        Self::RandomRequest,
    ];

    /// Returns the fixed wire value for this marker kind.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Assertion => WHITEBOX_DOORBELL_KIND_ASSERTION,
            Self::Lifecycle => WHITEBOX_DOORBELL_KIND_LIFECYCLE,
            Self::Event => WHITEBOX_DOORBELL_KIND_EVENT,
            Self::Coverage => WHITEBOX_DOORBELL_KIND_COVERAGE,
            Self::RandomRequest => WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
        }
    }

    /// Parses a marker-kind wire value.
    #[must_use]
    pub const fn from_wire_value(kind: u16) -> Option<Self> {
        match kind {
            WHITEBOX_DOORBELL_KIND_ASSERTION => Some(Self::Assertion),
            WHITEBOX_DOORBELL_KIND_LIFECYCLE => Some(Self::Lifecycle),
            WHITEBOX_DOORBELL_KIND_EVENT => Some(Self::Event),
            WHITEBOX_DOORBELL_KIND_COVERAGE => Some(Self::Coverage),
            WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST => Some(Self::RandomRequest),
            _ => None,
        }
    }

    /// Returns the canonical semantic label for this marker kind.
    #[must_use]
    pub const fn semantic_label(self) -> &'static str {
        match self {
            Self::Assertion => "guest_assertion_marker",
            Self::Lifecycle => "guest_lifecycle_marker",
            Self::Event => "guest_event_marker",
            Self::Coverage => "guest_coverage_marker",
            Self::RandomRequest => "app_random_request",
        }
    }

    /// Returns whether this marker kind is observational.
    #[must_use]
    pub const fn is_observational(self) -> bool {
        !matches!(self, Self::RandomRequest)
    }
}

/// Closed assertion marker flavor vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WhiteboxAssertionMarkerFlavor {
    /// The condition must hold whenever evaluated.
    Always,
    /// The condition must hold at least once.
    Sometimes,
    /// The point is expected to be reached.
    Reachable,
    /// The point is expected never to be reached.
    Unreachable,
}

impl WhiteboxAssertionMarkerFlavor {
    /// Stable assertion marker flavor order used by ABI-conformance tests.
    pub const ALL: [Self; WHITEBOX_DOORBELL_ASSERTION_FLAVOR_COUNT] = [
        Self::Always,
        Self::Sometimes,
        Self::Reachable,
        Self::Unreachable,
    ];

    /// Returns the fixed wire value for this assertion flavor.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Always => 0,
            Self::Sometimes => 1,
            Self::Reachable => 2,
            Self::Unreachable => 3,
        }
    }

    /// Parses an assertion flavor wire value.
    #[must_use]
    pub const fn from_wire_value(flavor: u8) -> Option<Self> {
        match flavor {
            0 => Some(Self::Always),
            1 => Some(Self::Sometimes),
            2 => Some(Self::Reachable),
            3 => Some(Self::Unreachable),
            _ => None,
        }
    }

    /// Returns the assertion/property semantic label for this flavor.
    #[must_use]
    pub const fn semantic_label(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Sometimes => "sometimes",
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
        }
    }
}

/// Lifecycle marker event vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WhiteboxLifecycleMarkerEvent {
    /// The guest finished its white-box setup phase.
    SetupComplete,
    /// The guest workload is complete.
    TestDone,
}

impl WhiteboxLifecycleMarkerEvent {
    /// Stable lifecycle marker event order used by ABI-conformance tests.
    pub const ALL: [Self; WHITEBOX_DOORBELL_LIFECYCLE_EVENT_COUNT] =
        [Self::SetupComplete, Self::TestDone];

    /// Returns the fixed wire value for this lifecycle event.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::SetupComplete => WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE,
            Self::TestDone => WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE,
        }
    }

    /// Parses a lifecycle event wire value.
    #[must_use]
    pub const fn from_wire_value(event: u16) -> Option<Self> {
        match event {
            WHITEBOX_DOORBELL_LIFECYCLE_SETUP_COMPLETE => Some(Self::SetupComplete),
            WHITEBOX_DOORBELL_LIFECYCLE_TEST_DONE => Some(Self::TestDone),
            _ => None,
        }
    }

    /// Returns the canonical semantic label for this lifecycle event.
    #[must_use]
    pub const fn semantic_label(self) -> &'static str {
        match self {
            Self::SetupComplete => "setup_complete",
            Self::TestDone => "test_done",
        }
    }
}

/// One length-prefixed marker detail key/value pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxMarkerDetail {
    /// Detail key.
    pub key: String,
    /// Detail value.
    pub value: String,
}

impl WhiteboxMarkerDetail {
    /// Builds one marker detail pair.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Decoded assertion marker body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxAssertionMarkerBody {
    /// Assertion flavor.
    pub flavor: WhiteboxAssertionMarkerFlavor,
    /// Guest-observed condition value.
    pub condition: bool,
    /// Whether this marker was catalog-declared and must be finalized if unseen.
    pub must_hit: bool,
    /// Assertion id in the shared assertion id space.
    pub id: String,
    /// Human-readable assertion message.
    pub message: String,
    /// Source location supplied by the guest emitter.
    pub location: String,
    /// Structured assertion details.
    pub details: Vec<WhiteboxMarkerDetail>,
}

/// Decoded diagnostic event marker body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxEventMarkerBody {
    /// Event name.
    pub name: String,
    /// Structured event details.
    pub details: Vec<WhiteboxMarkerDetail>,
}

/// Decoded named coverage marker body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxCoverageMarkerBody {
    /// Semantic coverage point name.
    pub point: String,
}

/// Decoded app-controlled randomness request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhiteboxRandomRequestBody {
    /// Guest request identifier.
    pub request_id: u32,
    /// Requested reply width in bytes.
    pub width_bytes: u8,
    /// Deterministic RNG stream tag.
    pub stream_tag: String,
}

/// Decoded closed marker payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WhiteboxMarkerPayload {
    /// Guest assertion marker.
    Assertion(WhiteboxAssertionMarkerBody),
    /// Guest lifecycle marker.
    Lifecycle(WhiteboxLifecycleMarkerEvent),
    /// Guest diagnostic event marker.
    Event(WhiteboxEventMarkerBody),
    /// Guest semantic coverage marker.
    Coverage(WhiteboxCoverageMarkerBody),
    /// App-controlled randomness request marker.
    RandomRequest(WhiteboxRandomRequestBody),
}

impl WhiteboxMarkerPayload {
    /// Returns the closed marker kind for this payload.
    #[must_use]
    pub const fn kind(&self) -> WhiteboxDoorbellMarkerKind {
        match self {
            Self::Assertion(_) => WhiteboxDoorbellMarkerKind::Assertion,
            Self::Lifecycle(_) => WhiteboxDoorbellMarkerKind::Lifecycle,
            Self::Event(_) => WhiteboxDoorbellMarkerKind::Event,
            Self::Coverage(_) => WhiteboxDoorbellMarkerKind::Coverage,
            Self::RandomRequest(_) => WhiteboxDoorbellMarkerKind::RandomRequest,
        }
    }

    /// Returns whether this marker payload is purely observational.
    #[must_use]
    pub const fn is_observational(&self) -> bool {
        self.kind().is_observational()
    }
}

/// Decodes a closed white-box marker payload from a doorbell frame.
///
/// # Errors
///
/// Returns [`WhiteboxMarkerPayloadDecodeError`] when the frame carries an
/// unknown kind or the kind-specific body is malformed.
pub fn decode_whitebox_marker_payload(
    frame: &WhiteboxDoorbellFrame,
) -> Result<WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError> {
    let Some(kind) = WhiteboxDoorbellMarkerKind::from_wire_value(frame.kind()) else {
        return Err(WhiteboxMarkerPayloadDecodeError::UnknownKind { kind: frame.kind() });
    };
    decode_marker_payload_body(kind, frame.payload())
}

fn decode_marker_payload_body(
    kind: WhiteboxDoorbellMarkerKind,
    bytes: &[u8],
) -> Result<WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError> {
    let mut reader = BodyReader::new(kind, bytes);
    let payload = match kind {
        WhiteboxDoorbellMarkerKind::Assertion => {
            let flavor = reader.read_u8("flavor")?;
            let Some(flavor) = WhiteboxAssertionMarkerFlavor::from_wire_value(flavor) else {
                return Err(WhiteboxMarkerPayloadDecodeError::InvalidAssertionFlavor { flavor });
            };
            let condition = reader.read_bool("condition")?;
            let must_hit = reader.read_bool("must_hit")?;
            let id = reader.read_lp_string("id")?;
            let message = reader.read_lp_string("message")?;
            let location = reader.read_lp_string("location")?;
            let details = reader.read_details("details")?;
            WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
                flavor,
                condition,
                must_hit,
                id,
                message,
                location,
                details,
            })
        }
        WhiteboxDoorbellMarkerKind::Lifecycle => {
            let event = reader.read_u16_le("event")?;
            let Some(event) = WhiteboxLifecycleMarkerEvent::from_wire_value(event) else {
                return Err(WhiteboxMarkerPayloadDecodeError::InvalidLifecycleEvent { event });
            };
            WhiteboxMarkerPayload::Lifecycle(event)
        }
        WhiteboxDoorbellMarkerKind::Event => {
            let name = reader.read_lp_string("name")?;
            let details = reader.read_details("details")?;
            WhiteboxMarkerPayload::Event(WhiteboxEventMarkerBody { name, details })
        }
        WhiteboxDoorbellMarkerKind::Coverage => {
            let point = reader.read_lp_string("point")?;
            WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody { point })
        }
        WhiteboxDoorbellMarkerKind::RandomRequest => {
            let request_id = reader.read_u32_le("request_id")?;
            let width_bytes = reader.read_u8("width")?;
            if width_bytes == 0 || width_bytes > WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES {
                return Err(WhiteboxMarkerPayloadDecodeError::InvalidRandomWidth {
                    width_bytes,
                    max_width_bytes: WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
                });
            }
            let stream_tag = reader.read_lp_string("stream_tag")?;
            WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
                request_id,
                width_bytes,
                stream_tag,
            })
        }
    };
    reader.finish()?;
    Ok(payload)
}

/// Encodes the body bytes for a closed white-box marker payload.
///
/// # Errors
///
/// Returns [`WhiteboxMarkerPayloadEncodeError`] when a length-prefixed string or
/// key/value count cannot fit in its fixed `u16` field.
pub fn encode_whitebox_marker_payload_body(
    payload: &WhiteboxMarkerPayload,
) -> Result<Vec<u8>, WhiteboxMarkerPayloadEncodeError> {
    let mut bytes = Vec::new();
    match payload {
        WhiteboxMarkerPayload::Assertion(assertion) => {
            bytes.push(assertion.flavor.wire_value());
            bytes.push(bool_wire_value(assertion.condition));
            bytes.push(bool_wire_value(assertion.must_hit));
            push_lp_string("id", &assertion.id, &mut bytes)?;
            push_lp_string("message", &assertion.message, &mut bytes)?;
            push_lp_string("location", &assertion.location, &mut bytes)?;
            push_details(&assertion.details, &mut bytes)?;
        }
        WhiteboxMarkerPayload::Lifecycle(event) => {
            bytes.extend_from_slice(&event.wire_value().to_le_bytes());
        }
        WhiteboxMarkerPayload::Event(event) => {
            push_lp_string("name", &event.name, &mut bytes)?;
            push_details(&event.details, &mut bytes)?;
        }
        WhiteboxMarkerPayload::Coverage(coverage) => {
            push_lp_string("point", &coverage.point, &mut bytes)?;
        }
        WhiteboxMarkerPayload::RandomRequest(request) => {
            if request.width_bytes == 0
                || request.width_bytes > WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES
            {
                return Err(WhiteboxMarkerPayloadEncodeError::InvalidRandomWidth {
                    width_bytes: request.width_bytes,
                    max_width_bytes: WHITEBOX_DOORBELL_RANDOM_REQUEST_MAX_WIDTH_BYTES,
                });
            }
            bytes.extend_from_slice(&request.request_id.to_le_bytes());
            bytes.push(request.width_bytes);
            push_lp_string("stream_tag", &request.stream_tag, &mut bytes)?;
        }
    }
    Ok(bytes)
}

/// Encodes a closed marker payload into a complete doorbell frame.
///
/// # Errors
///
/// Returns [`WhiteboxMarkerPayloadEncodeError`] when the body cannot be encoded
/// or the complete frame exceeds the doorbell frame payload limit.
pub fn encode_whitebox_marker_frame(
    payload: &WhiteboxMarkerPayload,
) -> Result<Vec<u8>, WhiteboxMarkerPayloadEncodeError> {
    let body = encode_whitebox_marker_payload_body(payload)?;
    encode_whitebox_doorbell_frame(payload.kind().wire_value(), &body).map_err(
        |error| match error {
            WhiteboxDoorbellFrameEncodeError::PayloadTooLarge { len, max_len } => {
                WhiteboxMarkerPayloadEncodeError::FramePayloadTooLarge { len, max_len }
            }
        },
    )
}

fn bool_wire_value(value: bool) -> u8 {
    u8::from(value)
}

fn push_details(
    details: &[WhiteboxMarkerDetail],
    bytes: &mut Vec<u8>,
) -> Result<(), WhiteboxMarkerPayloadEncodeError> {
    let count = u16::try_from(details.len()).map_err(|_error| {
        WhiteboxMarkerPayloadEncodeError::TooManyDetails {
            count: details.len(),
            max_count: u16::MAX as usize,
        }
    })?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for detail in details {
        push_lp_string("detail.key", &detail.key, bytes)?;
        push_lp_string("detail.value", &detail.value, bytes)?;
    }
    Ok(())
}

fn push_lp_string(
    field: &'static str,
    value: &str,
    bytes: &mut Vec<u8>,
) -> Result<(), WhiteboxMarkerPayloadEncodeError> {
    let len = u16::try_from(value.len()).map_err(|_error| {
        WhiteboxMarkerPayloadEncodeError::StringTooLong {
            field,
            len: value.len(),
            max_len: u16::MAX as usize,
        }
    })?;
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct BodyReader<'a> {
    kind: WhiteboxDoorbellMarkerKind,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BodyReader<'a> {
    fn new(kind: WhiteboxDoorbellMarkerKind, bytes: &'a [u8]) -> Self {
        Self {
            kind,
            bytes,
            offset: 0,
        }
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, WhiteboxMarkerPayloadDecodeError> {
        let bytes = self.read_exact(field, 1)?;
        Ok(bytes[0])
    }

    fn read_bool(&mut self, field: &'static str) -> Result<bool, WhiteboxMarkerPayloadDecodeError> {
        match self.read_u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(WhiteboxMarkerPayloadDecodeError::InvalidBool {
                kind: self.kind,
                field,
                value,
            }),
        }
    }

    fn read_u16_le(
        &mut self,
        field: &'static str,
    ) -> Result<u16, WhiteboxMarkerPayloadDecodeError> {
        let bytes = self.read_exact(field, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_le(
        &mut self,
        field: &'static str,
    ) -> Result<u32, WhiteboxMarkerPayloadDecodeError> {
        let bytes = self.read_exact(field, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_lp_string(
        &mut self,
        field: &'static str,
    ) -> Result<String, WhiteboxMarkerPayloadDecodeError> {
        let declared_len = usize::from(self.read_u16_le(field)?);
        let remaining_len = self.remaining_len();
        if declared_len > remaining_len {
            return Err(
                WhiteboxMarkerPayloadDecodeError::LengthPrefixExceedsPayload {
                    kind: self.kind,
                    field,
                    declared_len,
                    remaining_len,
                },
            );
        }
        let start = self.offset;
        self.offset += declared_len;
        let value = std::str::from_utf8(&self.bytes[start..self.offset]).map_err(|_error| {
            WhiteboxMarkerPayloadDecodeError::InvalidUtf8 {
                kind: self.kind,
                field,
            }
        })?;
        Ok(value.to_owned())
    }

    fn read_details(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<WhiteboxMarkerDetail>, WhiteboxMarkerPayloadDecodeError> {
        let count = self.read_u16_le(field)?;
        let mut details = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let key = self.read_lp_string("detail.key")?;
            let value = self.read_lp_string("detail.value")?;
            details.push(WhiteboxMarkerDetail { key, value });
        }
        Ok(details)
    }

    fn read_exact(
        &mut self,
        field: &'static str,
        needed: usize,
    ) -> Result<&'a [u8], WhiteboxMarkerPayloadDecodeError> {
        if self.remaining_len() < needed {
            return Err(WhiteboxMarkerPayloadDecodeError::PayloadTooShort {
                kind: self.kind,
                field,
                needed,
                remaining: self.remaining_len(),
            });
        }
        let start = self.offset;
        self.offset += needed;
        Ok(&self.bytes[start..self.offset])
    }

    fn remaining_len(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn finish(&self) -> Result<(), WhiteboxMarkerPayloadDecodeError> {
        let trailing_len = self.remaining_len();
        if trailing_len == 0 {
            Ok(())
        } else {
            Err(WhiteboxMarkerPayloadDecodeError::TrailingBytes {
                kind: self.kind,
                trailing_len,
            })
        }
    }
}

/// Error returned while decoding a marker payload body.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WhiteboxMarkerPayloadDecodeError {
    /// The frame carried a marker kind outside the closed vocabulary.
    #[error("unknown white-box marker kind {kind}")]
    UnknownKind {
        /// Unknown marker kind.
        kind: u16,
    },
    /// A fixed-width field was missing bytes.
    #[error(
        "white-box marker {kind:?} field {field} needs {needed} bytes with only {remaining} remaining"
    )]
    PayloadTooShort {
        /// Marker kind being decoded.
        kind: WhiteboxDoorbellMarkerKind,
        /// Field being decoded.
        field: &'static str,
        /// Required byte count.
        needed: usize,
        /// Remaining byte count.
        remaining: usize,
    },
    /// A length-prefixed field declared more bytes than remain in the payload.
    #[error(
        "white-box marker {kind:?} field {field} declared {declared_len} bytes with only {remaining_len} remaining"
    )]
    LengthPrefixExceedsPayload {
        /// Marker kind being decoded.
        kind: WhiteboxDoorbellMarkerKind,
        /// Field being decoded.
        field: &'static str,
        /// Declared byte count.
        declared_len: usize,
        /// Remaining byte count.
        remaining_len: usize,
    },
    /// A body carried bytes after the expected layout.
    #[error("white-box marker {kind:?} has {trailing_len} trailing payload bytes")]
    TrailingBytes {
        /// Marker kind being decoded.
        kind: WhiteboxDoorbellMarkerKind,
        /// Number of trailing bytes.
        trailing_len: usize,
    },
    /// A length-prefixed string was not UTF-8.
    #[error("white-box marker {kind:?} field {field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Marker kind being decoded.
        kind: WhiteboxDoorbellMarkerKind,
        /// Field being decoded.
        field: &'static str,
    },
    /// A boolean field used a value other than zero or one.
    #[error("white-box marker {kind:?} field {field} used invalid bool value {value}")]
    InvalidBool {
        /// Marker kind being decoded.
        kind: WhiteboxDoorbellMarkerKind,
        /// Field being decoded.
        field: &'static str,
        /// Invalid boolean byte.
        value: u8,
    },
    /// An assertion marker carried an unknown flavor.
    #[error("white-box assertion marker used invalid flavor {flavor}")]
    InvalidAssertionFlavor {
        /// Invalid flavor byte.
        flavor: u8,
    },
    /// A lifecycle marker carried an unknown event.
    #[error("white-box lifecycle marker used invalid event {event}")]
    InvalidLifecycleEvent {
        /// Invalid lifecycle event value.
        event: u16,
    },
    /// A random request asked for an invalid reply width.
    #[error("white-box random request width {width_bytes} is outside 1..={max_width_bytes}")]
    InvalidRandomWidth {
        /// Requested width.
        width_bytes: u8,
        /// Maximum supported width.
        max_width_bytes: u8,
    },
}

/// Error returned while encoding a marker payload body.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WhiteboxMarkerPayloadEncodeError {
    /// A string cannot fit in the `u16` length prefix.
    #[error("white-box marker field {field} length {len} exceeds maximum {max_len}")]
    StringTooLong {
        /// Field being encoded.
        field: &'static str,
        /// Observed byte count.
        len: usize,
        /// Maximum encodable byte count.
        max_len: usize,
    },
    /// The detail vector cannot fit in the `u16` count prefix.
    #[error("white-box marker detail count {count} exceeds maximum {max_count}")]
    TooManyDetails {
        /// Observed detail count.
        count: usize,
        /// Maximum encodable detail count.
        max_count: usize,
    },
    /// A complete encoded frame exceeds the doorbell frame payload ceiling.
    #[error("white-box marker frame payload length {len} exceeds maximum {max_len}")]
    FramePayloadTooLarge {
        /// Observed frame payload length.
        len: usize,
        /// Maximum encodable frame payload length.
        max_len: usize,
    },
    /// A random request asked for an invalid reply width.
    #[error("white-box random request width {width_bytes} is outside 1..={max_width_bytes}")]
    InvalidRandomWidth {
        /// Requested width.
        width_bytes: u8,
        /// Maximum supported width.
        max_width_bytes: u8,
    },
}

/// One frozen marker-payload golden vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhiteboxMarkerPayloadGoldenVector {
    /// Stable corpus name.
    pub name: &'static str,
    /// Doorbell protocol version the vector belongs to.
    pub protocol_version: u16,
    /// Marker kind carried by the vector.
    pub kind: u16,
    /// Kind-specific body bytes.
    pub payload: &'static [u8],
    /// Complete doorbell frame bytes.
    pub frame: &'static [u8],
}

/// Frozen marker-payload golden-vector corpus.
pub const GOLDEN_WHITEBOX_MARKER_PAYLOAD_VECTORS: [WhiteboxMarkerPayloadGoldenVector; 5] = [
    WhiteboxMarkerPayloadGoldenVector {
        name: "assert-always",
        protocol_version: 2,
        kind: WHITEBOX_DOORBELL_KIND_ASSERTION,
        payload: &[
            0, 1, 1, 9, 0, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x2e, 0x6f, 0x6b, 2, 0, 0x6f, 0x6b,
            10, 0, 0x67, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x72, 0x73, 0x3a, 0x37, 1, 0, 4, 0, 0x63,
            0x61, 0x73, 0x65, 5, 0, 0x73, 0x6d, 0x6f, 0x6b, 0x65,
        ],
        frame: &[
            0x43, 0x52, 0x42, 0x4c, 2, 0, 1, 0, 45, 0, 0, 0, 0, 1, 1, 9, 0, 0x61, 0x73, 0x73, 0x65,
            0x72, 0x74, 0x2e, 0x6f, 0x6b, 2, 0, 0x6f, 0x6b, 10, 0, 0x67, 0x75, 0x65, 0x73, 0x74,
            0x2e, 0x72, 0x73, 0x3a, 0x37, 1, 0, 4, 0, 0x63, 0x61, 0x73, 0x65, 5, 0, 0x73, 0x6d,
            0x6f, 0x6b, 0x65,
        ],
    },
    WhiteboxMarkerPayloadGoldenVector {
        name: "lifecycle-setup-complete",
        protocol_version: 2,
        kind: WHITEBOX_DOORBELL_KIND_LIFECYCLE,
        payload: &[1, 0],
        frame: &[0x43, 0x52, 0x42, 0x4c, 2, 0, 2, 0, 2, 0, 0, 0, 1, 0],
    },
    WhiteboxMarkerPayloadGoldenVector {
        name: "event-note",
        protocol_version: 2,
        kind: WHITEBOX_DOORBELL_KIND_EVENT,
        payload: &[
            4, 0, 0x6e, 0x6f, 0x74, 0x65, 1, 0, 5, 0, 0x70, 0x68, 0x61, 0x73, 0x65, 4, 0, 0x69,
            0x6e, 0x69, 0x74,
        ],
        frame: &[
            0x43, 0x52, 0x42, 0x4c, 2, 0, 3, 0, 21, 0, 0, 0, 4, 0, 0x6e, 0x6f, 0x74, 0x65, 1, 0, 5,
            0, 0x70, 0x68, 0x61, 0x73, 0x65, 4, 0, 0x69, 0x6e, 0x69, 0x74,
        ],
    },
    WhiteboxMarkerPayloadGoldenVector {
        name: "coverage-hot-path",
        protocol_version: 2,
        kind: WHITEBOX_DOORBELL_KIND_COVERAGE,
        payload: &[8, 0, 0x68, 0x6f, 0x74, 0x2d, 0x70, 0x61, 0x74, 0x68],
        frame: &[
            0x43, 0x52, 0x42, 0x4c, 2, 0, 4, 0, 10, 0, 0, 0, 8, 0, 0x68, 0x6f, 0x74, 0x2d, 0x70,
            0x61, 0x74, 0x68,
        ],
    },
    WhiteboxMarkerPayloadGoldenVector {
        name: "random-request",
        protocol_version: 2,
        kind: WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
        payload: &[0x04, 0x03, 0x02, 0x01, 4, 3, 0, 0x72, 0x6e, 0x67],
        frame: &[
            0x43, 0x52, 0x42, 0x4c, 2, 0, 5, 0, 10, 0, 0, 0, 0x04, 0x03, 0x02, 0x01, 4, 3, 0, 0x72,
            0x6e, 0x67,
        ],
    },
];
