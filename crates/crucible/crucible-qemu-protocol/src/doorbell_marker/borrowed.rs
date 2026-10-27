//! Decodes marker bodies without copying their containing frame payload.

use super::{
    WhiteboxDoorbellMarkerKind, WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError,
    decode_marker_payload_body,
};
use crate::WhiteboxDoorbellFrameView;

/// Decodes a closed marker body directly from a borrowed doorbell frame.
///
/// The frame payload is not copied. Variable-length fields in the resulting
/// marker retain their existing owned representation and validation rules.
///
/// # Errors
///
/// Returns [`WhiteboxMarkerPayloadDecodeError`] for unknown marker kinds or
/// malformed kind-specific bodies.
pub fn decode_whitebox_marker_payload_view(
    frame: WhiteboxDoorbellFrameView<'_>,
) -> Result<WhiteboxMarkerPayload, WhiteboxMarkerPayloadDecodeError> {
    let Some(kind) = WhiteboxDoorbellMarkerKind::from_wire_value(frame.kind()) else {
        return Err(WhiteboxMarkerPayloadDecodeError::UnknownKind { kind: frame.kind() });
    };
    decode_marker_payload_body(kind, frame.payload())
}
