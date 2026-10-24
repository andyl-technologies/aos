//! Borrows validated exchange records without constructing owned payloads.
//!
//! The parent module specifies the fixed `CRGX` wire format. A view retains its
//! original complete `CRGI` slice; encoding copies it directly to fixed storage.

use super::*;

/// One validated fixed-size exchange with a borrowed encoded record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestIntrospectionDoorbellView<'a> {
    kind: GuestIntrospectionDoorbellKind,
    record: Option<&'a [u8]>,
}

impl<'a> GuestIntrospectionDoorbellView<'a> {
    /// Builds an exchange from an optional borrowed canonical record.
    ///
    /// # Errors
    /// Returns a record error for malformed encoded fields, or a kind/record
    /// mismatch when the exchange kind and record presence disagree.
    pub fn new(
        kind: GuestIntrospectionDoorbellKind,
        record: Option<&'a [u8]>,
    ) -> Result<Self, GuestIntrospectionDoorbellError> {
        if let Some(bytes) = record {
            GuestIntrospectionRecord::validate_encoded(bytes)
                .map_err(GuestIntrospectionDoorbellError::Record)?;
        }
        if kind.carries_record() != record.is_some() {
            return Err(GuestIntrospectionDoorbellError::KindRecordMismatch { kind });
        }
        Ok(Self { kind, record })
    }

    /// Borrows and validates an exact fixed-size guest exchange buffer.
    ///
    /// # Errors
    /// Returns the same framing, reserved-byte, padding and record errors as
    /// [`GuestIntrospectionDoorbellFrame::decode`].
    pub fn decode(bytes: &'a [u8]) -> Result<Self, GuestIntrospectionDoorbellError> {
        let (kind, record) = parse_frame(bytes)?;
        Self::new(kind, record)
    }

    /// Returns the validated exchange kind.
    #[must_use]
    pub const fn kind(&self) -> GuestIntrospectionDoorbellKind {
        self.kind
    }

    /// Returns the original complete encoded record, when present.
    #[must_use]
    pub const fn record(&self) -> Option<&'a [u8]> {
        self.record
    }

    /// Copies the validated exchange into its exact zero-padded fixed buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES] {
        let mut output = [0; GUEST_INTROSPECTION_DOORBELL_FRAME_BYTES];
        let length = self.record.map_or(0, <[u8]>::len);
        output[..4].copy_from_slice(&GUEST_INTROSPECTION_DOORBELL_MAGIC);
        output[4..6].copy_from_slice(&GUEST_INTROSPECTION_DOORBELL_VERSION.to_le_bytes());
        output[6] = self.kind.wire_value();
        // Private validated fields bound the complete record to 4,592 bytes.
        output[8..12].copy_from_slice(&(length as u32).to_le_bytes());
        if let Some(record) = self.record {
            let end = GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES + record.len();
            output[GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES..end].copy_from_slice(record);
        }
        output
    }
}

/// Parses frame shape without constructing or validating owned record fields.
///
/// # Errors
/// Returns invalid header, record extent, presence or padding errors.
pub(super) fn parse_frame(
    bytes: &[u8],
) -> Result<(GuestIntrospectionDoorbellKind, Option<&[u8]>), GuestIntrospectionDoorbellError> {
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
        Some(&bytes[GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES..record_end])
    };
    Ok((kind, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_introspection::{
        GuestIntrospectionMessage, GuestOutputStream, GUEST_INTROSPECTION_MAX_CHUNK_BYTES,
    };

    #[test]
    fn borrowed_exchange_preserves_maximum_payload_and_literal_header() {
        let record = GuestIntrospectionRecord::new(
            7,
            GuestIntrospectionMessage::Output {
                stream: GuestOutputStream::Stderr,
                bytes: vec![0x5a; GUEST_INTROSPECTION_MAX_CHUNK_BYTES],
            },
        )
        .unwrap();
        let expected_record = record.encode().unwrap();
        let expected_frame = GuestIntrospectionDoorbellFrame::response(record)
            .encode()
            .unwrap();

        let view = GuestIntrospectionDoorbellView::decode(&expected_frame).unwrap();

        assert_eq!(view.kind(), GuestIntrospectionDoorbellKind::Response);
        assert_eq!(view.record(), Some(expected_record.as_slice()));
        assert_eq!(
            view.record().unwrap().as_ptr(),
            expected_frame[GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES..].as_ptr()
        );
        assert_eq!(
            &expected_frame[..16],
            &[
                b'C', b'R', b'G', b'X', 1, 0, 2, 0, 0x14, 0x10, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(view.encode(), expected_frame);
        assert_eq!(
            GuestIntrospectionDoorbellView::new(view.kind(), view.record())
                .unwrap()
                .encode(),
            expected_frame
        );
        assert!(
            expected_frame[GUEST_INTROSPECTION_DOORBELL_HEADER_BYTES + expected_record.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn borrowed_exchange_refuses_header_record_and_padding_mutations() {
        let record = GuestIntrospectionRecord::new(7, GuestIntrospectionMessage::Close).unwrap();
        let valid = GuestIntrospectionDoorbellFrame::request(record)
            .encode()
            .unwrap();
        for (offset, value, expected) in [
            (0, 0, GuestIntrospectionDoorbellError::Magic),
            (4, 2, GuestIntrospectionDoorbellError::Version { actual: 2 }),
            (
                6,
                255,
                GuestIntrospectionDoorbellError::Kind { actual: 255 },
            ),
            (7, 1, GuestIntrospectionDoorbellError::Reserved),
            (12, 1, GuestIntrospectionDoorbellError::Reserved),
            (
                16,
                0,
                GuestIntrospectionDoorbellError::Record(GuestIntrospectionError::InvalidMagic),
            ),
            (4607, 1, GuestIntrospectionDoorbellError::NonzeroPadding),
        ] {
            let mut changed = valid;
            changed[offset] = value;

            assert_eq!(
                GuestIntrospectionDoorbellView::decode(&changed),
                Err(expected.clone())
            );
            assert_eq!(
                GuestIntrospectionDoorbellFrame::decode(&changed),
                Err(expected)
            );
        }
        for length in 0..valid.len() {
            assert_eq!(
                GuestIntrospectionDoorbellView::decode(&valid[..length]),
                Err(GuestIntrospectionDoorbellError::FrameLength { actual: length })
            );
        }
        assert_eq!(
            GuestIntrospectionDoorbellView::new(GuestIntrospectionDoorbellKind::Request, None),
            Err(GuestIntrospectionDoorbellError::KindRecordMismatch {
                kind: GuestIntrospectionDoorbellKind::Request
            })
        );
    }
}
