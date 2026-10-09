//! Borrowed native record payload decoding and canonical byte encoding.
//!
//! The namespace byte is uninterpreted DATA. Domain owners decode their closed
//! namespace after the header-length check and before field validation, then
//! allocate their owned records only after the complete payload passes bounds.
//! This module does not admit records, transactions, or semantic transitions.
//!
//! ```text
//! namespace:u8 | key-length:u16le | value-length:u32le | key | value
//! value-length = u32::MAX represents DELETE and carries no value bytes
//! ```

use crate::framing::FrameError;
use crate::geometry::EncodedRecordLayout;

/// Reports native record representation failures without namespace admission.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The payload violates the existing native record layout.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
    /// A key or checked payload width exceeds its existing bound.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

/// Borrows a payload whose fixed header is present but not yet interpreted.
pub struct RecordHeader<'a> {
    payload: &'a [u8],
}

impl<'a> RecordHeader<'a> {
    /// Checks only that the native seven-byte header is present.
    ///
    /// The owner performs closed namespace decoding before calling
    /// [`Self::decode_fields`]. No payload bytes are allocated or copied.
    ///
    /// # Errors
    ///
    /// Returns the existing truncated-header error for fewer than seven bytes.
    pub fn read(payload: &'a [u8]) -> Result<Self, RecordError> {
        if payload.len() < 7 {
            return Err(RecordError::MalformedRecord("record header is truncated"));
        }
        Ok(Self { payload })
    }

    /// Returns the raw namespace byte without decoding or admitting it.
    #[must_use]
    pub fn namespace_byte(&self) -> u8 {
        self.payload[0]
    }

    /// Decodes bounded key/value slices after the owner's namespace check.
    ///
    /// The returned slices borrow the original payload. This checks lengths,
    /// not domain record semantics, and makes no owned allocation.
    ///
    /// # Errors
    ///
    /// Preserves the original width parsing, key-bound, checked payload-width,
    /// and exact/maximum payload-length errors in that order. A payload exceeding
    /// the record-byte bound remains a malformed record-length error.
    pub fn decode_fields(
        &self,
        maximum_key_bytes: usize,
        maximum_record_bytes: usize,
    ) -> Result<RecordFields<'a>, RecordError> {
        let payload = self.payload;
        let key_length = u16::from_le_bytes([payload[1], payload[2]]) as usize;
        let value_length = u32::from_le_bytes(
            payload[3..7]
                .try_into()
                .map_err(|_| RecordError::MalformedRecord("invalid value length"))?,
        );
        if key_length == 0 || key_length > maximum_key_bytes {
            return Err(RecordError::LimitExceeded("record key bytes"));
        }
        let expected = if value_length == u32::MAX {
            7_usize.checked_add(key_length)
        } else {
            7_usize
                .checked_add(key_length)
                .and_then(|length| length.checked_add(value_length as usize))
        }
        .ok_or(RecordError::LimitExceeded("record payload bytes"))?;
        if expected != payload.len() || payload.len() > maximum_record_bytes {
            return Err(RecordError::MalformedRecord("record length mismatch"));
        }
        let key = &payload[7..7 + key_length];
        let value = if value_length == u32::MAX {
            None
        } else {
            Some(&payload[7 + key_length..])
        };
        Ok(RecordFields { key, value })
    }
}

/// Borrows structurally decoded record DATA without admitting its contents.
pub struct RecordFields<'a> {
    /// Borrows the exact key bytes from the original payload.
    pub key: &'a [u8],
    /// Borrows a present, possibly empty, value or represents a DELETE.
    pub value: Option<&'a [u8]>,
}

/// Encodes raw namespace DATA and fields using the existing native geometry.
///
/// This does not validate namespace identity, nonempty keys, or domain records.
/// The checked layout precedes allocation and copies the actual supplied bytes.
///
/// # Errors
///
/// Preserves existing key-width, value-width, and aggregate payload-width errors
/// from [`EncodedRecordLayout`], before allocating the payload.
///
/// # Panics
///
/// Panics if the resulting allocation exceeds the platform's `Vec` capacity
/// bound, preserving the existing encoder's allocation behavior.
pub fn encode_record_fields(
    namespace_byte: u8,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<Vec<u8>, FrameError> {
    let layout = EncodedRecordLayout::new(key.len(), value.map(<[u8]>::len))?;
    let value_bytes = value.unwrap_or_default();
    let mut payload = Vec::with_capacity(layout.payload_bytes);
    payload.push(namespace_byte);
    payload.extend_from_slice(&layout.key_length.to_le_bytes());
    payload.extend_from_slice(&layout.value_length.to_le_bytes());
    payload.extend_from_slice(key);
    payload.extend_from_slice(value_bytes);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_put_empty_put_and_delete_bytes_remain_little_endian() {
        let cases: [(Option<&[u8]>, &[u8]); 3] = [
            (Some(b"v"), &[254, 1, 0, 1, 0, 0, 0, b'k', b'v']),
            (Some(b""), &[254, 1, 0, 0, 0, 0, 0, b'k']),
            (None, &[254, 1, 0, 255, 255, 255, 255, b'k']),
        ];

        for (value, expected) in cases {
            let payload = encode_record_fields(254, b"k", value).unwrap();

            assert_eq!(payload, expected);
            let header = RecordHeader::read(&payload).unwrap();
            assert_eq!(header.namespace_byte(), 254);
            let fields = header.decode_fields(1, payload.len()).unwrap();
            assert_eq!(fields.key, b"k");
            assert_eq!(fields.value, value);
            assert!(std::ptr::eq(fields.key, &payload[7..8]));
            if let Some(value) = fields.value {
                assert!(std::ptr::eq(value, &payload[8..]));
            }
        }
    }

    #[test]
    fn header_stage_checks_only_presence_and_exposes_raw_namespace_data() {
        let payload = [255, 0, 0, 255, 255, 255, 255];

        for length in 0..7 {
            assert!(matches!(
                RecordHeader::read(&payload[..length]),
                Err(RecordError::MalformedRecord("record header is truncated")),
            ));
        }
        let header = RecordHeader::read(&payload).unwrap();

        assert_eq!(header.namespace_byte(), 255);
        assert!(matches!(
            header.decode_fields(0, 0),
            Err(RecordError::LimitExceeded("record key bytes")),
        ));
    }

    #[test]
    fn field_bounds_preserve_key_before_length_and_malformed_payload_limit() {
        let short = [255, 2, 0, 0, 0, 0, 0, b'k'];
        let header = RecordHeader::read(&short).unwrap();

        assert!(matches!(
            header.decode_fields(1, 0),
            Err(RecordError::LimitExceeded("record key bytes")),
        ));
        assert!(matches!(
            header.decode_fields(2, usize::MAX),
            Err(RecordError::MalformedRecord("record length mismatch")),
        ));

        let payload = encode_record_fields(255, b"k", Some(b"v")).unwrap();
        let header = RecordHeader::read(&payload).unwrap();

        assert!(matches!(
            header.decode_fields(1, payload.len() - 1),
            Err(RecordError::MalformedRecord("record length mismatch")),
        ));
        assert!(header.decode_fields(1, payload.len()).is_ok());
    }

    #[test]
    fn trailing_bytes_and_delete_value_bytes_are_not_silently_discarded() {
        for value in [Some(b"v".as_slice()), None] {
            let mut payload = encode_record_fields(1, b"k", value).unwrap();
            payload.push(0);
            let header = RecordHeader::read(&payload).unwrap();

            assert!(matches!(
                header.decode_fields(1, usize::MAX),
                Err(RecordError::MalformedRecord("record length mismatch")),
            ));
        }
    }

    #[test]
    fn encoder_width_checks_do_not_admit_nonempty_keys() {
        let payload = encode_record_fields(255, b"", Some(b"v")).unwrap();
        let header = RecordHeader::read(&payload).unwrap();

        assert!(matches!(
            header.decode_fields(usize::MAX, usize::MAX),
            Err(RecordError::LimitExceeded("record key bytes")),
        ));
        assert!(matches!(
            encode_record_fields(255, &vec![0; u16::MAX as usize + 1], Some(b"")),
            Err(FrameError::LimitExceeded("record key bytes")),
        ));
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn checked_payload_sum_rejects_32_bit_overflow_before_length_mismatch() {
        let payload = [255, 255, 255, 254, 255, 255, 255];
        let header = RecordHeader::read(&payload).unwrap();

        assert!(matches!(
            header.decode_fields(u16::MAX as usize, usize::MAX),
            Err(RecordError::LimitExceeded("record payload bytes")),
        ));
    }
}
