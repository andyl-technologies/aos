//! Plugin-to-host transport for completed app-random doorbell decisions.
//!
//! This is not a guest ABI. The guest sends the frozen kind-5 request body;
//! after serving it synchronously, the production plugin publishes this compact
//! result through the existing plugin-to-host SPSC queue:
//!
//! ```text
//! offset  size  field
//! 0       4     guest request id, little-endian
//! 4       1     reply width in bytes
//! 5       8     served value, little-endian
//! 13      2     stream-tag byte length, little-endian
//! 15      N     UTF-8 stream tag
//! ```

use thiserror::Error;

/// Internal SPSC entry kind for a completed app-random decision.
///
/// The value is outside the frozen guest marker-kind registry and therefore
/// cannot be confused with a guest-originated observational marker.
pub const WHITEBOX_SHMEM_KIND_APP_RANDOM_DECISION: u16 = 0xff05;

const FIXED_LEN: usize = 15;

/// Returns the canonical default-domain stream name for one node and guest tag.
#[must_use]
pub fn app_random_stream_name(node_name: &str, stream_tag: &str) -> String {
    format!(
        "app-random/node:{}:{}/stream:{}:{}",
        node_name.len(),
        node_name,
        stream_tag.len(),
        stream_tag
    )
}

/// Returns whether a canonical app-random stream name belongs to `node_name`.
///
/// The length-framed node component prevents a prefix collision with another
/// node name or an embedded `/stream:` substring.
#[must_use]
pub fn app_random_stream_name_belongs_to_node(stream_name: &str, node_name: &str) -> bool {
    app_random_stream_name_components(stream_name)
        .is_some_and(|(recorded_node, _stream_tag)| recorded_node == node_name)
}

/// Returns whether `stream_name` is one canonical app-random stream name.
///
/// This parser is used when a typed campaign branch replaces a model-sampled
/// selection: the preceding named RNG draw remains the schedule-level proof
/// that the branch consumes one application-random request.
#[must_use]
pub fn app_random_stream_name_is_canonical(stream_name: &str) -> bool {
    app_random_stream_name_components(stream_name).is_some()
}

fn app_random_stream_name_components(stream_name: &str) -> Option<(&str, &str)> {
    let framed_node = stream_name.strip_prefix("app-random/node:")?;
    let (declared_node_len, node_and_stream) = framed_node.split_once(':')?;
    let node_len = parse_canonical_length(declared_node_len)?;
    let node = node_and_stream.get(..node_len)?;
    let framed_stream = node_and_stream
        .get(node_len..)
        .and_then(|tail| tail.strip_prefix("/stream:"))?;
    let (declared_tag_len, tag) = framed_stream.split_once(':')?;
    (parse_canonical_length(declared_tag_len) == Some(tag.len())).then_some((node, tag))
}

fn parse_canonical_length(value: &str) -> Option<usize> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.bytes().try_fold(0_usize, |length, byte| {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        length.checked_mul(10)?.checked_add(usize::from(digit))
    })
}

/// One completed deterministic app-random request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomDecisionTransportRecord {
    request_id: u32,
    width_bytes: u8,
    value: u64,
    stream_tag: String,
}

impl AppRandomDecisionTransportRecord {
    /// Builds a transport record after validating the requested width and value.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomDecisionTransportError`] when the width is outside
    /// `1..=8`, the value does not fit that width, or the stream tag is too long.
    pub fn new(
        request_id: u32,
        width_bytes: u8,
        value: u64,
        stream_tag: impl Into<String>,
    ) -> Result<Self, AppRandomDecisionTransportError> {
        let stream_tag = stream_tag.into();
        validate(width_bytes, value, stream_tag.len())?;
        Ok(Self {
            request_id,
            width_bytes,
            value,
            stream_tag,
        })
    }

    /// Decodes one complete plugin-to-host result record.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomDecisionTransportError`] when the bytes are truncated,
    /// have trailing data, contain invalid UTF-8, or fail width/value validation.
    pub fn decode(bytes: &[u8]) -> Result<Self, AppRandomDecisionTransportError> {
        if bytes.len() < FIXED_LEN {
            return Err(AppRandomDecisionTransportError::Truncated {
                len: bytes.len(),
                minimum_len: FIXED_LEN,
            });
        }
        let request_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let width_bytes = bytes[4];
        let value = u64::from_le_bytes([
            bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
        ]);
        let tag_len = usize::from(u16::from_le_bytes([bytes[13], bytes[14]]));
        let expected_len = FIXED_LEN.saturating_add(tag_len);
        if bytes.len() != expected_len {
            return Err(AppRandomDecisionTransportError::LengthMismatch {
                expected_len,
                actual_len: bytes.len(),
            });
        }
        let stream_tag = std::str::from_utf8(&bytes[FIXED_LEN..])
            .map_err(|_source| AppRandomDecisionTransportError::InvalidUtf8)?
            .to_owned();
        Self::new(request_id, width_bytes, value, stream_tag)
    }

    /// Encodes the record for one shared-memory entry payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_LEN + self.stream_tag.len());
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.push(self.width_bytes);
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(&(self.stream_tag.len() as u16).to_le_bytes());
        bytes.extend_from_slice(self.stream_tag.as_bytes());
        bytes
    }

    /// Returns the guest-provided request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// Returns the reply width in bytes.
    #[must_use]
    pub const fn width_bytes(&self) -> u8 {
        self.width_bytes
    }

    /// Returns the deterministic value written to guest memory.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns the guest-provided stream tag.
    #[must_use]
    pub fn stream_tag(&self) -> &str {
        &self.stream_tag
    }
}

fn validate(
    width_bytes: u8,
    value: u64,
    stream_tag_len: usize,
) -> Result<(), AppRandomDecisionTransportError> {
    if !(1..=8).contains(&width_bytes) {
        return Err(AppRandomDecisionTransportError::InvalidWidth { width_bytes });
    }
    let width_bits = width_bytes.saturating_mul(8);
    if width_bits < 64 && value >= (1_u64 << width_bits) {
        return Err(AppRandomDecisionTransportError::ValueOutOfRange { width_bits, value });
    }
    if stream_tag_len > usize::from(u16::MAX) {
        return Err(AppRandomDecisionTransportError::StreamTagTooLong {
            len: stream_tag_len,
            maximum: usize::from(u16::MAX),
        });
    }
    Ok(())
}

/// Invalid plugin-to-host app-random result bytes.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRandomDecisionTransportError {
    /// The fixed portion of the record was missing.
    #[error("app-random decision record has {len} bytes, expected at least {minimum_len}")]
    Truncated {
        /// Actual byte length.
        len: usize,
        /// Minimum fixed length.
        minimum_len: usize,
    },
    /// The stream-tag length did not consume the complete entry.
    #[error("app-random decision record length is {actual_len}, expected {expected_len}")]
    LengthMismatch {
        /// Length declared by the fixed header.
        expected_len: usize,
        /// Actual payload length.
        actual_len: usize,
    },
    /// The reply width was outside `1..=8`.
    #[error("app-random decision width {width_bytes} bytes is outside 1..=8")]
    InvalidWidth {
        /// Invalid reply width.
        width_bytes: u8,
    },
    /// The served value did not fit the requested width.
    #[error("app-random value {value} does not fit {width_bits} bits")]
    ValueOutOfRange {
        /// Requested width in bits.
        width_bits: u8,
        /// Invalid value.
        value: u64,
    },
    /// The stream tag exceeded its fixed `u16` prefix.
    #[error("app-random stream tag has {len} bytes, maximum {maximum}")]
    StreamTagTooLong {
        /// Actual byte length.
        len: usize,
        /// Maximum representable byte length.
        maximum: usize,
    },
    /// The stream tag was not UTF-8.
    #[error("app-random stream tag is not valid UTF-8")]
    InvalidUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_decision_round_trips() {
        let record = AppRandomDecisionTransportRecord::new(7, 3, 0x0000_beef, "node-local")
            .unwrap_or_else(|error| panic!("record should validate: {error}"));
        assert_eq!(
            AppRandomDecisionTransportRecord::decode(&record.encode()),
            Ok(record)
        );
    }

    #[test]
    fn completed_decision_rejects_out_of_range_value() {
        assert_eq!(
            AppRandomDecisionTransportRecord::new(7, 1, 0x100, "node-local"),
            Err(AppRandomDecisionTransportError::ValueOutOfRange {
                width_bits: 8,
                value: 0x100,
            })
        );
    }

    #[test]
    fn stream_name_membership_uses_the_complete_length_framed_node() {
        let stream = app_random_stream_name("node-a", "tag/with/slashes");
        assert!(app_random_stream_name_is_canonical(&stream));
        assert!(app_random_stream_name_belongs_to_node(&stream, "node-a"));
        assert!(!app_random_stream_name_belongs_to_node(&stream, "node"));
        assert!(!app_random_stream_name_belongs_to_node(
            &stream,
            "node-a/stream"
        ));
        assert!(!app_random_stream_name_belongs_to_node(
            "app-random/node:6:node-a/stream:3:toolong",
            "node-a"
        ));
        assert!(!app_random_stream_name_is_canonical(
            "app-random/node:6:node-a/stream:3:toolong"
        ));
        assert!(!app_random_stream_name_belongs_to_node(
            "app-random/node:6:node-a/stream:03:tag",
            "node-a"
        ));
        assert!(!app_random_stream_name_is_canonical(
            "app-random/node:6:node-a/stream:03:tag"
        ));
    }
}
