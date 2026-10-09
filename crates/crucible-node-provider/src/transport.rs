//! Length-prefixed CNP/1 stream framing with fatal-error fencing.
//!
//! ```text
//! frame = uint32_be(json_byte_length) || utf8_json
//! ```
//!
//! A framing or parsing failure permanently poisons the reader. Its owner must
//! close the connection and retain any unresolved operation obligations.

use std::io::{Read, Write};

use crucible_node_contract::canonical;
use serde_json::Value;

use crate::ProviderError;

/// Limits JSON bytes in one CNP/1 frame before body allocation.
pub const MAX_FRAME_BYTES: usize = 16_777_216;

/// Limits nested JSON containers independently of frame byte length.
pub const MAX_NESTING: usize = 64;

/// Decodes bounded frames from a stream whose reads may split any byte range.
pub struct FrameReader<R> {
    stream: R,
    maximum_bytes: usize,
    maximum_nesting: usize,
    failed: bool,
}

impl<R: Read> FrameReader<R> {
    /// Creates a reader with a positive limit within the CNP/1 hard ceiling.
    ///
    /// # Errors
    /// Rejects a zero allowance or one larger than [`MAX_FRAME_BYTES`].
    pub fn new(stream: R, maximum_bytes: usize) -> Result<Self, ProviderError> {
        Self::with_limits(stream, maximum_bytes, MAX_NESTING)
    }

    /// Creates a reader enforcing both negotiated byte and nesting limits.
    ///
    /// # Errors
    /// Rejects zero or larger-than-baseline limits before reading any bytes.
    pub fn with_limits(
        stream: R,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        check_limit(maximum_bytes)?;
        if maximum_nesting == 0 || maximum_nesting > MAX_NESTING {
            return Err(ProviderError::Frame("invalid negotiated nesting limit"));
        }

        Ok(Self {
            stream,
            maximum_bytes,
            maximum_nesting,
            failed: false,
        })
    }

    /// Reads exactly one JSON frame, distinguishing clean EOF from truncation.
    ///
    /// # Errors
    /// Rejects invalid lengths before allocation, partial frames, malformed
    /// JSON, duplicate keys, invalid Unicode, and reuse after any failure.
    /// An error leaves the stream fenced; bytes are never scanned to resync.
    pub fn read(&mut self) -> Result<Option<Value>, ProviderError> {
        if self.failed {
            return Err(ProviderError::Frame("connection already failed"));
        }

        let result = self.read_frame();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(crate) fn stream_mut(&mut self) -> &mut R {
        &mut self.stream
    }

    fn read_frame(&mut self) -> Result<Option<Value>, ProviderError> {
        let mut header = [0_u8; 4];
        let first = loop {
            match self.stream.read(&mut header[..1]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if first == 0 {
            return Ok(None);
        }
        self.stream.read_exact(&mut header[1..])?;

        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > self.maximum_bytes {
            return Err(ProviderError::Frame("length outside admitted allowance"));
        }

        let mut body = vec![0_u8; length];
        self.stream.read_exact(&mut body)?;
        Ok(Some(canonical::parse_json_with_depth(
            &body,
            self.maximum_bytes,
            self.maximum_nesting,
        )?))
    }
}

/// Writes one bounded canonical JSON frame to a connected stream.
///
/// # Errors
/// Rejects invalid limits, oversized JSON and I/O failures. Partial writes
/// leave the connection unusable; callers must retain uncertain effects and
/// must not retransmit on the same stream as a new operation.
pub fn write_frame(
    stream: &mut impl Write,
    value: &Value,
    maximum_bytes: usize,
) -> Result<(), ProviderError> {
    write_frame_with_limits(stream, value, maximum_bytes, MAX_NESTING)
}

/// Writes a frame under the negotiated byte and container-depth allowances.
///
/// # Errors
/// Rejects invalid limits, JSON outside either allowance, or incomplete I/O.
/// Validation finishes before any frame bytes are sent. An I/O failure leaves
/// the connection unusable and does not settle any associated operation.
pub fn write_frame_with_limits(
    stream: &mut impl Write,
    value: &Value,
    maximum_bytes: usize,
    maximum_nesting: usize,
) -> Result<(), ProviderError> {
    check_limit(maximum_bytes)?;
    if maximum_nesting == 0 || maximum_nesting > MAX_NESTING {
        return Err(ProviderError::Frame("invalid negotiated nesting limit"));
    }

    let bytes = canonical::canonical_json(value)?;
    if bytes.len() > maximum_bytes {
        return Err(ProviderError::Frame("outgoing length exceeds allowance"));
    }
    canonical::parse_json_with_depth(&bytes, maximum_bytes, maximum_nesting)?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| ProviderError::Frame("outgoing length is unrepresentable"))?;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn check_limit(maximum_bytes: usize) -> Result<(), ProviderError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_FRAME_BYTES {
        return Err(ProviderError::Frame("invalid negotiated frame limit"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;

    struct Fragmented {
        bytes: Cursor<Vec<u8>>,
    }

    impl Read for Fragmented {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(1);
            self.bytes.read(&mut output[..length])
        }
    }

    #[test]
    fn stream_fragmentation_and_adjacent_frames_preserve_boundaries() {
        let mut stream = Vec::new();
        write_frame(&mut stream, &json!({"one": "1"}), 128).unwrap();
        write_frame(&mut stream, &json!({"two": "2"}), 128).unwrap();
        let mut reader = FrameReader::new(
            Fragmented {
                bytes: Cursor::new(stream),
            },
            128,
        )
        .unwrap();

        assert_eq!(reader.read().unwrap(), Some(json!({"one": "1"})));
        assert_eq!(reader.read().unwrap(), Some(json!({"two": "2"})));
        assert_eq!(reader.read().unwrap(), None);
    }

    #[test]
    fn truncation_is_not_clean_eof_and_fences_reuse() {
        for bytes in [vec![0], vec![0, 0, 0], vec![0, 0, 0, 2, b'{']] {
            let mut reader = FrameReader::new(Cursor::new(bytes), 128).unwrap();

            assert!(reader.read().is_err());
            assert!(matches!(
                reader.read(),
                Err(ProviderError::Frame("connection already failed"))
            ));
        }
    }

    #[test]
    fn invalid_prefix_never_allocates_or_reads_the_body() {
        for length in [0_u32, 129, u32::MAX] {
            let bytes = length.to_be_bytes().to_vec();
            let mut reader = FrameReader::new(Cursor::new(bytes), 128).unwrap();

            assert!(matches!(reader.read(), Err(ProviderError::Frame(_))));
            assert_eq!(reader.stream.position(), 4);
        }
    }

    #[test]
    fn duplicate_keys_and_invalid_unicode_are_fatal() {
        for body in [
            b"{\"a\":1,\"a\":2}".as_slice(),
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\xff\"}",
        ] {
            let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(body);
            let mut reader = FrameReader::new(Cursor::new(bytes), 128).unwrap();

            assert!(reader.read().is_err());
            assert!(reader.read().is_err());
        }
    }

    #[test]
    fn a_smaller_negotiated_nesting_limit_is_enforced() {
        let mut stream = Vec::new();
        write_frame(&mut stream, &json!({"nested": {"value": "1"}}), 128).unwrap();
        let mut reader = FrameReader::with_limits(Cursor::new(stream), 128, 1).unwrap();

        assert!(reader.read().is_err());
        assert!(reader.read().is_err());
    }

    #[test]
    fn outbound_validation_finishes_before_frame_publication() {
        let mut stream = Vec::new();
        let nested = json!({"nested": {"value": "1"}});

        assert!(write_frame_with_limits(&mut stream, &nested, 128, 1).is_err());
        assert!(stream.is_empty());

        write_frame_with_limits(&mut stream, &nested, 128, 2).unwrap();
        let mut reader = FrameReader::with_limits(Cursor::new(stream), 128, 2).unwrap();
        assert_eq!(reader.read().unwrap(), Some(nested));
    }
}
