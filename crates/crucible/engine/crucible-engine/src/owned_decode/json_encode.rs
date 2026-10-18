//! Exact borrowed JSON output ownership under the active original account.

use std::io::{self, Write};

use super::{DecodeAdmissionError, reserve_vec};

struct Counter {
    length: usize,
    maximum: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::other("JSON output exceeds its admitted format bound"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Output {
    bytes: Vec<u8>,
    length: usize,
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.length.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "JSON serialization changed after counting",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encodes borrowed JSON after reserving its exact output storage.
///
/// # Errors
/// Refuses length overflow, invalid serialization, allocation failure, or an
/// exhausted original account before constructing the owned output buffer.
pub fn to_json_vec<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, DecodeAdmissionError> {
    to_json_vec_bounded(value, usize::MAX)
}

/// Encodes borrowed JSON within both its format ceiling and original account.
///
/// The second pass cannot grow beyond the first pass's exact count. Custom
/// serializers must themselves admit any private allocations they perform.
///
/// # Errors
/// Returns the same failures as [`to_json_vec`], and refuses output longer
/// than `maximum` or a serializer that changes its output between passes.
pub fn to_json_vec_bounded<T: serde::Serialize + ?Sized>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, DecodeAdmissionError> {
    let mut count = Counter { length: 0, maximum };
    serde_json::to_writer(&mut count, value).map_err(DecodeAdmissionError::new)?;
    let mut bytes = Vec::new();
    reserve_vec(&mut bytes, count.length)?;
    let mut output = Output {
        bytes,
        length: count.length,
    };
    serde_json::to_writer(&mut output, value).map_err(DecodeAdmissionError::new)?;
    if output.bytes.len() != count.length {
        return Err(DecodeAdmissionError::new(io::Error::other(
            "JSON serialization changed after counting",
        )));
    }
    Ok(output.bytes)
}
