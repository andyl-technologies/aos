//! Counted display output admitted before its owned byte buffer is allocated.

use std::fmt::{self, Display, Write};

use super::{DecodeAdmissionError, reserve_vec};

struct Counter(usize);

impl Write for Counter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 = self.0.checked_add(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

struct Output {
    bytes: Vec<u8>,
    length: usize,
}

impl Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > self.length.saturating_sub(self.bytes.len()) {
            return Err(fmt::Error);
        }
        self.bytes.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

/// Renders borrowed display text after reserving its exact output storage.
///
/// The second pass cannot grow beyond the counted length. Custom formatters
/// must separately admit any private allocations they perform.
///
/// # Errors
/// Refuses length overflow, formatting or allocation failure, exhausted
/// original credit, or a formatter changing its output length between passes.
pub fn display_string(value: &(impl Display + ?Sized)) -> Result<String, DecodeAdmissionError> {
    let mut count = Counter(0);
    write!(&mut count, "{value}").map_err(DecodeAdmissionError::new)?;
    let mut bytes = Vec::new();
    reserve_vec(&mut bytes, count.0)?;
    let mut output = Output {
        bytes,
        length: count.0,
    };
    write!(&mut output, "{value}").map_err(DecodeAdmissionError::new)?;
    if output.bytes.len() != count.0 {
        return Err(DecodeAdmissionError::new(fmt::Error));
    }
    String::from_utf8(output.bytes).map_err(DecodeAdmissionError::new)
}
