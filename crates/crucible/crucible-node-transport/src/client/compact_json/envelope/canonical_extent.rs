//! Counts JCS token widths without allocating whole strings, trees or text banks.
//!
//! Object order is immaterial to length. UTF-8 passes through JSON unchanged
//! except ASCII controls, quotation marks and reverse solidus. Number width
//! comes from the authoritative finite-number writer, including integer-to-f64
//! conversion and negative-zero normalization; bank bytes remain lossless.

use super::{Error, FLOAT, SIGNED, UNSIGNED};
use serde_json::{Number, Value};
use std::io::{self, Write};

pub(super) struct CanonicalExtent {
    used: usize,
    maximum: usize,
}

impl CanonicalExtent {
    pub(super) fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    pub(super) fn bytes(&self) -> usize {
        self.used
    }

    pub(super) fn add(&mut self, bytes: usize) -> Result<(), Error> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|&used| used <= self.maximum)
            .ok_or(Error::Geometry)?;
        Ok(())
    }

    pub(super) fn string(&mut self, text: &str) -> Result<(), Error> {
        self.add(2)?;
        for byte in text.bytes() {
            self.add(match byte {
                b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
                0..=0x1f => 6,
                _ => 1,
            })?;
        }
        Ok(())
    }

    pub(super) fn number(&mut self, tag: u8, bytes: [u8; 8]) -> Result<(), Error> {
        let number = match tag {
            UNSIGNED => Number::from(u64::from_le_bytes(bytes)),
            SIGNED => Number::from(i64::from_le_bytes(bytes)),
            FLOAT => Number::from_f64(f64::from_bits(u64::from_le_bytes(bytes)))
                .ok_or(Error::Unsupported)?,
            _ => return Err(Error::Unsupported),
        };
        let mut width = ScalarWidth(0);
        crucible_node_format::canonical::canonical_json_to_writer(
            &Value::Number(number),
            &mut width,
        )
        .map_err(|_| Error::Unsupported)?;
        self.add(width.0)
    }
}

// The finite-number writer emits only its fixed inline Ryu buffer. This sink
// never errors, so an exhausted outer restriction cannot allocate an I/O error
// or serde_json diagnostic; the checked outer addition refuses afterwards.
struct ScalarWidth(usize);

impl Write for ScalarWidth {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;

    size_of::<ScalarWidth>()
        + size_of::<&mut CanonicalExtent>()
        + size_of::<Number>()
        + size_of::<Value>()
        + size_of::<Option<Number>>()
        + size_of::<[u8; 8]>()
        + size_of::<u8>()
        + size_of::<&str>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<Result<(), Error>>()
        + crucible_node_format::canonical::canonical_number_counter_scratch_bytes_data()
}
