//! Reads and writes Terrane's deterministic CBOR subset.
//!
//! Decoding borrows input slices and bounds collection lengths before callers
//! allocate. No generic value tree is created during validation.

use alloc::vec::Vec;
use core::fmt;

/// Maximum nesting of a generic CBOR value.
pub const MAX_NESTING: usize = 64;

/// A deterministic CBOR decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input ended early or contains invalid UTF-8.
    Malformed,
    /// An integer, length, or map order is noncanonical.
    NonCanonical,
    /// A schema size or nesting limit was exceeded.
    Limit,
    /// The item uses an excluded CBOR form.
    Unsupported,
    /// Bytes follow a complete top-level item.
    TrailingData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed CBOR"),
            Self::NonCanonical => f.write_str("noncanonical CBOR"),
            Self::Limit => f.write_str("CBOR limit exceeded"),
            Self::Unsupported => f.write_str("unsupported CBOR form"),
            Self::TrailingData => f.write_str("trailing CBOR data"),
        }
    }
}

impl core::error::Error for Error {}

/// A zero-copy reader over one deterministic CBOR item.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a reader without allocating or copying `input`.
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    /// Returns the consumed byte count.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the unconsumed bytes.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    /// Returns an already validated range of the borrowed input.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if the range is outside the input.
    pub fn slice(&self, start: usize, end: usize) -> Result<&'a [u8], Error> {
        self.input.get(start..end).ok_or(Error::Malformed)
    }

    /// Returns the next item's CBOR major type.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] at end of input.
    pub fn peek_major(&self) -> Result<u8, Error> {
        self.remaining()
            .first()
            .map(|byte| byte >> 5)
            .ok_or(Error::Malformed)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Limit)?;
        let bytes = self.input.get(self.position..end).ok_or(Error::Malformed)?;
        self.position = end;
        Ok(bytes)
    }

    fn argument(&mut self, major: u8) -> Result<u64, Error> {
        let initial = self.take(1)?[0];
        if initial >> 5 != major {
            return Err(Error::Malformed);
        }
        let additional = initial & 31;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| Error::Malformed)?,
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| Error::Malformed)?,
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Malformed)?),
            _ => return Err(Error::Unsupported),
        };
        let minimal = match additional {
            24 => value >= 24,
            25 => value > u64::from(u8::MAX),
            26 => value > u64::from(u16::MAX),
            27 => value > u64::from(u32::MAX),
            _ => true,
        };
        if !minimal {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }

    /// Reads an unsigned integer.
    ///
    /// # Errors
    /// Rejects a missing, noninteger, or nonminimal item.
    pub fn uint(&mut self) -> Result<u64, Error> {
        self.argument(0)
    }

    /// Reads a negative integer's CBOR argument `n` (the value is `-1-n`).
    ///
    /// # Errors
    /// Rejects a missing, noninteger, or nonminimal item.
    pub fn negative_argument(&mut self) -> Result<u64, Error> {
        self.argument(1)
    }

    /// Reads a definite byte string up to `limit` bytes.
    ///
    /// # Errors
    /// Rejects noncanonical encoding, truncated input, or a claimed length
    /// above `limit` before consuming the body.
    pub fn bytes(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.argument(2)?).map_err(|_| Error::Limit)?;
        if length > limit {
            return Err(Error::Limit);
        }
        self.take(length)
    }

    /// Reads a definite UTF-8 string up to `limit` encoded bytes.
    ///
    /// # Errors
    /// Rejects invalid UTF-8, noncanonical encoding, truncated input, or a
    /// claimed length above `limit` before consuming the body.
    pub fn text(&mut self, limit: usize) -> Result<&'a str, Error> {
        let length = usize::try_from(self.argument(3)?).map_err(|_| Error::Limit)?;
        if length > limit {
            return Err(Error::Limit);
        }
        core::str::from_utf8(self.take(length)?).map_err(|_| Error::Malformed)
    }

    /// Reads an array length bounded by `limit` and remaining input.
    ///
    /// # Errors
    /// Rejects a malformed, noncanonical, or oversized array header.
    pub fn array(&mut self, limit: usize) -> Result<usize, Error> {
        self.collection(4, limit)
    }

    /// Reads a map length bounded by `limit` and remaining input.
    ///
    /// # Errors
    /// Rejects a malformed, noncanonical, or oversized map header.
    pub fn map(&mut self, limit: usize) -> Result<usize, Error> {
        self.collection(5, limit)
    }

    fn collection(&mut self, major: u8, limit: usize) -> Result<usize, Error> {
        let length = usize::try_from(self.argument(major)?).map_err(|_| Error::Limit)?;
        let minimum_bytes = if major == 5 { 2 } else { 1 };
        if length > limit || length > self.remaining().len() / minimum_bytes {
            return Err(Error::Limit);
        }
        Ok(length)
    }

    /// Reads one of the permitted simple values as its marker byte.
    ///
    /// # Errors
    /// Rejects simple values other than true, false, and null, and all floats.
    pub fn simple(&mut self) -> Result<u8, Error> {
        let marker = self.take(1)?[0];
        if matches!(marker, 0xf4..=0xf6) {
            Ok(marker)
        } else {
            Err(Error::Unsupported)
        }
    }

    /// Validates and skips one generic deterministic value.
    ///
    /// # Errors
    /// Rejects noncanonical maps, unsupported types, excessive nesting, or
    /// values larger than `max_bytes`.
    pub fn skip_value(&mut self, max_bytes: usize) -> Result<(), Error> {
        self.skip_nested(0, max_bytes)
    }

    fn skip_nested(&mut self, depth: usize, max_bytes: usize) -> Result<(), Error> {
        if depth >= MAX_NESTING {
            return Err(Error::Limit);
        }
        let start = self.position;
        match self.peek_major()? {
            0 => {
                self.uint()?;
            }
            1 => {
                self.negative_argument()?;
            }
            2 => {
                self.bytes(max_bytes)?;
            }
            3 => {
                self.text(max_bytes)?;
            }
            4 => {
                let count = self.array(max_bytes)?;
                for _ in 0..count {
                    self.skip_nested(depth + 1, max_bytes)?;
                }
            }
            5 => {
                let count = self.map(max_bytes)?;
                let mut previous = None;
                for _ in 0..count {
                    let key_start = self.position;
                    match self.peek_major()? {
                        0 => {
                            self.uint()?;
                        }
                        2 => {
                            self.bytes(max_bytes)?;
                        }
                        3 => {
                            self.text(max_bytes)?;
                        }
                        _ => return Err(Error::Unsupported),
                    }
                    let key = &self.input[key_start..self.position];
                    if previous.is_some_and(|prior: &[u8]| key <= prior) {
                        return Err(Error::NonCanonical);
                    }
                    previous = Some(key);
                    self.skip_nested(depth + 1, max_bytes)?;
                }
            }
            7 => {
                self.simple()?;
            }
            _ => return Err(Error::Unsupported),
        }
        if self.position - start > max_bytes {
            return Err(Error::Limit);
        }
        Ok(())
    }

    /// Returns borrowed bytes of one validated generic value.
    ///
    /// # Errors
    /// Returns the errors described by [`Self::skip_value`].
    pub fn raw_value(&mut self, max_bytes: usize) -> Result<&'a [u8], Error> {
        let start = self.position;
        self.skip_value(max_bytes)?;
        Ok(&self.input[start..self.position])
    }

    /// Verifies that the top-level item consumed the entire input.
    ///
    /// # Errors
    /// Returns [`Error::TrailingData`] if bytes remain.
    pub fn finish(&self) -> Result<(), Error> {
        if self.remaining().is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }
}

/// Appends a shortest-form CBOR header.
pub fn write_argument(output: &mut Vec<u8>, major: u8, argument: u64) {
    let prefix = major << 5;
    match argument {
        0..=23 => output.push(prefix | argument as u8),
        24..=255 => {
            output.push(prefix | 24);
            output.push(argument as u8);
        }
        256..=65535 => {
            output.push(prefix | 25);
            output.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            output.push(prefix | 26);
            output.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// Appends an unsigned integer in shortest form.
pub fn write_uint(output: &mut Vec<u8>, value: u64) {
    write_argument(output, 0, value);
}

/// Appends a negative integer from its CBOR argument `n` (`-1-n`).
pub fn write_negative_argument(output: &mut Vec<u8>, argument: u64) {
    write_argument(output, 1, argument);
}

/// Appends a definite byte string in shortest form.
pub fn write_bytes(output: &mut Vec<u8>, value: &[u8]) {
    write_argument(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

/// Appends a definite UTF-8 string in shortest form.
pub fn write_text(output: &mut Vec<u8>, value: &str) {
    write_argument(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

/// Appends a definite array header in shortest form.
pub fn write_array(output: &mut Vec<u8>, count: usize) {
    write_argument(output, 4, count as u64);
}

/// Appends a definite map header in shortest form.
pub fn write_map(output: &mut Vec<u8>, count: usize) {
    write_argument(output, 5, count as u64);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::vec::Vec;

    use super::{Decoder, Error, write_bytes, write_negative_argument, write_uint};

    #[test]
    fn shortest_numbers_and_borrowed_strings_round_trip() {
        let mut encoded = Vec::new();
        for value in [23, 24, 255, 256, 65535, 65536, u64::MAX] {
            write_uint(&mut encoded, value);
        }
        write_negative_argument(&mut encoded, u64::MAX);
        write_bytes(&mut encoded, b"raw\0bytes");

        let mut decoder = Decoder::new(&encoded);
        for value in [23, 24, 255, 256, 65535, 65536, u64::MAX] {
            assert_eq!(decoder.uint().expect("canonical integer"), value);
        }
        assert_eq!(decoder.negative_argument(), Ok(u64::MAX));
        assert_eq!(decoder.bytes(9), Ok(&b"raw\0bytes"[..]));
        decoder.finish().expect("all items consumed");
    }

    #[test]
    fn rejects_nonminimal_and_excluded_forms() {
        for bytes in [
            &[0x18, 0x17][..],
            &[0x59, 0, 1, 0][..],
            &[0x9f, 0xff][..],
            &[0xc0, 0][..],
            &[0xf9, 0, 0][..],
            &[0x61, 0xff][..],
        ] {
            assert!(Decoder::new(bytes).skip_value(64).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn checks_claimed_length_before_consuming_body() {
        assert_eq!(
            Decoder::new(&[0x5a, 0xff, 0xff, 0xff, 0xff]).bytes(65536),
            Err(Error::Limit)
        );
        assert_eq!(
            Decoder::new(&[0x9a, 0xff, 0xff, 0xff, 0xff]).array(100),
            Err(Error::Limit)
        );
    }

    #[test]
    fn rejects_duplicate_and_out_of_order_map_keys() {
        for bytes in [&[0xa2, 1, 0, 1, 1][..], &[0xa2, 2, 0, 1, 0][..]] {
            assert_eq!(Decoder::new(bytes).skip_value(64), Err(Error::NonCanonical));
        }
    }
}
