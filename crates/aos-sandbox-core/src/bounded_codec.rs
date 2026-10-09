//! Bounded byte decoding without format, signature, or authority policy.
//!
//! Callers map mechanical failures into their own errors and retain ownership
//! of framing, version checks, semantic limits, and canonical validation.

use crate::ObjectDigest;

/// Identifies a byte-reading failure for a format-specific error mapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    /// The requested range overflows its offset.
    LengthOverflow,
    /// The requested bytes are missing.
    Truncated,
    /// Reserved bytes contain a nonzero value.
    NonzeroReserved,
    /// Unconsumed bytes remain at the end of a record.
    TrailingBytes,
}

/// Borrows one checked byte region and returns its end offset.
///
/// This stateless operation neither advances a cursor nor validates a format.
/// The region borrows the original input without allocating.
///
/// # Errors
///
/// Returns [`ReadError::LengthOverflow`] before range extraction if offset plus
/// count overflows, or [`ReadError::Truncated`] when the region is absent.
pub fn checked_byte_region(
    bytes: &[u8],
    offset: usize,
    count: usize,
) -> Result<(&[u8], usize), ReadError> {
    let end = offset.checked_add(count).ok_or(ReadError::LengthOverflow)?;
    let value = bytes.get(offset..end).ok_or(ReadError::Truncated)?;
    Ok((value, end))
}

/// Reads bounded fields while preserving caller-owned error classification.
pub struct BoundedReader<'a, E> {
    bytes: &'a [u8],
    offset: usize,
    error: fn(ReadError) -> E,
}

macro_rules! integer_reader {
    ($name:ident, $integer:ty) => {
        #[doc = concat!("Reads a big-endian `", stringify!($integer), "` field.")]
        ///
        /// # Errors
        ///
        /// Returns the mapped truncation or offset-overflow error.
        pub fn $name(&mut self) -> Result<$integer, E> {
            Ok(<$integer>::from_be_bytes(self.array()?))
        }
    };
}

impl<'a, E> BoundedReader<'a, E> {
    /// Creates a reader over an already bounded record and its error mapper.
    pub const fn new(bytes: &'a [u8], error: fn(ReadError) -> E) -> Self {
        Self {
            bytes,
            offset: 0,
            error,
        }
    }

    /// Returns the number of unconsumed bytes.
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    /// Borrows the original unconsumed bytes without advancing the reader.
    ///
    /// The immutable view retains the original input lifetime and performs no
    /// format, signature, or authority validation.
    pub fn remaining_bytes(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    /// Reports whether every byte has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads an exact byte range, leaving the cursor unchanged on failure.
    ///
    /// # Errors
    ///
    /// Returns the mapped offset-overflow or truncation error.
    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], E> {
        let (value, end) = checked_byte_region(self.bytes, self.offset, count)
            .map_err(self.error)?;
        self.offset = end;
        Ok(value)
    }

    /// Reads one fixed-width array.
    ///
    /// # Errors
    ///
    /// Returns the mapped truncation or offset-overflow error.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], E> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| (self.error)(ReadError::Truncated))
    }

    integer_reader!(u8, u8);
    integer_reader!(u16, u16);
    integer_reader!(u32, u32);
    integer_reader!(u64, u64);
    integer_reader!(i64, i64);

    /// Reads a digest as data without authenticating it.
    ///
    /// # Errors
    ///
    /// Returns the mapped truncation or offset-overflow error.
    pub fn digest(&mut self) -> Result<ObjectDigest, E> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }

    /// Consumes an exact reserved field and verifies that every byte is zero.
    ///
    /// # Errors
    ///
    /// Returns the mapped range error or nonzero-reserved error.
    pub fn zeros(&mut self, count: usize) -> Result<(), E> {
        if self.bytes(count)?.iter().any(|byte| *byte != 0) {
            return Err((self.error)(ReadError::NonzeroReserved));
        }
        Ok(())
    }

    /// Rejects unconsumed trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns the mapped trailing-bytes error when the record is incomplete.
    pub fn finish(self) -> Result<(), E> {
        if self.is_empty() {
            Ok(())
        } else {
            Err((self.error)(ReadError::TrailingBytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_reads_preserve_big_endian_values_and_reject_every_short_prefix() {
        let bytes = 0x0102_0304_0506_0708_u64.to_be_bytes();
        for length in 0..bytes.len() {
            let mut reader = BoundedReader::new(&bytes[..length], core::convert::identity);
            assert_eq!(reader.u64(), Err(ReadError::Truncated));
            assert_eq!(reader.remaining(), length);
        }

        let mut reader = BoundedReader::new(&bytes, core::convert::identity);
        assert_eq!(reader.u64(), Ok(0x0102_0304_0506_0708));
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn failed_ranges_preserve_position_and_reserved_and_tail_errors_stay_distinct() {
        let mut reader = BoundedReader::new(&[0, 1, 0], core::convert::identity);
        assert_eq!(reader.u8(), Ok(0));
        assert_eq!(reader.bytes(usize::MAX), Err(ReadError::LengthOverflow));
        assert_eq!(reader.bytes(3), Err(ReadError::Truncated));
        assert_eq!(reader.remaining(), 2);
        assert_eq!(reader.zeros(1), Err(ReadError::NonzeroReserved));
        assert_eq!(reader.finish(), Err(ReadError::TrailingBytes));
    }

    #[test]
    fn remaining_bytes_borrows_original_input_without_advancing_or_losing_failed_ranges() {
        let bytes = [1, 2, 3];
        let mut reader = BoundedReader::new(&bytes, core::convert::identity);
        let original_tail = reader.remaining_bytes();
        assert_eq!(original_tail, &bytes);
        assert_eq!(reader.remaining(), 3);

        assert_eq!(reader.u8(), Ok(1));
        assert_eq!(original_tail, &bytes);
        assert_eq!(reader.remaining_bytes(), &bytes[1..]);

        assert_eq!(reader.bytes(usize::MAX), Err(ReadError::LengthOverflow));
        assert_eq!(reader.remaining_bytes(), &bytes[1..]);
        assert_eq!(reader.bytes(3), Err(ReadError::Truncated));
        assert_eq!(reader.remaining_bytes(), &bytes[1..]);
    }

    #[test]
    fn checked_regions_preserve_borrowed_pointers_and_report_overflow_before_missing_ranges() {
        let bytes = [1, 2, 3, 4];
        let (middle, end) = {
            let offset = 1;
            checked_byte_region(&bytes, offset, 2).unwrap()
        };

        assert_eq!(middle, &bytes[1..3]);
        assert_eq!(end, 3);
        assert!(std::ptr::eq(middle.as_ptr(), bytes[1..].as_ptr()));

        for offset in 0..=bytes.len() {
            let (empty, end) = checked_byte_region(&bytes, offset, 0).unwrap();

            assert!(empty.is_empty());
            assert_eq!(end, offset);
            assert!(std::ptr::eq(empty.as_ptr(), bytes[offset..].as_ptr()));
        }

        let input = &bytes[..0];
        let (empty, end) = checked_byte_region(input, 0, 0).unwrap();
        assert_eq!(end, 0);
        assert!(std::ptr::eq(empty.as_ptr(), input.as_ptr()));

        assert_eq!(checked_byte_region(&bytes, 3, 2), Err(ReadError::Truncated));
        assert_eq!(checked_byte_region(&bytes, 5, 0), Err(ReadError::Truncated));
        assert_eq!(checked_byte_region(input, usize::MAX, 0), Err(ReadError::Truncated));
        assert_eq!(
            checked_byte_region(input, usize::MAX, 1),
            Err(ReadError::LengthOverflow)
        );
    }

    #[test]
    fn range_errors_invoke_the_original_mapper_once_before_cursor_commit() {
        thread_local! {
            static MAPPING_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        }

        fn mapped_error(error: ReadError) -> (ReadError, usize) {
            let count = MAPPING_COUNT.with(|count| {
                let next = count.get() + 1;
                count.set(next);
                next
            });
            (error, count)
        }

        MAPPING_COUNT.with(|count| count.set(0));
        let mut reader = BoundedReader::new(&[7, 8], mapped_error);

        assert_eq!(reader.u8(), Ok(7));
        assert_eq!(reader.bytes(usize::MAX), Err((ReadError::LengthOverflow, 1)));
        assert_eq!(reader.bytes(2), Err((ReadError::Truncated, 2)));
        assert_eq!(reader.remaining_bytes(), &[8]);
        assert_eq!(reader.u8(), Ok(8));
        assert_eq!(reader.finish(), Ok(()));
        MAPPING_COUNT.with(|count| assert_eq!(count.get(), 2));
    }
}
