//! Counts borrowed logical JSON before constructing its future owning output.
//!
//! The passive row first admits the real serializers' Bytes temporaries and
//! these fixed views. This pass stores no output or DOM. Numeric values use the
//! defining canonical scalar formatter; member ordering changes no byte count.
//! The later owning pass still needs its independent DOM/canonical/output row.

use crate::node_contract::RuntimeError;
use crucible_node_format::canonical;
use serde::Serialize;
use serde_json::{Number, Value, ser::Formatter};
use std::{
    io::{self, Write},
    mem::size_of,
};

/// Counts an actual borrowed logical view under an earlier admitted work row.
///
/// The caller holds the same owning read and frozen SDK frontier throughout the
/// quote and effect. A count grants neither output allocation nor SDK activity.
pub(super) fn canonical_encoded_extent_data<T: Serialize + ?Sized>(
    value: &T,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut sink = ExtentSink { length: 0, maximum };
    let mut serializer = serde_json::Serializer::with_formatter(
        &mut sink,
        CanonicalExtentFormatter { in_string: false },
    );
    value
        .serialize(&mut serializer)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(sink.length)
}

struct ExtentSink {
    length: usize,
    maximum: usize,
}

impl Write for ExtentSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .length
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        self.length = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CanonicalExtentFormatter {
    in_string: bool,
}

// JSON map-key numbers are strings in the resulting Value. Preserve their
// ordinary decimal spelling; only actual numeric values receive JCS formatting.
macro_rules! integer_formatter {
    ($name:ident, $type:ty) => {
        fn $name<W: Write + ?Sized>(&mut self, writer: &mut W, value: $type) -> io::Result<()> {
            if self.in_string {
                return serde_json::ser::CompactFormatter.$name(writer, value);
            }
            scalar_number(writer, Number::from(value))
        }
    };
}

impl Formatter for CanonicalExtentFormatter {
    integer_formatter!(write_i8, i8);
    integer_formatter!(write_i16, i16);
    integer_formatter!(write_i32, i32);
    integer_formatter!(write_i64, i64);
    integer_formatter!(write_u8, u8);
    integer_formatter!(write_u16, u16);
    integer_formatter!(write_u32, u32);
    integer_formatter!(write_u64, u64);

    fn write_i128<W: Write + ?Sized>(&mut self, writer: &mut W, value: i128) -> io::Result<()> {
        if self.in_string {
            return serde_json::ser::CompactFormatter.write_i128(writer, value);
        }
        scalar_number(
            writer,
            Number::from_i128(value).ok_or(io::ErrorKind::InvalidData)?,
        )
    }

    fn write_u128<W: Write + ?Sized>(&mut self, writer: &mut W, value: u128) -> io::Result<()> {
        if self.in_string {
            return serde_json::ser::CompactFormatter.write_u128(writer, value);
        }
        scalar_number(
            writer,
            Number::from_u128(value).ok_or(io::ErrorKind::InvalidData)?,
        )
    }

    fn write_f32<W: Write + ?Sized>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        if self.in_string {
            return serde_json::ser::CompactFormatter.write_f32(writer, value);
        }
        // Use the same scalar conversion as serde_json::to_value, including
        // whichever Number representation this actual build selects.
        scalar_value(writer, Value::from(value))
    }

    fn write_f64<W: Write + ?Sized>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        if self.in_string {
            return serde_json::ser::CompactFormatter.write_f64(writer, value);
        }
        scalar_number(
            writer,
            Number::from_f64(value).ok_or(io::ErrorKind::InvalidData)?,
        )
    }

    fn write_number_str<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        value: &str,
    ) -> io::Result<()> {
        if self.in_string {
            return serde_json::ser::CompactFormatter.write_number_str(writer, value);
        }
        let number = value.parse::<Number>().map_err(io::Error::other)?;
        scalar_number(writer, number)
    }

    fn begin_string<W: Write + ?Sized>(&mut self, writer: &mut W) -> io::Result<()> {
        if self.in_string {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.in_string = true;
        writer.write_all(b"\"")
    }

    fn end_string<W: Write + ?Sized>(&mut self, writer: &mut W) -> io::Result<()> {
        if !self.in_string {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.in_string = false;
        writer.write_all(b"\"")
    }

    fn write_raw_fragment<W: Write + ?Sized>(
        &mut self,
        _writer: &mut W,
        _fragment: &str,
    ) -> io::Result<()> {
        // No selected logical component uses an opaque RawValue. Parsing one
        // here would allocate a hidden DOM before the final row was admitted.
        Err(io::ErrorKind::InvalidData.into())
    }
}

fn scalar_number<W: Write + ?Sized>(writer: &mut W, number: Number) -> io::Result<()> {
    // This is one actual scalar, not a future whole-history Value. The defining
    // branch uses its inline Number and stack Ryu buffer without a DOM bank.
    scalar_value(writer, Value::Number(number))
}

fn scalar_value<W: Write + ?Sized>(writer: &mut W, value: Value) -> io::Result<()> {
    canonical::canonical_json_to_writer(&value, &mut &mut *writer).map_err(io::Error::other)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<ExtentSink>()
        + size_of::<&mut ExtentSink>()
        + size_of::<CanonicalExtentFormatter>()
        + size_of::<serde_json::Serializer<&mut ExtentSink, CanonicalExtentFormatter>>()
        + size_of::<&mut serde_json::Serializer<&mut ExtentSink, CanonicalExtentFormatter>>()
        + size_of::<Value>()
        + size_of::<Number>()
        + size_of::<Option<Number>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<(), io::Error>>()
        + size_of::<Result<usize, io::Error>>()
        + canonical::canonical_number_counter_scratch_bytes_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn borrowed_count_matches_authoritative_canonical_value()
    -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize)]
        struct LogicalValue {
            float32: f32,
            numbers: [f64; 5],
            text: &'static str,
            integer_keys: BTreeMap<u64, &'static str>,
        }
        let mut integer_keys = BTreeMap::new();
        integer_keys.insert(u64::MAX, "retained key");
        let value = LogicalValue {
            float32: 1.2345678,
            numbers: [
                1.0e20,
                1.0e-6,
                -0.0,
                f64::MIN_POSITIVE,
                -1.2345678901234567e-6,
            ],
            text: "escaped\"\\\n non-ASCII: λ",
            integer_keys,
        };

        let count = canonical_encoded_extent_data(&value, 4096)?;
        let encoded = canonical::canonical_json(&serde_json::to_value(&value)?)?;

        assert_eq!(count, encoded.len());
        assert!(matches!(
            canonical_encoded_extent_data(&value, count - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        Ok(())
    }

    #[test]
    fn failed_extent_write_keeps_the_last_accepted_count() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut sink = ExtentSink {
            length: 0,
            maximum: 4,
        };

        sink.write_all(b"ok")?;
        assert!(sink.write_all(b"long").is_err());

        assert_eq!(sink.length, 2);
        Ok(())
    }
}
