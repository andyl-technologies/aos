//! Feeds real projected JSON chunks and opaque string extents to native geometry.
//!
//! This sink retains no output, DOM, token bytes or pathname. It recognizes only
//! structure needed by the original occurrence walk, not accepted JSON grammar.

use super::{Counter, DecodedStorage, refused};
use crate::errors::ProviderError;
use crate::profile::launch_projection::{ProjectedRecord, visit_fields};
use crate::profile::reference_packet::service::{
    PacketNative5LaunchValidationFields, PacketNative5LaunchValidationProjection,
    PacketNative5PathSerializationData, PacketNative5SourceLaunch,
};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};
use std::mem::size_of;

struct Stream {
    counter: Counter,
    stack: [u8; 64],
    depth: usize,
    string: Option<usize>,
    escaped: bool,
    completed_string: Option<usize>,
    atom: bool,
    bytes: usize,
    maximum: usize,
    error: Option<ProviderError>,
}

impl Stream {
    fn new(maximum: usize) -> Result<Self, ProviderError> {
        Ok(Self {
            counter: Counter::new(0)?,
            stack: [0; 64],
            depth: 0,
            string: None,
            escaped: false,
            completed_string: None,
            atom: false,
            bytes: 0,
            maximum,
            error: None,
        })
    }

    fn counted_bytes(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(refused)?;
        self.counter.encoded(bytes)?;
        Ok(())
    }

    fn begin_value(&mut self) -> Result<(), ProviderError> {
        if self.depth > 0 && self.stack[self.depth - 1] == b'[' {
            self.counter.array_value()?;
        }
        Ok(())
    }

    fn flush_string(&mut self, key: bool) -> Result<(), ProviderError> {
        if let Some(encoded) = self.completed_string.take() {
            self.counter.string(encoded, key, self.maximum)?;
        }
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), ProviderError> {
        if let Some(encoded) = &mut self.string {
            if self.escaped {
                *encoded = encoded.checked_add(1).ok_or_else(refused)?;
                self.escaped = false;
            } else if byte == b'"' {
                self.completed_string = self.string.take();
            } else {
                *encoded = encoded.checked_add(1).ok_or_else(refused)?;
                self.escaped = byte == b'\\';
            }
            return Ok(());
        }
        if self.atom {
            if !b" \t\r\n,:]}".contains(&byte) {
                return Ok(());
            }
            self.atom = false;
        }
        if byte.is_ascii_whitespace() {
            return Ok(());
        }
        self.flush_string(byte == b':')?;
        if b",:".contains(&byte) {
            return Ok(());
        }
        let closes = byte == b'}' || byte == b']';
        if !closes {
            self.begin_value()?;
        }
        match byte {
            b'{' | b'[' => {
                *self.stack.get_mut(self.depth).ok_or_else(refused)? = byte;
                self.depth += 1;
                self.counter.container(byte)?;
            }
            b'}' | b']' => {
                self.depth = self.depth.checked_sub(1).ok_or_else(refused)?;
                if self.stack[self.depth] != if byte == b'}' { b'{' } else { b'[' } {
                    return Err(refused());
                }
            }
            b'"' => self.string = Some(0),
            _ => self.atom = true,
        }
        Ok(())
    }

    fn opaque_string(&mut self, bytes: usize) -> Result<(), ProviderError> {
        if bytes < 2 || self.string.is_some() || self.atom {
            return Err(refused());
        }
        self.flush_string(false)?;
        self.begin_value()?;
        self.counted_bytes(bytes)?;
        // This is the exact encoded occurrence extent, not made-up JSON bytes.
        // A key cannot follow: the caller places it only at a value field slot.
        self.completed_string = Some(bytes - 2);
        Ok(())
    }

    fn finish(mut self, root: usize, element: usize) -> Result<DecodedStorage, ProviderError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if self.bytes == 0 || self.depth != 0 || self.string.is_some() || self.escaped {
            return Err(refused());
        }
        self.flush_string(false)?;
        self.counter.finish(root, element, self.maximum)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let result = (|| {
            self.counted_bytes(bytes.len())?;
            for &byte in bytes {
                self.byte(byte)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.error = Some(error);
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Only genuine scalar numbers pass through this formatter. The actual Format
// writer selects ECMAScript spelling from the same real Number, including the
// original integer-to-f64 semantics. No secret string or launch is fabricated.
struct CanonicalNumbers;

fn canonical_number(value: impl Serialize, writer: &mut (impl Write + ?Sized)) -> io::Result<()> {
    let number = serde_json::to_value(value).map_err(|_| io::ErrorKind::InvalidData)?;
    // Adapt the possibly-unsized formatter sink through a sized borrowed handle.
    let mut writer = writer;
    crucible_node_format::canonical::canonical_json_to_writer(&number, &mut writer)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

macro_rules! canonical_numbers {
    ($($name:ident: $kind:ty),* $(,)?) => {
        $(fn $name<W: Write + ?Sized>(&mut self, writer: &mut W, value: $kind) -> io::Result<()> {
            canonical_number(value, writer)
        })*
    };
}

impl serde_json::ser::Formatter for CanonicalNumbers {
    canonical_numbers!(
        write_i8: i8, write_i16: i16, write_i32: i32, write_i64: i64, write_i128: i128,
        write_u8: u8, write_u16: u16, write_u32: u32, write_u64: u64, write_u128: u128,
        write_f32: f32, write_f64: f64,
    );
}

fn canonical_field<W: Write>(
    writer: &mut W,
    value: &(impl Serialize + ?Sized),
) -> Result<(), serde_json::Error> {
    let mut serializer = serde_json::Serializer::with_formatter(writer, CanonicalNumbers);
    value.serialize(&mut serializer)
}

struct Record {
    stream: Stream,
    first: bool,
}

impl Record {
    fn prefix(&mut self, key: &'static str) -> Result<(), ProviderError> {
        if !self.first {
            self.stream.write_all(b",").map_err(|_| refused())?;
        }
        self.first = false;
        canonical_field(&mut self.stream, key).map_err(|_| refused())?;
        self.stream.write_all(b":").map_err(|_| refused())
    }
}

impl ProjectedRecord for Record {
    fn field(&mut self, key: &'static str, value: &impl Serialize) -> Result<(), ProviderError> {
        self.prefix(key)?;
        canonical_field(&mut self.stream, value).map_err(|_| refused())
    }

    fn token(&mut self, length: usize) -> Result<(), ProviderError> {
        self.prefix("admission_token")?;
        let encoded = base64::encoded_len(length, false)
            .and_then(|n| n.checked_add(2))
            .ok_or_else(refused)?;
        self.stream.opaque_string(encoded)
    }

    fn path(&mut self, path: PacketNative5PathSerializationData) -> Result<(), ProviderError> {
        self.prefix("effects")?;
        match path {
            PacketNative5PathSerializationData::QuotedUtf8 { bytes } => {
                self.stream.opaque_string(bytes)
            }
            PacketNative5PathSerializationData::InvalidUtf8
            | PacketNative5PathSerializationData::Unrepresentable => Err(refused()),
        }
    }
}

/// Quotes the real launch decoding occurrences without token/path reconstruction.
///
/// This is DATA only. It shares the raw native accumulator and the original
/// projected field/skip sequence. The byte observation is not a grammar proof,
/// Source association, reservation or native member. Serde retains ordinary
/// caller-contained allocation/error behavior; this is not a deep-safe parser.
///
/// # Errors
/// Refuses the original projected serialized-credit failure, zero layouts,
/// unsupported scanner depth/shape, inconsistent extent, overflow or a complete
/// occurrence component above maximum. No candidate input is repaired.
pub fn quote_projected_launch(
    launch: &PacketNative5LaunchValidationProjection<'_>,
    root: usize,
    element: usize,
    maximum: usize,
) -> Result<DecodedStorage, ProviderError> {
    if root == 0 || element == 0 {
        return Err(refused());
    }
    // Preserve the existing ordinary byte-credit check. Its float spelling is
    // not the JCS bank spelling, so it is not reused as canonical byte extent.
    launch.serialized_credit_data(maximum)?;
    let mut record = Record {
        stream: Stream::new(maximum)?,
        first: true,
    };
    record.stream.write_all(b"{").map_err(|_| refused())?;
    visit_fields(
        &launch.fields_data(),
        launch.token_length_data(),
        launch.path_serialization_data(),
        &mut record,
    )?;
    record.stream.write_all(b"}").map_err(|_| refused())?;
    record.stream.finish(root, element)
}

/// Names the projected adapter's actual fixed typed controls beside raw geometry.
///
/// The row includes the defining validation-input prerequisite, retained
/// projected view, fields_data return and shared-visitor borrow. It excludes
/// original dynamic input backing, recursive/compiler frames and serde
/// allocator/error backing. Its caller must supply actual operational containment;
/// this number is neither a complete constructor grant nor an observed population.
pub fn projected_counter_scratch_data() -> usize {
    super::counter_scratch_data()
        // Admit the defining shared validation-input family before the real
        // serialized_credit_data call; this is not borrowed from raw geometry.
        + PacketNative5SourceLaunch::VALIDATION_INPUT_COUNTER_SCRATCH_DATA
        // The caller retains its actual projected input through this loan.
        + size_of::<PacketNative5LaunchValidationProjection<'static>>()
        + size_of::<&PacketNative5LaunchValidationProjection<'static>>()
        // fields_data returns a copied view which is then borrowed by the
        // shared field visitor; both are distinct from its prior credit call.
        + size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&PacketNative5LaunchValidationFields<'static>>()
        + size_of::<Record>()
        + size_of::<Result<Stream, ProviderError>>()
        + size_of::<Result<DecodedStorage, ProviderError>>()
        + size_of::<serde_json::Serializer<&mut Stream, CanonicalNumbers>>()
        + size_of::<Value>()
        + size_of::<Result<Value, serde_json::Error>>()
        + crucible_node_format::canonical::canonical_number_counter_scratch_bytes_data()
        + size_of::<&mut Record>()
        + size_of::<Option<usize>>() * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoded_occurrences::quote;
    use crucible_node_format::canonical;
    use serde_json::json;

    #[test]
    fn actual_jcs_numbers_literals_and_utf16_key_order_match_the_raw_bank() {
        let cases = [
            json!([
                1.0,
                -0.0,
                1e-7,
                u64::MAX,
                i64::MIN,
                9_007_199_254_740_993u64
            ]),
            json!({"𝄞":"a\u{0}é\"\\", "\u{e000}":[{},[]], "$serde_json::private::RawValue":"[1,2]", "$serde_json::private::Number":"1.000"}),
        ];
        for value in cases {
            let bank = canonical::canonical_json(&value).unwrap();
            let expected =
                quote(&bank, size_of::<Value>(), size_of::<Value>(), usize::MAX).unwrap();
            let mut stream = Stream::new(usize::MAX).unwrap();
            canonical_field(&mut stream, &value).unwrap();
            assert_eq!(stream.bytes, bank.len());
            assert_eq!(
                stream
                    .finish(size_of::<Value>(), size_of::<Value>())
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn chunk_boundaries_and_opaque_extents_share_actual_string_and_array_counts() {
        let bank = br#"["a\"b",{"key":"abc"},-1,true]"#;
        let expected = quote(bank, size_of::<Value>(), size_of::<Value>(), usize::MAX).unwrap();
        for chunk in [1, 2, 7, bank.len()] {
            let mut stream = Stream::new(usize::MAX).unwrap();
            for bytes in bank.chunks(chunk) {
                stream.write_all(bytes).unwrap();
            }
            assert_eq!(
                stream
                    .finish(size_of::<Value>(), size_of::<Value>())
                    .unwrap(),
                expected
            );
        }
        let mut stream = Stream::new(usize::MAX).unwrap();
        stream.write_all(br#"["a\"b",{"key":"#).unwrap();
        stream.opaque_string(5).unwrap();
        stream.write_all(b"},-1,true]").unwrap();
        assert_eq!(
            stream
                .finish(size_of::<Value>(), size_of::<Value>())
                .unwrap(),
            expected
        );
    }

    #[test]
    fn malformed_structure_depth_and_inconsistent_opaque_position_refuse() {
        let mut stream = Stream::new(usize::MAX).unwrap();
        assert!(stream.write_all(b"{]").is_err());
        assert!(stream.finish(1, 1).is_err());
        let mut stream = Stream::new(usize::MAX).unwrap();
        assert!(stream.write_all(&[b'['; 65]).is_err());
        assert!(stream.finish(1, 1).is_err());
        let mut stream = Stream::new(usize::MAX).unwrap();
        stream.write_all(b"\"partial").unwrap();
        assert!(stream.opaque_string(5).is_err());
        assert!(stream.finish(1, 1).is_err());
    }
}
