//! Encodes complete source-private byte strings without numeric JSON expansion.
//!
//! This data-only edition has one canonical JSON shape:
//!
//! ```text
//! ["source-private.compact-bytes/7",3,["AAEC"]]
//! ```
//!
//! Each nonfinal chunk contains exactly 4096 base64 characters representing
//! 3072 bytes. A final chunk contains at most 4096 characters with canonical
//! padding. Empty input has length zero and an empty chunk list. This codec
//! retains no allocation identities and confers no native or adoption authority.

use serde::{Serialize, Serializer, ser::SerializeSeq, ser::SerializeTuple};

use crate::ProviderError;

const TAG: &str = "source-private.compact-bytes/7";
const PREFIX: &[u8] = b"[\"source-private.compact-bytes/7\",";
const RAW_CHUNK_BYTES: usize = 3072;
const ENCODED_CHUNK_BYTES: usize = 4096;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Borrows every original byte for bounded source-private JSON serialization.
///
/// Serialization uses a fixed stack chunk buffer and makes no owning byte copy.
/// Output storage, its finite admission and any allocation-alias graph remain
/// the caller's responsibility. The serialized bytes grant no source custody.
pub struct BorrowedCompactBytes<'a> {
    bytes: &'a [u8],
}

impl<'a> BorrowedCompactBytes<'a> {
    /// Names the actual encoded chunk and borrowed serializer headers.
    ///
    /// This excludes generic serializer state, recursive/compiler frames and
    /// allocator residency, which require separate simultaneous admission.
    pub const fn requested_serialization_scratch_bytes() -> usize {
        ENCODED_CHUNK_BYTES
            + std::mem::size_of::<Chunks<'static>>()
            + std::mem::size_of::<BorrowedCompactBytes<'static>>()
            + 2 * std::mem::size_of::<std::slice::Chunks<'static, u8>>()
    }

    /// Borrows a complete byte slice without allocation or interpretation.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

/// Reports the fixed compact serializer's prospective layout without byte data.
///
/// No Serialize implementation is provided: this is an encoding demand, not a
/// substitute compact body, original allocation identity or storage allowance.
pub(crate) struct CompactBytesSerializationLayoutData {
    pub(crate) maximum_raw_bytes: usize,
    pub(crate) full_chunks: usize,
    pub(crate) final_encoded_chunk_bytes: usize,
    pub(crate) chunk_count: usize,
    pub(crate) maximum_base64_bytes: usize,
    pub(crate) maximum_encoded_bytes: usize,
}

impl BorrowedCompactBytes<'_> {
    /// Counts the closed compact grammar for an explicit prospective raw extent.
    ///
    /// The bound comes from an independently derived body plan. No raw payload,
    /// owning Vec, fake ContentRef or completed native owner is created. Exact
    /// ASCII base64 geometry uses the same private constants as Serialize.
    ///
    /// # Errors
    /// Refuses checked chunk/base64/tuple arithmetic overflow.
    pub(crate) fn serialization_layout_data(
        maximum_raw_bytes: usize,
    ) -> Result<CompactBytesSerializationLayoutData, ProviderError> {
        let overflow = || ProviderError::ResourceExhausted("compact serialization layout data");
        let full_chunks = maximum_raw_bytes / RAW_CHUNK_BYTES;
        let remainder = maximum_raw_bytes % RAW_CHUNK_BYTES;
        let final_encoded_chunk_bytes =
            remainder.div_ceil(3).checked_mul(4).ok_or_else(overflow)?;
        let chunk_count = full_chunks
            .checked_add(usize::from(remainder != 0))
            .ok_or_else(overflow)?;
        let maximum_base64_bytes = full_chunks
            .checked_mul(ENCODED_CHUNK_BYTES)
            .and_then(|bytes| bytes.checked_add(final_encoded_chunk_bytes))
            .ok_or_else(overflow)?;
        let mut remaining = maximum_raw_bytes;
        let mut length_digits = 1usize;
        while remaining >= 10 {
            remaining /= 10;
            length_digits += 1;
        }
        // Outer/inner brackets, tag quotes, two tuple commas, decimal length,
        // each unescaped ASCII chunk's quotes and its list separators.
        let maximum_encoded_bytes = TAG
            .len()
            .checked_add(8)
            .and_then(|bytes| bytes.checked_add(length_digits))
            .and_then(|bytes| bytes.checked_add(maximum_base64_bytes))
            .and_then(|bytes| {
                chunk_count
                    .checked_mul(2)
                    .and_then(|quotes| bytes.checked_add(quotes))
            })
            .and_then(|bytes| bytes.checked_add(chunk_count.saturating_sub(1)))
            .ok_or_else(overflow)?;
        Ok(CompactBytesSerializationLayoutData {
            maximum_raw_bytes,
            full_chunks,
            final_encoded_chunk_bytes,
            chunk_count,
            maximum_base64_bytes,
            maximum_encoded_bytes,
        })
    }
}

impl Serialize for BorrowedCompactBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(TAG)?;
        tuple.serialize_element(&self.bytes.len())?;
        tuple.serialize_element(&Chunks(self.bytes))?;
        tuple.end()
    }
}

struct Chunks<'a>(&'a [u8]);

impl Serialize for Chunks<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self.0.len().div_ceil(RAW_CHUNK_BYTES);
        let mut sequence = serializer.serialize_seq(Some(count))?;
        let mut buffer = [0_u8; ENCODED_CHUNK_BYTES];

        for chunk in self.0.chunks(RAW_CHUNK_BYTES) {
            let length = encode_chunk(chunk, &mut buffer);
            // The encoder writes only the fixed ASCII alphabet and '='. A
            // checked conversion keeps this module entirely safe Rust.
            let encoded = std::str::from_utf8(&buffer[..length]).map_err(|_| {
                serde::ser::Error::custom("compact byte encoder produced non-ASCII")
            })?;
            sequence.serialize_element(encoded)?;
        }
        sequence.end()
    }
}

// Callers supply only chunks of at most RAW_CHUNK_BYTES, so every output
// quartet fits the fixed ENCODED_CHUNK_BYTES stack buffer.
fn encode_chunk(bytes: &[u8], buffer: &mut [u8; ENCODED_CHUNK_BYTES]) -> usize {
    let mut position = 0;
    for group in bytes.chunks(3) {
        let first = group[0];
        let second = group.get(1).copied().unwrap_or(0);
        let third = group.get(2).copied().unwrap_or(0);
        buffer[position] = ALPHABET[usize::from(first >> 2)];
        buffer[position + 1] = ALPHABET[usize::from((first & 3) << 4 | second >> 4)];
        buffer[position + 2] = if group.len() > 1 {
            ALPHABET[usize::from((second & 15) << 2 | third >> 6)]
        } else {
            b'='
        };
        buffer[position + 3] = if group.len() > 2 {
            ALPHABET[usize::from(third & 63)]
        } else {
            b'='
        };
        position += 4;
    }
    position
}

/// Borrows a completely validated compact tuple without owning decoded storage.
///
/// Private fields retain the same immutable input and its complete decoded
/// extent. This is a data plan, not source custody, alias identity, capture or
/// adoption authority. A caller may validate first, precharge and allocate its
/// original capacity once, then fill that very allocation without another buffer.
#[derive(Clone, Copy)]
pub struct ValidatedCompactBytes<'a> {
    input: &'a [u8],
    decoded_length: usize,
}

impl<'a> ValidatedCompactBytes<'a> {
    /// Names fixed borrowed validation/range controls without an encoder bank.
    ///
    /// This excludes owning decoded storage and the4096-byte serialization
    /// buffer, neither of which is used by validate or copy_range.
    pub const fn validation_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<Cursor<'static>>()
            + size_of::<[u8; 3]>() * 2
            + size_of::<std::slice::Iter<'static, [u8; 4]>>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, [u8; 4]>>>()
            + size_of::<std::slice::IterMut<'static, u8>>()
            + size_of::<std::iter::Enumerate<std::slice::IterMut<'static, u8>>>()
            + size_of::<Option<(usize, &'static [u8; 4])>>()
            + size_of::<Option<(usize, &'static mut u8)>>()
            + size_of::<(&[[u8; 4]], &[u8])>()
            + size_of::<&[u8]>() * 3
            + size_of::<usize>() * 10
            + size_of::<u8>() * 4
            + size_of::<bool>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<u8, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Validates the entire canonical tuple without allocation or byte copies.
    ///
    /// `maximum_input_bytes` bounds the complete encoded tuple and
    /// `maximum_decoded_bytes` bounds its decoded extent. These data bounds
    /// neither reserve storage nor authenticate an original capacity or owner.
    ///
    /// # Errors
    /// Rejects unsupported grammar/edition, escapes, numeric overflow,
    /// noncanonical base64/padding, changed chunk geometry, inconsistent total,
    /// trailing input or exceeded encoded/decoded byte limits.
    pub fn validate(
        input: &'a [u8],
        maximum_input_bytes: usize,
        maximum_decoded_bytes: usize,
    ) -> Result<Self, ProviderError> {
        let decoded_length = walk(input, maximum_input_bytes, maximum_decoded_bytes, |_| {})?;
        Ok(Self {
            input,
            decoded_length,
        })
    }

    /// Returns the complete validated decoded byte extent.
    pub fn decoded_length(&self) -> usize {
        self.decoded_length
    }

    /// Copies a validated decoded range into caller-owned fixed storage.
    ///
    /// Fixed chunk geometry permits direct quartet lookup for each requested
    /// byte, without rescanning or allocating the full decoded payload. Bounds
    /// are checked before writes; the original encoded input remains borrowed.
    ///
    /// # Errors
    /// Refuses an out-of-range extent or inconsistent validated framing.
    pub fn copy_range(&self, offset: usize, destination: &mut [u8]) -> Result<(), ProviderError> {
        let end = offset
            .checked_add(destination.len())
            .ok_or(ProviderError::Frame("compact borrowed range overflow"))?;
        if end > self.decoded_length {
            return Err(ProviderError::Frame("compact borrowed range extent"));
        }
        let mut cursor = Cursor {
            bytes: self.input,
            position: PREFIX.len(),
        };
        cursor.length()?;
        cursor.take(b',')?;
        cursor.take(b'[')?;
        let first_chunk = cursor.position;
        for (relative, byte) in destination.iter_mut().enumerate() {
            let index = offset + relative;
            let chunk = index / RAW_CHUNK_BYTES;
            let within = index % RAW_CHUNK_BYTES;
            let position = chunk
                .checked_mul(ENCODED_CHUNK_BYTES + 3)
                .and_then(|shift| first_chunk.checked_add(shift))
                .and_then(|position| position.checked_add(1 + (within / 3) * 4))
                .ok_or(ProviderError::Frame("compact borrowed range overflow"))?;
            let quartet_end = position
                .checked_add(4)
                .ok_or(ProviderError::Frame("compact borrowed quartet overflow"))?;
            let quartet = self
                .input
                .get(position..quartet_end)
                .ok_or(ProviderError::Frame("compact borrowed quartet extent"))?;
            let mut decoded = [0; 3];
            let mut used = 0;
            visit_chunk(quartet, |bytes| {
                decoded[..bytes.len()].copy_from_slice(bytes);
                used = bytes.len();
            })?;
            if within % 3 >= used {
                return Err(ProviderError::Frame("compact borrowed padding extent"));
            }
            *byte = decoded[within % 3];
        }
        Ok(())
    }

    /// Fills an empty preowned vector while preserving its actual capacity.
    ///
    /// No reservation, shrinking, intermediate owning buffer or capacity reset
    /// occurs. Spare capacity and nonzero empty allocations remain intact. The
    /// caller independently precharges the original allocation's complete
    /// capacity; decoded length does not establish its admission or identity.
    ///
    /// # Errors
    /// Rejects a nonempty destination or insufficient actual capacity before
    /// changing any destination byte, length or capacity. The retained input was
    /// fully validated and remains immutably borrowed through this fill.
    pub fn fill_preowned(&self, destination: &mut Vec<u8>) -> Result<(), ProviderError> {
        if !destination.is_empty() {
            return Err(ProviderError::Conflict(
                "compact preowned destination is not empty",
            ));
        }
        if destination.capacity() < self.decoded_length {
            return Err(ProviderError::ResourceExhausted(
                "compact preowned capacity is insufficient",
            ));
        }
        walk(self.input, self.input.len(), self.decoded_length, |bytes| {
            destination.extend_from_slice(bytes);
        })?;
        Ok(())
    }
}

/// Decodes one complete canonical compact byte tuple under explicit byte limits.
///
/// A first allocation-free pass validates the entire grammar, chunk geometry,
/// canonical padding and pad bits, numeric lengths and exact trailing extent.
/// Only then does a nonempty result request one exact decoded byte reservation.
/// The second pass reads the same immutable input into that reserved vector;
/// it never invokes serde parsing or creates intermediate strings or chunks.
///
/// `maximum_input_bytes` bounds the complete encoded tuple. `maximum_allocation_bytes`
/// bounds decoded vector storage requested and reported by this data decoder,
/// not allocator rounding, process peak memory or original native admission.
/// Those accounting and authority checks remain with the owning caller.
///
/// # Errors
/// Rejects unknown editions, noncanonical or malformed JSON/base64, inconsistent
/// lengths/chunks, overflow, trailing input, insufficient admitted byte limits
/// or a failed exact vector reservation. No result is returned on refusal.
pub fn decode(
    input: &[u8],
    maximum_input_bytes: usize,
    maximum_allocation_bytes: usize,
) -> Result<Vec<u8>, ProviderError> {
    decode_with_reservation(
        input,
        maximum_input_bytes,
        maximum_allocation_bytes,
        |length| {
            let mut result = Vec::new();
            result.try_reserve_exact(length).map_err(|_| {
                ProviderError::ResourceExhausted("compact decoded byte reservation")
            })?;
            Ok(result)
        },
    )
}

fn decode_with_reservation(
    input: &[u8],
    maximum_input_bytes: usize,
    maximum_allocation_bytes: usize,
    reserve: impl FnOnce(usize) -> Result<Vec<u8>, ProviderError>,
) -> Result<Vec<u8>, ProviderError> {
    let length = walk(input, maximum_input_bytes, maximum_allocation_bytes, |_| {})?;
    if length == 0 {
        return Ok(Vec::new());
    }

    let mut result = reserve(length)?;
    if !result.is_empty() || result.capacity() != length {
        return Err(ProviderError::ResourceExhausted(
            "compact decoded byte reservation differs",
        ));
    }
    walk(
        input,
        maximum_input_bytes,
        maximum_allocation_bytes,
        |bytes| {
            result.extend_from_slice(bytes);
        },
    )?;
    Ok(result)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, expected: u8) -> Result<(), ProviderError> {
        if self.bytes.get(self.position) != Some(&expected) {
            return Err(ProviderError::Frame("noncanonical compact byte grammar"));
        }
        self.position += 1;
        Ok(())
    }

    fn length(&mut self) -> Result<usize, ProviderError> {
        let begin = self.position;
        let mut length = 0_usize;
        while let Some(byte @ b'0'..=b'9') = self.bytes.get(self.position).copied() {
            length = length
                .checked_mul(10)
                .and_then(|value| value.checked_add(usize::from(byte - b'0')))
                .ok_or(ProviderError::Frame("compact byte length overflow"))?;
            self.position += 1;
        }
        if begin == self.position || self.position - begin > 1 && self.bytes[begin] == b'0' {
            return Err(ProviderError::Frame("noncanonical compact byte length"));
        }
        Ok(length)
    }

    fn chunk(&mut self) -> Result<&'a [u8], ProviderError> {
        self.take(b'"')?;
        let begin = self.position;
        loop {
            match self.bytes.get(self.position) {
                Some(b'"') => {
                    let chunk = &self.bytes[begin..self.position];
                    self.position += 1;
                    return Ok(chunk);
                }
                Some(_) if self.position - begin < ENCODED_CHUNK_BYTES => {
                    self.position += 1;
                }
                _ => return Err(ProviderError::Frame("compact byte chunk extent")),
            }
        }
    }
}

fn walk(
    input: &[u8],
    maximum_input_bytes: usize,
    maximum_allocation_bytes: usize,
    mut emit: impl FnMut(&[u8]),
) -> Result<usize, ProviderError> {
    if input.len() > maximum_input_bytes {
        return Err(ProviderError::ResourceExhausted(
            "compact encoded byte limit",
        ));
    }
    if !input.starts_with(PREFIX) {
        return Err(ProviderError::Frame("unsupported compact byte edition"));
    }
    let mut cursor = Cursor {
        bytes: input,
        position: PREFIX.len(),
    };
    let length = cursor.length()?;
    if length > maximum_allocation_bytes {
        return Err(ProviderError::ResourceExhausted(
            "compact decoded byte limit",
        ));
    }
    cursor.take(b',')?;
    cursor.take(b'[')?;

    let mut total = 0_usize;
    if cursor.bytes.get(cursor.position) == Some(&b']') {
        cursor.position += 1;
    } else {
        loop {
            let chunk = cursor.chunk()?;
            let final_chunk = match cursor.bytes.get(cursor.position) {
                Some(b',') => {
                    cursor.position += 1;
                    false
                }
                Some(b']') => {
                    cursor.position += 1;
                    true
                }
                _ => return Err(ProviderError::Frame("compact byte chunk separator")),
            };
            if !final_chunk && chunk.len() != ENCODED_CHUNK_BYTES {
                return Err(ProviderError::Frame("compact nonfinal chunk extent"));
            }
            let decoded = visit_chunk(chunk, &mut emit)?;
            if !final_chunk && decoded != RAW_CHUNK_BYTES {
                return Err(ProviderError::Frame("compact nonfinal chunk padding"));
            }
            total = total
                .checked_add(decoded)
                .ok_or(ProviderError::Frame("compact byte total overflow"))?;
            if total > length {
                return Err(ProviderError::Frame("compact byte total exceeds length"));
            }
            if final_chunk {
                break;
            }
        }
    }
    cursor.take(b']')?;
    if cursor.position != input.len() || total != length {
        return Err(ProviderError::Frame(
            "compact byte length or trailing extent",
        ));
    }
    Ok(length)
}

fn sextet(byte: u8) -> Result<u8, ProviderError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(ProviderError::Frame("noncanonical compact base64 alphabet")),
    }
}

fn visit_chunk(chunk: &[u8], mut emit: impl FnMut(&[u8])) -> Result<usize, ProviderError> {
    if chunk.is_empty() || chunk.len() > ENCODED_CHUNK_BYTES || !chunk.len().is_multiple_of(4) {
        return Err(ProviderError::Frame("compact base64 quartet extent"));
    }
    let mut decoded = 0;
    for (index, group) in chunk.as_chunks::<4>().0.iter().enumerate() {
        let first = sextet(group[0])?;
        let second = sextet(group[1])?;
        let last_group = (index + 1) * 4 == chunk.len();
        let mut bytes = [first << 2 | second >> 4, 0, 0];
        let length = if group[2] == b'=' {
            if !last_group || group[3] != b'=' || second & 15 != 0 {
                return Err(ProviderError::Frame(
                    "noncanonical compact base64 two-pad bits",
                ));
            }
            1
        } else {
            let third = sextet(group[2])?;
            bytes[1] = second << 4 | third >> 2;
            if group[3] == b'=' {
                if !last_group || third & 3 != 0 {
                    return Err(ProviderError::Frame("noncanonical compact base64 pad bits"));
                }
                2
            } else {
                bytes[2] = third << 6 | sextet(group[3])?;
                3
            }
        };
        emit(&bytes[..length]);
        decoded += length;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    //! Checks complete bytes, canonical refusal and the allocation boundary.

    // crucible-lint: allow panic-shortcut -- These bounded codec controls panic only when byte or allocation invariants fail.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::cell::Cell;

    fn encoded(bytes: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&BorrowedCompactBytes::new(bytes)).unwrap()
    }

    #[test]
    fn complete_binary_bytes_and_canonical_base64_vectors_roundtrip() {
        for (plain, base64) in [
            (b"".as_slice(), ""),
            (b"f".as_slice(), "Zg=="),
            (b"fo".as_slice(), "Zm8="),
            (b"foo".as_slice(), "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg=="),
            (b"fooba".as_slice(), "Zm9vYmE="),
            (b"foobar".as_slice(), "Zm9vYmFy"),
        ] {
            let body = encoded(plain);
            let expected = if plain.is_empty() {
                format!("[\"{TAG}\",0,[]]")
            } else {
                format!("[\"{TAG}\",{},[\"{base64}\"]]", plain.len())
            };
            assert_eq!(body, expected.as_bytes());
            let restored = decode(&body, body.len(), plain.len()).unwrap();
            assert_eq!(restored, plain);
            assert_eq!(restored.capacity(), plain.len());
        }

        let all_byte_values: Vec<u8> = (0_u8..=u8::MAX).collect();
        let body = encoded(&all_byte_values);
        assert_eq!(
            decode(&body, body.len(), all_byte_values.len()).unwrap(),
            all_byte_values
        );
    }

    #[test]
    fn exact_chunk_boundaries_preserve_the_complete_tail() {
        for length in [
            RAW_CHUNK_BYTES - 1,
            RAW_CHUNK_BYTES,
            RAW_CHUNK_BYTES + 1,
            RAW_CHUNK_BYTES * 2,
            RAW_CHUNK_BYTES * 2 + 1,
        ] {
            let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            let body = encoded(&bytes);
            let result = decode(&body, body.len(), length).unwrap();

            assert_eq!(result, bytes);
            assert_eq!(result.capacity(), length);
            let shape: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let chunks = shape[2].as_array().unwrap();
            assert_eq!(chunks.len(), length.div_ceil(RAW_CHUNK_BYTES));
            for chunk in &chunks[..chunks.len() - 1] {
                assert_eq!(chunk.as_str().unwrap().len(), ENCODED_CHUNK_BYTES);
                assert!(!chunk.as_str().unwrap().contains('='));
            }
        }
    }

    #[test]
    fn grammar_padding_and_trailing_errors_never_request_output_storage() {
        let calls = Cell::new(0);
        let canonical = String::from_utf8(encoded(b"f")).unwrap();
        let overflow = format!("[\"{TAG}\",{}0,[]]", usize::MAX);
        let exaggerated = format!("[\"{TAG}\",{},[\"Zg==\"]]", usize::MAX);
        let invalid = [
            "".to_owned(),
            canonical.replace("/7", "/6"),
            format!(" {canonical}"),
            format!("{canonical}\n"),
            canonical.replace(",1,", ",01,"),
            canonical.replace(",1,", ",1 ,"),
            canonical.replace(",1,", ",1e0,"),
            canonical.replace("Zg==", "Zh=="),
            canonical.replace("Zg==", "===="),
            canonical.replace("Zg==", "A==="),
            canonical.replace("Zg==", "Zg=+"),
            canonical.replace("Zg==", "Zg"),
            canonical.replace("Zg==", "Zg==Zg=="),
            canonical.replace("Zg==", "Zg\\u003d\\u003d"),
            canonical.replace("Zg==", "Zg ="),
            format!("{canonical}[]"),
            overflow,
            exaggerated,
            format!("[\"{TAG}\",0,[\"\"]]"),
            format!("[\"{TAG}\",1,[]]"),
            format!("[\"{TAG}\",2,[\"Zm9=\"]]"),
            format!("[\"{TAG}\",6,[\"Zm9v\",\"Zm9v\"]]"),
        ];

        for input in invalid {
            let result =
                decode_with_reservation(input.as_bytes(), input.len(), usize::MAX, |length| {
                    calls.set(calls.get() + 1);
                    Ok(Vec::with_capacity(length))
                });
            assert!(result.is_err(), "unexpected accepted input {input}");
        }
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn padded_nonfinal_full_chunk_and_oversize_chunk_refuse_before_allocation() {
        let first = "A".repeat(ENCODED_CHUNK_BYTES - 2) + "==";
        let padded_nonfinal = format!("[\"{TAG}\",3072,[\"{first}\",\"AA==\"]]");
        let oversize = format!(
            "[\"{TAG}\",3075,[\"{}\"]]",
            "A".repeat(ENCODED_CHUNK_BYTES + 4)
        );
        let calls = Cell::new(0);

        for input in [padded_nonfinal, oversize] {
            assert!(
                decode_with_reservation(input.as_bytes(), input.len(), 4096, |length| {
                    calls.set(calls.get() + 1);
                    Ok(Vec::with_capacity(length))
                })
                .is_err()
            );
        }
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn finite_credit_precedes_one_exact_nonempty_reservation() {
        let bytes = [7, 8, 9, 10];
        let body = encoded(&bytes);
        let calls = Cell::new(0);
        for (maximum_input, maximum_output) in
            [(body.len() - 1, bytes.len()), (body.len(), bytes.len() - 1)]
        {
            assert!(
                decode_with_reservation(&body, maximum_input, maximum_output, |length| {
                    calls.set(calls.get() + 1);
                    Ok(Vec::with_capacity(length))
                })
                .is_err()
            );
        }
        assert_eq!(calls.get(), 0);

        let result = decode_with_reservation(&body, body.len(), bytes.len(), |length| {
            calls.set(calls.get() + 1);
            assert_eq!(length, bytes.len());
            Ok(Vec::with_capacity(length))
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(result, bytes);
        assert_eq!(result.capacity(), bytes.len());
    }

    #[test]
    fn empty_bytes_need_no_reservation_and_nonexact_allocator_result_refuses() {
        let calls = Cell::new(0);
        let empty = encoded(&[]);
        let result = decode_with_reservation(&empty, empty.len(), 0, |_| {
            calls.set(calls.get() + 1);
            Err(ProviderError::ResourceExhausted(
                "unexpected empty allocation",
            ))
        })
        .unwrap();
        assert!(result.is_empty());
        assert_eq!(result.capacity(), 0);
        assert_eq!(calls.get(), 0);

        let body = encoded(b"abc");
        assert!(
            decode_with_reservation(&body, body.len(), 3, |_| {
                calls.set(calls.get() + 1);
                Ok(Vec::with_capacity(4))
            })
            .is_err()
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn measured_peer_sized_bytes_avoid_numeric_json_expansion_without_loss() {
        // The size matches Packet's retained peer ELF measurement. This fixture
        // checks all byte values and exact capacity, not executable provenance.
        let length: usize = 16_012_800;
        let bytes: Vec<u8> = (0..length).map(|index| (index % 256) as u8).collect();
        let body = encoded(&bytes);
        let chunks = length.div_ceil(RAW_CHUNK_BYTES);
        let expected = PREFIX.len()
            + length.to_string().len()
            + 2
            + length.div_ceil(3) * 4
            + chunks * 2
            + (chunks - 1)
            + 2;

        assert_eq!(body.len(), expected);
        assert!(body.len() * 12 < 512 * 1024 * 1024);
        let result = decode(&body, body.len(), length).unwrap();
        assert_eq!(result, bytes);
        assert_eq!(result.capacity(), length);
    }

    #[test]
    fn caller_reserves_original_spare_capacity_once_then_fills_same_allocation() {
        let body = encoded(b"original complete bytes");
        let plan = ValidatedCompactBytes::validate(&body, body.len(), 23).unwrap();
        assert_eq!(plan.decoded_length(), 23);
        let reservation_calls = Cell::new(0);
        let reserve_original = |capacity| {
            reservation_calls.set(reservation_calls.get() + 1);
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(capacity).unwrap();
            bytes
        };
        let mut destination = reserve_original(1024);
        let original_pointer = destination.as_ptr();
        let original_capacity = destination.capacity();

        plan.fill_preowned(&mut destination).unwrap();

        assert_eq!(destination, b"original complete bytes");
        assert_eq!(destination.capacity(), original_capacity);
        assert_eq!(destination.as_ptr(), original_pointer);
        assert_eq!(reservation_calls.get(), 1);
    }

    #[test]
    fn validated_empty_bytes_preserve_nonzero_original_capacity() {
        let body = encoded(&[]);
        let plan = ValidatedCompactBytes::validate(&body, body.len(), 0).unwrap();
        let mut destination = Vec::with_capacity(97);
        let original_pointer = destination.as_ptr();
        let original_capacity = destination.capacity();

        plan.fill_preowned(&mut destination).unwrap();

        assert_eq!(plan.decoded_length(), 0);
        assert!(destination.is_empty());
        assert_eq!(destination.capacity(), original_capacity);
        assert_eq!(destination.as_ptr(), original_pointer);
    }

    #[test]
    fn nonempty_and_insufficient_preowned_targets_remain_unchanged() {
        let body = encoded(b"abc");
        let plan = ValidatedCompactBytes::validate(&body, body.len(), 3).unwrap();
        let mut nonempty = Vec::with_capacity(128);
        nonempty.push(99);
        let nonempty_pointer = nonempty.as_ptr();
        let nonempty_capacity = nonempty.capacity();
        let mut insufficient = Vec::with_capacity(2);
        let insufficient_pointer = insufficient.as_ptr();
        let insufficient_capacity = insufficient.capacity();

        assert!(plan.fill_preowned(&mut nonempty).is_err());
        assert!(plan.fill_preowned(&mut insufficient).is_err());

        assert_eq!(nonempty, [99]);
        assert_eq!(nonempty.capacity(), nonempty_capacity);
        assert_eq!(nonempty.as_ptr(), nonempty_pointer);
        assert!(insufficient.is_empty());
        assert_eq!(insufficient.capacity(), insufficient_capacity);
        assert_eq!(insufficient.as_ptr(), insufficient_pointer);
    }

    #[test]
    fn malformed_input_cannot_create_a_plan_or_request_original_allocation() {
        let good = String::from_utf8(encoded(b"f")).unwrap();
        let requests = Cell::new(0);
        for bad in [
            good.replace("Zg==", "Zh=="),
            format!("{good}x"),
            good.replace(",1,", ",01,"),
            good.replace("/7", "/8"),
        ] {
            let checked = ValidatedCompactBytes::validate(bad.as_bytes(), bad.len(), 1);
            if let Ok(plan) = checked {
                requests.set(requests.get() + 1);
                let mut destination = Vec::with_capacity(64);
                plan.fill_preowned(&mut destination).unwrap();
            }
        }
        assert_eq!(requests.get(), 0);
    }

    #[test]
    fn original_capacity_is_independent_of_exact_decoded_length_credit() {
        let bytes: Vec<u8> = (0..RAW_CHUNK_BYTES + 1)
            .map(|index| (index % 251) as u8)
            .collect();
        let body = encoded(&bytes);
        assert!(ValidatedCompactBytes::validate(&body, body.len() - 1, bytes.len()).is_err());
        assert!(ValidatedCompactBytes::validate(&body, body.len(), bytes.len() - 1).is_err());
        let plan = ValidatedCompactBytes::validate(&body, body.len(), bytes.len()).unwrap();
        let mut destination = Vec::with_capacity(bytes.len() + 4096);
        let original_pointer = destination.as_ptr();
        let original_capacity = destination.capacity();

        plan.fill_preowned(&mut destination).unwrap();

        assert_eq!(destination, bytes);
        assert_eq!(destination.capacity(), original_capacity);
        assert_eq!(destination.as_ptr(), original_pointer);
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "validated borrowed ranges retain exact original bytes"
)]
mod borrowed_range_tests {
    use super::*;

    #[test]
    fn exact_ranges_cross_full_chunks_and_final_padding() {
        for length in [0usize, 1, 2, 3, 3071, 3072, 3073, 6145] {
            let original = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let encoded = serde_json::to_vec(&BorrowedCompactBytes::new(&original)).unwrap();
            let plan = ValidatedCompactBytes::validate(&encoded, encoded.len(), length).unwrap();
            for offset in [0, length / 2, length.saturating_sub(5), length] {
                let count = (length - offset).min(9);
                let mut destination = [0u8; 9];
                plan.copy_range(offset, &mut destination[..count]).unwrap();
                assert_eq!(&destination[..count], &original[offset..offset + count]);
            }
            if length > 3072 {
                let mut across = [0u8; 5];
                plan.copy_range(3070, &mut across[..(length - 3070).min(5)])
                    .unwrap();
                assert_eq!(
                    &across[..(length - 3070).min(5)],
                    &original[3070..(3075.min(length))]
                );
            }
            let mut untouched = [71u8; 2];
            assert!(plan.copy_range(length, &mut untouched).is_err());
            assert_eq!(untouched, [71; 2]);
            assert!(plan.copy_range(usize::MAX, &mut untouched).is_err());
            assert_eq!(untouched, [71; 2]);
        }
    }
}

#[cfg(test)]
mod serialization_layout_tests {
    use super::*;

    #[test]
    fn prospective_compact_layout_matches_actual_encoder_across_chunk_boundaries()
    -> Result<(), ProviderError> {
        for length in [
            0usize,
            1,
            2,
            3,
            RAW_CHUNK_BYTES - 1,
            RAW_CHUNK_BYTES,
            RAW_CHUNK_BYTES + 1,
            2 * RAW_CHUNK_BYTES,
            2 * RAW_CHUNK_BYTES + 2,
        ] {
            let original = vec![0xa5; length];
            let layout = BorrowedCompactBytes::serialization_layout_data(original.len())?;
            let encoded = serde_json::to_vec(&BorrowedCompactBytes::new(&original))
                .map_err(crucible_node_contract::ContractError::from)?;
            let validated =
                ValidatedCompactBytes::validate(&encoded, encoded.len(), original.len())?;
            assert_eq!(layout.maximum_raw_bytes, validated.decoded_length());
            assert_eq!(layout.maximum_encoded_bytes, encoded.len());
            assert_eq!(
                layout.chunk_count,
                layout.full_chunks + usize::from(layout.final_encoded_chunk_bytes != 0)
            );
            assert_eq!(
                layout.maximum_base64_bytes,
                layout.full_chunks * ENCODED_CHUNK_BYTES + layout.final_encoded_chunk_bytes
            );
        }
        Ok(())
    }

    #[test]
    fn compact_layout_refuses_overflow_without_allocating_body() {
        assert!(BorrowedCompactBytes::serialization_layout_data(usize::MAX).is_err());
    }
}
