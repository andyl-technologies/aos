//! Exact-length canonical hashing without an intermediate owned material buffer.
//!
//! The first pass counts the borrowed UTF-8 representation. The second pass
//! preserves the ordinary material hash's length prefix, word boundaries and
//! final partial word even when a formatter splits writes at different offsets.

use std::fmt::{self, Display, Write};

use super::{ContentHash, MaterialHasher};
use crate::model::{EngineError, scenario_serialization_error};

pub(crate) fn hash_material(
    domain: &str,
    material: &impl Display,
) -> Result<ContentHash, EngineError> {
    let budget = crate::owned_decode::current_budget();
    let _scratch = budget
        .as_ref()
        .map(|budget| {
            budget.reserve_scratch_bytes(
                (std::mem::size_of::<CountWriter>() + std::mem::size_of::<HashWriter>()) as u64,
            )
        })
        .transpose()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;

    let mut count = CountWriter(0);
    write!(&mut count, "{material}").map_err(|_| invalid_material())?;

    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(domain.as_bytes());
    hasher.write_u64(count.0);
    let mut writer = HashWriter {
        hasher,
        expected: count.0,
        written: 0,
        word: [0; 8],
        pending: 0,
    };
    write!(&mut writer, "{material}").map_err(|_| invalid_material())?;
    if writer.written != writer.expected {
        return Err(invalid_material());
    }
    if writer.pending != 0 {
        writer.hasher.mix_word(u64::from_le_bytes(writer.word));
    }
    writer.hasher.bytes_written = writer.hasher.bytes_written.wrapping_add(writer.written);
    Ok(ContentHash {
        bytes: writer.hasher.finish(),
    })
}

/// Counts borrowed canonical UTF-8 material without allocating output.
///
/// # Errors
/// Refuses original admission exhaustion, formatting failure or length overflow.
pub(crate) fn canonical_display_len(material: &impl Display) -> Result<usize, EngineError> {
    let budget = crate::owned_decode::current_budget();
    let _scratch = budget
        .as_ref()
        .map(|budget| budget.reserve_scratch_bytes(std::mem::size_of::<CountWriter>() as u64))
        .transpose()
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })?;
    let mut count = CountWriter(0);
    write!(&mut count, "{material}").map_err(|_| invalid_material())?;
    usize::try_from(count.0).map_err(|_| invalid_material())
}

/// Renders admitted lexical keys with an exact preallocation and no growing scratch.
pub(in crate::model) fn material_string(material: &impl Display) -> Result<String, EngineError> {
    crate::owned_decode::display_string(material)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

fn invalid_material() -> EngineError {
    scenario_serialization_error(
        "canonical material overflowed or changed between streaming passes",
    )
}

struct CountWriter(u64);

impl Write for CountWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 = self.0.checked_add(text.len() as u64).ok_or(fmt::Error)?;
        Ok(())
    }
}

struct HashWriter {
    hasher: MaterialHasher,
    expected: u64,
    written: u64,
    word: [u8; 8],
    pending: usize,
}

impl Write for HashWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let written = self
            .written
            .checked_add(text.len() as u64)
            .ok_or(fmt::Error)?;
        if written > self.expected {
            return Err(fmt::Error);
        }
        for byte in text.bytes() {
            self.word[self.pending] = byte;
            self.pending += 1;
            if self.pending == self.word.len() {
                self.hasher.mix_word(u64::from_le_bytes(self.word));
                self.word = [0; 8];
                self.pending = 0;
            }
        }
        self.written = written;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fragmented<'a>(&'a str);

    impl Display for Fragmented<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for character in self.0.chars() {
                write!(formatter, "{character}")?;
            }
            Ok(())
        }
    }

    #[test]
    fn streaming_preserves_length_prefix_and_partial_words() {
        for text in ["", "x", "1234567", "12345678", "123456789", "xé水abcdefgh"] {
            let expected = ContentHash::from_canonical_material("stream-test", text);
            let actual = hash_material("stream-test", &Fragmented(text))
                .unwrap_or_else(|error| panic!("stream borrowed material: {error}"));
            assert_eq!(actual, expected);
        }
    }
}
