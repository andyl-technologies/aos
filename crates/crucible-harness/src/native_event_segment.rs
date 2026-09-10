//! Strict decoding for canonical scheduler event-log segments.
//!
//! The native collector uses this module to authenticate and summarize event
//! segments without starting a Crucible runtime. It validates duplicated
//! binary index fields against the authenticated canonical entry material so
//! labels used in diagnostic reports cannot disagree with the material they
//! describe.
//!
//! Multi-byte integers and string lengths use little-endian encoding:
//!
//! ```text
//! magic[16] | version:u32 | previous_prefix[32] | entry_count:u64
//! repeated entry_count times:
//!   sequence:u64 | virtual_ticks:u64 | icount_retired:u64
//!   node_presence:u8 | node?:string | source:string | level:u8 | class:u8
//!   payload_kind:string | payload_attribute_count:u64
//!   content_hash[32] | material:string
//! string := length:u64 | utf8_bytes[length]
//! ```

use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::num::ParseIntError;
use std::str::Utf8Error;

const MAGIC: &[u8; 16] = b"CRUCIBLE-ELOGSEG";
const VERSION: u32 = 1;

/// One authenticated scheduler event decoded for diagnostic reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Dense event sequence encoded by the segment.
    pub sequence: u64,
    /// Virtual-time tick encoded by the segment.
    pub virtual_ticks: u64,
    /// Retired instruction count encoded by the segment.
    pub icount_retired: u64,
    /// Event kind authenticated by the canonical material.
    pub kind: String,
    /// Canonical event-entry material authenticated by its content hash.
    pub material: String,
}

/// A failure to decode or authenticate a scheduler event-log segment.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The segment does not begin with the canonical event-log magic.
    InvalidMagic,
    /// The segment declares an unsupported format version.
    UnsupportedVersion {
        /// Version declared by the segment.
        version: u32,
    },
    /// The segment declares more entries than the caller permits.
    EntryLimitExceeded {
        /// Entry count declared by the segment.
        declared: u64,
        /// Maximum entry count accepted by the caller.
        maximum: u64,
    },
    /// The declared entry count cannot be represented on this platform.
    EntryCountNotRepresentable {
        /// Entry count declared by the segment.
        count: u64,
    },
    /// Memory could not be reserved for all declared entries.
    EntryReservationFailed {
        /// Entry count declared by the segment.
        count: u64,
        /// Allocation failure reported by the standard library.
        source: TryReserveError,
    },
    /// An entry uses an invalid node-presence discriminant.
    InvalidNodePresence {
        /// Discriminant encoded by the entry.
        value: u8,
    },
    /// An entry uses an invalid event level.
    InvalidLevel {
        /// Level encoded by the entry.
        level: u8,
    },
    /// An entry uses an invalid event class.
    InvalidClass {
        /// Class encoded by the entry.
        class: u8,
    },
    /// An entry's content hash does not authenticate its canonical material.
    ContentHashMismatch {
        /// Sequence number encoded by the entry.
        sequence: u64,
    },
    /// Canonical material omits a required field.
    MissingMaterialField {
        /// Prefix identifying the required material field.
        field: &'static str,
    },
    /// Canonical material repeats a field that must be unique.
    RepeatedMaterialField {
        /// Prefix identifying the repeated material field.
        field: &'static str,
    },
    /// A material field that must be an unsigned integer cannot be parsed.
    InvalidMaterialU64 {
        /// Prefix identifying the invalid material field.
        field: &'static str,
        /// Integer parsing failure reported by the standard library.
        source: ParseIntError,
    },
    /// An indexed integer differs from its authenticated material value.
    MaterialU64Mismatch {
        /// Prefix identifying the material field.
        field: &'static str,
        /// Value encoded in the binary index.
        binary: u64,
        /// Value encoded in canonical material.
        material: u64,
    },
    /// An indexed string differs from its authenticated material value.
    MaterialStringMismatch {
        /// Prefix identifying the material field.
        field: &'static str,
        /// Value encoded in the binary index.
        binary: String,
        /// Value encoded in canonical material.
        material: String,
    },
    /// Advancing past a field would overflow the decoder offset.
    OffsetOverflow {
        /// Name of the field being decoded.
        field: &'static str,
    },
    /// The segment ends before a field is complete.
    Truncated {
        /// Name of the incomplete field.
        field: &'static str,
    },
    /// A string length cannot be represented on this platform.
    LengthNotRepresentable {
        /// Name of the string field.
        field: &'static str,
        /// Length declared by the segment.
        length: u64,
    },
    /// A string field is not valid UTF-8.
    InvalidUtf8 {
        /// Name of the invalid string field.
        field: &'static str,
        /// UTF-8 validation failure reported by the standard library.
        source: Utf8Error,
    },
    /// Bytes remain after all declared entries are decoded.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid event-segment magic"),
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported event-segment version {version}")
            }
            Self::EntryLimitExceeded { declared, maximum } => write!(
                formatter,
                "event segment declares {declared} entries above bound {maximum}"
            ),
            Self::EntryCountNotRepresentable { count } => {
                write!(formatter, "event entry count {count} is not representable")
            }
            Self::EntryReservationFailed { count, .. } => {
                write!(formatter, "reserve {count} decoded event entries")
            }
            Self::InvalidNodePresence { value } => {
                write!(formatter, "invalid event entry node-presence flag {value}")
            }
            Self::InvalidLevel { level } => {
                write!(formatter, "invalid event entry level {level}")
            }
            Self::InvalidClass { class } => {
                write!(formatter, "invalid event entry class {class}")
            }
            Self::ContentHashMismatch { sequence } => write!(
                formatter,
                "event entry {sequence} content hash does not authenticate its material"
            ),
            Self::MissingMaterialField { field } => {
                write!(formatter, "event material lacks `{field}` field")
            }
            Self::RepeatedMaterialField { field } => {
                write!(formatter, "event material repeats `{field}` field")
            }
            Self::InvalidMaterialU64 { field, source } => {
                write!(
                    formatter,
                    "event material field `{field}` is not u64: {source}"
                )
            }
            Self::MaterialU64Mismatch {
                field,
                binary,
                material,
            } => write!(
                formatter,
                "event binary field `{field}` value {binary} differs from material {material}"
            ),
            Self::MaterialStringMismatch {
                field,
                binary,
                material,
            } => write!(
                formatter,
                "event binary field `{field}` value `{binary}` differs from material `{material}`"
            ),
            Self::OffsetOverflow { field } => write!(formatter, "{field} offset overflow"),
            Self::Truncated { field } => write!(formatter, "truncated {field}"),
            Self::LengthNotRepresentable { field, length } => {
                write!(formatter, "{field} length {length} is not representable")
            }
            Self::InvalidUtf8 { field, .. } => write!(formatter, "{field} is not UTF-8"),
            Self::TrailingBytes { count } => {
                write!(formatter, "event segment has {count} trailing bytes")
            }
        }
    }
}

impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EntryReservationFailed { source, .. } => Some(source),
            Self::InvalidMaterialU64 { source, .. } => Some(source),
            Self::InvalidUtf8 { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Returns whether `bytes` starts with the scheduler event-segment magic.
#[must_use]
pub fn has_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Decodes one complete scheduler event-log segment within an entry bound.
///
/// # Errors
///
/// Returns an error when the segment is malformed, exceeds `maximum_entries`,
/// contains unauthenticated material, or has binary index fields that disagree
/// with the authenticated material.
pub fn decode(bytes: &[u8], maximum_entries: u64) -> Result<Vec<Entry>, DecodeError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.read_exact("magic", MAGIC.len())? != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let version = cursor.read_u32("version")?;
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion { version });
    }
    cursor.read_exact("previous prefix", 32)?;
    let entry_count = cursor.read_u64("entry count")?;
    if entry_count > maximum_entries {
        return Err(DecodeError::EntryLimitExceeded {
            declared: entry_count,
            maximum: maximum_entries,
        });
    }
    let capacity = usize::try_from(entry_count)
        .map_err(|_| DecodeError::EntryCountNotRepresentable { count: entry_count })?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(capacity)
        .map_err(|source| DecodeError::EntryReservationFailed {
            count: entry_count,
            source,
        })?;
    for _ in 0..entry_count {
        let sequence = cursor.read_u64("entry sequence")?;
        let virtual_ticks = cursor.read_u64("entry virtual time")?;
        let icount_retired = cursor.read_u64("entry icount")?;
        match cursor.read_u8("entry node presence")? {
            0 => {}
            1 => {
                cursor.read_string("entry node")?;
            }
            value => return Err(DecodeError::InvalidNodePresence { value }),
        }
        cursor.read_string("entry source")?;
        let level = cursor.read_u8("entry level")?;
        if level > 4 {
            return Err(DecodeError::InvalidLevel { level });
        }
        let class = cursor.read_u8("entry class")?;
        if class > 1 {
            return Err(DecodeError::InvalidClass { class });
        }
        let kind = cursor.read_string("entry payload kind")?;
        cursor.read_u64("entry payload attribute count")?;
        let content_hash = cursor.read_exact("entry content hash", 32)?;
        let material = cursor.read_string("entry material")?;
        if content_hash != entry_content_hash(material.as_bytes()) {
            return Err(DecodeError::ContentHashMismatch { sequence });
        }
        require_material_u64(&material, "sequence=", sequence)?;
        require_material_u64(&material, "at_virtual_time_ticks=", virtual_ticks)?;
        require_material_u64(&material, "at_icount_retired=", icount_retired)?;
        require_material_string(&material, "event_payload.kind=", &kind)?;
        entries.push(Entry {
            sequence,
            virtual_ticks,
            icount_retired,
            kind,
            material,
        });
    }
    cursor.finish()?;
    Ok(entries)
}

fn require_material_u64(
    material: &str,
    field: &'static str,
    binary: u64,
) -> Result<(), DecodeError> {
    let value = unique_material_value(material, field)?;
    let material = value
        .parse::<u64>()
        .map_err(|source| DecodeError::InvalidMaterialU64 { field, source })?;
    if material != binary {
        return Err(DecodeError::MaterialU64Mismatch {
            field,
            binary,
            material,
        });
    }
    Ok(())
}

fn require_material_string(
    material: &str,
    field: &'static str,
    binary: &str,
) -> Result<(), DecodeError> {
    let material = unique_material_value(material, field)?;
    if material != binary {
        return Err(DecodeError::MaterialStringMismatch {
            field,
            binary: binary.to_owned(),
            material: material.to_owned(),
        });
    }
    Ok(())
}

fn unique_material_value<'a>(
    material: &'a str,
    field: &'static str,
) -> Result<&'a str, DecodeError> {
    let mut values = material.lines().filter_map(|line| line.strip_prefix(field));
    let value = values
        .next()
        .ok_or(DecodeError::MissingMaterialField { field })?;
    if values.next().is_some() {
        return Err(DecodeError::RepeatedMaterialField { field });
    }
    Ok(value)
}

/// Computes the versioned content hash used by canonical event-entry material.
#[must_use]
pub fn entry_content_hash(material: &[u8]) -> [u8; 32] {
    let mut hasher = MaterialHasher::new();
    hasher.write_bytes(b"crucible.content-hash.v1");
    hasher.write_bytes(b"crucible.scheduler.event-log.entry.v1");
    hasher.write_bytes(material);
    hasher.finish()
}

struct MaterialHasher {
    lanes: [u64; 4],
    bytes_written: u64,
}

impl MaterialHasher {
    fn new() -> Self {
        Self {
            lanes: [
                0x243f_6a88_85a3_08d3,
                0x1319_8a2e_0370_7344,
                0xa409_3822_299f_31d0,
                0x082e_fa98_ec4e_6c89,
            ],
            bytes_written: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u64(bytes.len() as u64);
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.mix_word(u64::from_le_bytes(*chunk));
        }
        if !remainder.is_empty() {
            let mut word = [0; 8];
            word[..remainder.len()].copy_from_slice(remainder);
            self.mix_word(u64::from_le_bytes(word));
        }
        self.bytes_written = self.bytes_written.wrapping_add(bytes.len() as u64);
    }

    fn write_u64(&mut self, value: u64) {
        self.mix_word(value);
        self.bytes_written = self.bytes_written.wrapping_add(8);
    }

    fn mix_word(&mut self, word: u64) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            let rotation = 13 + (index as u32 * 7);
            let salt = (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            *lane ^= word.wrapping_add(salt);
            *lane = lane
                .rotate_left(rotation)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
            *lane ^= *lane >> 33;
        }
    }

    fn finish(&self) -> [u8; 32] {
        let mut lanes = self.lanes;
        for (index, lane) in lanes.iter_mut().enumerate() {
            let salt = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            *lane = finalize_hash_word(lane.wrapping_add(self.bytes_written).wrapping_add(salt));
        }
        let mut bytes = [0; 32];
        for (index, lane) in lanes.iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        bytes
    }
}

fn finalize_hash_word(mut word: u64) -> u64 {
    word ^= word >> 30;
    word = word.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    word ^= word >> 27;
    word = word.wrapping_mul(0x94d0_49bb_1331_11eb);
    word ^ (word >> 31)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, field: &'static str, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::OffsetOverflow { field })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DecodeError::Truncated { field })?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(self.read_exact(field, 1)?[0])
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.read_exact(field, 4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.read_exact(field, 8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, DecodeError> {
        let length = self.read_u64(field)?;
        let length = usize::try_from(length)
            .map_err(|_| DecodeError::LengthNotRepresentable { field, length })?;
        let bytes = self.read_exact(field, length)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|source| DecodeError::InvalidUtf8 { field, source })
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                count: self.bytes.len() - self.offset,
            })
        }
    }
}
