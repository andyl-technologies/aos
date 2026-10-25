//! Stores immutable JSON DATA without retaining a tree allocation per value.
//!
//! The private bank uses explicit scalar tags, little-endian eight-byte widths,
//! UTF-8 strings and length-delimited containers. It is an implementation detail,
//! not a process protocol or a replacement for authenticated original custody.
//! Its borrowed serializer emits the original logical JSON, including the exact
//! integer or floating-point representation; it performs no JSON parsing or
//! heap allocation. Owned materialization is a separate, allocating operation.
//!
//! Every scalar costs at most nine times its complete canonical JSON extent.
//! A container's seventeen-byte header fits within nine times its two JSON
//! delimiters. Applying these bounds to children and object keys proves the
//! same bound for a whole document, including arbitrary nested error details.
//! These DATA operations issue no allocation, journal, Source or native rights.

use crate::ProviderError;
use serde::{Serialize, Serializer, ser::SerializeMap, ser::SerializeSeq};
use serde_json::Value;

const NULL: u8 = 0;
const FALSE: u8 = 1;
const TRUE: u8 = 2;
const UNSIGNED: u8 = 3;
const SIGNED: u8 = 4;
const FLOAT: u8 = 5;
const STRING: u8 = 6;
const ARRAY: u8 = 7;
const OBJECT: u8 = 8;
const SCALAR_WIDTH: usize = 9;
const CONTAINER_WIDTH: usize = 17;
const MAXIMUM_DEPTH: usize = 64;

mod envelope;

/// Owns one immutable, losslessly encoded JSON DATA value.
///
/// No decoder accepts caller-supplied binary banks. Construction starts from an
/// actual borrowed Value and checks its complete geometry before allocating.
/// The bank does not preserve the caller's spare capacities or establish any
/// relationship between independently owning requests, journals or snapshots.
pub struct CompactJson {
    bytes: Vec<u8>,
}

impl crate::retained_metadata::ObserveMetadata for CompactJson {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self { bytes } = self;
        observer.vector::<u8>(bytes.capacity())
    }
}

impl CompactJson {
    /// Computes exact bank payload bytes without allocating or serializing JSON.
    ///
    /// The caller independently funds the borrowed walk and bounded recursion.
    /// The result excludes the bank's Vec header and the caller's original tree.
    ///
    /// # Errors
    /// Refuses checked overflow, nesting beyond 64 containers, arrays beyond the
    /// existing portable limit, or demand above the independent restriction.
    pub fn storage_bytes(value: &Value, maximum: usize) -> Result<usize, ProviderError> {
        measure(value, 0, maximum)
    }

    /// Bounds bank payload bytes from a complete canonical JSON byte ceiling.
    ///
    /// This checked grammar bound covers arbitrary supported JSON, not just
    /// successful typed responses. It grants no quota, reservation or alias
    /// discount. Independent bank headers and journal owners remain separate.
    ///
    /// # Errors
    /// Refuses multiplication overflow or a bound above the supplied restriction.
    pub fn maximum_storage_bytes(
        canonical_bytes: usize,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        canonical_bytes
            .checked_mul(9)
            .filter(|&bytes| bytes <= maximum)
            .ok_or_else(refused)
    }

    /// Copies the complete value into one checked, exactly requested byte bank.
    ///
    /// The caller admits construction before entering this method. The immutable
    /// source tree remains independently owned throughout measurement and copy.
    /// No JSON text, intermediate tree or normalized number is constructed.
    ///
    /// # Errors
    /// Refuses unsupported geometry, overflow, insufficient independent storage
    /// or allocation failure before publishing a bank.
    pub fn from_value(value: &Value, maximum: usize) -> Result<Self, ProviderError> {
        let requested = Self::storage_bytes(value, maximum)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(requested).map_err(|_| refused())?;
        if bytes.capacity() > maximum {
            return Err(refused());
        }

        encode(value, &mut bytes)?;
        if bytes.len() != requested {
            return Err(invalid());
        }
        Ok(Self { bytes })
    }

    /// Returns the actual retained Vec capacity, excluding its inline header.
    pub fn retained_bytes(&self) -> usize {
        self.bytes.capacity()
    }

    /// Borrows the original logical JSON without materializing a tree.
    ///
    /// Serializing this view reads the private checked bank directly. Allocation
    /// by the chosen output serializer remains the caller's separate operation.
    pub fn as_serializable(&self) -> impl Serialize + '_ {
        BorrowedValue(&self.bytes)
    }

    /// Materializes a fresh, independently owning JSON tree.
    ///
    /// This allocating operation requires its own admitted transient window;
    /// bank storage and the numeric DATA restriction do not fund that window.
    /// It preserves Number variants and floating-point bits without text parsing.
    ///
    /// # Errors
    /// Returns a serialization error if the private bank cannot be traversed.
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self.as_serializable())
    }
}

fn measure(value: &Value, depth: usize, maximum: usize) -> Result<usize, ProviderError> {
    let bytes = match value {
        Value::Null | Value::Bool(_) => 1,
        Value::Number(_) => SCALAR_WIDTH,
        Value::String(text) => add(SCALAR_WIDTH, text.len(), maximum)?,
        Value::Array(values) => {
            check_container(depth, values.len(), true)?;
            values.iter().try_fold(CONTAINER_WIDTH, |bytes, child| {
                add(bytes, measure(child, depth + 1, maximum)?, maximum)
            })?
        }
        Value::Object(values) => {
            check_container(depth, values.len(), false)?;
            values
                .iter()
                .try_fold(CONTAINER_WIDTH, |bytes, (key, child)| {
                    let key_bytes = add(SCALAR_WIDTH, key.len(), maximum)?;
                    let child_bytes = measure(child, depth + 1, maximum)?;
                    add(add(bytes, key_bytes, maximum)?, child_bytes, maximum)
                })?
        }
    };
    (bytes <= maximum).then_some(bytes).ok_or_else(refused)
}

fn check_container(depth: usize, length: usize, array: bool) -> Result<(), ProviderError> {
    if depth >= MAXIMUM_DEPTH || (array && length > crucible_node_format::MAX_ARRAY_ELEMENTS) {
        return Err(refused());
    }
    Ok(())
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, ProviderError> {
    left.checked_add(right)
        .filter(|&bytes| bytes <= maximum)
        .ok_or_else(refused)
}

fn encode(value: &Value, out: &mut Vec<u8>) -> Result<(), ProviderError> {
    match value {
        Value::Null => out.push(NULL),
        Value::Bool(false) => out.push(FALSE),
        Value::Bool(true) => out.push(TRUE),
        Value::Number(number) => {
            // Test the floating variant first: canonical JSON would turn -0.0
            // into 0 and can change integer spellings outside exact f64 range.
            let (tag, bits) = if number.is_f64() {
                (FLOAT, number.as_f64().ok_or_else(invalid)?.to_bits())
            } else if let Some(value) = number.as_u64() {
                (UNSIGNED, value)
            } else {
                (
                    SIGNED,
                    u64::from_le_bytes(number.as_i64().ok_or_else(invalid)?.to_le_bytes()),
                )
            };
            out.push(tag);
            out.extend_from_slice(&bits.to_le_bytes());
        }
        Value::String(text) => encode_string(text, out)?,
        Value::Array(values) => encode_container(ARRAY, values.len(), out, |out| {
            for value in values {
                encode(value, out)?;
            }
            Ok(())
        })?,
        Value::Object(values) => encode_container(OBJECT, values.len(), out, |out| {
            for (key, value) in values {
                encode_string(key, out)?;
                encode(value, out)?;
            }
            Ok(())
        })?,
    }
    Ok(())
}

fn encode_string(text: &str, out: &mut Vec<u8>) -> Result<(), ProviderError> {
    out.push(STRING);
    out.extend_from_slice(
        &u64::try_from(text.len())
            .map_err(|_| refused())?
            .to_le_bytes(),
    );
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn encode_container(
    tag: u8,
    count: usize,
    out: &mut Vec<u8>,
    write_children: impl FnOnce(&mut Vec<u8>) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    out.push(tag);
    out.extend_from_slice(&u64::try_from(count).map_err(|_| refused())?.to_le_bytes());
    let extent_offset = out.len();
    out.extend_from_slice(&[0; 8]);
    let payload_offset = out.len();

    write_children(out)?;
    let extent = u64::try_from(out.len() - payload_offset).map_err(|_| refused())?;
    out[extent_offset..payload_offset].copy_from_slice(&extent.to_le_bytes());
    Ok(())
}

#[derive(Clone, Copy)]
struct BorrowedValue<'a>(&'a [u8]);

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProviderError> {
        let (value, rest) = self.rest.split_at_checked(length).ok_or_else(invalid)?;
        self.rest = rest;
        Ok(value)
    }

    fn word(&mut self) -> Result<u64, ProviderError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
    }

    fn extent(&mut self) -> Result<usize, ProviderError> {
        usize::try_from(self.word()?).map_err(|_| invalid())
    }

    fn string(&mut self) -> Result<&'a str, ProviderError> {
        if self.take(1)? != [STRING] {
            return Err(invalid());
        }
        let length = self.extent()?;
        std::str::from_utf8(self.take(length)?).map_err(|_| invalid())
    }

    fn value(&mut self) -> Result<BorrowedValue<'a>, ProviderError> {
        let original = self.rest;
        let tag = self.take(1)?[0];
        match tag {
            NULL | FALSE | TRUE => {}
            UNSIGNED | SIGNED | FLOAT => {
                self.take(8)?;
            }
            STRING => {
                let extent = self.extent()?;
                self.take(extent)?;
            }
            ARRAY | OBJECT => {
                self.extent()?;
                let extent = self.extent()?;
                self.take(extent)?;
            }
            _ => return Err(invalid()),
        }
        Ok(BorrowedValue(&original[..original.len() - self.rest.len()]))
    }
}

impl Serialize for BorrowedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        let mut cursor = Cursor { rest: self.0 };
        let tag = cursor.take(1).map_err(S::Error::custom)?[0];
        match tag {
            NULL => serializer.serialize_unit(),
            FALSE | TRUE => serializer.serialize_bool(tag == TRUE),
            UNSIGNED => serializer.serialize_u64(cursor.word().map_err(S::Error::custom)?),
            SIGNED => serializer.serialize_i64(i64::from_le_bytes(
                cursor.word().map_err(S::Error::custom)?.to_le_bytes(),
            )),
            FLOAT => {
                serializer.serialize_f64(f64::from_bits(cursor.word().map_err(S::Error::custom)?))
            }
            STRING => {
                let mut cursor = Cursor { rest: self.0 };
                serializer.serialize_str(cursor.string().map_err(S::Error::custom)?)
            }
            ARRAY | OBJECT => serialize_container(tag, &mut cursor, serializer),
            _ => Err(S::Error::custom("invalid compact JSON DATA")),
        }
    }
}

fn serialize_container<S: Serializer>(
    tag: u8,
    cursor: &mut Cursor<'_>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;

    let count = cursor.extent().map_err(S::Error::custom)?;
    let extent = cursor.extent().map_err(S::Error::custom)?;
    let mut children = Cursor {
        rest: cursor.take(extent).map_err(S::Error::custom)?,
    };
    if tag == ARRAY {
        let mut sequence = serializer.serialize_seq(Some(count))?;
        for _ in 0..count {
            sequence.serialize_element(&children.value().map_err(S::Error::custom)?)?;
        }
        if !children.rest.is_empty() {
            return Err(S::Error::custom("invalid compact JSON DATA"));
        }
        sequence.end()
    } else {
        let mut map = serializer.serialize_map(Some(count))?;
        for _ in 0..count {
            let key = children.string().map_err(S::Error::custom)?;
            let value = children.value().map_err(S::Error::custom)?;
            map.serialize_entry(key, &value)?;
        }
        if !children.rest.is_empty() {
            return Err(S::Error::custom("invalid compact JSON DATA"));
        }
        map.end()
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact JSON DATA storage")
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("invalid compact JSON DATA")
}

#[cfg(test)]
mod tests;
