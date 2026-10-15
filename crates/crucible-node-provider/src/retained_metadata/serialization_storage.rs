//! Quotes actual closed Serialize, DOM and canonical requested storage.
//!
//! This visitor is data accounting, not Source allocation authority. Actual
//! retained fields supply custom Bytes temporary credit before Serialize runs.
//! No DOM/output bank is allocated here. Compiler frames and allocator physical
//! residency are not inferred from these requested-layout components.

use crate::{ProviderError, retained_metadata::RetainedProtocolMetadataFacts};
use serde::Serialize;
use serde::ser::{
    self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use std::fmt;
use std::mem::{align_of, size_of};

#[derive(Debug)]
struct Excess;

impl fmt::Display for Excess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("capture serialization allocation credit exhausted")
    }
}

impl std::error::Error for Excess {}

impl ser::Error for Excess {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

struct Credit {
    used: usize,
    maximum: usize,
    depth: usize,
    map_key: bool,
    encoded_upper: usize,
    parser_requested: usize,
    sequence_elements: usize,
    sequence_containers: usize,
}

impl Credit {
    fn add(&mut self, bytes: usize) -> Result<(), Excess> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(Excess)?;
        Ok(())
    }

    fn parser(&mut self, bytes: usize) -> Result<(), Excess> {
        self.parser_requested = self
            .parser_requested
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(Excess)?;
        Ok(())
    }

    fn encoded(&mut self, bytes: usize) -> Result<(), Excess> {
        self.encoded_upper = self
            .encoded_upper
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(Excess)?;
        Ok(())
    }

    fn container(&mut self, capacity: usize, map: bool) -> Result<Container<'_>, Excess> {
        if self.depth >= 64 {
            return Err(Excess);
        }
        self.depth += 1;
        self.encoded(2)?;
        let slots = if map {
            0
        } else {
            capacity.checked_mul(value_slot_bytes()).ok_or(Excess)?
        };
        self.add(slots)?;
        if !map {
            self.sequence_containers = self.sequence_containers.checked_add(1).ok_or(Excess)?;
            self.parser(
                capacity
                    .checked_mul(4)
                    .and_then(|slots| slots.checked_add(4))
                    .and_then(|slots| slots.checked_mul(value_slot_bytes()))
                    .ok_or(Excess)?,
            )?;
        }

        Ok(Container {
            credit: self,
            capacity,
            length: 0,
            map,
        })
    }

    fn string(&mut self, value: &str) -> Result<(), Excess> {
        let escaped = value.bytes().try_fold(2usize, |sum, byte| {
            let width = match byte {
                b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
                0..=31 => 6,
                _ => 1,
            };
            sum.checked_add(width).ok_or(Excess)
        })?;
        self.string_storage(value.len(), escaped)
    }

    fn string_extent(&mut self, bytes: usize) -> Result<(), Excess> {
        let escaped = bytes
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(Excess)?;
        self.string_storage(bytes, escaped)
    }

    fn string_storage(&mut self, bytes: usize, escaped: usize) -> Result<(), Excess> {
        self.add(bytes)?;
        // The actual canonical Parser owns a growable decoded UTF-8 bank.
        // Its min-capacity16 and doubling requests are bounded per string.
        self.parser(
            bytes
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(32))
                .ok_or(Excess)?,
        )?;

        // CNP decimal_integer serializes a temporary native to_string before
        // entering serialize_str. The pinned u64/i64 formatter requests at
        // most twenty bytes. Charge that possible bank for every string;
        // Bytes/base64 scratch was independently admitted before this walk.
        self.add(20)?;
        // JSON escaping emits at most six bytes per UTF-8 source byte plus
        // quotes. serde_json::to_string starts with 128 bytes; geometric
        // Vec growth has cumulative requests <=4*written+256 bytes.
        self.encoded(escaped)?;
        self.add(
            escaped
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or(Excess)?,
        )
    }

    fn key(&mut self, key: &str) -> Result<(), Excess> {
        self.string(key)?;
        self.encoded(1)?;

        // canonical_json's ordered map owns one UTF-16 vector per key.
        // UTF-16 units cannot exceed UTF-8 bytes; cumulative requested
        // geometric vector storage is <=4*n+8 u16 slots.
        self.add(
            key.len()
                .checked_mul(8)
                .and_then(|bytes| bytes.checked_add(16))
                .ok_or(Excess)?,
        )
    }

    fn variant(&mut self, variant: &str) -> Result<(), Excess> {
        self.encoded(2)?;
        self.add(map_node_bytes()?)?;
        self.parser(map_node_bytes()?)?;
        self.add(map_node_bytes_for::<Vec<u16>, (&str, &serde_json::Value)>()?)?;
        self.key(variant)
    }
}

/// Reports independently named storage for an actual closed Serialize view.
///
/// The visitor creates no DOM. Actual Bytes serialization itself creates a
/// base64 String before visiting it, so all such temporary banks are admitted
/// from the same actual typed metadata walk BEFORE invoking Serialize.
pub(crate) struct OriginalSerializationStorageData {
    pub(crate) dom_and_canonical_scratch_bytes: usize,
    pub(crate) projected_parser_requested_bytes: usize,
    pub(crate) canonical_output_requested_bytes: usize,
    pub(crate) serializer_temporary_requested_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
    pub(crate) maximum_encoded_bytes: usize,
    pub(crate) sequence_elements: usize,
    pub(crate) sequence_containers: usize,
}

impl OriginalSerializationStorageData {
    pub(crate) fn requested_total(&self) -> Result<usize, ProviderError> {
        [
            self.dom_and_canonical_scratch_bytes,
            self.projected_parser_requested_bytes,
            self.canonical_output_requested_bytes,
            self.serializer_temporary_requested_bytes,
            self.declared_counter_scratch_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, next| {
            sum.checked_add(next)
                .ok_or(ProviderError::ResourceExhausted(
                    "serialization requested storage",
                ))
        })
    }
}

pub(crate) fn actual_serialization_storage_data(
    value: &impl Serialize,
    actual_fields: RetainedProtocolMetadataFacts,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let refused = || ProviderError::ResourceExhausted("closed serialization storage");
    // Bytes uses URL_SAFE_NO_PAD.encode on its own Vec. Every such field is
    // among the actual typed vector banks. Summing ceil(length/3)*4 by an
    // upper bound over ALL actual vector capacities is conservative; it is not
    // a multiplier inferred from input/output JSON length. Other closed custom
    // string serialization is the closed decimal_integer formatter (20 bytes).
    let temporary = actual_fields
        .vector_banks
        .checked_mul(2)
        .and_then(|padding| actual_fields.vector_capacity_bytes.checked_add(padding))
        .and_then(|bytes| bytes.checked_div(3))
        .and_then(|groups| groups.checked_mul(4))
        .and_then(|bytes| bytes.checked_add(20))
        .ok_or_else(refused)?;
    let scratch = size_of::<Credit>()
        .checked_add(size_of::<OriginalSerializationStorageData>())
        .ok_or_else(refused)?;
    let available = maximum
        .checked_sub(temporary)
        .and_then(|bytes| bytes.checked_sub(scratch))
        .ok_or_else(refused)?;
    let mut credit = Credit {
        used: 0,
        maximum: available,
        depth: 0,
        map_key: false,
        encoded_upper: 0,
        parser_requested: 0,
        sequence_elements: 0,
        sequence_containers: 0,
    };
    value.serialize(&mut credit).map_err(|_| refused())?;
    let output = credit
        .encoded_upper
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or_else(refused)?;
    let result = OriginalSerializationStorageData {
        dom_and_canonical_scratch_bytes: credit.used,
        projected_parser_requested_bytes: credit.parser_requested,
        canonical_output_requested_bytes: output,
        serializer_temporary_requested_bytes: temporary,
        declared_counter_scratch_bytes: scratch,
        maximum_encoded_bytes: credit.encoded_upper,
        sequence_elements: credit.sequence_elements,
        sequence_containers: credit.sequence_containers,
    };
    if result.requested_total()? > maximum {
        return Err(refused());
    }
    Ok(result)
}

fn value_slot_bytes() -> usize {
    size_of::<serde_json::Value>()
}

fn map_node_bytes() -> Result<usize, Excess> {
    map_node_bytes_for::<String, serde_json::Value>()
}

fn map_node_bytes_for<K, V>() -> Result<usize, Excess> {
    // Pinned alloc BTree B=6: eleven K/V slots, twelve child edges and
    // parent/index/length header; extra alignment padding covers both nodes.
    let alignment = align_of::<K>()
        .max(align_of::<V>())
        .max(align_of::<usize>());
    size_of::<K>()
        .checked_add(size_of::<V>())
        .and_then(|entry| entry.checked_mul(11))
        .and_then(|bytes| bytes.checked_add(13 * size_of::<usize>() + 2 * size_of::<u16>()))
        .and_then(|bytes| bytes.checked_add(8 * (alignment - 1)))
        .ok_or(Excess)
}

struct Container<'a> {
    credit: &'a mut Credit,
    capacity: usize,
    length: usize,
    map: bool,
}

impl Container<'_> {
    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.length = self.length.checked_add(1).ok_or(Excess)?;
        if !self.map {
            self.credit.sequence_elements =
                self.credit.sequence_elements.checked_add(1).ok_or(Excess)?;
        }
        self.credit.encoded(1)?;
        if self.map {
            // A BTree cannot have more allocated nodes than inserted entries.
            // Internal layout covers both leaf and internal requested sizes.
            self.credit.add(map_node_bytes()?)?;
            self.credit.parser(map_node_bytes()?)?;
            self.credit
                .add(map_node_bytes_for::<Vec<u16>, (&str, &serde_json::Value)>()?)?;
        } else if self.length > self.capacity {
            self.capacity = self
                .capacity
                .checked_mul(2)
                .ok_or(Excess)?
                .max(self.length)
                .max(4);
            self.credit.add(
                self.capacity
                    .checked_mul(value_slot_bytes())
                    .ok_or(Excess)?,
            )?;
            // Unknown/short sequence hints must grow the projected parser's
            // independent array bank as well as serde_json's owned DOM bank.
            self.credit.parser(
                self.capacity
                    .checked_mul(4)
                    .and_then(|slots| slots.checked_mul(value_slot_bytes()))
                    .ok_or(Excess)?,
            )?;
        }

        value.serialize(&mut *self.credit)
    }

    fn finish(self) -> Result<(), Excess> {
        self.credit.depth -= 1;
        Ok(())
    }
}

impl<'a> ser::Serializer for &'a mut Credit {
    type Ok = ();
    type Error = Excess;
    type SerializeSeq = Container<'a>;
    type SerializeTuple = Container<'a>;
    type SerializeTupleStruct = Container<'a>;
    type SerializeTupleVariant = Container<'a>;
    type SerializeMap = Container<'a>;
    type SerializeStruct = Container<'a>;
    type SerializeStructVariant = Container<'a>;
    fn serialize_bool(self, _: bool) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(5)
        }
    }
    fn serialize_i8(self, _: i8) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(4)
        }
    }
    fn serialize_i16(self, _: i16) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(6)
        }
    }
    fn serialize_i32(self, _: i32) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(11)
        }
    }
    fn serialize_i64(self, _: i64) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(21)
        }
    }
    fn serialize_i128(self, _: i128) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(40)
        }
    }
    fn serialize_u8(self, _: u8) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(3)
        }
    }
    fn serialize_u16(self, _: u16) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(5)
        }
    }
    fn serialize_u32(self, _: u32) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(10)
        }
    }
    fn serialize_u64(self, _: u64) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(20)
        }
    }
    fn serialize_u128(self, _: u128) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(39)
        }
    }
    fn serialize_f32(self, _: f32) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(132)
        }
    }
    fn serialize_f64(self, _: f64) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.encoded(132)
        }
    }
    fn serialize_char(self, value: char) -> Result<(), Excess> {
        if self.map_key {
            return Err(Excess);
        }
        self.string(value.encode_utf8(&mut [0; 4]))
    }
    fn serialize_str(self, value: &str) -> Result<(), Excess> {
        if self.map_key {
            self.key(value)
        } else {
            self.string(value)
        }
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<(), Excess> {
        // The enrolled native Bytes emits a string. A different custom byte
        // serializer needs its own explicit layout path before it is accepted.
        Err(Excess)
    }
    fn serialize_none(self) -> Result<(), Excess> {
        self.encoded(4)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Excess> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Excess> {
        self.encoded(4)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Excess> {
        self.encoded(4)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), Excess> {
        self.string(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Excess> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Excess> {
        self.variant(variant)?;
        value.serialize(self)
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Container<'a>, Excess> {
        self.container(length.unwrap_or(0), false)
    }
    fn serialize_tuple(self, length: usize) -> Result<Container<'a>, Excess> {
        self.container(length, false)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        length: usize,
    ) -> Result<Container<'a>, Excess> {
        self.container(length, false)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        length: usize,
    ) -> Result<Container<'a>, Excess> {
        self.variant(variant)?;
        self.container(length, false)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Container<'a>, Excess> {
        self.container(0, true)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Container<'a>, Excess> {
        self.container(0, true)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Container<'a>, Excess> {
        self.variant(variant)?;
        self.container(0, true)
    }
    fn collect_str<T: ?Sized + fmt::Display>(self, _: &T) -> Result<(), Excess> {
        // The selected closed types use serialize_str. Unknown custom
        // formatted values cannot enroll allocation behavior through Display.
        Err(Excess)
    }
}

impl SerializeSeq for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeTuple for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeTupleStruct for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeTupleVariant for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeMap for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Excess> {
        // Selected native map keys use the string serializer. The key mode
        // additionally charges canonical UTF-16 sorting storage.
        self.credit.map_key = true;
        let result = key.serialize(&mut *self.credit);
        self.credit.map_key = false;
        result
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeStruct for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Excess> {
        self.credit.key(key)?;
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeStructVariant for Container<'_> {
    type Ok = ();
    type Error = Excess;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Excess> {
        self.credit.key(key)?;
        self.element(value)
    }
    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

/// Counts a source-private fixed field grammar before its owning DOM exists.
///
/// Only closed in-crate producers use this counter. It has no output bank,
/// callback, allocation right or live actor association. String extents are
/// prospective UTF-8 bounds; they are never reported as observed capacities.
/// Custom byte/string formatters must be represented by their explicit string
/// extent rather than invoked through `add_value`.
pub(crate) struct OriginalSerializationStorageProjection {
    credit: Credit,
}

impl OriginalSerializationStorageProjection {
    pub(crate) fn new(maximum: usize) -> Result<Self, ProviderError> {
        let minimum = size_of::<Self>()
            .checked_add(size_of::<OriginalSerializationStorageData>())
            .and_then(|bytes| bytes.checked_add(20))
            .ok_or_else(projection_excess)?;
        let available = maximum.checked_sub(minimum).ok_or_else(projection_excess)?;
        Ok(Self {
            credit: Credit {
                used: 0,
                maximum: available,
                depth: 0,
                map_key: false,
                encoded_upper: 0,
                parser_requested: 0,
                sequence_elements: 0,
                sequence_containers: 0,
            },
        })
    }

    /// Adds a closed future array's inline slots and parser/canonical geometry.
    ///
    /// Its elements are counted separately in traversal order by the same
    /// closed producer. This reserves no array and grants no decode credit.
    pub(crate) fn add_array_extent(&mut self, elements: usize) -> Result<(), ProviderError> {
        let refused = projection_excess;
        self.credit.sequence_containers = self
            .credit
            .sequence_containers
            .checked_add(1)
            .ok_or_else(refused)?;
        self.credit.sequence_elements = self
            .credit
            .sequence_elements
            .checked_add(elements)
            .ok_or_else(refused)?;
        let encoded = elements.checked_add(2).ok_or_else(refused)?;
        self.credit.encoded(encoded).map_err(|_| refused())?;
        let slots = elements
            .checked_mul(value_slot_bytes())
            .ok_or_else(refused)?;
        self.credit.add(slots).map_err(|_| refused())?;
        let parser = elements
            .checked_mul(4)
            .and_then(|count| count.checked_add(4))
            .and_then(|count| count.checked_mul(value_slot_bytes()))
            .ok_or_else(refused)?;
        self.credit.parser(parser).map_err(|_| refused())
    }

    /// Adds the braces of one fixed object; its fields are counted separately.
    pub(crate) fn add_object(&mut self) -> Result<(), ProviderError> {
        self.credit.encoded(2).map_err(|_| projection_excess())
    }

    /// Adds one key, separator and actual DOM/parser/canonical map entry layout.
    pub(crate) fn add_field(&mut self, key: &str) -> Result<(), ProviderError> {
        self.credit.key(key).map_err(|_| projection_excess())?;
        self.field_entry_layout()
    }

    /// Bounds a closed producer's future UTF-8 key without constructing it.
    ///
    /// The caller derives the extent from the actual key type's contract, such
    /// as Id's128-byte grammar, and separately authenticates its actual source
    /// plan. Six-byte JSON escaping and UTF-16 sort storage are preserved.
    /// This constructs neither an Id nor a map or live source permission.
    pub(crate) fn add_field_extent(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.credit
            .string_extent(bytes)
            .map_err(|_| projection_excess())?;
        self.credit.encoded(1).map_err(|_| projection_excess())?;
        let sort = bytes
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or_else(projection_excess)?;
        self.credit.add(sort).map_err(|_| projection_excess())?;
        self.field_entry_layout()
    }

    fn field_entry_layout(&mut self) -> Result<(), ProviderError> {
        self.credit.encoded(1).map_err(|_| projection_excess())?;
        self.credit
            .add(map_node_bytes().map_err(|_| projection_excess())?)
            .map_err(|_| projection_excess())?;
        self.credit
            .parser(map_node_bytes().map_err(|_| projection_excess())?)
            .map_err(|_| projection_excess())?;
        self.credit
            .add(
                map_node_bytes_for::<Vec<u16>, (&str, &serde_json::Value)>()
                    .map_err(|_| projection_excess())?,
            )
            .map_err(|_| projection_excess())
    }

    pub(crate) fn add_string(&mut self, value: &str) -> Result<(), ProviderError> {
        self.credit.string(value).map_err(|_| projection_excess())
    }

    pub(crate) fn add_string_extent(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.credit
            .string_extent(bytes)
            .map_err(|_| projection_excess())
    }

    /// Counts a closed producer's known unescaped ASCII string grammar.
    ///
    /// Callers establish the alphabet from their actual formatter: base64url or
    /// the fixed packet identifier prefix followed by decimal digits. Arbitrary
    /// string extents must continue using `add_string_extent`.
    pub(crate) fn add_unescaped_ascii_extent(&mut self, bytes: usize) -> Result<(), ProviderError> {
        let encoded = bytes.checked_add(2).ok_or_else(projection_excess)?;
        self.credit
            .string_storage(bytes, encoded)
            .map_err(|_| projection_excess())
    }

    /// Visits actual closed scalar/container children with only decimal scratch.
    pub(crate) fn add_value(&mut self, value: &impl Serialize) -> Result<(), ProviderError> {
        value
            .serialize(&mut self.credit)
            .map_err(|_| projection_excess())
    }

    pub(crate) fn finish(
        self,
        maximum: usize,
    ) -> Result<OriginalSerializationStorageData, ProviderError> {
        let output = self
            .credit
            .encoded_upper
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(projection_excess)?;
        let scratch = size_of::<Self>()
            .checked_add(size_of::<OriginalSerializationStorageData>())
            .ok_or_else(projection_excess)?;
        let result = OriginalSerializationStorageData {
            dom_and_canonical_scratch_bytes: self.credit.used,
            projected_parser_requested_bytes: self.credit.parser_requested,
            canonical_output_requested_bytes: output,
            serializer_temporary_requested_bytes: 20,
            declared_counter_scratch_bytes: scratch,
            maximum_encoded_bytes: self.credit.encoded_upper,
            sequence_elements: self.credit.sequence_elements,
            sequence_containers: self.credit.sequence_containers,
        };
        if result.requested_total()? > maximum {
            return Err(projection_excess());
        }
        Ok(result)
    }
}

fn projection_excess() -> ProviderError {
    ProviderError::ResourceExhausted("closed serialization projection storage")
}

#[cfg(test)]
#[path = "serialization_storage_tests.rs"]
mod tests;
