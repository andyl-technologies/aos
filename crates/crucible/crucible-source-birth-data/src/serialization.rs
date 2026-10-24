//! Preflights the pinned serde Value construction without allocating a Value.
//!
//! The visitor counts requested allocations cumulatively for typed Serialize
//! views: string/key copies, canonical string buffers and UTF-16 sort keys,
//! sequence banks including growth, and one maximum-size BTree node per map
//! entry. Future-decode modes also require the caller's actual closed-record
//! inline layout. Layouts are qualified for the source-built compiler and
//! serde_json default/std features. These reports convey no allocation authority.

use crate::errors::RuntimeError;

/// Shares the pinned immutable layout mirrors used by serializer geometry.
pub mod value_layout;
use serde::Serialize;
use serde::ser::{
    self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use std::fmt;

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
    future_decode: bool,
    selected_constructor: bool,
    encoded_upper: usize,
    maximum_decode_slot: usize,
    closed_inline_storage: usize,
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

    fn encoded(&mut self, bytes: usize) -> Result<(), Excess> {
        if self.selected_constructor {
            self.encoded_upper = self.encoded_upper.checked_add(bytes).ok_or(Excess)?;
        }
        Ok(())
    }

    fn numeric(&mut self) -> Result<(), Excess> {
        self.encoded(128)?;
        if self.selected_constructor {
            self.add(132)?;
        }
        Ok(())
    }

    fn container(&mut self, capacity: usize, map: bool) -> Result<Container<'_>, Excess> {
        self.encoded(2)?;
        if self.depth >= 128 {
            return Err(Excess);
        }
        self.depth += 1;
        let slots = if map {
            0
        } else {
            capacity
                .checked_mul(value_layout::value_slot_bytes())
                .ok_or(Excess)?
        };
        self.add(slots)?;
        if map && self.maximum_decode_slot != 0 {
            // Selected future DTOs retain their own typed object/map root
            // alongside the independently decoded DOM root, including `{}`.
            // Existing ordinary/constructor modes keep a zero extra slot.
            self.add(std::mem::size_of::<
                serde_json::Map<String, serde_json::Value>,
            >())?;
            self.add(value_layout::value_slot_bytes())?;
            self.add(self.maximum_decode_slot)?;
            // Retained Value accounting names an independent root even for
            // an empty object. Construction DOM, future decoded DOM and the
            // future typed object/map each keep their own conservative root;
            // a map header or per-entry node cannot stand in for these banks.
            self.add(value_layout::map_node_bytes())?;
            self.add(value_layout::map_node_bytes())?;
            self.add(value_layout::map_node_bytes())?;
        }
        if self.future_decode {
            // Closed future core records use typed vectors/maps; parsing also
            // retains a Value tree. Four requested slots per declared element
            // covers the pinned parser/Vec growth without a byte multiplier.
            if map {
                self.add(
                    capacity
                        .checked_mul(value_layout::map_node_bytes())
                        .ok_or(Excess)?,
                )?;
            } else {
                self.add(
                    capacity
                        .checked_mul(4)
                        .and_then(|count| {
                            count.checked_mul(
                                self.closed_inline_storage.max(self.maximum_decode_slot)
                                    + value_layout::value_slot_bytes(),
                            )
                        })
                        .ok_or(Excess)?,
                )?;
            }
        }
        Ok(Container {
            credit: self,
            capacity,
            length: 0,
            map,
        })
    }

    fn string(&mut self, value: &str) -> Result<(), Excess> {
        self.encoded(
            value
                .len()
                .checked_mul(6)
                .and_then(|n| n.checked_add(2))
                .ok_or(Excess)?,
        )?;
        self.add(value.len())?;
        if self.future_decode {
            let encoded = value.len().checked_mul(6).ok_or(Excess)?;
            // Parser escaped-token scratch, DOM String and typed String remain
            // distinct. Each is charged from this actual string event.
            self.add(
                encoded
                    .checked_mul(6)
                    .and_then(|bytes| bytes.checked_add(8))
                    .ok_or(Excess)?,
            )?;
        }
        // CNP decimal_integer serializes a temporary native to_string before
        // entering serialize_str. The pinned u64/i64 formatter requests at
        // most twenty bytes. Charge that possible bank for every string;
        // selected core types contain no Bytes/base64 or custom string codec.
        self.add(20)?;
        // JSON escaping emits at most six bytes per UTF-8 source byte plus
        // quotes. serde_json::to_string starts with 128 bytes; geometric
        // Vec growth has cumulative requests <=4*written+256 bytes.
        let escaped = value
            .len()
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(Excess)?;
        self.add(
            escaped
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or(Excess)?,
        )
    }

    fn key(&mut self, key: &str) -> Result<(), Excess> {
        self.encoded(1)?;
        self.string(key)?;
        if self.future_decode {
            // The parser visits key tokens as well as their values. Key-token
            // Value/typed slots, decoded map nodes and UTF-16 ordering nodes
            // coexist with the independently counted serialization map.
            self.add(
                4 * (self.closed_inline_storage.max(self.maximum_decode_slot)
                    + value_layout::value_slot_bytes()),
            )?;
            self.add(value_layout::map_node_bytes())?;
            self.add(value_layout::map_node_bytes_for::<
                Vec<u16>,
                (&str, &serde_json::Value),
            >())?;
        }
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
        self.encoded(4)?;
        self.add(value_layout::map_node_bytes())?;
        self.add(value_layout::map_node_bytes_for::<
            Vec<u16>,
            (&str, &serde_json::Value),
        >())?;
        self.key(variant)
    }
}

/// Returns a cumulative requested-allocation ceiling before Value construction.
///
/// # Errors
/// Refuses arithmetic overflow, unsupported serializer events or exhausted allocation credit.
pub fn value_allocations(value: &impl Serialize, maximum: usize) -> Result<usize, RuntimeError> {
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: false,
        selected_constructor: false,
        encoded_upper: 0,
        maximum_decode_slot: 0,
        closed_inline_storage: 0,
    };
    value
        .serialize(&mut credit)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(credit.used)
}

/// Bounds closed projected decoder trees before future bytes exist.
/// This observes source-owned structural events, never parsed providers or a
/// custom serializer. Unsupported custom map/string/byte codecs refuse.
///
/// # Errors
/// Refuses arithmetic overflow, unsupported serializer events or exhausted allocation credit.
pub fn future_decode_allocations(
    value: &impl Serialize,
    maximum: usize,
    closed_inline_storage: usize,
) -> Result<usize, RuntimeError> {
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: true,
        selected_constructor: false,
        encoded_upper: 0,
        maximum_decode_slot: 0,
        closed_inline_storage,
    };
    value
        .serialize(&mut credit)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(credit.used)
}

struct Container<'a> {
    credit: &'a mut Credit,
    capacity: usize,
    length: usize,
    map: bool,
}

impl Container<'_> {
    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.credit.encoded(1)?;
        self.length = self.length.checked_add(1).ok_or(Excess)?;
        if self.map {
            // A BTree cannot have more allocated nodes than inserted entries.
            // Internal layout covers both leaf and internal requested sizes.
            self.credit.add(value_layout::map_node_bytes())?;
            self.credit.add(value_layout::map_node_bytes_for::<
                Vec<u16>,
                (&str, &serde_json::Value),
            >())?;
        } else if self.length > self.capacity {
            self.capacity = self
                .capacity
                .checked_mul(2)
                .ok_or(Excess)?
                .max(self.length)
                .max(4);
            self.credit.add(
                self.capacity
                    .checked_mul(value_layout::value_slot_bytes())
                    .ok_or(Excess)?,
            )?;
        }
        if self.credit.future_decode {
            self.credit.add(
                4 * (self
                    .credit
                    .closed_inline_storage
                    .max(self.credit.maximum_decode_slot)
                    + value_layout::value_slot_bytes()),
            )?;
            if self.map {
                self.credit.add(value_layout::map_node_bytes())?;
            }
        }
        value.serialize(&mut *self.credit)
    }

    fn finish(self) -> Result<(), Excess> {
        if self.map && self.credit.selected_constructor {
            self.credit
                .add(original_constructor_ordered_collect_storage(self.length)?)?;
        }
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
            self.numeric()
        }
    }

    fn serialize_i16(self, _: i16) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_i32(self, _: i32) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_i64(self, _: i64) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_i128(self, _: i128) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_u8(self, _: u8) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_u16(self, _: u16) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_u32(self, _: u32) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_u64(self, _: u64) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_u128(self, _: u128) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_f32(self, _: f32) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
        }
    }

    fn serialize_f64(self, _: f64) -> Result<(), Excess> {
        if self.map_key {
            Err(Excess)
        } else {
            self.numeric()
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

    fn serialize_bytes(self, value: &[u8]) -> Result<(), Excess> {
        if self.future_decode {
            return Err(Excess);
        }
        self.add(
            value
                .len()
                .checked_mul(value_layout::value_slot_bytes())
                .ok_or(Excess)?,
        )
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

    fn collect_str<T: ?Sized + fmt::Display>(self, value: &T) -> Result<(), Excess> {
        // Selected core map keys are String or transparent Id and enter
        // serialize_str. A formatted custom key has no enrolled key codec.
        if self.map_key || self.future_decode || self.selected_constructor {
            return Err(Excess);
        }

        struct Length(usize);
        impl fmt::Write for Length {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                self.0 = self.0.checked_add(text.len()).ok_or(fmt::Error)?;
                Ok(())
            }
        }
        let mut length = Length(0);
        fmt::write(&mut length, format_args!("{value}")).map_err(|_| Excess)?;
        // Default collect_str formats into a growing String, then clones it
        // into Value. Cumulative geometric growth plus that clone is <=5n+8.
        self.add(
            length
                .0
                .checked_mul(5)
                .and_then(|bytes| bytes.checked_add(8))
                .ok_or(Excess)?,
        )?;
        let escaped = length
            .0
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(Excess)?;
        self.add(
            escaped
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or(Excess)?,
        )
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
        // Selected core map keys use the string serializer. The key mode
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

/// Sizes the actual shared visitor and result headers before the walk.
pub fn counter_scratch_data() -> usize {
    std::mem::size_of::<(usize, usize)>()
        + std::mem::size_of::<Result<(usize, usize), RuntimeError>>()
        + std::mem::size_of::<Credit>()
        + std::mem::size_of::<Container<'_>>()
}

/// Quotes actual selected DOM/canonical output and BTree FromIterator phases.
///
/// Ordinary counter rows retain their old arithmetic. Fixed formatter/sort
/// workspace and custom Bytes/U64 temporary banks are separate caller terms.
///
/// # Errors
/// Refuses arithmetic overflow, unsupported serializer events or exhausted allocation credit.
pub fn original_constructor_value_allocations(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: false,
        selected_constructor: true,
        encoded_upper: 0,
        maximum_decode_slot: 0,
        closed_inline_storage: 0,
    };
    value
        .serialize(&mut credit)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let output = credit
        .encoded_upper
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or(RuntimeError::ResourceLimit)?;
    credit
        .add(output)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(credit.used)
}

// canonical_json collects actual (UTF16 key, borrowed entry) tuples before
// moving them into the BTree. The collect Vec and stable-sort heap coexist
// with the DOM and growing tree already named by the ordinary key visitor.
fn original_constructor_ordered_collect_storage(entries: usize) -> Result<usize, Excess> {
    type Entry<'a> = (Vec<u16>, (&'a str, &'a serde_json::Value));
    let width = std::mem::size_of::<Entry<'_>>();
    let slots = if entries == 0 { 0 } else { entries.max(4) };
    let drift = if entries <= 20 {
        0
    } else {
        (entries - entries / 2)
            .max(entries.min(8_000_000 / width))
            .max(48)
    };
    let sort_slots = drift.max(entries / 2);
    let sort = if sort_slots <= 4096 / width {
        0
    } else {
        sort_slots.checked_mul(width).ok_or(Excess)?
    };
    slots
        .checked_mul(width)
        .and_then(|n| n.checked_add(sort))
        .ok_or(Excess)
}

/// Quotes selected construction and independent future typed decode geometry.
///
/// The defining closed caller supplies its actual largest DTO slot. Existing
/// ordinary and constructor modes keep a zero extra slot and their old rows.
/// Encoded extent is reported directly from the same serializer events; it is
/// never derived by treating requested heap as a wire-byte allowance.
///
/// # Errors
/// Refuses arithmetic overflow, unsupported serializer events or exhausted allocation credit.
pub fn original_constructor_and_decode_geometry(
    value: &impl Serialize,
    maximum_decode_slot: usize,
    maximum: usize,
    closed_inline_storage: usize,
) -> Result<(usize, usize), RuntimeError> {
    if maximum_decode_slot == 0 {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: true,
        selected_constructor: true,
        encoded_upper: 0,
        maximum_decode_slot,
        closed_inline_storage,
    };
    value
        .serialize(&mut credit)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let output = credit
        .encoded_upper
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or(RuntimeError::ResourceLimit)?;
    credit
        .add(output)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok((credit.used, credit.encoded_upper))
}

/// Returns both axes of the same defining selected-constructor Credit walk.
///
/// The caller independently funds the real serializer's typed formatter work
/// before entry. This constructs no DOM or canonical bank and uses no future
/// typed-decoder slot. Its output is allocation DATA only, not admission.
///
/// # Errors
/// Refuses arithmetic overflow, unsupported serializer events or exhausted allocation credit.
pub fn borrowed_constructor_geometry(
    value: &impl Serialize,
    maximum: usize,
) -> Result<(usize, usize), RuntimeError> {
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: false,
        selected_constructor: true,
        encoded_upper: 0,
        maximum_decode_slot: 0,
        closed_inline_storage: 0,
    };
    value
        .serialize(&mut credit)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let output = credit
        .encoded_upper
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .ok_or(RuntimeError::ResourceLimit)?;
    credit
        .add(output)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok((credit.used, credit.encoded_upper))
}
