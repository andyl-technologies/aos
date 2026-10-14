//! Preflights the pinned serde Value construction without allocating a Value.
//!
//! This private visitor is used only with the actual core-derived snapshot and
//! journal types. It counts requested allocations cumulatively, which also
//! bounds their simultaneous peak: string/key copies, canonical string buffers and UTF-16 sort keys, every sequence bank
//! including growth, and one maximum-size BTree node per map entry. Layouts are
//! qualified for the source-built compiler and serde_json default/std features.

use super::{RuntimeError, value_layout};
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

    fn container(&mut self, capacity: usize, map: bool) -> Result<Container<'_>, Excess> {
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
                                crate::node_contract::NodeRuntime::capture_closed_inline_storage()
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
        self.string(key)?;
        if self.future_decode {
            // The parser visits key tokens as well as their values. Key-token
            // Value/typed slots, decoded map nodes and UTF-16 ordering nodes
            // coexist with the independently counted serialization map.
            self.add(
                4 * (crate::node_contract::NodeRuntime::capture_closed_inline_storage()
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
        self.add(value_layout::map_node_bytes())?;
        self.add(value_layout::map_node_bytes_for::<
            Vec<u16>,
            (&str, &serde_json::Value),
        >())?;
        self.key(variant)
    }
}

/// Returns a cumulative requested-allocation ceiling before Value construction.
pub(super) fn value_allocations(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: false,
    };
    value
        .serialize(&mut credit)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(credit.used)
}

/// Bounds closed projected decoder trees before future bytes exist.
/// This observes source-owned structural events, never parsed providers or a
/// custom serializer. Unsupported custom map/string/byte codecs refuse.
pub(super) fn future_decode_allocations(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut credit = Credit {
        used: 0,
        maximum,
        depth: 0,
        map_key: false,
        future_decode: true,
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
                4 * (crate::node_contract::NodeRuntime::capture_closed_inline_storage()
                    + value_layout::value_slot_bytes()),
            )?;
            if self.map {
                self.credit.add(value_layout::map_node_bytes())?;
            }
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
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_i8(self, _: i8) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_i16(self, _: i16) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_i32(self, _: i32) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_i64(self, _: i64) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_i128(self, _: i128) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_u8(self, _: u8) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_u16(self, _: u16) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_u32(self, _: u32) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_u64(self, _: u64) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_u128(self, _: u128) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_f32(self, _: f32) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
    }
    fn serialize_f64(self, _: f64) -> Result<(), Excess> {
        if self.map_key { Err(Excess) } else { Ok(()) }
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
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Excess> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Excess> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Excess> {
        Ok(())
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
        if self.map_key || self.future_decode {
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

#[cfg(test)]
mod tests {
    use super::*;
    // Failed checked serialization is the assertion signal in these controls.
    #[allow(clippy::unwrap_used)]
    #[test]
    fn huge_sequence_hint_refuses_without_value_allocation() {
        struct HugeHint;
        impl Serialize for HugeHint {
            fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_seq(Some(usize::MAX))?.end()
            }
        }
        assert_eq!(
            value_allocations(&HugeHint, 4096),
            Err(RuntimeError::ResourceLimit)
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn core_container_credit_covers_actual_retained_value_storage() {
        use super::super::owned::OwnedStorage;
        let input = vec![vec!["alpha", "beta"], vec!["gamma"]];
        let admitted = value_allocations(&input, 65536).unwrap();
        let value = serde_json::to_value(&input).unwrap();
        assert!(admitted >= value.owned_storage().unwrap());
        assert_eq!(
            value_allocations(&input, admitted - 1),
            Err(RuntimeError::ResourceLimit)
        );
    }
}
