//! Bounds owned decoder children of the closed Source transfer projections.
//!
//! The selected DTO graph contains Strings/Ids, fixed Bytes and opaque Value
//! children. Its only typed sequence is Vec<Id>; opaque sequences contain Value.
//! Struct roots are charged separately by their actual DTO layouts. This
//! visitor conservatively treats every projected string as both an owned
//! String and a base64-decoded bank, and every object as a Value map. It never
//! constructs a request, Value, mapping, index or signing owner.

use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_format::Id;
use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};
use std::fmt;
use std::mem::size_of;

#[derive(Debug)]
struct Excess;

impl fmt::Display for Excess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Source transfer decoder backing exceeds its counter ceiling")
    }
}

impl std::error::Error for Excess {}

impl ser::Error for Excess {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

struct Counter {
    used: usize,
    maximum: usize,
    depth: usize,
}

impl Counter {
    fn add(&mut self, bytes: usize) -> Result<(), Excess> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|n| *n <= self.maximum)
            .ok_or(Excess)?;
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), Excess> {
        // Bytes::deserialize owns its encoded String and the base64 engine's
        // untruncated estimated Vec. A 43-byte digest therefore needs 33
        // decoded bytes; the actual 32-byte payload is not its capacity.
        let decoded = value
            .len()
            .checked_add(3)
            .and_then(|n| n.checked_div(4))
            .and_then(|n| n.checked_mul(3))
            .ok_or(Excess)?;
        self.add(value.len())?;
        self.add(decoded)?;
        self.add(size_of::<String>())?;
        self.add(size_of::<Vec<u8>>())
    }

    fn map_node(&self) -> Result<usize, Excess> {
        NodeRuntime::capture_protocol_tree_storage(
            1,
            0,
            size_of::<String>() + size_of::<serde_json::Value>(),
            std::mem::align_of::<String>().max(std::mem::align_of::<serde_json::Value>()),
            self.maximum,
        )
        .map_err(|_| Excess)
    }

    fn container(&mut self, map: bool) -> Result<Container<'_>, Excess> {
        if self.depth >= 128 {
            return Err(Excess);
        }
        self.depth += 1;
        self.add(size_of::<serde_json::Value>())?;
        if map {
            // The retained owning walk charges a root independently of entries,
            // even for {}. Entry nodes below cannot replace this root term.
            self.add(self.map_node()?)?;
        }
        Ok(Container {
            counter: self,
            map,
            entries: 0,
        })
    }
}

struct Container<'a> {
    counter: &'a mut Counter,
    map: bool,
    entries: usize,
}

impl Container<'_> {
    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Excess> {
        self.entries = self.entries.checked_add(1).ok_or(Excess)?;
        value.serialize(&mut *self.counter)
    }

    fn key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Excess> {
        self.entries = self.entries.checked_add(1).ok_or(Excess)?;
        // Keep the same checked per-node geometry as the retained owning walk.
        self.counter.add(self.counter.map_node()?)?;
        key.serialize(&mut *self.counter)
    }

    fn finish(self) -> Result<(), Excess> {
        if !self.map && self.entries != 0 {
            // Vec's pinned minimum capacity and doubling sequence: cumulative
            // requested slots are bounded by 4*n+4, including a final growth
            // while the old bank remains live. Value and Id are the only
            // possible element owners in these closed typed/opaque sequences.
            let width = size_of::<serde_json::Value>().max(size_of::<Id>());
            let bytes = self
                .entries
                .checked_mul(4)
                .and_then(|n| n.checked_add(4))
                .and_then(|n| n.checked_mul(width))
                .ok_or(Excess)?;
            self.counter.add(bytes)?;
        }
        self.counter.depth -= 1;
        Ok(())
    }
}

pub(super) fn measure(value: &impl Serialize, maximum: usize) -> Result<usize, RuntimeError> {
    let mut counter = Counter {
        used: 0,
        maximum,
        depth: 0,
    };
    value
        .serialize(&mut counter)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(counter.used)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Counter>()
        + size_of::<[Container<'static>; 128]>()
        + size_of::<Result<(), Excess>>()
        + size_of::<Result<usize, Excess>>()
        + size_of::<std::alloc::Layout>()
        + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
        + size_of::<Result<usize, RuntimeError>>()
}

impl<'a> ser::Serializer for &'a mut Counter {
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
        Ok(())
    }

    fn serialize_i8(self, _: i8) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_i16(self, _: i16) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_i32(self, _: i32) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_i64(self, _: i64) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_i128(self, _: i128) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_u8(self, _: u8) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_u16(self, _: u16) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_u32(self, _: u32) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_u64(self, _: u64) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_u128(self, _: u128) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_f32(self, _: f32) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_f64(self, _: f64) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<(), Excess> {
        self.string(v.encode_utf8(&mut [0; 4]))
    }

    fn serialize_str(self, v: &str) -> Result<(), Excess> {
        self.string(v)
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<(), Excess> {
        Err(Excess)
    }

    fn serialize_none(self) -> Result<(), Excess> {
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> Result<(), Excess> {
        v.serialize(self)
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
        v: &'static str,
    ) -> Result<(), Excess> {
        self.string(v)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<(), Excess> {
        v.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Excess> {
        Err(Excess)
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Container<'a>, Excess> {
        self.container(false)
    }

    fn serialize_tuple(self, _: usize) -> Result<Container<'a>, Excess> {
        self.container(false)
    }

    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Container<'a>, Excess> {
        self.container(false)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Container<'a>, Excess> {
        Err(Excess)
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Container<'a>, Excess> {
        self.container(true)
    }

    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Container<'a>, Excess> {
        self.container(true)
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Container<'a>, Excess> {
        Err(Excess)
    }

    fn collect_str<T: ?Sized + fmt::Display>(self, _: &T) -> Result<(), Excess> {
        Err(Excess)
    }
}

impl SerializeSeq for Container<'_> {
    type Ok = ();
    type Error = Excess;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Excess> {
        self.element(v)
    }

    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeTuple for Container<'_> {
    type Ok = ();
    type Error = Excess;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Excess> {
        self.element(v)
    }

    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeTupleStruct for Container<'_> {
    type Ok = ();
    type Error = Excess;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Excess> {
        self.element(v)
    }

    fn end(self) -> Result<(), Excess> {
        self.finish()
    }
}

impl SerializeTupleVariant for Container<'_> {
    type Ok = ();
    type Error = Excess;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &T) -> Result<(), Excess> {
        Err(Excess)
    }

    fn end(self) -> Result<(), Excess> {
        Err(Excess)
    }
}

impl SerializeMap for Container<'_> {
    type Ok = ();
    type Error = Excess;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Excess> {
        self.key(v)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Excess> {
        v.serialize(&mut *self.counter)
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
        k: &'static str,
        v: &T,
    ) -> Result<(), Excess> {
        self.key(k)?;
        v.serialize(&mut *self.counter)
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
        _: &'static str,
        _: &T,
    ) -> Result<(), Excess> {
        Err(Excess)
    }

    fn end(self) -> Result<(), Excess> {
        Err(Excess)
    }
}

#[cfg(test)]
mod tests {
    //! Exercises the real owning walk's independent empty-map root convention.
    // crucible-lint: allow panic-shortcut -- Closed DATA fixture failures stop the control.
    use super::*;

    #[test]
    fn empty_and_nested_empty_objects_keep_their_independent_map_roots() {
        let maximum = 16 * 1024 * 1024;
        let empty = serde_json::json!({});
        let root = NodeRuntime::capture_protocol_tree_storage(
            1,
            0,
            size_of::<String>() + size_of::<serde_json::Value>(),
            std::mem::align_of::<String>().max(std::mem::align_of::<serde_json::Value>()),
            maximum,
        )
        .unwrap();
        let minimum = size_of::<serde_json::Value>() + root;

        assert_eq!(measure(&empty, maximum).unwrap(), minimum);
        assert!(measure(&empty, minimum - 1).is_err());

        let actual =
            crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::
                value_storage_with_error::<RuntimeError>(
                    &empty,
                    0,
                    maximum,
                )
                .unwrap();

        assert!(actual > size_of::<serde_json::Value>());
        assert!(measure(&empty, maximum).unwrap() >= actual + size_of::<serde_json::Value>());

        let nested = serde_json::json!({"empty": {}, "children": [{}, {"inner": {}}]});
        let decoded: serde_json::Value = serde::Deserialize::deserialize(&nested).unwrap();

        let actual =
            crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::
                value_storage_with_error::<RuntimeError>(
                    &decoded,
                    0,
                    maximum,
                )
                .unwrap();

        assert_eq!(decoded, nested);
        assert!(measure(&nested, maximum).unwrap() >= actual + size_of::<serde_json::Value>());
    }
}
