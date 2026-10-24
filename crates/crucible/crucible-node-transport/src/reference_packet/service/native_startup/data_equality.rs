//! Compares closed installed binding data before another owning decode exists.
//!
//! The concrete baseline and initial host guards use this visitor with original
//! NodeBinding/Realize or complete ProviderManifest data. Those serializers contain primitive/Value children,
//! not Bytes formatters or erased callbacks. It constructs no temporary DOM and
//! never hashes/canonicalizes an untrusted numeric subtree. The known quoted
//! integer serializers may allocate one decimal String (at most 20 bytes) before
//! invoking the visitor; the actual native action separately admits that phase.

use serde::{
    Serialize, Serializer,
    ser::{
        self, SerializeMap, SerializeSeq, SerializeStruct, SerializeTuple, SerializeTupleStruct,
    },
};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Debug)]
struct Unsupported;

impl fmt::Display for Unsupported {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("unsupported closed binding serializer")
    }
}

impl std::error::Error for Unsupported {}

impl ser::Error for Unsupported {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<Compare<'static>>()
        + std::mem::size_of::<Sequence<'static>>()
        + std::mem::size_of::<Object<'static>>()
        + std::mem::size_of::<Key<'static>>()
        + std::mem::size_of::<Unsupported>()
        + 20
        + 4
}

/// Names one complete closed comparison-serializer layer and its adapters.
///
/// The caller composes the actual serialized field path and separately funds
/// owning leaf formatters. These logical source controls are not stack frames.
/// Unsupported is zero-sized and its custom error never formats Display text.
pub(crate) const fn serialization_layer_counter_scratch_data<T: ?Sized>() -> usize {
    use std::mem::size_of;

    size_of::<&T>() * 3
        + size_of::<Compare<'static>>() * 3
        + size_of::<View<'static>>() * 3
        + size_of::<Sequence<'static>>() * 3
        + size_of::<Object<'static>>() * 3
        + size_of::<Key<'static>>() * 3
        + size_of::<Unsupported>()
        + size_of::<Result<bool, Unsupported>>() * 4
        + size_of::<Result<(), Unsupported>>() * 3
        + size_of::<Result<Sequence<'static>, Unsupported>>()
        + size_of::<Result<Object<'static>, Unsupported>>()
        + size_of::<&Value>() * 4
        + size_of::<Option<&Value>>() * 4
        + size_of::<&Map<String, Value>>() * 2
        + size_of::<Option<&Map<String, Value>>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<(&String, &Value)>>()
        + size_of::<&str>() * 4
        + size_of::<&[Value]>() * 2
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 4
        + size_of::<bool>() * 4
        + size_of::<u64>() * 2
        + size_of::<i64>() * 2
        + size_of::<f64>() * 2
        + size_of::<char>()
        + size_of::<[u8; 4]>()
        + size_of::<u32>()
}

pub(crate) fn matches<T: Serialize + ?Sized>(actual: &Value, expected: &T) -> bool {
    expected
        .serialize(Compare(View::Value(actual)))
        .unwrap_or(false)
}

/// Borrows an object root without constructing or cloning a Value wrapper.
pub(crate) fn matches_object<T: Serialize + ?Sized>(
    actual: &Map<String, Value>,
    expected: &T,
) -> bool {
    expected
        .serialize(Compare(View::Object(actual)))
        .unwrap_or(false)
}

enum View<'a> {
    Value(&'a Value),
    Object(&'a Map<String, Value>),
}

impl<'a> View<'a> {
    fn value(&self) -> Option<&'a Value> {
        match self {
            Self::Value(value) => Some(value),
            Self::Object(_) => None,
        }
    }

    fn as_object(&self) -> Option<&'a Map<String, Value>> {
        match self {
            Self::Value(value) => value.as_object(),
            Self::Object(value) => Some(value),
        }
    }

    fn as_bool(&self) -> Option<bool> {
        self.value().and_then(Value::as_bool)
    }
    fn as_i64(&self) -> Option<i64> {
        self.value().and_then(Value::as_i64)
    }
    fn as_u64(&self) -> Option<u64> {
        self.value().and_then(Value::as_u64)
    }
    fn as_f64(&self) -> Option<f64> {
        self.value().and_then(Value::as_f64)
    }
    fn as_str(&self) -> Option<&'a str> {
        self.value().and_then(Value::as_str)
    }
    fn as_array(&self) -> Option<&'a Vec<Value>> {
        self.value().and_then(Value::as_array)
    }
    fn is_null(&self) -> bool {
        self.value().is_some_and(Value::is_null)
    }
}

struct Compare<'a>(View<'a>);

struct Sequence<'a> {
    values: &'a [Value],
    position: usize,
    matches: bool,
}

struct Object<'a> {
    values: &'a Map<String, Value>,
    pending: Option<&'a Value>,
    fields: usize,
    matches: bool,
}

macro_rules! scalar {
    ($name:ident,$ty:ty,$method:ident) => {
        fn $name(self, value: $ty) -> Result<bool, Unsupported> {
            Ok(self.0.$method() == Some(value))
        }
    };
}

impl<'a> Serializer for Compare<'a> {
    type Ok = bool;
    type Error = Unsupported;
    type SerializeSeq = Sequence<'a>;
    type SerializeTuple = Sequence<'a>;
    type SerializeTupleStruct = Sequence<'a>;
    type SerializeTupleVariant = ser::Impossible<bool, Unsupported>;
    type SerializeMap = Object<'a>;
    type SerializeStruct = Object<'a>;
    type SerializeStructVariant = ser::Impossible<bool, Unsupported>;

    scalar!(serialize_bool, bool, as_bool);
    scalar!(serialize_i64, i64, as_i64);
    scalar!(serialize_u64, u64, as_u64);
    scalar!(serialize_f64, f64, as_f64);

    fn serialize_i8(self, value: i8) -> Result<bool, Unsupported> {
        self.serialize_i64(i64::from(value))
    }
    fn serialize_i16(self, value: i16) -> Result<bool, Unsupported> {
        self.serialize_i64(i64::from(value))
    }
    fn serialize_i32(self, value: i32) -> Result<bool, Unsupported> {
        self.serialize_i64(i64::from(value))
    }
    fn serialize_u8(self, value: u8) -> Result<bool, Unsupported> {
        self.serialize_u64(u64::from(value))
    }
    fn serialize_u16(self, value: u16) -> Result<bool, Unsupported> {
        self.serialize_u64(u64::from(value))
    }
    fn serialize_u32(self, value: u32) -> Result<bool, Unsupported> {
        self.serialize_u64(u64::from(value))
    }
    fn serialize_f32(self, value: f32) -> Result<bool, Unsupported> {
        self.serialize_f64(f64::from(value))
    }
    fn serialize_char(self, value: char) -> Result<bool, Unsupported> {
        let mut bytes = [0_u8; 4];
        self.serialize_str(value.encode_utf8(&mut bytes))
    }
    fn serialize_str(self, value: &str) -> Result<bool, Unsupported> {
        Ok(self.0.as_str() == Some(value))
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_none(self) -> Result<bool, Unsupported> {
        Ok(self.0.is_null())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<bool, Unsupported> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<bool, Unsupported> {
        self.serialize_none()
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<bool, Unsupported> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<bool, Unsupported> {
        self.serialize_str(variant)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<bool, Unsupported> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Sequence<'a>, Unsupported> {
        let values = self.0.as_array().ok_or(Unsupported)?;
        Ok(Sequence {
            values,
            position: 0,
            matches: length.is_none_or(|n| n == values.len()),
        })
    }
    fn serialize_tuple(self, length: usize) -> Result<Sequence<'a>, Unsupported> {
        self.serialize_seq(Some(length))
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        length: usize,
    ) -> Result<Sequence<'a>, Unsupported> {
        self.serialize_seq(Some(length))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_map(self, length: Option<usize>) -> Result<Object<'a>, Unsupported> {
        let values = self.0.as_object().ok_or(Unsupported)?;
        Ok(Object {
            values,
            pending: None,
            fields: 0,
            matches: length.is_none_or(|n| n == values.len()),
        })
    }
    fn serialize_struct(self, _: &'static str, length: usize) -> Result<Object<'a>, Unsupported> {
        self.serialize_map(Some(length))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Unsupported> {
        Err(Unsupported)
    }
    fn collect_str<T: fmt::Display + ?Sized>(self, _: &T) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
}

impl SerializeSeq for Sequence<'_> {
    type Ok = bool;
    type Error = Unsupported;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Unsupported> {
        let actual = self.values.get(self.position).ok_or(Unsupported)?;
        self.matches &= value.serialize(Compare(View::Value(actual)))?;
        self.position = self.position.checked_add(1).ok_or(Unsupported)?;
        Ok(())
    }
    fn end(self) -> Result<bool, Unsupported> {
        Ok(self.matches && self.position == self.values.len())
    }
}

impl SerializeTuple for Sequence<'_> {
    type Ok = bool;
    type Error = Unsupported;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Unsupported> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<bool, Unsupported> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleStruct for Sequence<'_> {
    type Ok = bool;
    type Error = Unsupported;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Unsupported> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<bool, Unsupported> {
        SerializeSeq::end(self)
    }
}

impl<'a> SerializeMap for Object<'a> {
    type Ok = bool;
    type Error = Unsupported;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Unsupported> {
        if self.pending.is_some() {
            return Err(Unsupported);
        }
        // Closed String/static keys are compared directly. Iterating the
        // existing raw map avoids owning a formatted key or storing a borrow
        // of the serializer's potentially temporary input. No key is copied.
        let mut found = None;
        for (candidate, value) in self.values {
            if key.serialize(Key(candidate))? {
                if found.is_some() {
                    return Err(Unsupported);
                }
                found = Some(value);
            }
        }
        self.pending = Some(found.ok_or(Unsupported)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Unsupported> {
        let actual = self.pending.take().ok_or(Unsupported)?;
        self.matches &= value.serialize(Compare(View::Value(actual)))?;
        self.fields = self.fields.checked_add(1).ok_or(Unsupported)?;
        Ok(())
    }
    fn end(self) -> Result<bool, Unsupported> {
        Ok(self.matches && self.pending.is_none() && self.fields == self.values.len())
    }
}

impl SerializeStruct for Object<'_> {
    type Ok = bool;
    type Error = Unsupported;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Unsupported> {
        let actual = self.values.get(key).ok_or(Unsupported)?;
        self.matches &= value.serialize(Compare(View::Value(actual)))?;
        self.fields = self.fields.checked_add(1).ok_or(Unsupported)?;
        Ok(())
    }
    fn end(self) -> Result<bool, Unsupported> {
        SerializeMap::end(self)
    }
}

// Only string keys occur in these concrete NodeBinding/Value serializers. Every
// other key formatter refuses without allocating or invoking Display.
struct Key<'a>(&'a str);

macro_rules! reject_key_scalar {
    ($name:ident,$ty:ty) => {
        fn $name(self, _: $ty) -> Result<bool, Unsupported> {
            Err(Unsupported)
        }
    };
}

impl Serializer for Key<'_> {
    type Ok = bool;
    type Error = Unsupported;
    type SerializeSeq = ser::Impossible<bool, Unsupported>;
    type SerializeTuple = ser::Impossible<bool, Unsupported>;
    type SerializeTupleStruct = ser::Impossible<bool, Unsupported>;
    type SerializeTupleVariant = ser::Impossible<bool, Unsupported>;
    type SerializeMap = ser::Impossible<bool, Unsupported>;
    type SerializeStruct = ser::Impossible<bool, Unsupported>;
    type SerializeStructVariant = ser::Impossible<bool, Unsupported>;
    fn serialize_str(self, value: &str) -> Result<bool, Unsupported> {
        Ok(self.0 == value)
    }
    reject_key_scalar!(serialize_bool, bool);
    reject_key_scalar!(serialize_i8, i8);
    reject_key_scalar!(serialize_i16, i16);
    reject_key_scalar!(serialize_i32, i32);
    reject_key_scalar!(serialize_i64, i64);
    reject_key_scalar!(serialize_u8, u8);
    reject_key_scalar!(serialize_u16, u16);
    reject_key_scalar!(serialize_u32, u32);
    reject_key_scalar!(serialize_u64, u64);
    reject_key_scalar!(serialize_f32, f32);
    reject_key_scalar!(serialize_f64, f64);
    reject_key_scalar!(serialize_char, char);
    fn serialize_bytes(self, _: &[u8]) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_none(self) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_unit(self) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<bool, Unsupported> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Unsupported> {
        Err(Unsupported)
    }
    fn collect_str<T: fmt::Display + ?Sized>(self, _: &T) -> Result<bool, Unsupported> {
        Err(Unsupported)
    }
}
