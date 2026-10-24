//! Counts prospective reset strings through an actual borrowed serializer.
//!
//! This walk builds no Value or encoded bank. Actual custom serializers still
//! run: their formatter storage and original-custody guards belong to the caller.
//! The finite JSON container profile matches the canonical bootstrap parser.

use super::*;
use serde::{Serialize, ser};
use std::fmt;

/// Quotes reset populations before constructing an actual serialized body.
///
/// The caller admits this walk and its actual custom formatters first. No
/// future Initial, row, recipe or encoded body is manufactured by this walk.
///
/// # Errors
/// Refuses serializer errors, unsupported container depth, checked population
/// overflow or reset demand above the independent restriction.
pub(crate) fn quote_serialized_data<T: Serialize + ?Sized>(
    original: &T,
    maximum: usize,
) -> Result<JsonValueReparseConstructionData, ProviderError> {
    quote(original, 0, false, maximum)
}

/// Bounds native raw-token resets inside the actual closed outer depth.
///
/// The native raw scanner uses each full encoded JSON string token. Six bytes
/// per original UTF-8 byte plus its two quotes cover canonical escape spelling;
/// this differs deliberately from the owned-Value walk's decoded string length.
///
/// # Errors
/// Refuses an unsupported outer/serialized depth or the original serializer and
/// reset-population errors. Outer wrappers grant no new recursion allowance.
pub(crate) fn quote_serialized_raw_bound_data<T: Serialize + ?Sized>(
    original: &T,
    outer_depth: usize,
    maximum: usize,
) -> Result<JsonValueReparseConstructionData, ProviderError> {
    quote(original, outer_depth, true, maximum)
}

fn quote<T: Serialize + ?Sized>(
    original: &T,
    outer_depth: usize,
    raw_literal: bool,
    maximum: usize,
) -> Result<JsonValueReparseConstructionData, ProviderError> {
    if outer_depth > RAW_OUTER_DEPTH {
        return Err(exhausted());
    }
    let mut quote = JsonValueReparseConstructionData::default();
    original
        .serialize(&mut Scanner {
            quote: &mut quote,
            maximum,
            depth: outer_depth,
            raw_literal,
        })
        .map_err(|error| match error {
            Error::Population(error) => error,
            Error::Unsupported => exhausted(),
        })?;
    Ok(quote)
}

#[derive(Clone, Copy)]
enum Token {
    String { bytes: usize, reserved: bool },
    Other,
}

#[derive(Debug)]
enum Error {
    Population(ProviderError),
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("prospective JSON reset population unavailable")
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self::Unsupported
    }
}

struct Scanner<'a> {
    quote: &'a mut JsonValueReparseConstructionData,
    maximum: usize,
    depth: usize,
    raw_literal: bool,
}

struct Container<'a, 'q> {
    scanner: &'a mut Scanner<'q>,
    pending_reserved: bool,
    levels: usize,
}

impl<'q> Scanner<'q> {
    fn record(&mut self, token: Token) -> Result<(), Error> {
        match token {
            Token::String { bytes, .. } => {
                let extent = if self.raw_literal {
                    bytes
                        .checked_mul(6)
                        .and_then(|n| n.checked_add(2))
                        .ok_or(Error::Unsupported)?
                } else {
                    bytes
                };
                self.quote.add_string_data(extent, self.maximum)
            }
            Token::Other => self.quote.add_wrong_type_data(self.maximum),
        }
        .map_err(Error::Population)
    }

    fn enter(&mut self, levels: usize) -> Result<Container<'_, 'q>, Error> {
        let depth = self.depth.checked_add(levels).ok_or(Error::Unsupported)?;
        if depth > RAW_OUTER_DEPTH {
            return Err(Error::Unsupported);
        }
        self.depth = depth;
        Ok(Container {
            scanner: self,
            pending_reserved: false,
            levels,
        })
    }
}

impl Container<'_, '_> {
    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(&mut *self.scanner)?;
        Ok(())
    }

    fn field<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> Result<(), Error> {
        let token = value.serialize(&mut *self.scanner)?;
        if key == RAW_VALUE_KEY {
            self.scanner.record(token)?;
        }
        Ok(())
    }

    fn finish(self) -> Token {
        self.scanner.depth -= self.levels;
        Token::Other
    }
}

macro_rules! scalar {
    ($($method:ident($ty:ty)),+ $(,)?) => {$ (
        fn $method(self, _: $ty) -> Result<Token, Error> { Ok(Token::Other) }
    )+};
}

impl<'a, 'q> ser::Serializer for &'a mut Scanner<'q> {
    type Ok = Token;
    type Error = Error;
    type SerializeSeq = Container<'a, 'q>;
    type SerializeTuple = Container<'a, 'q>;
    type SerializeTupleStruct = Container<'a, 'q>;
    type SerializeTupleVariant = Container<'a, 'q>;
    type SerializeMap = Container<'a, 'q>;
    type SerializeStruct = Container<'a, 'q>;
    type SerializeStructVariant = Container<'a, 'q>;

    scalar!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64)
    );

    fn serialize_char(self, value: char) -> Result<Token, Error> {
        Ok(Token::String {
            bytes: value.len_utf8(),
            reserved: false,
        })
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<Token, Error> {
        Ok(self.enter(1)?.finish())
    }

    fn serialize_str(self, value: &str) -> Result<Token, Error> {
        Ok(Token::String {
            bytes: value.len(),
            reserved: value == RAW_VALUE_KEY,
        })
    }

    fn serialize_none(self) -> Result<Token, Error> {
        Ok(Token::Other)
    }
    fn serialize_unit(self) -> Result<Token, Error> {
        Ok(Token::Other)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Token, Error> {
        Ok(Token::Other)
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Token, Error> {
        value.serialize(self)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Token, Error> {
        // The closed bootstrap DTOs contain ordinary Value, never a RawValue
        // serializer that injects unvisited JSON syntax.
        if name == RAW_VALUE_KEY {
            return Err(Error::Unsupported);
        }
        value.serialize(self)
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<Token, Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Token, Error> {
        let mut object = self.enter(1)?;
        object.field(variant, value)?;
        Ok(object.finish())
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        self.enter(1)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        self.enter(1)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        self.enter(1)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        self.enter(1)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
        self.enter(1)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        if variant == RAW_VALUE_KEY {
            self.record(Token::Other)?;
        }
        self.enter(2)
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        if variant == RAW_VALUE_KEY {
            self.record(Token::Other)?;
        }
        self.enter(2)
    }

    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<Token, Error> {
        let mut text = DisplayExtent {
            bytes: 0,
            reserved: true,
        };
        fmt::write(&mut text, format_args!("{value}")).map_err(|_| Error::Unsupported)?;
        Ok(Token::String {
            bytes: text.bytes,
            reserved: text.reserved && text.bytes == RAW_VALUE_KEY.len(),
        })
    }
}

// Display can arrive in several writes. Compare each original byte without
// constructing the default Serializer::collect_str temporary String.
struct DisplayExtent {
    bytes: usize,
    reserved: bool,
}

impl fmt::Write for DisplayExtent {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.bytes.checked_add(value.len()).ok_or(fmt::Error)?;
        self.reserved &= RAW_VALUE_KEY.as_bytes().get(self.bytes..end) == Some(value.as_bytes());
        self.bytes = end;
        Ok(())
    }
}

macro_rules! sequence {
    ($trait:ident, $method:ident) => {
        impl ser::$trait for Container<'_, '_> {
            type Ok = Token;
            type Error = Error;
            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
                self.element(value)
            }
            fn end(self) -> Result<Token, Error> {
                Ok(self.finish())
            }
        }
    };
}

sequence!(SerializeSeq, serialize_element);
sequence!(SerializeTuple, serialize_element);
sequence!(SerializeTupleStruct, serialize_field);
sequence!(SerializeTupleVariant, serialize_field);

impl ser::SerializeMap for Container<'_, '_> {
    type Ok = Token;
    type Error = Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        self.pending_reserved = matches!(
            key.serialize(&mut *self.scanner)?,
            Token::String { reserved: true, .. }
        );
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let token = value.serialize(&mut *self.scanner)?;
        if self.pending_reserved {
            self.scanner.record(token)?;
        }
        self.pending_reserved = false;
        Ok(())
    }

    fn end(self) -> Result<Token, Error> {
        Ok(self.finish())
    }
}

macro_rules! structure {
    ($trait:ident) => {
        impl ser::$trait for Container<'_, '_> {
            type Ok = Token;
            type Error = Error;
            fn serialize_field<T: Serialize + ?Sized>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Error> {
                self.field(key, value)
            }
            fn end(self) -> Result<Token, Error> {
                Ok(self.finish())
            }
        }
    };
}

structure!(SerializeStruct);
structure!(SerializeStructVariant);

/// Names this actual finite serializer's direct and recursive fixed controls.
pub(crate) fn serialized_scanner_counter_scratch_data() -> usize {
    let frame = size_of::<Container<'static, 'static>>()
        + size_of::<Result<Container<'static, 'static>, Error>>()
        + size_of::<Token>()
        + size_of::<Result<Token, Error>>()
        + size_of::<&mut Scanner<'static>>()
        + size_of::<&str>()
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 3
        + size_of::<Result<(), Error>>();
    geometry::quote_counter_scratch_data()
        + RAW_OUTER_DEPTH * frame
        + size_of::<Scanner<'static>>()
        + size_of::<JsonValueReparseConstructionData>()
        + size_of::<Result<JsonValueReparseConstructionData, ProviderError>>()
        + size_of::<DisplayExtent>()
        + size_of::<fmt::Arguments<'static>>()
        + size_of::<fmt::Result>()
        + size_of::<&[u8]>() * 2
        + size_of::<Option<&[u8]>>()
        + size_of::<usize>() * 3
        + size_of::<bool>()
        + size_of::<Result<JsonValueReparseConstructionData, ProviderError>>()
}

#[cfg(test)]
#[path = "serialization/tests.rs"]
mod tests;
