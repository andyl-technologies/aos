//! Copies the defining Envelope serializer directly into a bounded private bank.
//!
//! Only the concrete Envelope is accepted. Its borrowed serializer uses strings,
//! finite numbers, nullable fields, maps and sequences without allocating a DOM.
//! Both passes are bounded; the writer refuses before any Vec growth, including
//! if a future serializer disagrees with the measuring pass.

use super::*;
use crate::envelope::Envelope;
use serde::ser::{Impossible, SerializeStruct, SerializeTuple, SerializeTupleStruct};

mod canonical_extent;
use canonical_extent::CanonicalExtent;

impl CompactJson {
    /// Measures bank and exact canonical extents before any whole-value allocation.
    ///
    /// Ordering object members changes no byte count. Strings follow JSON's
    /// escaping rules; numbers use the defining JCS writer on inline scalars.
    /// Neither pass constructs a tree, text bank or identity hash. The caller
    /// separately admits these bounded recursive controls before invocation.
    ///
    /// # Errors
    /// Refuses unsupported geometry or either independent byte restriction.
    pub(in crate::client) fn envelope_extents(
        original: &Envelope,
        maximum_bank_bytes: usize,
        maximum_canonical_bytes: usize,
    ) -> Result<(usize, usize), ProviderError> {
        let mut counter = Encoder::new(None, maximum_bank_bytes);
        counter.canonical = Some(CanonicalExtent::new(maximum_canonical_bytes));
        original.serialize(&mut counter).map_err(provider_error)?;
        let canonical = counter.canonical.ok_or_else(invalid)?.bytes();
        Ok((counter.position, canonical))
    }

    /// Copies a complete original envelope without an intermediate JSON tree.
    ///
    /// The defining Envelope serializer supplies field names and scalar formats.
    /// The caller independently admits both bounded traversals, fixed controls,
    /// recursion and the new bank before invoking this constructor. The borrowed
    /// original remains unchanged on every refusal.
    ///
    /// # Errors
    /// Refuses excessive geometry, unsupported serialization, unavailable bank
    /// storage or demand above the independent restriction.
    pub fn from_envelope(original: &Envelope, maximum: usize) -> Result<Self, ProviderError> {
        let mut counter = Encoder::new(None, maximum);
        original.serialize(&mut counter).map_err(provider_error)?;
        let requested = counter.position;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(requested).map_err(|_| refused())?;
        // The aggregate journal bound prices measured banks, so allocator
        // overcapacity cannot become an uncharged independent owner.
        if bytes.capacity() != requested {
            return Err(refused());
        }
        let mut writer = Encoder::new(Some(&mut bytes), requested);
        original.serialize(&mut writer).map_err(provider_error)?;
        if writer.position != requested {
            return Err(invalid());
        }
        Ok(Self { bytes })
    }
}

#[derive(Clone, Copy, Debug)]
enum Error {
    Geometry,
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Geometry => "compact envelope storage restriction",
            Self::Unsupported => "unsupported compact envelope serialization",
        })
    }
}

impl std::error::Error for Error {}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        // Error formatting must not create an unpriced String during either pass.
        Self::Unsupported
    }
}

fn provider_error(error: Error) -> ProviderError {
    match error {
        Error::Geometry => refused(),
        Error::Unsupported => invalid(),
    }
}

struct Encoder<'a> {
    output: Option<&'a mut Vec<u8>>,
    position: usize,
    maximum: usize,
    depth: usize,
    string_key: bool,
    canonical: Option<CanonicalExtent>,
}

impl<'a> Encoder<'a> {
    fn new(output: Option<&'a mut Vec<u8>>, maximum: usize) -> Self {
        Self {
            output,
            position: 0,
            maximum,
            depth: 0,
            string_key: false,
            canonical: None,
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(bytes.len())
            .filter(|&end| end <= self.maximum)
            .ok_or(Error::Geometry)?;
        if let Some(output) = &mut self.output {
            if end > output.capacity() {
                return Err(Error::Geometry);
            }
            output.extend_from_slice(bytes);
        }
        self.position = end;
        Ok(())
    }

    fn value(&self) -> Result<(), Error> {
        if self.string_key {
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }

    fn scalar(&mut self, tag: u8) -> Result<(), Error> {
        self.value()?;
        if let Some(canonical) = &mut self.canonical {
            canonical.add(match tag {
                NULL | TRUE => 4,
                FALSE => 5,
                _ => return Err(Error::Unsupported),
            })?;
        }
        self.emit(&[tag])
    }

    fn number(&mut self, tag: u8, bytes: [u8; 8]) -> Result<(), Error> {
        self.value()?;
        if let Some(canonical) = &mut self.canonical {
            canonical.number(tag, bytes)?;
        }
        self.emit(&[tag])?;
        self.emit(&bytes)
    }

    fn string(&mut self, value: &str) -> Result<(), Error> {
        self.string_key = false;
        self.emit(&[STRING])?;
        self.emit(
            &u64::try_from(value.len())
                .map_err(|_| Error::Geometry)?
                .to_le_bytes(),
        )?;
        self.emit(value.as_bytes())?;
        if let Some(canonical) = &mut self.canonical {
            canonical.string(value)?;
        }
        Ok(())
    }

    fn begin(&mut self, tag: u8, expected: Option<usize>) -> Result<Compound<'_, 'a>, Error> {
        self.value()?;
        if self.depth >= MAXIMUM_DEPTH {
            return Err(Error::Geometry);
        }
        let header = self.position;
        self.emit(&[tag])?;
        self.emit(&[0; 16])?;
        if let Some(canonical) = &mut self.canonical {
            // Both delimiters are counted before walking any children.
            canonical.add(2)?;
        }
        self.depth += 1;
        Ok(Compound {
            encoder: self,
            header,
            expected,
            count: 0,
            tag,
            pending_key: false,
        })
    }

    fn patch_word(&mut self, offset: usize, value: usize) -> Result<(), Error> {
        let bytes = u64::try_from(value)
            .map_err(|_| Error::Geometry)?
            .to_le_bytes();
        if let Some(output) = &mut self.output {
            let end = offset.checked_add(bytes.len()).ok_or(Error::Geometry)?;
            output
                .get_mut(offset..end)
                .ok_or(Error::Geometry)?
                .copy_from_slice(&bytes);
        }
        Ok(())
    }
}

struct Compound<'a, 'out> {
    encoder: &'a mut Encoder<'out>,
    header: usize,
    expected: Option<usize>,
    count: usize,
    tag: u8,
    pending_key: bool,
}

impl Compound<'_, '_> {
    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        if self.tag != ARRAY || self.count >= crucible_node_format::MAX_ARRAY_ELEMENTS {
            return Err(Error::Geometry);
        }
        if self.count != 0
            && let Some(canonical) = &mut self.encoder.canonical
        {
            canonical.add(1)?;
        }
        value.serialize(&mut *self.encoder)?;
        self.count = self.count.checked_add(1).ok_or(Error::Geometry)?;
        Ok(())
    }

    fn finish(self) -> Result<(), Error> {
        if self.pending_key || self.expected.is_some_and(|expected| expected != self.count) {
            return Err(Error::Unsupported);
        }
        let payload = self
            .header
            .checked_add(CONTAINER_WIDTH)
            .ok_or(Error::Geometry)?;
        let extent = self
            .encoder
            .position
            .checked_sub(payload)
            .ok_or(Error::Geometry)?;
        self.encoder.patch_word(self.header + 1, self.count)?;
        self.encoder
            .patch_word(self.header + SCALAR_WIDTH, extent)?;
        self.encoder.depth = self.encoder.depth.checked_sub(1).ok_or(Error::Geometry)?;
        Ok(())
    }
}

impl SerializeSeq for Compound<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }

    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl SerializeTuple for Compound<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }

    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl SerializeTupleStruct for Compound<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }

    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl SerializeMap for Compound<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        if self.tag != OBJECT || self.pending_key {
            return Err(Error::Unsupported);
        }
        if let Some(canonical) = &mut self.encoder.canonical {
            // Every member has a colon; all but the first also have a comma.
            canonical.add(if self.count == 0 { 1 } else { 2 })?;
        }
        self.encoder.string_key = true;
        key.serialize(&mut *self.encoder)?;
        if self.encoder.string_key {
            return Err(Error::Unsupported);
        }
        self.pending_key = true;
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        if !self.pending_key {
            return Err(Error::Unsupported);
        }
        value.serialize(&mut *self.encoder)?;
        self.pending_key = false;
        self.count = self.count.checked_add(1).ok_or(Error::Geometry)?;
        Ok(())
    }

    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl SerializeStruct for Compound<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        SerializeMap::serialize_entry(self, key, value)
    }

    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl<'a, 'out> Serializer for &'a mut Encoder<'out> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Compound<'a, 'out>;
    type SerializeTuple = Compound<'a, 'out>;
    type SerializeTupleStruct = Compound<'a, 'out>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Compound<'a, 'out>;
    type SerializeStruct = Compound<'a, 'out>;
    type SerializeStructVariant = Impossible<(), Error>;

    fn serialize_bool(self, value: bool) -> Result<(), Error> {
        self.scalar(if value { TRUE } else { FALSE })
    }

    fn serialize_i8(self, value: i8) -> Result<(), Error> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i16(self, value: i16) -> Result<(), Error> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i32(self, value: i32) -> Result<(), Error> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i64(self, value: i64) -> Result<(), Error> {
        if let Ok(value) = u64::try_from(value) {
            self.serialize_u64(value)
        } else {
            self.number(SIGNED, value.to_le_bytes())
        }
    }

    fn serialize_u8(self, value: u8) -> Result<(), Error> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u16(self, value: u16) -> Result<(), Error> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u32(self, value: u32) -> Result<(), Error> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u64(self, value: u64) -> Result<(), Error> {
        self.number(UNSIGNED, value.to_le_bytes())
    }

    fn serialize_f32(self, value: f32) -> Result<(), Error> {
        self.serialize_f64(f64::from(value))
    }

    fn serialize_f64(self, value: f64) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(Error::Unsupported);
        }
        self.number(FLOAT, value.to_bits().to_le_bytes())
    }

    fn serialize_char(self, value: char) -> Result<(), Error> {
        self.serialize_str(value.encode_utf8(&mut [0; 4]))
    }

    fn serialize_str(self, value: &str) -> Result<(), Error> {
        self.string(value)
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn serialize_none(self) -> Result<(), Error> {
        self.serialize_unit()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        self.value()?;
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), Error> {
        self.scalar(NULL)
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.value()?;
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn serialize_seq(self, length: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        self.begin(ARRAY, length)
    }

    fn serialize_tuple(self, length: usize) -> Result<Self::SerializeTuple, Error> {
        self.begin(ARRAY, Some(length))
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        length: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        self.begin(ARRAY, Some(length))
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::Unsupported)
    }

    fn serialize_map(self, length: Option<usize>) -> Result<Self::SerializeMap, Error> {
        self.begin(OBJECT, length)
    }

    fn serialize_struct(
        self,
        _: &'static str,
        length: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        self.begin(OBJECT, Some(length))
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::Unsupported)
    }

    fn collect_str<T: std::fmt::Display + ?Sized>(self, _: &T) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
