//! Retains recorded metadata in bounded, input-backed field maps.
//!
//! ```text
//! u16 mode | u16 flags | four (u32 count | u32 length | field bytes) maps
//! field: u16 name_length | u32 value_length | name | value
//! maps: attributes, xattrs, governing-root properties, graft overrides
//! ```

use terrane_format::cbor::Decoder;
use terrane_format::tree_format::{
    Attribute, ExtendedAttribute, MAX_ATTRIBUTES, MAX_COMPONENT, MAX_NODE_ITEMS_BYTES, Property,
};

use super::{Error, number, offset32};

pub(super) const MINIMUM: usize = 36;

/// Borrows one named field without decoding its value or copying bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field<'a> {
    /// The exact recorded name, UTF-8 except in the raw xattr map.
    pub name: &'a [u8],
    /// Raw xattr bytes, or a complete canonical CBOR attribute/property value.
    pub value: &'a [u8],
}

/// Borrows a checked field map in canonical length-then-byte name order.
#[derive(Clone, Copy, Debug)]
pub struct Fields<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> Fields<'a> {
    /// Returns the number of recorded fields.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.count
    }

    /// Returns whether the recorded map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates borrowed fields without allocation or CBOR decoding.
    #[must_use]
    pub fn iter(&self) -> FieldsIter<'a> {
        FieldsIter { fields: *self }
    }

    /// Finds an exact field name without allocation or CBOR decoding.
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.iter()
            .find(|field| field.name == name)
            .map(|field| field.value)
    }
}

/// Scans the fields of a previously checked metadata map.
#[derive(Debug)]
pub struct FieldsIter<'a> {
    fields: Fields<'a>,
}

impl<'a> Iterator for FieldsIter<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fields.count == 0 {
            return None;
        }
        let bytes = self.fields.bytes;
        let name_length = number::<2>(bytes, 0).ok()? as usize;
        let value_length = offset32(bytes, 2).ok()?;
        let end = 6usize.checked_add(name_length)?.checked_add(value_length)?;
        let field = Field {
            name: bytes.get(6..6 + name_length)?,
            value: bytes.get(6 + name_length..end)?,
        };
        self.fields.bytes = bytes.get(end..)?;
        self.fields.count -= 1;
        Some(field)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.fields.count as usize;
        (count, Some(count))
    }
}

impl ExactSizeIterator for FieldsIter<'_> {}
impl std::iter::FusedIterator for FieldsIter<'_> {}

/// Preserves recorded metadata without applying presentation schemas or defaults.
#[derive(Clone, Copy, Debug)]
pub struct Metadata<'a> {
    /// Recorded permission and special bits; absent for synthesized/graft roots and symlinks.
    pub mode: Option<u16>,
    /// Recorded CBOR attributes, including unrecognized names.
    pub attributes: Fields<'a>,
    /// Recorded raw extended attributes, including unrecognized names.
    pub xattrs: Fields<'a>,
    /// Properties of this root or graft's referenced root; empty on ordinary entries.
    pub root_properties: Fields<'a>,
    /// Overrides recorded on this graft entry; empty on other entries.
    pub graft_overrides: Fields<'a>,
    /// Distinguishes an explicitly recorded empty attribute map from absence.
    pub attributes_present: bool,
    /// Distinguishes an explicitly recorded empty xattr map from absence.
    pub xattrs_present: bool,
}

/// Owns only small vectors of borrowed canonical values during compilation.
#[derive(Default)]
pub(super) struct Input<'a> {
    pub mode: Option<u16>,
    pub attributes: Vec<Attribute<'a>>,
    pub xattrs: Vec<ExtendedAttribute<'a>>,
    pub root_properties: Vec<Property<'a>>,
    pub graft_overrides: Vec<Property<'a>>,
    pub attributes_present: bool,
    pub xattrs_present: bool,
    pub canonical_path: Option<Vec<u8>>,
}

impl Input<'_> {
    pub fn encoded_length(&self) -> Result<usize, Error> {
        self.fields().try_fold(MINIMUM, |size, field| {
            size.checked_add(6)
                .and_then(|size| size.checked_add(field.name.len()))
                .and_then(|size| size.checked_add(field.value.len()))
                .ok_or(Error::Limit)
        })
    }

    fn fields(&self) -> impl Iterator<Item = Field<'_>> {
        self.attributes
            .iter()
            .map(|field| Field {
                name: field.name.as_bytes(),
                value: field.value,
            })
            .chain(self.xattrs.iter().map(|field| Field {
                name: field.name,
                value: field.value,
            }))
            .chain(
                self.root_properties
                    .iter()
                    .chain(&self.graft_overrides)
                    .map(|field| Field {
                        name: field.name.as_bytes(),
                        value: field.value,
                    }),
            )
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != self.encoded_length()? {
            return Err(Error::Encoding);
        }
        output[..2].copy_from_slice(&self.mode.unwrap_or(0).to_le_bytes());
        let flags = u16::from(self.mode.is_some())
            | (u16::from(self.attributes_present) << 1)
            | (u16::from(self.xattrs_present) << 2);
        output[2..4].copy_from_slice(&flags.to_le_bytes());
        let counts = [
            self.attributes.len(),
            self.xattrs.len(),
            self.root_properties.len(),
            self.graft_overrides.len(),
        ];
        let mut fields = self.fields();
        let mut cursor = 4;
        for count in counts {
            let header = cursor;
            cursor += 8;
            for _ in 0..count {
                let field = fields.next().ok_or(Error::Encoding)?;
                let name = u16::try_from(field.name.len()).map_err(|_| Error::Limit)?;
                let value = u32::try_from(field.value.len()).map_err(|_| Error::Limit)?;
                output[cursor..cursor + 2].copy_from_slice(&name.to_le_bytes());
                output[cursor + 2..cursor + 6].copy_from_slice(&value.to_le_bytes());
                cursor += 6;
                output[cursor..cursor + field.name.len()].copy_from_slice(field.name);
                cursor += field.name.len();
                output[cursor..cursor + field.value.len()].copy_from_slice(field.value);
                cursor += field.value.len();
            }
            let count = u32::try_from(count).map_err(|_| Error::Limit)?;
            let length = u32::try_from(cursor - header - 8).map_err(|_| Error::Limit)?;
            output[header..header + 4].copy_from_slice(&count.to_le_bytes());
            output[header + 4..header + 8].copy_from_slice(&length.to_le_bytes());
        }
        validate(output)
    }
}

/// Parses only four fixed map headers on a previously validated entry.
pub(super) fn view(bytes: &[u8]) -> Result<Metadata<'_>, Error> {
    let mode = number::<2>(bytes, 0)? as u16;
    let flags = number::<2>(bytes, 2)?;
    if flags & !7 != 0 || mode > 0x0fff || (flags & 1 == 0 && mode != 0) {
        return Err(Error::Encoding);
    }
    let mut cursor = 4usize;
    let mut map = || {
        let count = number::<4>(bytes, cursor)? as u32;
        let length = offset32(bytes, cursor + 4)?;
        cursor = cursor.checked_add(8).ok_or(Error::Encoding)?;
        let end = cursor.checked_add(length).ok_or(Error::Encoding)?;
        let fields = Fields {
            bytes: bytes.get(cursor..end).ok_or(Error::Encoding)?,
            count,
        };
        cursor = end;
        Ok::<_, Error>(fields)
    };
    let result = Metadata {
        mode: (flags & 1 != 0).then_some(mode),
        attributes: map()?,
        xattrs: map()?,
        root_properties: map()?,
        graft_overrides: map()?,
        attributes_present: flags & 2 != 0,
        xattrs_present: flags & 4 != 0,
    };
    if cursor != bytes.len()
        || (!result.attributes_present && !result.attributes.is_empty())
        || (!result.xattrs_present && !result.xattrs.is_empty())
    {
        return Err(Error::Encoding);
    }
    Ok(result)
}

enum ValueEncoding {
    Cbor,
    Raw,
    Property,
}

/// Canonical value validation belongs at open, never in hot-path field access.
pub(super) fn validate(bytes: &[u8]) -> Result<(), Error> {
    let metadata = view(bytes)?;
    for (fields, encoding, limit) in [
        (metadata.attributes, ValueEncoding::Cbor, MAX_ATTRIBUTES),
        (metadata.xattrs, ValueEncoding::Raw, MAX_NODE_ITEMS_BYTES),
        (
            metadata.root_properties,
            ValueEncoding::Property,
            MAX_NODE_ITEMS_BYTES,
        ),
        (
            metadata.graft_overrides,
            ValueEncoding::Property,
            MAX_NODE_ITEMS_BYTES,
        ),
    ] {
        if fields.count as usize > limit {
            return Err(Error::Encoding);
        }
        let mut iterator = fields.iter();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..fields.count {
            let field = iterator.next().ok_or(Error::Encoding)?;
            if field.name.is_empty()
                || field.name.len() > MAX_COMPONENT
                || field.value.len() > MAX_NODE_ITEMS_BYTES
                || previous.is_some_and(|name| (name.len(), name) >= (field.name.len(), field.name))
            {
                return Err(Error::Encoding);
            }
            match encoding {
                ValueEncoding::Raw => {}
                ValueEncoding::Property => {
                    std::str::from_utf8(field.name).map_err(|_| Error::Encoding)?;
                    terrane_format::tree_format::validate_property_value(field.value)
                        .map_err(|_| Error::Encoding)?;
                }
                ValueEncoding::Cbor => {
                    std::str::from_utf8(field.name).map_err(|_| Error::Encoding)?;
                    let mut decoder = Decoder::new(field.value);
                    decoder
                        .raw_value(MAX_NODE_ITEMS_BYTES)
                        .map_err(|_| Error::Encoding)?;
                    decoder.finish().map_err(|_| Error::Encoding)?;
                }
            }
            previous = Some(field.name);
        }
        if !iterator.fields.bytes.is_empty() {
            return Err(Error::Encoding);
        }
    }
    Ok(())
}
