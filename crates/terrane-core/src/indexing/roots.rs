//! Encodes owner-local attribute-to-Node bindings without inherited pointers.
//!
//! ```text
//! {"value": {"uid": "0000000000000000000000000000000000000000000000000000000000000000"}, "inherit": false}
//! ```

use alloc::vec::Vec;

use super::Error;
use crate::cbor::{self, Decoder};
use crate::identity::Digest;
use crate::properties::registered_attribute;

const MAX_BINDING_BYTES: usize = 65536;

/// A registered attribute and its unverified index Node digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexBinding<'a> {
    /// Registered name of the indexed attribute.
    pub attribute: &'a str,
    /// Digest naming a Node, whose contents require independent verification.
    pub node: Digest,
}

/// Validated owner-local bindings in canonical encoded-key order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexRoots<'a> {
    bindings: Vec<IndexBinding<'a>>,
}

impl<'a> IndexRoots<'a> {
    /// Decodes the exact noninherited `index-roots` property wrapper.
    ///
    /// # Errors
    /// Rejects bare values, inherited or extra fields, invalid attribute names,
    /// malformed hex digests, noncanonical CBOR, trailing bytes, or size limits.
    pub fn decode_binding(encoded: &'a [u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_BINDING_BYTES {
            return Err(Error::Limit);
        }

        let mut decoder = Decoder::new(encoded);
        if decoder.map(2)? != 2 || decoder.text(5)? != "value" {
            return Err(Error::Schema);
        }
        let start = decoder.position();
        scan_value(&mut decoder)?;
        let value = decoder.slice(start, decoder.position())?;
        if decoder.text(7)? != "inherit" || decoder.simple()? != 0xf4 {
            return Err(Error::Schema);
        }
        decoder.finish()?;

        Self::decode_value(value)
    }

    /// Decodes a canonical attribute-to-lowercase-hex map, without its wrapper.
    ///
    /// This value alone is useful as data; an explicit root property must use
    /// [`Self::decode_binding`] to enforce its noninheritance contract.
    ///
    /// # Errors
    /// Rejects invalid registered names, malformed digests, noncanonical maps,
    /// duplicate keys, trailing bytes, or input above 64 KiB.
    pub fn decode_value(encoded: &'a [u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_BINDING_BYTES {
            return Err(Error::Limit);
        }

        // Complete borrowed validation precedes any collection allocation.
        let mut scanner = Decoder::new(encoded);
        let count = scan_value(&mut scanner)?;
        scanner.finish()?;

        let mut decoder = Decoder::new(encoded);
        decoder.map(count)?;
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            bindings.push(read_binding(&mut decoder)?);
        }
        Ok(Self { bindings })
    }

    /// Borrows every binding in canonical encoded-key order.
    pub fn as_bindings(&self) -> &[IndexBinding<'a>] {
        &self.bindings
    }

    /// Returns this owner's binding for an attribute, without ancestor lookup.
    pub fn get(&self, attribute: &str) -> Option<Digest> {
        self.bindings
            .iter()
            .find(|binding| binding.attribute == attribute)
            .map(|binding| binding.node)
    }

    /// Encodes the canonical value map, without an inheritance wrapper.
    pub fn encode_value(&self) -> Vec<u8> {
        let mut output = Vec::new();
        cbor::write_map(&mut output, self.bindings.len());
        for binding in &self.bindings {
            cbor::write_text(&mut output, binding.attribute);
            cbor::write_argument(&mut output, 3, 64);
            for byte in binding.node {
                output.push(b"0123456789abcdef"[usize::from(byte >> 4)]);
                output.push(b"0123456789abcdef"[usize::from(byte & 15)]);
            }
        }
        output
    }

    /// Encodes the exact canonical noninherited property wrapper.
    ///
    /// # Errors
    /// Rejects a value whose wrapper would exceed the 64 KiB property limit.
    pub fn encode_binding(&self) -> Result<Vec<u8>, Error> {
        let value = self.encode_value();
        if value.len() > MAX_BINDING_BYTES - 16 {
            return Err(Error::Limit);
        }

        let mut output = Vec::new();
        cbor::write_map(&mut output, 2);
        cbor::write_text(&mut output, "value");
        output.extend_from_slice(&value);
        cbor::write_text(&mut output, "inherit");
        output.push(0xf4);
        Ok(output)
    }
}

fn scan_value(decoder: &mut Decoder<'_>) -> Result<usize, Error> {
    let count = decoder.map(MAX_BINDING_BYTES)?;
    // Every pair needs at least a nonempty name and a 66-byte hex string.
    if count > decoder.remaining().len() / 68 {
        return Err(Error::Limit);
    }

    let mut previous = None;
    for _ in 0..count {
        let start = decoder.position();
        let attribute = decoder.text(255)?;
        let key = decoder.slice(start, decoder.position())?;
        if previous.is_some_and(|prior| key <= prior) {
            return Err(Error::Cbor(cbor::Error::NonCanonical));
        }
        previous = Some(key);

        if !registered_attribute(attribute) {
            return Err(Error::UnknownAttribute);
        }
        decode_hex(decoder.text(64)?)?;
    }
    Ok(count)
}

fn read_binding<'a>(decoder: &mut Decoder<'a>) -> Result<IndexBinding<'a>, Error> {
    let attribute = decoder.text(255)?;
    let node = decode_hex(decoder.text(64)?)?;
    Ok(IndexBinding { attribute, node })
}

fn decode_hex(text: &str) -> Result<Digest, Error> {
    if text.len() != 64 {
        return Err(Error::Schema);
    }

    let mut digest = [0; 32];
    for (pair, byte) in text.as_bytes().as_chunks::<2>().0.iter().zip(&mut digest) {
        *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Ok(digest)
}

fn hex_digit(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::Schema),
    }
}
