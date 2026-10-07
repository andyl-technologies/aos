//! Validates opaque index keys as canonical values followed by object digests.
//!
//! ```text
//! key = canonical-CBOR(attribute-value) || object-digest32
//! ```

use alloc::vec::Vec;

use super::Error;
use crate::cbor::Decoder;
use crate::identity::Digest;

/// The maximum complete opaque index key length, including its object digest.
pub const MAX_INDEX_KEY_BYTES: usize = 4096;

/// One exact canonical attribute representation paired with its object target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexKey<'a> {
    value: &'a [u8],
    object: Digest,
}

impl<'a> IndexKey<'a> {
    /// Constructs key data after validating the complete canonical value.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unsupported, trailing, or oversized
    /// value bytes before allocating the encoded key.
    pub fn new(value: &'a [u8], object: Digest) -> Result<Self, Error> {
        validate_value(value)?;
        Ok(Self { value, object })
    }

    /// Decodes an opaque key, borrowing the exact canonical value prefix.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical values, missing or extra digest bytes,
    /// trailing value representations, or keys longer than 4096 bytes.
    pub fn decode(encoded: &'a [u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_INDEX_KEY_BYTES || encoded.len() <= 32 {
            return Err(Error::Limit);
        }

        let (value, object) = encoded.split_at(encoded.len() - 32);
        let object = object.try_into().map_err(|_| Error::Schema)?;
        Self::new(value, object)
    }

    /// Borrows the complete canonical attribute value without normalization.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Returns the object digest carried by this key.
    pub const fn object(&self) -> Digest {
        self.object
    }

    /// Encodes the exact value bytes followed by the object digest.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.value.len() + 32);
        output.extend_from_slice(self.value);
        output.extend_from_slice(&self.object);
        output
    }

    /// Returns inclusive lower and upper keys for this exact value's objects.
    ///
    /// Unsigned byte comparison includes both endpoints and all object digests
    /// between them. Consumers must not treat the upper endpoint as exclusive.
    pub fn equality_bounds(&self) -> (Vec<u8>, Vec<u8>) {
        let lower = Self {
            value: self.value,
            object: [0; 32],
        }
        .encode();
        let upper = Self {
            value: self.value,
            object: [255; 32],
        }
        .encode();
        (lower, upper)
    }
}

fn validate_value(value: &[u8]) -> Result<(), Error> {
    if value.len() > MAX_INDEX_KEY_BYTES - 32 {
        return Err(Error::Limit);
    }

    let mut decoder = Decoder::new(value);
    decoder.skip_value(MAX_INDEX_KEY_BYTES - 32)?;
    decoder.finish()?;
    Ok(())
}
