//! Represents the closed index evaluation profile separately from retained recipes.
//!
//! ```text
//! {1: "index", 2: [owner32], 3: {"profile": "terrane-index/v1", "attribute": "uid"}}
//! ```

use alloc::vec::Vec;

use super::Error;
use crate::cbor::{self, Decoder};
use crate::identity::{Digest, IdentityError, IdentityKind, TERRANE_V1};
use crate::properties::registered_attribute;

/// The registered, closed v1 index evaluation profile.
pub const INDEX_EVALUATION_PROFILE: &str = "terrane-index/v1";

// Fixed fields require 81 bytes; the longest attribute's text header and body
// require 257 bytes. This bound also rejects oversized input before traversal.
const MAX_RECIPE_BYTES: usize = 338;

/// A detached index recipe naming an owner and one registered attribute.
///
/// The owner digest represents a completed root supplied by the caller. This
/// data type does not load that root or verify completion, coverage, producers,
/// or current authority. Generic retained recipes use their existing codecs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexEvaluationRecipe<'a> {
    owner: Digest,
    attribute: &'a str,
}

impl<'a> IndexEvaluationRecipe<'a> {
    /// Constructs the closed recipe data from an owner digest and attribute.
    ///
    /// # Errors
    /// Rejects unregistered attribute names, including empty or oversized names.
    pub fn new(owner: Digest, attribute: &'a str) -> Result<Self, Error> {
        if !registered_attribute(attribute) {
            return Err(Error::UnknownAttribute);
        }
        Ok(Self { owner, attribute })
    }

    /// Decodes exactly one owner operand and the two registered arguments.
    ///
    /// # Errors
    /// Rejects malformed or noncanonical CBOR, unknown/missing/duplicate fields,
    /// operand counts other than one, unsupported profiles, unregistered names,
    /// trailing bytes, or input above the maximum possible schema size.
    pub fn decode(encoded: &'a [u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_RECIPE_BYTES {
            return Err(Error::Limit);
        }

        let mut decoder = Decoder::new(encoded);
        if decoder.map(3)? != 3
            || decoder.uint()? != 1
            || decoder.text(5)? != "index"
            || decoder.uint()? != 2
            || decoder.array(1)? != 1
        {
            return Err(Error::Schema);
        }
        let owner = decoder.bytes(32)?.try_into().map_err(|_| Error::Schema)?;
        if decoder.uint()? != 3
            || decoder.map(2)? != 2
            || decoder.text(7)? != "profile"
            || decoder.text(16)? != INDEX_EVALUATION_PROFILE
            || decoder.text(9)? != "attribute"
        {
            return Err(Error::Schema);
        }
        let attribute = decoder.text(255)?;
        decoder.finish()?;

        Self::new(owner, attribute)
    }

    /// Returns the completed owner root's unverified digest.
    pub const fn owner(&self) -> Digest {
        self.owner
    }

    /// Borrows the indexed registered attribute name.
    pub const fn attribute(&self) -> &'a str {
        self.attribute
    }

    /// Returns the registered evaluation profile name.
    pub const fn profile(&self) -> &'static str {
        INDEX_EVALUATION_PROFILE
    }

    /// Encodes the detached recipe in canonical field and argument order.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        cbor::write_map(&mut output, 3);
        cbor::write_uint(&mut output, 1);
        cbor::write_text(&mut output, "index");
        cbor::write_uint(&mut output, 2);
        cbor::write_array(&mut output, 1);
        cbor::write_bytes(&mut output, &self.owner);
        cbor::write_uint(&mut output, 3);
        cbor::write_map(&mut output, 2);
        cbor::write_text(&mut output, "profile");
        cbor::write_text(&mut output, INDEX_EVALUATION_PROFILE);
        cbor::write_text(&mut output, "attribute");
        cbor::write_text(&mut output, self.attribute);
        output
    }

    /// Computes the recipe lookup key in the existing Memo identity domain.
    ///
    /// This lookup key is distinct from an encoded memo's own identity and
    /// carries no evidence that any memo or index is verified.
    ///
    /// # Errors
    /// Returns an identity error if the configured v1 identity calculation fails.
    pub fn identity(&self) -> Result<Digest, IdentityError> {
        TERRANE_V1
            .calculate(IdentityKind::Memo, &self.encode())?
            .terrane_v1_digest()
    }
}
