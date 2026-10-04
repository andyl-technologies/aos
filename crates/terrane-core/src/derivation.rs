//! Owns the common immutable derivation memo record (DRV-21).
//!
//! A memo retains a recipe lookup hash and a claimed resulting root. Recipe
//! replay establishes their relationship separately under DRV-22. Index trees,
//! realization roots and materialized composites use this same record format.
//!
//! ```text
//! memo = {1: recipe-hash32, 2: result-root32}
//! ```
//!
//! The canonical encoding is 71 bytes. The recipe lookup key hashes the recipe;
//! the immutable memo identity hashes these record bytes. Both use the registered
//! `terrane-memo-v1` domain, including its terminating NUL.

use alloc::vec::Vec;
use core::fmt;

use crate::cbor::{self, Decoder};
use crate::identity::{Digest, IdentityError, IdentityKind, TERRANE_V1};

const ENCODED_BYTES: usize = 71;

/// A rejected common memo encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoError {
    /// Canonical CBOR parsing failed.
    Encoding(cbor::Error),
    /// Fields, their order, or digest lengths disagree with the memo schema.
    Schema,
    /// Input exceeds the exact canonical record's maximum size.
    Limit,
}

impl From<cbor::Error> for MemoError {
    fn from(error: cbor::Error) -> Self {
        Self::Encoding(error)
    }
}

impl fmt::Display for MemoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "invalid memo CBOR: {error}"),
            Self::Schema => formatter.write_str("invalid common memo fields"),
            Self::Limit => formatter.write_str("common memo input exceeds 71 bytes"),
        }
    }
}

impl core::error::Error for MemoError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            Self::Schema | Self::Limit => None,
        }
    }
}

/// Retains the common advisory association between a recipe and a resulting root.
///
/// Decoding establishes the two-field data contract. Recipe evaluation must
/// independently establish the association before its result is served; this
/// value itself carries no producer, trust, coverage or publication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Memo {
    recipe_hash: Digest,
    result_root: Digest,
}

impl Memo {
    /// Creates a memo claim from the recipe lookup hash and resulting Node root.
    pub const fn new(recipe_hash: Digest, result_root: Digest) -> Self {
        Self {
            recipe_hash,
            result_root,
        }
    }

    /// Decodes the exact common canonical memo schema.
    ///
    /// # Errors
    /// Rejects oversized, malformed or noncanonical input, missing, duplicate,
    /// reordered or unknown fields, non-32-byte digests and trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, MemoError> {
        if encoded.len() > ENCODED_BYTES {
            return Err(MemoError::Limit);
        }

        let mut decoder = Decoder::new(encoded);
        if decoder.map(2)? != 2 || decoder.uint()? != 1 {
            return Err(MemoError::Schema);
        }
        let recipe_hash = decoder
            .bytes(32)?
            .try_into()
            .map_err(|_| MemoError::Schema)?;
        if decoder.uint()? != 2 {
            return Err(MemoError::Schema);
        }
        let result_root = decoder
            .bytes(32)?
            .try_into()
            .map_err(|_| MemoError::Schema)?;
        decoder.finish()?;

        Ok(Self::new(recipe_hash, result_root))
    }

    /// Returns the recipe lookup hash retained in field 1.
    pub const fn recipe_hash(&self) -> Digest {
        self.recipe_hash
    }

    /// Returns the claimed resulting Node root retained in field 2.
    pub const fn result_root(&self) -> Digest {
        self.result_root
    }

    /// Encodes the common memo in canonical field order.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(ENCODED_BYTES);
        cbor::write_map(&mut encoded, 2);
        cbor::write_uint(&mut encoded, 1);
        cbor::write_bytes(&mut encoded, &self.recipe_hash);
        cbor::write_uint(&mut encoded, 2);
        cbor::write_bytes(&mut encoded, &self.result_root);
        encoded
    }

    /// Computes the immutable record identity from its canonical encoded bytes.
    ///
    /// This address is distinct from the recipe lookup key in field 1.
    ///
    /// # Errors
    /// Returns an identity error if the registered Memo domain cannot identify
    /// these bytes in the Terrane v1 profile.
    pub fn identity(&self) -> Result<Digest, IdentityError> {
        TERRANE_V1
            .calculate(IdentityKind::Memo, &self.encode())?
            .terrane_v1_digest()
    }
}

#[cfg(test)]
mod record_tests;
