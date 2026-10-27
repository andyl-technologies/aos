//! Owns canonical object manifests and identities computed from known chunks.
//!
//! Plaintext hashes are supplied by the writer's original streaming pass.
//! Encoding and identity calculation never fetch or reread chunk plaintext.
//!
//! ```text
//! {1: size, 2: [[chunk_digest, length], ...],
//!  3: {"blake3": plaintext_digest, ...}, 4: optional_media_type}
//! ```

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use crate::{
    cbor::{self, Decoder},
    chunking::ChunkProfile,
    identity::{Digest, Identity, IdentityError, IdentityKind, TERRANE_V1},
    tree_format::ContentRef,
};

/// A chunk identity and its plaintext length, in file order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRef {
    /// The digest in the `terrane-chunk-v1` domain.
    pub digest: Digest,
    /// The number of plaintext bytes.
    pub length: u64,
}

/// The canonical content metadata of a file larger than the inline threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    /// The total plaintext byte count.
    pub size: u64,
    /// The ordered chunk references, including the final chunk.
    pub chunks: Vec<ChunkRef>,
    /// Registered whole-file plaintext hashes, including BLAKE3.
    pub hashes: BTreeMap<String, Vec<u8>>,
    /// An advisory media type, preserved verbatim even when unknown.
    pub media_type: Option<String>,
}

/// A malformed encoding, invalid manifest, or identity mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Canonical CBOR decoding failed.
    Cbor(cbor::Error),
    /// The manifest violates its schema or active chunk profile.
    InvalidManifest,
    /// The requested identity does not match the canonical manifest.
    Identity(IdentityError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "invalid manifest CBOR: {error}"),
            Self::InvalidManifest => f.write_str("manifest violates schema or chunk profile"),
            Self::Identity(error) => write!(f, "invalid manifest identity: {error}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::InvalidManifest => None,
        }
    }
}

impl From<cbor::Error> for Error {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<IdentityError> for Error {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

fn hash_length(name: &str) -> Option<usize> {
    match name {
        "blake3" | "sha256" | "git-blob-sha256" => Some(32),
        "sha512" => Some(64),
        "git-blob-sha1" => Some(20),
        _ => None,
    }
}

impl Manifest {
    /// Validates sizes, chunk count, and registered plaintext hash lengths.
    ///
    /// Non-final boundary verification remains the chunk admission path's job;
    /// this metadata-only check does not fetch already admitted chunks.
    ///
    /// # Errors
    /// Rejects missing hashes, invalid chunk lengths, overflow, or a size sum
    /// and chunk count inconsistent with the active profile.
    pub fn validate(&self, profile: &ChunkProfile) -> Result<(), Error> {
        let minimum = profile.minimum() as u64;
        let maximum = profile.maximum() as u64;
        let count_limit = self.size.div_ceil(minimum).saturating_add(1);
        if self.chunks.is_empty() || self.chunks.len() as u64 > count_limit {
            return Err(Error::InvalidManifest);
        }

        // The empty object has globally known chunk and plaintext identities;
        // accepting arbitrary digests would invent content without any bytes.
        if self.size == 0 {
            let empty_chunk = TERRANE_V1
                .calculate(IdentityKind::Chunk, &[])?
                .terrane_v1_digest()?;
            let empty_hash = blake3::hash(&[]);
            if self.chunks[0].digest != empty_chunk
                || self.hashes.get("blake3").map(Vec::as_slice)
                    != Some(empty_hash.as_bytes().as_slice())
            {
                return Err(Error::InvalidManifest);
            }
        }

        let mut total = 0_u64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            let final_chunk = index + 1 == self.chunks.len();
            if chunk.length > maximum
                || (!final_chunk && chunk.length < minimum)
                || (chunk.length == 0 && self.size != 0)
            {
                return Err(Error::InvalidManifest);
            }
            total = total
                .checked_add(chunk.length)
                .ok_or(Error::InvalidManifest)?;
        }
        if total != self.size || (self.size <= minimum && self.chunks.len() != 1) {
            return Err(Error::InvalidManifest);
        }
        if !self.hashes.contains_key("blake3")
            || self
                .hashes
                .iter()
                .any(|(name, digest)| hash_length(name) != Some(digest.len()))
        {
            return Err(Error::InvalidManifest);
        }
        Ok(())
    }

    /// Encodes the manifest with deterministic CBOR map ordering.
    ///
    /// # Errors
    /// Rejects metadata that fails [`Self::validate`].
    pub fn encode(&self, profile: &ChunkProfile) -> Result<Vec<u8>, Error> {
        self.validate(profile)?;
        let mut output = Vec::new();
        cbor::write_map(&mut output, 3 + usize::from(self.media_type.is_some()));
        cbor::write_uint(&mut output, 1);
        cbor::write_uint(&mut output, self.size);
        cbor::write_uint(&mut output, 2);
        cbor::write_array(&mut output, self.chunks.len());
        for chunk in &self.chunks {
            cbor::write_array(&mut output, 2);
            cbor::write_bytes(&mut output, &chunk.digest);
            cbor::write_uint(&mut output, chunk.length);
        }
        cbor::write_uint(&mut output, 3);
        cbor::write_map(&mut output, self.hashes.len());
        let mut hashes: Vec<_> = self.hashes.iter().collect();
        // Registered names are shorter than 24 bytes, so encoded order is
        // length first and lexicographic second.
        hashes.sort_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
        for (name, digest) in hashes {
            cbor::write_text(&mut output, name);
            cbor::write_bytes(&mut output, digest);
        }
        if let Some(media_type) = &self.media_type {
            cbor::write_uint(&mut output, 4);
            cbor::write_text(&mut output, media_type);
        }
        Ok(output)
    }

    /// Computes object identity using known chunk identities and content hashes.
    ///
    /// # Errors
    /// Rejects invalid metadata or an identity profile failure.
    pub fn identity(&self, profile: &ChunkProfile) -> Result<Identity, Error> {
        Ok(TERRANE_V1.calculate(IdentityKind::Manifest, &self.encode(profile)?)?)
    }

    /// Selects an inline chunk for small files and a manifest for larger files.
    ///
    /// Plaintext hashes of inline files remain available in `hashes` for entry
    /// attributes; they do not create a separate object identity.
    ///
    /// # Errors
    /// Rejects invalid metadata or an identity calculation failure.
    pub fn content_ref(&self, profile: &ChunkProfile) -> Result<ContentRef, Error> {
        self.validate(profile)?;
        if self.size <= profile.minimum() as u64 {
            let chunk = self.chunks.first().ok_or(Error::InvalidManifest)?;
            Ok(ContentRef::Inline(chunk.digest))
        } else {
            Ok(ContentRef::Manifest(
                self.identity(profile)?.terrane_v1_digest()?,
            ))
        }
    }

    /// Decodes and validates one canonical manifest without fetching chunks.
    ///
    /// Collection and string allocations are bounded by the supplied input.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, unknown or missing fields, invalid digest
    /// lengths, trailing bytes, or metadata inconsistent with the profile.
    pub fn decode(input: &[u8], profile: &ChunkProfile) -> Result<Self, Error> {
        let mut decoder = Decoder::new(input);
        let fields = decoder.map(4)?;
        if !(3..=4).contains(&fields) || decoder.uint()? != 1 {
            return Err(Error::InvalidManifest);
        }
        let size = decoder.uint()?;
        if decoder.uint()? != 2 {
            return Err(Error::InvalidManifest);
        }
        let count_limit = size.div_ceil(profile.minimum() as u64).saturating_add(1);
        let allocation_limit = usize::try_from(count_limit)
            .unwrap_or(usize::MAX)
            .min(input.len());
        let count = decoder.array(allocation_limit)?;
        let mut chunks = Vec::new();
        for _ in 0..count {
            if decoder.array(2)? != 2 {
                return Err(Error::InvalidManifest);
            }
            let digest = decoder
                .bytes(32)?
                .try_into()
                .map_err(|_| Error::InvalidManifest)?;
            chunks.push(ChunkRef {
                digest,
                length: decoder.uint()?,
            });
        }
        if decoder.uint()? != 3 {
            return Err(Error::InvalidManifest);
        }
        let count = decoder.map(input.len())?;
        let mut hashes = BTreeMap::new();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let start = decoder.position();
            let name = decoder.text(input.len())?;
            let encoded_name = decoder.slice(start, decoder.position())?;
            if previous.is_some_and(|key| key >= encoded_name) {
                return Err(Error::Cbor(cbor::Error::NonCanonical));
            }
            previous = Some(encoded_name);
            let length = hash_length(name).ok_or(Error::InvalidManifest)?;
            let digest = decoder.bytes(length)?;
            if digest.len() != length {
                return Err(Error::InvalidManifest);
            }
            hashes.insert(String::from(name), digest.to_vec());
        }
        let media_type = if fields == 4 {
            if decoder.uint()? != 4 {
                return Err(Error::InvalidManifest);
            }
            Some(String::from(decoder.text(input.len())?))
        } else {
            None
        };
        decoder.finish()?;
        let manifest = Self {
            size,
            chunks,
            hashes,
            media_type,
        };
        manifest.validate(profile)?;
        Ok(manifest)
    }

    /// Verifies the requested manifest identity before returning decoded metadata.
    ///
    /// # Errors
    /// Rejects another identity domain, a digest mismatch, or invalid metadata.
    pub fn decode_verified(
        input: &[u8],
        profile: &ChunkProfile,
        expected: &Identity,
    ) -> Result<Self, Error> {
        if expected.kind() != IdentityKind::Manifest {
            return Err(Error::InvalidManifest);
        }
        TERRANE_V1.verify(expected, input)?;
        Self::decode(input, profile)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
