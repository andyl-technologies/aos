//! Connects pack reads to bounded native raw, zstd, and dictionary decoding.
//!
//! Chunk envelopes carry the full dictionary digest; the pack's reserved
//! two-byte field does not select a dictionary. The runtime fetches missing
//! dictionaries through the ordinary content path before a local pack read.

use super::{BodyDecoder, PackError};
use std::collections::BTreeMap;
use terrane_core::chunking::ChunkProfile;
use terrane_core::codec::{Codec as ChunkCodec, parse_envelope};
use terrane_core::identity::{Digest, IdentityKind, TERRANE_V1};

/// A native decoder bounded by the configured chunk profile and verified identities.
///
/// Reads use the relaxed final-chunk boundary context because the pack index
/// does not encode final/nonfinal position. Store admission must separately
/// establish canonical chunk boundaries using the object's manifest context.
pub struct NativeBodyDecoder<'a> {
    profile: &'a ChunkProfile,
    dictionaries: Option<&'a BTreeMap<Digest, Vec<u8>>>,
}

impl<'a> NativeBodyDecoder<'a> {
    /// Creates a decoder with locally fetched dictionary plaintext indexed by digest.
    ///
    /// Every supplied dictionary is independently verified against its envelope
    /// identity by the native codec before decompression; map labels alone are
    /// never sufficient evidence of dictionary identity.
    pub const fn new(
        profile: &'a ChunkProfile,
        dictionaries: &'a BTreeMap<Digest, Vec<u8>>,
    ) -> Self {
        Self {
            profile,
            dictionaries: Some(dictionaries),
        }
    }

    /// Creates a raw/zstd decoder that explicitly rejects missing dictionaries.
    pub const fn without_dictionaries(profile: &'a ChunkProfile) -> Self {
        Self {
            profile,
            dictionaries: None,
        }
    }
}

impl BodyDecoder for NativeBodyDecoder<'_> {
    fn decode(
        &self,
        encoded: &[u8],
        plaintext_len: u32,
        dictionary_id: u16,
        expected_hash: &Digest,
    ) -> Result<Vec<u8>, PackError> {
        if dictionary_id != 0 {
            return Err(PackError::Reserved);
        }
        let envelope = parse_envelope(encoded).map_err(crate::codec::FrameError::Envelope)?;
        let dictionary = match envelope.codec {
            ChunkCodec::ZstdDictionary(identity) => self
                .dictionaries
                .and_then(|dictionaries| dictionaries.get(&identity))
                .map(Vec::as_slice),
            _ => None,
        };
        let identity = TERRANE_V1.from_digest(IdentityKind::Chunk, expected_hash)?;
        let verified = crate::codec::decode_verified(
            encoded,
            plaintext_len as usize,
            self.profile,
            true,
            &identity,
            dictionary,
        )?;
        Ok(verified.plaintext().to_vec())
    }
}
