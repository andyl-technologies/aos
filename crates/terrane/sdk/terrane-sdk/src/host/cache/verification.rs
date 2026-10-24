//! Inspects standalone codec envelopes under existing CDC-12/CDC-13 bounds.

use crate::codec::{FrameError, inspect_chunk};
use terrane_format::{
    chunking::ChunkProfile,
    codec::{Codec, CodecError},
};

/// Returns a standalone envelope's checked declared plaintext length.
///
/// This is structural inspection, not identity verification or admission.
/// Callers must still decode and hash the plaintext before using it.
///
/// # Errors
/// Rejects malformed envelopes, unknown frame sizes, concatenated frames,
/// profile-limit violations and compressed bodies exceeding CDC-13.
pub fn inspect_standalone_length(
    encoded: &[u8],
    profile: &ChunkProfile,
) -> Result<usize, FrameError> {
    let envelope = terrane_format::codec::parse_envelope(encoded)?;
    let length = match envelope.codec {
        Codec::Raw => envelope.body.len(),
        Codec::Zstd | Codec::ZstdDictionary(_) => {
            zstd::zstd_safe::get_frame_content_size(envelope.body)
                .map_err(|_| FrameError::InvalidFrame)?
                .ok_or(FrameError::UnknownContentSize)?
                .try_into()
                .map_err(|_| FrameError::Envelope(CodecError::DeclaredLengthTooLarge))?
        }
    };
    inspect_chunk(encoded, length, profile.maximum())?;
    Ok(length)
}

/// Returns an allocation bound for one valid encoded chunk under CDC-13.
///
/// The bound includes the codec byte and dictionary identity. It is a memory
/// read limit, not a filesystem reservation or a new accepted format limit.
///
/// # Errors
/// Returns a limit error when arithmetic cannot represent the profile bound.
pub fn maximum_encoded_chunk_bytes(profile: &ChunkProfile) -> Result<usize, FrameError> {
    profile
        .maximum()
        .checked_add(profile.maximum() / 100)
        .and_then(|size| size.checked_add(terrane_format::codec::FRAME_OVERHEAD_BYTES))
        .and_then(|size| size.checked_add(33))
        .ok_or(FrameError::Envelope(CodecError::DeclaredLengthTooLarge))
}
