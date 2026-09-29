//! Parses chunk codec envelopes and enforces limits before decompression.
//!
//! A stored chunk starts with a codec byte. Dictionary-coded chunks carry a
//! 32-byte dictionary identity before the zstd frame. Frame inspection and
//! decompression live in the portable `terrane` crate; this module performs
//! checks that need neither zstd nor a system allocator.

//! ```text
//! raw: 0x00 || plaintext
//! zstd: 0x01 || single_sized_frame
//! dictionary: 0x02 || dictionary_chunk_digest[32] || single_sized_frame
//! ```

use core::fmt;

/// The number of bytes in a `terrane-v1` dictionary identity.
pub const DICTIONARY_ID_SIZE: usize = 32;

/// The fixed part of the permitted zstd frame overhead, in bytes.
pub const FRAME_OVERHEAD_BYTES: usize = 128;

/// The compression applied to a chunk body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Codec {
    /// The body is the plaintext bytes.
    Raw,
    /// The body is exactly one zstd frame.
    Zstd,
    /// The body is exactly one zstd frame using the named dictionary.
    ZstdDictionary([u8; DICTIONARY_ID_SIZE]),
}

/// A parsed chunk envelope whose body excludes the codec and dictionary ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedChunk<'a> {
    /// The codec described by the envelope.
    pub codec: Codec,
    /// The raw bytes or a single zstd frame.
    pub body: &'a [u8],
}

/// A malformed chunk envelope or a violation of its declared size bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The envelope has no codec byte.
    MissingCodec,
    /// The codec byte has no registered meaning.
    UnknownCodec(u8),
    /// A dictionary-coded chunk does not contain a complete identity.
    TruncatedDictionaryIdentity,
    /// The declared plaintext exceeds the active chunk profile's maximum.
    DeclaredLengthTooLarge,
    /// The body length cannot be the declared raw plaintext length.
    RawLengthMismatch,
    /// A compressed body exceeds the profile's allowed frame overhead.
    CompressedLengthTooLarge,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCodec => f.write_str("chunk envelope has no codec byte"),
            Self::UnknownCodec(codec) => write!(f, "unknown chunk codec {codec:#04x}"),
            Self::TruncatedDictionaryIdentity => {
                f.write_str("dictionary-coded chunk has a truncated identity")
            }
            Self::DeclaredLengthTooLarge => {
                f.write_str("declared plaintext exceeds the chunk profile maximum")
            }
            Self::RawLengthMismatch => f.write_str("raw body differs from declared length"),
            Self::CompressedLengthTooLarge => {
                f.write_str("compressed body exceeds the frame overhead bound")
            }
        }
    }
}

impl core::error::Error for CodecError {}

/// Parses the codec byte and optional dictionary identity.
///
/// The dictionary identity is opaque here. A receiver must resolve and verify
/// the exact named dictionary before decoding the frame.
///
/// # Errors
///
/// Returns an error for an absent or unknown codec byte, or for an incomplete
/// dictionary identity.
pub fn parse_envelope(encoded: &[u8]) -> Result<EncodedChunk<'_>, CodecError> {
    let (&codec, body) = encoded.split_first().ok_or(CodecError::MissingCodec)?;

    let chunk = match codec {
        0x00 => EncodedChunk {
            codec: Codec::Raw,
            body,
        },
        0x01 => EncodedChunk {
            codec: Codec::Zstd,
            body,
        },
        0x02 => {
            let (identity, frame) = body
                .split_at_checked(DICTIONARY_ID_SIZE)
                .ok_or(CodecError::TruncatedDictionaryIdentity)?;
            let mut dictionary_id = [0; DICTIONARY_ID_SIZE];
            dictionary_id.copy_from_slice(identity);

            EncodedChunk {
                codec: Codec::ZstdDictionary(dictionary_id),
                body: frame,
            }
        }
        other => return Err(CodecError::UnknownCodec(other)),
    };

    Ok(chunk)
}

/// Checks the declared plaintext length and encoded body overhead.
///
/// The ratio check includes the dictionary ID in the encoded body and
/// compares integers without rounding away a fraction of a byte:
/// `100 * (encoded_body - plaintext) <= 12800 + plaintext`.
///
/// # Errors
///
/// Returns an error when the declared plaintext exceeds the profile maximum,
/// raw length disagrees with its declaration, or a compressed body exceeds
/// the permitted 128 bytes plus one percent overhead.
pub fn validate_envelope_size(
    chunk: EncodedChunk<'_>,
    declared_plaintext_len: usize,
    profile_max: usize,
) -> Result<(), CodecError> {
    if declared_plaintext_len > profile_max {
        return Err(CodecError::DeclaredLengthTooLarge);
    }

    match chunk.codec {
        Codec::Raw if chunk.body.len() != declared_plaintext_len => {
            Err(CodecError::RawLengthMismatch)
        }
        Codec::Raw => Ok(()),
        Codec::Zstd | Codec::ZstdDictionary(_) => {
            let encoded_body_len = chunk.body.len().saturating_add(
                usize::from(matches!(chunk.codec, Codec::ZstdDictionary(_))) * DICTIONARY_ID_SIZE,
            );
            let excess = encoded_body_len.saturating_sub(declared_plaintext_len) as u128;
            let scaled_excess = excess * 100;
            let scaled_allowance =
                (FRAME_OVERHEAD_BYTES as u128 * 100) + declared_plaintext_len as u128;

            if scaled_excess > scaled_allowance {
                Err(CodecError::CompressedLengthTooLarge)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{Codec, CodecError, EncodedChunk, parse_envelope, validate_envelope_size};

    #[test]
    fn parses_all_codec_envelopes_and_rejects_missing_fields() {
        assert_eq!(
            parse_envelope(&[0x00, 3]).map(|chunk| chunk.codec),
            Ok(Codec::Raw)
        );
        assert_eq!(
            parse_envelope(&[0x01, 7]).map(|chunk| chunk.codec),
            Ok(Codec::Zstd)
        );

        let mut encoded = alloc::vec![0x02];
        encoded.extend_from_slice(&[9; 32]);
        encoded.push(7);
        let chunk = parse_envelope(&encoded).expect("dictionary envelope");
        assert_eq!(chunk.codec, Codec::ZstdDictionary([9; 32]));
        assert_eq!(chunk.body, &[7]);

        assert_eq!(parse_envelope(&[]), Err(CodecError::MissingCodec));
        assert_eq!(parse_envelope(&[0xff]), Err(CodecError::UnknownCodec(0xff)));
        assert_eq!(
            parse_envelope(&[0x02, 0]),
            Err(CodecError::TruncatedDictionaryIdentity)
        );
    }

    #[test]
    fn checks_exact_fractional_overhead_and_profile_maximum() {
        let excess = [0; 230];
        let too_large = EncodedChunk {
            codec: Codec::Zstd,
            body: &excess,
        };
        assert_eq!(
            validate_envelope_size(too_large, 100, 100),
            Err(CodecError::CompressedLengthTooLarge),
        );
        assert_eq!(
            validate_envelope_size(too_large, 100, 99),
            Err(CodecError::DeclaredLengthTooLarge),
        );

        let permitted = [0; 229];
        let permitted = EncodedChunk {
            codec: Codec::Zstd,
            body: &permitted,
        };
        assert_eq!(validate_envelope_size(permitted, 100, 100), Ok(()));

        let raw = EncodedChunk {
            codec: Codec::Raw,
            body: &[1],
        };
        assert_eq!(
            validate_envelope_size(raw, 2, 100),
            Err(CodecError::RawLengthMismatch)
        );

        let dictionary_body = [0; 198];
        let dictionary_chunk = EncodedChunk {
            codec: Codec::ZstdDictionary([0; 32]),
            body: &dictionary_body,
        };
        assert_eq!(
            validate_envelope_size(dictionary_chunk, 100, 100),
            Err(CodecError::CompressedLengthTooLarge),
        );
    }
}
