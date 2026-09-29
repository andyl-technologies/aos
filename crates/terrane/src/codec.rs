//! Encodes independent zstd chunk frames and inspects untrusted frames.
//!
//! Frame metadata and output limits are checked before zstd receives a
//! destination buffer. Identity verification joins this code when the
//! identity profile implementation lands.

use std::{fmt, io};

use terrane_core::codec::{self, Codec, CodecError, EncodedChunk};

const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// A malformed zstd chunk or a failure to encode or decode it.
#[derive(Debug)]
pub enum FrameError {
    /// The surrounding codec envelope or its declared size is invalid.
    Envelope(CodecError),
    /// The body is not exactly one ordinary zstd frame.
    InvalidFrame,
    /// The zstd frame omits its decompressed content size.
    UnknownContentSize,
    /// The frame's content-size field differs from the declared chunk size.
    ContentSizeMismatch,
    /// The named dictionary was not supplied for decoding.
    MissingDictionary,
    /// A zstd operation failed.
    Zstd(io::Error),
    /// The actual plaintext length differs from its declaration.
    PlaintextLengthMismatch,
    /// Some chunks in a candidate pass-through stream use another codec.
    MixedCodecs,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(error) => write!(f, "invalid codec envelope: {error}"),
            Self::InvalidFrame => f.write_str("chunk body is not one ordinary zstd frame"),
            Self::UnknownContentSize => f.write_str("zstd frame omits content size"),
            Self::ContentSizeMismatch => {
                f.write_str("zstd frame content size differs from declaration")
            }
            Self::MissingDictionary => {
                f.write_str("dictionary-coded chunk requires its named dictionary")
            }
            Self::Zstd(error) => write!(f, "zstd operation failed: {error}"),
            Self::PlaintextLengthMismatch => {
                f.write_str("decoded chunk length differs from declaration")
            }
            Self::MixedCodecs => f.write_str("chunks cannot be passed through as one zstd stream"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Envelope(error) => Some(error),
            Self::Zstd(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodecError> for FrameError {
    fn from(error: CodecError) -> Self {
        Self::Envelope(error)
    }
}

/// Inspects an encoded chunk before allocating a decompression buffer.
///
/// This check rejects skippable frames, missing content sizes, truncation,
/// and extra trailing frames. A dictionary-coded body still requires the
/// named dictionary before decompression.
///
/// # Errors
///
/// Returns an error if envelope bounds fail, the frame is malformed or
/// concatenated, or its content size differs from the declaration.
pub fn inspect_chunk<'a>(
    encoded: &'a [u8],
    declared_plaintext_len: usize,
    profile_max: usize,
) -> Result<EncodedChunk<'a>, FrameError> {
    let chunk = codec::parse_envelope(encoded)?;
    codec::validate_envelope_size(chunk, declared_plaintext_len, profile_max)?;

    if matches!(chunk.codec, Codec::Raw) {
        return Ok(chunk);
    }

    if !chunk.body.starts_with(&ZSTD_FRAME_MAGIC) {
        return Err(FrameError::InvalidFrame);
    }

    let frame_len = zstd::zstd_safe::find_frame_compressed_size(chunk.body)
        .map_err(|_| FrameError::InvalidFrame)?;
    if frame_len != chunk.body.len() {
        return Err(FrameError::InvalidFrame);
    }

    let content_size = zstd::zstd_safe::get_frame_content_size(chunk.body)
        .map_err(|_| FrameError::InvalidFrame)?
        .ok_or(FrameError::UnknownContentSize)?;
    if content_size != declared_plaintext_len as u64 {
        return Err(FrameError::ContentSizeMismatch);
    }

    Ok(chunk)
}

/// Encodes one chunk, choosing raw storage when zstd saves less than 3%.
///
/// The dictionary is selected by the caller's content classification. The
/// caller supplies its already-verified chunk identity for the envelope.
///
/// # Errors
///
/// Returns an error when the plaintext exceeds the profile maximum, zstd
/// compression fails, or the generated frame lacks its content-size header.
pub fn encode_chunk(
    plaintext: &[u8],
    profile_max: usize,
    compression_level: i32,
    dictionary: Option<(&[u8], [u8; 32])>,
) -> Result<Vec<u8>, FrameError> {
    if plaintext.len() > profile_max {
        return Err(FrameError::Envelope(CodecError::DeclaredLengthTooLarge));
    }

    let mut compressor = match dictionary {
        Some((bytes, _)) => zstd::bulk::Compressor::with_dictionary(compression_level, bytes),
        None => zstd::bulk::Compressor::new(compression_level),
    }
    .map_err(FrameError::Zstd)?;
    let frame = compressor.compress(plaintext).map_err(FrameError::Zstd)?;

    if (frame.len() as u128 * 100) >= (plaintext.len() as u128 * 97) {
        let mut encoded = Vec::with_capacity(plaintext.len() + 1);
        encoded.push(0x00);
        encoded.extend_from_slice(plaintext);
        return Ok(encoded);
    }

    let mut encoded = Vec::with_capacity(frame.len() + 33);
    if let Some((_, identity)) = dictionary {
        encoded.push(0x02);
        encoded.extend_from_slice(&identity);
    } else {
        encoded.push(0x01);
    }
    encoded.extend_from_slice(&frame);
    inspect_chunk(&encoded, plaintext.len(), profile_max)?;
    Ok(encoded)
}

/// Returns stored frames in manifest order for compressed pass-through.
///
/// The input envelopes must have been admitted under the receiver rules.
///
/// # Errors
///
/// Returns an error for raw or mixed codecs, or different dictionary IDs.
pub fn frames_for_passthrough<'a>(
    chunks: impl IntoIterator<Item = EncodedChunk<'a>>,
) -> Result<Vec<&'a [u8]>, FrameError> {
    let mut frames = Vec::new();
    let mut codec = None;

    for chunk in chunks {
        if matches!(chunk.codec, Codec::Raw) || codec.is_some_and(|first| first != chunk.codec) {
            return Err(FrameError::MixedCodecs);
        }
        codec = Some(chunk.codec);
        frames.push(chunk.body);
    }

    Ok(frames)
}

// This stays private until identity and boundary verification can produce a
// `VerifiedChunk`; callers must never admit these bytes on their own.
#[cfg(test)]
fn decompress_bounded(
    chunk: EncodedChunk<'_>,
    declared_plaintext_len: usize,
    dictionary: Option<&[u8]>,
) -> Result<Vec<u8>, FrameError> {
    if matches!(chunk.codec, Codec::Raw) {
        return Ok(chunk.body.to_vec());
    }

    let mut decompressor = match chunk.codec {
        Codec::Zstd => zstd::bulk::Decompressor::new(),
        Codec::ZstdDictionary(_) => match dictionary {
            Some(bytes) => zstd::bulk::Decompressor::with_dictionary(bytes),
            None => return Err(FrameError::MissingDictionary),
        },
        Codec::Raw => return Ok(chunk.body.to_vec()),
    }
    .map_err(FrameError::Zstd)?;

    let mut plaintext = Vec::with_capacity(declared_plaintext_len);
    let actual = decompressor
        .decompress_to_buffer(chunk.body, &mut plaintext)
        .map_err(FrameError::Zstd)?;
    if actual != declared_plaintext_len {
        return Err(FrameError::PlaintextLengthMismatch);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{
        FrameError, decompress_bounded, encode_chunk, frames_for_passthrough, inspect_chunk,
    };
    use terrane_core::codec::Codec;

    const MAX: usize = 4 * 1024 * 1024;

    #[test]
    fn codec_writer_uses_raw_for_short_bytes_and_one_sized_frame_for_repetition() {
        let raw = encode_chunk(b"xy", MAX, 3, None).expect("raw encoding");
        assert_eq!(raw, b"\x00xy");

        let plaintext = vec![b'a'; 32 * 1024];
        let compressed = encode_chunk(&plaintext, MAX, 3, None).expect("zstd encoding");
        let parsed = inspect_chunk(&compressed, plaintext.len(), MAX).expect("valid frame");
        assert_eq!(parsed.codec, Codec::Zstd);
        assert_eq!(
            decompress_bounded(parsed, plaintext.len(), None).expect("decode"),
            plaintext
        );
    }

    #[test]
    fn rejects_bomb_header_truncated_frame_and_trailing_frame() {
        let frame = zstd::bulk::compress(&vec![0_u8; 4096], 3).expect("compress");
        let mut envelope = vec![0x01];
        envelope.extend_from_slice(&frame);

        assert!(matches!(
            inspect_chunk(&envelope, 0, MAX),
            Err(FrameError::ContentSizeMismatch)
        ));
        assert!(matches!(
            inspect_chunk(&envelope, MAX + 1, MAX),
            Err(FrameError::Envelope(_))
        ));

        let mut truncated = envelope.clone();
        truncated.pop();
        assert!(matches!(
            inspect_chunk(&truncated, 4096, MAX),
            Err(FrameError::InvalidFrame)
        ));

        let mut doubled = envelope.clone();
        doubled.extend_from_slice(&frame);
        assert!(matches!(
            inspect_chunk(&doubled, 4096, MAX),
            Err(FrameError::InvalidFrame)
        ));

        let skippable = [0x01, 0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        assert!(matches!(
            inspect_chunk(&skippable, 0, MAX),
            Err(FrameError::InvalidFrame)
        ));
    }

    #[test]
    fn rejects_unknown_content_size_from_streaming_writer() {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).expect("encoder");
        encoder.write_all(b"hello").expect("write");
        let frame = encoder.finish().expect("finish");
        let mut envelope = vec![0x01];
        envelope.extend_from_slice(&frame);

        assert!(matches!(
            inspect_chunk(&envelope, 5, MAX),
            Err(FrameError::UnknownContentSize)
        ));
    }

    #[test]
    fn same_codec_frames_concatenate_to_object_plaintext() {
        let first = vec![b'a'; 16 * 1024];
        let second = vec![b'b'; 16 * 1024];
        let a = encode_chunk(&first, MAX, 3, None).expect("first frame");
        let b = encode_chunk(&second, MAX, 3, None).expect("second frame");
        let a = inspect_chunk(&a, first.len(), MAX).expect("inspect first");
        let b = inspect_chunk(&b, second.len(), MAX).expect("inspect second");
        let frames = frames_for_passthrough([a, b]).expect("compatible frames");
        let stream: Vec<u8> = frames.into_iter().flatten().copied().collect();
        let decoded = zstd::stream::decode_all(&stream[..]).expect("concatenated decoding");

        assert_eq!(decoded, [first, second].concat());
    }

    #[test]
    fn dictionary_codec_keeps_identity_outside_the_frame() {
        let dictionary = b"a recurring content class prefix and common vocabulary";
        let plaintext = vec![b'a'; 32 * 1024];
        let encoded = encode_chunk(&plaintext, MAX, 3, Some((dictionary, [7; 32])))
            .expect("dictionary encoding");
        let parsed = inspect_chunk(&encoded, plaintext.len(), MAX).expect("dictionary frame");
        assert_eq!(parsed.codec, Codec::ZstdDictionary([7; 32]));
        assert_eq!(
            decompress_bounded(parsed, plaintext.len(), Some(dictionary))
                .expect("decode dictionary"),
            plaintext,
        );
        assert!(matches!(
            decompress_bounded(parsed, plaintext.len(), None),
            Err(FrameError::MissingDictionary)
        ));
    }
}
