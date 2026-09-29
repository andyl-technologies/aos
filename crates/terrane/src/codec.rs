//! Encodes independent zstd chunk frames and inspects untrusted frames.
//!
//! Frame metadata and output limits are checked before zstd receives a
//! destination buffer. Decoded bytes stay private until identity and
//! boundary checks produce a [`VerifiedChunk`].

//! ```text
//! raw: 0x00 || plaintext
//! zstd: 0x01 || single_sized_frame
//! dictionary: 0x02 || dictionary_chunk_digest[32] || single_sized_frame
//! ```

use std::{fmt, io};

use terrane_core::{
    chunking::ChunkProfile,
    codec::{self, Codec, CodecError, EncodedChunk},
    identity::{Identity, IdentityError, IdentityKind, TERRANE_V1},
};

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
    /// The supplied dictionary has a different identity than the envelope.
    WrongDictionary,
    /// The offered identity uses a domain other than the chunk domain.
    WrongIdentityKind,
    /// The offered identity or a computed identity is invalid.
    Identity(IdentityError),
    /// A zstd operation failed.
    Zstd(io::Error),
    /// The actual plaintext length differs from its declaration.
    PlaintextLengthMismatch,
    /// A non-final chunk is shorter than the profile minimum.
    NonfinalChunkTooShort,
    /// A non-final chunk does not end at its first profile boundary.
    BoundaryMismatch,
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
            Self::WrongDictionary => f.write_str("supplied dictionary has another identity"),
            Self::WrongIdentityKind => f.write_str("offered identity is not a chunk identity"),
            Self::Identity(error) => write!(f, "chunk identity verification failed: {error}"),
            Self::Zstd(error) => write!(f, "zstd operation failed: {error}"),
            Self::PlaintextLengthMismatch => {
                f.write_str("decoded chunk length differs from declaration")
            }
            Self::NonfinalChunkTooShort => {
                f.write_str("non-final chunk is shorter than the profile minimum")
            }
            Self::BoundaryMismatch => {
                f.write_str("non-final chunk ends at a noncanonical boundary")
            }
            Self::MixedCodecs => f.write_str("chunks cannot be passed through as one zstd stream"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Envelope(error) => Some(error),
            Self::Identity(error) => Some(error),
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

impl From<IdentityError> for FrameError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
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
/// The dictionary is selected by the caller's content classification. Its
/// envelope identity is computed from its plaintext in the chunk domain.
///
/// # Errors
///
/// Returns an error when the plaintext exceeds the profile maximum, zstd
/// compression or identity calculation fails, or the generated frame lacks
/// its content-size header.
pub fn encode_chunk(
    plaintext: &[u8],
    profile_max: usize,
    compression_level: i32,
    dictionary: Option<&[u8]>,
) -> Result<Vec<u8>, FrameError> {
    if plaintext.len() > profile_max || dictionary.is_some_and(|bytes| bytes.len() > profile_max) {
        return Err(FrameError::Envelope(CodecError::DeclaredLengthTooLarge));
    }

    let mut compressor = match dictionary {
        Some(bytes) => zstd::bulk::Compressor::with_dictionary(compression_level, bytes),
        None => zstd::bulk::Compressor::new(compression_level),
    }
    .map_err(FrameError::Zstd)?;
    let frame = compressor.compress(plaintext).map_err(FrameError::Zstd)?;
    let body_len = frame
        .len()
        .saturating_add(usize::from(dictionary.is_some()) * codec::DICTIONARY_ID_SIZE);

    if (body_len as u128 * 100) >= (plaintext.len() as u128 * 97) {
        let mut encoded = Vec::with_capacity(plaintext.len() + 1);
        encoded.push(0x00);
        encoded.extend_from_slice(plaintext);
        return Ok(encoded);
    }

    let mut encoded = Vec::with_capacity(frame.len() + 33);
    if let Some(dictionary_bytes) = dictionary {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, dictionary_bytes)?
            .terrane_v1_digest()?;
        encoded.push(0x02);
        encoded.extend_from_slice(&identity);
    } else {
        encoded.push(0x01);
    }
    encoded.extend_from_slice(&frame);
    inspect_chunk(&encoded, plaintext.len(), profile_max)?;
    Ok(encoded)
}

/// A chunk whose frame, plaintext, identity, and boundary passed admission.
///
/// Its borrowed envelope is immutable for the lifetime of the verification
/// result. Callers may admit the plaintext and the original frame only after
/// receiving this value.
#[derive(Debug)]
pub struct VerifiedChunk<'a> {
    plaintext: Vec<u8>,
    identity: Identity,
    encoded: &'a [u8],
    codec: Codec,
}

impl VerifiedChunk<'_> {
    /// Borrows the verified plaintext.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// Borrows the verified chunk identity.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the codec that was checked on admission.
    #[must_use]
    pub const fn codec(&self) -> Codec {
        self.codec
    }

    /// Borrows the verified stored envelope.
    #[must_use]
    pub const fn encoded(&self) -> &[u8] {
        self.encoded
    }
}

/// Privately decodes and verifies an offered chunk before it can be admitted.
///
/// The caller marks the final chunk so that a short EOF chunk is permitted.
/// For codec `0x02`, the caller must provide the exact dictionary named by
/// the envelope. No plaintext is exposed until all checks have passed.
///
/// # Errors
///
/// Returns an error for malformed envelopes or frames, missing or mismatched
/// dictionaries, decompression failure, length or identity mismatch, a
/// non-final short chunk, or a noncanonical non-final boundary.
pub fn decode_verified<'a>(
    encoded: &'a [u8],
    declared_plaintext_len: usize,
    profile: &ChunkProfile,
    final_chunk: bool,
    expected_identity: &Identity,
    dictionary: Option<&[u8]>,
) -> Result<VerifiedChunk<'a>, FrameError> {
    if expected_identity.kind() != IdentityKind::Chunk {
        return Err(FrameError::WrongIdentityKind);
    }
    if !final_chunk && declared_plaintext_len < profile.minimum() {
        return Err(FrameError::NonfinalChunkTooShort);
    }

    let chunk = inspect_chunk(encoded, declared_plaintext_len, profile.maximum())?;
    if let Codec::ZstdDictionary(dictionary_id) = chunk.codec {
        let dictionary_bytes = dictionary.ok_or(FrameError::MissingDictionary)?;
        if dictionary_bytes.len() > profile.maximum() {
            return Err(FrameError::Envelope(CodecError::DeclaredLengthTooLarge));
        }
        let actual_id = TERRANE_V1
            .calculate(IdentityKind::Chunk, dictionary_bytes)?
            .terrane_v1_digest()?;
        if actual_id != dictionary_id {
            return Err(FrameError::WrongDictionary);
        }
    }

    let plaintext = decompress_bounded(chunk, declared_plaintext_len, dictionary)?;
    TERRANE_V1.verify(expected_identity, &plaintext)?;
    if !final_chunk && !profile.valid_nonfinal_chunk(&plaintext) {
        return Err(FrameError::BoundaryMismatch);
    }

    Ok(VerifiedChunk {
        plaintext,
        identity: expected_identity.clone(),
        encoded,
        codec: chunk.codec,
    })
}

/// Returns stored frames in manifest order for compressed pass-through.
///
/// Input chunks must already have passed [`decode_verified`].
///
/// # Errors
///
/// Returns an error for raw or mixed codecs, or different dictionary IDs.
pub fn frames_for_passthrough<'a>(
    chunks: &'a [VerifiedChunk<'a>],
) -> Result<Vec<&'a [u8]>, FrameError> {
    if chunks.is_empty() {
        return Err(FrameError::MixedCodecs);
    }

    let mut frames = Vec::new();
    let mut codec = None;

    for chunk in chunks {
        if matches!(chunk.codec, Codec::Raw) || codec.is_some_and(|first| first != chunk.codec) {
            return Err(FrameError::MixedCodecs);
        }
        codec = Some(chunk.codec);
        let envelope = codec::parse_envelope(chunk.encoded)?;
        frames.push(envelope.body);
    }

    Ok(frames)
}

// The public receiver exposes only the fully verified result.
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
#[allow(clippy::expect_used)]
mod tests {
    use std::io::{Read, Write};

    use super::{
        FrameError, decode_verified, decompress_bounded, encode_chunk, frames_for_passthrough,
        inspect_chunk,
    };
    use terrane_core::{
        chunking::ChunkProfile,
        codec::Codec,
        identity::{Identity, IdentityKind, TERRANE_V1},
    };

    const MAX: usize = 4 * 1024 * 1024;

    fn identity(bytes: &[u8]) -> Identity {
        TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .expect("chunk identity")
    }

    #[test]
    fn dictionary_plaintext_must_fit_a_standalone_final_chunk() {
        let dictionary = vec![3; 65];
        assert!(matches!(
            encode_chunk(b"abc", 64, 3, Some(&dictionary)),
            Err(FrameError::Envelope(_))
        ));

        let profile = ChunkProfile::new(16, 32, 64, 48, 2, [0; 32]).expect("profile");
        let plaintext = vec![4; 32];
        let mut encoded = vec![0x02];
        encoded.extend_from_slice(identity(&dictionary).digest());
        let frame = zstd::bulk::Compressor::with_dictionary(3, &dictionary)
            .expect("compressor")
            .compress(&plaintext)
            .expect("frame");
        encoded.extend_from_slice(&frame);
        assert!(matches!(
            decode_verified(
                &encoded,
                plaintext.len(),
                &profile,
                true,
                &identity(&plaintext),
                Some(&dictionary)
            ),
            Err(FrameError::Envelope(_))
        ));
    }

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
    fn bounded_decoder_rejects_a_frame_with_false_content_size() {
        let frame = zstd::bulk::compress(&vec![0_u8; 8192], 3).expect("compress");
        let mut forged = None;
        for position in 5..frame.len().min(10) {
            for byte in 0..=u8::MAX {
                let mut candidate = frame.clone();
                candidate[position] = byte;
                if matches!(
                    zstd::zstd_safe::get_frame_content_size(&candidate),
                    Ok(Some(256))
                ) {
                    forged = Some(candidate);
                    break;
                }
            }
            if forged.is_some() {
                break;
            }
        }
        let forged = forged.expect("fixture permits a one-byte false size");
        let mut encoded = vec![0x01];
        encoded.extend_from_slice(&forged);
        let inspected = inspect_chunk(&encoded, 256, MAX).expect("header declares 256 bytes");

        assert!(decompress_bounded(inspected, 256, None).is_err());
        let profile = ChunkProfile::cdc_1m([0; 32]);
        assert!(
            decode_verified(&encoded, 256, &profile, true, &identity(&[0; 256]), None,).is_err()
        );
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
        assert!(frames_for_passthrough(&[]).is_err());

        let first = vec![b'a'; 16 * 1024];
        let second = vec![b'b'; 16 * 1024];
        let a = encode_chunk(&first, MAX, 3, None).expect("first frame");
        let b = encode_chunk(&second, MAX, 3, None).expect("second frame");
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let a = decode_verified(&a, first.len(), &profile, true, &identity(&first), None)
            .expect("verify first");
        let b = decode_verified(&b, second.len(), &profile, true, &identity(&second), None)
            .expect("verify second");
        let verified = [a, b];
        let frames = frames_for_passthrough(&verified).expect("compatible frames");
        let stream: Vec<u8> = frames.into_iter().flatten().copied().collect();
        let decoded = zstd::stream::decode_all(&stream[..]).expect("concatenated decoding");

        assert_eq!(decoded, [first, second].concat());
    }

    #[test]
    fn dictionary_frames_require_the_same_verified_dictionary() {
        let dictionary = b"content class vocabulary and recurring prefix";
        let other_dictionary = b"another content class with different terms";
        let first = vec![b'a'; 16 * 1024];
        let second = vec![b'b'; 16 * 1024];
        let profile = ChunkProfile::cdc_1m([0; 32]);

        let a = encode_chunk(&first, MAX, 3, Some(dictionary)).expect("first frame");
        let b = encode_chunk(&second, MAX, 3, Some(dictionary)).expect("second frame");
        let a = decode_verified(
            &a,
            first.len(),
            &profile,
            true,
            &identity(&first),
            Some(dictionary),
        )
        .expect("verify first");
        let b = decode_verified(
            &b,
            second.len(),
            &profile,
            true,
            &identity(&second),
            Some(dictionary),
        )
        .expect("verify second");
        let chunks = [a, b];
        let frames = frames_for_passthrough(&chunks).expect("same dictionary");
        let stream: Vec<u8> = frames.into_iter().flatten().copied().collect();
        let mut decoder = zstd::stream::Decoder::with_dictionary(&stream[..], dictionary)
            .expect("dictionary decoder");
        let mut decoded = Vec::new();
        decoder
            .read_to_end(&mut decoded)
            .expect("decode concatenated frames");
        assert_eq!(decoded, [first, second].concat());

        let b = encode_chunk(&[b'b'; 16 * 1024], MAX, 3, Some(other_dictionary))
            .expect("other dictionary frame");
        let other = decode_verified(
            &b,
            16 * 1024,
            &profile,
            true,
            &identity(&[b'b'; 16 * 1024]),
            Some(other_dictionary),
        )
        .expect("verify other dictionary");
        let [first_chunk, _second_chunk] = chunks;
        assert!(matches!(
            frames_for_passthrough(&[first_chunk, other]),
            Err(FrameError::MixedCodecs)
        ));
    }

    #[test]
    fn dictionary_codec_keeps_identity_outside_the_frame() {
        let dictionary = b"a recurring content class prefix and common vocabulary";
        let plaintext = vec![b'a'; 32 * 1024];
        let encoded =
            encode_chunk(&plaintext, MAX, 3, Some(dictionary)).expect("dictionary encoding");
        let parsed = inspect_chunk(&encoded, plaintext.len(), MAX).expect("dictionary frame");
        let dictionary_id = identity(dictionary).terrane_v1_digest().expect("digest");
        assert_eq!(parsed.codec, Codec::ZstdDictionary(dictionary_id));
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let verified = decode_verified(
            &encoded,
            plaintext.len(),
            &profile,
            true,
            &identity(&plaintext),
            Some(dictionary),
        )
        .expect("decode dictionary");
        assert_eq!(verified.plaintext(), plaintext);
        assert!(matches!(
            decode_verified(
                &encoded,
                plaintext.len(),
                &profile,
                true,
                &identity(&plaintext),
                None
            ),
            Err(FrameError::MissingDictionary)
        ));
        assert!(matches!(
            decode_verified(
                &encoded,
                plaintext.len(),
                &profile,
                true,
                &identity(&plaintext),
                Some(b"wrong dictionary")
            ),
            Err(FrameError::WrongDictionary)
        ));
    }

    #[test]
    fn admission_requires_identity_size_and_first_nonfinal_boundary() {
        let profile = ChunkProfile::new(4, 16, 64, 48, 2, [0; 32]).expect("small profile");
        let chunk = (0..=u8::MAX)
            .find_map(|seed| {
                let bytes: Vec<u8> = (0..64)
                    .map(|index| (index * 31 + usize::from(seed)) as u8)
                    .collect();
                let cut = profile.first_boundary(&bytes);
                (cut > 5).then(|| bytes[..cut].to_vec())
            })
            .expect("fixture with a nontrivial cut");
        let encoded = encode_chunk(&chunk, profile.maximum(), 3, None).expect("encode");
        let expected = identity(&chunk);
        let verified = decode_verified(&encoded, chunk.len(), &profile, false, &expected, None)
            .expect("canonical chunk");
        assert_eq!(verified.plaintext(), chunk);
        assert_eq!(verified.identity(), &expected);

        assert!(matches!(
            decode_verified(
                &encoded,
                chunk.len(),
                &profile,
                false,
                &identity(b"other"),
                None
            ),
            Err(FrameError::Identity(_))
        ));
        let wrong_kind = TERRANE_V1
            .calculate(IdentityKind::Manifest, &chunk)
            .expect("identity");
        assert!(matches!(
            decode_verified(&encoded, chunk.len(), &profile, false, &wrong_kind, None),
            Err(FrameError::WrongIdentityKind)
        ));

        let noncanonical = &chunk[..chunk.len() - 1];
        let encoded = encode_chunk(noncanonical, profile.maximum(), 3, None).expect("encode");
        assert!(matches!(
            decode_verified(
                &encoded,
                noncanonical.len(),
                &profile,
                false,
                &identity(noncanonical),
                None
            ),
            Err(FrameError::BoundaryMismatch)
        ));

        let short = encode_chunk(b"ab", profile.maximum(), 3, None).expect("encode");
        assert!(matches!(
            decode_verified(&short, 2, &profile, false, &identity(b"ab"), None),
            Err(FrameError::NonfinalChunkTooShort)
        ));
        assert!(decode_verified(&short, 2, &profile, true, &identity(b"ab"), None).is_ok());
    }
}
