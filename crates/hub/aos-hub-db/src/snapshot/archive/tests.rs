//! Framing-only authentication, terminal commitment and resource-limit tests.

use std::cell::Cell;
use std::io::{Cursor, Read, Write};
use std::rc::Rc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

use super::frames::{COMMITMENT_BYTES, FRAME_CAP, HEADER_BYTES, PREFIX_BYTES, TAG_BYTES};
use super::*;

fn context() -> StreamContext {
    StreamContext::new([42; 16], StreamRole::Private)
}

fn key(seed: u64) -> (FreshStreamKey, [u8; 32]) {
    // Deterministic RNG is a fixture only; production requires fresh entropy.
    let fresh = FreshStreamKey::generate(&mut StdRng::seed_from_u64(seed)).unwrap();
    let bytes = fresh.with_private_key_bytes(|bytes| *bytes);
    (fresh, bytes)
}

fn encode(input: &[u8], seed: u64) -> (Vec<u8>, [u8; 32], StreamSummary) {
    let (fresh, key) = key(seed);
    let mut encoder =
        StreamEncoder::new(Vec::new(), fresh, context(), StreamLimits::default()).unwrap();
    encoder.write_plaintext(input).unwrap();
    let (bytes, summary) = encoder.finish().unwrap();
    (bytes, key, summary)
}

fn decode(bytes: &[u8], key: [u8; 32]) -> anyhow::Result<(Vec<u8>, StreamSummary)> {
    let mut decoder = StreamDecoder::new(
        Cursor::new(bytes),
        StreamDecryptionKey::from_bytes(key),
        context(),
        StreamLimits::default(),
    )?;
    let mut plaintext = Vec::new();
    while let Some(chunk) = decoder.next_chunk()? {
        assert!(chunk.len() <= FRAME_CAP && !chunk.is_empty());
        chunk.with_private_bytes(|bytes| plaintext.extend_from_slice(bytes));
    }
    let summary = decoder.summary().unwrap().clone();
    assert!(decoder.next_chunk()?.is_none());
    Ok((plaintext, summary))
}

fn end_offset(bytes: &[u8]) -> usize {
    bytes.len() - PREFIX_BYTES - COMMITMENT_BYTES - TAG_BYTES
}

fn data_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut offset = HEADER_BYTES;
    let end = end_offset(bytes);
    let mut ranges = Vec::new();
    while offset < end {
        let length =
            u32::from_be_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()) as usize;
        let next = offset + PREFIX_BYTES + length;
        ranges.push(offset..next);
        offset = next;
    }
    assert_eq!(offset, end);
    ranges
}

#[test]
fn empty_binary_and_multiframe_round_trip_with_exact_complete_hash() {
    for size in [
        0,
        1,
        FRAME_CAP - 1,
        FRAME_CAP,
        FRAME_CAP + 1,
        3 * FRAME_CAP + 23,
    ] {
        let input = (0..size)
            .map(|index| (index % 256) as u8)
            .collect::<Vec<_>>();
        let (bytes, key, written) = encode(&input, 1);
        let (output, verified) = decode(&bytes, key).unwrap();
        assert_eq!(input, output);
        assert_eq!(written, verified);
        assert_eq!(verified.plaintext_bytes, size as u64);
        assert_eq!(
            verified.data_frames,
            (size as u64).div_ceil(FRAME_CAP as u64)
        );
        assert_eq!(verified.ciphertext_bytes, bytes.len() as u64);
        assert_eq!(
            verified.ciphertext_sha256,
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
    }
}

#[test]
fn write_partitioning_is_independent_of_arbitrary_typed_record_boundaries() {
    let input = b"{\"record\":\"PRIVATE\\n\"}\nnot-json\n\0\xff".repeat(30_000);
    let (bytes, _, expected) = encode(&input, 2);
    let (fresh, _) = key(2);
    let mut encoder =
        StreamEncoder::new(Vec::new(), fresh, context(), StreamLimits::default()).unwrap();
    encoder.write_plaintext(&[]).unwrap();
    for chunk in input.chunks(37) {
        encoder.write_plaintext(chunk).unwrap();
    }
    let (partitioned, summary) = encoder.finish().unwrap();
    assert_eq!(bytes, partitioned);
    assert_eq!(expected, summary);
}

#[test]
fn fresh_keys_and_retries_produce_different_ciphertexts() {
    let mut rng = StdRng::seed_from_u64(3);
    let first = FreshStreamKey::generate(&mut rng).unwrap();
    let second = FreshStreamKey::generate(&mut rng).unwrap();
    assert_ne!(
        first.with_private_key_bytes(|bytes| *bytes),
        second.with_private_key_bytes(|bytes| *bytes)
    );
    let mut a = StreamEncoder::new(Vec::new(), first, context(), StreamLimits::default()).unwrap();
    let mut b = StreamEncoder::new(Vec::new(), second, context(), StreamLimits::default()).unwrap();
    a.write_plaintext(b"PRIVATE").unwrap();
    b.write_plaintext(b"PRIVATE").unwrap();
    assert_ne!(a.finish().unwrap().0, b.finish().unwrap().0);
}

#[test]
fn every_fixed_header_byte_is_checked_before_decrypting() {
    let (original, key, _) = encode(b"PRIVATE", 4);
    for offset in 0..HEADER_BYTES {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(
            StreamDecoder::new(
                Cursor::new(bytes),
                StreamDecryptionKey::from_bytes(key),
                context(),
                StreamLimits::default()
            )
            .is_err(),
            "offset {offset}"
        );
    }
    for wrong in [
        StreamContext::new([43; 16], StreamRole::Private),
        StreamContext::new([42; 16], StreamRole::Metadata),
    ] {
        assert!(StreamDecoder::new(
            Cursor::new(&original),
            StreamDecryptionKey::from_bytes(key),
            wrong,
            StreamLimits::default()
        )
        .is_err());
    }
}

#[test]
fn altered_matching_archive_role_and_identity_still_fail_aad_authentication() {
    let (original, key, _) = encode(b"PRIVATE", 5);
    for (offset, wrong) in [
        (11, StreamContext::new([42; 16], StreamRole::Metadata)),
        (
            12,
            StreamContext::new(
                [
                    43, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                ],
                StreamRole::Private,
            ),
        ),
    ] {
        let mut bytes = original.clone();
        bytes[offset] = if offset == 11 { 1 } else { 43 };
        let mut decoder = StreamDecoder::new(
            Cursor::new(bytes),
            StreamDecryptionKey::from_bytes(key),
            wrong,
            StreamLimits::default(),
        )
        .unwrap();
        assert!(decoder.next_chunk().is_err());
        assert!(decoder.summary().is_none());
    }
}

#[test]
fn wrong_keys_and_ciphertext_or_tag_tampering_return_no_plaintext() {
    let (original, key, _) = encode(b"PRIVATE-CIPHERTEXT-TEST", 6);
    assert!(decode(&original, [99; 32]).is_err());
    for offset in [
        HEADER_BYTES + PREFIX_BYTES,
        HEADER_BYTES + PREFIX_BYTES + 10,
        end_offset(&original) - 1,
        original.len() - 1,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(decode(&bytes, key).is_err());
    }
    let mut bytes = original;
    bytes[HEADER_BYTES + PREFIX_BYTES] ^= 1;
    let mut decoder = StreamDecoder::new(
        Cursor::new(bytes),
        StreamDecryptionKey::from_bytes(key),
        context(),
        StreamLimits::default(),
    )
    .unwrap();
    assert!(decoder.next_chunk().is_err());
    assert!(decoder.next_chunk().is_err());
    assert!(decoder.summary().is_none());
}

#[test]
fn authenticated_data_is_not_stream_completion_before_end_and_clean_eof() {
    let (bytes, key, _) = encode(b"PRIVATE", 7);
    let mut decoder = StreamDecoder::new(
        Cursor::new(&bytes),
        StreamDecryptionKey::from_bytes(key),
        context(),
        StreamLimits::default(),
    )
    .unwrap();
    let chunk = decoder.next_chunk().unwrap().unwrap();
    assert!(decoder.summary().is_none());
    assert!(!format!("{chunk:?} {decoder:?}").contains("PRIVATE"));
    chunk.with_private_bytes(|bytes| assert_eq!(bytes, b"PRIVATE"));
    assert!(decoder.next_chunk().unwrap().is_none());
    assert!(decoder.summary().is_some());
}

#[test]
fn truncations_missing_end_and_partial_prefixes_reject() {
    let (bytes, key, _) = encode(b"PRIVATE", 8);
    for length in 0..bytes.len() {
        assert!(decode(&bytes[..length], key).is_err(), "length {length}");
    }
}

#[test]
fn appended_bytes_duplicate_end_and_concatenated_streams_reject() {
    let (bytes, key, _) = encode(b"PRIVATE", 9);
    for suffix in [
        &b"\0"[..],
        &b"PRIVATE-TRAILING"[..],
        &bytes[end_offset(&bytes)..],
        &bytes[..],
    ] {
        let mut appended = bytes.clone();
        appended.extend_from_slice(suffix);
        assert!(decode(&appended, key).is_err());
    }
}

#[test]
fn data_order_duplicate_drop_and_stream_splice_reject() {
    let (bytes, key, _) = encode(&vec![42; 2 * FRAME_CAP + 1], 10);
    let ranges = data_ranges(&bytes);
    let mut reordered = bytes[..HEADER_BYTES].to_vec();
    reordered.extend_from_slice(&bytes[ranges[1].clone()]);
    reordered.extend_from_slice(&bytes[ranges[0].clone()]);
    reordered.extend_from_slice(&bytes[ranges[2].start..]);
    assert!(decode(&reordered, key).is_err());
    let mut duplicate = bytes[..ranges[1].start].to_vec();
    duplicate.extend_from_slice(&bytes[ranges[0].clone()]);
    duplicate.extend_from_slice(&bytes[ranges[1].start..]);
    assert!(decode(&duplicate, key).is_err());
    let mut dropped = bytes[..HEADER_BYTES].to_vec();
    dropped.extend_from_slice(&bytes[ranges[1].start..]);
    assert!(decode(&dropped, key).is_err());
    let (other, _, _) = encode(&vec![43; 2 * FRAME_CAP + 1], 11);
    let mut spliced = bytes.clone();
    spliced[ranges[1].clone()].copy_from_slice(&other[ranges[1].clone()]);
    assert!(decode(&spliced, key).is_err());
}

#[test]
fn altered_sequence_kind_reserved_or_length_fields_reject() {
    let (original, key, _) = encode(b"PRIVATE", 12);
    for relative in [0, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        let mut bytes = original.clone();
        bytes[HEADER_BYTES + relative] ^= 1;
        assert!(decode(&bytes, key).is_err());
    }
    let mut bytes = original;
    bytes[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(decode(&bytes, key).is_err());
}

#[test]
fn final_counter_hash_sequence_and_tag_tampering_reject() {
    let (original, key, _) = encode(b"PRIVATE", 13);
    let end = end_offset(&original);
    for offset in [
        end,
        end + 7,
        end + 8,
        end + 9,
        end + 12,
        end + 15,
        end + PREFIX_BYTES,
        end + PREFIX_BYTES + 8,
        end + PREFIX_BYTES + 16,
        original.len() - 1,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(decode(&bytes, key).is_err());
    }
}

fn resign_end(bytes: &mut [u8], key: [u8; 32]) {
    let offset = end_offset(bytes);
    let sequence = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(b"AOSH");
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    let mut aad = b"aos.hub.snapshot-stream-frame/v1\0".to_vec();
    aad.extend_from_slice(&bytes[..HEADER_BYTES]);
    aad.extend_from_slice(&bytes[offset..offset + PREFIX_BYTES + COMMITMENT_BYTES]);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut tag = Vec::new();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut tag)
        .unwrap();
    let length = bytes.len();
    bytes[length - TAG_BYTES..].copy_from_slice(&tag);
}

#[test]
fn even_authenticated_false_final_counts_or_hashes_fail_observed_reconciliation() {
    let (original, key, _) = encode(b"PRIVATE", 14);
    let end = end_offset(&original);
    for relative in [0, 8, 16] {
        let mut bytes = original.clone();
        bytes[end + PREFIX_BYTES + relative] ^= 1;
        resign_end(&mut bytes, key);
        let error = decode(&bytes, key).unwrap_err();
        assert_eq!(error.to_string(), "snapshot stream end commitment differs");
    }
}

#[test]
fn empty_end_also_authenticates_archive_role_and_header_digest() {
    let (original, key, summary) = encode(&[], 15);
    assert_eq!(summary.data_frames, 0);
    assert_eq!(summary.plaintext_bytes, 0);
    let mut bytes = original.clone();
    bytes[11] = 1;
    let wrong = StreamContext::new([42; 16], StreamRole::Metadata);
    let mut decoder = StreamDecoder::new(
        Cursor::new(bytes),
        StreamDecryptionKey::from_bytes(key),
        wrong,
        StreamLimits::default(),
    )
    .unwrap();
    assert!(decoder.next_chunk().is_err());
    let mut bytes = original;
    let end = end_offset(&bytes);
    bytes[end + PREFIX_BYTES + 16] ^= 1;
    resign_end(&mut bytes, key);
    assert!(decode(&bytes, key).is_err());
}

#[test]
fn tiny_limits_are_exact_and_failures_poison_encoders() {
    let limit = StreamLimits {
        max_data_frames: 1,
        max_plaintext_bytes: 3,
        max_ciphertext_bytes: (HEADER_BYTES
            + PREFIX_BYTES
            + 3
            + TAG_BYTES
            + PREFIX_BYTES
            + COMMITMENT_BYTES
            + TAG_BYTES) as u64,
    };
    let (fresh, key) = key(16);
    let mut encoder = StreamEncoder::new(Vec::new(), fresh, context(), limit).unwrap();
    encoder.write_plaintext(b"abc").unwrap();
    let (bytes, summary) = encoder.finish().unwrap();
    let mut decoder = StreamDecoder::new(
        Cursor::new(&bytes),
        StreamDecryptionKey::from_bytes(key),
        context(),
        limit,
    )
    .unwrap();
    assert_eq!(decoder.next_chunk().unwrap().unwrap().len(), 3);
    assert!(decoder.next_chunk().unwrap().is_none());
    assert_eq!(decoder.summary(), Some(&summary));
    let (fresh, _) = self::key(17);
    let mut encoder = StreamEncoder::new(Vec::new(), fresh, context(), limit).unwrap();
    assert!(encoder.write_plaintext(b"abcd").is_err());
    assert!(encoder.write_plaintext(b"a").is_err());
    assert!(encoder.finish().is_err());
    for tight in [
        StreamLimits {
            max_plaintext_bytes: 2,
            ..limit
        },
        StreamLimits {
            max_data_frames: 0,
            ..limit
        },
        StreamLimits {
            max_ciphertext_bytes: limit.max_ciphertext_bytes - 1,
            ..limit
        },
    ] {
        let mut decoder = StreamDecoder::new(
            Cursor::new(&bytes),
            StreamDecryptionKey::from_bytes(key),
            context(),
            tight,
        )
        .unwrap();
        assert!(decoder.next_chunk().is_err());
        assert!(decoder.summary().is_none());
    }
}

#[test]
fn invalid_local_hard_limits_reject_before_input_or_output() {
    for limits in [
        StreamLimits {
            max_data_frames: u64::MAX,
            ..StreamLimits::default()
        },
        StreamLimits {
            max_plaintext_bytes: u64::MAX,
            ..StreamLimits::default()
        },
        StreamLimits {
            max_ciphertext_bytes: u64::MAX,
            ..StreamLimits::default()
        },
        StreamLimits {
            max_ciphertext_bytes: 0,
            ..StreamLimits::default()
        },
    ] {
        let (fresh, key) = key(18);
        assert!(StreamEncoder::new(Vec::new(), fresh, context(), limits).is_err());
        assert!(StreamDecoder::new(
            Cursor::new([]),
            StreamDecryptionKey::from_bytes(key),
            context(),
            limits
        )
        .is_err());
    }
}

struct CountRead {
    bytes: Cursor<Vec<u8>>,
    count: Rc<Cell<usize>>,
}
impl Read for CountRead {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.bytes.read(bytes)?;
        self.count.set(self.count.get() + count);
        Ok(count)
    }
}

#[test]
fn malicious_lengths_and_frame_budgets_reject_before_ciphertext_read() {
    let (original, key, _) = encode(b"PRIVATE", 19);
    for length in [0, 1, 16, (FRAME_CAP + TAG_BYTES + 1) as u32, u32::MAX] {
        let mut bytes = original.clone();
        bytes[HEADER_BYTES + 12..HEADER_BYTES + 16].copy_from_slice(&length.to_be_bytes());
        let count = Rc::new(Cell::new(0));
        let reader = CountRead {
            bytes: Cursor::new(bytes),
            count: count.clone(),
        };
        let mut decoder = StreamDecoder::new(
            reader,
            StreamDecryptionKey::from_bytes(key),
            context(),
            StreamLimits::default(),
        )
        .unwrap();
        assert!(decoder.next_chunk().is_err());
        assert_eq!(count.get(), HEADER_BYTES + PREFIX_BYTES);
    }
    let count = Rc::new(Cell::new(0));
    let reader = CountRead {
        bytes: Cursor::new(original),
        count: count.clone(),
    };
    let mut decoder = StreamDecoder::new(
        reader,
        StreamDecryptionKey::from_bytes(key),
        context(),
        StreamLimits {
            max_data_frames: 0,
            ..StreamLimits::default()
        },
    )
    .unwrap();
    assert!(decoder.next_chunk().is_err());
    assert_eq!(count.get(), HEADER_BYTES + PREFIX_BYTES);
}

struct FailWriter {
    remaining: usize,
}
impl Write for FailWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("PRIVATE-WRITER-ERROR"));
        }
        let count = self.remaining.min(bytes.len());
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn partial_writer_failures_poison_writes_and_finish_without_error_leakage() {
    let (fresh, _) = key(20);
    let mut encoder = StreamEncoder::new(
        FailWriter {
            remaining: HEADER_BYTES + PREFIX_BYTES + 1,
        },
        fresh,
        context(),
        StreamLimits::default(),
    )
    .unwrap();
    let error = encoder.write_plaintext(&vec![42; FRAME_CAP]).unwrap_err();
    assert_eq!(error.to_string(), "snapshot stream output failed");
    assert!(!format!("{error:#} {encoder:?}").contains("PRIVATE"));
    assert!(encoder.write_plaintext(b"PRIVATE").is_err());
    assert!(encoder.finish().is_err());
    let (fresh, _) = key(21);
    let mut encoder = StreamEncoder::new(
        FailWriter {
            remaining: HEADER_BYTES + 1,
        },
        fresh,
        context(),
        StreamLimits::default(),
    )
    .unwrap();
    encoder.write_plaintext(b"PRIVATE").unwrap();
    assert!(encoder.finish().is_err());
}

#[test]
fn reader_errors_are_redacted_and_cannot_yield_completion() {
    struct ErrorReader;
    impl Read for ErrorReader {
        fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("PRIVATE-READER-ERROR"))
        }
    }
    let error = StreamDecoder::new(
        ErrorReader,
        StreamDecryptionKey::from_bytes([42; 32]),
        context(),
        StreamLimits::default(),
    )
    .unwrap_err();
    assert!(!format!("{error:#} {error:?}").contains("PRIVATE"));
    let (bytes, key, _) = encode(b"PRIVATE", 22);
    let mut decoder = StreamDecoder::new(
        Cursor::new(&bytes[..bytes.len() - 1]),
        StreamDecryptionKey::from_bytes(key),
        context(),
        StreamLimits::default(),
    )
    .unwrap();
    decoder.next_chunk().unwrap();
    let error = decoder.next_chunk().unwrap_err();
    assert!(!format!("{error:#} {error:?}").contains("PRIVATE"));
    assert!(decoder.summary().is_none());
    assert!(decoder.next_chunk().is_err());
}

#[test]
fn keys_encoder_decoder_and_chunks_have_no_plaintext_debug_or_wire_leakage() {
    let (fresh, key) = key(23);
    assert_eq!(format!("{fresh:?}"), "FreshStreamKey { <redacted> }");
    let reader_key = StreamDecryptionKey::from_bytes(key);
    assert_eq!(
        format!("{reader_key:?}"),
        "StreamDecryptionKey { <redacted> }"
    );
    let mut encoder =
        StreamEncoder::new(Vec::new(), fresh, context(), StreamLimits::default()).unwrap();
    encoder
        .write_plaintext(b"PRIVATE-PLAINTEXT-WIRE-MARKER")
        .unwrap();
    assert!(!format!("{encoder:?}").contains("PRIVATE"));
    let (bytes, _) = encoder.finish().unwrap();
    assert!(!bytes
        .windows(29)
        .any(|window| window == b"PRIVATE-PLAINTEXT-WIRE-MARKER"));
    let mut decoder = StreamDecoder::new(
        Cursor::new(bytes),
        reader_key,
        context(),
        StreamLimits::default(),
    )
    .unwrap();
    let chunk = decoder.next_chunk().unwrap().unwrap();
    assert_eq!(format!("{chunk:?}"), "PrivateStreamChunk { <redacted> }");
}

#[test]
fn failed_external_rng_context_is_redacted() {
    struct RefuseRng;
    impl rand::TryRngCore for RefuseRng {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            Err(std::io::Error::other("PRIVATE-RNG-ERROR"))
        }
        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            Err(std::io::Error::other("PRIVATE-RNG-ERROR"))
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> std::result::Result<(), Self::Error> {
            bytes.fill(42);
            Err(std::io::Error::other("PRIVATE-RNG-ERROR"))
        }
    }
    impl rand::TryCryptoRng for RefuseRng {}
    let error = FreshStreamKey::generate(&mut RefuseRng).unwrap_err();
    assert_eq!(error.to_string(), "snapshot stream key generation failed");
    assert!(!format!("{error:#} {error:?}").contains("PRIVATE"));
}
