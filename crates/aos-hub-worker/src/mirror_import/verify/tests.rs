//! Incremental source verification under actual frame and byte bounds.

use super::*;

fn nar(encoded: &[u8], plain: &[u8]) -> MirrorVerification {
    MirrorVerification::Nar {
        file_sha256: Some(hex::encode(Sha256::digest(encoded))),
        file_size: encoded.len() as u64,
        compression: "zstd".into(),
        nar_sha256: hex::encode(Sha256::digest(plain)),
        nar_size: plain.len() as u64,
    }
}

#[test]
fn decodes_large_source_in_small_chunks_without_retaining_plain_bytes() {
    let plain: Vec<u8> = (0..32 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let encoded = zstd::stream::encode_all(plain.as_slice(), 1).unwrap();
    let mut verifier = Verifier::new(&nar(&encoded, &plain)).unwrap();

    for chunk in encoded.chunks(137) {
        verifier.feed(chunk).unwrap();
    }
    assert!(verifier.peak_pending <= MAX_PENDING);
    assert_eq!(verifier.finish().unwrap().1.unwrap().0, plain.len() as u64);
}

#[test]
fn accepts_concatenated_frames_and_checks_signed_plain_identity() {
    let plain = b"first frame second frame";
    let mut encoded = zstd::stream::encode_all(&plain[..12], 1).unwrap();
    encoded.extend(zstd::stream::encode_all(&plain[12..], 1).unwrap());
    let original = nar(&encoded, plain);
    let mut verifier = Verifier::new(&original).unwrap();
    for chunk in encoded.chunks(1) {
        verifier.feed(chunk).unwrap();
    }
    assert_eq!(verifier.frames, 2);
    verifier.finish().unwrap();

    let mut changed = original;
    if let MirrorVerification::Nar { nar_sha256, .. } = &mut changed {
        *nar_sha256 = "0".repeat(64);
    }
    let mut verifier = Verifier::new(&changed).unwrap();
    verifier.feed(&encoded).unwrap();
    assert!(verifier.finish().is_err());
}

#[test]
fn refuses_large_windows_before_decoder_allocation_and_truncated_streams() {
    // A non-single-segment frame advertises a 16 MiB window.
    assert!(frame_header(&[0x28, 0xb5, 0x2f, 0xfd, 0, 112], MAX_WINDOW).is_err());
    let plain = b"bounded source";
    let encoded = zstd::stream::encode_all(plain.as_slice(), 1).unwrap();
    let mut verifier = Verifier::new(&nar(&encoded, plain)).unwrap();
    verifier.feed(&encoded[..encoded.len() - 1]).unwrap();
    assert!(verifier.finish().is_err());
}

#[test]
fn refuses_mutated_encoded_identity_and_plain_length_overflow() {
    let plain = b"bounded source";
    let encoded = zstd::stream::encode_all(plain.as_slice(), 1).unwrap();
    let mut original = nar(&encoded, plain);
    if let MirrorVerification::Nar { file_sha256, .. } = &mut original {
        *file_sha256 = Some("0".repeat(64));
    }
    let mut verifier = Verifier::new(&original).unwrap();
    verifier.feed(&encoded).unwrap();
    assert!(verifier.finish().is_err());

    if let MirrorVerification::Nar { nar_size, .. } = &mut original {
        *nar_size -= 1;
    }
    let mut verifier = Verifier::new(&original).unwrap();
    assert!(verifier.feed(&encoded).is_err());
}

#[test]
fn small_metadata_refuses_an_advertised_bulk_decoder_window_before_allocation() {
    let frame = [0x28, 0xb5, 0x2f, 0xfd, 0, 72];
    assert!(frame_header(
        &frame,
        aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFER_BYTES
    )
    .is_err());
    assert!(frame_header(&frame, MAX_WINDOW).unwrap().is_some());
}
