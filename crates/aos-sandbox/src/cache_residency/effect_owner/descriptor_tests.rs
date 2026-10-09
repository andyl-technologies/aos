//! Exact portable-object framing for memory and disk Cache admissions.
//!
//! These pure callbacks establish object integrity, not physical sealing,
//! resident catalog currentness, consumer disclosure, or FUSE qualification.

use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest, format::descriptor_for_bytes};
use aos_sandbox_linux::immutable_file::MaterializationCallbacks as _;
use sha2::{Digest as _, Sha256};

use super::{CacheOwnerErrorV1, DescriptorVerifier, verify_bytes};

const CONTENT_MEDIA_TYPE: &str = "application/vnd.aos.sandbox.content.v1";

fn descriptor(bytes: &[u8]) -> ObjectDescriptor {
    descriptor_for_bytes(
        MediaType::new(CONTENT_MEDIA_TYPE).expect("content type"),
        bytes,
    )
}

fn verify_disk_chunks(expected: &ObjectDescriptor, chunks: &[&[u8]]) -> bool {
    let mut verifier = DescriptorVerifier::new(expected);
    for chunk in chunks {
        if verifier.verify_chunk(chunk).is_err() {
            return false;
        }
    }
    verifier.finish_verification().is_ok()
}

#[test]
fn cache_object_descriptor_accepts_the_portable_golden_frame_not_raw_sha256() {
    let bytes = b"hello";
    let expected = descriptor(bytes);
    assert_eq!(
        expected.digest().to_string(),
        "sha256:a40bf7a4525f9711f56ba2f9a4e91cf0ee0fe60a01f7716c9eb6d03dde09d903"
    );

    assert!(verify_bytes(&expected, bytes).is_ok());
    assert!(verify_disk_chunks(&expected, &[bytes]));

    let raw = ObjectDescriptor::new(
        expected.media_type().clone(),
        ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
        bytes.len() as u64,
    );
    assert!(matches!(
        verify_bytes(&raw, bytes),
        Err(CacheOwnerErrorV1::IntegrityFailure)
    ));
    assert!(!verify_disk_chunks(&raw, &[bytes]));
}

#[test]
fn cache_object_descriptor_rejects_media_size_and_payload_substitution() {
    let bytes = b"hello";
    let expected = descriptor(bytes);
    let wrong_media = ObjectDescriptor::new(
        MediaType::new("application/vnd.aos.sandbox.tree.v1").expect("tree type"),
        expected.digest(),
        expected.encoded_size(),
    );
    let wrong_size = ObjectDescriptor::new(
        expected.media_type().clone(),
        expected.digest(),
        expected.encoded_size() + 1,
    );

    for substituted in [&wrong_media, &wrong_size] {
        assert!(verify_bytes(substituted, bytes).is_err());
        assert!(!verify_disk_chunks(substituted, &[bytes]));
    }
    for substituted in [
        b"jello".as_slice(),
        b"hell".as_slice(),
        b"hello!".as_slice(),
    ] {
        assert!(verify_bytes(&expected, substituted).is_err());
        assert!(!verify_disk_chunks(&expected, &[substituted]));
    }
}

#[test]
fn cache_object_descriptor_streaming_preserves_every_chunk_boundary() {
    let bytes = b"hello";
    let expected = descriptor(bytes);

    for boundary in 0..=bytes.len() {
        assert!(verify_disk_chunks(
            &expected,
            &[&bytes[..boundary], &[], &bytes[boundary..]],
        ));
    }
}

#[test]
fn cache_object_descriptor_failed_updates_cannot_be_ignored_or_reused() {
    let expected = descriptor(b"hello");
    let mut poisoned = DescriptorVerifier::new(&expected);
    assert!(poisoned.verify_chunk(b"hello").is_ok());
    assert!(poisoned.verify_chunk(b"!").is_err());
    assert!(poisoned.verify_chunk(b"").is_err());
    assert!(poisoned.finish_verification().is_err());
    assert!(poisoned.finish_verification().is_err());

    let mut completed = DescriptorVerifier::new(&expected);
    assert!(completed.verify_chunk(b"hello").is_ok());
    assert!(completed.finish_verification().is_ok());
    assert!(completed.verify_chunk(b"").is_err());
    assert!(completed.finish_verification().is_err());
}

#[test]
fn cache_object_descriptor_empty_objects_still_require_the_exact_frame() {
    let expected = descriptor(b"");
    assert!(verify_bytes(&expected, b"").is_ok());
    assert!(verify_disk_chunks(&expected, &[&[]]));
    assert!(verify_bytes(&expected, b"!").is_err());
    assert!(!verify_disk_chunks(&expected, &[b"!"]));
}
