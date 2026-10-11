//! Canonical streaming identities and adversarial original-extent checks.

// crucible-lint: allow panic-shortcut -- These streaming tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::canonical;

#[test]
fn stream_identity_matches_canonical_blob_across_buffer_boundaries() {
    for length in [0, 1, 65_535, 65_536, 65_537, 200_003] {
        let bytes: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
        let expected = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
        let actual = hash_stream(&mut bytes.as_slice(), length as u64).unwrap();
        assert_eq!(actual, expected);
    }
    let empty = hash_stream(&mut [].as_slice(), 0).unwrap();
    assert_eq!(
        empty.hash.digest,
        "493153ee1b4d07570e6b4659bdd6e96e47ce4d29e7a754ab89e9a8645aaeb9ce"
    );
    let binary = hash_stream(&mut [0, 255].as_slice(), 2).unwrap();
    assert_eq!(
        binary.hash.digest,
        "8fcdff24189cb41339b899af10fd86a3400665e4890e031a4d8921615f1fdbc4"
    );
}

#[test]
fn stream_refuses_short_excess_and_unrepresentable_original_extents() {
    assert!(hash_stream(&mut b"short".as_slice(), 6).is_err());
    assert!(hash_stream(&mut b"excess".as_slice(), 5).is_err());
    assert!(hash_stream(&mut b"x".as_slice(), 0).is_err());
    assert!(hash_stream(&mut [].as_slice(), GEM5_MAX_IMAGE_BYTES + 1).is_err());
}

#[test]
fn stream_io_failure_never_returns_a_partial_content_identity() {
    struct Fails;
    impl Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read fault"))
        }
    }
    assert!(hash_stream(&mut Fails, 1).is_err());
    assert!(hash_stream(&mut Fails, 0).is_err());
}

#[test]
fn installed_image_ceiling_is_checked_before_any_reader_allocation() {
    struct Fault;
    impl Read for Fault {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("extent admitted"))
        }
    }
    assert!(matches!(
        hash_stream(&mut Fault, GEM5_MAX_IMAGE_BYTES),
        Err(ProviderError::Io(_))
    ));
    assert!(matches!(
        hash_stream(&mut Fault, GEM5_MAX_IMAGE_BYTES + 1),
        Err(ProviderError::ResourceExhausted(_))
    ));
}
