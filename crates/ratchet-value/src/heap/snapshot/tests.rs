//! Round-trip and corruption tests for the heap-image snapshot format.
//!
//! Split out of `snapshot.rs` verbatim to keep that file under the
//! source-file line cap; see the parent module for the wire format.

use super::*;
use crate::heap::reservation_registry::reservation_containing_address;
use crate::value::compressed::CandidateCScalarStore;

/// Two wide integers that do not fit the inline `i32` payload, so each boxes
/// a hash-consed cell in the reservation arena — giving the round trip real
/// `(domain, index)` heap words to resolve.
const WIDE_A: i64 = 1_000_000_000_000;
const WIDE_B: i64 = -42_000_000_000;

#[test]
fn reservation_image_round_trip_is_address_free_and_value_equal() {
    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        // The chunked fallback is not snapshottable; nothing to prove here.
        return;
    }

    let mut scalars = CandidateCScalarStore::new(arena.clone());
    let word_a = scalars.encode_int(WIDE_A).expect("boxes a wide integer");
    let word_b = scalars.encode_int(WIDE_B).expect("boxes a wide integer");
    let index_a = word_a.arena_index().expect("boxed word carries an index");
    let domain = arena.arena_domain_id().expect("reservation-backed arena");

    let image = capture_reservation(&arena).expect("captures the reservation");
    let bytes = image.to_bytes();

    // Drop the source reservation so its domain is free to re-register.
    drop(scalars);
    drop(arena);
    assert!(
        reservation_base(domain).is_none(),
        "dropping the source reservation withdraws its domain"
    );

    let reloaded = HeapImage::from_bytes(&bytes).expect("parses the serialized image");
    let restored = restore_reservation(&reloaded).expect("restores the reservation");
    assert_eq!(
        restored.arena_domain_id(),
        Some(domain),
        "restore preserves the original domain"
    );

    // Address-free resolution: the dumped word is untouched, and the
    // registry now rebinds its domain to the fresh base, so `domain + index`
    // names the reloaded mapping with no per-word rewrite.
    let base = reservation_base(domain).expect("restored domain is registered");
    assert_eq!(
        word_a.arena_domain(),
        Some(domain),
        "domain word is unchanged"
    );
    assert_eq!(
        word_a.arena_index(),
        Some(index_a),
        "index word is unchanged"
    );
    assert_eq!(
        reservation_containing_address(base + index_a.raw() as usize),
        Some((domain, base)),
        "the restored mapping owns the resolved address"
    );

    // Byte-identical arena round trip: re-capturing the restored arena
    // reproduces the exact used-lane bytes and metadata.
    let recaptured = capture_reservation(&restored).expect("re-captures the restored arena");
    assert_eq!(recaptured.low, image.low);
    assert_eq!(recaptured.high, image.high);
    assert_eq!(recaptured.domain, image.domain);
    assert_eq!(recaptured.capacity, image.capacity);

    // End-to-end value equality: a fresh scalar store over the restored
    // reservation decodes both boxed cells to their original integers.
    let mut restored_scalars = CandidateCScalarStore::new(restored.clone());
    restored_scalars.adopt_reloaded_regions();
    assert_eq!(
        restored_scalars.decode_int(word_a).expect("decodes a"),
        WIDE_A
    );
    assert_eq!(
        restored_scalars.decode_int(word_b).expect("decodes b"),
        WIDE_B
    );
}

#[test]
fn from_bytes_rejects_a_corrupted_image() {
    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        return;
    }
    let mut scalars = CandidateCScalarStore::new(arena.clone());
    scalars.encode_int(WIDE_A).expect("boxes a wide integer");
    let image = capture_reservation(&arena).expect("captures the reservation");
    let mut bytes = image.to_bytes();

    // Flip a payload byte; the trailing digest must catch it.
    let mid = HEADER_LEN + image.low.len() / 2;
    bytes[mid] ^= 0xff;
    assert!(matches!(
        HeapImage::from_bytes(&bytes),
        Err(SnapshotError::IntegrityMismatch { .. })
    ));

    // A short buffer is a clean truncation error, not a panic.
    assert!(matches!(
        HeapImage::from_bytes(&bytes[..HEADER_LEN]),
        Err(SnapshotError::Truncated { .. })
    ));
}

#[test]
fn from_bytes_rejects_bad_magic_and_version() {
    let image = HeapImage {
        domain: 1,
        capacity: 0x1000,
        old_base: 0x4000,
        low: vec![1, 2, 3, 4],
        high: Vec::new(),
        relocations: vec![RelocationEntry { index: 8, kind: 4 }],
        list_payloads: vec![ListPayload {
            index: 16,
            element_bytes: vec![9, 10, 11, 12, 13, 14, 15, 16],
        }],
        context_payloads: vec![ContextPayload {
            index: 8,
            context_bytes: vec![1, 2, 3],
        }],
        primop_payloads: vec![PrimopPayload {
            index: 24,
            primop_bytes: vec![7, 6, 5, 4],
        }],
        frame_payloads: vec![FramePayload {
            index: 0,
            frame_bytes: vec![0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0],
        }],
        closure_payloads: vec![ClosurePayload {
            index: 32,
            closure_bytes: vec![9, 8, 7],
        }],
        attrs_payloads: vec![OwnedAttrsPayload {
            index: 48,
            attrs_bytes: vec![1, 2],
        }],
        string_payloads: vec![OwnedStringPayload {
            index: 56,
            string_bytes: vec![3, 4, 5],
        }],
        symbol_names: vec![b"alpha".to_vec()],
        module_fingerprints: vec![[7u8; 32]],
    };
    let good = image.to_bytes();

    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xff;
    // Recompute the digest so magic is what fails, not integrity.
    fix_digest(&mut bad_magic);
    assert!(matches!(
        HeapImage::from_bytes(&bad_magic),
        Err(SnapshotError::BadMagic)
    ));

    let mut bad_version = good.clone();
    bad_version[8] = 0xff;
    fix_digest(&mut bad_version);
    assert!(matches!(
        HeapImage::from_bytes(&bad_version),
        Err(SnapshotError::UnsupportedVersion { .. })
    ));
}

#[test]
fn wire_round_trip_preserves_every_payload_segment() {
    let image = HeapImage {
        domain: 3,
        capacity: 0x2000,
        old_base: 0x8000,
        low: vec![1, 2, 3, 4, 5, 6, 7, 8],
        high: vec![9, 10],
        relocations: vec![RelocationEntry { index: 8, kind: 4 }],
        list_payloads: vec![ListPayload {
            index: 16,
            element_bytes: vec![1; 16],
        }],
        context_payloads: vec![ContextPayload {
            index: 8,
            context_bytes: vec![2; 5],
        }],
        primop_payloads: vec![PrimopPayload {
            index: 24,
            primop_bytes: vec![3; 7],
        }],
        frame_payloads: vec![
            FramePayload {
                index: 0,
                frame_bytes: vec![4; 12],
            },
            FramePayload {
                index: 1,
                frame_bytes: vec![5; 20],
            },
        ],
        closure_payloads: vec![ClosurePayload {
            index: 40,
            closure_bytes: vec![6; 9],
        }],
        attrs_payloads: vec![OwnedAttrsPayload {
            index: 48,
            attrs_bytes: vec![7; 11],
        }],
        string_payloads: vec![OwnedStringPayload {
            index: 56,
            string_bytes: vec![8; 4],
        }],
        symbol_names: vec![b"alpha".to_vec(), b"".to_vec(), b"zeta".to_vec()],
        module_fingerprints: vec![[0u8; 32], [9u8; 32]],
    };
    let parsed = HeapImage::from_bytes(&image.to_bytes()).expect("wire image parses");
    assert_eq!(parsed, image);
}

/// Recomputes the trailing digest so a header-field mutation is exercised in
/// isolation from the integrity check.
fn fix_digest(bytes: &mut [u8]) {
    let len = bytes.len();
    let digest = xxh3_64(&bytes[..len - 8]);
    bytes[len - 8..].copy_from_slice(&digest.to_le_bytes());
}
