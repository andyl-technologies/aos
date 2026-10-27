//! Checks literal session-purpose geometry and independent custody declarations.

use super::*;

const PURPOSE: &str = "
435255435053503100000001000000e000000000000000030000000000000005
00000000000000070102030405060708090a0b0c0d0e0f101112131415161718
191a1b1c1d1e1f20a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8
b9babbbcbdbebfc0000000000000000000000000000000000000000000001000
000000000000000b000000000000000d00000000000100000000000000000001
0000000000010000000000000000000300000000000010000000000000000001
0000000000000000000000000000000000000000000000000000000000000000";

fn purpose() -> PublisherPurpose {
    let header = header();
    PublisherPurpose {
        lender_generation: header.lender_generation,
        account_generation: header.account_generation,
        process_generation: header.process_generation,
        capability: header.capability,
        reservation: header.reservation,
        device: 0,
        inode: 0,
        producer_event: 11,
        receiver_event: 13,
        backing_bytes: 65_536,
    }
}

#[test]
fn sealed_publisher_purpose_matches_independent_literal() {
    let bytes = vector::<PUBLISHER_PURPOSE_BYTES>(PURPOSE);

    assert_eq!(purpose().encode().unwrap(), bytes);
    assert_eq!(PublisherPurpose::decode(&bytes).unwrap(), purpose());
}

#[test]
fn sealed_publisher_purpose_refuses_framing_geometry_and_padding() {
    let original = vector::<PUBLISHER_PURPOSE_BYTES>(PURPOSE);

    for length in 0..PUBLISHER_PURPOSE_BYTES {
        assert!(PublisherPurpose::decode(&original[..length]).is_err());
    }
    let mut oversized = original.to_vec();
    oversized.push(0);
    assert!(PublisherPurpose::decode(&oversized).is_err());

    for offset in (0..16).chain(120..128).chain(152..PUBLISHER_PURPOSE_BYTES) {
        let mut bytes = original;
        bytes[offset] ^= 1;
        assert!(PublisherPurpose::decode(&bytes).is_err(), "offset {offset}");
    }
}

#[test]
fn sealed_publisher_purpose_refuses_exhaustion_aliases_and_short_backing() {
    for offset in [16, 24, 32, 128, 136] {
        for value in [0_u64, u64::MAX] {
            let mut bytes = vector::<PUBLISHER_PURPOSE_BYTES>(PURPOSE);
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert!(PublisherPurpose::decode(&bytes).is_err());
        }
    }
    for range in [40..72, 72..104] {
        let mut bytes = vector::<PUBLISHER_PURPOSE_BYTES>(PURPOSE);
        bytes[range].fill(0);
        assert!(PublisherPurpose::decode(&bytes).is_err());
    }

    let mut changed = purpose();
    changed.receiver_event = changed.producer_event;
    assert!(changed.encode().is_err());

    let mut bytes = vector::<PUBLISHER_PURPOSE_BYTES>(PURPOSE);
    bytes[136..144].copy_from_slice(&11_u64.to_be_bytes());
    assert!(PublisherPurpose::decode(&bytes).is_err());

    let mut changed = purpose();
    changed.backing_bytes = 4095;
    assert!(changed.encode().is_err());

    let mut bytes = vector::<PUBLISHER_PURPOSE_BYTES>(PURPOSE);
    bytes[144..152].copy_from_slice(&4095_u64.to_be_bytes());
    bytes[160..168].copy_from_slice(&4095_u64.to_be_bytes());
    assert!(PublisherPurpose::decode(&bytes).is_err());
}
