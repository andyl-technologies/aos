//! Checks exact immutable identities and the separate setup selector.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;

fn pair() -> RuntimeArtifactPair {
    RuntimeArtifactPair {
        process_generation: 3,
        account_generation: 9,
        source_assignment: [11; 32],
        libc: RuntimeArtifactIdentity {
            file_len: 4096,
            sha256: [21; 32],
        },
        loader: RuntimeArtifactIdentity {
            file_len: 2048,
            sha256: [22; 32],
        },
    }
}

#[test]
fn runtime_pair_matches_exact_independent_role_layout() {
    let value = pair();
    let bytes = value.encode().unwrap();
    assert_eq!(&bytes[..16], b"CRUCRTA1\0\0\0\x01\0\0\0\xc0");
    assert_eq!(&bytes[64..72], &[0, 0, 0, 1, 0, 0, 0, 62]);
    assert_eq!(&bytes[128..136], &[0, 0, 0, 2, 0, 0, 0, 62]);
    assert_eq!(&bytes[80..112], &[21; 32]);
    assert_eq!(&bytes[144..176], &[22; 32]);
    assert_eq!(RuntimeArtifactPair::decode(&bytes), Ok(value));

    let mut boundary = value;
    boundary.libc.file_len = i64::MAX as u64;
    boundary.loader.file_len = 1;
    boundary.process_generation = u64::MAX - 1;
    boundary.account_generation = u64::MAX - 1;
    assert_eq!(
        RuntimeArtifactPair::decode(&boundary.encode().unwrap()),
        Ok(boundary)
    );
}

#[test]
fn runtime_pair_refuses_all_truncations_selectors_and_reserved_bytes() {
    let bytes = pair().encode().unwrap();
    for length in 0..bytes.len() {
        assert!(RuntimeArtifactPair::decode(&bytes[..length]).is_err());
    }
    for offset in (0..16).chain(64..72).chain(112..136).chain(176..192) {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            RuntimeArtifactPair::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(RuntimeArtifactPair::decode(&trailing).is_err());
}

#[test]
fn runtime_pair_refuses_absent_identities_exhausted_generations_and_offset_overflow() {
    let bytes = pair().encode().unwrap();
    for offset in [16, 24] {
        for invalid in [0, u64::MAX] {
            let mut changed = bytes;
            changed[offset..offset + 8].copy_from_slice(&invalid.to_be_bytes());
            assert!(RuntimeArtifactPair::decode(&changed).is_err());
        }
    }
    for offset in [72, 136] {
        for invalid in [0, (i64::MAX as u64) + 1, u64::MAX] {
            let mut changed = bytes;
            changed[offset..offset + 8].copy_from_slice(&invalid.to_be_bytes());
            assert!(RuntimeArtifactPair::decode(&changed).is_err());
        }
    }
    for offset in [32, 80, 144] {
        let mut changed = bytes;
        changed[offset..offset + 32].fill(0);
        assert!(RuntimeArtifactPair::decode(&changed).is_err());
    }
    let mut value = pair();
    value.libc.file_len = 0;
    assert!(value.encode().is_err());
    value = pair();
    value.loader.sha256.fill(0);
    assert!(value.encode().is_err());
}

#[test]
fn setup_ten_refuses_mixed_editions_and_preserves_dormant_footer() {
    use crate::deferred_cleanup::DeferredCleanupSetup;
    use crate::publisher_subscription::PublisherSetup;
    let cleanup = DeferredCleanupSetup {
        publisher: PublisherSetup {
            region_len: 4096,
            process_generation: 3,
            device_digest_workspace: None,
            lender_generation: 4,
            device: 0,
            inode: 0,
            producer_event: 5,
            receiver_event: 6,
        },
        delegation_incarnation: 7,
    };
    let setup = RuntimeArtifactSetup { cleanup };
    let bytes = setup.encode().unwrap();
    let ordinary = cleanup.encode().unwrap();
    assert_eq!(bytes[4], 0x1a);
    assert_eq!(&bytes[5..], &ordinary[5..]);
    assert_eq!(RuntimeArtifactSetup::decode(&bytes), Ok(setup));
    assert!(DeferredCleanupSetup::decode(&bytes).is_err());
    assert!(RuntimeArtifactSetup::decode(&ordinary).is_err());
    for length in 0..bytes.len() {
        assert!(RuntimeArtifactSetup::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(RuntimeArtifactSetup::decode(&trailing).is_err());
    for tag in [0x16, 0x17, 0x18, 0x19, 0x1b] {
        let mut changed = bytes;
        changed[4] = tag;
        assert!(RuntimeArtifactSetup::decode(&changed).is_err());
    }
}

#[test]
fn runtime_pair_matches_all_public_vectors_and_exact_accepted_round_trips() {
    let vectors = include_str!("../../tests/fixtures/runtime-artifact-v1.tsv");
    let mut count = 0;
    let mut accepted = 0;
    for line in vectors.lines().filter(|line| !line.starts_with('#')) {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 3);
        let (words, remainder) = fields[2].as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        let bytes = words
            .iter()
            .map(|word| u8::from_str_radix(std::str::from_utf8(word).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(fields[2].len(), bytes.len() * 2);
        let decoded = RuntimeArtifactPair::decode(&bytes);
        assert_eq!(decoded.is_ok(), fields[1] == "1", "{}", fields[0]);
        if let Ok(pair) = decoded {
            assert_eq!(pair.encode().unwrap().as_slice(), bytes, "{}", fields[0]);
            accepted += 1;
        }
        count += 1;
    }
    assert_eq!((count, accepted), (272, 2));
}
