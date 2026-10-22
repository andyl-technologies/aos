//! Checks complete manifest bounds, exact launch bytes and transfer correlation.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::native_transfer::tests::{runtime, transfer};
use crate::native_transfer::{put32, put64};

fn material() -> (Vec<u8>, NativeTransfer, RuntimeArtifactPair) {
    let runtime = runtime();
    let mut transfer = transfer();
    transfer.artifact_count = 4;
    let artifacts_end = HEADER_BYTES + 4 * ARTIFACT_BYTES;
    let producers_end = artifacts_end + NATIVE_PROFILE_PRODUCERS * PRODUCER_BYTES;
    let mut bytes = vec![0; producers_end + 16];
    bytes[..8].copy_from_slice(b"CRUCNPM1");
    put32(&mut bytes, 8, 1);
    for (offset, value) in [(16, 8), (24, 6), (32, 4), (40, 5)] {
        put64(&mut bytes, offset, value);
    }
    for (offset, identity) in [
        (48, [13; 32]),
        (80, [11; 32]),
        (112, [14; 32]),
        (144, transfer.runtime_pair_sha256),
        (176, transfer.process_contract_sha256),
        (224, [71; 32]),
    ] {
        bytes[offset..offset + 32].copy_from_slice(&identity);
    }
    put32(&mut bytes, 208, 4);
    put32(&mut bytes, 212, 16);
    put32(&mut bytes, 220, 4096);

    for index in 0..4 {
        let row = HEADER_BYTES + index * ARTIFACT_BYTES;
        put32(&mut bytes, row, index as u32 + 1);
        put32(&mut bytes, row + 4, 62);
        let (length, digest) = match index {
            2 => (runtime.libc.file_len, runtime.libc.sha256),
            3 => (runtime.loader.file_len, runtime.loader.sha256),
            _ => (4096, [index as u8 + 81; 32]),
        };
        put64(&mut bytes, row + 8, length);
        bytes[row + 16..row + 48].fill(index as u8 + 41);
        bytes[row + 48..row + 80].copy_from_slice(&digest);
        put32(&mut bytes, row + 80, if index < 2 { 12 } else { 0 });
        put32(&mut bytes, row + 84, index as u32 + 1);
        bytes[row + 88..row + 120].fill(index as u8 + 91);
    }
    for index in 0..NATIVE_PROFILE_PRODUCERS {
        let row = artifacts_end + index * PRODUCER_BYTES;
        put32(&mut bytes, row, index as u32 + 1);
        put32(&mut bytes, row + 4, 1);
        put64(&mut bytes, row + 8, 1);
        bytes[row + 16..row + 48].fill(index as u8 + 101);
        bytes[row + 48..row + 80].fill(index as u8 + 121);
        bytes[row + 80..row + 112].fill(index as u8 + 141);
        for (offset, amount) in [
            (112, 4096),
            (120, 8192),
            (128, 4096),
            (136, 1),
            (144, 2),
            (152, 16384),
            (160, 4096),
            (168, 64),
        ] {
            put64(&mut bytes, row + offset, amount);
        }
        put32(&mut bytes, row + 176, index as u32 % 10 + 1);
        put32(&mut bytes, row + 180, 1);
    }

    let arguments: [&[u8]; 2] = [b"qemu-system-x86_64", b"\xff"];
    let environment: [&[u8]; 2] = [b"A=1", b"B=2"];
    put32(&mut bytes, producers_end, arguments.len() as u32);
    put32(&mut bytes, producers_end + 4, environment.len() as u32);
    let arguments_start = bytes.len();
    for argument in arguments {
        bytes.extend_from_slice(&(argument.len() as u32).to_be_bytes());
        bytes.extend_from_slice(argument);
    }
    let arguments_bytes = bytes.len() - arguments_start;
    let environment_start = bytes.len();
    for entry in environment {
        bytes.extend_from_slice(&(entry.len() as u32).to_be_bytes());
        bytes.extend_from_slice(entry);
    }
    let environment_bytes = bytes.len() - environment_start;
    put32(&mut bytes, producers_end + 8, arguments_bytes as u32);
    put32(&mut bytes, producers_end + 12, environment_bytes as u32);
    let launch_bytes = bytes.len() - producers_end;
    put32(&mut bytes, 216, launch_bytes as u32);
    let total = bytes.len();
    put32(&mut bytes, 12, total as u32);
    transfer.profile_manifest_sha256 = Sha256::digest(&bytes).into();
    (bytes, transfer, runtime)
}

#[test]
fn manifest_borrows_all_rows_exact_launch_bytes_and_matching_transfer() {
    let (bytes, transfer, runtime) = material();
    let manifest = NativeProfileManifest::decode(&bytes).unwrap();

    assert_eq!(manifest.as_bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(manifest.as_bytes(), bytes);
    assert_eq!(manifest.artifacts().len(), 4);
    assert_eq!(manifest.producers().len(), 16);
    assert_eq!(
        manifest.arguments().collect::<Vec<_>>(),
        [b"qemu-system-x86_64".as_slice(), b"\xff"]
    );
    assert_eq!(manifest.environment().collect::<Vec<_>>(), [b"A=1", b"B=2"]);
    manifest.corroborate_transfer(&transfer, &runtime).unwrap();
}

#[test]
fn manifest_refuses_every_truncation_trailing_bytes_and_unsupported_header() {
    let (bytes, _, _) = material();
    for length in 0..bytes.len() {
        assert!(
            NativeProfileManifest::decode(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(NativeProfileManifest::decode(&trailing).is_err());
    for (offset, value) in [
        (8, 2),
        (208, 0),
        (208, 1),
        (208, 33),
        (212, 0),
        (212, 15),
        (212, 17),
        (216, 15),
        (216, 16385),
        (220, 8192),
    ] {
        let mut malformed = bytes.clone();
        put32(&mut malformed, offset, value);
        assert!(
            NativeProfileManifest::decode(&malformed).is_err(),
            "header {offset}/{value}"
        );
    }
    for offset in [16, 24, 32, 40] {
        for value in [0, u64::MAX] {
            let mut malformed = bytes.clone();
            put64(&mut malformed, offset, value);
            assert!(NativeProfileManifest::decode(&malformed).is_err());
        }
    }
    for offset in [48, 80, 112, 144, 176, 224] {
        let mut malformed = bytes.clone();
        malformed[offset..offset + 32].fill(0);
        assert!(NativeProfileManifest::decode(&malformed).is_err());
    }
}

#[test]
fn manifest_refuses_duplicate_artifacts_wrong_aliases_and_unlisted_dependencies() {
    let (bytes, _, _) = material();
    for (offset, value) in [(0, 2), (4, 183), (80, 1), (80, 16), (84, 2)] {
        let mut malformed = bytes.clone();
        put32(&mut malformed, HEADER_BYTES + offset, value);
        assert!(
            NativeProfileManifest::decode(&malformed).is_err(),
            "artifact {offset}/{value}"
        );
    }
    for length in [0, i64::MAX as u64 + 1, u64::MAX] {
        let mut malformed = bytes.clone();
        put64(&mut malformed, HEADER_BYTES + 8, length);
        assert!(NativeProfileManifest::decode(&malformed).is_err());
    }
    for offset in [16, 48, 88] {
        let mut malformed = bytes.clone();
        malformed[HEADER_BYTES + offset..HEADER_BYTES + offset + 32].fill(0);
        assert!(NativeProfileManifest::decode(&malformed).is_err());
    }
    let mut duplicate = bytes.clone();
    duplicate[HEADER_BYTES + ARTIFACT_BYTES + 16..HEADER_BYTES + ARTIFACT_BYTES + 48].fill(41);
    assert!(NativeProfileManifest::decode(&duplicate).is_err());

    for artifact in 0..4 {
        for offset in 120..128 {
            let mut malformed = bytes.clone();
            malformed[HEADER_BYTES + artifact * ARTIFACT_BYTES + offset] = 1;
            assert!(NativeProfileManifest::decode(&malformed).is_err());
        }
    }
}

fn unselect(bytes: &mut [u8], kind: usize) {
    let row = HEADER_BYTES + 4 * ARTIFACT_BYTES + (kind - 1) * PRODUCER_BYTES;
    bytes[row..row + PRODUCER_BYTES].fill(0);
    put32(bytes, row, kind as u32);
    put32(bytes, row + 4, 2);
    put64(bytes, row + 168, 1);
    put32(bytes, row + 180, 1);
}

#[test]
fn manifest_requires_compulsory_producers_and_canonical_unselected_rows() {
    let (bytes, _, _) = material();
    for kind in [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16] {
        let mut malformed = bytes.clone();
        unselect(&mut malformed, kind);
        assert!(
            NativeProfileManifest::decode(&malformed).is_err(),
            "kind {kind}"
        );
    }
    for kind in [9, 10, 13, 14] {
        let mut unselected = bytes.clone();
        unselect(&mut unselected, kind);
        assert!(NativeProfileManifest::decode(&unselected).is_ok());
        let row = HEADER_BYTES + 4 * ARTIFACT_BYTES + (kind - 1) * PRODUCER_BYTES;
        for offset in [8, 16, 48, 80, 112, 120, 128, 136, 144, 152, 160, 176, 184] {
            let mut malformed = unselected.clone();
            malformed[row + offset] = 1;
            assert!(
                NativeProfileManifest::decode(&malformed).is_err(),
                "unselected {kind}/{offset}"
            );
        }
    }
}

#[test]
fn manifest_refuses_invalid_required_producer_limits_and_reserved_bytes() {
    let (bytes, _, _) = material();
    let row = HEADER_BYTES + 4 * ARTIFACT_BYTES;
    for (offset, value) in [
        (0, 2),
        (4, 0),
        (4, 3),
        (176, 0),
        (176, 11),
        (180, 0),
        (180, 2),
    ] {
        let mut malformed = bytes.clone();
        put32(&mut malformed, row + offset, value);
        assert!(NativeProfileManifest::decode(&malformed).is_err());
    }
    for (offset, value) in [
        (8, 0),
        (8, u64::MAX),
        (152, 0),
        (160, 0),
        (160, 16385),
        (168, 0),
        (168, 3),
    ] {
        let mut malformed = bytes.clone();
        put64(&mut malformed, row + offset, value);
        assert!(
            NativeProfileManifest::decode(&malformed).is_err(),
            "limit {offset}/{value}"
        );
    }
    for offset in [16, 48, 80] {
        let mut malformed = bytes.clone();
        malformed[row + offset..row + offset + 32].fill(0);
        assert!(NativeProfileManifest::decode(&malformed).is_err());
    }
    for producer in 0..16 {
        for offset in 184..192 {
            let mut malformed = bytes.clone();
            malformed[row + producer * PRODUCER_BYTES + offset] = 1;
            assert!(NativeProfileManifest::decode(&malformed).is_err());
        }
    }

    let mut no_requests = bytes;
    put64(&mut no_requests, row + 152, 0);
    put64(&mut no_requests, row + 160, 0);
    assert!(NativeProfileManifest::decode(&no_requests).is_ok());
}

#[test]
fn manifest_preserves_shared_typed_producer_coordinates_without_issuing_ownership() {
    let (mut bytes, _, _) = material();
    let row = HEADER_BYTES + 4 * ARTIFACT_BYTES;
    bytes[row + 16..row + 48].fill(41);
    bytes[row + PRODUCER_BYTES + 16..row + PRODUCER_BYTES + 48].fill(41);
    bytes[80..112].fill(13);
    bytes[112..144].fill(13);

    // Typed equality is neither duplicate artifact backing nor proof of a
    // disjoint producer charge. Only the actual payer can establish the latter.
    let manifest = NativeProfileManifest::decode(&bytes).unwrap();
    assert_eq!(
        manifest.producers().next().unwrap().child,
        manifest.artifacts().next().unwrap().child
    );
}

#[test]
fn manifest_refuses_malformed_launch_totals_nuls_and_duplicate_environment_names() {
    let (bytes, _, _) = material();
    let launch = HEADER_BYTES + 4 * ARTIFACT_BYTES + 16 * PRODUCER_BYTES;
    for (offset, value) in [
        (0, 0),
        (0, 129),
        (4, 65),
        (8, 0),
        (12, 0),
        (16, 0),
        (16, 4097),
        (16, u32::MAX),
    ] {
        let mut malformed = bytes.clone();
        put32(&mut malformed, launch + offset, value);
        assert!(
            NativeProfileManifest::decode(&malformed).is_err(),
            "launch {offset}/{value}"
        );
    }
    let mut nul = bytes.clone();
    nul[launch + 20] = 0;
    assert!(NativeProfileManifest::decode(&nul).is_err());

    let env = launch + 16 + read32(&bytes, launch + 8) as usize;
    let second = env + 4 + 3;
    let mut duplicate = bytes.clone();
    duplicate[second + 4] = b'A';
    assert!(NativeProfileManifest::decode(&duplicate).is_err());
    let mut no_equals = bytes.clone();
    no_equals[env + 5] = b'X';
    assert!(NativeProfileManifest::decode(&no_equals).is_err());
    let mut empty_name = bytes.clone();
    empty_name[env + 4] = b'=';
    assert!(NativeProfileManifest::decode(&empty_name).is_err());

    let mut excludes_prefixes = bytes;
    let payload_only = read32(&excludes_prefixes, launch + 8) - 8;
    put32(&mut excludes_prefixes, launch + 8, payload_only);
    assert!(NativeProfileManifest::decode(&excludes_prefixes).is_err());
}

#[test]
fn manifest_refuses_correlated_but_foreign_coordinates_and_runtime_artifacts() {
    let (bytes, transfer, runtime) = material();
    for offset in [
        16,
        24,
        32,
        40,
        48,
        80,
        112,
        144,
        176,
        HEADER_BYTES + 2 * ARTIFACT_BYTES + 48,
    ] {
        let mut foreign = bytes.clone();
        foreign[offset] ^= 1;
        let manifest = NativeProfileManifest::decode(&foreign).unwrap();
        let mut digest_matches = transfer;
        digest_matches.profile_manifest_sha256 = Sha256::digest(&foreign).into();
        assert!(
            manifest
                .corroborate_transfer(&digest_matches, &runtime)
                .is_err(),
            "correlation {offset}"
        );
    }
    let manifest = NativeProfileManifest::decode(&bytes).unwrap();
    let mut foreign = transfer;
    foreign.profile_manifest_sha256[0] ^= 1;
    assert!(manifest.corroborate_transfer(&foreign, &runtime).is_err());
    foreign = transfer;
    foreign.artifact_count = 5;
    assert!(manifest.corroborate_transfer(&foreign, &runtime).is_err());
}
