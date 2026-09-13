//! Regression tests for the exact protected manifest language.

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use super::*;

const GOLDEN_HEX: &str = concat!(
    "414f53425343303100010401000100001010101010101010101010101010101020202020202020202020202020202020",
    "000000000000000721212121212121212121212121212121212121212121212121212121212121210000000000000008",
    "222222222222222222222222222222222222222222222222222222222222222200000000000000092323232323232323",
    "232323232323232323232323232323232323232323232323242424242424242424242424242424243030303030303030",
    "3030303030303030000000000000000a4040404040404040404040404040404040404040404040404040404040404040",
    "50505050505050505050505050505050000000000000001434750f98bd59fcfc946da45aaabe933be154a4b5094e1c4a",
    "bf42866505f3c97e01000000000000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "0000000000000005000000000000000f0000000000000000000000000000000031313131313131313131313131313131",
    "000000000000000b41414141414141414141414141414141414141414141414141414141414141415151515151515151",
    "515151515151515100000000000000156a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827",
    "02000000000000008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940000000000000006",
    "00000000000000100000000000000000000000000000000032323232323232323232323232323232000000000000000c",
    "424242424242424242424242424242424242424242424242424242424242424252525252525252525252525252525252",
    "0000000000000016b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b767090300000000000000ed",
    "4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10000000000000007000000000000001100",
    "00000000000000000000000000000033333333333333333333333333333333000000000000000d434343434343434343",
    "4343434343434343434343434343434343434343434343535353535353535353535353535353530000000000000017c5b9",
    "40ed3f65c391965de8295fc5d25f474fa57b48d36eb10ad363b8539c1b790400000000000000ca93ac1705187071d67b",
    "83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0000000000000008000000000000001200000000000000000000",
    "000000000000",
);
const GOLDEN_BINDING_HEX: &str = "61aea33546af9d99c79ac81bf0705500a81c94d472dbf98681c87308103dbb26";

fn manifest() -> BrokerSessionSecurityManifestV1 {
    let keys = core::array::from_fn(|index| {
        let seed = [u8::try_from(index + 1).unwrap_or(1); 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let usage = key_usages()[index];
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            [0x30 + u8::try_from(index).unwrap_or(0); 16],
            10 + u64::try_from(index).unwrap_or(0),
            [0x40 + u8::try_from(index).unwrap_or(0); 32],
            [0x50 + u8::try_from(index).unwrap_or(0); 16],
            20 + u64::try_from(index).unwrap_or(0),
            usage,
            &signing_key,
        )
        .unwrap_or_else(|error| panic!("valid signer failed: {error}"));
        BrokerSessionSecurityKeyPinV1::new(
            signer,
            signing_key.verifying_key().to_bytes(),
            5 + u64::try_from(index).unwrap_or(0),
            15 + u64::try_from(index).unwrap_or(0),
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("valid pin failed: {error}"))
    });
    BrokerSessionSecurityManifestV1::new(
        BrokerSessionProtocolV1::Network,
        BrokerSessionSecurityAudienceV1::NodeController,
        1,
        0,
        [0x10; 16],
        [0x20; 16],
        7,
        [0x21; 32],
        8,
        [0x22; 32],
        9,
        [0x23; 32],
        [0x24; 16],
        keys,
    )
    .unwrap_or_else(|error| panic!("valid manifest failed: {error}"))
}

#[test]
fn exact_golden_offsets_binding_and_round_trip() {
    let manifest = manifest();
    let encoded = manifest.encode();

    assert_eq!(encoded.len(), 920);
    assert_eq!(&encoded[0..8], b"AOSBSC01");
    assert_eq!(&encoded[8..10], &1_u16.to_be_bytes());
    assert_eq!(encoded[10], 4);
    assert_eq!(encoded[11], 1);
    assert_eq!(&encoded[12..14], &1_u16.to_be_bytes());
    assert_eq!(&encoded[14..16], &0_u16.to_be_bytes());
    assert_eq!(&encoded[16..32], &[0x10; 16]);
    assert_eq!(&encoded[32..48], &[0x20; 16]);
    assert_eq!(&encoded[48..56], &7_u64.to_be_bytes());
    assert_eq!(&encoded[56..88], &[0x21; 32]);
    assert_eq!(&encoded[88..96], &8_u64.to_be_bytes());
    assert_eq!(&encoded[96..128], &[0x22; 32]);
    assert_eq!(&encoded[128..136], &9_u64.to_be_bytes());
    assert_eq!(&encoded[136..168], &[0x23; 32]);
    assert_eq!(&encoded[168..184], &[0x24; 16]);
    for (index, usage) in [1_u8, 2, 3, 4].into_iter().enumerate() {
        let start = 184 + index * 184;
        assert_eq!(encoded[start + 112], usage);
        assert_eq!(&encoded[start + 113..start + 120], &[0; 7]);
        assert_eq!(&encoded[start + 170..start + 176], &[0; 6]);
    }

    assert_eq!(hex::encode(encoded), GOLDEN_HEX);
    assert_eq!(
        hex::encode(manifest.binding().as_bytes()),
        GOLDEN_BINDING_HEX
    );
    assert_eq!(
        BrokerSessionSecurityManifestV1::decode(&encoded),
        Ok(manifest)
    );
}

#[test]
fn exact_length_magic_version_and_closed_codes_fail() {
    let encoded = manifest().encode();
    assert!(BrokerSessionSecurityManifestV1::decode(&encoded[..919]).is_err());
    let mut too_long = encoded.to_vec();
    too_long.push(0);
    assert!(BrokerSessionSecurityManifestV1::decode(&too_long).is_err());

    for (offset, value) in [(0, 0), (9, 2), (10, 0), (10, 5), (11, 0), (11, 2)] {
        let mut mutated = encoded;
        mutated[offset] = value;
        assert!(BrokerSessionSecurityManifestV1::decode(&mutated).is_err());
    }

    let mut wrong_version = encoded;
    wrong_version[12..14].copy_from_slice(&2_u16.to_be_bytes());
    assert!(BrokerSessionSecurityManifestV1::decode(&wrong_version).is_err());
    let mut wrong_minor = encoded;
    wrong_minor[14..16].copy_from_slice(&1_u16.to_be_bytes());
    assert!(BrokerSessionSecurityManifestV1::decode(&wrong_minor).is_err());
}

#[test]
fn every_prefix_sentinel_fails() {
    let encoded = manifest().encode();
    for range in [
        16..32,
        32..48,
        48..56,
        56..88,
        88..96,
        96..128,
        128..136,
        136..168,
        168..184,
    ] {
        let mut mutated = encoded;
        mutated[range].fill(0);
        assert!(BrokerSessionSecurityManifestV1::decode(&mutated).is_err());
    }
}

#[test]
fn signer_reserved_codes_order_and_sentinels_fail() {
    let encoded = manifest().encode();
    for index in 0..4 {
        let start = 184 + index * 184;
        for range in [
            start..start + 16,
            start + 16..start + 24,
            start + 24..start + 56,
            start + 56..start + 72,
            start + 72..start + 80,
            start + 80..start + 112,
        ] {
            let mut mutated = encoded;
            mutated[range].fill(0);
            assert!(BrokerSessionSecurityManifestV1::decode(&mutated).is_err());
        }

        let mut bad_usage = encoded;
        bad_usage[start + 112] = if index == 0 { 2 } else { 1 };
        assert!(BrokerSessionSecurityManifestV1::decode(&bad_usage).is_err());
        let mut unknown_usage = encoded;
        unknown_usage[start + 112] = 5;
        assert!(BrokerSessionSecurityManifestV1::decode(&unknown_usage).is_err());
        for reserved in start + 113..start + 120 {
            let mut mutated = encoded;
            mutated[reserved] = 1;
            assert!(BrokerSessionSecurityManifestV1::decode(&mutated).is_err());
        }
        for reserved in start + 170..start + 176 {
            let mut mutated = encoded;
            mutated[reserved] = 1;
            assert!(BrokerSessionSecurityManifestV1::decode(&mutated).is_err());
        }
    }
}

#[test]
fn key_currentness_language_is_canonical() {
    let encoded = manifest().encode();
    for index in 0..4 {
        let start = 184 + index * 184;
        for offset in [start + 152, start + 160] {
            let mut zero_floor = encoded;
            zero_floor[offset..offset + 8].fill(0);
            assert!(BrokerSessionSecurityManifestV1::decode(&zero_floor).is_err());
        }
        for offset in [start + 168, start + 169] {
            let mut bad_boolean = encoded;
            bad_boolean[offset] = 2;
            assert!(BrokerSessionSecurityManifestV1::decode(&bad_boolean).is_err());
        }

        let mut absent_nonzero = encoded;
        absent_nonzero[start + 176..start + 184].copy_from_slice(&30_u64.to_be_bytes());
        assert!(BrokerSessionSecurityManifestV1::decode(&absent_nonzero).is_err());
        let mut present_zero = encoded;
        present_zero[start + 169] = 1;
        assert!(BrokerSessionSecurityManifestV1::decode(&present_zero).is_err());
        let mut nonadvancing = encoded;
        nonadvancing[start + 169] = 1;
        nonadvancing[start + 176..start + 184]
            .copy_from_slice(&(20 + u64::try_from(index).unwrap_or(0)).to_be_bytes());
        assert!(BrokerSessionSecurityManifestV1::decode(&nonadvancing).is_err());

        let mut authority_floor_too_high = encoded;
        authority_floor_too_high[start + 152..start + 160]
            .copy_from_slice(&(11 + u64::try_from(index).unwrap_or(0)).to_be_bytes());
        assert!(BrokerSessionSecurityManifestV1::decode(&authority_floor_too_high).is_err());
        let mut key_floor_too_high = encoded;
        key_floor_too_high[start + 160..start + 168]
            .copy_from_slice(&(21 + u64::try_from(index).unwrap_or(0)).to_be_bytes());
        assert!(BrokerSessionSecurityManifestV1::decode(&key_floor_too_high).is_err());
    }
}

#[test]
fn fingerprints_weak_keys_and_pairwise_identity_fail() {
    let encoded = manifest().encode();
    let mut fingerprint = encoded;
    fingerprint[184 + 80] ^= 1;
    assert!(BrokerSessionSecurityManifestV1::decode(&fingerprint).is_err());
    let mut raw_key = encoded;
    raw_key[184 + 120] ^= 1;
    assert!(BrokerSessionSecurityManifestV1::decode(&raw_key).is_err());

    let weak = [0_u8; 32];
    let weak_signer = BrokerSessionSignerReferenceV1::new(
        [1; 16],
        1,
        [2; 32],
        [3; 16],
        1,
        Sha256::digest(weak).into(),
        BrokerSessionKeyUsageV1::ClientHello,
    )
    .unwrap_or_else(|error| panic!("shape-valid signer failed: {error}"));
    assert!(BrokerSessionSecurityKeyPinV1::new(weak_signer, weak, 1, 1, false, None).is_err());

    let second = 184 + 184;
    let mut repeated_key_id = encoded;
    repeated_key_id[second + 56..second + 72].copy_from_slice(&encoded[184 + 56..184 + 72]);
    assert!(BrokerSessionSecurityManifestV1::decode(&repeated_key_id).is_err());

    let mut repeated_public_key = encoded;
    repeated_public_key[second + 80..second + 112].copy_from_slice(&encoded[184 + 80..184 + 112]);
    repeated_public_key[second + 120..second + 152].copy_from_slice(&encoded[184 + 120..184 + 152]);
    assert!(BrokerSessionSecurityManifestV1::decode(&repeated_public_key).is_err());
}

#[test]
fn audience_protocol_matrix_and_active_state_are_explicit() {
    let host_root = BrokerSessionSecurityManifestV1::new(
        BrokerSessionProtocolV1::Host,
        BrokerSessionSecurityAudienceV1::RootMount,
        1,
        0,
        manifest().domain_id(),
        manifest().route_id(),
        1,
        [1; 32],
        1,
        [2; 32],
        1,
        [3; 32],
        [4; 16],
        manifest().key_pins().clone(),
    );
    assert!(host_root.is_ok());

    let wrong_root = BrokerSessionSecurityManifestV1::new(
        BrokerSessionProtocolV1::Network,
        BrokerSessionSecurityAudienceV1::RootMount,
        1,
        0,
        manifest().domain_id(),
        manifest().route_id(),
        1,
        [1; 32],
        1,
        [2; 32],
        1,
        [3; 32],
        [4; 16],
        manifest().key_pins().clone(),
    );
    assert!(wrong_root.is_err());

    let mut revoked = manifest().encode();
    revoked[184 + 168] = 1;
    let decoded = BrokerSessionSecurityManifestV1::decode(&revoked)
        .unwrap_or_else(|error| panic!("revoked manifest should be shape-valid: {error}"));
    assert!(decoded.require_all_active().is_err());

    let mut superseded = manifest().encode();
    superseded[184 + 169] = 1;
    superseded[184 + 176..184 + 184].copy_from_slice(&30_u64.to_be_bytes());
    let decoded = BrokerSessionSecurityManifestV1::decode(&superseded)
        .unwrap_or_else(|error| panic!("superseded manifest should be shape-valid: {error}"));
    assert!(decoded.require_all_active().is_err());
}

#[test]
fn every_protocol_has_only_its_exact_supported_version() {
    for (protocol, expected) in [
        (BrokerSessionProtocolV1::Host, (1, 0)),
        (BrokerSessionProtocolV1::Storage, (1, 0)),
        (BrokerSessionProtocolV1::Mount, (2, 0)),
        (BrokerSessionProtocolV1::Network, (1, 0)),
    ] {
        let template = manifest();
        let valid = BrokerSessionSecurityManifestV1::new(
            protocol,
            BrokerSessionSecurityAudienceV1::NodeController,
            expected.0,
            expected.1,
            template.domain_id(),
            template.route_id(),
            1,
            [1; 32],
            1,
            [2; 32],
            1,
            [3; 32],
            [4; 16],
            template.key_pins().clone(),
        );
        assert!(valid.is_ok());

        let wrong = BrokerSessionSecurityManifestV1::new(
            protocol,
            BrokerSessionSecurityAudienceV1::NodeController,
            expected.0,
            expected.1 + 1,
            template.domain_id(),
            template.route_id(),
            1,
            [1; 32],
            1,
            [2; 32],
            1,
            [3; 32],
            [4; 16],
            template.key_pins().clone(),
        );
        assert!(wrong.is_err());
    }
}
