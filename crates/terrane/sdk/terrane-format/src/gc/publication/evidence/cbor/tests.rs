//! Exercises hand-transcribed evidence witnesses independently of record codecs.
//!
//! Fixtures assemble fixed CDDL bodies with local byte/string framing only.
//! Production evidence encoders do not generate fixtures. Changes require
//! review against the published schemas and unchanged legacy golden vectors.
//! Successful decode demonstrates format consistency, never native authority.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use alloc::vec;

mod guard;
mod lineage;
mod original;
mod published;
mod view_interpretation;

const BEHAVIOR_NAMES: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn fixture_digest(output: &mut Vec<u8>, value: &[u8; 32]) {
    output.extend_from_slice(&[0x58, 0x20]);
    output.extend_from_slice(value);
}

fn fixture_string(output: &mut Vec<u8>, major: u8, value: &[u8]) {
    let length = value.len();
    match length {
        0..=23 => output.push(major | u8::try_from(length).unwrap()),
        24..=255 => output.extend_from_slice(&[major | 24, u8::try_from(length).unwrap()]),
        256..=65535 => {
            output.push(major | 25);
            output.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        }
        _ => panic!("fixture body is unexpectedly large"),
    }
    output.extend_from_slice(value);
}

fn local() -> LocalOriginalRegistration {
    LocalOriginalRegistration {
        original_id: [1; 32],
        root: b"/r".to_vec(),
        domain: "public".into(),
        root_device: 1,
        root_inode: 2,
        coordination_device: 3,
        coordination_inode: 4,
        control: b"/c".to_vec(),
    }
}

fn local_fixture() -> Vec<u8> {
    let mut bytes = vec![0x89, 1];
    fixture_digest(&mut bytes, &[1; 32]);
    bytes.extend_from_slice(&[
        0x42, b'/', b'r', 0x66, b'p', b'u', b'b', b'l', b'i', b'c', 1, 2, 3, 4, 0x42, b'/', b'c',
    ]);
    bytes
}

fn acl() -> AuthorityAcl {
    vec![
        AuthorityGrant {
            principal: "p".into(),
            verbs: 1,
        },
        AuthorityGrant {
            principal: "p".into(),
            verbs: 2,
        },
    ]
}

fn bootstrap() -> OriginalBootstrap {
    OriginalBootstrap {
        original_id: [1; 32],
        ref_name: "refs/heads/_/main".into(),
        epoch: 3,
        acl: acl(),
    }
}

fn bootstrap_fixture() -> Vec<u8> {
    let mut bytes = vec![0x85, 1];
    fixture_digest(&mut bytes, &[1; 32]);
    fixture_string(&mut bytes, 0x60, b"refs/heads/_/main");
    bytes.extend_from_slice(&[3, 0x82, 0x82, 0x61, b'p', 1, 0x82, 0x61, b'p', 2]);
    bytes
}

fn association() -> OriginalAssociation {
    OriginalAssociation {
        commit: [2; 32],
        original_id: [1; 32],
        ref_name: "refs/heads/_/main".into(),
        epoch: 3,
    }
}

fn association_fixture() -> Vec<u8> {
    let mut bytes = vec![0x85, 1];
    fixture_digest(&mut bytes, &[2; 32]);
    fixture_digest(&mut bytes, &[1; 32]);
    fixture_string(&mut bytes, 0x60, b"refs/heads/_/main");
    bytes.push(3);
    bytes
}

fn import() -> OriginalImport {
    OriginalImport {
        version: ImportVersion::LocalV1,
        registration: PhysicalRegistration::Local(local()),
        bootstrap: bootstrap(),
        association: association(),
    }
}

fn import_fixture() -> Vec<u8> {
    let mut bytes = vec![0x84, 1];
    bytes.extend_from_slice(&local_fixture());
    bytes.extend_from_slice(&bootstrap_fixture());
    bytes.extend_from_slice(&association_fixture());
    bytes
}

fn issuer() -> IssuerRow {
    IssuerRow {
        issuer: "i".into(),
        key_id: "k".into(),
        public_key: [5; 32],
        retired_at: None,
    }
}

fn issuer_fixture() -> Vec<u8> {
    let mut bytes = vec![0x84, 0x61, b'i', 0x61, b'k'];
    fixture_digest(&mut bytes, &[5; 32]);
    bytes.push(0xf6);
    bytes
}

fn disclosure() -> DisclosureRow {
    DisclosureRow {
        repository: "01".repeat(32),
        domain: "public".into(),
        public_key: [6; 32],
        not_before: 1,
        not_after: Some(2),
    }
}

fn disclosure_fixture() -> Vec<u8> {
    let mut bytes = vec![0x85, 0x78, 0x40];
    bytes.extend_from_slice("01".repeat(32).as_bytes());
    bytes.extend_from_slice(&[0x66, b'p', b'u', b'b', b'l', b'i', b'c']);
    fixture_digest(&mut bytes, &[6; 32]);
    bytes.extend_from_slice(&[1, 2]);
    bytes
}

fn profile() -> SeededChunkProfile {
    SeededChunkProfile {
        minimum: 262144,
        target: 1048576,
        maximum: 4194304,
        window: 48,
        normalization: 2,
        seed: [7; 32],
    }
}

fn profile_fixture() -> Vec<u8> {
    let mut bytes = vec![
        0x86, 0x1a, 0, 4, 0, 0, 0x1a, 0, 0x10, 0, 0, 0x1a, 0, 0x40, 0, 0, 0x18, 0x30, 2,
    ];
    fixture_digest(&mut bytes, &[7; 32]);
    bytes
}

fn config() -> TrustedGuardConfig {
    TrustedGuardConfig {
        store_name: "s".into(),
        private_domain_hint: "hint".into(),
        home: Locality {
            region: Some("r".into()),
            zone: None,
            host: Some("h".into()),
        },
        initial_acl: acl(),
        minimum_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: profile(),
        policy_authority: None,
    }
}

fn config_fixture() -> Vec<u8> {
    let mut bytes = vec![
        0xaa, 0, 1, 1, 0x61, b's', 2, 0x64, b'h', b'i', b'n', b't', 3, 0xa2, 1, 0x61, b'r', 3,
        0x61, b'h', 4, 0x82, 0x82, 0x61, b'p', 1, 0x82, 0x61, b'p', 2, 5, 0x1a, 0, 4, 0, 0, 6,
        0x66, b'p', b'u', b'b', b'l', b'i', b'c', 7, 0x66, b'c', b'd', b'c', b'-', b'1', b'm', 8,
    ];
    bytes.extend_from_slice(&profile_fixture());
    bytes.extend_from_slice(&[9, 0xf6]);
    bytes
}

fn registries() -> ConfiguredRegistryInputs {
    ConfiguredRegistryInputs {
        property_revision: 1,
        behavioral_properties: BEHAVIOR_NAMES.iter().map(|name| (*name).into()).collect(),
        attribute_revision: 1,
        selector_revision: 1,
        tree_revision: 1,
        chunk_revision: 1,
        identity_profile: "terrane-v1".into(),
        later_properties: vec![],
    }
}

fn registry_fixture() -> Vec<u8> {
    let mut bytes = vec![0xa9, 0, 1, 1, 1, 2, 0x98, 0x21];
    for name in BEHAVIOR_NAMES {
        fixture_string(&mut bytes, 0x60, name.as_bytes());
    }
    bytes.extend_from_slice(&[3, 1, 4, 1, 5, 1, 6, 1, 7, 0x6a]);
    bytes.extend_from_slice(b"terrane-v1");
    bytes.extend_from_slice(&[8, 0x80]);
    bytes
}

fn guard() -> GuardSnapshot {
    GuardSnapshot {
        registration: PhysicalRegistration::Local(local()),
        issuers: vec![],
        disclosures: vec![],
        configuration: config(),
        registries: registries(),
    }
}

fn guard_fixture() -> Vec<u8> {
    let mut bytes = vec![0xa6, 0, 1, 1];
    bytes.extend_from_slice(&local_fixture());
    bytes.extend_from_slice(&[2, 0x80, 3, 0x80, 4]);
    bytes.extend_from_slice(&config_fixture());
    bytes.push(5);
    bytes.extend_from_slice(&registry_fixture());
    bytes
}

fn registration_pin() -> RequiredControlPin {
    RequiredControlPin {
        kind: ControlKind::Registration,
        owner: PhysicalRegistration::Local(local()),
        key: "registration.cbor".into(),
        digest: *blake3::hash(&local_fixture()).as_bytes(),
    }
}

fn pin_fixture() -> Vec<u8> {
    let mut bytes = vec![0x84, 0];
    bytes.extend_from_slice(&local_fixture());
    fixture_string(&mut bytes, 0x60, b"registration.cbor");
    fixture_digest(&mut bytes, blake3::hash(&local_fixture()).as_bytes());
    bytes
}

fn used() -> LineageUsedInputs {
    LineageUsedInputs {
        issuers: vec![],
        disclosures: vec![],
        controls: vec![registration_pin()],
        registries: registries(),
        configuration: config(),
        views: vec![],
        view_interpretations: None,
    }
}

fn used_fixture() -> Vec<u8> {
    let mut bytes = vec![0xa7, 0, 1, 1, 0x80, 2, 0x80, 3, 0x81];
    bytes.extend_from_slice(&pin_fixture());
    bytes.push(4);
    bytes.extend_from_slice(&registry_fixture());
    bytes.push(5);
    bytes.extend_from_slice(&config_fixture());
    bytes.extend_from_slice(&[6, 0x80]);
    bytes
}

fn legacy_commit_fixture() -> Vec<u8> {
    // Published legacy vector fixes encoding, identity and primitive signature;
    // it supplies neither the later authoring context nor original authority.
    hex_bytes(concat!(
        "a70158209366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c",
        "20bbc392028003a8016e6973737565722e6578616d706c650250010203040506",
        "0708090a0b0c0d0e0f10036663692d6a6f620402067274657272616e652d636c",
        "692f636f6d6d6974071a68e7780008010901041a68e778000567696e69746961",
        "6c06a2010102666364632d316d0858400b1b8d248ff55846868046c342ee3ae5",
        "ca049862cec1c4c8ad9207f6fab19e73a6f5013337b587370634e366d70998ed",
        "715d1105f7ba505f6f519bd967dd710d"
    ))
}

fn legacy_ref_fixture() -> Vec<u8> {
    hex_bytes(concat!(
        "a4015820c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4ced",
        "e9c579d60201030104a1016965752d776573742d31"
    ))
}

fn checked_lineage() -> CheckedLineage {
    let source = RefRecord::decode(&legacy_ref_fixture()).unwrap();
    CheckedLineage {
        source_name: "refs/tags/_/alias".into(),
        commit_id: source.commit,
        source,
        commit_bytes: legacy_commit_fixture(),
        guard_digest: *blake3::hash(&guard_fixture()).as_bytes(),
        loss_generation: 0,
        controls: vec![registration_pin()],
        original: PhysicalRegistration::Local(local()),
        used: used(),
    }
}

fn lineage_fixture() -> Vec<u8> {
    let mut bytes = vec![0xaa, 0, 1, 1];
    fixture_string(&mut bytes, 0x60, b"refs/tags/_/alias");
    bytes.push(2);
    fixture_string(&mut bytes, 0x40, &legacy_ref_fixture());
    bytes.push(3);
    let commit_id: [u8; 32] =
        hex_bytes("c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6")
            .try_into()
            .unwrap();
    fixture_digest(&mut bytes, &commit_id);
    bytes.push(4);
    fixture_string(&mut bytes, 0x40, &legacy_commit_fixture());
    bytes.push(5);
    fixture_digest(&mut bytes, blake3::hash(&guard_fixture()).as_bytes());
    bytes.extend_from_slice(&[6, 0, 7, 0x81]);
    bytes.extend_from_slice(&pin_fixture());
    bytes.push(8);
    bytes.extend_from_slice(&local_fixture());
    bytes.push(9);
    bytes.extend_from_slice(&used_fixture());
    bytes
}
