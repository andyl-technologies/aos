//! Builds complete legacy immutable and ref models from their described fields.

use super::support::{assert_published_digest, digest, domain_digest, fixed, hexadecimal, wire};
use super::token_model;
use std::collections::BTreeMap;
use terrane_format::{
    auth::Token,
    chunking::ChunkProfile,
    derived::{AttrRecord, AttributeValue},
    identity::{Digest, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
    pack_format::{BundleRecord, decode_bundle, encode_bundle},
    refs::{
        Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance, RefLogReason,
        RefLogRecord, RefRecord,
    },
    tree_format::{ContentRef, Entry, EntryKind, LeafItem, Node, NodeItems, encode_node},
};

fn manifest_identity() -> Digest {
    digest("012fb6dded774e62a96a38b832da9f2f8f7eb5caa5dddefd2b405a4602b53e0c")
}

fn commit_identity() -> Digest {
    digest("c8efdd180de6c5b1e04abe4435238e8969776497759682c6094a4cede9c579d6")
}

fn node_identity() -> Digest {
    digest("9366ec79c4c37d11877e5767bab653177f4e80be8ed6aeb0cdcf4c3c20bbc392")
}

fn assert_identity(kind: IdentityKind, bytes: &[u8], expected: Digest) {
    assert_eq!(
        TERRANE_V1
            .calculate(kind, bytes)
            .unwrap()
            .terrane_v1_digest()
            .unwrap(),
        expected
    );
}

/// Compares the complete manifest model, wire and published identity.
///
/// # Panics
///
/// Panics if any encoding, decoding, identity or publication control differs.
pub(super) fn manifest() {
    let model = Manifest {
        size: 300_000,
        chunks: vec![
            ChunkRef {
                digest: digest("5860ee5a4a84d54950c417a0636b35e6e3fbbc1d52f8cf9efb810f0031278d67"),
                length: 262_144,
            },
            ChunkRef {
                digest: digest("39e1233664267460cfc8a61ceaff03ed99aa78475f4f5cb17ce2a2181c7b8746"),
                length: 37_856,
            },
        ],
        hashes: BTreeMap::from([
            (
                "blake3".into(),
                hexadecimal("6cc9dce05d4cff8c5bef5c5a24681e42b13f03e34a0bc5e66f65a91d48c944fa"),
            ),
            (
                "sha256".into(),
                hexadecimal("3c65ea93424a9c362fec0e3a69ea36031e8a358441479dd665cc6110eabe7b08"),
            ),
        ]),
        media_type: None,
    };
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let published = wire("## Manifest (encoding vector)", 0);

    assert_eq!(model.encode(&profile).unwrap(), published);
    assert_eq!(Manifest::decode(&published, &profile).unwrap(), model);
    assert_eq!(
        model
            .identity(&profile)
            .unwrap()
            .terrane_v1_digest()
            .unwrap(),
        manifest_identity()
    );
    assert_identity(IdentityKind::Manifest, &published, manifest_identity());
    assert_published_digest(
        "## Manifest (encoding vector)",
        "Object identity (domain `terrane-manifest-v1`): `",
        "`.\n",
        domain_digest(b"terrane-manifest-v1", &published),
    );
}

/// Compares the complete commit model, unsigned preimage and published hashes.
///
/// # Panics
///
/// Panics if any encoding, decoding, identity or publication control differs.
pub(super) fn commit() {
    let model = Commit {
        tree: node_identity(),
        parents: vec![],
        provenance: Provenance {
            issuer: "issuer.example".into(),
            token_id: core::array::from_fn(|index| u8::try_from(index + 1).unwrap()),
            subject: "ci-job".into(),
            kind: PrincipalKind::Workload,
            workload_identity: None,
            process: "terrane-cli/commit".into(),
            observed_at: 1_760_000_000,
            writer_epoch: 1,
            source: CommitSource::Built,
            embedded_token: None,
        },
        timestamp: 1_760_000_000,
        message: "initial".into(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: Some(fixed(concat!(
            "0b1b8d248ff55846868046c342ee3ae5ca049862cec1c4c8ad9207f6fab19e73a",
            "6f5013337b587370634e366d70998ed715d1105f7ba505f6f519bd967dd710d"
        ))),
    };
    let preimage = wire("## Commit", 0);
    let published = wire("## Commit", 1);

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(Commit::decode(&published).unwrap(), model);
    assert_eq!(model.signature_preimage().unwrap(), preimage);
    assert_eq!(
        blake3::hash(&preimage).as_bytes(),
        &digest("b3044fe851beb31a8462050527e959ca55ad1ab6cca5a3738986c216bda258cd")
    );
    assert_eq!(model.identity().unwrap(), commit_identity());
    assert_identity(IdentityKind::Commit, &published, commit_identity());
    assert_published_digest(
        "## Commit",
        "| BLAKE3 of the preimage | `",
        "` |\n",
        *blake3::hash(&preimage).as_bytes(),
    );
    assert_published_digest(
        "## Commit",
        "Commit identity (domain `terrane-commit-v1`): `",
        "`.\n",
        domain_digest(b"terrane-commit-v1", &published),
    );
}

/// Compares the independent token projection and ordinary decoded fields.
///
/// # Panics
///
/// Panics if the published token differs from its described model or identity.
pub(super) fn token() {
    let independently_encoded = token_model::wire_projection();
    let published = wire("## Capability token", 2);
    let decoded = Token::decode(&published).unwrap();

    assert_eq!(independently_encoded, published);
    assert_eq!(decoded.encode(), published);
    assert_eq!(decoded.signing_public_key(), token_model::next_key());
    assert_eq!(decoded, Token::decode(&independently_encoded).unwrap());
    assert_identity(
        IdentityKind::Policy,
        &published,
        digest("80b4bc13d21a64079eee4dec8887c51869ae38d6e81f3f59471cc3ab322c61e0"),
    );
}

fn reference_model() -> RefRecord {
    RefRecord {
        commit: commit_identity(),
        seq: 1,
        writer_epoch: 1,
        home: Locality {
            region: Some("eu-west-1".into()),
            zone: None,
            host: None,
        },
        policy: None,
        candidate_id: None,
    }
}

/// Compares the complete ref model with its published wire.
///
/// # Panics
///
/// Panics if encoding or decoding differs from the described model.
pub(super) fn reference() {
    let model = reference_model();
    let published = wire("## Ref record and reflog record", 0);

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(RefRecord::decode(&published).unwrap(), model);
}

/// Compares the complete reflog model with its published wire.
///
/// # Panics
///
/// Panics if encoding or decoding differs from the described model.
pub(super) fn reflog() {
    let model = RefLogRecord {
        record: reference_model(),
        previous_commit: None,
        principal: "ci-job".into(),
        reason: RefLogReason::Commit,
        timestamp: 1_760_000_000,
        expected_previous: None,
        committed_previous: None,
    };
    let published = wire("## Ref record and reflog record", 1);

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(RefLogRecord::decode(&published).unwrap(), model);
}

/// Compares the complete attribute model, wire and published identity.
///
/// # Panics
///
/// Panics if any encoding, decoding, identity or publication control differs.
pub(super) fn attribute() {
    let model = AttrRecord::new(
        manifest_identity(),
        AttributeValue::Sha256(digest(
            "3c65ea93424a9c362fec0e3a69ea36031e8a358441479dd665cc6110eabe7b08",
        )),
        commit_identity(),
    );
    let published = wire("## Attribute record", 0);
    let expected = digest("d66a8b356e79357277b5ef355d78ec061591ce79a13a3ea68675251a454bf592");

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(AttrRecord::decode(&published).unwrap(), model);
    assert_eq!(
        model.identity().unwrap().terrane_v1_digest().unwrap(),
        expected
    );
    assert_identity(IdentityKind::Attribute, &published, expected);
    assert_published_digest(
        "## Attribute record",
        "Record identity (domain `terrane-attr-v1`): `",
        "`.\n",
        domain_digest(b"terrane-attr-v1", &published),
    );
}

/// Compares the complete bundle and its independently constructed nested node.
///
/// # Panics
///
/// Panics if the published bytes, decoded fields or identities differ.
pub(super) fn bundle() {
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"hello.txt".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: 15,
                    content: ContentRef::Inline(digest(
                        "9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0",
                    )),
                    link_id: None,
                },
                attrs: vec![],
                attrs_present: false,
                xattrs: vec![],
                xattrs_present: false,
                provenance: None,
            },
        }]),
        props: None,
    };
    let payload = encode_node(&node, true, 262_144).unwrap();
    assert_eq!(payload, wire("## Leaf node with one inline file", 1));
    assert_identity(IdentityKind::Node, &payload, node_identity());
    let objects = [BundleRecord {
        kind: 2,
        hash: node_identity(),
        bytes: &payload,
    }];
    let published = wire("### descriptor-bundle", 1);
    let decoded = decode_bundle(&published).unwrap();

    assert_eq!(encode_bundle(&commit_identity(), &objects), published);
    assert_eq!(decoded.root_commit(), &commit_identity());
    assert_eq!(decoded.objects(), objects);
    assert_identity(
        IdentityKind::Bundle,
        &published,
        digest("488d3ad454092551a80c8723f1f699da90b0ca35289cb4168fb589727dc17249"),
    );
}
