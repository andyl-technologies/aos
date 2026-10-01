//! Exercises authenticated side attributes through actual durable publication.

#![allow(clippy::unwrap_used)]

use terrane_core::derived::{AttrRecord, AttributeValue};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

use super::StagedUpload;
use terrane_core::tree_builder::Tree;

use super::tests::{fixture, request, request_file, secret, token};

#[tokio::test]
async fn commit_requirements_use_only_authenticated_readable_side_records() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request_file(Vec::new(), b"source plaintext"))
        .await
        .unwrap();
    let object = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"source plaintext")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let producer = coordinator
        .guard()
        .verified_tree(first.commit)
        .await
        .unwrap();
    let mut hashes = terrane_core::derived::PlaintextHashes::new(16);
    hashes.update(b"source plaintext").unwrap();
    let value = AttributeValue::Sha256(hashes.finish().unwrap().sha256);
    let mut record = AttrRecord::new(object, value, first.commit);
    record.sign(&producer.commit, &secret()).unwrap();
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o600,
                    size: 16,
                    content: ContentRef::Inline(object),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "hashes",
                value: b"\x81\x66sha256",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let candidate = || {
        let mut candidate = request(vec![first.commit]);
        candidate.commit.tree = tree.root_identity();
        candidate.uploads = tree
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        candidate.uploads.extend(
            request_file(vec![first.commit], b"source plaintext")
                .uploads
                .into_iter()
                .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
        );
        candidate
    };
    // No inline hash or caller witness is present: the requirement fails closed.
    assert!(
        coordinator
            .advance(&mut session, candidate())
            .await
            .is_err()
    );
    let mut forged = record.clone();
    forged.signature.as_mut().unwrap()[0] ^= 1;
    let mut bad = candidate();
    bad.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Attribute,
        bytes: forged.encode().unwrap(),
    });
    assert!(coordinator.advance(&mut session, bad).await.is_err());
    let mut candidate = candidate();
    candidate.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Attribute,
        bytes: record.encode().unwrap(),
    });
    let published = coordinator.advance(&mut session, candidate).await.unwrap();
    assert_eq!(published.seq, first.seq + 1);
    assert_eq!(published.commit, session.record().unwrap().commit);
}
