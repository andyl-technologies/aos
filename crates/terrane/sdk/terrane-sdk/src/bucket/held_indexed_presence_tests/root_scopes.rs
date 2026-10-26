//! Discovers genuine signed root occurrences before scoped index negotiation.

use terrane_format::{
    auth::{Attenuation, Grant, Token, Verbs},
    identity::{IdentityKind, TERRANE_V1},
    surface::View,
    tree_builder::Tree,
    tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse},
};

use crate::ref_advance::{
    StagedUpload,
    tests::{fixture, request_file, secret, token},
};

const REFERENCE: &str = "refs/heads/_/main";

fn scoped_token(path: &str, not_after: Option<u64>) -> Vec<u8> {
    Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after,
                not_before: None,
                grants: Some(vec![
                    Grant::new(format!("{REFERENCE}:{path}"), Verbs::new(1).unwrap()).unwrap(),
                ]),
                caveats: Vec::new(),
            },
            &secret(),
            terrane_format::auth::public_key_from_secret(&[0x71; 32]),
        )
        .unwrap()
        .encode()
}

#[tokio::test]
async fn guarded_root_discovery_preserves_nested_only_and_same_digest_scopes() {
    let native = fixture().await;
    let bytes = b"root-scoped negotiation payload";
    let mut request = request_file(Vec::new(), bytes);
    let child = request.commit.tree;
    let entries = [b"docs".as_slice(), b"secret".as_slice()]
        .into_iter()
        .map(|key| LeafItem {
            key: key.to_vec(),
            entry: Entry {
                kind: EntryKind::Tree {
                    root: child,
                    props: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        })
        .collect();
    let parent = Tree::build(
        entries,
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    request.commit.tree = parent.root_identity();
    request
        .uploads
        .extend(parent.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let mut writer = native.begin(REFERENCE, &token(), "sdk").await.unwrap();
    native.advance(&mut writer, request).await.unwrap();
    let repository = native.repository();

    assert_eq!(
        repository
            .readable_root_paths(REFERENCE, &token(), "sdk")
            .await
            .unwrap(),
        [b"/".to_vec(), b"/docs".to_vec(), b"/secret".to_vec()]
    );
    let scoped = scoped_token("/docs", None);
    assert!(
        repository
            .ref_head(REFERENCE, &scoped, "sdk")
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .readable_root_paths(REFERENCE, &scoped, "sdk")
            .await
            .unwrap(),
        [b"/docs".to_vec()]
    );
    assert!(
        repository
            .readable_root_paths(REFERENCE, &scoped_token("/docs/file", None), "sdk")
            .await
            .unwrap()
            .is_empty()
    );

    let view = View::parse(&format!("{REFERENCE}:/docs")).unwrap();
    let prepared = repository
        .prepare_file_read(&view, b"file", &scoped, "sdk")
        .await
        .unwrap();
    let digest = TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    assert_eq!(prepared.indexed_presence(&[digest]).await.unwrap(), [true]);
    let sibling = View::parse(&format!("{REFERENCE}:/secret")).unwrap();
    assert!(
        repository
            .prepare_file_read(&sibling, b"file", &scoped, "sdk")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn guarded_root_discovery_checks_identity_even_for_absent_refs() {
    let native = fixture().await;
    let repository = native.repository();

    assert!(
        repository
            .readable_root_paths(REFERENCE, &token(), "sdk")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .readable_root_paths(REFERENCE, b"invalid token", "sdk")
            .await
            .is_err()
    );
    assert!(
        repository
            .readable_root_paths(REFERENCE, &scoped_token("/docs", Some(1)), "sdk")
            .await
            .is_err()
    );
}
