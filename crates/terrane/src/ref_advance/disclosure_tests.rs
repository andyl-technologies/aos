//! Exercises scoped disclosure admission against two physically separate buckets.

#![allow(clippy::unwrap_used)]

use super::native_fixture::NativeFixture;
use super::tests::{Validator, config, fixture, raw_fixture, request, request_file, token};
use super::{CommitTiming, Coordinator, DisclosureUpload, StagedUpload};
use crate::bucket::FileBucket;
use crate::guard::Guard;
use crate::store::{ContentStore, TokioClock, TokioLocalFs};
use std::time::Duration;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

#[tokio::test]
async fn disclosure_factory_checks_actual_source_and_destination_before_fresh_upload() {
    let unused = raw_fixture().await;
    let mut source_config = unused.guard().config().clone();
    source_config.storage_domain = "private:writer".into();
    source_config.private_domain = "private:writer".into();
    let source_bucket = FileBucket::open(
        config(unused.store().root().to_owned()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let source = Coordinator::new(
        Guard::new(
            source_bucket,
            TokioClock,
            unused.guard().keys().to_vec(),
            source_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let source = NativeFixture::initialize(source).await;
    let destination = fixture().await;
    assert_ne!(source.store().root(), destination.store().root());
    let reference = "refs/heads/_/main";
    let mut destination_session = destination.begin(reference, &token(), "sdk").await.unwrap();
    let destination_head = destination
        .advance(&mut destination_session, request(Vec::new()))
        .await
        .unwrap();
    let bytes = b"private file";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    let object = identity.terrane_v1_digest().unwrap();
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: bytes.len() as u64,
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
                value: b"\x6eprivate:writer",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let original = request_file(Vec::new(), bytes);
    let chunk = original
        .uploads
        .iter()
        .find(|upload| matches!(upload, StagedUpload::Chunk { .. }))
        .unwrap()
        .clone();
    let mut proposal = request(Vec::new());
    proposal.commit.tree = tree.root_identity();
    proposal.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    proposal.uploads.push(chunk.clone());
    let mut source_session = source.begin(reference, &token(), "sdk").await.unwrap();
    let source_head = source.advance(&mut source_session, proposal).await.unwrap();
    assert_eq!(
        source
            .store()
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap(),
        vec![true]
    );
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap(),
        vec![false]
    );
    let input = |upload| DisclosureUpload {
        source_reference: reference.into(),
        source_commit: source_head.commit,
        source_path: b"/file".to_vec(),
        source_token: token(),
        destination_reference: reference.into(),
        destination_path: b"/file".to_vec(),
        destination_token: token(),
        surface: "sdk".into(),
        upload,
    };
    let mut corrupt = chunk.clone();
    if let StagedUpload::Chunk { encoded, .. } = &mut corrupt {
        *encoded.last_mut().unwrap() ^= 1;
    }
    assert!(
        destination
            .prepare_disclosure(source.guard(), input(corrupt))
            .await
            .is_err()
    );
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap(),
        vec![false]
    );
    let receipt = destination
        .prepare_disclosure(source.guard(), input(chunk.clone()))
        .await
        .unwrap();
    assert_eq!(receipt.source().domain, "private:writer");
    assert_eq!(receipt.destination().domain, "public");
    assert_eq!(
        receipt.source_access().read_commit(),
        Some(&source_head.commit)
    );
    assert_eq!(
        receipt.source_access().reference_record(),
        Some(&source_head)
    );
    assert_eq!(receipt.source_path(), b"/file");
    assert_eq!(receipt.record().identity(), &identity);
    assert_eq!(
        destination
            .store()
            .has(std::slice::from_ref(&identity))
            .await
            .unwrap(),
        vec![true]
    );
    assert_eq!(destination_session.record(), Some(&destination_head));

    let mut incomplete = request(vec![destination_head.commit]);
    incomplete.disclosures.push(receipt);
    assert!(
        destination
            .advance(&mut destination_session, incomplete)
            .await
            .is_err()
    );
    assert_eq!(destination_session.record(), Some(&destination_head));

    let revoked_tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: bytes.len() as u64,
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
                value: b"\x80",
            },
            Property {
                name: "domain",
                value: b"\x6eprivate:writer",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut revoke = request(vec![source_head.commit]);
    revoke.commit.tree = revoked_tree.root_identity();
    revoke.uploads = revoked_tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    source.advance(&mut source_session, revoke).await.unwrap();

    assert!(
        destination
            .prepare_disclosure(source.guard(), input(chunk))
            .await
            .is_err()
    );
    assert_eq!(destination_session.record(), Some(&destination_head));
}

#[tokio::test]
async fn disclosure_role_is_dedicated_and_missing_seed_is_not_repaired() {
    use crate::bucket::held::SingleHeld;
    use crate::repository::local_authority::disclosure;
    use crate::store::{Clock, LocalFs};

    let source = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = source.begin(reference, &token(), "sdk").await.unwrap();
    let head = source
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let original = source.guard().original_commit(&head.commit).unwrap();
    let authority = original.baseline().authority();
    let roles = source.guard().configured_disclosure_roles().unwrap();
    assert_eq!(roles.len(), 1);
    let role = &roles[0];
    assert_eq!(role.domain, authority.domain());
    assert_ne!(role.public_key, source.guard().keys()[0].public_key);
    assert_ne!(
        role.public_key,
        terrane_core::auth::Token::decode(&token())
            .unwrap()
            .signing_public_key()
    );
    let now = source
        .guard()
        .clock()
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let seed_path = {
        let holder = SingleHeld::acquire(source.store()).await.unwrap();
        let held = holder.destination();
        let identity = held.identity_proof();
        let mut controls = source
            .guard()
            .hold_original_registration(authority, &identity)
            .await
            .unwrap();
        let signer = disclosure::load(source.guard(), authority, &mut controls, now)
            .await
            .unwrap();
        assert_eq!(signer.role(), role);
        let records = signer.retained_records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].1.len(), 32);
        let retained = controls.retain_named(&records).await.unwrap();
        assert_eq!(retained.records().len(), 2);
        authority.control().join(&records[1].0)
    };

    source.store().fs().remove_file(&seed_path).await.unwrap();
    let holder = SingleHeld::acquire(source.store()).await.unwrap();
    let held = holder.destination();
    let identity = held.identity_proof();
    let mut controls = source
        .guard()
        .hold_original_registration(authority, &identity)
        .await
        .unwrap();
    assert!(
        disclosure::load(source.guard(), authority, &mut controls, now)
            .await
            .is_err()
    );
    assert!(
        source
            .store()
            .fs()
            .symlink_metadata(&seed_path)
            .await
            .is_err()
    );
    assert_eq!(source.guard().configured_disclosure_roles().unwrap(), roles);
}
