//! Exercises guarded publication against reopened native durable storage.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::guard::{Guard, GuardConfig};
use crate::store::{
    ContentStore, ContentValidator, LocalFs, MetaUpload, RefStore, StoreFailure, TokioClock,
    TokioLocalFs,
};
use std::time::Duration;
use terrane_core::auth::{Authority, Grant, IssuerKey, Token, Verbs};
use terrane_core::chunking::ChunkProfile;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{Property, TreeUse};

/// Validates the canonical metadata accepted by the shared native test bucket.
pub(crate) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let valid = match upload.kind() {
            IdentityKind::Node => {
                terrane_core::tree_format::decode_node(upload.bytes(), true, 262144).is_ok()
            }
            IdentityKind::Commit => Commit::decode(upload.bytes()).is_ok(),
            IdentityKind::Attribute => {
                terrane_core::derived::AttrRecord::decode(upload.bytes()).is_ok()
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(crate::guard::invalid())
        }
    }
}

type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

fn key(hex: &str) -> [u8; 32] {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub(super) fn secret() -> [u8; 32] {
    key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
}

fn public() -> [u8; 32] {
    key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
}

/// Issues the shared fixture's writer token with its registered test key.
///
/// # Panics
/// Panics when the fixed test key, grants or token cannot be encoded.
pub(crate) fn token() -> Vec<u8> {
    Token::issue(
        Authority {
            issuer: "test".into(),
            key_id: "key".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [1; 16],
            grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
            workload: None,
        },
        &secret(),
        public(),
    )
    .unwrap()
    .encode()
}

/// Establishes independent administrative ownership before opening the payload.
///
/// # Panics
/// Panics when the actual private test administration directory cannot be checked.
pub(super) async fn config(root: std::path::PathBuf) -> FileBucketConfig {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let administrative = root.with_file_name(format!(
        "{}-operator",
        root.file_name().unwrap().to_string_lossy()
    ));
    if let Err(error) = TokioLocalFs.symlink_metadata(&administrative).await {
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        TokioLocalFs.create_dir_new(&administrative).await.unwrap();
        TokioLocalFs
            .set_permissions_and_sync(&administrative, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
    }
    let operator = TokioLocalFs
        .symlink_metadata(&administrative)
        .await
        .unwrap();
    assert!(operator.is_dir());
    assert!(!operator.file_type().is_symlink());
    assert_eq!(operator.mode() & 0o777, 0o700);

    FileBucketConfig {
        root,
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid: operator.uid(),
            control: None,
        }),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: ChunkProfile::cdc_1m([0; 32]),
        locality: Locality::default(),
    }
}

/// Opens a fresh native fixture with production protected retention initialized.
///
/// # Panics
/// Panics when test storage or protected native authority cannot be initialized.
pub(crate) async fn fixture() -> super::native_fixture::NativeFixture<TokioLocalFs> {
    super::native_fixture::NativeFixture::initialize(raw_fixture().await).await
}

pub(super) async fn raw_fixture() -> Coordinator<Bucket, TokioClock, TokioLocalFs> {
    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix = entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let bucket = FileBucket::open(
        config(std::env::temp_dir().join(format!("terrane-ref-{suffix}"))).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    configured(bucket)
}

pub(super) fn configured<S: crate::store::Store>(
    bucket: S,
) -> Coordinator<S, TokioClock, TokioLocalFs> {
    configured_with_fs(bucket, TokioLocalFs)
}

pub(super) fn configured_with_fs<S: crate::store::Store, F>(
    bucket: S,
    fs: F,
) -> Coordinator<S, TokioClock, F> {
    Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![IssuerKey {
                issuer: "test".into(),
                key_id: "key".into(),
                public_key: public(),
                retirement: None,
            }],
            GuardConfig {
                store_name: "local".into(),
                private_domain: "private:test".into(),
                home: Locality::default(),
                initial_acl: vec![("writer".into(), 31)],
                min_chunk_size: 262144,
                storage_domain: "public".into(),
                chunk_profile_name: "cdc-1m".into(),
                chunk_profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
                policy_authority: None,
            },
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        fs,
    )
}

#[tokio::test]
async fn notes_sidecars_refuse_branch_sessions_and_policy_advances() {
    let coordinator = raw_fixture().await;
    let reference = "refs/notes/_/advisory";
    let before = {
        let held = crate::bucket::held::SingleHeld::acquire(coordinator.store())
            .await
            .unwrap();
        held.destination()
            .observe_publication()
            .await
            .unwrap()
            .stamp()
    };

    // Invalid classes must be refused before token validation or any effects.
    assert!(matches!(
        coordinator.begin(reference, &[], "sdk").await,
        Err(AdvanceError::InvalidRefClass)
    ));
    assert!(matches!(
        coordinator
            .begin_scoped(reference, &[], &[b"/".to_vec()], "sdk")
            .await,
        Err(AdvanceError::InvalidRefClass)
    ));
    assert!(matches!(
        coordinator.set_policy(reference, None, &[], "sdk").await,
        Err(AdvanceError::InvalidRefClass)
    ));

    let held = crate::bucket::held::SingleHeld::acquire(coordinator.store())
        .await
        .unwrap();
    assert_eq!(
        held.destination()
            .observe_publication()
            .await
            .unwrap()
            .stamp(),
        before
    );
}

#[tokio::test]
async fn rollback_is_an_ordinary_selected_advance_to_an_earlier_commit() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request_file(Vec::new(), b"source plaintext"))
        .await
        .unwrap();
    let second = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    let rolled_back = coordinator
        .rollback(&mut session, first.commit, &token(), "sdk")
        .await
        .unwrap();
    assert_eq!(rolled_back.commit, first.commit);
    assert_eq!(rolled_back.seq, second.seq + 1);
    assert_eq!(rolled_back.writer_epoch, session.epoch());
    let root = coordinator.store().root().to_owned();
    let reopened = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let logs = reopened.ref_log_read(session.reference(), 1).await.unwrap();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[2].reason, terrane_core::refs::RefLogReason::Rollback);
    assert_eq!(logs[2].expected_previous, Some(Some(second)));
    assert_eq!(logs[2].record, rolled_back);
    assert_eq!(
        reopened.ref_get(session.reference()).await.unwrap(),
        Some(rolled_back)
    );
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn fork_creates_fresh_commit_with_source_parent_and_copied_receipts() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request_file(Vec::new(), b"source plaintext"))
        .await
        .unwrap();
    let mut fork_request = request(Vec::new());
    fork_request.uploads.clear();
    let fork = coordinator
        .fork(session.reference(), "refs/heads/_/child", fork_request)
        .await
        .unwrap();
    assert_ne!(fork.commit, first.commit);
    let original = coordinator
        .guard()
        .verified_tree(first.commit)
        .await
        .unwrap();
    let copied = coordinator
        .guard()
        .verified_tree(fork.commit)
        .await
        .unwrap();
    assert_eq!(copied.commit.commit().tree, original.commit.commit().tree);
    assert_eq!(copied.commit.commit().parents, vec![first.commit]);
    let receipt = &copied
        .commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_ref()
        .unwrap()[0];
    assert!(
        matches!(&receipt.origin, terrane_core::refs::EntryOrigin::Source(source)
        if source.commit == first.commit && source.root == original.evidence.root && source.path == b"file")
    );
    assert!(
        matches!(&receipt.attributes.as_ref().unwrap()[0].1, terrane_core::refs::EntryOrigin::Source(source)
        if source.commit == first.commit && source.path == b"file")
    );
    assert_eq!(
        copied
            .commit
            .commit()
            .profile_pair
            .commit_context
            .as_ref()
            .unwrap()
            .reference(),
        "refs/heads/_/child"
    );
    let mut duplicate = request(Vec::new());
    duplicate.uploads.clear();
    assert!(matches!(
        coordinator
            .fork(session.reference(), "refs/heads/_/child", duplicate)
            .await,
        Err(AdvanceError::Fenced { .. })
    ));
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

pub(crate) fn request(parents: Vec<[u8; 32]>) -> CommitRequest {
    request_acl(parents, 31)
}

/// Builds the shared file proposal with the fixture's full writer ACL.
///
/// # Panics
/// Panics when the canonical fixture tree or content identity cannot be built.
pub(crate) fn request_file(parents: Vec<[u8; 32]>, plaintext: &[u8]) -> CommitRequest {
    request_file_acl(parents, plaintext, 31)
}

/// Builds an unsigned file proposal with an explicit canonical root ACL.
///
/// # Panics
/// Panics when the canonical fixture tree or content identity cannot be built.
pub(crate) fn request_file_acl(
    parents: Vec<[u8; 32]>,
    plaintext: &[u8],
    verbs: u8,
) -> CommitRequest {
    use terrane_core::tree_format::{Attribute, ContentRef, Entry, EntryKind, LeafItem};

    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap();
    let mut request = request(parents);
    let mut acl = vec![0x81, 0x82, 0x66];
    acl.extend_from_slice(b"writer");
    terrane_core::cbor::write_uint(&mut acl, u64::from(verbs));
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(identity.terrane_v1_digest().unwrap()),
                    link_id: None,
                },
                attrs: vec![Attribute {
                    name: "note",
                    value: b"\x61x",
                }],
                attrs_present: true,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(vec![
            Property {
                name: "acl",
                value: &acl,
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
    request.commit.tree = tree.root_identity();
    request.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    request.uploads.push(StagedUpload::Chunk {
        encoded: terrane_core::codec::encode_envelope(terrane_core::codec::EncodedChunk {
            codec: terrane_core::codec::Codec::Raw,
            body: plaintext,
        }),
        identity,
        declared_plaintext_len: plaintext.len(),
        position: crate::store::ChunkPosition::Final,
        profile: Box::new(ChunkProfile::cdc_1m([0; 32])),
    });
    request
}

#[tokio::test]
async fn immutable_read_keeps_its_target_and_rechecks_live_policy() {
    use terrane_core::tree_format::ContentRef;

    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request_file(Vec::new(), b"first"))
        .await
        .unwrap();
    let snapshot = coordinator
        .guard()
        .read_commit_snapshot(first.commit, &token(), b"/file", "sdk")
        .await
        .unwrap();
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, b"first").unwrap();
    let content = ContentRef::Inline(identity.terrane_v1_digest().unwrap());
    let second = coordinator
        .advance(&mut session, request_file(vec![first.commit], b"second"))
        .await
        .unwrap();
    assert_ne!(snapshot.commit.identity(), second.commit);
    assert_eq!(
        coordinator
            .guard()
            .read_content(&snapshot, b"/file", content, 5)
            .await
            .unwrap(),
        b"first"
    );
    let access = coordinator
        .guard()
        .domain_content_access(&snapshot, b"/file", content, 5)
        .await
        .unwrap();
    assert!(access.permits_identity(&identity));
    let root = TERRANE_V1
        .from_digest(IdentityKind::Node, &snapshot.evidence.root)
        .unwrap();
    assert!(!access.permits_identity(&root));
    assert_eq!(access.binding().root, root);
    assert_eq!(access.read_commit(), Some(&first.commit));
    assert_eq!(access.reference_record(), Some(&second));
    assert_eq!(access.read_path(&identity), Some(b"/file".as_slice()));
    assert_eq!(access.reference_record(), Some(&second));
    assert!(
        coordinator
            .guard()
            .read_content(&snapshot, b"/outside", content, 5)
            .await
            .is_err()
    );
    coordinator
        .advance(&mut session, request_acl(vec![second.commit], 0))
        .await
        .unwrap();
    assert!(
        coordinator
            .guard()
            .read_content(&snapshot, b"/file", content, 5)
            .await
            .is_err()
    );
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn multiwriter_rebases_with_ordered_verified_core_merge_and_source_receipts() {
    use terrane_core::refs::{MergePolicy, RefLogReason, RefPolicy};

    let coordinator = fixture().await;
    let mut initial = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    coordinator
        .advance(&mut initial, request_file(Vec::new(), b"base"))
        .await
        .unwrap();
    let base = coordinator
        .set_policy(
            initial.reference(),
            Some(RefPolicy {
                multi_writer: Some(true),
                merge_policies: Some(vec![MergePolicy::PreferTheirs]),
                ..RefPolicy::default()
            }),
            &token(),
            "sdk",
        )
        .await
        .unwrap();
    let mut ours = coordinator
        .begin(initial.reference(), &token(), "sdk")
        .await
        .unwrap();
    let mut theirs = coordinator
        .begin(initial.reference(), &token(), "sdk")
        .await
        .unwrap();
    assert_eq!(ours.epoch(), theirs.epoch());
    let current = coordinator
        .advance(&mut ours, request_file(vec![base.commit], b"ours"))
        .await
        .unwrap();
    let merged = coordinator
        .advance(&mut theirs, request_file(vec![base.commit], b"theirs"))
        .await
        .unwrap();
    assert_eq!(merged.seq, current.seq + 1);
    assert_eq!(merged.writer_epoch, current.writer_epoch);
    let signed = coordinator
        .guard()
        .verified_tree(merged.commit)
        .await
        .unwrap();
    assert_eq!(signed.commit.commit().parents[0], current.commit);
    assert_eq!(signed.commit.commit().parents.len(), 2);
    assert!(signed.commit.commit().profile_pair.recipe.is_some());
    let own_commit = signed.commit.commit().parents[1];
    let receipt = &signed
        .commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_ref()
        .unwrap()[0];
    assert!(
        matches!(&receipt.origin, terrane_core::refs::EntryOrigin::Source(source) if source.commit == own_commit)
    );
    let snapshot = coordinator
        .guard()
        .read_snapshot(initial.reference(), &token(), b"/file", "sdk")
        .await
        .unwrap();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"theirs")
        .unwrap();
    assert_eq!(
        coordinator
            .guard()
            .read_content(
                &snapshot,
                b"/file",
                terrane_core::tree_format::ContentRef::Inline(
                    identity.terrane_v1_digest().unwrap()
                ),
                6
            )
            .await
            .unwrap(),
        b"theirs"
    );
    let root = coordinator.store().root().to_owned();
    let reopened = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let logs = reopened.ref_log_read(initial.reference(), 1).await.unwrap();
    assert_eq!(logs.last().unwrap().reason, RefLogReason::Merge);
    assert_eq!(logs.last().unwrap().expected_previous, Some(Some(current)));
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn explicit_merge_and_fold_recompute_signed_source_views_and_ordered_parents() {
    use terrane_core::refs::{MergePolicy, RefLogReason};

    for fold in [false, true] {
        let coordinator = fixture().await;
        let mut parent = coordinator
            .begin("refs/heads/_/main", &token(), "sdk")
            .await
            .unwrap();
        let base = coordinator
            .advance(&mut parent, request_file(Vec::new(), b"base"))
            .await
            .unwrap();
        let mut signing = request(Vec::new());
        signing.uploads.clear();
        let fork = coordinator
            .fork(parent.reference(), "refs/heads/_/child", signing)
            .await
            .unwrap();
        let mut child = coordinator
            .begin("refs/heads/_/child", &token(), "sdk")
            .await
            .unwrap();
        let incoming = coordinator
            .advance(&mut child, request_file(vec![fork.commit], b"incoming"))
            .await
            .unwrap();
        let mut signing = request(Vec::new());
        signing.uploads.clear();
        let record = if fold {
            let outcome = coordinator
                .fold(
                    &mut parent,
                    child.reference(),
                    signing,
                    &[MergePolicy::Error],
                )
                .await
                .unwrap();
            assert!(outcome.excluded.is_empty());
            outcome.record
        } else {
            coordinator
                .merge(
                    &mut parent,
                    child.reference(),
                    signing,
                    &[MergePolicy::Error],
                )
                .await
                .unwrap()
        };
        let selected = coordinator
            .guard()
            .verified_tree(record.commit)
            .await
            .unwrap();
        let source = coordinator
            .guard()
            .verified_tree(incoming.commit)
            .await
            .unwrap();
        assert_eq!(
            selected.commit.commit().parents,
            vec![base.commit, incoming.commit]
        );
        assert_eq!(selected.commit.commit().tree, source.commit.commit().tree);
        let receipt = &selected
            .commit
            .commit()
            .profile_pair
            .entry_receipts
            .as_ref()
            .unwrap()[0];
        assert!(
            matches!(&receipt.origin, terrane_core::refs::EntryOrigin::Source(source) if source.commit == incoming.commit)
        );
        let logs = coordinator
            .store()
            .ref_log_read(parent.reference(), 1)
            .await
            .unwrap();
        assert_eq!(
            logs.last().unwrap().reason,
            if fold {
                RefLogReason::Fold
            } else {
                RefLogReason::Merge
            }
        );
        assert_eq!(
            coordinator
                .store()
                .ref_get(child.reference())
                .await
                .unwrap(),
            Some(incoming)
        );
        tokio::fs::remove_dir_all(coordinator.store().root())
            .await
            .unwrap();
    }
}

fn request_acl(parents: Vec<[u8; 32]>, mask: u8) -> CommitRequest {
    let mut acl = vec![0x81, 0x82, 0x66, b'w', b'r', b'i', b't', b'e', b'r'];
    if mask < 24 {
        acl.push(mask);
    } else {
        acl.extend([0x18, mask]);
    }
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: &acl,
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
    let uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    CommitRequest {
        commit: Commit {
            tree: tree.root_identity(),
            parents,
            provenance: Provenance {
                issuer: "".into(),
                token_id: [0; 16],
                subject: "".into(),
                kind: PrincipalKind::Human,
                workload_identity: None,
                process: "test".into(),
                observed_at: 0,
                writer_epoch: 0,
                source: CommitSource::Built,
                embedded_token: None,
            },
            timestamp: 0,
            message: "advance".into(),
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
            signature: None,
        },
        uploads,
        token: token(),
        terminal_secret: secret(),
        surface: "sdk".into(),
        reference_records: Vec::new(),
        disclosures: Vec::new(),
    }
}

#[tokio::test]
async fn ref_advance_ordering_survives_reopen_with_exact_log_and_commit() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let second = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    assert_eq!(second.seq, 2);
    assert_eq!(second.writer_epoch, first.writer_epoch);

    let root = coordinator.store().root().to_owned();
    let reopened = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.ref_get(session.reference()).await.unwrap(),
        Some(second.clone())
    );
    let log = reopened.ref_log_read(session.reference(), 1).await.unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[1].previous_commit, Some(first.commit));
    assert_eq!(log[1].record, second);
    let id = TERRANE_V1
        .from_digest(IdentityKind::Commit, &second.commit)
        .unwrap();
    let bytes = reopened.get(&id, None).await.unwrap();
    let commit = Commit::decode(&bytes).unwrap();
    assert_eq!(commit.parents, vec![first.commit]);
    assert!(commit.signature.is_some());
    let node = TERRANE_V1
        .from_digest(IdentityKind::Node, &commit.tree)
        .unwrap();
    assert!(reopened.get(&node, None).await.is_ok());
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn ref_epoch_fencing_requires_a_new_session_after_conflict() {
    let coordinator = fixture().await;
    let mut winner = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let mut loser = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let record = coordinator
        .advance(&mut winner, request(Vec::new()))
        .await
        .unwrap();

    assert!(
        matches!(coordinator.advance(&mut loser, request(Vec::new())).await,
        Err(AdvanceError::Fenced { current: Some(current) }) if *current == record)
    );
    assert!(matches!(
        coordinator
            .advance(&mut loser, request(vec![record.commit]))
            .await,
        Err(AdvanceError::Fenced { .. })
    ));
    let renewed = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    assert_eq!(renewed.epoch(), record.writer_epoch + 1);
    assert_eq!(
        coordinator
            .store()
            .ref_get(winner.reference())
            .await
            .unwrap(),
        Some(record)
    );
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn ref_watch_emits_current_then_waits_and_fills_every_committed_sequence() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let mut watch = coordinator
        .watch(session.reference(), &token(), "sdk")
        .await
        .unwrap();
    assert_eq!(watch.next().await.unwrap().unwrap().record, first);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), watch.next())
            .await
            .is_err()
    );

    let second = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    let third = coordinator
        .advance(&mut session, request(vec![second.commit]))
        .await
        .unwrap();
    assert_eq!(watch.next().await.unwrap().unwrap().record, second);
    assert_eq!(watch.next().await.unwrap().unwrap().record, third);
    watch.close();
    assert!(watch.next().await.unwrap().is_none());
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn current_acl_revocation_cannot_be_overridden_by_candidate_acl() {
    let coordinator = fixture().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let revoked = coordinator
        .advance(&mut session, request_acl(vec![first.commit], 1))
        .await
        .unwrap();

    assert!(
        coordinator
            .advance(&mut session, request(vec![revoked.commit]))
            .await
            .is_err()
    );
    assert_eq!(
        coordinator
            .store()
            .ref_get(session.reference())
            .await
            .unwrap(),
        Some(revoked)
    );
    assert_eq!(
        coordinator
            .store()
            .ref_log_read(session.reference(), 1)
            .await
            .unwrap()
            .len(),
        2
    );
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn revoked_current_admin_denies_acl_restore_but_preserves_commit_only_publication() {
    let coordinator = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let revoked = coordinator
        .advance(&mut session, request_acl(vec![first.commit], 15))
        .await
        .unwrap();

    let restored = coordinator
        .advance(&mut session, request_acl(vec![revoked.commit], 31))
        .await;
    assert!(matches!(restored, Err(AdvanceError::Store(ref error))
        if matches!(error.kind(), crate::store::StoreErrorKind::Denied { .. })));
    assert_eq!(
        coordinator.store().ref_get(reference).await.unwrap(),
        Some(revoked.clone())
    );
    assert_eq!(
        coordinator
            .store()
            .ref_log_read(reference, 1)
            .await
            .unwrap()
            .len(),
        2
    );

    let commit_only = Token::issue(
        Authority {
            issuer: "test".into(),
            key_id: "key".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [3; 16],
            grants: vec![Grant::new(reference.into(), Verbs::new(4).unwrap()).unwrap()],
            workload: None,
        },
        &secret(),
        public(),
    )
    .unwrap()
    .encode();
    let mut ordinary = request_acl(vec![revoked.commit], 15);
    ordinary.token = commit_only;
    let published = coordinator.advance(&mut session, ordinary).await.unwrap();
    assert_eq!(published.seq, revoked.seq + 1);
    assert_eq!(
        coordinator.store().ref_get(reference).await.unwrap(),
        Some(published)
    );
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn source_scoped_tag_only_authority_creates_signed_immutable_tags() {
    let coordinator = fixture().await;
    let source = "refs/heads/_/main";
    let mut session = coordinator.begin(source, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), b"tagged"))
        .await
        .unwrap();
    let restricted = Token::issue(
        Authority {
            issuer: "test".into(),
            key_id: "key".into(),
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            groups: Vec::new(),
            not_after: u64::MAX,
            not_before: None,
            token_id: [2; 16],
            grants: vec![Grant::new(source.into(), Verbs::new(8).unwrap()).unwrap()],
            workload: None,
        },
        &secret(),
        public(),
    )
    .unwrap()
    .encode();
    assert!(coordinator.begin(source, &restricted, "sdk").await.is_err());
    let plain = coordinator
        .tag(source, "refs/tags/_/plain", &restricted, "sdk")
        .await
        .unwrap();
    assert_eq!(plain.commit, head.commit);
    assert_eq!(plain.writer_epoch, head.writer_epoch);
    assert_eq!(plain.seq, 1);
    assert_eq!(plain.candidate_id, None);
    assert!(
        coordinator
            .tag(source, "refs/tags/_/plain", &restricted, "sdk")
            .await
            .is_err()
    );
    let annotated = coordinator
        .annotated_tag(
            source,
            "refs/tags/_/signed",
            &restricted,
            "sdk",
            &super::TagAnnotation {
                attestation: vec![0xa0],
                terminal_secret: secret(),
            },
        )
        .await
        .unwrap();
    let envelope = annotated
        .policy
        .as_ref()
        .unwrap()
        .snapshot
        .as_ref()
        .unwrap();
    assert_eq!(envelope.tag.as_str(), "refs/tags/_/signed");
    assert_eq!(envelope.commit, head.commit);
    assert_eq!(envelope.signer_key.len(), 64);
    let root = coordinator.store().root().to_path_buf();
    let reopened = FileBucket::open(config(root).await, TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    assert_eq!(
        reopened.ref_get("refs/tags/_/signed").await.unwrap(),
        Some(annotated)
    );
}

#[tokio::test]
async fn private_local_bootstrap_uses_configured_acl_domain_and_profile() {
    let original = raw_fixture().await;
    let mut guard_config = original.guard().config().clone();
    guard_config.storage_domain = "private:writer".into();
    guard_config.private_domain = "private:writer".into();
    let root = original.store().root().to_path_buf();
    let bucket = FileBucket::open(config(root).await, TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    let coordinator = Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            original.guard().keys().to_vec(),
            guard_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let coordinator = super::native_fixture::NativeFixture::initialize(coordinator).await;
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x6eprivate:writer",
            },
            Property {
                name: "durability",
                value: b"\x65local",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut candidate = request(Vec::new());
    candidate.commit.tree = tree.root_identity();
    candidate.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let published = coordinator.advance(&mut session, candidate).await.unwrap();
    assert_eq!(published.seq, 1);
}
