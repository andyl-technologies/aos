//! Exercises scoped disclosure admission against two physically separate buckets.

#![allow(clippy::unwrap_used)]

use super::native_fixture::NativeFixture;
use super::tests::{Validator, config, fixture, raw_fixture, request, request_file, token};
use super::{CommitTiming, Coordinator, DisclosureUpload, StagedUpload};
use crate::bucket::FileBucket;
use crate::guard::Guard;
use crate::store::{ContentStore, TokioClock, TokioLocalFs};
use std::time::Duration;
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

#[cfg(unix)]
mod ancestry;
#[cfg(unix)]
mod boundary_checks;
#[cfg(unix)]
mod collection_history;
#[cfg(unix)]
mod conflicts;
#[cfg(unix)]
mod control_lock;
#[cfg(unix)]
mod coverage;
#[cfg(unix)]
mod current_authority;
#[cfg(unix)]
mod dictionaries;
#[cfg(unix)]
mod domain_scope;
#[cfg(unix)]
mod fresh_recovery;
#[cfg(unix)]
mod historical_keys;
#[cfg(unix)]
mod import_controls;
#[cfg(unix)]
mod index_rebuild;
#[cfg(unix)]
mod limited;
#[cfg(unix)]
mod materialization;
mod multiple;
#[cfg(unix)]
mod occupied_recovery;
#[cfg(unix)]
mod occurrences;
#[cfg(unix)]
mod original_acl;
#[cfg(unix)]
mod parents;
#[cfg(unix)]
mod producers;
#[cfg(unix)]
mod raw_kinds;
#[cfg(unix)]
mod recorded;
#[cfg(unix)]
mod rotation;
#[cfg(unix)]
mod whiteouts;
#[cfg(unix)]
pub(crate) mod witness_support;

#[cfg(unix)]
#[tokio::test]
async fn disclosure_current_authority_rechecks_both_whole_heads_tokens_epochs_and_root_acls() {
    current_authority::recheck_current_authority().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_domain_reference_order_and_dedup_remain_scoped() {
    domain_scope::preserve_domain_scope().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_projection_rejects_tree_whiteout_conflict_and_index_entries() {
    raw_kinds::reject_special_projections().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_original_binding_rejects_copied_or_conflicting_import_controls() {
    import_controls::reject_copied_controls().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_original_acl_verification_survives_destination_only_reopen() {
    original_acl::retain_original_authorization().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_uses_public_introducer_and_public_ancestry() {
    ancestry::check_public_selectors().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_copied_attributes_require_independent_public_producers() {
    producers::preserve_public_attribute_producer().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_first_and_second_parent_cuts_require_complete_origins() {
    parents::certify_complete_parent_cuts().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_nested_and_repeated_root_occurrences_check_actual_domains() {
    occurrences::certify_repeated_roots().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_rejects_whole_commit_receipt_and_projection_mutations() {
    boundary_checks::reject_signed_mutations().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_projection_safe_materialization_certifies_each_flattened_file() {
    materialization::certify_flattened_files().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_graft_preserves_independent_private_attribute_producer() {
    materialization::preserve_relocated_attribute_producer().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_replacement_graft_preserves_carried_private_producers() {
    materialization::preserve_replacement_graft_producers().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_projection_safe_conflict_resolution_certifies_selected_file() {
    conflicts::certify_resolved_file().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_directory_marker_and_raw_symlink_have_limited_scope() {
    limited::certify_limited_entries().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_rejects_uncovered_siblings_attributes_and_unanchored_parents() {
    coverage::reject_incomplete_boundaries().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_dictionary_dependencies_preserve_registered_codecs_and_verified_lengths() {
    dictionaries::publish_dictionary_codecs().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_paired_retry_reopens_a_fresh_destination_before_source_erasure() {
    fresh_recovery::recover_fresh_transition().await;
}

#[cfg(unix)]
mod recovery;

#[cfg(unix)]
#[tokio::test]
async fn disclosure_paired_retry_recovers_exact_installed_imports_without_relaxing_open() {
    recovery::recover_cached_transition().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_paired_retry_refuses_unrelated_added_role_carriers() {
    recovery::refuse_unrelated_transition().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_paired_publication_refuses_equal_subjects_of_different_kinds() {
    recovery::refuse_cross_kind_pair().await;
}

#[tokio::test]
async fn disclosure_boundary_manifest_and_multiple_source_certificates() {
    multiple::publish_independent_manifests().await;
}

/// Creates real independently generated signing credentials and protected state.
///
/// # Panics
/// Panics if native fixture initialization or protected signing setup refuses.
pub(crate) async fn independent_factory(
    domain: &str,
) -> (
    NativeFixture<TokioLocalFs>,
    crate::repository::local_authority::LocalAuthority,
    std::path::PathBuf,
) {
    independent_factory_kind(domain, terrane_format::refs::PrincipalKind::Human).await
}

async fn independent_factory_kind(
    domain: &str,
    principal_kind: terrane_format::refs::PrincipalKind,
) -> (
    NativeFixture<TokioLocalFs>,
    crate::repository::local_authority::LocalAuthority,
    std::path::PathBuf,
) {
    independent_factory_claims(domain, principal_kind, Vec::new()).await
}

/// Initializes genuine signed group claims without changing ordinary fixture defaults.
async fn independent_factory_claims(
    domain: &str,
    principal_kind: terrane_format::refs::PrincipalKind,
    groups: Vec<String>,
) -> (
    NativeFixture<TokioLocalFs>,
    crate::repository::local_authority::LocalAuthority,
    std::path::PathBuf,
) {
    independent_factory_profile(domain, principal_kind, groups, None).await
}

/// Chooses actual authoring inputs before initializing any protected native state.
async fn independent_factory_profile(
    domain: &str,
    principal_kind: terrane_format::refs::PrincipalKind,
    groups: Vec<String>,
    authoring: Option<crate::guard::AuthoringNamespaceProfile>,
) -> (
    NativeFixture<TokioLocalFs>,
    crate::repository::local_authority::LocalAuthority,
    std::path::PathBuf,
) {
    use crate::repository::local_authority::{LocalAuthority, LocalAuthorityParameters};
    use crate::store::LocalFs;
    use std::os::unix::fs::MetadataExt;
    use terrane_format::auth::{Authority, Grant, Verbs};

    let raw = raw_fixture().await;
    let root = raw.store().root().to_owned();
    let credentials = root.with_file_name(format!(
        "{}-credentials",
        root.file_name().unwrap().to_string_lossy(),
    ));
    let owner_uid = TokioLocalFs.metadata(&root).await.unwrap().uid();
    let authority = LocalAuthority::initialize(
        &TokioLocalFs,
        &root,
        &credentials,
        LocalAuthorityParameters {
            owner_uid,
            authority: Authority {
                issuer: "local".into(),
                key_id: "initial".into(),
                subject: "writer".into(),
                kind: principal_kind,
                groups,
                not_after: u64::MAX,
                not_before: None,
                token_id: TokioLocalFs
                    .random_bytes(16)
                    .await
                    .unwrap()
                    .try_into()
                    .unwrap(),
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
                workload: None,
            },
        },
    )
    .await
    .unwrap();
    let mut guard_config = raw.guard().config().clone();
    guard_config.storage_domain = domain.into();
    drop(raw);
    let bucket = FileBucket::open(config(root).await, TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    let keys = vec![authority.issuer_key().clone()];
    let guard = match authoring {
        Some(profile) => Guard::new_with_authoring_namespace_profile(
            bucket,
            TokioClock,
            keys,
            guard_config,
            profile,
        ),
        None => Guard::new(bucket, TokioClock, keys, guard_config),
    };
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    (
        NativeFixture::initialize(coordinator).await,
        authority,
        credentials,
    )
}

#[tokio::test]
async fn disclosure_paired_factories_keep_identical_labels_independent_after_source_erasure() {
    use super::{DisclosureCommitRequest, DisclosureCommitSelection};

    let (source, source_authority, source_credentials) = independent_factory("public").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    assert_eq!(
        source_authority.issuer_key().issuer,
        destination_authority.issuer_key().issuer
    );
    assert_eq!(
        source_authority.issuer_key().key_id,
        destination_authority.issuer_key().key_id
    );
    assert_ne!(
        source_authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );

    let reference = "refs/heads/_/main";
    let plaintext = b"independent factory disclosure";
    let mut source_session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let original = request_file(Vec::new(), plaintext);
    let mut source_request = source_authority.commit_request(original.commit, "sdk".into());
    source_request.uploads = original.uploads;
    let source_head = source
        .advance(&mut source_session, source_request)
        .await
        .unwrap();
    let mut destination_session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let proposed = request_file(Vec::new(), plaintext);
    let mut proposal = destination_authority.commit_request(proposed.commit, "sdk".into());
    proposal.uploads = proposed.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut destination_session,
            DisclosureCommitRequest {
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
                proposal,
            },
        )
        .await
        .unwrap();
    assert_eq!(destination_session.record(), Some(&published));

    let source_root = source.store().root().to_owned();
    let source_control = source_root.with_file_name(format!(
        "{}-original-control",
        source_root.file_name().unwrap().to_string_lossy()
    ));
    let destination_root = destination.store().root().to_owned();
    let destination_config = destination.guard().config().clone();
    drop(source_session);
    drop(source);
    drop(source_authority);
    tokio::fs::remove_dir_all(source_root).await.unwrap();
    tokio::fs::remove_dir_all(source_control).await.unwrap();
    tokio::fs::remove_dir_all(source_credentials).await.unwrap();
    drop(destination_session);
    drop(destination);

    let bucket = FileBucket::open(
        config(destination_root).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let reopened = NativeFixture::reopen(Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![destination_authority.issuer_key().clone()],
            destination_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    ))
    .await;
    let snapshot = reopened
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), published.commit);
    let (location, _) = snapshot.history.locate(published.commit, b"file").unwrap();
    let EntryKind::File { content, size, .. } = snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("published entry is a file");
    };
    assert_eq!(
        reopened
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
}

/// Preserves a genuine file proposal while changing only its explicit root domain.
fn private_file_request(parents: Vec<[u8; 32]>, plaintext: &[u8]) -> super::CommitRequest {
    use terrane_format::tree_format::Attribute;

    let mut proposal = request_file(parents, plaintext);
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: plaintext.len() as u64,
                    content: ContentRef::Inline(content),
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
    proposal.commit.tree = tree.root_identity();
    proposal
        .uploads
        .retain(|upload| matches!(upload, StagedUpload::Chunk { .. }));
    proposal
        .uploads
        .extend(tree.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    proposal
}

#[tokio::test]
async fn disclosure_boundary_reopens_after_source_and_signing_seed_erasure() {
    use super::{DisclosureCommitRequest, DisclosureCommitSelection};

    let (original, original_authority, original_credentials) = independent_factory("public").await;
    let (source, source_authority, source_credentials) =
        independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    assert_eq!(
        original_authority.issuer_key().issuer,
        source_authority.issuer_key().issuer
    );
    assert_eq!(
        source_authority.issuer_key().key_id,
        destination_authority.issuer_key().key_id
    );
    assert_ne!(
        original_authority.issuer_key().public_key,
        source_authority.issuer_key().public_key
    );
    assert_ne!(
        source_authority.issuer_key().public_key,
        destination_authority.issuer_key().public_key
    );
    let reference = "refs/heads/_/main";
    let plaintext = b"public origin preserved across private descendants";
    let mut original_session = original
        .begin(reference, original_authority.token(), "sdk")
        .await
        .unwrap();
    let initial = request_file(Vec::new(), plaintext);
    let mut proposal = original_authority.commit_request(initial.commit, "sdk".into());
    proposal.uploads = initial.uploads;
    let public_head = original
        .advance(&mut original_session, proposal)
        .await
        .unwrap();

    let mut source_session = source
        .begin(reference, source_authority.token(), "sdk")
        .await
        .unwrap();
    let initial = private_file_request(Vec::new(), plaintext);
    let mut proposal = source_authority.commit_request(initial.commit, "sdk".into());
    proposal.uploads = initial.uploads;
    let normalized = source
        .advance_disclosure(
            original.guard(),
            &mut source_session,
            DisclosureCommitRequest {
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: public_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: original_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
                proposal,
            },
        )
        .await
        .unwrap();

    let snapshot = source
        .guard()
        .read_snapshot(reference, source_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let (location, _) = snapshot.history.locate(normalized.commit, b"file").unwrap();
    let preserved = snapshot.history.entry(&location).unwrap();
    let secret = b"private sibling must stay private";
    let secret_identity = TERRANE_V1.calculate(IdentityKind::Chunk, secret).unwrap();
    let secret_entry = Entry {
        kind: EntryKind::File {
            mode: 0o600,
            size: secret.len() as u64,
            content: ContentRef::Inline(secret_identity.terrane_v1_digest().unwrap()),
            link_id: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let tree = Tree::build(
        vec![
            LeafItem {
                key: b"file".to_vec(),
                entry: preserved,
            },
            LeafItem {
                key: b"secret".to_vec(),
                entry: secret_entry,
            },
        ],
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
    let mut private =
        source_authority.commit_request(request(vec![normalized.commit]).commit, "sdk".into());
    private.commit.tree = tree.root_identity();
    private.uploads = tree
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    private.uploads.extend(
        request_file(Vec::new(), secret)
            .uploads
            .into_iter()
            .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
    );
    let private_root = tree.root_identity();
    drop(tree);
    let private_head = source.advance(&mut source_session, private).await.unwrap();
    assert_eq!(
        source
            .guard()
            .read_snapshot(reference, source_authority.token(), b"/file", "sdk")
            .await
            .unwrap()
            .history
            .introducing_commit(&terrane_format::provenance::EntryLocation {
                commit: private_head.commit,
                root: private_root,
                path: b"file".to_vec()
            })
            .unwrap(),
        normalized.commit
    );

    let mut destination_session = destination
        .begin(reference, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let selected = request_file(Vec::new(), plaintext);
    let mut proposal = destination_authority.commit_request(selected.commit, "sdk".into());
    proposal.uploads = selected.uploads;
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut destination_session,
            DisclosureCommitRequest {
                selections: vec![DisclosureCommitSelection {
                    source_reference: reference.into(),
                    source_commit: private_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
                proposal,
            },
        )
        .await
        .unwrap();
    let private_commit_id = TERRANE_V1
        .from_digest(IdentityKind::Commit, &private_head.commit)
        .unwrap();
    let private_node_id = TERRANE_V1
        .from_digest(IdentityKind::Node, &private_root)
        .unwrap();
    let normalized_id = TERRANE_V1
        .from_digest(IdentityKind::Commit, &normalized.commit)
        .unwrap();
    assert_eq!(
        destination
            .store()
            .has(&[
                private_commit_id,
                private_node_id,
                normalized_id,
                secret_identity
            ])
            .await
            .unwrap(),
        vec![false; 4]
    );
    assert_eq!(
        destination
            .store()
            .has(&[TERRANE_V1
                .from_digest(IdentityKind::Commit, &public_head.commit)
                .unwrap()])
            .await
            .unwrap(),
        vec![true]
    );

    let erase = |root: &std::path::Path| {
        root.with_file_name(format!(
            "{}-original-control",
            root.file_name().unwrap().to_string_lossy()
        ))
    };
    let original_root = original.store().root().to_owned();
    let original_control = erase(&original_root);
    let source_root = source.store().root().to_owned();
    let source_control = erase(&source_root);
    let destination_root = destination.store().root().to_owned();
    let destination_config = destination.guard().config().clone();
    drop(snapshot);
    drop(original_session);
    drop(source_session);
    drop(destination_session);
    drop(original);
    drop(source);
    drop(original_authority);
    drop(source_authority);
    for path in [
        original_root,
        original_control,
        original_credentials,
        source_root,
        source_control,
        source_credentials,
    ] {
        tokio::fs::remove_dir_all(path).await.unwrap();
    }
    drop(destination);
    let bucket = FileBucket::open(
        config(destination_root).await,
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let reopened = NativeFixture::reopen(Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![destination_authority.issuer_key().clone()],
            destination_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    ))
    .await;
    let snapshot = reopened
        .guard()
        .read_snapshot(reference, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(snapshot.commit.identity(), published.commit);
    let (location, _) = snapshot.history.locate(published.commit, b"file").unwrap();
    let EntryKind::File { content, size, .. } = snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("selected projection is a file");
    };
    assert_eq!(
        reopened
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
    assert!(snapshot.history.commit(&private_head.commit).is_none());
    assert!(snapshot.history.commit(&normalized.commit).is_none());
    assert!(snapshot.history.commit(&public_head.commit).is_some());
}

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
        terrane_format::auth::Token::decode(&token())
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

/// Stages negative administrative fixtures from an actual checked local factory.
///
/// This helper supplies no publication capability and does not stand in for the
/// paired producer. Its records preserve genuine original and dedicated-role
/// coordinates so each negative isolates the intended protected-context check.
#[cfg(unix)]
async fn stage_same_local_import(
    source: &NativeFixture<TokioLocalFs>,
    original: &crate::guard::OriginalCommitContext,
) -> crate::repository::local_authority::retention::ImportRecord {
    use crate::bucket::held::SingleHeld;
    use crate::repository::local_authority::{
        disclosure,
        import_binding::ImportBindingRecord,
        public_trust::PublicTrustRecord,
        retention::{self, Record},
    };
    use crate::store::Clock;

    let authority = source.guard().configured_original_authority().unwrap();
    assert_eq!(original.baseline().authority(), &authority);
    let import = original.retained_import_record().unwrap();
    let binding = ImportBindingRecord {
        commit: *original.commit(),
        source_authority: *authority.id(),
        destination_authority: *authority.id(),
        import_digest: *blake3::hash(&import.encode().unwrap()).as_bytes(),
    };
    let holder = SingleHeld::acquire(source.store()).await.unwrap();
    let held = holder.destination();
    let identity = held.identity_proof();
    let mut controls = source
        .guard()
        .hold_original_registration(&authority, &identity)
        .await
        .unwrap();
    let now = source
        .guard()
        .clock()
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signer = disclosure::load(source.guard(), &authority, &mut controls, now)
        .await
        .unwrap();
    let trust = PublicTrustRecord {
        import_digest: binding.import_digest,
        source_authority: binding.source_authority,
        destination_authority: binding.destination_authority,
        issuer_keys: source.guard().keys().to_vec(),
        disclosure_roles: vec![signer.role().clone()],
    };
    let owner = source.store().publication_operator_uid().unwrap();

    retention::retain(
        source.store().fs(),
        authority.control(),
        owner,
        &import.selector(),
        &import,
        true,
    )
    .await
    .unwrap();
    retention::retain(
        source.store().fs(),
        authority.control(),
        owner,
        &binding.selector().unwrap(),
        &binding,
        true,
    )
    .await
    .unwrap();
    retention::retain(
        source.store().fs(),
        authority.control(),
        owner,
        &trust.selector().unwrap(),
        &trust,
        true,
    )
    .await
    .unwrap();
    controls.revalidate().await.unwrap();
    import
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_same_local_import_cannot_replace_missing_original_records() {
    use crate::bucket::held::SingleHeld;
    use crate::store::LocalFs;

    for missing_bootstrap in [true, false] {
        let source = fixture().await;
        let reference = "refs/heads/_/main";
        let mut session = source.begin(reference, &token(), "sdk").await.unwrap();
        let head = source
            .advance(&mut session, request(Vec::new()))
            .await
            .unwrap();
        let original = source.guard().original_commit(&head.commit).unwrap();
        let import = stage_same_local_import(&source, &original).await;
        let authority = source.guard().configured_original_authority().unwrap();
        let selector = if missing_bootstrap {
            import.baseline.selector().unwrap()
        } else {
            import.association.selector()
        };
        let missing = authority.control().join(selector);

        source.store().fs().remove_file(&missing).await.unwrap();
        let holder = SingleHeld::acquire(source.store()).await.unwrap();
        let held = holder.destination();
        let identity = held.identity_proof();
        assert!(
            source
                .guard()
                .load_original_import_held(&authority, &import, &identity)
                .await
                .is_err()
        );
        assert!(
            source
                .store()
                .fs()
                .symlink_metadata(&missing)
                .await
                .is_err()
        );
        assert!(
            source
                .store()
                .fs()
                .symlink_metadata(&authority.control().join(import.selector()))
                .await
                .is_ok()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_ordinary_original_check_refuses_new_local_supplement() {
    use crate::bucket::held::SingleHeld;
    use crate::guard::{ConsumedResolver, HistoryObservation};
    use terrane_format::gc::publication::evidence::ControlKind;

    let source = fixture().await;
    let reference = "refs/heads/_/main";
    let mut session = source.begin(reference, &token(), "sdk").await.unwrap();
    let head = source
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let original = source.guard().original_commit(&head.commit).unwrap();
    let import = stage_same_local_import(&source, &original).await;
    let authority = source.guard().configured_original_authority().unwrap();
    let holder = SingleHeld::acquire(source.store()).await.unwrap();
    let held = holder.destination();
    let identity = held.identity_proof();
    let observation = HistoryObservation::held(&identity);

    assert!(
        source
            .guard()
            .revalidate_original_context(&original, observation)
            .await
            .is_err()
    );
    assert_eq!(
        source.guard().original_commit(&head.commit).unwrap(),
        original
    );
    // The producer's borrowed guard starts with the same strict original map.
    // Its explicit transition uses the native verifier and the actual holder;
    // installing the concrete guard alone cannot update this copied context.
    let held_guard = source
        .guard()
        .held_guard(holder.destination(), TokioClock)
        .unwrap();
    let held_supplement = held_guard
        .load_original_import_held(&authority, &import, &identity)
        .await
        .unwrap();
    assert_eq!(
        held_guard.original_commit(&head.commit).unwrap(),
        held_supplement
    );
    assert_eq!(
        source.guard().original_commit(&head.commit).unwrap(),
        original
    );

    let supplement = source
        .guard()
        .load_original_import_held(&authority, &import, &identity)
        .await
        .unwrap();
    assert_eq!(supplement, held_supplement);
    assert_eq!(supplement.baseline(), original.baseline());
    assert_eq!(supplement.commit(), original.commit());
    source
        .guard()
        .revalidate_original_context(&supplement, observation)
        .await
        .unwrap();
    assert!(
        source
            .guard()
            .revalidate_original_context(&original, observation)
            .await
            .is_err()
    );

    let consumed = ConsumedResolver::new(source.guard(), &authority).unwrap();
    consumed.original(&supplement).unwrap();
    let inputs = consumed.finish().unwrap();
    let kinds = inputs
        .controls
        .iter()
        .map(|pin| pin.kind)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        kinds,
        [
            ControlKind::Registration,
            ControlKind::Bootstrap,
            ControlKind::Association,
            ControlKind::Import,
            ControlKind::ImportBinding,
            ControlKind::ImportTrust,
        ]
        .into_iter()
        .collect()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_boundary_preserves_historical_key_windows_and_current_revocation() {
    historical_keys::retain_keys_and_revoke_current_read().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_direct_history_refuses_pending_guard_mismatch() {
    historical_keys::refuse_pending_guard_mismatch().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_direct_history_closes_retained_import_controls() {
    historical_keys::close_retained_import_controls().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_projection_safe_whiteout_application_keeps_public_baseline() {
    whiteouts::materialize_public_removal().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_projection_safe_index_rebuild_requires_current_attribute_producers() {
    index_rebuild::rebuild_with_current_producer().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_rotation_retains_historical_certificates_and_issues_with_new_key() {
    rotation::retain_historical_and_issue_new().await;
}

#[cfg(unix)]
#[tokio::test]
async fn disclosure_rotation_denies_current_admin_and_ambiguous_issue_time_without_effects() {
    rotation::deny_admin_and_ambiguous_time().await;
}
