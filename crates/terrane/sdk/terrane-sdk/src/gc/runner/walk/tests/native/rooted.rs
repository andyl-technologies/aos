//! Checks independently selected public producers beside an exact certified cut.
//!
//! Portable initialization supplies copied data; the genuine paired disclosure
//! supplies separately checked historical signing trust before any collector
//! qualification. The two source participants remain distinct physical buckets.

use super::*;
use crate::bucket::{FileBucketConfig, FileBucketPublicationConfig};
use crate::ref_advance::disclosure_tests::{independent_factory, witness_support};
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::local_authority::{LocalAuthority, LocalAuthorityParameters};
use crate::store::{CapabilityReport, TokioClock, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use terrane_format::auth::{Authority, Grant, Verbs};
use terrane_format::refs::PrincipalKind;

type PublicRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

/// Copies quiescent payload data without the source's external authority controls.
async fn copy_payload(source: &Path, destination: &Path) {
    let mut pending = vec![(source.to_owned(), destination.to_owned())];
    while let Some((source, destination)) = pending.pop() {
        tokio::fs::create_dir_all(&destination)
            .await
            .assert_success();
        TokioLocalFs
            .set_permissions_and_sync(
                &destination,
                TokioLocalFs
                    .metadata(&source)
                    .await
                    .assert_success()
                    .permissions(),
            )
            .await
            .assert_success();
        let mut entries = tokio::fs::read_dir(&source).await.assert_success();
        while let Some(entry) = entries.next_entry().await.assert_success() {
            let output = destination.join(entry.file_name());
            if entry.file_type().await.assert_success().is_dir() {
                pending.push((entry.path(), output));
            } else {
                tokio::fs::copy(entry.path(), output).await.assert_success();
            }
        }
    }
}

fn sibling(root: &Path, suffix: &str) -> PathBuf {
    root.with_file_name(format!(
        "{}-{suffix}",
        root.file_name().assert_success().to_string_lossy()
    ))
}

/// Initializes a new native destination without importing source signing authority.
async fn copied_destination(
    source: &witness_support::IndexFixture,
) -> (PublicRepository, LocalAuthority, FileBucketConfig, PathBuf) {
    let nonce = TokioLocalFs.random_bytes(16).await.assert_success();
    let tag: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let root = source.store().root().with_extension(format!("copy-{tag}"));
    copy_payload(source.store().root(), &root).await;
    let owner_uid = TokioLocalFs.metadata(&root).await.assert_success().uid();
    let policy = source.guard().config().clone();
    let config = FileBucketConfig {
        root: root.clone(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: policy.chunk_profile.as_ref().clone(),
        locality: source.store().capabilities().locality.clone(),
        publication_control: Some(FileBucketPublicationConfig {
            operator_uid: owner_uid,
            control: None,
        }),
    };
    let bucket = FileBucket::initialize_portable_copy(
        config.clone(),
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(config.chunk_profile.clone()),
    )
    .await
    .assert_success();
    let credentials = sibling(&root, "credentials");
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
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_after: u64::MAX,
                not_before: None,
                token_id: TokioLocalFs
                    .random_bytes(16)
                    .await
                    .assert_success()
                    .try_into()
                    .assert_success(),
                grants: vec![
                    Grant::new("refs/**".into(), Verbs::new(31).assert_success()).assert_success(),
                ],
                workload: None,
            },
        },
    )
    .await
    .assert_success();
    let control = sibling(&root, "original-control");
    TokioLocalFs.create_dir_new(&control).await.assert_success();
    TokioLocalFs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await
        .assert_success();
    let coordinator = coordinator(bucket, &authority, policy);
    let repository = Repository::initialize_native_retention(
        coordinator,
        &DomainNamespace {
            root,
            domain: "public".into(),
        },
        &control,
        owner_uid,
    )
    .await
    .assert_success();
    (repository, authority, config, credentials)
}

fn coordinator(
    bucket: FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
    authority: &LocalAuthority,
    policy: crate::guard::GuardConfig,
) -> Coordinator<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>
{
    Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            policy,
        ),
        CommitTiming::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )
        .assert_success(),
        TokioLocalFs,
    )
}

/// Reopens only destination controls after the original source is actually erased.
async fn reopen(
    repository: PublicRepository,
    authority: &LocalAuthority,
    config: &FileBucketConfig,
) -> PublicRepository {
    let policy = repository.coordinator().guard().config().clone();
    drop(repository);
    let bucket = FileBucket::open(
        config.clone(),
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(config.chunk_profile.clone()),
    )
    .await
    .assert_success();
    Repository::reopen_native_retention(
        coordinator(bucket, authority, policy),
        &DomainNamespace {
            root: config.root.clone(),
            domain: "public".into(),
        },
        &sibling(&config.root, "original-control"),
        config
            .publication_control
            .as_ref()
            .assert_success()
            .operator_uid,
    )
    .await
    .assert_success()
}

/// Traverses a genuinely rooted source independently of a destination audit cut.
///
/// # Panics
/// Panics if portable initialization, genuine import/actor admission, reopen or
/// either expansion order fails its independent identity/context assertions.
pub(super) async fn independently_rooted_source_keeps_own_producer_context() {
    let (source, source_authority, source_credentials) = independent_factory("public").await;
    let source = witness_support::production_metadata(source, &source_authority).await;
    let plaintext = b"independent public source survives its certified audit cut";
    let object = digest(IdentityKind::Chunk, plaintext);
    let value = AttributeValue::Sha256([11; 32]).encode().assert_success();
    let mut file = entry(plaintext);
    file.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &value,
    }];
    file.attrs_present = true;
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file,
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
        ]),
        262144,
        TreeUse::Ordinary,
    )
    .assert_success();
    let request = witness_support::proposal(&source_authority, Vec::new(), &tree, &[plaintext]);
    let secret = request.terminal_secret;
    let mut writer = source
        .begin("refs/heads/_/main", source_authority.token(), "sdk")
        .await
        .assert_success();
    let source_head = source.advance(&mut writer, request).await.assert_success();
    drop(writer);
    let source_verified = source
        .guard()
        .verified_tree(source_head.commit)
        .await
        .assert_success();
    let mut record = AttrRecord::new(object, AttributeValue::Sha256([11; 32]), source_head.commit);
    record
        .sign(&source_verified.commit, &secret)
        .assert_success();
    let bytes = record.encode().assert_success();
    let record_hash = digest(IdentityKind::Attribute, &bytes);
    assert_eq!(
        source
            .store()
            .put(ContentUpload::Meta(
                MetaUpload::new(IdentityKind::Attribute, &bytes).assert_success(),
            ))
            .await
            .assert_success()
            .terrane_v1_digest()
            .assert_success(),
        record_hash
    );
    let (destination, authority, config, credentials) = copied_destination(&source).await;
    let mut writer = destination
        .begin("refs/heads/_/public", authority.token(), "sdk")
        .await
        .assert_success();
    let public_head = destination
        .coordinator()
        .advance_disclosure(
            source.guard(),
            &mut writer,
            DisclosureCommitRequest {
                proposal: witness_support::proposal(&authority, Vec::new(), &tree, &[plaintext]),
                selections: vec![DisclosureCommitSelection {
                    source_reference: "refs/heads/_/main".into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .assert_success();
    drop(writer);
    let read = destination
        .coordinator()
        .guard()
        .read_snapshot("refs/heads/_/main", authority.token(), b"/file", "sdk")
        .await
        .assert_success();
    assert_eq!(read.commit.identity(), source_head.commit);
    drop(source_authority);
    witness_support::erase_index_source(source, source_credentials).await;
    let destination = reopen(destination, &authority, &config).await;
    let concrete = destination.coordinator().guard();
    let original = concrete.configured_original_authority().assert_success();
    let collection =
        Collection::start(concrete, &original, "collector".into(), 1_000, 1, windows())
            .await
            .assert_success();
    let holder = SingleHeld::acquire(concrete.store()).await.assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let adapted = crate::guard::collection_authority::historical_guard(
        concrete,
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let consumed = ConsumedResolver::new(concrete, &original).assert_success();
    let roots = crate::selected_bridge::native_collection_roots::cycle(
        &adapted,
        &consumed,
        &held,
        &observed,
        &collection.session,
        1,
    )
    .await
    .assert_success();
    for commit in [source_head.commit, public_head.commit] {
        assert!(
            roots
                .snapshot()
                .roots
                .iter()
                .any(|root| root.commit == commit)
        );
        assert!(roots.history(&commit).assert_success().is_some());
    }
    let public = roots
        .history(&public_head.commit)
        .assert_success()
        .assert_success();
    let dependencies = public
        .completed()
        .dependencies(public_head.commit)
        .assert_success();
    assert!(!dependencies.parents().contains(&source_head.commit));
    // The certified content edge is cut, while the independently preserved
    // attribute origin still requires S's completed history in its own scope.
    assert!(dependencies.witnesses().contains(&source_head.commit));
    let receipt = public
        .tree()
        .commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_ref()
        .assert_success()
        .iter()
        .find(|receipt| receipt.root == public.tree().evidence.root && receipt.path == b"file")
        .assert_success();
    assert!(receipt.disclosure_proof.is_some());
    let reintroduced = receipt.reintroduced_from.as_ref().assert_success();
    assert_eq!(reintroduced.commit, source_head.commit);
    assert_eq!(reintroduced.root, tree.root_identity());
    assert_eq!(reintroduced.path, b"file");
    assert!(
        receipt
            .attributes
            .as_ref()
            .assert_success()
            .iter()
            .any(|(name, origin)| {
                name == "hash.sha256"
                    && matches!(origin, terrane_format::refs::EntryOrigin::Source(source)
                        if source.commit == source_head.commit
                            && source.root == tree.root_identity()
                            && source.path == b"file")
            })
    );
    let batch = dependencies.disclosure().assert_success();
    assert!(
        batch
            .boundaries()
            .iter()
            .any(|edge| edge.source().commit == source_head.commit
                && edge.source().root == tree.root_identity()
                && edge.source().path == b"file"
                && edge.target().commit == public_head.commit
                && edge.target().root == public.tree().evidence.root
                && edge.target().path == b"file")
    );
    let source_context =
        ProofContext::new(source_head.commit, tree.root_identity(), b"/".to_vec()).assert_success();
    let public_context = ProofContext::new(
        public_head.commit,
        public.tree().evidence.root,
        b"/".to_vec(),
    )
    .assert_success();
    let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
    for order in [
        [public_head.commit, source_head.commit],
        [source_head.commit, public_head.commit],
    ] {
        let mut state = frontier(order[0], false);
        state.pending.extend(frontier(order[1], false).pending);
        let mut marks = BTreeSet::new();
        for _ in 0..2 {
            expand(
                &adapted,
                &consumed,
                observation,
                &roots,
                &mut state,
                &mut marks,
            )
            .await
            .assert_success();
        }
        assert!(marks.contains(&source_head.commit));
        assert!(marks.contains(&record_hash));
        for context in [&source_context, &public_context] {
            assert!(state.objects.contains(&ExpandedObject {
                kind: 7,
                hash: record_hash,
                flags: 0,
                proof_context: Some(context.clone()),
            }));
        }
        assert!(
            state
                .pending
                .iter()
                .any(|pending| pending.hash == source_head.commit
                    && pending.is_witness()
                    && pending.proof_context.as_ref() == Some(&source_context))
        );
    }
    drop(roots);
    drop(adapted);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    drop(destination);
    drop(authority);
    for path in [
        sibling(&config.root, "original-control"),
        config.root.clone(),
        credentials,
    ] {
        tokio::fs::remove_dir_all(path).await.assert_success();
    }
}
