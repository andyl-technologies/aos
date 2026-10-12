//! Exercises genuine selected key rotation and immutable historical certificates.

use super::current_authority::{Factory, attenuate};
use super::witness_support::{control, file, physical_snapshot, proposal, storage_failure};
use super::*;
use crate::domain::DomainNamespace;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::Repository;
use crate::store::{Clock, LocalFs, RefStore, StoreErrorKind};
use std::os::unix::fs::MetadataExt;
use terrane_core::auth::{Caveat, Verbs};
use terrane_core::provenance::{DisclosureCandidate, OriginalBootstrapPolicy};

const REFERENCE: &str = "refs/heads/_/main";
const NEW_REFERENCE: &str = "refs/heads/_/rotated";
const PLAINTEXT: &[u8] = b"historical certificates retain their actual issuing key";

async fn reopen(factory: Factory) -> Factory {
    let Factory {
        repository,
        authority,
        fs,
        clock,
        private,
    } = factory;
    let root = repository.coordinator().store().root().to_owned();
    let policy = repository.coordinator().guard().config().clone();
    drop(repository);
    let bucket = FileBucket::open(
        config(root.clone()).await,
        fs.clone(),
        TokioClock,
        Validator,
    )
    .await
    .unwrap();
    let owner = fs.metadata(&root).await.unwrap().uid();
    let namespace = DomainNamespace {
        root: root.clone(),
        domain: policy.storage_domain.clone(),
    };
    let coordinator = Coordinator::new(
        Guard::new(
            bucket,
            clock.clone(),
            vec![authority.issuer_key().clone()],
            policy,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        fs.clone(),
    );
    let repository =
        Repository::reopen_native_retention(coordinator, &namespace, &control(&root), owner)
            .await
            .unwrap();
    Factory {
        repository,
        authority,
        fs,
        clock,
        private,
    }
}

fn tree(names: &[&[u8]], private: bool) -> Tree<'static> {
    Tree::build(
        names
            .iter()
            .map(|name| LeafItem {
                key: name.to_vec(),
                entry: file(PLAINTEXT),
            })
            .collect(),
        materialization::properties(private),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap()
}

async fn issue(
    source: &Factory,
    destination: &Factory,
    source_reference: &str,
    source_commit: [u8; 32],
    destination_name: &[u8],
    names: &[&[u8]],
    parents: Vec<[u8; 32]>,
) -> [u8; 32] {
    let mut target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination.authority,
                    parents,
                    &tree(names, false),
                    &[PLAINTEXT],
                ),
                selections: vec![DisclosureCommitSelection {
                    source_reference: source_reference.into(),
                    source_commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: [b"/".as_slice(), destination_name].concat(),
                }],
            },
        )
        .await
        .unwrap()
        .commit
}

async fn certificate_keys(destination: &Factory, commit: [u8; 32]) -> Vec<[u8; 32]> {
    let guard = destination.coordinator().guard();
    let checked = guard
        .read_snapshot(REFERENCE, destination.authority.token(), b"/", "sdk")
        .await
        .unwrap();
    let roles = guard.history_disclosure_roles().unwrap();
    let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
    let original = guard.original_commit(&commit).unwrap();
    let baseline = original.baseline();
    let owner = baseline
        .authority()
        .id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let acl = baseline
        .acl()
        .iter()
        .map(|(subject, verbs)| (subject.as_str(), *verbs))
        .collect::<Vec<_>>();
    let (_, batch) = DisclosureCandidate::new_with_bootstrap(
        &checked.history,
        commit,
        &authorities,
        guard.defaults_for(&checked.evidence),
        &owner,
        OriginalBootstrapPolicy {
            authority: &owner,
            reference: baseline.reference(),
            writer_epoch: baseline.epoch(),
            acl: &acl,
        },
    )
    .and_then(|candidate| candidate.finish())
    .unwrap();
    batch
        .boundaries()
        .iter()
        .map(|boundary| *boundary.authority_key())
        .collect()
}

/// Retains an actual old certificate beside a newly issued certificate after reopen.
///
/// # Panics
/// Panics if selected rotation loses a source dependency, mutates historical
/// protected bytes, fails ordinary reopen, or issues with an obsolete key.
pub(super) async fn retain_historical_and_issue_new() {
    let source = Factory::initialize(true).await;
    let destination = Factory::initialize(false).await;
    source.clock.enable_timer();
    destination.clock.enable_timer();
    let mut author = source
        .coordinator()
        .begin(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    let original = source
        .repository
        .commit_request(
            &mut author,
            proposal(
                &source.authority,
                Vec::new(),
                &tree(&[b"file"], true),
                &[PLAINTEXT],
            ),
        )
        .await
        .unwrap();
    let old = issue(
        &source,
        &destination,
        REFERENCE,
        original.commit,
        b"old",
        &[b"old"],
        Vec::new(),
    )
    .await;
    let old_roles = source
        .coordinator()
        .guard()
        .configured_disclosure_roles()
        .unwrap();
    assert_eq!(old_roles.len(), 1);
    let old_key = old_roles[0].public_key;
    assert_eq!(certificate_keys(&destination, old).await, vec![old_key]);
    let protected_before = physical_snapshot(&control(source.coordinator().store().root())).await;
    let source_head = source
        .coordinator()
        .store()
        .ref_get(REFERENCE)
        .await
        .unwrap();
    source.clock.set(
        old_roles[0].not_before + 10,
        source.clock.monotonic().as_secs(),
    );
    let new_key = source
        .repository
        .rotate_disclosure_key(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    assert_ne!(new_key, old_key);
    assert_eq!(
        source
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        source_head
    );
    let protected_after = physical_snapshot(&control(source.coordinator().store().root())).await;
    for (path, bytes) in protected_before {
        // Native publication replaces its selected descriptor; historical role,
        // seed and Original records must retain their exact protected bytes.
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("disclosure-")
        {
            assert_eq!(protected_after.get(&path), Some(&bytes));
        }
    }
    let source = reopen(source).await;
    assert_eq!(
        source
            .coordinator()
            .guard()
            .configured_disclosure_roles()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(certificate_keys(&destination, old).await, vec![old_key]);
    // The immutable old import trust cannot be silently rewritten to the new
    // signer even though the old source Original remains genuinely readable.
    let retained_import = destination
        .coordinator()
        .guard()
        .original_commit(&original.commit)
        .unwrap()
        .retained_import_record()
        .unwrap();
    let mut refused_target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let refused_head = refused_target.record().cloned();
    let refused = destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut refused_target,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination.authority,
                    vec![old],
                    &tree(&[b"old", b"conflict"], false),
                    &[PLAINTEXT],
                ),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: original.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: b"/conflict".to_vec(),
                }],
            },
        )
        .await;
    assert!(refused.is_err());
    assert_eq!(refused_target.record(), refused_head.as_ref());
    assert_eq!(
        destination
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        refused_head
    );
    assert_eq!(
        destination
            .coordinator()
            .guard()
            .original_commit(&original.commit)
            .unwrap()
            .retained_import_record()
            .unwrap(),
        retained_import
    );
    let mut author = source
        .coordinator()
        .begin(NEW_REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    let current = source
        .repository
        .commit_request(
            &mut author,
            proposal(
                &source.authority,
                Vec::new(),
                &tree(&[b"file"], true),
                &[PLAINTEXT],
            ),
        )
        .await
        .unwrap();
    let newest = source
        .coordinator()
        .guard()
        .configured_disclosure_roles()
        .unwrap()
        .into_iter()
        .find(|role| role.public_key == new_key)
        .unwrap();
    let current_wall = source
        .clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    source
        .clock
        .set(newest.not_before - 1, source.clock.monotonic().as_secs());
    let mut rollback_target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let rollback_head = rollback_target.record().cloned();
    let rollback = destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut rollback_target,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination.authority,
                    vec![old],
                    &tree(&[b"old", b"new"], false),
                    &[PLAINTEXT],
                ),
                selections: vec![DisclosureCommitSelection {
                    source_reference: NEW_REFERENCE.into(),
                    source_commit: current.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: b"/new".to_vec(),
                }],
            },
        )
        .await;
    assert!(rollback.is_err());
    assert_eq!(rollback_target.record(), rollback_head.as_ref());
    assert_eq!(
        destination
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        rollback_head
    );
    source
        .clock
        .set(current_wall, source.clock.monotonic().as_secs());
    // A missing selected newest seed cannot fall back to the still-present
    // historical seed, including when public plaintext is already deduplicated.
    let seed_name = format!(
        "disclosure-{}.seed",
        new_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let seed = control(source.coordinator().store().root()).join(seed_name);
    let hidden = seed.with_extension("held-aside");
    tokio::fs::rename(&seed, &hidden).await.unwrap();
    let mut refused_target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let refused_head = refused_target.record().cloned();
    let refused = destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut refused_target,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination.authority,
                    vec![old],
                    &tree(&[b"old", b"new"], false),
                    &[PLAINTEXT],
                ),
                selections: vec![DisclosureCommitSelection {
                    source_reference: NEW_REFERENCE.into(),
                    source_commit: current.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source.authority.token().to_vec(),
                    destination_path: b"/new".to_vec(),
                }],
            },
        )
        .await;
    assert!(refused.is_err());
    assert_eq!(refused_target.record(), refused_head.as_ref());
    assert_eq!(
        destination
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        refused_head
    );
    tokio::fs::rename(&hidden, &seed).await.unwrap();
    let published = issue(
        &source,
        &destination,
        NEW_REFERENCE,
        current.commit,
        b"new",
        &[b"old", b"new"],
        vec![old],
    )
    .await;
    let keys = certificate_keys(&destination, published).await;
    assert!(keys.contains(&old_key));
    assert!(keys.contains(&new_key));
    assert_eq!(
        destination
            .coordinator()
            .guard()
            .original_commit(&original.commit)
            .unwrap_or_else(|error| {
                panic!("the imported Original must remain protected after signer rotation: {error}")
            })
            .commit(),
        &original.commit
    );
    drop(author);
    let source_root = source.coordinator().store().root().to_owned();
    let credentials = source_root.with_file_name(format!(
        "{}-current-credentials",
        source_root.file_name().unwrap().to_string_lossy()
    ));
    drop(source);
    for path in [control(&source_root), source_root, credentials] {
        tokio::fs::remove_dir_all(&path).await.unwrap();
        assert!(!path.exists());
    }
    let destination = reopen(destination).await;
    let keys = certificate_keys(&destination, published).await;
    assert!(keys.contains(&old_key));
    assert!(keys.contains(&new_key));
}

/// Refuses absent current Admin and equal issue-time rotation before any effect.
///
/// # Panics
/// Panics if refusal writes protected state or changes a selected whole head.
pub(super) async fn deny_admin_and_ambiguous_time() {
    let source = Factory::initialize(true).await;
    let mut author = source
        .coordinator()
        .begin(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    let head = source
        .repository
        .commit_request(&mut author, source.proposal(Vec::new(), 31))
        .await
        .unwrap();
    let root = source.coordinator().store().root().to_owned();
    let bucket_before = physical_snapshot(&root).await;
    let protected_before = physical_snapshot(&control(&root)).await;
    let read_only = attenuate(&source, Caveat::Verb(Verbs::new(1).unwrap()));
    let denied = source
        .repository
        .rotate_disclosure_key(REFERENCE, &read_only, "sdk")
        .await
        .unwrap_err();
    assert!(matches!(
        storage_failure(denied).kind(),
        StoreErrorKind::Denied { verb: "admin", .. }
    ));
    let expired = attenuate(&source, Caveat::Before(1001));
    source.clock.set(1001, 0);
    let denied = source
        .repository
        .rotate_disclosure_key(REFERENCE, &expired, "sdk")
        .await
        .unwrap_err();
    assert!(matches!(
        storage_failure(denied).kind(),
        StoreErrorKind::Denied { verb: "admin", .. }
    ));
    source.clock.set(1000, 0);
    assert!(
        source
            .repository
            .rotate_disclosure_key(REFERENCE, source.authority.token(), "sdk")
            .await
            .is_err()
    );
    assert_eq!(
        source
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        Some(head)
    );
    assert_eq!(physical_snapshot(&root).await, bucket_before);
    assert_eq!(physical_snapshot(&control(&root)).await, protected_before);
}
