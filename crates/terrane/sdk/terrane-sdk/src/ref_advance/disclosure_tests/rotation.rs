//! Exercises genuine selected key rotation and immutable historical certificates.

use super::current_authority::{Factory, attenuate};
use super::witness_support::{
    control, control_snapshot, file, physical_snapshot, proposal, storage_failure,
};
use super::*;
use crate::domain::DomainNamespace;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::Repository;
use crate::store::{Clock, LocalFs, RefStore, StoreErrorKind};
use std::error::Error as _;
use std::os::unix::fs::MetadataExt;
use terrane_format::auth::{Caveat, Verbs};
use terrane_format::provenance::{DisclosureCandidate, OriginalBootstrapPolicy};

const REFERENCE: &str = "refs/heads/_/main";
const NEW_REFERENCE: &str = "refs/heads/_/rotated";
const PLAINTEXT: &[u8] = b"historical certificates retain their actual issuing key";

fn assert_retention_denied(failure: &crate::store::StoreFailure, phase: &str) {
    assert!(
        matches!(
            failure.kind(),
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
        ),
        "{phase}: unexpected storage outcome: {failure:?}"
    );
    assert!(
        matches!(
            failure
                .source()
                .and_then(|source| source.downcast_ref::<crate::repository::Error>()),
            Some(crate::repository::Error::Denied)
        ),
        "{phase}: expected protected retention refusal: {failure:?}"
    );
}

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
    let mut entries = names
        .iter()
        .map(|name| LeafItem {
            key: name.to_vec(),
            entry: file(PLAINTEXT),
        })
        .collect::<Vec<_>>();
    // These names describe a namespace set, not operation or layer order.
    // Canonical construction still rejects duplicate keys after sorting.
    entries.sort_by(|left, right| left.key.cmp(&right.key));

    Tree::build(
        entries,
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
    let previous = if target.record().is_some() {
        Some(
            destination
                .coordinator()
                .guard()
                .read_snapshot(REFERENCE, destination.authority.token(), b"/", "sdk")
                .await
                .unwrap(),
        )
    } else {
        None
    };
    // Carry the authenticated old entry, including its original-introducer
    // attributes. Recreating equal plaintext would replace the certified entry
    // and cannot preserve its historical disclosure boundary under PROV-28.
    let mut entries = names
        .iter()
        .map(|name| {
            let entry = if *name == destination_name {
                file(PLAINTEXT)
            } else {
                let previous = previous.as_ref().unwrap();
                assert_eq!(
                    Some(previous.commit.identity()),
                    target.record().map(|head| head.commit)
                );
                let (location, _) = previous
                    .history
                    .locate(previous.commit.identity(), name)
                    .unwrap();
                previous.history.entry(&location).unwrap()
            };
            LeafItem {
                key: name.to_vec(),
                entry,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let candidate = Tree::build(
        entries,
        materialization::properties(false),
        262144,
        TreeUse::Ordinary,
    )
    .unwrap();
    destination
        .coordinator()
        .advance_disclosure(
            source.coordinator().guard(),
            &mut target,
            DisclosureCommitRequest {
                proposal: proposal(&destination.authority, parents, &candidate, &[PLAINTEXT]),
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

async fn certificate_keys(
    destination: &Factory,
    commit: [u8; 32],
    expected: &[(&[u8], [u8; 32])],
) -> Vec<[u8; 32]> {
    let guard = destination.coordinator().guard();
    let checked = guard
        .read_snapshot(REFERENCE, destination.authority.token(), b"/", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), commit);
    let roles = guard.history_disclosure_roles().unwrap();
    let authorities = roles.iter().map(|role| role.view()).collect::<Vec<_>>();
    let mut keys = Vec::new();
    // A carried entry inherits its public introducing commit's certificate;
    // the current candidate batch contains only its own proof-bearing receipts.
    for (path, expected_introducer) in expected {
        let (current, _) = checked.history.locate(commit, path).unwrap();
        let introducer = checked.history.introducing_commit(&current).unwrap();
        assert_eq!(introducer, *expected_introducer);
        if introducer != commit {
            assert!(checked.commit.commit().parents.contains(&introducer));
        }
        let (target, _) = checked.history.locate(introducer, path).unwrap();
        assert_eq!(
            checked.history.entry(&current).unwrap(),
            checked.history.entry(&target).unwrap()
        );
        let original = guard.original_commit(&introducer).unwrap();
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
            introducer,
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
        let matching = batch
            .boundaries()
            .iter()
            .filter(|boundary| boundary.target() == &target)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].target_domain(), "public");
        keys.push(*matching[0].authority_key());
    }
    keys
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
    assert_eq!(
        certificate_keys(&destination, old, &[(b"old", old)]).await,
        vec![old_key]
    );
    let protected_before = control_snapshot(source.coordinator().store().root()).await;
    let source_head = source
        .coordinator()
        .store()
        .ref_get(REFERENCE)
        .await
        .unwrap();
    source.clock.set(
        old_roles[0].not_before
            + destination
                .coordinator()
                .maximum_commit_duration()
                .as_secs()
            + 10,
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
    let protected_after = control_snapshot(source.coordinator().store().root()).await;
    let source_control = control(source.coordinator().store().root());
    assert!(protected_before.contains_key(&source_control.join("registration.cbor")));
    let association = format!(
        "commit-{}.cbor",
        original
            .commit
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert!(protected_before.contains_key(&source_control.join(association)));
    assert!(protected_before.keys().any(|path| {
        path.file_name()
            .unwrap()
            .as_encoded_bytes()
            .starts_with(b"bootstrap-")
    }));
    for (path, entry) in protected_before {
        let name = path.file_name().unwrap().as_encoded_bytes();
        // Retention selectors identify immutable Original registration,
        // bootstrap, association and import/binding/trust records. Rotation
        // adds role/seed files and replaces the selected descriptor; directory
        // timestamps may change, but existing protected files must stay exact.
        let original_record = name == b"registration.cbor"
            || (name.ends_with(b".cbor")
                && [b"bootstrap-".as_slice(), b"commit-", b"import-"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix)));
        if original_record || name.starts_with(b"disclosure-") {
            assert_eq!(
                protected_after.get(&path),
                Some(&entry),
                "rotation changed retained protected file: {path:?}"
            );
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
    assert_eq!(
        certificate_keys(&destination, old, &[(b"old", old)]).await,
        vec![old_key]
    );
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
    // This authorized session's epoch baseline is retained before production
    // checks conflicting import trust. Complete that genuine setup before the
    // refusal oracle, so its mandatory additive record is not a false mutation.
    let guard = destination.coordinator().guard();
    let retention = crate::repository::local_authority::NativeRetention {
        authority: guard.configured_original_authority().unwrap(),
        owner_uid: destination
            .coordinator()
            .store()
            .publication_operator_uid()
            .unwrap(),
        authoring_acl: guard.config().initial_acl.clone(),
    };
    retention
        .retain_baseline(guard, &destination.fs, &refused_target)
        .await
        .unwrap();
    let conflict_before = physical_snapshot(destination.coordinator().store().root()).await;
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
    let failure = match refused {
        Err(crate::ref_advance::AdvanceError::Store(failure)) => failure,
        outcome => panic!("conflicting old import trust: unexpected result: {outcome:?}"),
    };
    assert_retention_denied(&failure, "conflicting old import trust");
    assert_eq!(
        physical_snapshot(destination.coordinator().store().root()).await,
        conflict_before
    );
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
    assert_eq!(
        certificate_keys(&destination, old, &[(b"old", old)]).await,
        vec![old_key]
    );
    let fresh = Factory::initialize(false).await;
    let imported = issue(
        &source,
        &fresh,
        REFERENCE,
        original.commit,
        b"conflict",
        &[b"conflict"],
        Vec::new(),
    )
    .await;
    assert_eq!(
        certificate_keys(&fresh, imported, &[(b"conflict", imported)]).await,
        vec![new_key]
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
    let mut rollback_target = destination
        .coordinator()
        .begin(REFERENCE, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let rollback_head = rollback_target.record().cloned();
    let rollback_before = physical_snapshot(destination.coordinator().store().root()).await;
    // Real timer progression must not heal the rollback during native setup.
    // Keep the old role valid and the newest role future for the entire existing
    // commit bound, so refusal cannot be explained by both roles being invalid.
    source
        .clock
        .set(old_roles[0].not_before, source.clock.monotonic().as_secs());
    let rollback_wall = source
        .clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(rollback_wall >= old_roles[0].not_before);
    assert!(old_roles[0].not_after.is_none_or(|end| rollback_wall < end));
    assert!(rollback_wall < newest.not_before);
    assert!(
        newest.not_before - rollback_wall
            > destination
                .coordinator()
                .maximum_commit_duration()
                .as_secs()
    );
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
    let failure = match rollback {
        Err(crate::ref_advance::AdvanceError::Store(failure)) => failure,
        outcome => panic!("newest role clock rollback: unexpected result: {outcome:?}"),
    };
    assert_retention_denied(&failure, "newest role clock rollback");
    let rollback_wall = source
        .clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(rollback_wall >= old_roles[0].not_before);
    assert!(old_roles[0].not_after.is_none_or(|end| rollback_wall < end));
    assert!(rollback_wall < newest.not_before);
    assert_eq!(
        physical_snapshot(destination.coordinator().store().root()).await,
        rollback_before
    );
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
    let missing_seed_before = physical_snapshot(destination.coordinator().store().root()).await;
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
    let failure = match refused {
        Err(crate::ref_advance::AdvanceError::Store(failure)) => failure,
        outcome => panic!("missing selected newest seed: unexpected result: {outcome:?}"),
    };
    assert!(
        matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ),
        "missing selected newest seed: unexpected storage outcome: {failure:?}"
    );
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::NotFound),
        "missing selected newest seed: unexpected cause: {failure:?}"
    );
    assert_eq!(
        physical_snapshot(destination.coordinator().store().root()).await,
        missing_seed_before
    );
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
    let keys = certificate_keys(
        &destination,
        published,
        &[(b"old", old), (b"new", published)],
    )
    .await;
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
    let keys = certificate_keys(
        &destination,
        published,
        &[(b"old", old), (b"new", published)],
    )
    .await;
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
    let protected_before = control_snapshot(&root).await;
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
    let ambiguous = source
        .repository
        .rotate_disclosure_key(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap_err();
    assert_retention_denied(&storage_failure(ambiguous), "equal rotation issue time");
    assert_eq!(
        source
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        Some(head.clone())
    );
    assert_eq!(physical_snapshot(&root).await, bucket_before);
    assert_eq!(control_snapshot(&root).await, protected_before);
    source.clock.set(1001, 0);
    source
        .repository
        .rotate_disclosure_key(REFERENCE, source.authority.token(), "sdk")
        .await
        .unwrap();
    assert_eq!(
        source
            .coordinator()
            .store()
            .ref_get(REFERENCE)
            .await
            .unwrap(),
        Some(head)
    );
}
