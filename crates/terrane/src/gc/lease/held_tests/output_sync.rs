//! Qualifies exact lease durability work without weakening historical/current checks.

use super::*;
use crate::gc::lease::fixture::Validator;
use crate::store::{Clock, LeaseSyncEvent, NativeEffectClock};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use terrane_core::gc::publication::{PublicationCommit, PublicationTransaction};

fn events(
    receiver: std::sync::mpsc::Receiver<LeaseSyncEvent>,
) -> (BTreeMap<PathBuf, usize>, BTreeMap<PathBuf, usize>) {
    let mut files = BTreeMap::new();
    let mut directories = BTreeMap::new();
    for event in receiver.try_iter() {
        let counts = match event {
            LeaseSyncEvent::File(path) => (&mut files, path),
            LeaseSyncEvent::Directory(path) => (&mut directories, path),
        };
        *counts.0.entry(counts.1).or_default() += 1;
    }
    (files, directories)
}

fn replace(path: &Path) {
    let original = std::fs::read(path).require();
    let temporary = path.with_extension("same-byte-replacement");
    std::fs::write(&temporary, &original).require();
    let permissions = std::fs::metadata(path).require().permissions();
    std::fs::set_permissions(&temporary, permissions).require();
    std::fs::rename(temporary, path).require();
    assert_eq!(std::fs::read(path).require(), original);
}

async fn expected(
    fixture: &Fixture,
    revision: u64,
    held: &crate::bucket::held::HeldBucket<'_, HeldFs, NativeEffectClock, Validator, true>,
    retained: &crate::guard::RetainedControls,
) -> (BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
    let root = &fixture.base.config.root;
    let control = fixture.base.parent.join("publication");
    let slot_path = control.join(format!("publication/commits/{revision}"));
    let slot = PublicationCommit::decode(&std::fs::read(&slot_path).require()).require();
    let transaction_path = control.join(&slot.transaction_key);
    let transaction =
        PublicationTransaction::decode(&std::fs::read(&transaction_path).require()).require();
    let observed = held.observe_publication_unrepaired().await.require();
    let guard = held
        .selected_guard_snapshot_record(&observed)
        .await
        .require()
        .require();
    let mut files = BTreeSet::from([
        slot_path,
        transaction_path,
        root.join(&transaction.snapshot.key),
        root.join("publication/PORTABLE"),
        root.join("gc/lease"),
        guard.path().to_owned(),
        control.join("backend-registration.cbor"),
    ]);
    files.extend(
        retained
            .records()
            .iter()
            .map(|record| record.path().to_owned()),
    );
    let scopes = [root.as_path(), control.as_path(), retained.directory()];
    let mut directories = BTreeSet::from([retained.directory().to_owned()]);
    for file in &files {
        let scope = scopes
            .iter()
            .filter(|scope| file.starts_with(scope))
            .max_by_key(|scope| scope.components().count())
            .require();
        let mut directory = file.parent().require();
        loop {
            directories.insert(directory.to_owned());
            if directory == *scope {
                break;
            }
            directory = directory.parent().require();
        }
    }
    (files, directories)
}

fn exact(
    actual: (BTreeMap<PathBuf, usize>, BTreeMap<PathBuf, usize>),
    expected: (BTreeSet<PathBuf>, BTreeSet<PathBuf>),
) {
    assert_eq!(
        actual.0.keys().cloned().collect::<BTreeSet<_>>(),
        expected.0
    );
    assert_eq!(
        actual.1.keys().cloned().collect::<BTreeSet<_>>(),
        expected.1
    );
    assert!(actual.0.values().all(|count| *count == 1));
    assert!(actual.1.values().all(|count| *count == 1));
    assert!(
        actual
            .0
            .keys()
            .all(|path| path.extension().is_none_or(|extension| extension != "pack"))
    );
}

#[tokio::test]
async fn acquire_and_held_renewal_sync_exact_outputs_and_all_original_controls() {
    let fixture = Fixture::new().await;
    let acquire_events = fixture.fs.observe_syncs();
    let (mut session, initial) = fixture.session().await;
    let collector = fixture.collector();
    let exclusion = collector.hold_namespace().await.require();
    let held = exclusion.destination();
    let retained = fixture.retained(&held).await;
    exact(
        events(acquire_events),
        expected(&fixture, initial.revision, &held, &retained).await,
    );
    let old_slot = fixture.base.parent.join(format!(
        "publication/publication/commits/{}",
        initial.revision
    ));
    let acquisitions = fixture.fs.locks();
    let mut context = collector.held(&held, Some(&retained)).await.require();
    fixture.base.clock.set(105, 5);
    let renew_events = fixture.fs.observe_syncs();
    session.renew_held(&mut context).await.require();
    let actual = events(renew_events);
    assert!(!actual.0.contains_key(&old_slot));
    exact(
        actual,
        expected(&fixture, initial.revision + 1, &held, &retained).await,
    );
    assert_eq!(fixture.fs.locks(), acquisitions);
    assert_eq!(session.lease().expiry, 140);
    assert!(session.recheck().is_ok());
    assert_excluded(&fixture.lock_paths());
}

#[tokio::test]
async fn historical_preimages_remain_checked_when_omitted_from_sync_inventory() {
    for historical in 0..3 {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        let control = fixture.base.parent.join("publication");
        let old_slot = control.join(format!("publication/commits/{}", initial.revision));
        let slot = PublicationCommit::decode(&std::fs::read(&old_slot).require()).require();
        let old_transaction = control.join(&slot.transaction_key);
        let transaction =
            PublicationTransaction::decode(&std::fs::read(&old_transaction).require()).require();
        let path = match historical {
            0 => old_slot,
            1 => old_transaction,
            _ => fixture.base.config.root.join(&transaction.snapshot.key),
        };
        fixture.base.clock.set(105, 5);
        let completed = fixture.fs.observe_syncs();
        let (arrived, release) = fixture.fs.pause();
        let guard = Arc::clone(&fixture.guard);
        let authority = fixture.base.authority.clone();
        let worker = tokio::spawn(async move {
            let collector = Collector::new(guard.as_ref(), &authority);
            let exclusion = collector.hold_namespace().await.require();
            let held = exclusion.destination();
            let mut context = collector.held(&held, None).await.require();
            let result = session.renew_held(&mut context).await;
            (session, result)
        });
        arrival(arrived).await;
        replace(&path);
        release.send(()).require();
        let (session, result) = worker.await.require();
        let CollectionError::Lease(LeaseError::Store(failure)) = result.require_error() else {
            panic!("historical replacement lost exact lease-store refusal");
        };
        assert!(matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ));
        assert_eq!(
            std::error::Error::source(&failure).require().to_string(),
            "exact read metadata changed"
        );
        assert_eq!(session.lease(), &initial.lease);
        assert!(session.recheck().is_err());
        assert_eq!(events(completed), (BTreeMap::new(), BTreeMap::new()));
        fixture.fs.assert_consumed();
    }
}

#[tokio::test]
async fn original_replacement_and_actual_expiry_refuse_before_first_sync() {
    for expired in [false, true] {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        fixture.base.clock.set(105, 5);
        let completed = fixture.fs.observe_syncs();
        let (arrived, release) = fixture.fs.pause();
        let guard = Arc::clone(&fixture.guard);
        let authority = fixture.base.authority.clone();
        let control = authority.control().to_owned();
        let worker = tokio::spawn(async move {
            let collector = Collector::new(guard.as_ref(), &authority);
            let exclusion = collector.hold_namespace().await.require();
            let held = exclusion.destination();
            let mut context = collector.held(&held, None).await.require();
            let result = session.renew_held(&mut context).await;
            (session, result)
        });
        arrival(arrived).await;
        if expired {
            fixture.base.clock.set(initial.lease.expiry, 20);
        } else {
            replace(&control.join("registration.cbor"));
        }
        release.send(()).require();
        let (session, result) = worker.await.require();
        let CollectionError::Lease(LeaseError::Store(failure)) = result.require_error() else {
            panic!("current authority lost exact lease-store refusal");
        };
        if expired {
            assert!(
                matches!(failure.kind(), StoreErrorKind::Denied { verb, .. } if *verb == "gc-lease")
            );
        } else {
            assert!(matches!(
                failure.kind(),
                StoreErrorKind::Unavailable { retry_after: None }
            ));
            assert_eq!(
                std::error::Error::source(&failure).require().to_string(),
                "exact read metadata changed"
            );
        }
        assert!(session.recheck().is_err());
        assert_eq!(session.lease(), &initial.lease);
        assert_eq!(events(completed), (BTreeMap::new(), BTreeMap::new()));
        fixture.fs.assert_consumed();
    }
}

#[tokio::test]
async fn noop_and_swallowed_real_sync_failure_never_acknowledge_renewal() {
    for noop in [false, true] {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        let collector = fixture.collector();
        let exclusion = collector.hold_namespace().await.require();
        let held = exclusion.destination();
        let mut context = collector.held(&held, None).await.require();
        fixture.base.clock.set(105, 5);
        let completed = fixture.fs.observe_syncs();
        if noop {
            fixture.fs.noop();
        } else {
            fixture.fs.fault(EffectFault::BeforeFileSync, true);
        }
        let CollectionError::Lease(LeaseError::Store(failure)) =
            session.renew_held(&mut context).await.require_error()
        else {
            panic!("missing acknowledgment lost exact lease-store refusal");
        };
        assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
        assert_eq!(
            std::error::Error::source(&failure).require().to_string(),
            "native lease publication acknowledgment unavailable"
        );
        assert_eq!(session.lease(), &initial.lease);
        assert!(session.recheck().is_err());
        assert_eq!(events(completed), (BTreeMap::new(), BTreeMap::new()));
        fixture.fs.assert_consumed();
    }
}

#[tokio::test]
async fn lease_acknowledges_real_unrelated_cache_repair_and_removal() {
    use crate::bucket::held::SingleHeld;
    use crate::gc::runner::fixture::{Fixture as SignedFixture, Validator as SignedValidator};
    use terrane_core::bucket::{BucketCapabilities, BucketKey};
    use terrane_core::gc::publication::LogicalChange;

    let source = SignedFixture::new().await;
    let note_name = "refs/notes/profiles/_/lease-output";
    let note_key = BucketKey::ref_record(note_name)
        .require()
        .as_str()
        .to_owned();
    let note_bytes = b"selected advisory cache".to_vec();
    let root = source.config.root.clone();
    let (head_key, head_bytes) = {
        let holder = SingleHeld::acquire(source.guard().store()).await.require();
        let held = holder.destination();
        let before = held.observe_publication_unrepaired().await.require();
        let capabilities_bytes = before.logical()["CAPABILITIES"].as_deref().require();
        let mut capabilities = BucketCapabilities::decode(capabilities_bytes).require();
        let names = capabilities.ref_names.as_mut().require();
        let insertion = names
            .binary_search_by(|row| row.as_bytes().cmp(note_name.as_bytes()))
            .require_error();
        names.insert(insertion, note_name.into());
        held.publish_raw(
            &before,
            vec![
                LogicalChange {
                    key: note_key.clone(),
                    expected: None,
                    new: Some(note_bytes.clone()),
                },
                LogicalChange {
                    key: "CAPABILITIES".into(),
                    expected: Some(capabilities_bytes.to_vec()),
                    new: Some(capabilities.encode().require()),
                },
            ],
        )
        .await
        .require();
        let selected = held.observe_publication_unrepaired().await.require();
        assert_eq!(selected.logical()[&note_key].as_ref(), Some(&note_bytes));
        // Inventory names are monotone even after their selected value is absent.
        // Reopen must verify the actual history before the lease repairs caches.
        held.publish_raw(
            &selected,
            vec![LogicalChange {
                key: note_key.clone(),
                expected: Some(note_bytes.clone()),
                new: None,
            }],
        )
        .await
        .require();
        let after = held.observe_publication_unrepaired().await.require();
        assert_eq!(after.logical()[&note_key], None);
        assert!(
            BucketCapabilities::decode(after.logical()["CAPABILITIES"].as_deref().require())
                .require()
                .ref_names
                .as_ref()
                .require()
                .iter()
                .any(|name| name == note_name)
        );
        let (key, bytes) = after
            .logical()
            .iter()
            .find(|(key, bytes)| key.starts_with("refs/heads/") && bytes.is_some())
            .require();
        (key.clone(), bytes.as_ref().require().clone())
    };
    {
        let fs = HeldFs::from_native(source.fs.clone());
        let bucket = crate::bucket::FileBucket::open(
            source.config.clone(),
            fs.clone(),
            source.clock.retain_native_clock().require(),
            SignedValidator,
        )
        .await
        .require();
        let guard = Guard::new(
            bucket,
            source.clock.retain_native_clock().require(),
            source.guard().keys().to_vec(),
            source.guard().config().clone(),
        );
        let coordinator = crate::ref_advance::Coordinator::new(
            guard,
            crate::ref_advance::CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .require(),
            fs.clone(),
        );
        let repository = crate::repository::Repository::reopen_native_retention(
            coordinator,
            &crate::domain::DomainNamespace {
                root: source.config.root.clone(),
                domain: source.guard().config().storage_domain.clone(),
            },
            source.authority.control(),
            source
                .config
                .publication_control
                .as_ref()
                .require()
                .operator_uid,
        )
        .await
        .require();
        let guard = repository.coordinator().guard();
        let selected_head = terrane_core::refs::RefRecord::decode(&head_bytes).require();
        let authority = guard
            .original_commit(&selected_head.commit)
            .require()
            .baseline()
            .authority()
            .clone();
        assert_eq!(authority.id(), source.authority.id());

        // These are independent observations under one real namespace holder,
        // not replacement configuration or permission for the lease producer.
        {
            let holder = SingleHeld::acquire(guard.store()).await.require();
            let held = holder.destination();
            assert_eq!(held.root(), guard.store().root());
            assert_eq!(held.root(), authority.root());
            assert_eq!(held.physical_identity(), authority.physical_identity());
            assert_eq!(authority.domain(), guard.config().storage_domain);
            let (profile_name, profile) = guard.store().publication_profile();
            assert_eq!(profile_name, guard.config().chunk_profile_name);
            assert_eq!(profile, guard.config().chunk_profile.as_ref());

            let observed = held.observe_publication_unrepaired().await.require();
            let consumed = crate::guard::ConsumedResolver::new(guard, &authority).require();
            consumed.registration(&authority).require();
            let configured_snapshot = consumed.snapshot_bytes().require();
            let selected_snapshot = held
                .selected_guard_snapshot(&observed)
                .await
                .require()
                .require();
            assert_eq!(
                configured_snapshot, selected_snapshot,
                "reconstructed Guard configuration differs from actual selected Guard"
            );
        }
        let collector = Collector::new(guard, &authority);
        let head_path = root.join(&head_key);
        let note_path = root.join(&note_key);
        assert_eq!(std::fs::read(&head_path).require(), head_bytes);
        std::fs::remove_file(&head_path).require();
        std::fs::write(&note_path, &note_bytes).require();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&note_path, std::fs::Permissions::from_mode(0o600)).require();
        let completed = fs.observe_syncs();
        let receipt = collector.acquire("cache-repair".into(), 20).await.require();
        let (files, directories) = events(completed);
        assert_eq!(files.get(&head_path), Some(&1));
        assert!(!files.contains_key(&note_path));
        assert!(directories.contains_key(note_path.parent().require()));
        assert!(files.values().all(|count| *count == 1));
        assert!(directories.values().all(|count| *count == 1));
        assert_eq!(std::fs::read(&head_path).require(), head_bytes);
        assert_eq!(
            std::fs::symlink_metadata(&note_path).require_error().kind(),
            std::io::ErrorKind::NotFound
        );
        let holder = collector.hold_namespace().await.require();
        let held = holder.destination();
        let after = held.observe_publication_unrepaired().await.require();
        assert_eq!(after.logical()[&note_key], None);
        assert_eq!(after.logical()[&head_key].as_ref(), Some(&head_bytes));
        assert_eq!(
            GcLease::decode(after.logical()["gc/lease"].as_deref().require()).require(),
            receipt.lease
        );
    }
    source.cleanup();
}
