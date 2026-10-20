//! Qualifies actual creator-backed native observations without collection permission.
//!
//! Each case uses the production native factory, signed fixture and real pack
//! admission. Neutral observations remain data; only actual executor results
//! retain the pair. No case treats these results as mark, grace or deletion proof.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::pack::PackId;
use crate::store::{LocalFs, StoreErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::gc::{CreationJournal, JournalState};

macro_rules! observed_pair {
    ($fixture:ident, $collection:ident, $holder:ident, $held:ident, $selected:ident, $read:ident) => {
        let $fixture = Fixture::new().await;
        let $collection = Collection::start(
            $fixture.guard(),
            &$fixture.authority,
            "collector".into(),
            1_000,
            1,
            windows(),
        )
        .await
        .unwrap();
        let $holder = SingleHeld::acquire($fixture.guard().store()).await.unwrap();
        let $held = $holder.destination();
        let $selected = $held.observe_publication_unrepaired().await.unwrap();
        let metadata = MetadataStore::new(&$held, &$selected, &$collection.session);
        let catalog = metadata.collection_catalog().await.unwrap();
        let mut data = None;
        let mut paths = Vec::new();
        for row in catalog.inventory().unwrap() {
            let id = PackId::from_random_bytes(row.pack_id);
            let index = tokio::fs::read($fixture.config.root.join(id.index_key()))
                .await
                .unwrap();
            assert_eq!(&index[..6], b"TRPK\x01\x00");
            if index[6] & 2 == 0 {
                paths.push($fixture.config.root.join(id.pack_key()));
                data.get_or_insert(id);
            }
        }
        assert!(!paths.is_empty());
        $fixture.fs.forbid_data_body_reads(&paths).unwrap();
        let $read = metadata.pack_index(&catalog, data.unwrap()).await.unwrap();
        drop(metadata);
        $fixture.fs.reset();
    };
}

macro_rules! close_fixture {
    ($fixture:ident, $collection:ident, $holder:ident, $held:ident, $selected:ident) => {
        drop($selected);
        drop($held);
        drop($holder);
        drop($collection);
        $fixture.cleanup();
    };
}

fn journal(control: &Path, key: &str) -> std::path::PathBuf {
    let suffix: String = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    control.join(".terrane-creation").join(suffix)
}

async fn replace_same_bytes(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let old = std::fs::File::open(path).unwrap();
    let previous = old.metadata().unwrap();
    let bytes = tokio::fs::read(path).await.unwrap();
    let replacement = path.with_extension("pair-replacement");
    tokio::fs::write(&replacement, &bytes).await.unwrap();
    tokio::fs::set_permissions(
        &replacement,
        std::fs::Permissions::from_mode(previous.mode()),
    )
    .await
    .unwrap();
    tokio::fs::rename(&replacement, path).await.unwrap();
    let actual = std::fs::symlink_metadata(path).unwrap();
    assert_ne!(
        (previous.dev(), previous.ino()),
        (actual.dev(), actual.ino())
    );
    assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
}

fn native_refusal(error: &crate::store::StoreFailure) {
    // Unknown native versions return Unsupported. A changed Frame preimage is
    // a physical refresh failure and preserves the established Unavailable kind.
    assert!(matches!(
        error.kind(),
        StoreErrorKind::Unsupported | StoreErrorKind::Unavailable { .. }
    ));
}

#[tokio::test]
async fn native_current_pair_retains_real_creator_versions_without_data_body_reads() {
    observed_pair!(fixture, collection, holder, held, selected, read);
    let expected = read
        .metadata()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    let pair = crate::store::native_publication_effects::observe_current_pair(
        &fixture.fs,
        &selected,
        &read,
    )
    .await
    .unwrap();
    assert_eq!(pair.inventory(), read.inventory());
    assert_eq!(pair.snapshot(), read.snapshot());
    assert_eq!(
        pair.pack_modified_unix_seconds().unwrap(),
        expected.as_secs() + u64::from(expected.subsec_nanos() != 0)
    );
    // Fixture clock is deliberately wall=100; backend time must not come from it.
    assert!(pair.pack_modified_unix_seconds().unwrap() > 100);
    assert_eq!(fixture.fs.effects(), 1);
    fixture.fs.reset();
    crate::store::native_publication_effects::recheck_current_pair_for_test(
        &fixture.fs,
        &selected,
        &pair,
    )
    .await
    .unwrap();
    assert_eq!(fixture.fs.effects(), 1);
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    for lane in 0..3 {
        let result = match lane {
            0 => fixture.fs.read(read.pack_path()).await,
            1 => fixture.fs.read_nofollow(read.pack_path()).await,
            _ => {
                fixture
                    .fs
                    .read_range(
                        read.pack_path(),
                        crate::store::ByteRange {
                            start: 0,
                            length: 1,
                        },
                    )
                    .await
            }
        };
        assert!(result.is_err());
    }
    assert_eq!(fixture.fs.data_body_read_attempts(), 3);
    drop(pair);
    close_fixture!(fixture, collection, holder, held, selected);
}

#[tokio::test]
async fn native_current_pair_noop_acknowledgment_never_produces_result() {
    observed_pair!(fixture, collection, holder, held, selected, read);
    fixture.fs.noop_next_current_pair();
    let error = match crate::store::native_publication_effects::observe_current_pair(
        &fixture.fs,
        &selected,
        &read,
    )
    .await
    {
        Ok(_) => panic!("no-op unit success created a native result"),
        Err(error) => error,
    };
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
    assert_eq!(fixture.fs.effects(), 1);
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    fixture.fs.assert_current_pair_hook_consumed();
    close_fixture!(fixture, collection, holder, held, selected);
}

#[tokio::test]
async fn native_current_pair_rejects_missing_pending_owned_and_misbound_journals() {
    for index in [false, true] {
        for case in 0..7 {
            observed_pair!(fixture, collection, holder, held, selected, read);
            let id = read.snapshot().header().id();
            let key = if index { id.index_key() } else { id.pack_key() };
            let control = fixture
                .config
                .publication_control
                .as_ref()
                .unwrap()
                .control
                .as_ref()
                .unwrap();
            let path = journal(control, &key);
            let original = tokio::fs::read(&path).await.unwrap();
            let mut record = CreationJournal::decode(&original).unwrap();
            assert_eq!(record.encode().unwrap(), original);
            match case {
                0 => {
                    tokio::fs::remove_file(&path).await.unwrap();
                }
                1 => {
                    record.state = JournalState::Pending;
                }
                2 => {
                    record.state = JournalState::Invalidated;
                }
                3 => {
                    let JournalState::Committed {
                        binding,
                        file_identity,
                    } = record.state
                    else {
                        panic!("valid creator baseline missing");
                    };
                    record.state = JournalState::DeleteOwned {
                        binding,
                        file_identity,
                        operation_key: format!("gc/1/delete/{id}/{}", "09".repeat(32)),
                        authorization: [7; 32],
                    };
                }
                4 => {
                    record.key = if index {
                        PackId::from_random_bytes([9; 16]).index_key()
                    } else {
                        PackId::from_random_bytes([9; 16]).pack_key()
                    };
                }
                5 => {
                    let JournalState::Committed {
                        ref mut file_identity,
                        ..
                    } = record.state
                    else {
                        panic!("valid creator baseline missing");
                    };
                    file_identity.fill(0);
                }
                _ => {
                    let JournalState::Committed {
                        ref mut binding, ..
                    } = record.state
                    else {
                        panic!("valid creator baseline missing");
                    };
                    match binding {
                        terrane_format::gc::ArtifactBinding::Pack { digest, .. }
                        | terrane_format::gc::ArtifactBinding::Index { digest, .. } => {
                            digest[0] ^= 1
                        }
                        _ => panic!("valid container binding missing"),
                    }
                }
            }
            if case != 0 {
                let bytes = record.encode().unwrap();
                assert_eq!(CreationJournal::decode(&bytes).unwrap(), record);
                tokio::fs::write(&path, bytes).await.unwrap();
            }
            let before = tokio::fs::read(read.index().path()).await.unwrap();
            let result = crate::store::native_publication_effects::observe_current_pair(
                &fixture.fs,
                &selected,
                &read,
            )
            .await;
            assert!(
                matches!(result, Err(ref error) if matches!(error.kind(), StoreErrorKind::Unsupported))
            );
            assert_eq!(fixture.fs.effects(), usize::from(case == 5));
            assert_eq!(fixture.fs.data_body_read_attempts(), 0);
            assert_eq!(tokio::fs::read(read.index().path()).await.unwrap(), before);
            if case == 0 {
                assert!(!path.exists());
            }
            close_fixture!(fixture, collection, holder, held, selected);
        }
    }
}

#[tokio::test]
async fn native_current_pair_rejects_changed_native_names_metadata_and_index_bindings() {
    for after_read in [false, true] {
        for target in 0..10 {
            observed_pair!(fixture, collection, holder, held, selected, read);
            let id = read.snapshot().header().id();
            let control = fixture
                .config
                .publication_control
                .as_ref()
                .unwrap()
                .control
                .as_ref()
                .unwrap();
            let paths = [
                read.pack_path().to_owned(),
                read.index().path().to_owned(),
                journal(control, &id.pack_key()),
                journal(control, &id.index_key()),
            ];
            let (arrival, release) = fixture
                .fs
                .pause_current_pair(read.pack_path().to_owned(), after_read);
            let waiter = tokio::task::spawn_blocking(move || {
                arrival.recv_timeout(Duration::from_secs(10)).unwrap()
            });
            let mut operation = Box::pin(
                crate::store::native_publication_effects::observe_current_pair(
                    &fixture.fs,
                    &selected,
                    &read,
                ),
            );
            tokio::select! {
                result = &mut operation => panic!("pair ended before actual handoff: {}", result.is_ok()),
                result = waiter => result.unwrap(),
            }
            match target {
                0..=3 => replace_same_bytes(&paths[target]).await,
                4 => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&paths[0])
                        .unwrap()
                        .set_len(read.inventory().pack_size + 1)
                        .unwrap();
                }
                5 => {
                    tokio::fs::set_permissions(&paths[0], std::fs::Permissions::from_mode(0o666))
                        .await
                        .unwrap();
                }
                6 => {
                    let old = control.with_extension("pair-original-control");
                    tokio::fs::rename(control, old).await.unwrap();
                    std::fs::DirBuilder::new()
                        .recursive(false)
                        .create(control)
                        .unwrap();
                    tokio::fs::set_permissions(control, std::fs::Permissions::from_mode(0o700))
                        .await
                        .unwrap();
                }
                7 => {
                    tokio::fs::set_permissions(control, std::fs::Permissions::from_mode(0o755))
                        .await
                        .unwrap();
                }
                8 => {
                    let mut bytes = tokio::fs::read(&paths[1]).await.unwrap();
                    bytes[0] ^= 1;
                    tokio::fs::write(&paths[1], bytes).await.unwrap();
                }
                _ => {
                    tokio::fs::hard_link(&paths[1], paths[1].with_extension("linked-index"))
                        .await
                        .unwrap();
                }
            }
            release.send(()).unwrap();
            let result = operation.await;
            match result {
                Ok(_) => panic!("changed native pair was acknowledged"),
                Err(error) => native_refusal(&error),
            }
            fixture.fs.assert_current_pair_hook_consumed();
            assert_eq!(fixture.fs.effects(), 1);
            assert_eq!(fixture.fs.data_body_read_attempts(), 0);
            close_fixture!(fixture, collection, holder, held, selected);
        }
    }
}

#[tokio::test]
async fn native_current_pair_rechecks_versions_during_every_native_effect() {
    for target in 0..4 {
        observed_pair!(fixture, collection, holder, held, selected, read);
        let pair = crate::store::native_publication_effects::observe_current_pair(
            &fixture.fs,
            &selected,
            &read,
        )
        .await
        .unwrap();
        fixture.fs.reset();
        let id = read.snapshot().header().id();
        let control = fixture
            .config
            .publication_control
            .as_ref()
            .unwrap()
            .control
            .as_ref()
            .unwrap();
        let paths = [
            read.pack_path().to_owned(),
            read.index().path().to_owned(),
            journal(control, &id.pack_key()),
            journal(control, &id.index_key()),
        ];
        let (arrival, release) = fixture
            .fs
            .pause_current_pair_root_sync(fixture.config.root.clone());
        let waiter = tokio::task::spawn_blocking(move || {
            arrival.recv_timeout(Duration::from_secs(10)).unwrap()
        });
        let mut operation = Box::pin(
            crate::store::native_publication_effects::recheck_current_pair_for_test(
                &fixture.fs,
                &selected,
                &pair,
            ),
        );
        tokio::select! {
            result = &mut operation => panic!("effect ended before actual final sync: {}", result.is_ok()),
            result = waiter => result.unwrap(),
        }
        replace_same_bytes(&paths[target]).await;
        release.send(()).unwrap();
        native_refusal(&operation.await.unwrap_err());
        fixture.fs.assert_current_pair_hook_consumed();
        assert_eq!(fixture.fs.effects(), 1);
        assert_eq!(fixture.fs.data_body_read_attempts(), 0);
        drop(pair);
        close_fixture!(fixture, collection, holder, held, selected);
    }
}

#[tokio::test]
async fn native_current_pair_cancellation_keeps_actual_exclusion_through_worker_completion() {
    let fixture = Fixture::new().await;
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    let cap = terrane_format::bucket::BucketCapabilities::decode(
        &tokio::fs::read(fixture.config.root.join("CAPABILITIES"))
            .await
            .unwrap(),
    )
    .unwrap();
    let manifest = terrane_format::bucket::GenerationManifest::decode(
        &tokio::fs::read(fixture.config.root.join(format!(
            "objects/index/{}/MANIFEST",
            cap.generation.unwrap()
        )))
        .await
        .unwrap(),
    )
    .unwrap();
    let mut data = None;
    for row in manifest.inventory.unwrap() {
        let id = PackId::from_random_bytes(row.pack_id);
        let index = tokio::fs::read(fixture.config.root.join(id.index_key()))
            .await
            .unwrap();
        if index[6] & 2 == 0 {
            data = Some(id);
            break;
        }
    }
    let id = data.unwrap();
    let (arrival, release) = fixture
        .fs
        .pause_current_pair(fixture.config.root.join(id.pack_key()), false);
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    fixture.fs.reset();
    let mut operation = Box::pin(async {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let selected = held.observe_publication_unrepaired().await.unwrap();
        let metadata = MetadataStore::new(&held, &selected, &collection.session);
        let catalog = metadata.collection_catalog().await.unwrap();
        let read = metadata.pack_index(&catalog, id).await.unwrap();
        crate::store::native_publication_effects::observe_current_pair(
            &fixture.fs,
            &selected,
            &read,
        )
        .await
    });
    tokio::select! {
        result = &mut operation => panic!("pair ended before held worker: {}", result.is_ok()),
        result = waiter => result.unwrap(),
    }
    drop(operation);
    let namespace = fixture
        .config
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(namespace)
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    release.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            contender.lock().unwrap();
            contender.unlock().unwrap();
        }),
    )
    .await
    .unwrap()
    .unwrap();
    fixture.fs.assert_current_pair_hook_consumed();
    assert_eq!(fixture.fs.effects(), 1);
    drop(collection);
    fixture.cleanup();
}
