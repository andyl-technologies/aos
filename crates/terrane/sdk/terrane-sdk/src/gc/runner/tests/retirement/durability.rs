//! Qualifies original-descriptor and scoped-directory durability in a real barrier.

use super::*;
use crate::store::RetirementSyncEvent;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;

/// Identifies an actual original held throughout the native durability phase.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Descriptor {
    number: std::os::fd::RawFd,
    identity: (u64, u64),
}

/// Keeps every field that distinguishes a native directory synchronization scope.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DirectoryScope {
    path: PathBuf,
    root: PathBuf,
    owner: u32,
    control: bool,
}

fn record_directory(
    records: &mut BTreeMap<DirectoryScope, (Descriptor, usize)>,
    scope: DirectoryScope,
    descriptor: Descriptor,
) {
    match records.entry(scope) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert((descriptor, 1));
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let (original, count) = entry.get_mut();
            assert_eq!(*original, descriptor);
            *count += 1;
        }
    }
}

#[tokio::test]
async fn gc_initial_retirement_syncs_each_scoped_directory_once_after_all_original_files() {
    let fixture = Fixture::new().await;
    let (id, upper) = orphan(&fixture).await;
    let base = upper
        .checked_add(windows().grace())
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut collection = completed(&fixture, base, windows()).await;
    let before = image(&fixture).await;
    let progress = collection.state().clone();
    let control = fixture.parent.join("publication");
    let owner = fixture
        .config
        .publication_control
        .as_ref()
        .unwrap()
        .operator_uid;
    let events = fixture
        .fs
        .observe_retirement_syncs(fixture.next_checkpoint_slot().await);

    let tombstone = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(tombstone.pack, *id.as_bytes());
    assert_eq!(tombstone.cycle, collection.roots().cycle);
    assert_eq!(tombstone.timestamp, base);
    assert_eq!(collection.state(), &progress);
    let mut captured_files = BTreeMap::new();
    let mut synced_files = BTreeMap::new();
    let mut captured_directories = BTreeMap::new();
    let mut synced_directories = BTreeMap::new();
    let mut last_file_sync = None;
    let mut first_directory_sync = None;
    let mut directory_depths = Vec::new();
    for (position, event) in events.try_iter().enumerate() {
        match event {
            RetirementSyncEvent::FileCaptured {
                path,
                descriptor,
                identity,
            } => {
                *captured_files
                    .entry((
                        path,
                        Descriptor {
                            number: descriptor,
                            identity,
                        },
                    ))
                    .or_insert(0usize) += 1;
            }
            RetirementSyncEvent::FileSynced {
                path,
                descriptor,
                identity,
            } => {
                *synced_files
                    .entry((
                        path,
                        Descriptor {
                            number: descriptor,
                            identity,
                        },
                    ))
                    .or_insert(0usize) += 1;
                last_file_sync = Some(position);
            }
            RetirementSyncEvent::DirectoryCaptured {
                path,
                root,
                owner,
                control,
                descriptor,
                identity,
            } => {
                record_directory(
                    &mut captured_directories,
                    DirectoryScope {
                        path,
                        root,
                        owner,
                        control,
                    },
                    Descriptor {
                        number: descriptor,
                        identity,
                    },
                );
            }
            RetirementSyncEvent::DirectorySynced {
                path,
                root,
                owner,
                control,
                descriptor,
                identity,
            } => {
                first_directory_sync.get_or_insert(position);
                directory_depths.push(path.components().count());
                record_directory(
                    &mut synced_directories,
                    DirectoryScope {
                        path,
                        root,
                        owner,
                        control,
                    },
                    Descriptor {
                        number: descriptor,
                        identity,
                    },
                );
            }
        }
    }
    assert_eq!(events.try_recv(), Err(TryRecvError::Disconnected));
    assert!(captured_files.len() > 1);
    assert_eq!(synced_files, captured_files);
    assert!(last_file_sync.unwrap() < first_directory_sync.unwrap());
    assert!(
        directory_depths
            .windows(2)
            .all(|depths| depths[0] >= depths[1])
    );
    assert!(captured_directories.values().any(|(_, count)| *count > 1));
    assert_eq!(synced_directories.len(), captured_directories.len());
    for (scope, (original, _)) in &captured_directories {
        assert_eq!(scope.owner, owner);
        assert_eq!(
            &scope.root,
            if scope.control {
                &control
            } else {
                &fixture.config.root
            }
        );
        assert!(scope.path.starts_with(&scope.root));
        let (synced, count) = synced_directories.get(scope).unwrap();
        assert_eq!(synced, original);
        assert_eq!(*count, 1);
    }
    assert!(synced_directories.keys().any(|scope| scope.control));
    assert!(synced_directories.keys().any(|scope| !scope.control));

    let key = format!("trash/{}/{id}", tombstone.cycle);
    let bytes = tokio::fs::read(fixture.config.root.join(&key))
        .await
        .unwrap();
    assert_eq!(bytes, tombstone.encode());
    let record =
        CreationJournal::decode(&tokio::fs::read(journal(&fixture, &key)).await.unwrap()).unwrap();
    assert_eq!(record.key, key);
    let JournalState::Committed {
        binding,
        file_identity,
    } = record.state
    else {
        panic!("Trash was not genuinely committed");
    };
    assert_eq!(binding, ArtifactBinding::Trash(bytes));
    let metadata = std::fs::symlink_metadata(fixture.config.root.join(&key)).unwrap();
    assert_eq!(
        file_identity,
        [metadata.dev().to_be_bytes(), metadata.ino().to_be_bytes()].concat(),
    );
    assert_eq!(fixture.selected_state(tombstone.cycle).await, progress);
    assert_preserved(&fixture, &before, id, tombstone.cycle, true).await;
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    drop(collection);
    fixture.cleanup();
}
