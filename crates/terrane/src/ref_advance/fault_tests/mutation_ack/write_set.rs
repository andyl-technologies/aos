//! Observes actual common durability syscalls through production repository fixtures.
//!
//! Expected output names come independently from the actual selecting transaction
//! and deliberately changed physical caches. No fixture constructs a checked
//! mutation, supplies its write inventory or fills its acknowledgment channel.

use super::{
    FaultFs, Hook, Hooks, LocalFs, NativeFixture, Path, PathBuf, PublicationProof, TokioLocalFs,
    arrived, initialized, replace_same_bytes, request, selected, token, unavailable,
};
use crate::store::MutationSyncEvent;
use std::collections::BTreeSet;
use std::sync::{Arc, mpsc};
use terrane_core::gc::publication::LogicalChange;
use terrane_core::refs::RefRecord;

/// Holds one fixture-local cache fault for the actual candidate projection handoff.
pub(super) struct CacheChange {
    root: PathBuf,
    target: PathBuf,
    replacement: Option<Vec<u8>>,
}

/// Changes a cache after borrowed revalidation, before the checked frame reads it.
///
/// This hook neither projects logical data nor observes the producer's write
/// inventory. The unchanged cache repair or removal must happen in the genuine
/// subsequent mutation, with its final actual durability syscalls observed below.
///
/// # Errors
/// Rejects poisoned fixture state and failed actual cache creation or removal.
///
/// # Panics
/// Panics if the injected cache differs from its immediately verified state.
pub(super) fn before_candidate_projection(hooks: &Hooks, root: &Path) -> std::io::Result<()> {
    let change = {
        let mut pending = hooks
            .cache_change
            .lock()
            .map_err(|_| std::io::Error::other("cache fault selector poisoned"))?;
        if pending.as_ref().is_some_and(|change| change.root == root) {
            pending.take()
        } else {
            None
        }
    };
    if let Some(change) = change {
        match change.replacement {
            Some(bytes) => {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&change.target)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                assert_eq!(std::fs::read(&change.target)?, bytes);
            }
            None => {
                std::fs::remove_file(&change.target)?;
                assert!(!change.target.exists());
            }
        }
    }
    Ok(())
}

fn observe(hooks: &Hooks) -> mpsc::Receiver<MutationSyncEvent> {
    let (sender, receiver) = mpsc::channel();
    hooks.arm(Hook::Observe(sender));
    receiver
}

fn arm_cache_change(hooks: &Hooks, root: &Path, target: PathBuf, replacement: Option<Vec<u8>>) {
    let mut pending = hooks.cache_change.lock().unwrap();
    assert!(pending.is_none());
    *pending = Some(CacheChange {
        root: root.to_owned(),
        target,
        replacement,
    });
}

async fn seeded() -> (
    FaultFs,
    Arc<NativeFixture<FaultFs>>,
    crate::ref_advance::WriterSession,
    RefRecord,
) {
    let (fs, coordinator) = initialized().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let record = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    (fs, coordinator, session, record)
}

fn required_directories(path: &Path, root: &Path, expected: &mut BTreeSet<PathBuf>) {
    let mut directory = path.parent().unwrap();
    loop {
        assert!(directory.starts_with(root));
        expected.insert(directory.to_owned());
        if directory == root {
            break;
        }
        directory = directory.parent().unwrap();
    }
}

async fn assert_inventory(
    coordinator: &NativeFixture<FaultFs>,
    record: &RefRecord,
    events: mpsc::Receiver<MutationSyncEvent>,
    additional: &[(PathBuf, bool)],
) -> (BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
    let (stamp, state, control) = selected(coordinator).await;
    let root = coordinator.store().root();
    let slot_path = control.join(format!("publication/commits/{}", stamp.0));
    let transaction = super::transaction(&slot_path).await.unwrap();
    assert_eq!(transaction.new, state);
    // Resolve the real transaction name from the verified selecting slot rather
    // than from the production synchronization request or emitted event list.
    let slot_bytes = TokioLocalFs
        .read_nofollow(&control.join(format!("publication/commits/{}", stamp.0)))
        .await
        .unwrap();
    let slot = terrane_core::gc::publication::PublicationCommit::decode(&slot_bytes).unwrap();
    let mut files = BTreeSet::from([
        control.join(format!("publication/commits/{}", stamp.0)),
        control.join(&slot.transaction_key),
        root.join(&transaction.snapshot.key),
        root.join("publication/PORTABLE"),
        control.join(format!(
            "publication/guards/{}",
            blake3::Hash::from_bytes(state.guard.unwrap()).to_hex()
        )),
    ]);
    if let PublicationProof::Candidate(lineage) = transaction.proof {
        files.insert(control.join(format!(
            "publication/lineage/{}",
            blake3::Hash::from_bytes(lineage).to_hex()
        )));
        let lineage_bytes = TokioLocalFs
            .read_nofollow(&control.join(format!(
                "publication/lineage/{}",
                blake3::Hash::from_bytes(lineage).to_hex()
            )))
            .await
            .unwrap();
        let lineage =
            terrane_core::gc::publication::evidence::CheckedLineage::decode(&lineage_bytes)
                .unwrap();
        let log = terrane_core::bucket::BucketKey::reflog_candidate(
            &lineage.source_name,
            lineage.source.seq,
            &lineage.source.candidate_id.unwrap(),
        )
        .unwrap();
        files.insert(root.join(log.as_str()));
    } else {
        panic!("expected actual checked candidate transaction");
    }
    let mut absent = BTreeSet::new();
    for change in &transaction.changes {
        let path = root.join(&change.key);
        if let Some(bytes) = &change.new {
            assert_eq!(TokioLocalFs.read_nofollow(&path).await.unwrap(), *bytes);
            files.insert(path);
        } else {
            assert!(!path.exists());
            absent.insert(path);
        }
    }
    for (path, present) in additional {
        if *present {
            files.insert(path.clone());
        } else {
            absent.insert(path.clone());
        }
    }
    let mut directories = BTreeSet::new();
    for path in files.iter().chain(&absent) {
        let boundary = if path.starts_with(&control) {
            &control
        } else {
            root
        };
        required_directories(path, boundary, &mut directories);
    }
    let context = coordinator.guard().original_commit(&record.commit).unwrap();
    let original = context.baseline().authority().control();
    files.insert(original.join("registration.cbor"));
    files.insert(original.join(format!(
        "commit-{}.cbor",
        blake3::Hash::from_bytes(record.commit).to_hex()
    )));
    files.insert(original.join(format!(
        "bootstrap-{}-{}-{}.cbor",
        blake3::Hash::from_bytes(*context.baseline().authority().id()).to_hex(),
        blake3::hash(context.baseline().reference().as_bytes()).to_hex(),
        context.baseline().epoch(),
    )));
    directories.insert(original.to_owned());

    let events: Vec<_> = events.try_iter().collect();
    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    let mut directories_started = false;
    for event in events {
        match event {
            MutationSyncEvent::File(path) => {
                assert!(
                    !directories_started,
                    "file sync followed directory durability"
                );
                assert!(
                    actual_files.insert(path),
                    "same final file synchronized twice"
                );
            }
            MutationSyncEvent::Directory(path) => {
                directories_started = true;
                assert!(
                    actual_directories.insert(path),
                    "same directory synchronized twice"
                );
            }
        }
    }
    assert_eq!(actual_files, files);
    assert_eq!(actual_directories, directories);
    (actual_files, actual_directories)
}

#[tokio::test]
async fn written_mutation_syncs_exact_outputs_and_unique_directories() {
    let (fs, coordinator, mut session, first) = seeded().await;
    let (old_stamp, _, control) = selected(&coordinator).await;
    let old_slot = control.join(format!("publication/commits/{}", old_stamp.0));
    let old_transaction = super::transaction(&old_slot).await.unwrap();
    let events = observe(&fs.mutation);

    let second = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();

    fs.mutation.consumed();
    let (files, _) = assert_inventory(&coordinator, &second, events, &[]).await;
    assert!(!files.contains(&old_slot));
    assert!(
        !files.contains(
            &coordinator
                .store()
                .root()
                .join(old_transaction.snapshot.key)
        )
    );
    assert!(!files.contains(&control.join("backend-registration.cbor")));
    let original = coordinator.guard().original_commit(&second.commit).unwrap();
    assert!(
        files.contains(
            &original
                .baseline()
                .authority()
                .control()
                .join("registration.cbor")
        )
    );
    assert!(
        !files.contains(&original.baseline().authority().control().join(format!(
            "commit-{}.cbor",
            blake3::Hash::from_bytes(first.commit).to_hex()
        )))
    );
}

#[tokio::test]
async fn written_mutation_syncs_unchanged_projection_repair() {
    let (fs, coordinator, mut session, first) = seeded().await;
    let other = "refs/heads/_/unchanged";
    let mut other_session = coordinator.begin(other, &token(), "sdk").await.unwrap();
    let other_record = coordinator
        .advance(&mut other_session, request(Vec::new()))
        .await
        .unwrap();
    let key = terrane_core::bucket::BucketKey::ref_record(other).unwrap();
    let target = coordinator.store().root().join(key.as_str());
    let bytes = TokioLocalFs.read_nofollow(&target).await.unwrap();
    assert_eq!(bytes, other_record.encode().unwrap());
    arm_cache_change(
        &fs.mutation,
        coordinator.store().root(),
        target.clone(),
        None,
    );
    let events = observe(&fs.mutation);

    let next = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();

    assert!(
        fs.mutation.cache_change.lock().unwrap().is_none(),
        "actual checked candidate projection handoff not reached"
    );
    fs.mutation.consumed();
    assert_eq!(TokioLocalFs.read_nofollow(&target).await.unwrap(), bytes);
    let (stamp, _, control) = selected(&coordinator).await;
    let transaction = super::transaction(&control.join(format!("publication/commits/{}", stamp.0)))
        .await
        .unwrap();
    assert!(
        transaction
            .changes
            .iter()
            .all(|change| change.key != key.as_str())
    );
    assert_inventory(&coordinator, &next, events, &[(target, true)]).await;
}

#[tokio::test]
async fn written_mutation_syncs_removed_projection_cache_directory() {
    let (fs, coordinator, mut session, first) = seeded().await;
    let other = "refs/heads/_/removed/cache";
    let mut other_session = coordinator.begin(other, &token(), "sdk").await.unwrap();
    let old = coordinator
        .advance(&mut other_session, request(Vec::new()))
        .await
        .unwrap();
    let key = terrane_core::bucket::BucketKey::ref_record(other).unwrap();
    let target = coordinator.store().root().join(key.as_str());
    let bytes = old.encode().unwrap();
    {
        let held = crate::bucket::held::SingleHeld::acquire(coordinator.store())
            .await
            .unwrap();
        let destination = held.destination();
        let observed = destination.observe_publication().await.unwrap();
        destination
            .publish_raw(
                &observed,
                vec![LogicalChange {
                    key: key.as_str().into(),
                    expected: Some(bytes.clone()),
                    new: None,
                }],
            )
            .await
            .unwrap();
    }
    assert!(!target.exists());
    arm_cache_change(
        &fs.mutation,
        coordinator.store().root(),
        target.clone(),
        Some(bytes),
    );
    let events = observe(&fs.mutation);

    let next = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();

    assert!(
        fs.mutation.cache_change.lock().unwrap().is_none(),
        "actual checked candidate projection handoff not reached"
    );
    fs.mutation.consumed();
    assert!(!target.exists());
    let (files, directories) =
        assert_inventory(&coordinator, &next, events, &[(target.clone(), false)]).await;
    assert!(!files.contains(&target));
    assert!(directories.contains(target.parent().unwrap()));
}

#[tokio::test]
async fn written_mutation_syncs_newly_created_projection_directories() {
    let (fs, coordinator) = initialized().await;
    let reference = "refs/heads/_/new/directory/branch";
    let key = terrane_core::bucket::BucketKey::ref_record(reference).unwrap();
    let target = coordinator.store().root().join(key.as_str());
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    assert!(!target.parent().unwrap().exists());
    let events = observe(&fs.mutation);

    let record = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();

    fs.mutation.consumed();
    let (_, directories) = assert_inventory(&coordinator, &record, events, &[]).await;
    assert!(directories.contains(target.parent().unwrap()));
    assert!(directories.contains(&coordinator.store().root().join("refs/heads/_/new")));
}

#[tokio::test]
async fn written_mutation_retains_unsynchronized_history_preimages() {
    for case in 0..3 {
        let (fs, coordinator, mut session, first) = seeded().await;
        let (stamp, _, control) = selected(&coordinator).await;
        let slot = control.join(format!("publication/commits/{}", stamp.0));
        let bytes = TokioLocalFs.read_nofollow(&slot).await.unwrap();
        let selecting = terrane_core::gc::publication::PublicationCommit::decode(&bytes).unwrap();
        let transaction = super::transaction(&slot).await.unwrap();
        let target = match case {
            0 => slot,
            1 => control.join(selecting.transaction_key),
            _ => coordinator.store().root().join(transaction.snapshot.key),
        };
        let (arrival, release) = fs.mutation.pause();
        let retained = Arc::clone(&coordinator);
        let task = tokio::spawn(async move {
            retained
                .advance(&mut session, request(vec![first.commit]))
                .await
        });
        arrived(arrival).await;

        replace_same_bytes(&target);
        release.send(()).unwrap();

        unavailable(task.await.unwrap().unwrap_err());
        fs.mutation.consumed();
    }
}

#[tokio::test]
async fn written_mutation_retains_unsynchronized_source_lineage_preimage() {
    let (fs, coordinator, session, _) = seeded().await;
    let (_, state, control) = selected(&coordinator).await;
    let source = state
        .sources
        .iter()
        .find(|row| row.name == session.reference())
        .unwrap();
    let target = control.join(format!(
        "publication/lineage/{}",
        blake3::Hash::from_bytes(source.digest).to_hex()
    ));
    let (arrival, release) = fs.mutation.pause();
    let retained = Arc::clone(&coordinator);
    let source = session.reference().to_owned();
    let task = tokio::spawn(async move {
        let mut candidate = request(Vec::new());
        candidate.uploads.clear();
        retained
            .fork(&source, "refs/heads/_/child", candidate)
            .await
    });
    arrived(arrival).await;

    replace_same_bytes(&target);
    release.send(()).unwrap();

    unavailable(task.await.unwrap().unwrap_err());
    fs.mutation.consumed();
}
