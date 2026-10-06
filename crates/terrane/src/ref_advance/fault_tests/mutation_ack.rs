//! Exercises common publication acknowledgment through real repository producers.
//!
//! Fault selectors inspect genuine selecting slots. They neither construct a
//! checked mutation nor populate its private acknowledgment channel. All ordinary
//! I/O and authority factories remain the native implementations.

use super::{
    AdvanceError, FaultFs, LocalFs, NativeFixture, Path, PathBuf, RefStore, StoreErrorKind,
    TokioLocalFs, configured_with_fs, fixture, request, token,
};
use crate::store::{EffectFault, EffectFaultProbe, NativeEffectFailure, NativeFsEffect};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use terrane_core::gc::publication::{PublicationCommit, PublicationProof, PublicationTransaction};

/// Retains finite selectors and actual submitted common acknowledgment slots.
#[derive(Clone, Default)]
pub(super) struct Hooks {
    pending: Arc<Mutex<Option<Hook>>>,
    slots: Arc<Mutex<Vec<PathBuf>>>,
}

enum Hook {
    Noop,
    Fault {
        fault: EffectFault,
        swallow: bool,
    },
    Pause {
        arrived: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    },
    Directory {
        arrived: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        after: mpsc::Sender<()>,
    },
}

impl Hooks {
    fn arm(&self, hook: Hook) {
        let mut pending = self.pending.lock().unwrap();
        assert!(
            pending.is_none(),
            "a prior common acknowledgment hook is unconsumed"
        );
        *pending = Some(hook);
    }

    fn consumed(&self) {
        assert!(
            self.pending.lock().unwrap().is_none(),
            "actual common phase never consumed its hook"
        );
    }

    fn pause(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, receiver) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        self.arm(Hook::Pause {
            arrived,
            release: resume,
        });
        (receiver, release)
    }
}

/// Runs only the actual common acknowledgment, preserving physical fault causes.
///
/// # Errors
/// Propagates real native errors, malformed actual selecting records, poisoned
/// instrumentation and failed bounded worker rendezvous.
///
/// # Panics
/// Panics if a swallowed injected fault was not reached by the actual native worker.
pub(super) async fn execute(
    fs: &FaultFs,
    mut effect: NativeFsEffect,
) -> Result<(), NativeEffectFailure> {
    let EffectFaultProbe::SealMutationPublication(path) = effect.fault_probe() else {
        return Err(std::io::Error::other("incorrect common fault dispatch").into());
    };
    let path = path.to_owned();
    let transaction = transaction(&path).await?;
    fs.mutation
        .slots
        .lock()
        .map_err(|_| std::io::Error::other("mutation slot observer poisoned"))?
        .push(path);
    let hook = if matches!(transaction.proof, PublicationProof::Candidate(_)) {
        fs.mutation
            .pending
            .lock()
            .map_err(|_| std::io::Error::other("mutation selector poisoned"))?
            .take()
    } else {
        None
    };
    let mut swallow = false;
    match hook {
        Some(Hook::Noop) => return Ok(()),
        Some(Hook::Fault {
            fault,
            swallow: requested,
        }) => {
            effect = effect.inject_test_faults(vec![fault]);
            swallow = requested;
        }
        Some(Hook::Pause { arrived, release }) => {
            return tokio::task::spawn_blocking(move || {
                // This genuine submitted request owns its native exclusions
                // even after the asynchronous waiter is cancelled.
                arrived.send(()).map_err(std::io::Error::other)?;
                release
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(std::io::Error::other)?;
                effect.execute_inline()
            })
            .await
            .map_err(std::io::Error::other)?;
        }
        Some(Hook::Directory {
            arrived,
            release,
            after,
        }) => {
            effect = effect.test_directory_sync_handoff(arrived, release, after);
        }
        None => {}
    }
    let result = TokioLocalFs.execute_retained_effect(effect).await;
    if swallow {
        match result {
            Err(NativeEffectFailure::Io(error)) => {
                assert!(error.to_string().contains("injected creation"));
                return Ok(());
            }
            other => panic!("actual common sync fault was not reached: {other:?}"),
        }
    }
    result
}

async fn transaction(slot_path: &Path) -> std::io::Result<PublicationTransaction> {
    let slot = PublicationCommit::decode(&TokioLocalFs.read_nofollow(slot_path).await?)
        .map_err(std::io::Error::other)?;
    let control = slot_path
        .ancestors()
        .nth(3)
        .ok_or_else(|| std::io::Error::other("actual slot lacks backend control"))?;
    let bytes = TokioLocalFs
        .read_nofollow(&control.join(&slot.transaction_key))
        .await?;
    let revision = slot_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::other("actual slot name is not canonical"))?;
    slot.check_transaction(&format!("publication/commits/{revision}"), &bytes)
        .map_err(std::io::Error::other)?;
    PublicationTransaction::decode(&bytes).map_err(std::io::Error::other)
}

async fn selected(
    coordinator: &NativeFixture<FaultFs>,
) -> (
    (u64, [u8; 32]),
    terrane_core::gc::publication::PublicationState,
    PathBuf,
) {
    let held = crate::bucket::held::SingleHeld::acquire(coordinator.store())
        .await
        .unwrap();
    let destination = held.destination();
    let observed = destination.observe_publication().await.unwrap();
    let control = observed
        .physical_reads()
        .first()
        .unwrap()
        .path()
        .parent()
        .unwrap()
        .to_owned();
    (observed.stamp(), observed.state().clone(), control)
}

async fn initialized() -> (FaultFs, Arc<NativeFixture<FaultFs>>) {
    let fs = FaultFs::default();
    let coordinator = Arc::new(
        NativeFixture::initialize(configured_with_fs(fixture(fs.clone()).await, fs.clone())).await,
    );
    (fs, coordinator)
}

fn unavailable(error: AdvanceError) {
    let failure = match error {
        AdvanceError::Indeterminate { source, .. } => *source,
        AdvanceError::Store(source) => source,
        other => panic!("expected typed native refusal, got {other:?}"),
    };
    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
    assert!(std::error::Error::source(&failure).is_some());
}

fn unsupported(error: AdvanceError) {
    assert!(matches!(error, AdvanceError::Store(failure)
        if matches!(failure.kind(), StoreErrorKind::Unsupported)));
}

async fn arrived(receiver: mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
}

fn replace_same_bytes(path: &Path) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let before = std::fs::symlink_metadata(path).unwrap();
    let bytes = std::fs::read(path).unwrap();
    let replacement = path.with_extension("ack-replacement");
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&replacement)
        .unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(file);
    std::fs::write(&replacement, &bytes).unwrap();
    std::fs::rename(&replacement, path).unwrap();
    let after = std::fs::symlink_metadata(path).unwrap();
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

fn excluded(paths: &[PathBuf]) {
    for path in paths {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(
            matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "actual retained lock was released: {}",
            path.display()
        );
    }
}

#[tokio::test]
async fn checked_mutation_acknowledges_actual_guard_and_ref_publication() {
    let (fs, coordinator) = initialized().await;
    let (_, guard_state, _) = selected(&coordinator).await;
    assert!(guard_state.guard.is_some());
    let initial_slots = fs.mutation.slots.lock().unwrap().clone();
    assert!(!initial_slots.is_empty());
    let mut guard_proof = false;
    for path in initial_slots {
        let transaction = transaction(&path).await.unwrap();
        if let PublicationProof::Guard(digest) = transaction.proof {
            assert_eq!(transaction.old.as_ref().unwrap().guard, None);
            assert_eq!(transaction.new.guard, Some(digest));
            let control = path.ancestors().nth(3).unwrap();
            let bytes = TokioLocalFs
                .read_nofollow(&control.join(format!(
                    "publication/guards/{}",
                    blake3::Hash::from_bytes(digest).to_hex(),
                )))
                .await
                .unwrap();
            assert_eq!(blake3::hash(&bytes).as_bytes(), &digest);
            terrane_core::gc::publication::evidence::GuardSnapshot::decode(&bytes).unwrap();
            guard_proof = true;
        }
    }
    assert!(
        guard_proof,
        "genuine initial Guard publication never completed"
    );

    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let record = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    assert_eq!(record.seq, 1);
    assert_eq!(record.writer_epoch, session.epoch());
    assert_eq!(
        coordinator.store().ref_get(reference).await.unwrap(),
        Some(record.clone())
    );
    let (stamp, state, control) = selected(&coordinator).await;
    let slot_path = control.join(format!("publication/commits/{}", stamp.0));
    assert!(fs.mutation.slots.lock().unwrap().contains(&slot_path));
    let slot_bytes = TokioLocalFs.read_nofollow(&slot_path).await.unwrap();
    assert_eq!(blake3::hash(&slot_bytes).as_bytes(), &stamp.1);
    let transaction = transaction(&slot_path).await.unwrap();
    assert_eq!(transaction.new, state);
    assert_eq!(state.guard, guard_state.guard);
    assert!(matches!(transaction.proof, PublicationProof::Candidate(_)));
    let ref_key = terrane_core::bucket::BucketKey::ref_record(reference).unwrap();
    let change = transaction
        .changes
        .iter()
        .find(|row| row.key == ref_key.as_str())
        .unwrap();
    assert_eq!(change.expected, None);
    assert_eq!(change.new, Some(record.encode().unwrap()));
    let pointer = TokioLocalFs
        .read_nofollow(&coordinator.store().root().join("publication/PORTABLE"))
        .await
        .unwrap();
    assert_eq!(pointer, transaction.snapshot.encode().unwrap());
    let snapshot = TokioLocalFs
        .read_nofollow(&coordinator.store().root().join(&transaction.snapshot.key))
        .await
        .unwrap();
    transaction.check_snapshot(&snapshot).unwrap();
}

#[tokio::test]
async fn checked_mutation_denies_noop_unit_success() {
    let (fs, coordinator) = initialized().await;
    let mut session = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    fs.mutation.arm(Hook::Noop);

    unsupported(
        coordinator
            .advance(&mut session, request(Vec::new()))
            .await
            .unwrap_err(),
    );
    fs.mutation.consumed();
    assert_eq!(session.record(), None);
    // The selecting slot can already be visible. Readback does not acknowledge
    // durability or replace the closed native result.
    let record = coordinator
        .store()
        .ref_get(session.reference())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.seq, 1);
    assert!(matches!(
        coordinator
            .advance(&mut session, request(vec![record.commit]))
            .await,
        Err(AdvanceError::Fenced { .. })
    ));
}

#[tokio::test]
async fn checked_mutation_denies_swallowed_sync_failures() {
    for case in 0..16 {
        let (fs, coordinator) = initialized().await;
        let reference = "refs/heads/_/main";
        let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
        let first = coordinator
            .advance(&mut session, request(Vec::new()))
            .await
            .unwrap();
        let (_, _, control) = selected(&coordinator).await;
        let original = coordinator.guard().original_commit(&first.commit).unwrap();
        let original_control = original.baseline().authority().control().to_owned();
        let fault = match case / 2 {
            0 => EffectFault::BeforeFileSync,
            1 => EffectFault::AfterFileSync,
            2 => EffectFault::BeforeDirectorySyncAt(coordinator.store().root().to_owned()),
            3 => EffectFault::AfterDirectorySyncAt(coordinator.store().root().to_owned()),
            4 => EffectFault::BeforeDirectorySyncAt(control),
            5 => EffectFault::AfterDirectorySyncAt(control),
            6 => EffectFault::BeforeDirectorySyncAt(original_control),
            _ => EffectFault::AfterDirectorySyncAt(original_control),
        };
        let swallow = case % 2 == 1;
        fs.mutation.arm(Hook::Fault { fault, swallow });

        let error = coordinator
            .advance(&mut session, request(vec![first.commit]))
            .await
            .unwrap_err();
        fs.mutation.consumed();
        if swallow {
            unsupported(error);
        } else {
            unavailable(error);
        }
        assert_eq!(session.record(), Some(&first));
        let selected = coordinator
            .store()
            .ref_get(reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.seq, 2);
        assert!(matches!(
            coordinator
                .advance(&mut session, request(vec![selected.commit]))
                .await,
            Err(AdvanceError::Fenced { .. })
        ));
    }
}

#[tokio::test]
async fn checked_mutation_retains_selected_guard_and_control_preimages() {
    for guard_record in [true, false] {
        let (fs, coordinator) = initialized().await;
        let reference = "refs/heads/_/main";
        let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
        let first = coordinator
            .advance(&mut session, request(Vec::new()))
            .await
            .unwrap();
        let (_, state, control) = selected(&coordinator).await;
        let target = if guard_record {
            control.join(format!(
                "publication/guards/{}",
                blake3::Hash::from_bytes(state.guard.unwrap()).to_hex()
            ))
        } else {
            coordinator
                .guard()
                .original_commit(&first.commit)
                .unwrap()
                .baseline()
                .authority()
                .control()
                .join("registration.cbor")
        };
        let (arrival, release) = fs.mutation.pause();
        let selected_coordinator = Arc::clone(&coordinator);
        let task = tokio::spawn(async move {
            selected_coordinator
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
async fn checked_mutation_cancellation_retains_actual_exclusions() {
    let (fs, coordinator) = initialized().await;
    let reference = "refs/heads/_/main";
    let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let control = coordinator
        .guard()
        .original_commit(&first.commit)
        .unwrap()
        .baseline()
        .authority()
        .control()
        .to_owned();
    let coordination = coordinator.store().root().join(
        terrane_core::bucket::BucketKey::parse("CAPABILITIES")
            .unwrap()
            .lock_name(),
    );
    let paths = [coordination, control.join("retention.lock")];
    let (arrival, release) = fs.mutation.pause();
    let selected_coordinator = Arc::clone(&coordinator);
    let task = tokio::spawn(async move {
        selected_coordinator
            .advance(&mut session, request(vec![first.commit]))
            .await
    });
    arrived(arrival).await;
    excluded(&paths);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    excluded(&paths);
    fs.mutation.consumed();
    release.send(()).unwrap();

    // A genuine later namespace acquisition waits for the detached physical
    // worker. This bounded acquisition proves exclusion release follows worker
    // completion rather than cancellation of its asynchronous waiter.
    let held = tokio::time::timeout(
        Duration::from_secs(5),
        crate::bucket::held::SingleHeld::acquire(coordinator.store()),
    )
    .await
    .unwrap()
    .unwrap();
    let destination = held.destination();
    let selected = destination.observe_publication().await.unwrap();
    assert!(selected.state().guard.is_some());
    assert_eq!(
        selected
            .state()
            .branches
            .iter()
            .find(|row| row.name == reference)
            .map(|row| &row.selection),
        Some(
            &terrane_core::gc::publication::CommittedSelection::Selected(
                destination
                    .ref_get(reference)
                    .await
                    .unwrap()
                    .unwrap()
                    .into(),
            )
        )
    );
}

#[tokio::test]
async fn checked_mutation_refreshes_before_actual_directory_sync() {
    for changed in 0..3 {
        let (fs, coordinator) = initialized().await;
        let reference = "refs/heads/_/main";
        let mut session = coordinator.begin(reference, &token(), "sdk").await.unwrap();
        let first = coordinator
            .advance(&mut session, request(Vec::new()))
            .await
            .unwrap();
        let (_, state, control) = selected(&coordinator).await;
        let original_control = coordinator
            .guard()
            .original_commit(&first.commit)
            .unwrap()
            .baseline()
            .authority()
            .control()
            .to_owned();
        let target = match changed {
            1 => Some(control.join(format!(
                "publication/guards/{}",
                blake3::Hash::from_bytes(state.guard.unwrap()).to_hex()
            ))),
            2 => Some(original_control.join("registration.cbor")),
            _ => None,
        };
        let (arrival, receiver) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (after, synced) = mpsc::channel();
        fs.mutation.arm(Hook::Directory {
            arrived: arrival,
            release: resume,
            after,
        });
        let selected_coordinator = Arc::clone(&coordinator);
        let task = tokio::spawn(async move {
            let result = selected_coordinator
                .advance(&mut session, request(vec![first.commit]))
                .await;
            (session, result)
        });
        arrived(receiver).await;
        if let Some(target) = target {
            replace_same_bytes(&target);
        }
        release.send(()).unwrap();
        let (session, result) = task.await.unwrap();
        fs.mutation.consumed();

        if changed == 0 {
            let record = result.unwrap();
            assert_eq!(record.seq, 2);
            assert_eq!(session.record(), Some(&record));
            synced.try_recv().unwrap();
        } else {
            unavailable(result.unwrap_err());
            assert!(
                !matches!(synced.try_recv(), Ok(())),
                "changed current control reached the actual directory sync syscall"
            );
            assert_eq!(session.record().unwrap().seq, 1);
        }
    }
}
