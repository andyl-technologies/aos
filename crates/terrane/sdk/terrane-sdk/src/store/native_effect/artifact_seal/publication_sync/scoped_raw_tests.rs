//! Exercises actual scoped durability with retained native descriptors and locks.

#![allow(
    clippy::unwrap_used,
    reason = "Real filesystem fixture assertions intentionally panic."
)]

use super::super::super::super::super::parent_paths;
use super::super::super::super::{
    MetadataStamp, NamedFence, NativeExclusion, ParentFence, Projection,
};
use super::super::{Inventory, SyncEvent, SyncScope, synchronize_raw};
use super::*;
use std::{
    fs::OpenOptions,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
};

fn parents(path: &Path) -> Vec<ParentFence> {
    parent_paths(path)
        .unwrap()
        .into_iter()
        .map(|path| ParentFence {
            stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap(),
            path,
        })
        .collect()
}

struct Fixture {
    root: PathBuf,
    worker: Worker,
    targets: BTreeMap<PathBuf, Target>,
    scopes: Vec<SyncScope>,
    candidates: BTreeSet<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "scoped-raw-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let lock_path = root.join("coordination");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        lock.lock().unwrap();
        let stamp = MetadataStamp::checked(&lock.metadata().unwrap()).unwrap();
        let owner = stamp.owner;
        let names = vec![
            NamedFence {
                path: root.clone(),
                stamp: MetadataStamp::checked(&std::fs::metadata(&root).unwrap()).unwrap(),
                policy: FencePolicy::NamespaceDirectory { owner },
                descriptor: None,
                parents: parents(&root),
            },
            NamedFence {
                path: lock_path.clone(),
                stamp,
                policy: FencePolicy::NamespaceCoordination { owner },
                descriptor: Some(0),
                parents: parents(&lock_path),
            },
        ];
        let mut targets = BTreeMap::new();
        let mut reads = Vec::new();
        let mut candidates = BTreeSet::new();
        for name in ["a.idx", "b.idx", "source"] {
            let path = root.join(name);
            let bytes = format!("actual {name}").into_bytes();
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut file, &bytes).unwrap();
            let stamp = MetadataStamp::checked(&file.metadata().unwrap()).unwrap();
            reads.push(ExactRead {
                path: path.clone(),
                expected: Some(bytes.clone()),
                identity: Some(stamp.identity),
                metadata: Some(stamp),
                policy: FencePolicy::Payload { owner },
                owner,
                parents: parents(&path),
            });
            if name != "source" {
                candidates.insert(path.clone());
                targets.insert(
                    path,
                    Target {
                        root: root.clone(),
                        owner,
                        protected: false,
                        expected: Some(bytes),
                    },
                );
            }
        }
        Self {
            scopes: vec![SyncScope {
                path: root.clone(),
                owner,
                protected: false,
            }],
            worker: Worker {
                projection: Projection {
                    exclusions: vec![NativeExclusion { file: lock }].into(),
                    names,
                    preimages: reads,
                    final_check: None,
                    directories: None,
                    pairs: Vec::new(),
                },
                faults: Vec::new(),
                gates: Vec::new(),
            },
            root,
            targets,
            candidates,
        }
    }

    fn synchronize(&mut self) -> Result<(), NativeEffectFailure> {
        self.synchronize_with_events(None)
    }

    fn synchronize_with_events(
        &mut self,
        completed_syncs: Option<&mpsc::Sender<SyncEvent>>,
    ) -> Result<(), NativeEffectFailure> {
        synchronize_raw(
            Inventory {
                scopes: &self.scopes,
                targets: std::mem::take(&mut self.targets),
                original_directories: &[],
                completed_syncs,
            },
            &mut self.worker,
            &self.candidates,
        )
    }

    fn gate(&mut self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, receive) = mpsc::channel();
        let (release, released) = mpsc::channel();
        self.worker
            .gates
            .push(super::super::super::super::TestGate {
                phase: TestGatePhase::AfterSourceSync,
                arrived,
                release: released,
            });
        (receive, release)
    }

    fn finish(self) {
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn actual_scoped_output_sync_preserves_complete_inventory() {
    let mut fixture = Fixture::new();
    fixture.synchronize().unwrap();
    fixture.worker.refresh(&[]).unwrap();
    fixture.finish();
}

#[test]
fn unrelated_output_body_change_refuses_final_whole_descriptor_check() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("a.idx");
    let (first, first_release) = fixture.gate();
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        first.recv().unwrap();
        first_release.send(()).unwrap();
        arrived.recv().unwrap();
        std::fs::write(path, b"corrupted body").unwrap();
        release.send(()).unwrap();
    });
    assert!(
        matches!(fixture.synchronize(), Err(NativeEffectFailure::Io(error))
        if error.to_string() == "sealed artifact body changed")
    );
    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn consumed_payload_body_remains_current_during_other_output_sync() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("source");
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::write(path, b"changed source").unwrap();
        release.send(()).unwrap();
    });
    assert!(fixture.synchronize().is_err());
    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn replaced_eligible_output_inode_refuses_fresh_receipt() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("b.idx");
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::rename(&path, path.with_extension("old")).unwrap();
        std::fs::write(path, b"actual b.idx").unwrap();
        release.send(()).unwrap();
    });
    assert!(fixture.synchronize().is_err());
    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn actual_scoped_syscall_failure_is_never_success() {
    let mut fixture = Fixture::new();
    fixture.worker.faults.push(EffectFault::BeforeFileSync);
    assert!(fixture.synchronize().is_err());
    fixture.finish();
}

#[test]
fn current_output_body_change_refuses_after_actual_sync() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("a.idx");
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::write(path, b"changed current target").unwrap();
        release.send(()).unwrap();
    });
    assert!(fixture.synchronize().is_err());
    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn consumed_absence_remains_current_during_output_sync() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("consumed-absence");
    let owner = fixture.scopes[0].owner;
    fixture.worker.projection.preimages.push(ExactRead {
        path: path.clone(),
        expected: None,
        identity: None,
        metadata: None,
        policy: FencePolicy::Payload { owner },
        owner,
        parents: parents(&path),
    });
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::write(path, b"new absent input").unwrap();
        release.send(()).unwrap();
    });
    assert!(fixture.synchronize().is_err());
    mutation.join().unwrap();
    fixture.finish();
}

struct TestClock(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::store::Clock for TestClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + self.monotonic()
    }

    fn monotonic(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.load(Ordering::SeqCst) as u64)
    }
}

#[test]
fn deadline_change_at_actual_sync_handoff_refuses() {
    let mut fixture = Fixture::new();
    let clock = Arc::new(AtomicUsize::new(0));
    fixture.worker.projection.final_check =
        Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&clock))),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        clock.store(10, Ordering::SeqCst);
        release.send(()).unwrap();
    });
    assert!(matches!(
        fixture.synchronize(),
        Err(NativeEffectFailure::Rejected(_))
    ));
    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn mismatched_closed_output_receipts_refuse_real_synchronization() {
    for mismatch in 0..3 {
        let mut fixture = Fixture::new();
        let target = fixture
            .targets
            .get_mut(&fixture.root.join("a.idx"))
            .unwrap();
        match mismatch {
            0 => target.owner = target.owner.saturating_add(1),
            1 => target.root = fixture.root.join("unretained-root"),
            _ => target.expected = Some(b"different expected bytes".to_vec()),
        }
        assert!(fixture.synchronize().is_err());
        fixture.finish();
    }
}

#[test]
fn actual_exclusion_survives_scoped_durability_handoff() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join("coordination");
    let (arrived, release) = fixture.gate();
    let (completed, completion) = mpsc::channel();
    let observer = std::thread::spawn(move || {
        arrived.recv().unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        release.send(()).unwrap();
        completion.recv().unwrap();
        contender.try_lock().unwrap();
    });
    fixture.synchronize().unwrap();
    fixture.finish();
    completed.send(()).unwrap();
    observer.join().unwrap();
}

#[derive(Clone, Copy, Debug)]
enum PersistentTamper {
    Replacement,
    Symlink,
    Fifo,
    HardLink,
    WritableMode,
    Removal,
    RestoredInodeWithChangedBody,
}

impl PersistentTamper {
    fn apply(self, path: &Path) {
        match self {
            Self::Replacement => {
                std::fs::rename(path, path.with_extension("saved")).unwrap();
                std::fs::write(path, b"actual a.idx").unwrap();
            }
            Self::Symlink => {
                std::fs::remove_file(path).unwrap();
                symlink(path.with_file_name("source"), path).unwrap();
            }
            Self::Fifo => {
                std::fs::remove_file(path).unwrap();
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    path,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap();
            }
            Self::HardLink => {
                std::fs::hard_link(path, path.with_extension("linked")).unwrap();
            }
            Self::WritableMode => {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
            }
            Self::Removal => std::fs::remove_file(path).unwrap(),
            Self::RestoredInodeWithChangedBody => {
                let saved = path.with_extension("saved");
                std::fs::rename(path, &saved).unwrap();
                std::fs::write(path, b"actual a.idx").unwrap();
                std::fs::write(&saved, b"changed body on the retained inode").unwrap();
                std::fs::rename(saved, path).unwrap();
            }
        }
    }
}

#[test]
fn persistent_prior_output_tampering_refuses_complete_final_verification() {
    for tamper in [
        PersistentTamper::Replacement,
        PersistentTamper::Symlink,
        PersistentTamper::Fifo,
        PersistentTamper::HardLink,
        PersistentTamper::WritableMode,
        PersistentTamper::Removal,
        PersistentTamper::RestoredInodeWithChangedBody,
    ] {
        let mut fixture = Fixture::new();
        let prior = fixture.root.join("a.idx");
        let current = fixture.root.join("b.idx");
        let (first, first_release) = fixture.gate();
        let (later, later_release) = fixture.gate();
        let path = prior.clone();
        let mutation = std::thread::spawn(move || {
            first.recv().unwrap();
            first_release.send(()).unwrap();
            later.recv().unwrap();
            tamper.apply(&path);
            later_release.send(()).unwrap();
        });
        let (events, observed) = mpsc::channel();

        assert!(
            fixture.synchronize_with_events(Some(&events)).is_err(),
            "{tamper:?}"
        );
        mutation.join().unwrap();
        let completed: Vec<_> = observed.try_iter().collect();
        assert!(completed.contains(&SyncEvent::File(prior)), "{tamper:?}");
        assert!(completed.contains(&SyncEvent::File(current)), "{tamper:?}");
        assert!(
            completed.contains(&SyncEvent::Directory(fixture.root.clone())),
            "{tamper:?}"
        );

        // Both actual file syncs and directory durability finish, but the
        // persistent fault cannot become a successful final acknowledgment.
        fixture.finish();
    }
}

#[test]
fn unclassified_or_conflicting_output_remains_fresh_at_other_sync() {
    for conflicting in [false, true] {
        let mut fixture = Fixture::new();
        let prior = fixture.root.join("a.idx");
        let current = fixture.root.join("b.idx");
        if conflicting {
            let read = fixture
                .worker
                .projection
                .preimages
                .iter()
                .find(|read| read.path == prior)
                .unwrap();
            let variant = ExactRead {
                path: read.path.clone(),
                expected: read.expected.clone(),
                identity: read.identity,
                metadata: read.metadata,
                policy: FencePolicy::ProtectedRecord { owner: read.owner },
                owner: read.owner,
                parents: parents(&prior),
            };
            fixture.worker.projection.preimages.push(variant);
        } else {
            fixture.candidates.remove(&prior);
        }
        let (first, first_release) = fixture.gate();
        let (later, later_release) = fixture.gate();
        let path = prior.clone();
        let mutation = std::thread::spawn(move || {
            first.recv().unwrap();
            first_release.send(()).unwrap();
            later.recv().unwrap();
            std::fs::write(path, b"changed unclassified input").unwrap();
            later_release.send(()).unwrap();
        });
        let (events, observed) = mpsc::channel();

        assert!(fixture.synchronize_with_events(Some(&events)).is_err());
        mutation.join().unwrap();
        let completed: Vec<_> = observed.try_iter().collect();
        assert_eq!(completed, vec![SyncEvent::File(prior)]);
        assert!(!completed.contains(&SyncEvent::File(current)));

        fixture.finish();
    }
}

#[test]
fn changed_next_target_body_refuses_before_its_actual_sync() {
    let mut fixture = Fixture::new();
    let prior = fixture.root.join("a.idx");
    let current = fixture.root.join("b.idx");
    let path = current.clone();
    let (arrived, release) = fixture.gate();
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        std::fs::write(path, b"changed next target").unwrap();
        release.send(()).unwrap();
    });
    let (events, observed) = mpsc::channel();

    assert!(
        matches!(fixture.synchronize_with_events(Some(&events)), Err(NativeEffectFailure::Io(error))
        if error.to_string() == "sealed artifact body changed")
    );
    mutation.join().unwrap();
    let completed: Vec<_> = observed.try_iter().collect();
    assert_eq!(completed, vec![SyncEvent::File(prior)]);
    assert!(!completed.contains(&SyncEvent::File(current)));

    fixture.finish();
}

fn raw_gate(fixture: &mut Fixture, phase: TestGatePhase) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (arrived, receive) = mpsc::channel();
    let (release, released) = mpsc::channel();
    fixture
        .worker
        .gates
        .push(super::super::super::super::TestGate {
            phase,
            arrived,
            release: released,
        });
    (receive, release)
}

#[derive(Clone, Copy, Debug)]
enum PreparationFault {
    Source,
    Absence,
    ProtectedControl,
    TargetBody,
    TargetMode,
    TargetReplacement,
}

#[test]
fn prepared_raw_handoff_faults_refuse_before_sync_syscall_entry() {
    for fault in [
        PreparationFault::Source,
        PreparationFault::Absence,
        PreparationFault::ProtectedControl,
        PreparationFault::TargetBody,
        PreparationFault::TargetMode,
        PreparationFault::TargetReplacement,
    ] {
        let mut fixture = Fixture::new();
        let path = match fault {
            PreparationFault::Source | PreparationFault::ProtectedControl => {
                fixture.root.join("source")
            }
            PreparationFault::Absence => fixture.root.join("absent-input"),
            _ => fixture.root.join("a.idx"),
        };
        if matches!(fault, PreparationFault::Absence) {
            let owner = fixture.scopes[0].owner;
            fixture.worker.projection.preimages.push(ExactRead {
                path: path.clone(),
                expected: None,
                identity: None,
                metadata: None,
                policy: FencePolicy::Payload { owner },
                owner,
                parents: parents(&path),
            });
        }
        if matches!(fault, PreparationFault::ProtectedControl) {
            let read = fixture
                .worker
                .projection
                .preimages
                .iter_mut()
                .find(|read| read.path == path)
                .unwrap();
            read.policy = FencePolicy::ProtectedRecord { owner: read.owner };
        }
        let (arrived, release) = raw_gate(&mut fixture, TestGatePhase::BeforeRawSyncRefresh);
        let mutation = std::thread::spawn(move || {
            arrived.recv().unwrap();
            match fault {
                PreparationFault::TargetMode => {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap()
                }
                PreparationFault::TargetReplacement => {
                    std::fs::rename(&path, path.with_extension("saved")).unwrap();
                    std::fs::write(path, b"actual a.idx").unwrap();
                }
                _ => std::fs::write(path, b"changed prepared dependency").unwrap(),
            }
            release.send(()).unwrap();
        });
        let before = file_sync_attempts();

        assert!(fixture.synchronize().is_err(), "{fault:?}");
        assert_eq!(file_sync_attempts(), before, "{fault:?}");

        mutation.join().unwrap();
        fixture.finish();
    }
}

#[test]
fn prepared_raw_deadline_refuses_before_sync_syscall_entry() {
    let mut fixture = Fixture::new();
    let clock = Arc::new(AtomicUsize::new(0));
    fixture.worker.projection.final_check =
        Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&clock))),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
    let (arrived, release) = raw_gate(&mut fixture, TestGatePhase::BeforeRawSyncRefresh);
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        clock.store(10, Ordering::SeqCst);
        release.send(()).unwrap();
    });
    let before = file_sync_attempts();

    assert!(matches!(
        fixture.synchronize(),
        Err(NativeEffectFailure::Rejected(_))
    ));
    assert_eq!(file_sync_attempts(), before);

    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn raw_outer_post_refresh_checks_current_after_post_body_read() {
    let mut fixture = Fixture::new();
    let clock = Arc::new(AtomicUsize::new(0));
    fixture.worker.projection.final_check =
        Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&clock))),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
    let (arrived, release) = raw_gate(&mut fixture, TestGatePhase::AfterRawSyncBody);
    let mutation = std::thread::spawn(move || {
        arrived.recv().unwrap();
        clock.store(10, Ordering::SeqCst);
        release.send(()).unwrap();
    });
    let before = file_sync_attempts();

    assert!(matches!(
        fixture.synchronize(),
        Err(NativeEffectFailure::Rejected(_))
    ));
    assert_eq!(file_sync_attempts(), before + 1);

    mutation.join().unwrap();
    fixture.finish();
}

#[test]
fn canceled_raw_waiter_retains_exclusion_through_prepared_handoff() {
    let mut fixture = Fixture::new();
    let root = fixture.root.clone();
    let (arrived, release) = raw_gate(&mut fixture, TestGatePhase::BeforeRawSyncRefresh);
    let (receipt, waiter) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = fixture.synchronize();
        assert!(result.is_ok());
        assert!(receipt.send(result).is_err());
        fixture.finish();
    });
    arrived.recv().unwrap();
    drop(waiter);
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("coordination"))
        .unwrap();

    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    release.send(()).unwrap();
    worker.join().unwrap();
    contender.try_lock().unwrap();
}
