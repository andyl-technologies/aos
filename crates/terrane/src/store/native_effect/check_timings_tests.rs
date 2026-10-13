//! Checks diagnostic parity against actual native leaves and primitive effects.
//!
//! Fixtures supply physical mechanics only; they do not qualify publication.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::{
    check_timings::{Group, Scope},
    *,
};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "native-check-timings-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn leaf(&self, name: &str) -> ExactRead {
        use std::io::Write;
        let path = self.0.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"actual whole bytes").unwrap();
        capture(&path, Some(b"actual whole bytes".to_vec()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn capture(path: &Path, expected: Option<Vec<u8>>) -> ExactRead {
    let metadata = std::fs::symlink_metadata(path).ok();
    let owner = std::fs::metadata(path.parent().unwrap()).unwrap().uid();
    ExactRead {
        path: path.to_owned(),
        expected,
        identity: metadata
            .as_ref()
            .map(|metadata| (metadata.dev(), metadata.ino())),
        metadata: metadata
            .as_ref()
            .map(|metadata| MetadataStamp::checked(metadata).unwrap()),
        policy: FencePolicy::Payload { owner },
        owner,
        parents: parent_paths(path)
            .unwrap()
            .into_iter()
            .map(|path| ParentFence {
                stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap(),
                path,
            })
            .collect(),
    }
}

fn outcome(result: io::Result<()>) -> Result<(), (io::ErrorKind, String)> {
    result.map_err(|error| (error.kind(), error.to_string()))
}

fn assert_leaf_parity(read: &ExactRead) -> Result<(), (io::ErrorKind, String)> {
    let mut outcomes = Vec::new();
    for enabled in [false, true] {
        let scope = Scope::new(enabled);
        let mut scratch = Vec::with_capacity(128);
        outcomes.push(outcome(read.check_with_scratch(&mut scratch)));
        assert_eq!(scope.calls(Group::Leaf), usize::from(enabled));
        assert_eq!(scope.calls(Group::Parents), usize::from(enabled));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    outcomes.remove(0)
}

#[test]
fn whole_body_and_absence_checks_have_identical_diagnostic_outcomes() {
    let fixture = Fixture::new();
    let mut read = fixture.leaf("whole");
    assert_leaf_parity(&read).unwrap();

    // Preserve the real descriptor stamp while requiring short, long and unequal
    // whole values. The detecting byte must catch the extra actual suffix.
    for expected in [
        b"actual whole byte".as_slice(),
        b"actual whole bytes!",
        b"unequal full bytes",
    ] {
        read.expected = Some(expected.to_vec());
        assert_eq!(
            assert_leaf_parity(&read).unwrap_err().1,
            "whole preimage changed"
        );
    }

    let absent = capture(&fixture.0.join("absent"), None);
    assert_leaf_parity(&absent).unwrap();
    std::fs::write(&absent.path, b"unexpected").unwrap();
    assert_eq!(
        assert_leaf_parity(&absent).unwrap_err().1,
        "exact read metadata changed"
    );

    std::fs::remove_file(&read.path).unwrap();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "whole preimage changed"
    );
}

#[test]
fn native_incarnation_policy_open_and_parent_refusals_are_identical() {
    let fixture = Fixture::new();
    let read = fixture.leaf("replaced");
    std::fs::rename(&read.path, fixture.0.join("previous")).unwrap();
    let replacement = fixture.leaf("replaced");
    assert_ne!(read.identity, replacement.identity);
    assert_eq!(
        read.metadata.unwrap().mode,
        replacement.metadata.unwrap().mode
    );
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "exact read metadata changed"
    );

    let read = fixture.leaf("symlink");
    std::fs::remove_file(&read.path).unwrap();
    std::os::unix::fs::symlink(fixture.0.join("previous"), &read.path).unwrap();
    let expected = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&read.path)
        .unwrap_err();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err(),
        (expected.kind(), expected.to_string())
    );

    let read = fixture.leaf("policy");
    std::fs::set_permissions(&read.path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "unsafe native physical fence"
    );

    let read = fixture.leaf("hardlink");
    std::fs::hard_link(&read.path, fixture.0.join("alias")).unwrap();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "unsafe native physical fence"
    );

    let read = fixture.leaf("directory");
    std::fs::remove_file(&read.path).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&read.path)
        .unwrap();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "unsafe native physical fence"
    );

    let parent = fixture.0.join("parent-directory");
    let old_parent = fixture.0.join("old-parent-directory");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let read = fixture.leaf("parent-directory/leaf");
    std::fs::rename(&parent, &old_parent).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    std::fs::rename(old_parent.join("leaf"), &read.path).unwrap();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "native parent incarnation changed"
    );

    let mut read = fixture.leaf("parent");
    read.parents.pop();
    assert_eq!(
        assert_leaf_parity(&read).unwrap_err().1,
        "incomplete native parent fence"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn actual_native_body_read_eio_records_attempted_work_with_diagnostics() {
    // The fixture retains the real memory leaf beneath qualifying ancestry.
    // Its unchanged regular 0600 inode must fail at unmapped address zero
    // inside the actual body read, after every payload and parent check.
    let memory = super::body_read_eio_fixture::ActualBodyReadEio::new().unwrap();
    let read = capture(memory.path(), Some(Vec::new()));
    read.policy.validate(read.metadata.unwrap()).unwrap();
    check_parents(&read.path, &read.parents, read.owner).unwrap();

    let mut outcomes = Vec::new();
    for enabled in [false, true] {
        let scope = Scope::new(enabled);
        let error = read.check().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        outcomes.push((error.kind(), error.to_string()));
        for group in [
            Group::Leaf,
            Group::Parents,
            Group::Open,
            Group::Descriptor,
            Group::BodyRead,
        ] {
            assert_eq!(scope.calls(group), usize::from(enabled));
        }
        assert_eq!(scope.calls(Group::NamedAfter), 0);
        assert_eq!(scope.calls(Group::BodyCompare), 0);
    }
    assert_eq!(outcomes[0], outcomes[1]);
    memory.finish().unwrap();
}

fn worker(preimages: Vec<ExactRead>) -> PrimitiveWorker {
    PrimitiveWorker {
        exclusions: Vec::new().into(),
        names: Vec::new(),
        preimages,
        final_check: None,
        pairs: Vec::new(),
        faults: Vec::new(),
        #[cfg(feature = "tokio")]
        gates: Vec::new(),
    }
}

#[test]
fn projection_counts_actual_rows_and_preserves_first_refusal_and_read_fault() {
    let fixture = Fixture::new();
    for enabled in [false, true] {
        let first = fixture.leaf(if enabled { "first-on" } else { "first-off" });
        let second = fixture.leaf(if enabled { "second-on" } else { "second-off" });
        let second_path = second.path.clone();
        let mut worker = worker(vec![first, second]);
        worker
            .faults
            .push(EffectFault::UnavailableRead(second_path));
        let scope = Scope::new(enabled);
        let projection = projection::Projection {
            exclusions: &worker.exclusions,
            names: &worker.names,
            preimages: &worker.preimages,
            final_check: None,
            pairs: &worker.pairs,
            faults: &worker.faults,
        };
        let failure = projection.check(None, None).unwrap_err();
        assert!(matches!(failure, NativeEffectFailure::Io(error)
            if error.to_string() == "injected retained exact read failure"));
        assert_eq!(scope.calls(Group::Preimage), if enabled { 2 } else { 0 });
        assert_eq!(scope.calls(Group::Leaf), usize::from(enabled));
        assert_eq!(scope.calls(Group::FenceAfter), 0);

        // An earlier physical mismatch must still win over the later read fault.
        std::fs::remove_file(&worker.preimages[0].path).unwrap();
        let failure = projection.check(None, None).unwrap_err();
        assert!(matches!(failure, NativeEffectFailure::Io(error)
            if error.to_string() == "whole preimage changed"));
        assert_eq!(scope.calls(Group::Preimage), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::Leaf), if enabled { 2 } else { 0 });
    }
}

#[test]
fn diagnostic_scopes_restore_outer_sinks_and_do_not_observe_disabled_work() {
    let fixture = Fixture::new();
    let read = fixture.leaf("scope");
    let outer = Scope::new(true);
    read.check().unwrap();
    {
        let disabled = Scope::new(false);
        read.check().unwrap();
        assert_eq!(disabled.calls(Group::Leaf), 0);
        assert!(disabled.summary().is_empty());
        let inner = Scope::new(true);
        read.check().unwrap();
        assert_eq!(inner.calls(Group::Leaf), 1);
        assert_eq!(outer.calls(Group::Leaf), 1);
    }
    read.check().unwrap();
    assert_eq!(outer.calls(Group::Leaf), 2);
    assert!(!outer.summary().contains("actual whole bytes"));
    assert!(
        !outer
            .summary()
            .contains(&fixture.0.to_string_lossy().into_owned())
    );
}

#[test]
fn retained_descriptor_fence_refusal_precedes_every_preimage_with_diagnostics() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let read = fixture.leaf("coordination");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&read.path)
            .unwrap();
        file.lock().unwrap();
        let stamp = MetadataStamp::checked(&file.metadata().unwrap()).unwrap();
        let mut worker = worker(vec![fixture.leaf("preimage")]);
        worker.exclusions = vec![NativeExclusion::from_held_descriptor(
            file.try_clone().unwrap(),
        )]
        .into();
        worker.names.push(NamedFence {
            path: read.path.clone(),
            stamp,
            policy: FencePolicy::NamespaceCoordination { owner: stamp.owner },
            parents: read.parents,
            descriptor: Some(0),
        });
        let scope = Scope::new(enabled);
        let projection = projection::Projection {
            exclusions: &worker.exclusions,
            names: &worker.names,
            preimages: &worker.preimages,
            final_check: None,
            pairs: &worker.pairs,
            faults: &worker.faults,
        };
        projection.check(None, None).unwrap();
        assert_eq!(scope.calls(Group::Name), if enabled { 2 } else { 0 });
        assert_eq!(scope.calls(Group::Preimage), usize::from(enabled));

        std::fs::rename(&read.path, fixture.0.join("old-coordination")).unwrap();
        fixture.leaf("coordination");
        assert!(
            matches!(projection.check(None, None), Err(NativeEffectFailure::Io(error))
            if error.to_string() == "current physical fence changed")
        );
        assert_eq!(scope.calls(Group::Name), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::Preimage), usize::from(enabled));
        drop(file);
    }
}

#[test]
fn successful_and_refused_actual_primitives_have_identical_effects() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.0.join("stage");
        let target = fixture.0.join("target");
        let scope = Scope::new(enabled);
        let mut worker = worker(Vec::new());
        worker
            .execute(
                Plan::WriteNew {
                    path: path.clone(),
                    bytes: b"fixed primitive bytes".to_vec(),
                },
                None,
            )
            .unwrap();
        worker
            .execute(Plan::SyncFile { path: path.clone() }, None)
            .unwrap();
        worker
            .execute(
                Plan::RenameNoReplace {
                    from: path.clone(),
                    to: target.clone(),
                },
                None,
            )
            .unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"fixed primitive bytes");
        assert_eq!(scope.calls(Group::Write), usize::from(enabled));
        assert_eq!(scope.calls(Group::FileSync), if enabled { 3 } else { 0 });
        assert_eq!(scope.calls(Group::RenameNoReplace), usize::from(enabled));

        worker.faults.push(EffectFault::BeforeFileSync);
        assert!(
            worker
                .execute(
                    Plan::SyncFile {
                        path: target.clone()
                    },
                    None
                )
                .is_err()
        );
        assert_eq!(scope.calls(Group::FileSync), if enabled { 3 } else { 0 });
        assert_eq!(std::fs::read(&target).unwrap(), b"fixed primitive bytes");
        worker.faults.clear();
        worker
            .execute(
                Plan::Remove {
                    path: target.clone(),
                },
                None,
            )
            .unwrap();
        assert!(!target.exists());
        // Count the actual failing syscall as well as the successful one.
        assert!(worker.execute(Plan::Remove { path: target }, None).is_err());
        assert_eq!(scope.calls(Group::Remove), if enabled { 2 } else { 0 });
    }
}

#[cfg(feature = "tokio")]
struct CountingClock {
    samples: Arc<AtomicUsize>,
    elapsed: Arc<AtomicUsize>,
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl crate::store::Clock for CountingClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + self.monotonic()
    }

    fn monotonic(&self) -> std::time::Duration {
        self.samples.fetch_add(1, Ordering::SeqCst);
        std::time::Duration::from_secs(self.elapsed.load(Ordering::SeqCst) as u64)
    }
}

#[cfg(feature = "tokio")]
#[test]
fn current_denial_remains_last_without_extra_authority_clock_samples() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let read = fixture.leaf("current");
        let samples = Arc::new(AtomicUsize::new(0));
        let mut worker = worker(vec![read]);
        worker.final_check = Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(CountingClock {
                samples: Arc::clone(&samples),
                elapsed: Arc::new(AtomicUsize::new(10)),
            }),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
        let scope = Scope::new(enabled);
        let projection = projection::Projection {
            exclusions: &worker.exclusions,
            names: &worker.names,
            preimages: &worker.preimages,
            final_check: worker.final_check.as_ref(),
            pairs: &worker.pairs,
            faults: &worker.faults,
        };
        assert!(
            matches!(projection.check(None, None), Err(NativeEffectFailure::Rejected(error))
            if matches!(error.kind(), crate::store::StoreErrorKind::Denied { verb: "test-deadline", .. }))
        );
        assert_eq!(samples.load(Ordering::SeqCst), 1);
        assert_eq!(scope.calls(Group::BodyRead), usize::from(enabled));
        assert_eq!(scope.calls(Group::FenceAfter), usize::from(enabled));
        assert_eq!(scope.calls(Group::Current), usize::from(enabled));
    }
}

#[cfg(all(feature = "tokio", feature = "send"))]
#[test]
fn current_denial_after_actual_sync_preserves_final_refusal_and_clock_samples() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let samples = Arc::new(AtomicUsize::new(0));
        let elapsed = Arc::new(AtomicUsize::new(0));
        let mut worker = worker(Vec::new());
        worker.final_check = Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(CountingClock {
                samples: Arc::clone(&samples),
                elapsed: Arc::clone(&elapsed),
            }),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        worker.gates.push(TestGate {
            phase: TestGatePhase::AfterDirectorySync,
            arrived,
            release: released,
        });
        let path = fixture.0.clone();
        let task = std::thread::spawn(move || {
            let scope = Scope::new(enabled);
            let result = worker.execute(Plan::SyncDirectory { path }, None);
            (
                result,
                scope.calls(Group::DirectorySync),
                scope.calls(Group::FinalCurrent),
            )
        });
        received
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        elapsed.store(10, Ordering::SeqCst);
        release.send(()).unwrap();
        let (result, syncs, final_checks) = task.join().unwrap();
        assert!(matches!(result, Err(NativeEffectFailure::Rejected(error))
            if matches!(error.kind(), crate::store::StoreErrorKind::Denied { verb: "test-deadline", .. })));
        assert_eq!(syncs, usize::from(enabled));
        assert_eq!(final_checks, usize::from(enabled));
        assert_eq!(samples.load(Ordering::SeqCst), 3);
    }
}

#[cfg(all(feature = "tokio", feature = "send"))]
#[test]
fn mutation_after_actual_source_sync_preserves_fresh_body_refusal() {
    for enabled in [false, true] {
        let fixture = Fixture::new();
        let read = fixture.leaf("source");
        let source = read.path.clone();
        let target = fixture.0.join("target");
        let mut worker = worker(vec![read]);
        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        worker.gates.push(TestGate {
            phase: TestGatePhase::AfterSourceSync,
            arrived,
            release: released,
        });
        let from = source.clone();
        let to = target.clone();
        let task = std::thread::spawn(move || {
            let scope = Scope::new(enabled);
            let result = worker.execute(Plan::RenameNoReplace { from, to }, None);
            (
                result,
                scope.calls(Group::BodyRead),
                scope.calls(Group::RenameNoReplace),
            )
        });
        received
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        std::fs::write(&source, b"changed whole body").unwrap();
        release.send(()).unwrap();
        let (result, reads, renames) = task.join().unwrap();
        assert!(matches!(result, Err(NativeEffectFailure::Io(error))
            if error.to_string() == "whole preimage changed"));
        assert_eq!(reads, if enabled { 3 } else { 0 });
        assert_eq!(renames, 0);
        assert!(!target.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"changed whole body");
    }
}
