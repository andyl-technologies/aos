//! Exercises physical-effect mechanics with actual kernel exclusions.
//!
//! These tests initialize private commands only within this module. They do
//! not mint actor authority or qualify a selected publisher or native collector.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture assertions intentionally panic."
)]

use super::*;
use std::cell::Cell;
use std::fs::OpenOptions;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};

// Deliberately Send, not Sync or Clone: the effect owns only actual descriptor
// duplicates, so no stronger associated lock contract is needed.
struct HeldLock {
    file: File,
    _not_sync: Cell<()>,
    path: PathBuf,
}

#[cfg(feature = "tokio")]
struct TestClock(Arc<AtomicUsize>);

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl crate::store::Clock for TestClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + self.monotonic()
    }

    fn monotonic(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.0.load(Ordering::SeqCst) as u64)
    }
}

fn fixture() -> (PathBuf, HeldLock) {
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "retained-effect-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("coordination"))
        .unwrap();
    file.lock().unwrap();
    let held = HeldLock {
        file,
        _not_sync: Cell::new(()),
        path: root.join("coordination"),
    };
    (root, held)
}

fn parents(path: &std::path::Path) -> Vec<ParentFence> {
    parent_paths(path)
        .unwrap()
        .into_iter()
        .map(|path| ParentFence {
            stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap(),
            path,
        })
        .collect()
}

fn effect(held: &HeldLock, plan: Plan) -> NativeFsEffect {
    NativeFsEffect {
        exclusions: vec![NativeExclusion::from_held_descriptor(
            held.file.try_clone().unwrap(),
        )]
        .into(),
        names: vec![NamedFence {
            path: held.path.clone(),
            stamp: MetadataStamp::checked(&held.file.metadata().unwrap()).unwrap(),
            policy: FencePolicy::NamespaceCoordination {
                owner: MetadataStamp::checked(&held.file.metadata().unwrap())
                    .unwrap()
                    .owner,
            },
            parents: parents(&held.path),
            descriptor: Some(0),
        }],
        preimages: Vec::new(),
        final_check: None,
        plan,
        #[cfg(feature = "tokio")]
        gates: Vec::new(),
        faults: Vec::new(),
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn dropped_waiter_keeps_actual_kernel_lock_until_physical_remove_finishes() {
    let (root, held) = fixture();
    let path = root.join("pack");
    std::fs::write(&path, b"old physical bytes").unwrap();
    let (arrived, received) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let mut request = effect(&held, Plan::Remove { path: path.clone() });
    request.gates.push(TestGate {
        phase: TestGatePhase::BeforeChecks,
        arrived,
        release: released,
    });
    let task = tokio::spawn(request.execute_tokio());
    tokio::task::spawn_blocking(move || received.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(held);

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

    // An independent OS thread and runtime contend on a separately opened
    // descriptor. It cannot be delayed by the abandoned worker's pool.
    let restored = path.clone();
    let second_runtime = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            contender.lock().unwrap();
            assert!(!path.exists());
            std::fs::write(&path, b"new reachable placement").unwrap();
            File::open(&path).unwrap().sync_all().unwrap();
            File::open(path.parent().unwrap())
                .unwrap()
                .sync_all()
                .unwrap();
        });
    });
    second_runtime.join().unwrap();
    assert_eq!(std::fs::read(restored).unwrap(), b"new reachable placement");
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[test]
fn queued_expired_check_precedes_actual_remove() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()
        .unwrap();

    runtime.block_on(async {
        let (root, held) = fixture();
        let path = root.join("pack");
        std::fs::write(&path, b"protected bytes").unwrap();

        let exact_clock = Arc::new(AtomicUsize::new(0));
        let mut request = effect(&held, Plan::Remove { path: path.clone() });
        request.final_check = Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&exact_clock))),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));

        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let busy_worker = tokio::task::spawn_blocking(move || {
            arrived.send(()).unwrap();
            released.recv().unwrap();
        });
        received
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        let mut waiter = Box::pin(request.execute_tokio());
        // The only blocking worker is occupied. Polling submits the actual
        // effect and proves it cannot execute until the queue is released.
        poll_fn(|context| {
            assert!(matches!(waiter.as_mut().poll(context), Poll::Pending));
            Poll::Ready(())
        })
        .await;

        exact_clock.store(10, Ordering::SeqCst);
        release.send(()).unwrap();
        let failure = waiter.await.unwrap_err();
        busy_worker.await.unwrap();

        assert!(matches!(failure, NativeEffectFailure::Rejected(failure)
            if matches!(failure.kind(), crate::store::StoreErrorKind::Denied { verb: "test-deadline", .. })));
        assert_eq!(std::fs::read(path).unwrap(), b"protected bytes");

        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn all_fixed_variants_complete() {
    use std::os::unix::fs::PermissionsExt;
    let (root, held) = fixture();
    let path = root.join("new");
    for plan in [
        Plan::CreateDirectoryNew {
            path: root.join("new-parent"),
        },
        Plan::WriteNew {
            path: path.clone(),
            bytes: b"bytes".to_vec(),
        },
        Plan::SyncFile { path: path.clone() },
        Plan::Permissions {
            path: path.clone(),
            permissions: std::fs::Permissions::from_mode(0o600),
        },
        Plan::SyncDirectory { path: root.clone() },
        Plan::Remove { path: path.clone() },
    ] {
        effect(&held, plan).execute_inline().unwrap();
    }
    assert!(!path.exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn whole_preimage_mismatch_precedes_actual_remove() {
    let (root, held) = fixture();
    let path = root.join("pack");
    std::fs::write(&path, b"changed").unwrap();
    let mut request = effect(&held, Plan::Remove { path: path.clone() });
    use std::os::unix::fs::MetadataExt;
    let observed = std::fs::symlink_metadata(&path).unwrap();
    request.preimages.push(ExactRead {
        path: path.clone(),
        expected: Some(b"original".to_vec()),
        identity: Some((observed.dev(), observed.ino())),
        metadata: Some(MetadataStamp::checked(&observed).unwrap()),
        policy: FencePolicy::Payload {
            owner: observed.uid(),
        },
        owner: observed.uid(),
        parents: parents(&path),
    });
    assert!(request.execute_inline().is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"changed");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn physical_replacement_with_equal_bytes_precedes_actual_remove() {
    use std::os::unix::fs::MetadataExt;
    let (root, held) = fixture();
    let path = root.join("pack");
    std::fs::write(&path, b"same bytes").unwrap();
    let observed = std::fs::symlink_metadata(&path).unwrap();
    let mut request = effect(&held, Plan::Remove { path: path.clone() });
    request.preimages.push(ExactRead {
        path: path.clone(),
        expected: Some(b"same bytes".to_vec()),
        identity: Some((observed.dev(), observed.ino())),
        metadata: Some(MetadataStamp::checked(&observed).unwrap()),
        policy: FencePolicy::Payload {
            owner: observed.uid(),
        },
        owner: observed.uid(),
        parents: parents(&path),
    });
    std::fs::rename(&path, root.join("old-incarnation")).unwrap();
    std::fs::write(&path, b"same bytes").unwrap();
    assert!(request.execute_inline().is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"same bytes");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn replaced_coordination_rejects_the_old_retained_descriptor() {
    let (root, held) = fixture();
    let path = root.join("pack");
    std::fs::write(&path, b"protected").unwrap();
    let request = effect(&held, Plan::Remove { path: path.clone() });
    std::fs::rename(&held.path, root.join("old-coordination")).unwrap();
    std::fs::write(&held.path, b"new namespace").unwrap();
    assert!(request.execute_inline().is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"protected");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn atomic_no_replace_sync_failure_leaves_one_protected_name() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (root, held) = fixture();
    let from = root.join("protected-stage");
    let to = root.join("selected-slot");
    std::fs::write(&from, b"canonical protected bytes").unwrap();
    std::fs::set_permissions(&from, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut request = effect(
        &held,
        Plan::RenameNoReplace {
            from: from.clone(),
            to: to.clone(),
        },
    );
    let observed = MetadataStamp::checked(&std::fs::symlink_metadata(&from).unwrap()).unwrap();
    request.names.push(NamedFence {
        path: from.clone(),
        stamp: observed,
        policy: FencePolicy::ProtectedRecord {
            owner: observed.owner,
        },
        parents: parents(&from),
        descriptor: None,
    });
    let error = request
        .inject_test_faults(vec![EffectFault::BeforeDirectorySync])
        .execute_inline()
        .unwrap_err();

    assert!(
        matches!(error, NativeEffectFailure::Io(error) if error.kind() == io::ErrorKind::Other)
    );
    assert!(!from.exists());
    let installed = std::fs::symlink_metadata(&to).unwrap();
    assert_eq!(installed.nlink(), 1);
    assert_eq!(installed.mode() & 0o777, 0o600);
    FencePolicy::ProtectedRecord {
        owner: observed.owner,
    }
    .validate(MetadataStamp::checked(&installed).unwrap())
    .unwrap();
    assert_eq!(std::fs::read(to).unwrap(), b"canonical protected bytes");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn atomic_no_replace_collision_preserves_both_single_link_incarnations() {
    use std::os::unix::fs::MetadataExt;
    let (root, held) = fixture();
    let from = root.join("stage");
    let to = root.join("selected-slot");
    std::fs::write(&from, b"new").unwrap();
    std::fs::write(&to, b"old").unwrap();
    let error = effect(
        &held,
        Plan::RenameNoReplace {
            from: from.clone(),
            to: to.clone(),
        },
    )
    .execute_inline()
    .unwrap_err();
    assert!(
        matches!(error, NativeEffectFailure::Io(error) if error.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(std::fs::read(&from).unwrap(), b"new");
    assert_eq!(std::fs::read(&to).unwrap(), b"old");
    assert_eq!(std::fs::symlink_metadata(&from).unwrap().nlink(), 1);
    assert_eq!(std::fs::symlink_metadata(&to).unwrap().nlink(), 1);
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn private_control_directory_and_record_have_positive_physical_effect() {
    use std::os::unix::fs::PermissionsExt;
    let (root, held) = fixture();
    let control = root.join("control");
    std::fs::create_dir(&control).unwrap();
    std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = control.join("record");
    std::fs::write(&path, b"protected").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut request = effect(&held, Plan::Remove { path: path.clone() });
    for (path, policy) in [
        (
            root.clone(),
            FencePolicy::NamespaceDirectory {
                owner: MetadataStamp::checked(&std::fs::symlink_metadata(&root).unwrap())
                    .unwrap()
                    .owner,
            },
        ),
        (
            control.clone(),
            FencePolicy::PrivateControlDirectory {
                owner: MetadataStamp::checked(&std::fs::symlink_metadata(&control).unwrap())
                    .unwrap()
                    .owner,
            },
        ),
        (
            path.clone(),
            FencePolicy::ProtectedRecord {
                owner: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap())
                    .unwrap()
                    .owner,
            },
        ),
    ] {
        let stamp = MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap();
        request.names.push(NamedFence {
            parents: parents(&path),
            path,
            stamp,
            policy,
            descriptor: None,
        });
    }
    request.execute_inline().unwrap();
    assert!(!path.exists());
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_record_mode_and_link_policy_precede_removal() {
    use std::os::unix::fs::PermissionsExt;
    for add_alias in [false, true] {
        let (root, held) = fixture();
        let path = root.join("protected");
        std::fs::write(&path, b"protected").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if add_alias {
            std::fs::hard_link(&path, root.join("alias")).unwrap();
        } else {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // Capture even the changed inode/bytes: semantic policy must refuse
        // regardless of equality to the recorded metadata shape.
        let stamp = MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap();
        let mut request = effect(&held, Plan::Remove { path: path.clone() });
        request.names.push(NamedFence {
            path: path.clone(),
            stamp,
            policy: FencePolicy::ProtectedRecord { owner: stamp.owner },
            parents: parents(&path),
            descriptor: None,
        });
        assert!(request.execute_inline().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"protected");
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn replaced_parent_rejects_equal_bytes_and_preserved_file_inode() {
    use std::os::unix::fs::MetadataExt;
    let (root, held) = fixture();
    let parent = root.join("payload-parent");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("pack");
    std::fs::write(&path, b"same bytes").unwrap();
    let observed = std::fs::symlink_metadata(&path).unwrap();
    let mut request = effect(&held, Plan::Remove { path: path.clone() });
    request.preimages.push(ExactRead {
        path: path.clone(),
        expected: Some(b"same bytes".to_vec()),
        identity: Some((observed.dev(), observed.ino())),
        metadata: Some(MetadataStamp::checked(&observed).unwrap()),
        policy: FencePolicy::Payload {
            owner: observed.uid(),
        },
        owner: observed.uid(),
        parents: parents(&path),
    });
    let old_parent = root.join("old-parent");
    std::fs::rename(&parent, &old_parent).unwrap();
    std::fs::create_dir(&parent).unwrap();
    // Move the original file back: a raw file identity check would pass.
    std::fs::rename(old_parent.join("pack"), &path).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().ino(),
        observed.ino()
    );
    assert!(request.execute_inline().is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"same bytes");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn write_new_is_private_under_permissive_umask() {
    use std::os::unix::fs::PermissionsExt;
    const CHILD: &str = "TERRANE_NATIVE_EFFECT_UMASK_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let old = rustix::process::umask(rustix::fs::Mode::empty());
        let (root, held) = fixture();
        let path = root.join("private-stage");
        effect(
            &held,
            Plan::WriteNew {
                path: path.clone(),
                bytes: b"private".to_vec(),
            },
        )
        .execute_inline()
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        rustix::process::umask(old);
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
        return;
    }

    // The test binary is itself built from source. Isolate process-global
    // umask in this child rather than altering other parallel test fixtures.
    let name = concat!(
        module_path!(),
        "::write_new_is_private_under_permissive_umask"
    );
    let (_, test) = name.split_once("::").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
fn replacing_rename_installs_actual_bytes_before_failed_directory_sync() {
    let (root, held) = fixture();
    let from = root.join("stage");
    let to = root.join("cache");
    std::fs::write(&from, b"successor").unwrap();
    std::fs::write(&to, b"previous").unwrap();
    let error = effect(
        &held,
        Plan::Rename {
            from: from.clone(),
            to: to.clone(),
        },
    )
    .inject_test_faults(vec![EffectFault::BeforeDirectorySync])
    .execute_inline()
    .unwrap_err();
    assert!(
        matches!(error, NativeEffectFailure::Io(error) if error.kind() == io::ErrorKind::Other)
    );
    assert!(!from.exists());
    assert_eq!(std::fs::read(to).unwrap(), b"successor");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn restored_named_inode_refuses_permissions_on_an_opened_decoy() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (root, held) = fixture();
    let path = root.join("protected-record");
    let original = root.join("saved-original");
    let decoy = root.join("decoy");
    std::fs::write(&path, b"expected original").unwrap();
    std::fs::write(&decoy, b"unrelated decoy").unwrap();
    for path in [&path, &decoy] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let expected = std::fs::symlink_metadata(&path).unwrap();
    let decoy_identity = std::fs::symlink_metadata(&decoy).unwrap().ino();
    let mut request = effect(
        &held,
        Plan::Permissions {
            path: path.clone(),
            permissions: std::fs::Permissions::from_mode(0o400),
        },
    );
    request.preimages.push(ExactRead {
        path: path.clone(),
        expected: Some(b"expected original".to_vec()),
        identity: Some((expected.dev(), expected.ino())),
        metadata: Some(MetadataStamp::checked(&expected).unwrap()),
        policy: FencePolicy::ProtectedRecord {
            owner: expected.uid(),
        },
        owner: expected.uid(),
        parents: parents(&path),
    });
    let (before_open, reached_before_open) = std::sync::mpsc::channel();
    let (open, permit_open) = std::sync::mpsc::channel();
    let (after_open, reached_after_open) = std::sync::mpsc::channel();
    let (check, permit_check) = std::sync::mpsc::channel();
    request.gates.push(TestGate {
        phase: TestGatePhase::BeforeOpen,
        arrived: before_open,
        release: permit_open,
    });
    request.gates.push(TestGate {
        phase: TestGatePhase::AfterOpen,
        arrived: after_open,
        release: permit_check,
    });
    let task = tokio::spawn(request.execute_tokio());
    tokio::task::spawn_blocking(move || {
        reached_before_open.recv_timeout(std::time::Duration::from_secs(5))
    })
    .await
    .unwrap()
    .unwrap();
    std::fs::rename(&path, &original).unwrap();
    std::fs::rename(&decoy, &path).unwrap();
    open.send(()).unwrap();
    tokio::task::spawn_blocking(move || {
        reached_after_open.recv_timeout(std::time::Duration::from_secs(5))
    })
    .await
    .unwrap()
    .unwrap();
    std::fs::rename(&path, &decoy).unwrap();
    std::fs::rename(&original, &path).unwrap();
    check.send(()).unwrap();
    let outcome = task.await.unwrap();

    // The full expected projection is restored and valid. Mutation of the
    // independently opened decoy is the failure a descriptor check prevents.
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().ino(),
        expected.ino()
    );
    assert_eq!(
        std::fs::symlink_metadata(&decoy).unwrap().ino(),
        decoy_identity
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"expected original");
    assert_eq!(std::fs::read(&decoy).unwrap(), b"unrelated decoy");
    assert_eq!(
        std::fs::symlink_metadata(&decoy)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(matches!(outcome, Err(NativeEffectFailure::Io(_))));
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn changed_whole_control_after_actual_source_sync_rejects_final_rename() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for replace in [false, true] {
        let (root, held) = fixture();
        let from = root.join("stage");
        let to = root.join("selected-slot");
        let control = root.join("used-registration");
        std::fs::write(&from, b"successor").unwrap();
        std::fs::write(&control, b"original checked control").unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o600)).unwrap();
        if replace {
            std::fs::write(&to, b"previous").unwrap();
        }
        let plan = if replace {
            Plan::Rename {
                from: from.clone(),
                to: to.clone(),
            }
        } else {
            Plan::RenameNoReplace {
                from: from.clone(),
                to: to.clone(),
            }
        };
        let mut request = effect(&held, plan);
        let metadata = std::fs::symlink_metadata(&control).unwrap();
        request.preimages.push(ExactRead {
            path: control.clone(),
            expected: Some(b"original checked control".to_vec()),
            identity: Some((metadata.dev(), metadata.ino())),
            metadata: Some(MetadataStamp::checked(&metadata).unwrap()),
            policy: FencePolicy::ProtectedRecord {
                owner: metadata.uid(),
            },
            owner: metadata.uid(),
            parents: parents(&control),
        });
        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        request.gates.push(TestGate {
            phase: TestGatePhase::AfterSourceSync,
            arrived,
            release: released,
        });
        let task = tokio::spawn(request.execute_tokio());
        tokio::task::spawn_blocking(move || {
            received.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .unwrap();
        // Simulate changed consumed evidence at the actual worker boundary,
        // preserving its inode/mode; a metadata-only recheck would accept it.
        std::fs::write(&control, b"different actual control").unwrap();
        release.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(std::fs::read(&from).unwrap(), b"successor");
        if replace {
            assert_eq!(std::fs::read(&to).unwrap(), b"previous");
        } else {
            assert!(!to.exists());
        }
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn cancelled_atomic_rename_keeps_kernel_exclusion_through_directory_sync() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (root, held) = fixture();
    let from = root.join("stage");
    let to = root.join("selected-slot");
    std::fs::write(&from, b"protected successor").unwrap();
    std::fs::set_permissions(&from, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut request = effect(
        &held,
        Plan::RenameNoReplace {
            from: from.clone(),
            to: to.clone(),
        },
    );
    let (arrived, received) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    request.gates.push(TestGate {
        phase: TestGatePhase::AfterRename,
        arrived,
        release: released,
    });
    let task = tokio::spawn(request.execute_tokio());
    tokio::task::spawn_blocking(move || received.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(held);
    assert!(!from.exists());
    let metadata = std::fs::symlink_metadata(&to).unwrap();
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
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
    let installed = to.clone();
    let second_runtime = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            contender.lock().unwrap();
            assert_eq!(std::fs::read(installed).unwrap(), b"protected successor");
        });
    });
    second_runtime.join().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[test]
fn unavailable_runtime_refuses_before_actual_remove() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let (root, held) = fixture();
    let path = root.join("pack");
    std::fs::write(&path, b"protected").unwrap();
    let mut request = Box::pin(effect(&held, Plan::Remove { path: path.clone() }).execute_tokio());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        request.as_mut().poll(&mut context),
        Poll::Ready(Err(NativeEffectFailure::Io(_)))
    ));
    assert_eq!(std::fs::read(path).unwrap(), b"protected");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn actual_tokio_binding_retains_its_guard_and_executes_the_fixed_effect() {
    use crate::store::{LocalFs, TokioLocalFs};
    use std::os::unix::fs::PermissionsExt;
    let (root, fixture_held) = fixture();
    let coordination = root.join("tokio-coordination");
    let path = root.join("private-stage");
    let binding = TokioLocalFs;
    let held = binding.lock_exclusive(&coordination).await.unwrap();
    let stamp = MetadataStamp::checked(&std::fs::symlink_metadata(&coordination).unwrap()).unwrap();
    let request = NativeFsEffect {
        exclusions: vec![binding.retain_native_exclusion(&held).unwrap()].into(),
        names: vec![NamedFence {
            path: coordination.clone(),
            stamp,
            policy: FencePolicy::NamespaceCoordination { owner: stamp.owner },
            parents: parents(&coordination),
            descriptor: Some(0),
        }],
        preimages: Vec::new(),
        final_check: None,
        plan: Plan::WriteNew {
            path: path.clone(),
            bytes: b"actual binding".to_vec(),
        },
        faults: Vec::new(),
        gates: Vec::new(),
    };
    binding.execute_retained_effect(request).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"actual binding");
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(held);
    drop(fixture_held);
    std::fs::remove_dir_all(root).unwrap();
}
