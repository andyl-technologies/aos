//! Exercises opened-directory incarnation checks and actual kernel retention.
//!
//! Private fixture commands test mechanics only; they grant no publication authority.

#![allow(
    clippy::unwrap_used,
    reason = "Physical fixture assertions intentionally panic."
)]

use super::super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn fixture() -> (PathBuf, File) {
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "directory-receipt-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("coordination"))
        .unwrap();
    lock.lock().unwrap();
    (root, lock)
}

fn ancestry(path: &std::path::Path) -> Vec<ParentFence> {
    parent_paths(path)
        .unwrap()
        .into_iter()
        .map(|path| ParentFence {
            stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap()).unwrap(),
            path,
        })
        .collect()
}

fn directory(path: &std::path::Path) -> NativeOpenedDirectory {
    let file = File::open(path).unwrap();
    let stamp = MetadataStamp::checked(&file.metadata().unwrap()).unwrap();
    NativeOpenedDirectory {
        file,
        path: path.to_owned(),
        stamp,
        policy: FencePolicy::PrivateControlDirectory { owner: stamp.owner },
        parents: ancestry(path),
    }
}

fn request(root: &std::path::Path, lock: &File, plan: Plan) -> NativeFsEffect {
    let stamp = MetadataStamp::checked(&lock.metadata().unwrap()).unwrap();
    let coordination = root.join("coordination");
    NativeFsEffect {
        exclusions: vec![NativeExclusion::from_held_descriptor(
            lock.try_clone().unwrap(),
        )]
        .into(),
        names: vec![NamedFence {
            parents: ancestry(&coordination),
            path: coordination,
            stamp,
            policy: FencePolicy::NamespaceCoordination { owner: stamp.owner },
            descriptor: Some(0),
        }],
        preimages: Vec::new(),
        final_check: None,
        plan,
        gates: Vec::new(),
        faults: Vec::new(),
    }
}

fn wrapped(root: &std::path::Path, operation: Plan) -> Plan {
    Plan::RetainedDirectories {
        directories: vec![directory(root)].into(),
        operation: Box::new(operation),
    }
}

#[tokio::test]
async fn wrapped_primitives_preserve_actual_fault_identity_and_bytes() {
    let (root, lock) = fixture();
    for retained in [false, true] {
        let path = root.join(format!("write-{retained}"));
        let plan = Plan::WriteNew {
            path: path.clone(),
            bytes: b"exact body".to_vec(),
        };
        let effect = request(
            &root,
            &lock,
            if retained { wrapped(&root, plan) } else { plan },
        );
        assert!(
            matches!(effect.fault_probe(), EffectFaultProbe::WriteNew(actual) if actual == path)
        );
        assert!(effect.rename_noreplace_source().is_none());
        effect.execute_tokio().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"exact body");
        let target = root.join(format!("installed-{retained}"));
        let plan = Plan::RenameNoReplace {
            from: path.clone(),
            to: target.clone(),
        };
        let effect = request(
            &root,
            &lock,
            if retained { wrapped(&root, plan) } else { plan },
        );
        assert!(
            matches!(effect.fault_probe(), EffectFaultProbe::RenameNoReplace(actual) if actual == target)
        );
        assert_eq!(effect.rename_noreplace_source(), Some(path.as_path()));
        effect.execute_tokio().await.unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(target).unwrap(), b"exact body");
    }
    drop(lock);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn nested_retention_refuses_before_actual_write() {
    let (root, lock) = fixture();
    let target = root.join("must-not-exist");
    let effect = request(
        &root,
        &lock,
        wrapped(
            &root,
            wrapped(
                &root,
                Plan::WriteNew {
                    path: target.clone(),
                    bytes: vec![1],
                },
            ),
        ),
    );
    assert!(matches!(effect.fault_probe(), EffectFaultProbe::Other));
    assert!(effect.execute_tokio().await.is_err());
    assert!(!target.exists());
    drop(lock);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn actual_directory_policy_and_parent_replacements_refuse_write() {
    enum DirectoryFault {
        NamedReplacement,
        ParentReplacement,
        UnsafeMode,
        WrongConfiguredOwner,
    }

    for fault in [
        DirectoryFault::NamedReplacement,
        DirectoryFault::ParentReplacement,
        DirectoryFault::UnsafeMode,
        DirectoryFault::WrongConfiguredOwner,
    ] {
        let (root, lock) = fixture();
        let parent = root.join("parent");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let child = parent.join("child");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&child)
            .unwrap();
        let target = root.join("must-not-exist");
        let mut receipt = directory(&child);
        match fault {
            DirectoryFault::NamedReplacement => {
                std::fs::rename(&child, parent.join("old-child")).unwrap();
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&child)
                    .unwrap();
            }
            DirectoryFault::ParentReplacement => {
                std::fs::rename(&parent, root.join("old-parent")).unwrap();
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&parent)
                    .unwrap();
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&child)
                    .unwrap();
            }
            DirectoryFault::UnsafeMode => {
                std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap()
            }
            DirectoryFault::WrongConfiguredOwner => {
                receipt.policy = FencePolicy::PrivateControlDirectory {
                    owner: receipt.stamp.owner.wrapping_add(1),
                }
            }
        }
        let effect = request(
            &root,
            &lock,
            Plan::RetainedDirectories {
                directories: vec![receipt].into(),
                operation: Box::new(Plan::WriteNew {
                    path: target.clone(),
                    bytes: vec![1],
                }),
            },
        );
        assert!(effect.execute_tokio().await.is_err());
        assert!(!target.exists());
        drop(lock);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn aborted_waiter_retains_directory_and_kernel_exclusion_through_durability() {
    for phase in [TestGatePhase::BeforeChecks, TestGatePhase::AfterRename] {
        let (root, lock) = fixture();
        let from = root.join("stage");
        let to = root.join("installed");
        std::fs::write(&from, b"durable successor").unwrap();
        std::fs::set_permissions(&from, std::fs::Permissions::from_mode(0o600)).unwrap();
        let directories: Arc<[NativeOpenedDirectory]> = vec![directory(&root)].into();
        let retained = Arc::downgrade(&directories);
        let mut effect = request(
            &root,
            &lock,
            Plan::RetainedDirectories {
                directories,
                operation: Box::new(Plan::RenameNoReplace {
                    from: from.clone(),
                    to: to.clone(),
                }),
            },
        );
        let (arrived, arrival) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        effect.gates.push(TestGate {
            phase,
            arrived,
            release: released,
        });
        let task = tokio::spawn(effect.execute_tokio());
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(30)))
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_retained_directory(&retained);
        drop(lock);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("coordination"))
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        let (acquired, receipt) = std::sync::mpsc::channel();
        let installed = to.clone();
        let worker = std::thread::spawn(move || {
            contender.lock().unwrap();
            assert_eq!(std::fs::read(&installed).unwrap(), b"durable successor");
            assert!(!from.exists());
            acquired.send(()).unwrap();
        });
        assert!(matches!(
            receipt.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.send(()).unwrap();
        receipt.recv_timeout(Duration::from_secs(30)).unwrap();
        worker.join().unwrap();
        assert!(retained.upgrade().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn queued_aborted_waiter_retains_actual_directories_and_namespace_lock() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (root, lock) = fixture();
        let target = root.join("queued-body");
        let directories: Arc<[NativeOpenedDirectory]> = vec![directory(&root)].into();
        let retained = Arc::downgrade(&directories);
        let effect = request(
            &root,
            &lock,
            Plan::RetainedDirectories {
                directories,
                operation: Box::new(Plan::WriteNew {
                    path: target.clone(),
                    bytes: b"queued durable body".to_vec(),
                }),
            },
        );
        let (occupied, occupancy) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let busy = tokio::task::spawn_blocking(move || {
            occupied.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(30)).unwrap();
        });
        occupancy.recv_timeout(Duration::from_secs(30)).unwrap();
        let mut waiter = Box::pin(effect.execute_tokio());
        poll_fn(|context| {
            assert!(matches!(waiter.as_mut().poll(context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        drop(waiter);
        assert_retained_directory(&retained);
        drop(lock);
        assert!(!target.exists());
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("coordination"))
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        let (acquired, receipt) = std::sync::mpsc::channel();
        let installed = target.clone();
        let observer = std::thread::spawn(move || {
            contender.lock().unwrap();
            assert_eq!(std::fs::read(installed).unwrap(), b"queued durable body");
            acquired.send(()).unwrap();
        });
        assert!(matches!(
            receipt.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        release.send(()).unwrap();
        busy.await.unwrap();
        receipt.recv_timeout(Duration::from_secs(30)).unwrap();
        observer.join().unwrap();
        assert!(retained.upgrade().is_none());
        std::fs::remove_dir_all(root).unwrap();
    });
}

// The transient observation is dropped before worker release; only the command
// may retain the actual opened descriptor through its remaining durability work.
fn assert_retained_directory(retained: &std::sync::Weak<[NativeOpenedDirectory]>) {
    let directories = retained.upgrade().unwrap();
    assert_eq!(directories.len(), 1);
    let opened = MetadataStamp::checked(&directories[0].file.metadata().unwrap()).unwrap();
    assert!(opened.same_incarnation(directories[0].stamp));
}
