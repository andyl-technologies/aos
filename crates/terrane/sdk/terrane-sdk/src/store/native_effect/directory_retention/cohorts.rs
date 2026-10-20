//! Exercises original descriptor sharing across retained initializer cohorts.

#![allow(
    clippy::unwrap_used,
    reason = "Physical fixture assertions intentionally panic."
)]

use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> std::path::PathBuf {
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "directory-cohort-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    root
}

fn capture(path: &Path) -> NativeOpenedDirectory {
    directory(
        path,
        FencePolicy::PrivateControlDirectory {
            owner: rustix::process::geteuid().as_raw(),
        },
    )
    .unwrap()
}

#[test]
fn extended_cohorts_share_original_descriptor_but_fresh_captures_do_not() {
    let root = fixture();
    let original = capture(&root);
    let fresh = capture(&root);
    assert!(!Arc::ptr_eq(&original.file, &fresh.file));
    assert_ne!(original.file.as_raw_fd(), fresh.file.as_raw_fd());

    let directories: Directories = Arc::new(Mutex::new(vec![original].into()));
    let previous = Arc::clone(&directories.lock().unwrap());
    retain_directory(&directories, fresh).unwrap();
    let current = Arc::clone(&directories.lock().unwrap());
    assert_eq!(current.len(), 2);
    assert!(Arc::ptr_eq(&previous[0].file, &current[0].file));
    assert_eq!(previous[0].file.as_raw_fd(), current[0].file.as_raw_fd());
    assert!(!Arc::ptr_eq(&current[0].file, &current[1].file));
    previous[0].check().unwrap();
    current[0].check().unwrap();
    current[1].check().unwrap();

    let retained = Arc::downgrade(&previous[0].file);
    let mut cohorts = vec![previous, current];
    for _ in 0..3 {
        let fresh = capture(&root);
        for cohort in &cohorts {
            for receipt in cohort.iter() {
                assert!(!Arc::ptr_eq(&receipt.file, &fresh.file));
                assert_ne!(receipt.file.as_raw_fd(), fresh.file.as_raw_fd());
            }
        }
        retain_directory(&directories, fresh).unwrap();
        let next = Arc::clone(&directories.lock().unwrap());
        assert_eq!(next.len(), cohorts.last().unwrap().len() + 1);
        for cohort in &cohorts {
            assert!(Arc::ptr_eq(&cohort[0].file, &next[0].file));
            assert_eq!(cohort[0].file.as_raw_fd(), next[0].file.as_raw_fd());
            cohort[0].check().unwrap();
        }
        cohorts.push(next);
    }

    drop(directories);
    while cohorts.len() > 1 {
        cohorts.remove(0);
        assert!(retained.upgrade().is_some());
    }
    assert!(retained.upgrade().is_some());
    drop(cohorts);
    assert!(retained.upgrade().is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cohort_extension_refuses_replaced_ancestor_without_rebinding() {
    let root = fixture();
    let parent = root.join("parent");
    let child = parent.join("child");
    std::fs::create_dir(&parent).unwrap();
    std::fs::create_dir(&child).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directories: Directories = Arc::new(Mutex::new(vec![capture(&child)].into()));
    let original = Arc::clone(&directories.lock().unwrap());

    std::fs::rename(&parent, root.join("old-parent")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&child)
        .unwrap();
    let replacement = capture(&child);
    assert!(retain_directory(&directories, replacement).is_err());
    let unchanged = Arc::clone(&directories.lock().unwrap());
    assert!(Arc::ptr_eq(&original, &unchanged));
    assert!(original[0].check().is_err());

    drop(unchanged);
    drop(original);
    drop(directories);
    std::fs::remove_dir_all(root).unwrap();
}
