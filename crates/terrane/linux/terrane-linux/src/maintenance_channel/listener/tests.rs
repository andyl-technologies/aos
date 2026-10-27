//! Exercises explicit socket retirement on the guest's original ext4 inodes.

#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    directory: PathBuf,
    roles: MaintenanceRoles,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "mc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let serve_uid = rustix::process::geteuid().as_raw();
        Self {
            directory,
            roles: MaintenanceRoles {
                serve_uid,
                gc_uid: serve_uid.checked_add(1).unwrap(),
            },
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.join("maintenance.sock")
    }

    fn bind(&self) -> MaintenanceListener {
        MaintenanceListener::bind(&self.path(), self.roles).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn inode(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn explicit_retirement_removes_original_name_and_allows_fresh_binding() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let original = inode(&fixture.path());
    // Keep the original inode alive so the filesystem cannot recycle its number.
    let retained = rustix::fs::open(fixture.path(), OFlags::PATH, Mode::empty()).unwrap();

    listener.retire().unwrap();

    assert!(!fixture.path().try_exists().unwrap());
    let replacement = fixture.bind();
    assert_ne!(inode(&fixture.path()), original);
    replacement.retire().unwrap();
    drop(retained);
}

#[test]
fn retirement_refuses_replacement_without_removing_either_inode() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let original = inode(&fixture.path());
    let moved = fixture.directory.join("retained.sock");
    fs::rename(fixture.path(), &moved).unwrap();
    fs::write(fixture.path(), b"replacement custody").unwrap();
    let replacement = inode(&fixture.path());

    assert!(listener.retire().is_err());

    assert_eq!(inode(&moved), original);
    assert_eq!(inode(&fixture.path()), replacement);
    assert_eq!(fs::read(fixture.path()).unwrap(), b"replacement custody");
}

#[test]
fn retirement_uses_retained_parent_after_ancestor_replacement() {
    let fixture = Fixture::new();
    let directory = fixture.directory.join("parent");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("maintenance.sock");
    let listener = MaintenanceListener::bind(&path, fixture.roles).unwrap();
    let original = inode(&path);
    let moved = fixture.directory.join("original-parent");
    fs::rename(&directory, &moved).unwrap();
    fs::create_dir(&directory).unwrap();
    let replacement = MaintenanceListener::bind(&path, fixture.roles).unwrap();
    let replacement_inode = inode(&path);
    assert_ne!(replacement_inode, original);

    listener.retire().unwrap();

    assert!(!moved.join("maintenance.sock").try_exists().unwrap());
    assert_eq!(inode(&path), replacement_inode);
    replacement.retire().unwrap();
}

#[test]
fn ordinary_drop_preserves_name_for_failed_startup_diagnosis() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let original = inode(&fixture.path());

    drop(listener);

    assert_eq!(inode(&fixture.path()), original);
    assert!(MaintenanceListener::bind(&fixture.path(), fixture.roles).is_err());
}

#[test]
fn retirement_refuses_newly_writable_parent_without_removing_socket() {
    let fixture = Fixture::new();
    let listener = fixture.bind();
    let original = inode(&fixture.path());
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o722)).unwrap();

    assert!(listener.retire().is_err());

    assert_eq!(inode(&fixture.path()), original);
}
