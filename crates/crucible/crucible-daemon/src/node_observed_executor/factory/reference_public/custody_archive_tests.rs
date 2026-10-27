//! Exercises actual private files independently of semantic release authority.

// crucible-lint: allow panic-shortcut -- Private file fixture assertions intentionally fail on invariant drift.
// crucible-lint: allow rust-allow -- These test-only file fixture assertions deliberately panic.
#![allow(clippy::unwrap_used)]

use std::{
    fs::{self, DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    directory: PathBuf,
    attempt: OriginalArchiveAttempt,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "private-original-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let directory_file = File::from(
            rustix::fs::open(
                &directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
        );
        // This private fixture tests the sink only. It supplies no peer, world,
        // native seal, queue receipt or ordinary semantic release authority.
        Self {
            directory,
            attempt: OriginalArchiveAttempt {
                identity: crucible_node_format::U64::new(7),
                source: None,
                bytes: b"complete unchanged private originals\n".to_vec(),
                directory: directory_file,
                file: None,
                attempted: false,
                complete: false,
            },
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.join("resolved-original-custody-7.custody")
    }

    fn uncertain_prefix(&mut self, bytes: &[u8]) -> u64 {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path())
            .unwrap();
        file.write_all(bytes).unwrap();
        let inode = file.metadata().unwrap().ino();
        self.attempt.file = Some(file);
        self.attempt.attempted = true;
        inode
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn exact_prefix_retry_keeps_the_same_original_file_and_bytes() {
    let mut fixture = Fixture::new();
    let inode = fixture.uncertain_prefix(b"complete unchanged");

    assert!(fixture.attempt.poll().unwrap());

    assert_eq!(
        fixture
            .attempt
            .file
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), fixture.attempt.bytes);
    assert!(
        fixture
            .attempt
            .complete_for(crucible_node_format::U64::new(7))
    );
    assert!(
        !fixture
            .attempt
            .complete_for(crucible_node_format::U64::new(8))
    );
}

#[test]
fn foreign_prefix_refuses_without_replacing_or_truncating_the_original() {
    let mut fixture = Fixture::new();
    let inode = fixture.uncertain_prefix(b"foreign private prefix");

    assert!(fixture.attempt.poll().is_err());

    assert_eq!(
        fixture
            .attempt
            .file
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), b"foreign private prefix");
    assert!(
        !fixture
            .attempt
            .complete_for(crucible_node_format::U64::new(7))
    );
}

#[test]
fn occupied_symlink_cannot_be_followed_or_renewed_as_another_attempt() {
    let mut fixture = Fixture::new();
    let foreign = fixture.directory.join("foreign");
    fs::write(&foreign, b"foreign unchanged").unwrap();
    symlink(&foreign, fixture.path()).unwrap();

    assert!(fixture.attempt.poll().is_err());
    fs::remove_file(fixture.path()).unwrap();
    assert!(fixture.attempt.poll().is_err());

    assert!(fixture.attempt.attempted);
    assert!(fixture.attempt.file.is_none());
    assert_eq!(fs::read(&foreign).unwrap(), b"foreign unchanged");
    assert!(!fixture.path().exists());
}

#[test]
fn changed_link_count_holds_the_original_descriptor_and_archive() {
    let mut fixture = Fixture::new();
    let inode = fixture.uncertain_prefix(b"complete unchanged");
    fs::hard_link(fixture.path(), fixture.directory.join("another-link")).unwrap();

    assert!(fixture.attempt.poll().is_err());

    assert_eq!(
        fixture
            .attempt
            .file
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), b"complete unchanged");
    assert!(
        !fixture
            .attempt
            .complete_for(crucible_node_format::U64::new(7))
    );
}

#[test]
fn changed_directory_permissions_refuse_before_original_write() {
    let mut fixture = Fixture::new();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(fixture.attempt.poll().is_err());

    assert!(!fixture.attempt.attempted);
    assert!(fixture.attempt.file.is_none());
    assert!(!fixture.path().exists());
}

#[test]
fn replaced_directory_entry_cannot_acknowledge_the_original_inode() {
    let mut fixture = Fixture::new();
    let inode = fixture.uncertain_prefix(b"complete unchanged");
    fs::rename(fixture.path(), fixture.directory.join("original-held")).unwrap();
    fs::write(fixture.path(), b"replacement").unwrap();

    assert!(fixture.attempt.poll().is_err());

    assert_eq!(
        fixture
            .attempt
            .file
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), b"replacement");
    assert_eq!(
        fs::read(fixture.directory.join("original-held")).unwrap(),
        b"complete unchanged"
    );
    assert!(
        !fixture
            .attempt
            .complete_for(crucible_node_format::U64::new(7))
    );
}

#[test]
fn exact_source_block_retry_preserves_file_and_descriptor_after_source_path_loss() {
    let mut fixture = Fixture::new();
    let source_path = fixture.directory.join("original-source");
    let source = std::rc::Rc::new(
        super::super::super::package::OriginalPackageSourceCustody::fixture_for_sink(
            &source_path,
            b"complete original executable and source fixture bytes\n",
        ),
    );
    fixture.attempt.source = Some(source.clone());
    let mut expected = fixture.attempt.bytes.clone();
    source.write_originals(&mut expected).unwrap();
    let inode = fixture.uncertain_prefix(&expected[..expected.len() - 3]);
    fs::remove_file(&source_path).unwrap();

    assert!(fixture.attempt.poll().unwrap());

    assert!(!source_path.exists());
    assert_eq!(
        fixture
            .attempt
            .file
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), expected);
    assert!(
        fixture
            .attempt
            .complete_for(crucible_node_format::U64::new(7))
    );
}
