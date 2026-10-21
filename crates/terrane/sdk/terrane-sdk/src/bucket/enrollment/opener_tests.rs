//! Checks inode classification before readable opens, without administrative setup.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture assertions intentionally panic."
)]

use super::super::super::tests::Fixture;
use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn enrollment_child_classification_refuses_special_files_before_readable_reopen() {
    let fixture = Fixture::new();
    let parent = File::open(&fixture.parent).unwrap();
    let policy = FencePolicy::Payload {
        owner: fixture.owner,
    };
    rustix::fs::mkfifoat(
        &parent,
        c"fifo",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    std::os::unix::fs::symlink("/dev/null", fixture.parent.join("symlink")).unwrap();
    std::fs::create_dir(fixture.parent.join("directory")).unwrap();
    for name in [c"fifo", c"symlink", c"directory"] {
        assert!(classify_child(&parent, name, policy).is_err(), "{name:?}");
    }

    // O_PATH classification inspects this real device without invoking its
    // readable open operation. No privileged mknod fixture is required.
    let devices = File::open("/dev").unwrap();
    assert!(classify_child(&devices, c"null", policy).is_err());
}

#[test]
fn enrollment_child_classification_checks_policy_before_readable_reopen() {
    let fixture = Fixture::new();
    let path = fixture.parent.join("regular");
    std::fs::write(&path, b"bounded regular data").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let parent = File::open(&fixture.parent).unwrap();
    let policy = FencePolicy::Payload {
        owner: fixture.owner,
    };
    assert!(classify_child(&parent, c"regular", policy).is_err());

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&path, fixture.parent.join("alias")).unwrap();
    assert!(classify_child(&parent, c"regular", policy).is_err());
}

#[test]
fn enrollment_child_reopens_pinned_regular_inode_without_canonical_name_lookup() {
    use rustix::fs::{Mode, OFlags, fcntl_getfl};

    let fixture = Fixture::new();
    let named = fixture.parent.join("named");
    let moved = fixture.parent.join("moved");
    std::fs::create_dir(&named).unwrap();
    std::fs::write(named.join("regular"), b"original").unwrap();
    std::fs::set_permissions(
        named.join("regular"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let parent = File::open(&named).unwrap();
    let classified = classify_child(
        &parent,
        c"regular",
        FencePolicy::Payload {
            owner: fixture.owner,
        },
    )
    .unwrap();
    assert!(
        fcntl_getfl(&classified.retained)
            .unwrap()
            .contains(OFlags::PATH)
    );

    // Moving the parent preserves the original regular inode's metadata. The
    // old canonical pathname now names a FIFO, which must never be reopened.
    std::fs::rename(&named, &moved).unwrap();
    std::fs::create_dir(&named).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        named.join("regular"),
        Mode::RUSR | Mode::WUSR,
    )
    .unwrap();
    let readable = reopen_child(classified).unwrap();
    let flags = fcntl_getfl(&readable).unwrap();
    assert!(flags.contains(OFlags::NONBLOCK));
    assert!(!flags.intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR));
    let mut actual = [0; 8];
    readable.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(&actual, b"original");
    let original = std::fs::symlink_metadata(moved.join("regular")).unwrap();
    let opened = readable.metadata().unwrap();
    assert_eq!(
        (opened.dev(), opened.ino()),
        (original.dev(), original.ino())
    );
}
