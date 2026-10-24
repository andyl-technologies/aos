//! Real-filesystem controls for bounded descriptor-relative cleanup.

use super::*;
use std::error::Error;
use std::fs;

fn directory(path: &Path) -> Result<OwnedFd, rustix::io::Errno> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
}

#[test]
fn cleanup_unlinks_symlinks_without_following_their_target() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::NamedTempFile::new()?;
    fs::write(outside.path(), b"retained outside bytes")?;
    fs::write(root.path().join("artifact"), b"discard")?;
    fs::create_dir(root.path().join("nested"))?;
    fs::write(root.path().join("nested/child"), b"discard")?;
    std::os::unix::fs::symlink(outside.path(), root.path().join("external"))?;

    LinuxDirectoryCleanup::new(directory(root.path())?, root.path()).clear_contents(5)?;

    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    assert_eq!(fs::read(outside.path())?, b"retained outside bytes");
    assert!(root.path().is_dir(), "cleanup leaves the root in place");
    Ok(())
}

#[test]
fn diagnostic_path_replacement_does_not_redirect_cleanup() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let named = root.path().join("named");
    let retained = root.path().join("retained");
    fs::create_dir(&named)?;
    fs::write(named.join("original"), b"discard")?;
    let original = directory(&named)?;
    fs::rename(&named, &retained)?;
    fs::create_dir(&named)?;
    fs::write(named.join("replacement"), b"keep")?;

    LinuxDirectoryCleanup::new(original, &named).clear_contents(2)?;

    assert_eq!(fs::read_dir(&retained)?.count(), 0);
    assert_eq!(fs::read(named.join("replacement"))?, b"keep");
    Ok(())
}

#[test]
fn exact_entry_bound_and_one_short_use_real_partial_cleanup() -> Result<(), Box<dyn Error>> {
    let exact = tempfile::tempdir()?;
    fs::write(exact.path().join("a"), b"a")?;
    fs::write(exact.path().join("b"), b"b")?;
    LinuxDirectoryCleanup::new(directory(exact.path())?, exact.path()).clear_contents(3)?;
    assert_eq!(fs::read_dir(exact.path())?.count(), 0);

    let short = tempfile::tempdir()?;
    fs::write(short.path().join("a"), b"a")?;
    fs::write(short.path().join("b"), b"b")?;
    let retained_original = directory(short.path())?;
    let cleanup_duplicate = retained_original.try_clone()?;

    let error = LinuxDirectoryCleanup::new(cleanup_duplicate, short.path())
        .clear_contents(2)
        .unwrap_err();

    assert!(matches!(
        error,
        LinuxDirectoryCleanupError::Bound {
            reason: LinuxDirectoryCleanupBoundReason::EntryLimitExceeded,
            ..
        }
    ));
    assert_eq!(fs::read_dir(short.path())?.count(), 1);
    LinuxDirectoryCleanup::new(retained_original.try_clone()?, short.path()).clear_contents(2)?;
    assert_eq!(fs::read_dir(short.path())?.count(), 0);
    assert!(
        fstat(&retained_original).is_ok(),
        "outer authority remains owned"
    );
    Ok(())
}

#[test]
fn iterative_cleanup_handles_a_deep_real_directory_tree() -> Result<(), Box<dyn Error>> {
    const DEPTH: u64 = 64;
    let root = tempfile::tempdir()?;
    let mut current = directory(root.path())?;
    for _ in 0..DEPTH {
        rustix::fs::mkdirat(&current, "nested", Mode::from_bits_truncate(0o700))?;
        current = openat(
            &current,
            "nested",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
    }
    drop(current);

    LinuxDirectoryCleanup::new(directory(root.path())?, root.path()).clear_contents(DEPTH + 1)?;

    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    Ok(())
}

#[test]
fn a_regular_file_descriptor_returns_the_original_filesystem_error() -> Result<(), Box<dyn Error>> {
    let file = tempfile::NamedTempFile::new()?;
    let descriptor: OwnedFd = file.reopen()?.into();

    let error = LinuxDirectoryCleanup::new(descriptor, file.path())
        .clear_contents(1)
        .unwrap_err();

    match error {
        LinuxDirectoryCleanupError::Io {
            operation, source, ..
        } => {
            assert_eq!(operation, LinuxDirectoryCleanupOperation::OpenDirectoryScan);
            assert_eq!(source.raw_os_error(), Some(libc::ENOTDIR));
        }
        other => panic!("expected typed directory-open failure, got {other:?}"),
    }
    assert!(file.path().is_file());
    Ok(())
}

#[test]
fn a_replaced_named_child_refuses_identity_before_removal() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let named = root.path().join("child");
    fs::create_dir(&named)?;
    let original = directory(&named)?;
    fs::rename(&named, root.path().join("retained"))?;
    fs::create_dir(&named)?;
    let parent = directory(root.path())?;
    let name = CString::new("child")?;

    let error = verify_cleanup_child_identity(&parent, &name, &original, root.path()).unwrap_err();

    assert!(matches!(
        error,
        LinuxDirectoryCleanupError::DirectoryIdentity { .. }
    ));
    assert!(named.is_dir());
    assert!(root.path().join("retained").is_dir());
    Ok(())
}

#[test]
fn closed_bound_reasons_preserve_all_existing_diagnostics() {
    let reasons = [
        (
            LinuxDirectoryCleanupBoundReason::RootFrameMissing,
            "artifact-cleanup traversal lost its root frame",
        ),
        (
            LinuxDirectoryCleanupBoundReason::ChildFrameMissing,
            "artifact-cleanup traversal lost a child frame",
        ),
        (
            LinuxDirectoryCleanupBoundReason::ParentNameMissing,
            "nested artifact directory omitted its parent name",
        ),
        (
            LinuxDirectoryCleanupBoundReason::ParentFrameMissing,
            "nested artifact directory omitted its parent frame",
        ),
        (
            LinuxDirectoryCleanupBoundReason::EntryCountOverflow,
            "attempt artifact entry count overflowed",
        ),
        (
            LinuxDirectoryCleanupBoundReason::EntryLimitExceeded,
            "attempt artifacts exceed the cleanup-entry ceiling",
        ),
        (
            LinuxDirectoryCleanupBoundReason::ChildNameReservationFailed,
            "attempt artifact cleanup cannot retain bounded child names",
        ),
    ];
    for (reason, expected) in reasons {
        assert_eq!(reason.as_str(), expected);
        assert_eq!(reason.to_string(), expected);
        let error = LinuxDirectoryCleanupError::Bound {
            path: std::path::PathBuf::from("/diagnostic-only"),
            reason,
        };
        assert_eq!(
            error.to_string(),
            format!("directory cleanup failed for /diagnostic-only: {expected}")
        );
    }
}
