//! Physical SELinux labels for the two copied guest PID 1 executables.
//!
//! The immutable package supplies executable bytes, but copying into a fresh
//! ZFS workspace does not carry a `security.selinux` xattr. The authenticated
//! Storage publisher applies these two exact labels before publishing its
//! guest-root marker. Every subsequent physical readback checks the copied
//! inodes again; a source-package label or tree digest is not a substitute.

use std::os::fd::BorrowedFd;
use std::path::Path;

use aos_sandbox_linux::path::BeneathRoot;
use rustix::fs::{Mode, OFlags, XattrFlags, fgetxattr, fsetxattr, fstat, fsync, open};

const XATTR_NAME: &str = "security.selinux";
const MAXIMUM_LABEL_BYTES: usize = 128;
const GUEST_BOOTSTRAP_PATH: &str = "usr/libexec/aos-sandbox-guest-init";
const GUEST_SYSTEMD_PATH: &str = "usr/lib/systemd/systemd";
const GUEST_BOOTSTRAP_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_payload_bootstrap_exec_t:s0\0";
const GUEST_SYSTEMD_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_payload_systemd_exec_t:s0\0";

const EXECUTABLE_LABELS: [(&str, &[u8]); 2] = [
    (GUEST_BOOTSTRAP_PATH, GUEST_BOOTSTRAP_LABEL),
    (GUEST_SYSTEMD_PATH, GUEST_SYSTEMD_LABEL),
];

/// Applies and reads back exact labels on the two copied workspace executables.
///
/// This function requires no capability grant on the Storage publisher. Linux
/// delegates valid `security.selinux` xattr writes to SELinux relabel policy;
/// missing policy, an unsupported ZFS xattr, or a foreign inode fails closed.
/// The caller must authenticate the fresh workspace and retain exclusive
/// custody until the marker has been durably published.
///
/// # Errors
///
/// Rejects a changed root, unsafe executable, expired effect deadline, failed
/// SELinux relabel, failed sync, or any label that differs on physical readback.
pub fn label_copied_guest_executables_before_v1(
    workspace: &Path,
    mut before_deadline: impl FnMut() -> bool,
) -> Result<(), GuestRootLabelErrorV1> {
    if !before_deadline() {
        return Err(GuestRootLabelErrorV1::Deadline);
    }
    let root = open(
        workspace,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let root = BeneathRoot::from_owned(root)?;
    verify_root(root.as_fd())?;

    for (relative_path, expected) in EXECUTABLE_LABELS {
        if !before_deadline() {
            return Err(GuestRootLabelErrorV1::Deadline);
        }
        let executable = root.open_regular(Path::new(relative_path))?;
        verify_executable(executable.as_fd())?;

        fsetxattr(
            executable.as_fd(),
            XATTR_NAME,
            expected,
            XattrFlags::empty(),
        )?;
        fsync(executable.as_fd())?;
        verify_one_label(executable.as_fd(), expected)?;
    }

    if !before_deadline() {
        return Err(GuestRootLabelErrorV1::Deadline);
    }
    verify_copied_guest_executable_labels_fd_v1(root.as_fd())
}

/// Reads both copied executable labels beneath one already-pinned root FD.
///
/// This check is suitable for Storage inventory and Host's authenticated
/// detached-root export. It never accepts labels from the immutable source
/// package or from an unpinned path.
///
/// # Errors
///
/// Rejects a foreign root or executable, symlink or mount traversal, missing
/// xattr, invalid xattr length, or a label other than the exact required type.
pub fn verify_copied_guest_executable_labels_fd_v1(
    root_fd: BorrowedFd<'_>,
) -> Result<(), GuestRootLabelErrorV1> {
    let root = BeneathRoot::from_owned(rustix::io::fcntl_dupfd_cloexec(root_fd, 0)?)?;
    verify_root(root.as_fd())?;

    for (relative_path, expected) in EXECUTABLE_LABELS {
        let executable = root.open_regular(Path::new(relative_path))?;
        verify_executable(executable.as_fd())?;
        verify_one_label(executable.as_fd(), expected)?;
    }
    Ok(())
}

fn verify_root(fd: BorrowedFd<'_>) -> Result<(), GuestRootLabelErrorV1> {
    let stat = fstat(fd)?;
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    Ok(())
}

fn verify_executable(fd: BorrowedFd<'_>) -> Result<(), GuestRootLabelErrorV1> {
    let stat = fstat(fd)?;
    if stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o100 == 0
        || stat.st_nlink != 1
    {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    Ok(())
}

fn verify_one_label(fd: BorrowedFd<'_>, expected: &[u8]) -> Result<(), GuestRootLabelErrorV1> {
    verify_attribute(fd, XATTR_NAME, expected)
}

fn verify_attribute(
    fd: BorrowedFd<'_>,
    attribute: &str,
    expected: &[u8],
) -> Result<(), GuestRootLabelErrorV1> {
    let mut actual = [0_u8; MAXIMUM_LABEL_BYTES];
    let actual_bytes = fgetxattr(fd, attribute, &mut actual[..])?;
    if actual[..actual_bytes] != *expected {
        return Err(GuestRootLabelErrorV1::WrongLabel);
    }
    Ok(())
}

/// Reports an unsafe or unverified workspace executable label.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootLabelErrorV1 {
    /// The authenticated publication effect expired before labeling completed.
    #[error("guest-root label effect deadline expired")]
    Deadline,
    /// The workspace root or executable inode is not protected.
    #[error("guest-root label inode is unsafe")]
    UnsafeInode,
    /// An executable does not retain the exact required SELinux label.
    #[error("guest-root executable label differs from production policy")]
    WrongLabel,
    /// Bounded descriptor resolution rejected a path or inode.
    #[error("guest-root label path is invalid: {0}")]
    Path(#[from] aos_sandbox_linux::Error),
    /// A physical filesystem or xattr operation failed.
    #[error("guest-root label I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsFd as _;

    use super::*;

    const TEST_ATTRIBUTE: &str = "user.aos_guest_root_label_test";

    #[test]
    fn physical_xattr_readback_rejects_substitution_and_absence() {
        let directory = tempfile::tempdir().unwrap();
        File::create(directory.path().join("copied-init")).unwrap();
        let file = File::open(directory.path().join("copied-init")).unwrap();
        let expected = b"system_u:object_r:aos_sandbox_payload_bootstrap_exec_t:s0\0";

        assert!(verify_attribute(file.as_fd(), TEST_ATTRIBUTE, expected).is_err());
        fsetxattr(file.as_fd(), TEST_ATTRIBUTE, expected, XattrFlags::empty()).unwrap();
        verify_attribute(file.as_fd(), TEST_ATTRIBUTE, expected).unwrap();

        let mut substituted = expected.to_vec();
        substituted[0] = b'x';
        fsetxattr(
            file.as_fd(),
            TEST_ATTRIBUTE,
            &substituted,
            XattrFlags::empty(),
        )
        .unwrap();
        assert!(matches!(
            verify_attribute(file.as_fd(), TEST_ATTRIBUTE, expected),
            Err(GuestRootLabelErrorV1::WrongLabel)
        ));
    }

    #[test]
    fn label_program_has_distinct_fixed_executables() {
        assert_ne!(EXECUTABLE_LABELS[0].0, EXECUTABLE_LABELS[1].0);
        assert_ne!(EXECUTABLE_LABELS[0].1, EXECUTABLE_LABELS[1].1);
        assert!(
            EXECUTABLE_LABELS
                .iter()
                .all(|(_, label)| label.ends_with(&[0]))
        );
    }
}
