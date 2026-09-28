//! Physical SELinux confinement projection for the copied Guest owner substrate.
//!
//! The immutable package supplies executable bytes, but copying into a fresh
//! ZFS workspace does not carry a `security.selinux` xattr. Storage labels the
//! complete copied loader/library/package closure, fixed TCB and configuration
//! names, and their ancestors before its existing guest-root marker. Root UID
//! ownership alone cannot protect these objects from an admitted UID-zero tenant.

use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_sandbox_linux::path::BeneathRoot;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, XattrFlags, fgetxattr, fsetxattr, fstat, fsync, lgetxattr,
    lsetxattr, open, openat, statat,
};

const XATTR_NAME: &str = "security.selinux";
const MAXIMUM_LABEL_BYTES: usize = 128;
const GUEST_BOOTSTRAP_PATH: &str = "usr/libexec/aos-sandbox-guest-init";
const GUEST_SYSTEMD_PATH: &str = "usr/lib/systemd/systemd";
const GUEST_BOOTSTRAP_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_payload_bootstrap_exec_t:s0\0";
const GUEST_SYSTEMD_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_payload_systemd_exec_t:s0\0";
const OWNER_EXEC_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_owner_exec_t:s0\0";
const STORE_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_store_t:s0\0";
const ANCHOR_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_anchor_t:s0\0";
const CONFIG_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_config_t:s0\0";
const RUNTIME_METADATA_LABEL: &[u8] =
    b"system_u:object_r:aos_sandbox_guest_runtime_metadata_t:s0\0";
const PRIVATE_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_private_t:s0\0";
const PUBLICATION_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_publication_t:s0\0";
const MAXIMUM_ENTRIES: usize = 250_000;
const MAXIMUM_PATH_BYTES: usize = 4096;

const EXECUTABLE_LABELS: [(&str, &[u8]); 7] = [
    (GUEST_BOOTSTRAP_PATH, GUEST_BOOTSTRAP_LABEL),
    (GUEST_SYSTEMD_PATH, GUEST_SYSTEMD_LABEL),
    ("usr/libexec/aos-sandbox-guest-agent", OWNER_EXEC_LABEL),
    ("usr/libexec/aos-sandbox-guest-exec", OWNER_EXEC_LABEL),
    ("usr/libexec/aos-sandbox-exec-gate", OWNER_EXEC_LABEL),
    ("usr/sbin/sshd", OWNER_EXEC_LABEL),
    ("usr/libexec/sshd-session", OWNER_EXEC_LABEL),
];

const ANCHORS: &[&str] = &[
    "usr",
    "usr/lib",
    "usr/libexec",
    "usr/lib/systemd",
    "usr/sbin",
    "nix",
    "etc",
    "var",
    "var/lib",
    "run",
];
const CONFIG_DIRECTORIES: &[&str] = &["etc/systemd", "etc/pam.d", "etc/ld.so.conf.d"];
const PRIVATE_DIRECTORIES: &[&str] = &[
    "etc/aos",
    "etc/aos/sandbox-agent",
    "etc/aos/sandbox-attach",
    "var/lib/aos-sandbox-agent",
    "var/lib/aos-sandbox-agent/guest-effects-v1",
    "var/empty",
    "run/systemd",
];
const PUBLICATION_DIRECTORY: &str = "etc/aos/sandbox-guest-root";
const CONFIG_FILES: &[&str] = &[
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/nsswitch.conf",
    "etc/ld.so.preload",
    "etc/ld.so.cache",
    "etc/ld.so.conf",
    "etc/hostname",
];
// Nspawn's existing resolver setup and Guest PID 1's machine-id setup must
// not gain write permission on NSS, PAM, loader configuration, or units.
const RUNTIME_METADATA_FILES: &[&str] = &["etc/machine-id", "etc/resolv.conf"];

/// Applies and reads back the fixed copied Guest confinement projection.
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

    project(root.as_fd(), true, &mut before_deadline)?;

    if !before_deadline() {
        return Err(GuestRootLabelErrorV1::Deadline);
    }
    verify_copied_guest_executable_labels_fd_v1(root.as_fd())
}

/// Reads the complete fixed confinement projection beneath one pinned root FD.
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

    project(root.as_fd(), false, &mut || true)
}

/// Protects the actual fresh manager subtree before the first Guest child.
///
/// Nspawn can populate `/run/systemd` before PID 1 starts. Its actual directory
/// and existing regular files are projected, not assumed absent or trusted
/// because a copied directory had a label. Symlinks, sockets and submounts in
/// this pre-manager tree fail closed; later fixed Owner-created sockets and
/// units inherit the private type from the enforcing policy.
///
/// # Errors
///
/// Rejects a nonroot/non-PID-1/non-Owner caller, foreign runtime mount, unsafe
/// object, excessive tree, unsupported xattr or mismatching physical readback.
pub fn label_fresh_guest_manager_before_v1() -> Result<(), GuestRootLabelErrorV1> {
    aos_sandbox_linux::guest_confinement::require_guest_owner()?;
    if std::process::id() != 1 || rustix::process::geteuid().as_raw() != 0 {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    let run = open(
        "/run",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if rustix::fs::fstatfs(&run)?.f_type as u64 != 0x0102_1994 {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    verify_root(run.as_fd())?;
    verify_one_label(run.as_fd(), ANCHOR_LABEL)?;
    match rustix::fs::mkdirat(&run, "systemd", Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let manager = open_directory(run.as_fd(), Path::new("systemd"))?;
    let mut count = 0;
    project_tree(
        manager.as_fd(),
        0,
        &mut count,
        PRIVATE_LABEL,
        false,
        true,
        &mut || true,
    )?;
    count = 0;
    project_tree(
        manager.as_fd(),
        0,
        &mut count,
        PRIVATE_LABEL,
        false,
        false,
        &mut || true,
    )
}

fn project(
    root: BorrowedFd<'_>,
    install: bool,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootLabelErrorV1> {
    label_descriptor(root, ANCHOR_LABEL, install, before_deadline)?;
    for path in ANCHORS {
        let directory = open_directory(root, Path::new(path))?;
        label_descriptor(directory.as_fd(), ANCHOR_LABEL, install, before_deadline)?;
    }
    for (paths, expected) in [
        (CONFIG_DIRECTORIES, CONFIG_LABEL),
        (PRIVATE_DIRECTORIES, PRIVATE_LABEL),
    ] {
        for path in paths {
            let directory = open_directory(root, Path::new(path))?;
            label_descriptor(directory.as_fd(), expected, install, before_deadline)?;
        }
    }
    // The fixed marker owner publishes after this projection. Keep its exact
    // subtree distinct from Guest-private trust/ledger and immutable config.
    // Parent anchors are labeled separately, not recursively across this cut.
    for (paths, expected) in [
        (CONFIG_DIRECTORIES, CONFIG_LABEL),
        (
            &[
                "etc/aos/sandbox-agent",
                "etc/aos/sandbox-attach",
                "var/lib/aos-sandbox-agent",
                "var/empty",
                "run/systemd",
            ][..],
            PRIVATE_LABEL,
        ),
        (&[PUBLICATION_DIRECTORY][..], PUBLICATION_LABEL),
    ] {
        for path in paths {
            let directory = open_directory(root, Path::new(path))?;
            let mut count = 0;
            project_tree(
                directory.as_fd(),
                0,
                &mut count,
                expected,
                true,
                install,
                before_deadline,
            )?;
        }
    }
    let root = BeneathRoot::from_owned(rustix::io::fcntl_dupfd_cloexec(root, 0)?)?;
    for (paths, expected) in [
        (CONFIG_FILES, CONFIG_LABEL),
        (RUNTIME_METADATA_FILES, RUNTIME_METADATA_LABEL),
    ] {
        for path in paths {
            let file = root.open_regular(Path::new(path))?;
            verify_root(file.as_fd())?;
            label_descriptor(file.as_fd(), expected, install, before_deadline)?;
        }
    }
    for (path, expected) in EXECUTABLE_LABELS {
        let file = root.open_regular(Path::new(path))?;
        verify_executable(file.as_fd())?;
        label_descriptor(file.as_fd(), expected, install, before_deadline)?;
    }
    let credential = root.open_regular(Path::new("etc/aos/sandbox-agent/guest-executable-v1"))?;
    label_descriptor(credential.as_fd(), PRIVATE_LABEL, install, before_deadline)?;

    let store = open_directory(root.as_fd(), Path::new("nix/store"))?;
    let mut count = 0;
    project_tree(
        store.as_fd(),
        0,
        &mut count,
        STORE_LABEL,
        true,
        install,
        before_deadline,
    )
}

fn project_tree(
    directory: BorrowedFd<'_>,
    path_bytes: usize,
    count: &mut usize,
    expected: &[u8],
    permit_symlinks: bool,
    install: bool,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootLabelErrorV1> {
    verify_root(directory)?;
    label_descriptor(directory, expected, install, before_deadline)?;
    let anchor = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = std::fs::read_dir(&anchor)?;
    for entry in entries {
        check_deadline(before_deadline)?;
        *count = count
            .checked_add(1)
            .filter(|value| *value <= MAXIMUM_ENTRIES)
            .ok_or(GuestRootLabelErrorV1::UnsafeInode)?;
        let name = entry?.file_name();
        let child_bytes = path_bytes
            .checked_add(name.as_bytes().len() + 1)
            .filter(|length| *length <= MAXIMUM_PATH_BYTES)
            .ok_or(GuestRootLabelErrorV1::UnsafeInode)?;
        let stat = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        if stat.st_uid != 0 {
            return Err(GuestRootLabelErrorV1::UnsafeInode);
        }
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child = openat(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                require_same_inode(child.as_fd(), &stat)?;
                project_tree(
                    child.as_fd(),
                    child_bytes,
                    count,
                    expected,
                    permit_symlinks,
                    install,
                    before_deadline,
                )?;
            }
            FileType::RegularFile => {
                let child = openat(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                require_same_inode(child.as_fd(), &stat)?;
                verify_root(child.as_fd())?;
                label_descriptor(child.as_fd(), expected, install, before_deadline)?;
            }
            FileType::Symlink => {
                if !permit_symlinks {
                    return Err(GuestRootLabelErrorV1::UnsafeInode);
                }
                // The final symlink is never followed. The parent remains the
                // retained directory and the publication caller holds this tree
                // quiescent. Restat joins both xattr operations to that inode.
                let path = Path::new(&anchor).join(&name);
                let mut actual = [0_u8; MAXIMUM_LABEL_BYTES];
                if install
                    && !lgetxattr(&path, XATTR_NAME, &mut actual[..])
                        .is_ok_and(|length| actual[..length] == *expected)
                {
                    lsetxattr(&path, XATTR_NAME, expected, XattrFlags::empty())?;
                }
                let length = lgetxattr(&path, XATTR_NAME, &mut actual[..])?;
                let after = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
                if actual[..length] != *expected
                    || stat.st_dev != after.st_dev
                    || stat.st_ino != after.st_ino
                {
                    return Err(GuestRootLabelErrorV1::WrongLabel);
                }
            }
            _ => return Err(GuestRootLabelErrorV1::UnsafeInode),
        }
    }
    if install {
        fsync(directory)?;
    }
    check_deadline(before_deadline)
}

fn open_directory(root: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd, GuestRootLabelErrorV1> {
    let root = BeneathRoot::from_owned(rustix::io::fcntl_dupfd_cloexec(root, 0)?)?;
    let pinned = root.resolve(
        path,
        aos_sandbox_linux::path::ResolveOptions {
            no_mount_crossing: true,
            require_directory: true,
        },
    )?;
    let readable = openat(
        pinned.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    verify_root(readable.as_fd())?;
    Ok(readable)
}

fn require_same_inode(
    fd: BorrowedFd<'_>,
    expected: &rustix::fs::Stat,
) -> Result<(), GuestRootLabelErrorV1> {
    let actual = fstat(fd)?;
    if actual.st_dev != expected.st_dev
        || actual.st_ino != expected.st_ino
        || actual.st_mode != expected.st_mode
    {
        return Err(GuestRootLabelErrorV1::UnsafeInode);
    }
    Ok(())
}

fn label_descriptor(
    fd: BorrowedFd<'_>,
    expected: &[u8],
    install: bool,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootLabelErrorV1> {
    check_deadline(before_deadline)?;
    if install && verify_one_label(fd, expected).is_err() {
        fsetxattr(fd, XATTR_NAME, expected, XattrFlags::empty())?;
        fsync(fd)?;
    }
    verify_one_label(fd, expected)
}

fn check_deadline(before_deadline: &mut impl FnMut() -> bool) -> Result<(), GuestRootLabelErrorV1> {
    if !before_deadline() {
        return Err(GuestRootLabelErrorV1::Deadline);
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
    /// Bounded physical directory enumeration failed.
    #[error("guest-root label directory read failed: {0}")]
    Directory(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    //! Physical projection and immutable/configuration scope tests.

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
        assert!(
            RUNTIME_METADATA_FILES
                .iter()
                .all(|path| !CONFIG_FILES.contains(path))
        );
        assert!(!RUNTIME_METADATA_FILES.contains(&"etc/hostname"));
        assert_ne!(RUNTIME_METADATA_LABEL, CONFIG_LABEL);
        assert_ne!(PUBLICATION_LABEL, PRIVATE_LABEL);
        assert!(!PRIVATE_DIRECTORIES.contains(&PUBLICATION_DIRECTORY));
    }
}
