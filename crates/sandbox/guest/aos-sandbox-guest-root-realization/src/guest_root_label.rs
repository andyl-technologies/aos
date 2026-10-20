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

mod read_original;
pub use read_original::{GuestRootLabelReadOriginalV1, GuestRootLabelReadFootprintV1, GuestRootLabelReadClosedV1, GuestRootLabelReadReachedDataV2};

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
    read_original::verify_ordinary(root_fd)
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
    read_original::project_engine(root, install, before_deadline, None, MAXIMUM_PATH_BYTES / 2, MAXIMUM_ENTRIES, None)
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
    read_original::project_tree_engine(directory, path_bytes, count, expected, permit_symlinks, install, before_deadline, None, 0, MAXIMUM_PATH_BYTES / 2, MAXIMUM_ENTRIES, None)
}

fn open_directory(root: BorrowedFd<'_>, path: &Path) -> Result<OwnedFd, GuestRootLabelErrorV1> {
    read_original::open_directory_ordinary(root, path)
}

fn require_same_inode(
    fd: BorrowedFd<'_>,
    expected: &rustix::fs::Stat,
) -> Result<(), GuestRootLabelErrorV1> {
    read_original::require_same_inode_engine(fd, expected, None)
}

fn label_descriptor(
    fd: BorrowedFd<'_>,
    expected: &[u8],
    install: bool,
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootLabelErrorV1> {
    read_original::label(fd, expected, install, before_deadline, None)
}

fn check_deadline(before_deadline: &mut impl FnMut() -> bool) -> Result<(), GuestRootLabelErrorV1> {
    if !before_deadline() {
        return Err(GuestRootLabelErrorV1::Deadline);
    }
    Ok(())
}

fn verify_root(fd: BorrowedFd<'_>) -> Result<(), GuestRootLabelErrorV1> {
    read_original::verify_root_engine(fd, None)
}

fn verify_executable(fd: BorrowedFd<'_>) -> Result<(), GuestRootLabelErrorV1> {
    read_original::verify_executable_engine(fd, None)
}

fn verify_one_label(fd: BorrowedFd<'_>, expected: &[u8]) -> Result<(), GuestRootLabelErrorV1> {
    verify_attribute(fd, XATTR_NAME, expected)
}

fn verify_attribute(
    fd: BorrowedFd<'_>,
    attribute: &str,
    expected: &[u8],
) -> Result<(), GuestRootLabelErrorV1> {
    read_original::attribute(fd, attribute, expected, None)
}

/// Reports an unsafe or unverified workspace executable label.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootLabelErrorV1 {
    /// The retained traversal exceeded its already-admitted recursion ceiling.
    #[error("guest-root label receiving depth is exhausted")]
    ReceivingDepth,
    /// The enclosing actual payer denied the next reached native prefix.
    #[error("guest root confinement reached-prefix admission refused")]
    ReceivingAdmission,
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

    #[test]
    #[ignore = "requires root, enforcing SELinux, new mount API and AOS_TEST_UNSHARE"]
    fn recursive_projection_rejects_directory_and_file_submounts() {
        const CHILD_ROOT: &str = "AOS_GUEST_LABEL_MOUNT_TEST_ROOT";
        const TEST: &str =
            "guest_root_label::tests::recursive_projection_rejects_directory_and_file_submounts";

        let Some(directory) = std::env::var_os(CHILD_ROOT) else {
            // The child owns a private mount namespace. Its exit removes every
            // fixture mount before the parent removes the temporary files.
            let directory = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(
                std::env::var_os("AOS_TEST_UNSHARE").expect("AOS unshare fixture path"),
            )
            .args(["--mount", "--propagation", "private", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", TEST, "--test-threads=1"])
            .env(CHILD_ROOT, directory.path())
            .output()
            .unwrap();

            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        };

        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let base = BeneathRoot::from_owned(File::open(&directory).unwrap().into()).unwrap();
        let mut label = [0_u8; MAXIMUM_LABEL_BYTES];
        let length = fgetxattr(base.as_fd(), XATTR_NAME, &mut label[..]).unwrap();
        let expected = &label[..length];

        for case in ["directory-bind", "file-bind", "directory-tmpfs"] {
            let case_path = Path::new(&directory).join(case);
            std::fs::create_dir(&case_path).unwrap();
            let is_file = case == "file-bind";
            let source_path = Path::new(&directory).join(format!("{case}-source"));
            let destination_path = case_path.join("mounted");
            if is_file {
                File::create(&source_path).unwrap();
                File::create(&destination_path).unwrap();
            } else {
                std::fs::create_dir(&source_path).unwrap();
                std::fs::create_dir(&destination_path).unwrap();
            }
            for path in [&case_path, &source_path, &destination_path] {
                let file = File::open(path).unwrap();
                fsetxattr(file.as_fd(), XATTR_NAME, expected, XattrFlags::empty()).unwrap();
            }
            let case_root =
                BeneathRoot::from_owned(File::open(&case_path).unwrap().into()).unwrap();
            project_tree(
                case_root.as_fd(),
                0,
                &mut 0,
                expected,
                false,
                false,
                &mut || true,
            )
            .unwrap();

            let source = base
                .resolve(
                    Path::new(&format!("{case}-source")),
                    aos_sandbox_linux::path::ResolveOptions::any(),
                )
                .unwrap();
            let destination = case_root
                .resolve(
                    Path::new("mounted"),
                    aos_sandbox_linux::path::ResolveOptions::any(),
                )
                .unwrap();
            let mount = if case == "directory-tmpfs" {
                aos_sandbox_linux::mount::FileSystemContext::open("tmpfs")
                    .unwrap()
                    .create()
                    .unwrap()
                    .mount()
                    .unwrap()
            } else {
                aos_sandbox_linux::mount::DetachedMount::clone_from(&source, false).unwrap()
            };
            mount.attach(&destination).unwrap();

            if case != "directory-tmpfs" {
                // This is a different mount of the exact same filesystem inode,
                // so a device/inode comparison cannot reject the substitution.
                let mounted =
                    statat(case_root.as_fd(), "mounted", AtFlags::SYMLINK_NOFOLLOW).unwrap();
                let original = fstat(source.as_fd()).unwrap();
                assert_eq!(mounted.st_dev, original.st_dev);
                assert_eq!(mounted.st_ino, original.st_ino);
            }
            for install in [false, true] {
                let error = project_tree(
                    case_root.as_fd(),
                    0,
                    &mut 0,
                    expected,
                    false,
                    install,
                    &mut || true,
                )
                .unwrap_err();
                assert!(matches!(
                    error,
                    GuestRootLabelErrorV1::Path(aos_sandbox_linux::Error::Syscall {
                        operation: "openat2",
                        source,
                    }) if source.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error())
                ));
            }
        }
    }
}
