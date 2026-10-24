//! Implements the Linux generic quota and inode project-attribute interfaces.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

const PROJECT_QUOTA: u32 = 2;
const Q_GETQUOTA: u32 = 0x800007;
const Q_SETQUOTA: u32 = 0x800008;
const Q_GETSTATE: u32 = 0x5808;
const FS_XFLAG_PROJINHERIT: u32 = 0x200;

#[repr(C)]
#[derive(Default)]
struct FsXattr {
    flags: u32,
    extent_size: u32,
    nextents: u32,
    project_id: u32,
    cow_extent_size: u32,
    padding: [u8; 8],
}

#[repr(C)]
#[derive(Default)]
struct Dqblk {
    block_hard: u64,
    block_soft: u64,
    current_space: u64,
    inode_hard: u64,
    inode_soft: u64,
    current_inodes: u64,
    block_time: u64,
    inode_time: u64,
    valid: u32,
}

#[repr(C)]
#[derive(Default)]
struct QuotaState {
    version: u8,
    pad: u8,
    flags: u16,
    incore: u32,
    files: [[u64; 3]; 3],
    timers: [u32; 3],
    warnings: [u16; 4],
    padding: u32,
    reserved: [u64; 7],
}

/// Reports the actual project assignment of an inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeProject {
    /// Kernel project identifier.
    pub project_id: u32,
    /// Whether newly created children inherit the project.
    pub inherit: bool,
    /// Native device identity.
    pub device: u64,
    /// Native inode identity.
    pub inode: u64,
}

/// Reports live kernel quota charges, independently of allocated inode blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeQuota {
    /// Finite enforced byte ceiling.
    pub hard_limit_bytes: u64,
    /// Kernel charged space, including delayed-allocation reservations.
    pub charged_reserved_bytes: u64,
    /// Inode ceiling; zero denotes no inode-specific ceiling.
    pub hard_inode_limit: u64,
    /// Kernel charged inode count.
    pub charged_inodes: u64,
}

fn quota<T>(file: &File, operation: u32, project: u32, value: &mut T) -> io::Result<()> {
    // SAFETY: The command fixes T's kernel ABI at each private call site. The
    // descriptor remains borrowed and value points to initialized writable T.
    let result = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            file.as_raw_fd(),
            (operation << 8) | PROJECT_QUOTA,
            project,
            value as *mut T,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl NativeProject {
    /// Reads the actual inode project and inheritance attributes.
    ///
    /// # Errors
    /// Returns kernel errors for unsupported filesystems or inaccessible inodes.
    pub fn inspect(file: &File) -> io::Result<Self> {
        let mut attributes = FsXattr::default();
        // SAFETY: FS_IOC_FSGETXATTR writes the ABI-compatible initialized struct.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                0x801c581f as libc::c_ulong,
                &mut attributes,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        Ok(Self {
            project_id: attributes.project_id,
            inherit: attributes.flags & FS_XFLAG_PROJINHERIT != 0,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

fn require_enforcement(file: &File) -> io::Result<()> {
    let mut state = QuotaState {
        version: 1,
        ..QuotaState::default()
    };
    quota(file, Q_GETSTATE, 0, &mut state)?;
    if state.flags & 0x30 != 0x30 {
        return Err(io::Error::other(
            "project accounting or enforcement disabled",
        ));
    }
    Ok(())
}

/// Rejects initial adoption of an already configured or charged project number.
///
/// This privileged live check complements the durable host ownership ledger;
/// project-zero roots do not prove a selected project is unused elsewhere.
///
/// # Errors
/// Returns kernel privilege or support errors, disabled-enforcement errors, or
/// an error when any previous limit, charge or quota timer exists for the ID.
pub fn require_unused_project(file: &File, project_id: u32) -> io::Result<()> {
    if project_id == 0 {
        return Err(io::Error::other("zero project identifier"));
    }
    require_enforcement(file)?;
    let mut value = Dqblk::default();
    quota(file, Q_GETQUOTA, project_id, &mut value)?;
    if value.block_hard != 0
        || value.block_soft != 0
        || value.current_space != 0
        || value.inode_hard != 0
        || value.inode_soft != 0
        || value.current_inodes != 0
        || value.block_time != 0
        || value.inode_time != 0
    {
        return Err(io::Error::other(
            "project number already has limits or charges",
        ));
    }
    Ok(())
}

impl NativeQuota {
    /// Queries live project accounting and enforced limits as the current caller.
    ///
    /// # Errors
    /// Returns permission errors without current quota-query privilege, and
    /// rejects disabled enforcement or an unlimited project.
    pub fn query(file: &File, project_id: u32) -> io::Result<Self> {
        if project_id == 0 {
            return Err(io::Error::other("zero project identifier"));
        }
        require_enforcement(file)?;
        let mut value = Dqblk::default();
        quota(file, Q_GETQUOTA, project_id, &mut value)?;
        let hard_limit_bytes = value
            .block_hard
            .checked_mul(1024)
            .filter(|limit| *limit != 0)
            .ok_or_else(|| io::Error::other("unlimited or overflowing project hard limit"))?;
        Ok(Self {
            hard_limit_bytes,
            charged_reserved_bytes: value.current_space,
            hard_inode_limit: value.inode_hard,
            charged_inodes: value.current_inodes,
        })
    }
}

/// Synchronizes an inode before reporting its allocated 512-byte blocks.
///
/// # Errors
/// Returns synchronization, metadata or arithmetic errors.
pub fn synchronized_allocated_bytes(file: &File) -> io::Result<u64> {
    file.sync_all()?;
    file.metadata()?
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::other("allocated block count overflow"))
}

/// Assigns a quiescent inheriting root and sets a finite project quota.
///
/// This host administrative operation must never be exposed through a query
/// broker. The caller must durably bind root, domain and owner before invoking
/// it, validate an empty directory skeleton, retain exclusive provisioning
/// custody, and prevent concurrent creation beneath the root.
///
/// # Errors
/// Returns invalid-input errors for zero or unaligned limits, and kernel errors
/// when privilege, project attributes or quota enforcement are unavailable.
pub fn provision_project(root: &File, project_id: u32, hard_limit_bytes: u64) -> io::Result<()> {
    if !root.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "project root must be a directory",
        ));
    }
    if project_id == 0 || hard_limit_bytes == 0 || !hard_limit_bytes.is_multiple_of(1024) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "finite aligned project limit required",
        ));
    }
    assign_project(root, project_id, true)?;
    let mut limit = Dqblk {
        block_hard: hard_limit_bytes / 1024,
        valid: 1,
        ..Dqblk::default()
    };
    quota(root, Q_SETQUOTA, project_id, &mut limit)?;
    root.sync_all()
}

/// Assigns project attributes without changing unrelated native flags.
///
/// Only administrative directory provisioning and original enrollment receipts
/// call this helper. It establishes neither a durable claim nor a quota limit.
pub(super) fn assign_project(root: &File, project_id: u32, inherit: bool) -> io::Result<()> {
    let mut attributes = FsXattr::default();
    // SAFETY: The descriptor is live and the ioctl writes an ABI-compatible struct.
    if unsafe {
        libc::ioctl(
            root.as_raw_fd(),
            0x801c581f as libc::c_ulong,
            &mut attributes,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if attributes.project_id != 0 && attributes.project_id != project_id {
        return Err(io::Error::other(
            "refusing to reassign existing charge owner",
        ));
    }
    attributes.project_id = project_id;
    if inherit {
        attributes.flags |= FS_XFLAG_PROJINHERIT;
    }
    // SAFETY: The ioctl reads only the initialized ABI-compatible attributes.
    if unsafe { libc::ioctl(root.as_raw_fd(), 0x401c5820 as libc::c_ulong, &attributes) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reads the external filesystem UUID from a retained native descriptor.
///
/// # Errors
/// Returns unsupported-filesystem errors or rejects a nonstandard UUID length.
pub fn filesystem_uuid(file: &File) -> io::Result<[u8; 16]> {
    let mut value = [0u8; 17];
    // SAFETY: FS_IOC_GETFSUUID writes the 17-byte fsuuid2 ABI buffer.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x80111500 as libc::c_ulong, &mut value) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if value[0] != 16 {
        return Err(io::Error::other("filesystem UUID must be 16 bytes"));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&value[1..]);
    Ok(uuid)
}

/// Opens an absolute path through retained, nonsymlink directory descriptors.
///
/// Ancestors must remain root-owned and not writable by other identities.
/// The final directory may belong to its configured Terrane role.
///
/// # Errors
/// Returns errors for relative paths, symlinks, unsafe ancestors or kernel failure.
pub fn open_host_path(path: &std::path::Path, directory: bool) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;
    if !path.is_absolute() {
        return Err(io::Error::other("host path must be absolute"));
    }
    let mut current = File::open("/")?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(io::Error::other("noncanonical host path"));
        };
        let parent = current.metadata()?;
        if parent.uid() != 0 || parent.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "host path ancestor lacks protected custody",
            ));
        }
        let name =
            CString::new(name.as_bytes()).map_err(|_| io::Error::other("NUL in host path"))?;
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if !last || directory {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: name is terminated; current remains live; openat returns a new FD.
        let descriptor = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the newly opened descriptor is uniquely owned here.
        current = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(current)
}
