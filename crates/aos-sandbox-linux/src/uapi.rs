//! Private Linux 6.18 UAPI and syscall shims.
//!
//! This is the only module in the crate that contains `unsafe`. Each call
//! converts successful descriptor returns immediately into [`OwnedFd`] and
//! borrows every input for the complete syscall duration.

use std::ffi::CStr;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::{Error, Result};

// Linux 6.18 `include/linux/socket.h`. glibc versions older than 2.39 do not
// publish these constants even when the running kernel implements the ABI.
pub(crate) const SO_PASSPIDFD: libc::c_int = 76;
pub(crate) const SCM_PIDFD: libc::c_int = 0x04;
pub(crate) const SO_PEERPIDFD: libc::c_int = 77;

const SEQPACKET_CONTROL_BYTES: usize = 512;

/// One control message returned by the kernel with all descriptor ownership
/// transferred out of the raw message buffer.
#[derive(Debug)]
pub(crate) enum RawAncillary {
    Credentials(libc::ucred),
    PidFd(OwnedFd),
    Rights(Vec<OwnedFd>),
    Unknown { level: i32, kind: i32 },
    Malformed(Vec<OwnedFd>),
}

#[derive(Debug)]
pub(crate) struct RawSeqpacketMessage {
    pub(crate) bytes: usize,
    pub(crate) flags: i32,
    pub(crate) ancillary: Vec<RawAncillary>,
}

pub(crate) const RESOLVE_NO_XDEV: u64 = 0x01;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(crate) const RESOLVE_BENEATH: u64 = 0x08;

pub(crate) const REQUIRED_IMMUTABLE_SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

pub(crate) struct VerityMeasurement {
    pub(crate) algorithm: u16,
    pub(crate) length: usize,
    pub(crate) digest: [u8; 64],
}

#[repr(C)]
struct RawVerityDigest {
    algorithm: u16,
    digest_size: u16,
    digest: [u8; 64],
}

#[repr(C)]
struct RawVerityEnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    signature_size: u32,
    reserved1: u32,
    signature_ptr: u64,
    reserved2: [u64; 11],
}

pub(crate) const OPEN_TREE_CLONE: u32 = 1;
pub(crate) const OPEN_TREE_CLOEXEC: u32 = libc::O_CLOEXEC as u32;
pub(crate) const AT_EMPTY_PATH: u32 = 0x1000;
pub(crate) const AT_RECURSIVE: u32 = 0x8000;
pub(crate) const RENAME_NOREPLACE: u32 = 1;
pub(crate) const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;
pub(crate) const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;
pub(crate) const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x0000_0040;
pub(crate) const MOVE_MOUNT_BENEATH: u32 = 0x0000_0200;
pub(crate) const FSOPEN_CLOEXEC: u32 = 1;
pub(crate) const FSMOUNT_CLOEXEC: u32 = 1;

pub(crate) const FSCONFIG_SET_FLAG: u32 = 0;
pub(crate) const FSCONFIG_SET_STRING: u32 = 1;
pub(crate) const FSCONFIG_SET_FD: u32 = 5;
pub(crate) const FSCONFIG_CMD_CREATE: u32 = 6;

pub(crate) const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
pub(crate) const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
pub(crate) const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
pub(crate) const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
pub(crate) const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
pub(crate) const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

pub(crate) const STATMOUNT_SB_BASIC: u64 = 0x0000_0001;
pub(crate) const STATMOUNT_MNT_BASIC: u64 = 0x0000_0002;
pub(crate) const STATMOUNT_MNT_ROOT: u64 = 0x0000_0008;
pub(crate) const STATMOUNT_MNT_POINT: u64 = 0x0000_0010;
pub(crate) const STATMOUNT_FS_TYPE: u64 = 0x0000_0020;
pub(crate) const STATMOUNT_MNT_NS_ID: u64 = 0x0000_0040;
pub(crate) const STATMOUNT_SB_SOURCE: u64 = 0x0000_0200;
pub(crate) const STATMOUNT_SUPPORTED_MASK: u64 = 0x0000_1000;
pub(crate) const STATMOUNT_MNT_UIDMAP: u64 = 0x0000_2000;
pub(crate) const STATMOUNT_MNT_GIDMAP: u64 = 0x0000_4000;
pub(crate) const LSMT_ROOT: u64 = u64::MAX;
pub(crate) const LISTMOUNT_REVERSE: u32 = 1 << 0;

const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
// Linux 6.18 `FS_IOC_MEASURE_VERITY`: _IOWR('f', 134, struct fsverity_digest).
const FS_IOC_MEASURE_VERITY: libc::c_ulong = 0xc004_6686;
// Linux 6.18 `FS_IOC_ENABLE_VERITY`: _IOW('f', 133, struct fsverity_enable_arg).
const FS_IOC_ENABLE_VERITY: libc::c_ulong = 0x4080_6685;
const PIDFD_GET_MNT_NAMESPACE: libc::c_ulong = 0xff03;
const PIDFD_GET_NET_NAMESPACE: libc::c_ulong = 0xff04;
const PIDFD_GET_PID_NAMESPACE: libc::c_ulong = 0xff05;
const PIDFD_GET_USER_NAMESPACE: libc::c_ulong = 0xff09;
const PIDFD_GET_UTS_NAMESPACE: libc::c_ulong = 0xff0a;
const PIDFD_GET_INFO: libc::c_ulong = 0xc048_ff0b;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_STATMOUNT: libc::c_long = 457;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_LISTMOUNT: libc::c_long = 458;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_OPEN_TREE_ATTR: libc::c_long = 467;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("aos-sandbox-linux currently supports x86_64 and aarch64");

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OpenHow {
    pub(crate) flags: u64,
    pub(crate) mode: u64,
    pub(crate) resolve: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawMountAttr {
    pub(crate) attr_set: u64,
    pub(crate) attr_clr: u64,
    pub(crate) propagation: u64,
    pub(crate) userns_fd: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawPidfdInfo {
    pub(crate) mask: u64,
    pub(crate) cgroup_id: u64,
    pub(crate) pid: u32,
    pub(crate) tgid: u32,
    pub(crate) ppid: u32,
    pub(crate) ruid: u32,
    pub(crate) rgid: u32,
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    pub(crate) suid: u32,
    pub(crate) sgid: u32,
    pub(crate) fsuid: u32,
    pub(crate) fsgid: u32,
    pub(crate) exit_code: i32,
    pub(crate) coredump_mask: u32,
    pub(crate) spare: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MountIdRequest {
    pub(crate) size: u32,
    pub(crate) mount_namespace_fd: u32,
    pub(crate) mount_id: u64,
    pub(crate) parameter: u64,
    pub(crate) mount_namespace_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawStatMount {
    pub(crate) size: u32,
    pub(crate) mount_options: u32,
    pub(crate) mask: u64,
    pub(crate) device_major: u32,
    pub(crate) device_minor: u32,
    pub(crate) superblock_magic: u64,
    pub(crate) superblock_flags: u32,
    pub(crate) filesystem_type: u32,
    pub(crate) mount_id: u64,
    pub(crate) parent_mount_id: u64,
    pub(crate) old_mount_id: u32,
    pub(crate) old_parent_mount_id: u32,
    pub(crate) mount_attributes: u64,
    pub(crate) propagation: u64,
    pub(crate) peer_group: u64,
    pub(crate) master: u64,
    pub(crate) propagate_from: u64,
    pub(crate) mount_root: u32,
    pub(crate) mount_point: u32,
    pub(crate) mount_namespace_id: u64,
    pub(crate) filesystem_subtype: u32,
    pub(crate) superblock_source: u32,
    pub(crate) option_count: u32,
    pub(crate) option_array: u32,
    pub(crate) security_option_count: u32,
    pub(crate) security_option_array: u32,
    pub(crate) supported_mask: u64,
    pub(crate) uid_map_count: u32,
    pub(crate) uid_map: u32,
    pub(crate) gid_map_count: u32,
    pub(crate) gid_map: u32,
    pub(crate) spare: [u64; 43],
}

impl Default for RawStatMount {
    fn default() -> Self {
        // The UAPI requires every reserved field and the output size to start
        // at zero. All-zero is a valid bit pattern for this integer-only C
        // structure.
        // SAFETY: `RawStatMount` contains only integer scalars and arrays.
        unsafe { std::mem::zeroed() }
    }
}

const STAT_STRING_BYTES: usize = 16 * 1024;

#[repr(C)]
pub(crate) struct StatMountBuffer {
    pub(crate) header: RawStatMount,
    pub(crate) strings: [u8; STAT_STRING_BYTES],
}

impl StatMountBuffer {
    fn zeroed() -> Box<Self> {
        // The kernel treats this as an output byte buffer. Zeroing also
        // guarantees reserved UAPI fields are initialized as required.
        // SAFETY: both fields accept the all-zero bit pattern.
        Box::new(unsafe { std::mem::zeroed() })
    }
}

pub(crate) fn pidfd_open(pid: u32) -> Result<OwnedFd> {
    // SAFETY: `pidfd_open` receives scalar arguments and returns a new fd.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    fd_result(result, "pidfd_open")
}

pub(crate) fn pidfd_send_signal_zero(pidfd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: the borrowed fd remains live for the call; signal 0 has no
    // side-effect and the siginfo pointer is intentionally null.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    unit_result(result, "pidfd_send_signal")
}

pub(crate) fn pidfd_getfd(pidfd: BorrowedFd<'_>, target: RawFd) -> Result<OwnedFd> {
    // SAFETY: the pidfd remains borrowed for the call; the returned descriptor
    // is new and immediately transferred to `OwnedFd`.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target, 0_u32) };
    fd_result(result, "pidfd_getfd")
}

pub(crate) fn pidfd_info(pidfd: BorrowedFd<'_>) -> Result<RawPidfdInfo> {
    let mut info = RawPidfdInfo {
        mask: 0x7,
        ..RawPidfdInfo::default()
    };
    // SAFETY: `info` is a live, correctly-sized writable C structure and the
    // pidfd borrow spans the ioctl.
    let result = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_INFO, &mut info) };
    if result < 0 {
        return Err(Error::syscall("PIDFD_GET_INFO"));
    }
    Ok(info)
}

#[derive(Clone, Copy)]
pub(crate) enum NamespaceIoctl {
    Mount,
    Network,
    Pid,
    User,
    Uts,
}

pub(crate) fn pidfd_namespace(pidfd: BorrowedFd<'_>, namespace: NamespaceIoctl) -> Result<OwnedFd> {
    let request = match namespace {
        NamespaceIoctl::Mount => PIDFD_GET_MNT_NAMESPACE,
        NamespaceIoctl::Network => PIDFD_GET_NET_NAMESPACE,
        NamespaceIoctl::Pid => PIDFD_GET_PID_NAMESPACE,
        NamespaceIoctl::User => PIDFD_GET_USER_NAMESPACE,
        NamespaceIoctl::Uts => PIDFD_GET_UTS_NAMESPACE,
    };
    // SAFETY: `_IO` namespace requests take no pointer argument, borrow the
    // pidfd, and return a new close-on-exec namespace descriptor.
    let result = unsafe { libc::ioctl(pidfd.as_raw_fd(), request) };
    fd_result(libc::c_long::from(result), "pidfd namespace ioctl")
}

pub(crate) fn is_namespace(fd: BorrowedFd<'_>) -> Result<bool> {
    Ok(filesystem_type(fd)? == NSFS_MAGIC)
}

pub(crate) fn filesystem_type(fd: BorrowedFd<'_>) -> Result<libc::c_long> {
    // SAFETY: `statfs` is fully initialized by `fstatfs`; the fd borrow spans
    // the call and the pointer is writable and correctly aligned.
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: described above.
    let result = unsafe { libc::fstatfs(fd.as_raw_fd(), std::ptr::addr_of_mut!(statfs)) };
    if result < 0 {
        return Err(Error::syscall("fstatfs"));
    }
    Ok(statfs.f_type)
}

pub(crate) fn namespace_type(fd: BorrowedFd<'_>) -> Result<i32> {
    // SAFETY: `NS_GET_NSTYPE` takes no pointer argument and only observes the
    // namespace descriptor borrowed for the duration of the ioctl.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), NS_GET_NSTYPE) };
    if result < 0 {
        return Err(Error::syscall("NS_GET_NSTYPE"));
    }
    Ok(result)
}

pub(crate) fn setns(fd: BorrowedFd<'_>, namespace_type: i32) -> Result<()> {
    // SAFETY: the descriptor remains borrowed for the call and the namespace
    // type is obtained from the closed `NamespaceKind` enum. Process-level
    // single-threading is enforced by the public token required by the caller.
    let result = unsafe { libc::setns(fd.as_raw_fd(), namespace_type) };
    if result < 0 {
        Err(Error::syscall("setns"))
    } else {
        Ok(())
    }
}

pub(crate) fn fchdir(fd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: the descriptor remains borrowed for the complete libc call.
    let result = unsafe { libc::fchdir(fd.as_raw_fd()) };
    unit_result(result.into(), "fchdir")
}

pub(crate) fn chroot_dot() -> Result<()> {
    // SAFETY: the static C string is NUL terminated and valid for the call.
    let result = unsafe { libc::chroot(c".".as_ptr()) };
    unit_result(result.into(), "chroot")
}

pub(crate) fn chdir_root() -> Result<()> {
    // SAFETY: the static C string is NUL terminated and valid for the call.
    let result = unsafe { libc::chdir(c"/".as_ptr()) };
    unit_result(result.into(), "chdir")
}

pub(crate) fn umount_detach(path: &CStr) -> Result<()> {
    // SAFETY: the path remains a live NUL-terminated C string for the call.
    let result = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
    unit_result(result.into(), "umount2")
}

pub(crate) fn fstat(fd: BorrowedFd<'_>) -> Result<libc::stat> {
    // SAFETY: `stat` is an output structure with an all-zero valid bit pattern.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the fd borrow and writable output live for the complete call.
    let result = unsafe { libc::fstat(fd.as_raw_fd(), std::ptr::addr_of_mut!(stat)) };
    if result < 0 {
        return Err(Error::syscall("fstat"));
    }
    Ok(stat)
}

pub(crate) fn get_seals(fd: BorrowedFd<'_>) -> Result<libc::c_int> {
    // SAFETY: `F_GET_SEALS` only observes the file description borrowed for
    // the duration of this call and takes no pointer argument.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if result < 0 {
        Err(Error::syscall("fcntl(F_GET_SEALS)"))
    } else {
        Ok(result)
    }
}

pub(crate) fn get_status_flags(fd: BorrowedFd<'_>) -> Result<libc::c_int> {
    // SAFETY: `F_GETFL` only observes the borrowed file description.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if result < 0 {
        Err(Error::syscall("fcntl(F_GETFL)"))
    } else {
        Ok(result)
    }
}

pub(crate) fn measure_verity(fd: BorrowedFd<'_>) -> Result<VerityMeasurement> {
    let mut measurement = RawVerityDigest {
        algorithm: 0,
        digest_size: 64,
        digest: [0; 64],
    };
    // SAFETY: the borrowed descriptor and writable fixed-capacity response
    // remain live for the ioctl. `digest_size` advertises the exact tail
    // capacity following the Linux `fsverity_digest` header.
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_MEASURE_VERITY,
            std::ptr::addr_of_mut!(measurement),
        )
    };
    if result < 0 {
        return Err(Error::syscall("ioctl(FS_IOC_MEASURE_VERITY)"));
    }
    if result != 0 {
        return Err(Error::MalformedKernelResponse {
            object: "fs-verity measurement",
            message: "ioctl returned a positive success value".to_string(),
        });
    }
    let length = usize::from(measurement.digest_size);
    if length > measurement.digest.len() {
        return Err(Error::MalformedKernelResponse {
            object: "fs-verity measurement",
            message: "kernel returned an oversized digest".to_string(),
        });
    }
    Ok(VerityMeasurement {
        algorithm: measurement.algorithm,
        length,
        digest: measurement.digest,
    })
}

pub(crate) fn enable_verity_sha256_4096(fd: BorrowedFd<'_>) -> Result<()> {
    let argument = RawVerityEnableArg {
        version: 1,
        hash_algorithm: 1,
        block_size: 4096,
        salt_size: 0,
        salt_ptr: 0,
        signature_size: 0,
        reserved1: 0,
        signature_ptr: 0,
        reserved2: [0; 11],
    };
    // SAFETY: the fixed-layout argument remains borrowed for the complete
    // ioctl. All optional pointer/length pairs and reserved fields are zero.
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_ENABLE_VERITY,
            std::ptr::addr_of!(argument),
        )
    };
    if result < 0 {
        return Err(Error::syscall("ioctl(FS_IOC_ENABLE_VERITY)"));
    }
    if result != 0 {
        return Err(Error::MalformedKernelResponse {
            object: "fs-verity enable",
            message: "ioctl returned a positive success value".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn fsync(fd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: `fsync` only observes and synchronizes the borrowed file
    // description for the duration of the call.
    let result = unsafe { libc::fsync(fd.as_raw_fd()) };
    if result < 0 {
        Err(Error::syscall("fsync"))
    } else {
        Ok(())
    }
}

pub(crate) fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no pointer arguments or process-state mutation.
    unsafe { libc::geteuid() }
}

pub(crate) fn renameat2(
    old_directory: BorrowedFd<'_>,
    old_name: &CStr,
    new_directory: BorrowedFd<'_>,
    new_name: &CStr,
    flags: u32,
) -> Result<()> {
    // SAFETY: both NUL-terminated names and borrowed directory descriptors
    // remain valid for the complete syscall. The caller supplies a vendored,
    // validated flag set.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_directory.as_raw_fd(),
            old_name.as_ptr(),
            new_directory.as_raw_fd(),
            new_name.as_ptr(),
            flags,
        )
    };
    unit_result(result, "renameat2")
}

pub(crate) fn map_readonly_shared(fd: BorrowedFd<'_>, length: usize) -> Result<*mut libc::c_void> {
    // SAFETY: the descriptor remains borrowed for the call, the nonzero
    // length is admitted by the caller, and a null address asks the kernel to
    // choose a fresh range. The returned range is owned by the caller.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if address == libc::MAP_FAILED {
        Err(Error::syscall("mmap(read-only shared immutable file)"))
    } else {
        Ok(address)
    }
}

pub(crate) fn unmap(address: *mut libc::c_void, length: usize) {
    // SAFETY: callers pass the exact address and length returned by
    // `map_readonly_shared` and invoke this exactly once during drop.
    let _ = unsafe { libc::munmap(address, length) };
}

pub(crate) fn statx_unique_mount_id(fd: BorrowedFd<'_>) -> Result<u64> {
    // `STATX_MNT_ID_UNIQUE` was added in Linux 6.8. Unlike `STATX_MNT_ID`,
    // the returned identifier is not reused during the running kernel's
    // lifetime and is therefore suitable for statmount requests and durable
    // broker observations.
    // SAFETY: `statx` is an output structure with an all-zero valid bit
    // pattern. The descriptor borrow and writable output span the syscall,
    // and the static empty pathname is NUL terminated.
    let mut statx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: described above. `AT_EMPTY_PATH` directs the kernel to inspect
    // the object pinned by `fd`, avoiding pathname re-resolution.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd.as_raw_fd(),
            c"".as_ptr(),
            AT_EMPTY_PATH,
            STATX_MNT_ID_UNIQUE,
            std::ptr::addr_of_mut!(statx),
        )
    };
    unit_result(result, "statx(STATX_MNT_ID_UNIQUE)")?;
    if statx.stx_mask & STATX_MNT_ID_UNIQUE != STATX_MNT_ID_UNIQUE {
        return Err(Error::MalformedKernelResponse {
            object: "statx",
            message: "kernel omitted STATX_MNT_ID_UNIQUE".to_string(),
        });
    }
    Ok(statx.stx_mnt_id)
}

pub(crate) fn ensure_cloexec(fd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: `F_GETFD` and `F_SETFD` operate only on the borrowed descriptor
    // and do not dereference an argument pointer.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(Error::syscall("fcntl(F_GETFD)"));
    }
    // SAFETY: as above; the scalar flag value preserves all existing bits.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(Error::syscall("fcntl(F_SETFD)"));
    }
    Ok(())
}

pub(crate) fn openat2(directory: BorrowedFd<'_>, path: &CStr, how: &OpenHow) -> Result<OwnedFd> {
    // SAFETY: the directory, C string, and immutable `open_how` all remain
    // live for the syscall; a successful return is a newly-owned fd.
    let result = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            path.as_ptr(),
            how,
            size_of::<OpenHow>(),
        )
    };
    fd_result(result, "openat2")
}

pub(crate) fn open_tree(path: BorrowedFd<'_>, recursive: bool) -> Result<OwnedFd> {
    let flags = OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC
        | AT_EMPTY_PATH
        | if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: the source descriptor remains borrowed, the empty C string is
    // static, and a successful result is a new detached mount fd.
    let result =
        unsafe { libc::syscall(libc::SYS_open_tree, path.as_raw_fd(), c"".as_ptr(), flags) };
    fd_result(result, "open_tree")
}

pub(crate) fn open_tree_attr(
    path: BorrowedFd<'_>,
    recursive: bool,
    attributes: &RawMountAttr,
) -> Result<OwnedFd> {
    let flags = OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC
        | AT_EMPTY_PATH
        | if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: all pointers and descriptor borrows remain valid for the call;
    // the successful result is a newly-owned detached mount descriptor.
    let result = unsafe {
        libc::syscall(
            SYS_OPEN_TREE_ATTR,
            path.as_raw_fd(),
            c"".as_ptr(),
            flags,
            attributes,
            size_of::<RawMountAttr>(),
        )
    };
    fd_result(result, "open_tree_attr")
}

pub(crate) fn mount_setattr(
    mount: BorrowedFd<'_>,
    recursive: bool,
    attributes: &RawMountAttr,
) -> Result<()> {
    let flags = AT_EMPTY_PATH | if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: all borrowed inputs remain live and the attribute structure has
    // the exact version-0 UAPI layout.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount.as_raw_fd(),
            c"".as_ptr(),
            flags,
            attributes,
            size_of::<RawMountAttr>(),
        )
    };
    unit_result(result, "mount_setattr")
}

pub(crate) fn move_mount(
    source: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    beneath: bool,
) -> Result<()> {
    // SAFETY: both descriptors and both static empty strings remain valid for
    // the syscall. The flags request descriptor-only source and destination.
    let result = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            source.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH
                | MOVE_MOUNT_T_EMPTY_PATH
                | if beneath { MOVE_MOUNT_BENEATH } else { 0 },
        )
    };
    unit_result(result, "move_mount")
}

pub(crate) fn fsopen(filesystem: &CStr) -> Result<OwnedFd> {
    // SAFETY: the filesystem name is a live C string and the result is a new
    // filesystem-context descriptor.
    let result = unsafe { libc::syscall(libc::SYS_fsopen, filesystem.as_ptr(), FSOPEN_CLOEXEC) };
    fd_result(result, "fsopen")
}

pub(crate) fn fsconfig(
    context: BorrowedFd<'_>,
    command: u32,
    key: Option<&CStr>,
    value: Option<&CStr>,
    auxiliary: RawFd,
) -> Result<()> {
    // SAFETY: the context and optional strings remain borrowed for the call;
    // commands determine whether each nullable pointer and scalar are read.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            command,
            key.map_or(std::ptr::null(), CStr::as_ptr),
            value.map_or(std::ptr::null(), CStr::as_ptr),
            auxiliary,
        )
    };
    unit_result(result, "fsconfig")
}

pub(crate) fn fsmount(context: BorrowedFd<'_>) -> Result<OwnedFd> {
    // SAFETY: the context is borrowed for the call and success returns a new
    // detached mount descriptor.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            context.as_raw_fd(),
            FSMOUNT_CLOEXEC,
            0_u32,
        )
    };
    fd_result(result, "fsmount")
}

pub(crate) fn statmount(request: &MountIdRequest) -> Result<Box<StatMountBuffer>> {
    let mut output = StatMountBuffer::zeroed();
    // SAFETY: request is immutable and live; output is a writable contiguous
    // buffer whose prefix exactly matches `struct statmount` version 0.
    let result = unsafe {
        libc::syscall(
            SYS_STATMOUNT,
            request,
            std::ptr::from_mut(output.as_mut()),
            size_of::<StatMountBuffer>(),
            0_u32,
        )
    };
    unit_result(result, "statmount")?;
    Ok(output)
}

pub(crate) fn listmount(request: &MountIdRequest, output: &mut [u64], flags: u32) -> Result<usize> {
    // SAFETY: request is immutable and live; the mutable slice supplies its
    // exact element count and remains exclusively borrowed for the call.
    let result = unsafe {
        libc::syscall(
            SYS_LISTMOUNT,
            request,
            output.as_mut_ptr(),
            output.len(),
            flags,
        )
    };
    if result < 0 {
        return Err(Error::syscall("listmount"));
    }
    usize::try_from(result).map_err(|_| Error::MalformedKernelResponse {
        object: "listmount",
        message: "negative or oversized result count".to_string(),
    })
}

pub(crate) fn prepare_seqpacket(fd: BorrowedFd<'_>) -> Result<()> {
    let socket_type = socket_integer_option(fd, libc::SO_TYPE, "getsockopt(SO_TYPE)")?;
    if socket_type != libc::SOCK_SEQPACKET {
        return Err(Error::WrongDescriptorType {
            expected: "Unix SOCK_SEQPACKET socket",
        });
    }
    let domain = socket_integer_option(fd, libc::SO_DOMAIN, "getsockopt(SO_DOMAIN)")?;
    if domain != libc::AF_UNIX {
        return Err(Error::WrongDescriptorType {
            expected: "Unix SOCK_SEQPACKET socket",
        });
    }
    let accepts_connections =
        socket_integer_option(fd, libc::SO_ACCEPTCONN, "getsockopt(SO_ACCEPTCONN)")?;
    if accepts_connections != 0 {
        return Err(Error::WrongDescriptorType {
            expected: "connected Unix SOCK_SEQPACKET socket, not a listener",
        });
    }
    require_connected_unix_peer(fd)?;

    ensure_cloexec(fd)?;
    // SAFETY: F_GETFL observes the borrowed descriptor and takes no pointer.
    let current = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if current < 0 {
        return Err(Error::syscall("fcntl(F_GETFL)"));
    }
    // SAFETY: F_SETFL consumes the scalar flags while the descriptor is live.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, current | libc::O_NONBLOCK) };
    unit_result(result.into(), "fcntl(F_SETFL, O_NONBLOCK)")
}

fn require_connected_unix_peer(fd: BorrowedFd<'_>) -> Result<()> {
    // All-zero is valid for sockaddr_storage and lets the kernel fill the
    // peer address without relying on a pathname representation.
    // SAFETY: sockaddr_storage is a plain C output structure.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the address and length are writable and live for the call. A
    // successful getpeername positively establishes connected socket state.
    let result = unsafe {
        libc::getpeername(
            fd.as_raw_fd(),
            std::ptr::addr_of_mut!(address).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    unit_result(result.into(), "getpeername(SOCK_SEQPACKET)")?;
    if usize::try_from(length).unwrap_or(0) < size_of::<libc::sa_family_t>()
        || i32::from(address.ss_family) != libc::AF_UNIX
    {
        return Err(Error::MalformedKernelResponse {
            object: "SOCK_SEQPACKET peer address",
            message: "getpeername returned a missing or non-Unix peer".to_string(),
        });
    }
    Ok(())
}

fn socket_integer_option(fd: BorrowedFd<'_>, option: i32, operation: &'static str) -> Result<i32> {
    let mut value = 0_i32;
    let mut length = size_of::<i32>() as libc::socklen_t;
    // SAFETY: the output integer and its length are writable and live for the
    // call, and the descriptor borrow spans the call.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::addr_of_mut!(value).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    unit_result(result.into(), operation)?;
    if length as usize != size_of::<i32>() {
        return Err(Error::MalformedKernelResponse {
            object: "socket option",
            message: format!("{operation} returned an unexpected length"),
        });
    }
    Ok(value)
}

pub(crate) fn enable_seqpacket_identity(fd: BorrowedFd<'_>) -> Result<()> {
    set_socket_bool(fd, libc::SO_PASSCRED, "setsockopt(SO_PASSCRED)")?;
    set_socket_bool(fd, SO_PASSPIDFD, "setsockopt(SO_PASSPIDFD)")
}

pub(crate) fn peer_credentials(fd: BorrowedFd<'_>) -> Result<libc::ucred> {
    // All-zero is valid for this integer-only output structure.
    // SAFETY: `ucred` contains only integer scalars.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output structure and length remain writable and live for
    // the call, and the connected socket descriptor is borrowed.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    unit_result(result.into(), "getsockopt(SO_PEERCRED)")?;
    if length as usize != size_of::<libc::ucred>() {
        return Err(Error::MalformedKernelResponse {
            object: "SO_PEERCRED",
            message: "kernel returned an unexpected credential length".to_string(),
        });
    }
    Ok(credentials)
}

pub(crate) fn peer_pidfd(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let mut peer_fd = -1_i32;
    let mut length = size_of::<RawFd>() as libc::socklen_t;
    // SAFETY: the output integer and length remain writable and live for the
    // call. On success Linux installs a new pidfd in `peer_fd`.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            std::ptr::addr_of_mut!(peer_fd).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    unit_result(result.into(), "getsockopt(SO_PEERPIDFD)")?;
    if peer_fd < 0 {
        return Err(Error::MalformedKernelResponse {
            object: "SO_PEERPIDFD",
            message: "kernel returned a negative descriptor".to_string(),
        });
    }
    // Adopt before validating the returned length so every successful kernel
    // installation is owned and closed on all later error paths.
    // SAFETY: SO_PEERPIDFD returned a fresh descriptor in this process, and
    // ownership has not been transferred elsewhere.
    let peer_fd = unsafe { OwnedFd::from_raw_fd(peer_fd) };
    ensure_cloexec(peer_fd.as_fd())?;
    if length as usize != size_of::<RawFd>() {
        return Err(Error::MalformedKernelResponse {
            object: "SO_PEERPIDFD",
            message: "kernel returned an unexpected descriptor length".to_string(),
        });
    }
    Ok(peer_fd)
}

fn set_socket_bool(fd: BorrowedFd<'_>, option: i32, operation: &'static str) -> Result<()> {
    let enabled = 1_i32;
    // SAFETY: the scalar option value remains live and correctly sized for
    // the complete call; the socket descriptor is borrowed.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::addr_of!(enabled).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    unit_result(result.into(), operation)
}

pub(crate) fn send_seqpacket(fd: BorrowedFd<'_>, payload: &[u8]) -> Result<usize> {
    // SAFETY: the byte slice remains readable and the descriptor remains
    // borrowed for the complete nonblocking send.
    let result = unsafe {
        libc::send(
            fd.as_raw_fd(),
            payload.as_ptr().cast(),
            payload.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if result < 0 {
        return Err(Error::syscall("send(SOCK_SEQPACKET)"));
    }
    usize::try_from(result).map_err(|_| Error::MalformedKernelResponse {
        object: "SOCK_SEQPACKET send",
        message: "kernel returned a negative or oversized byte count".to_string(),
    })
}

pub(crate) fn recv_seqpacket(
    fd: BorrowedFd<'_>,
    payload: &mut [u8],
    flags: i32,
) -> Result<RawSeqpacketMessage> {
    let mut byte = 0_u8;
    let (payload_pointer, payload_length) = if payload.is_empty() {
        (std::ptr::addr_of_mut!(byte).cast(), 0)
    } else {
        (payload.as_mut_ptr().cast(), payload.len())
    };
    let mut vector = libc::iovec {
        iov_base: payload_pointer,
        iov_len: payload_length,
    };
    let mut control = [0_usize; SEQPACKET_CONTROL_BYTES / size_of::<usize>()];
    // The all-zero bit pattern is the required initial state for `msghdr`.
    // SAFETY: `msghdr` contains only pointers and integer fields for which
    // null/zero is valid.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = std::ptr::addr_of_mut!(vector);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = SEQPACKET_CONTROL_BYTES;

    // SAFETY: every pointer in `message` targets live writable storage for
    // the call. The kernel initializes returned payload/control lengths and
    // flags. MSG_CMSG_CLOEXEC closes the exec race before fd adoption.
    let result = unsafe {
        libc::recvmsg(
            fd.as_raw_fd(),
            std::ptr::addr_of_mut!(message),
            flags | libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if result < 0 {
        return Err(Error::syscall("recvmsg(SOCK_SEQPACKET)"));
    }
    let bytes = usize::try_from(result).map_err(|_| Error::MalformedKernelResponse {
        object: "SOCK_SEQPACKET receive",
        message: "kernel returned a negative or oversized byte count".to_string(),
    })?;
    let ancillary = decode_control(&control, message.msg_controllen)?;
    Ok(RawSeqpacketMessage {
        bytes,
        flags: message.msg_flags,
        ancillary,
    })
}

fn decode_control(control: &[usize], used: usize) -> Result<Vec<RawAncillary>> {
    if used > std::mem::size_of_val(control) {
        return Err(Error::MalformedKernelResponse {
            object: "SOCK_SEQPACKET ancillary data",
            message: "kernel returned an oversized control length".to_string(),
        });
    }
    let bytes = control.as_ptr().cast::<u8>();
    let header_size = size_of::<libc::cmsghdr>();
    let data_offset = cmsg_align(header_size);
    let mut offset = 0;
    let mut output = Vec::new();
    while offset + header_size <= used {
        // SAFETY: bounds above cover a complete header. `read_unaligned`
        // avoids assuming stronger alignment for subsequent headers.
        let header = unsafe { std::ptr::read_unaligned(bytes.add(offset).cast::<libc::cmsghdr>()) };
        let length = header.cmsg_len;
        if length < data_offset || length > used - offset {
            return Err(Error::MalformedKernelResponse {
                object: "SOCK_SEQPACKET ancillary data",
                message: "invalid cmsghdr length".to_string(),
            });
        }
        let payload_length = length - data_offset;
        // SAFETY: the checked cmsg length covers the payload range.
        let payload =
            unsafe { std::slice::from_raw_parts(bytes.add(offset + data_offset), payload_length) };
        output.push(decode_cmsg(header.cmsg_level, header.cmsg_type, payload));
        offset = offset.saturating_add(cmsg_align(length));
    }
    Ok(output)
}

fn decode_cmsg(level: i32, kind: i32, payload: &[u8]) -> RawAncillary {
    if level != libc::SOL_SOCKET {
        return RawAncillary::Unknown { level, kind };
    }
    if kind == libc::SCM_CREDENTIALS && payload.len() == size_of::<libc::ucred>() {
        // SAFETY: the exact length was checked and unaligned reads are valid.
        return RawAncillary::Credentials(unsafe {
            std::ptr::read_unaligned(payload.as_ptr().cast::<libc::ucred>())
        });
    }
    if kind == libc::SCM_RIGHTS || kind == SCM_PIDFD {
        let descriptors = adopt_descriptors(payload);
        if kind == SCM_PIDFD && payload.len() == size_of::<RawFd>() && descriptors.len() == 1 {
            let mut descriptors = descriptors;
            return match descriptors.pop() {
                Some(fd) => RawAncillary::PidFd(fd),
                None => RawAncillary::Malformed(descriptors),
            };
        }
        return if kind == libc::SCM_RIGHTS && payload.len().is_multiple_of(size_of::<RawFd>()) {
            RawAncillary::Rights(descriptors)
        } else {
            RawAncillary::Malformed(descriptors)
        };
    }
    RawAncillary::Unknown { level, kind }
}

fn adopt_descriptors(payload: &[u8]) -> Vec<OwnedFd> {
    payload
        .chunks_exact(size_of::<RawFd>())
        .filter_map(|bytes| {
            // SAFETY: a complete native fd integer is present. recvmsg
            // installed each non-negative descriptor into this process and
            // ownership has not otherwise been transferred.
            let raw = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<RawFd>()) };
            (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) })
        })
        .collect()
}

const fn cmsg_align(length: usize) -> usize {
    let alignment = size_of::<usize>();
    (length + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
pub(crate) fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: the output array contains space for exactly two descriptors;
    // success transfers both newly-created descriptors to this process.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    };
    unit_result(result.into(), "socketpair(SOCK_SEQPACKET)")?;
    // SAFETY: socketpair returned two distinct fresh descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

#[cfg(test)]
pub(crate) fn unconnected_seqpacket() -> Result<OwnedFd> {
    // SAFETY: socket returns one fresh descriptor on success.
    let result = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    fd_result(result.into(), "socket(SOCK_SEQPACKET)")
}

#[cfg(test)]
pub(crate) fn seqpacket_listener() -> Result<OwnedFd> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_NAME: AtomicU64 = AtomicU64::new(0);

    let socket = unconnected_seqpacket()?;
    // All-zero makes sun_path[0] the abstract-namespace marker.
    // SAFETY: sockaddr_un is a plain C structure accepting all-zero bytes.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = format!(
        "aos-seqpacket-{}-{}",
        std::process::id(),
        NEXT_NAME.fetch_add(1, Ordering::Relaxed)
    );
    if name.len() + 1 > address.sun_path.len() {
        return Err(Error::invalid(
            "abstract socket name",
            "test name is too long",
        ));
    }
    for (destination, source) in address.sun_path[1..].iter_mut().zip(name.bytes()) {
        *destination = source as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
    // SAFETY: the address length covers the family, abstract marker, and
    // initialized name bytes; the socket remains borrowed for the call.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            length as libc::socklen_t,
        )
    };
    unit_result(result.into(), "bind(abstract SOCK_SEQPACKET)")?;
    // SAFETY: listen consumes only a descriptor and scalar backlog.
    let result = unsafe { libc::listen(socket.as_raw_fd(), 1) };
    unit_result(result.into(), "listen(SOCK_SEQPACKET)")?;
    Ok(socket)
}

#[cfg(test)]
pub(crate) fn send_seqpacket_rights(
    socket: BorrowedFd<'_>,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> Result<()> {
    let raw: Vec<RawFd> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
    let data_bytes = std::mem::size_of_val(raw.as_slice());
    let control_bytes = cmsg_align(size_of::<libc::cmsghdr>()) + cmsg_align(data_bytes);
    let mut control = vec![0_usize; control_bytes.div_ceil(size_of::<usize>())];
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: all-zero initializes optional msghdr pointers and lengths.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = std::ptr::addr_of_mut!(vector);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
    // SAFETY: the aligned control allocation covers the header and payload;
    // both remain live for sendmsg and contain borrowed descriptor integers.
    unsafe {
        let header = message.msg_control.cast::<libc::cmsghdr>();
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = cmsg_align(size_of::<libc::cmsghdr>()) + data_bytes;
        std::ptr::copy_nonoverlapping(
            raw.as_ptr().cast::<u8>(),
            message
                .msg_control
                .cast::<u8>()
                .add(cmsg_align(size_of::<libc::cmsghdr>())),
            data_bytes,
        );
    }
    // SAFETY: the fully initialized message borrows all referenced storage for
    // the duration of this nonblocking call.
    let result = unsafe {
        libc::sendmsg(
            socket.as_raw_fd(),
            std::ptr::addr_of!(message),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if result < 0 {
        Err(Error::syscall("sendmsg(SCM_RIGHTS)"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn is_cloexec(fd: BorrowedFd<'_>) -> Result<bool> {
    // SAFETY: F_GETFD only observes a descriptor borrowed for the call.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        Err(Error::syscall("fcntl(F_GETFD)"))
    } else {
        Ok(flags & libc::FD_CLOEXEC != 0)
    }
}

#[cfg(test)]
pub(crate) fn raw_fd_is_open(fd: RawFd) -> bool {
    // SAFETY: F_GETFD only observes the integer descriptor table entry.
    let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    result >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
}

#[cfg(test)]
pub(crate) fn duplicate_at_least(fd: BorrowedFd<'_>, minimum: RawFd) -> Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC borrows the source and returns a fresh owned fd.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    fd_result(result.into(), "fcntl(F_DUPFD_CLOEXEC)")
}

#[cfg(test)]
pub(crate) fn create_sealable_memfd() -> Result<OwnedFd> {
    // SAFETY: the static name is NUL terminated and successful memfd_create
    // returns a fresh descriptor.
    let result = unsafe {
        libc::memfd_create(
            c"aos-index-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    fd_result(result.into(), "memfd_create")
}

#[cfg(test)]
pub(crate) fn add_seals(fd: BorrowedFd<'_>, seals: libc::c_int) -> Result<()> {
    // SAFETY: F_ADD_SEALS consumes only the scalar mask and borrowed fd.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    unit_result(result.into(), "fcntl(F_ADD_SEALS)")
}

fn fd_result(result: libc::c_long, operation: &'static str) -> Result<OwnedFd> {
    if result < 0 {
        return Err(Error::syscall(operation));
    }
    let raw = RawFd::try_from(result).map_err(|_| Error::MalformedKernelResponse {
        object: "file descriptor",
        message: format!("{operation} returned an out-of-range descriptor"),
    })?;
    // SAFETY: each caller invokes a syscall documented to return a fresh fd on
    // success, and ownership has not been transferred elsewhere.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    ensure_cloexec(fd.as_fd())?;
    Ok(fd)
}

fn unit_result(result: libc::c_long, operation: &'static str) -> Result<()> {
    if result < 0 {
        Err(Error::syscall(operation))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_uapi_layouts_match_linux_6_18() {
        assert_eq!(size_of::<OpenHow>(), 24);
        assert_eq!(size_of::<RawMountAttr>(), 32);
        assert_eq!(size_of::<RawPidfdInfo>(), 72);
        assert_eq!(size_of::<MountIdRequest>(), 32);
        assert_eq!(size_of::<RawStatMount>(), 512);
        assert_eq!(size_of::<StatMountBuffer>(), 512 + STAT_STRING_BYTES);
        assert_eq!(std::mem::offset_of!(RawVerityDigest, digest), 4);
        assert_eq!(size_of::<RawVerityDigest>(), 68);
        assert_eq!(size_of::<RawVerityEnableArg>(), 128);
        assert_eq!(FS_IOC_MEASURE_VERITY, 0xc004_6686);
        assert_eq!(FS_IOC_ENABLE_VERITY, 0x4080_6685);
        assert_eq!(RENAME_NOREPLACE, 1);
    }

    #[test]
    fn vendored_syscall_numbers_match_supported_architectures() {
        assert_eq!(SYS_STATMOUNT, 457);
        assert_eq!(SYS_LISTMOUNT, 458);
        assert_eq!(SYS_OPEN_TREE_ATTR, 467);
    }

    #[test]
    fn vendored_socket_options_match_linux_6_18() {
        assert_eq!(SO_PASSPIDFD, 76);
        assert_eq!(SO_PEERPIDFD, 77);
        assert_eq!(SCM_PIDFD, 0x04);
    }
}
