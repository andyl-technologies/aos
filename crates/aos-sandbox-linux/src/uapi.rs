//! Private Linux 6.18 UAPI and syscall shims.
//!
//! This is the only module in the crate that contains `unsafe`. Each call
//! converts successful descriptor returns immediately into [`OwnedFd`] and
//! borrows every input for the complete syscall duration.

use std::ffi::CStr;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::{Error, Result};

pub(crate) const RESOLVE_NO_XDEV: u64 = 0x01;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(crate) const RESOLVE_BENEATH: u64 = 0x08;

pub(crate) const OPEN_TREE_CLONE: u32 = 1;
pub(crate) const OPEN_TREE_CLOEXEC: u32 = libc::O_CLOEXEC as u32;
pub(crate) const AT_EMPTY_PATH: u32 = 0x1000;
pub(crate) const AT_RECURSIVE: u32 = 0x8000;
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

const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
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
    // SAFETY: `statfs` is fully initialized by `fstatfs`; the fd borrow spans
    // the call and the pointer is writable and correctly aligned.
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: described above.
    let result = unsafe { libc::fstatfs(fd.as_raw_fd(), std::ptr::addr_of_mut!(statfs)) };
    if result < 0 {
        return Err(Error::syscall("fstatfs(namespace)"));
    }
    Ok(statfs.f_type == NSFS_MAGIC)
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

pub(crate) fn listmount(request: &MountIdRequest, output: &mut [u64]) -> Result<usize> {
    // SAFETY: request is immutable and live; the mutable slice supplies its
    // exact element count and remains exclusively borrowed for the call.
    let result = unsafe {
        libc::syscall(
            SYS_LISTMOUNT,
            request,
            output.as_mut_ptr(),
            output.len(),
            0_u32,
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
    }

    #[test]
    fn vendored_syscall_numbers_match_supported_architectures() {
        assert_eq!(SYS_STATMOUNT, 457);
        assert_eq!(SYS_LISTMOUNT, 458);
        assert_eq!(SYS_OPEN_TREE_ATTR, 467);
    }
}
