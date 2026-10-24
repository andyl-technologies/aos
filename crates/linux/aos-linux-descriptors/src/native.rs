//! Canonical native descriptor primitives and Linux pidfs/socket layouts.
//!
//! Borrowed queries confer no Sandbox or service role. Raw descriptor-return
//! adoption is explicitly unsafe and requires exclusive fresh native ownership.

use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use crate::{Error, Result};

/// Retains the canonical Linux SO_COOKIE ABI number.
pub const SO_COOKIE: libc::c_int = 57;

/// Retains the canonical Linux SO_PEERPIDFD ABI number.
pub const SO_PEERPIDFD: libc::c_int = 77;

/// Retains the canonical Linux SO_PASSPIDFD ABI number.
pub const SO_PASSPIDFD: libc::c_int = 76;

/// Retains the canonical Linux PIDFD_GET_INFO ABI number.
pub const PIDFD_GET_INFO: libc::c_ulong = 0xc048_ff0b;

/// Matches the exact Linux pidfs ioctl output layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawPidfdInfo {
    /// Native `mask` output field.
    pub mask: u64,
    /// Native `cgroup_id` output field.
    pub cgroup_id: u64,
    /// Native `pid` output field.
    pub pid: u32,
    /// Native `tgid` output field.
    pub tgid: u32,
    /// Native `ppid` output field.
    pub ppid: u32,
    /// Native `ruid` output field.
    pub ruid: u32,
    /// Native `rgid` output field.
    pub rgid: u32,
    /// Native `euid` output field.
    pub euid: u32,
    /// Native `egid` output field.
    pub egid: u32,
    /// Native `suid` output field.
    pub suid: u32,
    /// Native `sgid` output field.
    pub sgid: u32,
    /// Native `fsuid` output field.
    pub fsuid: u32,
    /// Native `fsgid` output field.
    pub fsgid: u32,
    /// Native `exit_code` output field.
    pub exit_code: i32,
    /// Native `coredump_mask` output field.
    pub coredump_mask: u32,
    /// Native `spare` output field.
    pub spare: u32,
}
/// Opens and enforces CLOEXEC on one process pin.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_open(pid: u32) -> Result<OwnedFd> {
    let result = pidfd_open_raw_result(pid);
    // SAFETY: the preceding native call returned a fresh unowned FD.
    unsafe { fd_result(result, "pidfd_open") }
}
/// Returns one actual current-process pin before the separate flag check.
// The current-self owner parks this fresh descriptor before either flag check.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_open_current_original() -> Result<OwnedFd> {
    pidfd_open_original(std::process::id())
}
/// Returns one actual process pin before the separate flag check.
// Selected owners park any fresh pidfd before the ordinary flag/type passes.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_open_original(pid: u32) -> Result<OwnedFd> {
    let result = pidfd_open_raw_result(pid);
    // SAFETY: the native return is fresh and has no existing descriptor owner.
    unsafe { adopt_created_fd(result, "pidfd_open") }
}
/// Returns the raw native pidfd-open result without adopting or checking it.
pub fn pidfd_open_raw_result(pid: u32) -> libc::c_long {
    // SAFETY: `pidfd_open` receives scalar arguments and returns a new fd.
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) }
}
/// Sends the specified signal to the pinned thread group.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_send_thread_group_signal(pidfd: BorrowedFd<'_>, signal: u8) -> Result<()> {
    const PIDFD_SIGNAL_THREAD_GROUP: u32 = 1 << 1;
    // SAFETY: the descriptor stays borrowed, all other arguments are scalar,
    // and the null siginfo asks the kernel to construct the sender identity.
    // Explicit scope never interprets this pidfd as a process-group selector.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            u32::from(signal),
            std::ptr::null::<libc::siginfo_t>(),
            PIDFD_SIGNAL_THREAD_GROUP,
        )
    };
    unit_result(result, "pidfd_send_signal thread group")
}
/// Duplicates one target descriptor through the kernel ptrace check.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_getfd(pidfd: BorrowedFd<'_>, target: RawFd) -> Result<OwnedFd> {
    // SAFETY: the pidfd remains borrowed for the call; the returned descriptor
    // is new and immediately transferred to `OwnedFd`.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target, 0_u32) };
    // SAFETY: the preceding native call returned a fresh unowned FD.
    unsafe { fd_result(result, "pidfd_getfd") }
}
/// Reads the pidfs info structure through the original kernel ioctl.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_info(pidfd: BorrowedFd<'_>) -> Result<RawPidfdInfo> {
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
/// Requires close-on-exec on the same descriptor without changing status flags.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn ensure_cloexec(fd: BorrowedFd<'_>) -> Result<()> {
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
/// Requires a connected non-listening Unix stream.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn validate_connected_unix_stream(fd: BorrowedFd<'_>) -> Result<()> {
    let socket_type = socket_integer_option(fd, libc::SO_TYPE, "getsockopt(SO_TYPE)")?;
    if socket_type != libc::SOCK_STREAM {
        return Err(Error::WrongDescriptorType {
            expected: "Unix SOCK_STREAM socket",
        });
    }
    let domain = socket_integer_option(fd, libc::SO_DOMAIN, "getsockopt(SO_DOMAIN)")?;
    if domain != libc::AF_UNIX {
        return Err(Error::WrongDescriptorType {
            expected: "Unix SOCK_STREAM socket",
        });
    }
    let accepts_connections =
        socket_integer_option(fd, libc::SO_ACCEPTCONN, "getsockopt(SO_ACCEPTCONN)")?;
    if accepts_connections != 0 {
        return Err(Error::WrongDescriptorType {
            expected: "connected Unix SOCK_STREAM socket, not a listener",
        });
    }
    require_connected_unix_stream_peer(fd)
}
/// Checks the original Unix stream peer-address ABI.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn require_connected_unix_stream_peer(fd: BorrowedFd<'_>) -> Result<()> {
    require_connected_unix_peer_with_labels(
        fd,
        "getpeername(SOCK_STREAM)",
        "SOCK_STREAM peer address",
    )
}
/// Checks a connected Unix peer with the supplied diagnostic labels.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn require_connected_unix_peer_with_labels(
    fd: BorrowedFd<'_>,
    operation: &'static str,
    object: &'static str,
) -> Result<()> {
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
    unit_result(result.into(), operation)?;
    if usize::try_from(length).unwrap_or(0) < size_of::<libc::sa_family_t>()
        || i32::from(address.ss_family) != libc::AF_UNIX
    {
        return Err(Error::MalformedKernelResponse {
            object,
            message: "getpeername returned a missing or non-Unix peer".to_string(),
        });
    }
    Ok(())
}
/// Reads the kernel socket cookie with its exact native width.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn socket_cookie(fd: BorrowedFd<'_>) -> Result<u64> {
    let mut cookie = 0_u64;
    let mut length = size_of::<u64>() as libc::socklen_t;
    // SAFETY: the output integer and length remain writable and live for the
    // call, and the socket descriptor remains borrowed throughout.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_COOKIE,
            std::ptr::addr_of_mut!(cookie).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    unit_result(result.into(), "getsockopt(SO_COOKIE)")?;
    if length as usize != size_of::<u64>() {
        return Err(Error::MalformedKernelResponse {
            object: "SO_COOKIE",
            message: "kernel returned an unexpected cookie length".to_string(),
        });
    }
    Ok(cookie)
}
/// Reads one integer socket option with its exact native width.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn socket_integer_option(fd: BorrowedFd<'_>, option: i32, operation: &'static str) -> Result<i32> {
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
/// Reads the original kernel Unix-peer credential structure.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn peer_credentials(fd: BorrowedFd<'_>) -> Result<libc::ucred> {
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
/// Enables one integer socket option on the borrowed endpoint.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn set_socket_bool(fd: BorrowedFd<'_>, option: i32, operation: &'static str) -> Result<()> {
    set_socket_integer(fd, option, 1, operation)
}
/// Sets one integer socket option on the borrowed endpoint.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn set_socket_integer(fd: BorrowedFd<'_>, option: i32, enabled: i32, operation: &'static str) -> Result<()> {
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
/// Requires the original credentials and pidfd reporting options.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn require_seqpacket_identity(fd: BorrowedFd<'_>) -> Result<()> {
    if socket_integer_option(fd, libc::SO_PASSCRED, "getsockopt(SO_PASSCRED)")? != 1
        || socket_integer_option(fd, SO_PASSPIDFD, "getsockopt(SO_PASSPIDFD)")? != 1
    {
        return Err(Error::invalid(
            "record subject options",
            "SO_PASSCRED and SO_PASSPIDFD must already be enabled",
        ));
    }
    Ok(())
}
/// Enables the original credentials and pidfd reporting options.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn enable_seqpacket_identity(fd: BorrowedFd<'_>) -> Result<()> {
    set_socket_bool(fd, libc::SO_PASSCRED, "setsockopt(SO_PASSCRED)")?;
    set_socket_bool(fd, SO_PASSPIDFD, "setsockopt(SO_PASSPIDFD)")
}
/// Enables credentials, pidfd and socket-security-context reporting.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn enable_stream_subject(fd: BorrowedFd<'_>) -> Result<()> {
    enable_seqpacket_identity(fd)?;
    set_socket_bool(fd, libc::SO_PASSSEC, "setsockopt(SO_PASSSEC)")
}
/// Requires the same three installed stream reporting options.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn require_stream_subject(fd: BorrowedFd<'_>) -> Result<()> {
    require_seqpacket_identity(fd)?;
    if socket_integer_option(fd, libc::SO_PASSSEC, "getsockopt(SO_PASSSEC)")? != 1 {
        return Err(Error::invalid(
            "stream subject options",
            "SO_PASSSEC must remain enabled",
        ));
    }
    Ok(())
}
/// Creates the original CLOEXEC duplicate at the specified lower bound.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn duplicate_at_least(fd: BorrowedFd<'_>, minimum: RawFd) -> Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC borrows the source and returns a fresh owned fd.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    // SAFETY: the preceding native call returned a fresh unowned FD.
    unsafe { fd_result(result.into(), "fcntl(F_DUPFD_CLOEXEC)") }
}

/// Immediately owns a successful fresh-descriptor result without observing flags.
/// Adopts one successful native descriptor return before checking its flags.
///
/// # Safety
/// A nonnegative `result` must name a fresh descriptor owned exclusively by the
/// caller, with no Rust owner yet. Negative syscall results transfer no FD.
///
/// # Errors
/// Returns the original syscall failure for a negative native result.
pub unsafe fn adopt_created_fd(result: libc::c_long, operation: &'static str) -> Result<OwnedFd> {
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
    Ok(fd)
}

/// Adopts one fresh native descriptor return and enforces close-on-exec.
///
/// # Safety
/// The successful raw result must be a fresh exclusively owned descriptor with
/// no existing Rust owner. This consumes its ownership, including on error.
///
/// # Errors
/// Returns the original syscall or descriptor-flag failure.
pub unsafe fn fd_result(result: libc::c_long, operation: &'static str) -> Result<OwnedFd> {
    // SAFETY: the native return is fresh and has no existing descriptor owner.
    let fd = unsafe { adopt_created_fd(result, operation) }?;
    ensure_cloexec(fd.as_fd())?;
    Ok(fd)
}
/// Preserves a native syscall failure under its actual operation label.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn unit_result(result: libc::c_long, operation: &'static str) -> Result<()> {
    if result < 0 {
        Err(Error::syscall(operation))
    } else {
        Ok(())
    }
}
/// Obtains the actual peer pidfd with the original CLOEXEC and width checks.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn peer_pidfd(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    peer_pidfd_observed(fd, None)?.ok_or(Error::WrongDescriptorType { expected: "pidfd" })
}
/// Parks the actual peer pidfd before its flag and width checks.
// Only the actual guarded peer capture supplies this private original slot.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn peer_pidfd_retaining_into_v1(
    fd: BorrowedFd<'_>,
    original: &mut Option<OwnedFd>,
) -> Result<()> {
    if original.is_some() { return Err(Error::WrongDescriptorType { expected: "vacant peer pidfd slot" }); }
    peer_pidfd_observed(fd, Some(original)).map(|_| ())
}
/// Shares ordinary or retained ownership of one actual peer-pidfd query.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn peer_pidfd_observed(
    fd: BorrowedFd<'_>,
    retained: Option<&mut Option<OwnedFd>>,
) -> Result<Option<OwnedFd>> {
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
    finish_peer_pidfd_observation_v1(peer_fd, length, retained)
}
/// Finishes one peer-pidfd return while retaining its actual descriptor.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn finish_peer_pidfd_observation_v1(
    peer_fd: OwnedFd,
    length: libc::socklen_t,
    retained: Option<&mut Option<OwnedFd>>,
) -> Result<Option<OwnedFd>> {
    let retaining = retained.is_some();
    let mut ordinary = None;
    let destination = retained.unwrap_or(&mut ordinary);
    // Install the actual adopted kernel FD before CLOEXEC/length validation.
    // The retained caller keeps this same slot on either later native error;
    // None uses a local slot with the existing immediate error disposition.
    *destination = Some(peer_fd);
    let Some(peer_fd) = destination.as_ref() else {
        return Err(Error::WrongDescriptorType { expected: "pidfd" });
    };
    ensure_cloexec(peer_fd.as_fd())?;
    if length as usize != size_of::<RawFd>() {
        return Err(Error::MalformedKernelResponse {
            object: "SO_PEERPIDFD",
            message: "kernel returned an unexpected descriptor length".to_string(),
        });
    }
    if retaining { return Ok(None); }
    match ordinary.take() {
        Some(peer_fd) => Ok(Some(peer_fd)),
        other => {
            drop(other);
            Err(Error::WrongDescriptorType { expected: "pidfd" })
        }
    }
}

/// Reads the borrowed descriptor's existing CLOEXEC flag without changing it.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn is_cloexec(fd: BorrowedFd<'_>) -> Result<bool> {
    // SAFETY: F_GETFD only observes a descriptor borrowed for the call.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        Err(Error::syscall("fcntl(F_GETFD)"))
    } else {
        Ok(flags & libc::FD_CLOEXEC != 0)
    }
}
/// Reads the existing native file-status flags.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn get_status_flags(fd: BorrowedFd<'_>) -> Result<libc::c_int> {
    // SAFETY: `F_GETFL` only observes the borrowed file description.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if result < 0 {
        Err(Error::syscall("fcntl(F_GETFL)"))
    } else {
        Ok(result)
    }
}
/// Creates the same nonblocking CLOEXEC Unix seqpacket pair.
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd)> {
    seqpacket_pair_with_flags(libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
}

/// Checks whether a fixture descriptor number is still open.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn raw_fd_is_open(fd: RawFd) -> bool {
    // SAFETY: F_GETFD only observes the integer descriptor table entry.
    let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    result >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
}

/// Clears CLOEXEC only for the existing native admission fixture.
#[cfg(any(test, feature = "test-fixtures"))]
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn clear_cloexec_for_test(fd: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: F_GETFD and F_SETFD operate only on the borrowed descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(Error::syscall("fcntl(F_GETFD)"));
    }
    // SAFETY: the scalar flag value preserves every bit except FD_CLOEXEC.
    let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    unit_result(result.into(), "fcntl(F_SETFD)")
}

/// Enables credentials only for the existing option-preservation fixture.
#[cfg(any(test, feature = "test-fixtures"))]
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn enable_socket_passcred_for_test(fd: BorrowedFd<'_>) -> Result<()> {
    set_socket_bool(fd, libc::SO_PASSCRED, "setsockopt(SO_PASSCRED)")
}

/// Reads the existing fixture credential-reporting option.
#[cfg(any(test, feature = "test-fixtures"))]
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn socket_passcred_for_test(fd: BorrowedFd<'_>) -> Result<bool> {
    Ok(socket_integer_option(fd, libc::SO_PASSCRED, "getsockopt(SO_PASSCRED)")? != 0)
}

/// Runs the existing signal-zero kernel qualification fixture.
#[cfg(any(test, feature = "test-fixtures"))]
///
/// # Errors
/// Returns the original native failure or malformed descriptor/response error.
pub fn pidfd_send_signal_zero_for_test(pidfd: BorrowedFd<'_>) -> Result<()> {
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

/// Creates a Unix seqpacket pair with the caller-specified socket flags.
///
/// # Errors
/// Returns the original native socketpair error.
pub fn seqpacket_pair_with_flags(flags: i32) -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: the output array contains space for exactly two descriptors;
    // success transfers both newly-created descriptors to this process.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | flags,
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
