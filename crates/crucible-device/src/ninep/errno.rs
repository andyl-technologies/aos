//! The Linux errno constants the 9p server returns in `Rlerror` replies.
//!
//! 9P2000.L reports every failure as an `Rlerror` carrying a Linux errno
//! ([IO-17]). This module names the fixed numeric codes the server uses so the
//! read-only boundary (`EROFS`), the unimplemented-type path (`ENOSYS`), and the
//! malformed-body path (`EINVAL`) are spelled out once and host-independent. The
//! values are the canonical Linux x86-64 errno numbers.

/// `EINVAL`: an invalid argument, returned for a malformed message body ([IO-17]).
pub const EINVAL: u32 = 22;

/// `ENOENT`: no such file or directory (a walk component that does not resolve).
pub const ENOENT: u32 = 2;

/// `EIO`: an I/O error (reserved for an internal inconsistency).
pub const EIO: u32 = 5;

/// `EBADF`: a bad file descriptor, returned for an unknown fid.
pub const EBADF: u32 = 9;

/// `ENOSYS`: a function not implemented, for an unknown message type ([IO-17]).
pub const ENOSYS: u32 = 38;

/// `EROFS`: a read-only filesystem, the boundary for every mutating op ([IO-17]).
pub const EROFS: u32 = 30;

/// `EISDIR`: a directory targeted by a plain `Tread` (clients must `readdir`).
pub const EISDIR: u32 = 21;

/// `ENOTDIR`: a non-directory targeted by `Treaddir`.
pub const ENOTDIR: u32 = 20;

/// `EMSGSIZE`: a request frame larger than the negotiated `msize` ([IO-18]).
pub const EMSGSIZE: u32 = 90;
