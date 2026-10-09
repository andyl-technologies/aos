//! Checked kernel identities for retained hot-fork control and wake endpoints.
//!
//! Socket cookies and bounded eventfd metadata are validated before a child
//! plan may reuse the process's established control and wake descriptors.

use std::io::{self, Read as _};

const HOT_FORK_ENDPOINT_FDINFO_MAX_BYTES: u64 = 4_096;

/// Reads the nonzero kernel identity of the retained control socket.
///
/// # Errors
///
/// Refuses a failed socket query, unexpected result size, or absent identity.
pub(super) fn hot_fork_control_socket_cookie(descriptor: std::os::fd::RawFd) -> io::Result<u64> {
    let mut cookie = 0_u64;
    let mut length = std::mem::size_of::<u64>() as libc::socklen_t;
    let status =
        // SAFETY: `cookie` and `length` are valid output buffers for SO_COOKIE.
        unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                std::ptr::from_mut(&mut cookie).cast(),
                &mut length,
            )
        };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<u64>() || cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control socket returned an invalid SO_COOKIE",
        ));
    }
    Ok(cookie)
}

// The versioned child plan carries kernel eventfd-id plus one; zero is absent.
/// Reads the bounded kernel identity of the retained wake eventfd.
///
/// # Errors
///
/// Refuses inaccessible, oversized, malformed, or ambiguous descriptor metadata.
pub(super) fn hot_fork_wake_eventfd_id(descriptor: std::os::fd::RawFd) -> io::Result<u64> {
    let path = format!("/proc/self/fdinfo/{descriptor}");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(HOT_FORK_ENDPOINT_FDINFO_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > HOT_FORK_ENDPOINT_FDINFO_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "eventfd fdinfo exceeds its fixed bound",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("eventfd fdinfo is not UTF-8: {error}"),
        )
    })?;
    hot_fork_eventfd_identity_token_from_fdinfo(text)
}

/// Converts one kernel eventfd identity into the checked one-based plan token.
///
/// # Errors
///
/// Refuses missing, repeated, invalid, or overflowing eventfd identities.
pub(super) fn hot_fork_eventfd_identity_token_from_fdinfo(text: &str) -> io::Result<u64> {
    let mut identity = None;
    for line in text.lines() {
        let Some(value) = line.strip_prefix("eventfd-id:") else {
            continue;
        };
        if identity.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "eventfd fdinfo repeats eventfd-id",
            ));
        }
        let parsed = value.trim().parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("eventfd-id is invalid: {error}"),
            )
        })?;
        // Linux may allocate eventfd ID zero. The versioned plan uses a
        // one-based token so zero can keep denoting an absent identity.
        identity = Some(parsed.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "eventfd-id exceeds token range")
        })?);
    }
    identity.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "eventfd fdinfo omits eventfd-id",
        )
    })
}
