//! Advisory locks for blob packfile descriptors.

use std::fs;
use std::io;
use std::os::fd::AsRawFd;

#[derive(Clone, Copy, Debug)]
pub(super) enum BlobPackFileLockMode {
    Shared,
    Exclusive,
}

impl BlobPackFileLockMode {
    const fn operation(self) -> libc::c_int {
        match self {
            Self::Shared => libc::LOCK_SH,
            Self::Exclusive => libc::LOCK_EX,
        }
    }
}

pub(super) fn lock_blob_pack_file(file: &fs::File, mode: BlobPackFileLockMode) -> io::Result<()> {
    loop {
        let result = unsafe {
            // SAFETY: `file` owns a live file descriptor for this call, and
            // `flock` does not outlive or alias Rust references. The returned
            // lock is advisory and attached to this opened descriptor.
            libc::flock(file.as_raw_fd(), mode.operation())
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(source);
    }
}

pub(super) fn unlock_blob_pack_file(file: &fs::File) {
    let result = unsafe {
        // SAFETY: `file` owns a live file descriptor for this call, and
        // unlocking releases only the advisory lock attached to that descriptor.
        libc::flock(file.as_raw_fd(), libc::LOCK_UN)
    };
    debug_assert_eq!(result, 0);
}
