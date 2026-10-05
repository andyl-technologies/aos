//! One-write captures without changing the inherited stderr open description.
//!
//! The single-guest libtest fixture inherits a tee pipeline FIFO. Linux proc
//! reopening gives that FIFO an independent nonblocking description. A read-only
//! SIGPIPE check refuses it unless broken writes are already ignored. This
//! observer never installs a handler or changes descriptor flags. Regular files
//! retain their original shared cursor and filesystem latency.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

pub(in crate::runtime::live_callbacks) fn destination(source: &impl AsFd) -> io::Result<File> {
    let pinned = File::from(source.as_fd().try_clone_to_owned()?);
    let original = pinned.metadata()?;
    if original.is_file() {
        return Ok(pinned);
    }
    #[cfg(target_os = "linux")]
    if original.file_type().is_fifo() && sigpipe_is_ignored()? {
        // std opens descriptors CLOEXEC. NONBLOCK applies only to this new open
        // description, never a duplicate of the inherited FIFO description.
        let reopened = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
            .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
        let observed = reopened.metadata()?;
        if original.dev() != observed.dev()
            || original.ino() != observed.ino()
            || original.file_type() != observed.file_type()
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(reopened);
    }
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(target_os = "linux")]
fn sigpipe_is_ignored() -> io::Result<bool> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null action performs only a disposition query; the successful
    // syscall initializes the complete writable output. No signal policy changes.
    let status = unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful query initialized the output above.
    let action = unsafe { action.assume_init() };
    Ok(action.sa_sigaction == libc::SIG_IGN)
}

#[cfg(test)]
mod tests;
