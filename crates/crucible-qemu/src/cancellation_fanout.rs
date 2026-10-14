//! Sticky cancellation fan-out to the per-node eventfds of one attempt.
//!
//! QEMU clears `O_NONBLOCK` on every descriptor it receives over
//! `SCM_RIGHTS`, and that flag belongs to the open file description that all
//! duplicates share. When concurrently launched nodes pass duplicates of one
//! cancellation eventfd to several source QEMU processes, one process's
//! receive can clear the flag while another validates its staged
//! nonblocking-eventfd contract. Each concurrent node therefore receives a
//! distinct eventfd minted here, and the attempt's terminal signal writes
//! every minted eventfd after the primary one.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::Mutex;

/// Most per-node eventfds one attempt cgroup may mint.
///
/// The fan-out retains one descriptor per minted eventfd for the attempt's
/// lifetime, because a QEMU process may still poll it after the host contract
/// that minted it is gone. The bound keeps repeated world assembly within one
/// attempt from exhausting the supervisor's descriptor table.
const MAX_CANCELLATION_FANOUT_MEMBERS: usize = 256;

/// Sticky cancellation state shared by every duplicate of one attempt cgroup.
#[derive(Debug, Default)]
pub(crate) struct QemuCancellationFanout {
    state: Mutex<FanoutState>,
}

#[derive(Debug, Default)]
struct FanoutState {
    signaled: bool,
    members: Vec<OwnedFd>,
}

impl QemuCancellationFanout {
    /// Mints one nonblocking eventfd that observes this attempt's cancellation.
    ///
    /// An eventfd minted after cancellation is readable before it is returned,
    /// so a late child contract cannot miss the sticky terminal event.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the fan-out is exhausted or poisoned, or the
    /// eventfd cannot be created, retained, or signaled.
    pub(crate) fn mint(&self) -> io::Result<OwnedFd> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("cancellation fan-out is poisoned"))?;
        if state.members.len() >= MAX_CANCELLATION_FANOUT_MEMBERS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "cancellation fan-out member limit is exhausted",
            ));
        }

        let event = create_nonblocking_eventfd()?;
        if state.signaled {
            write_eventfd(event.as_raw_fd(), 1)?;
        }
        state.members.push(event.try_clone()?);
        Ok(event)
    }

    /// Makes every minted and future member eventfd readable.
    ///
    /// Every member is attempted even after a failure, and the first failure
    /// is returned.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the fan-out is poisoned or a member write
    /// fails.
    pub(crate) fn signal(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("cancellation fan-out is poisoned"))?;
        state.signaled = true;

        let mut first_failure = None;
        for member in &state.members {
            if let Err(source) = write_eventfd(member.as_raw_fd(), 1) {
                first_failure.get_or_insert(source);
            }
        }
        first_failure.map_or(Ok(()), Err)
    }
}

/// Adds `value` to an eventfd counter, treating a saturated counter as written.
///
/// # Errors
///
/// Returns [`io::Error`] when the write fails or is short.
pub(crate) fn write_eventfd(descriptor: i32, value: u64) -> io::Result<()> {
    loop {
        let written = unsafe {
            // SAFETY: `value` is a valid u64 input buffer for eventfd.
            libc::write(
                descriptor,
                (&value as *const u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if written == 8 {
            return Ok(());
        }
        if written >= 0 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if source.kind() == io::ErrorKind::WouldBlock {
            // A saturated nonblocking eventfd is already readable, which is
            // the sticky wake postcondition required by pre-exec polling.
            return Ok(());
        }
        return Err(source);
    }
}

fn create_nonblocking_eventfd() -> io::Result<OwnedFd> {
    let descriptor = unsafe {
        // SAFETY: eventfd has no pointer arguments and returns one new fd.
        libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: successful eventfd returned a uniquely owned descriptor.
        OwnedFd::from_raw_fd(descriptor)
    })
}

#[cfg(test)]
#[path = "cancellation_fanout_tests.rs"]
mod tests;
