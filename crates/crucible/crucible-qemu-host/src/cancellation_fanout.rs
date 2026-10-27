//! Sticky cancellation fan-out to the per-node eventfds of one attempt.
//!
//! QEMU clears `O_NONBLOCK` on every descriptor it receives over
//! `SCM_RIGHTS`, and that flag belongs to the open file description that all
//! duplicates share. When concurrently launched nodes pass duplicates of one
//! cancellation eventfd to several source QEMU processes, one process's
//! receive can clear the flag while another validates its staged
//! nonblocking-eventfd contract. Each concurrent node therefore receives a
//! distinct eventfd minted here, and the attempt's terminal signal writes
//! every live minted eventfd after the primary one.
//!
//! Every mint also returns a [`QemuCancellationFanoutMembership`]. The fan-out
//! keeps its own duplicate of the minted eventfd in a slot until that
//! membership is explicitly retired after the QEMU process that received the
//! eventfd has been reaped. Retired slots are reused, so the member ceiling
//! bounds concurrently live node processes rather than every node a long
//! attempt has ever launched.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::{Arc, Mutex};

/// Most simultaneously retained per-node eventfds in one attempt cgroup.
///
/// A slot stays retained from mint until its membership is retired after the
/// owning QEMU process is reaped, because that process may still poll the
/// eventfd after the host contract that minted it is gone. The bound counts
/// live node processes and keeps the supervisor's descriptor table finite even
/// when a retirement is missed.
const MAX_LIVE_CANCELLATION_FANOUT_MEMBERS: usize = 256;

/// Sticky cancellation state shared by every duplicate of one attempt cgroup.
#[derive(Debug, Default)]
pub(crate) struct QemuCancellationFanout {
    state: Mutex<FanoutState>,
}

#[derive(Debug, Default)]
struct FanoutState {
    signaled: bool,
    /// Retained member duplicates; `None` marks a retired, reusable slot.
    slots: Vec<Option<OwnedFd>>,
    /// Indices of retired slots, reused before the slot table grows.
    free_slots: Vec<usize>,
}

impl FanoutState {
    fn live_members(&self) -> usize {
        self.slots.len() - self.free_slots.len()
    }

    /// Stores one retained duplicate, preferring a retired slot.
    fn occupy_slot(&mut self, retained: OwnedFd) -> usize {
        if let Some(slot) = self.free_slots.pop()
            && let Some(free) = self.slots.get_mut(slot)
        {
            *free = Some(retained);
            return slot;
        }
        self.slots.push(Some(retained));
        self.slots.len() - 1
    }
}

/// Linear claim on one retained fan-out slot.
///
/// Dropping a membership without [`Self::retire_after_reap`] keeps its eventfd
/// retained and signaled for the rest of the attempt. A missed retirement
/// therefore costs one descriptor, never a lost cancellation.
#[derive(Debug)]
#[must_use = "retire the cancellation membership after its QEMU process is reaped"]
pub(crate) struct QemuCancellationFanoutMembership {
    fanout: Arc<QemuCancellationFanout>,
    slot: usize,
}

impl QemuCancellationFanoutMembership {
    /// Releases the fan-out's duplicate once no process can poll the eventfd.
    ///
    /// The caller must already have reaped every QEMU process that received
    /// this membership's eventfd. A poisoned fan-out keeps the slot retained,
    /// which preserves the sticky-cancellation postcondition.
    pub(crate) fn retire_after_reap(self) {
        let Ok(mut state) = self.fanout.state.lock() else {
            return;
        };
        if let Some(member) = state.slots.get_mut(self.slot)
            && member.take().is_some()
        {
            state.free_slots.push(self.slot);
        }
    }
}

impl QemuCancellationFanout {
    /// Mints one nonblocking eventfd that observes this attempt's cancellation.
    ///
    /// An eventfd minted after cancellation is readable before it is returned,
    /// so a late child contract cannot miss the sticky terminal event. The
    /// returned membership keeps the fan-out's duplicate until it is retired.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the live-member ceiling is reached, the
    /// fan-out is poisoned, or the eventfd cannot be created, retained, or
    /// signaled.
    pub(crate) fn mint(
        self: &Arc<Self>,
    ) -> io::Result<(OwnedFd, QemuCancellationFanoutMembership)> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("cancellation fan-out is poisoned"))?;
        if state.live_members() >= MAX_LIVE_CANCELLATION_FANOUT_MEMBERS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "cancellation fan-out live member limit is exhausted",
            ));
        }

        let event = create_nonblocking_eventfd()?;
        if state.signaled {
            write_eventfd(event.as_raw_fd(), 1)?;
        }
        let slot = state.occupy_slot(event.try_clone()?);

        let membership = QemuCancellationFanoutMembership {
            fanout: Arc::clone(self),
            slot,
        };
        Ok((event, membership))
    }

    /// Makes every live and future member eventfd readable.
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
        for member in state.slots.iter().flatten() {
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
