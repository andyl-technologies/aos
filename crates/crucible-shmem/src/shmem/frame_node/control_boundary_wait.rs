//! Hostward notification on the existing public control-boundary ACK word.
//!
//! The futex carries no permission or time decision. A waiter must validate
//! its original request and complete boundary after every return. Linux's
//! expected-word comparison closes the release-before-park race without a
//! second request, polling interval, or process-private notification handle.

use std::time::Duration;

use super::*;

/// Result of one bounded shared control-boundary ACK wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlBoundaryWaitOutcome {
    /// The expected ACK word changed before the kernel could park the waiter.
    ValueChanged,
    /// A futex wake returned; the complete original boundary still needs validation.
    Woken,
    /// A signal interrupted the wait; the original deadline remains in force.
    Interrupted,
    /// The supplied remaining budget elapsed without a wake.
    TimedOut,
}

impl NodeSlot {
    /// Release-acknowledges a completed boundary and notifies shared waiters.
    ///
    /// The caller must finish coherent state publication and release its
    /// publication claim before this call. Idempotent acknowledgements also
    /// notify, so an earlier notification error cannot leave a parked peer.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] if notification fails. The already released ACK
    /// remains truthful and is not rolled back. Non-Linux tooling performs the
    /// release with the existing no-op wake shim; it cannot run bounded waits.
    pub fn acknowledge_control_boundary_and_notify(&self) -> Result<u32, FutexError> {
        self.acknowledge_with_notification(|| {
            futex::futex_wake_nonprivate(&self.control_boundary_ack, 0x7fff_ffff)
        })
    }

    fn acknowledge_with_notification(
        &self,
        notify: impl FnOnce() -> Result<FutexWakeResult, FutexError>,
    ) -> Result<u32, FutexError> {
        let acknowledgement = self.acknowledge_control_boundary();
        notify()?;
        Ok(acknowledgement)
    }

    /// Waits once on the exact original control ACK using a shared futex.
    ///
    /// `remaining` must come from the caller's retained absolute deadline.
    /// Spurious wakes and interruption never authenticate completion or renew
    /// that deadline. The kernel atomically compares `expected` before parking.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] for an unexpected syscall error, an unrepresentable
    /// timeout, or an unsupported non-Linux wait. No polling fallback is used.
    pub fn wait_control_boundary_ack(
        &self,
        expected: u32,
        remaining: Duration,
    ) -> Result<ControlBoundaryWaitOutcome, FutexError> {
        wait_ack(&self.control_boundary_ack, expected, remaining)
    }
}

#[cfg(target_os = "linux")]
fn wait_ack(
    acknowledgement: &AtomicU32,
    expected: u32,
    remaining: Duration,
) -> Result<ControlBoundaryWaitOutcome, FutexError> {
    let seconds = libc::time_t::try_from(remaining.as_secs()).map_err(|_| FutexError::Syscall {
        operation: "control ACK timeout conversion",
        errno: libc::EOVERFLOW,
    })?;
    let nanoseconds = i32::try_from(remaining.subsec_nanos()).map_err(|_| FutexError::Syscall {
        operation: "control ACK timeout conversion",
        errno: libc::EOVERFLOW,
    })?;
    let timeout = libc::timespec {
        tv_sec: seconds,
        tv_nsec: libc::c_long::from(nanoseconds),
    };

    // SAFETY: the aligned AtomicU32 and stack timespec live through this
    // syscall. FUTEX_WAIT uses a shared key and never accesses other fields.
    let result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            acknowledgement.as_ptr(),
            libc::FUTEX_WAIT,
            expected,
            &timeout as *const libc::timespec,
        )
    };
    if result == 0 {
        return Ok(ControlBoundaryWaitOutcome::Woken);
    }

    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    match errno {
        libc::EAGAIN => Ok(ControlBoundaryWaitOutcome::ValueChanged),
        libc::EINTR => Ok(ControlBoundaryWaitOutcome::Interrupted),
        libc::ETIMEDOUT => Ok(ControlBoundaryWaitOutcome::TimedOut),
        errno => Err(FutexError::Syscall {
            operation: "control ACK FUTEX_WAIT",
            errno,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_ack(
    _acknowledgement: &AtomicU32,
    _expected: u32,
    _remaining: Duration,
) -> Result<ControlBoundaryWaitOutcome, FutexError> {
    Err(FutexError::Syscall {
        operation: "control ACK FUTEX_WAIT",
        errno: libc::ENOSYS,
    })
}

#[cfg(all(test, target_os = "linux"))]
#[path = "control_boundary_wait_tests.rs"]
mod tests;
