//! Cross-process futex wait/wake decisions, result types, and syscall wrappers.

use super::*;

impl NodeSlot {
    /// Computes the race-free futex wait decision after an idle publish.
    #[must_use]
    pub fn prepare_futex_wait(&self) -> FutexWait {
        let expected = self.wake_signal.load(Ordering::Acquire);
        if self.is_runnable_after_idle_publish() {
            FutexWait::Runnable
        } else {
            FutexWait::Wait { expected }
        }
    }

    /// Returns `true` if a futex wait on `expected` is still warranted.
    #[must_use]
    pub fn futex_wait_still_valid(&self, expected: u32) -> bool {
        self.wake_signal.load(Ordering::Acquire) == expected
            && !self.is_runnable_after_idle_publish()
    }

    /// Wakes a node because an inbound frame became actionable.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex wake syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return a no-op
    /// success with zero woken waiters.
    pub fn wake_for_frame_delivery(&self) -> Result<WakeAction, FutexError> {
        self.wake_after_signal_increment()
    }

    /// Wakes a node because an in-flight device-I/O hold was released.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex wake syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return a no-op
    /// success with zero woken waiters.
    pub fn wake_for_device_io_release(&self) -> Result<WakeAction, FutexError> {
        self.wake_after_signal_increment()
    }

    /// Issues a non-private futex wake on this node's wake-signal word.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for a reason
    /// other than no waiters. Non-Linux developer-tooling builds return a
    /// no-op success with zero woken waiters.
    pub fn futex_wake_nonprivate(&self, max_waiters: u32) -> Result<FutexWakeResult, FutexError> {
        futex_wake_nonprivate(&self.wake_signal, max_waiters)
    }

    /// Waits on this node's wake-signal word using non-private `FUTEX_WAIT`.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return
    /// [`FutexWaitOutcome::Noop`] after the race-free pre-check.
    pub fn futex_wait_nonprivate(&self, wait: FutexWait) -> Result<FutexWaitOutcome, FutexError> {
        match wait {
            FutexWait::Runnable => Ok(FutexWaitOutcome::Runnable),
            FutexWait::Wait { expected } => {
                if self.futex_wait_still_valid(expected) {
                    self.futex_wait_word_nonprivate(expected)
                } else {
                    Ok(FutexWaitOutcome::ValueChanged)
                }
            }
        }
    }

    /// Calls non-private `FUTEX_WAIT` directly on the wake-signal word.
    ///
    /// This is the safe syscall wrapper used after the race-free re-check. A
    /// concurrent wake that changes the word before the syscall parks returns
    /// [`FutexWaitOutcome::ValueChanged`].
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return
    /// [`FutexWaitOutcome::Noop`].
    pub fn futex_wait_word_nonprivate(
        &self,
        expected: u32,
    ) -> Result<FutexWaitOutcome, FutexError> {
        futex_wait_nonprivate(&self.wake_signal, expected)
    }
}

/// A scheduler wake action for a parked node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeAction {
    /// The wake signal was incremented and a non-private futex wake was issued.
    Wake {
        /// The wake signal value before the release increment.
        previous: u32,
        /// The wake signal value after the release increment.
        new: u32,
        /// The result of issuing `FUTEX_WAKE` on the wake-signal word.
        futex: FutexWakeResult,
    },
}

/// A node-side futex wait decision after publishing an idle precondition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexWait {
    /// The node is already runnable and must not enter `FUTEX_WAIT`.
    Runnable,
    /// The node should wait on `wake_signal` while it still equals `expected`.
    Wait {
        /// The observed futex word used as the `FUTEX_WAIT` expected value.
        expected: u32,
    },
}

/// Result of a non-private futex wake syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWakeResult {
    /// Number of waiters woken by the syscall.
    pub waiters_woken: u32,
    /// Whether the private futex flag was used.
    pub futex_private: bool,
}

/// Result of a non-private futex wait syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexWaitOutcome {
    /// The node was already runnable and no syscall was needed.
    Runnable,
    /// The futex word changed before the wait could park.
    ValueChanged,
    /// The wait was interrupted by a signal.
    Interrupted,
    /// The futex wait returned because a waker woke this waiter.
    Woken,
    /// The non-Linux developer-tooling shim compiled the wait path to a no-op.
    Noop,
}

/// A futex syscall error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FutexError {
    /// The futex syscall failed unexpectedly.
    #[error("{operation} syscall failed with errno {errno}")]
    Syscall {
        /// The futex operation being attempted.
        operation: &'static str,
        /// The OS errno value.
        errno: i32,
    },
    /// The futex syscall returned an invalid nonnegative count.
    #[error("{operation} syscall returned invalid count {count}")]
    InvalidReturnCount {
        /// The futex operation being attempted.
        operation: &'static str,
        /// The raw return count.
        count: i64,
    },
}

/// An error produced while updating global region control flags.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionControlError {
    /// A slot wake failed while broadcasting a control-flag update.
    #[error("waking node slot {slot_index} for control flag failed")]
    WakeSlot {
        /// The index in the caller-provided slot iterator.
        slot_index: usize,
        /// The futex wake failure.
        #[source]
        source: FutexError,
    },
}

#[cfg(target_os = "linux")]
fn futex_wake_nonprivate(
    wake_signal: &AtomicU32,
    max_waiters: u32,
) -> Result<FutexWakeResult, FutexError> {
    // SAFETY: `wake_signal` is an aligned live `AtomicU32` valid for this syscall.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_futex,
            wake_signal.as_ptr(),
            libc::FUTEX_WAKE,
            max_waiters,
        )
    };
    if raw < 0 {
        return Err(last_futex_error("FUTEX_WAKE"));
    }

    let waiters_woken = u32::try_from(raw).map_err(|_| FutexError::InvalidReturnCount {
        operation: "FUTEX_WAKE",
        count: raw,
    })?;
    Ok(FutexWakeResult {
        waiters_woken,
        futex_private: FUTEX_PRIVATE,
    })
}

#[cfg(not(target_os = "linux"))]
fn futex_wake_nonprivate(
    _wake_signal: &AtomicU32,
    _max_waiters: u32,
) -> Result<FutexWakeResult, FutexError> {
    Ok(FutexWakeResult {
        waiters_woken: 0,
        futex_private: FUTEX_PRIVATE,
    })
}

#[cfg(target_os = "linux")]
fn futex_wait_nonprivate(
    wake_signal: &AtomicU32,
    expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    // SAFETY: `wake_signal` is aligned and live, and the null timeout is never dereferenced.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_futex,
            wake_signal.as_ptr(),
            libc::FUTEX_WAIT,
            expected,
            core::ptr::null::<libc::timespec>(),
        )
    };
    if raw == 0 {
        return Ok(FutexWaitOutcome::Woken);
    }

    let errno = last_errno();
    match errno {
        libc::EAGAIN => Ok(FutexWaitOutcome::ValueChanged),
        libc::EINTR => Ok(FutexWaitOutcome::Interrupted),
        _ => Err(FutexError::Syscall {
            operation: "FUTEX_WAIT",
            errno,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn futex_wait_nonprivate(
    _wake_signal: &AtomicU32,
    _expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    Ok(FutexWaitOutcome::Noop)
}

#[cfg(target_os = "linux")]
fn last_futex_error(operation: &'static str) -> FutexError {
    FutexError::Syscall {
        operation,
        errno: last_errno(),
    }
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
