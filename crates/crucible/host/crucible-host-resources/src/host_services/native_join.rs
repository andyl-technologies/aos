//! Owns one GNU/Linux pthread until a nonblocking physical join returns.
//!
//! The constructor consumes the unique Rust handle before any native query.
//! A returned Rust body is not evidence of task or TLS return. Only the real
//! libc join result closes this owner; callers retain their actual task,
//! stack and cleanup controls alongside it until that receipt. This module
//! does not promise allocator unmapping of libc's cached stack or TCB pages.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::thread::{JoinHandleExt, RawPthread};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::thread::JoinHandle;
use std::thread::ThreadId;

/// Distinguishes a still-running task from its actual successful join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeJoinObservation {
    /// The actual thread has not returned; its original owner remains live.
    Pending,
    /// The task and TLS have actually returned and were joined exactly once.
    Returned,
}

/// Preserves refusal without discarding the unique native join owner.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum NativeJoinError {
    /// A fork child cannot inspect or join its parent's thread handle.
    #[error("native worker belongs to another process")]
    ForeignProcess,
    /// The local owning slot has no native handle or returned receipt.
    #[error("native worker join owner is unavailable")]
    MissingOwner,
    /// An unexpected libc result makes further native queries uncertain.
    #[error("nonblocking native join returned status {status}")]
    Native {
        /// The actual signed libc result, not thread-local errno.
        status: i32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(all(target_os = "linux", target_env = "gnu"))]
enum Disposition {
    Active,
    Returned,
    Uncertain(i32),
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl Disposition {
    fn observe(&mut self, status: i32) -> Result<NativeJoinObservation, NativeJoinError> {
        match *self {
            Self::Returned => return Ok(NativeJoinObservation::Returned),
            Self::Uncertain(status) => return Err(NativeJoinError::Native { status }),
            Self::Active => {}
        }
        match status {
            0 => {
                *self = Self::Returned;
                Ok(NativeJoinObservation::Returned)
            }
            libc::EBUSY => Ok(NativeJoinObservation::Pending),
            status => {
                *self = Self::Uncertain(status);
                Err(NativeJoinError::Native { status })
            }
        }
    }
}

/// Retains the unique native task handle without a blocking join or detach.
///
/// Its containing issued body must remain in its preborn return recipient
/// while this owner is pending or uncertain. Dropping a raw owning facade is
/// not a physical-return mechanism. There is no raw-ID constructor or Clone.
#[must_use = "retain the unique native join owner through physical return"]
#[derive(Debug)]
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub struct NativeJoinOwner {
    native: Option<RawPthread>,
    thread: ThreadId,
    creator_process: u32,
    disposition: Disposition,
    last_status: Option<i32>,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl NativeJoinOwner {
    /// Transfers the actual unique join handle before its first native query.
    ///
    /// The worker delivers its real result and panic payload into its existing
    /// retained outcome cell before returning unit. Taking the pthread drops
    /// Rust's result-packet reference and never reads private packet storage.
    #[must_use]
    pub fn from_worker(worker: JoinHandle<()>) -> Self {
        let thread = worker.thread().id();
        let creator_process = std::process::id();
        let native = worker.into_pthread_t();
        Self {
            native: Some(native),
            thread,
            creator_process,
            disposition: Disposition::Active,
            last_status: None,
        }
    }

    /// Returns the actual Rust worker identity saved before native transfer.
    #[must_use]
    pub fn thread_id(&self) -> ThreadId {
        self.thread
    }

    /// Returns whether this is the actual process that acquired the handle.
    ///
    /// This pure negative perimeter precedes every native handle access.
    #[must_use]
    pub fn belongs_to_current_process(&self) -> bool {
        self.creator_process == std::process::id()
    }

    /// Returns the latest actual signed libc observation, if one was attempted.
    #[must_use]
    pub fn last_status(&self) -> Option<i32> {
        self.last_status
    }

    /// Observes physical return without waiting for the target thread.
    ///
    /// Pending keeps the same handle; success is latched before returning to
    /// any independent Original postcheck. No call follows success or an
    /// unexpected status. The caller separately checks its exact saved guard
    /// before and after, and may wait only under that guard's live authority.
    ///
    /// # Errors
    /// Refuses a foreign process or preserves the first unexpected libc code.
    pub fn poll(&mut self) -> Result<NativeJoinObservation, NativeJoinError> {
        if !self.belongs_to_current_process() {
            return Err(NativeJoinError::ForeignProcess);
        }
        match self.disposition {
            Disposition::Returned => return Ok(NativeJoinObservation::Returned),
            Disposition::Uncertain(status) => return Err(NativeJoinError::Native { status }),
            Disposition::Active => {}
        }
        let Some(native) = self.native else {
            return Err(NativeJoinError::MissingOwner);
        };
        let status = unsafe {
            // SAFETY: into_pthread_t transferred this joinable pthread's unique
            // ownership. No handle alias, detach or other join exists. Exclusive
            // mutable access serializes polling, and the creator-process check
            // prevents inherited child access. GNU libc 2.39 tryjoin returns
            // EBUSY without consuming the handle or waiting; zero consumes it.
            // The Rust trampoline returns null; actual Rust results have a
            // separately owned outcome cell, so no result pointer is needed.
            libc::pthread_tryjoin_np(native as libc::pthread_t, std::ptr::null_mut())
        };
        if status == 0 {
            self.native = None;
        }
        self.last_status = Some(status);
        self.disposition.observe(status)
    }
}

/// Keeps the native owner type available without issuing unsupported tasks.
///
/// This representation is unconstructible. Callers on unsupported platforms
/// must refuse before thread birth; it supplies no join or blocking fallback.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[derive(Debug)]
pub struct NativeJoinOwner {
    unavailable: std::convert::Infallible,
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
impl NativeJoinOwner {
    /// Returns the actual worker identity; no unsupported owner can exist.
    pub fn thread_id(&self) -> ThreadId {
        match self.unavailable {}
    }

    /// Returns the creation-process check; no unsupported owner can exist.
    pub fn belongs_to_current_process(&self) -> bool {
        match self.unavailable {}
    }

    /// Returns the last actual status; no unsupported owner can exist.
    pub fn last_status(&self) -> Option<i32> {
        match self.unavailable {}
    }

    /// Observes a supported native owner without a blocking fallback.
    ///
    /// # Errors
    /// No unsupported owner can be constructed or reach this method.
    pub fn poll(&mut self) -> Result<NativeJoinObservation, NativeJoinError> {
        match self.unavailable {}
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests;
