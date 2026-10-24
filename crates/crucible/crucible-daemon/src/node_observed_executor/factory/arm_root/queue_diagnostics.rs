//! Retains bounded original cleanup failures as data beside exact queue custody.
//!
//! Snapshots are observations of one retained target, never reclamation proof.
//! Cleanup records use fixed storage so failure formatting cannot replace the
//! original native capsule or require another allocation after its effects.

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
};

/// Reports one exact retained target's native cleanup state without authority.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRootCleanupStatus {
    /// Reports whether the original native capsule is currently in the entry.
    /// A false value also occurs while the cleanup lease owns that same capsule.
    pub custody_present: bool,
    /// Reports whether the cleanup lease currently owns the original capsule.
    pub in_flight: bool,
    /// Reports the queue's retained positive cleanup observation.
    /// This scalar cannot authorize namespace release or replace the owning handle.
    pub reclaimed: bool,
    /// Reports whether any cleanup attempt or custody correlation failed.
    pub failed: bool,
    /// Retains the first original refusal or unwind without replacing later custody.
    pub first_failure: Option<InstalledRootCleanupFailure>,
}

/// Describes the first bounded cleanup failure without claiming absence of effects.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "failure", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstalledRootCleanupFailure {
    /// Retains the first original cleanup refusal.
    Refused {
        /// Contains at most 2048 UTF-8 bytes of the original error display.
        reason: String,
    },
    /// Reports an unwind while retaining the same original cleanup capsule.
    Unwound {},
}

const MAXIMUM_REASON_BYTES: usize = 2048;

pub(super) struct CleanupFailureRecord {
    reason: Option<BoundedReason>,
}

impl CleanupFailureRecord {
    pub(super) fn refused(error: &impl fmt::Display) -> Self {
        match catch_unwind(AssertUnwindSafe(|| {
            let mut reason = BoundedReason::new();
            match fmt::write(&mut reason, format_args!("{error}")) {
                Ok(()) => Self {
                    reason: Some(reason),
                },
                Err(_) => Self::unwound(),
            }
        })) {
            Ok(failure) => failure,
            Err(_) => Self::unwound(),
        }
    }

    pub(super) fn unwound() -> Self {
        Self { reason: None }
    }

    pub(super) fn retain_first(original: &mut Option<Self>, failure: Self) {
        if original.is_none() {
            *original = Some(failure);
        }
    }

    pub(super) fn status(&self) -> InstalledRootCleanupFailure {
        match &self.reason {
            Some(reason) => InstalledRootCleanupFailure::Refused {
                reason: reason.as_str().to_owned(),
            },
            None => InstalledRootCleanupFailure::Unwound {},
        }
    }
}

pub(super) struct BoundedReason {
    bytes: [u8; MAXIMUM_REASON_BYTES],
    length: usize,
    truncated: bool,
}

impl BoundedReason {
    fn new() -> Self {
        Self {
            bytes: [0; MAXIMUM_REASON_BYTES],
            length: 0,
            truncated: false,
        }
    }

    fn as_str(&self) -> &str {
        // Every write copies a prefix ending at a UTF-8 boundary. The fallback
        // preserves a bounded diagnostic if that private invariant ever changes.
        std::str::from_utf8(&self.bytes[..self.length])
            .unwrap_or("original cleanup reason is not valid UTF-8")
    }
}

impl fmt::Write for BoundedReason {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated {
            return Ok(());
        }
        let remaining = MAXIMUM_REASON_BYTES - self.length;
        let mut end = value.len().min(remaining);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.bytes[self.length..self.length + end].copy_from_slice(&value.as_bytes()[..end]);
        self.length += end;
        self.truncated = end != value.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
