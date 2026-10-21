//! Retains the actual ordinary info/stat/info/liveness identity observation.
//!
//! The owner supplies no PID, path, file or process constructor. Its capture
//! borrows an already retained pidfd and uses the same original recipe. The
//! ordinary adapter keeps its original temporary File and byte disposal.

use std::error::Error as StdError;
use std::fs::File;

use super::{PidFd, PidFdInfo, PidFdProcessIdentity, ProcStatIdentity};
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

/// Retains native prefixes of one process identity observation without authority.
///
/// The genuine purpose pays its finite footprint before capture and retains
/// the whole owner through later comparisons and independently owed posts.
#[must_use = "retain the original File, bytes and actual native results"]
pub struct PidFdProcessIdentityOriginalV1 {
    pub(super) before: Option<Result<PidFdInfo>>,
    pub(super) path: Option<String>,
    pub(super) file: Option<File>,
    pub(super) open: Option<Result<()>>,
    pub(super) bytes: Vec<u8>,
    pub(super) read: Option<Result<usize>>,
    pub(super) length: Option<Result<()>>,
    pub(super) parsed: Option<Result<ProcStatIdentity>>,
    pub(super) after: Option<Result<PidFdInfo>>,
    pub(super) coordinates: Option<Result<()>>,
    pub(super) alive: Option<Result<bool>>,
    pub(super) binding: Option<Result<PidFdProcessIdentity>>,
    returned: Option<Result<PidFdProcessIdentity>>,
    reentry: Option<Error>,
    entered: bool,
    stat_retired: bool,
}

impl PidFdProcessIdentityOriginalV1 {
    /// Creates inert original destinations without observing a process.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            before: None, path: None, file: None, open: None, bytes: Vec::new(),
            read: None, length: None, parsed: None, after: None, coordinates: None,
            alive: None, binding: None, returned: None, reentry: None, entered: false,
            stat_retired: false,
        }
    }

    /// Supplies dominant memory bytes and the one actual stat descriptor.
    ///
    /// The shared bounded parser/read supplier covers byte capacity and its
    /// borrowed-field table. No Rust field is a namespace metadata entry.
    #[must_use]
    pub fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let (parser, _) = super::super::PidFdProcObservationsV1::stat_receiving_footprint_v1();
        Some((std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(parser)?.checked_add(64)?, 1))
    }

    /// Observes once through the original process-identity recipe.
    ///
    /// # Errors
    /// Retains unavailable native operations, malformed or oversized stat
    /// bytes, changed coordinates and exited processes. A second call refuses
    /// before IO and never overwrites the earlier original result.
    pub fn capture_once(&mut self, process: &PidFd) -> Result<()> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some(super::process_identity_observed(process, &mut Some(&mut *self)));
        if matches!(self.returned, Some(Ok(_))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Borrows the completed identity DATA without establishing currentness.
    #[must_use]
    pub fn identity(&self) -> Option<PidFdProcessIdentity> {
        if self.reentry.is_some() { return None; }
        self.returned.as_ref()?.as_ref().ok().copied()
    }

    /// Closes the complete positive stat file while retaining its native proof.
    ///
    /// The exact path, bytes, parsed coordinates, pidfd information and all
    /// native results remain resident. This performs no new observation and
    /// changes neither a financial charge nor currentness permission.
    ///
    /// # Errors
    /// Refuses failure, partial capture, absent file or repeated retirement.
    pub fn retire_positive_stat_file_once_v2(&mut self) -> Result<()> {
        if self.stat_retired || self.reentry.is_some() || self.failure().is_some()
            || !matches!(self.returned, Some(Ok(_))) || self.file.is_none() {
            return Err(closed());
        }
        drop(self.file.take());
        self.stat_retired = true;
        Ok(())
    }

    /// Borrows the first actual native or semantic refusal in recipe order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        error(&self.before).or_else(|| error(&self.open))
            .or_else(|| error(&self.read)).or_else(|| error(&self.length))
            .or_else(|| error(&self.parsed)).or_else(|| error(&self.after))
            .or_else(|| error(&self.coordinates)).or_else(|| error(&self.alive))
            .or_else(|| error(&self.binding)).or_else(|| error(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for PidFdProcessIdentityOriginalV1 {
    fn default() -> Self { Self::new() }
}

pub(super) fn observe_copy<T: Copy>(
    result: Result<T>,
    original: Option<&mut Option<Result<T>>>,
) -> Result<T> {
    match original {
        None => result,
        Some(original) => {
            *original = Some(result);
            match original.as_ref() {
                Some(Ok(value)) => Ok(*value),
                _ => Err(closed()),
            }
        }
    }
}

pub(super) fn closed() -> Error {
    Error::invalid("retained process identity", "original native outcome retained")
}

fn error<T>(original: &Option<Result<T>>) -> Option<&(dyn StdError + 'static)> {
    original.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    #[test]
    fn actual_identity_keeps_stat_prefix_and_matches_same_ordinary_recipe() {
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = PidFdProcessIdentityOriginalV1::new();

        original.capture_once(&process).unwrap();

        assert_eq!(original.identity(), Some(crate::pidfd::process_identity(&process).unwrap()));
        assert!(original.file.is_some());
        assert!(!original.bytes.is_empty());
        assert!(matches!(original.open, Some(Ok(()))));
        assert!(matches!(original.read, Some(Ok(_))));
        assert!(original.failure().is_none());
    }

    #[test]
    fn positive_retirement_keeps_the_same_native_identity_and_byte_evidence() {
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = PidFdProcessIdentityOriginalV1::new();
        original.capture_once(&process).unwrap();
        let identity = original.identity();
        let before = original.before.as_ref().unwrap() as *const _;
        let bytes = original.bytes.as_ptr();

        original.retire_positive_stat_file_once_v2().unwrap();

        assert!(original.file.is_none());
        assert_eq!(original.identity(), identity);
        assert!(std::ptr::eq(before, original.before.as_ref().unwrap()));
        assert_eq!(original.bytes.as_ptr(), bytes);
        assert!(matches!(original.returned, Some(Ok(_))));
        assert!(original.failure().is_none());
        assert!(original.retire_positive_stat_file_once_v2().is_err());
    }

    #[test]
    fn reentry_fences_without_overwriting_the_actual_native_prefix() {
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = PidFdProcessIdentityOriginalV1::new();
        original.capture_once(&process).unwrap();
        let before = original.before.as_ref().unwrap() as *const _;
        let read = original.read.as_ref().unwrap() as *const _;
        let bytes = original.bytes.as_ptr();

        assert!(original.capture_once(&process).is_err());
        let failure = original.failure().unwrap().downcast_ref::<Error>().unwrap() as *const Error;
        assert!(original.capture_once(&process).is_err());

        assert!(std::ptr::eq(before, original.before.as_ref().unwrap()));
        assert!(std::ptr::eq(read, original.read.as_ref().unwrap()));
        assert_eq!(bytes, original.bytes.as_ptr());
        assert!(matches!(original.returned, Some(Ok(_))));
        assert!(original.file.is_some());
        assert!(original.identity().is_none());
        assert!(std::ptr::eq(failure, original.failure().unwrap().downcast_ref::<Error>().unwrap()));
        assert!(original.retire_positive_stat_file_once_v2().is_err());
        assert!(original.file.is_some());
    }
}
