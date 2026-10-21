//! Retains the original stat acquisition at the shared pidfd identity recipe.
//!
//! This destination selects no PID/path and grants no process or healthy phase.
//! It receives only an already-retained pidfd from the genuine purpose owner.

use std::collections::TryReserveError;
use std::error::Error as StdError;

use super::negative_identity::ProcReadOriginalV1;
use super::*;

pub(super) struct StatCaptureOriginalsV1 {
    pub(super) path: Option<String>,
    pub(super) open: Option<std::result::Result<(), rustix::io::Errno>>,
    pub(super) filesystem: Option<std::result::Result<rustix::fs::StatFs, rustix::io::Errno>>,
    pub(super) flags: Option<std::result::Result<OFlags, rustix::io::Errno>>,
    pub(super) binding: Option<Result<()>>,
    pub(super) read: ProcReadOriginalV1,
    pub(super) initial_allocation: Option<std::result::Result<(), TryReserveError>>,
}

impl StatCaptureOriginalsV1 {
    pub(super) fn new() -> Self {
        Self {
            path: None,
            open: None,
            filesystem: None,
            flags: None,
            binding: None,
            read: ProcReadOriginalV1::new(),
            initial_allocation: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.open)
            .or_else(|| failure(&self.filesystem))
            .or_else(|| failure(&self.flags))
            .or_else(|| failure(&self.binding))
            .or_else(|| self.read.failure())
            .or_else(|| failure(&self.initial_allocation))
    }
}

pub(super) struct IdentityOriginalsV1 {
    pub(super) before: Option<Result<PidFdInfo>>,
    pub(super) stat: StatCaptureOriginalsV1,
    pub(super) parsed: Option<Result<super::super::identity::ProcStatIdentity>>,
    pub(super) after: Option<Result<PidFdInfo>>,
    pub(super) coordinates: Option<Result<()>>,
    pub(super) alive: Option<Result<bool>>,
}

impl IdentityOriginalsV1 {
    pub(super) fn new() -> Self {
        Self {
            before: None,
            stat: StatCaptureOriginalsV1::new(),
            parsed: None,
            after: None,
            coordinates: None,
            alive: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.before)
            .or_else(|| self.stat.failure())
            .or_else(|| failure(&self.parsed))
            .or_else(|| failure(&self.after))
            .or_else(|| failure(&self.coordinates))
            .or_else(|| failure(&self.alive))
    }
}

/// Retains one actual identity acquisition anchored by the supplied original pin.
///
/// This is nonauthorizing DATA, not a process constructor or healthy observation
/// loan. The purpose prepays it and keeps the same original pidfd throughout.
#[must_use = "retain the reached stat File, bytes and native originals"]
pub struct PidFdIdentityReadbackV1 {
    source: Option<PidFdProcObservationsV1>,
    originals: IdentityOriginalsV1,
    result: Option<Result<PidFdProcessIdentity>>,
    entered: bool,
}

impl PidFdIdentityReadbackV1 {
    /// Creates inert acquisition destinations without selecting a PID or path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            source: None,
            originals: IdentityOriginalsV1::new(),
            result: None,
            entered: false,
        }
    }

    /// Describes one stat File, actual owner and shared bounded parser/read work.
    ///
    /// Fourteen actual Result cells are retained, with one stat namespace and
    /// one fixed path cell; the shared parser table uses the admitted stat bound.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        let (heap, _) = PidFdProcObservationsV1::stat_receiving_footprint_v1();
        Some((
            std::mem::size_of::<Self>().checked_add(heap)?,
            1,
            MAXIMUM_PROC_STAT_BYTES.checked_add(16)?,
        ))
    }

    /// Captures once through the same stat/identity validation recipe.
    ///
    /// Independent final GET_INFO/liveness still run after a failed prefix.
    /// They never renew an external healthy phase or replace the first cause.
    ///
    /// # Errors
    /// Rejects reentry, unavailable procfs/kernel reads, malformed or changed
    /// stat/info coordinates or process exit. All reached native prefixes stay.
    pub fn capture_once(&mut self, original: &PidFd) -> Result<()> {
        if self.entered {
            return Err(closed());
        }
        self.entered = true;
        self.source = Some(crate::pidfd::prepare_proc_observations_v1(&(original)));
        let source = self.source.as_mut().ok_or_else(closed)?;
        source.phase = ObservationPhaseV1::Closed;
        self.result = Some(source.capture_stat_inner_observed(original, Some(&mut self.originals)));

        if self.originals.after.is_none() {
            self.originals.after = Some(original.info());
        }
        if self.originals.alive.is_none() {
            self.originals.alive = Some(original.is_alive());
        }
        if self.identity().is_some() && self.failure().is_none() {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Borrows the first actual native or typed cause in the capture order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.originals.failure().or_else(|| failure(&self.result))
    }

    /// Returns completed identity DATA without granting a healthy process phase.
    #[must_use]
    pub fn identity(&self) -> Option<PidFdProcessIdentity> {
        self.result.as_ref()?.as_ref().ok().copied()
    }
}

impl Default for PidFdIdentityReadbackV1 {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn observe_copy<T: Copy>(
    result: Result<T>,
    destination: Option<&mut Option<Result<T>>>,
) -> Result<T> {
    match destination {
        Some(destination) => {
            *destination = Some(result);
            match destination.as_ref() {
                Some(Ok(value)) => Ok(*value),
                _ => Err(closed()),
            }
        }
        None => result,
    }
}

pub(super) fn unit(slot: &Option<Result<()>>) -> Result<()> {
    match slot {
        Some(Ok(())) => Ok(()),
        _ => Err(closed()),
    }
}

fn failure<T, E: StdError + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as &dyn StdError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_self_identity_retains_stat_native_prefix_and_refuses_reentry() {
        let process = PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = PidFdIdentityReadbackV1::new();
        original.capture_once(&process).unwrap();
        assert_eq!(original.identity().unwrap(), crate::pidfd::process_identity(&process).unwrap());
        assert!(original.failure().is_none());
        let source = original.source.as_ref().unwrap();
        assert!(source.stat.file.is_some());
        assert!(!source.stat.current.is_empty());
        assert_eq!(source.stat.initial, source.stat.current);
        assert!(matches!(original.originals.stat.filesystem, Some(Ok(_))));
        assert!(matches!(original.originals.stat.flags, Some(Ok(_))));
        assert!(matches!(original.originals.after, Some(Ok(_))));
        assert!(matches!(original.originals.alive, Some(Ok(true))));
        assert!(original.capture_once(&process).is_err());
        assert!(original.identity().is_some());
        assert!(matches!(original.source.as_ref().unwrap().phase, ObservationPhaseV1::Closed));
    }
}
