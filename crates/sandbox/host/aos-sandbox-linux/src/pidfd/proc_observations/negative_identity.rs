//! Owns one prearmed negative identity observation over the same stat OFD.
//!
//! Preparation derives only a duplicate of an already-captured original stat
//! descriptor and its original identity. Observation never restores a healthy
//! observation phase, selects a PID/path or grants process/role authority.

use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::io::{Read as _, Seek as _, SeekFrom};

use super::*;
use super::super::identity::{
    ProcStatIdentity, identity_with_liveness, require_stat_coordinates,
};

pub(super) struct ProcReadOriginalV1 {
    allocation: Option<std::result::Result<(), TryReserveError>>,
    rewind: Option<std::io::Result<u64>>,
    last_read: Option<std::io::Result<usize>>,
    scratch: [u8; 256],
}

impl ProcReadOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            allocation: None,
            rewind: None,
            last_read: None,
            scratch: [0; 256],
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.allocation)
            .or_else(|| failure(&self.rewind))
            .or_else(|| failure(&self.last_read))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NegativePhaseV1 {
    Fresh,
    Prepared,
    Observed,
    Closed,
}

/// Retains a single negative identity sample from the original captured stat.
///
/// This passive DATA cannot reopen the source observation owner or establish
/// a healthy role. Its purpose owner must prepay and retain the whole sample,
/// same original pidfd and all independent surrounding currentness posts.
#[must_use = "retain the original negative descriptor, bytes and native causes"]
pub struct PidFdNegativeIdentityOriginalV1 {
    duplicate: Option<std::io::Result<File>>,
    expected: Option<PidFdProcessIdentity>,
    preparation: Option<Result<()>>,
    before: Option<Result<PidFdInfo>>,
    bytes: Vec<u8>,
    read_original: ProcReadOriginalV1,
    read: Option<Result<()>>,
    parsed: Option<Result<ProcStatIdentity>>,
    after: Option<Result<PidFdInfo>>,
    coordinates: Option<Result<()>>,
    alive: Option<Result<bool>>,
    identity: Option<Result<PidFdProcessIdentity>>,
    binding: Option<Result<()>>,
    result: Option<Result<()>>,
    phase: NegativePhaseV1,
}

impl PidFdNegativeIdentityOriginalV1 {
    /// Creates inert native destinations without opening or authorizing a process.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            duplicate: None,
            expected: None,
            preparation: None,
            before: None,
            bytes: Vec::new(),
            read_original: ProcReadOriginalV1::new(),
            read: None,
            parsed: None,
            after: None,
            coordinates: None,
            alive: None,
            identity: None,
            binding: None,
            result: None,
            phase: NegativePhaseV1::Fresh,
        }
    }

    /// Supplies actual sample, bounded stat/parser work and duplicate demand.
    ///
    /// This DATA grants no observation, process, account or healthy continuation.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        let (heap, _) = PidFdProcObservationsV1::stat_receiving_footprint_v1();
        let bytes = std::mem::size_of::<Self>().checked_add(heap)?;
        // Fourteen actual result destinations, plus a conservative borrowed
        // parser field-table cell for every admitted stat byte.
        let cells = MAXIMUM_PROC_STAT_BYTES.checked_add(14)?;
        Some((bytes, 1, cells))
    }

    /// Supplies this same reader's maximum requested stat traffic, including EOF.
    ///
    /// This is passive DATA; it grants no read, descriptor or healthy phase.
    #[must_use]
    pub fn maximum_requested_read_bytes_v1() -> Option<usize> {
        MAXIMUM_PROC_STAT_BYTES.checked_add(1)
    }

    /// Observes once using this same prearmed stat OFD and original pidfd.
    ///
    /// Before/after GET_INFO, bounded native read and parser results remain
    /// resident. The final independent GET_INFO still runs after read refusal.
    /// This sample becomes terminal even on success; source readiness is never
    /// changed or reconstructed.
    ///
    /// # Errors
    /// Rejects absent preparation, repeated entry, unavailable native facts,
    /// malformed bounded stat, changed coordinates, identity or process exit.
    pub fn observe_once(&mut self, original: &PidFd) -> Result<()> {
        if self.phase != NegativePhaseV1::Prepared {
            return Err(closed());
        }
        self.phase = NegativePhaseV1::Closed;
        self.result = Some(self.observe(original));
        if matches!(self.result, Some(Ok(()))) {
            self.phase = NegativePhaseV1::Observed;
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn observe(&mut self, original: &PidFd) -> Result<()> {
        self.before = Some(original.info());
        let file = match self.duplicate.as_mut() {
            Some(Ok(file)) => Some(file),
            _ => None,
        };
        self.read = Some(read_proc_bytes(
            file, &mut self.bytes, MAXIMUM_PROC_STAT_BYTES,
            Some(&mut self.read_original),
        ));
        if matches!(self.read, Some(Ok(()))) {
            self.parsed = Some(parse_proc_stat(&self.bytes));
        }
        // This original independent post is not suppressed by a failed read.
        self.after = Some(original.info());

        let before = *value(&self.before)?;
        value(&self.read)?;
        let stat = *value(&self.parsed)?;
        let after = *value(&self.after)?;
        self.coordinates = Some(require_stat_coordinates(before, stat, after));
        value(&self.coordinates)?;
        self.alive = Some(original.is_alive());
        self.identity = Some(identity_with_liveness(before, stat, *value(&self.alive)?));
        let identity = *value(&self.identity)?;
        self.binding = Some(if Some(identity) == self.expected {
            Ok(())
        } else {
            Err(Error::invalid("proc observation", "original process identity changed"))
        });
        value(&self.binding)?;
        Ok(())
    }

    /// Borrows the earliest actual native or typed original from this sample.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.duplicate)
            .or_else(|| failure(&self.preparation))
            .or_else(|| failure(&self.before))
            .or_else(|| self.read_original.failure())
            .or_else(|| failure(&self.read))
            .or_else(|| failure(&self.parsed))
            .or_else(|| failure(&self.after))
            .or_else(|| failure(&self.coordinates))
            .or_else(|| failure(&self.alive))
            .or_else(|| failure(&self.identity))
            .or_else(|| failure(&self.binding))
            .or_else(|| failure(&self.result))
    }

    /// Returns the already-retained final GET_INFO of a complete comparison.
    ///
    /// This copies native comparison DATA only after the original stat,
    /// coordinate, expected-identity and liveness checks all succeeded. It
    /// performs no IO, returns no descriptor, renews no healthy source and
    /// cannot replace continuously held process or purpose custody.
    #[must_use]
    pub fn completed_info_v1(&self) -> Option<PidFdInfo> {
        if !self.is_complete() { return None; }
        self.after.as_ref()?.as_ref().ok().copied()
    }

    /// Reports the complete same-original comparison without authorizing reuse.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.phase == NegativePhaseV1::Observed && matches!(self.result, Some(Ok(())))
    }
}

impl Default for PidFdNegativeIdentityOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl PidFdProcObservationsV1 {
    /// Prepares one negative sample from this same healthy captured stat OFD.
    ///
    /// The duplicate enters the supplied owner before any later fallible check.
    /// Preparation does not renew this source's readiness or choose a pathname.
    /// The genuine purpose caller must pay the sample's permanent duplicate and
    /// later fixed observation demand before entering this method.
    ///
    /// # Errors
    /// Retains failed duplication, missing/closed capture or repeated preparation.
    pub fn prepare_negative_identity_once_into(
        &self,
        original: &mut PidFdNegativeIdentityOriginalV1,
    ) -> Result<()> {
        self.prepare_negative_identity_recipe_into(original, true)
    }

    /// Prepares a negative DATA sample from an already-reached native prefix.
    ///
    /// This never opens a pathname, changes source readiness or supplies an
    /// original identity when the initial capture did not establish one. The
    /// actual caller prepays this duplicate and retains the primary source.
    ///
    /// # Errors
    /// Retains reentry, absent held OFD or failed duplication. The subsequent
    /// sample retains its native read even when original binding is absent.
    pub fn prepare_available_negative_identity_once_into_v1(
        &self, original: &mut PidFdNegativeIdentityOriginalV1,
    ) -> Result<()> {
        self.prepare_negative_identity_recipe_into(original, false)
    }

    fn prepare_negative_identity_recipe_into(
        &self, original: &mut PidFdNegativeIdentityOriginalV1, completed_source: bool,
    ) -> Result<()> {
        if original.phase != NegativePhaseV1::Fresh {
            return Err(closed());
        }
        original.phase = NegativePhaseV1::Closed;
        original.preparation = Some((|| {
            if completed_source && !matches!(self.phase, ObservationPhaseV1::StatCaptured | ObservationPhaseV1::Ready) {
                return Err(closed());
            }
            original.expected = self.original_identity;
            if completed_source && original.expected.is_none() {
                return Err(closed());
            }
            let file = self.stat.file.as_ref().ok_or_else(closed)?;
            original.duplicate = Some(file.try_clone());
            if !matches!(original.duplicate, Some(Ok(_))) {
                return Err(closed());
            }
            Ok(())
        })());
        if matches!(original.preparation, Some(Ok(()))) {
            original.phase = NegativePhaseV1::Prepared;
            Ok(())
        } else {
            Err(closed())
        }
    }
}

// All existing stat/context/selected helper reads share this exact bounded
// rewind/read loop. The optional destination only retains native outcomes and
// scratch; ordinary calls keep their original native error/source projection.
pub(super) fn read_proc_bytes(
    file: Option<&mut File>,
    bytes: &mut Vec<u8>,
    maximum: usize,
    original: Option<&mut ProcReadOriginalV1>,
) -> Result<()> {
    bytes.clear();
    let bound = maximum.checked_add(1).ok_or_else(closed)?;
    let retained = original.is_some();
    let mut local_allocation = None;
    let mut local_rewind = None;
    let mut local_read = None;
    let mut local_scratch = [0_u8; 256];
    let (allocation, rewind, read, scratch) = match original {
        Some(original) => (
            &mut original.allocation, &mut original.rewind,
            &mut original.last_read, &mut original.scratch,
        ),
        None => (
            &mut local_allocation, &mut local_rewind,
            &mut local_read, &mut local_scratch,
        ),
    };
    *allocation = Some(bytes.try_reserve_exact(bound));
    if !matches!(allocation, Some(Ok(()))) {
        return Err(Error::invalid("proc observation", "bounded read allocation failed"));
    }
    let file = file.ok_or_else(closed)?;
    *rewind = Some(file.seek(SeekFrom::Start(0)));
    if !matches!(rewind, Some(Ok(_))) {
        if !retained {
            if let Some(Err(source)) = rewind.take() {
                return Err(Error::Syscall {
                    operation: "rewind(original proc observation)", source,
                });
            }
        }
        return Err(closed());
    }

    let mut interrupted = 0;
    while bytes.len() < bound {
        let available = (bound - bytes.len()).min(scratch.len());
        *read = Some(file.read(&mut scratch[..available]));
        let count = match read.as_ref() {
            Some(Ok(count)) => *count,
            Some(Err(source)) if source.kind() == std::io::ErrorKind::Interrupted
                && interrupted < READ_INTERRUPT_LIMIT =>
            {
                interrupted += 1;
                continue;
            }
            _ => {
                if !retained {
                    if let Some(Err(source)) = read.take() {
                        return Err(Error::Syscall {
                            operation: "read(original proc observation)", source,
                        });
                    }
                }
                return Err(closed());
            }
        };
        if count == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&scratch[..count]);
        interrupted = 0;
    }
    Err(Error::invalid("proc observation", "record exceeds its fixed bound"))
}

fn value<T>(slot: &Option<Result<T>>) -> Result<&T> {
    match slot {
        Some(Ok(value)) => Ok(value),
        _ => Err(closed()),
    }
}

fn failure<T, E: StdError + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err())
        .map(|cause| cause as &dyn StdError)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use super::*;

    #[test]
    fn prearmed_same_stat_can_be_observed_without_reopening_closed_source() {
        let original = PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut source = crate::pidfd::prepare_proc_observations_v1(&(original));
        source.capture_stat(&original).unwrap();
        let mut negative = PidFdNegativeIdentityOriginalV1::new();
        source.prepare_negative_identity_once_into(&mut negative).unwrap();
        assert_ne!(
            source.stat.file.as_ref().unwrap().as_raw_fd(),
            negative.duplicate.as_ref().unwrap().as_ref().unwrap().as_raw_fd(),
        );

        // Context was never captured: the ordinary full-identity Ready gate
        // refuses and permanently closes this actual source as before.
        assert!(source.observe_identity(&original).is_err());
        assert!(matches!(source.phase, ObservationPhaseV1::Closed));
        negative.observe_once(&original).unwrap();

        assert!(negative.is_complete());
        assert!(negative.failure().is_none());
        assert_eq!(
            negative.identity.as_ref().unwrap().as_ref().unwrap(),
            source.original_identity.as_ref().unwrap(),
        );
        assert_eq!(negative.before.as_ref().unwrap().as_ref().unwrap().pid(), std::process::id());
        assert_eq!(negative.after.as_ref().unwrap().as_ref().unwrap().pid(), std::process::id());
        assert!(matches!(negative.read_original.last_read, Some(Ok(0))));
        assert!(matches!(source.phase, ObservationPhaseV1::Closed));
        assert!(source.observe_identity(&original).is_err());
        assert!(negative.observe_once(&original).is_err());
        assert!(negative.is_complete());
    }
}
