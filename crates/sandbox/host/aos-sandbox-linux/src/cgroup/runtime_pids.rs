//! Retains closed pids.max and memory.max observations through one slot engine.
//!
//! The actual caller supplies its own retained anchor. This reader
//! owns DATA only: no pathname, task cap, payer or replacement cgroup comes
//! from a caller. The ordinary seven-control reader shares its slot engine.

use super::{
    CgroupLimitControlV1, LimitControlSlotV1, RetainedCgroupAnchor,
    capture_limit_control_slot_v1, recheck_limit_control_slot_v1,
};
use crate::path::PendingRegularFileV1;
use crate::{Error, Result};

/// Reports a closed negative status while the original native cause stays held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("native pids.max observation refused")]
pub struct PidsLimitReadbackRefusalV1;

/// Retains one fixed pids.max record, original descriptors and active bookends.
///
/// A complete positive observation validates the native record, exact OFD/name
/// identity and active bookends. The caller compares borrowed raw DATA against
/// its own product policy. This reader sets no limit, grants no capacity and
/// establishes no perpetual currentness. All native outcomes survive a negative.
pub struct PidsLimitReadbackV1 {
    control: CgroupLimitControlV1,
    slot: LimitControlSlotV1,
    probes: [PendingRegularFileV1; 4],
    active: [Option<Result<()>>; 4],
    capture: Option<Result<()>>,
    recheck: Option<Result<()>>,
    settlement: Option<Result<()>>,
    entered: bool,
    rechecked: bool,
}

impl Default for PidsLimitReadbackV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl PidsLimitReadbackV1 {
    /// Counts three original/name controls and four independent active probes.
    pub const MAXIMUM_RETAINED_FILES_V1: usize = 7;

    /// Creates empty fixed native storage without opening or allocating input.
    #[must_use]
    pub fn new() -> Self {
        Self::for_control(CgroupLimitControlV1::PidsMax)
    }

    // Only closed fixed-control facades choose this value. No caller-selected
    // pathname, control kind or limit enters the public native constructor.
    fn for_control(control: CgroupLimitControlV1) -> Self {
        Self {
            control,
            slot: LimitControlSlotV1::default(),
            probes: std::array::from_fn(|_| PendingRegularFileV1::default()),
            active: std::array::from_fn(|_| None),
            capture: None,
            recheck: None,
            settlement: None,
            entered: false,
            rechecked: false,
        }
    }

    /// Supplies actual inline buffers, fixed paths and owning error windows.
    ///
    /// Allocation metadata and kernel residency remain backed separately by
    /// the installed cgroup. This is not a transitive allocator measurement.
    #[must_use]
    pub fn dominant_requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(3 * b"memory.max\0".len())?
            .checked_add(4 * b"cgroup.procs\0".len())?
            .checked_add(8 * 128)
    }

    /// Captures one present native record between retained active probes.
    ///
    /// # Errors
    /// Refuses reentry, a stale anchor, missing/changed files, original native
    /// failures or malformed input. Finite values and `max` remain native DATA;
    /// the first actual cause and every reached Result stay in this reader.
    pub fn capture_once(
        &mut self,
        anchor: &RetainedCgroupAnchor,
    ) -> std::result::Result<(), PidsLimitReadbackRefusalV1> {
        if self.entered {
            return Err(PidsLimitReadbackRefusalV1);
        }
        self.entered = true;
        self.active[0] = Some(anchor.validate_active_retaining(&mut self.probes[0]));
        if matches!(self.active[0], Some(Ok(()))) {
            self.capture = Some(capture_limit_control_slot_v1(
                anchor, self.control, &mut self.slot,
            ));
        }
        // A failed initial slot cannot suppress the independently available
        // retained active-directory post.
        self.active[1] = Some(anchor.validate_active_retaining(&mut self.probes[1]));
        self.require_initial()
    }

    /// Rechecks the original OFD and fresh name between two new active probes.
    ///
    /// # Errors
    /// Refuses repeated/incomplete capture, changed bytes/name/anchor, native
    /// failures or an absent record. The independent active post still
    /// runs after an earlier available failure.
    pub fn recheck_once(
        &mut self,
        anchor: &RetainedCgroupAnchor,
    ) -> std::result::Result<(), PidsLimitReadbackRefusalV1> {
        if self.rechecked || !self.entered {
            return Err(PidsLimitReadbackRefusalV1);
        }
        self.rechecked = true;
        self.active[2] = Some(anchor.validate_active_retaining(&mut self.probes[2]));
        if matches!(self.capture, Some(Ok(()))) {
            self.recheck = Some(recheck_limit_control_slot_v1(
                anchor, self.control, &mut self.slot,
            ));
        }
        self.active[3] = Some(anchor.validate_active_retaining(&mut self.probes[3]));
        self.require_initial()?;
        if matches!(self.active[2], Some(Ok(())))
            && matches!(self.active[3], Some(Ok(())))
            && matches!(self.recheck, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(PidsLimitReadbackRefusalV1)
        }
    }

    fn require_initial(&self) -> std::result::Result<(), PidsLimitReadbackRefusalV1> {
        if matches!(self.active[0], Some(Ok(())))
            && matches!(self.active[1], Some(Ok(())))
            && matches!(self.capture, Some(Ok(())))
            && self.slot.absent.is_none()
            && self.slot.length != 0
        {
            Ok(())
        } else {
            Err(PidsLimitReadbackRefusalV1)
        }
    }

    /// Borrows the original validated native record without product policy.
    #[must_use]
    pub fn initial_bytes(&self) -> Option<&[u8]> {
        if matches!(self.capture, Some(Ok(()))) && self.slot.absent.is_none() {
            Some(&self.slot.bytes[..self.slot.length])
        } else {
            None
        }
    }

    /// Borrows the same-OFD final record after its native name comparison.
    #[must_use]
    pub fn final_bytes(&self) -> Option<&[u8]> {
        if matches!(self.recheck, Some(Ok(()))) && self.slot.absent.is_none() {
            Some(&self.slot.final_bytes[..self.slot.final_length])
        } else {
            None
        }
    }

    /// Borrows the first chronological actual native failure.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.initial_failure().or_else(|| self.final_failure())
    }

    /// Borrows the first actual cause reached before the final bookend.
    #[must_use]
    pub fn initial_failure(&self) -> Option<&Error> {
        fn error(result: &Option<Result<()>>) -> Option<&Error> {
            result.as_ref()?.as_ref().err()
        }
        [
            error(&self.active[0]),
            self.slot.absent.as_ref(),
            self.slot.absence_bookend.as_ref(),
            error(&self.capture),
            error(&self.active[1]),
        ].into_iter().flatten().next()
    }

    /// Borrows the first actual final-bookend or disposal refusal.
    #[must_use]
    pub fn final_failure(&self) -> Option<&Error> {
        fn error(result: &Option<Result<()>>) -> Option<&Error> {
            result.as_ref()?.as_ref().err()
        }
        [
            error(&self.active[2]),
            self.slot.final_absence.as_ref(),
            error(&self.recheck),
            error(&self.active[3]),
            error(&self.settlement),
        ].into_iter().flatten().next()
    }

    /// Disposes only a completely positive original and its verification FDs.
    ///
    /// The admitting owner must first complete its independent original/profile
    /// posts. Bytes, whole native Results and closed phase remain resident.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or repeated disposal without releasing any
    /// partial native owner. It neither samples again nor refunds an account.
    pub fn settle_positive_once(
        &mut self,
    ) -> std::result::Result<(), PidsLimitReadbackRefusalV1> {
        if self.settlement.is_some() {
            return Err(PidsLimitReadbackRefusalV1);
        }
        self.settlement = Some(if self.require_initial().is_ok()
            && self.rechecked
            && self.final_failure().is_none()
            && matches!(self.active[2], Some(Ok(())))
            && matches!(self.active[3], Some(Ok(())))
            && matches!(self.recheck, Some(Ok(())))
        {
            drop(std::mem::take(&mut self.slot.opening));
            drop(std::mem::take(&mut self.slot.bookend));
            drop(std::mem::take(&mut self.slot.final_name));
            for probe in &mut self.probes {
                drop(std::mem::take(probe));
            }
            Ok(())
        } else {
            Err(Error::invalid("native pids.max disposal", "complete original is not positive"))
        });
        if matches!(self.settlement, Some(Ok(()))) {
            Ok(())
        } else {
            Err(PidsLimitReadbackRefusalV1)
        }
    }
}

/// Reports a closed memory.max readback while its actual native cause stays held.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("native memory.max observation refused")]
pub struct MemoryLimitReadbackRefusalV1;

/// Reads one of the two fixed native controller/delegation records.
///
/// The sole retained limit-file engine owns every read, name and active
/// bookend. This exposes DATA only and cannot enable or adopt a controller.
pub struct CgroupControllerReadbackV2 {
    original: PidsLimitReadbackV1,
    entered: bool,
    reentry: Option<crate::Error>,
}

impl CgroupControllerReadbackV2 {
    /// Creates an inert reader for the fixed available-controller record.
    #[must_use]
    pub fn available_v2() -> Self {
        Self { original: PidsLimitReadbackV1::for_control(CgroupLimitControlV1::Controllers), entered: false, reentry: None }
    }

    /// Creates an inert reader for the fixed delegated-controller record.
    #[must_use]
    pub fn delegated_v2() -> Self {
        Self { original: PidsLimitReadbackV1::for_control(CgroupLimitControlV1::SubtreeControl), entered: false, reentry: None }
    }

    /// Prices the same whole native reader and constructor representation.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let bytes = PidsLimitReadbackV1::dominant_requested_bytes_v1()?
            .checked_sub(std::mem::size_of::<PidsLimitReadbackV1>())?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(3 * (b"cgroup.subtree_control\0".len() - b"memory.max\0".len()))?;
        Some((bytes,
            PidsLimitReadbackV1::MAXIMUM_RETAINED_FILES_V1, 2))
    }

    /// Reads the same retained record between independently owed bookends.
    ///
    /// # Errors
    /// Retains missing/changed records and original native failures/reentry.
    pub fn capture_once_v2(&mut self, anchor: &RetainedCgroupAnchor)
        -> std::result::Result<(), PidsLimitReadbackRefusalV1>
    {
        if self.entered {
            self.reentry.get_or_insert_with(|| crate::Error::invalid("Guest controller readback", "original reentry"));
            return Err(PidsLimitReadbackRefusalV1);
        }
        self.entered = true;
        let primary = self.original.capture_once(anchor);
        let after = self.original.recheck_once(anchor);
        primary?;
        after
    }

    /// Borrows only the complete compared original native record.
    #[must_use]
    pub fn bytes_v2(&self) -> Option<&[u8]> {
        if self.failure().is_some() { return None; }
        let before = self.original.initial_bytes()?;
        (self.original.final_bytes()? == before).then_some(before)
    }

    /// Closes only this whole positive reader after the caller's comparisons.
    ///
    /// # Errors
    /// Retains failed/incomplete/reentered native prefixes without disposal.
    pub fn dispose_positive_once_v2(&mut self)
        -> std::result::Result<(), PidsLimitReadbackRefusalV1>
    {
        if self.reentry.is_some() { return Err(PidsLimitReadbackRefusalV1); }
        self.original.settle_positive_once()
    }

    /// Borrows the chronological original native or parser error.
    #[must_use]
    pub fn failure(&self) -> Option<&crate::Error> { self.original.failure().or(self.reentry.as_ref()) }
}

/// Retains the fixed memory.max record through the same native slot engine.
pub struct MemoryLimitReadbackV1 {
    original: PidsLimitReadbackV1,
}

impl Default for MemoryLimitReadbackV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryLimitReadbackV1 {
    /// Counts the same three control and four active-probe descriptor slots.
    pub const MAXIMUM_RETAINED_FILES_V1: usize = PidsLimitReadbackV1::MAXIMUM_RETAINED_FILES_V1;

    /// Creates empty fixed destinations without native observation.
    #[must_use]
    pub fn new() -> Self {
        Self { original: PidsLimitReadbackV1::for_control(CgroupLimitControlV1::MemoryMax) }
    }

    /// Supplies the actual same shared carrier, paths and owning error window.
    #[must_use]
    pub fn dominant_requested_bytes_v1() -> Option<usize> {
        PidsLimitReadbackV1::dominant_requested_bytes_v1()
    }

    /// Captures fixed memory.max between independently retained active probes.
    ///
    /// # Errors
    /// Retains repeated entry, native acquisition, malformed input and absence
    /// causes exactly as the shared Pids reader; no caller cap is accepted.
    pub fn capture_once(&mut self, anchor: &RetainedCgroupAnchor) -> std::result::Result<(), MemoryLimitReadbackRefusalV1> {
        self.original.capture_once(anchor).map_err(|_| MemoryLimitReadbackRefusalV1)
    }

    /// Rechecks that same OFD and native name between new active probes.
    ///
    /// # Errors
    /// Retains changed bytes/names, failed active posts and incomplete capture.
    pub fn recheck_once(&mut self, anchor: &RetainedCgroupAnchor) -> std::result::Result<(), MemoryLimitReadbackRefusalV1> {
        self.original.recheck_once(anchor).map_err(|_| MemoryLimitReadbackRefusalV1)
    }

    /// Borrows initial native bytes without interpreting a product limit.
    #[must_use]
    pub fn initial_bytes(&self) -> Option<&[u8]> {
        self.original.initial_bytes()
    }

    /// Borrows final same-OFD native bytes after their name comparison.
    #[must_use]
    pub fn final_bytes(&self) -> Option<&[u8]> {
        self.original.final_bytes()
    }

    /// Borrows the earliest actual failure from the shared native engine.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.original.failure()
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod tests {
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::path::Path;

    use super::*;
    use crate::cgroup::{CgroupLimitReadbackV1, CgroupV2Root};

    #[test]
    fn actual_pids_record_shares_ordinary_reader_and_retains_all_posts() {
        let root = CgroupV2Root::from_owned(rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap()).unwrap();
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership.lines().find_map(|line| line.strip_prefix("0::/")).unwrap();
        let anchor = root.resolve(Path::new(if relative.is_empty() { "." } else { relative })).unwrap();
        let mut ordinary = CgroupLimitReadbackV1::default();
        ordinary.capture(&anchor).unwrap();
        let expected = ordinary.bytes(CgroupLimitControlV1::PidsMax).unwrap();
        let mut retained = PidsLimitReadbackV1::new();

        let initial = retained.capture_once(&anchor);
        let final_post = retained.recheck_once(&anchor);

        assert_eq!(retained.initial_bytes(), Some(expected));
        assert_eq!(retained.final_bytes(), Some(expected));
        assert!(initial.is_ok());
        assert!(final_post.is_ok());
        let probes = std::array::from_fn::<_, 4, _>(|index| {
            assert!(matches!(retained.active[index], Some(Ok(()))));
            retained.probes[index].file().unwrap().as_fd().as_raw_fd()
        });
        let original = retained.slot.opening.file().unwrap().as_fd().as_raw_fd();
        let first = retained.failure().map(std::ptr::from_ref);

        assert!(retained.capture_once(&anchor).is_err());
        assert!(retained.recheck_once(&anchor).is_err());
        assert_eq!(retained.failure().map(std::ptr::from_ref), first);
        assert_eq!(retained.slot.opening.file().unwrap().as_fd().as_raw_fd(), original);
        for (index, original) in probes.into_iter().enumerate() {
            assert_eq!(retained.probes[index].file().unwrap().as_fd().as_raw_fd(), original);
        }
    }
}
