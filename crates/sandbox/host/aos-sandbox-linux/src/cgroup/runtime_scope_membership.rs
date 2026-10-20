//! Retains the existing exact/descendant membership flight at its old frontiers.
//!
//! The ordinary membership recipe and strict child resolver remain the sole
//! engines. This native DATA destination adds no extra observations after an
//! early error and proves no Host role, assignment, payment or effect grant.

use super::*;
use super::membership_readback::{MembershipStorage, recheck_process};

/// Records physical retirement of a complete membership observation's files.
///
/// The original stores this proof only after all its native comparisons and
/// liveness checks succeeded. The proof is point-in-time DATA; it grants no
/// authority, currentness, migration fence or financial capacity.
pub struct RuntimeScopeMembershipFilesDisposedV4 {
    info: PidFdInfo,
}

impl RuntimeScopeMembershipFilesDisposedV4 {
    /// Returns the complete snapshot whose temporary files actually retired.
    #[must_use]
    pub fn completed_info(&self) -> PidFdInfo {
        self.info
    }
}

/// Retains one exact or hinted-descendant observation without resampling.
#[derive(Default)]
pub struct RuntimeScopeMembershipOriginalV1 {
    child: InitialCgroupChildV5,
    exact: ExactCgroupMembershipReadbackV1,
    outer_probe: PendingRegularFileV1,
    outer_active: Option<Result<()>>,
    final_info: Option<Result<PidFdInfo>>,
    final_alive: Option<Result<bool>>,
    result: Option<Result<PidFdInfo>>,
    active_result: Option<Result<()>>,
    entered: bool,
    reentry: Option<Error>,
    native_disposed: Option<RuntimeScopeMembershipFilesDisposedV4>,
    active_disposed: bool,
}

impl RuntimeScopeMembershipOriginalV1 {
    /// Creates empty destinations without observing any kernel object.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Runs the same existing exact or strict-descendant membership flight once.
    ///
    /// # Errors
    /// Keeps every reached child/probe and the original refusal. It attempts no
    /// new post beyond those reached by the original ordinary recipe.
    pub fn capture_once(
        &mut self, anchor: &RetainedCgroupAnchor, process: &PidFd, hint: Option<&Path>,
    ) -> Result<()> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.result = Some(self.capture_recipe(anchor, process, hint));
        if matches!(self.result, Some(Ok(_))) { Ok(()) } else { Err(closed()) }
    }

    fn capture_recipe(
        &mut self, anchor: &RetainedCgroupAnchor, process: &PidFd, hint: Option<&Path>,
    ) -> Result<PidFdInfo> {
        let Some(hint) = hint else { return self.exact.capture_recipe_once(anchor, process); };
        anchor.resolve_worker_descendant_retaining(hint, &mut self.child)?;
        let child = self.child.anchor.as_ref().ok_or_else(closed)?;
        let info = self.exact.capture_recipe_once(child, process)?;
        self.outer_active = Some(anchor.validate_active_retaining(&mut self.outer_probe));
        if !matches!(self.outer_active, Some(Ok(()))) {
            return Err(closed());
        }
        recheck_process(process, info, self)
    }

    /// Retains the same single active-file validation used before socket opening.
    ///
    /// # Errors
    /// Keeps its actual native probe and cause; refuses a repeated entry.
    pub fn capture_active_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.active_result = Some(anchor.validate_active_retaining(&mut self.outer_probe));
        if matches!(self.active_result, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    /// Borrows the first actual reached child, membership or final native cause.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.exact.failure()
            .or_else(|| self.outer_active.as_ref()?.as_ref().err())
            .or_else(|| self.final_info.as_ref()?.as_ref().err())
            .or_else(|| self.final_alive.as_ref()?.as_ref().err())
            .or_else(|| self.active_result.as_ref()?.as_ref().err())
            .or_else(|| self.result.as_ref()?.as_ref().err())
            .or_else(|| self.reentry.as_ref())
    }

    /// Returns only the actual complete native snapshot as nonauthorizing DATA.
    #[must_use]
    pub fn completed_info(&self) -> Option<PidFdInfo> {
        self.result.as_ref()?.as_ref().ok().copied()
    }

    /// Physically closes the exact completed observation's temporary files.
    ///
    /// The caller finishes any additional comparison using this snapshot first.
    /// The original keeps every native result, its completed snapshot and its
    /// once-only entry fence. Failure, partial capture, active-only capture and
    /// reentry retain their native prefixes and cannot produce this proof.
    #[must_use]
    pub fn retire_completed_files_once_v4(
        &mut self,
    ) -> Option<&RuntimeScopeMembershipFilesDisposedV4> {
        let info = self.completed_info()?;
        if self.native_disposed.is_some() || self.failure().is_some() {
            return None;
        }
        if !self.exact.retire_completed_files_once_v1() {
            return None;
        }

        // Descendant resolution and the final outer active probe have no
        // consumer after the complete exact/outer/pidfd/liveness conjunction.
        // Their real anchor is temporary; the input anchor and pidfd remain
        // with the caller. Ordinary membership observations are unchanged.
        drop(std::mem::take(&mut self.child));
        drop(self.outer_probe.take_readable_file());
        self.native_disposed = Some(RuntimeScopeMembershipFilesDisposedV4 { info });
        self.native_disposed.as_ref()
    }

    /// Borrows this original's actual completed native-file disposal proof.
    #[must_use]
    pub fn native_disposal_v4(&self) -> Option<&RuntimeScopeMembershipFilesDisposedV4> {
        if self.failure().is_some() {
            return None;
        }
        self.native_disposed.as_ref()
    }

    /// Physically closes a complete active-only observation's temporary file.
    ///
    /// The original positive result and once fence remain. Failed, partial,
    /// exact-membership and repeated retirement attempts cannot enter this cut.
    /// This point-in-time disposal DATA grants no currentness or funding.
    #[must_use]
    pub fn retire_active_file_once_v5(&mut self) -> bool {
        if !matches!(self.active_result, Some(Ok(()))) || self.result.is_some()
            || self.failure().is_some() || self.active_disposed || self.outer_probe.file().is_err()
        { return false; }
        drop(self.outer_probe.take_readable_file());
        self.active_disposed = true;
        true
    }

    /// Reports physical disposal of this same complete active-only sample.
    #[must_use]
    pub fn active_file_is_disposed_v5(&self) -> bool {
        self.active_disposed && matches!(self.active_result, Some(Ok(()))) && self.failure().is_none()
    }

    /// Returns the exact-membership recipe's byte/FD/fixed-name bound.
    #[must_use]
    pub fn exact_receiving_demand_v1() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?;
        Some((bytes, 2, 1))
    }

    /// Returns the single active-file probe's byte/FD/fixed-name bound.
    #[must_use]
    pub fn active_receiving_demand_v1() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(b"cgroup.procs\0".len())?.checked_add(128)?, 1, 1))
    }

    /// Returns requested bytes, held native FDs and bounded actual path/name cardinality DATA.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        // Strict child/active recipes use the existing bounded4096 hint/path
        // conversion. Their pending child, root/target probes and exact pair
        // coexist with the final outer probe on a descendant flight.
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(MAXIMUM_DESCENDANT_HINT_BYTES.checked_mul(4)?)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?;
        let namespace_entries = MAXIMUM_DESCENDANT_HINT_BYTES.checked_div(2)?.checked_add(3)?;
        Some((bytes, 7, namespace_entries))
    }
}

fn closed() -> Error { Error::invalid("runtime scope membership", "original flight incomplete or refused") }

impl MembershipStorage for RuntimeScopeMembershipOriginalV1 {
    fn active_before(&mut self, _: &RetainedCgroupAnchor) -> Result<()> { Err(closed()) }
    fn info_before(&mut self, _: &PidFd) -> Result<PidFdInfo> { Err(closed()) }
    fn active_after(&mut self, _: &RetainedCgroupAnchor) -> Result<()> { Err(closed()) }

    fn info_after(&mut self, process: &PidFd) -> Result<PidFdInfo> {
        self.final_info = Some(process.info());
        match self.final_info.as_ref() { Some(Ok(value)) => Ok(*value), _ => Err(closed()) }
    }

    fn alive(&mut self, process: &PidFd) -> Result<bool> {
        self.final_alive = Some(process.is_alive());
        match self.final_alive.as_ref() { Some(Ok(value)) => Ok(*value), _ => Err(closed()) }
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    #[test]
    fn complete_exact_membership_retires_once_without_rearming_the_observation() {
        let descriptor = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let root = CgroupV2Root::from_owned(descriptor).unwrap();
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership.lines()
            .find_map(|line| line.strip_prefix("0::/")).unwrap();
        let anchor = root.resolve(Path::new(if relative.is_empty() { "." } else { relative })).unwrap();
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = RuntimeScopeMembershipOriginalV1::new();

        original.capture_once(&anchor, &process, None).unwrap();
        let observed = original.completed_info().unwrap();
        let disposed = original.retire_completed_files_once_v4().unwrap();

        assert_eq!(disposed.completed_info(), observed);
        assert_eq!(original.completed_info(), Some(observed));
        assert!(original.native_disposal_v4().is_some());
        assert!(original.retire_completed_files_once_v4().is_none());
        assert!(!original.exact.retire_completed_files_once_v1());
        assert!(original.capture_once(&anchor, &process, None).is_err());
        assert!(original.failure().is_some());
        assert!(original.native_disposal_v4().is_none());
    }

    #[test]
    fn complete_active_sample_closes_its_actual_file_and_never_rearms() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let descriptor = rustix::fs::open("/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let root = CgroupV2Root::from_owned(descriptor).unwrap();
        let anchor = root.resolve(Path::new(".")).unwrap();
        let mut original = RuntimeScopeMembershipOriginalV1::new();

        original.capture_active_once(&anchor).unwrap();
        let raw = original.outer_probe.file().unwrap().as_fd().as_raw_fd();
        assert!(Path::new(&format!("/proc/self/fd/{raw}")).exists());
        assert!(original.retire_active_file_once_v5());

        assert!(!Path::new(&format!("/proc/self/fd/{raw}")).exists());
        assert!(original.active_file_is_disposed_v5());
        assert!(!original.retire_active_file_once_v5());
        assert!(original.capture_active_once(&anchor).is_err());
        assert!(!original.active_file_is_disposed_v5());
        assert!(original.failure().is_some());
    }

    #[test]
    fn actual_descendant_refusal_keeps_the_original_and_cannot_retire() {
        let descriptor = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap();
        let root = CgroupV2Root::from_owned(descriptor).unwrap();
        let anchor = root.resolve(Path::new(".")).unwrap();
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = RuntimeScopeMembershipOriginalV1::new();
        // A deliberately unrelated hint reaches the real strict resolver's
        // native NOENT, without requiring a writable cgroup or a helper task.
        original.capture_once(&anchor, &process, Some(Path::new("aos-absent-membership-proof-v4")))
            .unwrap_err();
        let address = original.failure().unwrap() as *const Error;

        assert!(original.retire_completed_files_once_v4().is_none());
        assert!(!original.retire_active_file_once_v5());
        assert!(!original.active_file_is_disposed_v5());
        assert!(original.capture_once(&anchor, &process, None).is_err());
        assert_eq!(original.failure().unwrap() as *const Error, address);
        assert!(original.native_disposal_v4().is_none());
    }
}
