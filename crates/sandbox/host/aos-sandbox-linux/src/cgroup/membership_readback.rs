//! Shares exact membership semantics across local and retained native storage.
//!
//! The retained caller owns both active-file probe prefixes, all fresh pidfd
//! observations, its original semantic result and independent negative posts.
//! Neither a successful snapshot nor a retained file grants service authority.

use super::{Error, PendingRegularFileV1, PidFd, PidFdInfo, Result, RetainedCgroupAnchor};

pub(super) trait MembershipStorage {
    fn active_before(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()>;
    fn info_before(&mut self, process: &PidFd) -> Result<PidFdInfo>;
    fn active_after(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()>;
    fn info_after(&mut self, process: &PidFd) -> Result<PidFdInfo>;
    fn alive(&mut self, process: &PidFd) -> Result<bool>;
}

pub(super) struct LocalMembership;

impl MembershipStorage for LocalMembership {
    fn active_before(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        anchor.validate_active()
    }

    fn info_before(&mut self, process: &PidFd) -> Result<PidFdInfo> {
        process.info()
    }

    fn active_after(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        anchor.validate_active()
    }

    fn info_after(&mut self, process: &PidFd) -> Result<PidFdInfo> {
        process.info()
    }

    fn alive(&mut self, process: &PidFd) -> Result<bool> {
        process.is_alive()
    }
}

pub(super) fn observe_exact(
    anchor: &RetainedCgroupAnchor,
    process: &PidFd,
    storage: &mut impl MembershipStorage,
) -> Result<PidFdInfo> {
    storage.active_before(anchor)?;
    let before = storage.info_before(process)?;
    if before.cgroup_id() != Some(anchor.kernel_id) {
        return Err(Error::invalid("exact cgroup membership", "pidfd does not name this cgroup"));
    }
    storage.active_after(anchor)?;
    recheck_process(process, before, storage)
}

pub(super) fn recheck_process(
    process: &PidFd,
    before: PidFdInfo,
    storage: &mut impl MembershipStorage,
) -> Result<PidFdInfo> {
    let after = storage.info_after(process)?;
    if after.pid() != before.pid()
        || after.thread_group_id() != before.thread_group_id()
        || after.cgroup_id() != before.cgroup_id()
    {
        return Err(Error::invalid(
            "cgroup membership observation",
            "process identity or membership changed during observation",
        ));
    }
    if !storage.alive(process)? {
        return Err(Error::invalid("cgroup membership observation", "pinned process exited"));
    }
    Ok(after)
}

/// Reports incomplete or permanently fenced original membership observation.
///
/// Native and semantic causes remain in [`ExactCgroupMembershipReadbackV1`].
#[derive(Debug, thiserror::Error)]
#[error("original exact-cgroup membership observation is incomplete or fenced")]
pub struct ExactCgroupMembershipRefusalV1;

#[derive(Clone, Copy)]
enum Failure {
    BeforeActive,
    BeforeInfo,
    AfterActive,
    AfterInfo,
    Liveness,
    Recipe,
    Reentry,
}

/// Retains one exact membership flight and both actual active-file probes.
///
/// Its two bounded probes and native results must be paid before entry. A
/// complete snapshot remains point-in-time DATA, not a currentness token or a
/// migration fence. The caller retains the same anchor and pidfd separately.
pub struct ExactCgroupMembershipReadbackV1 {
    probes: [PendingRegularFileV1; 2],
    retired_probe_identities: [Option<crate::path::FileIdentity>; 2],
    files_retired: bool,
    before_active: Option<Result<()>>,
    before_info: Option<Result<PidFdInfo>>,
    after_active: Option<Result<()>>,
    after_info: Option<Result<PidFdInfo>>,
    liveness: Option<Result<bool>>,
    result: Option<Result<PidFdInfo>>,
    reentry: Option<Error>,
    first: Option<Failure>,
    entered: bool,
}

impl ExactCgroupMembershipReadbackV1 {
    /// Maximum simultaneously retained active-file probe descriptors.
    pub const MAXIMUM_RETAINED_FILES_V1: usize = 2;

    /// Returns the dominant inline, fixed-path and owning-error carriers.
    ///
    /// Both pidfd information snapshots are inline. The shared active recipe
    /// creates only the fixed `cgroup.procs` C string, including its terminator;
    /// its two probe FDs are counted separately. Eight 128-byte error carriers
    /// cover the fixed diagnostic strings and native/semantic result prefixes.
    /// Native allocation metadata remains backed by the service's hard limit;
    /// this is not an exact heap or transitive allocator measurement.
    #[must_use]
    pub fn dominant_requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(b"cgroup.procs\0".len())?
            .checked_add(8 * 128)
    }

    /// Counts the fixed named entry reached by both membership probes.
    ///
    /// Both probes open `cgroup.procs` under the same retained anchor. Their
    /// result slots, identities and once controls remain byte provision, not
    /// additional namespace entries. This grants no observation or FD reuse.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        1
    }

    /// Creates empty native probe storage without opening or reading anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            probes: std::array::from_fn(|_| PendingRegularFileV1::default()),
            retired_probe_identities: [None; 2],
            files_retired: false,
            before_active: None,
            before_info: None,
            after_active: None,
            after_info: None,
            liveness: None,
            result: None,
            reentry: None,
            first: None,
            entered: false,
        }
    }

    /// Enters the shared exact-membership recipe once and parks every result.
    ///
    /// Required after-active, pidfd and liveness posts are attempted even after
    /// an earlier native or semantic error; they never replace its first cause.
    ///
    /// # Errors
    /// Returns a negative marker while [`Self::failure`] borrows the original
    /// native or semantic cause. Reentry never resamples or drops prior probes.
    pub fn capture_once(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        process: &PidFd,
    ) -> std::result::Result<(), ExactCgroupMembershipRefusalV1> {
        if self.entered {
            self.reentry.get_or_insert_with(|| Error::invalid("exact cgroup membership", "already entered"));
            self.first.get_or_insert(Failure::Reentry);
            return Err(ExactCgroupMembershipRefusalV1);
        }
        self.entered = true;
        self.result = Some(observe_exact(anchor, process, self));
        if matches!(self.result, Some(Err(_))) {
            self.first.get_or_insert(Failure::Recipe);
            if self.after_active.is_none() {
                let _post = self.active_after(anchor);
            }
            if self.after_info.is_none() {
                let _post = self.info_after(process);
            }
            if self.liveness.is_none() {
                let _post = self.alive(process);
            }
            return Err(ExactCgroupMembershipRefusalV1);
        }
        Ok(())
    }

    // The RuntimeScope exchange owes its independent outer observations at
    // different frontiers. Retain the same primary recipe without adding the
    // recovery-only independent posts performed by capture_once after refusal.
    pub(super) fn capture_recipe_once(
        &mut self, anchor: &RetainedCgroupAnchor, process: &PidFd,
    ) -> Result<PidFdInfo> {
        if self.entered {
            return Err(Error::invalid("exact cgroup membership", "already entered"));
        }
        self.entered = true;
        self.result = Some(observe_exact(anchor, process, self));
        match self.result.as_ref() {
            Some(Ok(value)) => Ok(*value),
            _ => {
                self.first.get_or_insert(Failure::Recipe);
                Err(Error::invalid("exact cgroup membership", "original recipe refused"))
            }
        }
    }

    /// Borrows the actual original recipe Result as diagnostic kernel DATA.
    ///
    /// A later reentry refusal does not rewrite an earlier successful snapshot.
    /// The caller must check the actual capture outcome and [`Self::failure`].
    #[must_use]
    pub fn result(&self) -> Option<&Result<PidFdInfo>> {
        self.result.as_ref()
    }

    /// Drops both active probes only after the whole comparison is positive.
    ///
    /// The original pidfd/active/liveness Results and each probe's captured
    /// physical identity remain resident with the once-only fence. A caller
    /// must finish any additional same-snapshot semantic comparison first.
    /// Failure, partial acquisition and reentry never release a probe here.
    #[must_use]
    pub fn retire_completed_files_once_v1(&mut self) -> bool {
        if self.files_retired
            || !matches!(self.result, Some(Ok(_)))
            || !matches!(self.before_active, Some(Ok(())))
            || !matches!(self.before_info, Some(Ok(_)))
            || !matches!(self.after_active, Some(Ok(())))
            || !matches!(self.after_info, Some(Ok(_)))
            || !matches!(self.liveness, Some(Ok(true)))
            || self.failure().is_some()
            || self.probes.iter().any(|probe| probe.file().is_err())
        {
            return false;
        }
        for (index, probe) in self.probes.iter_mut().enumerate() {
            self.retired_probe_identities[index] = probe.file().ok().map(|file| file.identity());
            drop(probe.take_readable_file());
        }
        self.files_retired = true;
        true
    }

    /// Borrows the chronological native or semantic first cause.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        fn error<T>(result: &Option<Result<T>>) -> Option<&Error> {
            result.as_ref().and_then(|result| result.as_ref().err())
        }
        match self.first? {
            Failure::BeforeActive => error(&self.before_active),
            Failure::BeforeInfo => error(&self.before_info),
            Failure::AfterActive => error(&self.after_active),
            Failure::AfterInfo => error(&self.after_info),
            Failure::Liveness => error(&self.liveness),
            Failure::Recipe => error(&self.result),
            Failure::Reentry => self.reentry.as_ref(),
        }
    }
}

impl Default for ExactCgroupMembershipReadbackV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn project<T: Copy>(
    result: &Option<Result<T>>,
    first: &mut Option<Failure>,
    slot: Failure,
) -> Result<T> {
    match result.as_ref() {
        Some(Ok(value)) => Ok(*value),
        _ => {
            first.get_or_insert(slot);
            Err(Error::invalid("exact cgroup membership", "original native outcome retained"))
        }
    }
}

impl MembershipStorage for ExactCgroupMembershipReadbackV1 {
    fn active_before(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.before_active = Some(anchor.validate_active_retaining(&mut self.probes[0]));
        project(&self.before_active, &mut self.first, Failure::BeforeActive)
    }

    fn info_before(&mut self, process: &PidFd) -> Result<PidFdInfo> {
        self.before_info = Some(process.info());
        project(&self.before_info, &mut self.first, Failure::BeforeInfo)
    }

    fn active_after(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.after_active = Some(anchor.validate_active_retaining(&mut self.probes[1]));
        project(&self.after_active, &mut self.first, Failure::AfterActive)
    }

    fn info_after(&mut self, process: &PidFd) -> Result<PidFdInfo> {
        self.after_info = Some(process.info());
        project(&self.after_info, &mut self.first, Failure::AfterInfo)
    }

    fn alive(&mut self, process: &PidFd) -> Result<bool> {
        self.liveness = Some(process.is_alive());
        project(&self.liveness, &mut self.first, Failure::Liveness)
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod tests {
    use std::num::NonZeroU32;
    use std::os::fd::AsRawFd as _;
    use std::path::Path;

    use super::*;
    use crate::cgroup::CgroupV2Root;

    #[test]
    fn exact_readback_keeps_both_real_probes_and_refuses_resampling() {
        let root = CgroupV2Root::from_owned(rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ).unwrap()).unwrap();
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership.lines().find_map(|line| line.strip_prefix("0::/")).unwrap();
        let anchor = root.resolve(Path::new(if relative.is_empty() { "." } else { relative })).unwrap();
        let process = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let expected = anchor.verify_exact_membership(&process).unwrap();
        let mut readback = ExactCgroupMembershipReadbackV1::new();

        readback.capture_once(&anchor, &process).unwrap();

        assert_eq!(*readback.result().unwrap().as_ref().unwrap(), expected);
        assert!(readback.failure().is_none());
        let probes = std::array::from_fn::<_, 2, _>(|index| {
            readback.probes[index].file().unwrap().as_fd().as_raw_fd()
        });
        assert_ne!(probes[0], probes[1]);
        assert!(readback.capture_once(&anchor, &process).is_err());
        assert!(readback.failure().is_some());
        for (index, original) in probes.into_iter().enumerate() {
            assert_eq!(readback.probes[index].file().unwrap().as_fd().as_raw_fd(), original);
        }
    }
}
