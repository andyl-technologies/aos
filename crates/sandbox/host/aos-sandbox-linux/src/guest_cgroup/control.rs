//! Retains a fixed Guest control mutation and its independently owed identity posts.

use std::os::fd::{AsFd as _, OwnedFd};

use rustix::fs::{AtFlags, Mode, OFlags, fstat, openat, statat};

use crate::cgroup::{CgroupActiveOriginalV2, RetainedCgroupAnchor};
use crate::{Error, Result};

pub(super) struct ControlWriteOriginalV1 {
    owner: Option<Box<crate::guest_confinement::GuestOwnerOriginalV2>>,
    before: Option<Box<CgroupActiveOriginalV2>>,
    file: Option<rustix::io::Result<OwnedFd>>,
    stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    write: Option<rustix::io::Result<usize>>,
    file_after: Option<rustix::io::Result<rustix::fs::Stat>>,
    named_after: Option<rustix::io::Result<rustix::fs::Stat>>,
    after: Option<Box<CgroupActiveOriginalV2>>,
    body: Option<Result<()>>,
    positive: bool,
}

impl ControlWriteOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            owner: None,
            before: None,
            file: None,
            stat: None,
            write: None,
            file_after: None,
            named_after: None,
            after: None,
            body: None,
            positive: false,
        }
    }

    pub(super) fn migrate_self_once(&mut self, leaf: &RetainedCgroupAnchor) -> Result<()> {
        let bytes = format!("{}\n", std::process::id());
        self.capture(leaf, "cgroup.procs", bytes.as_bytes())
    }

    pub(super) fn delegate_once(
        &mut self,
        root: &RetainedCgroupAnchor,
        memory_missing: bool,
        pids_missing: bool,
    ) -> Result<()> {
        // Only these two fixed controller names can reach the native writer.
        let bytes: &[u8] = match (memory_missing, pids_missing) {
            (true, true) => b"+memory +pids\n",
            (true, false) => b"+memory\n",
            (false, true) => b"+pids\n",
            (false, false) => return Err(closed()),
        };
        self.capture(root, "cgroup.subtree_control", bytes)
    }

    fn capture(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        name: &'static str,
        bytes: &[u8],
    ) -> Result<()> {
        self.capture_clocked(anchor, name, bytes, None)
    }

    pub(super) fn limit_once(&mut self, anchor: &RetainedCgroupAnchor,
        memory: Option<u64>, cut: crate::process::FixedProcessCaptureCutV3,
        clock: &mut crate::process::capture_cut::CaptureProcessCutOriginalV3) -> Result<()>
    {
        let (name, value) = match memory {
            Some(0) => return Err(closed()),
            Some(value) => ("memory.max", value),
            None => ("pids.max", 4),
        };
        let bytes = format!("{value}\n");
        self.capture_clocked(anchor, name, bytes.as_bytes(), Some((cut, clock)))
    }

    // This irreversible denial is paired with cgroup.kill by the standing
    // SSH owner. It cannot raise a limit or admit a task after expiry.
    pub(super) fn seal_ssh_birth_once(&mut self, anchor: &RetainedCgroupAnchor)
        -> Result<()>
    {
        self.capture(anchor, "pids.max", b"0\n")
    }

    fn capture_clocked(&mut self, anchor: &RetainedCgroupAnchor, name: &'static str,
        bytes: &[u8], clock: Option<(crate::process::FixedProcessCaptureCutV3,
            &mut crate::process::capture_cut::CaptureProcessCutOriginalV3)>) -> Result<()>
    {
        if self.body.is_some() {
            return Err(closed());
        }
        self.before = Some(Box::new(CgroupActiveOriginalV2::new()));
        let primary = self.capture_inner(anchor, name, bytes, clock);
        self.body = Some(primary);
        self.after = Some(Box::new(CgroupActiveOriginalV2::new()));
        let after = self
            .after
            .as_mut()
            .ok_or_else(closed)?
            .capture_once_v2(anchor);
        if !matches!(self.body, Some(Ok(()))) {
            return Err(closed());
        }
        after?;
        self.positive = true;
        // This complete primitive closes its own exact File/name/active phase
        // before the separate native value/membership readback begins. Failed
        // writes, identity posts or anchor posts retain every reached owner.
        drop(self.file.take());
        drop(self.before.take());
        drop(self.after.take());
        Ok(())
    }

    fn capture_inner(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        name: &'static str,
        bytes: &[u8],
        clock: Option<(crate::process::FixedProcessCaptureCutV3,
            &mut crate::process::capture_cut::CaptureProcessCutOriginalV3)>,
    ) -> Result<()> {
        super::require_owner_retaining(&mut self.owner)?;
        self.before
            .as_mut()
            .ok_or_else(closed)?
            .capture_once_v2(anchor)?;
        self.file = Some(openat(
            anchor.as_fd(),
            name,
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let file = match self.file.as_ref() {
            Some(Ok(file)) => file,
            Some(Err(source)) => return Err(io("open fixed Guest cgroup control", *source)),
            None => return Err(closed()),
        };
        self.stat = Some(fstat(file));
        let stat = match self.stat.as_ref() {
            Some(Ok(stat)) if stat.st_uid == 0 => stat,
            Some(Err(source)) => return Err(io("stat fixed Guest cgroup control", *source)),
            _ => return Err(closed()),
        };
        crate::guest_confinement::require_guest_cgroup_object(file.as_fd())?;
        if let Some((cut, clock)) = clock { clock.observe(cut)?; }
        self.write = Some(rustix::io::write(file, bytes));
        // These two posts execute even after a short write, EINTR or native
        // failure. There is no retry, alternate File or later success adoption.
        self.file_after = Some(fstat(file));
        self.named_after = Some(statat(anchor.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW));
        match self.write.as_ref() {
            Some(Ok(count)) if *count == bytes.len() => {}
            Some(Err(source)) => return Err(io("write fixed Guest cgroup control", *source)),
            _ => return Err(closed()),
        }
        let after = match self.file_after.as_ref() {
            Some(Ok(stat)) => stat,
            Some(Err(source)) => return Err(io("recheck fixed Guest cgroup control", *source)),
            None => return Err(closed()),
        };
        let named = match self.named_after.as_ref() {
            Some(Ok(stat)) => stat,
            Some(Err(source)) => return Err(io("recheck named Guest cgroup control", *source)),
            None => return Err(closed()),
        };
        if stat.st_dev != after.st_dev
            || stat.st_ino != after.st_ino
            || stat.st_dev != named.st_dev
            || stat.st_ino != named.st_ino
            || after.st_uid != 0
            || named.st_uid != 0
        {
            return Err(closed());
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner
            .as_ref()
            .and_then(|original| original.failure())
            .or_else(|| {
                self.before
                    .as_ref()
                    .and_then(|original| original.failure())
                    .map(|cause| cause as _)
                    .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
                    .or_else(|| {
                        self.after
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
            })
    }

    pub(super) fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let owner = crate::guest_confinement::GuestOwnerOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(active.0.checked_mul(2)?)?
            .checked_add(4 * 24 + 2 * 12)?
            .checked_add(owner.0)?;
        Some((
            bytes,
            // A failed Owner predicate retains its three Files while this
            // writer still owes the independent trailing active observation.
            active.1.checked_mul(2)?.checked_add(1)?
                .max(owner.1.checked_add(active.1)?),
            2_usize.checked_add(owner.2)?,
        ))
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest control mutation",
        "original native phase is incomplete",
    )
}

fn io(operation: &'static str, source: rustix::io::Errno) -> Error {
    Error::Syscall {
        operation,
        source: source.into(),
    }
}
