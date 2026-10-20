//! Shares the fixed Owner-private directory recipes and their native custody.

use std::os::fd::AsFd as _;
use std::path::Path;

use rustix::fs::{Mode, fstat, mkdirat};

use crate::cgroup::{CgroupActiveOriginalV2, CgroupChildOriginalV2, RetainedCgroupAnchor};
use crate::{Error, Result};

pub(super) const EXECUTIONS: &str = "aos-executions-v1";
pub(super) const AGENT: &str = "aos-agent-v1";
pub(super) const MANAGER: &str = "init.scope";

pub(super) struct DirectoryOriginalV1 {
    owner: Option<Box<crate::guest_confinement::GuestOwnerOriginalV2>>,
    retained: bool,
    before: Option<Box<CgroupActiveOriginalV2>>,
    mkdir: Option<rustix::io::Result<()>>,
    child: Option<Box<CgroupChildOriginalV2>>,
    anchor: Option<RetainedCgroupAnchor>,
    stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    after: Option<Box<CgroupActiveOriginalV2>>,
    body: Option<Result<()>>,
}

impl DirectoryOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            owner: None,
            retained: true,
            before: None,
            mkdir: None,
            child: None,
            anchor: None,
            stat: None,
            after: None,
            body: None,
        }
    }

    pub(super) fn ordinary_execution_root(
        parent: &RetainedCgroupAnchor,
    ) -> Result<RetainedCgroupAnchor> {
        let mut original = Self::new();
        original.retained = false;
        original.capture(parent, EXECUTIONS, true)?;
        original.take_completed_once().ok_or_else(closed)
    }

    pub(super) fn capture_execution_root(&mut self, parent: &RetainedCgroupAnchor) -> Result<()> {
        self.capture(parent, EXECUTIONS, true)
    }

    pub(super) fn capture_agent_leaf(&mut self, parent: &RetainedCgroupAnchor) -> Result<()> {
        self.capture(parent, AGENT, false)
    }

    pub(super) fn capture_manager_leaf(&mut self, parent: &RetainedCgroupAnchor) -> Result<()> {
        self.capture(parent, MANAGER, false)
    }

    pub(super) fn capture_ssh_leaf(&mut self, parent: &RetainedCgroupAnchor,
        execution: &[u8; 16], cut: crate::process::FixedProcessCaptureCutV3,
        clock: &mut crate::process::capture_cut::CaptureProcessCutOriginalV3) -> Result<()>
    {
        if execution == &[0; 16] { return Err(closed()); }
        let mut name = String::with_capacity(36);
        name.push_str("ssh-");
        use std::fmt::Write as _;
        for byte in execution { write!(name, "{byte:02x}").map_err(|_| closed())?; }
        self.capture_clocked(parent, &name, false, Some((cut, clock)))
    }

    fn capture(
        &mut self,
        parent: &RetainedCgroupAnchor,
        name: &str,
        allow_existing: bool,
    ) -> Result<()> {
        self.capture_clocked(parent, name, allow_existing, None)
    }

    fn capture_clocked(&mut self, parent: &RetainedCgroupAnchor, name: &str,
        allow_existing: bool, clock: Option<(crate::process::FixedProcessCaptureCutV3,
            &mut crate::process::capture_cut::CaptureProcessCutOriginalV3)>) -> Result<()>
    {
        if self.body.is_some() {
            return Err(closed());
        }
        if self.retained {
            self.before = Some(Box::new(CgroupActiveOriginalV2::new()));
        }
        if !self.retained {
            self.capture_inner(parent, name, allow_existing, clock)?;
            self.body = Some(Ok(()));
            return Ok(());
        }
        self.body = Some(self.capture_inner(parent, name, allow_existing, clock));
        // The same held-parent observation remains owed after mkdir/resolve,
        // owner/mode or child refusal, independently of its primary cause.
        self.after = Some(Box::new(CgroupActiveOriginalV2::new()));
        let after = self
            .after
            .as_mut()
            .ok_or_else(closed)?
            .capture_once_v2(parent);
        if !matches!(self.body, Some(Ok(()))) {
            return Err(closed());
        }
        after?;
        Ok(())
    }

    fn capture_inner(
        &mut self,
        parent: &RetainedCgroupAnchor,
        name: &str,
        allow_existing: bool,
        clock: Option<(crate::process::FixedProcessCaptureCutV3,
            &mut crate::process::capture_cut::CaptureProcessCutOriginalV3)>,
    ) -> Result<()> {
        if self.retained {
            super::require_owner_retaining(&mut self.owner)?;
        } else {
            crate::guest_confinement::require_guest_owner()?;
        }
        if self.retained {
            self.before
                .as_mut()
                .ok_or_else(closed)?
                .capture_once_v2(parent)?;
        } else {
            parent.validate_active()?;
        }
        if let Some((cut, clock)) = clock { clock.observe(cut)?; }
        self.mkdir = Some(mkdirat(parent.as_fd(), name, Mode::from_raw_mode(0o700)));
        match self.mkdir.as_ref() {
            Some(Ok(())) => {}
            Some(Err(rustix::io::Errno::EXIST)) if allow_existing => {}
            Some(Err(source)) => {
                return Err(Error::Syscall {
                    operation: "create private Guest cgroup",
                    source: (*source).into(),
                });
            }
            None => return Err(closed()),
        }
        if self.retained {
            self.child = Some(Box::new(CgroupChildOriginalV2::new()));
            let child = self.child.as_mut().ok_or_else(closed)?;
            child.resolve_descendant_once(parent, Path::new(name))?;
            self.anchor = child.take_completed_once();
        } else {
            self.anchor = Some(parent.resolve_descendant(Path::new(name))?);
        }
        let anchor = self.anchor.as_ref().ok_or_else(closed)?;
        self.stat = Some(fstat(anchor.as_fd()));
        let stat = match self.stat.as_ref() {
            Some(Ok(stat)) => stat,
            Some(Err(source)) => {
                return Err(Error::Syscall {
                    operation: "stat private Guest cgroup",
                    source: (*source).into(),
                });
            }
            None => return Err(closed()),
        };
        crate::guest_confinement::require_guest_cgroup_object(anchor.as_fd())?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o777 != 0o700 {
            return Err(Error::invalid(
                "Guest private cgroup",
                "directory profile differs",
            ));
        }
        Ok(())
    }

    pub(super) fn take_completed_once(&mut self) -> Option<RetainedCgroupAnchor> {
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return None;
        }
        let anchor = self.anchor.take()?;
        // The exact moved child and both caller parent posts are positive.
        // Only these complete read-only temporary originals physically retire.
        drop(self.before.take());
        drop(self.after.take());
        drop(self.child.take());
        Some(anchor)
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
                    .or_else(|| {
                        self.child
                            .as_ref()
                            .and_then(|original| original.failure())
                            .map(|cause| cause as _)
                    })
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
        Self::receiving_obligations_for_name_v1(EXECUTIONS.len())
    }

    pub(super) fn receiving_obligations_for_name_v1(name_bytes: usize)
        -> Option<(usize, usize, usize)>
    {
        let active = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        let child = CgroupChildOriginalV2::receiving_obligations_v2(name_bytes)?;
        let owner = crate::guest_confinement::GuestOwnerOriginalV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(active.0.checked_mul(2)?)?
            .checked_add(child.0)?
            .checked_add(name_bytes.checked_add(1)?.checked_mul(2)?)?
            .checked_add(owner.0)?;
        Some((
            bytes,
            active.1.checked_mul(2)?.checked_add(child.1)?,
            (active
                .2
                .checked_mul(2)?
                .checked_add(child.2)?
                .checked_add(1)?)
            .checked_add(owner.2)?,
        ))
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest cgroup directory",
        "original native prefix is incomplete",
    )
}
