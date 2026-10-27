//! Rechecks the actual unreaped child after its private completion pipe reply.

use std::path::Path;

use crate::cgroup::{
    CgroupActiveOriginalV2, CgroupChildOriginalV2, ExactCgroupMembershipReadbackV1,
    RetainedCgroupAnchor,
};
use aos_linux_descriptors::pidfd::PidFd;
use crate::pidfd::PidFdProcessIdentityOriginalV1;
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;

pub(super) struct AgentCompletionOriginalV1 {
    child: CgroupChildOriginalV2,
    anchor: Option<RetainedCgroupAnchor>,
    identity: Option<Box<PidFdProcessIdentityOriginalV1>>,
    membership: Option<Box<ExactCgroupMembershipReadbackV1>>,
    after: Option<Box<CgroupActiveOriginalV2>>,
    body: Option<Result<()>>,
}

impl AgentCompletionOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            child: CgroupChildOriginalV2::new(),
            anchor: None,
            identity: None,
            membership: None,
            after: None,
            body: None,
        }
    }

    pub(super) fn capture_once(
        &mut self,
        root: &RetainedCgroupAnchor,
        actual_child: &PidFd,
    ) -> Result<()> {
        if self.body.is_some() {
            return Err(closed());
        }
        self.body = Some((|| {
            self.child
                .resolve_descendant_once(root, Path::new(super::directory::AGENT))?;
            self.anchor = self.child.take_completed_once();
            let leaf = self.anchor.as_ref().ok_or_else(closed)?;
            self.identity = Some(Box::new(PidFdProcessIdentityOriginalV1::new()));
            let identity = self.identity.as_mut().ok_or_else(closed)?;
            identity.capture_once(actual_child)?;
            let identity = identity.identity().ok_or_else(closed)?;
            if identity.parent_pid() != 1
                || identity.pid() == 1
                || identity.thread_group_id() != identity.pid()
                || identity.cgroup_id() != Some(leaf.kernel_id())
            {
                return Err(closed());
            }
            self.membership = Some(Box::new(ExactCgroupMembershipReadbackV1::new()));
            self.membership
                .as_mut()
                .ok_or_else(closed)?
                .capture_once(leaf, actual_child)
                .map_err(|_| closed())?;
            Ok(())
        })());
        // Independent original-root post remains owed even after a refused
        // child resolution, identity comparison or exact membership read.
        self.after = Some(Box::new(CgroupActiveOriginalV2::new()));
        let _ = self.after.as_mut().map(|after| after.capture_once_v2(root));
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(closed());
        }
        if !self
            .anchor
            .as_ref()
            .is_some_and(|anchor| self.child.retire_completed_prefix_once_v4(anchor))
        {
            return Err(closed());
        }
        // The actual unreaped Child/pidfd stay with PID 1. Only these fully
        // completed readonly observations and their temporary anchor retire.
        drop(self.identity.take());
        drop(self.membership.take());
        drop(self.after.take());
        drop(self.anchor.take());
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.child
            .failure()
            .map(|cause| cause as _)
            .or_else(|| {
                self.identity
                    .as_ref()
                    .and_then(|original| original.failure())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.membership
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
    }

    pub(super) fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let child = CgroupChildOriginalV2::receiving_obligations_v2(super::directory::AGENT.len())?;
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let after = CgroupActiveOriginalV2::receiving_obligations_v2()?;
        Some((
            std::mem::size_of::<Self>()
                .checked_mul(2)?
                .checked_add(child.0)?
                .checked_add(identity.0)?
                .checked_add(after.0)?
                .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?,
            child
                .1
                .checked_add(identity.1)?
                .checked_add(after.1)?
                .checked_add(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)?,
            child.2.checked_add(after.2)?.checked_add(2)?,
        ))
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest Agent completion",
        "same actual child has not completed fixed leaf placement",
    )
}
