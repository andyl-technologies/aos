//! Joins the actual child, PID 1 and fixed native roots to their sealed handoff.

use std::num::NonZeroU32;
use std::path::Path;

use crate::cgroup::{CgroupChildOriginalV2, ExactCgroupMembershipReadbackV1, RetainedCgroupAnchor};
use crate::pidfd::{PidFd, PidFdOpenAttemptV1, PidFdProcessIdentityOriginalV1};
use crate::{Error, Result};

use super::handoff::TopologyRecordV1;

pub(super) struct AgentParentOriginalV1 {
    children: [CgroupChildOriginalV2; 2],
    anchors: [Option<RetainedCgroupAnchor>; 2],
    parent_open: PidFdOpenAttemptV1,
    parent: Option<PidFd>,
    identity: [Option<Box<PidFdProcessIdentityOriginalV1>>; 2],
    membership: [Option<Box<ExactCgroupMembershipReadbackV1>>; 2],
    body: Option<Result<()>>,
}

impl AgentParentOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            children: std::array::from_fn(|_| CgroupChildOriginalV2::new()),
            anchors: [None, None],
            parent_open: PidFdOpenAttemptV1::new(),
            parent: None,
            identity: std::array::from_fn(|_| None),
            membership: std::array::from_fn(|_| None),
            body: None,
        }
    }

    pub(super) fn capture_once(
        &mut self,
        root: &RetainedCgroupAnchor,
        provisioning: &rustix::fs::Stat,
        actual_child: &PidFd,
        record: TopologyRecordV1,
    ) -> Result<()> {
        if self.body.is_some() {
            return Err(closed());
        }
        self.body = Some(self.capture(root, provisioning, actual_child, record));
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn capture(
        &mut self,
        root: &RetainedCgroupAnchor,
        provisioning: &rustix::fs::Stat,
        actual_child: &PidFd,
        record: TopologyRecordV1,
    ) -> Result<()> {
        if std::process::id() == 1
            || root.kernel_id() != record.root
            || [
                provisioning.st_dev,
                provisioning.st_ino,
                provisioning.st_size as u64,
            ] != record.provisioning
        {
            return Err(closed());
        }
        for (index, (name, expected)) in [
            (super::directory::MANAGER, record.manager),
            (super::directory::EXECUTIONS, record.execution),
        ]
        .into_iter()
        .enumerate()
        {
            self.children[index].resolve_descendant_once(root, Path::new(name))?;
            self.anchors[index] = self.children[index].take_completed_once();
            if !self.anchors[index]
                .as_ref()
                .is_some_and(|anchor| anchor.kernel_id() == expected)
            {
                return Err(closed());
            }
        }
        let parent = NonZeroU32::new(1).ok_or_else(closed)?;
        self.parent_open
            .capture_once(parent)
            .map_err(|_| closed())?;
        self.parent = self.parent_open.take_validated();
        let parent = self.parent.as_ref().ok_or_else(closed)?;
        for (index, process) in [actual_child, parent].into_iter().enumerate() {
            self.identity[index] = Some(Box::new(PidFdProcessIdentityOriginalV1::new()));
            self.identity[index]
                .as_mut()
                .ok_or_else(closed)?
                .capture_once(process)?;
            self.membership[index] = Some(Box::new(ExactCgroupMembershipReadbackV1::new()));
            self.membership[index]
                .as_mut()
                .ok_or_else(closed)?
                .capture_once(self.anchors[0].as_ref().ok_or_else(closed)?, process)
                .map_err(|_| closed())?;
        }
        let child = self.identity[0]
            .as_ref()
            .and_then(|original| original.identity())
            .ok_or_else(closed)?;
        let parent = self.identity[1]
            .as_ref()
            .and_then(|original| original.identity())
            .ok_or_else(closed)?;
        if child.pid() != std::process::id()
            || child.thread_group_id() != child.pid()
            || child.parent_pid() != 1
            || child.cgroup_id() != Some(record.manager)
            || parent.pid() != 1
            || parent.thread_group_id() != 1
            || parent.start_time_ticks() != record.parent_start
            || parent.cgroup_id() != Some(record.manager)
        {
            return Err(closed());
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.children
            .iter()
            .find_map(|original| original.failure().map(|cause| cause as _))
            .or_else(|| self.parent_open.failure().map(|cause| cause as _))
            .or_else(|| {
                self.identity
                    .iter()
                    .flatten()
                    .find_map(|original| original.failure().map(|cause| cause as _))
            })
            .or_else(|| {
                self.membership
                    .iter()
                    .flatten()
                    .find_map(|original| original.failure().map(|cause| cause as _))
            })
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(super) fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let child =
            CgroupChildOriginalV2::receiving_obligations_v2(super::directory::EXECUTIONS.len())?;
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let membership = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(child.0.checked_mul(2)?)?
            .checked_add(identity.0.checked_mul(2)?)?
            .checked_add(membership.checked_mul(2)?)?
            .checked_add(4 * 256)?;
        Some((
            bytes,
            child
                .1
                .checked_mul(2)?
                .checked_add(1)?
                .checked_add(identity.1.checked_mul(2)?)?
                .checked_add(
                    ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)?,
                )?,
            child.2.checked_mul(2)?.checked_add(2)?,
        ))
    }
}

fn closed() -> Error {
    Error::invalid(
        "Guest topology parent",
        "actual PID1/Agent native custody differs",
    )
}
