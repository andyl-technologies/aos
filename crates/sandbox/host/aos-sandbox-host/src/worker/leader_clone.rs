//! Shares supervisor pin duplication with a retained failed-adoption owner.
//!
//! This mechanical adapter duplicates only its actual borrowed PinnedLeader.
//! It creates no role, numeric-PID selector, scope permission or funding loan.

use super::*;
use aos_sandbox_linux::pidfd::RuntimeScopeReceivedPidFdOriginalV1;

macro_rules! clone_descriptor_v3 {
    (Local, $leader:ident, $original:ident) => {
        $leader.pidfd.as_fd().try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $leader:ident, $original:ident) => {{
        $original.duplicate = Some($leader.pidfd.as_fd().try_clone_to_owned());
        match $original.duplicate.take() {
            Some(Ok(fd)) => fd,
            Some(Err(cause)) => {
                $original.duplicate = Some(Err(cause));
                return Err(closed());
            }
            None => return Err(closed()),
        }
    }};
}

macro_rules! clone_adoption_v3 {
    (Local, $descriptor:ident, $original:ident) => {
        PidFd::from_owned($descriptor).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $descriptor:ident, $original:ident) => {{
        $original.adoption.capture_once($descriptor).map_err(|_| closed())?;
        $original.adoption.take_completed_once().ok_or_else(closed)?
    }};
}

macro_rules! clone_recipe_v3 {
    ($leader:ident, $mode:ident, $original:ident) => {{
        let descriptor = clone_descriptor_v3!($mode, $leader, $original);
        Ok(PinnedLeader {
            handle: $leader.handle,
            pidfd: clone_adoption_v3!($mode, descriptor, $original),
            cgroup: $leader.cgroup.clone(),
        })
    }};
}

pub(super) fn clone_local(leader: &PinnedLeader) -> Result<PinnedLeader> {
    clone_recipe_v3!(leader, Local, unused)
}

pub(crate) struct PinnedLeaderCloneOriginalV3 {
    duplicate: Option<std::io::Result<OwnedFd>>,
    adoption: RuntimeScopeReceivedPidFdOriginalV1,
    completed: Option<Result<PinnedLeader>>,
    entered: bool,
}

impl PinnedLeaderCloneOriginalV3 {
    pub(crate) fn new() -> Self {
        Self { duplicate: None, adoption: RuntimeScopeReceivedPidFdOriginalV1::new(), completed: None, entered: false }
    }

    pub(crate) fn capture_once_v3(&mut self, leader: &PinnedLeader) -> Result<()> {
        if self.entered { return Err(closed()); }
        self.entered = true;
        self.completed = Some((|| clone_recipe_v3!(leader, Retained, self))());
        if matches!(self.completed, Some(Ok(_))) { Ok(()) } else { Err(closed()) }
    }

    pub(crate) fn take_completed_once_v3(&mut self) -> Option<PinnedLeader> {
        if !matches!(self.completed, Some(Ok(_))) { return None; }
        self.completed.take()?.ok()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.duplicate.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.adoption.failure().map(|cause| cause as _))
            .or_else(|| self.completed.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(crate) fn receiving_obligations_v3() -> Option<(usize, usize)> {
        let adoption = RuntimeScopeReceivedPidFdOriginalV1::receiving_demand_v1()?;
        let path = aos_systemd_client::SandboxUnitName::from_incarnation([1; 16]).cgroup_path();
        Some((std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(adoption.0)?.checked_add(path.as_str().len().checked_mul(2)?)?, adoption.1))
    }
}

fn closed() -> HostError { HostError::Fence("retained supervisor duplicate is incomplete") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_supervisor_duplicate_moves_once_and_survives_refused_reentry() {
        let leader = PinnedLeader {
            handle: [1; 32],
            pidfd: PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap(),
            cgroup: SandboxUnitName::from_incarnation([2; 16]).cgroup_path(),
        };
        let mut original = PinnedLeaderCloneOriginalV3::new();
        original.capture_once_v3(&leader).unwrap();
        let before = original.completed.as_ref().unwrap().as_ref().unwrap().pidfd().info().unwrap();

        assert!(original.capture_once_v3(&leader).is_err());

        let duplicate = original.take_completed_once_v3().unwrap();
        assert_eq!(duplicate.handle(), leader.handle());
        assert_eq!(duplicate.pidfd().info().unwrap(), before);
        assert_eq!(before, leader.pidfd().info().unwrap());
        assert!(original.take_completed_once_v3().is_none());
        assert!(duplicate.pidfd().is_alive().unwrap());
    }
}
