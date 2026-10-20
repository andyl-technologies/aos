//! Shares sandbox-state projection and supervisor pinning with retained inputs.
//!
//! The selected caller parks the actual SDK observation before this native
//! recipe. Its returned leader remains here until the SDK local posts finish;
//! failed cgroup/freezer/pidfd prefixes never disappear behind a status marker.

use aos_sandbox_linux::cgroup::{
    CgroupChildOriginalV2, CgroupRootOriginalV2, FreezerReadOriginalV2,
};
use aos_sandbox_linux::path::BeneathRootResolveOriginalV2;
use aos_sandbox_linux::pidfd::{PidFdInfo, PidFdOpenAttemptV1};

use super::*;

type Native<T> = std::result::Result<T, aos_sandbox_linux::Error>;

macro_rules! leader_native {
    (Local, $original:ident, $field:ident, $expression:expr) => {
        $expression.map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $expression:expr) => {{
        $original.$field = Some($expression);
        match $original.$field.as_ref() {
            Some(Ok(value)) => *value,
            _ => return Err(closed("leader native observation failed; original retained")),
        }
    }};
}

macro_rules! leader_root {
    (Local, $worker:ident, $relative:ident, $original:ident) => {
        $worker.cgroup_root.resolve(Path::new($relative), ResolveOptions::directory())
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $worker:ident, $relative:ident, $original:ident) => {{
        $original.supervisor.resolve_once(&$worker.cgroup_root, Path::new($relative), ResolveOptions::directory())
            .map_err(|_| closed("supervisor root resolution failed; original retained"))?;
        $original.completed_supervisor = Some($original.supervisor.take_directory_root_once()
            .ok_or_else(|| closed("supervisor root is incomplete"))?);
        $original.completed_supervisor.as_ref().ok_or_else(|| closed("supervisor root is absent"))?
    }};
}

macro_rules! leader_pidfd {
    (Local, $pid:ident, $original:ident) => {
        PidFd::open($pid).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $pid:ident, $original:ident) => {{
        $original.opening.capture_once($pid)
            .map_err(|_| closed("supervisor pidfd opening failed; original retained"))?;
        $original.pidfd = Some($original.opening.take_validated()
            .ok_or_else(|| closed("supervisor pidfd opening is incomplete"))?);
        $original.pidfd.as_ref().ok_or_else(|| closed("supervisor pidfd is absent"))?
    }};
}

macro_rules! leader_finish {
    (Local, $original:ident, $handle:ident, $pidfd:ident, $cgroup:ident) => {
        Ok::<PinnedLeader, HostError>(PinnedLeader { handle: $handle, pidfd: $pidfd, cgroup: $cgroup.clone() })
    };
    (Retained, $original:ident, $handle:ident, $pidfd:ident, $cgroup:ident) => {
        Ok::<PinnedLeader, HostError>(PinnedLeader {
            handle: $handle,
            pidfd: $original.pidfd.take().ok_or_else(|| closed("completed leader pidfd is absent"))?,
            cgroup: $cgroup.clone(),
        })
    };
}

macro_rules! leader_recipe {
    ($worker:ident, $identity:ident, $observation:ident, $pid:ident, $mode:ident, $original:ident) => {{
        let invocation_id = $observation.invocation_id.ok_or_else(|| {
            HostError::Worker("sandbox leader has no systemd invocation ID".to_owned())
        })?;
        let cgroup = $observation.cgroup.as_ref().ok_or_else(|| {
            HostError::Worker("sandbox leader has no verified unit cgroup".to_owned())
        })?;
        let supervisor = cgroup.supervisor_subgroup();
        let supervisor_relative = supervisor.as_str().trim_start_matches('/');
        let supervisor = leader_root!($mode, $worker, supervisor_relative, $original);
        let pidfd = leader_pidfd!($mode, $pid, $original);
        let info = leader_native!($mode, $original, info, pidfd.info());
        if info.pid() != $pid.get() || info.thread_group_id() != $pid.get() {
            return Err(HostError::Worker(
                "systemd MainPID is not the pinned thread-group leader".to_owned(),
            ));
        }
        let cgroup_id = info.cgroup_id().ok_or_else(|| {
            HostError::Worker("kernel omitted leader cgroup identity".to_owned())
        })?;
        if cgroup_id != supervisor.identity().inode {
            return Err(HostError::Worker(
                "pinned leader is outside the expected supervisor cgroup".to_owned(),
            ));
        }
        if !leader_native!($mode, $original, alive, pidfd.is_alive()) {
            return Err(HostError::Worker(
                "sandbox supervisor exited during identity validation".to_owned(),
            ));
        }

        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.host.leader.v1\0");
        digest.update($identity.incarnation_id());
        digest.update(invocation_id);
        digest.update(cgroup_id.to_le_bytes());
        digest.update($pid.get().to_le_bytes());
        let handle = digest.finalize().into();
        leader_finish!($mode, $original, handle, pidfd, cgroup)
    }};
}


macro_rules! observation_freezer {
    (Local, $worker:ident, $cgroup:ident, $original:ident) => {
        resolve_payload_cgroup(&$worker.cgroup_root, $cgroup)?.freezer_state()
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $worker:ident, $cgroup:ident, $original:ident) => {{
        let payload = $cgroup.payload_subgroup();
        let relative = Path::new(payload.as_str().trim_start_matches('/'));
        $original.payload.resolve_once(&$worker.cgroup_root, relative, ResolveOptions::directory())
            .map_err(|_| closed("payload cgroup resolution failed; original retained"))?;
        let root = $original.payload.take_directory_root_once()
            .ok_or_else(|| closed("payload cgroup root is incomplete"))?;
        $original.root.from_beneath_once(root)
            .map_err(|_| closed("payload cgroup admission failed; original retained"))?;
        $original.completed_root = Some($original.root.take_completed_once()
            .ok_or_else(|| closed("payload cgroup admission is incomplete"))?);
        let root = $original.completed_root.as_ref().ok_or_else(|| closed("payload cgroup root is absent"))?;
        $original.child.resolve_once(root, Path::new("."))
            .map_err(|_| closed("payload same-root anchor failed; original retained"))?;
        $original.anchor = Some($original.child.take_completed_once()
            .ok_or_else(|| closed("payload same-root anchor is incomplete"))?);
        let anchor = $original.anchor.as_ref().ok_or_else(|| closed("payload same-root anchor is absent"))?;
        $original.freezer.observe_once(anchor)
            .map_err(|_| closed("payload freezer observation failed; original retained"))?;
        $original.freezer.take_completed_once()
            .ok_or_else(|| closed("payload freezer observation is incomplete"))?
    }};
}

macro_rules! observation_recipe {
    ($worker:ident, $identity:ident, $observation:ident, $mode:ident, $original:ident) => {{
        let payload_freezer = if $observation.active_state == "active" {
            let cgroup = $observation.cgroup.as_ref().ok_or_else(|| {
                HostError::Worker("active sandbox unit has no exact cgroup".to_owned())
            })?;
            Some(observation_freezer!($mode, $worker, cgroup, $original))
        } else { None };
        let state = classify_state($observation, payload_freezer);
        let leader = match $observation.supervisor_pid {
            Some(pid) => Some(leader_recipe!($worker, $identity, $observation, pid, $mode, $original)?),
            None if matches!(state, ObservedRuntimeState::Starting | ObservedRuntimeState::Ready | ObservedRuntimeState::Frozen) => {
                return Err(HostError::Worker(
                    "active sandbox unit has no supervisor MainPID".to_owned(),
                ));
            }
            None => None,
        };
        Ok(WorkerObservation {
            state,
            invocation_id: $observation.invocation_id,
            leader,
            payload: None,
        })
    }};
}

pub(super) fn project_local(
    worker: &SystemdOneShotWorker,
    identity: &HostRuntimeIdentity,
    observation: &SandboxUnitObservation,
) -> Result<WorkerObservation> {
    observation_recipe!(worker, identity, observation, Local, unused)
}

struct SandboxNativeMovedV4 {
    leader: Option<[u8; 32]>,
}

pub(in crate::worker) struct SandboxNativeOriginalV2 {
    entered: bool,
    completed_move: Option<SandboxNativeMovedV4>,
    observation: Option<SandboxUnitObservation>,
    payload: BeneathRootResolveOriginalV2,
    root: CgroupRootOriginalV2,
    completed_root: Option<CgroupV2Root>,
    child: CgroupChildOriginalV2,
    anchor: Option<RetainedCgroupAnchor>,
    freezer: FreezerReadOriginalV2,
    supervisor: BeneathRootResolveOriginalV2,
    completed_supervisor: Option<BeneathRoot>,
    opening: PidFdOpenAttemptV1,
    pidfd: Option<PidFd>,
    info: Option<Native<PidFdInfo>>,
    alive: Option<Native<bool>>,
    primary: Option<Result<WorkerObservation>>,
    refusal: Option<HostError>,
}

impl SandboxNativeOriginalV2 {
    pub(in crate::worker) fn new() -> Self {
        Self {
            entered: false,
            completed_move: None,
            observation: None,
            payload: BeneathRootResolveOriginalV2::new(),
            root: CgroupRootOriginalV2::new(),
            completed_root: None,
            child: CgroupChildOriginalV2::new(),
            anchor: None,
            freezer: FreezerReadOriginalV2::new(),
            supervisor: BeneathRootResolveOriginalV2::new(),
            completed_supervisor: None,
            opening: PidFdOpenAttemptV1::new(),
            pidfd: None,
            info: None,
            alive: None,
            primary: None,
            refusal: None,
        }
    }

    pub(in crate::worker) fn capture_once(
        &mut self,
        worker: &SystemdOneShotWorker,
        identity: &HostRuntimeIdentity,
        observation: SandboxUnitObservation,
    ) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("sandbox native observation cannot reenter"));
            return Err(closed("sandbox native observation cannot reenter"));
        }
        self.entered = true;
        self.observation = Some(observation);
        self.primary = Some((|| {
            let observation = self.observation.as_ref().ok_or_else(|| closed("SDK sandbox observation is absent"))?;
            observation_recipe!(worker, identity, observation, Retained, self)
        })());
        if matches!(self.primary, Some(Ok(_))) { Ok(()) } else {
            Err(closed("sandbox native observation failed; actual originals retained"))
        }
    }

    pub(in crate::worker) fn take_completed_once(&mut self) -> Option<WorkerObservation> {
        if !self.entered || self.refusal.is_some() || self.failure().is_some()
            || self.completed_move.is_some()
        {
            return None;
        }
        let completed = self.primary.as_ref()?.as_ref().ok()?;
        let witness = SandboxNativeMovedV4 {
            leader: completed.leader.as_ref().map(|leader| *leader.handle()),
        };

        // The sole production caller has completed its same SDK/local posts
        // and exact native-disposal proof before moving this observation. No
        // later check reads these fresh freezer/root/resolver probe Files;
        // the original worker root and actual returned leader pin stay held.
        drop(std::mem::replace(&mut self.payload, BeneathRootResolveOriginalV2::new()));
        drop(std::mem::replace(&mut self.root, CgroupRootOriginalV2::new()));
        drop(self.completed_root.take());
        drop(std::mem::replace(&mut self.child, CgroupChildOriginalV2::new()));
        drop(self.anchor.take());
        drop(std::mem::replace(&mut self.freezer, FreezerReadOriginalV2::new()));
        drop(std::mem::replace(&mut self.supervisor, BeneathRootResolveOriginalV2::new()));
        drop(self.completed_supervisor.take());
        drop(std::mem::replace(&mut self.opening, PidFdOpenAttemptV1::new()));
        self.completed_move = Some(witness);
        self.primary.take()?.ok()
    }

    pub(in crate::worker) fn native_files_after_completed_move_v4(&self) -> Option<usize> {
        if self.refusal.is_some() || self.primary.is_some() || self.failure().is_some() {
            return None;
        }
        Some(usize::from(self.completed_move.as_ref()?.leader.is_some()))
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.payload.failure().map(|cause| cause as _)
            .or_else(|| self.root.failure().map(|cause| cause as _))
            .or_else(|| self.child.failure().map(|cause| cause as _))
            .or_else(|| self.freezer.failure())
            .or_else(|| self.supervisor.failure().map(|cause| cause as _))
            .or_else(|| self.opening.failure().map(|cause| cause as _))
            .or_else(|| error(&self.info))
            .or_else(|| error(&self.alive))
            .or_else(|| error(&self.primary))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let mut bound = (std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(4 * 4096)?
            .checked_add(2 * std::mem::size_of::<PidFdOpenAttemptV1>())?, 1_usize, 0_usize);
        for next in [
            BeneathRootResolveOriginalV2::receiving_obligations_v2(4096)?,
            BeneathRootResolveOriginalV2::receiving_obligations_v2(4096)?,
            CgroupRootOriginalV2::receiving_obligations_v2()?,
            CgroupChildOriginalV2::receiving_obligations_v2(1)?,
            FreezerReadOriginalV2::receiving_obligations_v2()?,
        ] {
            bound = (bound.0.checked_add(next.0)?, bound.1.checked_add(next.1)?, bound.2.checked_add(next.2)?);
        }
        Some(bound)
    }
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed(message: &'static str) -> HostError { HostError::Fence(message) }

#[cfg(test)]
mod tests {
    use super::*;

    fn count_named_descriptors(path: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().filter_map(|entry| {
            std::fs::read_link(entry.unwrap().path()).ok()
        }).filter(|observed| observed == path).count()
    }

    #[test]
    fn cgroup_refusal_keeps_actual_opened_payload_and_completed_sdk_input() {
        let directory = tempfile::tempdir().unwrap();
        let name = SandboxUnitName::from_incarnation([19; 16]);
        let service = name.cgroup_path();
        let payload = service.payload_subgroup();
        let path = directory.path().join(payload.as_str().trim_start_matches('/'));
        std::fs::create_dir_all(&path).unwrap();
        let root = std::fs::File::open(directory.path()).unwrap();
        let worker = SystemdOneShotWorker::new(BeneathRoot::from_owned(root.into()).unwrap());
        let identity = HostRuntimeIdentity::new([17; 16], [19; 16], 1, 1, [23; 32]);
        let observation = SandboxUnitObservation {
            unit: name,
            load_state: "loaded".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            freezer_state: aos_systemd::FreezerState::Running,
            cgroup: Some(service),
            supervisor_pid: NonZeroU32::new(std::process::id()),
            invocation_id: Some([29; 16]),
            binding: Some([31; 32]),
        };
        let mut original = SandboxNativeOriginalV2::new();
        assert_eq!(count_named_descriptors(&path), 0);

        assert!(original.capture_once(&worker, &identity, observation).is_err());

        assert!(matches!(original.failure().unwrap().downcast_ref::<aos_sandbox_linux::Error>(),
            Some(aos_sandbox_linux::Error::WrongDescriptorType { .. })));
        let cause = original.failure().unwrap().downcast_ref::<aos_sandbox_linux::Error>().unwrap() as *const _;
        assert_eq!(count_named_descriptors(&path), 1);
        assert_eq!(original.observation.as_ref().unwrap().binding, Some([31; 32]));
        assert!(original.completed_root.is_none());
        assert!(original.take_completed_once().is_none());
        assert!(original.native_files_after_completed_move_v4().is_none());

        // A repeated entry refuses without replacing the original SDK input,
        // actual failed cgroup descriptor or first lower native cause.
        let replacement = original.observation.as_ref().unwrap().clone();
        assert!(original.capture_once(&worker, &identity, replacement).is_err());
        assert_eq!(original.failure().unwrap().downcast_ref::<aos_sandbox_linux::Error>().unwrap() as *const _, cause);
        assert_eq!(count_named_descriptors(&path), 1);
        assert!(original.native_files_after_completed_move_v4().is_none());
    }
}
