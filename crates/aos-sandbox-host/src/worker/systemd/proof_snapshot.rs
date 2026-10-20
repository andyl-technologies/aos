//! Shares runtime-proof construction with actual retained identity observations.
//!
//! Native process stat Files and the bounded boot-ID original stay with this
//! destination through later expected-proof and shifted-payload conjunctions.
//! A completed snapshot is DATA, not launch or cleanup permission.

use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;
use aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1;

use super::*;

macro_rules! snapshot_identity {
    (Local, $original:ident, $field:ident, $process:expr) => {
        $process.process_identity().map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $process:expr) => {{
        $original.require_deadline()?;
        $original.$field.capture_once($process)
            .map_err(|_| closed("runtime process identity failed; original retained"))?;
        $original.$field.identity()
            .ok_or_else(|| closed("runtime process identity is incomplete"))?
    }};
}

macro_rules! snapshot_mount {
    (Local, $original:ident, $field:ident, $file:expr) => {
        MountId::from_fd($file).map_err(|error| HostError::Worker(error.to_string()))?.get()
    };
    (Retained, $original:ident, $field:ident, $file:expr) => {{
        $original.require_deadline()?;
        $original.$field = Some(MountId::from_fd($file));
        match $original.$field.as_ref() {
            Some(Ok(mount)) => mount.get(),
            _ => return Err(closed("runtime mount identity failed; original retained")),
        }
    }};
}

macro_rules! snapshot_boot {
    (Local, $original:ident) => {
        KernelBootId::current().map_err(|error| HostError::Worker(error.to_string()))?.into_bytes()
    };
    (Retained, $original:ident) => {{
        $original.require_deadline()?;
        (*$original.boot.observe_once()
            .map_err(|_| closed("runtime boot identity failed; original retained"))?).into_bytes()
    }};
}

macro_rules! snapshot_recipe {
    ($workspace_mount_id:ident, $supervisor:ident, $payload:ident, $mode:ident, $original:ident) => {{
        let supervisor_identity = snapshot_identity!($mode, $original, supervisor_identity, &$supervisor.pidfd);
        let payload_identity = snapshot_identity!($mode, $original, payload_identity, &$payload.pidfd);
        let supervisor_cgroup_id = supervisor_identity
            .cgroup_id()
            .ok_or_else(|| HostError::Worker("kernel omitted supervisor cgroup identity".to_owned()))?;
        let payload_cgroup_id = payload_identity
            .cgroup_id()
            .ok_or_else(|| HostError::Worker("kernel omitted payload cgroup identity".to_owned()))?;
        let payload_root_mount_id = snapshot_mount!($mode, $original, payload_mount, $payload.root.as_fd());
        let network = $payload.network.identity();
        let mount = $payload.mount.identity();
        let user = $payload.user.identity();
        let snapshot = RuntimeProofSnapshot {
            host_boot_id: snapshot_boot!($mode, $original),
            supervisor: ProcessProofSnapshot {
                pid: supervisor_identity.pid(),
                thread_group_id: supervisor_identity.thread_group_id(),
                parent_pid: supervisor_identity.parent_pid(),
                cgroup_id: supervisor_cgroup_id,
                start_time_ticks: supervisor_identity.start_time_ticks(),
            },
            payload: ProcessProofSnapshot {
                pid: payload_identity.pid(),
                thread_group_id: payload_identity.thread_group_id(),
                parent_pid: payload_identity.parent_pid(),
                cgroup_id: payload_cgroup_id,
                start_time_ticks: payload_identity.start_time_ticks(),
            },
            supervisor_cgroup_id,
            payload_cgroup_id,
            workspace_mount_id: $workspace_mount_id,
            payload_root_mount_id,
            network_namespace: NamespaceProofSnapshot {
                device: network.device,
                inode: network.inode,
            },
            mount_namespace: NamespaceProofSnapshot {
                device: mount.device,
                inode: mount.inode,
            },
            user_namespace: NamespaceProofSnapshot {
                device: user.device,
                inode: user.inode,
            },
        };
        if !snapshot.validate() {
            return Err(HostError::Worker(
                "bound payload kernel proof contains a sentinel or contradiction".to_owned(),
            ));
        }
        Ok(snapshot)
    }};
}

pub(super) fn snapshot_local(
    pins: &LaunchPins,
    supervisor: &PinnedLeader,
    payload: &PinnedPayloadLeader,
) -> Result<RuntimeProofSnapshot> {
    let workspace_mount_id = MountId::from_fd(pins.workspace())
        .map_err(|error| HostError::Worker(error.to_string()))?.get();
    snapshot_local_with_workspace_mount_id(workspace_mount_id, supervisor, payload)
}

pub(super) fn snapshot_local_with_workspace_mount_id(
    workspace_mount_id: u64,
    supervisor: &PinnedLeader,
    payload: &PinnedPayloadLeader,
) -> Result<RuntimeProofSnapshot> {
    snapshot_recipe!(workspace_mount_id, supervisor, payload, Local, unused)
}

struct RuntimeSnapshotNativeDisposedV4 {
    snapshot: RuntimeProofSnapshot,
}

pub(in crate::worker) struct RuntimeProofOriginalV2 {
    deadline: tokio::time::Instant,
    entered: bool,
    native_disposed: Option<RuntimeSnapshotNativeDisposedV4>,
    workspace_mount: Option<std::result::Result<MountId, aos_sandbox_linux::Error>>,
    supervisor_identity: PidFdProcessIdentityOriginalV1,
    payload_identity: PidFdProcessIdentityOriginalV1,
    payload_mount: Option<std::result::Result<MountId, aos_sandbox_linux::Error>>,
    boot: RootOriginalKernelBootIdAttemptV1,
    primary: Option<Result<RuntimeProofSnapshot>>,
    refusal: Option<HostError>,
}

impl RuntimeProofOriginalV2 {
    pub(in crate::worker) fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            entered: false,
            native_disposed: None,
            workspace_mount: None,
            supervisor_identity: PidFdProcessIdentityOriginalV1::new(),
            payload_identity: PidFdProcessIdentityOriginalV1::new(),
            payload_mount: None,
            boot: RootOriginalKernelBootIdAttemptV1::new(),
            primary: None,
            refusal: None,
        }
    }

    pub(in crate::worker) fn capture_once(
        &mut self,
        pins: &LaunchPins,
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
    ) -> Result<RuntimeProofSnapshot> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("runtime proof cannot reenter"));
            return Err(closed("runtime proof cannot reenter"));
        }
        self.entered = true;
        self.primary = Some((|| {
            let workspace_mount_id = snapshot_mount!(Retained, self, workspace_mount, pins.workspace());
            snapshot_recipe!(workspace_mount_id, supervisor, payload, Retained, self)
        })());
        match self.primary.as_ref() {
            Some(Ok(proof)) => Ok(*proof),
            _ => Err(closed("runtime proof failed; actual native originals retained")),
        }
    }

    fn require_deadline(&self) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            Err(closed("original Launch worker deadline expired"))
        } else {
            Ok(())
        }
    }

    pub(in crate::worker) fn dispose_completed_native_once_v4(&mut self) -> Result<()> {
        if !self.entered || self.native_disposed.is_some() || !self.completed_for_parent_disposal_v4() {
            self.refusal.get_or_insert_with(|| closed("runtime snapshot native prefix is not disposable"));
            return Err(closed("runtime snapshot native prefix is not disposable"));
        }
        let snapshot = match self.primary.as_ref() {
            Some(Ok(snapshot)) => *snapshot,
            _ => return Err(closed("runtime snapshot is absent")),
        };

        // The full immutable snapshot retains every accepted process/boot
        // witness. Subsequent checks use the original supervisor/payload pins,
        // not these completed proc readers. Reentry remains permanently shut.
        drop(std::mem::replace(&mut self.supervisor_identity, PidFdProcessIdentityOriginalV1::new()));
        drop(std::mem::replace(&mut self.payload_identity, PidFdProcessIdentityOriginalV1::new()));
        drop(std::mem::replace(&mut self.boot, RootOriginalKernelBootIdAttemptV1::new()));
        self.native_disposed = Some(RuntimeSnapshotNativeDisposedV4 { snapshot });
        Ok(())
    }

    pub(in crate::worker) fn matches_snapshot_v4(&self, snapshot: RuntimeProofSnapshot) -> bool {
        matches!(self.primary, Some(Ok(actual)) if actual == snapshot)
    }

    pub(in crate::worker) fn native_is_disposed_v4(&self) -> bool {
        self.native_disposed.as_ref().is_some_and(|proof| {
            matches!(self.primary, Some(Ok(snapshot)) if snapshot == proof.snapshot)
        }) && self.completed_for_parent_disposal_v4()
    }

    pub(in crate::worker) fn completed_for_parent_disposal_v4(&self) -> bool {
        matches!(self.primary, Some(Ok(_))) && self.refusal.is_none() && self.failure().is_none()
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.workspace_mount)
            .or_else(|| self.supervisor_identity.failure())
            .or_else(|| self.payload_identity.failure())
            .or_else(|| error(&self.payload_mount))
            .or_else(|| self.boot.failure())
            .or_else(|| error(&self.primary))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    #[cfg(test)]
    pub(in crate::worker) fn completed_native_identities_for_test(&self) -> bool {
        self.supervisor_identity.identity().is_some()
            && self.payload_identity.identity().is_some()
            && self.boot.failure().is_none()
    }

    pub(in crate::worker) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        Some((
            std::mem::size_of::<Self>().checked_mul(2)?
                .checked_add(identity.0.checked_mul(2)?)?
                .checked_add(RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?)?,
            identity.1.checked_mul(2)?.checked_add(
                RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1,
            )?,
            3, // Actual supervisor stat, payload stat and fixed boot-ID name.
        ))
    }
}

fn error<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed(message: &'static str) -> HostError {
    HostError::Fence(message)
}
