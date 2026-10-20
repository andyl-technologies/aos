//! Shares supervisor executable/root/namespace proof with retained native owners.
//!
//! The ordinary entry immediately uses this same recipe. The selected entry
//! borrows the genuine prepaid worker, and keeps returned payload pins on the
//! actual quiescence owner before any later liveness or kernel recheck can fail.

use std::sync::Arc;

use aos_sandbox_linux::path::BeneathRootResolveOriginalV2;
use aos_sandbox_linux::pidfd::{PidFdInfo, PidFdNamespaceOriginalV2};
use tokio::sync::Mutex;

use super::*;
use crate::worker::launch::HostLaunchWorkerReceivingV2;

type Native<T> = std::result::Result<T, aos_sandbox_linux::Error>;

macro_rules! supervisor_native {
    (Local, $original:ident, $field:ident, $expression:expr) => {
        $expression.map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $expression:expr) => {{
        $original.require_deadline()?;
        $original.$field = Some($expression);
        match $original.$field.as_ref() {
            Some(Ok(value)) => value,
            _ => return Err(closed("supervisor native observation failed; original retained")),
        }
    }};
}

// Native owners borrow their completed values; scalar boolean predicates
// consume a copy while the actual Result remains on the same destination.
macro_rules! supervisor_boolean {
    (Local, $original:ident, $field:ident, $expression:expr) => {
        supervisor_native!(Local, $original, $field, $expression)
    };
    (Retained, $original:ident, $field:ident, $expression:expr) => {
        *supervisor_native!(Retained, $original, $field, $expression)
    };
}

macro_rules! supervisor_network {
    (Local, $original:ident, $pidfd:ident) => {
        $pidfd.namespace(NamespaceKind::Network)
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $pidfd:ident) => {{
        $original.require_deadline()?;
        $original.network.capture_once($pidfd, NamespaceKind::Network)
            .map_err(|_| closed("supervisor network observation failed; original retained"))?;
        $original.completed_network = Some($original.network.take_completed_once()
            .ok_or_else(|| closed("supervisor network observation is incomplete"))?);
        $original.completed_network.as_ref()
            .ok_or_else(|| closed("supervisor network observation is absent"))?
    }};
}

macro_rules! supervisor_payload_root {
    (Local, $original:ident, $root:ident, $leader:ident) => {
        resolve_payload_root($root, &$leader.cgroup)?
    };
    (Retained, $original:ident, $root:ident, $leader:ident) => {{
        $original.require_deadline()?;
        let payload = $leader.cgroup.payload_subgroup();
        let relative = Path::new(payload.as_str().trim_start_matches('/'));
        $original.root.resolve_once($root, relative, ResolveOptions::directory())
            .map_err(|_| closed("supervisor payload root failed; original retained"))?;
        $original.completed_root = Some($original.root.take_directory_root_once()
            .ok_or_else(|| closed("supervisor payload root is not a completed directory"))?);
        $original.completed_root.as_ref()
            .ok_or_else(|| closed("supervisor payload root is absent"))?
    }};
}

macro_rules! supervisor_inspect {
    (Local, $original:ident, $receiving:ident, $input:ident, $info:ident, $root:ident, $network:ident,
        $inspection:ident, $guard:ident, $payload:ident) => {
        let $payload = inspect_quiesced_payload(&$input, |inspector| {
            discover_payload_leader(inspector, $info.pid(), ($root.st_dev, $root.st_ino),
                ($network.device, $network.inode))
        })?;
    };
    (Retained, $original:ident, $receiving:ident, $input:ident, $info:ident, $root:ident, $network:ident,
        $inspection:ident, $guard:ident, $payload:ident) => {
        $original.inspection = Some($receiving.inspect_payload_v2($input, $info.pid(),
            ($root.st_dev, $root.st_ino), ($network.device, $network.inode)).await?);
        let $inspection = $original.inspection.as_ref()
            .ok_or_else(|| closed("supervisor payload inspection is absent"))?;
        let $guard = $inspection.lock().await;
        let $payload = $guard.payload()
            .ok_or_else(|| closed("supervisor payload pin is absent"))?;
    };
}

macro_rules! supervisor_recheck {
    (Local, $receiving:ident, $payload:ident, $leader:ident) => { $payload.recheck_kernel($leader)? };
    (Retained, $receiving:ident, $payload:ident, $leader:ident) => {
        $receiving.recheck_payload_v2($payload, $leader).await?
    };
}

macro_rules! supervisor_finish {
    (Local, $payload:ident) => { Ok($payload) };
    (Retained, $payload:ident) => { Ok(()) };
}

macro_rules! supervisor_prefix {
    ($cgroup_root:ident, $pins:ident, $leader:ident, $mode:ident, $original:ident,
        $pidfd:ident, $info:ident, $root:ident, $network:ident, $payload_root:ident) => {
        // The unforgeable policy witness couples this point-in-time root check to
        // the immutable command which prevents PID 1 and descendants from later
        // replacing their root. Binary identity is checked below before the
        // payload observation is accepted.
        let $pidfd = &$leader.pidfd;
        let $info = supervisor_native!($mode, $original, info, $pidfd.info());
        let executable_path = format!("/proc/{}/exe", $info.pid());
        let executable = supervisor_native!($mode, $original, executable, rustix::fs::open(
            executable_path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ));
        let expected = supervisor_native!($mode, $original, expected, rustix::fs::fstat($pins.executable()));
        let observed = supervisor_native!($mode, $original, observed, rustix::fs::fstat(&executable));
        if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino) {
            return Err(HostError::Worker(
                "nspawn supervisor executable differs from its pin".to_owned(),
            ));
        }

        let $network = supervisor_network!($mode, $original, $pidfd);
        if $network.identity() != $pins.network().identity() {
            return Err(HostError::Worker(
                "nspawn supervisor network namespace differs from its pin".to_owned(),
            ));
        }
        let $root = supervisor_native!($mode, $original, workspace, rustix::fs::fstat($pins.workspace()));
        let exported_root = supervisor_native!($mode, $original, exported, rustix::fs::fstat($pins.transferred_root()));
        if ($root.st_dev, $root.st_ino) != (exported_root.st_dev, exported_root.st_ino) {
            return Err(HostError::Worker(
                "exported root mount differs from the retained workspace".to_owned(),
            ));
        }
        let $network = $pins.network().identity();
        let $payload_root = supervisor_payload_root!($mode, $original, $cgroup_root, $leader);

    };
}

macro_rules! supervisor_recipe {
    ($cgroup_root:ident, $pins:ident, $leader:ident, $mode:ident, $original:ident, $receiving:ident) => {{
        supervisor_prefix!($cgroup_root, $pins, $leader, $mode, $original,
            pidfd, info, root, network, payload_root);
        supervisor_inspect!($mode, $original, $receiving, payload_root, info, root, network,
            inspection, payload_guard, payload);
        // The nspawn supervisor deliberately remains outside the guest root, so
        // `/proc/<supervisor>/root` is not evidence for the container root. The
        // root guarantee here is instead the owned descriptor transferred through
        // the fixed supervisor-only root FD role and retained until this
        // post-start check. Guest-root comparison must wait for payload PID 1
        // discovery and pinning; treating the supervisor root as equivalent would
        // be a false proof.
        if !supervisor_boolean!($mode, $original, payload_alive, payload.pidfd().is_alive())
        {
            return Err(HostError::Worker(
                "payload PID 1 exited during launch identity validation".to_owned(),
            ));
        }
        if !supervisor_boolean!($mode, $original, supervisor_alive, pidfd.is_alive())
        {
            return Err(HostError::Worker(
                "nspawn supervisor exited during launch identity validation".to_owned(),
            ));
        }
        supervisor_recheck!($mode, $receiving, payload, $leader);
        supervisor_finish!($mode, payload)
    }};
}

pub(super) fn verify_local(
    cgroup_root: &BeneathRoot,
    pins: &LaunchPins,
    leader: &PinnedLeader,
    _policy: PayloadRootContinuityPolicyV1,
) -> Result<PinnedPayloadLeader> {
    supervisor_recipe!(cgroup_root, pins, leader, Local, unused, unused)
}

struct SupervisorNativeDisposedV4 {
    inspection: std::sync::Weak<Mutex<PayloadInspectionQuiescenceOriginalV2>>,
}

pub(in crate::worker) struct SupervisorProofOriginalV2 {
    deadline: tokio::time::Instant,
    entered: bool,
    native_disposed: Option<SupervisorNativeDisposedV4>,
    info: Option<Native<PidFdInfo>>,
    executable: Option<rustix::io::Result<OwnedFd>>,
    expected: Option<rustix::io::Result<rustix::fs::Stat>>,
    observed: Option<rustix::io::Result<rustix::fs::Stat>>,
    network: PidFdNamespaceOriginalV2,
    completed_network: Option<NamespaceFd>,
    workspace: Option<rustix::io::Result<rustix::fs::Stat>>,
    exported: Option<rustix::io::Result<rustix::fs::Stat>>,
    root: BeneathRootResolveOriginalV2,
    completed_root: Option<BeneathRoot>,
    inspection: Option<Arc<Mutex<PayloadInspectionQuiescenceOriginalV2>>>,
    payload_alive: Option<Native<bool>>,
    supervisor_alive: Option<Native<bool>>,
    primary: Option<Result<()>>,
    refusal: Option<HostError>,
}

impl SupervisorProofOriginalV2 {
    pub(in crate::worker) fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            entered: false,
            native_disposed: None,
            info: None,
            executable: None,
            expected: None,
            observed: None,
            network: PidFdNamespaceOriginalV2::new(),
            completed_network: None,
            workspace: None,
            exported: None,
            root: BeneathRootResolveOriginalV2::new(),
            completed_root: None,
            inspection: None,
            payload_alive: None,
            supervisor_alive: None,
            primary: None,
            refusal: None,
        }
    }

    pub(in crate::worker) async fn verify_once(
        &mut self,
        cgroup_root: &BeneathRoot,
        pins: &LaunchPins,
        leader: &PinnedLeader,
        _policy: PayloadRootContinuityPolicyV1,
        receiving: &mut HostLaunchWorkerReceivingV2<'_, '_>,
    ) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("supervisor proof cannot reenter"));
            return Err(closed("supervisor proof cannot reenter"));
        }
        self.entered = true;
        self.primary = Some(async {
            supervisor_recipe!(cgroup_root, pins, leader, Retained, self, receiving)
        }.await);
        if matches!(self.primary, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed("supervisor proof failed; original native owners retained"))
        }
    }

    #[cfg(test)]
    pub(in crate::worker) fn prefix_for_test(
        &mut self,
        cgroup_root: &BeneathRoot,
        pins: &LaunchPins,
        leader: &PinnedLeader,
    ) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("supervisor proof cannot reenter"));
            return Err(closed("supervisor proof cannot reenter"));
        }
        self.entered = true;
        self.primary = Some((|| {
            supervisor_prefix!(cgroup_root, pins, leader, Retained, self,
                pidfd, info, root, network, payload_root);
            Ok(())
        })());
        if matches!(self.primary, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed("supervisor prefix failed; actual original retained"))
        }
    }

    #[cfg(test)]
    pub(in crate::worker) fn retained_executable_for_test(&self) -> Option<BorrowedFd<'_>> {
        self.executable.as_ref()?.as_ref().ok().map(|file| file.as_fd())
    }

    fn require_deadline(&self) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            Err(closed("original Launch worker deadline expired"))
        } else {
            Ok(())
        }
    }

    pub(in crate::worker) fn inspection(
        &self,
    ) -> Option<&Arc<Mutex<PayloadInspectionQuiescenceOriginalV2>>> {
        self.inspection.as_ref()
    }

    pub(in crate::worker) fn dispose_completed_native_once_v4(&mut self) -> Result<()> {
        if !self.entered || self.native_disposed.is_some() || !self.completed_for_parent_disposal_v4() {
            self.refusal.get_or_insert_with(|| closed("supervisor native prefix is not disposable"));
            return Err(closed("supervisor native prefix is not disposable"));
        }
        let inspection = self.inspection.as_ref()
            .ok_or_else(|| closed("supervisor inspection is absent"))?;

        // Both actual process liveness bookends and the complete payload
        // inspection have succeeded. No subsequent proof reads these fresh
        // executable/namespace/root duplicates. Original Launch and payload
        // pins, raw scalar results and the exact inspection association stay.
        drop(self.executable.take());
        drop(self.completed_network.take());
        drop(std::mem::replace(&mut self.network, PidFdNamespaceOriginalV2::new()));
        drop(self.completed_root.take());
        drop(std::mem::replace(&mut self.root, BeneathRootResolveOriginalV2::new()));
        self.native_disposed = Some(SupervisorNativeDisposedV4 {
            inspection: Arc::downgrade(inspection),
        });
        Ok(())
    }

    pub(in crate::worker) fn native_is_disposed_v4(&self) -> bool {
        self.native_disposed.as_ref().zip(self.inspection.as_ref())
            .is_some_and(|(proof, actual)| {
                std::sync::Weak::ptr_eq(&proof.inspection, &Arc::downgrade(actual))
            }) && self.completed_for_parent_disposal_v4()
    }

    pub(in crate::worker) fn completed_for_parent_disposal_v4(&self) -> bool {
        matches!(self.primary, Some(Ok(()))) && self.refusal.is_none()
            && self.inspection.is_some() && self.failure().is_none()
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.info)
            .or_else(|| error(&self.executable))
            .or_else(|| error(&self.expected))
            .or_else(|| error(&self.observed))
            .or_else(|| self.network.failure().map(|cause| cause as _))
            .or_else(|| error(&self.workspace))
            .or_else(|| error(&self.exported))
            .or_else(|| self.root.failure().map(|cause| cause as _))
            .or_else(|| error(&self.payload_alive))
            .or_else(|| error(&self.supervisor_alive))
            .or_else(|| error(&self.primary))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let resolved = BeneathRootResolveOriginalV2::receiving_obligations_v2(4096)?;
        let namespace = PidFdNamespaceOriginalV2::receiving_obligations_v2()?;
        Some((
            std::mem::size_of::<Self>().checked_mul(2)?
                .checked_add(4 * 32)?.checked_add(resolved.0)?.checked_add(namespace.0)?,
            1_usize.checked_add(resolved.1)?.checked_add(namespace.1)?,
            1_usize.checked_add(resolved.2)?.checked_add(namespace.2)?,
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
