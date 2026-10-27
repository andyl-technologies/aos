//! Keeps one payload-currentness flight's actual native refusal prefixes.
//!
//! The ordinary method immediately delegates to the same recipe with local
//! values. The selected owner holds real native objects and results; it grants
//! no role, effect, financial capacity or replacement process identity.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_linux::cgroup::{
    CgroupChildOriginalV2, CgroupRootOriginalV2, CgroupV2Root,
    RetainedCgroupAnchor, RuntimeScopeMembershipOriginalV1,
};
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_linux::pidfd::NamespaceKind;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::pidfd::PidFdNamespaceOriginalV2;

use super::{PinnedLeader, PinnedPayloadLeader};
use crate::{HostError, Result};

type Native<T> = std::result::Result<T, aos_linux_descriptors::Error>;

pub(super) struct PayloadKernelRecheckOriginalV2 {
    origin: Arc<()>,
    entered: bool,
    disposal_prepared: bool,
    disposal_entered: bool,
    disposal_refusal: Option<HostError>,
    supervisor_before: Option<Native<PidFdInfo>>,
    duplicate: Option<std::io::Result<OwnedFd>>,
    root: Option<CgroupRootOriginalV2>,
    completed_root: Option<CgroupV2Root>,
    child: Option<CgroupChildOriginalV2>,
    anchor: Option<RetainedCgroupAnchor>,
    membership: Option<RuntimeScopeMembershipOriginalV1>,
    status: NestedPidOriginalV2,
    current_root: Option<rustix::io::Result<OwnedFd>>,
    current_root_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    retained_root_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    namespaces: [Option<PidFdNamespaceOriginalV2>; 4],
    completed_namespaces: [Option<NamespaceFd>; 4],
    payload_after: Option<Native<PidFdInfo>>,
    supervisor_after: Option<Native<PidFdInfo>>,
    payload_alive: Option<Native<bool>>,
    supervisor_alive: Option<Native<bool>>,
    primary: Option<Result<()>>,
}

impl PayloadKernelRecheckOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            origin: Arc::new(()),
            entered: false,
            disposal_prepared: false,
            disposal_entered: false,
            disposal_refusal: None,
            supervisor_before: None,
            duplicate: None,
            root: Some(CgroupRootOriginalV2::new()),
            completed_root: None,
            child: Some(CgroupChildOriginalV2::new()),
            anchor: None,
            membership: Some(RuntimeScopeMembershipOriginalV1::new()),
            status: NestedPidOriginalV2::new(),
            current_root: None,
            current_root_stat: None,
            retained_root_stat: None,
            namespaces: std::array::from_fn(|_| Some(PidFdNamespaceOriginalV2::new())),
            completed_namespaces: std::array::from_fn(|_| None),
            payload_after: None,
            supervisor_after: None,
            payload_alive: None,
            supervisor_alive: None,
            primary: None,
        }
    }
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.supervisor_before)
            .or_else(|| error(&self.duplicate))
            .or_else(|| self.root.as_ref()?.failure().map(|cause| cause as _))
            .or_else(|| self.child.as_ref()?.failure().map(|cause| cause as _))
            .or_else(|| self.membership.as_ref()?.failure().map(|cause| cause as _))
            .or_else(|| self.status.failure())
            .or_else(|| error(&self.current_root))
            .or_else(|| error(&self.current_root_stat))
            .or_else(|| error(&self.retained_root_stat))
            .or_else(|| self.namespaces.iter().flatten().find_map(|original| {
                original.failure().map(|cause| cause as &(dyn std::error::Error + 'static))
            }))
            .or_else(|| error(&self.payload_after))
            .or_else(|| error(&self.supervisor_after))
            .or_else(|| error(&self.payload_alive))
            .or_else(|| error(&self.supervisor_alive))
            .or_else(|| error(&self.primary))
            .or_else(|| self.disposal_refusal.as_ref().map(|cause| cause as _))
    }

    fn prepare_positive_disposal(&mut self) -> Result<KernelRecheckCompletedV2> {
        if !self.entered || self.disposal_prepared || !matches!(self.primary, Some(Ok(()))) {
            return Err(closed("payload kernel recheck has no fresh positive completion"));
        }
        self.disposal_prepared = true;
        Ok(KernelRecheckCompletedV2 { origin: Arc::clone(&self.origin) })
    }

    fn dispose_temporary_fds(
        &mut self,
        completed: KernelRecheckCompletedV2,
    ) -> Result<KernelRecheckFdsDisposedV2> {
        if !self.disposal_prepared || self.disposal_entered
            || !Arc::ptr_eq(&completed.origin, &self.origin)
            || !matches!(self.primary, Some(Ok(())))
        {
            self.disposal_refusal.get_or_insert_with(|| closed("payload kernel temporary disposal refused"));
            return Err(closed("payload kernel temporary disposal refused; original retained"));
        }
        self.disposal_entered = true;

        // Only this complete synchronous recheck used these exact duplicate
        // roots, probes, proc File and fresh namespace handles. Its original
        // payload/supervisor input pins remain borrowed and untouched for all
        // later SDK/global observations. All successful scalar results, status
        // bytes and parsed values stay resident; no memory/namespace credit is
        // inferred from closing these actual native leaves.
        drop(self.current_root.take());
        drop(self.status.file.take());
        for namespace in &mut self.completed_namespaces {
            drop(namespace.take());
        }
        for namespace in &mut self.namespaces {
            drop(namespace.take());
        }
        drop(self.membership.take());
        drop(self.anchor.take());
        drop(self.child.take());
        drop(self.completed_root.take());
        drop(self.root.take());

        Ok(KernelRecheckFdsDisposedV2 { origin: completed.origin })
    }

    fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let status = super::MAXIMUM_PROC_STATUS_BYTES.checked_add(1)?.checked_mul(4)?
            .checked_add((super::MAXIMUM_PROC_STATUS_BYTES / 2)
                .checked_mul(std::mem::size_of::<u32>())?.checked_mul(4)?)?;
        let mut result = (
            std::mem::size_of::<Self>().checked_mul(2)?
                .checked_add(4 * std::mem::size_of::<usize>())?
                .checked_add(status)?.checked_add(2 * 32)?,
            2_usize, // Actual status File and /proc/PID/root, independent.
            2_usize, // The two actual proc names.
        );
        for next in [
            CgroupRootOriginalV2::receiving_obligations_v2()?,
            CgroupChildOriginalV2::receiving_obligations_v2(1)?,
            RuntimeScopeMembershipOriginalV1::receiving_demand_v1()?,
        ] {
            result = add(result, next)?;
        }
        for _ in 0..4 {
            result = add(result, PidFdNamespaceOriginalV2::receiving_obligations_v2()?)?;
        }
        Some(result)
    }
}

macro_rules! kernel_data {
    (Local, $original:ident, $field:ident, $expression:expr) => {
        $expression.map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $expression:expr) => {{
        $original.$field = Some($expression);
        match $original.$field.as_ref() {
            Some(Ok(value)) => *value,
            _ => return Err(closed("payload kernel data observation failed; original retained")),
        }
    }};
}

macro_rules! kernel_value {
    (Local, $original:ident, $field:ident, $expression:expr) => {
        $expression.map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $field:ident, $expression:expr) => {{
        $original.$field = Some($expression);
        match $original.$field.as_ref() {
            Some(Ok(value)) => value,
            _ => return Err(closed("payload kernel native observation failed; original retained")),
        }
    }};
}

macro_rules! kernel_root {
    (Local, $original:ident, $payload:ident) => {
        CgroupV2Root::from_owned($payload.cgroup.as_fd().try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?)
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $payload:ident) => {{
        $original.duplicate = Some($payload.cgroup.as_fd().try_clone_to_owned());
        let descriptor = match $original.duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            Some(Err(error)) => {
                $original.duplicate = Some(Err(error));
                return Err(closed("payload kernel root duplicate failed; original retained"));
            }
            None => return Err(closed("payload kernel root duplicate is absent")),
        };
        let root = $original.root.as_mut().ok_or_else(|| closed("payload kernel root original is absent"))?;
        root.admit_once(descriptor).map_err(|_| closed("payload kernel root admission failed; original retained"))?;
        $original.completed_root = Some(root.take_completed_once()
            .ok_or_else(|| closed("payload kernel root is incomplete"))?);
        $original.completed_root.as_ref().ok_or_else(|| closed("payload kernel root is absent"))?
    }};
}

macro_rules! kernel_anchor {
    (Local, $original:ident, $root:ident) => {
        $root.resolve(Path::new(".")).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $root:ident) => {{
        let child = $original.child.as_mut().ok_or_else(|| closed("payload kernel child original is absent"))?;
        child.resolve_once($root, Path::new("."))
            .map_err(|_| closed("payload kernel anchor failed; original retained"))?;
        $original.anchor = Some(child.take_completed_once()
            .ok_or_else(|| closed("payload kernel anchor is incomplete"))?);
        $original.anchor.as_ref().ok_or_else(|| closed("payload kernel anchor is absent"))?
    }};
}

macro_rules! kernel_membership {
    (Local, $original:ident, $anchor:ident, $payload:ident) => {
        if $payload.relative_cgroup_hint.is_empty() {
            $anchor.verify_exact_membership(&$payload.pidfd)
        } else {
            $anchor.verify_descendant_membership(&$payload.pidfd, Path::new(&$payload.relative_cgroup_hint))
        }.map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $anchor:ident, $payload:ident) => {{
        let hint = (!$payload.relative_cgroup_hint.is_empty())
            .then(|| Path::new(&$payload.relative_cgroup_hint));
        let membership = $original.membership.as_mut()
            .ok_or_else(|| closed("payload kernel membership original is absent"))?;
        membership.capture_once($anchor, &$payload.pidfd, hint)
            .map_err(|_| closed("payload kernel membership failed; original retained"))?;
        membership.completed_info().ok_or_else(|| closed("payload kernel membership is incomplete"))?
    }};
}

macro_rules! kernel_nested_pid {
    (Local, $original:ident, $pid:expr) => { super::systemd::read_nested_pid($pid)? };
    (Retained, $original:ident, $pid:expr) => { $original.status.capture_once($pid)? };
}

macro_rules! kernel_namespace {
    (Local, $original:ident, $payload:ident, $index:expr, $kind:expr) => {
        aos_sandbox_linux::pidfd::namespace(&($payload.pidfd), $kind).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $payload:ident, $index:expr, $kind:expr) => {{
        let namespace = $original.namespaces[$index].as_mut()
            .ok_or_else(|| closed("payload kernel namespace original is absent"))?;
        namespace.capture_once(&$payload.pidfd, $kind)
            .map_err(|_| closed("payload kernel namespace failed; original retained"))?;
        $original.completed_namespaces[$index] = Some(namespace.take_completed_once()
            .ok_or_else(|| closed("payload kernel namespace is incomplete"))?);
        $original.completed_namespaces[$index].as_ref()
            .ok_or_else(|| closed("payload kernel namespace is absent"))?.identity()
    }};
}

macro_rules! kernel_namespace_identity {
    (Local, $namespace:ident) => { $namespace.identity() };
    (Retained, $namespace:ident) => { $namespace };
}

macro_rules! kernel_recheck_recipe {
    ($mode:ident, $payload:ident, $supervisor:ident, $original:ident) => {{

        let supervisor_before = kernel_data!($mode, $original, supervisor_before, $supervisor.pidfd.info());
        let cgroup = kernel_root!($mode, $original, $payload);
        let anchor = kernel_anchor!($mode, $original, cgroup);
        let payload_before = kernel_membership!($mode, $original, anchor, $payload);
        if payload_before.thread_group_id() != payload_before.pid()
            || payload_before.parent_pid() != supervisor_before.pid()
            || kernel_nested_pid!($mode, $original,
                NonZeroU32::new(payload_before.pid()).ok_or_else(|| {
                    HostError::Worker("payload pidfd returned PID zero".to_owned())
                })?) != 1
        {
            return Err(HostError::Worker(
                "retained payload process no longer satisfies its exact scope".to_owned(),
            ));
        }

        let current_root = kernel_value!($mode, $original, current_root,
            super::systemd::open_payload_root_native(
                NonZeroU32::new(payload_before.pid())
                    .ok_or_else(|| HostError::Worker("payload pidfd returned PID zero".to_owned()))?
            ));
        let current_root = kernel_value!($mode, $original, current_root_stat, rustix::fs::fstat(&current_root));
        let retained_root =
            kernel_value!($mode, $original, retained_root_stat, rustix::fs::fstat(&$payload.root));
        let current_network = kernel_namespace!($mode, $original, $payload, 0, NamespaceKind::Network);
        let current_mount = kernel_namespace!($mode, $original, $payload, 1, NamespaceKind::Mount);
        let current_user = kernel_namespace!($mode, $original, $payload, 2, NamespaceKind::User);
        let current_pid = kernel_namespace!($mode, $original, $payload, 3, NamespaceKind::Pid);
        if (current_root.st_dev, current_root.st_ino)
            != (retained_root.st_dev, retained_root.st_ino)
            || kernel_namespace_identity!($mode, current_network) != $payload.network.identity()
            || kernel_namespace_identity!($mode, current_mount) != $payload.mount.identity()
            || kernel_namespace_identity!($mode, current_pid) != $payload.pid.identity()
            || kernel_namespace_identity!($mode, current_user) != $payload.user.identity()
        {
            return Err(HostError::Worker(
                "retained payload root or namespaces changed".to_owned(),
            ));
        }

        let payload_after = kernel_data!($mode, $original, payload_after, $payload.pidfd.info());
        let supervisor_after = kernel_data!($mode, $original, supervisor_after, $supervisor.pidfd.info());
        if payload_before != payload_after
            || supervisor_before != supervisor_after
            || !kernel_data!($mode, $original, payload_alive, $payload.pidfd.is_alive())
            || !kernel_data!($mode, $original, supervisor_alive, $supervisor.pidfd.is_alive())
        {
            return Err(HostError::Worker(
                "retained payload identity changed during revalidation".to_owned(),
            ));
        }
        Ok(())

    }};
}

pub(super) fn recheck(
    payload: &PinnedPayloadLeader,
    supervisor: &PinnedLeader,
    retained: Option<&mut PayloadKernelRecheckOriginalV2>,
) -> Result<()> {
    match retained {
        None => kernel_recheck_recipe!(Local, payload, supervisor, unused),
        Some(original) => {
            if original.entered {
                return Err(closed("payload kernel original cannot reenter"));
            }
            original.entered = true;
            original.primary = Some((|| kernel_recheck_recipe!(Retained, payload, supervisor, original))());
            if matches!(original.primary, Some(Ok(()))) {
                Ok(())
            } else {
                Err(closed("payload kernel recheck failed; native original retained"))
            }
        }
    }
}

struct NestedPidOriginalV2 {
    opened: Option<rustix::io::Result<OwnedFd>>,
    file: Option<File>,
    bytes: Vec<u8>,
    values: Vec<u32>,
    result: Option<std::result::Result<u32, super::systemd::PayloadStatusReadErrorV2>>,
}

impl NestedPidOriginalV2 {
    fn new() -> Self {
        Self { opened: None, file: None, bytes: Vec::new(), values: Vec::new(), result: None }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.opened).or_else(|| error(&self.result))
    }

    fn capture_once(&mut self, pid: NonZeroU32) -> Result<u32> {
        self.opened = Some(super::systemd::open_payload_status_native(pid));
        let descriptor = match self.opened.take() {
            Some(Ok(descriptor)) => descriptor,
            Some(Err(error)) => {
                self.opened = Some(Err(error));
                return Err(closed("payload status open failed; original retained"));
            }
            None => return Err(closed("payload status open is absent")),
        };
        self.file = Some(File::from(descriptor));
        self.result = Some(super::systemd::read_nested_pid_from(
            self.file.as_mut().ok_or_else(|| closed("payload status File is absent"))?,
            &mut self.bytes, &mut self.values, pid,
        ));
        match self.result.as_ref() {
            Some(Ok(pid)) => Ok(*pid),
            _ => Err(closed("payload status read/parse failed; original retained")),
        }
    }
}

struct KernelRecheckCompletedV2 {
    origin: Arc<()>,
}

struct KernelRecheckFdsDisposedV2 {
    origin: Arc<()>,
}

impl KernelRecheckFdsDisposedV2 {
    fn belongs_to(&self, original: &PayloadKernelRecheckOriginalV2) -> bool {
        original.disposal_entered && Arc::ptr_eq(&self.origin, &original.origin)
    }
}

struct KernelRecheckSlotV2 {
    original: Box<PayloadKernelRecheckOriginalV2>,
    disposal: Option<Result<KernelRecheckFdsDisposedV2>>,
}

impl KernelRecheckSlotV2 {
    fn observe_once_v3(&mut self, payload: &PinnedPayloadLeader, supervisor: &PinnedLeader) -> Result<()> {
        recheck(payload, supervisor, Some(&mut self.original))?;
        self.disposal = Some(match self.original.prepare_positive_disposal() {
            Ok(completed) => self.original.dispose_temporary_fds(completed),
            Err(error) => Err(error),
        });
        if self.disposal.as_ref().is_some_and(|result| {
            result.as_ref().is_ok_and(|proof| proof.belongs_to(&self.original))
        }) {
            Ok(())
        } else {
            Err(closed("payload kernel native disposal failed; complete original retained"))
        }
    }
}

/// Holds the additional final-scope check's same native slot reducer.
pub(crate) struct HostScopeKernelOriginalV3 {
    slot: Option<KernelRecheckSlotV2>,
}

impl HostScopeKernelOriginalV3 {
    pub(crate) fn new() -> Self { Self { slot: None } }

    pub(crate) fn capture_once_v3(&mut self, payload: &PinnedPayloadLeader, supervisor: &PinnedLeader) -> Result<()> {
        if self.slot.is_some() { return Err(closed("final-scope kernel slot cannot reenter")); }
        self.slot = Some(KernelRecheckSlotV2 {
            original: Box::new(PayloadKernelRecheckOriginalV2::new()), disposal: None,
        });
        self.slot.as_mut().ok_or_else(|| closed("final-scope kernel slot is absent"))?
            .observe_once_v3(payload, supervisor)
    }

    pub(crate) fn completed_for_parent_disposal_v4(&self) -> bool {
        self.slot.as_ref().is_some_and(|slot| {
            slot.original.failure().is_none() && slot.disposal.as_ref().is_some_and(|result| {
                result.as_ref().is_ok_and(|proof| proof.belongs_to(&slot.original))
            })
        })
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.slot.as_ref().and_then(|slot| slot.original.failure().or_else(|| error(&slot.disposal)))
    }

    pub(crate) fn receiving_obligations_v3() -> Option<(usize, usize, usize)> {
        let one = PayloadKernelRecheckOriginalV2::receiving_obligations_v2()?;
        Some((one.0.checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<KernelRecheckSlotV2>().checked_mul(2)?)?, one.1, one.2))
    }
}

// Three unchanged rechecks at each of two actual launch proof points. This is
// one finite same-launch native collector, never a recurring operation grant.
const KERNEL_RECHECKS: usize = 6;

pub(super) struct PayloadKernelRechecksV2 {
    slots: Vec<KernelRecheckSlotV2>,
    refusal: Option<HostError>,
}

impl PayloadKernelRechecksV2 {
    pub(super) fn new() -> Self {
        Self { slots: Vec::with_capacity(KERNEL_RECHECKS), refusal: None }
    }

    pub(super) fn observe_once(
        &mut self,
        payload: &PinnedPayloadLeader,
        supervisor: &PinnedLeader,
    ) -> Result<()> {
        if self.refusal.is_some() || self.slots.len() == KERNEL_RECHECKS {
            self.refusal.get_or_insert_with(|| closed("payload kernel recheck roster is exhausted"));
            return Err(closed("payload kernel recheck roster is exhausted"));
        }
        if self.slots.last().is_some_and(|previous| {
            !previous.disposal.as_ref().is_some_and(|result| {
                result.as_ref().is_ok_and(|proof| proof.belongs_to(&previous.original))
            })
        }) {
            self.refusal.get_or_insert_with(|| closed("prior payload kernel temporary native custody remains occupied"));
            return Err(closed("prior payload kernel temporary native custody remains occupied"));
        }
        self.slots.push(KernelRecheckSlotV2 {
            original: Box::new(PayloadKernelRecheckOriginalV2::new()),
            disposal: None,
        });
        let slot = self.slots.last_mut().ok_or_else(|| closed("payload kernel receiver is absent"))?;
        slot.observe_once_v3(payload, supervisor)
    }

    pub(super) fn completed_for_parent_disposal_v4(&self) -> bool {
        self.refusal.is_none() && self.slots.len() == KERNEL_RECHECKS
            && self.slots.iter().all(|slot| {
                slot.original.failure().is_none() && slot.disposal.as_ref().is_some_and(|result| {
                    result.as_ref().is_ok_and(|proof| proof.belongs_to(&slot.original))
                })
            })
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.slots.iter().find_map(|slot| slot.original.failure().or_else(|| error(&slot.disposal)))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn current_native_files_v4(&self) -> Option<usize> {
        let active = self.slots.iter().any(|slot| {
            !slot.disposal.as_ref().is_some_and(|result| {
                result.as_ref().is_ok_and(|proof| proof.belongs_to(&slot.original))
            })
        });
        if active { Some(Self::receiving_obligations_v2()?.1) } else { Some(0) }
    }

    #[cfg(test)]
    pub(super) fn first_original_address(&self) -> Option<*const ()> {
        Some(self.slots.first()?.original.as_ref() as *const _ as *const ())
    }

    #[cfg(test)]
    pub(super) fn can_dispose_first(&mut self) -> bool {
        self.slots.first_mut().is_some_and(|slot| {
            slot.original.prepare_positive_disposal().is_ok()
        })
    }

    pub(super) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let one = PayloadKernelRecheckOriginalV2::receiving_obligations_v2()?;
        let carriers = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<KernelRecheckSlotV2>()
                .checked_mul(KERNEL_RECHECKS)?.checked_mul(2)?)?;
        Some((one.0.checked_mul(KERNEL_RECHECKS)?.checked_add(carriers)?,
            one.1, // The next slot requires the previous actual FD-disposal proof.
            one.2.checked_mul(KERNEL_RECHECKS)?))
    }
}

fn add(left: (usize, usize, usize), right: (usize, usize, usize))
    -> Option<(usize, usize, usize)>
{
    Some((left.0.checked_add(right.0)?, left.1.checked_add(right.1)?, left.2.checked_add(right.2)?))
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed(message: &'static str) -> HostError {
    HostError::Fence(message)
}
