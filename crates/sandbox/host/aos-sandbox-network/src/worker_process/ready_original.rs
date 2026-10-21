//! Retains worker READY validation through the sole existing native recipe.
//!
//! The enrolled Network service pays the concrete retained owner before moving
//! READY rights here. A successful locator or namespace comparison grants no
//! worker authority.

use super::*;
use aos_sandbox_linux::cgroup::{
    CgroupActiveOriginalV2, RuntimeScopeMembershipOriginalV1, WorkerCgroupOpeningV1,
};
use aos_sandbox_linux::pidfd::NamespaceAdoptionFailureV2;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::pidfd::PidFdNamespaceOriginalV2;

pub(super) trait ReadyNativeV4 {
    fn descriptor_count(&self) -> usize;
    fn resolve(
        &mut self,
        parent: &RetainedCgroupAnchor,
        relative: &Path,
    ) -> Result<(), NetworkWorkerProcessError>;
    fn membership(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        after: bool,
    ) -> Result<PidFdInfo, NetworkWorkerProcessError>;
    fn target(&mut self) -> Result<NamespaceIdentity, NetworkWorkerProcessError>;
    fn subject_namespace(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<NamespaceIdentity, NetworkWorkerProcessError>;
    fn alive(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<bool, NetworkWorkerProcessError>;
    fn child_current(&mut self) -> Result<(), NetworkWorkerProcessError>;
    fn parent_current(
        &mut self,
        parent: &RetainedCgroupAnchor,
    ) -> Result<(), NetworkWorkerProcessError>;
}

pub(super) fn validate_ready_engine_v4(
    ready: &NetworkWorkerReadyV1,
    subject: &KernelAuthorizedRecordSubject,
    parent: &RetainedCgroupAnchor,
    host_namespace: &NamespaceFd,
    placement: WorkerCgroupPlacementV4,
    native: &mut impl ReadyNativeV4,
) -> Result<(), NetworkWorkerProcessError> {
    if native.descriptor_count() != 1 {
        return protocol("READY requires exactly one namespace descriptor");
    }
    let credentials = subject.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    placement.require_path(ready.cgroup(), WorkerCgroupRoleV4::Preparation)?;
    let relative = Path::new(ready.cgroup())
        .strip_prefix(placement.parent())
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)?;
    native.resolve(parent, relative)?;
    let info = native.membership(subject, false)?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != credentials.pid().get() {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    let target = native.target()?;
    let subject_namespace = native.subject_namespace(subject)?;
    if target != ready.namespace()
        || target != subject_namespace
        || target == host_namespace.identity()
        || !native.alive(subject)?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    native.membership(subject, true)?;
    native.child_current()?;
    native.parent_current(parent)
}

#[derive(Debug, thiserror::Error)]
#[error("Network READY validation refused; its complete originals remain retained")]
pub(crate) struct NetworkWorkerReadyRefusalV4 {
    _extra_descriptors: Option<Vec<OwnedFd>>,
}

#[derive(Clone, Copy)]
enum First {
    Resolve,
    MembershipBefore,
    Target,
    Namespace,
    Alive,
    MembershipAfter,
    ChildCurrent,
    ParentCurrent,
    Recipe,
    Reentry,
}

/// Owns the actual READY rights and every reached cgroup/namespace native prefix.
pub(crate) struct NetworkWorkerReadyOriginalV4 {
    descriptors: Option<Vec<OwnedFd>>,
    cgroup: WorkerCgroupOpeningV1,
    resolved: bool,
    membership: [RuntimeScopeMembershipOriginalV1; 2],
    target: Option<Result<NamespaceFd, NamespaceAdoptionFailureV2>>,
    subject_namespace: PidFdNamespaceOriginalV2,
    subject_namespace_value: Option<NamespaceFd>,
    alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    child_current: CgroupActiveOriginalV2,
    parent_current_entered: bool,
    result: Option<Result<(), NetworkWorkerProcessError>>,
    first: Option<First>,
    taken: bool,
}

impl NetworkWorkerReadyOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            descriptors: None,
            cgroup: WorkerCgroupOpeningV1::new(),
            resolved: false,
            membership: std::array::from_fn(|_| RuntimeScopeMembershipOriginalV1::new()),
            target: None,
            subject_namespace: PidFdNamespaceOriginalV2::new(),
            subject_namespace_value: None,
            alive: None,
            child_current: CgroupActiveOriginalV2::new(),
            parent_current_entered: false,
            result: None,
            first: None,
            taken: false,
        }
    }

    /// Bounds this actual READY owner and every lower native prefix before IO.
    pub(crate) fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let mut bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<WorkerCgroupPlacementV4>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<WorkerCgroupRoleV4>().checked_mul(2)?)?;
        let mut files = WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1;
        // The descendant locator plus cgroup.procs and cgroup.events are actual
        // names; successful snapshots of Rust control fields add no entries.
        let mut names = 3_usize;
        bytes = bytes.checked_add(WorkerCgroupOpeningV1::dominant_requested_bytes_v1()?)?;
        for (memory, native, namespace) in [
            RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?,
            RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?,
            CgroupActiveOriginalV2::receiving_obligations_v2()?,
            PidFdNamespaceOriginalV2::receiving_obligations_v2()?,
        ] {
            bytes = bytes.checked_add(memory)?;
            files = files.checked_add(native)?;
            names = names.checked_add(namespace)?;
        }
        // One actual received target NS and its retained adoption Result. The
        // received right itself is priced once by the caller's receive profile.
        bytes = bytes.checked_add(
            2 * std::mem::size_of::<Result<NamespaceFd, NamespaceAdoptionFailureV2>>(),
        )?;
        Some((bytes.checked_add(MAXIMUM_CGROUP_BYTES * 3)?, files, names))
    }

    pub(crate) fn observe_once_v4(
        &mut self,
        ready: &NetworkWorkerReadyV1,
        subject: &KernelAuthorizedRecordSubject,
        descriptors: Vec<OwnedFd>,
        parent: &RetainedCgroupAnchor,
        host: &NamespaceFd,
    ) -> Result<(), NetworkWorkerReadyRefusalV4> {
        if self.descriptors.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(NetworkWorkerReadyRefusalV4 {
                _extra_descriptors: Some(descriptors),
            });
        }
        self.descriptors = Some(descriptors);
        self.result = Some(validate_ready_engine_v4(ready, subject, parent, host, WorkerCgroupPlacementV4::Receiving, self));
        if !matches!(self.result, Some(Ok(()))) {
            self.first.get_or_insert(First::Recipe);
        }
        // The same parent active probe is independently owed once a native
        // descendant attempt entered, even when an earlier prefix refused.
        if self.resolved && !self.parent_current_entered {
            self.parent_current_entered = true;
            if self.cgroup.observe_owed_parent_once_v1(parent).is_err() {
                self.first.get_or_insert(First::ParentCurrent);
            }
        }
        if self.first.is_none() && matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NetworkWorkerReadyRefusalV4 {
                _extra_descriptors: None,
            })
        }
    }

    pub(crate) fn take_completed_custody_once_v4(
        &mut self,
    ) -> Option<(RetainedCgroupAnchor, NamespaceFd)> {
        if self.taken
            || self.first.is_some()
            || !matches!(self.result, Some(Ok(())))
            || self.cgroup.anchor().is_none()
            || !matches!(self.target, Some(Ok(_)))
        {
            return None;
        }
        let cgroup = self.cgroup.take_anchor_once()?;
        let Some(Ok(target)) = self.target.take() else {
            std::process::abort()
        };
        self.taken = true;
        Some((cgroup, target))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Resolve | First::ParentCurrent => self.cgroup.failure(),
            First::MembershipBefore => self.membership[0].failure().map(|cause| cause as _),
            First::MembershipAfter => self.membership[1].failure().map(|cause| cause as _),
            First::Target => self
                .target
                .as_ref()?
                .as_ref()
                .err()
                .map(|failure| failure.cause() as _),
            First::Namespace => self.subject_namespace.failure().map(|cause| cause as _),
            First::Alive => self.alive.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ChildCurrent => self.child_current.failure().map(|cause| cause as _),
            First::Recipe => self.result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reentry => Some(&NetworkWorkerProcessError::PeerMismatch),
        }
    }
}

impl ReadyNativeV4 for NetworkWorkerReadyOriginalV4 {
    fn descriptor_count(&self) -> usize {
        self.descriptors.as_ref().map_or(0, Vec::len)
    }
    fn resolve(
        &mut self,
        parent: &RetainedCgroupAnchor,
        relative: &Path,
    ) -> Result<(), NetworkWorkerProcessError> {
        self.resolved = true;
        self.cgroup
            .capture_descendant_once(parent, relative)
            .map_err(|_| {
                self.first.get_or_insert(First::Resolve);
                NetworkWorkerProcessError::PeerMismatch
            })
    }
    fn membership(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        after: bool,
    ) -> Result<PidFdInfo, NetworkWorkerProcessError> {
        let anchor = self
            .cgroup
            .anchor()
            .ok_or(NetworkWorkerProcessError::PeerMismatch)?;
        let index = usize::from(after);
        self.membership[index]
            .capture_once(anchor, subject.pidfd(), None)
            .map_err(|_| {
                self.first.get_or_insert(if after {
                    First::MembershipAfter
                } else {
                    First::MembershipBefore
                });
                NetworkWorkerProcessError::PeerMismatch
            })?;
        self.membership[index]
            .completed_info()
            .ok_or(NetworkWorkerProcessError::PeerMismatch)
    }
    fn target(&mut self) -> Result<NamespaceIdentity, NetworkWorkerProcessError> {
        let descriptor = self.descriptors.as_mut().and_then(Vec::pop).ok_or(
            NetworkWorkerProcessError::Protocol("READY namespace descriptor is absent"),
        )?;
        self.target = Some(NamespaceFd::from_owned_retaining_v2(
            descriptor,
            NamespaceKind::Network,
        ));
        match self.target.as_ref() {
            Some(Ok(target)) => Ok(target.identity()),
            _ => {
                self.first.get_or_insert(First::Target);
                Err(NetworkWorkerProcessError::PeerMismatch)
            }
        }
    }
    fn subject_namespace(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<NamespaceIdentity, NetworkWorkerProcessError> {
        self.subject_namespace
            .capture_once(subject.pidfd(), NamespaceKind::Network)
            .map_err(|_| {
                self.first.get_or_insert(First::Namespace);
                NetworkWorkerProcessError::PeerMismatch
            })?;
        self.subject_namespace_value = self.subject_namespace.take_completed_once();
        self.subject_namespace_value
            .as_ref()
            .map(NamespaceFd::identity)
            .ok_or(NetworkWorkerProcessError::PeerMismatch)
    }
    fn alive(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<bool, NetworkWorkerProcessError> {
        self.alive = Some(subject.is_alive());
        match self.alive.as_ref() {
            Some(Ok(value)) => Ok(*value),
            _ => {
                self.first.get_or_insert(First::Alive);
                Err(NetworkWorkerProcessError::PeerMismatch)
            }
        }
    }
    fn child_current(&mut self) -> Result<(), NetworkWorkerProcessError> {
        self.child_current
            .capture_once_v2(
                self.cgroup
                    .anchor()
                    .ok_or(NetworkWorkerProcessError::PeerMismatch)?,
            )
            .map_err(|_| {
                self.first.get_or_insert(First::ChildCurrent);
                NetworkWorkerProcessError::PeerMismatch
            })
    }
    fn parent_current(
        &mut self,
        parent: &RetainedCgroupAnchor,
    ) -> Result<(), NetworkWorkerProcessError> {
        self.parent_current_entered = true;
        self.cgroup.observe_parent_once(parent).map_err(|_| {
            self.first.get_or_insert(First::ParentCurrent);
            NetworkWorkerProcessError::PeerMismatch
        })
    }
}
