//! Retains the native admission prefixes of the two fixed limit proof points.
//!
//! Completed anchors move into the existing readback. Their original root and
//! child active probes remain here through the same proof's later checks and
//! owed observations. This object supplies no role, observation or admission.

use std::os::fd::OwnedFd;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{CgroupChildOriginalV2, CgroupLimitReadbackV1, CgroupRootOriginalV2, RuntimeScopeMembershipOriginalV1};
use aos_systemd_client::SandboxUnitName;

use super::{BoundPayloadReadbackV1, BoundReadbackPhaseV1};
use crate::state::transition::RuntimeProofSnapshot;
use crate::{HostError, Result};

/// Holds the actual accepted witness after its temporary limit files retire.
pub(in crate::worker) struct BoundLimitNativeDisposedV4 {
    snapshot: RuntimeProofSnapshot,
}

impl BoundLimitNativeDisposedV4 {
    pub(in crate::worker) fn snapshot_v4(&self) -> RuntimeProofSnapshot {
        self.snapshot
    }
}

pub(crate) struct HostLimitNativeOriginalV2 {
    pub(super) root_descriptor: Option<std::io::Result<OwnedFd>>,
    pub(super) root: CgroupRootOriginalV2,
    pub(super) ancestors: [CgroupChildOriginalV2; 4],
    pub(super) payload: CgroupChildOriginalV2,
    pub(super) bookends: [CgroupChildOriginalV2; 4],
    pub(super) memberships: [[RuntimeScopeMembershipOriginalV1; 2]; 3],
    pub(super) membership_rounds: usize,
    disposed: Option<BoundLimitNativeDisposedV4>,
}

impl HostLimitNativeOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            root_descriptor: None,
            root: CgroupRootOriginalV2::new(),
            ancestors: std::array::from_fn(|_| CgroupChildOriginalV2::new()),
            payload: CgroupChildOriginalV2::new(),
            bookends: std::array::from_fn(|_| CgroupChildOriginalV2::new()),
            memberships: std::array::from_fn(|_| std::array::from_fn(|_| RuntimeScopeMembershipOriginalV1::new())),
            membership_rounds: 0,
            disposed: None,
        }
    }

    pub(in crate::worker) fn disposal_v4(&self) -> Option<&BoundLimitNativeDisposedV4> {
        self.disposed.as_ref()
    }

    pub(in crate::worker) fn worker_disposal_v4(&self) -> Option<BoundLimitNativeDisposedV4> {
        Some(BoundLimitNativeDisposedV4 { snapshot: self.disposed.as_ref()?.snapshot })
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.root_descriptor {
            return Some(error);
        }
        if let Some(error) = self.root.failure() {
            return Some(error);
        }
        for original in &self.ancestors {
            if let Some(error) = original.failure() {
                return Some(error);
            }
        }
        if let Some(error) = self.payload.failure() {
            return Some(error);
        }
        self.memberships.iter().flatten().find_map(|original| {
            original.failure().map(|error| error as &(dyn std::error::Error + 'static))
        }).or_else(|| self.bookends.iter().find_map(|original| {
            original.failure().map(|error| error as &(dyn std::error::Error + 'static))
        }))
    }

    // All incarnation values have the same exact hex width. Derive the fixed
    // path lengths with the same producer rather than supplying a path ceiling.
    // Each completed anchor is a move from its corresponding lower original;
    // its FD is included once by that lower supplier, never added again here.
    pub(crate) fn receiving_demand_v2() -> Option<ResourceVector> {
        let service = SandboxUnitName::from_incarnation([1; 16]).cgroup_path();
        let mut native = CgroupRootOriginalV2::receiving_obligations_v2()?;
        for path in super::systemd::fixed_limit_paths(&service) {
            let child = CgroupChildOriginalV2::receiving_obligations_v2(path.len())?;
            native = add(native, child)?;
            native = add(native, child)?;
        }
        native = add(native, CgroupChildOriginalV2::receiving_obligations_v2("payload".len())?)?;
        for _ in 0..4 {
            native = add(native, CgroupLimitReadbackV1::segmented_active_receiving_obligations_v4()?)?;
            native = add(native, CgroupLimitReadbackV1::retained_control_receiving_obligations_v4()?)?;
        }

        // Each complete round physically retires both observations before
        // another round can enter. A failed round keeps both reached prefixes
        // and blocks the later rounds. Memory and real namespace entries stay
        // summed across all six originals; only their proven FD peak is two.
        let membership = RuntimeScopeMembershipOriginalV1::receiving_demand_v1()?;
        for _ in 0..6 {
            native.0 = native.0.checked_add(membership.0)?;
            native.2 = native.2.checked_add(membership.2)?;
        }
        // The actual selected recipe closes every completed admission probe
        // after its exact moved anchor comparison, each active interval before
        // its next phase, and each verified bookend before another resolver.
        // Keep all six membership byte/name liabilities, but one exact native
        // phase owns at most the following physical roster:
        // root + four ancestors + payload anchor, 28 original control OFDs,
        // one name-check FD, two active probes, one full four-FD resolver,
        // and both full seven-FD membership originals. Outputs included by a
        // current resolver may overlap an anchor; the bound stays conservative.
        native.1 = 1_usize.checked_add(4)?.checked_add(1)?
            .checked_add(7_usize.checked_mul(4)?)?
            .checked_add(1)?.checked_add(2)?
            .checked_add(CgroupChildOriginalV2::receiving_obligations_v2(1)?.1)?
            .checked_add(membership.1.checked_mul(2)?)?;

        // The existing readback also owns the moved anchors and fixed inline
        // control buffers. Cover constructor/local and resident carrier overlap
        // explicitly; this is byte provision, not namespace-field accounting.
        let bytes = native.0.checked_add(2 * std::mem::size_of::<BoundPayloadReadbackV1>())?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(native.1).ok()?)
            .with(D::MetadataEntries, u64::try_from(native.2).ok()?))
    }
}

impl BoundPayloadReadbackV1 {
    pub(in crate::worker) fn retire_ready_limit_files_once_v4(&mut self) -> Result<()> {
        let snapshot = self.verified()?.proof;
        let native = self.limit_native.as_ref()
            .ok_or(HostError::Fence("actual Launch limit original is absent"))?;
        if self.phase != BoundReadbackPhaseV1::Ready
            || self.failure_cause().is_some() || native.disposed.is_some()
            || native.membership_rounds != 3
            || native.memberships.iter().flatten().any(|original| original.native_disposal_v4().is_none())
            || self.limits.iter().any(|original| !original.completed_files_are_disposable_v4())
        {
            return Err(HostError::Fence("whole Ready limit flight is not disposable"));
        }

        // Every same-OFD/control, ancestor identity, membership and final
        // manager comparison succeeded. Later global checks use the moved
        // supervisor/payload pins and immutable verification frame, never
        // these limit-only anchor/probe/control descriptors. Keep all control
        // byte/absence/identity DATA and every membership's original Results.
        for original in &mut self.limits {
            if let Err(cause) = original.retire_completed_files_once_v4() {
                self.native_failure = Some(cause);
                return Err(HostError::Fence("Ready limit file disposal refused"));
            }
        }
        drop(self.root.take());
        for anchor in &mut self.anchors {
            drop(anchor.take());
        }
        drop(self.payload_anchor.take());
        for anchor in &mut self.anchor_bookends {
            drop(anchor.take());
        }
        let native = self.limit_native.as_mut()
            .ok_or(HostError::Fence("actual Launch limit original is absent"))?;
        drop(std::mem::replace(&mut native.root, CgroupRootOriginalV2::new()));
        for original in &mut native.ancestors {
            drop(std::mem::replace(original, CgroupChildOriginalV2::new()));
        }
        drop(std::mem::replace(&mut native.payload, CgroupChildOriginalV2::new()));
        for original in &mut native.bookends {
            drop(std::mem::replace(original, CgroupChildOriginalV2::new()));
        }
        native.disposed = Some(BoundLimitNativeDisposedV4 { snapshot });
        Ok(())
    }
}

fn add(left: (usize, usize, usize), right: (usize, usize, usize))
    -> Option<(usize, usize, usize)>
{
    Some((left.0.checked_add(right.0)?, left.1.checked_add(right.1)?, left.2.checked_add(right.2)?))
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use super::*;

    #[test]
    fn invalid_root_reports_the_same_lower_native_cause_before_its_status_marker() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor: OwnedFd = std::fs::File::open(directory.path()).unwrap().into();
        let mut readback = BoundPayloadReadbackV1::new_launch_receiving_v2();
        let returned = readback.limit_native.as_mut().unwrap().root.admit_once(descriptor);
        assert!(returned.is_err());
        readback.native_failure = returned.err();

        {
            let actual: &aos_sandbox_linux::Error =
                readback.limit_native.as_ref().unwrap().root.failure().unwrap();
            let selected = readback.failure_cause().unwrap();
            let marker = readback.native_failure.as_ref().unwrap();
            // The upper view intentionally borrows its error without a static
            // object bound. Compare data addresses, independently of a trait
            // vtable or a downcast that would require a static borrow.
            let actual_address = actual as *const aos_sandbox_linux::Error as *const ();
            let selected_address = selected as *const dyn std::error::Error as *const ();
            let marker_address = marker as *const aos_sandbox_linux::Error as *const ();
            assert_eq!(selected_address, actual_address);
            assert_ne!(selected_address, marker_address);
        }
        assert!(readback.retire_ready_limit_files_once_v4().is_err());
        assert!(readback.limit_native.as_ref().unwrap().disposal_v4().is_none());
        assert!(readback.limit_native.as_mut().unwrap().root.take_completed_once().is_none());
    }
}
