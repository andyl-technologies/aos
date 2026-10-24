//! Retires completed acquisition collectors after the real whole Launch Sent.
//!
//! Runtime process/namespace pins and the authenticated Agent remain on their
//! existing live owners. This proof records only the physical disposal of the
//! completed acquisition collector; it grants no Stop, reentry or capacity.

use super::*;

pub(crate) struct HostLaunchAcquisitionDisposedV4 {
    request: RequestIdentity,
    original: Weak<Mutex<HostLaunchWorkerOriginalV2>>,
}

pub(crate) struct HostLaunchAcquisitionDisposalV4<'slot> {
    original: &'slot mut Option<Arc<Mutex<HostLaunchWorkerOriginalV2>>>,
    request: RequestIdentity,
}

impl HostLaunchAcquisitionDisposalV4<'_> {
    pub(crate) fn dispose_after_parent_disposal_v4(self) -> Option<HostLaunchAcquisitionDisposedV4> {
        // Preparation exclusively borrowed this populated slot. An absent slot
        // cannot produce a disposal proof, even if a future caller changes that
        // invariant; the enclosing operation remains resident either way.
        let original = self.original.take()?;
        let retired = HostLaunchAcquisitionDisposedV4 {
            request: self.request,
            original: Arc::downgrade(&original),
        };
        drop(original);
        Some(retired)
    }
}

impl HostLaunchAcquisitionDisposedV4 {
    pub(crate) fn belongs_to_request_v4(&self, request: RequestIdentity) -> bool {
        self.request == request && self.original.upgrade().is_none()
    }
}

impl HostLaunchWorkerOriginalV2 {
    // The caller has already checked actual authenticated Sent, both upper
    // readbacks, completed Runtime-pin promotion and independent global posts.
    // Taking the complete owner only follows this non-IO whole native census.
    pub(crate) fn prepare_acquisition_disposal_v4(
        slot: &mut Option<Arc<Mutex<Self>>>,
        request: RequestIdentity,
    ) -> Result<HostLaunchAcquisitionDisposalV4<'_>> {
        let original = slot.as_ref()
            .ok_or_else(|| closed("Launch acquisition is absent"))?;
        if Arc::strong_count(original) != 1 {
            return Err(closed("Launch acquisition still has an active borrower"));
        }
        let owner = original.try_lock()
            .map_err(|_| closed("Launch acquisition is still borrowed"))?;
        if owner.request != request
            || owner.compensation_entered
            || owner.first.is_some()
            || owner.known_job_failure.is_some()
            || owner.inspections.len() != 2
            || owner.supervisors.len() != 2
            || owner.snapshots.len() != 2
            || owner.shifted.len() != 2
            || !owner.kernel_rechecks.completed_for_parent_disposal_v4()
        {
            return Err(closed("Launch acquisition lacks its whole native completion"));
        }
        for row in &owner.calls {
            if Arc::strong_count(row) != 1 {
                return Err(closed("Launch SDK row still has another owner"));
            }
            let row = row.try_lock()
                .map_err(|_| closed("Launch SDK row is still borrowed"))?;
            if row.first.is_some() || !row.storage_is_physically_compacted() {
                return Err(closed("Launch SDK row lacks its actual compacted disposition"));
            }
        }
        for (slot, native) in owner.inspections.iter().enumerate() {
            if Arc::strong_count(native) != 2 {
                return Err(closed("Launch inspection has an unexpected owning alias"));
            }
            let supervisor = owner.supervisors[slot].try_lock()
                .map_err(|_| closed("Launch supervisor proof is still borrowed"))?;
            if !supervisor.inspection().is_some_and(|expected| Arc::ptr_eq(expected, native)) {
                return Err(closed("Launch inspection differs from its actual supervisor proof"));
            }
            let native = native.try_lock()
                .map_err(|_| closed("Launch inspection is still borrowed"))?;
            if !native.completed_for_parent_disposal_v4() {
                return Err(closed("Launch inspection has unresolved native custody"));
            }
        }
        for native in &owner.supervisors {
            if Arc::strong_count(native) != 1 {
                return Err(closed("Launch native proof still has another owner"));
            }
            let native = native.try_lock().map_err(|_| closed("Launch supervisor proof is still borrowed"))?;
            if !native.completed_for_parent_disposal_v4() {
                return Err(closed("Launch supervisor proof has unresolved native custody"));
            }
        }
        for native in &owner.snapshots {
            if Arc::strong_count(native) != 1 {
                return Err(closed("Launch native proof still has another owner"));
            }
            let native = native.try_lock().map_err(|_| closed("Launch snapshot is still borrowed"))?;
            if !native.completed_for_parent_disposal_v4() {
                return Err(closed("Launch snapshot has unresolved native custody"));
            }
        }
        for native in &owner.shifted {
            if Arc::strong_count(native) != 1 {
                return Err(closed("Launch native proof still has another owner"));
            }
            let native = native.try_lock().map_err(|_| closed("Launch shifted proof is still borrowed"))?;
            if !native.completed_for_parent_disposal_v4() {
                return Err(closed("Launch shifted proof has unresolved native custody"));
            }
        }
        drop(owner);
        Ok(HostLaunchAcquisitionDisposalV4 { original: slot, request })
    }
}
