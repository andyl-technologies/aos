//! Retains native credits beneath the actual containing account owner.
//!
//! Closed publishers supply this credit before roster, process or launch
//! controls are born. Its private fields are available only inside the host
//! issuer; neither resource limits nor installed geometry construct funding.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use crucible_host_resources::host_services::HostServiceAllocator;
use std::sync::Arc;

use crucible_host_resources::host_services::process_birth::{
    AuthenticatedNativeSubdivision, NativePoolRefusal, ServiceBirthError,
};
use crucible_host_resources::host_services::{HostServiceError, HostServiceLeasePair};
use crucible_host_resources::host_supervision::{
    HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
#[cfg(feature = "private-measurement-domain")]
use crucible_host_resources::measurement_origin::{
    AuthenticatedActorFamily, MeasurementOriginError,
};

/// Refuses certified account publication without substituting an original.
#[derive(Debug, thiserror::Error)]
pub enum OriginalActorAccountError {
    /// The same authenticated normal main refused its checked subdivision.
    #[error("normal native purpose refused: {0}")]
    NativePurpose(#[from] ServiceBirthError),
    /// Preserves physical node/World return and its independent Cleanup post.
    #[error("normal native return refused: {0}")]
    NativeReturn(
        #[from] crucible_host_resources::host_services::process_birth::NativePoolReturnError,
    ),
    /// Preserves node/window birth custody and the independent Original postcut.
    #[error("normal native pool refused: {0}")]
    NativePool(#[from] NativePoolRefusal),
    /// The authenticated workflow refused before a separate original postcheck.
    #[error("original workflow refused: {source}; original: {original:?}")]
    #[cfg(feature = "private-measurement-domain")]
    WorkflowBoundary {
        /// Actual first immutable-workflow or service-profile refusal.
        #[source]
        source: MeasurementOriginError,
        /// The same retained preparation's independent postcheck.
        original: Option<HostSupervisionError>,
    },
    /// Saved Cleanup completion failed before its independent retry observation.
    #[error("Target Cleanup completion refused: {source}; post: {post:?}")]
    TargetCleanupBoundary {
        /// First actual completion or publication refusal of the saved Cleanup.
        #[source]
        source: HostSupervisionError,
        /// Distinct latest observation refusal of that same completed operation.
        post: Option<HostSupervisionError>,
    },
    /// The actual workflow parser failed before a separate original postcheck.
    #[error("original workflow decode refused: {source}; original: {original:?}")]
    WorkflowDecode {
        /// Actual parser syntax or typed admission marker.
        #[source]
        source: crucible_engine::owned_decode::ClosedJsonError,
        /// The same retained preparation's independent postcheck.
        original: Option<HostSupervisionError>,
    },
    /// The same authenticated invocation refused its identity or interval.
    #[error("original actor binding refused: {0}")]
    #[cfg(feature = "private-measurement-domain")]
    Origin(#[from] MeasurementOriginError),
    /// Either original account refused its unpublished or native charge.
    #[error("original actor account refused: {0}")]
    Account(#[from] HostServiceError),
    /// Account admission failed before a separate same-original refusal.
    #[error("original native account refused: {source}; original: {original:?}")]
    NativeAccountBoundary {
        /// The actual first original account refusal.
        #[source]
        source: HostServiceError,
        /// The same preparation's independent postcheck refusal.
        original: Option<HostSupervisionError>,
    },
    /// The same original supervisor or returned preparation refused.
    #[error("original actor supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
    /// The same actual native state refused control closure.
    #[error("original native control refused: {source}; original: {original:?}")]
    NativeControlBoundary {
        /// The actual native control refusal precedes this postcheck.
        #[source]
        source: super::native_resources::LinuxQemuNativeResourceError,
        /// The same retained Cleanup's independent boundary refusal.
        original: Option<HostSupervisionError>,
    },
    /// Retains decode admission before the same original postcut.
    #[error("original actor decode refused: {source}; original: {original:?}")]
    DecodeBoundary {
        /// First actual sticky decoder refusal.
        #[source]
        source: crucible_engine::owned_decode::DecodeAdmissionError,
        /// Separate same-original postcheck.
        original: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    },
    /// The same original decoder account refused constructor admission.
    #[error("original actor decode refused: {0}")]
    Decode(#[source] crucible_engine::owned_decode::DecodeAdmissionError),
    /// Required retained custody has already been consumed.
    #[error("original actor custody is unavailable")]
    Unavailable,
}

/// Retains the actual original native pair outside its future native allocation.
///
/// These immutable extents describe the pair; they do not certify Source,
/// domain installation, process birth, or a ResearchResident launch permission.
/// No numeric constructor or caller-supplied cleanup flag can release it.
#[must_use = "retain external paired native credit through actual control free"]
pub(in crate::linux_attempt_host) struct OriginalNativeAccountCredit {
    pub(in crate::linux_attempt_host) original: Option<RetainedNativeCredit>,
    pub(in crate::linux_attempt_host) full_resident_bytes: u64,
    pub(in crate::linux_attempt_host) full_backing_bytes: u64,
    pub(in crate::linux_attempt_host) total_metadata_bytes: u64,
    pub(in crate::linux_attempt_host) cpu_ceiling: u64,
    pub(in crate::linux_attempt_host) task_ceiling: u64,
    pub(in crate::linux_attempt_host) descriptor_ceiling: u64,
    pub(in crate::linux_attempt_host) normal_controls_bytes: u64,
    #[cfg(feature = "private-measurement-domain")]
    pub(in crate::linux_attempt_host) actor_family: Option<Arc<AuthenticatedActorFamily>>,
}

pub(in crate::linux_attempt_host) struct RetainedNativeCredit {
    pub(in crate::linux_attempt_host) _pair: Option<HostServiceLeasePair>,
    pub(in crate::linux_attempt_host) normal: Option<AuthenticatedNativeSubdivision>,
    pub(in crate::linux_attempt_host) preparation: Arc<HostOperationGuard>,
}

impl OriginalNativeAccountCredit {
    /// Saves credit only after every check while its source purpose stays held.
    ///
    /// # Errors
    /// Refuses an occupied destination, absent purpose, wrong Preparation or
    /// insufficient CPU/metadata geometry without consuming either slot.
    pub(super) fn move_from_normal_subdivision(
        source: &mut Option<AuthenticatedNativeSubdivision>,
        destination: &mut Option<Self>,
        preparation: &Arc<HostOperationGuard>,
        controls: u64,
    ) -> Result<(), OriginalActorAccountError> {
        if destination.is_some() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let purpose = source
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        purpose.verify_native_preparation(preparation)?;
        let bounds = purpose.bounds();
        if bounds.cpu_slots == 0 || controls > bounds.metadata_bytes {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let purpose = source
            .take()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        *destination = Some(Self {
            original: Some(RetainedNativeCredit {
                _pair: None,
                normal: Some(purpose),
                preparation: Arc::clone(preparation),
            }),
            full_resident_bytes: bounds.resident_peak_bytes,
            full_backing_bytes: bounds.backing_peak_bytes,
            total_metadata_bytes: bounds.metadata_bytes,
            cpu_ceiling: bounds.cpu_slots,
            task_ceiling: bounds.task_slots,
            descriptor_ceiling: bounds.file_descriptors,
            normal_controls_bytes: controls,
            #[cfg(feature = "private-measurement-domain")]
            actor_family: None,
        });
        Ok(())
    }

    /// Releases the same pair after its enclosing native control was freed.
    ///
    /// This private cut runs before any roster allocation, or after exclusive
    /// whole-roster control free. In either case a permanently prepaid external
    /// owner retains the same pair on refusal; no live roster controls remain.
    ///
    /// # Errors
    /// Preserves the same preparation's original refusal before pair release.
    pub(super) fn retire_after_control_free(&mut self) -> Result<(), OriginalActorAccountError> {
        let Some(retained) = self.original.as_ref() else {
            return Ok(());
        };
        if let Some(normal) = retained.normal.as_ref() {
            let cleanup = normal.retained_world_cleanup()?;
            let normal = self
                .original
                .as_mut()
                .and_then(|retained| retained.normal.as_mut())
                .ok_or(OriginalActorAccountError::Unavailable)?;
            let result = normal.retire_after_control_free(&cleanup);
            if normal.is_physically_returned() {
                drop(self.original.take());
            }
            return result.map_err(Into::into);
        }
        // Existing private/component pairs have no World claim. They retain
        // their original Preparation policy; this path issues no Main Cleanup.
        self.require_original()?;
        drop(self.original.take());
        Ok(())
    }

    pub(super) fn verify_quiescent_custody(&self) -> Result<(), OriginalActorAccountError> {
        match self.original.as_ref() {
            Some(retained) if retained.normal.is_none() => self.require_original(),
            // Normal custody was authentically moved into this credit before
            // birth; closed-slot observation neither returns it nor admits work.
            _ => Ok(()),
        }
    }

    pub(super) fn require_return_phase(&self) -> Result<(), OriginalActorAccountError> {
        match self.original.as_ref() {
            Some(retained) => match retained.normal.as_ref() {
                Some(normal) => {
                    let cleanup = normal.retained_world_cleanup()?;
                    normal.verify_world_cleanup(&cleanup)?;
                    Ok(())
                }
                None => self.require_original(),
            },
            None => Ok(()),
        }
    }

    pub(super) fn is_physically_returned(&self) -> bool {
        self.original.is_none()
    }

    pub(super) fn verify_preparation(
        &self,
        preparation: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorAccountError> {
        let retained = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !Arc::ptr_eq(&retained.preparation, preparation) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        preparation.wait_slice()?;
        self.require_original()
    }

    pub(super) fn verify_capture_supervisor(
        &self,
        supervisor: &HostOperationSupervisor,
    ) -> Result<(), OriginalActorAccountError> {
        let retained = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !retained.preparation.shares_outer_cap(supervisor) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        self.require_original()
    }

    #[cfg(test)]
    pub(super) fn reserve_mechanism_pair(
        resident: &HostServiceAllocator,
        metadata: &HostServiceAllocator,
    ) -> Result<HostServiceLeasePair, HostServiceError> {
        // These test counters establish retention and refund behavior only;
        // they cannot issue a configured native process purpose.
        let first = resident.reserve_resources(69, 1056, 1536 << 20)?;
        let second = metadata.reserve_resources(0, 0, 512 << 20)?;
        Ok(HostServiceLeasePair::new(first, second))
    }

    #[cfg(test)]
    pub(super) fn mechanism_credit(
        preparation: Arc<HostOperationGuard>,
    ) -> Result<(Self, HostServiceAllocator, HostServiceAllocator), HostServiceError> {
        let resident = HostServiceAllocator::new(69, 1056, 1536 << 20)?;
        let metadata = HostServiceAllocator::new(1, 1, 512 << 20)?;
        let pair = Self::reserve_mechanism_pair(&resident, &metadata)?;
        Ok((
            Self {
                original: Some(RetainedNativeCredit {
                    _pair: Some(pair),
                    normal: None,
                    preparation,
                }),
                full_resident_bytes: 1536 << 20,
                full_backing_bytes: 4 << 30,
                total_metadata_bytes: 512 << 20,
                cpu_ceiling: 1,
                task_ceiling: 69,
                descriptor_ceiling: 1056,
                normal_controls_bytes: 0,
                #[cfg(feature = "private-measurement-domain")]
                actor_family: None,
            },
            resident,
            metadata,
        ))
    }

    pub(super) fn prepare_fresh_launch(
        &self,
        attempt: super::NativeAccountAttempt,
        controller: Arc<super::original_node::OriginalNativeFreshLaunchError>,
    ) -> Result<super::original_node::OriginalNativeFreshPreparation, OriginalActorAccountError>
    {
        self.require_original()?;
        let retained = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(
            super::original_node::OriginalNativeFreshPreparation::retain(
                &retained.preparation,
                attempt,
                controller,
            ),
        )
    }

    pub(super) fn prepare_launch_controller(
        &self,
    ) -> Result<Arc<super::original_node::OriginalNativeFreshLaunchError>, OriginalActorAccountError>
    {
        let origin = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(super::original_node::OriginalNativeFreshLaunchError::prepare(&origin.preparation))
    }

    pub(super) fn enter_normal_preparation(&mut self) -> Result<(), OriginalActorAccountError> {
        self.require_original()?;
        let retained = self
            .original
            .as_mut()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if let Some(normal) = &retained.normal {
            // Claim assigned the actual Arc extent before this transition.
            // The main debit is retained independently of the completed initial
            // preparation and this new finite native preparation operation.
            retained.preparation = Arc::new(normal.begin_native_preparation()?);
        }
        self.require_original()
    }

    pub(super) fn normal_preparation_extent(&self) -> Result<u64, OriginalActorAccountError> {
        if self
            .original
            .as_ref()
            .and_then(|held| held.normal.as_ref())
            .is_none()
        {
            return Ok(0);
        }
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
        u64::try_from(layout.pad_to_align().size())
            .map_err(|_| OriginalActorAccountError::Unavailable)
    }

    pub(super) fn begin_cleanup(&self) -> Result<HostOperationGuard, OriginalActorAccountError> {
        Ok(self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?
            .preparation
            .begin_original_cleanup_control()?)
    }

    pub(super) fn verify_actor_family(
        &self,
        process: &crate::linux_attempt_process::LinuxQemuAttemptProcessFactory,
    ) -> Result<(), OriginalActorAccountError> {
        self.require_original()?;
        if let Some(normal) = self.original.as_ref().and_then(|held| held.normal.as_ref()) {
            process.verify_normal_family(normal.family())?;
            return self.require_original();
        }
        #[cfg(feature = "private-measurement-domain")]
        {
            let family = self
                .actor_family
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            process.verify_original_actor_family(family)?;
            return self.require_original();
        }
        #[cfg(not(feature = "private-measurement-domain"))]
        Err(OriginalActorAccountError::Unavailable)
    }

    /// Corroborates the actual installed normal parent without issuing authority.
    pub(super) fn native_parent_readback(&self) -> Result<[u64; 5], OriginalActorAccountError> {
        self.require_original()?;
        let normal = self
            .original
            .as_ref()
            .and_then(|held| held.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let fields = normal.family().native_containment_readback()?;
        self.require_original()?;
        Ok(fields)
    }

    /// Checks the same preparation retained with this external credit.
    ///
    /// # Errors
    /// Refuses missing consumed custody or the original operation's sticky
    /// cancellation, expiration, terminal state or unavailable synchronization.
    pub fn require_original(&self) -> Result<(), OriginalActorAccountError> {
        let retained = self
            .original
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if let Some(normal) = &retained.normal {
            normal.check()?;
        } else {
            retained.preparation.wait_slice()?;
        }
        Ok(())
    }

    /// Returns the original FULL resident extent.
    #[must_use]
    pub const fn full_resident_bytes(&self) -> u64 {
        self.full_resident_bytes
    }

    /// Returns the authored FULL backing requirement, not a backing grant.
    #[must_use]
    pub const fn full_backing_bytes(&self) -> u64 {
        self.full_backing_bytes
    }

    /// Returns TOTAL metadata before native control and allowance subtraction.
    #[must_use]
    pub const fn total_metadata_bytes(&self) -> u64 {
        self.total_metadata_bytes
    }

    pub(super) const fn task_ceiling(&self) -> u64 {
        self.task_ceiling
    }

    /// Observes the CPU allowance retained by this same original issuer.
    ///
    /// This preserves the existing coupled CPU/vCPU admission contract. The
    /// observation allocates nothing and cannot issue another subdivision.
    ///
    /// # Errors
    /// Refuses missing or failed original custody and a zero retained ceiling.
    pub(super) fn cpu_ceiling(&self) -> Result<u64, OriginalActorAccountError> {
        self.require_original()?;
        if self.cpu_ceiling == 0 {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(self.cpu_ceiling)
    }

    /// Checks a requested vCPU ceiling against this original's CPU allowance.
    ///
    /// This check does not establish configured CPU or thread allocation floors.
    ///
    /// # Errors
    /// Preserves the same original refusal before rejecting a zero request or
    /// a ceiling above its retained allowance.
    pub(super) fn require_vcpu_ceiling(
        &self,
        requested: u32,
    ) -> Result<(), OriginalActorAccountError> {
        let ceiling = self.cpu_ceiling()?;
        if requested == 0 || u64::from(requested) > ceiling {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn local_descriptor_ceiling(&self) -> Result<u64, OriginalActorAccountError> {
        self.require_original()?;
        self.original
            .as_ref()
            .and_then(|retained| retained.normal.as_ref())
            .map(AuthenticatedNativeSubdivision::local_file_descriptors)
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(super) const fn descriptor_ceiling(&self) -> u64 {
        self.descriptor_ceiling
    }
}

impl Drop for OriginalNativeAccountCredit {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            std::mem::forget(original);
        }
    }
}

#[cfg(test)]
mod tests;
