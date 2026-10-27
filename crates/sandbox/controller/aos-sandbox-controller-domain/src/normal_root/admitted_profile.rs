//! Carries only a genuinely completed Controller profile admission above transport.
//!
//! The fixed Bank or actual ordinary admission alone constructs an unshared
//! result. Its later Arc sharing preserves the existing startup frontier. No
//! caller profile, boolean, absent-value constructor or raw file issues it.

use std::sync::Arc;
use super::ProductionControllerNormalRootProfileV1;

/// Owns the actual completed profile result before its existing Arc allocation.
pub struct ControllerAdmittedStartupProfileV1 {
    profile: Option<ProductionControllerNormalRootProfileV1>,
}

impl ControllerAdmittedStartupProfileV1 {
    pub(crate) fn from_completed_admission(profile: Option<ProductionControllerNormalRootProfileV1>) -> Self {
        Self { profile }
    }

    /// Shares only this completed admission at the original upper startup frontier.
    #[must_use]
    pub fn into_shared(self) -> ControllerSharedStartupProfileV1 {
        ControllerSharedStartupProfileV1 { profile: self.profile.map(Arc::new) }
    }
}

/// Retains a genuine admitted profile or actual admitted absence for image binding.
///
/// Cloning shares only the same actual profile; it performs no admission,
/// currentness check, allocation of a profile or financial transition.
///
/// ```compile_fail
/// use aos_sandbox_controller_domain::normal_root::ControllerSharedStartupProfileV1;
/// let forged_absence = ControllerSharedStartupProfileV1 { profile: None };
/// ```
#[derive(Clone)]
pub struct ControllerSharedStartupProfileV1 {
    profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
}

impl ControllerSharedStartupProfileV1 {
    /// Borrows the same completed profile, if genuinely supplied and admitted.
    #[must_use]
    pub fn profile(&self) -> Option<&ProductionControllerNormalRootProfileV1> {
        self.profile.as_deref()
    }

    /// Shares the same admitted profile without admitting a replacement.
    #[must_use]
    pub fn profile_share(&self) -> Option<Arc<ProductionControllerNormalRootProfileV1>> {
        self.profile.clone()
    }
}

/// Borrows the four original native pins of one selected Controller profile.
///
/// Only the opaque admitted profile creates this view. It does not perform a
/// currentness observation or supply an admission, payer or process role.
#[doc(hidden)]
pub struct ControllerFloorServiceAnchorBorrowV1<'profile> {
    process: &'profile aos_linux_descriptors::pidfd::PidFd,
    cgroup: &'profile aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    fragment: &'profile aos_sandbox_broker::immutable_image::RetainedImmutableFileV1,
    manager: &'profile aos_sandbox_broker::immutable_image::RetainedImmutableFileV1,
    invocation: &'profile [u8; 16],
}

impl<'profile> ControllerFloorServiceAnchorBorrowV1<'profile> {
    /// Borrows the original Controller process pin.
    pub fn process(&self) -> &'profile aos_linux_descriptors::pidfd::PidFd { self.process }

    /// Borrows the original Controller cgroup pin.
    pub fn cgroup(&self) -> &'profile aos_sandbox_linux::cgroup::RetainedCgroupAnchor { self.cgroup }

    /// Borrows the original measured Controller unit fragment.
    pub fn fragment(&self) -> &'profile aos_sandbox_broker::immutable_image::RetainedImmutableFileV1 { self.fragment }

    /// Borrows the original measured PID1 executable.
    pub fn manager(&self) -> &'profile aos_sandbox_broker::immutable_image::RetainedImmutableFileV1 { self.manager }

    /// Borrows the original unit invocation comparison DATA.
    pub fn invocation(&self) -> &'profile [u8; 16] { self.invocation }
}

impl ControllerSharedStartupProfileV1 {
    /// Borrows the fixed floor-service pins of this actual selected admission.
    ///
    /// Genuine ordinary admission and admitted absence return no selected
    /// view. The existing measured PID1 pin remains owned by this same profile
    /// Arc; locating it performs no observation or replacement allocation.
    #[doc(hidden)]
    pub fn floor_service_anchors_v1(&self) -> Option<ControllerFloorServiceAnchorBorrowV1<'_>> {
        let original = self.profile.as_ref()?.lower_original_v1();
        if !original.has_resource_delivery() || !original.has_resource_launch()
            || !original.has_tpm_image_delivery()
        {
            return None;
        }
        let manager = original.runtime_measurements().iter()
            .find(|file| file.path().as_os_str() == std::ffi::OsStr::new(&original.schema().pid1.path))?;
        Some(ControllerFloorServiceAnchorBorrowV1 {
            process: original.original_process(), cgroup: original.original_cgroup(),
            fragment: original.fragment_measurement(), manager,
            invocation: &original.original_unit_observation().invocation,
        })
    }
}
