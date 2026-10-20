//! Retains actual local profile observations without renewing Baseline scopes.
//!
//! The genuine floor purpose prepays this passive destination before a primary
//! operation. It borrows only an already-admitted profile and shares Baseline's
//! exact local comparison recipe; it cannot select files or reopen healthy B.

use std::collections::TryReserveError;
use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1;
use aos_sandbox_linux::guest_confinement::CurrentThreadSubjectOriginalV1;
use aos_sandbox_linux::selinux_policy::RetainedLiveSelinuxPolicyReadbackV1;

use crate::immutable_image::ImmutableFileRevalidationOriginalV1;

use super::local_recipe::LocalCurrentness;
use super::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1};

pub(super) struct LocalCurrentnessOriginalsV1 {
    pub(super) profile: ImmutableFileRevalidationOriginalV1,
    pub(super) images: Vec<ImmutableFileRevalidationOriginalV1>,
    pub(super) images_allocation: Option<Result<(), TryReserveError>>,
    pub(super) nix: ImmutableFileRevalidationOriginalV1,
    pub(super) policy: RetainedLiveSelinuxPolicyReadbackV1,
    pub(super) subject: CurrentThreadSubjectOriginalV1,
    pub(super) membership: ExactCgroupMembershipReadbackV1,
    pub(super) fragment: ImmutableFileRevalidationOriginalV1,
}

impl LocalCurrentnessOriginalsV1 {
    pub(super) fn new() -> Self {
        Self {
            profile: ImmutableFileRevalidationOriginalV1::new(),
            images: Vec::new(),
            images_allocation: None,
            nix: ImmutableFileRevalidationOriginalV1::new(),
            policy: RetainedLiveSelinuxPolicyReadbackV1::new(),
            subject: CurrentThreadSubjectOriginalV1::new(),
            membership: ExactCgroupMembershipReadbackV1::new(),
            fragment: ImmutableFileRevalidationOriginalV1::new(),
        }
    }
}

/// Retains one same-profile local comparison as nonauthorizing negative DATA.
///
/// This owner retains every reached selected native prefix and shares the
/// existing local recipe. It cannot create an admitted profile, financial loan
/// or successful unit delivery. Complete PID1 comparison remains separate.
#[must_use = "retain actual profile-local native originals through the owed post"]
pub struct ControllerProfileLocalCurrentnessOriginalV1 {
    pub(super) local: LocalCurrentness,
    originals: LocalCurrentnessOriginalsV1,
    entered: bool,
}

impl ControllerProfileLocalCurrentnessOriginalV1 {
    /// Creates inert result destinations without native observation or a loan.
    #[must_use]
    pub fn new() -> Self {
        Self {
            local: LocalCurrentness::new(),
            originals: LocalCurrentnessOriginalsV1::new(),
            entered: false,
        }
    }

    /// Borrows the first actual native or semantic result in recipe order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.local.failure_observed(Some(&self.originals))
    }

    /// Reports complete local DATA without admitting the profile or its unit.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.entered && self.local.is_complete() && self.failure().is_none()
    }
}

impl Default for ControllerProfileLocalCurrentnessOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Describes one complete retained local sample using this actual pin count.
    ///
    /// It performs no IO and grants no admission. The purpose must independently
    /// fund this DATA before constructing/capturing the sample, and additionally
    /// fund all PID1 flights, semantic comparisons and simultaneous bookends.
    #[must_use]
    pub fn local_currentness_receiving_demand_v1(&self) -> Option<ResourceVector> {
        Self::local_currentness_demand_for_pin_count_v1(self.files.len())
    }

    pub(super) fn local_currentness_demand_for_pin_count_v1(count: usize) -> Option<ResourceVector> {
        let immutable = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let policy = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        let (subject_bytes, subject_files, _subject_cells) = CurrentThreadSubjectOriginalV1::receiving_demand_v1()?;
        let membership_bytes = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let immutable_inline = 3_usize.checked_mul(std::mem::size_of::<ImmutableFileRevalidationOriginalV1>())?;
        let lower_inline = immutable_inline
            .checked_add(std::mem::size_of::<RetainedLiveSelinuxPolicyReadbackV1>())?
            .checked_add(std::mem::size_of::<CurrentThreadSubjectOriginalV1>())?
            .checked_add(std::mem::size_of::<ExactCgroupMembershipReadbackV1>())?
            .checked_add(std::mem::size_of::<LocalCurrentness>())?;
        let local = LocalCurrentness::dominant_bytes(count).ok()?;
        // The fixed owner holds three inline immutable samples; reached image
        // samples occupy the reserved Vec. One additional construction sample
        // can coexist with its moved Vec destination during push.
        let bytes = std::mem::size_of::<ControllerProfileLocalCurrentnessOriginalV1>()
            .checked_sub(lower_inline)?
            .checked_add(local)?
            .checked_add(policy.memory_bytes)?
            .checked_add(subject_bytes)?
            .checked_add(membership_bytes)?
            .checked_add(std::mem::size_of::<ImmutableFileRevalidationOriginalV1>())?;
        // Successful policy, subject and status Files are actually retired
        // before the next primitive; successful membership probes retire
        // before liveness/fragment checks. Every failed primitive retains its
        // whole prefix and prevents subsequent primitive entry in this sample.
        let files = policy.open_files.max(subject_files)
            .max(ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1)
            .max(1);
        // The measured image pins and three fixed immutable names are the
        // actual resident namespace entries. Native result/control headers,
        // membership samples and policy/subject carriers are compiled bytes.
        let names = count.checked_add(3)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(names).ok()?);
        for _ in 0..count.checked_add(3)? {
            demand = demand.checked_add(immutable).ok()?;
        }
        Some(demand)
    }

    /// Captures one same-profile local sample without entering a healthy scope.
    ///
    /// The genuine purpose must prepay the exact demand from this profile and
    /// retain this profile, sample and all surrounding independent posts. A
    /// successful sample cannot restore any previous Baseline/financial state.
    ///
    /// # Errors
    /// Rejects repeated entry, unavailable native comparisons, changed image,
    /// policy, subject, credentials, status, membership or original process.
    pub fn observe_local_currentness_retaining_v1(
        &self,
        original: &mut ControllerProfileLocalCurrentnessOriginalV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if original.entered {
            return Err(ControllerProfileErrorV1::Service);
        }
        original.entered = true;
        original.local.capture_observed(self, Some(&mut original.originals));
        if original.is_complete() {
            Ok(())
        } else {
            Err(ControllerProfileErrorV1::Service)
        }
    }
}
