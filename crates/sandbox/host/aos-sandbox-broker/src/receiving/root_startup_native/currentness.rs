//! Holds the existing local Root observations under the actual service owner.
//!
//! These destinations do not admit a role or observation. The same Root
//! sampler prepays their finite recipe, then keeps failed native originals
//! through its independently owed outer posts.

use std::collections::TryReserveError;
use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1;
use aos_sandbox_linux::guest_confinement::CurrentThreadSubjectOriginalV1;
use aos_sandbox_linux::pidfd::{PidFdInfo, PidFdProcessIdentityOriginalV1};
use aos_sandbox_linux::selinux_policy::{PolicyReadbackError, RetainedLiveSelinuxPolicyReadbackV1};

use crate::immutable_image::{
    ImmutableExecutedFileOriginalV1, ImmutableFileRevalidationOriginalV1,
    ImmutableReadOriginalV1, RetainedImmutableFileV1,
};
use crate::profile_data::shared_read::BoundedFileReadOriginalV1;

use super::*;

const MAXIMUM_IMAGE_PASSES: usize = profile::MAXIMUM_RUNTIME_FILES + 3 + 3;

#[derive(Clone, Copy)]
enum Failure {
    Allocation,
    Image(usize),
    Executed,
    Maps,
    Policy,
    Subject,
    Status,
    Identity,
    Info,
    Membership,
}

pub(in crate::receiving) struct RootLocalCurrentnessOriginalV1 {
    images: Vec<ImmutableFileRevalidationOriginalV1>,
    allocation: Option<Result<(), TryReserveError>>,
    executed: ImmutableExecutedFileOriginalV1,
    maps: BoundedFileReadOriginalV1,
    policy: RetainedLiveSelinuxPolicyReadbackV1,
    policy_binding: Option<Result<(), PolicyReadbackError>>,
    subject: CurrentThreadSubjectOriginalV1,
    status: BoundedFileReadOriginalV1,
    identity: PidFdProcessIdentityOriginalV1,
    info: Option<aos_sandbox_linux::Result<PidFdInfo>>,
    membership: ExactCgroupMembershipReadbackV1,
    result: Option<Result<(), NormalRootStartupErrorV1>>,
    first: Option<Failure>,
}

impl RootLocalCurrentnessOriginalV1 {
    pub(in crate::receiving) fn new() -> Self {
        Self {
            images: Vec::new(),
            allocation: None,
            executed: ImmutableExecutedFileOriginalV1::new(),
            maps: BoundedFileReadOriginalV1::new(),
            policy: RetainedLiveSelinuxPolicyReadbackV1::new(),
            policy_binding: None,
            subject: CurrentThreadSubjectOriginalV1::new(),
            status: BoundedFileReadOriginalV1::new(),
            identity: PidFdProcessIdentityOriginalV1::new(),
            info: None,
            membership: ExactCgroupMembershipReadbackV1::new(),
            result: None,
            first: None,
        }
    }

    pub(in crate::receiving) fn demand_v1() -> Option<ResourceVector> {
        let image = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let image = usize::try_from(image.get(D::MemoryBytes)).ok()?;
        let policy = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        let (subject, _, _) = CurrentThreadSubjectOriginalV1::receiving_demand_v1()?;
        let (identity, _) = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let membership = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(image.checked_mul(MAXIMUM_IMAGE_PASSES)?.checked_mul(3)?)?
            .checked_add(BoundedFileReadOriginalV1::requested_bytes_v1(256 * 1024)?)?
            .checked_add(BoundedFileReadOriginalV1::requested_bytes_v1(64 * 1024)?)?
            .checked_add(policy.memory_bytes)?
            .checked_add(subject)?
            .checked_add(identity)?
            .checked_add(membership)?
            .checked_add(std::mem::size_of::<ImmutableExecutedFileOriginalV1>())?
            // Mapping identity/presence arrays have actual profile-member
            // widths. Fixed native path/formatter/error work is separate.
            .checked_add(MAXIMUM_IMAGE_PASSES.checked_mul(
                4 * (std::mem::size_of::<[u64; 3]>() + 1),
            )?)?
            .checked_add(16 * 4096)?;

        // Executed inode/maps/status/stat/subject retain one File each;
        // policy retains four and exact membership retains two probes.
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 1 + 1 + 1 + 1 + 1 + 4 + 2))
    }

    fn prepare(&mut self, count: usize) -> Result<(), NormalRootStartupErrorV1> {
        if self.result.is_some() || self.allocation.is_some() || count > MAXIMUM_IMAGE_PASSES {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.first = Some(Failure::Allocation);
        self.allocation = Some(self.images.try_reserve_exact(count));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.images.extend((0..count).map(|_| ImmutableFileRevalidationOriginalV1::new()));
        Ok(())
    }

    pub(in crate::receiving) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let Some(first) = self.first else {
            return cause(&self.result);
        };
        let actual = match first {
            Failure::Allocation => cause(&self.allocation),
            Failure::Image(index) => self.images.get(index).and_then(|image| image.failure()),
            Failure::Executed => self.executed.failure(),
            Failure::Maps => self.maps.failure(),
            Failure::Policy => self.policy.failure().or_else(|| cause(&self.policy_binding)),
            Failure::Subject => self.subject.failure(),
            Failure::Status => self.status.failure(),
            Failure::Identity => self.identity.failure(),
            Failure::Info => cause(&self.info),
            Failure::Membership => self.membership.failure().map(|cause| cause as &dyn Error),
        };
        actual.or_else(|| cause(&self.result))
    }
}

pub(in crate::receiving) struct RootUnitCurrentnessOriginalV1 {
    read: ImmutableReadOriginalV1,
    profile: ImmutableFileRevalidationOriginalV1,
    result: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootUnitCurrentnessOriginalV1 {
    pub(in crate::receiving) fn new() -> Self {
        Self {
            read: ImmutableReadOriginalV1::new(),
            profile: ImmutableFileRevalidationOriginalV1::new(),
            result: None,
        }
    }

    pub(in crate::receiving) fn demand_v1() -> Option<ResourceVector> {
        let current = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        // Unit normalization's line arrays are bounded by input bytes, with
        // the actual String/borrowed-line widths and separate byte buffers.
        let row = 4 * (std::mem::size_of::<String>() + std::mem::size_of::<&str>());
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(ImmutableReadOriginalV1::requested_bytes_v1(64 * 1024)?)?
            .checked_add((64 * 1024_usize).checked_mul(row.checked_add(8)?)?)?
            .checked_add(usize::try_from(current.get(D::MemoryBytes)).ok()?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    pub(in crate::receiving) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.read.failure()
            .or_else(|| self.profile.failure())
            .or_else(|| cause(&self.result))
    }
}

impl RootStartupNativeOriginalV1 {
    pub(in crate::receiving) fn require_local_current_retaining_v1(
        &self,
        original: &mut RootLocalCurrentnessOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if original.result.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let result = self.require_local_current_recipe(Some(original));
        original.result = Some(result);
        positive(&original.result)
    }

    pub(super) fn require_local_current_recipe(
        &self,
        mut original: Option<&mut RootLocalCurrentnessOriginalV1>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if let Some(original) = original.as_deref_mut() {
            original.prepare(3 + self.runtime.len() + self.evidence.len())?;
        }
        image(&self.profile_file, 0, &mut original)
            .map_err(|_| NormalRootStartupErrorV1::Profile)?;
        image(&self.manager, 1, &mut original)
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        image(&self.executable, 2, &mut original)
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Executed);
                self.executable.require_executed_retaining_v1(
                    std::process::id(), &mut original.executed,
                )
            }
            None => self.executable.require_executed(std::process::id()),
        }.map_err(|_| NormalRootStartupErrorV1::Image)?;
        for (index, file) in self.runtime.iter().chain(&self.evidence).enumerate() {
            image(file, index + 3, &mut original).map_err(|_| NormalRootStartupErrorV1::Image)?;
        }
        let required = [&*self.profile.executable.path, &*self.profile.loader.path];
        match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Maps);
                images::require_actual_mappings_retaining_v1(
                    &self.runtime, &required, &mut original.maps,
                )
            }
            None => images::require_actual_mappings(&self.runtime, &required),
        }?;

        match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Policy);
                original.policy.verify_once(&self.profile.canonical_policy.path)
                    .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
                original.policy_binding = Some(self.policy.require_same_observed_v1(
                    original.policy.verified().ok_or(NormalRootStartupErrorV1::Confinement)?,
                ));
                if !matches!(original.policy_binding, Some(Ok(()))) {
                    return Err(NormalRootStartupErrorV1::Confinement);
                }
            }
            None => self.policy.revalidate(&self.profile.canonical_policy.path)
                .map_err(|_| NormalRootStartupErrorV1::Confinement)?,
        }
        match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Subject);
                original.subject.observe_once(CONTEXT)
            }
            None => require_subject(CONTEXT),
        }.map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        if rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || rustix::process::getgid().as_raw() != self.profile.identities[1]
            || rustix::process::getegid().as_raw() != self.profile.identities[1]
        {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
        match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Status);
                read_root_bounded_confinement_recipe(
                    "/proc/self/status", 64 * 1024, &mut original.status, true,
                )?;
                require_status(&original.status.bytes)?;
            }
            None => require_status(&read_root_bounded_confinement_data_v1(
                "/proc/self/status", 64 * 1024,
            )?)?,
        }

        let identity = match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Identity);
                original.identity.capture_once(&self.process)
                    .map_err(|_| NormalRootStartupErrorV1::Service)?;
                original.identity.identity().ok_or(NormalRootStartupErrorV1::Service)?
            }
            None => self.process.process_identity().map_err(|_| NormalRootStartupErrorV1::Service)?,
        };
        if identity != self.identity {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let info = match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Info);
                original.info = Some(self.process.info());
                original.info.as_ref().and_then(|value| value.as_ref().ok()).copied()
                    .ok_or(NormalRootStartupErrorV1::Service)?
            }
            None => self.process.info().map_err(|_| NormalRootStartupErrorV1::Service)?,
        };
        if info.parent_pid() != 1 {
            return Err(NormalRootStartupErrorV1::Service);
        }
        match original.as_deref_mut() {
            Some(original) => {
                original.first = Some(Failure::Membership);
                original.membership.capture_once(&self.cgroup, &self.process)
                    .map_err(|_| NormalRootStartupErrorV1::Service)?;
                original.first = None;
            }
            None => self.cgroup.verify_exact_membership(&self.process)
                .map(|_| ())
                .map_err(|_| NormalRootStartupErrorV1::Service)?,
        }
        Ok(())
    }

    pub(in crate::receiving) fn require_final_unit_current_retaining_v1(
        &self,
        original: &mut RootUnitCurrentnessOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if original.result.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let result = self.require_final_unit_current_recipe(Some(original));
        original.result = Some(result);
        positive(&original.result)
    }

    pub(super) fn require_final_unit_current_recipe(
        &self,
        original: Option<&mut RootUnitCurrentnessOriginalV1>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        match original {
            Some(original) => {
                images::require_unit_retaining_v1(
                    &self.fragment, &self.profile_file, &self.profile, &mut original.read,
                )?;
                self.profile_file.revalidate_retaining(&mut original.profile)
                    .map_err(|_| NormalRootStartupErrorV1::Profile)
            }
            None => {
                require_unit(&self.fragment, &self.profile_file, &self.profile)?;
                self.profile_file.revalidate().map_err(|_| NormalRootStartupErrorV1::Profile)
            }
        }
    }
}

fn image(
    file: &RetainedImmutableFileV1,
    index: usize,
    original: &mut Option<&mut RootLocalCurrentnessOriginalV1>,
) -> Result<(), crate::immutable_image::ImmutableImageErrorV1> {
    match original.as_deref_mut() {
        Some(original) => {
            original.first = Some(Failure::Image(index));
            let slot = original.images.get_mut(index)
                .ok_or(crate::immutable_image::ImmutableImageErrorV1::Provisioning)?;
            file.revalidate_retaining(slot)
        }
        None => file.revalidate(),
    }
}

fn positive(slot: &Option<Result<(), NormalRootStartupErrorV1>>) -> Result<(), NormalRootStartupErrorV1> {
    match slot {
        Some(result) => *result,
        None => Err(NormalRootStartupErrorV1::Service),
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_status_error_precedes_outer_projection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing-status");
        let mut original = RootLocalCurrentnessOriginalV1::new();
        assert!(original.status.read_once(path.to_str().unwrap(), 64, false, true).is_err());
        original.first = Some(Failure::Status);
        original.result = Some(Err(NormalRootStartupErrorV1::Confinement));

        let actual = original.status.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert!(std::ptr::eq(original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(), actual));
    }

    #[test]
    fn finite_native_demand_has_no_scalar_namespace_fees() {
        let local = RootLocalCurrentnessOriginalV1::demand_v1().unwrap();
        let unit = RootUnitCurrentnessOriginalV1::demand_v1().unwrap();

        assert_eq!(local.get(D::OpenFiles), 11);
        assert_eq!(unit.get(D::OpenFiles), 0);
        assert_eq!(local.get(D::MetadataEntries), 0);
        assert_eq!(unit.get(D::MetadataEntries), 0);
        assert!(local.get(D::MemoryBytes) > 256 * 1024);
        assert!(unit.get(D::MemoryBytes) > 64 * 1024);
    }
}
