//! Same-RootR selected-image preparation before the positive startup handoff.
//!
//! The original Root owner supplies payment and custody. This reservoir keeps
//! the actual executable, runtime closure, policy, fragment and partial results;
//! it does not reconstruct an original profile or PID1 recipient from DATA.

use std::collections::TryReserveError;
use std::fs::File;
use std::path::Path;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::selinux_policy::{PolicyReadbackError, VerifiedLiveSelinuxPolicy};

use crate::immutable_image::{ImmutableImageErrorV1, PendingImmutableFileV1, RetainedImmutableFileV1};

use crate::profile_data::images;
use crate::profile_data::schema::ImagePinV1;
use super::root_observation_error::RootImageObservationErrorV1 as ImageObservationErrorV1;
use super::root_startup_native::{RootStartupNativeOriginalV1, RootStartupNativeFieldsV1};
use super::{RootObservationErrorV1 as NormalRootStartupErrorV1,
    RootInitialReceivingOriginalV1,
    RootProfileOriginalCaptureV1 as RootProfileOriginalReceivingV1};

#[derive(Debug, thiserror::Error)]
enum SelectedStartupFailureV1 {
    #[error("Root selected startup prerequisite differs")]
    Startup(#[from] NormalRootStartupErrorV1),
    #[error("Root selected image observation failed")]
    Image(#[from] ImageObservationErrorV1),
    #[error("Root selected immutable measurement failed")]
    Immutable(#[from] ImmutableImageErrorV1),
    #[error("Root selected executable open failed")]
    Io(#[from] std::io::Error),
    #[error("Root selected policy observation failed")]
    Policy(#[from] PolicyReadbackError),
    #[error("Root selected closure allocation failed")]
    Allocation(#[from] TryReserveError),
    #[error("Root selected closure reserve exceeds its admitted count")]
    Capacity,
    #[error("Root selected startup partial tuple is incomplete")]
    Incomplete,
}

/// Retains actual selected-image preparation from one enrolled Root owner.
///
/// Its complete constructor result owns the actual native fields and private
/// owner link. Neither arbitrary profile DATA nor field adoption creates it.
#[derive(Default)]
pub struct RootSelectedStartupOriginalV1 {
    executable: PendingImmutableFileV1,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    pending_pin: PendingImmutableFileV1,
    policy: Option<VerifiedLiveSelinuxPolicy>,
    fragment: PendingImmutableFileV1,
    receiving_prefix: Option<Result<ResourceVector, NormalRootStartupErrorV1>>,
    initial_owner: Option<std::sync::Arc<()>>,
    preparation: Option<Result<(), SelectedStartupFailureV1>>,
    assembly: Option<Result<(), SelectedStartupFailureV1>>,
    initial_restore: Option<Result<(), super::RootInitialRestoreFailureV1>>,
    initial_fields: Option<Result<(super::RootInitialStartupFieldsV1, std::sync::Arc<()>),
        super::RootInitialStartupPartsV1>>,
    completed: Option<RootStartupNativeOriginalV1>,
}

impl RootSelectedStartupOriginalV1 {
    /// Prices the actual retained profile's selected image and native owners.
    ///
    /// This comparison DATA grants no allowance. Both private native entry and
    /// the real upper Root adapter independently check their complete demand.
    ///
    /// # Errors
    /// Refuses absent actual profile custody or checked representation overflow.
    pub fn demand(
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<ResourceVector, NormalRootStartupErrorV1> {
        let error = || NormalRootStartupErrorV1::Profile;
        let profile = initial.profile_capture_v1()
            .and_then(|capture| capture.profile()).ok_or_else(error)?;
        let paths = profile.runtime_files.iter().chain([
            &profile.executable,
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ]);
        let mut path_bytes = 0usize;
        for pin in paths {
            path_bytes = path_bytes.checked_add(pin.path.len()).ok_or_else(error)?;
        }
        let files = profile.runtime_files.len().checked_add(5).ok_or_else(error)?;
        let cells = files.checked_mul(std::mem::size_of::<RetainedImmutableFileV1>())
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(error)?;
        let memory = path_bytes.checked_mul(4)
            .and_then(|bytes| bytes.checked_add(cells))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootStartupNativeOriginalV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootStartupNativeFieldsV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>().checked_mul(5)?))
            // Fixed bounded maps/status/unit representations and independent
            // selected-policy hashing chunks; no whole image file is buffered.
            .and_then(|bytes| bytes.checked_add(8 * 1024 * 1024))
            .ok_or_else(error)?;
        let memory = u64::try_from(memory).map_err(|_| error())?;
        let files = u64::try_from(files).map_err(|_| error())?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, files)
            // Thirteen actual parent fields in destination/construction; sealed
            // startup two fields and native fields twelve in both carriers;
            // two Arc link carriers, two conversion returns and five vectors.
            .with(D::MetadataEntries, files + 13 * 2 + 2 * 2 + 12 * 2 + 2 + 2 + 5)
            .with(D::PublicationStagingBytes, memory)
            .with(D::OutputBytes, memory))
    }

    // The outer original first admits the cumulative demand. Its actual
    // profile/PID1 reservoirs remain borrowed through this entire preparation.
    /// Receives selected originals only from this same enrolled Root receiver.
    ///
    /// # Errors
    /// Checks the actual private native demand before growth, preserves the
    /// actual first preparation cause and refuses repeated or unfunded entry.
    pub fn prepare_once(
        &mut self,
        identities: [u32; 4],
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.preparation.is_some() || self.receiving_prefix.is_some() {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.receiving_prefix = Some(initial.admit_selected_native_once_v1());
        if !matches!(self.receiving_prefix, Some(Ok(_))) {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.initial_owner = Some(initial.owner_link());
        self.preparation = Some((|| {
            let profile = initial.profile_capture_v1().ok_or(SelectedStartupFailureV1::Incomplete)?;
            let kernel = initial.kernel_capture_v1().ok_or(SelectedStartupFailureV1::Incomplete)?;
            self.prepare_inner(identities, profile, kernel)
        })());
        if matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Profile)
        }
    }

    fn prepare_inner(
        &mut self,
        identities: [u32; 4],
        original_profile: &RootProfileOriginalReceivingV1,
        original_kernel: &super::RootKernelOriginalCaptureV1,
    ) -> Result<(), SelectedStartupFailureV1> {
        let profile = original_profile.profile().ok_or(SelectedStartupFailureV1::Incomplete)?;
        let profile_file = original_profile.measurement()?;
        if profile.identities != identities
            || profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(NormalRootStartupErrorV1::Profile.into());
        }

        self.executable.park_original(File::open("/proc/self/exe")?);
        images::park_original_pin(&profile.executable, true, &mut self.executable)?;
        reserve_members(&mut self.runtime, profile.runtime_files.len())?;
        for pin in &profile.runtime_files {
            let executable = pin.path == profile.executable.path || pin.path == profile.loader.path;
            park_member(pin, executable, &mut self.pending_pin, &mut self.runtime)?;
        }

        self.policy = Some(VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path)?);
        if self.policy.as_ref().map(|policy| policy.digest())
            != Some(profile.canonical_policy.sha256)
        {
            return Err(NormalRootStartupErrorV1::Confinement.into());
        }

        reserve_members(&mut self.evidence, 3)?;
        for pin in [&profile.canonical_policy, &profile.source_policy, &profile.effective_matrix] {
            park_member(pin, false, &mut self.pending_pin, &mut self.evidence)?;
        }

        let observed = original_kernel.service_observation()
            .ok_or(SelectedStartupFailureV1::Incomplete)?;
        self.fragment.open_and_measure(observed.fragment.clone(), None, 64 * 1024, false)?;
        images::require_unit(self.fragment.measurement()?, profile_file, profile)
            .map_err(NormalRootStartupErrorV1::from)?;
        Ok(())
    }

    /// Borrows the first reached cause without retrying or disposing originals.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receiving_prefix.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.preparation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.initial_restore.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.assembly.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    /// Moves only this same receiver's complete native selected payload.
    ///
    /// # Errors
    /// Refuses reentry, foreign owner links or incomplete preparation. Reached
    /// partial originals are restored or retained whole before projecting debt.
    pub fn assemble_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.assembly.is_some() || !matches!(self.preparation, Some(Ok(())))
            || !self.initial_owner.as_ref().is_some_and(|owner| initial.same_owner_link(owner))
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.assembly = Some((|| {
            let originals = (
                initial.take_startup_originals_v1(),
                self.executable.take_measurement(),
                self.fragment.take_measurement(),
                self.policy.take(),
            );
            let (initial, executable, fragment, policy) = match originals {
                (Some(initial), Some(executable), Some(fragment), Some(policy))
                    if initial.is_complete_v1() =>
                {
                    (initial, executable, fragment, policy)
                }
                (initial_originals, executable, fragment, policy) => {
                    self.initial_restore = Some(initial.restore_startup_originals_v1(initial_originals));
                    self.executable.restore_measurement(executable);
                    self.fragment.restore_measurement(fragment);
                    self.policy = policy;
                    return Err(SelectedStartupFailureV1::Incomplete);
                }
            };
            self.initial_fields = Some(initial.into_linked_startup_fields_v1());
            let initial = match self.initial_fields.take() {
                Some(Ok(initial)) => initial,
                other => {
                    self.initial_fields = other;
                    self.executable.restore_measurement(Some(executable));
                    self.fragment.restore_measurement(Some(fragment));
                    self.policy = Some(policy);
                    return Err(SelectedStartupFailureV1::Incomplete);
                }
            };
            let (initial, initial_owner) = initial;
            let kernel = initial.kernel;
            self.completed = Some(RootStartupNativeOriginalV1 {
                fields: RootStartupNativeFieldsV1 {
                    profile_file: initial.profile_file,
                    profile: initial.profile,
                    manager: kernel.manager,
                    executable,
                    runtime: std::mem::take(&mut self.runtime),
                    evidence: std::mem::take(&mut self.evidence),
                    fragment,
                    policy,
                    process: kernel.process,
                    identity: kernel.identity,
                    cgroup: kernel.cgroup,
                    observed: kernel.observed,
                },
                initial_owner: Some(initial_owner),
                selected_permanent: std::sync::OnceLock::new(),
            });
            Ok(())
        })());
        if matches!(self.assembly, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Profile)
        }
    }

    /// Borrows only the complete actual native result of this same receiver.
    #[must_use]
    pub fn completed(&self) -> Option<&RootStartupNativeOriginalV1> {
        if !matches!(self.assembly, Some(Ok(()))) || self.failure().is_some() {
            return None;
        }
        self.completed.as_ref()
    }

    /// Moves the complete actual native result once without I/O or cloning.
    #[must_use]
    pub fn take_completed(&mut self) -> Option<RootStartupNativeOriginalV1> {
        self.completed()?;
        self.completed.take()
    }
}

impl From<images::ImageObservationErrorV1> for SelectedStartupFailureV1 {
    fn from(error: images::ImageObservationErrorV1) -> Self {
        Self::Image(error.into())
    }
}

fn reserve_members(
    members: &mut Vec<RetainedImmutableFileV1>,
    count: usize,
) -> Result<(), SelectedStartupFailureV1> {
    members.try_reserve_exact(count)?;
    if members.capacity() > count {
        return Err(SelectedStartupFailureV1::Capacity);
    }
    Ok(())
}

fn park_member(
    pin: &ImagePinV1,
    executable: bool,
    pending: &mut PendingImmutableFileV1,
    destination: &mut Vec<RetainedImmutableFileV1>,
) -> Result<(), SelectedStartupFailureV1> {
    images::park_selected_pin(pin, executable, pending)?;
    let file = pending.take_measurement().ok_or(SelectedStartupFailureV1::Incomplete)?;
    destination.push(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::resource_bank::NativeLayoutDemand;
    use std::mem::ManuallyDrop;

    #[test]
    fn unfunded_actual_receiver_refuses_before_any_selected_pin_and_keeps_cause() {
        let mut initial = ManuallyDrop::new(RootInitialReceivingOriginalV1::new(
            NativeLayoutDemand::new(1, 2),
        ));
        let mut selected = RootSelectedStartupOriginalV1::default();

        assert!(selected.prepare_once([0; 4], &mut initial).is_err());
        let first = selected.failure().unwrap().downcast_ref::<NormalRootStartupErrorV1>()
            .unwrap() as *const NormalRootStartupErrorV1;
        assert!(selected.prepare_once([0; 4], &mut initial).is_err());

        assert_eq!(first, selected.failure().unwrap().downcast_ref::<NormalRootStartupErrorV1>()
            .unwrap() as *const NormalRootStartupErrorV1);
        assert!(selected.executable.original().is_err());
        assert!(selected.runtime.is_empty());
        assert!(selected.evidence.is_empty());
        assert!(selected.initial_owner.is_none());
        assert!(selected.completed().is_none());
        assert!(selected.take_completed().is_none());

        // A second wrapper cannot reset the actual original's failed once gate.
        let native_first = initial.selected_admission_failure_v1().unwrap()
            .downcast_ref::<super::super::RootNativeAdmissionErrorV1>().unwrap()
            as *const super::super::RootNativeAdmissionErrorV1;
        let mut second = RootSelectedStartupOriginalV1::default();
        assert!(second.prepare_once([0; 4], &mut initial).is_err());
        assert_eq!(native_first, initial.selected_admission_failure_v1().unwrap()
            .downcast_ref::<super::super::RootNativeAdmissionErrorV1>().unwrap()
            as *const super::super::RootNativeAdmissionErrorV1);
        assert!(second.executable.original().is_err());
        assert!(second.runtime.is_empty());
        assert!(second.take_completed().is_none());
    }

    #[test]
    fn private_physical_owner_link_rejects_a_second_inert_receiver() {
        let first = ManuallyDrop::new(RootInitialReceivingOriginalV1::new(
            NativeLayoutDemand::new(1, 2),
        ));
        let mut second = ManuallyDrop::new(RootInitialReceivingOriginalV1::new(
            NativeLayoutDemand::new(1, 2),
        ));
        let selected_owner = first.owner_link();

        assert!(first.same_owner_link(&selected_owner));
        assert!(!second.same_owner_link(&selected_owner));
        assert!(second.take_startup_originals_v1().is_none());
        assert!(second.profile_capture_v1().is_none());
        assert!(second.kernel_capture_v1().is_none());
    }
}
