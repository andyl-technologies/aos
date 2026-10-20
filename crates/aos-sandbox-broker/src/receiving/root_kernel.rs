//! Actual Root process, PID1 image and same-anchor receiving bookends.
//!
//! The genuine first-table RootR owner prepays this fixed reservoir before any
//! profile or property decoder. These results remain DATA until that original
//! owner joins the observed recipient and producer to its sealed delivery.

use std::error::Error;
use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor, RootInitialCgroupReadbackV1};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo, PidFdProcessIdentity};

use crate::immutable_image::{ImmutableImageErrorV1, PendingImmutableFileV1};

use crate::profile_data::images;
use super::root_observation_error::RootImageObservationErrorV1 as ImageObservationErrorV1;
use super::{RootObservationErrorV1 as NormalRootStartupErrorV1,
    RootProfileOriginalCaptureV1 as RootProfileOriginalReceivingV1};
use super::root_service as service;

const MATERIALIZED_PROPERTY_BYTES: usize = 64 * 1024;

/// Retains Root's actual process, PID1 image and same-anchor bookends.
///
/// The physical observations grant no recipient, financial or semantic authority.
pub struct RootKernelOriginalCaptureV1 {
    process: Option<Result<PidFd, aos_sandbox_linux::Error>>,
    initial_process: Option<Result<PidFdInfo, aos_sandbox_linux::Error>>,
    startup_identity: Option<Result<PidFdProcessIdentity, aos_sandbox_linux::Error>>,
    cgroup_original: RootInitialCgroupReadbackV1,
    cgroup_capture: Option<Result<(), aos_sandbox_linux::Error>>,
    hierarchy: Option<CgroupV2Root>,
    cgroup: Option<Result<RetainedCgroupAnchor, NormalRootStartupErrorV1>>,
    initial_membership: Option<Result<PidFdInfo, aos_sandbox_linux::Error>>,
    containment: ReceivingContainmentReadbackV1,
    initial: Option<Result<(), NormalRootStartupErrorV1>>,
    manager: PendingImmutableFileV1,
    manager_measurement: Option<Result<(), ImageObservationErrorV1>>,
    manager_executed: Option<Result<(), ImmutableImageErrorV1>>,
    archive: Option<service::FirstGlobalPropertyArchive>,
    archive_settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    names_settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    archive_preparation: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(service::ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1>>,
    after: Option<Result<(service::ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1>>,
    property_binding: Option<Result<(), NormalRootStartupErrorV1>>,
    observation: Option<Result<(), NormalRootStartupErrorV1>>,
    profile_post: Option<Result<(), ImmutableImageErrorV1>>,
    manager_post: Option<Result<(), ImmutableImageErrorV1>>,
    manager_executed_post: Option<Result<(), ImmutableImageErrorV1>>,
    final_process: Option<Result<PidFdInfo, aos_sandbox_linux::Error>>,
    final_membership: Option<Result<PidFdInfo, aos_sandbox_linux::Error>>,
    final_binding: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootKernelOriginalCaptureV1 {
    /// Creates inert destinations and its private fixed Root observer interval.
    #[must_use]
    pub(super) fn new() -> Self {
        let lifetime = service::RootObserverLifetimeV1::begin();
        Self {
            process: None,
            initial_process: None,
            startup_identity: None,
            cgroup_original: RootInitialCgroupReadbackV1::new(),
            cgroup_capture: None,
            hierarchy: None,
            cgroup: None,
            initial_membership: None,
            containment: ReceivingContainmentReadbackV1::default(),
            initial: None,
            manager: PendingImmutableFileV1::default(),
            manager_measurement: None,
            manager_executed: None,
            archive: Some(service::FirstGlobalPropertyArchive::with_materialization_limit(
                2,
                lifetime,
                MATERIALIZED_PROPERTY_BYTES,
            )),
            archive_settlement: None,
            names_settlement: None,
            archive_preparation: None,
            before: None,
            after: None,
            property_binding: None,
            observation: None,
            profile_post: None,
            manager_post: None,
            manager_executed_post: None,
            final_process: None,
            final_membership: None,
            final_binding: None,
        }
    }

    /// Prices the same fixed process/image/containment/observer peak.
    ///
    /// Both actual native construction and wrapper destination are covered.
    /// The complete named fixed carrier census is additional to the unchanged
    /// twelve native result controls and the two shared observer suppliers.
    /// Returns `None` on arithmetic overflow; it provides no admission.
    #[must_use]
    pub fn fixed_demand() -> Option<ResourceVector> {
        let observer = service::fixed_property_observer_demand_v1(MATERIALIZED_PROPERTY_BYTES)?;
        let owner = std::mem::size_of::<Self>().checked_mul(2)?;
        let transfer = std::mem::size_of::<RootKernelStartupPartsV1>().checked_mul(2)?;
        let fields = std::mem::size_of::<RootKernelStartupFieldsV1>().checked_mul(2)?;
        let interval = std::mem::size_of::<(usize, usize, std::sync::atomic::AtomicBool)>();
        let memory = owner.checked_add(transfer)?.checked_add(fields)?.checked_add(interval)?
            .checked_add(2 * 1024 * 1024)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 12)
            .with(D::MetadataEntries, 12 + Self::fixed_control_cells_v1())
            .with(D::Pids, 2);
        fixed.checked_add(ReceivingContainmentReadbackV1::fixed_demand()).ok()?
            .checked_add(observer).ok()?.checked_add(observer).ok()
    }

    /// Counts the complete parent, archive, interval and transfer carriers.
    #[must_use]
    pub const fn fixed_control_cells_v1() -> u64 {
        // 27 parent fields; two archive fields; interval Arc destination and
        // heap control; wrapper/construction; six moved startup fields; and
        // take/restore tuples, five moved field destinations and their
        // conversion carrier. Shared observer/containment internals
        // remain separately paid by their actual demand helpers.
        27 + 2 + 2 + 2 + 6 + 2 + 5 + 1
    }

    /// Captures the actual current Root process and fixed cgroup originals.
    ///
    /// # Errors
    /// Retains reached causes and refuses absent, failed or repeated originals.
    pub(super) fn capture_fixed_once(
        &mut self,
        expected: ResourceVector,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.initial.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.initial = Some((|| {
            let pid = NonZeroU32::new(std::process::id())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.process = Some(PidFd::open(pid));
            let process = positive(&self.process)?;
            self.initial_process = Some(process.info());
            let info = positive(&self.initial_process)?;
            if info.pid() != std::process::id() || info.thread_group_id() != std::process::id()
                || info.parent_pid() != 1
            {
                return Err(NormalRootStartupErrorV1::Service);
            }
            self.cgroup_capture = Some(self.cgroup_original.capture_once());
            positive(&self.cgroup_capture)?;
            let (hierarchy, cgroup) = self.cgroup_original.take_validated_pair()
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.hierarchy = Some(hierarchy);
            self.cgroup = Some(Ok(cgroup));
            let cgroup = positive(&self.cgroup)?;
            self.initial_membership = Some(cgroup.verify_exact_membership(process));
            self.containment.capture(cgroup, expected);
            positive(&self.initial_membership)?;
            self.containment.require_initial().map_err(|_| NormalRootStartupErrorV1::Service)?;
            Ok(())
        })());
        positive(&self.initial).map(|_| ())
    }

    /// Measures the actual PID1 image and both fixed Root property bookends.
    ///
    /// # Errors
    /// Retains reached causes and refuses absent, failed or repeated originals.
    pub(super) fn observe_original_once(
        &mut self,
        original_pid1: &mut Option<OwnedFd>,
        profile: &RootProfileOriginalReceivingV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.observation.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.observation = Some(self.observe_original_inner(original_pid1, profile));
        positive(&self.observation).map(|_| ())
    }

    fn observe_original_inner(
        &mut self,
        original_pid1: &mut Option<OwnedFd>,
        profile: &RootProfileOriginalReceivingV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if !matches!(self.initial, Some(Ok(()))) || self.manager_measurement.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let decoded = profile.profile().ok_or(NormalRootStartupErrorV1::Profile)?;
        let original = original_pid1.take().ok_or(NormalRootStartupErrorV1::Activation)?;
        self.manager.park_original(File::from(original));
        self.manager_measurement = Some(
            images::park_original_pin(&decoded.pid1, true, &mut self.manager).map_err(Into::into),
        );
        positive(&self.manager_measurement)?;
        self.manager_executed = Some(self.manager.measurement()
            .and_then(|manager| manager.require_executed(1)));
        positive(&self.manager_executed)?;
        let file = profile.measurement().map_err(|_| NormalRootStartupErrorV1::Profile)?;
        let path = file.path().to_str().ok_or(NormalRootStartupErrorV1::Profile)?;
        let archive = self.archive.as_mut()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        self.archive_preparation = Some(archive.prepare());
        positive(&self.archive_preparation)?;

        // The second observation is independent even after the first Err.
        self.before = Some(service::observe_root_resource_with_archive(archive, path));
        self.after = Some(service::observe_root_resource_with_archive(archive, path));
        self.property_binding = Some((|| {
            if positive(&self.before)? != positive(&self.after)? {
                return Err(NormalRootStartupErrorV1::Service);
            }
            Ok(())
        })());
        positive(&self.property_binding).map(|_| ())
    }

    // Every reached native/image bookend is parked before the outer owner
    // chooses the first cause. No failed decoder is retried by this method.
    /// Completes all reached independent native/image posts exactly once.
    pub(super) fn finish_once(&mut self, profile: &RootProfileOriginalReceivingV1) {
        if self.final_binding.is_some() {
            return;
        }
        if let Ok(file) = profile.measurement() {
            self.profile_post = Some(file.revalidate());
        }
        if let Ok(manager) = self.manager.measurement() {
            self.manager_post = Some(manager.revalidate());
            self.manager_executed_post = Some(manager.require_executed(1));
        }
        if let Some(Ok(process)) = &self.process {
            self.final_process = Some(process.info());
            if let Some(Ok(cgroup)) = &self.cgroup {
                self.final_membership = Some(cgroup.verify_exact_membership(process));
            }
        }
        if let Some(Ok(cgroup)) = &self.cgroup {
            self.containment.recheck(cgroup);
        }
        self.final_binding = Some((|| {
            positive(&self.initial)?;
            if positive(&self.initial_process)? != positive(&self.final_process)? {
                return Err(NormalRootStartupErrorV1::Service);
            }
            positive(&self.final_membership)?;
            self.containment.require_current().map_err(|_| NormalRootStartupErrorV1::Service)?;
            Ok(())
        })());
    }

    /// Borrows the positive same-attempt recipient/producer DATA.
    pub fn observed_pair(&self) -> Option<([u8; 16], [u8; 16])> {
        if self.failure().is_some()
            || !matches!(self.final_binding, Some(Ok(())))
            || !matches!(self.profile_post, Some(Ok(())))
            || !matches!(self.manager_post, Some(Ok(())))
            || !matches!(self.manager_executed_post, Some(Ok(())))
            || !matches!(self.property_binding, Some(Ok(())))
        {
            return None;
        }
        let (observed, producer) = self.before.as_ref()?.as_ref().ok()?;
        Some((observed.invocation, *producer))
    }

    // Only the actual Root recipient join calls this after both independent
    // original kernel/image/PID1 posts succeeded. End the same actual transports
    // before Drop; a failed or ambiguous attempt remains completely resident.
    /// Disposes only the positively completed actual transport/name scratch.
    ///
    /// # Errors
    /// Retains reached causes and refuses absent, failed or repeated originals.
    pub(super) fn settle_selected_positive_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.archive_settlement.is_some()
            || self.names_settlement.is_some()
            || self.observed_pair().is_none()
            || self.failure().is_some()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.archive_settlement = Some(match self.archive.as_mut() {
            Some(archive) => archive.settle_positive_once(),
            None => Err(NormalRootStartupErrorV1::Service),
        });
        positive(&self.archive_settlement)?;
        drop(self.archive.take());

        // The common reader keeps its eight original control OFDs and all
        // Results; only positive before/final named handles are disposed.
        self.containment.settle_positive_named_verifications_once_v1();
        self.names_settlement = Some(if self.containment.named_verifications_settled_v1() {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Service)
        });
        positive(&self.names_settlement).map(|_| ())
    }

    /// Reports actual named-handle disposal after positive settlement.
    pub fn settled_named_descriptor_peak_v1(&self) -> Option<u64> {
        if self.archive.is_some()
            || !matches!(self.archive_settlement, Some(Ok(())))
            || !matches!(self.names_settlement, Some(Ok(())))
            || !self.containment.named_verifications_settled_v1()
            || self.failure().is_some()
        {
            return None;
        }
        // Two completed named bookends over the same fixed eight controls.
        // No observer/runtime FD credit is claimed: global signal ownership
        // remains fully covered by the original paid archive rows.
        super::receiving_limits::ReceivingContainmentCurrentnessV1::fixed_demand()
            .get(D::OpenFiles)
            .checked_mul(2)
    }

    /// Observes the same held original controls into its currentness destination.
    pub(super) fn observe_service_limits(
        &self,
        anchor: &RetainedCgroupAnchor,
        sample: &mut super::receiving_limits::ReceivingContainmentCurrentnessV1,
    ) {
        self.containment.observe_current_into(anchor, sample);
    }

    /// Borrows the completed same-attempt unit observation DATA.
    pub fn service_observation(&self) -> Option<&service::ServiceObservationV1> {
        self.observed_pair()?;
        self.before.as_ref()?.as_ref().ok().map(|pair| &pair.0)
    }

    /// Captures this same original process identity before the startup handoff.
    ///
    /// # Errors
    /// Retains reached causes and refuses absent, failed or repeated originals.
    pub(super) fn prepare_startup_identity_once(
        &mut self,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.startup_identity.is_some() || self.observed_pair().is_none() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let process = positive(&self.process)?;
        self.startup_identity = Some(process.process_identity());
        positive(&self.startup_identity).map(|_| ())
    }

    /// Moves the complete actual native startup originals together.
    pub(super) fn take_startup_originals(&mut self) -> Option<RootKernelStartupPartsV1> {
        self.observed_pair()?;
        positive(&self.startup_identity).ok()?;
        match (self.manager.take_measurement(), self.process.take(), self.cgroup.take(),
               self.startup_identity.take(), self.before.take())
        {
            (Some(manager), Some(Ok(process)), Some(Ok(cgroup)), Some(Ok(identity)),
             Some(Ok((observed, producer)))) =>
            {
                Some(RootKernelStartupPartsV1 {
                    manager, process, cgroup, identity, observed, producer,
                })
            }
            (manager, process, cgroup, identity, observed) => {
                self.manager.restore_measurement(manager);
                self.process = process;
                self.cgroup = cgroup;
                self.startup_identity = identity;
                self.before = observed;
                None
            }
        }
    }

    /// Restores the same atomic native transfer destinations.
    pub(super) fn restore_startup_originals(&mut self, originals: Option<RootKernelStartupPartsV1>) {
        if let Some(originals) = originals {
            self.manager.restore_measurement(Some(originals.manager));
            self.process = Some(Ok(originals.process));
            self.cgroup = Some(Ok(originals.cgroup));
            self.startup_identity = Some(Ok(originals.identity));
            self.before = Some(Ok((originals.observed, originals.producer)));
        }
    }

    /// Borrows the first reached actual native/image or fixed refusal.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)) };
        }
        cause!(self.process)
            .or_else(|| cause!(self.initial_process))
            .or_else(|| self.cgroup_original.failure())
            .or_else(|| cause!(self.cgroup_capture))
            .or_else(|| cause!(self.cgroup))
            .or_else(|| cause!(self.initial_membership))
            .or_else(|| {
                if matches!(self.initial, Some(Err(_))) {
                    self.containment.failure().or_else(|| cause!(self.initial))
                } else {
                    None
                }
            })
            .or_else(|| cause!(self.manager_measurement))
            .or_else(|| cause!(self.manager_executed))
            .or_else(|| cause!(self.archive_preparation))
            .or_else(|| cause!(self.before))
            .or_else(|| cause!(self.after))
            .or_else(|| cause!(self.property_binding))
            .or_else(|| cause!(self.observation))
            .or_else(|| cause!(self.profile_post))
            .or_else(|| cause!(self.manager_post))
            .or_else(|| cause!(self.manager_executed_post))
            .or_else(|| cause!(self.final_process))
            .or_else(|| cause!(self.final_membership))
            .or_else(|| self.containment.failure())
            .or_else(|| cause!(self.final_binding))
            .or_else(|| cause!(self.archive_settlement))
            .or_else(|| cause!(self.names_settlement))
            .or_else(|| cause!(self.startup_identity))
    }
}

/// Keeps an actual atomic native handoff sealed until all other fields exist.
///
/// The private fields prevent DATA construction or mutation before a failed
/// outer atomic transfer restores this same payload to its original capture.
pub struct RootKernelStartupPartsV1 {
    manager: crate::immutable_image::RetainedImmutableFileV1,
    process: PidFd,
    identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
    observed: service::ServiceObservationV1,
    producer: [u8; 16],
}

impl RootKernelStartupPartsV1 {
    /// Moves the native fields after the outer atomic tuple fully succeeds.
    ///
    /// This infallible ownership move performs no IO, cloning or admission.
    #[must_use]
    pub(super) fn into_startup_fields_v1(self) -> RootKernelStartupFieldsV1 {
        RootKernelStartupFieldsV1 {
            manager: self.manager,
            process: self.process,
            identity: self.identity,
            cgroup: self.cgroup,
            observed: self.observed,
        }
    }
}

/// Carries moved physical handles and readonly unit DATA without role authority.
pub struct RootKernelStartupFieldsV1 {
    /// Actual measured manager image.
    pub manager: crate::immutable_image::RetainedImmutableFileV1,
    /// Same actual Root process descriptor.
    pub process: PidFd,
    /// Identity captured from that same process before handoff.
    pub identity: PidFdProcessIdentity,
    /// Same actual Root cgroup anchor.
    pub cgroup: RetainedCgroupAnchor,
    /// Completed fixed-unit property DATA.
    pub observed: service::ServiceObservationV1,
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<&T, NormalRootStartupErrorV1> {
    result.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(NormalRootStartupErrorV1::Service)
}

use super::receiving_limits::ReceivingContainmentReadbackV1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_kernel_has_no_positive_pair_or_native_transfer() {
        let mut capture = RootKernelOriginalCaptureV1::new();
        assert!(capture.observed_pair().is_none());
        assert!(capture.take_startup_originals().is_none());
        assert!(capture.settled_named_descriptor_peak_v1().is_none());
        assert!(capture.failure().is_none());
    }
}
