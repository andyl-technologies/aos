//! Retains the same service's image, PID1, identity and membership comparison.
//!
//! The physical owner parks this sink before IO and disposes a positive sample
//! only after its whole native interval succeeds. Failed samples stay resident
//! beside the separately prepaid independently owed observation.

use std::error::Error;

use aos_sandbox_broker::immutable_image::{ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1, RetainedCgroupAnchor, StorageCgroupLayoutV1};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo, PidFdProcessIdentity, PidFdProcessIdentityOriginalV1};
use aos_systemd::FixedPid1PropertyFailureViewV1;
use crate::production_startup::Pid1LaunchImageV1;

use super::{FloorErrorV1, FloorServicePolicyReadbackV1, MeasuredFileV1,
    PolicyObservationV1, RetainedFloorServicePolicyV1};

pub(crate) struct FloorServiceCurrentnessOriginalV1 {
    pub(super) manager: [ImmutableFileRevalidationOriginalV1; 2],
    pub(super) manager_results: [Option<Result<(), ImmutableImageErrorV1>>; 2],
    pub(super) fragment: [ImmutableFileRevalidationOriginalV1; 2],
    pub(super) fragment_results: [Option<Result<(), ImmutableImageErrorV1>>; 2],
    pub(super) policy: FloorServicePolicyReadbackV1,
    pub(super) deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    pub(super) policy_result: Option<Result<(), FloorErrorV1>>,
    pub(super) observed: Option<PolicyObservationV1>,
    identity: PidFdProcessIdentityOriginalV1,
    identity_result: Option<aos_sandbox_linux::Result<()>>,
    info: Option<aos_sandbox_linux::Result<PidFdInfo>>,
    pub(super) binding: Option<Result<(), FloorErrorV1>>,
    pub(super) membership: ExactCgroupMembershipReadbackV1,
    pub(super) membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    pub(super) child_membership: [ExactCgroupMembershipReadbackV1; 2],
    pub(super) child_results: [Option<Result<(), ExactCgroupMembershipRefusalV1>>; 2],
    returned: Option<Result<(), FloorErrorV1>>,
    reentry: Option<FloorErrorV1>,
    entered: bool,
}

impl FloorServiceCurrentnessOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            manager: std::array::from_fn(|_| ImmutableFileRevalidationOriginalV1::new()),
            manager_results: [None, None],
            fragment: std::array::from_fn(|_| ImmutableFileRevalidationOriginalV1::new()),
            fragment_results: [None, None],
            policy: FloorServicePolicyReadbackV1::new(StorageCgroupLayoutV1::Ordinary),
            deadline: None, policy_result: None, observed: None,
            identity: PidFdProcessIdentityOriginalV1::new(), identity_result: None,
            info: None, binding: None,
            membership: ExactCgroupMembershipReadbackV1::new(), membership_result: None,
            child_membership: std::array::from_fn(|_| ExactCgroupMembershipReadbackV1::new()),
            child_results: [None, None],
            returned: None, reentry: None, entered: false,
        }
    }

    pub(crate) fn with_storage_layout_v2(layout: StorageCgroupLayoutV1) -> Self {
        let mut original = Self::new();
        original.policy = FloorServicePolicyReadbackV1::new(layout);
        original
    }

    pub(crate) fn with_shared_provider_v1(provider: std::sync::Arc<aos_systemd::SharedFixedPid1PropertyProviderV1>) -> Self {
        let mut original = Self::new();
        original.policy = FloorServicePolicyReadbackV1::with_shared_provider_v1(
            StorageCgroupLayoutV1::Ordinary, provider,
        );
        original
    }

    pub(crate) fn receiving_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_demand_v1(image)?;
        let old = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let shared = FloorServicePolicyReadbackV1::receiving_shared_demand_v1(image)?;
        let files = full.get(D::OpenFiles).checked_sub(old.get(D::OpenFiles))?
            .checked_add(shared.get(D::OpenFiles))?;
        Some(full.with(D::OpenFiles, files))
    }

    pub(crate) fn receiving_initial_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_initial_demand_v1(image)?;
        let old = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let shared = FloorServicePolicyReadbackV1::receiving_shared_demand_v1(image)?;
        let files = full.get(D::OpenFiles).checked_sub(old.get(D::OpenFiles))?
            .checked_add(shared.get(D::OpenFiles))?;
        Some(full.with(D::OpenFiles, files))
    }

    pub(crate) fn receiving_primary_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_shared_demand_v1(image)?;
        let policy = FloorServicePolicyReadbackV1::receiving_shared_demand_v1(image)?;
        let later = full.get(D::OpenFiles).checked_sub(policy.get(D::OpenFiles))?;
        Some(full.with(D::OpenFiles, later.max(policy.get(D::OpenFiles))))
    }

    pub(crate) fn observe_once(
        &mut self,
        service: &mut RetainedFloorServicePolicyV1,
        child: &PidFd,
    ) -> Result<(), FloorErrorV1> {
        self.observe_with_deadline(service, child, None)
    }

    pub(crate) fn observe_with_deadline(
        &mut self,
        service: &mut RetainedFloorServicePolicyV1,
        child: &PidFd,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        self.observe_recipe(service, Some(child), deadline)
    }

    pub(super) fn observe_initial_once(
        &mut self,
        service: &mut RetainedFloorServicePolicyV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        self.observe_recipe(service, None, deadline)
    }

    fn observe_recipe(
        &mut self,
        service: &mut RetainedFloorServicePolicyV1,
        child: Option<&PidFd>,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.deadline = deadline;
        self.returned = Some((|| {
            service.revalidate_observed(&mut Some(&mut *self))?;
            if let Some(child) = child {
                service.require_child_observed(child, &mut Some(&mut *self))?;
            }
            Ok(())
        })());
        match self.returned {
            Some(result) => result,
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(crate) fn observe_controller_owed_v1(
        &mut self, service: &mut RetainedFloorServicePolicyV1, child: Option<&PidFd>,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.deadline = deadline;
        let anchors = service.anchors()?;
        // Same retained primitives, independently owed despite a preceding
        // native refusal. No value from this path can construct a service.
        let _ = image(anchors.manager, Some((&mut self.manager[0], &mut self.manager_results[0])));
        let _ = image(anchors.fragment, Some((&mut self.fragment[0], &mut self.fragment_results[0])));
        self.policy_result = Some(self.policy.observe_controller_owed_with_deadline_v1(
            &service.launch_image, deadline,
        ));
        self.observed = self.policy.take_completed_once();
        let identity = identity(anchors.parent, Some(&mut *self));
        let info = info(anchors.parent, Some(&mut *self));
        self.binding = Some(match (self.observed.as_ref(), identity, info) {
            (Some(observed), Ok(identity), Ok(info)) if observed.fragment == anchors.fragment.path()
                && observed.invocation == service.invocation && identity == service.parent_identity
                && info.parent_pid() == 1 => Ok(()),
            _ => Err(FloorErrorV1::Provisioning),
        });
        let _ = membership(anchors.cgroup, anchors.parent,
            Some((&mut self.membership, &mut self.membership_result)));
        let _ = image(anchors.fragment, Some((&mut self.fragment[1], &mut self.fragment_results[1])));
        let _ = image(anchors.manager, Some((&mut self.manager[1], &mut self.manager_results[1])));
        let _ = membership(anchors.cgroup, anchors.parent,
            Some((&mut self.child_membership[0], &mut self.child_results[0])));
        if let Some(child) = child {
            let _ = membership(anchors.cgroup, child,
                Some((&mut self.child_membership[1], &mut self.child_results[1])));
        }
        self.returned = Some(if self.failure().is_some() { Err(FloorErrorV1::Unavailable) } else { Ok(()) });
        match self.returned { Some(result) => result, None => Err(FloorErrorV1::Unavailable) }
    }

    pub(super) fn observe_acquisition_prefix_owed_v1(
        &mut self,
        mut manager: Option<&mut MeasuredFileV1>,
        manager_open: &aos_sandbox_broker::immutable_image::BackendPid1ImageAcquisitionOriginalV1,
        mut fragment: Option<&mut MeasuredFileV1>,
        fragment_open: &aos_sandbox_broker::immutable_image::ImmutableFileAcquisitionOriginalV1,
        parent: Option<&PidFd>,
        cgroup: Option<&RetainedCgroupAnchor>,
        launch: &crate::production_startup::Pid1LaunchImageV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.deadline = deadline;

        match manager.as_deref_mut() {
            Some(file) => { let _ = image(file, Some((&mut self.manager[0], &mut self.manager_results[0]))); }
            None => self.manager_results[0] = manager_open.observe_available_held_once_v1(&mut self.manager[0]),
        }
        match fragment.as_deref_mut() {
            Some(file) => { let _ = image(file, Some((&mut self.fragment[0], &mut self.fragment_results[0]))); }
            None => self.fragment_results[0] = fragment_open.observe_available_held_once_v1(&mut self.fragment[0]),
        }
        self.policy_result = Some(self.policy.observe_controller_owed_with_deadline_v1(launch, deadline));
        self.observed = self.policy.take_completed_once();

        // The reached pidfd and cgroup remain the actual acquisition's
        // originals. Each primitive is independently owed even if an earlier
        // image or property comparison has refused.
        if let Some(parent) = parent {
            let _ = identity(parent, Some(&mut *self));
            let _ = info(parent, Some(&mut *self));
            if let Some(cgroup) = cgroup {
                let _ = membership(cgroup, parent,
                    Some((&mut self.membership, &mut self.membership_result)));
            }
        }
        match fragment.as_deref_mut() {
            Some(file) => { let _ = image(file, Some((&mut self.fragment[1], &mut self.fragment_results[1]))); }
            None => self.fragment_results[1] = fragment_open.observe_available_held_once_v1(&mut self.fragment[1]),
        }
        match manager.as_deref_mut() {
            Some(file) => { let _ = image(file, Some((&mut self.manager[1], &mut self.manager_results[1]))); }
            None => self.manager_results[1] = manager_open.observe_available_held_once_v1(&mut self.manager[1]),
        }
        // An incomplete service stays incomplete regardless of successful
        // descriptor observations. This route never assembles or publishes it.
        self.returned = Some(Err(FloorErrorV1::Unavailable));
        Err(FloorErrorV1::Unavailable)
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.reentry.is_none() && matches!(self.returned, Some(Ok(())))
    }

    pub(crate) fn receiving_demand_v1(
        image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Option<ResourceVector> {
        // Native/property/profile captures create no resident filesystem
        // namespace entries; their compiled fields and decoder overhead are
        // byte permits, while descriptors are counted independently.
        let policy = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?
            .with(D::MetadataEntries, 0);
        let immutable = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?
            .with(D::MetadataEntries, 0);
        let (identity_bytes, identity_files) = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(identity_bytes)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?.checked_mul(3)?)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(identity_files.checked_add(6)?).ok()?);
        own.checked_add(policy).ok()?
            .checked_add(immutable).ok()?.checked_add(immutable).ok()?
            .checked_add(immutable).ok()?.checked_add(immutable).ok()
    }

    /// Prices the healthy short-circuit service recipe without changing IO.
    ///
    /// Manager/fragment samples are metadata/hash-only. A failed policy stops
    /// before identity/membership; a successful policy's fresh files are gone
    /// before those later retained native probes begin. Owed service observers
    /// deliberately keep their full independently entered primitive bound.
    pub(crate) fn receiving_primary_demand_v1(
        image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Option<ResourceVector> {
        let complete = Self::receiving_demand_v1(image)?;
        let policy = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let primary = FloorServicePolicyReadbackV1::receiving_primary_demand_v1(image)?;
        let later = complete.get(D::OpenFiles).checked_sub(policy.get(D::OpenFiles))?;
        Some(complete.with(D::OpenFiles, later.max(primary.get(D::OpenFiles))))
    }

    // The closed initializer has no helper child yet. Its fixed recipe skips
    // both child/parent membership calls after the service revalidation.
    pub(super) fn receiving_initial_demand_v1(
        image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Option<ResourceVector> {
        let demand = Self::receiving_demand_v1(image)?;
        Some(demand.with(D::OpenFiles, demand.get(D::OpenFiles).checked_sub(4)?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.manager[0].failure().or_else(|| error(&self.manager_results[0]))
            .or_else(|| self.fragment[0].failure()).or_else(|| error(&self.fragment_results[0]))
            .or_else(|| self.policy.failure()).or_else(|| error(&self.policy_result))
            .or_else(|| self.identity.failure()).or_else(|| error(&self.identity_result))
            .or_else(|| error(&self.info)).or_else(|| error(&self.binding))
            .or_else(|| self.membership.failure().map(|cause| cause as _))
            .or_else(|| error(&self.membership_result))
            .or_else(|| self.fragment[1].failure()).or_else(|| error(&self.fragment_results[1]))
            .or_else(|| self.manager[1].failure()).or_else(|| error(&self.manager_results[1]))
            .or_else(|| self.child_membership[0].failure().map(|cause| cause as _))
            .or_else(|| error(&self.child_results[0]))
            .or_else(|| self.child_membership[1].failure().map(|cause| cause as _))
            .or_else(|| error(&self.child_results[1]))
            .or_else(|| error(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn property_failure_view_v1(&self) -> Option<FixedPid1PropertyFailureViewV1<'_>> {
        if self.manager[0].failure().is_some() || self.fragment[0].failure().is_some()
            || !matches!(self.policy_result, Some(Err(_)))
        {
            return None;
        }
        self.policy.property_failure_view_v1()
    }
}

pub(super) fn image(
    file: &MeasuredFileV1,
    original: Option<(&mut ImmutableFileRevalidationOriginalV1,
        &mut Option<Result<(), ImmutableImageErrorV1>>)>,
) -> Result<(), FloorErrorV1> {
    match original {
        None => file.revalidate().map_err(Into::into),
        Some((original, result)) => {
            *result = Some(file.revalidate_retaining(original));
            match result.as_ref() {
                Some(Ok(())) => Ok(()),
                Some(Err(ImmutableImageErrorV1::Unavailable)) => Err(FloorErrorV1::Unavailable),
                _ => Err(FloorErrorV1::Provisioning),
            }
        }
    }
}

pub(super) fn identity(
    process: &PidFd,
    original: Option<&mut FloorServiceCurrentnessOriginalV1>,
) -> Result<PidFdProcessIdentity, FloorErrorV1> {
    match original {
        None => process.process_identity().map_err(|_| FloorErrorV1::Unavailable),
        Some(original) => {
            original.identity_result = Some(original.identity.capture_once(process));
            if !matches!(original.identity_result, Some(Ok(()))) {
                return Err(FloorErrorV1::Unavailable);
            }
            original.identity.identity().ok_or(FloorErrorV1::Unavailable)
        }
    }
}

pub(super) fn info(
    process: &PidFd,
    original: Option<&mut FloorServiceCurrentnessOriginalV1>,
) -> Result<PidFdInfo, FloorErrorV1> {
    match original {
        None => process.info().map_err(|_| FloorErrorV1::Unavailable),
        Some(original) => {
            original.info = Some(process.info());
            match original.info.as_ref() {
                Some(Ok(info)) => Ok(*info),
                _ => Err(FloorErrorV1::Unavailable),
            }
        }
    }
}

pub(super) fn membership(
    anchor: &RetainedCgroupAnchor,
    process: &PidFd,
    original: Option<(&mut ExactCgroupMembershipReadbackV1,
        &mut Option<Result<(), ExactCgroupMembershipRefusalV1>>)>,
) -> Result<(), FloorErrorV1> {
    match original {
        None => anchor.verify_exact_membership(process).map(|_| ()).map_err(|_| FloorErrorV1::Unavailable),
        Some((original, result)) => {
            *result = Some(original.capture_once(anchor, process));
            if matches!(result, Some(Ok(()))) && original.retire_completed_files_once_v1() {
                // The complete exact-membership comparison is this helper's
                // result; later service probes borrow only its original
                // cgroup/pidfd anchors and retained DATA, never these files.
                Ok(())
            } else {
                Err(FloorErrorV1::Unavailable)
            }
        }
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
