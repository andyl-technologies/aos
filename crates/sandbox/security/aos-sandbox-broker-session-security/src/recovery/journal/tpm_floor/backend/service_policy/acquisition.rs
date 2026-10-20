//! Retains each original of the fixed Controller floor service opening.
//!
//! The sole ordinary/retained opening schedule lives in the parent. This
//! destination keeps its returned native prefixes until the complete typed
//! service and its immediate original revalidation succeed.

use std::error::Error;
use std::num::NonZeroU32;

use aos_sandbox_broker::immutable_image::{BackendPid1ImageAcquisitionOriginalV1,
    ImmutableFileAcquisitionOriginalV1, ImmutableImageErrorV1};
use aos_sandbox_linux::cgroup::{CgroupV2Root, ControllerInitialCgroupReadbackV1,
    ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo, PidFdOpenAttemptV1,
    PidFdProcessIdentityOriginalV1, PidFdOpenRefusalV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::production_startup::Pid1LaunchImageV1;
use crate::{BrokerSessionSecurityError, ProtectedBrokerSessionFixedEndpointV1};
use super::{FloorEndpointV1, FloorErrorV1, FloorServiceCurrentnessOriginalV1,
    FloorServicePolicyReadbackV1, MeasuredFileV1, PolicyObservationV1,
    RetainedFloorServicePolicyV1, require_original_manager_parent};

pub(crate) struct FloorServiceAcquisitionOriginalV1 {
    deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    endpoint: Option<Result<(), BrokerSessionSecurityError>>,
    launch_file: Option<Result<(), BrokerSessionSecurityError>>,
    manager_open: BackendPid1ImageAcquisitionOriginalV1,
    manager_result: Option<Result<(), ImmutableImageErrorV1>>,
    manager: Option<MeasuredFileV1>,
    parent_open: PidFdOpenAttemptV1,
    parent_result: Option<Result<(), PidFdOpenRefusalV1>>,
    parent: Option<PidFd>,
    info: Option<aos_sandbox_linux::Result<PidFdInfo>>,
    info_binding: Option<Result<(), FloorErrorV1>>,
    identity: Option<PidFdProcessIdentityOriginalV1>,
    identity_result: Option<aos_sandbox_linux::Result<()>>,
    policy: FloorServicePolicyReadbackV1,
    policy_result: Option<Result<(), FloorErrorV1>>,
    observed: Option<PolicyObservationV1>,
    cgroup_open: Option<ControllerInitialCgroupReadbackV1>,
    cgroup_result: Option<aos_sandbox_linux::Result<()>>,
    root: Option<CgroupV2Root>,
    cgroup: Option<RetainedCgroupAnchor>,
    membership: ExactCgroupMembershipReadbackV1,
    membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    fragment_open: ImmutableFileAcquisitionOriginalV1,
    fragment_result: Option<Result<(), ImmutableImageErrorV1>>,
    fragment: Option<MeasuredFileV1>,
    service: Option<RetainedFloorServicePolicyV1>,
    assembly: Option<Result<(), FloorErrorV1>>,
    initial: Option<FloorServiceCurrentnessOriginalV1>,
    initial_result: Option<Result<(), FloorErrorV1>>,
    returned: Option<Result<RetainedFloorServicePolicyV1, FloorErrorV1>>,
    transfer: Option<Result<(), FloorErrorV1>>,
    shared_process_info: Option<aos_sandbox_linux::Result<PidFdInfo>>,
    shared_profile: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    taken: bool,
    reentry: Option<FloorErrorV1>,
}

impl FloorServiceAcquisitionOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            deadline: None, endpoint: None, launch_file: None,
            manager_open: BackendPid1ImageAcquisitionOriginalV1::new(), manager_result: None,
            manager: None, parent_open: PidFdOpenAttemptV1::new(), parent_result: None,
            parent: None, info: None, info_binding: None,
            identity: Some(PidFdProcessIdentityOriginalV1::new()), identity_result: None,
            policy: FloorServicePolicyReadbackV1::new(aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::Ordinary),
            policy_result: None, observed: None,
            cgroup_open: Some(ControllerInitialCgroupReadbackV1::new()), cgroup_result: None,
            root: None, cgroup: None,
            membership: ExactCgroupMembershipReadbackV1::new(), membership_result: None,
            fragment_open: ImmutableFileAcquisitionOriginalV1::new(), fragment_result: None,
            fragment: None, service: None, assembly: None,
            initial: Some(FloorServiceCurrentnessOriginalV1::new()), initial_result: None,
            returned: None, transfer: None, shared_process_info: None,
            shared_profile: None, entered: false, taken: false, reentry: None,
        }
    }

    pub(crate) fn with_storage_layout_v2(layout: aos_sandbox_linux::cgroup::StorageCgroupLayoutV1) -> Self {
        let mut original = Self::new();
        original.policy = FloorServicePolicyReadbackV1::new(layout);
        original.initial = Some(FloorServiceCurrentnessOriginalV1::with_storage_layout_v2(layout));
        original
    }

    pub(crate) fn with_shared_provider_v1(provider: std::sync::Arc<aos_systemd_client::SharedFixedPid1PropertyProviderV1>) -> Self {
        let mut original = Self::new();
        original.policy = FloorServicePolicyReadbackV1::with_shared_provider_v1(
            aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::Ordinary,
            std::sync::Arc::clone(&provider),
        );
        original.initial = Some(FloorServiceCurrentnessOriginalV1::with_shared_provider_v1(provider));
        original
    }

    pub(crate) fn receiving_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_demand_v1(image)?;
        let old_policy = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let old_initial = FloorServiceCurrentnessOriginalV1::receiving_initial_demand_v1(image)?;
        let policy = FloorServicePolicyReadbackV1::receiving_shared_demand_v1(image)?;
        let initial = FloorServiceCurrentnessOriginalV1::receiving_initial_shared_demand_v1(image)?;
        let files = full.get(D::OpenFiles)
            .checked_sub(old_policy.get(D::OpenFiles).max(old_initial.get(D::OpenFiles)))?
            .checked_add(policy.get(D::OpenFiles).max(initial.get(D::OpenFiles)))?;
        Some(full.with(D::OpenFiles, files))
    }

    pub(crate) fn capture_once(
        &mut self,
        image: &Pid1LaunchImageV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.deadline = deadline;
        self.returned = Some(RetainedFloorServicePolicyV1::open_observed(
            FloorEndpointV1::ControllerStorageClient, image, Some(&mut *self),
        ));
        match self.returned.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(cause)) => Err(*cause),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(super) fn capture_endpoint(&mut self, image: &Pid1LaunchImageV1) -> Result<(), FloorErrorV1> {
        self.endpoint = Some(image.require_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient));
        if matches!(self.endpoint, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FloorErrorV1::Provisioning)
        }
    }

    pub(super) fn capture_manager(&mut self, image: &Pid1LaunchImageV1) -> Result<(), FloorErrorV1> {
        match image.file() {
            Ok(file) => {
                self.launch_file = Some(Ok(()));
                self.manager_result = Some(self.manager_open.capture_once(file));
            }
            Err(cause) => {
                self.launch_file = Some(Err(cause));
                return Err(FloorErrorV1::Provisioning);
            }
        }
        immutable_unit(&self.manager_result)?;
        self.manager = self.manager_open.take_completed_once();
        self.manager.as_ref().ok_or(FloorErrorV1::Unavailable).map(|_| ())
    }

    pub(super) fn capture_parent(&mut self) -> Result<(), FloorErrorV1> {
        let pid = NonZeroU32::new(std::process::id()).ok_or(FloorErrorV1::Unavailable)?;
        self.parent_result = Some(self.parent_open.capture_once(pid));
        unit(&self.parent_result)?;
        self.parent = self.parent_open.take_validated();
        self.parent.as_ref().ok_or(FloorErrorV1::Unavailable).map(|_| ())
    }

    pub(super) fn capture_info(&mut self) -> Result<(), FloorErrorV1> {
        self.info = Some(self.parent.as_ref().ok_or(FloorErrorV1::Unavailable)?.info());
        let info = self.info.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Unavailable)?;
        self.info_binding = Some(require_original_manager_parent(info));
        match self.info_binding {
            Some(result) => result,
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(super) fn capture_identity(&mut self) -> Result<(), FloorErrorV1> {
        self.identity_result = Some(self.identity.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .capture_once(self.parent.as_ref().ok_or(FloorErrorV1::Unavailable)?));
        unit(&self.identity_result)
    }

    pub(super) fn capture_policy(&mut self, image: &Pid1LaunchImageV1) -> Result<(), FloorErrorV1> {
        self.policy_result = Some(self.policy.observe_with_deadline(FloorEndpointV1::ControllerStorageClient, image, self.deadline));
        match self.policy_result {
            Some(Ok(())) => {}
            Some(Err(cause)) => return Err(cause),
            None => return Err(FloorErrorV1::Unavailable),
        }
        self.observed = self.policy.take_completed_once();
        self.observed.as_ref().ok_or(FloorErrorV1::Unavailable).map(|_| ())
    }

    pub(super) fn capture_cgroup(&mut self) -> Result<(), FloorErrorV1> {
        // The SAME policy decoder already requires the exact Controller path.
        // This closed facade routes the same hierarchy/resolve/probe kernels
        // and retains their actual rooted partials instead of local values.
        let original = self.cgroup_open.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        self.cgroup_result = Some(original.capture_once());
        unit(&self.cgroup_result)?;
        let (root, cgroup) = original.take_validated_pair().ok_or(FloorErrorV1::Unavailable)?;
        self.root = Some(root);
        self.cgroup = Some(cgroup);
        Ok(())
    }

    pub(super) fn capture_membership(&mut self) -> Result<(), FloorErrorV1> {
        self.membership_result = Some(self.membership.capture_once(
            self.cgroup.as_ref().ok_or(FloorErrorV1::Unavailable)?,
            self.parent.as_ref().ok_or(FloorErrorV1::Unavailable)?,
        ));
        unit(&self.membership_result)
    }

    pub(super) fn capture_fragment(&mut self) -> Result<(), FloorErrorV1> {
        let path = self.observed.as_ref().ok_or(FloorErrorV1::Unavailable)?.fragment.clone();
        self.fragment_result = Some(self.fragment_open.open_and_measure_once(path, None, 64 * 1024, false));
        immutable_unit(&self.fragment_result)?;
        self.fragment = self.fragment_open.take_completed_measurement_once();
        self.fragment.as_ref().ok_or(FloorErrorV1::Unavailable).map(|_| ())
    }

    pub(super) fn assemble(&mut self, image: &Pid1LaunchImageV1) -> Result<(), FloorErrorV1> {
        self.assembly = Some((|| {
            let identity = self.identity.as_ref().and_then(PidFdProcessIdentityOriginalV1::identity)
                .ok_or(FloorErrorV1::Unavailable)?;
            if self.parent.is_none() || self.cgroup.is_none() || self.fragment.is_none() || self.manager.is_none()
                || self.observed.is_none()
            {
                return Err(FloorErrorV1::Unavailable);
            }
            let parts = (
                self.parent.take(), self.cgroup.take(), self.fragment.take(),
                self.manager.take(), self.observed.take(),
            );
            match parts {
                (Some(parent), Some(cgroup), Some(fragment), Some(manager), Some(mut observed)) => {
                    self.service = Some(RetainedFloorServicePolicyV1 {
                        endpoint: FloorEndpointV1::ControllerStorageClient,
                        parent_identity: identity,
                        anchors: super::FloorServiceAnchorsV1::Owned { parent, cgroup, fragment, manager },
                        invocation: std::mem::take(&mut observed.invocation),
                        launch_image: image.clone(),
                    });
                    self.observed = Some(observed);
                }
                (parent, cgroup, fragment, manager, observed) => {
                    self.parent = parent;
                    self.cgroup = cgroup;
                    self.fragment = fragment;
                    self.manager = manager;
                    self.observed = observed;
                    return Err(FloorErrorV1::Unavailable);
                }
            }
            Ok(())
        })());
        match self.assembly {
            Some(result) => result,
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(super) fn capture_initial_currentness(&mut self) -> Result<(), FloorErrorV1> {
        self.initial_result = Some(self.initial.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .observe_initial_once(self.service.as_mut().ok_or(FloorErrorV1::Unavailable)?, self.deadline));
        match self.initial_result {
            Some(result) => result,
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(super) fn take_constructed_service(&mut self) -> Result<RetainedFloorServicePolicyV1, FloorErrorV1> {
        if !matches!(self.initial_result, Some(Ok(()))) {
            return Err(FloorErrorV1::Unavailable);
        }
        self.share_completed_profile_once()?;
        self.service.take().ok_or(FloorErrorV1::Unavailable)
    }

    fn share_completed_profile_once(&mut self) -> Result<(), FloorErrorV1> {
        let service = self.service.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        let binding = service.launch_image.controller_floor_profile_v1()
            .map_err(|_| FloorErrorV1::Provisioning)?;
        let Some(binding) = binding else { return Ok(()); };
        let shared = binding.floor_service_anchors_v1().ok_or(FloorErrorV1::Provisioning)?;
        // Both process pins refer to this still-running caller. The pidfds
        // remain held throughout this fresh comparison, excluding PID reuse.
        self.shared_process_info = Some(shared.process().info());
        let captured = service.anchors()?;
        self.shared_profile = Some((|| {
            let info = self.shared_process_info.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Unavailable)?;
            require_original_manager_parent(info)?;
            let original_info = self.info.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Unavailable)?;
            if info != original_info
                || captured.cgroup.kernel_id() != shared.cgroup().kernel_id()
                || service.invocation.as_slice() != shared.invocation()
                || !same_measurement(captured.fragment, shared.fragment())
                || !same_measurement(captured.manager, shared.manager())
            {
                return Err(FloorErrorV1::Provisioning);
            }
            Ok(())
        })());
        match self.shared_profile {
            Some(Ok(())) => {
                // Initial capture and its independent native post are whole
                // positive. Future probes use these exact shared originals;
                // the completed duplicate four-pin owner alone is retired.
                service.anchors = super::FloorServiceAnchorsV1::Shared(binding);
                Ok(())
            }
            Some(Err(cause)) => Err(cause),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(crate) fn take_completed_once(&mut self) -> Option<RetainedFloorServicePolicyV1> {
        if self.taken || self.reentry.is_some() || self.transfer.is_some()
            || !matches!(self.returned, Some(Ok(_)))
        {
            return None;
        }
        let pin_retired = self.manager_open.retire_completed_pin_file_once_v1();
        let membership_retired = self.membership.retire_completed_files_once_v1();
        self.transfer = Some(if pin_retired && membership_retired {
            Ok(())
        } else {
            Err(FloorErrorV1::Unavailable)
        });
        if !matches!(self.transfer, Some(Ok(()))) { return None; }
        // The complete service and its immediate same-native post succeeded.
        // These positive initial root/probe/stat/row temporaries are no longer
        // inputs to future custody. The actual service originals move below.
        drop(self.initial.take());
        drop(self.identity.take());
        drop(self.cgroup_open.take());
        drop(self.root.take());
        match self.returned.take() {
            Some(Ok(service)) => { self.taken = true; Some(service) }
            original => { self.returned = original; None }
        }
    }

    pub(crate) fn observe_controller_owed_v1(
        &mut self,
        original: &mut FloorServiceCurrentnessOriginalV1,
        child: Option<&PidFd>,
        image: &Pid1LaunchImageV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        // Assembly can succeed before its immediate currentness fails. Keep
        // that actual service as the target instead of constructing a second
        // owner or substituting a policy-only observation.
        if let Some(service) = self.service.as_mut() {
            return original.observe_controller_owed_v1(service, child, deadline);
        }
        if let Some(Ok(service)) = self.returned.as_mut() {
            return original.observe_controller_owed_v1(service, child, deadline);
        }
        original.observe_acquisition_prefix_owed_v1(
            self.manager.as_mut(), &self.manager_open,
            self.fragment.as_mut(), &self.fragment_open,
            self.parent.as_ref(), self.cgroup.as_ref(), image, deadline,
        )
    }

    pub(crate) fn receiving_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let manager = BackendPid1ImageAcquisitionOriginalV1::receiving_demand_v1()?;
        let fragment = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(4096)?;
        let policy = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?.with(D::MetadataEntries, 0);
        let initial = FloorServiceCurrentnessOriginalV1::receiving_initial_demand_v1(image)?;
        let (identity, _) = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(identity)?.checked_add(4 * 4096)?
            .checked_add(ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?)?;
        // parent pidfd1 + initial stat1 + closed root/child/probes6 + membership2.
        let own = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 10);
        let worker_tasks = policy.get(D::Pids).max(initial.get(D::Pids));
        let complete = own.checked_add(manager).ok()?.checked_add(fragment).ok()?
            .checked_add(policy).ok()?.checked_add(initial).ok()?;
        // A refused policy retains its full native owner and stops before
        // initial currentness. A successful policy has completed BOTH profile
        // posts and archive settlement; its fresh local and native PID1 files
        // are already disposed before the initializer enters its first row.
        // All original acquisition anchors stay covered by the summed base.
        let files = complete.get(D::OpenFiles).checked_sub(policy.get(D::OpenFiles))?
            .checked_sub(initial.get(D::OpenFiles))?
            .checked_add(policy.get(D::OpenFiles).max(initial.get(D::OpenFiles)))?;
        // The first row has completed native join/retirement before the
        // initializer starts its row. These actual workers never coexist.
        Some(complete.with(D::Pids, worker_tasks).with(D::OpenFiles, files))
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        // A reached failed row follows only positive earlier opening stages.
        // Its own first marker excludes a later independently owed profile
        // failure from replacing the original native/semantic cause.
        if matches!(self.policy_result, Some(Err(_))) {
            return self.policy.property_failure_view_v1();
        }
        if matches!(self.initial_result, Some(Err(_))) {
            return self.initial.as_ref()?.property_failure_view_v1();
        }
        None
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.endpoint).or_else(|| error(&self.launch_file))
            .or_else(|| self.manager_open.failure()).or_else(|| error(&self.manager_result))
            .or_else(|| self.parent_open.failure().map(|cause| cause as _))
            .or_else(|| error(&self.parent_result)).or_else(|| error(&self.info))
            .or_else(|| error(&self.info_binding))
            .or_else(|| self.identity.as_ref().and_then(PidFdProcessIdentityOriginalV1::failure))
            .or_else(|| error(&self.identity_result))
            .or_else(|| self.policy.failure()).or_else(|| error(&self.policy_result))
            .or_else(|| self.cgroup_open.as_ref().and_then(ControllerInitialCgroupReadbackV1::failure))
            .or_else(|| error(&self.cgroup_result))
            .or_else(|| self.membership.failure().map(|cause| cause as _))
            .or_else(|| error(&self.membership_result))
            .or_else(|| self.fragment_open.failure()).or_else(|| error(&self.fragment_result))
            .or_else(|| error(&self.assembly))
            .or_else(|| self.initial.as_ref().and_then(FloorServiceCurrentnessOriginalV1::failure))
            .or_else(|| error(&self.initial_result))
            .or_else(|| error(&self.shared_process_info)).or_else(|| error(&self.shared_profile))
            .or_else(|| error(&self.returned))
            .or_else(|| error(&self.transfer))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

fn unit<T, E>(slot: &Option<Result<T, E>>) -> Result<(), FloorErrorV1> {
    if matches!(slot, Some(Ok(_))) { Ok(()) } else { Err(FloorErrorV1::Unavailable) }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn immutable_unit(slot: &Option<Result<(), ImmutableImageErrorV1>>) -> Result<(), FloorErrorV1> {
    match slot.as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(ImmutableImageErrorV1::Provisioning)) => Err(FloorErrorV1::Provisioning),
        _ => Err(FloorErrorV1::Unavailable),
    }
}

fn same_measurement(left: &MeasuredFileV1, right: &MeasuredFileV1) -> bool {
    left.path() == right.path() && left.physical_identity() == right.physical_identity()
        && left.measured_digest_v1() == right.measured_digest_v1()
}
