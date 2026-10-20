//! Retains one actual process/image/service comparison and its raw causes.
//!
//! Healthy entry keeps the existing predicate order. Negative entry consumes
//! prearmed same-OFD stat/context samples, independently observes every reached
//! owner and never restores the original healthy phase or sends a TPM command.

use std::error::Error;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo, PidFdProcessIdentity,
    PidFdProcObservationsV1, PidFdNegativeIdentityOriginalV1, PidFdNegativeContextOriginalV1};
use crate::production_startup::Pid1LaunchImageV1;
use crate::recovery::{BrokerPhysicalOpenV1, FloorProfileV1, FloorErrorV1,
    HelperImageRevalidationOriginalV1, MeasuredHelperImageV1,
    FloorServiceCurrentnessOriginalV1, FloorServicePolicyReadbackV1,
    RetainedFloorServicePolicyV1};
use super::super::OwnedHelperChildV1;

type Native<T> = Result<T, aos_sandbox_linux::Error>;
#[derive(Clone, Copy)]
enum FirstV1 { Info, Coordinates, Alive, Wait, Identity, Image, Context, Service, Final, Closed }

pub(in crate::tpm_nv_custody::physical) struct BrokerPhysicalCurrentnessOriginalV2 {
    info: Option<Native<PidFdInfo>>,
    coordinates: Option<Result<(), FloorErrorV1>>,
    credentials: Option<Result<(), FloorErrorV1>>,
    self_ids: Option<(u32, u32)>,
    alive_binding: Option<Result<(), FloorErrorV1>>,
    wait_binding: Option<Result<(), FloorErrorV1>>,
    final_binding: Option<Result<(), FloorErrorV1>>,
    alive: Option<Native<bool>>,
    wait: Option<std::io::Result<Option<std::process::ExitStatus>>>,
    healthy_identity: aos_sandbox_linux::pidfd::PidFdProcOriginalsV1,
    healthy_context: aos_sandbox_linux::pidfd::PidFdProcOriginalsV1,
    identity: PidFdNegativeIdentityOriginalV1,
    identity_prepared: Option<Native<()>>,
    identity_result: Option<Native<()>>,
    identity_binding: Option<Result<(), FloorErrorV1>>,
    owner: crate::recovery::OwnerConfinementOriginalV1,
    owner_result: Option<Result<(), FloorErrorV1>>,
    image: HelperImageRevalidationOriginalV1,
    image_result: Option<Result<(), FloorErrorV1>>,
    context: PidFdNegativeContextOriginalV1,
    context_prepared: Option<Native<()>>,
    context_result: Option<Native<()>>,
    context_binding: Option<Result<(), FloorErrorV1>>,
    service: FloorServiceCurrentnessOriginalV1,
    fallback_policy: FloorServicePolicyReadbackV1,
    service_result: Option<Result<(), FloorErrorV1>>,
    final_alive: Option<Native<bool>>,
    completion: Option<Result<(), FloorErrorV1>>,
    entered: bool,
    negative: bool,
    first: Option<FirstV1>,
}

impl BrokerPhysicalCurrentnessOriginalV2 {
    pub(super) fn new() -> Self {
        Self { info: None, coordinates: None, credentials: None, self_ids: None,
            alive_binding: None, wait_binding: None, final_binding: None, alive: None, wait: None,
            healthy_identity: aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::new(),
            healthy_context: aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::new(),
            identity: PidFdNegativeIdentityOriginalV1::new(), identity_prepared: None,
            identity_result: None, identity_binding: None,
            owner: crate::recovery::OwnerConfinementOriginalV1::new(), owner_result: None,
            image: HelperImageRevalidationOriginalV1::new(), image_result: None,
            context: PidFdNegativeContextOriginalV1::new(), context_prepared: None,
            context_result: None, context_binding: None,
            service: FloorServiceCurrentnessOriginalV1::new(),
            fallback_policy: FloorServicePolicyReadbackV1::new(
                aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::Ordinary),
            service_result: None, final_alive: None, completion: None,
            entered: false, negative: false, first: None }
    }

    pub(super) fn with_storage_layout_v2(layout: aos_sandbox_linux::cgroup::StorageCgroupLayoutV1) -> Self {
        let mut original = Self::new();
        original.service = FloorServiceCurrentnessOriginalV1::with_storage_layout_v2(layout);
        original.fallback_policy = FloorServicePolicyReadbackV1::new(layout);
        original
    }

    pub(super) fn with_shared_provider_v1(provider: std::sync::Arc<aos_systemd_client::SharedFixedPid1PropertyProviderV1>) -> Self {
        let mut original = Self::new();
        original.service = FloorServiceCurrentnessOriginalV1::with_shared_provider_v1(
            std::sync::Arc::clone(&provider),
        );
        original.fallback_policy = FloorServicePolicyReadbackV1::with_shared_provider_v1(
            aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::Ordinary, provider,
        );
        original
    }

    pub(super) fn receiving_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_demand_v1(image)?;
        let old_service = FloorServiceCurrentnessOriginalV1::receiving_demand_v1(image)?;
        let old_fallback = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let service = FloorServiceCurrentnessOriginalV1::receiving_shared_demand_v1(image)?;
        let fallback = FloorServicePolicyReadbackV1::receiving_shared_demand_v1(image)?;
        let files = full.get(D::OpenFiles)
            .checked_sub(old_service.get(D::OpenFiles).max(old_fallback.get(D::OpenFiles)))?
            .checked_add(service.get(D::OpenFiles).max(fallback.get(D::OpenFiles)))?;
        Some(full.with(D::OpenFiles, files))
    }

    pub(super) fn receiving_primary_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_shared_demand_v1(image)?;
        let service = FloorServiceCurrentnessOriginalV1::receiving_shared_demand_v1(image)?;
        let fallback = FloorServicePolicyReadbackV1::receiving_shared_demand_v1(image)?;
        let primary = FloorServiceCurrentnessOriginalV1::receiving_primary_shared_demand_v1(image)?;
        let owner = crate::recovery::OwnerConfinementOriginalV1::receiving_demand_v1()?;
        let other = full.get(D::OpenFiles)
            .checked_sub(service.get(D::OpenFiles).max(fallback.get(D::OpenFiles)))?
            .checked_sub(owner.get(D::OpenFiles))?;
        Some(full.with(D::OpenFiles,
            other.checked_add(owner.get(D::OpenFiles).max(primary.get(D::OpenFiles)))?))
    }

    pub(super) fn receiving_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let helper = HelperImageRevalidationOriginalV1::receiving_demand_v1()?.with(D::MetadataEntries, 0);
        let service = FloorServiceCurrentnessOriginalV1::receiving_demand_v1(image)?;
        let fallback = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let (identity, identity_files, _) = PidFdNegativeIdentityOriginalV1::receiving_demand_v1()?;
        let (context, context_files, _) = PidFdNegativeContextOriginalV1::receiving_demand_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?.checked_add(identity)?.checked_add(context)?
            .checked_add(aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::receiving_bytes_v1()?.checked_mul(2)?)?;
        let own = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(identity_files.checked_add(context_files)?).ok()?);
        // One sample can enter only once. Its primary uses the actual held
        // service; its negative recipe selects either that same service, the
        // reached acquisition prefix, or the fixed-policy fallback. Those
        // branches cannot open both service and fallback descriptors in this
        // owner. Retain both byte reservoirs and their complete failed DATA;
        // only their mutually exclusive native descriptor peak is shared.
        let policy = service.checked_add(fallback).ok()?.with(
            D::OpenFiles, service.get(D::OpenFiles).max(fallback.get(D::OpenFiles)),
        );
        own.checked_add(helper).ok()?.checked_add(policy).ok()?
            .checked_add(crate::recovery::OwnerConfinementOriginalV1::receiving_demand_v1()?).ok()
    }

    // Only the real healthy primary takes the short-circuit service recipe;
    // negative entries keep the full independent service/fallback reservoir.
    pub(super) fn receiving_primary_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let complete = Self::receiving_demand_v1(image)?;
        let service = FloorServiceCurrentnessOriginalV1::receiving_demand_v1(image)?;
        let fallback = FloorServicePolicyReadbackV1::receiving_demand_v1(image)?;
        let primary = FloorServiceCurrentnessOriginalV1::receiving_primary_demand_v1(image)?;
        let owner = crate::recovery::OwnerConfinementOriginalV1::receiving_demand_v1()?.get(D::OpenFiles);
        let other = complete.get(D::OpenFiles)
            .checked_sub(service.get(D::OpenFiles).max(fallback.get(D::OpenFiles)))?
            .checked_sub(owner)?;
        // Failed confinement stops before service; a positive exact owner
        // comparison has actually retired both temporary readers already.
        let files = other.checked_add(owner.max(primary.get(D::OpenFiles)))?;
        Some(complete.with(D::OpenFiles, files))
    }

    pub(super) fn prepare_identity(&mut self, source: &PidFdProcObservationsV1) -> Result<(), FloorErrorV1> {
        if self.identity_prepared.is_none() {
            self.identity_prepared = Some(source.prepare_negative_identity_once_into(&mut self.identity));
        }
        if matches!(self.identity_prepared, Some(Ok(()))) { Ok(()) }
        else {
            self.first.get_or_insert(FirstV1::Identity);
            self.entered = true;
            self.completion = Some(Err(FloorErrorV1::Unavailable));
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(super) fn prepare_context(&mut self, source: &PidFdProcObservationsV1) -> Result<(), FloorErrorV1> {
        if self.context_prepared.is_none() {
            self.context_prepared = Some(source.prepare_negative_context_once_into(&mut self.context));
        }
        if matches!(self.context_prepared, Some(Ok(()))) { Ok(()) }
        else {
            self.first.get_or_insert(FirstV1::Context);
            self.entered = true;
            self.completion = Some(Err(FloorErrorV1::Unavailable));
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(super) fn prepare_available_prefix_v1(&mut self, source: &PidFdProcObservationsV1) {
        if self.identity_prepared.is_none() {
            self.identity_prepared = Some(source.prepare_available_negative_identity_once_into_v1(&mut self.identity));
        }
        if self.context_prepared.is_none() {
            self.context_prepared = Some(source.prepare_available_negative_context_once_into_v1(&mut self.context));
        }
    }

    fn require_info(info: PidFdInfo, child: &OwnedHelperChildV1, uid: u32, gid: u32) -> Result<(), FloorErrorV1> {
        let credentials = info.credentials().ok_or(FloorErrorV1::Unavailable)?;
        if info.parent_pid() != std::process::id() || info.pid() != child.0.id()
            || [credentials.real_user_id(), credentials.effective_user_id(),
                credentials.saved_user_id(), credentials.filesystem_user_id()] != [uid; 4]
            || [credentials.real_group_id(), credentials.effective_group_id(),
                credentials.saved_group_id(), credentials.filesystem_group_id()] != [gid; 4]
        { Err(FloorErrorV1::Unavailable) } else { Ok(()) }
    }

    pub(super) fn observe_primary(
        &mut self, pidfd: &PidFd, child: &mut OwnedHelperChildV1,
        expected: Option<PidFdProcessIdentity>, source: &mut PidFdProcObservationsV1,
        image: &MeasuredHelperImageV1, service: &mut RetainedFloorServicePolicyV1,
        profile: FloorProfileV1, poisoned: bool,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        if self.entered { self.first.get_or_insert(FirstV1::Closed); return Err(FloorErrorV1::Unavailable); }
        self.entered = true;
        self.completion = Some((|| {
            self.info = Some(pidfd.info());
            let info = match self.info.as_ref() { Some(Ok(info)) => *info, _ => {
                self.first = Some(FirstV1::Info); return Err(FloorErrorV1::Unavailable);
            }};
            // Preserve credentials and self UID/GID acquisition before the
            // original lazy liveness/try_wait/coordinate comparison sequence.
            self.credentials = Some(info.credentials().map(|_| ()).ok_or(FloorErrorV1::Unavailable));
            if !matches!(self.credentials, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
            let (uid, gid) = (rustix::process::geteuid().as_raw(), rustix::process::getegid().as_raw());
            self.self_ids = Some((uid, gid));
            if poisoned { self.first = Some(FirstV1::Closed); return Err(FloorErrorV1::Unavailable); }
            self.alive = Some(pidfd.is_alive());
            if !matches!(self.alive, Some(Ok(true))) { self.first = Some(FirstV1::Alive); return Err(FloorErrorV1::Unavailable); }
            self.wait = Some(child.0.try_wait());
            if !matches!(self.wait, Some(Ok(None))) { self.first = Some(FirstV1::Wait); return Err(FloorErrorV1::Unavailable); }
            self.coordinates = Some(Self::require_info(info, child, uid, gid));
            if !matches!(self.coordinates, Some(Ok(()))) { self.first = Some(FirstV1::Coordinates); return Err(FloorErrorV1::Unavailable); }
            let identity = source.observe_identity_retaining_v1(pidfd, &mut self.healthy_identity);
            match identity {
                Ok(actual) => { self.identity_result = Some(Ok(())); self.identity_binding = Some(
                    if Some(actual) == expected { Ok(()) } else { Err(FloorErrorV1::Unavailable) }); }
                Err(cause) => { self.identity_result = Some(Err(cause)); }
            }
            if !matches!(self.identity_result, Some(Ok(()))) || !matches!(self.identity_binding, Some(Ok(()))) {
                self.first = Some(FirstV1::Identity); return Err(FloorErrorV1::Unavailable);
            }
            self.image_result = Some(image.revalidate_primary_retaining_v1(&mut self.image));
            if !matches!(self.image_result, Some(Ok(()))) { self.first = Some(FirstV1::Image); return Err(FloorErrorV1::Unavailable); }
            self.owner_result = Some(self.owner.capture_floor_owner_once_v2(profile));
            if !matches!(self.owner_result, Some(Ok(()))) {
                self.first = Some(FirstV1::Context); return Err(FloorErrorV1::Unavailable);
            }
            if child.0.id() == 0 || child.0.id() == std::process::id() {
                return Err(FloorErrorV1::Provisioning);
            }
            match source.observe_context_retaining_v1(pidfd, &mut self.healthy_context) {
                Ok(bytes) => { self.context_result = Some(Ok(())); self.context_binding = Some(
                    BrokerPhysicalOpenV1::require_helper_context(profile, bytes)); }
                Err(cause) => { self.context_result = Some(Err(cause)); }
            }
            if !matches!(self.context_result, Some(Ok(()))) || !matches!(self.context_binding, Some(Ok(()))) {
                self.first = Some(FirstV1::Context); return Err(FloorErrorV1::Unavailable);
            }
            self.service_result = Some(self.service.observe_with_deadline(service, pidfd, deadline));
            if !matches!(self.service_result, Some(Ok(()))) { self.first = Some(FirstV1::Service); return Err(FloorErrorV1::Unavailable); }
            self.final_alive = Some(pidfd.is_alive());
            if !matches!(self.final_alive, Some(Ok(true))) { self.first = Some(FirstV1::Final); return Err(FloorErrorV1::Unavailable); }
            Ok(())
        })());
        self.completion.unwrap_or(Err(FloorErrorV1::Unavailable))
    }

    // No healthy operation gate is weakened here. Only the prearmed real
    // physical owner calls this after an entered primary; it never opens a
    // process/image, sends a TPM command or publishes a current floor.
    pub(super) fn observe_negative(
        &mut self, pidfd: Option<&PidFd>, child: Option<&mut OwnedHelperChildV1>,
        image: Option<&MeasuredHelperImageV1>, service: Option<&mut RetainedFloorServicePolicyV1>,
        service_opening: Option<&mut crate::recovery::FloorServiceAcquisitionOriginalV1>,
        launch: &Pid1LaunchImageV1, profile: FloorProfileV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        if self.entered { self.first.get_or_insert(FirstV1::Closed); return Err(FloorErrorV1::Unavailable); }
        self.entered = true;
        self.negative = true;
        if let Some(pidfd) = pidfd {
            self.info = Some(pidfd.info());
            self.credentials = Some(match self.info.as_ref() {
                Some(Ok(info)) => info.credentials().map(|_| ()).ok_or(FloorErrorV1::Unavailable),
                _ => Err(FloorErrorV1::Unavailable),
            });
            let (uid, gid) = (rustix::process::geteuid().as_raw(), rustix::process::getegid().as_raw());
            self.self_ids = Some((uid, gid));
            self.alive = Some(pidfd.is_alive());
            self.alive_binding = Some(if matches!(self.alive, Some(Ok(true))) { Ok(()) }
                else { Err(FloorErrorV1::Unavailable) });
            if let Some(child) = child {
                self.wait = Some(child.0.try_wait());
                self.wait_binding = Some(if matches!(self.wait, Some(Ok(None))) { Ok(()) }
                    else { Err(FloorErrorV1::Unavailable) });
                self.coordinates = Some(match self.info.as_ref() {
                    Some(Ok(info)) => Self::require_info(*info, child, uid, gid), _ => Err(FloorErrorV1::Unavailable),
                });
            }
            if self.identity_prepared.is_some() { self.identity_result = Some(self.identity.observe_once(pidfd)); }

        }
        if let Some(image) = image { self.image_result = Some(image.revalidate_owed_retaining_v1(&mut self.image)); }
        self.owner_result = Some(self.owner.capture_floor_owner_once_v2(profile));
        if let Some(pidfd) = pidfd {
            if self.context_prepared.is_some() {
                match self.context.observe_once(pidfd) {
                    Ok(bytes) => { self.context_result = Some(Ok(())); self.context_binding = Some(
                        BrokerPhysicalOpenV1::require_helper_context(profile, bytes)); }
                    Err(cause) => { self.context_result = Some(Err(cause)); }
                }
            }
        }
        self.service_result = Some(match (service, service_opening) {
            (Some(service), _) => self.service.observe_controller_owed_v1(service, pidfd, deadline),
            (None, Some(opening)) => opening.observe_controller_owed_v1(
                &mut self.service, pidfd, launch, deadline,
            ),
            (None, None) => self.fallback_policy.observe_controller_owed_with_deadline_v1(launch, deadline),
        });
        if let Some(pidfd) = pidfd {
            self.final_alive = Some(pidfd.is_alive());
            self.final_binding = Some(if matches!(self.final_alive, Some(Ok(true))) { Ok(()) }
                else { Err(FloorErrorV1::Unavailable) });
        }
        self.completion = Some(if self.failure().is_some()
            || self.alive.as_ref().is_some_and(|result| !matches!(result, Ok(true)))
            || self.wait.as_ref().is_some_and(|result| !matches!(result, Ok(None)))
            || self.final_alive.as_ref().is_some_and(|result| !matches!(result, Ok(true)))
        { Err(FloorErrorV1::Unavailable) } else { Ok(()) });
        self.completion.unwrap_or(Err(FloorErrorV1::Unavailable))
    }

    pub(super) fn is_complete(&self) -> bool { matches!(self.completion, Some(Ok(()))) }
    pub(super) fn is_entered(&self) -> bool { self.entered }

    pub(super) fn property_failure_view_v1(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let first = std::ptr::from_ref(self.failure()?).cast::<()>();
        if self.service.failure().is_some_and(|cause| std::ptr::from_ref(cause).cast::<()>() == first) {
            return self.service.property_failure_view_v1();
        }
        if self.fallback_policy.failure().is_some_and(|cause| std::ptr::from_ref(cause).cast::<()>() == first) {
            return self.fallback_policy.property_failure_view_v1();
        }
        None
    }

    pub(in crate::tpm_nv_custody::physical) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.info).or_else(|| error(&self.credentials))
            .or_else(|| error(&self.alive)).or_else(|| error(&self.alive_binding))
            .or_else(|| error(&self.wait)).or_else(|| error(&self.wait_binding))
            .or_else(|| error(&self.coordinates)).or_else(|| self.identity.failure())
            .or_else(|| self.healthy_identity.failure())
            .or_else(|| error(&self.identity_prepared)).or_else(|| error(&self.identity_result))
            .or_else(|| error(&self.identity_binding)).or_else(|| self.image.failure())
            .or_else(|| error(&self.image_result)).or_else(|| self.owner.failure())
            .or_else(|| error(&self.owner_result)).or_else(|| self.context.failure())
            .or_else(|| self.healthy_context.failure())
            .or_else(|| error(&self.context_prepared)).or_else(|| error(&self.context_result))
            .or_else(|| error(&self.context_binding)).or_else(|| self.service.failure())
            .or_else(|| self.fallback_policy.failure()).or_else(|| error(&self.service_result))
            .or_else(|| error(&self.final_alive)).or_else(|| error(&self.final_binding))
            .or_else(|| error(&self.completion))
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
