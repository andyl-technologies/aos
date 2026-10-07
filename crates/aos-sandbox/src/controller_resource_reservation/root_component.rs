//! Retains the original Root subdivision of the already-paid Components grant.
//!
//! R is one permanent purpose-13 claim, not a Root account or operation loan.
//! PID1 installs its whole-service bounds before exec, including the negative
//! prefix that authenticates these original image and delivery descriptors.
//! Native DATA never reconstructs that producer or refunds a dead invocation.

use std::fs::File;
use std::os::fd::OwnedFd;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::inherited_fd::RootInitialActivationTableV1;

use super::{ResourceReservationErrorV1, bootstrap};

pub(super) fn require_service_envelope(
    envelope: ResourceVector,
) -> Result<(), ResourceReservationErrorV1> {
    let cpu = envelope.get(D::CpuMicrosPerPeriod);
    let memory = envelope.get(D::MemoryBytes);
    if cpu == 0 || cpu % 1000 != 0 || cpu.checked_mul(10).is_none()
        || memory == 0 || memory % 4096 != 0
        || envelope.get(D::Pids) < 2 || envelope.get(D::Pids) == u64::MAX
        || envelope.get(D::OpenFiles) < 80 || envelope.get(D::OpenFiles) == u64::MAX
        || envelope.get(D::ConcurrentOperations) == 0
    {
        return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
    }
    Ok(())
}

// This owner captures only the current process's original four-role table.
// No descriptor, vector, observation or receipt argument constructs payment.
// The coarse caller error never replaces its owning native/canonical Result.
pub(crate) struct RootReceivingOriginalV1 {
    table: RootInitialActivationTableV1,
    entries: [Option<OwnedFd>; 4],
    names: Option<Result<Vec<String>, crate::normal_root::NormalRootStartupErrorV1>>,
    role_error: Option<ResourceReservationErrorV1>,
    policy: Option<File>,
    delivery: Option<File>,
    pid1: Option<OwnedFd>,
    profile: Option<OwnedFd>,
    process: u32,
    original: Option<Result<bootstrap::OriginalEnrollment, ResourceReservationErrorV1>>,
    shape: Option<Result<(), ResourceReservationErrorV1>>,
    armed: bool,
}

impl RootReceivingOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            table: RootInitialActivationTableV1::new(),
            entries: [const { None }; 4],
            names: None,
            role_error: None,
            policy: None,
            delivery: None,
            pid1: None,
            profile: None,
            process: std::process::id(),
            original: None,
            shape: None,
            armed: true,
        }
    }

    // The fixed table precedes even names parsing. All four returned OFDs are
    // parked before role selection; rejection keeps their actual owner/error.
    pub(crate) fn capture_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.names.is_some() || self.role_error.is_some() || self.process != std::process::id() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.table.observe_once().is_err() {
            self.role_error = Some(ResourceReservationErrorV1::EnrollmentUnavailable);
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        self.entries = self.table.take_completed_entries()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.names = Some(crate::normal_root::startup::names(4));
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok());
        let Some(names) = names else {
            self.role_error = Some(ResourceReservationErrorV1::EnrollmentUnavailable);
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        };
        let roles = [
            "aos-normal-root-pid1-image",
            "aos-normal-root-profile",
            "aos-resource-image-policy-v1",
            "aos-resource-pid1-enrollment-v1",
        ];
        if names.len() != roles.len()
            || roles.iter().any(|role| names.iter().filter(|name| name.as_str() == *role).count() != 1)
        {
            self.role_error = Some(ResourceReservationErrorV1::EnrollmentUnavailable);
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        for (name, entry) in names.iter().zip(&mut self.entries) {
            match name.as_str() {
                "aos-normal-root-pid1-image" => self.pid1 = entry.take(),
                "aos-normal-root-profile" => self.profile = entry.take(),
                "aos-resource-image-policy-v1" => self.policy = entry.take().map(File::from),
                "aos-resource-pid1-enrollment-v1" => self.delivery = entry.take().map(File::from),
                _ => return Err(ResourceReservationErrorV1::EnrollmentUnavailable),
            }
        }
        Ok(())
    }

    pub(crate) fn take_image_pair(&mut self) -> Option<(OwnedFd, OwnedFd)> {
        if !matches!(self.shape, Some(Ok(()))) || self.pid1.is_none() || self.profile.is_none() {
            return None;
        }
        Some((self.pid1.take()?, self.profile.take()?))
    }

    pub(crate) fn authenticate_once(&mut self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.original.is_some() || self.role_error.is_some() || self.names.is_none()
            || self.process != std::process::id()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let policy = self.policy.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let delivery = self.delivery.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.original = Some(bootstrap::observe_original_pair(policy, delivery));
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let envelope = original.policy.root_receiving
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.shape = Some(require_service_envelope(envelope));
        if !matches!(self.shape, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(envelope)
    }

    pub(crate) fn require_recipient(
        &self,
        invocation: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.shape, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if self.process != std::process::id()
            || original.recipient_invocation != invocation
            || original.identity.invocation != producer
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(())
    }

    pub(crate) fn envelope(&self) -> Option<ResourceVector> {
        if !matches!(self.shape, Some(Ok(()))) {
            return None;
        }
        self.original.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|original| original.policy.root_receiving)
    }

}

impl Drop for RootReceivingOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}
