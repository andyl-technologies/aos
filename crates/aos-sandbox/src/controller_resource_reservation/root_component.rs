//! Retains the original Root subdivision of the already-paid Components grant.
//!
//! R is one permanent purpose-13 claim, not a Root account or operation loan.
//! PID1 installs its whole-service bounds before exec, including the negative
//! prefix that authenticates these original image and delivery descriptors.
//! Native DATA never reconstructs that producer or refunds a dead invocation.

use std::error::Error;
use std::fs::File;
use std::os::fd::OwnedFd;

use aos_sandbox_core::ResourceVector;
use aos_sandbox_linux::inherited_fd::RootInitialActivationTableV1;

use super::{ResourceReservationErrorV1, bank, bootstrap};

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
    pair: bootstrap::OriginalEnrollmentPairAttemptV1,
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
            pair: bootstrap::OriginalEnrollmentPairAttemptV1::new(),
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

    pub(crate) fn authenticate_once(&mut self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.original.is_some() || self.role_error.is_some() || self.names.is_none()
            || self.process != std::process::id()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let policy = self.policy.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let delivery = self.delivery.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        // The shared destination keeps the same fixed buffers, native
        // observations and first error; the copied enrollment is DATA only.
        self.original = Some(match self.pair.observe_once(policy, delivery) {
            Ok(original) => Ok(*original),
            Err(_) => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
        });
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.shape = Some((original.policy.bootstrap_provisions().root_receiving)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
            .and_then(|envelope| bank::require_root_service_envelope(envelope)
                .map_err(ResourceReservationErrorV1::from)));
        if !matches!(self.shape, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        (original.policy.bootstrap_provisions().root_receiving)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.table.failure().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.pair.failure())
            .or_else(|| self.role_error.as_ref()
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.original.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.shape.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}

impl Drop for RootReceivingOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}
