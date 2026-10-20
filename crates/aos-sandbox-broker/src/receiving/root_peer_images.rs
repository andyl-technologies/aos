//! Owns the shared native policy and immutable-image inputs for a Root peer.
//!
//! The actual fixed role separately captures its own inherited profile and
//! prepays the exact selected shape under its original. This object retains
//! native comparison inputs only; caller-supplied profile DATA cannot create a
//! Root admission, role borrower, budget or positive service-purpose grant.

use std::collections::TryReserveError;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::selinux_policy::{PolicyReadbackError,
    RetainedLiveSelinuxPolicyReadbackV1};

use crate::immutable_image::ImmutableFileAcquisitionOriginalV1;
use crate::profile_data::{ControllerProfileErrorV1, images,
    schema::NormalRootProfileV1};

/// Reports an entered Root-image comparison while its native cause stays owned.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Root peer image observation is incomplete or differs")]
pub struct RootPeerImagesClosedV1;

/// Owns the original reached policy, image or allocation failure as DATA.
#[derive(Debug, thiserror::Error)]
pub enum RootPeerImageObservationErrorV1 {
    /// Preserves the shared fixed profile classification.
    #[error(transparent)]
    Profile(#[from] ControllerProfileErrorV1),
    /// Retains the actual immutable observation error.
    #[error(transparent)]
    Image(#[from] images::ImageObservationErrorV1),
    /// Retains the original live policy failure.
    #[error(transparent)]
    Policy(#[from] PolicyReadbackError),
    /// Retains the actual failed pending-owner vector reservation.
    #[error(transparent)]
    Allocation(#[from] TryReserveError),
}

/// Retains live policy and actual immutable Root-runtime/PID1/policy image pins.
#[derive(Default)]
pub struct RootPeerImageObservationsV1 {
    pins: Vec<ImmutableFileAcquisitionOriginalV1>,
    policy: RetainedLiveSelinuxPolicyReadbackV1,
    result: Option<Result<(), RootPeerImageObservationErrorV1>>,
    entered: bool,
    closed: bool,
}

impl RootPeerImageObservationsV1 {
    /// Creates empty destinations without opening or validating a role.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prices the actual bounded model's selected paths and native carriers.
    ///
    /// Returns `None` on checked geometry overflow. The bound performs no IO
    /// and supplies neither financial admission nor an accepted profile.
    #[must_use]
    pub fn receiving_demand_v1(profile: &NormalRootProfileV1) -> Option<ResourceVector> {
        let policy = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        let memory = size_of::<Self>().checked_add(policy.memory_bytes)?
            .checked_add(64 * 1024)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(policy.open_files).ok()?);
        for pin in profile.runtime_files.iter().chain([
            &profile.pid1, &profile.canonical_policy, &profile.source_policy,
            &profile.effective_matrix,
        ]) {
            // Each resident acquisition supplies its own actual initial native
            // prefix, path/canonical names and active construction byte peak.
            let acquisition = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(pin.path.len())?;
            demand = demand.checked_add(acquisition).ok()?;
        }
        // Rust owner/result fields do not create resident namespace entries.
        // The caller separately owns the bounded profile model and true
        // journal/model namespace liability under its same finite original.
        Some(demand)
    }

    /// Captures the actual live policy and each selected pending file once.
    ///
    /// # Errors
    /// Retains live policy, bounded allocation or immutable pin failures. The
    /// actual pending destination is published before each native acquisition.
    pub fn observe_once(&mut self, profile: &NormalRootProfileV1)
        -> Result<(), RootPeerImagesClosedV1>
    {
        if self.entered {
            self.closed = true;
            return Err(RootPeerImagesClosedV1);
        }
        self.entered = true;
        self.result = Some((|| {
            self.policy.verify_once(&profile.canonical_policy.path)?;
            if self.policy.verified().map(|policy| policy.digest())
                != Some(profile.canonical_policy.sha256)
            {
                return Err(ControllerProfileErrorV1::Confinement.into());
            }
            let count = profile.runtime_files.len().checked_add(4)
                .ok_or(ControllerProfileErrorV1::Profile)?;
            self.pins.try_reserve_exact(count)?;
            if self.pins.capacity() > count {
                return Err(ControllerProfileErrorV1::Profile.into());
            }
            for pin in profile.runtime_files.iter().chain([
                &profile.pid1, &profile.canonical_policy, &profile.source_policy,
                &profile.effective_matrix,
            ]) {
                self.pins.push(ImmutableFileAcquisitionOriginalV1::new());
                let pending = self.pins.last_mut().ok_or(ControllerProfileErrorV1::Image)?;
                let executable = pin.path == profile.executable.path
                    || pin.path == profile.loader.path || pin.path == profile.pid1.path;
                images::park_selected_pin_retaining_v1(pin, executable, pending)?;
            }
            Ok(())
        })());
        if self.is_complete() { Ok(()) } else { Err(RootPeerImagesClosedV1) }
    }

    /// Moves only the actual outer error to an existing caller's owning result.
    ///
    /// Native and partial acquisition owners remain here. This DATA adapter
    /// preserves an existing role's error type and drop order without cloning
    /// IO or allocation errors; it cannot produce a completed observation.
    #[must_use]
    pub fn take_failure_once(&mut self) -> Option<RootPeerImageObservationErrorV1> {
        match self.result.take() {
            Some(Err(cause)) => Some(cause),
            other => {
                self.result = other;
                None
            }
        }
    }

    /// Rechecks the same originally captured immutable inputs without reopening a role.
    ///
    /// # Errors
    /// Retains native image currentness failures and refuses incomplete capture.
    /// The actual role separately checks its own original profile and interval.
    pub fn recheck_images(&mut self) -> Result<(), ControllerProfileErrorV1> {
        if !self.is_complete() { return Err(ControllerProfileErrorV1::Profile); }
        for pin in &mut self.pins {
            pin.revalidate_completed().map_err(|_| ControllerProfileErrorV1::Image)?;
        }
        Ok(())
    }

    /// Returns whether its native input capture has completely compared equal.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && self.failure().is_none()
    }

    /// Borrows the actual policy/image cause before its fixed outer projection.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.policy.failure().or_else(|| self.pins.iter()
            .find_map(ImmutableFileAcquisitionOriginalV1::failure))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| self.closed.then_some(&RootPeerImagesClosedV1 as _))
    }
}
