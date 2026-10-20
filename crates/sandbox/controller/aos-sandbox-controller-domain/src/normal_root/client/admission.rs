//! Retains ordinary admission beside its original upper Nix custody.
//!
//! Selected C admission lives only in the paired StartupOpening owned by Bank.
//! This wrapper cannot accept an original C, replacement profile or raw files.

use std::os::fd::OwnedFd;

use aos_sandbox_broker::controller_receiving::profile::{
    ControllerSelectedProfileAdmissionV1, ControllerSelfProfileOriginalV1,
};

use super::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::normal_root::nix_startup::ProductionControllerNixStartupCaptureV1;

pub use aos_sandbox_broker::controller_receiving::profile::ControllerProfileAdmissionFailureV1;

/// Keeps the actual ordinary lower admission and its original auxiliary Nix role.
#[must_use = "retain the whole failed admission and its auxiliary originals"]
pub struct ProductionControllerSelectedProfileAdmissionV1 {
    inner: ControllerSelectedProfileAdmissionV1,
    nix: Option<ProductionControllerNixStartupCaptureV1>,
    completed: Option<(Option<ControllerSelfProfileOriginalV1>, Option<OwnedFd>)>,
    closed: Option<NormalRootStartupErrorV1>,
    moved: bool,
}

impl ProductionControllerSelectedProfileAdmissionV1 {
    pub(super) fn new(
        inner: ControllerSelectedProfileAdmissionV1,
        nix: Option<ProductionControllerNixStartupCaptureV1>,
    ) -> Self {
        Self { inner, nix, completed: None, closed: None, moved: false }
    }

    /// Runs only the actual lower ordinary admission once.
    ///
    /// # Errors
    /// Borrows its original retained profile, image, confinement or native cause.
    pub fn admit_selected_once(
        &mut self,
        uid: u32,
        gid: u32,
    ) -> Result<Option<&ControllerSelfProfileOriginalV1>, &ControllerProfileAdmissionFailureV1> {
        self.inner.admit_selected_once(uid, gid)
    }

    /// Borrows the same lower admission's actual first refusal.
    #[must_use]
    pub fn first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.first_failure().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Moves only positively completed ordinary roles into their upper owners.
    ///
    /// The returned unused absence duplicate is parked on the same original Nix
    /// capture before any output leaves this wrapper. All refused tuples remain
    /// resident here, including the actual lower profile and descriptor.
    ///
    /// # Errors
    /// Refuses repeated movement, incomplete lower admission or a missing Nix pair.
    fn take_admitted_roles(
        &mut self,
    ) -> Result<(
        Option<ProductionControllerNormalRootProfileV1>,
        Option<ProductionControllerNixStartupCaptureV1>,
    ), &(dyn std::error::Error + 'static)> {
        if self.moved || self.closed.is_some() || self.completed.is_some() {
            self.closed.get_or_insert(NormalRootStartupErrorV1::Profile);
            return Err(self.closed.as_ref().map(|cause| cause as &dyn std::error::Error)
                .unwrap_or(&CLOSED));
        }
        match self.inner.take_completed_ordinary_v1() {
            Ok(completed) => self.completed = Some(completed),
            Err(cause) => return Err(cause),
        }
        let Some((profile, unused)) = self.completed.as_mut() else {
            self.closed = Some(NormalRootStartupErrorV1::Profile);
            return Err(&CLOSED);
        };
        if unused.is_some() && (profile.is_some()
            || self.nix.as_ref().is_none_or(|nix| !nix.can_park_absent_root_delivery()))
        {
            self.closed = Some(NormalRootStartupErrorV1::Profile);
            return Err(self.closed.as_ref().map(|cause| cause as &dyn std::error::Error)
                .unwrap_or(&CLOSED));
        }
        if let (Some(nix), Some(delivery)) = (self.nix.as_mut(), unused.take()) {
            nix.park_absent_root_delivery(delivery);
        }
        let profile = profile.take().map(ProductionControllerNormalRootProfileV1::from_admitted_original_v1);
        self.completed = None;
        self.moved = true;
        Ok((profile, self.nix.take()))
    }
    /// Moves only the actual successful ordinary result into its typed image binding.
    ///
    /// # Errors
    /// Preserves the same incomplete, repeated or contradictory admission cause.
    #[doc(hidden)]
    pub fn take_admitted_binding_once(&mut self) -> Result<(
        crate::normal_root::ControllerAdmittedStartupProfileV1,
        Option<ProductionControllerNixStartupCaptureV1>,
    ), &(dyn std::error::Error + 'static)> {
        self.take_admitted_roles().map(|(profile, nix)| (
            crate::normal_root::ControllerAdmittedStartupProfileV1::from_completed_admission(profile), nix,
        ))
    }

}

static CLOSED: NormalRootStartupErrorV1 = NormalRootStartupErrorV1::Profile;

impl Drop for ProductionControllerSelectedProfileAdmissionV1 {
    fn drop(&mut self) {
        if !self.moved {
            std::process::abort();
        }
    }
}
