//! Adapts the one lower first-table router to existing upper startup owners.
//!
//! Selected profile and enrollment remain in the same opaque Parts until the
//! actual Bank consumes their StartupOpening. Only genuine no-C parts enter
//! ordinary admission. Nix, Git, Publisher and image inputs keep their existing
//! upper owners and are moved from that same routing result once.

use std::os::fd::OwnedFd;

use aos_sandbox_broker::controller_receiving::{
    ControllerInitialDeliveryCaptureV1, ControllerInitialDeliveryPartsV1,
    ControllerStartupOpeningV1, ControllerLaunchImageDeliveryOriginalV1,
};
use aos_sandbox_broker::controller_receiving::capture_ordinary_controller_initial_delivery_v1;

use crate::normal_root::NormalRootStartupErrorV1;
use crate::normal_root::nix_startup::ProductionControllerNixStartupCaptureV1;

pub use aos_sandbox_broker::controller_receiving::ControllerInitialDeliveryFailureRefV1 as ControllerInitialCaptureFailureRefV1;

/// Retains the same opaque router output until its real startup handoff.
///
/// No caller files, decoded profile or separately chosen C construct it.
/// Auxiliary descriptor DATA remain associated with this original table.
pub struct ProductionControllerNormalRootCaptureV1 {
    parts: Option<ControllerInitialDeliveryPartsV1>,
    ordinary_capture: Option<aos_sandbox_broker::controller_receiving::profile::ControllerProfileCaptureV1>,
    ordinary_entered: bool,
    nix: Option<ProductionControllerNixStartupCaptureV1>,
    git: Option<OwnedFd>,
}

/// Keeps Publisher and launch-image descriptors with their existing consumers.
pub type ProductionControllerNormalRootStartupPartsV1 = (
    ProductionControllerNormalRootCaptureV1,
    Option<OwnedFd>,
    ControllerLaunchImageDeliveryOriginalV1,
);

impl ProductionControllerNormalRootCaptureV1 {
    /// Creates resident first-table capture storage without IO or admission.
    #[must_use]
    pub fn begin_retained_capture(
        publisher: bool,
        nix_enabled: bool,
        git_source_cut: bool,
    ) -> ProductionControllerInitialCaptureAttemptV1 {
        ProductionControllerInitialCaptureAttemptV1 {
            inner: ControllerInitialDeliveryCaptureV1::new(publisher, nix_enabled, git_source_cut),
            pending: None,
            handoff_failed: false,
        }
    }

    /// Captures the unchanged ordinary fixed startup table.
    ///
    /// # Errors
    /// Preserves malformed roles, foreign activation or native duplication refusal.
    pub fn capture(publisher: bool) -> Result<ProductionControllerNormalRootStartupPartsV1, NormalRootStartupErrorV1> {
        Self::capture_with_backends(publisher, false, false)
    }

    /// Captures only the declared optional backend roles in the same table.
    ///
    /// # Errors
    /// Preserves ordinary initial table, role or duplication refusal.
    pub fn capture_with_backends(
        publisher: bool,
        nix_enabled: bool,
        git_source_cut: bool,
    ) -> Result<ProductionControllerNormalRootStartupPartsV1, NormalRootStartupErrorV1> {
        let mut parts = capture_ordinary_controller_initial_delivery_v1(publisher, nix_enabled, git_source_cut)
            .map_err(NormalRootStartupErrorV1::from)?;
        let auxiliary = parts.take_auxiliary_parts_once()
            .ok_or(NormalRootStartupErrorV1::Activation)?;
        Ok(Self::from_parts(parts, auxiliary))
    }

    fn from_parts(
        parts: ControllerInitialDeliveryPartsV1,
        auxiliary: (
            Option<aos_sandbox_broker::controller_receiving::ControllerNixDeliveryDataV1>,
            Option<OwnedFd>, Option<OwnedFd>, ControllerLaunchImageDeliveryOriginalV1,
        ),
    ) -> ProductionControllerNormalRootStartupPartsV1 {
        let (nix, git, publisher, image) = auxiliary;
        let nix = nix.map(|nix| {
            let (pid1, profile, root_profile, image_present) = nix.into_parts();
            ProductionControllerNixStartupCaptureV1::from_initial_table(
                pid1, profile, root_profile, image_present,
            )
        });
        (Self {
            parts: Some(parts), ordinary_capture: None, ordinary_entered: false, nix, git,
        }, publisher, image)
    }

    /// Moves this table's existing Nix inputs once to their original consumer.
    #[must_use]
    pub fn take_nix_startup(&mut self) -> Option<ProductionControllerNixStartupCaptureV1> {
        self.nix.take()
    }

    /// Moves this table's original Git listener DATA once.
    #[must_use]
    pub fn take_git_source_listener(&mut self) -> Option<OwnedFd> {
        self.git.take()
    }

    /// Reports actual paired enrollment delivery without creating an original.
    #[must_use]
    pub fn has_original_enrollment_v1(&self) -> bool {
        self.parts.as_ref().is_some_and(ControllerInitialDeliveryPartsV1::has_original_enrollment_v1)
    }

    /// Moves selected profile and enrollment together to their sole Bank owner.
    ///
    /// The Native carrier shape comes from the sole private Domain supplier.
    /// No separately supplied C, profile capture, file or model can be paired.
    /// Auxiliary consumers must first take their actual Nix and Git inputs.
    #[must_use]
    #[doc(hidden)]
    pub fn take_selected_startup_once_v1(
        &mut self,
    ) -> Option<ControllerStartupOpeningV1> {
        if !self.has_original_enrollment_v1() || self.nix.is_some() || self.git.is_some() {
            return None;
        }
        let layout = crate::controller_resource_reservation::initial_profile_native_layout_v1();
        Some(ControllerStartupOpeningV1::from_initial_delivery(self.parts.take()?, layout))
    }

    /// Begins only this actual no-C capture's retained ordinary admission.
    ///
    /// A rejected opaque Parts value stays on this owner. Selected profile and
    /// enrollment must enter the whole paired StartupOpening instead.
    #[doc(hidden)]
    pub fn begin_retained_ordinary_admission_once_v1(
        &mut self,
    ) -> Option<super::admission::ProductionControllerSelectedProfileAdmissionV1> {
        if self.ordinary_entered || self.git.is_some() || self.has_original_enrollment_v1() {
            return None;
        }
        self.ordinary_entered = true;
        let parts = self.parts.take()?;
        self.ordinary_capture = Some(match parts.into_ordinary_profile() {
            Ok(capture) => capture,
            Err(parts) => {
                self.parts = Some(parts);
                return None;
            }
        });
        let capture = self.ordinary_capture.take()?;
        match capture.begin_retained_ordinary_admission_v1() {
            Ok(inner) => Some(super::admission::ProductionControllerSelectedProfileAdmissionV1::new(
                inner, self.nix.take(),
            )),
            Err(capture) => {
                self.ordinary_capture = Some(capture);
                None
            }
        }
    }

    /// Consumes only ordinary no-C delivery through the canonical recipe.
    ///
    /// # Errors
    /// Rejects selected enrollment, unmoved auxiliary roles or ordinary refusal.
    pub fn admit_selected(
        mut self,
        uid: u32,
        gid: u32,
    ) -> Result<Option<super::ProductionControllerNormalRootProfileV1>, NormalRootStartupErrorV1> {
        if self.has_original_enrollment_v1() || self.nix.is_some() || self.git.is_some() {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        let parts = self.parts.take().ok_or(NormalRootStartupErrorV1::Activation)?;
        let capture = parts.into_ordinary_profile().map_err(|_| NormalRootStartupErrorV1::Activation)?;
        capture.admit_ordinary(uid, gid)
            .map(|profile| profile.map(super::ProductionControllerNormalRootProfileV1::from_admitted_original_v1))
            .map_err(Into::into)
    }

}

/// Retains lower table/duplication failures through the actual upper handoff.
#[must_use]
pub struct ProductionControllerInitialCaptureAttemptV1 {
    inner: ControllerInitialDeliveryCaptureV1,
    pending: Option<ControllerInitialDeliveryPartsV1>,
    handoff_failed: bool,
}

impl ProductionControllerInitialCaptureAttemptV1 {
    /// Performs the existing same-table capture once with full native custody.
    ///
    /// # Errors
    /// Borrows the actual lower initial table, role or duplication failure.
    pub fn capture_once(&mut self) -> Result<(), ControllerInitialCaptureFailureRefV1<'_>> {
        if self.handoff_failed {
            return Err(ControllerInitialCaptureFailureRefV1::Closed);
        }
        self.inner.capture_once()
    }

    /// Borrows the actual first lower cause without another observation.
    #[must_use]
    pub fn first_failure(&self) -> Option<ControllerInitialCaptureFailureRefV1<'_>> {
        self.inner.first_failure().or_else(|| {
            self.handoff_failed.then_some(ControllerInitialCaptureFailureRefV1::Closed)
        })
    }

    /// Moves the completed original routing result to existing upper owners.
    ///
    /// A contradictory auxiliary handoff keeps the actual Parts resident and
    /// closed. There is no fallible native action after the successful move.
    #[must_use]
    pub fn take_completed_parts(&mut self) -> Option<ProductionControllerNormalRootStartupPartsV1> {
        if self.handoff_failed || self.pending.is_some() {
            return None;
        }
        self.pending = self.inner.take_completed_parts();
        let auxiliary = self.pending.as_mut()?.take_auxiliary_parts_once();
        let Some(auxiliary) = auxiliary else {
            self.handoff_failed = true;
            return None;
        };
        Some(ProductionControllerNormalRootCaptureV1::from_parts(self.pending.take()?, auxiliary))
    }
}

impl Drop for ProductionControllerInitialCaptureAttemptV1 {
    fn drop(&mut self) {
        if self.handoff_failed || self.pending.is_some() {
            // The lower route has transferred its armed custody. This owner
            // must not release an unconsumed or contradictory paired handoff.
            std::process::abort();
        }
    }
}
