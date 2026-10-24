//! Owns the actual Root role's cumulative profile and selected prefixes.
//!
//! The one-time layout supplies adapter geometry only. Each permit is derived,
//! staged, and retained on the same Initial that owns enrollment and native
//! receiving; later borrowers cannot reconstruct it from account high-water.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{
    RootEnrollmentErrorV1, RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootNativeAdmissionErrorV1, RootObservationErrorV1,
};

/// Borrows the same settled Initial and its actual selected role prefix.
///
/// This lender carries no journal, accepted peer, or writer completion. A
/// native startup provision must perform those later stages itself.
pub struct RootSelectedProvisionBorrowV1<'initial> {
    initial: &'initial mut RootInitialReceivingOriginalV1,
    financial: RootJournalFinancialOriginalV1,
}

impl RootInitialReceivingOriginalV1 {
    pub(super) fn role_prefix_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<super::NativeLayoutDemand>()
            .checked_mul(3)?
            .checked_add(size_of::<Option<[ResourceVector; 3]>>().checked_mul(3)?
                .checked_add(size_of::<Option<ResourceVector>>().checked_mul(6)?)?)?
            .checked_add(
                size_of::<Result<ResourceVector, RootNativeAdmissionErrorV1>>().checked_mul(6)?,
            )?
            .checked_add(size_of::<Result<(), RootEnrollmentErrorV1>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Result<RootSelectedProvisionBorrowV1<'static>, RootObservationErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(2)?)?
            .checked_add(
                size_of::<Result<RootJournalFinancialOriginalV1, RootObservationErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Result<ResourceVector, RootObservationErrorV1>>().checked_mul(3)?,
            )?
            .checked_add(size_of::<ResourceVector>().checked_mul(12)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(3)?)
    }

    /// Stages the actual fixed role layout before entering native profile IO.
    ///
    /// # Errors
    /// Refuses repeated entry, missing layout, failed originals, or a failed
    /// actual Stage. Independent native profile posts retain their old engine.
    pub fn receive_role_profile_once_v1(&mut self) -> Result<(), RootEnrollmentErrorV1> {
        if self.role_profile_prefix.is_some()
            || self.process_id_v1() != std::process::id()
            || !matches!(self.root_shape_result_v1(), Some(Ok(())))
        {
            return Err(RootEnrollmentErrorV1::Conflict);
        }
        self.role_profile_prefix = Some((|| {
            let invalid = || RootObservationErrorV1::Profile;
            let envelope = self
                .enrollment_v1()
                .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                .ok_or_else(invalid)?;
            let [adapter, _, _] = self.role_layout.root_role_adapters().ok_or_else(invalid)?;
            let native = Self::fixed_profile_prefix_demand_v1().ok_or_else(invalid)?;
            let demand = native.checked_add(adapter)?;
            envelope.checked_sub(demand)?;
            self.require_receiving_demand_v1(demand)
                .map_err(|_| invalid())?;
            Ok(demand)
        })());
        if !matches!(self.role_profile_prefix, Some(Ok(_))) {
            return Err(RootEnrollmentErrorV1::Unavailable);
        }
        self.receive_profile_once()
    }

    /// Stages the same role prefix for selected image and currentness owners.
    ///
    /// # Errors
    /// Refuses missing actual profile completion, reentry, layout overflow, or
    /// a failed original Stage. No selected startup or role is manufactured.
    pub fn admit_role_selected_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        let invalid = || RootObservationErrorV1::Service;
        if self.role_selected_prefix.is_some()
            || self.failure().is_some()
            || self.process_id_v1() != std::process::id()
            || !matches!(self.recipient_binding, Some(Ok(())))
        {
            return Err(invalid());
        }
        self.role_selected_prefix = Some((|| {
            let envelope = self
                .enrollment_v1()
                .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
                .ok_or_else(invalid)?;
            let prefix = self
                .role_profile_prefix
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied()
                .ok_or_else(invalid)?;
            let [_, selected_adapter, currentness_adapter] =
                self.role_layout.root_role_adapters().ok_or_else(invalid)?;
            let selected = super::super::RootSelectedStartupOriginalV1::demand(self)?
                .checked_add(selected_adapter)?;
            let currentness = super::super::RootServiceCurrentnessOriginalV1::demand()
                .ok_or_else(invalid)?
                .checked_add(currentness_adapter)?;
            let disposed_names = self
                .kernel_capture_v1()
                .and_then(|kernel| kernel.settled_named_descriptor_peak_v1())
                .ok_or_else(invalid)?;
            // Only the named descriptors really disposed by this original are
            // reused. All memory and permanent observer reserves remain paid.
            let currentness = currentness.with(
                D::OpenFiles,
                currentness.get(D::OpenFiles).saturating_sub(disposed_names),
            );
            let demand = prefix.checked_add(selected)?.checked_add(currentness)?;
            envelope.checked_sub(demand)?;
            self.require_receiving_demand_v1(demand)
                .map_err(|_| invalid())?;
            Ok(demand)
        })());
        if matches!(self.role_selected_prefix, Some(Ok(_))) {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    /// Returns the exact held selected prefix as comparison DATA.
    ///
    /// This scalar does not construct a provision lender or native role.
    #[must_use]
    pub fn selected_role_prefix_data_v1(&self) -> Option<ResourceVector> {
        self.role_selected_prefix.as_ref()?.as_ref().ok().copied()
    }

    /// Borrows the retained role profile cause before any coarse projection.
    #[must_use]
    pub fn role_profile_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.role_profile_prefix
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    /// Borrows the retained role selected cause before any coarse projection.
    #[must_use]
    pub fn role_selected_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.role_selected_prefix
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    /// Lends actual selected provision custody after the native serving move.
    ///
    /// # Errors
    /// Refuses missing role prefixes, incomplete native settlement, or another
    /// process. The passive association performs no currentness sample.
    pub fn borrow_selected_provision_v1(
        &mut self,
    ) -> Result<RootSelectedProvisionBorrowV1<'_>, RootObservationErrorV1> {
        if self.permanent.is_none()
            || self.selected_role_prefix_data_v1().is_none()
            || self.process_id_v1() != std::process::id()
            || !matches!(self.recipient_binding, Some(Ok(())))
        {
            return Err(RootObservationErrorV1::Service);
        }
        let financial = RootJournalFinancialOriginalV1::from_selected_role_provision_v1(self)?;
        Ok(RootSelectedProvisionBorrowV1 {
            initial: self,
            financial,
        })
    }
}

impl RootInitialReceivingOriginalV1 {
    /// Copies this real constructor's fixed listener geometry without a grant.
    #[must_use]
    pub fn policy_listener_layout_data_v1(&self) -> Option<ResourceVector> {
        self.role_layout.root_listener_layout()
    }
}

impl RootSelectedProvisionBorrowV1<'_> {
    /// Borrows the same actual Initial for native physical preparation.
    pub fn initial_mut_v1(&mut self) -> &mut RootInitialReceivingOriginalV1 {
        self.initial
    }

    /// Borrows the same actual financial original without a new account.
    #[must_use]
    pub fn financial_original_v1(&self) -> &RootJournalFinancialOriginalV1 {
        &self.financial
    }

    /// Returns the exact original selected prefix without an observation.
    ///
    /// # Errors
    /// Refuses an absent or failed once result; no replacement prefix is made.
    pub fn selected_prefix_data_v1(&self) -> Result<ResourceVector, RootObservationErrorV1> {
        self.initial
            .selected_role_prefix_data_v1()
            .ok_or(RootObservationErrorV1::Service)
    }
}
