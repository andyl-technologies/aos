//! Borrows the same Source pair for the finite recovered enrollment purpose.
//!
//! This closed wrapper selects no transaction and exposes no append. Physical
//! name sampling, independent after and disposal share the provisioning engine.

use super::*;
use crate::controller_receiving::bank_launch::ControllerRecoveredEnrollmentReceivingV2;

/// Retains Source bookends paid by the actual recovered enrollment original.
#[must_use = "retain Source custody through enrollment and all independent posts"]
pub struct SourceRecoveredEnrollmentCurrentnessOriginalV2 {
    native: SourceProvisioningCurrentnessOriginalV1,
}

impl SourceRecoveredEnrollmentCurrentnessOriginalV2 {
    /// Prices the actual Source pair plus this retained constructor carrier.
    ///
    /// # Errors
    /// Returns fixed native name geometry or checked compiled-layout overflow.
    pub fn receiving_demand_v2() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let wrapper = u64::try_from(std::mem::size_of::<Self>())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        Ok(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, wrapper))?)
    }

    /// Borrows the original Source before/after refusal without cloning.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> { self.native.failure() }
}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Arms the actual Source pair after the finite enrollment's complete debit.
    ///
    /// # Errors
    /// Refuses overlap, wrong original, failed native entry or same-B capacity.
    /// A returned failed before observation retains its independent owed post.
    pub fn begin_recovered_enrollment_currentness_once_v2<C>(
        &mut self, receiving: &mut ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, co_resident: ResourceVector,
    ) -> Result<SourceRecoveredEnrollmentCurrentnessOriginalV2, ControllerBankLaunchErrorV1> {
        self.require_idle().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        receiving.require_source_original_v2(&self.original, controller, launch, profile)?;
        let complete = co_resident.checked_add(
            SourceRecoveredEnrollmentCurrentnessOriginalV2::receiving_demand_v2()?)?;
        receiving.require_complete_representation_v2(controller, launch, profile, complete)?;
        Ok(SourceRecoveredEnrollmentCurrentnessOriginalV2 {
            native: self.prepare_provisioning_pair_v1(false)?,
        })
    }

    /// Rejoins this unchanged Source prefix while enrollment remains current.
    ///
    /// # Errors
    /// Refuses another prefix, failed before, completed pair or foreign payer.
    pub fn require_recovered_enrollment_readonly_current_v2<C>(&self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
        receiving: &ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_binding_v1(&mut original.native)?;
        receiving.require_source_original_v2(&self.original, controller, launch, profile)
    }

    /// Attempts the independent paid Source after despite enrollment refusal.
    ///
    /// # Errors
    /// Retains actual same-Source native, prefix, overlap or reentry refusal.
    pub fn finish_recovered_enrollment_currentness_once_v2(&self,
        original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
    ) -> Result<(), SourceNativeErrorV1> {
        self.finish_provisioning_currentness_once_v1(&mut original.native)
    }

    /// Disposes Source only after positive enrollment C and Source native posts.
    ///
    /// # Errors
    /// Refuses changed prefix, foreign payer or unfinished/failed native custody.
    pub fn dispose_recovered_enrollment_currentness_after_posts_v2<C>(
        &mut self, original: &mut SourceRecoveredEnrollmentCurrentnessOriginalV2,
        receiving: &ControllerRecoveredEnrollmentReceivingV2,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_provisioning_disposal_v1(&original.native)?;
        receiving.require_completed_original_v2(controller, launch, profile)?;
        receiving.require_completed_source_original_v2(&self.original)?;
        self.dispose_provisioning_pair_v1(&mut original.native);
        Ok(())
    }
}
