//! Retains one fresh enrollment interval after the actual recovered D/X debits.
//!
//! The same baseline ledger, names and private Producer engine remain active.
//! This finite native original grants no Ready, operation or semantic replay;
//! the upper owner still joins fresh Source and clock bookends with complete
//! physical reconciliation and the unchanged authorization horizon.

use super::*;

mod funding_publication;
use funding_publication::PublicationOriginalV1;

/// Retains the separately paid, once-only successor enrollment native interval.
#[must_use = "retain every enrollment prefix through all independently owed posts"]
pub struct ControllerRecoveredEnrollmentReceivingV2 {
    predecessor: Result<(), ControllerBankLaunchErrorV1>,
    native: ControllerCreateProvisioningReceivingV1,
    publication: PublicationOriginalV1,
    publication_selected: bool,
}

impl ControllerRecoveredEnrollmentReceivingV2 {
    /// Prices this actual carrier and the shared fixed names/profile engine.
    ///
    /// # Errors
    /// Returns checked compiled-layout or native supplier overflow.
    pub fn receiving_demand_v2(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1>
    {
        let wrapper = u64::try_from(std::mem::size_of::<Self>())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ControllerCreateProvisioningReceivingV1::receiving_demand_v1(profile)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, wrapper))?)
    }

    /// Rejoins the actual active enrollment and same C/profile/launch.
    ///
    /// # Errors
    /// Refuses another owner, failed predecessor, entry, completion or purpose.
    pub fn require_current_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.predecessor.is_err() || self.publication_selected {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.native.require_current_v1(writer, launch, profile)?;
        launch.require_operator_recover_current_v1(writer)?;
        let base = *self.native.entry.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        self.native.original.require_recovered_enrollment_active_v2(base).map_err(Into::into)
    }

    /// Raises this enrollment's complete representation on the same residual B.
    ///
    /// # Errors
    /// Retains geometry, currentness or genuine same-ledger refusal.
    pub fn require_complete_representation_v2<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        self.native.require_complete_representation_v1(writer, launch, profile, complete)
    }

    /// Requires the paid receipt for independent upper after observations.
    ///
    /// This negative-capable comparison performs no debit or healthy-body check.
    ///
    /// # Errors
    /// Refuses failed predecessor, fixed geometry, conjunction or initial debit.
    pub fn require_prepaid_owed_observation_v2(&self)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if self.predecessor.is_err() || self.native.fixed.is_err()
            || self.native.conjunction.is_err() || self.native.entry.is_err() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Attempts all prearmed native posts independently of upper body refusal.
    ///
    /// # Errors
    /// Retains the original name, profile, recipient or disposal failure.
    pub fn finish_native_once_v2<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let result = self.native.finish_native_once(writer, launch, profile);
        if self.publication_selected {
            writer.fixed.fence();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        result
    }

    /// Requires positive native disposal and both still-idle actual funded slots.
    ///
    /// This comparison proves no reconciliation or fresh clock horizon.
    ///
    /// # Errors
    /// Refuses unfinished native custody, wrong successor or changed D/X.
    pub fn require_completed_original_v2<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.predecessor.is_err() { return Err(ControllerBankLaunchErrorV1::Conflict); }
        if !self.publication.is_complete_v1() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.native.require_completed_original_v1(writer, launch, profile)?;
        launch.require_operator_recover_current_v1(writer)?;
        self.native.original.require_recovered_intakes_funded_v2(profile).map_err(Into::into)
    }

    pub(crate) fn require_source_original_v2<P>(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(writer, launch, profile)?;
        self.native.require_source_original_v1(source, writer, launch, profile)
    }

    pub(crate) fn require_completed_source_original_v2(&self,
        source: &crate::controller_receiving::ControllerSourceOriginalRefV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.native.require_completed_source_original_v1(source)
    }

    /// Borrows the private profile failure only when it was the selected source.
    #[must_use]
    pub fn profile_failure_view_v2(&self)
        -> Option<crate::controller_receiving::profile::ControllerProfileFailureViewV1<'_>> {
        if self.predecessor.is_err() || self.publication_selected { return None; }
        self.native.profile_failure_view_v1()
    }

    /// Borrows the first actual predecessor or native refusal without cloning.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.predecessor.as_ref().err().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| if self.publication_selected { self.publication_failure_v1() }
                else { self.native.failure() })
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Begins fresh enrollment after completed Recover and actual funded D/X.
    ///
    /// Carried N, recovery highwaters, prior traffic and permanent intake debits
    /// remain on the same ledger. A refusal retains its whole native original;
    /// no old claim, initial-use admission or semantic Ready is constructed.
    #[must_use]
    pub fn begin_recovered_enrollment_receiving_once_v2(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        completed: &ControllerOperatorRecoverReceivingV1, complete: ResourceVector,
    ) -> ControllerRecoveredEnrollmentReceivingV2 {
        let predecessor = completed.require_completed_original_v1(self, launch, profile);
        let native = ControllerCreateProvisioningReceivingV1::begin_purpose_with_predecessor_v2(
            self, launch, profile, complete, ContinuationReceivingPurposeV1::RecoveredEnrollment,
            Some(&predecessor));
        ControllerRecoveredEnrollmentReceivingV2 {
            predecessor, native, publication: Default::default(), publication_selected: false,
        }
    }
}

/// Holds only constructor-issued completed native association, never a DATA flag.
pub(in crate::controller_receiving) struct RecoveredEnrollmentAssociationV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    _turn: Arc<std::sync::atomic::AtomicBool>,
}

impl RecoveredEnrollmentAssociationV1 {
    pub(in crate::controller_receiving) fn require_same_v1(&self,
        original: &Arc<ControllerReceivingOriginalV1>, identity: &Arc<ControllerWriterIdentityV1>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !Arc::ptr_eq(&self.original, original) || !Arc::ptr_eq(&self.identity, identity) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }
}

impl ControllerRecoveredEnrollmentReceivingV2 {
    pub(in crate::controller_receiving) fn completed_association_v1<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<RecoveredEnrollmentAssociationV1, ControllerBankLaunchErrorV1> {
        self.require_completed_original_v2(writer, launch, profile)?;
        Ok(RecoveredEnrollmentAssociationV1 {
            original: Arc::clone(&self.native.original), identity: Arc::clone(&self.native.identity),
            _turn: Arc::clone(self.native.turn_identity.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?),
        })
    }
}
