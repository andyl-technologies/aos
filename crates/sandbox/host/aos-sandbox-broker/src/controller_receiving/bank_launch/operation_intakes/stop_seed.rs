//! Issues only the recovered Stop seed from the same completed enrollment.
//!
//! This owner retains funding provenance. Stop native turns use the existing
//! provisioning profile destinations and exact baseline debits; no Delete or
//! Execution pool, reserved claim or fixed flight capacity is borrowed.

use super::*;

impl ControllerOperationIntakeOriginalV1 {
    /// Describes the intrinsic seed carrier before its constructor allocates.
    ///
    /// # Errors
    /// Refuses checked layout overflow; this creates no funding or authority.
    pub fn stop_seed_resident_demand_v3() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<usize>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(in crate::controller_receiving) fn require_stop_seed_unpublished_v3<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let OperationIntakeFundingV2::RecoveredLifecycleStop(receipt) = self.funding else {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        };
        if self.purpose != OperationIntakePurposeV1::LifecycleStop || self.active
            || self.entry.first.is_some() || !Arc::ptr_eq(&self.identity, writer.fixed.identity())
            || !writer.fixed.has_original(&self.original)
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        match (receipt.record_data_v3(), self.recovered_enrollment.as_ref(), self.recovered_cleanup.as_ref()) {
            (bank::RecoveredStopSeedFundingDataV3::Ordinary(_), Some(enrollment), None) => {
                enrollment.require_same_v1(&self.original, &self.identity)?;
            }
            (bank::RecoveredStopSeedFundingDataV3::Cleanup(row), None, Some(cleanup)) => {
                cleanup.require_same_v1(&self.original, &self.identity, row.association)?;
            }
            _ => return Err(ControllerBankLaunchErrorV1::Conflict),
        }
        launch.require_operator_recover_current_v1(writer)?;
        self.original.require_recovered_stop_seed_v3(profile, receipt)?;
        self.original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot(self.purpose).require_stop_seed_v3()?;
        Ok(())
    }

    /// Lends only the private actual seed's canonical publication model.
    ///
    /// # Errors
    /// Refuses another funding purpose, changed original or failed seed.
    pub fn stop_seed_record_data_v3<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<bank::RecoveredStopSeedFundingDataV3, ControllerBankLaunchErrorV1> {
        self.require_stop_seed_unpublished_v3(writer, launch, profile)?;
        let OperationIntakeFundingV2::RecoveredLifecycleStop(receipt) = self.funding else {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        };
        Ok(receipt.record_data_v3())
    }
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Debits one exact Stop seed from this recovered Controller's remaining B.
    ///
    /// The actual completed enrollment is required before debit. The returned
    /// private owner cannot enter ordinary operations until its exact row has
    /// been published/read back under real Source/C/clock bookends.
    ///
    /// # Errors
    /// Refuses foreign/incomplete enrollment, occupied slot, layout overflow or
    /// insufficient remaining baseline. Every successful debit remains spent.
    pub fn fund_recovered_lifecycle_stop_seed_v3(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        enrolled: &super::super::create_provisioning::ControllerRecoveredEnrollmentReceivingV2,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        let association = enrolled.completed_association_v1(self, launch, profile)?;
        self.fund_stop_seed_origin_v4(launch, profile, StopSeedOriginV4::Ordinary(association), complete)
    }

    /// Debits a finite cleanup seed from the same recovered baseline B.
    ///
    /// The genuine completed Recover native owner supplies financial provenance.
    /// Core retains the accepted Recover/current authorization/old-target/Source
    /// conjunction separately. This neither issues an effect nor enrolls an
    /// ordinary operation, even after successful publication.
    ///
    /// # Errors
    /// Refuses foreign or unfinished Recover, invalid references, occupied Stop
    /// slot, checked layout overflow or insufficient remaining original B.
    pub fn fund_recovered_host_stop_cleanup_seed_v1(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        recovered: &super::super::create_provisioning::ControllerOperatorRecoverReceivingV1,
        association: bank::RecoveredHostStopCleanupAssociationDataV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        let association = recovered.completed_cleanup_association_v1(self, launch, profile, association)?;
        self.fund_stop_seed_origin_v4(launch, profile, StopSeedOriginV4::Cleanup(association), complete)
    }

    fn fund_stop_seed_origin_v4(&mut self,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        association: StopSeedOriginV4, complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<ControllerOperationIntakeOriginalV1, ControllerBankLaunchErrorV1> {
        launch.require_operator_recover_current_v1(self)?;
        let original = self.fixed.original();
        original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(OperationIntakePurposeV1::LifecycleStop).require_vacant_recovered_v2()?;
        let mut preparation = FailedBeginGuardV1 {
            original, purpose: OperationIntakePurposeV1::LifecycleStop, completed: false,
        };
        let complete = complete.demand.checked_add(ControllerOperationIntakeOriginalV1::stop_seed_resident_demand_v3()?)?;
        let receipt = match &association {
            StopSeedOriginV4::Ordinary(_) => original.fund_recovered_stop_seed_v3(profile, complete,
                self.next_sequence(), self.durable_prefix_end_data_v1())?,
            StopSeedOriginV4::Cleanup(cleanup) => original.fund_recovered_stop_cleanup_seed_v1(profile, complete,
                self.next_sequence(), self.durable_prefix_end_data_v1(), cleanup.data_v1())?,
        };
        let funding = original.operation_intakes.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(OperationIntakePurposeV1::LifecycleStop).bind_stop_seed_once_v3(receipt)?;
        let mut owner = ControllerOperationIntakeOriginalV1::new_funded_v2(
            Arc::clone(original), Arc::clone(self.fixed.identity()),
            OperationIntakePurposeV1::LifecycleStop, funding, ResourceVector::ZERO,
        );
        match association {
            StopSeedOriginV4::Ordinary(enrollment) => owner.recovered_enrollment = Some(enrollment),
            StopSeedOriginV4::Cleanup(cleanup) => owner.recovered_cleanup = Some(cleanup),
        }
        preparation.completed = true;
        Ok(owner)
    }
}

enum StopSeedOriginV4 {
    Ordinary(super::super::create_provisioning::RecoveredEnrollmentAssociationV1),
    Cleanup(super::super::create_provisioning::RecoveredStopCleanupAssociationOriginalV1),
}
