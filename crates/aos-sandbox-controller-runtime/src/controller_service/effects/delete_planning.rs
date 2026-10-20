//! Retains the real default-local Runtime half of Transfer absence.
//!
//! This private original is not a Transfer inventory or an active Ownership
//! proof. It binds this process's never-opened private Transfer slot, the actual
//! C17 funding and measured default-local Controller image, and the same startup
//! Ownership configuration. Root must still join independent native absence and
//! the real local Ownership process/profile/fixed-directory observation.

use super::*;

mod collection;
mod entry;

pub(in crate::controller_service) use collection::ControllerDeletePlanningCollectionV2;
use aos_sandbox::ControllerDeleteSourceAuthorizedScopeV1;
use aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1;
use aos_sandbox_protocol::domain_ledger::delete_root::planning::{
    DELETE_ROOT_PLANNING_OPEN_BYTES_V3, DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3,
};

pub(in crate::controller_service) struct ControllerLocalTransferRuntimeOriginalV1 {
    funding: OperationIntakeFundingDataV1,
    profile: Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    ownership: SnapshotOwnershipDonationV3,
}

/// Borrows disjoint actual fields before the exclusive Source scope is built.
///
/// Only the concrete executor constructs this private context. Holding its
/// references prevents an ownership/profile or Transfer slot replacement while
/// the Source/C17 query is active; no caller-supplied flag or tuple qualifies it.
pub(in crate::controller_service) struct ControllerDeleteLocalRuntimeFieldsV1<'runtime> {
    request_scope: ControllerRequestScopeV1,
    transfer: &'runtime Option<aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1>,
    profile: &'runtime Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    ownership: &'runtime SnapshotOwnershipDonationV3,
    signer: &'runtime Option<crate::controller_service::plan_signer::ControllerBrokerPlanSignerV1>,
}

pub(in crate::controller_service) struct ControllerDeleteSourceRuntimeSplitV1<'runtime> {
    pub(in crate::controller_service) source: &'runtime mut ProtectedSourceDomainJournalOwnerV1,
    pub(in crate::controller_service) cache: ControllerDeleteCacheRuntimeFieldsV1<'runtime>,
    pub(in crate::controller_service) local: ControllerDeleteLocalRuntimeFieldsV1<'runtime>,
}

impl ControllerDeleteLocalRuntimeFieldsV1<'_> {
    pub(in crate::controller_service) fn seal_v1(
        &self,
        source: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
    ) -> Result<ControllerLocalTransferRuntimeOriginalV1, aos_sandbox::ResourceReservationErrorV1> {
        // This is the actual private process slot, not a supplied mode. The
        // default Runtime has no remaining path that opens/populates it.
        if self.transfer.is_some() {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        let bytes = std::mem::size_of::<ControllerLocalTransferRuntimeOriginalV1>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerDeleteSourceRuntimeSplitV1<'_>>().checked_mul(3)?))
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        let funding = source.local_transfer_runtime_funding_data_v3(
            bank, controller, self.profile, bytes,
        )?;
        Ok(ControllerLocalTransferRuntimeOriginalV1 {
            funding,
            profile: Arc::clone(self.profile),
            ownership: Arc::clone(self.ownership),
        })
    }

    pub(in crate::controller_service) fn require_same_runtime_v1(
        &self,
        retained: &ControllerLocalTransferRuntimeOriginalV1,
        source: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        if self.transfer.is_some()
            || !Arc::ptr_eq(self.profile, &retained.profile)
            || !Arc::ptr_eq(self.ownership, &retained.ownership)
            || self.ownership.get().is_none()
        {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        let actual = source.local_transfer_runtime_funding_data_v3(bank, controller, self.profile, 0)?;
        if actual != retained.funding {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

/// Keeps the actual Cache fields disjoint from the exclusively held Source.
///
/// The real initialized owners remain borrowed by the returned cut, preventing
/// replacement or a fallback bootstrap opener during planning/preaccept.
pub(in crate::controller_service) struct ControllerDeleteCacheRuntimeFieldsV1<'runtime> {
    initialized: &'runtime mut aos_sandbox::cache_residency::CacheResidentInitializationV1,
    owner: &'runtime mut Option<CacheResidencyProtectedOwnerV1>,
    physical: &'runtime Option<DormantCacheOwnerV1>,
}

impl ControllerDeleteCacheRuntimeFieldsV1<'_> {
    pub(in crate::controller_service) fn query_planning_once_v1<'cache>(
        &'cache mut self,
        authorized: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox::cache_residency::CacheDeleteInventoryOriginalV1<'cache>, aos_sandbox::ResourceReservationErrorV1> {
        let owner = self.owner.as_mut().ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        let physical = self.physical.as_ref().ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        let mut query = bank.borrow_delete_planning_cache_once_v1(
            self.initialized, owner, physical, authorized, controller, profile,
        )?;
        if query.run_once_v1().is_err() {
            // Finish the enclosing prearmed Source/C17 debt too while this
            // whole Cache/native/semantic query remains resident.
            let _ = query.finish_outer_source_failure_once_v1();
            std::process::abort();
        }
        Ok(query.finish_positive_once_v1())
    }
}

/// Keeps both genuine halves of the default-local planning observation resident.
///
/// The actual Root V2 native/bootstrap observation is compared against the
/// SAME protected Runtime verifier before a positive Transfer planning borrow.
/// The private default-off/never-opened slot and measured image stay joined to
/// that whole owner. This planning conjunction is not pending/preaccept or
/// permission to accept, destroy or advance a Root floor.
pub(in crate::controller_service) struct ControllerDeleteLocalRootPlanningOriginalV1<'profile> {
    local: ControllerLocalTransferRuntimeOriginalV1,
    root: aos_sandbox::ControllerDeletePlanningRootOriginalV1<'profile>,
    trust_join: Result<ControllerDeleteOwnershipPlanningBindingV2,
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningDataErrorV3>,
}

// Only the actual Root loan and protected configuration comparison below can
// construct this conjunction. An observed PID alone cannot bind the policy.
struct ControllerDeleteOwnershipPlanningBindingV2 {
    observation: aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningObservationDataV2,
}

impl<'runtime> ControllerDeleteLocalRuntimeFieldsV1<'runtime> {
    pub(in crate::controller_service) fn query_root_planning_once_v1<'query>(
        &'query self,
        source: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
    ) -> Result<ControllerDeleteLocalRootPlanningOriginalV1<'query>, aos_sandbox::ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<ControllerDeleteLocalRootPlanningOriginalV1<'_>>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(),
                aos_sandbox::ResourceReservationErrorV1>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(384usize.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningObservationDataV2>()
                .checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerDeleteTransferPlanningLoanV2<'_>>()
                .checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2>()
                .checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(DELETE_ROOT_PLANNING_OPEN_BYTES_V3
                .checked_add(DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3)?.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                aos_sandbox_core::ownership_lease::OwnershipLeaseTrustAnchorComparisonV1<'_>>()
                .checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningTrustDataV2>()
                .checked_mul(3)?))
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        // This actual same-C funding projection prepays the resident wrapper on
        // the genuine lane before the local owner or Root native client grows.
        let _ = source.local_transfer_runtime_funding_data_v3(bank, controller, self.profile, bytes)?;
        let local = self.seal_v1(source, bank, controller)?;
        let mut root = match bank.begin_delete_planning_comparison_once_v1(source, controller, self.profile) {
            Ok(root) => root,
            Err(_cause) => {
                let _after = bank.finish_delete_planning_source_failure_once_v1(source, controller, self.profile);
                std::process::abort();
            }
        };
        let checked = bank.borrow_delete_planning_comparison_v1(&mut root, source, controller);
        let trust_join = match checked {
            Ok(loan) if loan.open_v3().funding == local.funding => {
                let configuration = match self.ownership.get() {
                    Some(configuration) => configuration,
                    None => std::process::abort(),
                };
                let observation = *loan.observation_v2();
                observation.trust.require_verifier_comparison_v2(configuration.verifier())
                    .map(|()| ControllerDeleteOwnershipPlanningBindingV2 { observation })
            }
            _ => {
                let _after = bank.finish_delete_planning_source_failure_once_v1(source, controller, self.profile);
                std::process::abort();
            }
        };
        if let Err(_cause) = self.require_same_runtime_v1(&local, source, bank, controller) {
            let _after = bank.finish_delete_planning_source_failure_once_v1(source, controller, self.profile);
            std::process::abort();
        }
        // A pure configuration mismatch remains on the whole entered owner.
        // It cannot construct a complete borrowed Transfer planning cut.
        Ok(ControllerDeleteLocalRootPlanningOriginalV1 { local, root, trust_join })
    }
}

impl ControllerDeleteLocalRootPlanningOriginalV1<'_> {
    pub(in crate::controller_service) fn failure_v2(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.root.failure_v1().or_else(|| self.trust_join.as_ref().err()
            .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    pub(in crate::controller_service) fn borrow_transfer_planning_v2<'borrow>(
        &'borrow mut self,
        fields: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        source: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        controller: &mut Journal,
    ) -> Result<ControllerDeleteTransferPlanningLoanV2<'borrow>, aos_sandbox::ResourceReservationErrorV1> {
        fields.require_same_runtime_v1(&self.local, source, bank, controller)?;
        let binding = self.trust_join.as_ref()
            .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        let loan = bank.borrow_delete_planning_comparison_v1(&mut self.root, source, controller)?;
        // The native Root owner and immutable Runtime configuration remain
        // exactly those that completed this actual conjunction. No decoded
        // observation or new verifier can replace either side of it.
        if *loan.observation_v2() != binding.observation {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        if loan.open_v3().funding != self.local.funding {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        Ok(ControllerDeleteTransferPlanningLoanV2 { root: loan, _local: &self.local })
    }
}

/// Lends only the real default-local/Root/trust planning conjunction.
///
/// This private non-Copy type has no DATA constructor. It cannot borrow a
/// generic Root observation without the actual never-opened Runtime slot,
/// measured default-local image and exact protected verifier comparison.
pub(in crate::controller_service) struct ControllerDeleteTransferPlanningLoanV2<'borrow> {
    root: aos_sandbox::ControllerDeletePlanningRootLoanV1<'borrow>,
    _local: &'borrow ControllerLocalTransferRuntimeOriginalV1,
}

impl ControllerDeleteTransferPlanningLoanV2<'_> {
    // Only the actual same-Root native loan above supplies these full original
    // planning preimages. They remain comparison DATA rather than a new loan.
    pub(in crate::controller_service) fn canonical_planning_preimages_v2(&self) -> (
        &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningOpenDataV3,
        &aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningChallengeDataV3,
        &[u8; aos_sandbox_protocol::domain_ledger::delete_root::planning::DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2],
    ) {
        (self.root.open_v3(), self.root.challenge_v3(), self.root.bytes_v2())
    }

    pub(in crate::controller_service) fn completed_cut_data_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningDataErrorV3,
    > {
        aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::
            transfer_planning_cut_data_v2(
                self.root.open_v3(), self.root.challenge_v3(), self.root.bytes_v2(),
            )
    }
}


/// Lends only the real same-process Runtime and completed fresh Root read join.
struct ControllerDeleteTransferFreshLoanV2<'held> {
    root: &'held aos_sandbox_protocol::domain_ledger::delete_root::final_inventory::DeleteRootFreshTransferDataV2,
    _local: &'held ControllerLocalTransferRuntimeOriginalV1,
}

impl ControllerDeleteLocalRuntimeFieldsV1<'_> {
    fn borrow_fresh_transfer_v2<'held>(&self,
        retained: &'held ControllerLocalTransferRuntimeOriginalV1,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &'held mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        bank: &aos_sandbox::ControllerResourceBankOpeningV1, controller: &Journal,
    ) -> Result<ControllerDeleteTransferFreshLoanV2<'held>, aos_sandbox::ResourceReservationErrorV1> {
        if self.transfer.is_some() || !Arc::ptr_eq(self.profile, &retained.profile)
            || !Arc::ptr_eq(self.ownership, &retained.ownership)
        {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        let configuration = self.ownership.get().ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        let challenge = bank.borrow_retained_delete_pending_root_challenge_v2(pending, client, controller)?;
        bank.require_delete_pending_local_funding_v3(pending, controller, self.profile, &challenge, &retained.funding)?;
        drop(challenge);
        let root = client.fresh_transfer_comparison_data_v2()?;
        root.observation.trust.require_verifier_comparison_v2(configuration.verifier())
            .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        Ok(ControllerDeleteTransferFreshLoanV2 { root, _local: retained })
    }
}

impl ControllerDeleteTransferFreshLoanV2<'_> {
    fn completed_cut_data_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2,
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningDataErrorV3,
    > {
        self.root.owner_cut_data_v2()
    }
}
