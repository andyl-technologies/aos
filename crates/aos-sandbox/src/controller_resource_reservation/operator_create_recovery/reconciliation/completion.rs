//! Joins retained native observations and immutable signed inventory models.
//!
//! This closed first-local subset retains every old owner. It cannot restart
//! an active sandbox, restore a prior claim or enroll ordinary service itself.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::{
    ControllerInventoryDecodedOriginalV2,
};

/// Borrows one exact completed native query, Session journal and decoded body.
///
/// Its constructor checks the actual private query state's nonce, binding,
/// signed-packet/body commitments and same physical journal identity. It is
/// neither a supplied snapshot nor a currentness or enrollment factory.
#[doc(hidden)]
pub struct OperatorReconciliationInventoryProofV2<'held> {
    owner: &'held OperatorReconciliationObservationOriginalV2,
    index: usize,
    journal: &'held Journal,
    outcome: &'held AuthenticatedBrokerMethodOutcomeV1,
    decoded: &'held ControllerInventoryDecodedOriginalV2,
}

/// Retains the complete first-local stopped reconciliation conjunction.
///
/// This proof lends the same actual remaining residual, original authorization
/// bounds and native recipient to a separate ordinary enrollment. It creates
/// no new allowance, Session, normal intake, effect grant or Ready event.
#[doc(hidden)]
pub struct OperatorFirstLocalReconciliationCompleteV2<'held, 'completed> {
    seed: &'held OperatorRecoveredStoppedCreateSeedV1<'completed>,
    host: OperatorReconciliationInventoryProofV2<'held>,
    mount: OperatorReconciliationInventoryProofV2<'held>,
    network: OperatorReconciliationInventoryProofV2<'held>,
}

impl OperatorReconciliationObservationOriginalV2 {
    /// Lends only the actual completed query's immutable authenticated model.
    ///
    /// The Security owner lends its private Session journal and exact retained
    /// model here; substituting another row or caller-built empty model fails.
    ///
    /// # Errors
    /// Refuses another seed, Session, request/body/model commitment, method,
    /// cut, ordering or any incomplete Source/C/native/final-clock destination.
    pub fn borrow_completed_inventory_v2<'held>(&'held self,
        seed: &OperatorRecoveredStoppedCreateSeedV1<'_>,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
        index: usize, journal: &'held Journal,
        outcome: &'held AuthenticatedBrokerMethodOutcomeV1,
        decoded: &'held ControllerInventoryDecodedOriginalV2,
    ) -> Result<OperatorReconciliationInventoryProofV2<'held>, OperatorCreateRecoveryClosedV1> {
        self.require_completed_native_v2(seed, controller, source).map_err(|_| CLOSED)?;
        let count = self.required_inventory_count_v2();
        let method = super::super::storage::inventory::reconciliation_inventory_method_v2(self.role, index)
            .map_err(|_| CLOSED)?;
        let state = self.inventory.get(index).ok_or(CLOSED)?;
        state.require_completed_inventory_data_v2(journal, outcome, method, index + 1 != count)
            .map_err(|_| CLOSED)?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(CLOSED);
        };
        use sha2::Digest as _;
        if decoded.method_v2() != method
            || decoded.body_digest_v2() != <[u8; 32]>::from(sha2::Sha256::digest(exact_body)) {
            return Err(CLOSED);
        }
        let last = self.inventory[count - 1].completed_query_boundary_v2().ok_or(CLOSED)?;
        if last.0 != journal.snapshot_sequence() { return Err(CLOSED); }
        let mut prior = None;
        for state in &self.inventory[..count] {
            let cut = state.completed_query_boundary_v2().ok_or(CLOSED)?;
            if cut.1 != last.1 || cut.2 != last.2
                || prior.is_some_and(|previous: (u64, u64)| previous.0 >= cut.0 || previous.1 >= cut.3) {
                return Err(CLOSED);
            }
            prior = Some((cut.0, cut.3));
        }
        Ok(OperatorReconciliationInventoryProofV2 { owner: self, index, journal, outcome, decoded })
    }
}

impl<'held, 'completed> OperatorFirstLocalReconciliationCompleteV2<'held, 'completed> {
    /// Joins only the ordered actual no-active observations of this recovery.
    ///
    /// # Errors
    /// Refuses missing complete native absence, residual Host/Network/Mount
    /// resources, substituted roles/models, another boot or original expiry.
    pub fn require_first_local_v2(seed: &'held OperatorRecoveredStoppedCreateSeedV1<'completed>,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
        host: OperatorReconciliationInventoryProofV2<'held>,
        mount: OperatorReconciliationInventoryProofV2<'held>,
        network: OperatorReconciliationInventoryProofV2<'held>,
    ) -> Result<Self, OperatorCreateRecoveryClosedV1> {
        if host.owner.role != ControllerReconciliationInventoryRoleV2::Host || host.index != 0
            || network.owner.role != ControllerReconciliationInventoryRoleV2::Network || network.index != 0
            || mount.owner.role != ControllerReconciliationInventoryRoleV2::Mount || mount.index != 0 {
            return Err(CLOSED);
        }
        let (original, cutoff, _) = seed.original_horizon_v1()?;
        crate::controller_inventory_absence::require_first_local_inventory_absence_data_v2(
            original, cutoff, host.outcome, host.decoded, mount.outcome, mount.decoded,
            network.outcome, network.decoded,
        ).map_err(|_| CLOSED)?;
        let complete = Self { seed, host, mount, network };
        {
            let bank = complete.network.owner.bank.lock().map_err(|_| CLOSED)?;
            complete.require_same_completed_v2(&bank,
                controller, &complete.network.owner.profile, source).map_err(|_| CLOSED)?;
        }
        Ok(complete)
    }

    pub(crate) fn require_same_completed_v2(&self, bank: &ControllerResourceBankOpeningV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.seed.require_same_completed_v1(bank, controller, profile)?;
        for proof in [&self.host, &self.mount, &self.network] {
            proof.owner.require_completed_native_with_bank_v2(self.seed, controller, source, bank)?;
            if proof.journal.snapshot_sequence() != proof.owner.inventory[
                proof.owner.required_inventory_count_v2() - 1].completed_query_boundary_v2()
                    .ok_or(ResourceReservationErrorV1::Conflict)?.0 {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        Ok(())
    }

    pub(crate) fn completed_native_v2(&self) -> Result<&ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1> {
        self.network.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn require_same_source_v2(&self, source: &ProtectedSourceDomainJournalOwnerV1)
        -> Result<(), ResourceReservationErrorV1> {
        self.seed.require_same_current_source_v1(source)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn completed_resident_demand_v2(&self, controller: &Journal)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bank = self.network.owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.completed_resident_demand_with_bank_v2(&bank, controller)
    }

    pub(crate) fn completed_resident_demand_with_bank_v2(&self,
        bank: &ControllerResourceBankOpeningV1, controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        bank.completed_operator_recover_resident_demand_v1(self.completed_native_v2()?, controller,
            &self.network.owner.profile)
    }

    pub(crate) fn original_horizon_v2(&self) -> Result<(RawPairedClockSample, u64, i64), OperatorCreateRecoveryClosedV1> {
        self.seed.original_horizon_v1()
    }

    pub(crate) fn profile_original_v2(&self) -> &ProductionControllerNormalRootProfileV1 {
        &self.network.owner.profile
    }
}

