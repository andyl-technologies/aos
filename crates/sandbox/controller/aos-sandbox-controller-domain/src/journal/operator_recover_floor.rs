//! Appends the sole floor or exact observation row under actual Recover custody.
//!
//! The owner is temporarily moved from and restored to the same Journal. Its
//! presence never permits a generic append: both crossings require the exact
//! selected transaction and the genuine current successor receiver. The floor
//! additionally requires its sole encoder recipe; observation admission can
//! enter only after actual protected authorization and revision readback.

use super::{CommitResult, Journal, JournalError, JournalTransaction};
use crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1;
use crate::controller_resource_reservation::operator_create_recovery::{
    OperatorCreateRecoveryOriginalV1, OperatorRecoverCustodyV2,
};

pub(super) struct OperatorRecoverAppendLoanV1<'loan> {
    original: &'loan mut OperatorCreateRecoveryOriginalV1,
    transaction: &'loan JournalTransaction,
    purpose: OperatorRecoverAppendPurposeV1,
}

#[derive(Clone, Copy)]
enum OperatorRecoverAppendPurposeV1 { AuthorizationFloor, ObservationAdmission, MetadataCompletion }

impl OperatorRecoverAppendLoanV1<'_> {
    pub(super) fn require_transition(&mut self, journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if self.transaction != transaction { return Err(JournalError::ProtectedBoundary); }
        match self.purpose {
            OperatorRecoverAppendPurposeV1::AuthorizationFloor => self.original.require_floor_transition_v1(journal),
            OperatorRecoverAppendPurposeV1::ObservationAdmission => self.original.require_observation_transition_v1(journal, transaction),
            OperatorRecoverAppendPurposeV1::MetadataCompletion => self.original.require_metadata_transition_v1(journal, transaction),
        }
    }

    pub(super) fn final_crossing(&mut self, journal: &Journal) -> Result<(), JournalError> {
        let transaction = self.transaction;
        match self.purpose {
            OperatorRecoverAppendPurposeV1::AuthorizationFloor => self.require_transition(journal, transaction),
            OperatorRecoverAppendPurposeV1::ObservationAdmission =>
                self.original.final_observation_crossing_v1(journal, transaction),
            OperatorRecoverAppendPurposeV1::MetadataCompletion =>
                self.original.final_metadata_crossing_v1(journal, transaction),
        }
    }

    pub(super) fn matches_identity_v1(&self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> bool {
        self.original.matches_identity_v1(identity)
    }
}

impl Journal {
    pub(crate) fn commit_operator_recover_metadata_v1(&mut self,
        original: &mut OperatorCreateRecoveryOriginalV1, transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        original.require_metadata_transition_v1(self, transaction)?;
        let mut loan = OperatorRecoverAppendLoanV1 { original, transaction,
            purpose: OperatorRecoverAppendPurposeV1::MetadataCompletion };
        self.commit_create_storage_original_v1(transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::OperatorRecover(&mut loan))
    }

    pub(crate) fn operator_recover_append_carrier_bytes_v1() -> Option<usize> {
        std::mem::size_of::<OperatorRecoverAppendLoanV1<'_>>().checked_mul(3)
    }

    pub(crate) fn commit_operator_recover_observation_v1(&mut self,
        original: &mut OperatorCreateRecoveryOriginalV1, transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        original.require_observation_transition_v1(self, transaction)?;
        let mut loan = OperatorRecoverAppendLoanV1 { original, transaction,
            purpose: OperatorRecoverAppendPurposeV1::ObservationAdmission };
        self.commit_create_storage_original_v1(transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::OperatorRecover(&mut loan))
    }

    pub(crate) fn install_operator_recover_entry_v2(&mut self,
        original: OperatorRecoverCustodyV2,
    ) -> Result<(), OperatorRecoverCustodyV2> {
        if self.operator_recovery.is_some() || self.provisioning.is_some()
            || self.start_admission.is_some() || self.execution_admission.is_some() {
            return Err(original);
        }
        self.operator_recovery = Some(original);
        Ok(())
    }

    pub(crate) fn install_operator_recover_v1(&mut self,
        original: Box<OperatorCreateRecoveryOriginalV1>,
    ) -> Result<(), Box<OperatorCreateRecoveryOriginalV1>> {
        if self.operator_recovery.is_some() || self.provisioning.is_some()
            || self.start_admission.is_some() || self.execution_admission.is_some() {
            return Err(original);
        }
        self.operator_recovery = Some(OperatorRecoverCustodyV2::Entered(original));
        Ok(())
    }

    pub(crate) fn take_operator_recover_v1(&mut self)
        -> Option<Box<OperatorCreateRecoveryOriginalV1>> {
        match self.operator_recovery.take() {
            Some(OperatorRecoverCustodyV2::Entered(original)) => Some(original),
            refused => { self.operator_recovery = refused; None }
        }
    }

    pub(crate) fn operator_recover_entry_is_occupied_v2(&self) -> bool {
        self.operator_recovery.is_some() || self.provisioning.is_some()
            || self.start_admission.is_some() || self.execution_admission.is_some()
    }

    pub(crate) fn operator_recover_original_mut_v1(&mut self)
        -> Option<&mut OperatorCreateRecoveryOriginalV1> {
        match self.operator_recovery.as_mut()? {
            OperatorRecoverCustodyV2::Entered(original) => Some(original.as_mut()),
            OperatorRecoverCustodyV2::EntryRefused(_) => None,
        }
    }

    pub(crate) fn operator_recover_entry_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.operator_recovery.as_ref()? {
            OperatorRecoverCustodyV2::EntryRefused(original) => original.failure_v2(),
            OperatorRecoverCustodyV2::Entered(_) => None,
        }
    }

    pub(crate) fn commit_operator_recover_floor_v1(&mut self,
        transaction: &JournalTransaction, recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let Some(mut original) = self.take_operator_recover_v1() else {
            if self.operator_recovery.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            if self.start_admission.is_some() {
                return self.commit_start_authorization_floor_v1(transaction, recipe);
            }
            return self.commit(transaction);
        };
        let result = original.prepare_floor_once_v1(self, transaction, recipe).and_then(|()| {
            let mut loan = OperatorRecoverAppendLoanV1 { original: &mut original, transaction,
                purpose: OperatorRecoverAppendPurposeV1::AuthorizationFloor };
            self.commit_create_storage_original_v1(transaction,
                super::create_storage_append::CreateStorageAppendOriginalV1::OperatorRecover(&mut loan))
        });
        self.operator_recovery = Some(OperatorRecoverCustodyV2::Entered(original));
        result
    }
}
