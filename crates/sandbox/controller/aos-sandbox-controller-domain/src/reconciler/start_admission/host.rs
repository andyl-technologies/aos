//! Restricts the same Start native receiver to its private Host child recipes.
//!
//! Admission4 and Catalog6 retain separate append destinations on the original
//! Start payer. Activation5 additionally requires the same physically disposed
//! catalog completion. Presence of this scope never enables the legacy public
//! Start floor/admission ports or an ordinary Journal commit.

use super::*;
use crate::controller_resource_reservation::StartHostPublicationContractV2;
use crate::host_catalog_reconciliation::publication_recipe::{
    HostCatalogCommitPhaseV2, HostCatalogCommitRecipeV2,
};
use crate::reconciler::provisioning::CoreCommitRecipeV1;

/// Names the private child admission, catalog and activation recipe phases.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StartHostCoreScopePhaseV2 {
    Admission,
    Catalog,
    Activation,
    Applying,
    Applied,
}

impl StartHostCoreScopePhaseV2 {
    pub(crate) fn stage_v2(self) -> usize {
        match self {
            Self::Admission => 4,
            Self::Catalog => 6,
            Self::Activation => 5,
            Self::Applying | Self::Applied => 2,
        }
    }
}

pub(super) struct StartHostScopeDataV2 {
    contract: Arc<StartHostPublicationContractV2>,
    phase: StartHostCoreScopePhaseV2,
    root_resident: aos_sandbox_model::ResourceVector,
    core_entered: bool,
    catalog_entered: Option<HostCatalogCommitPhaseV2>,
}

impl StartAdmissionScopeV1 {
    /// Moves the genuine current native state after its actual Root-before.
    pub(crate) fn from_host_entry_v2(
        entry: &mut crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
        phase: StartHostCoreScopePhaseV2,
        root: &crate::normal_root::RootStartResourceCurrentTurnV2<'_>,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let (native, identity, contract, root_resident) =
            entry.take_host_publication_scope_state_v2(controller, phase, root, source)?;
        Ok(Self {
            native,
            identity,
            plan: None,
            floor_entered: false,
            admission_entered: false,
            host: Some(StartHostScopeDataV2 {
                contract,
                phase,
                root_resident,
                core_entered: false,
                catalog_entered: None,
            }),
        })
    }

    pub(crate) fn host_scope_receiving_demand_v2() -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::reconciler::core_journal::CoreJournalMutationV2<'static, 'static>>()
                .checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::ProtectedBoundary)?;
        Ok(aos_sandbox_model::ResourceVector::ZERO.with(
            aos_sandbox_model::ResourceDimension::MemoryBytes, bytes))
    }

    pub(crate) fn is_host_scope_v2(&self) -> bool {
        self.host.is_some()
    }

    pub(crate) fn require_host_current_v2(&self, controller: &Journal) -> Result<(), JournalError> {
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.native.require_current_v1(controller).map_err(|_| JournalError::ProtectedBoundary)?;
        self.native.require_host_scope_contract_v2(controller, &host.contract, host.phase)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn prepay_host_core_v2(&mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
        recipe: &CoreCommitRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_host_current_v2(controller)?;
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if host.core_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        let index = match host.phase {
            StartHostCoreScopePhaseV2::Admission => {
                recipe.require_start_host_admission_v2(&host.contract.plan)?;
                2
            }
            StartHostCoreScopePhaseV2::Activation => {
                recipe.require_start_host_activation_v2(host.contract.plan.operation_id(), &host.contract.prepared)?;
                5
            }
            StartHostCoreScopePhaseV2::Applying | StartHostCoreScopePhaseV2::Applied => {
                recipe.require_start_host_child_v2(&host.contract.plan, controller, transaction)?;
                if host.phase == StartHostCoreScopePhaseV2::Applying { 6 } else { 7 }
            }
            StartHostCoreScopePhaseV2::Catalog => return Err(JournalError::ProtectedBoundary),
        };
        self.native.require_host_append_once_v2(controller, transaction, index,
            host.root_resident.checked_add(Self::host_scope_receiving_demand_v2()?)
                .map_err(|_| JournalError::ProtectedBoundary)?)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn prepare_host_core_recipe_v2(&mut self,
        _transaction: &JournalTransaction,
        recipe: &CoreCommitRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        let host = self.host.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if host.core_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        match host.phase {
            StartHostCoreScopePhaseV2::Admission => recipe.require_start_host_admission_v2(&host.contract.plan)?,
            StartHostCoreScopePhaseV2::Activation => recipe.require_start_host_activation_v2(
                host.contract.plan.operation_id(), &host.contract.prepared)?,
            StartHostCoreScopePhaseV2::Applying | StartHostCoreScopePhaseV2::Applied =>
                recipe.require_start_host_child_kind_v2()?,
            StartHostCoreScopePhaseV2::Catalog => return Err(JournalError::ProtectedBoundary),
        }
        host.core_entered = true;
        Ok(())
    }

    pub(crate) fn require_host_core_recipe_v2(&self,
        controller: &Journal,
        _transaction: &JournalTransaction,
        recipe: &CoreCommitRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_host_current_v2(controller)?;
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if !host.core_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        match host.phase {
            StartHostCoreScopePhaseV2::Admission => recipe.require_start_host_admission_v2(&host.contract.plan),
            StartHostCoreScopePhaseV2::Activation => recipe.require_start_host_activation_v2(
                host.contract.plan.operation_id(), &host.contract.prepared),
            StartHostCoreScopePhaseV2::Applying | StartHostCoreScopePhaseV2::Applied =>
                recipe.require_start_host_child_v2(&host.contract.plan, controller, _transaction),
            StartHostCoreScopePhaseV2::Catalog => Err(JournalError::ProtectedBoundary),
        }
    }

    fn require_catalog_recipe_data_v2(&self,
        transaction: &JournalTransaction,
        recipe: &HostCatalogCommitRecipeV2<'_>,
    ) -> Result<(), JournalError> {
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if host.phase != StartHostCoreScopePhaseV2::Catalog
            || host.contract.catalog_generation != recipe.catalog_generation_v2()
            || host.contract.catalog_digest != recipe.catalog_digest_v2()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        recipe.require_transaction_v2(transaction)
    }

    pub(crate) fn prepay_host_catalog_v2(&mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
        recipe: &HostCatalogCommitRecipeV2<'_>,
    ) -> Result<(), JournalError> {
        self.require_host_current_v2(controller)?;
        self.require_catalog_recipe_data_v2(transaction, recipe)?;
        recipe.require_history_v2(controller)?;
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if host.catalog_entered.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let index = match recipe.phase_v2() {
            HostCatalogCommitPhaseV2::Pending => 3,
            HostCatalogCommitPhaseV2::Confirmation => 4,
        };
        self.native.require_host_append_once_v2(controller, transaction, index,
            host.root_resident.checked_add(Self::host_scope_receiving_demand_v2()?)
                .map_err(|_| JournalError::ProtectedBoundary)?)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn prepare_host_catalog_recipe_v2(&mut self,
        transaction: &JournalTransaction,
        recipe: &HostCatalogCommitRecipeV2<'_>,
    ) -> Result<(), JournalError> {
        self.require_catalog_recipe_data_v2(transaction, recipe)?;
        let host = self.host.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if host.catalog_entered.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        host.catalog_entered = Some(recipe.phase_v2());
        Ok(())
    }

    pub(crate) fn require_host_catalog_recipe_v2(&self,
        controller: &Journal,
        transaction: &JournalTransaction,
        recipe: &HostCatalogCommitRecipeV2<'_>,
    ) -> Result<(), JournalError> {
        self.require_host_current_v2(controller)?;
        self.require_catalog_recipe_data_v2(transaction, recipe)?;
        if self.host.as_ref().and_then(|host| host.catalog_entered) != Some(recipe.phase_v2()) {
            return Err(JournalError::ProtectedBoundary);
        }
        recipe.require_history_v2(controller)
    }
}

impl StartAdmissionScopeV1 {
    pub(crate) fn host_native_boot_v2(&self) -> Result<[u8; 16], JournalError> {
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        Ok(host.contract.origin.first_native_clock_v1().host_boot_id())
    }

    pub(crate) fn host_admission_contract_v2(&self)
        -> Result<Arc<StartHostPublicationContractV2>, JournalError> {
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if host.phase != StartHostCoreScopePhaseV2::Admission || host.core_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(Arc::clone(&host.contract))
    }
}

impl StartAdmissionScopeV1 {
    pub(crate) fn take_host_activation_original_v2(&mut self)
        -> Result<(Arc<StartHostPublicationContractV2>, crate::publication::AuthorityPublicationActivationV1), JournalError> {
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if host.phase != StartHostCoreScopePhaseV2::Activation || host.core_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        let contract = Arc::clone(&host.contract);
        let activation = self.native.take_host_activation_original_v2(&contract)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((contract, activation))
    }
}

impl StartAdmissionScopeV1 {
    pub(crate) fn host_effect_inputs_v2(&mut self, complete: bool)
        -> Result<(Arc<StartHostPublicationContractV2>, crate::PreparedAuthorityEffectV1,
            Option<crate::ValidatedAuthorityEffectReceiptV1>), JournalError> {
        let host = self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let expected = if complete { StartHostCoreScopePhaseV2::Applied }
            else { StartHostCoreScopePhaseV2::Applying };
        if host.phase != expected || host.core_entered { return Err(JournalError::ProtectedBoundary); }
        let contract = Arc::clone(&host.contract);
        let (dispatch, receipt) = self.native.take_host_effect_inputs_v2(&contract, complete)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((contract, dispatch, receipt))
    }
}
