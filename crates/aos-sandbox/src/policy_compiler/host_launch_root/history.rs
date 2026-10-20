//! Joins historical Create through the actual Host native and semantic owners.
//!
//! The genuine Host stage pays every reached selector before model growth.
//! Historical STOPPED is the closed native COMMIT/EOF receipt, while the same
//! current Source cut supplies both immutable Completing and latest Terminal.
//! Neither current projection bytes nor historical packet deadlines grant Start.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{OperationId, ResourceId, ResourceDimension as D, ResourceVector};
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_protocol::domain_ledger::{
    operation::effect_key,
    effect_history::{EffectLedgerRecord, EffectState, LifecycleEffectReceiptDataV1,
        decode_effect, decode_lifecycle_effect_receipt_v1, effect_decoding_receiving_bytes_v1},
    create_storage_history::continuation::ContinuationNativeReceiptDataV1,
};

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::{JournalError, RecordNamespace};
use crate::lifecycle::{LifecycleHistoricalReadOriginalV1,
    retained_lifecycle_replay_receiving_demand_v1};
use crate::lifecycle::protected_journal::{LifecycleProtectedRecordKindV1,
    lifecycle_protected_key_v1};
use crate::normal_root::{NormalRootStartupErrorV1, RootHostLaunchStageReceivingV1};
use crate::cold_launch_publication::completion::{
    create_stopped_controller_receiving_demand_v1,
    create_stopped_historical_comparison_receiving_demand_v2, require_create_terminal_source_v1,
};
use crate::policy_compiler::provisioning_current::{
    RootProvisioningNativeViewsV1,
    apply_readonly::RootHostReadonlyContextV2,
    HistoricalCreateSessionOriginalV1,
};
use crate::policy_compiler::provisioning_current::create_finality::controller::CreateFinalityControllerOriginalV1;

type Cause = Box<dyn Error>;

pub(crate) struct RootHostHistoricalCreateOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    effect: Option<Result<EffectLedgerRecord, Cause>>,
    controller: CreateFinalityControllerOriginalV1,
    source: LifecycleHistoricalReadOriginalV1,
    session: HistoricalCreateSessionOriginalV1,
    result: Option<Result<(), Cause>>,
    reentered: bool,
}

impl RootHostHistoricalCreateOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None, funding: None, effect: None,
            controller: CreateFinalityControllerOriginalV1::new(),
            source: LifecycleHistoricalReadOriginalV1::new(),
            session: HistoricalCreateSessionOriginalV1::new(),
            result: None, reentered: false,
        }
    }

    fn receiving_demand_v2(&self, readonly: &RootHostReadonlyContextV2,
        views: &RootProvisioningNativeViewsV1, parent: OperationId,
    ) -> Result<ResourceVector, JournalError> {
        let state = readonly.controller_state_v2()?;
        let source = views.prepared_host_launch_source_v2()?;
        let effect = row(state, RecordNamespace::Effect, &effect_key(parent, 0))
            .ok_or(JournalError::ProtectedBoundary)?;
        let effect_bytes = effect_decoding_receiving_bytes_v1(effect.len())
            .ok_or(JournalError::JournalTooLarge)?;
        let fixed = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(effect_bytes))
            .and_then(|bytes| bytes.checked_add(LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let schema = retained_lifecycle_replay_receiving_demand_v1(source.all_records())
            .ok_or(JournalError::JournalTooLarge)?;
        let controller = create_stopped_controller_receiving_demand_v1(state)
            .ok_or(JournalError::JournalTooLarge)?;
        let comparison = create_stopped_historical_comparison_receiving_demand_v2()
            .ok_or(JournalError::JournalTooLarge)?;
        let session = HistoricalCreateSessionOriginalV1::decoding_receiving_demand_v1(
            usize::try_from(readonly.session_v2()?.end).map_err(|_| JournalError::JournalTooLarge)?)?;
        controller.checked_add(schema)
            .and_then(|demand| demand.checked_add(comparison))
            .and_then(|demand| demand.checked_add(session))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed)))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn observe_once_v2(&mut self, stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        readonly: &mut RootHostReadonlyContextV2, views: &RootProvisioningNativeViewsV1,
        parent: OperationId, manifest: &BrokerSessionManifestV1,
        original_root: ContinuationNativeReceiptDataV1<'_>, lane: [u8; 16],
        node: [u8; 16], boot: [u8; 16],
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some(self.receiving_demand_v2(readonly, views, parent));
        let demand = self.geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(JournalError::JournalTooLarge)?;
        self.funding = Some(stage.admit_host_historical_create_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v2(readonly, views, parent, manifest,
            original_root, lane, node, boot));
        self.require_complete_v2()
    }

    fn observe_inner_v2(&mut self, readonly: &mut RootHostReadonlyContextV2,
        views: &RootProvisioningNativeViewsV1, parent: OperationId,
        manifest: &BrokerSessionManifestV1, original_root: ContinuationNativeReceiptDataV1<'_>,
        lane: [u8; 16], node: [u8; 16], boot: [u8; 16],
    ) -> Result<(), Cause> {
        let state = readonly.controller_state_v2()?;
        let operation = row(state, RecordNamespace::Operation, parent.as_bytes())
            .ok_or(JournalError::ProtectedBoundary)?;
        let effect = row(state, RecordNamespace::Effect, &effect_key(parent, 0))
            .ok_or(JournalError::ProtectedBoundary)?;
        let historical = readonly.historical_v2()?;
        // Root's private receipt already joins exact parent/project/sandbox.
        // The graph loader additionally checks these same raw current models.
        self.effect = Some(decode_effect(effect).map_err(|cause| Box::new(cause) as Cause));
        let model = self.effect.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let EffectState::Applied { receipt: applied, .. } = model.state()
        else { return Err(JournalError::ProtectedBoundary.into()); };
        let receipt_bytes = applied.as_bytes();
        let LifecycleEffectReceiptDataV1::CreateStopped(receipt) =
            decode_lifecycle_effect_receipt_v1(receipt_bytes, lane)?
        else { return Err(JournalError::ProtectedBoundary.into()); };
        let (_, project, sandbox) = historical.target_v2();
        historical.require_rows_v2(parent, project, sandbox, operation, effect)?;

        // The native receipt is fixed and owned by readonly. Field-splitting
        // its model lets the same graph loaders borrow a mutable readonly C.
        {
            let (controller, historical) = readonly.controller_with_historical_v2()?;
            self.controller.observe_historical_once_v2(controller, receipt,
                parent, receipt_bytes, historical)?;
        }
        let fields = self.controller.resources_v2()?.fields_v1();
        let source = views.prepared_host_launch_source_v2()?;
        self.source.observe_once_v1(source, parent)?;
        let key = lifecycle_protected_key_v1(LifecycleProtectedRecordKindV1::Effect,
            fields.project, ResourceId::from_bytes(*fields.sandbox.as_bytes()), parent)?;
        self.source.historical_once_v1(parent, &key)?;
        self.session.observe_host_once_v2(readonly.session_v2()?, manifest, node, boot)?;
        self.session.require_plan_association_v1(self.controller.publication_v2()?)?;
        let (completing, record) = self.source.historical_operation_v1()?;
        let (terminal, _) = self.source.operation_v1()?;
        let (inventory_exchange, inventory) = self.session.inventory_v1()?;
        require_create_terminal_source_v1(completing, record, terminal,
            aos_sandbox_core::ObjectDigest::from_bytes(inventory.encoded_response_digest_v1()))?;
        let (controller, historical) = readonly.controller_with_historical_v2()?;
        self.controller.compare_historical_once_v2(controller,
            historical, completing, record, receipt, original_root,
            self.session.admitted_plan_v1()?, lane, self.session.apply_v1()?,
            self.session.apply_response_v1()?, inventory_exchange, inventory)?;
        Ok(())
    }

    /// Borrows selectors from the actual authenticated immutable Create pair.
    ///
    /// The same canonical comparison, completed historical native proof and
    /// Source relation remain prerequisites; this performs no new IO or replay.
    pub(crate) fn creation_workspace_selectors_v2(&self)
        -> Result<([u8; 32], [u8; 16]), JournalError>
    {
        self.require_complete_v2()?;
        let models = self.controller.models_v1()?;
        let (_, inventory) = self.session.inventory_v1()?;
        let workspace = crate::cold_launch_publication::completion::
            selected_create_workspace_inventory_data_v2(*models.resources, models.binding,
                self.session.apply_response_v1()?, inventory)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((*workspace.workspace_handle(), *workspace.creation_operation_id()))
    }

    pub(crate) fn current_storage_history_v2(
        &self,
        native: &crate::policy_compiler::create_storage_current::controller_readonly::
            native_read::RootFixedNativeReadbackV1<'_>,
    ) -> Result<crate::policy_compiler::provisioning_current::HistoricalStorageHistoryBorrowV2<'_>, JournalError> {
        self.require_complete_v2()?;
        self.session.verified_history_for_native_v2(native)
    }

    pub(crate) fn creation_inventory_v2(&self)
        -> Result<&aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory, JournalError>
    {
        self.require_complete_v2()?;
        self.session.inventory_v1().map(|(_, inventory)| inventory)
    }

    pub(crate) fn require_current_workspace_inventory_v2(
        &self,
        inventory: &aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory,
    ) -> Result<(), JournalError> {
        self.require_complete_v2()?;
        let models = self.controller.models_v1()?;
        crate::cold_launch_publication::completion::require_create_workspace_inventory_data_v1(
            *models.resources, models.binding, self.session.apply_response_v1()?, inventory,
        ).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if !self.reentered && matches!(self.funding, Some(Ok(())))
            && matches!(self.result, Some(Ok(()))) && self.failure().is_none()
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.funding.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.effect.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.controller.failure())
            .or_else(|| self.source.failure())
            .or_else(|| self.session.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn row<'state>(
    state: &'state std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    namespace: RecordNamespace, key: &[u8],
) -> Option<&'state [u8]> {
    state.iter().find_map(|((actual, name), value)| {
        (*actual == namespace && name.as_slice() == key).then_some(value.as_slice())
    })
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;
