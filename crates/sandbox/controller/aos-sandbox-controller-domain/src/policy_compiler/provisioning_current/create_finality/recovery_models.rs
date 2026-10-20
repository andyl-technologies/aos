//! Joins independent Root C/Source reads with both signed Storage observations.
//!
//! The new Recover authorization and native payer remain distinct from the
//! historical successful Apply. This owner compares metadata-only finality; it
//! cannot issue a plan, resume a request or construct an old C23/Root original.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceId, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationKindV1;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    decode_lifecycle_effect_receipt_v1, LifecycleEffectReceiptDataV1,
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::FinalityRecoverQueryDataV1;
use sha2::{Digest as _, Sha256};

use crate::cold_launch_publication::completion::{
    create_stopped_comparison_receiving_demand_v1, create_stopped_controller_receiving_demand_v1,
    require_create_terminal_source_v1, require_create_workspace_inventory_data_v1,
};
use crate::journal::{Journal, JournalError};
use crate::lifecycle::protected_journal::{
    lifecycle_protected_key_v1, LifecycleProtectedRecordKindV1, LifecycleReplayReceivingV1,
};
use crate::lifecycle::{
    retained_lifecycle_replay_receiving_demand_v1, LifecycleHistoricalReadOriginalV1,
};
use crate::normal_root::RootPolicyAcceptedFlightV1;

use super::{
    authorization::CreateFinalityAuthorizationOriginalV1,
    controller::CreateFinalityControllerOriginalV1, session::CreateFinalitySessionOriginalV1,
};

type Cause = Box<dyn Error>;

/// Retains the actual paid full models and exact comparison result.
pub(crate) struct CreateFinalityRecoveryModelsOriginalV1 {
    authorization: CreateFinalityAuthorizationOriginalV1,
    controller: CreateFinalityControllerOriginalV1,
    source: LifecycleHistoricalReadOriginalV1,
    root_closed: Option<Result<(), Cause>>,
    result: Option<Result<(), Cause>>,
    reentered: bool,
}

impl CreateFinalityRecoveryModelsOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            authorization: CreateFinalityAuthorizationOriginalV1::new(),
            controller: CreateFinalityControllerOriginalV1::new(),
            source: LifecycleHistoricalReadOriginalV1::new(),
            root_closed: None,
            result: None,
            reentered: false,
        }
    }

    /// Prices every reached selector before candidates or semantic models grow.
    pub(crate) fn receiving_demand_v1(
        controller: &Journal,
        source: &Journal,
        query: FinalityRecoverQueryDataV1,
    ) -> Result<ResourceVector, Cause> {
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let selection =
            LifecycleReplayReceivingV1::additional_selection_receiving_v1(source.all_records())
                .ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()?)
            })
            .and_then(|bytes| {
                bytes.checked_add(ContinuationKindV1::Closed.receipt_bytes().checked_mul(3)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let projection =
            crate::controller_service::public_projection::sandbox_source_receiving_bytes_v1(
                controller,
            )
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(
            CreateFinalityAuthorizationOriginalV1::receiving_demand_v1(controller, query)?
                .checked_add(
                    create_stopped_controller_receiving_demand_v1(state)
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(
                    create_stopped_comparison_receiving_demand_v1()
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(
                    retained_lifecycle_replay_receiving_demand_v1(source.all_records())
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(selection)?
                .checked_add(
                    ResourceVector::ZERO.with(
                        D::MemoryBytes,
                        bytes
                            .checked_add(projection)
                            .ok_or(JournalError::JournalTooLarge)?,
                    ),
                )?,
        )
    }

    /// Compares only actual independently read models under the genuine flight.
    pub(crate) fn observe_once_v1(
        &mut self,
        controller: &mut Journal,
        source: &Journal,
        session: &CreateFinalitySessionOriginalV1,
        query: FinalityRecoverQueryDataV1,
        node: [u8; 16],
        partition: (ResourceVector, ResourceVector, ResourceVector),
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(
            self.observe_inner_v1(controller, source, session, query, node, partition, flight),
        );
        self.require_complete_v1()
    }

    fn observe_inner_v1(
        &mut self,
        controller: &mut Journal,
        source: &Journal,
        session: &CreateFinalitySessionOriginalV1,
        query: FinalityRecoverQueryDataV1,
        node: [u8; 16],
        partition: (ResourceVector, ResourceVector, ResourceVector),
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), Cause> {
        self.authorization
            .observe_once_v1(controller, query, node, partition)?;
        let target = self.authorization.target_v1()?;
        self.controller
            .observe_recovery_once_v1(controller, target, query.lane)?;
        let models = self.controller.models_v1()?;
        session.require_plan_association_v1(models.publication)?;

        // The same full schema replay supplies latest Terminal and the preserved
        // Completing Effect named by516. No writer or current Source capability
        // is reconstructed from these independently observed historical rows.
        self.source.observe_once_v1(source, target)?;
        let fields = models.resources.fields_v1();
        let key = lifecycle_protected_key_v1(
            LifecycleProtectedRecordKindV1::Effect,
            fields.project,
            ResourceId::from_bytes(*fields.sandbox.as_bytes()),
            target,
        )?;
        self.source.historical_once_v1(target, &key)?;
        let (completing, completing_record) = self.source.historical_operation_v1()?;
        let (terminal, _) = self.source.operation_v1()?;
        let (old_inventory, old_inventory_model) = session.historical_inventory_v1()?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = old_inventory.result()
        else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        require_create_terminal_source_v1(
            completing,
            completing_record,
            terminal,
            ObjectDigest::from_bytes(Sha256::digest(exact_body).into()),
        )?;

        let LifecycleEffectReceiptDataV1::CreateStopped(receipt) =
            decode_lifecycle_effect_receipt_v1(self.controller.receipt_bytes_v1()?, query.lane)?
        else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        let root = receipt.root_closed_v1();
        let mut root_bytes = [0; ContinuationKindV1::Closed.receipt_bytes()];
        root.encode_into(query.lane, ContinuationKindV1::Closed, &mut root_bytes)?;
        self.root_closed = Some(
            flight
                .require_finality_recover_storage_closed_v1(&root_bytes)
                .map_err(|cause| Box::new(cause) as Cause),
        );
        if !matches!(self.root_closed, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let [template] = models.publication.templates() else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        self.controller.compare_data_v1(
            controller,
            completing,
            completing_record,
            session.apply_v1()?,
            session.apply_response_v1()?,
            old_inventory,
            old_inventory_model,
            receipt,
            root,
            template.canonical_plan(),
            query.lane,
        )?;

        // The fresh distinct Session is independently signed and current; only
        // its catalog comparison shares the pure old workspace tail. The old
        // Apply→Inventory Session ordering predicate above remains unchanged.
        let (_, inventory) = session.fresh_inventory_v1()?;
        require_create_workspace_inventory_data_v1(
            *models.resources,
            models.binding,
            session.apply_response_v1()?,
            inventory,
        )?;
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if !self.reentered && matches!(self.result, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn controller_v1(
        &self,
    ) -> Result<super::controller::CreateFinalityControllerDataV1<'_>, JournalError> {
        self.require_complete_v1()?;
        self.controller.models_v1()
    }

    pub(crate) fn receipt_bytes_v1(&self) -> Result<&[u8], JournalError> {
        self.require_complete_v1()?;
        self.controller.receipt_bytes_v1()
    }

    pub(crate) fn source_terminal_commitment_v1(&self) -> Result<[u8; 32], JournalError> {
        self.require_complete_v1()?;
        Ok(*self.source.operation_v1()?.1.digest().as_bytes())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.authorization
            .failure()
            .or_else(|| self.controller.failure())
            .or_else(|| self.source.failure())
            .or_else(|| {
                self.root_closed
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| &**cause)
            })
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| &**cause))
    }
}
