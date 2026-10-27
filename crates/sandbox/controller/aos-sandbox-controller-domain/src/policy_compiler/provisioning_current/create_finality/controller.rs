//! Retains preterminal Controller selectors and established durable validators.
//!
//! The enclosing Root final stage pays the complete reached decoder/map
//! invoice before entering. This owner borrows only the actual independently
//! captured Controller Journal; no replayed rows construct a writer or grant.

use std::error::Error;

use aos_sandbox_model::OperationId;
use aos_sandbox_protocol::domain_ledger::{
    operation::{OperationRecord, decode_operation, effect_key},
    public_operation::OperationState,
    effect_history::{EffectLedgerRecord, EffectState, PublicMutationEffectHistoryV1,
        CreateStoppedLifecycleReceiptDataV1, decode_effect},
    ownership_gate::OwnershipGateStatusV1,
    provisioning_resources::{ProvisioningResourceRecordsV1, decode_provisioning_resource_row_v1,
        provisioning_parent_key_v1, validate_provisioning_resource_links_v1},
};
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use crate::journal::{JournalError, RecordNamespace};
use crate::journal::historical_observation::HistoricalObservationV1;
use crate::controller_service::public_projection::get_from_observation_v2;
use aos_sandbox_protocol::public_api::projection::{PublicProjectionKindV1, PublicProjectionRecordV1};
use crate::publication::{CurrentAuthorityPublicationV1,
    validate_durable_effect_attempt_observed_v2, validate_publication_observed_v2};
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityLimits};
use crate::cold_launch_publication::completion::{CreateStoppedPreAckSubjectsV1,
    require_create_stopped_pre_ack_v1, CreateStoppedEvidenceSubjectsV2,
    CreateStoppedHistoricalSubjectsV2, require_create_stopped_historical_v2};
use aos_sandbox_policy::native::RootCreateStoppedHistoricalOriginalV2;
use crate::lifecycle::{LifecycleOperationV1, LifecycleRecordDigestV1};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory;

type Cause = Box<dyn Error>;

pub(crate) struct CreateFinalityControllerOriginalV1 {
    parent: Option<Result<OperationRecord, Cause>>,
    child: Option<Result<OperationRecord, Cause>>,
    parent_effect: Option<Result<EffectLedgerRecord, Cause>>,
    child_effect: Option<Result<EffectLedgerRecord, Cause>>,
    accepted: Option<Result<PublicMutationEffectHistoryV1, Cause>>,
    request: Option<Result<DormantSandboxRequestKindV1, Cause>>,
    resources: Option<Result<ProvisioningResourceRecordsV1, Cause>>,
    parent_projection: Option<Result<PublicProjectionRecordV1, Cause>>,
    gate: Option<Result<OwnershipGateStatusV1, Cause>>,
    binding: Option<Result<RuntimeAuthorityBindingV1, Cause>>,
    publication: Option<Result<CurrentAuthorityPublicationV1, Cause>>,
    returned: Option<Result<(), Cause>>,
    reentered: bool,
}

impl CreateFinalityControllerOriginalV1 {
    /// Prices new same-owner interfaces before any Controller candidate grows.
    pub(crate) fn observation_control_bytes_v2() -> Option<usize> {
        Self::common_observation_control_bytes_v2()?
            .checked_add(HistoricalObservationV1::receiving_control_bytes_v1()?)?
            .checked_add(crate::controller_service::public_projection::projection_observation_control_bytes_v2()?)?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
    }

    /// Prices the actual historical branch, which does not read a current projection.
    pub(crate) fn historical_observation_control_bytes_v2() -> Option<usize> {
        Self::common_observation_control_bytes_v2()?
            .checked_add(std::mem::size_of::<&RootCreateStoppedHistoricalOriginalV2>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), aos_sandbox_policy::native::RootReadonlyErrorV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(aos_sandbox_policy::native::RootReadonlyErrorV1, JournalError)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), JournalError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
    }

    fn common_observation_control_bytes_v2() -> Option<usize> {
        let interfaces = std::mem::size_of::<HistoricalObservationV1<'_>>().checked_mul(3)?
            .checked_add(std::mem::size_of::<(
                &mut Self, HistoricalObservationV1<'_>, CreateStoppedLifecycleReceiptDataV1<'_>,
                OperationId, &[u8], Option<&RootCreateStoppedHistoricalOriginalV2>,
            )>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), Cause>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), JournalError>>().checked_mul(3)?)?;
        interfaces
            .checked_add(crate::publication::current_observation_control_bytes_v2()?)?
            .checked_add(crate::publication::gate_observation_control_bytes_v2()?)?
            .checked_add(crate::publication::effect_observation_control_bytes_v2()?)?
            .checked_add(crate::runtime_authority::current_observation_control_bytes_v2()?)?
            .checked_add(crate::reconciler::ownership_gate_observation_control_bytes_v2()?)?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(crate) fn new() -> Self {
        Self { parent: None, child: None, parent_effect: None, child_effect: None,
            accepted: None, request: None, resources: None, parent_projection: None, gate: None,
            binding: None, publication: None, returned: None, reentered: false }
    }

    pub(crate) fn observe_once_v1(&mut self, controller: HistoricalObservationV1<'_>,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>, expected_parent: OperationId,
        final_receipt: &[u8],
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.returned = Some(self.observe_inner_v1(controller, receipt, expected_parent, final_receipt, None));
        self.require_complete_v1()
    }

    /// Selects the same canonical models after a genuine historical native proof.
    pub(crate) fn observe_historical_once_v2(&mut self, controller: HistoricalObservationV1<'_>,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>, expected_parent: OperationId,
        final_receipt: &[u8], historical: &RootCreateStoppedHistoricalOriginalV2,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.returned = Some(self.observe_inner_v1(controller, receipt, expected_parent,
            final_receipt, Some(historical)));
        self.require_complete_v1()
    }

    fn observe_inner_v1(&mut self, controller: HistoricalObservationV1<'_>,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>, expected_parent: OperationId,
        final_receipt: &[u8], historical: Option<&RootCreateStoppedHistoricalOriginalV2>,
    ) -> Result<(), Cause> {
        validate_publication_observed_v2(controller)?;
        validate_provisioning_resource_links_v1(
            controller.state_v1())?;
        if receipt.operation_v1() != expected_parent { return Err(JournalError::ProtectedBoundary.into()); }
        self.parent = Some(operation_v1(controller, expected_parent));
        let parent = value(&self.parent)?;
        // The ordinary path remains pre-ACK Applying. Only an actual full
        // historical native receipt selects Succeeded after the terminal CAS.
        let expected_state = if historical.is_some() { OperationState::Succeeded }
            else { OperationState::Applying };
        if parent.state() != expected_state { return Err(JournalError::ProtectedBoundary.into()); }
        let publication_operation = receipt.publication_operation_v1();
        self.child = Some(operation_v1(controller, publication_operation));
        if self.parent_effect.is_none() {
            self.parent_effect = Some(effect_v1(controller, expected_parent));
        }
        let parent_effect = value(&self.parent_effect)?;
        if !matches!(parent_effect.state(), EffectState::Applied { receipt, .. }
            if receipt.as_bytes() == final_receipt)
        { return Err(JournalError::ProtectedBoundary.into()); }
        self.accepted = Some(parent_effect.plan().public_mutation_context()
            .map_err(|cause| Box::new(cause) as Cause)
            .and_then(|context| context.ok_or_else(|| Box::new(JournalError::ProtectedBoundary) as Cause)));
        self.request = Some(value(&self.accepted)?.validated_request().map_err(|cause| Box::new(cause) as Cause));
        let key = provisioning_parent_key_v1(expected_parent);
        self.resources = Some((|| {
            let raw = controller.get(RecordNamespace::DesiredState, &key).ok_or(JournalError::ProtectedBoundary)?;
            let (_, records) = decode_provisioning_resource_row_v1(&key, raw)?
                .ok_or(JournalError::ProtectedBoundary)?;
            records.require_companions_v1(controller.state_v1())?;
            Ok(records)
        })());
        let sandbox = value(&self.resources)?.fields_v1().sandbox;
        if let Some(historical) = historical {
            let fields = value(&self.resources)?.fields_v1();
            let operation = controller.get(RecordNamespace::Operation, expected_parent.as_bytes())
                .ok_or(JournalError::ProtectedBoundary)?;
            let effect = controller.get(RecordNamespace::Effect, &effect_key(expected_parent, 0))
                .ok_or(JournalError::ProtectedBoundary)?;
            historical.require_rows_v2(expected_parent, fields.project, fields.sandbox, operation, effect)
                .map_err(crate::journal::historical_observation::root_readonly_error_v1)?;
        } else {
            self.parent_projection = Some(get_from_observation_v2(controller,
                PublicProjectionKindV1::Sandbox, *sandbox.as_bytes())
                .map_err(|cause| Box::new(cause) as Cause)
                .and_then(|projection| projection.ok_or_else(|| Box::new(JournalError::ProtectedBoundary) as Cause)));
            value(&self.parent_projection)?;
        }
        self.gate = Some(crate::reconciler::validated_ownership_gate_from_observation_v2(controller, publication_operation)
            .map_err(|cause| Box::new(cause) as Cause)
            .and_then(|gate| gate.ok_or_else(|| Box::new(JournalError::ProtectedBoundary) as Cause)));
        let OwnershipGateStatusV1::Activated { publication_digest, .. } = value(&self.gate)?
        else { return Err(JournalError::ProtectedBoundary.into()); };
        let activated = *publication_digest;
        self.binding = Some((|| {
            crate::runtime_authority::current_observed_v2(
                controller, RuntimeAuthorityLimits::default(), sandbox)?.ok_or_else(|| Box::new(JournalError::ProtectedBoundary) as Cause)
        })());
        self.publication = Some(crate::publication::current_observed_v2(controller, sandbox)
            .map_err(|cause| Box::new(cause) as Cause)
            .and_then(|publication| publication.ok_or_else(|| Box::new(JournalError::ProtectedBoundary) as Cause)));
        self.child_effect = Some(effect_v1(controller, publication_operation));
        value(&self.binding)?;
        let effect = value(&self.child_effect)?;
        let authority = effect.plan().authority().ok_or(JournalError::ProtectedBoundary)?;
        let dispatch = effect.dispatch().ok_or(JournalError::ProtectedBoundary)?;
        // The dispatch binds the effect authority, while the runtime binding
        // remains independently joined by the complete pre-ACK comparison.
        validate_durable_effect_attempt_observed_v2(controller, sandbox, activated, authority.digest(),
            authority.source_draft_digest(), authority.audience(), authority.template_digest(),
            effect.plan().request(), dispatch, None)?;
        let EffectState::Applied { receipt, .. } = effect.state()
        else { return Err(JournalError::ProtectedBoundary.into()); };
        crate::reconciler::validate_durable_receipt_history_v1(dispatch, receipt.as_bytes())?;
        Ok(())
    }

    pub(crate) fn compare_data_v1(&self, controller: HistoricalObservationV1<'_>,
        source: &LifecycleOperationV1, source_record: LifecycleRecordDigestV1,
        apply: &AuthenticatedBrokerMethodOutcomeV1,
        apply_response: &aos_sandbox_api::aos::sandbox::local::v1::StorageResult,
        inventory_exchange: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &ValidatedStorageInventory,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>,
        root: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
        admitted_plan: &[u8], lane: [u8; 16],
    ) -> Result<(), Cause> {
        self.require_complete_v1()?;
        let child_operation = *value(&self.child)?;
        let child_bytes = controller.get(RecordNamespace::Effect,
            &effect_key(receipt.publication_operation_v1(), 0)).ok_or(JournalError::ProtectedBoundary)?;
        let DormantSandboxRequestKindV1::Create(request) = value(&self.request)?
        else { return Err(JournalError::ProtectedBoundary.into()); };
        require_create_stopped_pre_ack_v1(CreateStoppedPreAckSubjectsV1 {
            receipt, resources: *value(&self.resources)?, original_root: root,
            accepted: value(&self.accepted)?, lane, parent_operation: *value(&self.parent)?,
            parent_effect: value(&self.parent_effect)?, parent_projection: value(&self.parent_projection)?,
            request, child_operation,
            child: value(&self.child_effect)?, child_bytes, binding: value(&self.binding)?,
            publication: value(&self.publication)?, source, source_record,
            apply, apply_response, inventory_exchange, inventory,
            admitted_plan,
        })?;
        Ok(())
    }

    /// Reuses the sole workspace/Source comparison after actual historical replay.
    ///
    /// The enclosing Host owner separately authenticates both exact signed
    /// historical exchanges and the full Source Completing-to-Terminal chain.
    pub(crate) fn compare_historical_once_v2(&self, controller: HistoricalObservationV1<'_>,
        historical: &RootCreateStoppedHistoricalOriginalV2,
        source: &crate::lifecycle::LifecycleOperationV1,
        source_record: crate::lifecycle::LifecycleRecordDigestV1,
        receipt: CreateStoppedLifecycleReceiptDataV1<'_>,
        root: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
        admitted_plan: &[u8], lane: [u8; 16],
        apply: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        apply_response: &aos_sandbox_api::aos::sandbox::local::v1::StorageResult,
        inventory_exchange: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory,
    ) -> Result<(), Cause> {
        self.require_complete_v1()?;
        let parent = receipt.operation_v1();
        let operation = controller.get(RecordNamespace::Operation, parent.as_bytes())
            .ok_or(JournalError::ProtectedBoundary)?;
        let effect = controller.get(RecordNamespace::Effect, &effect_key(parent, 0))
            .ok_or(JournalError::ProtectedBoundary)?;
        let child_bytes = controller.get(RecordNamespace::Effect,
            &effect_key(receipt.publication_operation_v1(), 0)).ok_or(JournalError::ProtectedBoundary)?;
        let DormantSandboxRequestKindV1::Create(request) = value(&self.request)?
        else { return Err(JournalError::ProtectedBoundary.into()); };
        require_create_stopped_historical_v2(CreateStoppedHistoricalSubjectsV2 {
            native: historical,
            parent_operation_bytes: operation,
            parent_effect_bytes: effect,
            evidence: CreateStoppedEvidenceSubjectsV2 {
                receipt, resources: *value(&self.resources)?, original_root: root,
                accepted: value(&self.accepted)?, lane, parent_operation: *value(&self.parent)?,
                parent_effect: value(&self.parent_effect)?, request,
                child_operation: *value(&self.child)?, child: value(&self.child_effect)?, child_bytes,
                binding: value(&self.binding)?, publication: value(&self.publication)?, source, source_record,
                apply, apply_response, inventory_exchange, inventory, admitted_plan,
            },
        })?;
        Ok(())
    }

    pub(crate) fn resources_v2(&self)
        -> Result<ProvisioningResourceRecordsV1, JournalError> {
        self.require_complete_v1()?;
        value(&self.resources).copied()
    }

    pub(crate) fn publication_v2(&self)
        -> Result<&CurrentAuthorityPublicationV1, JournalError> {
        self.require_complete_v1()?;
        value(&self.publication)
    }

    /// Selects the same strict preterminal C models from the actual held Effect.
    ///
    /// Recovery does not supply an adopted receipt. The canonical historical
    /// Applied bytes are first retained by this same owner; their fixed copy
    /// permits the existing mutable selector to consume them without an alias.
    pub(crate) fn observe_recovery_once_v1(&mut self, controller: HistoricalObservationV1<'_>,
        parent: OperationId, lane: [u8; 16],
    ) -> Result<(), JournalError> {
        if self.returned.is_some() || self.parent_effect.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.returned = Some((|| {
            self.parent_effect = Some(effect_v1(controller, parent));
            let EffectState::Applied { receipt, .. } = value(&self.parent_effect)?.state()
            else { return Err(JournalError::ProtectedBoundary.into()); };
            let bytes: [u8; aos_sandbox_protocol::domain_ledger::effect_history::
                CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1] = receipt.as_bytes().try_into()?;
            let aos_sandbox_protocol::domain_ledger::effect_history::
                LifecycleEffectReceiptDataV1::CreateStopped(receipt) =
                aos_sandbox_protocol::domain_ledger::effect_history::
                    decode_lifecycle_effect_receipt_v1(&bytes, lane)?
            else { return Err(JournalError::ProtectedBoundary.into()); };
            self.observe_inner_v1(controller, receipt, parent, &bytes, None)
        })());
        self.require_complete_v1()
    }

    pub(crate) fn receipt_bytes_v1(&self) -> Result<&[u8], JournalError> {
        self.require_complete_v1()?;
        match value(&self.parent_effect)?.state() {
            EffectState::Applied { receipt, .. } => Ok(receipt.as_bytes()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Borrows only the actual independently replayed Controller subjects.
    pub(crate) fn models_v1(&self) -> Result<CreateFinalityControllerDataV1<'_>, JournalError> {
        self.require_complete_v1()?;
        Ok(CreateFinalityControllerDataV1 {
            parent: value(&self.parent)?, parent_effect: value(&self.parent_effect)?,
            accepted: value(&self.accepted)?, request: value(&self.request)?,
            resources: value(&self.resources)?, projection: value(&self.parent_projection)?,
            child: value(&self.child)?, child_effect: value(&self.child_effect)?,
            binding: value(&self.binding)?, publication: value(&self.publication)?,
        })
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if !self.reentered && matches!(self.returned, Some(Ok(()))) && self.failure().is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.parent).or_else(|| cause(&self.child)).or_else(|| cause(&self.parent_effect))
            .or_else(|| cause(&self.accepted)).or_else(|| cause(&self.request))
            .or_else(|| cause(&self.resources)).or_else(|| cause(&self.parent_projection)).or_else(|| cause(&self.gate))
            .or_else(|| cause(&self.binding)).or_else(|| cause(&self.publication))
            .or_else(|| cause(&self.child_effect)).or_else(|| cause(&self.returned))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn value<T>(result: &Option<Result<T, Cause>>) -> Result<&T, JournalError> {
    result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T>(result: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}

fn operation_v1(controller: HistoricalObservationV1<'_>, operation: OperationId) -> Result<OperationRecord, Cause> {
    Ok(decode_operation(controller.get(RecordNamespace::Operation, operation.as_bytes())
        .ok_or(JournalError::ProtectedBoundary)?)?)
}

fn effect_v1(controller: HistoricalObservationV1<'_>, operation: OperationId) -> Result<EffectLedgerRecord, Cause> {
    Ok(decode_effect(controller.get(RecordNamespace::Effect, &effect_key(operation, 0))
        .ok_or(JournalError::ProtectedBoundary)?)?)
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;

/// Borrows complete historical DATA without minting a current authority or writer.
pub(crate) struct CreateFinalityControllerDataV1<'models> {
    pub(crate) parent: &'models OperationRecord,
    pub(crate) parent_effect: &'models EffectLedgerRecord,
    pub(crate) accepted: &'models PublicMutationEffectHistoryV1,
    pub(crate) request: &'models DormantSandboxRequestKindV1,
    pub(crate) resources: &'models ProvisioningResourceRecordsV1,
    pub(crate) projection: &'models PublicProjectionRecordV1,
    pub(crate) child: &'models OperationRecord,
    pub(crate) child_effect: &'models EffectLedgerRecord,
    pub(crate) binding: &'models RuntimeAuthorityBindingV1,
    pub(crate) publication: &'models CurrentAuthorityPublicationV1,
}
