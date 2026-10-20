//! Classifies the complete supported historical Create/Start/settled-Stop family.
//!
//! These comparisons run under the caller's actual paid current C/Source cut.
//! Unknown or pending lifecycle families remain closed. Literal failed Stop
//! attempts are classified only by the shared completed-Stop/A8 proof.

use sha2::Digest as _;
use std::error::Error;
use std::mem::size_of;

use super::completed_start::CatalogMaintenanceCompletedStartOriginalV1;
use super::recover_family::CatalogMaintenanceRecoverFamilyOriginalV1;
use crate::lifecycle::{
    LifecycleCurrentOperationSelectionOriginalV1, LifecycleHistoricalReadOriginalV1,
    LifecycleIntentV1, LifecyclePhaseV1, LifecycleTerminalResultV1,
    completed_stop::CompletedStopHistoryOriginalV1,
};
use crate::{Journal, JournalError, RecordNamespace};
use aos_sandbox_model::{ObjectDigest, OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::{
        KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1, controller_intent::ControllerIntentBodyDataV1,
    },
    effect_history::{
        EffectLedgerRecord, EffectState, LifecycleEffectReceiptDataV1, decode_effect,
        decode_lifecycle_effect_receipt_v1, lifecycle_child_effect_commitment_v1,
    },
    operation::{OperationRecord, decode_operation},
    provisioning_resources::{
        ProvisioningModeDataV1, ProvisioningResourceRecordsV1, decode_provisioning_resource_row_v1,
        provisioning_parent_key_v1,
    },
    public_operation::OperationState,
};
use aos_sandbox_protocol::public_api::{
    PublicOperationMethodV1,
    projection::{
        PROJECTION_KEY_PREFIX, PublicProjectionRecordV1, PublicProjectionResourceV1,
        decode_checked_public_projection_v1,
    },
};

const CLOSED: JournalError = JournalError::ProtectedBoundary;
type Cause = Box<dyn Error + Send + Sync>;

struct CreateEntry {
    source: LifecycleCurrentOperationSelectionOriginalV1,
    completing: LifecycleCurrentOperationSelectionOriginalV1,
    gate: Option<aos_sandbox_protocol::domain_ledger::ownership_gate::OwnershipGateStatusV1>,
    operation: Option<OperationRecord>,
    effect: Option<EffectLedgerRecord>,
    child: Option<OperationRecord>,
    child_effect: Option<EffectLedgerRecord>,
    resources: Option<ProvisioningResourceRecordsV1>,
    parent: OperationId,
    publication: Option<OperationId>,
}

impl CreateEntry {
    fn new(parent: OperationId) -> Self {
        Self {
            source: LifecycleCurrentOperationSelectionOriginalV1::new(),
            completing: LifecycleCurrentOperationSelectionOriginalV1::new(),
            gate: None,
            operation: None,
            effect: None,
            child: None,
            child_effect: None,
            resources: None,
            parent,
            publication: None,
        }
    }

    fn observe(
        &mut self,
        controller: &Journal,
        source: &LifecycleHistoricalReadOriginalV1,
        history: &CompletedStopHistoryOriginalV1,
        starts: &CatalogMaintenanceCompletedStartOriginalV1,
    ) -> Result<(), Cause> {
        let (projection, verifier) = source.projection_ready_v1()?;
        self.source
            .select_once_v1(projection, verifier, self.parent)?;
        let (_, original, _) = self.source.completed_v1().ok_or(CLOSED)?;
        let LifecycleIntentV1::Create { sandbox } = original.intent() else {
            return Err(CLOSED.into());
        };
        if original.phase() != LifecyclePhaseV1::Terminal
            || original.terminal_result() != Some(LifecycleTerminalResultV1::Succeeded)
            || !history
                .completed_operations_v1()?
                .any(|(_, project, target)| project == original.project() && target == *sandbox)
        {
            return Err(CLOSED.into());
        }

        aos_sandbox_protocol::domain_ledger::provisioning_resources::
            validate_provisioning_resource_links_v1(
                controller.historical_read_view_v1().materialized_state_v1())?;
        self.operation = Some(decode_operation(
            controller
                .get(RecordNamespace::Operation, self.parent.as_bytes())
                .ok_or(CLOSED)?,
        )?);
        let operation = self.operation.as_ref().ok_or(CLOSED)?;
        if operation.state() != OperationState::Succeeded
            || operation.effect_count() != 1
            || operation.ownership_gated()
            || operation.runtime_intent_digest().is_some()
            || operation
                .public_operation()
                .is_none_or(|public| public.method() != PublicOperationMethodV1::CreateSandbox)
        {
            return Err(CLOSED.into());
        }
        self.effect = Some(decode_effect(
            controller
                .get(
                    RecordNamespace::Effect,
                    &aos_sandbox_protocol::domain_ledger::operation::effect_key(self.parent, 0),
                )
                .ok_or(CLOSED)?,
        )?);
        let effect = self.effect.as_ref().ok_or(CLOSED)?;
        if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateSandbox)
            || effect.plan().authority().is_some()
        {
            return Err(CLOSED.into());
        }
        let context = effect.plan().public_mutation_context()?.ok_or(CLOSED)?;
        if context.project() != original.project() || context.caller() != original.caller() {
            return Err(CLOSED.into());
        }
        let request = context.validated_request()?;
        let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Create(request) =
            &request
        else {
            return Err(CLOSED.into());
        };
        let key = provisioning_parent_key_v1(self.parent);
        let raw = controller
            .get(RecordNamespace::DesiredState, &key)
            .ok_or(CLOSED)?;
        let (_, resources) = decode_provisioning_resource_row_v1(&key, raw)?.ok_or(CLOSED)?;
        resources
            .require_companions_v1(controller.historical_read_view_v1().materialized_state_v1())?;
        let fields = resources.fields_v1();
        if fields.mode != ProvisioningModeDataV1::CreateStopped
            || fields.parent != self.parent || fields.project != original.project()
            || fields.sandbox != *sandbox || fields.public_request
                != aos_sandbox_protocol::domain_ledger::provisioning_resources::
                    provisioning_public_request_digest_v1(context.canonical_request())
        { return Err(CLOSED.into()); }
        crate::cold_launch_publication::completion::require_create_source_admission_data_v1(
            original, resources, &context, request,
        )?;
        crate::cold_launch_publication::completion::require_create_source_semantic_manifest_v2(
            original,
            resources,
            starts
                .require_sandbox_v1(fields.project, fields.sandbox)?
                .manifest_v1(),
        )?;
        aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedTerminalTransactionDataV1::
            from_data_v1(self.parent, fields.project, fields.sandbox,
                controller.get(RecordNamespace::Operation, self.parent.as_bytes()).ok_or(CLOSED)?,
                controller.get(RecordNamespace::Effect,
                    &aos_sandbox_protocol::domain_ledger::operation::effect_key(self.parent, 0))
                    .ok_or(CLOSED)?)?;
        self.resources = Some(resources);
        self.publication = Some(fields.publication_operation);

        // The checked literal Intent supplies its historical lane. Neither
        // its old native names nor paired clock is adopted as current proof.
        let mut lane = None;
        for (key, value) in controller.records(RecordNamespace::CreateStorageHistory) {
            let key = KeyV1::decode(key)?;
            if key.owner() != OwnerV1::Controller || key.revision() != 1 {
                continue;
            }
            let envelope =
                RecordEnvelopeV1::decode(value, key, PhaseV1::new(OwnerV1::Controller, 1)?)?;
            let intent = ControllerIntentBodyDataV1::decode(envelope.body())?;
            if intent.identity.operation != self.parent.into_bytes() {
                continue;
            }
            if intent.identity.project != fields.project.into_bytes()
                || intent.identity.sandbox != fields.sandbox.into_bytes()
                || intent.identity.lane != key.lane()
                || lane.replace(key.lane()).is_some()
            {
                return Err(CLOSED.into());
            }
        }
        let EffectState::Applied { receipt, .. } = effect.state() else {
            return Err(CLOSED.into());
        };
        let LifecycleEffectReceiptDataV1::CreateStopped(receipt) =
            decode_lifecycle_effect_receipt_v1(receipt.as_bytes(), lane.ok_or(CLOSED)?)?
        else {
            return Err(CLOSED.into());
        };
        receipt.require_resources_v1(resources)?;
        if receipt.operation_v1() != self.parent
            || receipt.publication_operation_v1() != fields.publication_operation
        {
            return Err(CLOSED.into());
        }
        let historical_key = crate::lifecycle::lifecycle_protected_key_v1(
            crate::lifecycle::protected_journal::LifecycleProtectedRecordKindV1::Effect,
            fields.project,
            aos_sandbox_model::ResourceId::from_bytes(fields.sandbox.into_bytes()),
            self.parent,
        )?;
        self.completing
            .select_key_once_v1(projection, verifier, self.parent, &historical_key)?;
        let (_, completing, completing_record) = self.completing.completed_v1().ok_or(CLOSED)?;
        if receipt.source_v1().as_bytes() != completing_record.digest().as_bytes()
            || original.predecessor_digest() != Some(*completing_record)
        {
            return Err(CLOSED.into());
        }
        let [terminal_step] = original.steps() else {
            return Err(CLOSED.into());
        };
        // This typed digest is already in the actual authenticated terminal
        // Source record. It is historical comparison, never a new observation.
        let inventory = terminal_step.inventory().ok_or(CLOSED)?;
        crate::cold_launch_publication::completion::require_create_terminal_source_inventory_v2(
            completing,
            *completing_record,
            original,
            inventory,
        )?;
        let child_effect_key = aos_sandbox_protocol::domain_ledger::operation::effect_key(
            fields.publication_operation,
            0,
        );
        let child_effect = controller
            .get(RecordNamespace::Effect, &child_effect_key)
            .ok_or(CLOSED)?;
        if receipt.child_effect_v1() != lifecycle_child_effect_commitment_v1(child_effect) {
            return Err(CLOSED.into());
        }
        self.child = Some(decode_operation(
            controller
                .get(
                    RecordNamespace::Operation,
                    fields.publication_operation.as_bytes(),
                )
                .ok_or(CLOSED)?,
        )?);
        self.child_effect = Some(decode_effect(child_effect)?);
        let child = self.child.as_ref().ok_or(CLOSED)?;
        let effect = self.child_effect.as_ref().ok_or(CLOSED)?;
        if child.state() != OperationState::Succeeded
            || child.effect_count() != 1
            || child.public_operation().is_some()
            || !child.ownership_gated()
            || !matches!(effect.state(), EffectState::Applied { .. })
            || effect.plan().method()
                != Some(
                    aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                )
            || effect.plan().authority().is_none_or(|authority| {
                authority.operation_id() != fields.publication_operation
                    || authority.step() != 0
                    || authority.source_draft_digest() != fields.source_draft
            })
        {
            return Err(CLOSED.into());
        }
        self.gate = Some(
            aos_sandbox_protocol::domain_ledger::ownership_gate::decode_ownership_gate(
                controller
                    .get(
                        RecordNamespace::OwnershipGate,
                        fields.publication_operation.as_bytes(),
                    )
                    .ok_or(CLOSED)?,
            )?,
        );
        let gate =
            aos_sandbox_protocol::domain_ledger::runtime_authority_history::crosslinks::gate_plan(
                self.gate.as_ref().ok_or(CLOSED)?,
            );
        let authority = effect.plan().authority().ok_or(CLOSED)?;
        let dispatch = effect.dispatch().ok_or(CLOSED)?;
        if authority.audience() != aos_sandbox_model::BrokerAudience::Storage
            || authority.method()
                != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        {
            return Err(CLOSED.into());
        }
        let mut matching = gate
            .publication_draft()
            .templates()
            .iter()
            .filter(|template| {
                template.digest() == authority.template_digest()
                && template.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::
                    BROKER_METHOD_STORAGE_APPLY
                && aos_sandbox_model::ObjectDigest::from_bytes(sha2::Sha256::digest(
                    template.canonical_plan()).into()) == fields.root_plan
            });
        let template = matching.next().ok_or(CLOSED)?;
        if matching.next().is_some()
            || child.runtime_intent_digest().is_none()
            || effect.plan().request() != template.body_without_deadline()
        {
            return Err(CLOSED.into());
        }
        // Reconstruct the actual old dispatch against its immutable prepared
        // publication/lease. Today's Start publication is a different lineage.
        crate::publication::validate_durable_effect_attempt(
            controller,
            fields.sandbox,
            dispatch.publication_digest(),
            authority.digest(),
            fields.source_draft,
            aos_sandbox_model::BrokerAudience::Storage,
            template.digest(),
            template.body_without_deadline(),
            dispatch,
            None,
        )?;
        Ok(())
    }
}

pub(in crate::controller_resource_reservation) struct CatalogMaintenanceClosedFamilyOriginalV1 {
    creates: Vec<CreateEntry>,
    projections: Vec<PublicProjectionRecordV1>,
    returned: Option<Result<(), Cause>>,
    controller: Option<[u8; 32]>,
    reentered: bool,
}

impl CatalogMaintenanceClosedFamilyOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            creates: Vec::new(),
            projections: Vec::new(),
            returned: None,
            controller: None,
            reentered: false,
        }
    }

    pub(super) fn receiving_demand_v1(
        controller: &Journal,
        source: &Journal,
    ) -> Option<ResourceVector> {
        let count = source.all_records().count();
        let plane = crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::
            additional_selection_receiving_v1(source.all_records())?;
        let models = crate::cold_launch_publication::completion::
            create_stopped_controller_receiving_demand_v1(
                controller.historical_read_view_v1().materialized_state_v1())?;
        let mut demand = ResourceVector::ZERO;
        for _ in 0..count {
            demand = demand
                .checked_add(plane)
                .ok()?
                .checked_add(plane)
                .ok()?
                .checked_add(plane)
                .ok()?
                .checked_add(models)
                .ok()?
                .checked_add(models)
                .ok()?
                .checked_add(models)
                .ok()?;
        }
        let projections =
            aos_sandbox_protocol::public_api::projection::operation_list_receiving_bytes_v3(
                controller.records(RecordNamespace::DesiredState),
            )?;
        let bytes = size_of::<Self>()
            .checked_mul(3)?
            .checked_add(
                size_of::<CreateEntry>()
                    .checked_mul(count)?
                    .checked_mul(3)?,
            )?
            .checked_add(projections)?;
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
            .ok()
    }

    pub(super) fn observe_once_v1(
        &mut self,
        controller: &Journal,
        source: &LifecycleHistoricalReadOriginalV1,
        history: &CompletedStopHistoryOriginalV1,
        starts: &CatalogMaintenanceCompletedStartOriginalV1,
        recoveries: &CatalogMaintenanceRecoverFamilyOriginalV1,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered = true;
            return Err(CLOSED);
        }
        self.returned = Some((|| {
            let (projection, _) = source.projection_ready_v1()?;
            for envelope in projection.records() {
                use crate::lifecycle::protected_journal::LifecycleProtectedRecordKindV1 as Kind;
                if !matches!(
                    envelope.key().kind(),
                    Kind::Intent | Kind::Operation | Kind::Effect
                ) {
                    continue;
                }
                let id = OperationId::from_bytes(envelope.key().identity()[32..48].try_into()?);
                if history.operation_is_completed_v1(id)?
                    || starts.source_operation_is_proved_v1(id)
                    || self.creates.iter().any(|entry| entry.parent == id)
                {
                    continue;
                }
                self.creates
                    .try_reserve_exact(1)
                    .map_err(|_| JournalError::JournalTooLarge)?;
                self.creates.push(CreateEntry::new(id));
                self.creates
                    .last_mut()
                    .ok_or(CLOSED)?
                    .observe(controller, source, history, starts)?;
            }
            if self.creates.is_empty() {
                return Err(CLOSED.into());
            }
            for (namespace, key, value) in controller.all_records() {
                match namespace {
                    RecordNamespace::Operation => {
                        let id = OperationId::from_bytes(key.try_into()?);
                        if !history.operation_is_completed_v1(id)?
                            && !starts.operation_is_proved_v1(id)
                            && !recoveries.operation_is_proved_v1(id)
                            && !self
                                .creates
                                .iter()
                                .any(|entry| entry.parent == id || entry.publication == Some(id))
                        {
                            return Err(CLOSED.into());
                        }
                    }
                    RecordNamespace::Effect => {
                        let (id, step) = key.split_at_checked(16).ok_or(CLOSED)?;
                        if step != 0u32.to_be_bytes() {
                            return Err(CLOSED.into());
                        }
                        let id = OperationId::from_bytes(id.try_into()?);
                        if !history.operation_is_completed_v1(id)?
                            && !starts.operation_is_proved_v1(id)
                            && !self
                                .creates
                                .iter()
                                .any(|entry| entry.parent == id || entry.publication == Some(id))
                        {
                            return Err(CLOSED.into());
                        }
                    }
                    RecordNamespace::DesiredState if key.starts_with(PROJECTION_KEY_PREFIX) => {
                        self.projections
                            .try_reserve_exact(1)
                            .map_err(|_| JournalError::JournalTooLarge)?;
                        self.projections
                            .push(decode_checked_public_projection_v1(key, value)?);
                        let row = self.projections.last().ok_or(CLOSED)?;
                        let PublicProjectionResourceV1::Sandbox(sandbox) = row.resource() else {
                            return Err(CLOSED.into());
                        };
                        if !history.operation_is_completed_v1(row.operation())?
                            || !history.completed_operations_v1()?.any(|(_, project, target)|
                                project == row.project() && target.as_bytes() == sandbox.sandbox_id.as_slice())
                            || sandbox.desired.as_option().is_none_or(|desired|
                                desired.lifecycle.as_known()
                                    != Some(aos_sandbox_api::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED))
                        { return Err(CLOSED.into()); }
                    }
                    RecordNamespace::DesiredState
                    | RecordNamespace::Idempotency
                    | RecordNamespace::OwnershipGate
                    | RecordNamespace::AuthorityPublication
                    | RecordNamespace::PublisherAuthority
                    | RecordNamespace::PublisherPolicy
                    | RecordNamespace::PublisherIngress
                    | RecordNamespace::RuntimeAuthority
                    | RecordNamespace::SandboxSpec
                    | RecordNamespace::ControllerIdentity
                    | RecordNamespace::GlobalCapacityReservation
                    | RecordNamespace::BrokerSessionTraffic
                    | RecordNamespace::CliAuthorizationTime
                    | RecordNamespace::OperatorRecovery
                    | RecordNamespace::PublicOperationAuthorization
                    | RecordNamespace::PublicCapabilityBootstrap
                    | RecordNamespace::ControllerResourceReservation
                    | RecordNamespace::CreateStorageHistory
                    | RecordNamespace::ControllerPolicyHold
                    | RecordNamespace::SourceDomainPolicyHold
                    | RecordNamespace::StorageResourceInventory
                    | RecordNamespace::NetworkResourceInventory
                    | RecordNamespace::DestinationSlotInventory
                    | RecordNamespace::HostCatalogReconciliation => {}
                    _ => return Err(CLOSED.into()),
                }
            }
            if self.projections.len() != 1 {
                return Err(CLOSED.into());
            }
            self.controller = Some(family_controller_commitment(controller));
            Ok(())
        })());
        self.require_complete_v1()
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if self.reentered
            || !matches!(self.returned, Some(Ok(())))
            || self.creates.iter().any(|entry| {
                entry.source.failure_v1().is_some() || entry.completing.failure_v1().is_some()
            })
        {
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation) fn source_operation_is_proved_v1(
        &self,
        id: OperationId,
    ) -> bool {
        self.require_complete_v1().is_ok() && self.creates.iter().any(|entry| entry.parent == id)
    }

    pub(super) fn require_same_v1(&self, controller: &Journal) -> Result<(), JournalError> {
        self.require_complete_v1()?;
        if self.controller != Some(family_controller_commitment(controller)) {
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.creates
            .iter()
            .find_map(|entry| {
                entry
                    .source
                    .failure_v1()
                    .or_else(|| entry.completing.failure_v1())
            })
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref() as _)
            })
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn family_controller_commitment(controller: &Journal) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    // These exact logical families earned the classification. The same M may
    // append its native inventory snapshots and financial accounting rows;
    // its native owner independently enforces those actual successor cuts.
    let mut hash =
        Sha256::new().chain_update(b"aos.sandbox.maintenance.completed-family.controller.v1\0");
    for (namespace, key, value) in controller.all_records().filter(|(namespace, _, _)| {
        matches!(
            namespace,
            RecordNamespace::Operation
                | RecordNamespace::Effect
                | RecordNamespace::DesiredState
                | RecordNamespace::RuntimeAuthority
                | RecordNamespace::AuthorityPublication
                | RecordNamespace::OwnershipGate
                | RecordNamespace::OperatorRecovery
                | RecordNamespace::Idempotency
                | RecordNamespace::PublicOperationAuthorization
                | RecordNamespace::CreateStorageHistory
        )
    }) {
        hash.update((namespace as u16).to_be_bytes());
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key);
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}
