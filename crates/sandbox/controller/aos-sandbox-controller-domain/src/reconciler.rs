//! Single-node desired-state reconciliation and durable effect ledger.
//!
//! Admission stores the desired value, operation, idempotency decision, and
//! ordered effect plans in one journal transaction. Reconciliation writes an
//! `Applying` intent before invoking an effect executor. After restart, an
//! ambiguous `Applying` effect is observed by its stable operation/step key;
//! an absent effect is retried with the exact request bytes, while an applied
//! effect is completed from its durable executor receipt. This requires every
//! executor implementation to make one effect key idempotent. Ownership-gated
//! effects additionally retain the exact selected publication and broker
//! packet before `Applying` becomes externally visible.
//!
//! Runtime-holder admission additionally commits an exact intent digest in the
//! operation record. Activation commits its binding and current head in the
//! same transaction as the ownership publication and gate release. The durable
//! operation formats are closed schemas:
//!
//! ```text
//! V1 = version:u8 || state:u8 || flags:u8 || reserved:u8
//!      || effect_count:u32le || runtime_intent_digest_or_zero:32bytes
//! V2 = V1-header-with-version-2-and-public-flag || public_metadata:64bytes
//! ```
//!
//! The zero digest slot denotes an operation without a holder intent. Runtime
//! authority records require and cross-check the exact nonzero digest. V1
//! remains the canonical encoding for internal operations; V2 adds immutable
//! public identity and restart-stable observation metadata.

use aos_sandbox_model::{ObjectDigest, OperationId, SandboxId};
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
#[cfg(test)]
use aos_sandbox_ownership_protocol::CLAIM_BYTES;
use aos_sandbox_ownership_protocol::OwnershipClaimV1;

use crate::GuardianPlanRequestV1;
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;

/// Lends a closed original Git read/issuance crossing to its installed executor.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use crate::cli_model::authorization_adapter::GitCoverageReadMetadataOperationV1;

use crate::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalRecord, JournalTransaction,
    RecordNamespace,
};
use crate::publication::{
    AuthorityPublicationActivationPartsV1, AuthorityPublicationActivationV1,
    AuthorityPublicationDraftV1, AuthorityPublicationStore, validate_durable_effect_attempt,
    validate_durable_gate_publication, validate_publication_namespace,
};

pub(crate) mod start_admission;
mod start_host_completed;
pub(crate) use start_host_completed::{
    completed_start_host_publication_receiving_demand_v2,
    require_completed_start_host_publication_data_v2,
};
mod accepted_start;
mod core_journal;
mod admission_records;
#[cfg(target_os = "linux")]
pub(crate) use admission_records::{prepare_delete_admission_transaction_v3, prepare_delete_admission_comparison_data_v3};
pub(crate) use accepted_start::accepted_start_origin_from_journal_v1;

mod create_failure;
mod stop_residual;
mod execution_target;
mod execution_acceptance;
pub(crate) use execution_acceptance::{accepted_create_execution_effect_from_journal_v1,
    accepted_execution_effect_from_journal_v3, accepted_stop_effect_from_journal_v4,
    accepted_public_effect_models_receiving_bytes_v4,
    accepted_public_effect_models_receiving_bytes_retaining_v4};
pub use execution_target::accepted_execution_target_from_journal_v1;
pub(crate) use execution_target::AcceptedExecutionTargetOriginalV2;
#[cfg(target_os = "linux")]
mod create_q04;
#[cfg(target_os = "linux")]
pub(crate) use create_q04::{validate_original_claim_rows_v1, RootAcceptedCreateRowsV1};
#[cfg(target_os = "linux")]
pub(crate) use create_q04::{Q04OriginalRowBindingV1, read_original_q04_rows_v1};
#[cfg(target_os = "linux")]
pub(crate) use create_q04::OriginalQ04ControllerLedgerV1;
#[cfg(target_os = "linux")]
pub(crate) use create_q04::require_original_pending as require_q04_original_pending_v1;
#[cfg(target_os = "linux")]
pub use create_q04::continue_original_create_q04_policy_subgate_v1;
#[cfg(target_os = "linux")]
mod provisioning_geometry;
mod effect;
#[cfg(target_os = "linux")]
mod fuse_admission;
mod observe_reservation;
mod operator_repair_failure;
pub(crate) mod project_admission;
mod runtime_authority;

use crate::runtime_authority::{
    RuntimeAuthorityIntentV1, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
    RuntimeAuthorityStore,
};
pub(crate) use runtime_authority::{
    runtime_authority_claim, validate_runtime_authority_binding,
    validate_runtime_authority_operations, validate_runtime_authority_pending,
};

#[cfg(test)]
use create_failure::CreateFailureReceiptV1;
pub(crate) use create_failure::{ClosedCreateFailurePlanDataV2, plan_closed_create_failure_rows_data_v2};
pub(crate) use operator_repair_failure::{
    RepairPreconditionFailureReceiptV1, RECEIPT_BYTES as REPAIR_FAILURE_RECEIPT_BYTES,
    RECEIPT_DOMAIN as REPAIR_FAILURE_RECEIPT_DOMAIN,
};
pub use effect::{
    AuthorityEffectAttemptTimingV1, AuthorityEffectObservationV1, PreparedAuthorityBrokerRequestV1,
    PreparedAuthorityEffectV1, PublicMutationEffectV1, ValidatedAuthorityEffectReceiptV1,
    ValidatedHostEffectReceiptV1,
};
use aos_sandbox_protocol::publication::AuthorityBoundEffectPlanV1;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectDomain, EffectLedgerRecord, EffectPlan, EffectReceipt, EffectState,
    MAXIMUM_DIAGNOSTIC_BYTES, PreparedAuthorityEffectHistoryV1, effect_body_digest,
    PublicMutationEffectHistoryV1, decode_effect, encode_effect,
};
#[cfg(target_os = "linux")]
use aos_sandbox_protocol::domain_ledger::effect_history::{decode_effect_with_q04, q04_effect_subgate};
#[cfg(target_os = "linux")]
pub(crate) use fuse_admission::accepted_fuse_admission_v1;
#[cfg(target_os = "linux")]
mod nix_admission;
#[cfg(target_os = "linux")]
pub(crate) use nix_admission::{accepted_nix_start_admission_v2, require_current_effect_v2};
pub use observe_reservation::{
    adopt_execution_observe_child_v1, prepare_completed_execution_observe_child_v1, observe_child_adoption_state_v1, observe_child_identity_v1,
    completed_execution_observe_from_journal_v4,
};
#[cfg(feature = "project-negative-recovery-vm-fixture")]
pub use project_admission::vm_fixture::{
    fail_retired_project_history_vm_operation_v1, prepare_project_history_vm_flight_v1,
    preview_project_history_vm_reservation_v1, require_project_history_vm_flight_v1,
};
pub(crate) use project_admission::live_create_sandbox_admission_revision_v1;
#[cfg(feature = "project-negative-recovery-vm-fixture")]
use project_admission::retained_create_sandbox_admission_revision_v1;
pub use project_admission::{
    ControllerProjectAdmissionJournalErrorV1, ControllerProjectHistoryAcceptanceV1,
    RetainedControllerProjectAdmissionV1, accept_controller_project_admission_outcome_v1,
    accept_controller_project_history_floor_v1,
    accept_controller_project_reservation_cancellation_v1,
    authorize_controller_project_admission_dispatch_v1,
    checked_live_create_sandbox_admission_revision_v1, prepare_current_create_project_admission_v1,
    retained_controller_project_admission_v1,
};
use aos_sandbox_protocol::domain_ledger::operation::{
    MAXIMUM_EFFECTS, MAXIMUM_GATED_EFFECTS, OPERATION_KEY_BYTES, OPERATION_RECORD_V2_BYTES,
    OperationRecord, decode_operation, decode_operation_key, effect_key, encode_operation_record,
};
use aos_sandbox_protocol::domain_ledger::ownership_gate::{
    OwnershipGateDataErrorV1, OwnershipGatePlanV1, OwnershipGateStatusV1, decode_ownership_gate,
    encode_ownership_gate,
};
#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::operation::{
    OPERATION_RECORD_V1_BYTES, OPERATION_RUNTIME_INTENT_DIGEST_BYTES, RECORD_VERSION_V1,
};
use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
pub(crate) use aos_sandbox_protocol::domain_ledger::public_operation::{
    public_operation_method_from_record_code_v1, public_operation_method_record_code_v1,
};
pub use aos_sandbox_protocol::domain_ledger::public_operation::{
    PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
};

/// Defines one atomically admitted desired mutation and its ordered effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPlan {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
    desired_key: Vec<u8>,
    desired_value: Vec<u8>,
    effects: Vec<EffectPlan>,
    ownership_gate: Option<OwnershipGatePlanV1>,
    runtime_authority: Option<RuntimeAuthorityIntentV1>,
    public_operation: Option<PublicOperationAdmissionV1>,
    accepted_start: Option<aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1>,
    local_records: Vec<JournalRecord>,
}

impl OperationPlan {
    /// Constructs a complete operation admission plan.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for an all-zero operation ID,
    /// empty desired key/value, no effects, or more than 4093 effects.
    pub fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        effects: Vec<EffectPlan>,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || effects.is_empty()
            || effects.len() > MAXIMUM_EFFECTS
            || effects.iter().any(|effect| effect.authority().is_some())
        {
            return Err(ReconcilerError::InvalidPlan("invalid operation plan"));
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects,
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            accepted_start: None,
            local_records: Vec::new(),
        })
    }

    /// Constructs an atomically completed controller-local mutation.
    ///
    /// This path is intentionally crate-private. It exists for state owned by
    /// the controller journal itself, such as publisher capability authority,
    /// and cannot be used to represent a privileged or externally observed
    /// effect. The supplied records commit in the same transaction as desired
    /// state, idempotency, and public operation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the operation identity,
    /// desired state, authority records, or atomic transaction bounds are
    /// invalid.
    pub(crate) fn completed_local(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        local_records: Vec<JournalRecord>,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || local_records.is_empty()
            || local_records.len() > MAXIMUM_EFFECTS
            || local_records.iter().any(|record| {
                (record.namespace() != RecordNamespace::PublisherAuthority
                    && !aos_sandbox_protocol::public_api::projection::is_public_projection_deletion_record_v1(record))
                    || record.key().is_empty()
                    || (record.namespace() == RecordNamespace::PublisherAuthority
                        && record.value().is_none())
                    || (record.namespace() == RecordNamespace::DesiredState
                        && record.key() == desired_key)
            })
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid completed local operation plan",
            ));
        }
        for (index, record) in local_records.iter().enumerate() {
            if local_records[..index]
                .iter()
                .any(|prior| prior.namespace() == record.namespace() && prior.key() == record.key())
            {
                return Err(ReconcilerError::InvalidPlan(
                    "completed local operation contains duplicate records",
                ));
            }
        }

        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects: Vec::new(),
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            accepted_start: None,
            local_records,
        })
    }

    /// Constructs an atomically completed public attach without an agent effect.
    ///
    /// # Errors
    ///
    /// Rejects invalid desired state or an endpoint record for another operation.
    pub(crate) fn completed_public_attach(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        route_record: JournalRecord,
        decision_record: JournalRecord,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || route_record.namespace() != RecordNamespace::PublicAttachRoute
            || route_record.key() != operation_id.as_bytes()
            || route_record.value().is_none()
            || decision_record.namespace() != RecordNamespace::PublicAttachRoute
            || decision_record.key() != crate::attach_decision::decision_key(operation_id)
            || decision_record.value().is_none()
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid completed public attach plan",
            ));
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects: Vec::new(),
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            accepted_start: None,
            local_records: vec![route_record, decision_record],
        })
    }

    /// Constructs a completed acknowledgment of an already blocked operation.
    ///
    /// The caller must have checked the protected target's terminal phase and
    /// public resource-version fence. This plan atomically retains only the
    /// acknowledgment; it neither changes the target nor dispatches cleanup.
    ///
    /// # Errors
    ///
    /// Rejects mismatched operation identities or a malformed protected
    /// acknowledgment record.
    pub(crate) fn completed_operator_abandon(
        operation_id: OperationId,
        target: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        acknowledgment: JournalRecord,
    ) -> Result<Self, ReconcilerError> {
        if operation_id.as_bytes() == &[0; 16]
            || target.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || !crate::operator_abandon_ack::validates_record_v1(
                &acknowledgment,
                operation_id,
                target,
                idempotency_key.as_bytes(),
                request_digest,
            )
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid completed operator abandonment",
            ));
        }
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects: Vec::new(),
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            accepted_start: None,
            local_records: vec![acknowledgment],
        })
    }

    /// Adds protected controller-local records to a still-active operation.
    ///
    /// These records are committed atomically with the operation and its
    /// effects, but do not make the operation complete. This is intentionally
    /// restricted to operator-recovery state: recovery admission must retain
    /// its checked current head before its effect becomes eligible.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the plan has no effect,
    /// a record is outside the operator-recovery namespace, records collide,
    /// or the atomic transaction bound would be exceeded.
    pub(crate) fn with_operator_recovery_records(
        mut self,
        local_records: Vec<JournalRecord>,
    ) -> Result<Self, ReconcilerError> {
        let atomic_records = self.effects.len().checked_add(local_records.len()).ok_or(
            ReconcilerError::InvalidPlan("operator-recovery records exceed admission bounds"),
        )?;
        if self.effects.is_empty()
            || !self.local_records.is_empty()
            || local_records.is_empty()
            || atomic_records > MAXIMUM_EFFECTS
            || local_records.iter().any(|record| {
                record.namespace() != RecordNamespace::OperatorRecovery
                    || record.key().is_empty()
                    || record.value().is_none()
            })
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid operator-recovery admission records",
            ));
        }
        for (index, record) in local_records.iter().enumerate() {
            if local_records[..index]
                .iter()
                .any(|prior| prior.key() == record.key())
            {
                return Err(ReconcilerError::InvalidPlan(
                    "operator-recovery admission contains duplicate records",
                ));
            }
        }

        self.local_records = local_records;
        Ok(self)
    }

    /// Constructs an operation held behind an atomically admitted ownership gate.
    ///
    /// The claim and validated publication draft remain non-authorizing durable
    /// inputs. Only [`crate::NodeController::resume_ownership`] may supply
    /// verified activation facts through the crate-private opaque bridge. The
    /// draft determines the expected authority; callers cannot provide that
    /// security-sensitive reference separately.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for the ordinary operation
    /// invariants, more than 4092 effects, an effect not derived from the exact
    /// publication draft, or an invalid or mismatched gate.
    #[allow(clippy::too_many_arguments)]
    pub fn ownership_gated(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        desired_key: Vec<u8>,
        desired_value: Vec<u8>,
        effects: Vec<AuthorityBoundEffectPlanV1>,
        claim: OwnershipClaimV1,
        publication_draft: AuthorityPublicationDraftV1,
    ) -> Result<Self, ReconcilerError> {
        if effects.len() > MAXIMUM_GATED_EFFECTS {
            return Err(ReconcilerError::InvalidPlan(
                "ownership-gated operation has too many effects",
            ));
        }
        if effects.iter().any(|effect| {
            !effect.is_supported_authority_apply()
                || effect.source_draft_digest() != publication_draft.digest()
        }) {
            return Err(ReconcilerError::InvalidPlan(
                "ownership-gated effects must be descriptor-free broker Apply templates",
            ));
        }
        let effects: Vec<EffectPlan> = effects
            .into_iter()
            .enumerate()
            .map(|(step, effect)| {
                effect
                    .into_inner(operation_id, u32::try_from(step).unwrap_or(u32::MAX))
                    .map_err(ReconcilerError::from)
            })
            .collect::<Result<_, _>>()?;
        if operation_id.as_bytes() == &[0; 16]
            || desired_key.is_empty()
            || desired_value.is_empty()
            || effects.is_empty()
            || effects.iter().any(|effect| {
                effect
                    .authority()
                    .is_none_or(|binding| binding.source_draft_digest() != publication_draft.digest())
            })
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid ownership-gated operation plan",
            ));
        }
        let mut plan = Self {
            operation_id,
            idempotency_key,
            request_digest,
            desired_key,
            desired_value,
            effects,
            ownership_gate: None,
            runtime_authority: None,
            public_operation: None,
            accepted_start: None,
            local_records: Vec::new(),
        };
        plan.ownership_gate = Some(OwnershipGatePlanV1::new(
            operation_id,
            plan.idempotency_key.clone(),
            request_digest,
            claim,
            publication_draft,
        )?);
        Ok(plan)
    }

    /// Quotes that canonical pending encoding before its reached allocation.
    pub(crate) fn pending_ownership_gate_receiving_bytes_v2(&self) -> Result<usize, ReconcilerError> {
        let gate = self.ownership_gate.as_ref().ok_or(ReconcilerError::InvalidPlan(
            "the Host publication child requires its admitted ownership gate",
        ))?;
        aos_sandbox_protocol::domain_ledger::ownership_gate::ownership_gate_encoded_bytes_v1(gate)
            .map_err(Into::into)
    }

    /// Encodes the private plan's same canonical pending gate for exact rejoin.
    pub(crate) fn pending_ownership_gate_bytes_v2(&self) -> Result<Vec<u8>, ReconcilerError> {
        let gate = self.ownership_gate.as_ref().ok_or(ReconcilerError::InvalidPlan(
            "the Host publication child requires its admitted ownership gate",
        ))?;
        encode_ownership_gate(&OwnershipGateStatusV1::Pending(gate.clone()))
            .map_err(Into::into)
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Binds a holder intent to this ownership-gated operation's atomic admission.
    ///
    /// The compiler must authenticate and authorize the holder before constructing
    /// the intent. This method does not establish live runtime authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an ungated plan, an admission that exceeds the
    /// journal transaction bound, or revocation not bound to exactly one
    /// canonical Host Stop effect for this assignment.
    pub fn with_runtime_authority(
        mut self,
        intent: RuntimeAuthorityIntentV1,
    ) -> Result<Self, ReconcilerError> {
        let maximum_effects =
            MAXIMUM_GATED_EFFECTS - 1 - usize::from(self.public_operation.is_some());
        if self.ownership_gate.is_none() || self.effects.len() > maximum_effects {
            return Err(ReconcilerError::InvalidPlan(
                "runtime authority intent requires a bounded ownership-gated Host Apply plan",
            ));
        }
        let gate = self
            .ownership_gate
            .as_ref()
            .ok_or(ReconcilerError::InvalidPlan(
                "runtime intent requires an ownership gate",
            ))?;
        runtime_authority::validate_intent_effects(
            intent.state(),
            self.operation_id,
            gate.publication_draft(),
            &self.effects,
        )?;
        self.runtime_authority = Some(intent);
        Ok(self)
    }

    /// Attaches the three exact provisioning companions to the gated child.
    ///
    /// The Native issuer pays the complete plan and fixed companion geometry
    /// before this transformation. These immutable DATA records grant no
    /// payment, workspace completion, publication activation, or Host launch.
    pub(crate) fn with_provisioning_resource_records_v1(
        mut self,
        records: aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRecordsV1,
    ) -> Result<Self, ReconcilerError> {
        use aos_sandbox_protocol::domain_ledger::provisioning_resources::
            require_provisioning_publication_gate_v1;

        if self.public_operation.is_some() || self.runtime_authority.is_none()
            || !self.local_records.is_empty()
            || records.fields_v1().publication_operation != self.operation_id
        {
            return Err(ReconcilerError::InvalidPlan(
                "provisioning companions require their distinct gated child",
            ));
        }
        let gate = self.ownership_gate.as_ref().ok_or(ReconcilerError::InvalidPlan(
            "provisioning companions require an ownership gate",
        ))?;
        require_provisioning_publication_gate_v1(records, gate)?;
        let records = records.records_v1();
        let maximum_effects = MAXIMUM_GATED_EFFECTS.checked_sub(1 + records.len())
            .ok_or(ReconcilerError::InvalidPlan("provisioning companion bound overflow"))?;
        if self.effects.len() > maximum_effects
            || records.iter().any(|record| record.key() == self.desired_key)
        {
            return Err(ReconcilerError::InvalidPlan(
                "provisioning companions exceed the exact atomic plan shape",
            ));
        }

        self.local_records.extend(records);
        Ok(self)
    }

    /// Adds immutable public observation metadata to this admission.
    ///
    /// Direct desired-state plans begin at their semantic commit boundary.
    /// A single controller-orchestration effect may instead advertise
    /// cancellation while it remains accepted and has not begun execution.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when metadata was already
    /// attached or its extra atomic record would exceed admission bounds.
    pub fn with_public_operation(
        mut self,
        public_operation: PublicOperationAdmissionV1,
    ) -> Result<Self, ReconcilerError> {
        let maximum_effects = if self.ownership_gate.is_some() {
            MAXIMUM_GATED_EFFECTS - 1 - usize::from(self.runtime_authority.is_some())
        } else {
            MAXIMUM_EFFECTS - 1
        };
        let atomic_records = self
            .effects
            .len()
            .checked_add(self.local_records.len())
            .ok_or(ReconcilerError::InvalidPlan(
                "public operation metadata exceeds admission bounds",
            ))?;
        if self.public_operation.is_some() || atomic_records > maximum_effects {
            return Err(ReconcilerError::InvalidPlan(
                "public operation metadata is duplicate or exceeds admission bounds",
            ));
        }
        self.public_operation = Some(public_operation);
        Ok(self)
    }

    pub(crate) fn require_accepted_start_data_v1(&self,journal:&Journal)->Result<(),ReconcilerError> {
        if !matches!(journal.check_idempotency(&self.idempotency_key,self.request_digest),
            IdempotencyOutcome::Replay(operation) if operation==self.operation_id) {
            return Err(ReconcilerError::IdempotencyConflict);
        }
        let bytes=journal.get(RecordNamespace::Operation,self.operation_id.as_bytes())
            .ok_or(ReconcilerError::CorruptLedger("accepted Start missing"))?;
        let operation=decode_operation(bytes)?;
        if operation.accepted_start_origin_v1()!=self.accepted_start
            || operation.public_operation()!=self.public_operation.as_ref().map(PublicOperationAdmissionV1::durable)
            || operation.effect_count()!=1 || operation.ownership_gated() {
            return Err(ReconcilerError::IdempotencyConflict);
        }
        Ok(())
    }

    // The retained plan is already resident. This pays the additional decoded
    // public context, current Sandbox comparison and fixed Operation decoder
    // before the Source-origin stage calls those same existing engines.
    pub(crate) fn start_source_context_receiving_demand_v1(&self,journal:&Journal)
        ->Option<aos_sandbox_model::ResourceVector> {
        let [effect]=self.effects.as_slice() else {return None;};
        let context=aos_sandbox_protocol::domain_ledger::effect_history::
            effect_decoding_receiving_bytes_v1(effect.request().len())?;
        let operation=std::mem::size_of::<aos_sandbox_protocol::domain_ledger::operation::OperationRecord>()
            .checked_mul(2)?;
        let new_use = aos_sandbox_protocol::domain_ledger::delete_batch::new_use::
            public_mutation_new_use_receiving_bytes_v2();
        let memory=u64::try_from(context.checked_add(operation)?.checked_add(new_use)?).ok()?
            .checked_add(crate::controller_service::public_projection::sandbox_source_receiving_bytes_v1(journal)?)?;
        Some(aos_sandbox_model::ResourceVector::ZERO.with(
            aos_sandbox_model::ResourceDimension::MemoryBytes,memory))
    }

    /// Borrows the actual sole private Host effect without creating a plan.
    pub(crate) fn start_host_effect_plan_v2(&self) -> Result<&EffectPlan, ReconcilerError> {
        let [effect] = self.effects.as_slice() else {
            return Err(ReconcilerError::InvalidPlan("private Host child requires exactly one effect"));
        };
        if self.public_operation.is_some() || self.ownership_gate.is_none()
            || self.runtime_authority.is_none() || effect.authority().is_none() {
            return Err(ReconcilerError::InvalidPlan("private Host child has another grammar"));
        }
        Ok(effect)
    }

    pub(crate) fn original_start_context_v1(&self)
        ->Result<aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1,ReconcilerError> {
        let [effect]=self.effects.as_slice() else {
            return Err(ReconcilerError::InvalidPlan("Start needs its sole canonical public effect"));
        };
        if effect.public_mutation_method()!=Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::StartSandbox)
            || self.accepted_start.is_none() || self.ownership_gate.is_some() || self.runtime_authority.is_some() {
            return Err(ReconcilerError::InvalidPlan("invalid retained public Start context"));
        }
        effect.public_mutation_context().map_err(ReconcilerError::from)?
            .ok_or(ReconcilerError::InvalidPlan("retained Start context missing"))
    }

    pub(crate) fn require_public_execution_admission_shape_v2(&self)
        -> Result<(), ReconcilerError> {
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

        let [effect] = self.effects.as_slice() else {
            return Err(ReconcilerError::InvalidPlan("Execution needs its sole canonical public effect"));
        };
        if effect.public_mutation_method() != Some(PublicOperationMethodV1::CreateExecution)
            || self.public_operation.as_ref().is_none_or(|public| {
                public.method() != PublicOperationMethodV1::CreateExecution
            })
            || self.accepted_start.is_some() || self.ownership_gate.is_some()
            || self.runtime_authority.is_some()
        {
            return Err(ReconcilerError::InvalidPlan("invalid retained public Execution plan"));
        }
        Ok(())
    }

    pub(crate) fn require_same_public_execution_projection_v2(&self, journal: &Journal)
        -> Result<(), crate::JournalError>
    {
        self.require_public_execution_admission_shape_v2()
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        if journal.get(RecordNamespace::DesiredState, &self.desired_key) != Some(self.desired_value.as_slice()) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    // This is the immutable original selected by the sole compiler, including
    // idempotent replay. It is never replaced by a reconnect's fresh clock.
    pub(crate) const fn accepted_start_origin_data_v1(&self)
        ->Option<aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1> {
        self.accepted_start
    }

    // Only the checked public compiler attaches original Start coordinates.
    pub(crate) fn with_accepted_start_origin_v1(mut self,
        origin: Option<aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1>,
    ) -> Result<Self, ReconcilerError> {
        if self.accepted_start.is_some() || origin.is_some_and(|origin| {
            self.public_operation.as_ref().is_none_or(|public| {
                public.method() != aos_sandbox_protocol::public_api::PublicOperationMethodV1::StartSandbox
                    || public.accepted_wall_seconds() != origin.accepted_clock_v1().wall_seconds()
            })
        }) { return Err(ReconcilerError::InvalidPlan("invalid original Start admission")); }
        self.accepted_start = origin;
        Ok(self)
    }

    /// Returns the digest of the normalized request admitted by this plan.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

/// Reports the result of operation admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptOutcome {
    /// This plan was atomically committed as a new operation.
    Accepted(OperationId),
    /// The exact request was already admitted as this operation.
    Replay(OperationId),
}

#[cfg(test)]
fn create_failure_receipt(receipt: &EffectReceipt) -> Result<Option<CreateFailureReceiptV1>, ()> {
    CreateFailureReceiptV1::decode(receipt.as_bytes())
}

/// Reports the executor's observation of an ambiguous in-flight effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectObservation {
    /// No effect with this stable key is externally visible.
    Absent,
    /// The effect is externally complete with this verified receipt.
    Applied(EffectReceipt),
}

/// Classifies an effect failure without exposing an executor error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectFailure {
    /// The same exact effect may be retried later.
    Retryable(String),
    /// Reconciliation cannot proceed without a new desired mutation or repair.
    Permanent(String),
}

impl std::fmt::Display for EffectFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic())
    }
}

impl std::error::Error for EffectFailure {}

/// Reports method-specific Repair orchestration without a generic Apply receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorStorageRepairReconcileV1 {
    /// Original physical or terminal custody remains pending or ambiguous.
    Pending,
    /// The actual six-row terminal CAS and exact owner settlement completed.
    Terminal,
}

impl EffectFailure {
    fn diagnostic(&self) -> &str {
        match self {
            Self::Retryable(value) | Self::Permanent(value) => value,
        }
    }

    fn validate(&self) -> Result<(), ReconcilerError> {
        if self.diagnostic().is_empty() || self.diagnostic().len() > MAXIMUM_DIAGNOSTIC_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid effect failure diagnostic length",
            ));
        }
        Ok(())
    }
}

/// Carries one concrete cleanup response with its post-disposal native proof.
///
/// The private proof constructors require actual role-specific Source/native
/// completion. The reconciler checks the exact same Controller and complete
/// terminal cut before letting the Node compare its public response projection.
#[cfg(target_os = "linux")]
#[must_use = "validate the native proof before returning its public response"]
pub enum OperatorCleanupRecoveryCompletionV2 {
    /// Retains completed Source22 Stop and Recover metadata custody.
    Stop {
        /// Contains the exact stored Recover response projection.
        response: aos_sandbox_api::aos::sandbox::v1::Operation,
        /// Proves real Stop22 terminal and Source disposition.
        completion: crate::controller_lifecycle_stop::ControllerHostStopCleanupCompletionV1,
    },
    /// Retains the existing completed NoApply and fresh Source/C18 custody.
    Execution {
        /// Contains the exact stored Recover response projection.
        response: aos_sandbox_api::aos::sandbox::v1::Operation,
        /// Proves real NoApply terminal and Source disposition.
        completion: crate::controller_execution_operation::ControllerExecutionNoApplyCompletionV2,
    },
}

/// Executes idempotent single-node effects through fixed local boundaries.
pub trait SingleNodeEffectExecutor {
    /// Keeps both actual Execution Sessions borrowed across admission and bind.
    ///
    /// # Errors
    /// Refuses missing or failed native originals. The default supplies no owner.
    #[cfg(target_os = "linux")]
    fn admit_original_execution_availability_once_v2(
        &mut self,
        _controller: &mut Journal,
        _maximum_pending_operations: usize,
    ) -> Result<AcceptOutcome, crate::ResourceReservationErrorV1> {
        Err(crate::ResourceReservationErrorV1::Conflict)
    }

    /// Moves the actual Runtime C18 into serial predurable public compilation.
    ///
    /// # Errors
    /// Refuses missing, busy or failed originals. The default supplies no owner.
    #[cfg(target_os = "linux")]
    fn take_original_execution_public_custody_once_v2(
        &mut self,
        _controller: &mut Journal,
    ) -> Result<Option<crate::controller_execution_operation::ControllerExecutionPublicCustodyTransferV2>,
        crate::ResourceReservationErrorV1>
    {
        Ok(None)
    }

    /// Restores the whole original after every serial public compiler return.
    #[cfg(target_os = "linux")]
    fn retain_original_execution_public_custody_v2(
        &mut self,
        _custody: crate::controller_execution_operation::ControllerExecutionRuntimeCustodyV2,
    ) {
        std::process::abort();
    }

    /// Moves the actual fresh four-role context after full recovered enrollment.
    ///
    /// The default supplies no context. Concrete executors keep all failed
    /// enrollment/context originals resident and never reconstruct a context
    /// from historical metadata or successful comparison data.
    #[cfg(target_os = "linux")]
    fn take_recovered_ordinary_sessions_once_v2(&mut self) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2> {
        None
    }

    /// Observes an existing execution without replaying its accepted effect.
    ///
    /// The production owner uses its same consumed purpose18 subdivision and
    /// independent Source/Controller posts. Historical rows alone supply no
    /// native or terminal permission to an implementation.
    ///
    /// # Errors
    /// Refuses unavailable genuine observation custody or any retained failure.
    #[cfg(target_os = "linux")]
    fn observe_current_executions_v4(&mut self, journal: &mut Journal) -> Result<(), EffectFailure> {
        if journal.records(RecordNamespace::ControllerExecutionSpecAttempt).next().is_some() {
            Err(EffectFailure::Retryable("execution observation custody is unavailable".to_owned()))
        } else {
            Ok(())
        }
    }

    /// Captures the fixed account cut using genuine resident original owners.
    ///
    /// # Errors
    /// The default refuses before effects; it is not a fallback producer.
    #[cfg(target_os = "linux")]
    fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        _journal: &mut Journal,
        _original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        _original_bootstrap: &crate::publisher_admin::policy::GitUploadBootstrapAppendV1,
        _original_source: &crate::publisher_admin::policy::VerifiedPublisherPolicySourceV1,
        _original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        _original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        _attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        Err(crate::cache_residency::CacheResidentUnavailableV1)
    }

    /// Commits the exact successor through the same retained account attempt.
    ///
    /// # Errors
    /// The default refuses rather than constructing a substitute owner.
    #[cfg(target_os = "linux")]
    fn commit_existing_git_coverage_account_v1(
        &mut self,
        _journal: &mut Journal,
        _original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        _original_bootstrap: &crate::publisher_admin::policy::GitUploadBootstrapAppendV1,
        _original_source: &crate::publisher_admin::policy::VerifiedPublisherPolicySourceV1,
        _original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        _original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        _attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        Err(crate::cache_residency::CacheResidentUnavailableV1)
    }

    /// Runs the fixed enrolled metadata crossing with both original writers.
    ///
    /// # Errors
    /// The default refuses before effects; no substitute owner or clock exists.
    #[cfg(target_os = "linux")]
    fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        _controller: &mut Journal,
        _original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        _operation: &mut GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        Err(crate::cache_residency::CacheResidentUnavailableV1)
    }

    /// Compares the fixed cohort through the same resident Cache owners.
    ///
    /// Coordinates and flight selection are DATA. The concrete installed
    /// implementation retains actual owners, append outcomes and typed causes;
    /// this default does not supply an alternative initialization producer.
    ///
    /// # Errors
    /// Refuses unsupported executors or original-owner/census/append failures.
    /// Failure never permits reconstruction, retry or allocation.
    #[cfg(target_os = "linux")]
    fn compare_existing_cache_git_coverage_v1(
        &mut self,
        _original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        _flight: aos_sandbox_model::format::git_upload_enrollment::GitCoverageFlightV1,
        _original_nonce: [u8; 16],
        _original_account: Option<&mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(
        aos_sandbox_model::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
        aos_sandbox_model::format::git_upload_enrollment::GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), crate::cache_residency::CacheResidentUnavailableV1> {
        Err(crate::cache_residency::CacheResidentUnavailableV1)
    }

    /// Initializes the same fixed existing Cache and borrows local project usage.
    ///
    /// # Errors
    /// Returns unavailable when the concrete executor lacks resident originals,
    /// complete provisioned history, or current observation custody. No global
    /// project account or operation admission is produced by this hook.
    fn existing_cache_project_usage_v1(
        &mut self,
        _project: aos_sandbox_model::ProjectId,
    ) -> Result<crate::cache_residency::CacheProjectUsageLoanV1<'_>, crate::cache_residency::CacheResidentUnavailableV1> {
        Err(crate::cache_residency::CacheResidentUnavailableV1)
    }

    /// Rechecks the same initialization originals after the short usage loan.
    ///
    /// # Errors
    /// Refuses unavailable or changed resident originals; implementations must
    /// retain actual causes and must not reopen or reconstruct their owners.
    fn recheck_existing_cache_project_usage_v1(
        &mut self,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        Err(crate::cache_residency::CacheResidentUnavailableV1)
    }

    /// Selects the closed original-gen1 Create policy-subgate continuation.
    ///
    /// Only the installed caller supplies its genuinely admitted normal-Root
    /// profile. The default refuses selection without touching ordinary owners.
    /// Selection itself grants no public Create or generic Effect completion.
    ///
    /// # Errors
    /// Refuses missing genuine owner support or a repeated/failed selection.
    #[cfg(target_os = "linux")]
    fn select_original_create_q04_policy_subgate_v1(
        &mut self,
        _controller: &mut Journal,
        _profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), EffectFailure> {
        Err(EffectFailure::Permanent("original Q04 owner selection is unavailable".to_owned()))
    }

    /// Continues a selected Create subgate without returning a generic receipt.
    ///
    /// `None` preserves the literal ordinary Create executor path. A selected
    /// implementation retains the real owners through policy and final Root
    /// clearance; success still leaves Operation/Effect Applying and pending.
    /// The existing dispatch and authority-gate shapes are negative graph
    /// checks, not permissions: selection refuses either before owner I/O.
    ///
    /// # Errors
    /// Selected failures must retain original first causes and debt before
    /// deliberate terminal handling, never generic Apply/retry or dropped Err.
    #[cfg(target_os = "linux")]
    fn reconcile_original_create_q04_policy_subgate_v1(
        &mut self,
        _operation: OperationId,
        _step: u32,
        _effect_count: u32,
        _plan: &EffectPlan,
        _dispatch: Option<&PreparedAuthorityEffectV1>,
        _authority_gate: Option<(SandboxId, ObjectDigest)>,
        _journal: &mut Journal,
    ) -> Option<Result<(), EffectFailure>> {
        None
    }

    /// Lends a genuine fresh Start entry after its paid historical prelude.
    ///
    /// # Errors
    /// Retains the original native/accounting cause at the installed executor.
    #[cfg(target_os = "linux")]
    fn prepare_original_start_entry_v1(&mut self,_peer:&crate::public_api_session::PublicApiPeer,
        _encoded:&[u8],_journal:&mut Journal,
    )->Result<Option<crate::AcceptedStartEntryOriginalV1>,crate::ResourceReservationErrorV1> {Ok(None)}

    /// Runs the finite original Delete pipeline through final native disposition.
    ///
    /// # Errors
    /// Refuses unavailable genuine runtime ownership or an early authorization.
    /// Entered failures retain the whole prefix and finish their owed posts.
    #[cfg(target_os = "linux")]
    fn admit_original_delete_once_v4(
        &mut self,
        _peer: &crate::public_api_session::PublicApiPeer,
        _capability: aos_sandbox_model::CapabilityId,
        _handle: &[u8],
        _encoded: &[u8],
        _journal: &mut Journal,
    ) -> Result<AcceptOutcome, crate::ResourceReservationErrorV1> {
        Err(crate::ResourceReservationErrorV1::Conflict)
    }

    /// Runs all independently owed Start posts on the same owning entry.
    #[cfg(target_os = "linux")]
    fn finish_original_start_entry_v1(&mut self,_entry:&mut crate::AcceptedStartEntryOriginalV1,
        _journal:&mut Journal,
    ) {std::process::abort();}

    /// Writes the first Start Source origin through the same retained Source owner.
    ///
    /// The selected implementation always returns the entire entry after its
    /// independently owed Source, C and paired-clock posts.
    #[cfg(target_os = "linux")]
    fn admit_original_start_source_origin_v1(&mut self,_entry:&mut crate::AcceptedStartEntryOriginalV1,
        _journal:&mut Journal,
    ) {std::process::abort();}

    /// Advances only the installed genuine Start owner under its fresh native payer.
    ///
    /// No ordinary effect is dispatched by this hook. A selected refusal stays
    /// resident at the executor and cannot become Failed or a generic retry.
    ///
    /// # Errors
    /// Retains the original native, transport, authorization or temporal cause.
    #[cfg(target_os = "linux")]
    fn progress_original_start_once_v1(&mut self,_operation:OperationId,_journal:&mut Journal)
        ->Option<Result<(),crate::ResourceReservationErrorV1>> {None}

    /// Advances only the genuine accepted Stop on its same baseline native owner.
    ///
    /// The caller selects the already decoded canonical public Stop method.
    /// The implementation pays its accepted graph before Source or Host use,
    /// retains all refused prefixes, and never returns generic receipt DATA.
    ///
    /// # Errors
    /// Keeps native, Source, signed dispatch, residual or terminal CAS refusal.
    #[cfg(target_os = "linux")]
    fn progress_original_lifecycle_stop_once_v4(&mut self, _operation: OperationId,
        _journal: &mut Journal,
    ) -> Option<Result<(), crate::ResourceReservationErrorV1>> { None }

    /// Permanently retains the whole fresh Start entry after its actual posts.
    #[cfg(target_os = "linux")]
    fn retain_original_start_entry_v1(&mut self,_entry:crate::AcceptedStartEntryOriginalV1) {
        std::process::abort();
    }

    /// Lends an actual separately funded publication turn for a selected Create.
    ///
    /// The returned owners remain the original issued action and same C
    /// receiver. `None` leaves the selected original Create pending; it never
    /// permits generic Apply or treats Storage completion as launch readiness.
    ///
    /// # Errors
    /// The installed issuer retains every original Root, Session, finance and
    /// native cause before returning a coarse failure to Core.
    #[cfg(target_os = "linux")]
    fn prepare_original_publication_turn_v1(
        &mut self,
        _operation: OperationId,
        _plan: &EffectPlan,
        _journal: &mut Journal,
    ) -> Result<Option<(crate::OriginalPublicationActionV1,
        crate::CreateProvisioningOriginalsV1,
        crate::normal_root::RootStorageApplyClientOriginalV1)>, EffectFailure> {
        Ok(None)
    }

    /// Retains all three original owners and the complete Core/native turn result.
    ///
    /// A selected issuer implements this together with its prepare method.
    /// Core always calls it after returning the same receiver and running its
    /// independently owed native post, including a failed semantic body.
    ///
    /// The default terminates the process if an implementation lends a turn
    /// without implementing its mandatory permanent retention handback.
    #[cfg(target_os = "linux")]
    fn retain_original_publication_turn_v1(
        &mut self,
        _action: crate::OriginalPublicationActionV1,
        _receiving: crate::CreateProvisioningOriginalsV1,
        _root: crate::normal_root::RootStorageApplyClientOriginalV1,
        _returned: Result<(), crate::OriginalPublicationActionClosedV1>,
    ) {
        std::process::abort();
    }

    /// Issues only the fixed administrative successor on real original owners.
    ///
    /// The default is retaining terminal refusal. Production borrows its SAME
    /// Source field and the sole Controller Journal; returned packet bytes are
    /// not Source mutation, current ancestry, funding or Root floor authority.
    ///
    /// # Errors
    /// Returns resident first-cause failure requiring deliberate termination;
    /// it must never be reduced to an ordinary dropped error or retried.
    #[cfg(target_os = "linux")]
    fn issue_source_successor_v2<'writers, 'profile, 'credentials>(
        &'writers mut self,
        journal: &'writers mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut crate::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<
        aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2,
        crate::policy_compiler::FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        Err(crate::policy_compiler::unavailable_source_successor_issuer_v2(
            journal, profile, credentials,
        ))
    }

    /// Issues selected project DATA using fresh credentials and a new Root flight.
    ///
    /// # Errors
    /// Retains the genuine failed writer/credential loans until termination.
    #[cfg(target_os = "linux")]
    fn issue_project_source_successor_v3<'writers, 'profile, 'credentials>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut crate::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2, crate::policy_compiler::FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>> {
        Err(crate::policy_compiler::unavailable_project_issuer_v3(journal, profile, credentials))
    }

    /// Completes only the actual retained first Source successor obligation.
    ///
    /// The default keeps selected failure custody; actual absence is inert.
    ///
    /// # Errors
    /// Returns a resident failed owner that must survive deliberate termination.
    #[cfg(target_os = "linux")]
    fn coordinate_retained_first_source_successor_v2<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
        crate::policy_compiler::unavailable_first_source_successor_v2(journal, profile)
    }

    /// Observes authorized Create recovery through the actual Source/Session owner.
    ///
    /// This method does not perform subsequent physical reconciliation.
    ///
    /// This hook performs observation only. Its successful return cannot mint
    /// public completion, restore the old Apply receiver or authorize effects.
    ///
    /// # Errors
    /// Refuses unavailable actual native inventory or any failed currentness.
    #[cfg(target_os = "linux")]
    fn observe_operator_create_recovery_sources_v1(&mut self,
        _journal: &mut Journal, _original: &mut crate::OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), crate::OperatorCreateRecoveryClosedV1> {
        Err(crate::OperatorCreateRecoveryClosedV1)
    }

    /// Settles the actual Recover Source after the independently owed C posts.
    ///
    /// A concrete executor must retain the same Source owner throughout entry
    /// and settlement. The default grants no completed observation.
    #[cfg(target_os = "linux")]
    fn finish_operator_create_recovery_after_native_v1(&mut self,
        _journal: &Journal, _original: &mut crate::OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), crate::OperatorCreateRecoveryClosedV1> {
        Err(crate::OperatorCreateRecoveryClosedV1)
    }

    /// Completes cleanup through a distinct actual payer after Recover finance.
    ///
    /// The actual new owner must finish its Source/native/clock posts, positive
    /// disposal and protected C terminal append before releasing its proof.
    /// Reconciler checks that proof immediately; Node checks the stored response.
    ///
    /// # Errors
    /// Refuses unavailable concrete cleanup, grant, completion or disposition.
    #[cfg(target_os = "linux")]
    fn complete_operator_cleanup_recovery_v2(&mut self,
        _journal: &mut Journal, _original: &mut crate::OperatorCreateRecoveryOriginalV1,
        _purpose: aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1,
    ) -> Result<OperatorCleanupRecoveryCompletionV2, crate::OperatorCreateRecoveryClosedV1> {
        Err(crate::OperatorCreateRecoveryClosedV1)
    }

    /// Observes the closed first-local population after original Recover posts.
    ///
    /// This distinct interval preserves historical metadata completion and
    /// keeps all physical observations resident. It grants no ordinary service.
    ///
    /// # Errors
    /// Refuses unavailable physical receiving, an unsupported population or
    /// any native, signed-inventory, Source or original-horizon refusal.
    #[cfg(target_os = "linux")]
    fn reconcile_first_local_after_recover_v2(&mut self,
        _journal: &mut Journal, _original: &crate::OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), crate::OperatorCreateRecoveryClosedV1> {
        Err(crate::OperatorCreateRecoveryClosedV1)
    }

    /// Enters the same enrolled B's finite catalog maintenance on the actual Source.
    ///
    /// # Errors
    /// Refuses unavailable native custody, another installed context or admission.
    #[cfg(target_os = "linux")]
    fn begin_catalog_maintenance_once_v2(&mut self,
        _journal: &mut Journal, _original: &mut crate::CatalogMaintenanceOriginalV2,
        _bank: &std::sync::Arc<std::sync::Mutex<crate::ControllerResourceBankOpeningV1>>,
        _profile: &std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        _runtime: &std::sync::Arc<tokio::runtime::Runtime>,
        _shape: crate::CatalogMaintenanceSdkShapeDataV2,
    ) -> Result<(), crate::CatalogMaintenanceClosedV2> { Err(crate::CatalogMaintenanceClosedV2) }

    /// Enters real recurring no-effect refresh under the same installed B.
    ///
    /// # Errors
    /// Refuses unavailable native custody, another context or failed admission.
    #[cfg(target_os = "linux")]
    fn begin_catalog_refresh_once_v2(&mut self,
        _journal: &mut Journal, _original: &mut crate::CatalogMaintenanceOriginalV2,
        _bank: &std::sync::Arc<std::sync::Mutex<crate::ControllerResourceBankOpeningV1>>,
        _profile: &std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        _runtime: &std::sync::Arc<tokio::runtime::Runtime>,
        _shape: crate::CatalogMaintenanceSdkShapeDataV2,
    ) -> Result<(), crate::CatalogMaintenanceClosedV2> { Err(crate::CatalogMaintenanceClosedV2) }

    /// Lends only a closed current borrow of this executor's actual Source.
    ///
    /// # Errors
    /// Refuses unavailable or changed native Source/current maintenance custody.
    #[cfg(target_os = "linux")]
    fn borrow_catalog_maintenance_source_v2<'source>(&'source mut self,
        _journal: &Journal, _original: &mut crate::CatalogMaintenanceOriginalV2,
    ) -> Result<crate::CatalogMaintenanceSourceBorrowV2<'source>, crate::ResourceReservationErrorV1> {
        Err(crate::ResourceReservationErrorV1::Conflict)
    }

    /// Performs every independently owed Source/C/clock post of the same interval.
    #[cfg(target_os = "linux")]
    fn finish_catalog_maintenance_once_v2(&mut self,
        _journal: &mut Journal, _original: &mut crate::CatalogMaintenanceOriginalV2,
    ) {}

    /// Fences cold public Create success before the Runtime publishes Ready.
    ///
    /// The concrete executor retains its actual Source and fixed observer.
    /// Missing authenticated recovery custody is closed by default.
    ///
    /// # Errors
    /// Refuses a cold completed Create or unhealthy original Controller.
    #[cfg(target_os = "linux")]
    fn coordinate_cold_create_stopped_observer_once_v1(&mut self, journal: &mut Journal)
        -> Result<(), crate::journal::CreateStoppedColdObserverClosedV1> {
        crate::journal::CreateStoppedColdObserverOriginalV1::new()
            .observe_without_source_once_v1(journal)
    }

    /// Completes provisioned Source genesis using the executor's real owner.
    ///
    /// This internal startup hook is closed by default. The production override
    /// retains its actual Source writer and existing Controller-role signer
    /// across the original Root flight; it cannot expose a raw floor or open
    /// public mutations. The completion digest is historical data only.
    ///
    /// # Errors
    ///
    /// Rejects unavailable genuine owner custody or any incomplete, conflicting
    /// or ambiguous genesis phase. Implementations must preserve exact restart
    /// recovery instead of admitting a replacement attempt.
    #[cfg(target_os = "linux")]
    fn coordinate_provisioned_source_genesis_v1(
        &mut self,
        _journal: &mut Journal,
        _input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        _profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        ObjectDigest,
        crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1,
    > {
        Err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::AdmissionClosed.into())
    }

    /// Prepares only the original image-owned FirstGlobal prefix.
    ///
    /// # Errors
    /// The default executor has no genuine bank/Source owner and stays closed.
    #[cfg(target_os = "linux")]
    fn prepare_first_global_prefix_v1(
        &mut self,
        _journal: &mut Journal,
        _profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        Err(crate::controller_resource_reservation::ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    /// Coordinates the resource-bearing Global purpose under resident originals.
    ///
    /// # Errors
    /// Returns the resident failed writer loan when the genuine Source owner is unavailable.
    #[cfg(target_os = "linux")]
    fn coordinate_configured_global_genesis_v2<'writers, 'profile>(
        &'writers mut self,
        journal: &'writers mut Journal,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, crate::policy_compiler::FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile>> {
        Err(crate::policy_compiler::unavailable_global_genesis_v2(journal, input, profile))
    }

    /// Coordinates genuine configured mixed genesis under resident originals.
    ///
    /// # Errors
    /// Returns a resident failed writer loan; no ordinary fallback is attempted.
    #[cfg(target_os = "linux")]
    fn coordinate_configured_project_genesis_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, crate::policy_compiler::FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile>> {
        Err(crate::policy_compiler::unavailable_project_genesis_v3(journal, input, profile))
    }

    /// Coordinates the selected project history under genuine retained writers.
    ///
    /// # Errors
    /// Returns the whole retaining failure when the actual Source owner is absent.
    #[cfg(target_os = "linux")]
    fn coordinate_project_successor_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        project: aos_sandbox_model::ProjectId,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        crate::policy_compiler::unavailable_project_successor_v3(journal, profile, project)
    }

    /// Settles the genuine global predecessor using explicitly mixed comparison.
    ///
    /// # Errors
    /// Retains failed originals; no configured pair creates a Source owner.
    #[cfg(target_os = "linux")]
    fn coordinate_predecessor_successor_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        crate::policy_compiler::unavailable_predecessor_successor_v3(journal, profile, input)
    }

    /// Supplies advisory timing for one authority-bound attempt preparation.
    ///
    /// Returning `None` explicitly leaves authority-bound execution disabled.
    /// This hook must not perform external effects; the resulting attempt has
    /// not yet been made durable.
    fn authority_effect_timing(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
    ) -> Option<AuthorityEffectAttemptTimingV1> {
        None
    }

    /// Signs the exact post-lease Guardian arm plan requested for a Host launch.
    ///
    /// The request already commits the selected current lease and host boot.
    /// Returning `None` leaves Guardian-gated Host launches disabled. This hook
    /// must not start Guardian or payload units; the resulting plan is inserted
    /// into an exact packet and made durable first.
    fn prepare_guardian_plan(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _request: &GuardianPlanRequestV1,
    ) -> Option<SignedBrokerPlan> {
        None
    }

    /// Observes whether one stable effect key is already applied.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure when observation is temporarily unavailable
    /// or a permanent failure when the stable effect identity is contradictory.
    fn observe(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure>;

    /// Applies one exact idempotent effect request.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for transient boundary errors or a
    /// permanent failure for a rejected or contradictory fixed request.
    fn apply(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure>;

    /// Takes only a genuine completed NoApply and Source-disposal witness.
    ///
    /// The default has no witness. The kernel independently checks the same
    /// actual Controller owner, full current cut and exact terminal relation;
    /// a generic effect error or receipt cannot select this path.
    #[cfg(target_os = "linux")]
    fn take_execution_no_apply_completion_v2(&mut self, _operation: OperationId)
        -> Option<crate::controller_execution_operation::ControllerExecutionNoApplyCompletionV2> {
        None
    }

    /// Reconciles the exact public Storage Repair through its atomic terminal owner.
    ///
    /// This method-specific hook may commit the accepted Effect and Operation
    /// only together with the checked Sandbox successor, recovery head, exact
    /// predecessor archive and held receipt. It must not return a receipt for
    /// generic Apply to commit separately. Other public methods never use it.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for unavailable qualified orchestration or
    /// unsettled original custody, and a permanent failure for contradictions.
    fn reconcile_operator_storage_repair(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _plan: &EffectPlan,
        _journal: &mut Journal,
        _completion_wall_seconds: i64,
    ) -> Result<OperatorStorageRepairReconcileV1, EffectFailure> {
        Err(EffectFailure::Retryable("operator Storage Repair coordinator is unavailable".to_owned()))
    }

    /// Observes one controller-orchestration effect with journal custody.
    ///
    /// The default preserves ordinary executor behavior. Production
    /// orchestration may override this hook to reconcile controller-owned
    /// projections and separately protected source-domain state. It must not
    /// change this operation's operation or effect-ledger records.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure while exact orchestration remains pending,
    /// or a permanent failure for contradictory protected state.
    fn observe_controller(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        _journal: &mut Journal,
    ) -> Result<EffectObservation, EffectFailure> {
        self.observe(operation_id, step, plan)
    }

    /// Applies one controller-orchestration effect with journal custody.
    ///
    /// The default preserves ordinary executor behavior. An override may
    /// commit method-specific controller records, but completion evidence must
    /// still cover every external effect and authenticated readback required
    /// by the public mutation.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for recoverable pending work, or a permanent
    /// failure when protected state rejects the exact admitted request.
    fn apply_controller(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        _journal: &mut Journal,
    ) -> Result<EffectReceipt, EffectFailure> {
        self.apply(operation_id, step, plan)
    }

    /// Borrows the actual retained provisioning cause without changing custody.
    fn original_provisioning_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    /// Formats the original cause while any native property guard is borrowed.
    fn fmt_original_provisioning_failure_v1(&self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self.original_provisioning_failure_v1() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original provisioning purpose is closed"),
        }
    }

    /// Observes the exact Storage child using its installed provisioning owner.
    ///
    /// Returning `None` preserves ordinary behavior only without an actual
    /// provisioning scope. A selected original never falls back to Legacy IO.
    #[cfg(target_os = "linux")]
    fn observe_original_provisioning_authority_v1(
        &mut self, _operation: OperationId, _step: u32,
        _prepared: &PreparedAuthorityEffectV1, _journal: &mut Journal,
    ) -> Option<Result<AuthorityEffectObservationV1, EffectFailure>> {
        None
    }

    /// Applies the exact Storage child using its retained same-C23 Session IO.
    ///
    /// The concrete executor returns the same original to the Journal scope
    /// before returning any result; Core still always owes C23 and Root posts.
    #[cfg(target_os = "linux")]
    fn apply_original_provisioning_authority_v1(
        &mut self, _operation: OperationId, _step: u32,
        _prepared: &PreparedAuthorityEffectV1, _journal: &mut Journal,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        None
    }

    /// Observes one exact durably recorded authority-bound broker attempt.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure when authenticated observation is
    /// temporarily unavailable or a permanent failure for contradictory
    /// durable broker state.
    fn observe_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _prepared: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        Err(EffectFailure::Permanent(
            "authority-bound effect execution is unsupported".to_owned(),
        ))
    }

    /// Applies one exact durably recorded authority-bound broker attempt.
    ///
    /// # Errors
    ///
    /// Returns a retryable failure for transient transport or broker errors,
    /// or a permanent failure when the exact request is rejected.
    fn apply_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _prepared: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        Err(EffectFailure::Permanent(
            "authority-bound effect execution is unsupported".to_owned(),
        ))
    }
}

/// Reports one bounded reconciliation pass outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    /// Ownership is pending and no effect was made eligible or invoked.
    OwnershipPending,
    /// An adopted Observe child remains inert until a separate handoff protocol exists.
    ObserveChildPending,
    /// Durable state advanced without invoking an external effect.
    Progressed,
    /// An effect was applied or recovered and its receipt became durable.
    EffectApplied,
    /// A transient executor failure left the durable effect intent in flight.
    RetryPending,
    /// A prepared failed-Create cut awaits fresh held Host proof; no new effect is dispatched.
    CreateFailurePending,
    /// Every planned effect and the terminal operation success are durable.
    Succeeded,
    /// Desired Stop committed while explicit Capture cleanup debt remains.
    CommittedWithResidualCleanup,
    /// Protected orchestration canceled the operation before semantic commit.
    CanceledBeforeCommit,
    /// An exact Create no-Apply proof settled the operation and execution as failed.
    FailedBeforeCommit,
    /// A permanent executor failure durably blocked the operation.
    PermanentlyBlocked,
}

#[cfg(target_os = "linux")]
fn is_closed_no_apply_prepare_v2(journal: &Journal, operation: OperationId) -> bool {
    journal.get(RecordNamespace::ControllerCreateFailurePrepare, operation.as_bytes())
        .is_some_and(|bytes| bytes.starts_with(aos_sandbox_protocol::host_execution_no_apply::closed_controller::CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2))
}

#[cfg(target_os = "linux")]
pub(crate) fn require_closed_no_apply_terminal_ack_data_v2(journal: &Journal,
    ack: aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2,
) -> Result<(), ReconcilerError> {
    use aos_sandbox_protocol::host_execution_no_apply::closed_controller::ClosedCreateFailurePrepareDataV2;
    let bytes = journal.get(RecordNamespace::ControllerCreateFailurePrepare, ack.operation.as_bytes())
        .ok_or(ReconcilerError::InvalidExecutorOutput("NoApply completion lost its actual prepare"))?;
    let prepare = ClosedCreateFailurePrepareDataV2::decode_canonical(ack.operation.as_bytes(), bytes)
        .map_err(|_| ReconcilerError::InvalidExecutorOutput("NoApply completion prepare is malformed"))?;
    if prepare.root_floor != ack.root_floor || prepare.root_sequence != ack.root_sequence
        || prepare.digest() != ack.controller_prepare || prepare.settled_cas_digest() != ack.settled_cas {
        return Err(ReconcilerError::InvalidExecutorOutput("NoApply completion prepare/ACK identity changed"));
    }
    let plan = plan_closed_create_failure_rows_data_v2(journal, prepare.identity.marker,
        prepare.identity.terminal_archive, prepare.identity.signed_terminal, prepare.wall_seconds)?;
    if !plan.settled_data_v2() || plan.prepared_data_v2() != Some(prepare) {
        return Err(ReconcilerError::InvalidExecutorOutput("NoApply completion is not the exact actual three-row terminal"));
    }
    Ok(())
}

/// Identifies a durable operation state that still requires mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnfinishedOperationStateV1 {
    /// The operation is admitted but has not issued its first effect.
    Accepted,
    /// At least one exact effect intent is durably in flight.
    Applying,
    /// The operation is waiting for separately authorized ownership activation.
    OwnershipPending,
}

/// Identifies one validated durable operation that is not terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedUnfinishedOperationV1 {
    operation_id: OperationId,
    state: UnfinishedOperationStateV1,
}

impl ValidatedUnfinishedOperationV1 {
    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the validated nonterminal state.
    #[must_use]
    pub const fn state(self) -> UnfinishedOperationStateV1 {
        self.state
    }
}

/// Reports admission, ledger, journal, or executor-contract failures.
#[derive(Debug, thiserror::Error)]
pub enum ReconcilerError {
    /// Protected portable sandbox-specification history could not be validated.
    #[error("sandbox-specification state failed: {0}")]
    SandboxSpec(#[source] Box<crate::SandboxSpecStateError>),
    /// Protected destination-slot history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment-slot state failed: {0}")]
    AttachmentSlot(#[source] Box<crate::AttachmentSlotStateError>),
    /// Protected filesystem-view revision history could not be validated.
    #[error("filesystem-view revision state failed: {0}")]
    FilesystemViewRevision(#[source] Box<crate::FilesystemViewRevisionStateError>),
    /// Protected attachment desired-state history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment desired state failed: {0}")]
    AttachmentDesired(#[source] Box<crate::AttachmentDesiredStateError>),
    /// Protected attachment verification history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment verification failed: {0}")]
    AttachmentVerification(#[source] Box<crate::AttachmentVerificationError>),
    /// Protected attachment-source custody history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("attachment source custody failed: {0}")]
    AttachmentSource(#[source] Box<crate::AttachmentSourceError>),
    /// Protected Mount-attempt history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("mount attempt failed: {0}")]
    MountAttempt(#[source] Box<crate::mount_attempt::MountAttemptError>),
    /// Protected Mount source-acquisition inventory could not be validated.
    #[cfg(target_os = "linux")]
    #[error("Mount source-acquisition inventory failed: {0}")]
    MountSourceAcquisitionInventory(#[source] Box<crate::MountSourceAcquisitionInventoryError>),
    /// Protected destination-slot inventory could not be validated.
    #[cfg(target_os = "linux")]
    #[error("destination-slot inventory failed: {0}")]
    DestinationSlotInventory(#[source] Box<crate::mount_attempt::MountAttemptError>),
    /// Protected Storage or Network resource inventory could not be validated.
    #[cfg(target_os = "linux")]
    #[error("broker resource inventory failed: {0}")]
    ResourceInventory(#[source] Box<crate::ResourceInventoryError>),
    /// Durable Host catalog projection or publication state could not be validated.
    #[cfg(target_os = "linux")]
    #[error("Host catalog reconciliation failed: {0}")]
    HostCatalogReconciliation(#[source] Box<crate::HostCatalogReconciliationError>),
    /// Protected destination-slot effect history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("destination-slot effect failed: {0}")]
    DestinationSlotEffect(#[source] Box<crate::DestinationSlotEffectError>),
    /// Protected namespace-target allocation history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("namespace target failed: {0}")]
    NamespaceTarget(#[source] Box<crate::runtime_scope::NamespaceTargetError>),
    /// Protected runtime-generation history could not be validated.
    #[cfg(target_os = "linux")]
    #[error("runtime generation failed: {0}")]
    RuntimeGeneration(#[source] Box<crate::runtime_scope::RuntimeGenerationError>),
    /// Protected runtime-authority validation or mutation preparation failed.
    #[error("runtime authority failed: {0}")]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    /// Accepted provisioning/resource companions disagree with their source rows.
    #[error("provisioning resource history failed: {0}")]
    ProvisioningResource(#[from] aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1),
    /// Atomic historical Create STOPPED transaction DATA differs.
    #[cfg(target_os = "linux")]
    #[error("Create STOPPED terminal history failed: {0}")]
    CreateStoppedTerminal(#[from] aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedTerminalDataErrorV1),
    /// Durable journal operation failed.
    #[error("sandbox journal failed: {0}")]
    Journal(#[from] JournalError),
    /// An operation plan violates local bounds or required fields.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// A client reused an idempotency key for different semantic bytes.
    #[error("idempotency key is already bound to another request")]
    IdempotencyConflict,
    /// The requested operation does not exist in the durable ledger.
    #[error("operation is absent from the durable ledger")]
    OperationNotFound,
    /// A fresh idempotency key attempted to reuse a durable operation ID.
    #[error("operation identity already exists in the durable ledger")]
    OperationAlreadyExists,
    /// The configured durable nonterminal-operation capacity is exhausted.
    #[error("controller admission is backpressured by pending durable work")]
    AdmissionBackpressure,
    /// The requested operation has no ownership gate.
    #[error("operation has no durable ownership gate")]
    OwnershipGateNotFound,
    /// A released ownership gate was replayed with different activation facts.
    #[error("ownership gate activation conflicts with its durable result")]
    OwnershipActivationConflict,
    /// A new activation would replace current authority with older state.
    #[error("ownership publication is not a valid current successor")]
    OwnershipPublicationNotSuccessor,
    /// Durable operation or effect bytes violate the closed versioned schema.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// An executor returned unbounded or empty evidence.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
    /// A public operation transition lacks a valid monotone wall-clock sample.
    #[error("public operation clock observation is missing or invalid")]
    PublicOperationClock,
    /// A public operation exhausted its monotone observation sequence.
    #[error("public operation observation sequence is exhausted")]
    PublicOperationSequenceExhausted,
    /// Current publication selection or attempt attenuation failed.
    #[error("authority-bound effect preparation failed: {0}")]
    AuthorityPublication(#[from] crate::AuthorityPublicationError),
}

impl From<aos_sandbox_protocol::domain_ledger::public_operation::PublicOperationDataError>
    for ReconcilerError
{
    fn from(
        error: aos_sandbox_protocol::domain_ledger::public_operation::PublicOperationDataError,
    ) -> Self {
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicOperationDataError;

        match error {
            PublicOperationDataError::InvalidPlan(reason) => Self::InvalidPlan(reason),
            PublicOperationDataError::CorruptLedger(reason) => Self::CorruptLedger(reason),
            PublicOperationDataError::PublicOperationClock => Self::PublicOperationClock,
            PublicOperationDataError::PublicOperationSequenceExhausted => {
                Self::PublicOperationSequenceExhausted
            }
        }
    }
}

impl From<OwnershipGateDataErrorV1> for ReconcilerError {
    fn from(error: OwnershipGateDataErrorV1) -> Self {
        match error {
            OwnershipGateDataErrorV1::InvalidPlan(reason) => Self::InvalidPlan(reason),
            OwnershipGateDataErrorV1::CorruptLedger(reason) => Self::CorruptLedger(reason),
        }
    }
}

/// Reports whether exact ownership-gate activation committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipGateActivationOutcome {
    /// Publication records and gate release committed atomically.
    Activated,
    /// The exact activation facts were already durable.
    Replay,
}

#[cfg(target_os = "linux")]
pub(crate) mod provisioning;

/// Reconciles one exclusively owned single-node journal.
///
/// A poisoned journal rejects admission, gate resolution, and reconciliation
/// before replay or executor interaction, even if structural validation was
/// previously cached. Recovery requires reopening the journal.
pub struct Reconciler<E> {
    journal: Journal,
    executor: E,
    scheduling_cursor: Option<OperationId>,
    ledger_validated: bool,
}

impl<E> Reconciler<E>
where
    E: SingleNodeEffectExecutor,
{
    /// Constructs a reconciler over an exclusively opened journal.
    #[must_use]
    pub const fn new(journal: Journal, executor: E) -> Self {
        Self {
            journal,
            executor,
            scheduling_cursor: None,
            ledger_validated: false,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_original_start_entry_v1(&mut self,peer:&crate::public_api_session::PublicApiPeer,
        encoded:&[u8],
    )->Result<Option<crate::AcceptedStartEntryOriginalV1>,crate::ResourceReservationErrorV1> {
        self.ledger_validated=false;
        self.executor.prepare_original_start_entry_v1(peer,encoded,&mut self.journal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admit_original_delete_once_v4(
        &mut self,
        peer: &crate::public_api_session::PublicApiPeer,
        capability: aos_sandbox_model::CapabilityId,
        handle: &[u8],
        encoded: &[u8],
    ) -> Result<AcceptOutcome, crate::ResourceReservationErrorV1> {
        self.ledger_validated = false;
        self.executor.admit_original_delete_once_v4(peer, capability, handle, encoded, &mut self.journal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_original_execution_public_custody_once_v2(
        &mut self,
    ) -> Result<Option<crate::controller_execution_operation::ControllerExecutionPublicCustodyTransferV2>,
        crate::ResourceReservationErrorV1>
    {
        self.ledger_validated = false;
        self.executor.take_original_execution_public_custody_once_v2(&mut self.journal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_original_execution_public_custody_v2(
        &mut self,
        custody: crate::controller_execution_operation::ControllerExecutionRuntimeCustodyV2,
    ) {
        self.executor.retain_original_execution_public_custody_v2(custody);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admit_original_execution_availability_once_v2(
        &mut self,
        maximum_pending_operations: usize,
    ) -> Result<AcceptOutcome, crate::ResourceReservationErrorV1> {
        self.ledger_validated = false;
        self.executor.admit_original_execution_availability_once_v2(
            &mut self.journal, maximum_pending_operations)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn finish_original_start_entry_v1(&mut self,entry:&mut crate::AcceptedStartEntryOriginalV1) {
        self.executor.finish_original_start_entry_v1(entry,&mut self.journal);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admit_original_start_source_origin_v1(&mut self,entry:&mut crate::AcceptedStartEntryOriginalV1) {
        self.ledger_validated=false;
        self.executor.admit_original_start_source_origin_v1(entry,&mut self.journal);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_original_start_entry_v1(&mut self,entry:crate::AcceptedStartEntryOriginalV1) {
        self.executor.retain_original_start_entry_v1(entry);
    }

    /// Borrows the sole journal writer for a short composed controller action.
    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        self.ledger_validated = false;
        &mut self.journal
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_admin::policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_admin::policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.ledger_validated = false;
        self.executor.capture_existing_git_coverage_account_cut_v1(
            &mut self.journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_existing_git_coverage_account_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_admin::policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_admin::policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_model::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.ledger_validated = false;
        self.executor.commit_existing_git_coverage_account_v1(
            &mut self.journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        operation: &mut GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.ledger_validated = false;
        self.executor.run_existing_git_coverage_read_metadata_v1(
            &mut self.journal, original_inputs, operation,
        )
    }

    pub(crate) fn existing_cache_project_usage_v1(
        &mut self,
        project: aos_sandbox_model::ProjectId,
    ) -> Result<crate::cache_residency::CacheProjectUsageLoanV1<'_>, crate::cache_residency::CacheResidentUnavailableV1> {
        self.executor.existing_cache_project_usage_v1(project)
    }

    pub(crate) fn recheck_existing_cache_project_usage_v1(
        &mut self,
    ) -> Result<(), crate::cache_residency::CacheResidentUnavailableV1> {
        self.executor.recheck_existing_cache_project_usage_v1()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn select_original_create_q04_policy_subgate_v1(
        &mut self,
        profile: std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), EffectFailure> {
        self.executor.select_original_create_q04_policy_subgate_v1(&mut self.journal, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn compare_existing_cache_git_coverage_v1(
        &mut self,
        original_inputs: &mut crate::public_api_session::GitCoverageCredentialCustodyV1,
        flight: aos_sandbox_model::format::git_upload_enrollment::GitCoverageFlightV1,
        original_nonce: [u8; 16],
        original_account: Option<&mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(
        aos_sandbox_model::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
        aos_sandbox_model::format::git_upload_enrollment::GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), crate::cache_residency::CacheResidentUnavailableV1> {
        self.executor.compare_existing_cache_git_coverage_v1(
            original_inputs, flight, original_nonce, original_account,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn issue_source_successor_v2<'writers, 'profile, 'credentials>(
        &'writers mut self,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut crate::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<
        aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2,
        crate::policy_compiler::FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        self.ledger_validated = false;
        self.executor.issue_source_successor_v2(
            &mut self.journal, profile, credentials,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn issue_project_source_successor_v3<'writers, 'profile, 'credentials>(
        &'writers mut self, profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut crate::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2, crate::policy_compiler::FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>> {
        self.ledger_validated = false;
        self.executor.issue_project_source_successor_v3(&mut self.journal, profile, credentials)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn observe_operator_create_recovery_sources_v1(&mut self,
        original: &mut crate::OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), crate::OperatorCreateRecoveryClosedV1> {
        self.ledger_validated = false;
        self.executor.observe_operator_create_recovery_sources_v1(&mut self.journal, original)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn finish_operator_create_recovery_after_native_v1(&mut self,
        original: &mut crate::OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), crate::OperatorCreateRecoveryClosedV1> {
        self.executor.finish_operator_create_recovery_after_native_v1(&self.journal, original)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn complete_operator_cleanup_recovery_v2(&mut self,
        original: &mut crate::OperatorCreateRecoveryOriginalV1,
        purpose: aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1,
    ) -> Result<aos_sandbox_api::aos::sandbox::v1::Operation, crate::OperatorCreateRecoveryClosedV1> {
        self.ledger_validated = false;
        let completed = self.executor.complete_operator_cleanup_recovery_v2(&mut self.journal, original, purpose)?;
        use aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1 as Purpose;
        let closed = crate::OperatorCreateRecoveryClosedV1;
        match (purpose, completed) {
            (Purpose::StopCleanup, OperatorCleanupRecoveryCompletionV2::Stop { response, completion }) => {
                let operation = OperationId::from_bytes(response.operation_id.as_slice().try_into().map_err(|_| closed)?);
                completion.require_recovery_current_v1(&self.journal, operation).map_err(|_| closed)?;
                Ok(response)
            }
            (Purpose::ExecutionNoApply, OperatorCleanupRecoveryCompletionV2::Execution { response, completion }) => {
                let operation = OperationId::from_bytes(response.operation_id.as_slice().try_into().map_err(|_| closed)?);
                completion.require_recovery_current_v2(&self.journal, operation).map_err(|_| closed)?;
                Ok(response)
            }
            _ => Err(closed),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_recovered_ordinary_sessions_once_v2(&mut self) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2> {
        self.executor.take_recovered_ordinary_sessions_once_v2()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn reconcile_first_local_after_recover_v2(&mut self,
        original: &crate::OperatorCreateRecoveryOriginalV1,
    ) -> Result<(), crate::OperatorCreateRecoveryClosedV1> {
        self.ledger_validated = false;
        self.executor.reconcile_first_local_after_recover_v2(&mut self.journal, original)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn begin_catalog_maintenance_once_v2(&mut self,
        original: &mut crate::CatalogMaintenanceOriginalV2,
        bank: &std::sync::Arc<std::sync::Mutex<crate::ControllerResourceBankOpeningV1>>,
        profile: &std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        runtime: &std::sync::Arc<tokio::runtime::Runtime>,
        shape: crate::CatalogMaintenanceSdkShapeDataV2,
    ) -> Result<(), crate::CatalogMaintenanceClosedV2> {
        self.ledger_validated = false;
        self.executor.begin_catalog_maintenance_once_v2(&mut self.journal, original, bank, profile, runtime, shape)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn begin_catalog_refresh_once_v2(&mut self,
        original: &mut crate::CatalogMaintenanceOriginalV2,
        bank: &std::sync::Arc<std::sync::Mutex<crate::ControllerResourceBankOpeningV1>>,
        profile: &std::sync::Arc<crate::normal_root::ProductionControllerNormalRootProfileV1>,
        runtime: &std::sync::Arc<tokio::runtime::Runtime>,
        shape: crate::CatalogMaintenanceSdkShapeDataV2,
    ) -> Result<(), crate::CatalogMaintenanceClosedV2> {
        self.ledger_validated = false;
        self.executor.begin_catalog_refresh_once_v2(&mut self.journal, original, bank, profile, runtime, shape)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn borrow_catalog_maintenance_interval_v2<'owner, 'controller>(
        &'controller mut self, original: &'owner mut crate::CatalogMaintenanceOriginalV2,
    ) -> Result<crate::ControllerCatalogMaintenanceLoanV2<'owner, 'controller>, crate::ResourceReservationErrorV1> {
        self.ledger_validated = false;
        let source = self.executor.borrow_catalog_maintenance_source_v2(&self.journal, original)?;
        source.into_interval_v2(original, &mut self.journal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn finish_catalog_maintenance_once_v2(&mut self, original: &mut crate::CatalogMaintenanceOriginalV2) {
        self.executor.finish_catalog_maintenance_once_v2(&mut self.journal, original)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_catalog_maintenance_sdk_disposal_v2<'owner>(
        &self, original: &'owner mut crate::CatalogMaintenanceOriginalV2,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<crate::ControllerCatalogMaintenanceCatalogDisposalV2<'owner>, crate::ResourceReservationErrorV1> {
        original.prepare_catalog_sdk_disposal_once_v2(&self.journal, source, outcome)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_catalog_maintenance_storage_sdk_disposal_v3<'owner>(
        &self,
        original: &'owner mut crate::CatalogMaintenanceOriginalV2,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
        resource: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        native: &[u8; 64],
    ) -> Result<
        crate::ControllerMaintenanceStorageSdkDisposalV3<'owner>,
        crate::ResourceReservationErrorV1,
    > {
        original.prepare_storage_sdk_disposal_once_v3(
            &self.journal,
            prepared,
            resource,
            inventory,
            native,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn completed_catalog_maintenance_cold_native_v2<'completed>(
        &self, original: &'completed crate::CatalogMaintenanceOriginalV2,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
    ) -> Result<crate::CatalogMaintenanceColdCompletedNativeBorrowV2<'completed>, crate::ResourceReservationErrorV1> {
        original.completed_cold_native_v2(&self.journal, source)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn completed_catalog_maintenance_refresh_native_v2<'completed>(
        &self, original: &'completed crate::CatalogMaintenanceOriginalV2,
        source: &crate::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2,
    ) -> Result<crate::CatalogMaintenanceRefreshCompletedNativeBorrowV2<'completed>, crate::ResourceReservationErrorV1> {
        original.completed_refresh_native_v2(&self.journal, source)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn require_recovered_ordinary_session_for_maintenance_v2(
        &self, session: &crate::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        context: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2,
        bank: &crate::ControllerResourceBankOpeningV1,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), crate::ResourceReservationErrorV1> {
        session.require_completed_recovered_ordinary_context_v2(context, bank, &self.journal, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_cold_create_stopped_observer_once_v1(&mut self)
        -> Result<(), crate::journal::CreateStoppedColdObserverClosedV1> {
        self.ledger_validated = false;
        self.executor.coordinate_cold_create_stopped_observer_once_v1(&mut self.journal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn observe_current_executions_v4(&mut self) -> Result<(), EffectFailure> {
        self.ledger_validated = false;
        self.executor.observe_current_executions_v4(&mut self.journal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_provisioned_source_genesis_v1(
        &mut self,
        input: &crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        ObjectDigest,
        crate::hierarchy::controller_genesis_input::ControllerSourceGenesisInputErrorV1,
    > {
        self.ledger_validated = false;
        self.executor
            .coordinate_provisioned_source_genesis_v1(&mut self.journal, input, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_configured_project_genesis_v3<'writers, 'profile>(
        &'writers mut self,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, crate::policy_compiler::FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile>> {
        self.ledger_validated = false;
        self.executor.coordinate_configured_project_genesis_v3(&mut self.journal, input, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_configured_global_genesis_v2<'writers, 'profile>(
        &'writers mut self,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, crate::policy_compiler::FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile>> {
        self.ledger_validated = false;
        self.executor.coordinate_configured_global_genesis_v2(&mut self.journal, input, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_first_global_prefix_v1(
        &mut self,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1> {
        self.ledger_validated = false;
        self.executor.prepare_first_global_prefix_v1(&mut self.journal, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_retained_first_source_successor_v2<'writers, 'profile>(
        &'writers mut self, profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
        self.ledger_validated = false;
        self.executor.coordinate_retained_first_source_successor_v2(&mut self.journal, profile)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_project_successor_v3<'writers, 'profile>(
        &'writers mut self, profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        project: aos_sandbox_model::ProjectId,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        self.ledger_validated = false;
        self.executor.coordinate_project_successor_v3(&mut self.journal, profile, project)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn coordinate_predecessor_successor_v3<'writers, 'profile>(
        &'writers mut self,
        input: &'writers crate::hierarchy::controller_genesis_input::ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, crate::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        self.ledger_validated = false;
        self.executor.coordinate_predecessor_successor_v3(&mut self.journal, input, profile)
    }

    /// Loads and validates an operation's durable ownership gate, when present.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the operation is absent or the gate,
    /// operation state, or original idempotency decision is inconsistent.
    pub fn ownership_gate(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let operation = self.load_operation(operation_id)?;
        self.load_and_validate_ownership_gate(operation_id, operation)
    }

    /// Atomically releases one pending gate with a validated publication bridge.
    ///
    /// The opaque bridge owns exactly the prepared/current publication records
    /// and their structural summary facts. This composition point performs no
    /// ownership service call and grants no authority by itself.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for an absent or corrupt gate, mismatched
    /// publication context, conflicting replay, stale publication, duplicate
    /// records, or durability failure.
    pub(crate) fn activate_ownership_gate(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        self.activate_ownership_gate_inner(operation_id, activation, None)
    }

    pub(crate) fn activate_ownership_gate_at(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
        wall_seconds: i64,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        self.activate_ownership_gate_inner(operation_id, activation, Some(wall_seconds))
    }

    fn activate_ownership_gate_inner(
        &mut self,
        operation_id: OperationId,
        activation: AuthorityPublicationActivationV1,
        wall_seconds: Option<i64>,
    ) -> Result<OwnershipGateActivationOutcome, ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.activate_ownership_gate_inner(operation_id, activation, wall_seconds);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    /// Atomically admits desired state, an operation, and its effect ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for an idempotency conflict, record bound
    /// violation, or journal durability failure.
    pub fn accept(&mut self, plan: &OperationPlan) -> Result<AcceptOutcome, ReconcilerError> {
        self.accept_inner(plan, None)
    }

    /// Atomically admits a plan while bounding nonterminal durable work.
    ///
    /// Exact idempotent replay remains available while the bound is reached.
    /// This method is crate-private because admission policy belongs to the
    /// activated controller service rather than the general ledger API.
    pub(crate) fn accept_bounded(
        &mut self,
        plan: &OperationPlan,
        maximum_pending_operations: usize,
    ) -> Result<AcceptOutcome, ReconcilerError> {
        if maximum_pending_operations == 0 {
            return Err(ReconcilerError::InvalidPlan(
                "pending operation bound is zero",
            ));
        }
        self.accept_inner(plan, Some(maximum_pending_operations))
    }

    fn accept_inner(
        &mut self,
        plan: &OperationPlan,
        maximum_pending_operations: Option<usize>,
    ) -> Result<AcceptOutcome, ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.accept_inner(plan, maximum_pending_operations);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn pending_operation_count(&self) -> Result<usize, ReconcilerError> {
        core_journal::readonly::pending_operation_count(&self.journal)
    }

    /// Returns the first validated operation that still requires active work.
    ///
    /// The query performs no journal mutation and never invokes the executor.
    /// It validates the complete recovered ledger, scans the journal-bounded
    /// Operation namespace, and retains at most one result.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when journal health, an operation record, or
    /// any cross-referenced durable ledger namespace fails validation.
    pub fn validated_unfinished_operation(
        &mut self,
    ) -> Result<Option<ValidatedUnfinishedOperationV1>, ReconcilerError> {
        self.ensure_ledger_validated_read_only()?;

        let mut first = None;
        let adopted_children = observe_reservation::adopted_operations(&self.journal)?;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            if adopted_children.contains(&operation_id) {
                continue;
            }
            let operation = decode_operation(value)?;
            let state = match operation.state() {
                OperationState::Accepted => UnfinishedOperationStateV1::Accepted,
                OperationState::Applying => UnfinishedOperationStateV1::Applying,
                OperationState::OwnershipPending => UnfinishedOperationStateV1::OwnershipPending,
                OperationState::Succeeded
                | OperationState::CanceledBeforeCommit
                | OperationState::FailedBeforeCommit
                | OperationState::CommittedWithResidualCleanup
                | OperationState::PermanentlyBlocked => continue,
            };
            first.get_or_insert(ValidatedUnfinishedOperationV1 {
                operation_id,
                state,
            });
        }

        Ok(first)
    }

    /// Loads one restart-stable established public operation resource.
    ///
    /// Internal V1 operations deliberately return `None`; their ledger lacks
    /// the public method, generation, audit identity, and timestamps required
    /// to construct a truthful established resource.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the recovered ledger or any referenced
    /// effect record is corrupt.
    pub fn public_operation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<aos_sandbox_api::aos::sandbox::v1::Operation>, ReconcilerError> {
        self.ensure_ledger_validated_read_only()?;
        recovered_public_operation_resource_v1(&self.journal, operation_id)
    }

    /// Loads the immutable current-authorization scope for a public operation.
    ///
    /// V2 observations recovered from before this scope was introduced return
    /// `None` and remain available only through protected diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the ledger or authorization binding is
    /// malformed or refers to a non-public operation.
    pub fn public_operation_authorization(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<PublicOperationAuthorizationV1>, ReconcilerError> {
        self.ensure_ledger_validated_read_only()?;
        self.journal
            .get(
                RecordNamespace::PublicOperationAuthorization,
                operation_id.as_bytes(),
            )
            .map(PublicOperationAuthorizationV1::decode)
            .transpose()
            .map_err(ReconcilerError::from)
    }

    /// Borrows the installed executor's original provisioning failure.
    ///
    /// This read-only forwarding view does not replace the retained owner or
    /// open a failed native purpose. It conveys no completion authority.
    #[doc(hidden)]
    pub fn original_provisioning_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)> {
        self.executor.original_provisioning_failure_v1()
    }

    /// Borrows a formatter for the same installed original provisioning cause.
    ///
    /// The formatter holds no allocated diagnostic or temporary error guard;
    /// the executor borrows its selected native archive only while formatting.
    #[doc(hidden)]
    pub fn original_provisioning_failure_view_v1(&self) -> impl std::fmt::Display + '_ {
        OriginalProvisioningFailureDisplayV1(&self.executor)
    }

    /// Advances one operation by at most one durable transition or effect.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] when the operation is absent, ledger bytes
    /// are corrupt, executor output violates bounds, or a journal commit fails.
    pub fn reconcile_once(
        &mut self,
        operation_id: OperationId,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        self.reconcile_once_inner(operation_id, None)
    }

    /// Advances one operation using its caller's wall-clock observation.
    ///
    /// Public operations require this entry point so every durable observation
    /// transition receives an atomic, monotone reconciliation timestamp. This
    /// low-level value grants no authority; activated controllers must source
    /// it through their protected clock boundary.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::reconcile_once`], plus
    /// [`ReconcilerError::PublicOperationClock`] if the supplied wall time
    /// moves backward or is outside the protobuf timestamp range.
    pub fn reconcile_once_at(
        &mut self,
        operation_id: OperationId,
        wall_seconds: i64,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        self.reconcile_once_inner(operation_id, Some(wall_seconds))
    }

    fn reconcile_once_inner(
        &mut self,
        operation_id: OperationId,
        wall_seconds: Option<i64>,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let operation = self.load_operation(operation_id)?;
        if observe_reservation::is_adopted_child(&self.journal, operation_id)? {
            return Ok(ReconcileOutcome::ObserveChildPending);
        }
        let gate = self.load_and_validate_ownership_gate(operation_id, operation)?;
        // Metadata completion has no executable Effect. Only the closed Root-
        // admitted joint terminal CAS can finish it; an empty generic loop
        // must never turn its durable Accepted prefix into public success.
        if operation.state() == OperationState::Accepted
            && operation.public_operation().is_some_and(|public| matches!(public.recovery_kind_v1(),
                aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::MetadataComplete
                    | aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::StopCleanup
                    | aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::ExecutionNoApply)) {
            return Ok(ReconcileOutcome::RetryPending);
        }
        match operation.state() {
            OperationState::OwnershipPending => return Ok(ReconcileOutcome::OwnershipPending),
            OperationState::Succeeded | OperationState::PermanentlyBlocked => {
                if has_operator_repair_settlement_debt_v1(&self.journal, operation_id)? {
                    let effect = decode_effect(
                        self.journal
                            .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
                            .ok_or(ReconcilerError::CorruptLedger(
                                "Repair settlement debt lost its effect",
                            ))?,
                    )
                    .map_err(ReconcilerError::from)?
                    .into_parts();
                    return self.reconcile_applying(
                        operation_id,
                        0,
                        operation.effect_count(),
                        1,
                        effect.0,
                        None,
                        None,
                        wall_seconds,
                    );
                }
                return Ok(if operation.state() == OperationState::Succeeded {
                    ReconcileOutcome::Succeeded
                } else {
                    ReconcileOutcome::PermanentlyBlocked
                });
            }
            OperationState::CommittedWithResidualCleanup => {
                // Exact cold ledger validation already joined its sole residual
                // companion. A normal reconcile cannot reissue containment.
                return Ok(ReconcileOutcome::CommittedWithResidualCleanup);
            }
            OperationState::CanceledBeforeCommit => {
                return Ok(ReconcileOutcome::CanceledBeforeCommit);
            }
            OperationState::FailedBeforeCommit => {
                #[cfg(target_os = "linux")]
                if is_closed_no_apply_prepare_v2(&self.journal, operation_id) {
                    return self.require_execution_no_apply_completion_v2(operation_id);
                }
                return Ok(ReconcileOutcome::FailedBeforeCommit);
            }
            OperationState::Accepted | OperationState::Applying => {}
        }
        #[cfg(target_os = "linux")]
        self.journal.require_git_coverage_new_admission_v1()?;
        if create_failure::has_prepare_floor(&self.journal, operation_id)? {
            return Ok(ReconcileOutcome::CreateFailurePending);
        }
        #[cfg(target_os = "linux")]
        if let Some(returned)=self.executor.progress_original_start_once_v1(operation_id,&mut self.journal) {
            // The installed original keeps all reached results and mandatory
            // posts. The public Start remains nonterminal until real launch
            // completion; this route never enters ordinary effect dispatch.
            returned.map_err(|_|ReconcilerError::InvalidExecutorOutput(
                "the original Start continuation retains a refusal",
            ))?;
            return Ok(ReconcileOutcome::RetryPending);
        }
        #[cfg(target_os = "linux")]
        if operation.public_operation().is_some_and(|public|
            public.method() == aos_sandbox_protocol::public_api::PublicOperationMethodV1::StopSandbox)
        {
            if let Some(returned) = self.executor.progress_original_lifecycle_stop_once_v4(
                operation_id, &mut self.journal)
            {
                // No generic failure/retry transition may overwrite a reached
                // residual CAS or turn supplied receipt DATA into Applied.
                self.ledger_validated = false;
                returned.map_err(|_| ReconcilerError::InvalidExecutorOutput(
                    "the original Stop continuation retains a refusal"))?;
                self.ensure_ledger_validated()?;
                return match self.load_operation(operation_id)?.state() {
                    OperationState::CommittedWithResidualCleanup => Ok(ReconcileOutcome::CommittedWithResidualCleanup),
                    OperationState::Succeeded => Ok(ReconcileOutcome::Succeeded),
                    _ => Ok(ReconcileOutcome::RetryPending),
                };
            }
        }
        #[cfg(target_os = "linux")]
        if !self.has_original_provisioning_operation_v1(operation_id)
            && create_q04::require_original_pending(&self.journal)? {
            // Only the actual sole public parent may ask its retained issuer
            // for a separately funded turn. Every generic effect and every
            // unrelated operation remains behind the original Q04 fence.
            return self.continue_original_publication_parent_v1(operation_id, operation);
        }

        let mut canceled_before_commit = false;
        for step in 0..operation.effect_count() {
            let key = effect_key(operation_id, step);
            let bytes = self
                .journal
                .get(RecordNamespace::Effect, &key)
                .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
            #[cfg(target_os = "linux")]
            let (record, q04) = decode_effect_with_q04(bytes)
                .map_err(ReconcilerError::from)
                .map(|(record, q04)| (record.into_parts(), q04))?;
            #[cfg(not(target_os = "linux"))]
            let record = decode_effect(bytes)
                .map_err(ReconcilerError::from)?
                .into_parts();
            #[cfg(target_os = "linux")]
            if q04.is_some() {
                // A historical policy subgate cannot dispatch Create, retire
                // it, or restart Stage through generic reconciliation. Only
                // the original selected invocation advances its closed phase.
                return Ok(ReconcileOutcome::RetryPending);
            }
            match record.1 {
                EffectState::Applied { receipt, .. } => {
                    if receipt
                        .canceled_before_commit_evidence()
                        .map_err(|()| {
                            ReconcilerError::CorruptLedger(
                                "invalid canceled-before-commit effect receipt",
                            )
                        })?
                        .is_some()
                    {
                        if operation.effect_count() != 1
                            || step != 0
                            || record.0.public_mutation_method().is_none()
                        {
                            return Err(ReconcilerError::CorruptLedger(
                                "invalid canceled-before-commit effect receipt",
                            ));
                        }
                        canceled_before_commit = true;
                    }
                    continue;
                }
                EffectState::PermanentlyBlocked { .. } => {
                    self.store_operation(
                        operation_id,
                        OperationState::PermanentlyBlocked,
                        operation.effect_count(),
                        wall_seconds,
                    )?;
                    return Ok(ReconcileOutcome::PermanentlyBlocked);
                }
                EffectState::Planned => {
                    let dispatch = if let Some(binding) = record.0.authority() {
                        let OwnershipGateStatusV1::Activated {
                            plan: gate_plan,
                            publication_digest,
                            ..
                        } = gate.as_ref().ok_or(ReconcilerError::CorruptLedger(
                            "authority effect has no activated ownership gate",
                        ))?
                        else {
                            return Err(ReconcilerError::CorruptLedger(
                                "authority effect advanced while ownership is pending",
                            ));
                        };
                        let timing = self
                            .executor
                            .authority_effect_timing(operation_id, step)
                            .ok_or(ReconcilerError::InvalidExecutorOutput(
                                "authority-bound effect execution is unsupported",
                            ))?;
                        let sandbox = gate_plan.claim().assignment().sandbox();
                        let (selected_publication, attempt) = self.prepare_bound_current_attempt(
                            operation_id,
                            step,
                            sandbox,
                            *publication_digest,
                            binding.source_draft_digest(),
                            binding.audience(),
                            binding.template_digest(),
                            timing,
                        )?;
                        Some(PreparedAuthorityEffectV1::new(
                            binding.digest(),
                            selected_publication,
                            timing.clock(),
                            attempt,
                        ))
                    } else {
                        None
                    };
                    let applying = EffectLedgerRecord::from_parts((
                        record.0,
                        EffectState::Applying {
                            attempt: 1,
                            diagnostic: String::new(),
                        },
                        dispatch.map(PreparedAuthorityEffectV1::into_history),
                        record.3,
                    ));
                    self.store_effect(
                        operation_id,
                        step,
                        &applying,
                        Some(operation.effect_count()),
                        wall_seconds,
                    )?;
                    #[cfg(target_os = "linux")]
                    self.journal.retain_unissued_original_provisioning_attempt_v1(operation_id, step)?;
                    return Ok(ReconcileOutcome::Progressed);
                }
                EffectState::Applying { attempt, .. } => {
                    return self.reconcile_applying(
                        operation_id,
                        step,
                        operation.effect_count(),
                        attempt,
                        record.0,
                        record.2.map(PreparedAuthorityEffectV1::from_history),
                        match gate.as_ref() {
                            Some(OwnershipGateStatusV1::Activated {
                                plan,
                                publication_digest,
                                ..
                            }) => Some((plan.claim().assignment().sandbox(), *publication_digest)),
                            _ => None,
                        },
                        wall_seconds,
                    );
                }
            }
        }

        let (state, outcome) = if canceled_before_commit {
            (
                OperationState::CanceledBeforeCommit,
                ReconcileOutcome::CanceledBeforeCommit,
            )
        } else {
            (OperationState::Succeeded, ReconcileOutcome::Succeeded)
        };
        self.store_operation(operation_id, state, operation.effect_count(), wall_seconds)?;
        Ok(outcome)
    }

    /// Advances one fairly selected nonterminal operation by one step.
    ///
    /// Returns `Ok(None)` when no admitted operation needs reconciliation.
    /// The cursor is scheduling state only; durable correctness and effect
    /// ordering do not depend on preserving it across process restart.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError`] for corrupt operation records or the same
    /// journal and executor failures as [`Self::reconcile_once`].
    pub fn reconcile_next(
        &mut self,
    ) -> Result<Option<(OperationId, ReconcileOutcome)>, ReconcilerError> {
        self.reconcile_next_inner(None)
    }

    /// Advances one fairly selected operation at a caller-supplied wall time.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::reconcile_next`] and rejects a
    /// nonmonotone public-operation timestamp.
    pub fn reconcile_next_at(
        &mut self,
        wall_seconds: i64,
    ) -> Result<Option<(OperationId, ReconcileOutcome)>, ReconcilerError> {
        self.reconcile_next_inner(Some(wall_seconds))
    }

    fn reconcile_next_inner(
        &mut self,
        wall_seconds: Option<i64>,
    ) -> Result<Option<(OperationId, ReconcileOutcome)>, ReconcilerError> {
        self.ensure_ledger_validated()?;
        let mut first = None;
        let mut after_cursor = None;
        for (key, value) in self.journal.records(RecordNamespace::Operation) {
            let operation_id = decode_operation_key(key)?;
            let operation = decode_operation(value)?;
            if (operation.state().is_terminal()
                && !has_operator_repair_settlement_debt_v1(&self.journal, operation_id)?)
                || operation.state() == OperationState::OwnershipPending
            {
                continue;
            }
            first.get_or_insert(operation_id);
            if self
                .scheduling_cursor
                .is_some_and(|cursor| operation_id > cursor)
            {
                after_cursor = Some(operation_id);
                break;
            }
        }
        let Some(operation_id) = after_cursor.or(first) else {
            return Ok(None);
        };
        self.scheduling_cursor = Some(operation_id);
        let outcome = self.reconcile_once_inner(operation_id, wall_seconds)?;
        Ok(Some((operation_id, outcome)))
    }

    fn validate_all_ownership_gates(
        &mut self,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.validate_all_ownership_gates(validate_current_boot);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn validate_public_operation_authorizations(&self) -> Result<(), ReconcilerError> {
        core_journal::readonly::validate_public_operation_authorizations(&self.journal)
    }

    fn ensure_ledger_validated(&mut self) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.ensure_ledger_validated();
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn ensure_ledger_validated_read_only(&mut self) -> Result<(), ReconcilerError> {
        self.ensure_ledger_validated_for(false)
    }

    fn ensure_ledger_validated_for(
        &mut self,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.ensure_ledger_validated_for(validate_current_boot);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn validate_gated_effects_for_activation(
        &self,
        operation_id: OperationId,
        effect_count: u32,
    ) -> Result<(), ReconcilerError> {
        core_journal::readonly::validate_gated_effects_for_activation(&self.journal, operation_id, effect_count)
    }

    fn validate_operation_gate_relation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.validate_operation_gate_relation(operation_id);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn load_and_validate_ownership_gate(
        &mut self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.load_and_validate_ownership_gate(operation_id, operation);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn load_and_validate_ownership_gate_for(
        &mut self,
        operation_id: OperationId,
        operation: OperationRecord,
        validate_current_boot: bool,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.load_and_validate_ownership_gate_for(operation_id, operation, validate_current_boot);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    fn validate_canceled_operation(
        &self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<(), ReconcilerError> {
        core_journal::readonly::validate_canceled_operation(&self.journal, operation_id, operation)
    }

    fn validate_effect_authority_bindings(
        &mut self,
        operation_id: OperationId,
        effect_count: u32,
        draft: Option<&AuthorityPublicationDraftV1>,
        activated_publication: Option<ObjectDigest>,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        let returned = kernel.validate_effect_authority_bindings(operation_id, effect_count, draft, activated_publication, validate_current_boot);
        self.ledger_validated = kernel.ledger_validated;
        returned
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_bound_current_attempt(
        &mut self,
        operation_id: OperationId,
        step: u32,
        sandbox: SandboxId,
        activated_publication: ObjectDigest,
        source_draft_digest: ObjectDigest,
        audience: aos_sandbox_model::BrokerAudience,
        template_digest: ObjectDigest,
        timing: AuthorityEffectAttemptTimingV1,
    ) -> Result<(ObjectDigest, crate::BrokerDispatchAttemptV1), ReconcilerError> {
        let guardian_request = AuthorityPublicationStore::new(&mut self.journal)
            .select_bound_guardian_plan_request(
                sandbox,
                activated_publication,
                source_draft_digest,
                audience,
                template_digest,
                timing.clock().host_boot_id(),
            )?;
        let guardian_plan = guardian_request
            .as_ref()
            .map(|request| {
                self.executor
                    .prepare_guardian_plan(operation_id, step, request)
                    .ok_or(ReconcilerError::InvalidExecutorOutput(
                        "Guardian plan signing is unavailable for Host launch",
                    ))
            })
            .transpose()?;
        AuthorityPublicationStore::new(&mut self.journal)
            .select_bound_current_attempt(
                sandbox,
                activated_publication,
                source_draft_digest,
                audience,
                template_digest,
                guardian_plan.as_ref(),
                timing.deadline(),
                timing.clock(),
            )
            .map_err(ReconcilerError::AuthorityPublication)
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_applying(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
        dispatch: Option<PreparedAuthorityEffectV1>,
        authority_gate: Option<(SandboxId, ObjectDigest)>,
        wall_seconds: Option<i64>,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        if is_operator_storage_repair_effect_v1(&plan)? {
            if step != 0 || effect_count != 1 || dispatch.is_some() || authority_gate.is_some() {
                return Err(ReconcilerError::InvalidPlan(
                    "operator Storage Repair has a nonexact effect graph",
                ));
            }
            let Some(clock) = wall_seconds else {
                return Ok(ReconcileOutcome::RetryPending);
            };
            let result = self.executor.reconcile_operator_storage_repair(
                operation_id,
                step,
                &plan,
                &mut self.journal,
                clock,
            );
            self.ledger_validated = false;
            self.ensure_ledger_validated()?;
            match result {
                Ok(OperatorStorageRepairReconcileV1::Terminal) => {
                    #[cfg(target_os = "linux")]
                    let decision = crate::controller::verify_atomic_operator_storage_repair_terminal_v2(&mut self.journal, operation_id)
                        .map_err(|_| ReconcilerError::InvalidExecutorOutput("Repair terminal rows failed independent readback"))?;
                    #[cfg(not(target_os = "linux"))]
                    return Err(ReconcilerError::InvalidExecutorOutput(
                        "Repair terminal owner is unsupported",
                    ));
                    #[cfg(target_os = "linux")]
                    return Ok(match decision {
                        crate::controller::RepairPublicTerminalV1::Succeeded => ReconcileOutcome::Succeeded,
                        crate::controller::RepairPublicTerminalV1::OriginalPreconditionReplaced => ReconcileOutcome::PermanentlyBlocked,
                    });
                }
                Ok(OperatorStorageRepairReconcileV1::Pending)
                | Err(EffectFailure::Retryable(_)) => {
                    return Ok(ReconcileOutcome::RetryPending);
                }
                Err(EffectFailure::Permanent(_)) => {
                    // A contradicted possibly sent Repair stays under original
                    // custody. Generic failure cannot rewrite its terminal rows.
                    return Err(ReconcilerError::InvalidExecutorOutput(
                        "Repair coordinator contradicted original custody",
                    ));
                }
            }
        }
        #[cfg(target_os = "linux")]
        if plan.public_mutation_method() == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox) {
            if let Some(result) = self.executor.reconcile_original_create_q04_policy_subgate_v1(
                operation_id, step, effect_count, &plan, dispatch.as_ref(), authority_gate,
                &mut self.journal,
            ) {
                result.map_err(|_| ReconcilerError::InvalidExecutorOutput(
                    "selected Q04 original custody cannot fall back to generic Apply",
                ))?;
                self.ledger_validated = false;
                self.ensure_ledger_validated()?;
                if !create_q04::require_original_pending(&self.journal)? {
                    return Err(ReconcilerError::InvalidExecutorOutput(
                        "Q04 policy subgate lost its pending fence",
                    ));
                }
                return self.advance_original_publication_from_executor_v1(operation_id, &plan);
            }
        }
        let receipt = if let Some(prepared) = dispatch.as_ref() {
            #[cfg(target_os = "linux")]
            let observed = if self.journal.has_provisioning_scope_v1() {
                self.executor.observe_original_provisioning_authority_v1(
                    operation_id, step, prepared, &mut self.journal,
                ).unwrap_or_else(|| Err(EffectFailure::Permanent(
                    "the original provisioning Storage observation is unavailable".to_owned(),
                )))
            } else {
                self.executor.observe_authority(operation_id, step, prepared)
            };
            #[cfg(not(target_os = "linux"))]
            let observed = self.executor.observe_authority(operation_id, step, prepared);
            let observed = match observed {
                Ok(value) => value,
                Err(failure) => {
                    return self.handle_failure(
                        operation_id,
                        step,
                        effect_count,
                        attempt,
                        plan,
                        dispatch.clone(),
                        failure,
                        wall_seconds,
                    );
                }
            };
            match observed {
                AuthorityEffectObservationV1::Applied(receipt) => {
                    receipt.into_effect_receipt_for(prepared)?
                }
                AuthorityEffectObservationV1::Pending => return Ok(ReconcileOutcome::RetryPending),
                AuthorityEffectObservationV1::Absent => {
                    let binding = plan.authority().ok_or(ReconcilerError::CorruptLedger(
                        "authority dispatch has no binding",
                    ))?;
                    let (sandbox, activated_publication) = authority_gate.ok_or(
                        ReconcilerError::CorruptLedger("authority dispatch has no activated gate"),
                    )?;
                    let timing = self
                        .executor
                        .authority_effect_timing(operation_id, step)
                        .ok_or(ReconcilerError::InvalidExecutorOutput(
                            "authority-bound effect execution is unsupported",
                        ))?;
                    let (publication_digest, fresh_attempt) = self.prepare_bound_current_attempt(
                        operation_id,
                        step,
                        sandbox,
                        activated_publication,
                        binding.source_draft_digest(),
                        binding.audience(),
                        binding.template_digest(),
                        timing,
                    )?;
                    let fresh = PreparedAuthorityEffectV1::new(
                        binding.digest(),
                        publication_digest,
                        timing.clock(),
                        fresh_attempt,
                    );
                    let next_attempt =
                        attempt
                            .checked_add(1)
                            .ok_or(ReconcilerError::InvalidExecutorOutput(
                                "effect retry counter exhausted",
                            ))?;
                    let refreshed = EffectLedgerRecord::from_parts((
                        plan.clone(),
                        EffectState::Applying {
                            attempt: next_attempt,
                            diagnostic: String::new(),
                        },
                        Some(fresh.clone().into_history()),
                        None,
                    ));
                    // This commit is the crash boundary: no Apply may use the
                    // fresh packet until its exact replacement is durable.
                    self.store_effect(operation_id, step, &refreshed, None, wall_seconds)?;
                    #[cfg(target_os = "linux")]
                    self.journal.retain_unissued_original_provisioning_attempt_v1(operation_id, step)?;
                    #[cfg(target_os = "linux")]
                    let applied = if self.journal.has_provisioning_scope_v1() {
                        self.executor.apply_original_provisioning_authority_v1(
                            operation_id, step, &fresh, &mut self.journal,
                        ).unwrap_or_else(|| Err(EffectFailure::Permanent(
                            "the original provisioning Storage Apply is unavailable".to_owned(),
                        )))
                    } else {
                        self.executor.apply_authority(operation_id, step, &fresh)
                    };
                    #[cfg(not(target_os = "linux"))]
                    let applied = self.executor.apply_authority(operation_id, step, &fresh);
                    match applied {
                        Ok(receipt) => {
                            let receipt = receipt.into_effect_receipt_for(&fresh)?;
                            let applied = EffectLedgerRecord::from_parts((
                                plan,
                                EffectState::Applied {
                                    attempt: next_attempt,
                                    receipt,
                                },
                                Some(fresh.into_history()),
                                None,
                            ));
                            self.store_effect(operation_id, step, &applied, None, wall_seconds)?;
                            return Ok(ReconcileOutcome::EffectApplied);
                        }
                        Err(failure) => {
                            return self.handle_failure(
                                operation_id,
                                step,
                                effect_count,
                                next_attempt,
                                plan,
                                Some(fresh),
                                failure,
                                wall_seconds,
                            );
                        }
                    }
                }
            }
        } else {
            if plan.method().is_none() && plan.public_mutation_method().is_none() {
                return self.handle_failure(
                    operation_id,
                    step,
                    effect_count,
                    attempt,
                    plan,
                    None,
                    EffectFailure::Permanent("effect has no closed dispatch method".to_owned()),
                    wall_seconds,
                );
            }
            let controller_effect = plan.public_mutation_method().is_some();
            let observed = if controller_effect {
                self.executor
                    .observe_controller(operation_id, step, &plan, &mut self.journal)
            } else {
                self.executor.observe(operation_id, step, &plan)
            };
            if controller_effect {
                self.ledger_validated = false;
                self.ensure_ledger_validated()?;
            }
            #[cfg(target_os = "linux")]
            if controller_effect && step == 0 && effect_count == 1
                && plan.public_mutation_method() == Some(PublicOperationMethodV1::CreateExecution)
                && is_closed_no_apply_prepare_v2(&self.journal, operation_id) {
                return self.require_execution_no_apply_completion_v2(operation_id);
            }
            let observed = match observed {
                Ok(value) => value,
                Err(failure) => {
                    return self.handle_failure(
                        operation_id,
                        step,
                        effect_count,
                        attempt,
                        plan,
                        None,
                        failure,
                        wall_seconds,
                    );
                }
            };
            match observed {
                EffectObservation::Applied(receipt) => receipt,
                EffectObservation::Absent => {
                    let applied = if controller_effect {
                        self.executor
                            .apply_controller(operation_id, step, &plan, &mut self.journal)
                    } else {
                        self.executor.apply(operation_id, step, &plan)
                    };
                    if controller_effect {
                        self.ledger_validated = false;
                        self.ensure_ledger_validated()?;
                    }
                    #[cfg(target_os = "linux")]
                    if controller_effect && step == 0 && effect_count == 1
                        && plan.public_mutation_method() == Some(PublicOperationMethodV1::CreateExecution)
                        && is_closed_no_apply_prepare_v2(&self.journal, operation_id) {
                        return self.require_execution_no_apply_completion_v2(operation_id);
                    }
                    match applied {
                        Ok(receipt) => receipt,
                        Err(failure) => {
                            return self.handle_failure(
                                operation_id,
                                step,
                                effect_count,
                                attempt,
                                plan,
                                None,
                                failure,
                                wall_seconds,
                            );
                        }
                    }
                }
            }
        };
        // The residual extension needs its closed protected Source/native
        // terminal transaction. Generic executor receipt DATA cannot create
        // an Applied effect that the ordinary success fold would misclassify.
        if receipt.as_bytes().starts_with(b"AOSLIF04") {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "Stop residual requires the protected residual terminal transaction",
            ));
        }
        if receipt
            .canceled_before_commit_evidence()
            .map_err(|()| {
                ReconcilerError::InvalidExecutorOutput(
                    "invalid canceled-before-commit effect receipt",
                )
            })?
            .is_some()
            && (effect_count != 1 || step != 0 || plan.public_mutation_method().is_none())
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid canceled-before-commit effect receipt",
            ));
        }
        if create_failure::has_special_receipt_data_v2(receipt.as_bytes())
            .map_err(|()| ReconcilerError::InvalidExecutorOutput("invalid failed-Create receipt"))?
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "failed-Create requires the protected three-record transaction",
            ));
        }
        let applied = EffectLedgerRecord::from_parts((
            plan,
            EffectState::Applied { attempt, receipt },
            dispatch.map(PreparedAuthorityEffectV1::into_history),
            None,
        ));
        self.store_effect(operation_id, step, &applied, None, wall_seconds)?;
        Ok(ReconcileOutcome::EffectApplied)
    }

    #[cfg(target_os = "linux")]
    fn require_execution_no_apply_completion_v2(&mut self, operation: OperationId)
        -> Result<ReconcileOutcome, ReconcilerError> {
        let Some(completed) = self.executor.take_execution_no_apply_completion_v2(operation) else {
            // Actual prepare/terminal rows are durable facts even when a
            // later native post or ACK is ambiguous. Never rewrite them as a
            // generic retry/failure or infer Root completion from those rows.
            return Ok(ReconcileOutcome::CreateFailurePending);
        };
        completed.require_current_v2(&self.journal, operation)?;
        Ok(ReconcileOutcome::FailedBeforeCommit)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_failure(
        &mut self,
        operation_id: OperationId,
        step: u32,
        effect_count: u32,
        attempt: u32,
        plan: EffectPlan,
        dispatch: Option<PreparedAuthorityEffectV1>,
        failure: EffectFailure,
        wall_seconds: Option<i64>,
    ) -> Result<ReconcileOutcome, ReconcilerError> {
        failure.validate()?;
        match failure {
            EffectFailure::Retryable(diagnostic) => {
                let next_attempt =
                    attempt
                        .checked_add(1)
                        .ok_or(ReconcilerError::InvalidExecutorOutput(
                            "effect retry counter exhausted",
                        ))?;
                let applying = EffectLedgerRecord::from_parts((
                    plan,
                    EffectState::Applying {
                        attempt: next_attempt,
                        diagnostic,
                    },
                    dispatch.map(PreparedAuthorityEffectV1::into_history),
                    None,
                ));
                self.store_effect(operation_id, step, &applying, None, wall_seconds)?;
                Ok(ReconcileOutcome::RetryPending)
            }
            EffectFailure::Permanent(diagnostic) => {
                let blocked = EffectLedgerRecord::from_parts((
                    plan,
                    EffectState::PermanentlyBlocked {
                        attempt,
                        diagnostic,
                    },
                    dispatch.map(PreparedAuthorityEffectV1::into_history),
                    None,
                ));
                self.store_effect(
                    operation_id,
                    step,
                    &blocked,
                    Some(effect_count),
                    wall_seconds,
                )?;
                Ok(ReconcileOutcome::PermanentlyBlocked)
            }
        }
    }

    fn load_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationRecord, ReconcilerError> {
        core_journal::readonly::load_operation(&self.journal, operation_id)
    }

    fn store_operation(
        &mut self,
        operation_id: OperationId,
        state: OperationState,
        effect_count: u32,
        wall_seconds: Option<i64>,
    ) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        kernel.store_operation(operation_id, state, effect_count, wall_seconds)
    }

    fn store_effect(
        &mut self,
        operation_id: OperationId,
        step: u32,
        record: &EffectLedgerRecord,
        operation_effect_count: Option<u32>,
        wall_seconds: Option<i64>,
    ) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        kernel.store_effect(operation_id, step, record, operation_effect_count, wall_seconds, false)
    }

    fn commit_records(&mut self, records: Vec<JournalRecord>) -> Result<(), ReconcilerError> {
        let mut kernel = core_journal::CoreJournalMutationV2::ordinary_v2(
            &mut self.journal, &mut self.executor, self.ledger_validated,
        );
        kernel.commit_records(records)
    }
}

pub(crate) fn recovered_public_operation_admission_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicOperationAdmissionV1>, ReconcilerError> {
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation() else {
        return Ok(None);
    };
    let authorization = journal
        .get(
            RecordNamespace::PublicOperationAuthorization,
            operation_id.as_bytes(),
        )
        .map(PublicOperationAuthorizationV1::decode)
        .transpose()?
        .ok_or(ReconcilerError::CorruptLedger(
            "public operation has no authorization scope",
        ))?;

    Ok(Some(public.into_admission(authorization)))
}

pub(crate) fn recovered_public_operation_authorization_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<PublicOperationAuthorizationV1>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    if decode_operation(operation_bytes)?
        .public_operation()
        .is_none()
    {
        return Ok(None);
    }
    journal
        .get(
            RecordNamespace::PublicOperationAuthorization,
            operation_id.as_bytes(),
        )
        .map(PublicOperationAuthorizationV1::decode)
        .transpose()
        .map_err(ReconcilerError::from)
}

pub(crate) fn recovered_public_operation_resource_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<aos_sandbox_api::aos::sandbox::v1::Operation>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation() else {
        return Ok(None);
    };
    create_failure::validate_failed_create_operation(journal, operation_id, operation)?;

    let mut applied_effects = 0_u32;
    let mut applying_effects = 0_u32;
    let mut blocked_effects = 0_u32;
    let mut canceled_effects = 0_u32;
    let mut failed_create_effects = 0_u32;
    let mut failed_repair_effects = 0_u32;
    let mut stop_residual_effects = 0_u32;
    let mut controller_method = None;
    let mut effect_records = Vec::with_capacity(operation.effect_count() as usize);
    for step in 0..operation.effect_count() {
        let bytes = journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, step))
            .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
        let effect = decode_effect(bytes).map_err(ReconcilerError::from)?;
        if operation.effect_count() == 1 {
            controller_method = effect.plan().public_mutation_method();
        }
        match effect.state() {
            EffectState::Applied { receipt, .. } => {
                increment_effect_count(&mut applied_effects)?;
                if stop_residual::classify(operation_id, effect.plan(), receipt)?.is_some() {
                    if step != 0 || operation.effect_count() != 1 {
                        return Err(ReconcilerError::CorruptLedger("residual Stop has another effect graph"));
                    }
                    increment_effect_count(&mut stop_residual_effects)?;
                }

                if operator_repair_failure::classify(receipt)? {
                    if step != 0
                        || operation.effect_count() != 1
                        || !is_operator_storage_repair_effect_v1(effect.plan())?
                    {
                        return Err(ReconcilerError::CorruptLedger(
                            "Repair failure has another method or step",
                        ));
                    }
                    increment_effect_count(&mut failed_repair_effects)?;
                }
                if receipt
                    .canceled_before_commit_evidence()
                    .map_err(|()| {
                        ReconcilerError::CorruptLedger(
                            "invalid canceled-before-commit effect receipt",
                        )
                    })?
                    .is_some()
                {
                    if operation.effect_count() != 1
                        || step != 0
                        || effect.plan().public_mutation_method().is_none()
                    {
                        return Err(ReconcilerError::CorruptLedger(
                            "invalid canceled-before-commit effect receipt",
                        ));
                    }
                    increment_effect_count(&mut canceled_effects)?;
                }
                if create_failure::has_special_receipt_data_v2(receipt.as_bytes())
                    .map_err(|()| ReconcilerError::CorruptLedger("invalid failed-Create receipt"))?
                {
                    if operation.effect_count() != 1
                        || step != 0
                        || effect.plan().public_mutation_method()
                            != Some(
                                aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateExecution,
                            )
                    {
                        return Err(ReconcilerError::CorruptLedger(
                            "invalid failed-Create receipt",
                        ));
                    }
                    increment_effect_count(&mut failed_create_effects)?;
                }
            }
            EffectState::Applying { .. } => increment_effect_count(&mut applying_effects)?,
            EffectState::PermanentlyBlocked { .. } => {
                increment_effect_count(&mut blocked_effects)?;
            }
            EffectState::Planned => {}
        }
        effect_records.push(bytes);
    }
    let state_matches_effects = match operation.state() {
        OperationState::OwnershipPending | OperationState::Accepted => {
            applied_effects == 0
                && applying_effects == 0
                && blocked_effects == 0
                && failed_create_effects == 0
        }
        OperationState::Applying => {
            applying_effects + applied_effects != 0
                && blocked_effects == 0
                && failed_create_effects == 0
        }
        OperationState::Succeeded => {
            applied_effects == operation.effect_count()
                && canceled_effects == 0
                && failed_create_effects == 0
        }
        OperationState::CommittedWithResidualCleanup => {
            operation.effect_count() == 1 && stop_residual_effects == 1
                && applied_effects == 1 && applying_effects == 0 && blocked_effects == 0
                && canceled_effects == 0 && failed_create_effects == 0 && failed_repair_effects == 0
        }
        OperationState::CanceledBeforeCommit => {
            applied_effects == operation.effect_count()
                && canceled_effects == 1
                && failed_create_effects == 0
        }
        OperationState::FailedBeforeCommit => {
            applied_effects == 1 && failed_create_effects == 1 && canceled_effects == 0
        }
        OperationState::PermanentlyBlocked => {
            failed_create_effects == 0
                && canceled_effects == 0
                && ((operation.effect_count() == 0
                        && public.recovery_kind_v1()
                            == aos_sandbox_protocol::domain_ledger::public_operation::PublicRecoveryKindV1::StopCleanup)
                    || (failed_repair_effects == 0 && blocked_effects != 0)
                    || (failed_repair_effects == 1
                        && applied_effects == 1
                        && applying_effects == 0
                        && blocked_effects == 0))
        }
    };
    if !state_matches_effects
        || (failed_repair_effects != 0 && operation.state() != OperationState::PermanentlyBlocked)
        || (stop_residual_effects != 0 && operation.state() != OperationState::CommittedWithResidualCleanup)
    {
        return Err(ReconcilerError::CorruptLedger(
            "public operation state contradicts its effects",
        ));
    }

    if failed_repair_effects == 1 {
        operator_repair_failure::validate(journal, operation_id)?;
        return Ok(Some(public.project_original_precondition_replaced(
            operation_id,
            operation_bytes,
            &effect_records,
        )));
    }

    // A failed-Create receipt occupies an Applied ledger slot for atomic
    // replacement, but it is never completed execution work.
    Ok(Some(public.project(
        operation_id,
        operation.state(),
        operation.effect_count(),
        applied_effects - failed_create_effects,
        controller_method.is_some(),
        operation.state() == OperationState::Accepted
            && controller_method.is_some_and(|method| {
                !matches!(
                    method,
                    aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation
                        | aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover
                )
            }),
        operation_bytes,
        &effect_records,
    )))
}

/// Reads one established public operation directly from protected journal state.
///
/// This read-only entry point is intended for a production effect executor that
/// already holds the controller journal through [`SingleNodeEffectExecutor`]'s
/// journal-custody hook. It grants no mutation or effect authority.
///
/// # Errors
///
/// Returns [`ReconcilerError`] when protected authority is absent or the
/// operation or any referenced effect record is corrupt.
pub fn public_operation_resource_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<aos_sandbox_api::aos::sandbox::v1::Operation>, ReconcilerError> {
    recovered_public_operation_resource_v1(journal, operation_id)
}

// Complete DATA field order retains overridden state in this consuming owner.
type EffectRecordParts = (
    EffectPlan,
    EffectState,
    Option<PreparedAuthorityEffectHistoryV1>,
    Option<
        aos_sandbox_protocol::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataV1,
    >,
);

/// Carries one retained public Repair admission into a separately proved terminal CAS.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(crate) struct PendingOperatorRepairLedgerV1 {
    operation_id: OperationId,
    operation: OperationRecord,
    effect: EffectRecordParts,
    request: crate::cli_model::OperatorRecoveryRequestV1,
    context: PublicMutationEffectHistoryV1,
}

#[allow(dead_code, reason = "public operator Repair route remains closed")]
impl PendingOperatorRepairLedgerV1 {
    pub(crate) const fn request(&self) -> &crate::cli_model::OperatorRecoveryRequestV1 {
        &self.request
    }

    pub(crate) const fn context(&self) -> &PublicMutationEffectHistoryV1 {
        &self.context
    }

    /// Prepares the exact completed Effect and Operation records.
    ///
    /// The caller retains them with the physical proof and protected successor
    /// in one transaction. The receipt has already been independently checked.
    ///
    /// # Errors
    ///
    /// Rejects an invalid completion clock, effect receipt, or durable codec.
    pub(crate) fn complete(
        self,
        receipt: EffectReceipt,
        completion_wall_seconds: i64,
    ) -> Result<[JournalRecord; 2], ReconcilerError> {
        self.complete_decision(receipt, completion_wall_seconds, OperationState::Succeeded)
    }

    /// Retains physical completion without publishing a replaced public successor.
    ///
    /// # Errors
    ///
    /// Rejects invalid receipt, clock, attempt, or durable ledger encoding.
    pub(crate) fn complete_original_precondition_replaced(
        self,
        receipt: EffectReceipt,
        completion_wall_seconds: i64,
    ) -> Result<[JournalRecord; 2], ReconcilerError> {
        self.complete_decision(receipt, completion_wall_seconds, OperationState::PermanentlyBlocked)
    }

    fn complete_decision(
        self,
        receipt: EffectReceipt,
        completion_wall_seconds: i64,
        decision: OperationState,
    ) -> Result<[JournalRecord; 2], ReconcilerError> {
        completed_effect_operation_records_v1(self.operation_id, self.operation, self.effect,
            receipt, completion_wall_seconds, decision, CompletionPurposeV1::Repair)
    }
}

impl OperationPlan {
    // Pure comparison of the exact private child after qualified native Host
    // completion. No Operation/Effect DTO supplies a completion permission.
    pub(crate) fn require_completed_start_host_child_data_v2(&self, journal: &Journal)
        -> Result<(), ReconcilerError> {
        let [expected] = self.effects.as_slice() else {
            return Err(ReconcilerError::InvalidPlan("the Start Host child lost its sole effect"));
        };
        if self.public_operation.is_some() || self.ownership_gate.is_none() || self.runtime_authority.is_none() {
            return Err(ReconcilerError::InvalidPlan("the Start Host child changed family"));
        }
        let operation = decode_operation(journal.get(RecordNamespace::Operation, self.operation_id.as_bytes())
            .ok_or(ReconcilerError::OperationNotFound)?)?;
        let (effect, q04) = decode_effect_with_q04(journal.get(RecordNamespace::Effect,
            &effect_key(self.operation_id, 0)).ok_or(ReconcilerError::CorruptLedger("Start Host child effect missing"))?)?;
        if operation.state() != OperationState::Succeeded || operation.public_operation().is_some()
            || operation.effect_count() != 1 || q04.is_some()
            || effect.plan() != expected || !matches!(effect.state(), EffectState::Applied { .. })
        { return Err(ReconcilerError::InvalidPlan("the exact Start Host child is incomplete")); }
        Ok(())
    }
}

// This shares the existing public Effect/Operation codec and state transition.
// Only the private Start native context can commit the returned DATA records.
pub(crate) fn completed_start_effect_operation_records_v2(
    journal: &Journal, plan: &OperationPlan, receipt: EffectReceipt, wall: i64,
) -> Result<[JournalRecord; 2], ReconcilerError> {
    plan.require_accepted_start_data_v1(journal)?;
    let operation_id = plan.operation_id();
    let operation = decode_operation(journal.get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::OperationNotFound)?)?;
    let effect = decode_effect(journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("Start effect is absent"))?)?;
    let [expected] = plan.effects.as_slice() else {
        return Err(ReconcilerError::InvalidPlan("Start must keep its sole admitted effect"));
    };
    if operation.state() != OperationState::Accepted || operation.effect_count() != 1
        || !matches!(effect.state(), EffectState::Planned) || effect.plan() != expected
        || operation.accepted_start_origin_v1() != plan.accepted_start_origin_data_v1()
    { return Err(ReconcilerError::InvalidPlan("the original Start terminal predecessor changed")); }
    completed_effect_operation_records_v1(operation_id, operation, effect.into_parts(), receipt,
        wall, OperationState::Succeeded, CompletionPurposeV1::Repair)
}

// Only the same accepted Stop/native terminal context appends these DATA rows.
// Generic executor receipts remain refused by the ordinary Applied fold.
pub(crate) fn completed_stop_residual_effect_operation_records_v4(
    journal: &Journal,
    operation_id: OperationId,
    expected: &PublicMutationEffectHistoryV1,
    receipt: EffectReceipt,
    wall: i64,
) -> Result<[JournalRecord; 2], ReconcilerError> {
    let context = accepted_stop_effect_from_journal_v4(journal, operation_id)?
        .ok_or(ReconcilerError::InvalidPlan("residual Stop lost its accepted context"))?;
    if &context != expected { return Err(ReconcilerError::InvalidPlan("residual Stop context changed")); }
    let operation = decode_operation(journal.get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::OperationNotFound)?)?;
    let (effect, q04) = decode_effect_with_q04(journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("residual Stop effect is absent"))?)?;
    if q04.is_some() || stop_residual::classify(operation_id, effect.plan(), &receipt)?.is_none() {
        return Err(ReconcilerError::InvalidPlan("residual Stop effect changed family"));
    }
    completed_effect_operation_records_v1(operation_id, operation, effect.into_parts(), receipt,
        wall, OperationState::CommittedWithResidualCleanup, CompletionPurposeV1::StopResidual)
}

// The native Source Stop successor and actual adjacent Inventory borrower
// supply completion provenance; this helper only constructs the same two rows.
pub(crate) fn completed_stop_success_effect_operation_records_v5(
    journal: &Journal, operation_id: OperationId,
    expected: &PublicMutationEffectHistoryV1, receipt: EffectReceipt, wall: i64,
) -> Result<[JournalRecord; 2], ReconcilerError> {
    let context = accepted_stop_effect_from_journal_v4(journal, operation_id)?
        .ok_or(ReconcilerError::InvalidPlan("Stop lost its accepted context"))?;
    if &context != expected { return Err(ReconcilerError::InvalidPlan("Stop context changed")); }
    let operation = decode_operation(journal.get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::OperationNotFound)?)?;
    let (effect, q04) = decode_effect_with_q04(journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("Stop effect is absent"))?)?;
    if q04.is_some() || !matches!(
        aos_sandbox_protocol::domain_ledger::effect_history::decode_lifecycle_effect_receipt_v1(receipt.as_bytes(), [0; 16])?,
        aos_sandbox_protocol::domain_ledger::effect_history::LifecycleEffectReceiptDataV1::Ordinary { operation, .. }
            if operation == operation_id)
    { return Err(ReconcilerError::InvalidPlan("Stop success requires ordinary terminal receipt")); }
    completed_effect_operation_records_v1(operation_id, operation, effect.into_parts(), receipt,
        wall, OperationState::Succeeded, CompletionPurposeV1::StopSuccess)
}

/// Selects only the existing Repair and private inert-child completion recipes.
#[derive(Clone, Copy)]
enum CompletionPurposeV1<'evidence> {
    Repair,
    StopResidual,
    StopSuccess,
    ReservedObserve(&'evidence aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1),
}

// Only the original Delete finalizer can append these comparison DATA rows.
// The ordinary executor still cannot turn a supplied receipt into Delete IO.
pub(crate) fn completed_delete_effect_operation_records_v4(
    journal: &Journal,
    plan: &OperationPlan,
    receipt: EffectReceipt,
    wall: i64,
) -> Result<[JournalRecord; 2], ReconcilerError> {
    let operation_id = plan.operation_id();
    let operation = decode_operation(journal.get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::OperationNotFound)?)?;
    let effect = decode_effect(journal.get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("Delete effect is absent"))?)?;
    let [expected] = plan.effects.as_slice() else {
        return Err(ReconcilerError::InvalidPlan("Delete must keep its sole admitted effect"));
    };
    if operation.state() != OperationState::Accepted || operation.effect_count() != 1
        || !matches!(effect.state(), EffectState::Planned) || effect.plan() != expected
        || expected.public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::DeleteSandbox)
        || operation.public_operation()
            != plan.public_operation.as_ref().map(PublicOperationAdmissionV1::durable)
        || !matches!(journal.check_idempotency(&plan.idempotency_key, plan.request_digest()),
            IdempotencyOutcome::Replay(actual) if actual == operation_id)
    {
        return Err(ReconcilerError::InvalidPlan("the original Delete terminal predecessor changed"));
    }
    completed_effect_operation_records_v1(operation_id, operation, effect.into_parts(), receipt,
        wall, OperationState::Succeeded, CompletionPurposeV1::Repair)
}

// One exact Effect/Operation encoding recipe; the caller alone retains the
// genuine writer/payer and commits these two DATA records atomically.
fn completed_effect_operation_records_v1(
    operation_id: OperationId, operation: OperationRecord, effect: EffectRecordParts,
    receipt: EffectReceipt, completion_wall_seconds: i64, decision: OperationState,
    purpose: CompletionPurposeV1<'_>,
) -> Result<[JournalRecord; 2], ReconcilerError> {
    let attempt = match &effect.1 {
        EffectState::Planned => 1,
        EffectState::Applying { attempt, .. } => *attempt,
        _ => {
            return Err(ReconcilerError::InvalidPlan(
                "Repair effect is already terminal",
            ));
        }
    };
    let state = EffectState::Applied { attempt, receipt };
    let record = EffectLedgerRecord::from_parts((effect.0, state, effect.2, effect.3));
    let effect = match purpose {
        CompletionPurposeV1::Repair | CompletionPurposeV1::StopResidual | CompletionPurposeV1::StopSuccess => encode_effect(&record),
        CompletionPurposeV1::ReservedObserve(completion) =>
            aos_sandbox_protocol::domain_ledger::effect_history::observe_completion::encode_completed_observe_effect_v1(&record, completion),
    }.map_err(ReconcilerError::from)?;
    decode_effect(&effect).map_err(ReconcilerError::from)?;
    let operation = match purpose {
        CompletionPurposeV1::Repair | CompletionPurposeV1::StopResidual | CompletionPurposeV1::StopSuccess => {
            if matches!(purpose, CompletionPurposeV1::StopResidual)
                && decision != OperationState::CommittedWithResidualCleanup
            { return Err(ReconcilerError::InvalidPlan("residual Stop cannot become ordinary success")); }
            if matches!(purpose, CompletionPurposeV1::StopSuccess) && decision != OperationState::Succeeded {
                return Err(ReconcilerError::InvalidPlan("healthy Stop requires ordinary success"));
            }
            let public = operation.public_operation().ok_or(ReconcilerError::InvalidPlan(
                "Repair operation is not public"))?.advance(decision, completion_wall_seconds)?;
            encode_operation_record(operation.with_state_and_public_operation(decision, Some(public)))
        }
        CompletionPurposeV1::ReservedObserve(_) => {
            if operation.public_operation().is_some() || decision != OperationState::Succeeded {
                return Err(ReconcilerError::InvalidPlan("reserved Observe cannot become public"));
            }
            encode_operation_record(operation.with_state_and_public_operation(decision, None))
        }
    };
    decode_operation(&operation)?;
    Ok([
        JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(operation_id, 0).to_vec(),
            effect,
        ),
        JournalRecord::put(
            RecordNamespace::Operation,
            operation_id.as_bytes().to_vec(),
            operation,
        ),
    ])
}

/// Loads the exact pending public Repair operation and its authenticated effect.
///
/// # Errors
///
/// Rejects absent, terminal, corrupt, or mismatched Operation, Effect,
/// authorization, and idempotency rows.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(crate) fn pending_operator_repair_ledger_v1(
    journal: &Journal,
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    request_digest: [u8; 32],
) -> Result<PendingOperatorRepairLedgerV1, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let operation_bytes = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::OperationNotFound)?;
    let operation = decode_operation(operation_bytes)?;
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger("Repair effect is absent"))?;
    let effect = decode_effect(effect_bytes).map_err(ReconcilerError::from)?;
    recovered_public_operation_resource_v1(journal, operation_id)?.ok_or(
        ReconcilerError::CorruptLedger("Repair public operation is absent"),
    )?;
    pending_operator_repair_from_exact_rows_v1(
        journal,
        operation_id,
        sandbox_id,
        request_digest,
        operation,
        effect,
    )
}

fn pending_operator_repair_from_exact_rows_v1(
    journal: &Journal,
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    request_digest: [u8; 32],
    operation: OperationRecord,
    effect: EffectLedgerRecord,
) -> Result<PendingOperatorRepairLedgerV1, ReconcilerError> {
    use aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryAction;
    use aos_sandbox_model::{ResourceKind, Selector};

    let context = effect
        .plan()
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
        .ok_or(ReconcilerError::CorruptLedger(
            "Repair effect has no admission context",
        ))?;
    let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::OperatorRecover(
        request,
    ) = context.validated_request().map_err(ReconcilerError::from)?
    else {
        return Err(ReconcilerError::CorruptLedger(
            "Repair effect names another method",
        ));
    };
    let request = crate::cli_model::OperatorRecoveryRequestV1::try_from(request)
        .map_err(|_| ReconcilerError::CorruptLedger("invalid public Repair request"))?;
    let public = recovered_public_operation_admission_v1(journal, operation_id)?.ok_or(
        ReconcilerError::CorruptLedger("Repair has no public operation"),
    )?;
    let selector_matches = matches!(
        public.authorization().selector(),
        Selector::Resource { resource } if resource.as_bytes() == &sandbox_id
    );
    let idempotency =
        IdempotencyKey::new(request.idempotency_key().to_vec()).map_err(JournalError::from)?;
    if operation_id.as_bytes() == &[0; 16]
        || sandbox_id == [0; 16]
        || request_digest == [0; 32]
        || !matches!(
            operation.state(),
            OperationState::Accepted | OperationState::Applying
        )
        || operation.effect_count() != 1
        || operation.ownership_gated()
        || operation.runtime_intent_digest().is_some()
        || !matches!(
            effect.state(),
            EffectState::Planned | EffectState::Applying { .. }
        )
        || effect.plan().public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover)
        || request.action() != OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        || request.resource_id() != sandbox_id
        || public.method()
            != aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover
        || public.authorization().resource_kind() != ResourceKind::Sandbox
        || !selector_matches
        || public.project() != context.project()
        || public.accepted_wall_seconds() != context.accepted_wall_seconds()
        || journal.check_idempotency(&idempotency, request_digest)
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(ReconcilerError::InvalidPlan(
            "pending public Repair ledger disagrees",
        ));
    }
    Ok(PendingOperatorRepairLedgerV1 {
        operation_id,
        operation,
        effect: effect.into_parts(),
        request,
        context,
    })
}

/// Verifies exact terminal public rows against the checked archived predecessor.
pub(crate) fn verify_operator_repair_terminal_public_rows_v2(
    journal: &Journal,
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    request_digest: [u8; 32],
    predecessor_operation: &[u8],
    predecessor_effect: &[u8],
    receipt: &[u8],
    completion_wall_seconds: i64,
) -> Result<(), ReconcilerError> {
    journal.ensure_protected_authority()?;
    let pending = pending_operator_repair_from_exact_rows_v1(
        journal,
        operation_id,
        sandbox_id,
        request_digest,
        decode_operation(predecessor_operation)?,
        decode_effect(predecessor_effect).map_err(ReconcilerError::from)?,
    )?;
    let terminal = pending.complete(
        EffectReceipt::new(receipt.to_vec()).map_err(ReconcilerError::from)?,
        completion_wall_seconds,
    )?;
    if !terminal
        .iter()
        .all(|record| journal.get(record.namespace(), record.key()) == record.value())
    {
        return Err(ReconcilerError::CorruptLedger(
            "Repair terminal public rows disagree with exact predecessor",
        ));
    }
    Ok(())
}

/// Regenerates only the original Repair's truthful failure decision rows.
///
/// Archived predecessor bytes retain their original admission and attempt;
/// this method neither rebases a resource nor accepts generic failure evidence.
///
/// # Errors
///
/// Rejects inconsistent original authorization, idempotency, receipt, or clock.
#[allow(clippy::too_many_arguments)]
pub(crate) fn operator_repair_failure_terminal_rows_v1(
    journal: &Journal,
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    request_digest: [u8; 32],
    predecessor_operation: &[u8],
    predecessor_effect: &[u8],
    receipt: &[u8],
    completion_wall_seconds: i64,
) -> Result<[JournalRecord; 2], ReconcilerError> {
    journal.ensure_protected_authority()?;
    let failure = RepairPreconditionFailureReceiptV1::decode(receipt)
        .map_err(|()| ReconcilerError::CorruptLedger("invalid Repair failure decision"))?;
    if failure.operation() != operation_id {
        return Err(ReconcilerError::CorruptLedger(
            "Repair failure names another operation",
        ));
    }
    pending_operator_repair_from_exact_rows_v1(
        journal,
        operation_id,
        sandbox_id,
        request_digest,
        decode_operation(predecessor_operation)?,
        decode_effect(predecessor_effect).map_err(ReconcilerError::from)?,
    )?
    .complete_original_precondition_replaced(
        EffectReceipt::new(receipt.to_vec()).map_err(ReconcilerError::from)?,
        completion_wall_seconds,
    )
}

/// Joins archived original rows to the real authorization and idempotency owner.
///
/// # Errors
///
/// Rejects terminal predecessors or substituted original request custody.
pub(crate) fn operator_repair_original_ledger_v1(
    journal: &Journal,
    operation_id: OperationId,
    sandbox_id: [u8; 16],
    request_digest: [u8; 32],
    predecessor_operation: &[u8],
    predecessor_effect: &[u8],
) -> Result<PendingOperatorRepairLedgerV1, ReconcilerError> {
    pending_operator_repair_from_exact_rows_v1(
        journal,
        operation_id,
        sandbox_id,
        request_digest,
        decode_operation(predecessor_operation)?,
        decode_effect(predecessor_effect).map_err(ReconcilerError::from)?,
    )
}


// Root's final same-native Controller/Session comparison uses this sole
// historical receipt checker; no effect module or parser is exposed.
pub(crate) fn validate_durable_receipt_history_v1(
    prepared: &PreparedAuthorityEffectHistoryV1, receipt: &[u8],
) -> Result<(), ReconcilerError> {
    effect::validate_durable_receipt_history(prepared, receipt)
}

/// Reads the validated publication digest of one activated ownership gate.
///
/// The caller already holds the reconciler's journal through its executor
/// hook. A pending or ungated operation returns `None`; an activated gate is
/// not evidence until its immutable publication has been checked against the
/// exact admitted draft and lease artifacts.
///
/// # Errors
///
/// Returns [`ReconcilerError`] for absent protected authority, inconsistent
/// operation/gate state, or corrupt publication evidence.
pub fn activated_ownership_gate_digest_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<ObjectDigest>, ReconcilerError> {
    match validated_ownership_gate_from_journal_v1(journal, operation_id)? {
        Some(OwnershipGateStatusV1::Activated {
            publication_digest, ..
        }) => Ok(Some(publication_digest)),
        Some(OwnershipGateStatusV1::Pending(_)) | None => Ok(None),
    }
}

pub(crate) fn validated_ownership_gate_from_journal_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
    journal.ensure_protected_authority()?;
    let operation = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .map(decode_operation)
        .transpose()?;
    let gate = journal
        .get(RecordNamespace::OwnershipGate, operation_id.as_bytes())
        .map(|bytes| decode_ownership_gate(bytes).map_err(ReconcilerError::from))
        .transpose()?;
    let (operation, gate) = match (operation, gate) {
        (None, None) => {
            return Ok(None);
        }
        (Some(operation), None) if !operation.ownership_gated() => {
            return Ok(None);
        }
        (Some(operation), Some(gate)) => (operation, gate),
        _ => {
            return Err(ReconcilerError::CorruptLedger(
                "ownership gate does not match its operation",
            ));
        }
    };
    let plan = match &gate {
        OwnershipGateStatusV1::Pending(plan) | OwnershipGateStatusV1::Activated { plan, .. } => {
            plan
        }
    };
    if !operation.ownership_gated()
        || plan.operation_id() != operation_id
        || journal.check_idempotency(plan.idempotency_key(), plan.request_digest())
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(ReconcilerError::CorruptLedger(
            "ownership gate does not match its operation",
        ));
    }
    match &gate {
        OwnershipGateStatusV1::Pending(_)
            if operation.state() == OperationState::OwnershipPending =>
        {
            Ok(Some(gate))
        }
        OwnershipGateStatusV1::Activated {
            plan,
            publication_digest,
            lease_generation,
            lease_digest,
        } if matches!(
            operation.state(),
            OperationState::Accepted
                | OperationState::Applying
                | OperationState::Succeeded
                | OperationState::PermanentlyBlocked
                | OperationState::FailedBeforeCommit
        ) =>
        {
            validate_durable_gate_publication(
                journal,
                *publication_digest,
                plan.publication_draft(),
                plan.claim(),
                *lease_generation,
                *lease_digest,
            )
            .map_err(|_| {
                ReconcilerError::CorruptLedger("activated ownership publication is corrupt")
            })?;
            Ok(Some(gate))
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "ownership gate state does not match its operation",
        )),
    }
}

pub(crate) fn transition_operation(
    operation: OperationRecord,
    state: OperationState,
    wall_seconds: Option<i64>,
) -> Result<OperationRecord, ReconcilerError> {
    let public_operation = operation
        .public_operation()
        .map(|public| {
            let wall_seconds = wall_seconds.ok_or(ReconcilerError::PublicOperationClock)?;
            public.advance(state, wall_seconds).map_err(ReconcilerError::from)
        })
        .transpose()?;

    Ok(operation.with_state_and_public_operation(state, public_operation))
}

fn increment_effect_count(count: &mut u32) -> Result<(), ReconcilerError> {
    *count = count
        .checked_add(1)
        .ok_or(ReconcilerError::CorruptLedger("effect count overflow"))?;
    Ok(())
}

fn is_operator_storage_repair_effect_v1(plan: &EffectPlan) -> Result<bool, ReconcilerError> {
    if plan.public_mutation_method()
        != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover)
    {
        return Ok(false);
    }
    let Some(context) = plan
        .public_mutation_context()
        .map_err(ReconcilerError::from)?
    else {
        return Ok(false);
    };
    let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::OperatorRecover(
        request,
    ) = context.validated_request().map_err(ReconcilerError::from)?
    else {
        return Err(ReconcilerError::InvalidPlan(
            "Recover effect has another public request",
        ));
    };
    let request = crate::cli_model::OperatorRecoveryRequestV1::try_from(request)
        .map_err(|_| ReconcilerError::InvalidPlan("Recover effect request is invalid"))?;
    Ok(request.action()
        == aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR
            as i32)
}

fn has_operator_repair_settlement_debt_v1(
    journal: &Journal,
    operation: OperationId,
) -> Result<bool, ReconcilerError> {
    let Some(effect) = journal.get(RecordNamespace::Effect, &effect_key(operation, 0)) else {
        return Ok(false);
    };
    if !is_operator_storage_repair_effect_v1(
        decode_effect(effect).map_err(ReconcilerError::from)?.plan(),
    )? {
        return Ok(false);
    }
    let mut has_hold = false;
    for epoch in 0..4_u8 {
        let hold = [
            b"storage-repair-progress-v1/".as_slice(),
            operation.as_bytes(),
            &[8 + 3 * epoch],
        ]
        .concat();
        has_hold |= journal
            .get(RecordNamespace::OperatorRecovery, &hold)
            .is_some();
    }
    if !has_hold {
        return Ok(false);
    }

    #[cfg(target_os = "linux")]
    return crate::controller::has_operator_storage_repair_settlement_debt_v1(journal, operation)
        .map_err(|_| ReconcilerError::CorruptLedger("invalid Repair owner settlement custody"));

    #[cfg(not(target_os = "linux"))]
    Err(ReconcilerError::CorruptLedger(
        "Repair owner settlement requires Linux custody",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    fn encode_operation(
        state: OperationState,
        effect_count: u32,
        ownership_gated: bool,
        runtime_intent_digest: Option<ObjectDigest>,
    ) -> Vec<u8> {
        encode_operation_record(OperationRecord::new(
            state,
            effect_count,
            ownership_gated,
            runtime_intent_digest,
            None,
        ))
    }

    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::PathBuf;

    use aos_sandbox_api::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, BrokerMethod, RuntimeObservation, RuntimeState,
    };
    use aos_sandbox_model::{
        LeaseAssignment, NodeId, PrincipalId, ProjectId, RawClockProvenance, RawPairedClockSample,
        ResourceId, ResourceKind, Selector,
    };
    use buffa::Message as _;

    use super::*;
    use aos_sandbox_protocol::domain_ledger::effect_history::BrokerDispatchAttemptHistoryV1;
    use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
    use crate::journal::JournalLimits;
    use crate::publication::tests::{
        activation_claim, alternate_descriptor_free_activation_fixture,
        descriptor_free_activation_fixture, descriptor_free_launch_activation_fixture,
        descriptor_free_mount_activation_fixture, descriptor_host_activation_fixture,
        signed_guardian_plan,
    };
    use crate::publication::{
        AuthorityPublicationDraftV1, AuthorityPublicationError, AuthorityPublicationStore,
    };

    #[test]
    fn closed_recover_pending_never_enters_generic_effect_or_terminal_loop() {
        use aos_sandbox_protocol::domain_ledger::public_operation::{
            DurablePublicOperationV1, PublicRecoveryKindV1,
        };
        for kind in [
            PublicRecoveryKindV1::MetadataComplete,
            PublicRecoveryKindV1::StopCleanup,
            PublicRecoveryKindV1::ExecutionNoApply,
        ] {
            let directory = TestDirectory::new();
            let (mut journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let operation_id = OperationId::from_bytes([0xde; 16]);
            let metadata = match kind {
                PublicRecoveryKindV1::MetadataComplete => {
                    DurablePublicOperationV1::metadata_complete_initial_v1(
                        *operation_id.as_bytes(),
                        100,
                    )
                }
                PublicRecoveryKindV1::StopCleanup => {
                    DurablePublicOperationV1::stop_cleanup_initial_v1(*operation_id.as_bytes(), 100)
                }
                PublicRecoveryKindV1::ExecutionNoApply => {
                    DurablePublicOperationV1::execution_no_apply_initial_v1(
                        *operation_id.as_bytes(),
                        100,
                    )
                }
                PublicRecoveryKindV1::Ordinary => unreachable!(),
            }
            .unwrap();
            let pending =
                OperationRecord::new(OperationState::Accepted, 0, false, None, Some(metadata));
            let encoded = encode_operation_record(pending);
            journal
                .commit(
                    &JournalTransaction::new(
                        [0xdf; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            operation_id.as_bytes().to_vec(),
                            encoded.clone(),
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());

            for wall in [101, 102] {
                assert_eq!(
                    reconciler.reconcile_once_at(operation_id, wall).unwrap(),
                    ReconcileOutcome::RetryPending
                );
                assert_eq!(
                    reconciler
                        .journal
                        .get(RecordNamespace::Operation, operation_id.as_bytes()),
                    Some(encoded.as_slice())
                );
            }
            assert_eq!(reconciler.executor.observe_calls, 0);
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn effect_failure_error_borrows_original_classification_and_diagnostic() {
        for failure in [
            EffectFailure::Retryable("original retryable diagnostic".to_owned()),
            EffectFailure::Permanent("original permanent diagnostic".to_owned()),
        ] {
            let error: &(dyn std::error::Error + 'static) = &failure;

            assert_eq!(error.to_string(), failure.diagnostic());
            assert!(std::ptr::eq(
                error.downcast_ref::<EffectFailure>().unwrap(),
                &failure,
            ));
            assert!(error.source().is_none());
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-reconciler-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("state.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    pub(super) struct Executor {
        applied: BTreeMap<(OperationId, u32), EffectReceipt>,
        failures: VecDeque<EffectFailure>,
        apply_calls: usize,
        observe_calls: usize,
        timing_calls: usize,
        authority_pending: bool,
        authority_receipt_override: Option<ValidatedHostEffectReceiptV1>,
        guardian_plan_requests: Vec<GuardianPlanRequestV1>,
        guardian_plan_override: Option<SignedBrokerPlan>,
        host_boot_id: Option<[u8; 16]>,
    }

    fn host_receipt_bytes(prepared: &PreparedAuthorityEffectV1) -> Vec<u8> {
        let request = ApplyRuntimeRequest::decode_from_slice(prepared.attempt().body()).unwrap();
        let fence = request.fence.as_option().unwrap();
        let incarnation: [u8; 16] = fence.incarnation_id.as_slice().try_into().unwrap();
        let assignment_digest: [u8; 32] = fence.assignment_digest.as_slice().try_into().unwrap();
        let observation = RuntimeObservation {
            runtime_handle: aos_sandbox_protocol::semantics::host::runtime_handle_v1(
                &incarnation,
                fence.assignment_epoch,
                &assignment_digest,
            )
            .to_vec(),
            state: RuntimeState::RUNTIME_STATE_READY.into(),
            observation_sequence: 1,
            fence: Some(fence.clone()).into(),
            ..Default::default()
        };
        observation.encode_to_vec()
    }

    fn host_receipt(prepared: &PreparedAuthorityEffectV1) -> ValidatedHostEffectReceiptV1 {
        prepared
            .validate_host_receipt(host_receipt_bytes(prepared))
            .unwrap()
    }

    impl SingleNodeEffectExecutor for Executor {
        fn authority_effect_timing(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
        ) -> Option<AuthorityEffectAttemptTimingV1> {
            self.timing_calls += 1;
            let provenance = RawClockProvenance::new_untrusted([0x91; 16]).unwrap();
            let clock = RawPairedClockSample::new_untrusted(
                provenance,
                self.host_boot_id.unwrap_or([0x92; 16]),
                150,
                1_000,
            )
            .unwrap();
            Some(AuthorityEffectAttemptTimingV1::new(clock, 2_000))
        }

        fn prepare_guardian_plan(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            request: &GuardianPlanRequestV1,
        ) -> Option<SignedBrokerPlan> {
            self.guardian_plan_requests.push(request.clone());
            self.guardian_plan_override
                .clone()
                .or_else(|| Some(signed_guardian_plan(request)))
        }

        fn observe(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            self.observe_calls += 1;
            Ok(self
                .applied
                .get(&(operation_id, step))
                .cloned()
                .map_or(EffectObservation::Absent, EffectObservation::Applied))
        }

        fn apply(
            &mut self,
            operation_id: OperationId,
            step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            self.apply_calls += 1;
            if let Some(failure) = self.failures.pop_front() {
                return Err(failure);
            }
            let receipt = EffectReceipt::new(vec![step as u8 + 1]).unwrap();
            self.applied.insert((operation_id, step), receipt.clone());
            Ok(receipt)
        }

        fn observe_authority(
            &mut self,
            operation_id: OperationId,
            step: u32,
            prepared: &PreparedAuthorityEffectV1,
        ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
            self.observe_calls += 1;
            Ok(if self.authority_pending {
                AuthorityEffectObservationV1::Pending
            } else if self.applied.contains_key(&(operation_id, step)) {
                AuthorityEffectObservationV1::Applied(
                    self.authority_receipt_override
                        .take()
                        .unwrap_or_else(|| host_receipt(prepared)),
                )
            } else {
                AuthorityEffectObservationV1::Absent
            })
        }

        fn apply_authority(
            &mut self,
            operation_id: OperationId,
            step: u32,
            prepared: &PreparedAuthorityEffectV1,
        ) -> Result<ValidatedHostEffectReceiptV1, EffectFailure> {
            self.apply_calls += 1;
            if let Some(failure) = self.failures.pop_front() {
                return Err(failure);
            }
            let receipt = EffectReceipt::new(vec![step as u8 + 1]).unwrap();
            self.applied.insert((operation_id, step), receipt);
            Ok(self
                .authority_receipt_override
                .take()
                .unwrap_or_else(|| host_receipt(prepared)))
        }
    }

    struct CanceledControllerExecutor;

    impl SingleNodeEffectExecutor for CanceledControllerExecutor {
        fn observe(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            Err(EffectFailure::Permanent(
                "controller effect used the broker hook".to_owned(),
            ))
        }

        fn apply(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            Err(EffectFailure::Permanent(
                "controller effect used the broker hook".to_owned(),
            ))
        }

        fn observe_controller(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
            _journal: &mut Journal,
        ) -> Result<EffectObservation, EffectFailure> {
            Ok(EffectObservation::Absent)
        }

        fn apply_controller(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
            _journal: &mut Journal,
        ) -> Result<EffectReceipt, EffectFailure> {
            Ok(EffectReceipt::canceled_before_commit(
                ObjectDigest::from_bytes([0xc7; 32]),
            ))
        }
    }

    fn operation() -> OperationPlan {
        OperationPlan::new(
            OperationId::from_bytes([0x44; 16]),
            IdempotencyKey::new(b"request".to_vec()).unwrap(),
            [0x55; 32],
            b"sandbox".to_vec(),
            b"running".to_vec(),
            vec![
                EffectPlan::new(
                    EffectDomain::Storage,
                    BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                    b"create".to_vec(),
                )
                .unwrap(),
                EffectPlan::new(
                    EffectDomain::Host,
                    BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                    b"start".to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn generic_executor_cannot_publish_stop_residual_receipt_data() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        let operation_id = plan.operation_id();
        reconciler.accept(&plan).unwrap();
        reconciler.reconcile_once(operation_id).unwrap();

        // Even a selected version prefix cannot enter generic success. Its
        // actual receipt validation and native terminal owner belong to the
        // distinct closed transaction, never to this supplied DATA.
        reconciler.executor.applied.insert(
            (operation_id, 0), EffectReceipt::new(b"AOSLIF04".to_vec()).unwrap(),
        );
        let returned = reconciler.reconcile_once(operation_id);

        assert!(matches!(returned, Err(ReconcilerError::InvalidExecutorOutput(_))));
        let effect = decode_effect(reconciler.journal.get(
            RecordNamespace::Effect, &effect_key(operation_id, 0),
        ).unwrap()).unwrap();
        assert!(!matches!(effect.state(), EffectState::Applied { .. }));
        assert_eq!(reconciler.load_operation(operation_id).unwrap().state(), OperationState::Applying);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    fn public_operation_authorization() -> PublicOperationAuthorizationV1 {
        PublicOperationAuthorizationV1::new(
            ProjectId::from_bytes([0x91; 16]),
            ResourceKind::Sandbox,
            Selector::Resource {
                resource: ResourceId::from_bytes([0x92; 16]),
            },
        )
        .unwrap()
    }

    fn cancelable_controller_operation() -> OperationPlan {
        use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
        use aos_sandbox_api::aos::sandbox::v1::{MutationContext, SandboxLifecycleRequest};

        let request = SandboxLifecycleRequest {
            sandbox_id: vec![0x92; 16],
            mutation: Some(MutationContext {
                idempotency_key: b"cancelable-controller-operation".to_vec(),
                expected_resource_version: vec![0x94],
                operation_timeout: Some(aos_sandbox_api::aos::sandbox::v1::Duration {
                    nanoseconds: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let envelope = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::StartSandbox,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        let effect = {
            let selected_method = PublicOperationMethodV1::StartSandbox;
            (PublicMutationEffectV1::new(
                PrincipalId::from_bytes([0x93; 16]),
                ProjectId::from_bytes([0x91; 16]),
                100,
                envelope,
            )
            .unwrap())
            .into_plan(selected_method)
        }
        .unwrap();

        OperationPlan::new(
            OperationId::from_bytes([0xc1; 16]),
            IdempotencyKey::new(b"cancelable-controller-operation".to_vec()).unwrap(),
            [0xc2; 32],
            b"controller-operation".to_vec(),
            b"accepted".to_vec(),
            vec![effect],
        )
        .unwrap()
        .with_public_operation(
            PublicOperationAdmissionV1::new(
                PublicOperationMethodV1::StartSandbox,
                7,
                [0xc3; 16],
                100,
                public_operation_authorization(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn failed_create_fixture() -> (
        OperationPlan,
        aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV1,
    ) {
        use aos_sandbox_api::aos::sandbox::v1::{
            Command, CreateExecutionRequest, Duration, Execution, ExecutionIoMode, ExecutionPhase,
            MutationContext, Timestamp,
        };
        use aos_sandbox_protocol::host_execution_no_apply::{
            HostExecutionNoApplyRecordFieldsV1, HostExecutionNoApplyRecordV1,
        };

        use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
        use aos_sandbox_protocol::public_api::{
            EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1, EXECUTION_STREAM_FEATURE_V1,
            EXECUTION_TIMEOUT_FEATURE_V1, PublicOperationMethodV1, semantic_feature_v1,
        };
        use aos_sandbox_protocol::public_api::projection::{
            PublicProjectionPlanV1, PublicProjectionResourceV1,
        };

        let project = ProjectId::from_bytes([0x91; 16]);
        let operation_id = OperationId::from_bytes([0xd1; 16]);
        let execution_id = [0xd2; 16];
        let sandbox_id = vec![0xd3; 16];
        let incarnation_id = vec![0xd4; 16];
        let mut required_features = [
            EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1,
            EXECUTION_STREAM_FEATURE_V1,
            EXECUTION_TIMEOUT_FEATURE_V1,
        ]
        .into_iter()
        .map(|name| semantic_feature_v1(name).unwrap())
        .collect::<Vec<_>>();
        required_features.sort_by(|left, right| left.namespace.cmp(&right.namespace));
        let command = Command {
            arguments: vec![b"true".to_vec()],
            execution_timeout: Duration {
                nanoseconds: 1,
                ..Default::default()
            }
            .into(),
            io_mode: ExecutionIoMode::EXECUTION_IO_MODE_STREAM.into(),
            stream_features: vec![semantic_feature_v1(EXECUTION_STREAM_FEATURE_V1).unwrap()],
            ..Default::default()
        };
        let request = CreateExecutionRequest {
            sandbox_id: sandbox_id.clone(),
            command: Some(command.clone()).into(),
            client_public_key: vec![0xa1; 32],
            proof_of_possession: vec![0xa2; 64],
            mutation: MutationContext {
                idempotency_key: b"failed-create-fixture".to_vec(),
                expected_resource_version: vec![0xa3],
                expected_incarnation_id: incarnation_id.clone(),
                operation_timeout: Duration {
                    nanoseconds: 1,
                    ..Default::default()
                }
                .into(),
                required_features,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let envelope = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::CreateExecution,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        let effect = {
            let selected_method = PublicOperationMethodV1::CreateExecution;
            (PublicMutationEffectV1::new(
                PrincipalId::from_bytes([0x93; 16]),
                project,
                100,
                envelope,
            )
            .unwrap())
            .into_plan(selected_method)
        }
        .unwrap();
        let execution = Execution {
            execution_id: execution_id.to_vec(),
            sandbox_id,
            sandbox_incarnation_id: incarnation_id,
            resource_version: vec![0xa4],
            command: Some(command).into(),
            phase: ExecutionPhase::EXECUTION_PHASE_REQUESTED.into(),
            audit_id: operation_id.into_bytes().to_vec(),
            desired_generation: 1,
            observation_sequence: 1,
            assignment_epoch: 1,
            last_successful_reconciliation_time: Timestamp {
                seconds: 100,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let (desired_key, desired_value) = PublicProjectionPlanV1::new(
            project,
            operation_id,
            PublicProjectionResourceV1::Execution(execution),
        )
        .unwrap()
        .into_desired_state();
        let plan = OperationPlan::new(
            operation_id,
            IdempotencyKey::new(b"failed-create-fixture".to_vec()).unwrap(),
            [0xa5; 32],
            desired_key,
            desired_value,
            vec![effect],
        )
        .unwrap()
        .with_public_operation(
            PublicOperationAdmissionV1::new(
                PublicOperationMethodV1::CreateExecution,
                1,
                [0xa6; 16],
                100,
                PublicOperationAuthorizationV1::new(
                    project,
                    ResourceKind::Execution,
                    Selector::Resource {
                        resource: ResourceId::from_bytes(execution_id),
                    },
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let marker = HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
            execution_id,
            create_operation_id: operation_id.into_bytes(),
            original_request_id: [0xb1; 16],
            terminal_request_id: [0xb2; 16],
            host_boot_id: [0xb3; 16],
            assignment_digest: [0xb4; 32],
            source_record_digest: [0xb5; 32],
            original_session_binding: [0xb6; 32],
            original_signed_request_digest: [0xb7; 32],
            terminal_session_binding: [0xb8; 32],
            terminal_signed_request_digest: [0xb9; 32],
            runtime_handle: [0xba; 32],
            execution_store_binding: [0xbb; 32],
            commit_sequence: 1,
        })
        .unwrap();
        (plan, marker)
    }

    fn gated_operation_with_publication(
        lease_generation: u64,
    ) -> (
        OperationPlan,
        AuthorityPublicationDraftV1,
        crate::publication::PreparedAuthorityPublicationV1,
    ) {
        let (draft, prepared) = descriptor_free_activation_fixture(lease_generation);
        let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
            &draft,
            draft.templates()[0].digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)
        .unwrap();
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x31; 16]),
            IdempotencyKey::new(b"gated-request".to_vec()).unwrap(),
            [0x32; 32],
            b"gated-sandbox".to_vec(),
            b"pending-ownership".to_vec(),
            vec![effect],
            activation_claim(&draft, lease_generation),
            draft.clone(),
        )
        .unwrap();
        (plan, draft, prepared)
    }

    fn gated_operation() -> OperationPlan {
        gated_operation_with_publication(1).0
    }

    fn gated_launch_operation_with_publication(
        lease_generation: u64,
    ) -> (
        OperationPlan,
        AuthorityPublicationDraftV1,
        crate::publication::PreparedAuthorityPublicationV1,
    ) {
        let (draft, prepared) = descriptor_free_launch_activation_fixture(lease_generation);
        let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
            &draft,
            draft.templates()[0].digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)
        .unwrap();
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x35; 16]),
            IdempotencyKey::new(b"guardian-gated-launch".to_vec()).unwrap(),
            [0x36; 32],
            b"guardian-gated-sandbox".to_vec(),
            b"pending-launch".to_vec(),
            vec![effect],
            activation_claim(&draft, lease_generation),
            draft.clone(),
        )
        .unwrap();
        (plan, draft, prepared)
    }

    fn gate_activation(
        reconciler: &mut Reconciler<Executor>,
        draft: &AuthorityPublicationDraftV1,
        prepared: &crate::publication::PreparedAuthorityPublicationV1,
    ) -> AuthorityPublicationActivationV1 {
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .prepare_gate_activation(draft, prepared)
            .unwrap()
    }

    fn protected_runtime_journal(directory: &TestDirectory) -> Journal {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            &directory.0,
            "state.journal",
            JournalLimits::default(),
            fs::metadata(&directory.0).unwrap().uid(),
        )
        .unwrap()
        .0
    }

    pub(super) fn live_create_sandbox_plan(descriptor_byte: u8) -> OperationPlan {
        use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
        use crate::controller::ControllerRequestScopeV1;
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
        use aos_sandbox_api::aos::sandbox::v1::{CreateSandboxRequest, Duration, ObjectDescriptor};

        let project = ProjectId::from_bytes([0x91; 16]);
        let operation_id = OperationId::from_bytes([0xc1; 16]);
        let key = b"live-create-sandbox".to_vec();
        let specification = ObjectDescriptor {
            media_type: "application/vnd.aos.sandbox.spec.v1+cbor".to_owned(),
            sha256: vec![descriptor_byte; 32],
            encoded_size: 1,
            ..Default::default()
        };
        let requested_policy = ObjectDescriptor {
            media_type: "application/vnd.aos.sandbox.policy.v1+cbor".to_owned(),
            ..specification.clone()
        };
        let request = CreateSandboxRequest {
            project_id: project.as_bytes().to_vec(),
            expected_project_resource_version: vec![0xa1; 32],
            specification: Some(specification).into(),
            requested_policy: Some(requested_policy).into(),
            idempotency_key: key.clone(),
            operation_timeout: Some(Duration {
                nanoseconds: 1,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let envelope = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::CreateSandbox,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0xe1; 32])).unwrap();
        let request_digest =
            scope.public_request_digest(PrincipalId::from_bytes([0x93; 16]), project, &envelope);
        let effect = {
            let selected_method = PublicOperationMethodV1::CreateSandbox;
            (PublicMutationEffectV1::new(
                PrincipalId::from_bytes([0x93; 16]),
                project,
                100,
                envelope,
            )
            .unwrap())
            .into_plan(selected_method)
        }
        .unwrap();
        let authorization = PublicOperationAuthorizationV1::new(
            project,
            ResourceKind::ChildDelegation,
            Selector::Resource {
                resource: ResourceId::from_bytes(*project.as_bytes()),
            },
        )
        .unwrap();

        OperationPlan::new(
            operation_id,
            IdempotencyKey::new(key).unwrap(),
            request_digest,
            b"live-create-sandbox".to_vec(),
            b"accepted".to_vec(),
            vec![effect],
        )
        .unwrap()
        .with_public_operation(
            PublicOperationAdmissionV1::new(
                PublicOperationMethodV1::CreateSandbox,
                1,
                [0xc3; 16],
                100,
                authorization,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn live_create_admission_revision_survives_preparing_retry_and_cold_replay() {
        let directory = TestDirectory::new();
        let plan = live_create_sandbox_plan(0xd1);
        let operation_id = plan.operation_id();
        let scope =
            crate::controller::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0xe1; 32]))
                .unwrap();
        let admitted;
        {
            let mut reconciler =
                Reconciler::new(protected_runtime_journal(&directory), Executor::default());
            reconciler.accept(&plan).unwrap();
            let current = recovered_public_operation_resource_v1(&reconciler.journal, operation_id)
                .unwrap()
                .unwrap();
            admitted = live_create_sandbox_admission_revision_v1(&reconciler.journal, operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(current.resource_version, admitted.0.as_bytes());
            assert_eq!(admitted.1, 1);
            assert_eq!(admitted.2, plan.request_digest());
            assert_eq!(
                checked_live_create_sandbox_admission_revision_v1(
                    &reconciler.journal,
                    operation_id,
                    scope,
                    &plan.effects[0],
                )
                .unwrap(),
                Some((admitted.0, admitted.1)),
            );

            assert_eq!(
                reconciler.reconcile_once_at(operation_id, 101).unwrap(),
                ReconcileOutcome::Progressed,
            );
            let preparing =
                recovered_public_operation_resource_v1(&reconciler.journal, operation_id)
                    .unwrap()
                    .unwrap();
            assert_ne!(preparing.resource_version, current.resource_version);
            assert_eq!(
                live_create_sandbox_admission_revision_v1(&reconciler.journal, operation_id)
                    .unwrap(),
                Some(admitted),
            );
            assert_eq!(
                checked_live_create_sandbox_admission_revision_v1(
                    &reconciler.journal,
                    operation_id,
                    scope,
                    &plan.effects[0],
                )
                .unwrap(),
                Some((admitted.0, admitted.1)),
            );

            let effect = decode_effect(
                reconciler
                    .journal
                    .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
                    .unwrap(),
            )
            .unwrap();
            let effect = effect.into_parts();
            reconciler
                .store_effect(
                    operation_id,
                    0,
                    &EffectLedgerRecord::from_parts((
                        effect.0,
                        EffectState::Applying {
                            attempt: 2,
                            diagnostic: "retry".to_owned(),
                        },
                        None,
                        None,
                    )),
                    None,
                    Some(102),
                )
                .unwrap();
            assert_eq!(
                live_create_sandbox_admission_revision_v1(&reconciler.journal, operation_id)
                    .unwrap(),
                Some(admitted),
            );
        }

        let journal = protected_runtime_journal(&directory);
        assert_eq!(
            live_create_sandbox_admission_revision_v1(&journal, operation_id).unwrap(),
            Some(admitted),
        );
        assert_eq!(
            checked_live_create_sandbox_admission_revision_v1(
                &journal,
                operation_id,
                scope,
                &plan.effects[0],
            )
            .unwrap(),
            Some((admitted.0, admitted.1)),
        );
    }

    #[test]
    fn live_create_selector_rejects_changed_request_with_same_idempotency_key() {
        let directory = TestDirectory::new();
        let plan = live_create_sandbox_plan(0xd1);
        let changed = live_create_sandbox_plan(0xd2);
        let operation_id = plan.operation_id();
        let scope =
            crate::controller::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0xe1; 32]))
                .unwrap();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 101).unwrap(),
            ReconcileOutcome::Progressed,
        );

        reconciler
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(operation_id, 0).to_vec(),
                encode_effect(&EffectLedgerRecord::from_parts((
                    changed.effects[0].clone(),
                    EffectState::Applying {
                        attempt: 1,
                        diagnostic: String::new(),
                    },
                    None,
                    None,
                )))
                .unwrap(),
            )])
            .unwrap();
        assert_eq!(
            checked_live_create_sandbox_admission_revision_v1(
                &reconciler.journal,
                operation_id,
                scope,
                &plan.effects[0],
            )
            .unwrap(),
            None,
        );
        assert_eq!(
            checked_live_create_sandbox_admission_revision_v1(
                &reconciler.journal,
                operation_id,
                scope,
                &changed.effects[0],
            )
            .unwrap(),
            None,
        );
    }

    #[test]
    fn live_create_selector_rejects_non_create_and_terminal_effects() {
        let directory = TestDirectory::new();
        let plan = live_create_sandbox_plan(0xd1);
        let mut other = cancelable_controller_operation();
        other.operation_id = OperationId::from_bytes([0xc4; 16]);
        let operation_id = plan.operation_id();
        let scope =
            crate::controller::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0xe1; 32]))
                .unwrap();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        reconciler.accept(&plan).unwrap();
        reconciler.accept(&other).unwrap();

        assert_eq!(
            checked_live_create_sandbox_admission_revision_v1(
                &reconciler.journal,
                other.operation_id(),
                scope,
                &other.effects[0],
            )
            .unwrap(),
            None,
        );
        let terminal = transition_operation(
            reconciler.load_operation(operation_id).unwrap(),
            OperationState::Succeeded,
            Some(101),
        )
        .unwrap();
        reconciler
            .commit_records(vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(operation_id, 0).to_vec(),
                    encode_effect(&EffectLedgerRecord::from_parts((
                        plan.effects[0].clone(),
                        EffectState::Applied {
                            attempt: 1,
                            receipt: EffectReceipt::new(vec![1]).unwrap(),
                        },
                        None,
                        None,
                    )))
                    .unwrap(),
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    operation_id.into_bytes().to_vec(),
                    encode_operation_record(terminal),
                ),
            ])
            .unwrap();
        assert_eq!(
            checked_live_create_sandbox_admission_revision_v1(
                &reconciler.journal,
                operation_id,
                scope,
                &plan.effects[0],
            )
            .unwrap(),
            None,
        );
    }

    fn applying_failed_create_reconciler(
        directory: &TestDirectory,
        plan: &OperationPlan,
    ) -> Reconciler<Executor> {
        let operation_id = plan.operation_id();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(directory), Executor::default());
        reconciler.accept(plan).unwrap();

        let operation = reconciler.load_operation(operation_id).unwrap();
        let mut effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
                .unwrap(),
        )
        .unwrap();
        effect = {
            let replacement = EffectState::Applying {
                attempt: 1,
                diagnostic: "original Host handoff unresolved".to_owned(),
            };
            let mut parts = effect.into_parts();
            parts.1 = replacement;
            EffectLedgerRecord::from_parts(parts)
        };
        let applying =
            transition_operation(operation, OperationState::Applying, Some(101)).unwrap();
        reconciler
            .commit_records(vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(operation_id, 0).to_vec(),
                    encode_effect(&effect).unwrap(),
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    operation_id.into_bytes().to_vec(),
                    encode_operation_record(applying),
                ),
            ])
            .unwrap();
        reconciler
    }

    fn commit_protected_effect_record(
        journal: &mut Journal,
        transaction_id: u8,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> u64 {
        journal
            .commit(
                &JournalTransaction::new(
                    [transaction_id; 16],
                    vec![JournalRecord::put(RecordNamespace::Effect, key, value)],
                )
                .unwrap(),
            )
            .unwrap()
            .commit_sequence
    }

    #[test]
    fn v1_effect_rejection_preserves_retained_rows_before_executor_activity() {
        for (profile, operation) in [
            ("generic", operation()),
            ("authority-bound", gated_operation()),
        ] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            reconciler.accept(&operation).unwrap();
            let operation_id = operation.operation_id();
            let key = effect_key(operation_id, 0);
            let mut legacy = reconciler
                .journal
                .get(RecordNamespace::Effect, &key)
                .unwrap()
                .to_vec();
            assert_eq!(legacy[0], 2, "{profile}");
            legacy[0] = 1;
            legacy.drain(18..22);
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        [0xa7; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Effect,
                            key.to_vec(),
                            legacy.clone(),
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            let retained_operation = reconciler
                .journal
                .get(RecordNamespace::Operation, operation_id.as_bytes())
                .unwrap()
                .to_vec();
            let retained_sequence = reconciler.journal.snapshot_sequence();

            assert!(
                matches!(
                    reconciler.reconcile_once(operation_id),
                    Err(ReconcilerError::CorruptLedger(
                        "invalid effect record header"
                    ))
                ),
                "{profile}",
            );

            assert_eq!(reconciler.executor.observe_calls, 0, "{profile}");
            assert_eq!(reconciler.executor.apply_calls, 0, "{profile}");
            assert_eq!(reconciler.executor.timing_calls, 0, "{profile}");
            assert!(
                reconciler.executor.guardian_plan_requests.is_empty(),
                "{profile}",
            );
            assert!(reconciler.executor.applied.is_empty(), "{profile}");
            assert_eq!(
                reconciler.journal.get(RecordNamespace::Effect, &key),
                Some(legacy.as_slice()),
                "{profile}",
            );
            assert_eq!(
                reconciler
                    .journal
                    .get(RecordNamespace::Operation, operation_id.as_bytes()),
                Some(retained_operation.as_slice()),
                "{profile}",
            );
            assert_eq!(
                reconciler.journal.snapshot_sequence(),
                retained_sequence,
                "{profile}",
            );
        }
    }

    #[test]
    fn bare_controller_effect_recovery_preserves_rows_before_executor_activity() {
        let cases = [
            (1, 0_u32, &[][..], &[][..], OperationState::Accepted),
            (2, 1, &[][..], &b"try"[..], OperationState::Applying),
            (3, 1, &[1][..], &[][..], OperationState::Succeeded),
            (
                4,
                1,
                &[][..],
                &b"blocked"[..],
                OperationState::PermanentlyBlocked,
            ),
            (255, 0, &[][..], &[][..], OperationState::Accepted),
        ];
        for (state, attempt, receipt, diagnostic, operation_state) in cases {
            let directory = TestDirectory::new();
            let plan = cancelable_controller_operation();
            let operation_id = plan.operation_id();
            let key = effect_key(operation_id, 0);
            let context = plan.effects[0].public_mutation_context().unwrap().unwrap();
            let request = context.canonical_request();
            let mut reconciler =
                Reconciler::new(protected_runtime_journal(&directory), Executor::default());
            reconciler.accept(&plan).unwrap();

            // Assemble the retired V3 layout independently of the live encoder.
            // State 255 also pins missing-context refusal before state decoding.
            let mut legacy = vec![3, 7, state, 0];
            legacy.extend_from_slice(&attempt.to_le_bytes());
            legacy.extend_from_slice(&u32::try_from(request.len()).unwrap().to_le_bytes());
            legacy.extend_from_slice(&u32::try_from(receipt.len()).unwrap().to_le_bytes());
            legacy.extend_from_slice(&u16::try_from(diagnostic.len()).unwrap().to_le_bytes());
            legacy.extend_from_slice(
                &i32::from(public_operation_method_record_code_v1(
                    plan.effects[0].public_mutation_method().unwrap(),
                ))
                .to_be_bytes(),
            );
            legacy.extend_from_slice(request);
            legacy.extend_from_slice(receipt);
            legacy.extend_from_slice(diagnostic);
            let operation = transition_operation(
                reconciler.load_operation(operation_id).unwrap(),
                operation_state,
                Some(101),
            )
            .unwrap();
            let operation_bytes = encode_operation_record(operation);
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        [0xa8; 16],
                        vec![
                            JournalRecord::put(
                                RecordNamespace::Effect,
                                key.to_vec(),
                                legacy.clone(),
                            ),
                            JournalRecord::put(
                                RecordNamespace::Operation,
                                operation_id.into_bytes().to_vec(),
                                operation_bytes.clone(),
                            ),
                        ],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(reconciler);

            let mut recovered =
                Reconciler::new(protected_runtime_journal(&directory), Executor::default());
            let retained_sequence = recovered.journal.snapshot_sequence();
            let retained_file = fs::read(directory.journal()).unwrap();
            assert!(
                matches!(
                    recovered.reconcile_once_at(operation_id, 102),
                    Err(ReconcilerError::CorruptLedger(
                        "controller effect method/request mismatch"
                    ))
                ),
                "state {state}"
            );
            assert!(
                matches!(
                    recovered_public_operation_resource_v1(&recovered.journal, operation_id),
                    Err(ReconcilerError::CorruptLedger(
                        "controller effect method/request mismatch"
                    ))
                ),
                "state {state}"
            );

            assert_eq!(recovered.executor.observe_calls, 0, "state {state}");
            assert_eq!(recovered.executor.apply_calls, 0, "state {state}");
            assert_eq!(recovered.executor.timing_calls, 0, "state {state}");
            assert!(recovered.executor.guardian_plan_requests.is_empty());
            assert_eq!(
                recovered.journal.get(RecordNamespace::Effect, &key),
                Some(legacy.as_slice())
            );
            assert_eq!(
                recovered
                    .journal
                    .get(RecordNamespace::Operation, operation_id.as_bytes()),
                Some(operation_bytes.as_slice()),
            );
            assert_eq!(recovered.journal.snapshot_sequence(), retained_sequence);
            assert_eq!(fs::read(directory.journal()).unwrap(), retained_file);
        }
    }

    #[test]
    fn runtime_holder_admission_activation_and_reopen_retain_exact_intent() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let holder = PrincipalId::from_bytes([0x91; 16]);
        let intent = RuntimeAuthorityIntentV1::bind_holder(holder, None).unwrap();
        let plan = plan.with_runtime_authority(intent).unwrap();
        let sandbox = draft.manifest().manifest().sandbox();
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .count(),
            1
        );
        assert_eq!(
            reconciler
                .load_operation(plan.operation_id())
                .unwrap()
                .runtime_intent_digest(),
            Some(intent.digest())
        );
        assert!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .is_none()
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::OwnershipPending
        );

        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        let binding = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(binding.holder(), Some(holder));
        assert_eq!(binding.manifest(), draft.manifest());
        assert_eq!(binding.publication_digest(), prepared.digest());
        assert_eq!(binding.revision(), 1);
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .count(),
            3
        );
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        assert_eq!(
            reconciler
                .load_operation(plan.operation_id())
                .unwrap()
                .runtime_intent_digest(),
            Some(intent.digest())
        );
        drop(reconciler);

        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Replay(plan.operation_id())
        );
        let recovered = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(recovered, binding);
    }

    #[test]
    fn runtime_intent_rejects_unprotected_admission_and_missing_recovery_links() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, _, _) = gated_operation_with_publication(1);
        let plan = plan
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x92; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.accept(&plan),
            Err(ReconcilerError::RuntimeAuthority(_))
        ));
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::Operation)
                .count(),
            0
        );
        drop(reconciler);

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();
        let pending_key = reconciler
            .journal
            .records(RecordNamespace::RuntimeAuthority)
            .next()
            .unwrap()
            .0
            .to_vec();
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xa1; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::RuntimeAuthority,
                        pending_key,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(reconciler.accept(&plan).is_err());
        assert_eq!(reconciler.executor.apply_calls, 0);

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();
        let mut operation = reconciler
            .journal
            .get(RecordNamespace::Operation, plan.operation_id().as_bytes())
            .unwrap()
            .to_vec();
        operation[8..].fill(0);
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xa2; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        plan.operation_id().into_bytes().to_vec(),
                        operation,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        let error = reconciler.accept(&plan).unwrap_err();
        assert!(matches!(
            error,
            ReconcilerError::RuntimeAuthority(
                crate::runtime_authority::RuntimeAuthorityError::CorruptState
            )
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_activation_rechecks_admitted_revision_without_partial_publication() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (first, draft, prepared) = gated_operation_with_publication(1);
        let first = first
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x93; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        let second = OperationPlan::ownership_gated(
            OperationId::from_bytes([0x94; 16]),
            IdempotencyKey::new(b"competing-runtime-intent".to_vec()).unwrap(),
            [0x95; 32],
            b"same-sandbox".to_vec(),
            b"competing-holder".to_vec(),
            vec![
                aos_sandbox_protocol::publication::bind_authority_publication_effect(
                    &draft,
                    draft.templates()[0].digest(),
                )
                .map_err(crate::publication::AuthorityPublicationError::from)
                .unwrap(),
            ],
            activation_claim(&draft, 1),
            draft.clone(),
        )
        .unwrap()
        .with_runtime_authority(
            RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x96; 16]), None)
                .unwrap(),
        )
        .unwrap();
        reconciler.accept(&first).unwrap();
        reconciler.accept(&second).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(first.operation_id(), activation)
            .unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        assert!(matches!(
            reconciler.activate_ownership_gate(second.operation_id(), activation),
            Err(ReconcilerError::RuntimeAuthority(
                crate::runtime_authority::RuntimeAuthorityError::CompareAndSwap
            ))
        ));
        assert!(matches!(
            reconciler.ownership_gate(second.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
        let current = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(draft.manifest().manifest().sandbox())
        .unwrap()
        .unwrap();
        assert_eq!(current.operation(), first.operation_id());
        assert_eq!(current.revision(), 1);
    }

    #[test]
    fn runtime_stop_revocation_commits_tombstone_before_executor_io_and_survives_reopen() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (bound, first_draft, first_prepared) = gated_operation_with_publication(1);
        let bound = bound
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0xb1; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        reconciler.accept(&bound).unwrap();
        let activation = gate_activation(&mut reconciler, &first_draft, &first_prepared);
        reconciler
            .activate_ownership_gate(bound.operation_id(), activation)
            .unwrap();

        let (draft, prepared) = descriptor_free_activation_fixture(2);
        let revoke = OperationPlan::ownership_gated(
            OperationId::from_bytes([0xb2; 16]),
            IdempotencyKey::new(b"revoke-holder".to_vec()).unwrap(),
            [0xb3; 32],
            b"runtime".to_vec(),
            b"stop".to_vec(),
            vec![
                aos_sandbox_protocol::publication::bind_authority_publication_effect(
                    &draft,
                    draft.templates()[0].digest(),
                )
                .map_err(crate::publication::AuthorityPublicationError::from)
                .unwrap(),
            ],
            activation_claim(&draft, 2),
            draft.clone(),
        )
        .unwrap()
        .with_runtime_authority(RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap())
        .unwrap();
        reconciler.accept(&revoke).unwrap();
        assert_eq!(
            reconciler.reconcile_once(revoke.operation_id()).unwrap(),
            ReconcileOutcome::OwnershipPending
        );
        let sandbox = draft.manifest().manifest().sandbox();
        assert_eq!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap()
            .state(),
            RuntimeAuthorityStateV1::Bound
        );
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(revoke.operation_id(), activation)
            .unwrap();
        let tombstone = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(tombstone.state(), RuntimeAuthorityStateV1::Revoked);
        assert_eq!(tombstone.holder(), None);
        assert_eq!(tombstone.revision(), 2);
        assert_eq!(tombstone.publication_digest(), prepared.digest());
        assert_eq!(reconciler.executor.apply_calls, 0);
        drop(reconciler);
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert_eq!(
            reconciler.accept(&revoke).unwrap(),
            AcceptOutcome::Replay(revoke.operation_id())
        );
        assert_eq!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap(),
            tombstone
        );
    }

    #[test]
    fn runtime_revocation_rejects_other_signed_actions_and_multiple_stop_effects() {
        use crate::publication::tests::descriptor_free_control_activation_fixture;
        use aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction;
        for action in [
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            RuntimeAction::RUNTIME_ACTION_THAW,
            RuntimeAction::RUNTIME_ACTION_KILL,
            RuntimeAction::RUNTIME_ACTION_STOP,
        ] {
            let (draft, _) = descriptor_free_control_activation_fixture(2, action);
            let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
                &draft,
                draft.templates()[0].digest(),
            )
            .map_err(crate::publication::AuthorityPublicationError::from)
            .unwrap();
            let effects = if action == RuntimeAction::RUNTIME_ACTION_STOP {
                vec![effect.clone(), effect]
            } else {
                vec![effect]
            };
            let plan = OperationPlan::ownership_gated(
                OperationId::from_bytes([0xb4; 16]),
                IdempotencyKey::new(b"wrong-revoke".to_vec()).unwrap(),
                [0xb5; 32],
                b"runtime".to_vec(),
                b"stop".to_vec(),
                effects,
                activation_claim(&draft, 2),
                draft,
            )
            .unwrap();
            assert!(
                matches!(
                    plan.with_runtime_authority(RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap()),
                    Err(ReconcilerError::InvalidPlan(_))
                ),
                "{action:?}"
            );
        }
    }

    #[test]
    fn runtime_revocation_cannot_stop_a_replacement_assignment_instead_of_current() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (bound, draft, prepared) = gated_operation_with_publication(1);
        let bound = bound
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0xb6; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        reconciler.accept(&bound).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(bound.operation_id(), activation)
            .unwrap();
        let replacement = crate::publication::tests::descriptor_free_stop_draft_with_node(99);
        assert_eq!(
            replacement.manifest().manifest().sandbox(),
            draft.manifest().manifest().sandbox()
        );
        assert_ne!(replacement.manifest(), draft.manifest());
        let revoke = OperationPlan::ownership_gated(
            OperationId::from_bytes([0xb7; 16]),
            IdempotencyKey::new(b"wrong-runtime-stop".to_vec()).unwrap(),
            [0xb8; 32],
            b"runtime".to_vec(),
            b"stop".to_vec(),
            vec![
                aos_sandbox_protocol::publication::bind_authority_publication_effect(
                    &replacement,
                    replacement.templates()[0].digest(),
                )
                .map_err(crate::publication::AuthorityPublicationError::from)
                .unwrap(),
            ],
            activation_claim(&replacement, 2),
            replacement,
        )
        .unwrap()
        .with_runtime_authority(RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap())
        .unwrap();
        assert!(matches!(
            reconciler.accept(&revoke),
            Err(ReconcilerError::RuntimeAuthority(
                crate::runtime_authority::RuntimeAuthorityError::ActivationConflict
            ))
        ));
        assert_eq!(
            reconciler
                .journal
                .records(RecordNamespace::Operation)
                .count(),
            1
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_recovery_rejects_removal_of_activated_binding_and_head() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let plan = plan
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x97; 16]), None)
                    .unwrap(),
            )
            .unwrap();
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        let deletions = reconciler
            .journal
            .records(RecordNamespace::RuntimeAuthority)
            .filter(|(key, _)| !key.starts_with(b"pending/"))
            .map(|(key, _)| JournalRecord::delete(RecordNamespace::RuntimeAuthority, key.to_vec()))
            .collect();
        reconciler
            .journal_mut()
            .commit(&JournalTransaction::new([0xa2; 16], deletions).unwrap())
            .unwrap();
        assert!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .is_err()
        );
        assert!(reconciler.accept(&plan).is_err());
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn runtime_successor_preserves_history_and_historical_replay_cannot_repoint_head() {
        use aos_sandbox_model::PrincipalId;
        let directory = TestDirectory::new();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        let mut first = None;
        for generation in 1..=2_u8 {
            let (_, draft, prepared) = gated_operation_with_publication(u64::from(generation));
            let plan = OperationPlan::ownership_gated(
                OperationId::from_bytes([generation; 16]),
                IdempotencyKey::new(vec![generation]).unwrap(),
                [generation; 32],
                b"runtime".to_vec(),
                vec![generation],
                vec![
                    aos_sandbox_protocol::publication::bind_authority_publication_effect(
                        &draft,
                        draft.templates()[0].digest(),
                    )
                    .map_err(crate::publication::AuthorityPublicationError::from)
                    .unwrap(),
                ],
                activation_claim(&draft, u64::from(generation)),
                draft.clone(),
            )
            .unwrap()
            .with_runtime_authority(
                RuntimeAuthorityIntentV1::bind_holder(
                    PrincipalId::from_bytes([generation + 10; 16]),
                    (generation > 1).then_some(u64::from(generation - 1)),
                )
                .unwrap(),
            )
            .unwrap();
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            if generation == 1 {
                first = Some((plan, draft, prepared));
            }
        }
        let (first, draft, prepared) = first.unwrap();
        let sandbox = draft.manifest().manifest().sandbox();
        let head = RuntimeAuthorityStore::load(
            reconciler.journal_mut(),
            RuntimeAuthorityLimits::default(),
        )
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap();
        assert_eq!(head.revision(), 2);
        assert_eq!(head.holder(), Some(PrincipalId::from_bytes([12; 16])));
        let replay = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(first.operation_id(), replay)
                .unwrap(),
            OwnershipGateActivationOutcome::Replay
        );
        assert_eq!(
            reconciler.accept(&first).unwrap(),
            AcceptOutcome::Replay(first.operation_id())
        );
        assert_eq!(
            RuntimeAuthorityStore::load(
                reconciler.journal_mut(),
                RuntimeAuthorityLimits::default()
            )
            .unwrap()
            .current(sandbox)
            .unwrap()
            .unwrap(),
            head
        );
        let mut substituted = first;
        substituted.runtime_authority = Some(
            RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([99; 16]), None).unwrap(),
        );
        assert!(matches!(
            reconciler.accept(&substituted),
            Err(ReconcilerError::IdempotencyConflict)
        ));
    }

    #[test]
    fn poisoned_journal_blocks_replay_and_all_executor_io_even_with_cached_validation() {
        for authority_bound in [false, true] {
            for cached_validation in [false, true] {
                let directory = TestDirectory::new();
                let (journal, _) =
                    Journal::open(directory.journal(), JournalLimits::default()).unwrap();
                let mut reconciler = Reconciler::new(journal, Executor::default());
                let plan = if authority_bound {
                    let (plan, draft, prepared) = gated_operation_with_publication(1);
                    reconciler.accept(&plan).unwrap();
                    let activation = gate_activation(&mut reconciler, &draft, &prepared);
                    reconciler
                        .activate_ownership_gate(plan.operation_id(), activation)
                        .unwrap();
                    plan
                } else {
                    let plan = operation();
                    reconciler.accept(&plan).unwrap();
                    plan
                };
                assert_eq!(
                    reconciler.reconcile_once(plan.operation_id()).unwrap(),
                    ReconcileOutcome::Progressed
                );
                assert_eq!(reconciler.executor.observe_calls, 0);

                // A directory at the exact temporary-file name forces the
                // real compaction I/O failure path, leaving diagnostic state.
                fs::create_dir(directory.0.join("state.journal.compact.tmp")).unwrap();
                assert!(matches!(
                    reconciler.journal.compact(),
                    Err(JournalError::Io(_))
                ));
                reconciler.ledger_validated = cached_validation;

                assert!(matches!(
                    reconciler.accept(&plan),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert!(matches!(
                    reconciler.ownership_gate(plan.operation_id()),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert!(matches!(
                    reconciler.reconcile_once(plan.operation_id()),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert!(matches!(
                    reconciler.reconcile_next(),
                    Err(ReconcilerError::Journal(JournalError::Poisoned))
                ));
                assert_eq!(reconciler.executor.observe_calls, 0);
                assert_eq!(reconciler.executor.apply_calls, 0);
            }
        }
    }

    #[test]
    fn admission_is_atomic_and_exact_replay_is_idempotent() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Accepted(plan.operation_id())
        );
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Replay(plan.operation_id())
        );
    }

    #[test]
    fn operator_abandon_acknowledgment_cannot_be_replaced() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let target = OperationId::from_bytes([3; 16]);
        let plan = |identity: u8, idempotency: &'static [u8]| {
            let operation = OperationId::from_bytes([identity; 16]);
            let acknowledgment = crate::operator_abandon_ack::record_v1(
                operation,
                target,
                aos_sandbox_model::PrincipalId::from_bytes([4; 16]),
                aos_sandbox_model::ProjectId::from_bytes([5; 16]),
                idempotency,
                [6; 32],
                ObjectDigest::from_bytes([7; 32]),
                b"version",
            )
            .unwrap();
            OperationPlan::completed_operator_abandon(
                operation,
                target,
                IdempotencyKey::new(idempotency.to_vec()).unwrap(),
                [6; 32],
                vec![identity],
                b"desired".to_vec(),
                acknowledgment,
            )
            .unwrap()
        };
        let first = plan(1, b"first");
        let second = plan(2, b"second");

        assert_eq!(
            reconciler.accept(&first).unwrap(),
            AcceptOutcome::Accepted(first.operation_id())
        );
        assert_eq!(
            reconciler.accept(&first).unwrap(),
            AcceptOutcome::Replay(first.operation_id())
        );
        assert!(matches!(
            reconciler.accept(&second),
            Err(ReconcilerError::IdempotencyConflict)
        ));
    }

    #[test]
    fn unfinished_operation_audit_preserves_accepted_journal_and_executor_state() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        let before = fs::read(&path).unwrap();
        let before_length = fs::metadata(&path).unwrap().len();

        let unfinished = reconciler
            .validated_unfinished_operation()
            .unwrap()
            .unwrap();

        assert_eq!(unfinished.operation_id(), plan.operation_id());
        assert_eq!(unfinished.state(), UnfinishedOperationStateV1::Accepted);
        assert_eq!(fs::metadata(&path).unwrap().len(), before_length);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(reconciler.executor.timing_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 0);
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn unfinished_operation_audit_preserves_authority_applying_journal_without_executor_calls() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        reconciler.executor.timing_calls = 0;
        reconciler.executor.guardian_plan_requests.clear();
        reconciler.executor.observe_calls = 0;
        reconciler.executor.apply_calls = 0;
        reconciler.ledger_validated = false;
        let before = fs::read(&path).unwrap();
        let before_length = fs::metadata(&path).unwrap().len();

        let unfinished = reconciler
            .validated_unfinished_operation()
            .unwrap()
            .unwrap();

        assert_eq!(unfinished.operation_id(), plan.operation_id());
        assert_eq!(unfinished.state(), UnfinishedOperationStateV1::Applying);
        assert_eq!(fs::metadata(&path).unwrap().len(), before_length);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(reconciler.executor.timing_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 0);
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn unfinished_operation_audit_includes_ownership_pending() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = gated_operation();
        reconciler.accept(&plan).unwrap();

        let unfinished = reconciler
            .validated_unfinished_operation()
            .unwrap()
            .unwrap();

        assert_eq!(unfinished.operation_id(), plan.operation_id());
        assert_eq!(
            unfinished.state(),
            UnfinishedOperationStateV1::OwnershipPending
        );
        assert_eq!(reconciler.executor.timing_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 0);
        assert_eq!(reconciler.executor.observe_calls, 0);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn ownership_gate_admission_replay_and_restart_are_exact() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (plan, draft, _) = gated_operation_with_publication(1);
        let claim = activation_claim(&draft, 1);
        {
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            assert_eq!(
                reconciler.accept(&plan).unwrap(),
                AcceptOutcome::Accepted(plan.operation_id())
            );
            assert_eq!(
                reconciler.accept(&plan).unwrap(),
                AcceptOutcome::Replay(plan.operation_id())
            );
            assert_eq!(
                reconciler.reconcile_once(plan.operation_id()).unwrap(),
                ReconcileOutcome::OwnershipPending
            );
            assert_eq!(reconciler.executor.apply_calls, 0);
        }

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gate = reconciler
            .ownership_gate(plan.operation_id())
            .unwrap()
            .unwrap();
        let OwnershipGateStatusV1::Pending(recovered) = gate else {
            panic!("recovered gate was activated");
        };
        assert_eq!(recovered.claim(), &claim);
        assert_eq!(recovered.publication_draft(), &draft);
        assert_eq!(recovered.publication_draft_digest(), draft.digest());
        assert!(reconciler.reconcile_next().unwrap().is_none());
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn authority_effect_values_are_bound_to_operation_and_step_keys() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (draft, _) = descriptor_free_activation_fixture(1);
        let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
            &draft,
            draft.templates()[0].digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)
        .unwrap();
        let operation_id = OperationId::from_bytes([0xc1; 16]);
        let plan = OperationPlan::ownership_gated(
            operation_id,
            IdempotencyKey::new(b"location-bound-effects".to_vec()).unwrap(),
            [0xc2; 32],
            b"location-sandbox".to_vec(),
            b"pending".to_vec(),
            vec![effect.clone(), effect],
            activation_claim(&draft, 1),
            draft,
        )
        .unwrap();
        reconciler.accept(&plan).unwrap();
        let first_key = effect_key(operation_id, 0);
        let second_key = effect_key(operation_id, 1);
        let first = reconciler
            .journal
            .get(RecordNamespace::Effect, &first_key)
            .unwrap()
            .to_vec();
        let second = reconciler
            .journal
            .get(RecordNamespace::Effect, &second_key)
            .unwrap()
            .to_vec();
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xc3; 16],
                    vec![
                        JournalRecord::put(RecordNamespace::Effect, first_key.to_vec(), second),
                        JournalRecord::put(RecordNamespace::Effect, second_key.to_vec(), first),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.ownership_gate(operation_id),
            Err(ReconcilerError::CorruptLedger(_))
        ));
    }

    #[test]
    fn ownership_gate_activation_commits_publication_and_release_atomically() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let publication = prepared.digest();
        let lease_generation = prepared.lease_generation();
        let lease = prepared.lease_digest();
        {
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            assert_eq!(
                reconciler
                    .activate_ownership_gate(plan.operation_id(), activation)
                    .unwrap(),
                OwnershipGateActivationOutcome::Activated
            );
        }

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let current = AuthorityPublicationStore::new(reconciler.journal_mut())
            .current(draft.manifest().manifest().sandbox())
            .unwrap()
            .unwrap();
        assert_eq!(current.digest(), publication);
        assert!(matches!(
            reconciler.ownership_gate(plan.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Activated {
                publication_digest,
                lease_generation: recovered_generation,
                lease_digest,
                ..
            }) if publication_digest == publication
                && recovered_generation == lease_generation
                && lease_digest == lease
        ));
        let replay = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(plan.operation_id(), replay)
                .unwrap(),
            OwnershipGateActivationOutcome::Replay
        );
        let (changed_draft, changed_prepared) = descriptor_free_activation_fixture(2);
        let conflicting = gate_activation(&mut reconciler, &changed_draft, &changed_prepared);
        assert!(matches!(
            reconciler.activate_ownership_gate(plan.operation_id(), conflicting),
            Err(ReconcilerError::OwnershipActivationConflict)
        ));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn protected_gate_read_requires_validated_activation_publication() {
        let directory = TestDirectory::new();
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let plan = plan
            .with_public_operation(
                PublicOperationAdmissionV1::new(
                    aos_sandbox_protocol::public_api::PublicOperationMethodV1::StartSandbox,
                    1,
                    [0x41; 16],
                    100,
                    public_operation_authorization(),
                )
                .unwrap(),
            )
            .unwrap();
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            activated_ownership_gate_digest_from_journal_v1(
                &reconciler.journal,
                plan.operation_id(),
            )
            .unwrap(),
            None,
        );
        let operation =
            recovered_public_operation_resource_v1(&reconciler.journal, plan.operation_id())
                .unwrap()
                .unwrap();
        let checked =
            aos_sandbox_protocol::public_api::CheckedOperationResourceV1::try_from(operation).unwrap();
        let recovery = crate::controller::prepare_operator_recovery_operation_current_v1(
            &reconciler.journal,
            &checked,
        )
        .unwrap()
        .into_record();
        assert_eq!(recovery.value().unwrap()[1] & 1, 1);

        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate_at(plan.operation_id(), activation, 101)
            .unwrap();
        assert_eq!(
            activated_ownership_gate_digest_from_journal_v1(
                &reconciler.journal,
                plan.operation_id(),
            )
            .unwrap(),
            Some(prepared.digest()),
        );
    }

    #[test]
    fn host_launch_signs_after_lease_selection_and_refreshes_before_absent_retry() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();

        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 1);
        let first_request = reconciler.executor.guardian_plan_requests[0].clone();
        assert_eq!(first_request.lease_generation(), 1);
        assert_eq!(first_request.lease_digest(), prepared.lease_digest());
        let first_record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let first_dispatch = first_record.dispatch().unwrap();
        assert_eq!(first_dispatch.attempt().lease_generation(), 1);
        let first_companion = aos_sandbox_protocol::decode_host_guardian_companion_v1(
            first_dispatch.attempt().body(),
        )
        .unwrap();
        assert_eq!(
            first_companion.broker_plan(),
            signed_guardian_plan(&first_request).canonical_plan(),
        );

        reconciler
            .executor
            .failures
            .push_back(EffectFailure::Retryable("transport lost".to_owned()));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
        assert_eq!(reconciler.executor.guardian_plan_requests.len(), 2);

        let (_, renewed) = descriptor_free_launch_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("guardian-launch-renewal").unwrap(),
                OperationId::new(),
                [0xd8; 16],
            )
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        let renewed_request = reconciler.executor.guardian_plan_requests.last().unwrap();
        assert_eq!(renewed_request.lease_generation(), 2);
        assert_eq!(renewed_request.lease_digest(), renewed.lease_digest());
        assert_ne!(renewed_request.lease_digest(), first_request.lease_digest());
        let applied = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let applied_dispatch = applied.dispatch().unwrap();
        assert_eq!(applied_dispatch.attempt().lease_generation(), 2);
        let renewed_companion = aos_sandbox_protocol::decode_host_guardian_companion_v1(
            applied_dispatch.attempt().body(),
        )
        .unwrap();
        assert_eq!(
            renewed_companion.broker_plan(),
            signed_guardian_plan(renewed_request).canonical_plan(),
        );
        assert_ne!(
            renewed_companion.broker_plan(),
            first_companion.broker_plan(),
        );
    }

    #[test]
    fn renewed_host_launch_rejects_a_stale_guardian_plan_before_apply() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let stale_guardian = signed_guardian_plan(&reconciler.executor.guardian_plan_requests[0]);
        let effect_key = effect_key(plan.operation_id(), 0);
        let before = reconciler
            .journal
            .get(RecordNamespace::Effect, &effect_key)
            .unwrap()
            .to_vec();

        let (_, renewed) = descriptor_free_launch_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("stale-guardian-renewal").unwrap(),
                OperationId::new(),
                [0xd9; 16],
            )
            .unwrap();
        reconciler.executor.guardian_plan_override = Some(stale_guardian);
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::AuthorityPublication(
                AuthorityPublicationError::DispatchAttempt(
                    crate::BrokerDispatchAttemptError::GuardianPlanMismatch
                        | crate::BrokerDispatchAttemptError::GuardianContextMismatch
                )
            ))
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
        assert_eq!(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key)
                .unwrap(),
            before,
        );
    }

    #[test]
    fn durable_host_launch_rejects_body_packet_and_boot_substitution_before_io() {
        for mutation in ["body", "packet", "boot"] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            reconciler.reconcile_once(plan.operation_id()).unwrap();

            let effect_key = effect_key(plan.operation_id(), 0);
            let mut record = decode_effect(
                reconciler
                    .journal
                    .get(RecordNamespace::Effect, &effect_key)
                    .unwrap(),
            )
            .unwrap();
            let durable = record.dispatch().unwrap();
            let mut body = durable.attempt().body().to_vec();
            let mut packet = durable.attempt().packet().to_vec();
            let mut host_boot_id = durable.preparation_host_boot_id();
            match mutation {
                "body" => *body.last_mut().unwrap() ^= 1,
                "packet" => *packet.last_mut().unwrap() ^= 1,
                "boot" => host_boot_id = [0x93; 16],
                _ => unreachable!(),
            }
            let substituted = BrokerDispatchAttemptHistoryV1::from_durable_parts(
                durable.attempt().template_digest(),
                durable.attempt().lease_digest(),
                durable.attempt().lease_generation(),
                durable.attempt().deadline_boottime_nanoseconds(),
                body,
                packet,
            );
            record = {
                let replacement = Some(PreparedAuthorityEffectHistoryV1::from_durable_parts(
                    durable.binding_digest(),
                    durable.publication_digest(),
                    durable.preparation_wall_seconds(),
                    durable.preparation_boottime_nanoseconds(),
                    host_boot_id,
                    substituted,
                ));
                let mut parts = record.into_parts();
                parts.2 = replacement;
                EffectLedgerRecord::from_parts(parts)
            };
            let replacement = JournalRecord::put(
                RecordNamespace::Effect,
                effect_key.to_vec(),
                encode_effect(&record).unwrap(),
            );
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        match mutation {
                            "body" => [0xe1; 16],
                            "packet" => [0xe2; 16],
                            "boot" => [0xe3; 16],
                            _ => unreachable!(),
                        },
                        vec![replacement],
                    )
                    .unwrap(),
                )
                .unwrap();

            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.observe_calls, 0, "{mutation}");
            assert_eq!(reconciler.executor.apply_calls, 0, "{mutation}");
        }
    }

    #[test]
    fn completed_v1_host_launch_remains_historical_after_reboot() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_launch_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        let apply_calls = reconciler.executor.apply_calls;

        reconciler.executor.host_boot_id = Some([0x93; 16]);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Succeeded
        );
        assert_eq!(reconciler.executor.apply_calls, apply_calls);
    }

    #[test]
    fn authority_attempt_is_durable_before_io_and_reused_after_restart() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        let durable_attempt;
        {
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            assert_eq!(
                reconciler.reconcile_once(plan.operation_id()).unwrap(),
                ReconcileOutcome::Progressed
            );
            assert_eq!(reconciler.executor.apply_calls, 0);
            let record = decode_effect(
                reconciler
                    .journal
                    .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                    .unwrap(),
            )
            .unwrap();
            let record = record.into_parts();
            durable_attempt = record.2.unwrap();
        }

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let recovered = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap()
        .into_parts()
        .2
        .unwrap();
        assert_eq!(recovered, durable_attempt);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
    }

    #[test]
    fn authenticated_pending_retains_the_exact_durable_attempt() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        let before = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        reconciler.executor.authority_pending = true;
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        let after = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(before, after);
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn v1_durable_bytes_omit_clock_provenance_but_bind_host_boot() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let durable = record.dispatch().unwrap();
        let alternate_clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([0xee; 16]).unwrap(),
            durable.preparation_host_boot_id(),
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
        )
        .unwrap();
        let mut alternate = record.clone();
        alternate = {
            let replacement = Some({
                let binding_digest = durable.binding_digest();
                let publication_digest = durable.publication_digest();
                let preparation_clock = alternate_clock;
                let attempt = durable.attempt().clone();
                PreparedAuthorityEffectHistoryV1::from_durable_parts(
                    binding_digest,
                    publication_digest,
                    preparation_clock.wall_seconds(),
                    preparation_clock.boottime_nanoseconds(),
                    preparation_clock.host_boot_id(),
                    attempt,
                )
            });
            let mut parts = alternate.into_parts();
            parts.2 = replacement;
            EffectLedgerRecord::from_parts(parts)
        };
        assert_eq!(
            encode_effect(&record).unwrap(),
            encode_effect(&alternate).unwrap()
        );

        let another_boot = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([0xee; 16]).unwrap(),
            [0xef; 16],
            durable.preparation_wall_seconds(),
            durable.preparation_boottime_nanoseconds(),
        )
        .unwrap();
        alternate = {
            let replacement = Some({
                let binding_digest = durable.binding_digest();
                let publication_digest = durable.publication_digest();
                let preparation_clock = another_boot;
                let attempt = durable.attempt().clone();
                PreparedAuthorityEffectHistoryV1::from_durable_parts(
                    binding_digest,
                    publication_digest,
                    preparation_clock.wall_seconds(),
                    preparation_clock.boottime_nanoseconds(),
                    preparation_clock.host_boot_id(),
                    attempt,
                )
            });
            let mut parts = alternate.into_parts();
            parts.2 = replacement;
            EffectLedgerRecord::from_parts(parts)
        };
        assert_ne!(
            encode_effect(&record).unwrap(),
            encode_effect(&alternate).unwrap()
        );
    }

    #[test]
    fn authenticated_absent_persists_current_replacement_before_failed_apply() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let (_, renewed) = descriptor_free_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("absent-renewal").unwrap(),
                OperationId::new(),
                [0xd1; 16],
            )
            .unwrap();
        reconciler
            .executor
            .failures
            .push_back(EffectFailure::Retryable("transport lost".to_owned()));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        let effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let effect = effect.into_parts();
        assert_eq!(effect.2.unwrap().publication_digest(), renewed.digest());
        assert_eq!(reconciler.executor.apply_calls, 1);
    }

    #[test]
    fn validated_receipt_tokens_cannot_cross_attempts_on_apply_or_observe() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let old = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap()
        .into_parts()
        .2
        .unwrap();
        let old = PreparedAuthorityEffectV1::from_history(old);
        let old_apply_token = host_receipt(&old);
        let old_observe_token = host_receipt(&old);
        let (_, renewed) = descriptor_free_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("token-renewal").unwrap(),
                OperationId::new(),
                [0xda; 16],
            )
            .unwrap();

        reconciler.executor.authority_receipt_override = Some(old_apply_token);
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::InvalidExecutorOutput(_))
        ));
        let fresh = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap()
        .into_parts()
        .2
        .unwrap();
        assert_eq!(fresh.publication_digest(), renewed.digest());

        reconciler.executor.authority_receipt_override = Some(old_observe_token);
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::InvalidExecutorOutput(_))
        ));
    }

    #[test]
    fn substituted_durable_authority_attempt_fails_before_executor_io() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        let mut record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let durable = record.dispatch().unwrap();
        let mut packet = durable.attempt().packet().to_vec();
        packet.push(0xff);
        let substituted = BrokerDispatchAttemptHistoryV1::from_durable_parts(
            durable.attempt().template_digest(),
            durable.attempt().lease_digest(),
            durable.attempt().lease_generation(),
            durable.attempt().deadline_boottime_nanoseconds(),
            durable.attempt().body().to_vec(),
            packet,
        );
        record = {
            let replacement = Some(PreparedAuthorityEffectHistoryV1::from_durable_parts(
                durable.binding_digest(),
                durable.publication_digest(),
                durable.preparation_wall_seconds(),
                durable.preparation_boottime_nanoseconds(),
                durable.preparation_host_boot_id(),
                substituted,
            ));
            let mut parts = record.into_parts();
            parts.2 = replacement;
            EffectLedgerRecord::from_parts(parts)
        };
        let replacement = JournalRecord::put(
            RecordNamespace::Effect,
            effect_key(plan.operation_id(), 0).to_vec(),
            encode_effect(&record).unwrap(),
        );
        reconciler
            .journal_mut()
            .commit(&JournalTransaction::new([0xd7; 16], vec![replacement]).unwrap())
            .unwrap();

        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::CorruptLedger(_))
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn substituted_applied_host_receipt_fails_recovery_before_executor_io() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        reconciler
            .activate_ownership_gate(plan.operation_id(), activation)
            .unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        let key = effect_key(plan.operation_id(), 0);
        let mut record = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &key)
                .unwrap(),
        )
        .unwrap();
        let EffectState::Applied { attempt, .. } = *record.state() else {
            panic!("effect was not applied");
        };
        record = {
            let replacement = EffectState::Applied {
                attempt,
                receipt: EffectReceipt::new(vec![0xff]).unwrap(),
            };
            let mut parts = record.into_parts();
            parts.1 = replacement;
            EffectLedgerRecord::from_parts(parts)
        };
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [0xd8; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Effect,
                        key.to_vec(),
                        encode_effect(&record).unwrap(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.reconcile_once(plan.operation_id()),
            Err(ReconcilerError::CorruptLedger(_))
        ));
        assert_eq!(reconciler.executor.apply_calls, 1);
    }

    #[test]
    fn descriptor_bearing_authority_effect_is_explicitly_blocked_before_io() {
        let (draft, _) = descriptor_host_activation_fixture(1);
        let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
            &draft,
            draft.templates()[0].digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)
        .unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                OperationId::from_bytes([0xa1; 16]),
                IdempotencyKey::new(b"descriptor-gated".to_vec()).unwrap(),
                [0xa2; 32],
                b"descriptor-sandbox".to_vec(),
                b"pending".to_vec(),
                vec![effect],
                activation_claim(&draft, 1),
                draft,
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));
    }

    #[test]
    fn descriptor_free_mount_authority_effect_is_admitted() {
        let (draft, _) = descriptor_free_mount_activation_fixture();
        let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
            &draft,
            draft.templates()[0].digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)
        .unwrap();
        let plan = OperationPlan::ownership_gated(
            OperationId::from_bytes([0xa3; 16]),
            IdempotencyKey::new(b"mount-gated".to_vec()).unwrap(),
            [0xa4; 32],
            b"mount-sandbox".to_vec(),
            b"pending".to_vec(),
            vec![effect],
            activation_claim(&draft, 1),
            draft,
        )
        .unwrap();

        assert_eq!(plan.effects.len(), 1);
        assert_eq!(plan.effects[0].domain(), EffectDomain::Mount);
    }

    #[test]
    fn crafted_audience_method_mismatches_fail_before_executor_io() {
        for applying in [false, true] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            if applying {
                let activation = gate_activation(&mut reconciler, &draft, &prepared);
                reconciler
                    .activate_ownership_gate(plan.operation_id(), activation)
                    .unwrap();
                reconciler.reconcile_once(plan.operation_id()).unwrap();
            }
            let key = effect_key(plan.operation_id(), 0);
            let mut bytes = reconciler
                .journal
                .get(RecordNamespace::Effect, &key)
                .unwrap()
                .to_vec();
            // The fixed header + operation + step + source digest precede audience.
            bytes[70] = 2;
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        [0xa5 + u8::from(applying); 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Effect,
                            key.to_vec(),
                            bytes,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn ownership_gate_rejects_a_different_draft_with_the_same_claim_context() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, _) = gated_operation_with_publication(1);
        let (alternate_draft, alternate_prepared) = alternate_descriptor_free_activation_fixture();
        assert_eq!(
            activation_claim(&draft, 1),
            activation_claim(&alternate_draft, 1)
        );
        assert_ne!(draft.digest(), alternate_draft.digest());
        reconciler.accept(&plan).unwrap();

        let activation = gate_activation(&mut reconciler, &alternate_draft, &alternate_prepared);
        assert!(matches!(
            reconciler.activate_ownership_gate(plan.operation_id(), activation),
            Err(ReconcilerError::OwnershipActivationConflict)
        ));
        assert!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(draft.manifest().manifest().sandbox())
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            reconciler.ownership_gate(plan.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
    }

    #[test]
    fn activated_gate_replays_its_prepared_publication_after_current_renews() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let activation = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap(),
            OwnershipGateActivationOutcome::Activated
        );

        let (renewed_draft, renewed) = descriptor_free_activation_fixture(2);
        assert_eq!(renewed_draft.digest(), draft.digest());
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &renewed,
                &IdempotencyKey::new("renewed-current").unwrap(),
                OperationId::new(),
                [0xb1; 16],
            )
            .unwrap();
        let historical_replay = gate_activation(&mut reconciler, &draft, &prepared);
        assert_eq!(
            reconciler
                .activate_ownership_gate(plan.operation_id(), historical_replay)
                .unwrap(),
            OwnershipGateActivationOutcome::Replay
        );
        assert_eq!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(draft.manifest().manifest().sandbox())
                .unwrap()
                .unwrap()
                .digest(),
            renewed.digest()
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        let effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        let effect = effect.into_parts();
        assert_eq!(effect.2.unwrap().publication_digest(), renewed.digest());
    }

    #[test]
    fn pending_activation_rechecks_current_after_bridge_preparation() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let (plan, draft, prepared) = gated_operation_with_publication(1);
        reconciler.accept(&plan).unwrap();
        let stale_activation = gate_activation(&mut reconciler, &draft, &prepared);

        let (_, newer) = descriptor_free_activation_fixture(2);
        AuthorityPublicationStore::new(reconciler.journal_mut())
            .publish(
                &newer,
                &IdempotencyKey::new("newer-before-activation").unwrap(),
                OperationId::new(),
                [0xb2; 16],
            )
            .unwrap();
        assert!(matches!(
            reconciler.activate_ownership_gate(plan.operation_id(), stale_activation),
            Err(ReconcilerError::OwnershipPublicationNotSuccessor)
        ));
        assert!(matches!(
            reconciler.ownership_gate(plan.operation_id()).unwrap(),
            Some(OwnershipGateStatusV1::Pending(_))
        ));
        assert_eq!(
            AuthorityPublicationStore::new(reconciler.journal_mut())
                .current(draft.manifest().manifest().sandbox())
                .unwrap()
                .unwrap()
                .digest(),
            newer.digest()
        );
    }

    #[test]
    fn activated_gate_requires_gate_prepared_and_current_records() {
        for corruption in 0..3 {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();

            let record = match corruption {
                0 => JournalRecord::delete(
                    RecordNamespace::OwnershipGate,
                    plan.operation_id().into_bytes().to_vec(),
                ),
                1 => {
                    let key = reconciler
                        .journal
                        .records(RecordNamespace::AuthorityPublication)
                        .find(|(_, value)| *value == prepared.canonical_bytes())
                        .map(|(key, _)| key.to_vec())
                        .unwrap();
                    JournalRecord::delete(RecordNamespace::AuthorityPublication, key)
                }
                2 => {
                    let key = reconciler
                        .journal
                        .records(RecordNamespace::AuthorityPublication)
                        .find(|(_, value)| *value != prepared.canonical_bytes())
                        .map(|(key, _)| key.to_vec())
                        .unwrap();
                    JournalRecord::delete(RecordNamespace::AuthorityPublication, key)
                }
                _ => unreachable!(),
            };
            reconciler
                .journal_mut()
                .commit(&JournalTransaction::new([0xc0 + corruption; 16], vec![record]).unwrap())
                .unwrap();
            assert!(matches!(
                reconciler.ownership_gate(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn gated_provenance_detects_deleted_gate_in_every_released_state() {
        for (case, state) in [
            (1_u8, OperationState::Accepted),
            (2, OperationState::Applying),
            (3, OperationState::Succeeded),
            (4, OperationState::PermanentlyBlocked),
        ] {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (plan, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&plan).unwrap();
            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            reconciler
                .activate_ownership_gate(plan.operation_id(), activation)
                .unwrap();
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new(
                        [0xe0 + case; 16],
                        vec![
                            JournalRecord::put(
                                RecordNamespace::Operation,
                                plan.operation_id().into_bytes().to_vec(),
                                encode_operation(state, 1, true, None),
                            ),
                            JournalRecord::delete(
                                RecordNamespace::OwnershipGate,
                                plan.operation_id().into_bytes().to_vec(),
                            ),
                        ],
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(matches!(
                reconciler.reconcile_once(plan.operation_id()),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }
    }

    #[test]
    fn operation_record_v1_is_fixed_and_rejects_noncanonical_headers() {
        let bytes = encode_operation(OperationState::Accepted, 1, false, None);
        assert_eq!(bytes.len(), OPERATION_RECORD_V1_BYTES);
        assert_eq!(&bytes[..8], &[RECORD_VERSION_V1, 1, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&bytes[8..], &[0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES]);
        assert_eq!(
            decode_operation(&bytes).unwrap(),
            OperationRecord::new(OperationState::Accepted, 1, false, None, None)
        );

        let mut invalid = vec![
            bytes[..6].to_vec(),
            bytes[..8].to_vec(),
            bytes[..39].to_vec(),
            [bytes.clone(), vec![0]].concat(),
        ];
        for version in [0, 2, 3] {
            let mut unknown_version = bytes.clone();
            unknown_version[0] = version;
            invalid.push(unknown_version);
        }
        for (offset, value) in [(1, 0), (2, 0x80), (3, 1)] {
            let mut invalid_header = bytes.clone();
            invalid_header[offset] = value;
            invalid.push(invalid_header);
        }
        for count in [0_u32, u32::MAX] {
            let mut invalid_count = bytes.clone();
            invalid_count[4..8].copy_from_slice(&count.to_le_bytes());
            invalid.push(invalid_count);
        }
        for malformed in invalid {
            assert!(matches!(
                decode_operation(&malformed).map_err(ReconcilerError::from),
                Err(ReconcilerError::CorruptLedger(_))
            ));
        }
    }

    #[test]
    fn operation_record_v1_binds_only_gated_bounded_intent_provenance() {
        let intent = ObjectDigest::from_bytes([0x81; 32]);
        let bytes = encode_operation(OperationState::OwnershipPending, 1, true, Some(intent));
        assert_eq!(bytes[0], RECORD_VERSION_V1);
        assert_eq!(&bytes[8..], intent.as_bytes());
        assert_eq!(
            decode_operation(&bytes).unwrap().runtime_intent_digest(),
            Some(intent)
        );

        let without_intent = encode_operation(OperationState::OwnershipPending, 1, true, None);
        assert_eq!(
            decode_operation(&without_intent)
                .unwrap()
                .runtime_intent_digest(),
            None
        );

        assert!(
            decode_operation(&encode_operation(
                OperationState::Accepted,
                4093,
                false,
                None,
            ))
            .is_ok()
        );
        assert!(
            decode_operation(&encode_operation(
                OperationState::OwnershipPending,
                4092,
                true,
                None,
            ))
            .is_ok()
        );
        assert!(
            decode_operation(&encode_operation(
                OperationState::OwnershipPending,
                4093,
                true,
                None,
            ))
            .is_err()
        );
        assert!(
            decode_operation(&encode_operation(
                OperationState::OwnershipPending,
                4091,
                true,
                Some(intent),
            ))
            .is_ok()
        );

        for malformed in [
            encode_operation(OperationState::OwnershipPending, 1, false, None),
            encode_operation(OperationState::Accepted, 1, false, Some(intent)),
            encode_operation(OperationState::OwnershipPending, 4092, true, Some(intent)),
        ] {
            assert!(decode_operation(&malformed).is_err());
        }
    }

    #[test]
    fn public_operation_v2_survives_restart_and_tracks_atomic_progress() {
        use aos_sandbox_protocol::public_api::{
            CheckedOperationObservationV1,
            CheckedOperationPhaseV1,
            CheckedOperationResourceV1,
            PublicOperationMethodV1,
        };

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let plan = operation()
            .with_public_operation(
                PublicOperationAdmissionV1::new(
                    PublicOperationMethodV1::StartSandbox,
                    7,
                    [0xa1; 16],
                    100,
                    public_operation_authorization(),
                )
                .unwrap(),
            )
            .unwrap();
        let operation_id = plan.operation_id();
        let mut reconciler = Reconciler::new(journal, Executor::default());

        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Replay(operation_id)
        );
        let mismatched_scope = PublicOperationAuthorizationV1::new(
            ProjectId::from_bytes([0x91; 16]),
            ResourceKind::Sandbox,
            Selector::Resource {
                resource: ResourceId::from_bytes([0x93; 16]),
            },
        )
        .unwrap();
        let mismatched_plan = operation()
            .with_public_operation(
                PublicOperationAdmissionV1::new(
                    PublicOperationMethodV1::StartSandbox,
                    7,
                    [0xa1; 16],
                    100,
                    mismatched_scope,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.accept(&mismatched_plan),
            Err(ReconcilerError::IdempotencyConflict)
        ));
        assert_eq!(
            reconciler
                .public_operation_authorization(operation_id)
                .unwrap(),
            Some(public_operation_authorization())
        );
        let accepted = reconciler.public_operation(operation_id).unwrap().unwrap();
        let accepted_version = accepted.resource_version.clone();
        CheckedOperationResourceV1::try_from(accepted.clone()).unwrap();
        let checked = CheckedOperationObservationV1::try_from(accepted).unwrap();
        assert_eq!(
            checked.resource().phase(),
            CheckedOperationPhaseV1::Committed
        );
        assert_eq!(checked.resource().progress(), (0, 2));
        assert_eq!(checked.observation_sequence(), 1);
        assert!(!checked.resource().cancelable());

        assert!(matches!(
            reconciler.reconcile_once(operation_id),
            Err(ReconcilerError::PublicOperationClock)
        ));
        assert_eq!(
            reconciler
                .public_operation(operation_id)
                .unwrap()
                .unwrap()
                .resource_version,
            accepted_version
        );

        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 101).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 102).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        let first_applied = reconciler.public_operation(operation_id).unwrap().unwrap();
        let checked = CheckedOperationObservationV1::try_from(first_applied).unwrap();
        assert_eq!(checked.resource().progress(), (1, 2));
        assert_eq!(checked.observation_sequence(), 3);

        drop(reconciler);
        let journal = protected_runtime_journal(&directory);
        let mut reopened = Reconciler::new(journal, Executor::default());
        assert_eq!(
            reopened
                .public_operation_authorization(operation_id)
                .unwrap(),
            Some(public_operation_authorization())
        );
        let recovered = reopened.public_operation(operation_id).unwrap().unwrap();
        let checked = CheckedOperationObservationV1::try_from(recovered).unwrap();
        assert_eq!(
            checked.resource().method(),
            PublicOperationMethodV1::StartSandbox
        );
        assert_eq!(checked.resource().progress(), (1, 2));
        assert_eq!(checked.observation_sequence(), 3);

        assert_eq!(
            reopened.reconcile_once_at(operation_id, 103).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reopened.reconcile_once_at(operation_id, 104).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(
            reopened.reconcile_once_at(operation_id, 105).unwrap(),
            ReconcileOutcome::Succeeded
        );
        let completed = reopened.public_operation(operation_id).unwrap().unwrap();
        let checked = CheckedOperationObservationV1::try_from(completed).unwrap();
        assert_eq!(
            checked.resource().phase(),
            CheckedOperationPhaseV1::Succeeded
        );
        assert_eq!(checked.resource().progress(), (2, 2));
        assert_eq!(checked.observation_sequence(), 6);
        assert_eq!(
            checked
                .resource()
                .as_proto()
                .completed_at
                .as_option()
                .unwrap()
                .seconds,
            105
        );
    }

    #[test]
    fn controller_cancellation_receipt_projects_canceled_terminal_state() {
        use aos_sandbox_protocol::public_api::{
            CheckedOperationObservationV1,
            CheckedOperationPhaseV1,
        };

        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let plan = cancelable_controller_operation();
        let operation_id = plan.operation_id();
        let mut reconciler = Reconciler::new(journal, CanceledControllerExecutor);

        reconciler.accept(&plan).unwrap();
        let accepted = reconciler.public_operation(operation_id).unwrap().unwrap();
        let accepted = CheckedOperationObservationV1::try_from(accepted).unwrap();
        assert_eq!(
            accepted.resource().phase(),
            CheckedOperationPhaseV1::Accepted
        );
        assert!(accepted.resource().cancelable());

        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 101).unwrap(),
            ReconcileOutcome::Progressed
        );
        let applying = reconciler.public_operation(operation_id).unwrap().unwrap();
        let applying = CheckedOperationObservationV1::try_from(applying).unwrap();
        assert_eq!(
            applying.resource().phase(),
            CheckedOperationPhaseV1::Preparing
        );
        assert!(!applying.resource().cancelable());

        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 102).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 103).unwrap(),
            ReconcileOutcome::CanceledBeforeCommit
        );
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 104).unwrap(),
            ReconcileOutcome::CanceledBeforeCommit
        );

        let canceled = reconciler.public_operation(operation_id).unwrap().unwrap();
        let canceled = CheckedOperationObservationV1::try_from(canceled).unwrap();
        assert_eq!(
            canceled.resource().phase(),
            CheckedOperationPhaseV1::CanceledBeforeCommit
        );
        assert_eq!(canceled.resource().progress(), (1, 1));
        assert!(!canceled.resource().cancelable());
        assert_eq!(
            canceled
                .resource()
                .as_proto()
                .completed_at
                .as_option()
                .unwrap()
                .seconds,
            103
        );
    }

    #[test]
    fn closed_create_planner_rejoins_prepared_and_cold_terminal_rows() {
        use aos_sandbox_protocol::host_execution_no_apply::{
            BeforeArgumentNoApplySourceDataV2, BeforeArgumentNoApplySourceFieldsV2,
            ClosedBeforeArgumentNoApplyRecordFieldsV2, ClosedBeforeArgumentNoApplyRecordV2,
            closed_controller::{ClosedCreateFailureIdentityDataV2, ClosedCreateFailurePrepareDataV2},
        };

        let directory = TestDirectory::new();
        let (accepted, old_marker) = failed_create_fixture();
        let old = old_marker.fields();
        let operation = accepted.operation_id();
        let source = BeforeArgumentNoApplySourceDataV2::new(BeforeArgumentNoApplySourceFieldsV2 {
            create_operation: operation.into_bytes(),
            execution: old.execution_id,
            sandbox: [0xd3; 16],
            incarnation: [0xd4; 16],
            node: [0xd5; 16],
            host_boot: old.host_boot_id,
            assignment_epoch: 1,
            desired_generation: 1,
            accepted_request_digest: [0xa5; 32],
            assignment_digest: [0xb1; 32],
        })
        .unwrap();
        let marker =
            ClosedBeforeArgumentNoApplyRecordV2::new(ClosedBeforeArgumentNoApplyRecordFieldsV2 {
                source,
                terminal_request: [0xb2; 16],
                terminal_session: [0xb3; 32],
                signed_terminal_request: [0xb4; 32],
                runtime_handle: [0xb5; 32],
                execution_store: [0xb6; 32],
                observed_preclose_cut: [0xb7; 32],
                observed_epoch: 1,
                commit_sequence: 3,
            })
            .unwrap();
        let archive = ObjectDigest::from_bytes([0xb8; 32]);
        let terminal = ObjectDigest::from_bytes([0xb9; 32]);
        let mut reconciler = applying_failed_create_reconciler(&directory, &accepted);
        let initial = plan_closed_create_failure_rows_data_v2(
            &reconciler.journal,
            marker,
            archive,
            terminal,
            102,
        )
        .unwrap();
        assert!(initial.prepared_data_v2().is_none());
        assert!(!initial.settled_data_v2());
        let (predecessor, successor) = initial.row_digests_data_v2();
        let prepare = ClosedCreateFailurePrepareDataV2 {
            operation,
            identity: ClosedCreateFailureIdentityDataV2 {
                marker,
                terminal_archive: archive,
                signed_terminal: terminal,
            },
            root_floor: ObjectDigest::from_bytes([0xba; 32]),
            root_sequence: 1,
            wall_seconds: 102,
            predecessor: predecessor.map(ObjectDigest::from_bytes),
            successor: successor.map(ObjectDigest::from_bytes),
        };

        let prepare_rows = vec![JournalRecord::put(
            RecordNamespace::ControllerCreateFailurePrepare,
            operation.into_bytes().to_vec(),
            prepare.encode_canonical(),
        )];
        assert!(matches!(reconciler.commit_records(prepare_rows.clone()),
            Err(ReconcilerError::Journal(JournalError::ProtectedBoundary))));
        let Reconciler { journal, .. } = reconciler;
        journal.append_closed_no_apply_planner_fixture_data_v2(
            &JournalTransaction::new([0xec; 16], prepare_rows).unwrap(),
        ).unwrap();
        let mut journal = protected_runtime_journal(&directory);
        let prepared = plan_closed_create_failure_rows_data_v2(
            &journal,
            marker,
            archive,
            terminal,
            102,
        )
        .unwrap();
        assert_eq!(prepared.prepared_data_v2(), Some(prepare));
        assert!(!prepared.settled_data_v2());
        let terminal_transaction = JournalTransaction::new([0xed; 16], prepared.records_data_v2().to_vec()).unwrap();
        assert!(matches!(journal.commit(&terminal_transaction), Err(JournalError::ProtectedBoundary)));
        journal.append_closed_no_apply_planner_fixture_data_v2(&terminal_transaction).unwrap();

        let journal = protected_runtime_journal(&directory);
        let next = journal.snapshot_sequence();
        let settled =
            plan_closed_create_failure_rows_data_v2(&journal, marker, archive, terminal, 102).unwrap();
        assert!(settled.settled_data_v2());
        assert_eq!(settled.prepared_data_v2(), Some(prepare));
        assert_eq!(settled.row_digests_data_v2(), (predecessor, successor));
        assert_eq!(journal.snapshot_sequence(), next);
        assert!(
            plan_closed_create_failure_rows_data_v2(
                &journal,
                marker,
                archive,
                ObjectDigest::from_bytes([0xff; 32]),
                102,
            )
            .is_err()
        );
        assert!(
            plan_closed_create_failure_rows_data_v2(&journal, marker, archive, terminal, 103,).is_err()
        );
        let mut cold = Reconciler::new(journal, Executor::default());
        assert_eq!(cold.reconcile_once_at(operation, 104).unwrap(), ReconcileOutcome::CreateFailurePending);
        assert_eq!(cold.journal.snapshot_sequence(), next);
        assert_eq!(cold.executor.apply_calls, 0);
    }

    #[test]
    fn failed_create_settlement_is_atomic_terminal_and_replays_exactly() {
        use aos_sandbox_api::aos::sandbox::v1::{ExecutionPhase, OperationPhase};
        use sha2::{Digest as _, Sha256};

        use aos_sandbox_protocol::public_api::projection::{
            PublicProjectionKindV1, PublicProjectionResourceV1,
        };
        use crate::controller_service::public_projection::{PublicProjectionStoreV1};

        let directory = TestDirectory::new();
        let (plan, marker) = failed_create_fixture();
        let operation_id = plan.operation_id();
        let execution_id = marker.fields().execution_id;
        let mut reconciler = applying_failed_create_reconciler(&directory, &plan);

        let proof = create_failure::CreateFailureSettlementProofV1::test_only(marker);
        let _lost_prepared = reconciler
            .prepare_create_failed_before_commit(operation_id, proof, 102)
            .unwrap();
        drop(reconciler);

        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert_eq!(
            reconciler.reconcile_once_at(operation_id, 102).unwrap(),
            ReconcileOutcome::CreateFailurePending
        );
        assert!(
            reconciler
                .prepare_create_failed_before_commit(
                    operation_id,
                    create_failure::CreateFailureSettlementProofV1::test_only(marker),
                    103,
                )
                .is_err()
        );
        let mut foreign_fields = marker.fields();
        foreign_fields.terminal_request_id = [0xee; 16];
        let foreign_marker =
            aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV1::new(
                foreign_fields,
            )
            .unwrap();
        assert!(
            reconciler
                .prepare_create_failed_before_commit(
                    operation_id,
                    create_failure::CreateFailureSettlementProofV1::test_only(foreign_marker),
                    102,
                )
                .is_err()
        );
        let original_effect_bytes = reconciler
            .journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
            .unwrap()
            .to_vec();
        let mut changed_effect = decode_effect(&original_effect_bytes).unwrap().into_parts();
        let EffectState::Applying { diagnostic, .. } = &mut changed_effect.1 else {
            panic!("expected applying effect");
        };
        *diagnostic = "changed after Controller prepare".to_owned();
        let changed_effect = EffectLedgerRecord::from_parts(changed_effect);
        reconciler
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(operation_id, 0).to_vec(),
                encode_effect(&changed_effect).unwrap(),
            )])
            .unwrap();
        assert!(
            reconciler
                .recover_create_failure_settlement_ack_v1(operation_id)
                .is_err()
        );
        drop(reconciler);
        let mut reconciler =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert!(reconciler.public_operation(operation_id).is_err());
        reconciler
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(operation_id, 0).to_vec(),
                original_effect_bytes,
            )])
            .unwrap();
        reconciler.ledger_validated = false;
        let prepared = reconciler
            .prepare_create_failed_before_commit(
                operation_id,
                create_failure::CreateFailureSettlementProofV1::test_only(marker),
                102,
            )
            .unwrap();
        assert!(
            reconciler
                .recover_create_failure_settlement_ack_v1(operation_id)
                .unwrap()
                .is_none()
        );
        let acknowledgment = reconciler
            .settle_create_failed_before_commit(prepared)
            .unwrap();
        assert_eq!(acknowledgment.operation_id, operation_id);
        assert_eq!(
            acknowledgment.controller_floor,
            create_failure::test_prepare_floor_digest(&reconciler.journal, operation_id)
        );
        assert_ne!(acknowledgment.controller_cas.as_bytes(), &[0; 32]);
        assert_eq!(
            reconciler
                .recover_create_failure_settlement_ack_v1(operation_id)
                .unwrap(),
            Some(acknowledgment)
        );
        assert!(
            reconciler
                .prepare_create_failed_before_commit(
                    operation_id,
                    create_failure::CreateFailureSettlementProofV1::test_only(marker),
                    103,
                )
                .is_err()
        );
        let execution = PublicProjectionStoreV1::new(&reconciler.journal)
            .get(PublicProjectionKindV1::Execution, execution_id)
            .unwrap()
            .unwrap();
        let PublicProjectionResourceV1::Execution(execution) = execution.resource() else {
            panic!("expected execution projection");
        };
        assert_eq!(
            execution.phase.as_known(),
            Some(ExecutionPhase::EXECUTION_PHASE_FAILED)
        );
        assert_eq!(execution.observation_sequence, 2);
        assert!(execution.result.as_option().is_none());

        drop(reconciler);
        let mut recovered =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert_eq!(
            recovered
                .recover_create_failure_settlement_ack_v1(operation_id)
                .unwrap(),
            Some(acknowledgment)
        );
        let resource = recovered.public_operation(operation_id).unwrap().unwrap();
        assert_eq!(
            resource.phase.as_known(),
            Some(OperationPhase::OPERATION_PHASE_FAILED_BEFORE_COMMIT)
        );
        assert_eq!(resource.progress.as_option().unwrap().completed_units, 0);
        assert_eq!(
            recovered.reconcile_once_at(operation_id, 104).unwrap(),
            ReconcileOutcome::FailedBeforeCommit
        );
        assert!(
            recovered
                .validated_unfinished_operation()
                .unwrap()
                .is_none()
        );

        let original_effect = decode_effect(
            recovered
                .journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
                .unwrap(),
        )
        .unwrap();
        let EffectState::Applied {
            receipt: original_receipt,
            ..
        } = original_effect.state()
        else {
            panic!("expected terminal receipt");
        };
        let original_receipt =
            create_failure::CreateFailureReceiptV1::decode(original_receipt.as_bytes())
                .unwrap()
                .unwrap();
        let mut foreign_fields = marker.fields();
        foreign_fields.create_operation_id = [0xee; 16];
        let foreign_marker =
            aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV1::new(
                foreign_fields,
            )
            .unwrap();
        let wrong_marker = create_failure::CreateFailureReceiptV1 {
            marker: foreign_marker,
            ..original_receipt
        };
        for forged_receipt in [wrong_marker.encode(), {
            let mut unknown_marker = original_receipt.encode();
            unknown_marker[108] ^= 1;
            let checksum_start = unknown_marker.len() - 32;
            let checksum = Sha256::new()
                .chain_update(b"aos.sandbox.create-failed-before-commit.v1\0")
                .chain_update(&unknown_marker[..checksum_start])
                .finalize();
            unknown_marker[checksum_start..].copy_from_slice(&checksum);
            unknown_marker
        }] {
            let mut forged_effect = original_effect.clone();
            forged_effect = {
                let replacement = EffectState::Applied {
                    attempt: 1,
                    receipt: EffectReceipt::from_bytes_unchecked(forged_receipt),
                };
                let mut parts = forged_effect.into_parts();
                parts.1 = replacement;
                EffectLedgerRecord::from_parts(parts)
            };
            recovered
                .commit_records(vec![JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(operation_id, 0).to_vec(),
                    encode_effect(&forged_effect).unwrap(),
                )])
                .unwrap();
            recovered.ledger_validated = false;
            assert!(recovered.public_operation(operation_id).is_err());

            recovered
                .commit_records(vec![JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(operation_id, 0).to_vec(),
                    encode_effect(&original_effect).unwrap(),
                )])
                .unwrap();
            recovered.ledger_validated = false;
            assert!(recovered.public_operation(operation_id).is_ok());
        }

        let terminal_operation = recovered.load_operation(operation_id).unwrap();
        let altered_operation = transition_operation(
            terminal_operation,
            OperationState::FailedBeforeCommit,
            Some(105),
        )
        .unwrap();
        recovered
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(altered_operation),
            )])
            .unwrap();
        recovered.ledger_validated = false;
        assert!(recovered.public_operation(operation_id).is_err());
        recovered
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::Operation,
                operation_id.into_bytes().to_vec(),
                encode_operation_record(terminal_operation),
            )])
            .unwrap();
        recovered.ledger_validated = false;
        assert!(recovered.public_operation(operation_id).is_ok());

        let floor_bytes = recovered
            .journal
            .get(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation_id.as_bytes(),
            )
            .unwrap()
            .to_vec();
        recovered
            .commit_records(vec![JournalRecord::delete(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation_id.into_bytes().to_vec(),
            )])
            .unwrap();
        drop(recovered);
        let mut recovered =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert!(recovered.public_operation(operation_id).is_err());
        recovered
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation_id.into_bytes().to_vec(),
                floor_bytes,
            )])
            .unwrap();
        recovered.ledger_validated = false;
        assert!(recovered.public_operation(operation_id).is_ok());

        let foreign_floor_key = [0xee; 16];
        let copied_floor = recovered
            .journal
            .get(
                RecordNamespace::ControllerCreateFailurePrepare,
                operation_id.as_bytes(),
            )
            .unwrap()
            .to_vec();
        recovered
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                foreign_floor_key.to_vec(),
                copied_floor,
            )])
            .unwrap();
        drop(recovered);
        let mut recovered =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert!(recovered.public_operation(operation_id).is_err());
        recovered
            .commit_records(vec![JournalRecord::delete(
                RecordNamespace::ControllerCreateFailurePrepare,
                foreign_floor_key.to_vec(),
            )])
            .unwrap();
        recovered.ledger_validated = false;
        assert!(recovered.public_operation(operation_id).is_ok());

        recovered
            .commit_records(vec![JournalRecord::delete(
                RecordNamespace::DesiredState,
                plan.desired_key.clone(),
            )])
            .unwrap();
        recovered.ledger_validated = false;
        assert!(recovered.public_operation(operation_id).is_err());
    }

    #[test]
    fn failed_create_floor_and_host_phases_survive_independent_cold_replay() {
        use aos_sandbox_model::ExecutionId;

        use crate::runtime_execution::no_apply_settlement::{
            ControllerAssertedSettlementArchivesV1, HostObservedSettlementIdentityV1,
            HostSettlementRecordV1, HostSettlementStageV1, lease_key, validate_history,
        };

        let controller_directory = TestDirectory::new();
        let host_directory = TestDirectory::new();
        let (plan, marker) = failed_create_fixture();
        let operation_id = plan.operation_id();
        let execution = ExecutionId::from_bytes(marker.fields().execution_id);
        let mut host = protected_runtime_journal(&host_directory);
        let marker_sequence = commit_protected_effect_record(
            &mut host,
            0xe1,
            [b'n']
                .into_iter()
                .chain(marker.fields().execution_id)
                .collect(),
            marker.encode_canonical().to_vec(),
        );
        let observed = HostObservedSettlementIdentityV1::from_marker_and_handoff(
            marker,
            ObjectDigest::from_bytes([0xe2; 32]),
        )
        .unwrap();
        let archives = ControllerAssertedSettlementArchivesV1::new(
            ObjectDigest::from_bytes([0xa1; 32]),
            ObjectDigest::from_bytes([0xa2; 32]),
        )
        .unwrap();
        let preliminary = HostSettlementRecordV1::preliminary(
            observed,
            archives,
            marker_sequence + 1,
            ObjectDigest::from_bytes([0xa3; 32]),
            [0xe3; 32],
            [0xe4; 16],
            marker_sequence + 3,
        )
        .unwrap();
        let preliminary_sequence = commit_protected_effect_record(
            &mut host,
            0xe5,
            lease_key(execution, HostSettlementStageV1::Preliminary),
            preliminary.encode_canonical().to_vec(),
        );
        assert_eq!(preliminary_sequence, preliminary.commit_sequence);

        let mut controller = applying_failed_create_reconciler(&controller_directory, &plan);
        assert!(!create_failure::has_prepare_floor(&controller.journal, operation_id).unwrap());
        assert_eq!(
            validate_history(
                marker,
                Some(preliminary),
                None,
                None,
                preliminary.commit_sequence
            ),
            Ok(Some(HostSettlementStageV1::Preliminary))
        );

        let proof = create_failure::CreateFailureSettlementProofV1::test_only(marker)
            .with_test_lease(preliminary.digest())
            .with_test_lease_epoch(preliminary.epoch);
        let _lost_prepared = controller
            .prepare_create_failed_before_commit(operation_id, proof, 102)
            .unwrap();
        drop(controller);
        drop(host);

        let mut controller = Reconciler::new(
            protected_runtime_journal(&controller_directory),
            Executor::default(),
        );
        let mut host = protected_runtime_journal(&host_directory);
        let original = HostSettlementRecordV1::decode_canonical(
            host.get(
                RecordNamespace::Effect,
                &lease_key(execution, HostSettlementStageV1::Preliminary),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(original, preliminary);
        assert_eq!(
            controller.reconcile_once_at(operation_id, 102).unwrap(),
            ReconcileOutcome::CreateFailurePending
        );
        assert!(create_failure::has_prepare_floor(&controller.journal, operation_id).unwrap());
        let floor_digest =
            create_failure::test_prepare_floor_digest(&controller.journal, operation_id);
        let sealed = preliminary
            .seal_floor(floor_digest, preliminary_sequence + 3)
            .unwrap();
        let sealed_sequence = commit_protected_effect_record(
            &mut host,
            0xe6,
            lease_key(execution, HostSettlementStageV1::FloorSealed),
            sealed.encode_canonical().to_vec(),
        );
        assert_eq!(sealed_sequence, sealed.commit_sequence);
        drop(host);
        drop(controller);

        let mut controller = Reconciler::new(
            protected_runtime_journal(&controller_directory),
            Executor::default(),
        );
        let mut host = protected_runtime_journal(&host_directory);
        let reopened_sealed = HostSettlementRecordV1::decode_canonical(
            host.get(
                RecordNamespace::Effect,
                &lease_key(execution, HostSettlementStageV1::FloorSealed),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reopened_sealed, sealed);
        assert_eq!(
            controller.reconcile_once_at(operation_id, 103).unwrap(),
            ReconcileOutcome::CreateFailurePending
        );
        assert!(
            create_failure::test_historical_host_floor_join(
                &controller.journal,
                operation_id,
                preliminary,
                sealed,
                sealed_sequence,
            )
            .is_ok()
        );

        let foreign_floor = sealed.with_test_controller_floor(ObjectDigest::from_bytes([0xff; 32]));
        assert!(
            create_failure::test_historical_host_floor_join(
                &controller.journal,
                operation_id,
                preliminary,
                foreign_floor,
                sealed_sequence,
            )
            .is_err()
        );
        let foreign_archives = ControllerAssertedSettlementArchivesV1::new(
            ObjectDigest::from_bytes([0xfa; 32]),
            archives.signed_terminal_outcome,
        )
        .unwrap();
        let foreign_preliminary = preliminary.with_test_archives(foreign_archives);
        let foreign_sealed = foreign_preliminary
            .seal_floor(floor_digest, sealed_sequence)
            .unwrap();
        assert!(
            create_failure::test_historical_host_floor_join(
                &controller.journal,
                operation_id,
                foreign_preliminary,
                foreign_sealed,
                sealed_sequence,
            )
            .is_err()
        );

        let prepared = controller
            .prepare_create_failed_before_commit(operation_id, proof, 102)
            .unwrap();
        let ack = controller
            .settle_create_failed_before_commit(prepared)
            .unwrap();
        let canonical_ack = ack.encode_canonical();
        assert_eq!(
            create_failure::ControllerCreateFailureSettlementAckV1::decode_canonical(
                &canonical_ack
            )
            .unwrap(),
            ack,
        );
        let mut altered_ack = canonical_ack;
        altered_ack[92] ^= 1;
        assert!(
            create_failure::ControllerCreateFailureSettlementAckV1::decode_canonical(&altered_ack)
                .is_err()
        );
        let retained = sealed
            .retain_ack(ack.controller_cas, sealed_sequence + 3)
            .unwrap();
        let retained_sequence = commit_protected_effect_record(
            &mut host,
            0xe9,
            lease_key(execution, HostSettlementStageV1::AckRetained),
            retained.encode_canonical().to_vec(),
        );
        assert_eq!(retained_sequence, retained.commit_sequence);
        drop(host);
        drop(controller);

        let controller = Reconciler::new(
            protected_runtime_journal(&controller_directory),
            Executor::default(),
        );
        let mut host = protected_runtime_journal(&host_directory);
        assert_eq!(
            HostSettlementRecordV1::decode_canonical(
                host.get(
                    RecordNamespace::Effect,
                    &lease_key(execution, HostSettlementStageV1::AckRetained),
                )
                .unwrap(),
            )
            .unwrap(),
            retained,
        );
        let ack = controller
            .recover_create_failure_settlement_ack_v1(operation_id)
            .unwrap()
            .unwrap();
        assert!(
            ack.validate_host_retention(
                &controller.journal,
                preliminary,
                sealed,
                retained,
                retained_sequence,
            )
            .is_ok()
        );
        assert!(
            ack.validate_host_retention(
                &controller.journal,
                preliminary,
                sealed,
                retained.with_test_controller_cas(ObjectDigest::from_bytes([0xfe; 32])),
                retained_sequence,
            )
            .is_err()
        );
        assert!(
            ack.validate_host_retention(
                &controller.journal,
                preliminary,
                sealed,
                retained,
                retained_sequence - 1,
            )
            .is_err()
        );
        assert!(validate_history(marker, None, Some(sealed), None, sealed_sequence).is_err());
        assert!(
            validate_history(
                marker,
                Some(preliminary),
                None,
                Some(sealed),
                sealed_sequence
            )
            .is_err()
        );

        commit_protected_effect_record(
            &mut host,
            0xe7,
            lease_key(execution, HostSettlementStageV1::FloorSealed),
            foreign_floor.encode_canonical().to_vec(),
        );
        drop(host);
        drop(controller);

        let mut controller = protected_runtime_journal(&controller_directory);
        let host = protected_runtime_journal(&host_directory);
        let hostile_sealed = HostSettlementRecordV1::decode_canonical(
            host.get(
                RecordNamespace::Effect,
                &lease_key(execution, HostSettlementStageV1::FloorSealed),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            create_failure::test_historical_host_floor_join(
                &controller,
                operation_id,
                preliminary,
                hostile_sealed,
                sealed_sequence + 3,
            )
            .is_err()
        );
        controller
            .commit(
                &JournalTransaction::new(
                    [0xe8; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::ControllerCreateFailurePrepare,
                        operation_id.into_bytes().to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(controller);

        let missing_floor = protected_runtime_journal(&controller_directory);
        assert!(
            create_failure::test_historical_host_floor_join(
                &missing_floor,
                operation_id,
                preliminary,
                sealed,
                sealed_sequence,
            )
            .is_err()
        );
    }

    #[test]
    fn execution_family_keeps_create_facade_and_rejects_unrelated_accepted_start() {
        let directory = TestDirectory::new();
        let (create, _) = failed_create_fixture();
        let operation = create.operation_id();
        let mut reconciler = Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        reconciler.accept(&create).unwrap();

        assert_eq!(accepted_create_execution_effect_from_journal_v1(&reconciler.journal, operation)
            .unwrap(), accepted_execution_effect_from_journal_v3(&reconciler.journal, operation).unwrap());
        assert!(accepted_execution_effect_from_journal_v3(&reconciler.journal, operation)
            .unwrap().is_some());
        drop(reconciler);

        let other_directory = TestDirectory::new();
        let start = cancelable_controller_operation();
        let operation = start.operation_id();
        let mut other = Reconciler::new(protected_runtime_journal(&other_directory), Executor::default());
        other.accept(&start).unwrap();
        assert!(accepted_execution_effect_from_journal_v3(&other.journal, operation).unwrap().is_none());
        assert!(accepted_create_execution_effect_from_journal_v1(&other.journal, operation).unwrap().is_none());
    }

    #[test]
    fn execution_family_reopens_control_and_cancel_without_widening_create_reader() {
        use aos_sandbox_api::aos::sandbox::v1::{CancelExecutionRequest, ExecutionControlAction,
            ExecutionControlRequest, ExecutionSignal};
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1 as Method;
        use crate::cli_model::{PublicApiAuditMethodV1 as Audit, PublicMutationRequestV1};

        for cancel in [false, true] {
            let directory = TestDirectory::new();
            let (mut plan, marker) = failed_create_fixture();
            let original = plan.effects[0].public_mutation_context().unwrap().unwrap();
            let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Exec(create) =
                original.validated_request().unwrap() else { panic!("fixture has another request") };
            let mutation = create.mutation;
            let (method, audit, bytes) = if cancel {
                (Method::CancelExecution, Audit::CancelExecution, CancelExecutionRequest {
                    execution_id: marker.fields().execution_id.to_vec(), mutation,
                    ..Default::default()
                }.encode_to_vec())
            } else {
                (Method::ControlExecution, Audit::ControlExecution, ExecutionControlRequest {
                    execution_id: marker.fields().execution_id.to_vec(), mutation,
                    action: ExecutionControlAction::EXECUTION_CONTROL_ACTION_SIGNAL.into(),
                    signal: ExecutionSignal::EXECUTION_SIGNAL_TERMINATE.into(),
                    ..Default::default()
                }.encode_to_vec())
            };
            let envelope = PublicMutationRequestV1::new(audit, &bytes).unwrap().encode();
            plan.effects = vec![PublicMutationEffectV1::new(original.caller(), original.project(),
                100, envelope).unwrap().into_plan(method).unwrap()];
            plan.public_operation = Some(PublicOperationAdmissionV1::new(method, 1,
                [0xa6; 16], 100, PublicOperationAuthorizationV1::new(original.project(),
                    ResourceKind::Execution, Selector::Resource {
                        resource: ResourceId::from_bytes(marker.fields().execution_id),
                    }).unwrap()).unwrap());
            let operation = plan.operation_id();
            let mut reconciler = Reconciler::new(protected_runtime_journal(&directory), Executor::default());
            reconciler.accept(&plan).unwrap();
            let expected = plan.effects[0].public_mutation_context().unwrap().unwrap();

            assert_eq!(accepted_execution_effect_from_journal_v3(&reconciler.journal, operation)
                .unwrap(), Some(expected.clone()));
            assert!(accepted_create_execution_effect_from_journal_v1(&reconciler.journal, operation)
                .unwrap().is_none());
            drop(reconciler);

            let reopened = protected_runtime_journal(&directory);
            assert_eq!(accepted_execution_effect_from_journal_v3(&reopened, operation)
                .unwrap(), Some(expected));
            assert!(accepted_create_execution_effect_from_journal_v1(&reopened, operation)
                .unwrap().is_none());
        }
    }

    #[test]
    fn failed_create_state_rejects_generic_and_cancel_receipts() {
        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let (plan, _) = failed_create_fixture();
        let operation_id = plan.operation_id();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();
        let operation = reconciler.load_operation(operation_id).unwrap();
        let effect_bytes = reconciler
            .journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
            .unwrap();
        let mut effect = decode_effect(effect_bytes).unwrap();
        let failed =
            transition_operation(operation, OperationState::FailedBeforeCommit, Some(102)).unwrap();

        for receipt in [
            EffectReceipt::new(vec![1]).unwrap(),
            EffectReceipt::canceled_before_commit(ObjectDigest::from_bytes([2; 32])),
        ] {
            effect = {
                let replacement = EffectState::Applied {
                    attempt: 1,
                    receipt,
                };
                let mut parts = effect.into_parts();
                parts.1 = replacement;
                EffectLedgerRecord::from_parts(parts)
            };
            assert!(
                create_failure::validate_failed_create_operation(
                    &reconciler.journal,
                    operation_id,
                    failed,
                )
                .is_err()
            );
            let records = vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(operation_id, 0).to_vec(),
                    encode_effect(&effect).unwrap(),
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    operation_id.into_bytes().to_vec(),
                    encode_operation_record(failed),
                ),
            ];
            reconciler.commit_records(records).unwrap();
            assert!(reconciler.public_operation(operation_id).is_err());
        }
    }

    #[test]
    fn multi_effect_cold_replay_rejects_failed_create_receipt_on_later_step() {
        let directory = TestDirectory::new();
        let journal = protected_runtime_journal(&directory);
        let plan = operation();
        let operation_id = plan.operation_id();
        let (_, marker) = failed_create_fixture();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        reconciler.accept(&plan).unwrap();

        let effect_bytes = reconciler
            .journal
            .get(RecordNamespace::Effect, &effect_key(operation_id, 1))
            .unwrap();
        let mut later_effect = decode_effect(effect_bytes).unwrap();
        let proof = create_failure::CreateFailureSettlementProofV1::test_only(marker);
        let receipt = proof.into_receipt(
            ObjectDigest::from_bytes([0xc1; 32]),
            ObjectDigest::from_bytes([0xc2; 32]),
            ObjectDigest::from_bytes([0xc3; 32]),
            1,
            1,
            100,
        );
        later_effect = {
            let replacement = EffectState::Applied {
                attempt: 1,
                receipt: EffectReceipt::from_bytes_unchecked(receipt.encode()),
            };
            let mut parts = later_effect.into_parts();
            parts.1 = replacement;
            EffectLedgerRecord::from_parts(parts)
        };
        reconciler
            .commit_records(vec![JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(operation_id, 1).to_vec(),
                encode_effect(&later_effect).unwrap(),
            )])
            .unwrap();
        let operation = reconciler.load_operation(operation_id).unwrap();
        assert_eq!(operation.effect_count(), 2);
        assert!(
            create_failure::validate_failed_create_operation(
                &reconciler.journal,
                operation_id,
                operation,
            )
            .is_err()
        );

        drop(reconciler);
        let mut recovered =
            Reconciler::new(protected_runtime_journal(&directory), Executor::default());
        assert!(recovered.validated_unfinished_operation().is_err());
    }

    #[test]
    fn public_operation_v2_rejects_corrupt_metadata_and_backward_time() {
        use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

        let metadata = PublicOperationAdmissionV1::new(
            PublicOperationMethodV1::CreateView,
            9,
            [0xb1; 16],
            200,
            public_operation_authorization(),
        )
        .unwrap()
        .durable();
        let operation =
            OperationRecord::new(OperationState::Accepted, 1, false, None, Some(metadata));
        let bytes = encode_operation_record(operation);
        assert_eq!(bytes.len(), OPERATION_RECORD_V2_BYTES);
        assert_eq!(decode_operation(&bytes).unwrap(), operation);

        let mut reserved = bytes.clone();
        reserved[41] = 1;
        assert!(matches!(
            decode_operation(&reserved).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(_))
        ));

        assert!(matches!(
            transition_operation(operation, OperationState::Applying, Some(199)),
            Err(ReconcilerError::PublicOperationClock)
        ));

        let authorization = public_operation_authorization();
        let mut authorization_bytes = authorization.encode().unwrap();
        assert_eq!(
            PublicOperationAuthorizationV1::decode(&authorization_bytes).unwrap(),
            authorization
        );
        let last = authorization_bytes.len() - 1;
        authorization_bytes[last] ^= 1;
        assert!(matches!(
            PublicOperationAuthorizationV1::decode(&authorization_bytes)
                .map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(_))
        ));
    }

    #[test]
    fn ownership_pending_is_skipped_without_starving_ready_work() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gated = gated_operation();
        let mut ready = operation();
        ready.operation_id = OperationId::from_bytes([0x91; 16]);
        ready.idempotency_key = IdempotencyKey::new(b"ready-request".to_vec()).unwrap();
        ready.desired_key = b"ready-sandbox".to_vec();
        reconciler.accept(&gated).unwrap();
        reconciler.accept(&ready).unwrap();

        for expected in [
            ReconcileOutcome::Progressed,
            ReconcileOutcome::EffectApplied,
            ReconcileOutcome::Progressed,
            ReconcileOutcome::EffectApplied,
            ReconcileOutcome::Succeeded,
        ] {
            let (operation, outcome) = reconciler.reconcile_next().unwrap().unwrap();
            assert_eq!(operation, ready.operation_id());
            assert_eq!(outcome, expected);
        }
        assert!(reconciler.reconcile_next().unwrap().is_none());
        assert_eq!(reconciler.executor.apply_calls, 2);
    }

    #[test]
    fn ownership_gate_corruption_missing_and_extra_pending_fail_closed() {
        for corruption in 0..4 {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (gated, draft, _) = gated_operation_with_publication(1);
            reconciler.accept(&gated).unwrap();
            let record = match corruption {
                0 => JournalRecord::delete(
                    RecordNamespace::OwnershipGate,
                    gated.operation_id().into_bytes().to_vec(),
                ),
                1 => {
                    let mut bytes = reconciler
                        .journal
                        .get(
                            RecordNamespace::OwnershipGate,
                            gated.operation_id().as_bytes(),
                        )
                        .unwrap()
                        .to_vec();
                    *bytes.last_mut().unwrap() ^= 1;
                    JournalRecord::put(
                        RecordNamespace::OwnershipGate,
                        gated.operation_id().into_bytes().to_vec(),
                        bytes,
                    )
                }
                2 => JournalRecord::put(
                    RecordNamespace::Operation,
                    gated.operation_id().into_bytes().to_vec(),
                    encode_operation(OperationState::Accepted, 1, true, None),
                ),
                3 => {
                    let mut bytes = reconciler
                        .journal
                        .get(
                            RecordNamespace::OwnershipGate,
                            gated.operation_id().as_bytes(),
                        )
                        .unwrap()
                        .to_vec();
                    let mut wrong_claim = activation_claim(&draft, 1);
                    let assignment = wrong_claim.assignment();
                    wrong_claim = OwnershipClaimV1::acquire(
                        *wrong_claim.request_id(),
                        assignment,
                        wrong_claim.desired_generation(),
                        NodeId::from_bytes([0xfe; 16]),
                        wrong_claim.requested_maximum_seconds(),
                    )
                    .unwrap();
                    bytes[116..148].copy_from_slice(wrong_claim.digest().as_bytes());
                    let idempotency_length =
                        usize::from(u16::from_be_bytes(bytes[64..66].try_into().unwrap()));
                    let key_id_length =
                        usize::from(u16::from_be_bytes(bytes[66..68].try_into().unwrap()));
                    let claim_start = 252 + idempotency_length + key_id_length;
                    bytes[claim_start..claim_start + CLAIM_BYTES]
                        .copy_from_slice(wrong_claim.canonical_bytes());
                    JournalRecord::put(
                        RecordNamespace::OwnershipGate,
                        gated.operation_id().into_bytes().to_vec(),
                        bytes,
                    )
                }
                _ => unreachable!(),
            };
            reconciler
                .journal_mut()
                .commit(&JournalTransaction::new([corruption as u8 + 1; 16], vec![record]).unwrap())
                .unwrap();
            assert!(matches!(
                reconciler.reconcile_next(),
                Err(ReconcilerError::CorruptLedger(_))
            ));
            assert_eq!(reconciler.executor.apply_calls, 0);
        }

        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gated = gated_operation();
        reconciler.accept(&gated).unwrap();
        reconciler
            .journal_mut()
            .commit(
                &JournalTransaction::new(
                    [9; 16],
                    vec![JournalRecord::delete(
                        RecordNamespace::Operation,
                        gated.operation_id().into_bytes().to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            reconciler.reconcile_next(),
            Err(ReconcilerError::CorruptLedger("orphan ownership gate"))
        ));
    }

    #[test]
    fn activation_requires_the_exact_unadvanced_planned_effect_set() {
        for corruption in 0..6 {
            let directory = TestDirectory::new();
            let (journal, _) =
                Journal::open(directory.journal(), JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let (gated, draft, prepared) = gated_operation_with_publication(1);
            reconciler.accept(&gated).unwrap();
            let effect = EffectPlan::new(
                EffectDomain::Host,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                b"arm".to_vec(),
            )
            .unwrap();
            let record = match corruption {
                0 => JournalRecord::delete(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                ),
                1 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 1).to_vec(),
                    encode_effect(&EffectLedgerRecord::from_parts((
                        effect,
                        EffectState::Planned,
                        None,
                        None,
                    )))
                    .unwrap(),
                ),
                2 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord::from_parts((
                        effect,
                        EffectState::Applying {
                            attempt: 1,
                            diagnostic: String::new(),
                        },
                        None,
                        None,
                    )))
                    .unwrap(),
                ),
                3 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord::from_parts((
                        effect,
                        EffectState::Applied {
                            attempt: 1,
                            receipt: EffectReceipt::new(b"receipt".to_vec()).unwrap(),
                        },
                        None,
                        None,
                    )))
                    .unwrap(),
                ),
                4 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord::from_parts((
                        effect,
                        EffectState::PermanentlyBlocked {
                            attempt: 1,
                            diagnostic: "blocked".to_owned(),
                        },
                        None,
                        None,
                    )))
                    .unwrap(),
                ),
                5 => JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(gated.operation_id(), 0).to_vec(),
                    encode_effect(&EffectLedgerRecord::from_parts((
                        effect,
                        EffectState::Planned,
                        None,
                        None,
                    )))
                    .unwrap(),
                ),
                _ => unreachable!(),
            };
            reconciler
                .journal_mut()
                .commit(
                    &JournalTransaction::new([corruption as u8 + 21; 16], vec![record]).unwrap(),
                )
                .unwrap();

            let activation = gate_activation(&mut reconciler, &draft, &prepared);
            let activation_error = reconciler
                .activate_ownership_gate(gated.operation_id(), activation)
                .unwrap_err();
            assert!(matches!(
                activation_error,
                ReconcilerError::CorruptLedger(_)
            ));
            assert!(
                AuthorityPublicationStore::new(reconciler.journal_mut())
                    .current(draft.manifest().manifest().sandbox())
                    .unwrap()
                    .is_none()
            );
            let recovered = reconciler.ownership_gate(gated.operation_id());
            assert!(matches!(recovered, Err(ReconcilerError::CorruptLedger(_))));
        }
    }

    #[test]
    fn ownership_gate_bounds_and_pending_backpressure_fail_before_effects() {
        let ordinary = operation();
        let (draft, _) = descriptor_free_activation_fixture(1);
        let manifest = draft.manifest();
        let semantics = manifest.manifest();
        let mismatched_claim = OwnershipClaimV1::acquire(
            [0x73; 16],
            LeaseAssignment::new(
                semantics.sandbox(),
                semantics.incarnation(),
                semantics.epoch(),
                manifest.digest(),
            )
            .unwrap(),
            semantics.desired_generation(),
            NodeId::from_bytes([0xff; 16]),
            60,
        )
        .unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                ordinary.operation_id,
                ordinary.idempotency_key.clone(),
                ordinary.request_digest,
                ordinary.desired_key.clone(),
                ordinary.desired_value.clone(),
                vec![
                    aos_sandbox_protocol::publication::bind_authority_publication_effect(
                        &draft,
                        draft.templates()[0].digest()
                    )
                    .map_err(crate::publication::AuthorityPublicationError::from)
                    .unwrap()
                ],
                mismatched_claim,
                draft.clone(),
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));
        let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
            &draft,
            draft.templates()[0].digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)
        .unwrap();
        assert!(matches!(
            OperationPlan::ownership_gated(
                ordinary.operation_id,
                ordinary.idempotency_key,
                ordinary.request_digest,
                ordinary.desired_key,
                ordinary.desired_value,
                vec![effect; MAXIMUM_GATED_EFFECTS + 1],
                activation_claim(&draft, 1),
                draft,
            ),
            Err(ReconcilerError::InvalidPlan(_))
        ));

        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let gated = gated_operation();
        reconciler.accept_bounded(&gated, 1).unwrap();
        assert_eq!(
            reconciler.accept_bounded(&gated, 1).unwrap(),
            AcceptOutcome::Replay(gated.operation_id())
        );
        assert!(matches!(
            reconciler.accept_bounded(&operation(), 1),
            Err(ReconcilerError::AdmissionBackpressure)
        ));
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn effects_are_intended_before_execution_and_complete_in_order() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        reconciler.accept(&plan).unwrap();

        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(reconciler.executor.apply_calls, 1);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Succeeded
        );
    }

    #[test]
    fn restart_observes_ambiguous_effect_without_reapplying() {
        let directory = TestDirectory::new();
        let path = directory.journal();
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::Progressed
        );
        reconciler.executor.applied.insert(
            (plan.operation_id(), 0),
            EffectReceipt::new(b"recovered".to_vec()).unwrap(),
        );
        let executor = reconciler.executor;
        drop(reconciler.journal);

        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, executor);
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
        assert_eq!(reconciler.executor.apply_calls, 0);
    }

    #[test]
    fn retryable_failure_preserves_inflight_intent() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let executor = Executor {
            failures: VecDeque::from([EffectFailure::Retryable("busy".to_string())]),
            ..Executor::default()
        };
        let mut reconciler = Reconciler::new(journal, executor);
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::RetryPending
        );
        let effect = decode_effect(
            reconciler
                .journal
                .get(RecordNamespace::Effect, &effect_key(plan.operation_id(), 0))
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            *effect.state(),
            EffectState::Applying {
                attempt: 2,
                ref diagnostic,
            } if diagnostic == "busy"
        ));
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::EffectApplied
        );
    }

    #[test]
    fn permanent_failure_blocks_effect_and_operation_atomically() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let executor = Executor {
            failures: VecDeque::from([EffectFailure::Permanent("rejected".to_string())]),
            ..Executor::default()
        };
        let mut reconciler = Reconciler::new(journal, executor);
        let plan = operation();
        reconciler.accept(&plan).unwrap();
        reconciler.reconcile_once(plan.operation_id()).unwrap();
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::PermanentlyBlocked
        );
        assert_eq!(
            reconciler.reconcile_once(plan.operation_id()).unwrap(),
            ReconcileOutcome::PermanentlyBlocked
        );
    }

    #[test]
    fn fresh_request_cannot_overwrite_an_existing_operation_identity() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let first = operation();
        reconciler.accept(&first).unwrap();

        let mut collision = operation();
        collision.idempotency_key = IdempotencyKey::new(b"another-request".to_vec()).unwrap();
        collision.request_digest = [0x77; 32];
        assert!(matches!(
            reconciler.accept(&collision),
            Err(ReconcilerError::OperationAlreadyExists)
        ));
    }

    fn observe_reservation_fixture(execution: [u8; 16]) -> (OperationId, Vec<u8>) {
        let mut receipt = [5; 40];
        receipt[..8].copy_from_slice(b"AOSEXE01");
        let reservation = ControllerExecutionObserveReservationV1::new(
            aos_sandbox_model::ExecutionId::from_bytes(execution),
            OperationId::from_bytes([0x22; 16]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 32],
            &receipt,
        )
        .unwrap();
        (reservation.observe_operation(), reservation.encode())
    }

    #[test]
    fn fresh_request_cannot_take_a_reserved_execution_observe_identity() {
        let directory = TestDirectory::new();
        let (mut journal, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let execution = [0x11; 16];
        let (reserved, value) = observe_reservation_fixture(execution);
        let transaction = JournalTransaction::new(
            [0x33; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerExecutionObserveReservation,
                execution.to_vec(),
                value,
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        drop(journal);

        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let sequence = reconciler.journal.snapshot_sequence();
        let mut collision = operation();
        collision.operation_id = reserved;
        assert!(matches!(
            reconciler.accept(&collision),
            Err(ReconcilerError::OperationAlreadyExists)
        ));
        assert_eq!(reconciler.journal.snapshot_sequence(), sequence);

        let other = operation();
        assert_eq!(
            reconciler.accept(&other).unwrap(),
            AcceptOutcome::Accepted(other.operation_id())
        );
    }

    #[test]
    fn corrupt_execution_observe_reservation_blocks_new_admission() {
        let directory = TestDirectory::new();
        let (mut journal, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let execution = [0x11; 16];
        let (_, mut value) = observe_reservation_fixture(execution);
        value[159] ^= 1;
        let transaction = JournalTransaction::new(
            [0x33; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerExecutionObserveReservation,
                execution.to_vec(),
                value,
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();

        let mut reconciler = Reconciler::new(journal, Executor::default());
        let sequence = reconciler.journal.snapshot_sequence();
        assert!(matches!(
            reconciler.accept(&operation()),
            Err(ReconcilerError::CorruptLedger(_))
        ));
        assert_eq!(reconciler.journal.snapshot_sequence(), sequence);
    }

    #[test]
    fn pending_operation_selection_advances_fairly() {
        let directory = TestDirectory::new();
        let (journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let mut reconciler = Reconciler::new(journal, Executor::default());
        let mut first = operation();
        first.operation_id = OperationId::from_bytes([0x11; 16]);
        first.idempotency_key = IdempotencyKey::new(b"first".to_vec()).unwrap();
        first.desired_key = b"first-sandbox".to_vec();
        let mut second = operation();
        second.operation_id = OperationId::from_bytes([0x22; 16]);
        second.idempotency_key = IdempotencyKey::new(b"second".to_vec()).unwrap();
        second.desired_key = b"second-sandbox".to_vec();
        reconciler.accept(&first).unwrap();
        reconciler.accept(&second).unwrap();

        let selected_first = reconciler.reconcile_next().unwrap().unwrap().0;
        let selected_second = reconciler.reconcile_next().unwrap().unwrap().0;
        assert_eq!(selected_first, first.operation_id());
        assert_eq!(selected_second, second.operation_id());
    }

    #[test]
    fn restart_after_every_durable_boundary_converges_without_duplicate_effects() {
        for crash_after in 0..=5 {
            let directory = TestDirectory::new();
            let path = directory.journal();
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, Executor::default());
            let plan = operation();
            reconciler.accept(&plan).unwrap();

            for _ in 0..crash_after {
                reconciler.reconcile_once(plan.operation_id()).unwrap();
            }
            let executor = reconciler.executor;
            drop(reconciler.journal);

            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            let mut reconciler = Reconciler::new(journal, executor);
            let mut terminal = false;
            for _ in 0..16 {
                if reconciler.reconcile_once(plan.operation_id()).unwrap()
                    == ReconcileOutcome::Succeeded
                {
                    terminal = true;
                    break;
                }
            }
            assert!(terminal, "did not converge after boundary {crash_after}");
            assert_eq!(reconciler.executor.apply_calls, 2);
            assert_eq!(reconciler.executor.applied.len(), 2);
        }
    }

    #[test]
    fn operation_codec_preserves_state_header_count_and_provenance_error_order() {
        let mut bytes = encode_operation(OperationState::Accepted, 1, false, None);
        bytes[0] = 0xff;
        bytes[1] = 0;
        assert!(matches!(
            decode_operation(&bytes).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger("unknown operation state"))
        ));
        assert!(matches!(
            decode_operation(&bytes[..39]).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid operation record version, flags, or length"
            ))
        ));

        bytes[1] = OperationState::Accepted as u8;
        assert!(matches!(
            decode_operation(&bytes).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid operation record version, flags, or length"
            ))
        ));

        let intent = ObjectDigest::from_bytes([0x81; 32]);
        for (state, count, expected) in [
            (OperationState::Accepted, 0, "invalid effect count"),
            (
                OperationState::Succeeded,
                0,
                "completed local operation has runtime authority",
            ),
            (
                OperationState::OwnershipPending,
                1,
                "ownership-pending operation lacks gated provenance",
            ),
        ] {
            let bytes = encode_operation(state, count, false, Some(intent));
            assert!(matches!(
                decode_operation(&bytes).map_err(ReconcilerError::from),
                Err(ReconcilerError::CorruptLedger(message)) if message == expected
            ));
        }
    }

    #[test]
    fn ownership_gate_codec_preserves_fixed_header_and_activation_error_order() {
        let plan = gated_operation().ownership_gate.unwrap();
        let gate = OwnershipGateStatusV1::Pending(plan);
        let bytes = encode_ownership_gate(&gate)
            .map_err(ReconcilerError::from)
            .unwrap();
        assert_eq!(
            decode_ownership_gate(&bytes)
                .map_err(ReconcilerError::from)
                .unwrap(),
            gate
        );

        let mut bad_magic = bytes[..8].to_vec();
        bad_magic[0] ^= 1;
        assert!(matches!(
            decode_ownership_gate(&bad_magic).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate version"
            ))
        ));
        for length in [0, 7, 8, 9, 10, 11, 15, 16, 251] {
            assert!(
                matches!(
                    decode_ownership_gate(&bytes[..length]).map_err(ReconcilerError::from),
                    Err(ReconcilerError::CorruptLedger("truncated ownership gate"))
                ),
                "length {length}"
            );
        }

        let mut bad_version = bytes[..10].to_vec();
        bad_version[9] ^= 1;
        assert!(matches!(
            decode_ownership_gate(&bad_version).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate version"
            ))
        ));

        let mut bad_reserved = bytes[..16].to_vec();
        bad_reserved[10] = 0xff;
        bad_reserved[11] = 1;
        assert!(matches!(
            decode_ownership_gate(&bad_reserved).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate reserved bytes"
            ))
        ));

        let mut bad_state = bytes;
        bad_state[10] = 0xff;
        assert!(matches!(
            decode_ownership_gate(&bad_state).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate activation state"
            ))
        ));
    }

    #[test]
    fn ownership_gate_codec_preserves_bounds_length_utf8_and_nested_error_order() {
        let plan = gated_operation().ownership_gate.unwrap();
        let gate = OwnershipGateStatusV1::Pending(plan);
        let bytes = encode_ownership_gate(&gate)
            .map_err(ReconcilerError::from)
            .unwrap();
        let idempotency_length = usize::from(u16::from_be_bytes(bytes[64..66].try_into().unwrap()));
        let key_id_length = usize::from(u16::from_be_bytes(bytes[66..68].try_into().unwrap()));
        let key_id_start = 252 + idempotency_length;
        let claim_start = key_id_start + key_id_length;

        let mut corrupt = bytes.clone();
        corrupt[key_id_start] = 0xff;
        corrupt[claim_start] ^= 1;
        corrupt[10] = 0xff;
        corrupt.push(0);
        corrupt[16..32].fill(0);
        assert!(matches!(
            decode_ownership_gate(&corrupt).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate fields"
            ))
        ));

        corrupt[16..32].copy_from_slice(&bytes[16..32]);
        assert!(matches!(
            decode_ownership_gate(&corrupt).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate length"
            ))
        ));

        corrupt.pop().unwrap();
        assert!(matches!(
            decode_ownership_gate(&corrupt).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "ownership key ID is not UTF-8"
            ))
        ));

        corrupt[key_id_start] = bytes[key_id_start];
        assert!(matches!(
            decode_ownership_gate(&corrupt).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid canonical ownership claim"
            ))
        ));

        corrupt[claim_start] = bytes[claim_start];
        corrupt[116] ^= 1;
        assert!(matches!(
            decode_ownership_gate(&corrupt).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "ownership claim digest mismatch"
            ))
        ));

        corrupt[116] = bytes[116];
        assert!(matches!(
            decode_ownership_gate(&corrupt).map_err(ReconcilerError::from),
            Err(ReconcilerError::CorruptLedger(
                "invalid ownership gate activation state"
            ))
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod provisioning_plan_tests;

struct OriginalProvisioningFailureDisplayV1<'held, E>(&'held E);

impl<E: SingleNodeEffectExecutor> std::fmt::Display for OriginalProvisioningFailureDisplayV1<'_, E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_original_provisioning_failure_v1(formatter)
    }
}
