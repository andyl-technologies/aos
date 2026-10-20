//! Shares historical Runtime operation/gate/effect crosslink comparisons.
//!
//! Parsed gates and plans remain owned through the caller's next native guard.
//! These helpers validate DATA only: they do not authenticate a protected
//! Journal, current execution, trust anchor, payer or publication permission.
//! Actual native adapters keep their provenance and currentness checks at the
//! original boundaries, independently of this portable historical result.

use aos_sandbox_core::{ObjectDigest, OperationId, RecordNamespace};
use crate::publication::{AuthorityPublicationDraftV1, PublicationHistoryError};
use crate::domain_ledger::{
    effect_history::{EffectHistoryDataError, EffectPlan, decode_effect},
    operation::{decode_operation, effect_key},
    ownership_gate::{OwnershipGateDataErrorV1, OwnershipGatePlanV1, OwnershipGateStatusV1, decode_ownership_gate},
    public_operation::{OperationState, PublicOperationDataError},
    readonly::{HistoricalLedgerReadViewV1, HistoricalLedgerComparisonV2, IdempotencyOutcome},
};
use super::{RuntimeAuthorityBindingV1, RuntimeAuthorityPendingV1, RuntimeAuthorityStateV1};

/// Reports the established flat comparison/parser classification as DATA.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeCrosslinkDataErrorV1 {
    /// Preserves the historical Runtime reader's original guard/link classification.
    #[error(transparent)]
    RuntimeHistory(#[from] super::ledger_read::RuntimeHistoryReadErrorV1),
    /// An historical input violates the established effect/plan contract.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// Historical operation, gate or effect links disagree.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// Effect receipt DATA violates the established output grammar.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
    /// Public-operation DATA has an invalid recorded clock.
    #[error("public operation clock observation is missing or invalid")]
    PublicOperationClock,
    /// Public-operation DATA exhausted its observation sequence.
    #[error("public operation observation sequence is exhausted")]
    PublicOperationSequenceExhausted,
    /// The existing publication-effect binder rejected its DATA.
    #[error(transparent)]
    Publication(#[from] PublicationHistoryError),
}

impl From<PublicOperationDataError> for RuntimeCrosslinkDataErrorV1 {
    fn from(error: PublicOperationDataError) -> Self {
        match error {
            PublicOperationDataError::InvalidPlan(reason) => Self::InvalidPlan(reason),
            PublicOperationDataError::CorruptLedger(reason) => Self::CorruptLedger(reason),
            PublicOperationDataError::PublicOperationClock => Self::PublicOperationClock,
            PublicOperationDataError::PublicOperationSequenceExhausted => {
                Self::PublicOperationSequenceExhausted
            },
        }
    }
}

impl From<OwnershipGateDataErrorV1> for RuntimeCrosslinkDataErrorV1 {
    fn from(error: OwnershipGateDataErrorV1) -> Self {
        match error {
            OwnershipGateDataErrorV1::InvalidPlan(reason) => Self::InvalidPlan(reason),
            OwnershipGateDataErrorV1::CorruptLedger(reason) => Self::CorruptLedger(reason),
        }
    }
}

impl From<EffectHistoryDataError> for RuntimeCrosslinkDataErrorV1 {
    fn from(error: EffectHistoryDataError) -> Self {
        match error {
            EffectHistoryDataError::InvalidPlan(reason) => Self::InvalidPlan(reason),
            EffectHistoryDataError::CorruptLedger(reason) => Self::CorruptLedger(reason),
            EffectHistoryDataError::InvalidExecutorOutput(reason) => {
                Self::InvalidExecutorOutput(reason)
            },
        }
    }
}

/// Retains the actual parsed activated plan until the caller's native checks.
///
/// This is historical comparison DATA and cannot construct Native acceptance.
pub struct RuntimeBindingGateContextV1 {
    plan: OwnershipGatePlanV1,
    publication_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
}

impl RuntimeBindingGateContextV1 {
    /// Moves the same parsed plan and fixed activation fields without cloning.
    pub fn into_parts(self) -> (OwnershipGatePlanV1, ObjectDigest, u64, ObjectDigest) {
        (
            self.plan,
            self.publication_digest,
            self.lease_generation,
            self.lease_digest,
        )
    }
}

/// Checks pending request/gate/effect DATA and returns the same owned gate.
///
/// # Errors
///
/// Rejects the original malformed DATA or exact crosslink/shape mismatch.
pub fn pending_context(
    journal: HistoricalLedgerReadViewV1<'_>,
    pending: &RuntimeAuthorityPendingV1,
) -> Result<OwnershipGateStatusV1, RuntimeCrosslinkDataErrorV1> {
    pending_context_comparison_v2(HistoricalLedgerComparisonV2::Native(journal), pending)
}

pub(crate) fn pending_context_comparison_v2(
    journal: HistoricalLedgerComparisonV2<'_>,
    pending: &RuntimeAuthorityPendingV1,
) -> Result<OwnershipGateStatusV1, RuntimeCrosslinkDataErrorV1> {
    let gate = runtime_gate_comparison_v2(journal, pending.operation())?;
    let operation = journal
        .get(RecordNamespace::Operation, pending.operation().as_bytes())
        .ok_or(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority operation is missing",
        ))
        .and_then(|bytes| decode_operation(bytes).map_err(RuntimeCrosslinkDataErrorV1::from))?;
    let plan = gate_plan(&gate);
    if operation.runtime_intent_digest() != Some(pending.intent_digest())
        || plan.request_digest_bytes() != pending.request_digest()
        || plan.publication_draft().manifest() != pending.manifest()
        || plan.publication_draft_digest() != pending.source_draft_digest()
    {
        return Err(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority intent does not match its admitted ownership gate",
        ));
    }
    if pending.state() == RuntimeAuthorityStateV1::Revoked {
        if operation.effect_count() != 1 {
            return Err(RuntimeCrosslinkDataErrorV1::CorruptLedger(
                "runtime revocation requires one Stop effect",
            ));
        }
        let effect = journal
            .get(RecordNamespace::Effect, &effect_key(pending.operation(), 0))
            .ok_or(RuntimeCrosslinkDataErrorV1::CorruptLedger(
                "runtime revocation effect is missing",
            ))
            .and_then(|bytes| decode_effect(bytes).map_err(RuntimeCrosslinkDataErrorV1::from))?
            .into_parts();
        validate_intent_effects(
            pending.state(),
            pending.operation(),
            plan.publication_draft(),
            &[effect.0],
        )?;
    }
    Ok(gate)
}

/// Checks the exact canonical Host Stop shape for a revocation intent.
///
/// # Errors
///
/// Rejects the original malformed DATA or exact crosslink/shape mismatch.
pub fn validate_intent_effects(
    state: RuntimeAuthorityStateV1,
    operation: OperationId,
    draft: &AuthorityPublicationDraftV1,
    effects: &[EffectPlan],
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    if state == RuntimeAuthorityStateV1::Bound {
        return Ok(());
    }
    let invalid = || {
        RuntimeCrosslinkDataErrorV1::InvalidPlan(
            "runtime revocation requires one canonical Host Stop effect",
        )
    };
    let [effect] = effects else {
        return Err(invalid());
    };
    let binding = effect.authority().ok_or_else(invalid)?;
    let template = draft
        .templates()
        .iter()
        .find(|template| template.digest() == binding.template_digest())
        .ok_or_else(invalid)?;
    if template.audience() != aos_sandbox_core::BrokerAudience::Host
        || template.method()
            != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        || !template.descriptor_roles().is_empty()
        || crate::publication::bind_authority_publication_effect(
            &draft,
            template.digest(),
        )?
        .into_inner(operation, 0)
        .map_err(RuntimeCrosslinkDataErrorV1::from)?
            != *effect
    {
        return Err(invalid());
    }

    let checked =
        crate::decode_runtime_template_v1(template.body_without_deadline())
            .map_err(|_| invalid())?;
    let canonical =
        crate::semantics::host::canonical_host_template_semantics_v1(&checked)
            .map_err(|_| invalid())?;
    let semantics = template.semantics();
    let manifest = draft.manifest().manifest();
    let fence = checked.fence();
    if canonical.verb() != aos_sandbox_core::BrokerVerb::HostStop
        || canonical.verb() != semantics.verb()
        || canonical.target() != semantics.target()
        || canonical.commitment() != semantics.argument_commitment()
        || fence.sandbox_id() != manifest.sandbox().as_bytes()
        || fence.incarnation_id() != manifest.incarnation().as_bytes()
        || fence.assignment_epoch() != manifest.epoch().get()
        || fence.desired_generation() != manifest.desired_generation().get()
        || fence.assignment_digest() != draft.manifest().digest().as_bytes()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Checks binding activation DATA and returns the same parsed plan context.
///
/// # Errors
///
/// Rejects the original malformed DATA or exact crosslink/shape mismatch.
pub fn binding_context(
    journal: HistoricalLedgerReadViewV1<'_>,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<RuntimeBindingGateContextV1, RuntimeCrosslinkDataErrorV1> {
    binding_context_comparison_v2(HistoricalLedgerComparisonV2::Native(journal), binding)
}

pub(crate) fn binding_context_comparison_v2(
    journal: HistoricalLedgerComparisonV2<'_>,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<RuntimeBindingGateContextV1, RuntimeCrosslinkDataErrorV1> {
    let gate = runtime_gate_comparison_v2(journal, binding.operation())?;
    let OwnershipGateStatusV1::Activated {
        plan,
        publication_digest,
        lease_generation,
        lease_digest,
    } = gate
    else {
        return Err(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority decision precedes ownership activation",
        ));
    };
    if plan.request_digest_bytes() != binding.request_digest()
        || plan.publication_draft().manifest() != binding.manifest()
        || plan.publication_draft_digest() != binding.source_draft_digest()
        || publication_digest != binding.publication_digest()
        || lease_generation != binding.lease_generation()
        || lease_digest != binding.lease_digest()
    {
        return Err(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority decision does not match its activated ownership gate",
        ));
    }
    Ok(RuntimeBindingGateContextV1 {
        plan,
        publication_digest,
        lease_generation,
        lease_digest,
    })
}

/// Borrows the plan from either historical ownership-gate state.
pub fn gate_plan(gate: &OwnershipGateStatusV1) -> &OwnershipGatePlanV1 {
    match gate {
        OwnershipGateStatusV1::Pending(plan) | OwnershipGateStatusV1::Activated { plan, .. } => {
            plan
        }
    }
}

/// Checks historical operation, idempotency and ownership-gate agreement.
///
/// # Errors
///
/// Rejects the original malformed DATA or exact crosslink/shape mismatch.
pub fn runtime_gate(
    journal: HistoricalLedgerReadViewV1<'_>,
    operation_id: OperationId,
) -> Result<OwnershipGateStatusV1, RuntimeCrosslinkDataErrorV1> {
    runtime_gate_comparison_v2(HistoricalLedgerComparisonV2::Native(journal), operation_id)
}

pub(crate) fn runtime_gate_comparison_v2(
    journal: HistoricalLedgerComparisonV2<'_>,
    operation_id: OperationId,
) -> Result<OwnershipGateStatusV1, RuntimeCrosslinkDataErrorV1> {
    let operation = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority operation is missing",
        ))
        .and_then(|bytes| decode_operation(bytes).map_err(RuntimeCrosslinkDataErrorV1::from))?;
    let gate = journal
        .get(RecordNamespace::OwnershipGate, operation_id.as_bytes())
        .ok_or(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority gate is missing",
        ))
        .and_then(|bytes| decode_ownership_gate(bytes).map_err(RuntimeCrosslinkDataErrorV1::from))?;
    let plan = gate_plan(&gate);
    if !operation.ownership_gated()
        || plan.operation_id() != operation_id
        || journal.check_idempotency(plan.idempotency_key(), plan.request_digest())
            != IdempotencyOutcome::Replay(operation_id)
        || !matches!(
            (&gate, operation.state()),
            (
                OwnershipGateStatusV1::Pending(_),
                OperationState::OwnershipPending
            ) | (
                OwnershipGateStatusV1::Activated { .. },
                OperationState::Accepted
                    | OperationState::Applying
                    | OperationState::Succeeded
                    | OperationState::PermanentlyBlocked
            )
        )
    {
        return Err(RuntimeCrosslinkDataErrorV1::CorruptLedger(
            "runtime authority gate and operation disagree",
        ));
    }
    Ok(gate)
}

/// Resolves the same exact saved operation/gate links from supplied full rows.
///
/// These historical models cannot supply a current Native or Ownership loan.
/// The enclosing caller independently retains its paid native/schema proof.
///
/// # Errors
/// Rejects the same operation, idempotency, claim, draft and gate mismatch as
/// the ordinary historical reader, preserving its canonical parser and order.
pub fn runtime_gate_rows_data_v2(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    operation: OperationId,
) -> Result<OwnershipGateStatusV1, RuntimeCrosslinkDataErrorV1> {
    runtime_gate_comparison_v2(HistoricalLedgerComparisonV2::Rows(rows), operation)
}
