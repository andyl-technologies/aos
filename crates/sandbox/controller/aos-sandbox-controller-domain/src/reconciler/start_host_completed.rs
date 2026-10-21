//! Compares a completed private Host child in an already authenticated full C cut.
//!
//! Root retains the actual replay/native owner and independently authenticates
//! the initial compiled successor, signed lease, paired Host/Guardian plans and
//! Host1/fresh3 exchanges. This comparison neither grants a role nor completes a
//! transport. It checks the protected C tuple before the final Root ACK exists.

use super::*;
use aos_sandbox_model::{CanonicalAssignmentManifestV1, ResourceDimension, ResourceVector};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use crate::policy_compiler::provisioning_current::current_manifest::CurrentProtectedAssignmentDataV2;

/// Prices the same actual full-state canonical comparison models before decoding.
///
/// # Errors
/// Rejects arithmetic overflow or an unavailable canonical model/name bound.

pub(crate) fn completed_start_host_publication_receiving_from_observation_v2(
    controller: crate::journal::historical_observation::HistoricalObservationV1<'_>,
) -> Result<ResourceVector, JournalError> {
    let state = controller.state_v1();
    let models = crate::cold_launch_publication::completion::controller_selector_model_bytes_v1(state)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), ReconcilerError>>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::domain_ledger::runtime_authority_history::
            current_assignment::current_assignment_links_control_bytes_v2()?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::ProtectedBoundary)?;
    let names = crate::cold_launch_publication::completion::controller_selector_namespace_entries_v1(state)
        .and_then(|names| u64::try_from(names).ok()).ok_or(JournalError::ProtectedBoundary)?;
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, models)
        .with(ResourceDimension::MetadataEntries, names))
}

/// Compares the exact current2, activated gate and completed one-effect child.
///
/// `current` is the actual selected protected pair from this same full C cut.
/// The caller separately verifies the Host/Guardian pair and authenticated
/// Host1/fresh3 history, then supplies that exact Host1 body and success receipt.
/// No supplied receipt or DATA tuple establishes completion on its own.
///
/// # Errors
/// Rejects unhealthy C, a changed current pair, another parent/reply/lease/plan,
/// a public or nonterminal child, a different dispatch, or a different receipt.
#[allow(clippy::too_many_arguments)]

pub(crate) fn require_completed_start_host_publication_from_observation_v2(
    controller: crate::journal::historical_observation::HistoricalObservationV1<'_>,
    current: &CurrentProtectedAssignmentDataV2,
    parent: OperationId,
    root_reply: [u8; 32],
    manifest: &CanonicalAssignmentManifestV1,
    lease: &SignedOwnershipLease,
    host_plan: &[u8],
    host_signature: &[u8],
    template_body: &[u8],
    host_request_body: &[u8],
    host_receipt: &[u8],
) -> Result<(), ReconcilerError> {
    controller.ensure_protected_authority()?;
    let binding = current.binding_data_v2();
    let publication = current.publication_v2();
    aos_sandbox_protocol::domain_ledger::runtime_authority_history::current_assignment::
        require_current_assignment_history_data_v2(binding.historical_data_v1(), publication.history_data_v2())
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let child = crate::controller_resource_reservation::start_host_publication_operation_id_data_v2(
        parent, root_reply, publication.digest(),
    );
    if binding.operation() != child || binding.manifest() != manifest
        || publication.manifest() != manifest
        || binding.request_digest() != publication.digest().as_bytes()
        || publication.lease_digest() != lease.digest()
        || publication.lease_generation() != lease.generation()
        || publication.lease().canonical_lease() != lease.canonical_lease()
        || publication.lease().canonical_signature() != lease.canonical_signature()
        || publication.lease().canonical_receipt() != lease.canonical_receipt()
        || publication.lease().canonical_receipt_signature() != lease.canonical_receipt_signature()
    {
        return Err(conflict_v2());
    }

    let operation = core_journal::readonly::load_operation_rows_v2(controller.rows_data_v2(), child)?;
    if operation.state() != OperationState::Succeeded || operation.effect_count() != 1
        || !operation.ownership_gated() || operation.public_operation().is_some()
        || operation.runtime_intent_digest().is_none()
    {
        return Err(conflict_v2());
    }
    let gate = decode_ownership_gate(controller.get(RecordNamespace::OwnershipGate, child.as_bytes())
        .ok_or_else(conflict_v2)?)?;
    let OwnershipGateStatusV1::Activated {
        plan, publication_digest, lease_generation, lease_digest,
    } = gate else {
        return Err(conflict_v2());
    };
    if plan.operation_id() != child || plan.request_digest() != *publication.digest().as_bytes()
        || plan.claim().assignment() != lease.assignment()
        || plan.publication_draft().manifest() != manifest
        || plan.publication_draft_digest() != binding.source_draft_digest()
        || publication_digest != publication.digest() || lease_generation != lease.generation()
        || lease_digest != lease.digest()
    {
        return Err(conflict_v2());
    }

    let [template] = publication.templates() else { return Err(conflict_v2()); };
    if template.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        || template.canonical_plan() != host_plan
        || template.canonical_plan_signature() != host_signature
        || template.body_without_deadline() != template_body
    {
        return Err(conflict_v2());
    }
    let record = decode_effect(controller.get(RecordNamespace::Effect, &effect_key(child, 0))
        .ok_or_else(conflict_v2)?)?;
    let expected = aos_sandbox_protocol::publication::bind_authority_publication_effect(
        plan.publication_draft(), template.digest(),
    ).map_err(crate::AuthorityPublicationError::from)?.into_inner(child, 0)?;
    if record.plan() != &expected || record.project_admission().is_some() {
        return Err(conflict_v2());
    }
    let (_, state, dispatch, _) = record.into_parts();
    let EffectState::Applied { attempt: 1, receipt } = state else { return Err(conflict_v2()); };
    let dispatch = dispatch.ok_or_else(conflict_v2)?;
    let authority = expected.authority().ok_or_else(conflict_v2)?;
    if dispatch.binding_digest() != authority.digest()
        || dispatch.publication_digest() != publication.digest()
        || dispatch.attempt().template_digest() != template.digest()
        || dispatch.attempt().lease_digest() != lease.digest()
        || dispatch.attempt().lease_generation() != lease.generation()
        || dispatch.attempt().body() != host_request_body
        || receipt.as_bytes() != host_receipt
    {
        return Err(conflict_v2());
    }
    crate::publication::validate_durable_effect_attempt_observed_v2(controller, manifest.manifest().sandbox(),
        publication.digest(), authority.digest(), authority.source_draft_digest(),
        authority.audience(), template.digest(), template.body_without_deadline(),
        &dispatch, None)?;
    effect::validate_durable_receipt_history(&dispatch, receipt.as_bytes())?;
    Ok(())
}

fn conflict_v2() -> ReconcilerError {
    ReconcilerError::InvalidExecutorOutput("completed private Start Host tuple differs from actual final C")
}

/// Prices the reached Host completion comparison interfaces before its quote.
pub(crate) fn completed_host_observation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    size_of::<(crate::journal::historical_observation::HistoricalObservationV1<'_>, &CurrentProtectedAssignmentDataV2, OperationId, [u8; 32],
        &CanonicalAssignmentManifestV1, &SignedOwnershipLease, &[u8], &[u8], &[u8], &[u8], &[u8])>().checked_mul(3)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), ReconcilerError>>().checked_mul(3)?)?
        .checked_add(size_of::<(aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, OperationId)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<OperationRecord, ReconcilerError>>().checked_mul(3)?)?
        .checked_add(crate::publication::effect_observation_control_bytes_v2()?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
