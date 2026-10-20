//! Compares a completed private Host child in an already authenticated full C cut.
//!
//! Root retains the actual replay/native owner and independently authenticates
//! the initial compiled successor, signed lease, paired Host/Guardian plans and
//! Host1/fresh3 exchanges. This comparison neither grants a role nor completes a
//! transport. It checks the protected C tuple before the final Root ACK exists.

use super::*;
use aos_sandbox_core::{CanonicalAssignmentManifestV1, ResourceDimension, ResourceVector};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use crate::policy_compiler::provisioning_current::current_manifest::CurrentProtectedAssignmentDataV2;

/// Prices the same actual full-state canonical comparison models before decoding.
///
/// # Errors
/// Rejects arithmetic overflow or an unavailable canonical model/name bound.
pub(crate) fn completed_start_host_publication_receiving_demand_v2(
    controller: &Journal,
) -> Result<ResourceVector, JournalError> {
    let state = controller.historical_read_view_v1().materialized_state_v1();
    let models = crate::cold_launch_publication::completion::controller_selector_model_bytes_v1(state)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), ReconcilerError>>().checked_mul(2)?))
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
pub(crate) fn require_completed_start_host_publication_data_v2(
    controller: &Journal,
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
    crate::policy_compiler::provisioning_current::current_manifest::require_current_assignment_records_v2(
        binding, publication,
    )?;
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

    let operation = core_journal::readonly::load_operation(controller, child)?;
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
    validate_durable_effect_attempt(controller, manifest.manifest().sandbox(),
        publication.digest(), authority.digest(), authority.source_draft_digest(),
        authority.audience(), template.digest(), template.body_without_deadline(),
        &dispatch, None)?;
    effect::validate_durable_receipt_history(&dispatch, receipt.as_bytes())?;
    Ok(())
}

fn conflict_v2() -> ReconcilerError {
    ReconcilerError::InvalidExecutorOutput("completed private Start Host tuple differs from actual final C")
}
