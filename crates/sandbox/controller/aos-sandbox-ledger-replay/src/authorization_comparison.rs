//! Recomputes saved Delete authorization DATA without a native store or decision.
//!
//! Publisher policy rows, capability JSON, time-floor history, and scope checks
//! use their canonical existing recipes. The caller retains its genuine native
//! predecessor, admission, authenticated source and independently owed posts.

use std::collections::BTreeMap;
use aos_sandbox_model::{AuthorizationContext, AuditId, CapabilityId, CapabilityRecord,
    ChannelBinding, CLOCK_PAIR_TOLERANCE_NANOSECONDS, ObjectDigest, Operation,
    PrincipalId, ProjectId, RawPairedClockSample, RecordNamespace, ResourceKind, Selector};
use aos_sandbox_protocol::public_api::{authorization_error::CliAuthorizationAdapterError,
    model::AuthorizationRevisionDigestV1, mutation::ResolvedPublicMutationRequestV1};
use aos_sandbox_protocol::publisher_policy::{PublisherReadDataV2,
    current_data::{controller_head_from_data_v2, current_policy_from_data_v2,
        revocation_head_from_data_v2}};
use aos_sandbox_protocol::domain_ledger::delete_root::{
    authorization::DeleteRootAuthorizationFieldsV2, named_cuts::DeleteAuthorizationCutDataV2,
    transport::DeleteRootOpenDataV2,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use sha2::{Digest as _, Sha256};

mod capability_read;
mod capability_rows;
mod current_records;
use capability_rows::{PublisherAuthorityLimits, resolve_current_capability_from_data_v2};
crate::define_provider_time_floor_data_recipe_v1!(
    CliAuthorizationAdapterError::ProtectedAuthorizationRejected
);
crate::define_current_authorization_records_data_recipe_v1!();

/// Selects only the existing pure scope/lifetime comparison rule.
pub enum CapabilityCheckV1 {
    /// Requires the exact requested scope.
    Scope,
    // Preserve scope-denied negative DATA after the ordinary floor crossing;
    // Denied is distinct from the real context, validity or revocation errors.
    /// Preserves the established denied-scope lifetime comparison.
    RetainedLifetime,
}

/// Compares saved capability/policy/revocation inputs without issuing a decision.
///
/// # Errors
/// Rejects any mismatched binding, scope, validity interval or revocation DATA.
#[allow(clippy::too_many_arguments)]
pub fn validate_current_capability_inputs(
    capability: &aos_sandbox_model::CapabilityRecord,
    policy: &aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1,
    controller: &aos_sandbox_protocol::publisher_policy::PublisherControllerHeadV1,
    revocation: &aos_sandbox_protocol::publisher_policy::PublisherRevocationHeadV1,
    holder: PrincipalId,
    channel_binding: ChannelBinding,
    resource_kind: ResourceKind,
    operation: Operation,
    selector: &Selector,
    trusted_now: i64,
    check: CapabilityCheckV1,
) -> Result<(), CliAuthorizationAdapterError> {
    let claims = capability.claims();
    if controller.principal != claims.audience
        || revocation.scope != claims.revocation_scope
        || revocation.generation != claims.revocation_generation.get()
        || policy.project() != claims.project
        || policy.descriptor().digest() != claims.policy_digest
        || trusted_now < policy.not_before()
        || trusted_now >= policy.expires_at()
    {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }

    let context = AuthorizationContext {
        now: trusted_now,
        audience: controller.principal,
        holder,
        channel_binding,
        project: claims.project,
        sandbox: claims.sandbox,
        incarnation: claims.incarnation,
        assignment_epoch: claims.assignment_epoch,
        revocation_generation: claims.revocation_generation,
    };
    match capability.authorize(&context, resource_kind, operation, selector) {
        Ok(()) => {}
        Err(aos_sandbox_model::AuthorizationError::Denied)
            if matches!(check, CapabilityCheckV1::RetainedLifetime) => {}
        Err(_) => return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected),
    }

    Ok(())
}

/// Compares the nonzero recorded project with the capability project.
///
/// # Errors
/// Rejects a sentinel or differing project.
pub fn require_authenticated_project(
    authenticated_project: ProjectId,
    capability_project: ProjectId,
) -> Result<(), CliAuthorizationAdapterError> {
    if authenticated_project.as_bytes() == &[0; 16] || authenticated_project != capability_project {
        return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
    }
    Ok(())
}

/// Recomputes the exact historical Delete authorization commitment.
///
/// # Errors
/// Rejects malformed requests or any saved capability/policy/floor/scope mismatch.
pub fn recompute_delete_authorization_cut_from_records_v2(
    records: PublisherReadDataV2<'_>,
    input: &[u8],
    fields: DeleteRootAuthorizationFieldsV2,
    open: DeleteRootOpenDataV2,
) -> Result<[u8; 32], CliAuthorizationAdapterError> {
    let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
    let request = ResolvedPublicMutationRequestV1::decode_delete(input).map_err(|_| refused())?;
    let selector = request.selector().ok_or_else(refused)?;
    let current = CurrentAuthorizationRecordsV1::load_v1(records,
        CapabilityId::from_bytes(fields.capability))?;
    let claims = current.capability.claims();
    let policy = &current.policy;
    let floor = current.floor;
    require_authenticated_project(ProjectId::from_bytes(fields.project), claims.project)?;
    if floor.clock != open.authorization_clock
        || fields.authorized_wall != floor.clock.wall_seconds()
        || u64::try_from(input.len()).ok() != Some(fields.input_bytes)
        || fields.capability_not_before != claims.not_before
        || fields.capability_expires != claims.expires_at
        || fields.policy_not_before != policy.not_before()
        || fields.policy_expires != policy.expires_at()
        || fields.capability_expires.min(fields.policy_expires) != open.authorization_expires
    {
        return Err(refused());
    }
    current.require_scope_v1(PrincipalId::from_bytes(fields.caller),
        ChannelBinding::new(fields.channel), request.resource_kind(),
        request.operation(), selector, fields.authorized_wall)?;
    let revision = current.revision_v1();
    Ok(DeleteAuthorizationCutDataV2 {
        project: *claims.project.as_bytes(),
        caller: fields.caller,
        input,
        revision: *revision.digest().as_bytes(),
        channel: *claims.channel_binding.as_bytes(),
        capability_not_before: claims.not_before,
        capability_expires: claims.expires_at,
        policy_not_before: policy.not_before(),
        policy_expires: policy.expires_at(),
        authorized_wall: floor.clock.wall_seconds(),
    }
    .digest_v2())
}

/// Prices the real saved-row comparison and canonical decoder control owners.
///
/// This checked Memory-only DATA quote excludes dynamic row/model payloads;
/// the actual native owner must admit its full semantic formula before growth.
/// It grants no funding, protected decision or native entry.
#[must_use]
pub fn receiving_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    capability_rows::receiving_control_bytes_v2()?
        .checked_add(size_of::<CurrentAuthorizationRecordsV1>().checked_mul(3)?)?
        .checked_add(size_of::<Result<CurrentAuthorizationRecordsV1,
            CliAuthorizationAdapterError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Option<ProtectedTimeFloorRevisionV1>,
            CliAuthorizationAdapterError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<[u8;32], CliAuthorizationAdapterError>>()
            .checked_mul(3)?)?
        .checked_add(size_of::<AuthorizationContext>().checked_mul(3)?)?
        .checked_add(size_of::<(PublisherReadDataV2<'_>, &[u8],
            DeleteRootAuthorizationFieldsV2, DeleteRootOpenDataV2)>().checked_mul(2)?)
}
