//! Recomputes Delete's authorization comparison from Root's own held C rows.
//!
//! This constructs no protected decision or native store. The actual Root
//! consumer funds input/models and retains its full-cold native prefix/posts;
//! ordinary Controller authorization retains its exclusive native guards.

use super::*;
use crate::publisher_admin::PublisherReadDataV2;
use super::current_records::CurrentAuthorizationRecordsV1;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    authorization::DeleteRootAuthorizationFieldsV2, named_cuts::DeleteAuthorizationCutDataV2,
    transport::DeleteRootOpenDataV2,
};
use aos_sandbox_protocol::public_api::mutation::ResolvedPublicMutationRequestV1;

pub(crate) fn recompute_delete_authorization_cut_from_records_v2(
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
