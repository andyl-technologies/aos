//! Shares saved capability, policy, revocation and protected-floor comparisons.
//!
//! These borrowed-row consumers construct no native store or current decision.
//! Their concrete callers retain and fund the actual full Controller replay.

use super::*;
use aos_sandbox_core::{CapabilityRecord, ResourceId};
use crate::publisher_admin::{
    PublisherReadDataV2,
    capabilities::resolve_current_capability_from_data_v2,
    policy::{controller_head_from_data_v2, current_policy_from_data_v2,
        revocation_head_from_data_v2},
};

pub(super) struct CurrentAuthorizationRecordsV1 {
    pub(super) capability: CapabilityRecord,
    pub(super) controller: crate::publisher_admin::policy::PublisherControllerHeadV1,
    pub(super) revocation: crate::publisher_admin::policy::PublisherRevocationHeadV1,
    pub(super) policy: aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1,
    pub(super) floor: ProtectedTimeFloorRevisionV1,
}

impl CurrentAuthorizationRecordsV1 {
    pub(super) fn load_v1(records: PublisherReadDataV2<'_>, capability: CapabilityId)
        -> Result<Self, CliAuthorizationAdapterError>
    {
        let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
        let capability = resolve_current_capability_from_data_v2(
            records, capability, PublisherAuthorityLimits::default(),
        ).map_err(|_| refused())?;
        let claims = capability.claims();
        let controller = controller_head_from_data_v2(records)
            .map_err(|_| refused())?.ok_or_else(refused)?;
        let revocation = revocation_head_from_data_v2(records, claims.revocation_scope)
            .map_err(|_| refused())?.ok_or_else(refused)?;
        let policy = current_policy_from_data_v2(records, claims.project)
            .map_err(|_| refused())?.ok_or_else(refused)?;
        let floor = load_protected_time_floor_records(
            records.records(RecordNamespace::CliAuthorizationTime),
        )?.ok_or_else(refused)?;
        Ok(Self { capability, controller, revocation, policy, floor })
    }

    pub(super) fn require_scope_v1(&self, holder: PrincipalId, channel: ChannelBinding,
        kind: ResourceKind, operation: Operation, selector: &Selector, wall: i64,
    ) -> Result<(), CliAuthorizationAdapterError> {
        validate_current_capability_inputs(&self.capability, &self.policy,
            &self.controller, &self.revocation, holder, channel, kind, operation,
            selector, wall, CapabilityCheckV1::Scope)
    }

    pub(super) fn revision_v1(&self) -> AuthorizationRevisionDigestV1 {
        protected_authorization_revision(&self.capability, self.controller.generation,
            self.policy.generation(), self.floor)
    }
}

/// Rechecks only the exact metadata-finality Recover scope against held rows.
///
/// The concrete request owner already validates the original operation/version
/// and evidence. This comparison cannot admit an effect or revive its lease.
pub(crate) fn recompute_create_recovery_authorization_from_records_v1(
    records: PublisherReadDataV2<'_>,
    request: &super::super::OperatorRecoveryRequestV1,
    project: ProjectId, caller: PrincipalId, capability: CapabilityId,
    channel: ChannelBinding, original: RawPairedClockSample,
) -> Result<AuthorizationRevisionDigestV1, CliAuthorizationAdapterError> {
    compare_create_recovery_authorization_from_records_v1(
        records, request, project, caller, capability, channel, original,
    ).map(|(revision, _)| revision)
}

/// Compares current protected authorization and its exact wall expiry as DATA.
///
/// This shares the actual holder/channel/scope/revocation/floor kernel with the
/// live admission. Neither returned value constructs a current decision, peer
/// or admission. The independent native reader must keep the complete interval
/// and enforce both original clock bounds before every reached frontier.
pub(crate) fn compare_create_recovery_authorization_from_records_v1(
    records: PublisherReadDataV2<'_>,
    request: &super::super::OperatorRecoveryRequestV1,
    project: ProjectId, caller: PrincipalId, capability: CapabilityId,
    channel: ChannelBinding, original: RawPairedClockSample,
) -> Result<(AuthorizationRevisionDigestV1, i64), CliAuthorizationAdapterError> {
    let refused = || CliAuthorizationAdapterError::ProtectedAuthorizationRejected;
    if request.action() != aos_proto::aos::sandbox::v1::OperatorRecoveryAction::
        OPERATOR_RECOVERY_ACTION_RETRY as i32 {
        return Err(refused());
    }
    let current = CurrentAuthorizationRecordsV1::load_v1(records, capability)?;
    require_authenticated_project(project, current.capability.claims().project)?;
    if current.floor.clock != original { return Err(refused()); }
    let selector = Selector::Resource {
        resource: ResourceId::from_bytes(request.resource_id()),
    };
    current.require_scope_v1(caller, channel, ResourceKind::Operation,
        Operation::LifecycleControl, &selector, original.wall_seconds())?;
    let expires = current.capability.claims().expires_at.min(current.policy.expires_at());
    Ok((current.revision_v1(), expires))
}
