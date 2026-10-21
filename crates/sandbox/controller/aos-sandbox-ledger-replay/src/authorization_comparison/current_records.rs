//! Shares saved-row authorization loading and exact scope/revision comparison.
//!
//! Instantiations retain only capability/policy/revocation/floor DATA. No current
//! decision, writer, authenticated request or native lifetime can be minted here.

/// Defines the canonical private saved-row comparison for concrete error/floor DATA.
#[macro_export]
macro_rules! define_current_authorization_records_data_recipe_v1 {
    () => {
        pub(super) struct CurrentAuthorizationRecordsV1 {
            pub(super) capability: CapabilityRecord,
            pub(super) controller: aos_sandbox_protocol::publisher_policy::PublisherControllerHeadV1,
            pub(super) revocation: aos_sandbox_protocol::publisher_policy::PublisherRevocationHeadV1,
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
                aos_sandbox_protocol::domain_ledger::delete_root::named_cuts::protected_authorization_revision_data_v2(
                    &self.capability, self.controller.generation, self.policy.generation(),
                    self.floor.generation, self.floor.clock, self.floor.digest.as_bytes(),
                )
            }
        }
    };
}
