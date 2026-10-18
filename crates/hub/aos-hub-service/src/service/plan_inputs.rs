//! Sealed request preconditions for reviewed Hub control-plane mutations.

use aos_hub_api as pb;
/// Stored preconditions for one placement write-authority promotion.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementPromotionPlanInput {
    pub(super) request: pb::PlacementMutationRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) candidate_placement_id: i64,
    pub(super) candidate_placement_name: String,
    pub(super) candidate_resource_version: i64,
    pub(super) candidate_write_spec_version: i64,
    pub(super) candidate_binding_write_revision: i64,
    pub(super) authority_incarnation_id: String,
    pub(super) authority_id: Option<i64>,
    pub(super) authority_resource_version: Option<i64>,
    pub(super) authority_desired_generation: Option<i64>,
    pub(super) observed_placement_id: Option<i64>,
    pub(super) observed_placement_name: Option<String>,
}

/// Exact authority tuple sealed by a promotion-cancellation plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct CancelPlacementPromotionPlanInput {
    pub(super) request: pb::SurfaceMutationRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) authority_id: i64,
    pub(super) authority_incarnation_id: String,
    pub(super) authority_resource_version: i64,
    pub(super) desired_generation: i64,
    pub(super) desired_placement_id: i64,
    pub(super) observed_placement_id: i64,
}

/// Immutable preconditions and desired state for placement creation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementCreatePlanInput {
    pub(super) request: pb::PlanCreatePlacementRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) org_id: Option<i64>,
    pub(super) binding_db_id: i64,
}

/// Immutable preconditions and replacement desired state for a placement.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementUpdatePlanInput {
    pub(super) request: pb::PlanUpdatePlacementRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) placement_id: i64,
    pub(super) baseline_resource_version: i64,
}

/// Immutable preconditions for placement metadata deletion.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementDeletePlanInput {
    pub(super) request: pb::PlacementMutationRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) placement_id: i64,
    pub(super) baseline_resource_version: i64,
}

/// Immutable preconditions for a placement lifecycle transition.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementLifecyclePlanInput {
    pub(super) request: pb::PlacementMutationRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) placement_id: i64,
    pub(super) baseline_resource_version: i64,
    pub(super) resulting_state: String,
    pub(super) resulting_read_enabled: bool,
}

/// One exact placement member sealed into a policy mutation plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementPolicyMemberPlanSeal {
    pub(super) name: String,
    pub(super) placement_id: i64,
    pub(super) resource_version: i64,
    pub(super) kind: String,
}

/// One normalized immutable replica group sealed into a policy plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementPolicyGroupPlanSeal {
    pub(super) group_id: String,
    pub(super) purpose: String,
    pub(super) range_start: Option<i64>,
    pub(super) range_end: Option<i64>,
    pub(super) members: Vec<PlacementPolicyMemberPlanSeal>,
}

/// Complete reviewed input for creating or revising a placement policy.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementPolicyMutationPlanInput {
    pub(super) request: pb::PlanPlacementPolicyMutationRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) owner_scope_key: String,
    pub(super) baseline_policy_resource_version: Option<i64>,
    pub(super) kind: String,
    pub(super) local_boundary_id: Option<String>,
    pub(super) local_boundary_revision: Option<i64>,
    pub(super) local_boundary_content_digest: Option<String>,
    pub(super) allow_remote_fallback: Option<bool>,
    pub(super) retry_on: Vec<String>,
    pub(super) groups: Vec<PlacementPolicyGroupPlanSeal>,
}

/// Exact physical and observation evidence for equivalence confirmation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementEquivalencePlanInput {
    pub(super) request: pb::PlanPlacementEquivalenceRequest,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) placement_a_id: i64,
    pub(super) placement_a_version: i64,
    pub(super) placement_a_observation_version: i64,
    pub(super) placement_a_inventory_digest: String,
    pub(super) placement_b_id: i64,
    pub(super) placement_b_version: i64,
    pub(super) placement_b_observation_version: i64,
    pub(super) placement_b_inventory_digest: String,
    pub(super) physical_identity_fingerprint: String,
    pub(super) evidence_digest: String,
    pub(super) stable_id: String,
}

/// Exact preconditions for deleting a placement equivalence.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct PlacementEquivalenceDeletePlanInput {
    pub(super) stable_id: String,
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) baseline_resource_version: i64,
}

/// Immutable inputs for creating or replacing a storage-binding spec.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct BindingMutationPlanInput {
    pub(super) request: pb::PlanBindingMutationRequest,
    pub(super) org_id: Option<i64>,
    pub(super) binding_db_id: Option<i64>,
    pub(super) baseline_resource_version: Option<i64>,
}

/// Immutable preconditions for storage-binding deletion.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct BindingDeletePlanInput {
    pub(super) stable_id: String,
    pub(super) owner_scope_key: String,
    pub(super) org_id: Option<i64>,
    pub(super) binding_db_id: i64,
    pub(super) baseline_resource_version: i64,
}

/// Immutable preconditions for setting or rotating one credential purpose.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct BindingCredentialPlanInput {
    pub(super) request: pb::PlanBindingCredentialRequest,
    pub(super) binding_db_id: i64,
    pub(super) owner_scope_key: String,
    pub(super) credential_fingerprint: String,
}

/// Immutable preconditions for granting or revoking binding consumption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct BindingGrantPlanInput {
    pub(super) request: pb::PlanConsumerScopeGrantRequest,
    pub(super) binding_db_id: i64,
    pub(super) owner_scope_key: String,
    pub(super) baseline_grant_resource_version: Option<i64>,
    pub(super) pin_resolutions: Vec<GrantPinResolutionSeal>,
}

/// Exact source and optional replacement target sealed for grant revocation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct GrantPinResolutionSeal {
    pub(super) source: aos_hub_db::db::ConsumerScopeGrantPinRecord,
    pub(super) action_kind: String,
    pub(super) replacement: Option<pb::PinResolutionTarget>,
    pub(super) replacement_resource_version: Option<i64>,
}

/// Durable, replay-safe grant revocation handed to the topology controller.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct GrantRevocationOperationDetail {
    pub(super) resource_kind: String,
    pub(super) resource_stable_id: String,
    pub(super) resource_generation: i64,
    pub(super) consumer_scope_key: String,
    pub(super) expected_grant_resource_version: i64,
    pub(super) resolutions: Vec<GrantPinResolutionSeal>,
    pub(super) actor: String,
    pub(super) request_id: String,
}

/// Immutable preconditions for instance or organization topology defaults.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct TopologyDefaultsPlanInput {
    pub(super) defaults: pb::TopologyDefaults,
    pub(super) org_id: Option<i64>,
    pub(super) baseline_resource_version: Option<i64>,
}

/// Immutable preconditions for organization creation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct OrganizationCreatePlanInput {
    pub(super) request: pb::PlanCreateOrganizationRequest,
}

/// Immutable preconditions for organization profile mutation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct OrganizationUpdatePlanInput {
    pub(super) request: pb::PlanUpdateOrganizationRequest,
    pub(super) org_id: i64,
    pub(super) baseline_resource_version: i64,
}

/// Immutable preconditions for organization deletion.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct OrganizationDeletePlanInput {
    pub(super) request: pb::PlanDeleteOrganizationRequest,
    pub(super) org_id: i64,
    pub(super) baseline_resource_version: i64,
}

/// Immutable preconditions for enrolling or rotating one signing-key generation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct SigningKeyMutationPlanInput {
    pub(super) request: pb::PlanSigningKeyMutationRequest,
    pub(super) baseline: Option<aos_hub_db::db::SigningKeyRecord>,
}

/// Immutable preconditions for retiring one signing-key head.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct SigningKeyRetirementPlanInput {
    pub(super) request: pb::PlanRetireSigningKeyRequest,
    pub(super) baseline: aos_hub_db::db::SigningKeyRecord,
}

/// Immutable preconditions for replacing one typed signing-key usage.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct SigningKeyUsagePlanInput {
    pub(super) request: pb::PlanSigningKeyUsageRequest,
    pub(super) baseline: Option<aos_hub_db::db::SigningKeyUsageRecord>,
    pub(super) consumer: aos_hub_db::db::SigningKeyConsumerRecord,
    pub(super) key: aos_hub_db::db::SigningKeyRecord,
}

/// Immutable preconditions for replacing deployment-wide instance settings.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct InstanceSettingsPlanInput {
    pub(super) writes: Vec<(String, Option<String>)>,
    pub(super) baseline_digest: String,
}

/// Immutable preconditions for creating an organization-owned automation principal.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ServiceAccountCreatePlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) name: String,
    pub(super) baseline_principal_id: Option<i64>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ServiceAccountUpdatePlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) service_account_id: i64,
    pub(super) current_name: String,
    pub(super) new_name: String,
    pub(super) baseline_resource_version: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ServiceAccountDeletePlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) service_account_id: i64,
    pub(super) name: String,
    pub(super) baseline_resource_version: String,
}

/// Immutable preconditions for replacing one direct membership grant.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct MembershipPlanInput {
    pub(super) principal_kind: String,
    pub(super) principal_ref: String,
    pub(super) principal_id: i64,
    pub(super) scope: String,
    pub(super) desired_role: Option<String>,
    pub(super) baseline_role: Option<String>,
}

/// Immutable preconditions for creating one invitation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct InvitationCreatePlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) email: String,
    pub(super) scope: String,
    pub(super) role: String,
    pub(super) ttl_secs: i64,
}

/// Immutable preconditions for cancelling one pending invitation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct InvitationCancelPlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) invitation_id: i64,
    pub(super) baseline_resource_version: String,
    pub(super) baseline_created_at: i64,
}

/// Sealed desired state and exact baseline for one organization IdP mutation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct IdentityProviderSetPlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) issuer: String,
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
    pub(super) jwks_uri: String,
    pub(super) client_id: String,
    pub(super) client_secret_enc: Option<String>,
    pub(super) client_secret_action: String,
    pub(super) scopes: String,
    pub(super) groups_claim: Option<String>,
    pub(super) role_map_json: String,
    pub(super) allow_jit: bool,
    pub(super) enforce_sso: bool,
    pub(super) default_role: String,
    pub(super) baseline_resource_version: Option<i64>,
    pub(super) baseline_incarnation_id: Option<String>,
    pub(super) incarnation_id: String,
}

/// Exact baseline for removing one organization IdP configuration.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct IdentityProviderRemovePlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) baseline_resource_version: i64,
    pub(super) baseline_incarnation_id: Option<String>,
}

/// Exact ownership and revision sealed by an organization-domain plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct OrganizationDomainPlanInput {
    pub(super) org_id: i64,
    pub(super) org_slug: String,
    pub(super) domain: String,
    pub(super) txt_challenge: String,
    pub(super) baseline_resource_version: Option<i64>,
    pub(super) baseline_incarnation_id: Option<String>,
    pub(super) incarnation_id: String,
}

/// Immutable preconditions for issuing one scoped access-token generation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct AccessTokenIssuePlanInput {
    pub(super) owner_kind: String,
    pub(super) owner_ref: String,
    pub(super) owner_id: i64,
    pub(super) scope: String,
    pub(super) permissions: Vec<String>,
    pub(super) ttl_secs: i64,
    pub(super) comment: Option<String>,
}

/// Immutable preconditions for retiring one access-token generation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct AccessTokenRetirementPlanInput {
    pub(super) token_id: String,
}

/// Immutable enrollment identities and CAS state sealed by a reporter plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct AbilityDeploymentReporterPlanInput {
    pub(super) registry_id: i64,
    pub(super) registry_slug: String,
    pub(super) scope_key: String,
    pub(super) deployment: String,
    pub(super) principal_kind: String,
    pub(super) principal_id: i64,
    pub(super) principal_ref: String,
    pub(super) enabled: bool,
    pub(super) baseline_resource_version: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct DomainCreatePlanInput {
    pub(super) request: pb::PlanDomainMutationRequest,
    pub(super) org_id: Option<i64>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct DomainConfigurationPlanInput {
    pub(super) stable_id: String,
    pub(super) owner_scope_key: String,
    pub(super) baseline_resource_version: i64,
    pub(super) dns: Option<aos_hub_db::db::DeliveryDnsConfigurationSpec>,
    pub(super) certificate: Option<aos_hub_db::db::DeliveryCertificateConfigurationSpec>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct DomainDeletePlanInput {
    pub(super) stable_id: String,
    pub(super) owner_scope_key: String,
    pub(super) baseline_resource_version: i64,
}

/// Immutable inputs sealed by a network-boundary creation plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NetworkPolicyCreatePlanInput {
    pub(super) request: pb::PlanNetworkPolicyMutationRequest,
    pub(super) org_id: Option<i64>,
}

/// Immutable inputs sealed by a network-boundary revision plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NetworkPolicyRevisionPlanInput {
    pub(super) request: pb::PlanNetworkPolicyRevisionRequest,
    pub(super) expected_boundary_version: i64,
}

/// Immutable inputs sealed by a network-boundary lifecycle plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NetworkPolicyLifecyclePlanInput {
    pub(super) request: pb::PlanNetworkPolicyLifecycleRequest,
    pub(super) expected_lifecycle_version: i64,
    pub(super) expected_consumer_version: i64,
    pub(super) default_cas: Option<NetworkPolicyDefaultPlanSeal>,
    pub(super) coordination_operation_id: Option<String>,
    pub(super) coordination_impacts: Vec<aos_hub_db::db::NetworkPolicyServingPinRecord>,
    pub(super) coordination_revisions: Vec<aos_hub_db::db::NetworkPolicyCoordinationRevisionSeal>,
    pub(super) coordination_resolutions: Vec<aos_hub_db::db::NetworkPolicyPinResolutionSeal>,
}

/// Serializable form of the exact default-pointer CAS sealed by a lifecycle plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NetworkPolicyDefaultPlanSeal {
    pub(super) boundary_resource_version: i64,
    pub(super) previous_revision: Option<i64>,
    pub(super) previous_resource_version: Option<i64>,
}

/// Immutable inputs sealed by a network-boundary grant plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NetworkPolicyGrantPlanInput {
    pub(super) request: pb::PlanConsumerScopeGrantRequest,
    pub(super) owner_scope_key: String,
    pub(super) baseline_grant_resource_version: Option<i64>,
    pub(super) pin_resolutions: Vec<GrantPinResolutionSeal>,
}

/// Immutable inputs sealed by a network-boundary deletion plan.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct NetworkPolicyDeletePlanInput {
    pub(super) request: pb::PlanDeleteTopologyResourceRequest,
    pub(super) owner_scope_key: String,
    pub(super) expected_resource_version: i64,
}

/// Immutable endpoint creation/update inputs with exact grant carry-forward seals.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct EndpointMutationPlanInput {
    pub(super) request: pb::PlanEndpointMutationRequest,
    pub(super) org_id: Option<i64>,
    pub(super) expected_resource_version: Option<i64>,
    pub(super) owner_grant: Option<EndpointGrantPlanSeal>,
    pub(super) carried_grants: Vec<EndpointGrantPlanSeal>,
    pub(super) affected_resources: Vec<aos_hub_db::db::EndpointImpactRecord>,
    pub(super) old_boundary_revision: Option<DeliveryBoundaryRevisionPlanSeal>,
    pub(super) new_boundary_revision: DeliveryBoundaryRevisionPlanSeal,
}

/// Exact source and target seals for selecting a staged endpoint generation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct EndpointActivationPlanInput {
    pub(super) endpoint_id: String,
    pub(super) source_generation: i64,
    pub(super) source_content_digest: String,
    pub(super) target_generation: i64,
    pub(super) target_content_digest: String,
    pub(super) expected_resource_version: i64,
    pub(super) affected_resources: Vec<aos_hub_db::db::EndpointImpactRecord>,
}

/// Exact source grant copied into a new endpoint generation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct EndpointGrantPlanSeal {
    pub(super) consumer_scope_key: String,
    pub(super) grant_generation: i64,
    pub(super) resource_version: i64,
}

/// Exact desired/observed/lifecycle fence for an endpoint boundary revision.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct DeliveryBoundaryRevisionPlanSeal {
    pub(super) boundary_id: String,
    pub(super) revision: i64,
    pub(super) content_digest: String,
    pub(super) observation_state: String,
    pub(super) observed_at: i64,
    pub(super) lifecycle_state: String,
    pub(super) consumer_version: i64,
    pub(super) resource_version: i64,
}

/// Immutable endpoint scope-grant plan inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct EndpointScopeGrantPlanInput {
    pub(super) request: pb::PlanConsumerScopeGrantRequest,
    pub(super) owner_scope_key: String,
    pub(super) endpoint_generation: i64,
    pub(super) baseline_grant_resource_version: Option<i64>,
    pub(super) pin_resolutions: Vec<GrantPinResolutionSeal>,
}

/// Immutable endpoint deletion inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct EndpointDeletePlanInput {
    pub(super) request: pb::PlanDeleteTopologyResourceRequest,
    pub(super) owner_scope_key: String,
    pub(super) expected_resource_version: i64,
}

/// Immutable gateway enable/disable/delete plan inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct GatewayLifecyclePlanInput {
    pub(super) request: pb::PlanDeleteTopologyResourceRequest,
    pub(super) owner_scope_key: String,
    pub(super) expected_resource_version: i64,
}

/// Immutable gateway creation/update inputs with exact grant carry-forward seals.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct GatewayMutationPlanInput {
    pub(super) request: pb::PlanGatewayMutationRequest,
    pub(super) org_id: Option<i64>,
    pub(super) binding_id: i64,
    pub(super) expected_resource_version: Option<i64>,
    pub(super) owner_grant: Option<GatewayGrantPlanSeal>,
    pub(super) carried_grants: Vec<GatewayGrantPlanSeal>,
}

/// Exact source gateway grant copied into a new immutable generation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct GatewayGrantPlanSeal {
    pub(super) consumer_scope_key: String,
    pub(super) grant_generation: i64,
    pub(super) resource_version: i64,
}

/// Immutable gateway consumer-scope grant plan inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct GatewayScopeGrantPlanInput {
    pub(super) request: pb::PlanConsumerScopeGrantRequest,
    pub(super) owner_scope_key: String,
    pub(super) gateway_generation: i64,
    pub(super) baseline_grant_resource_version: Option<i64>,
    pub(super) pin_resolutions: Vec<GrantPinResolutionSeal>,
}

/// Immutable create/update route inputs and exact URL-reservation candidates.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RouteMutationPlanInput {
    pub(super) request: pb::PlanRouteMutationRequest,
    pub(super) predecessor_route_id: Option<String>,
    pub(super) predecessor_resource_version: Option<i64>,
    pub(super) surface: RouteSurfacePlanSeal,
    pub(super) canonical_url: String,
    pub(super) reservation: Option<RouteReservationPlanSeal>,
    pub(super) expected_resource_version: Option<i64>,
}

/// Stable typed surface identity sealed into route and canonical plans.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RouteSurfacePlanSeal {
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
}

/// Privacy-minimized candidate reservation digests under every retained key.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct RouteReservationPlanSeal {
    pub(super) active_version: i64,
    pub(super) candidates: Vec<RouteReservationDigestPlanSeal>,
}

/// One versioned HMAC digest safe to persist in a topology plan.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct RouteReservationDigestPlanSeal {
    pub(super) key_version: i64,
    pub(super) digest: String,
}

/// Immutable route enable/disable/delete plan inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RouteLifecyclePlanInput {
    pub(super) request: pb::PlanDeleteTopologyResourceRequest,
    pub(super) expected_resource_version: i64,
}

/// Immutable canonical-route selection plan inputs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RouteAdvertisementPlanInput {
    pub(super) request: pb::PlanRouteAdvertisementRequest,
    pub(super) surface: RouteSurfacePlanSeal,
    pub(super) baseline_resource_version: Option<i64>,
}

/// Immutable preconditions for managed-registry identity creation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RegistryCreatePlanInput {
    pub(super) request: pb::PlanCreateRegistryRequest,
    pub(super) org_id: i64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RegistryUpdatePlanInput {
    pub(super) request: pb::PlanUpdateRegistryRequest,
    pub(super) registry_id: i64,
    pub(super) owner_scope_key: String,
    pub(super) expected_resource_version: i64,
}

/// Immutable preconditions for project identity creation.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ProjectCreatePlanInput {
    pub(super) request: pb::PlanCreateProjectRequest,
    pub(super) org_id: i64,
    pub(super) owner_scope_key: String,
}

/// Immutable preconditions for deleting one empty project identity.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ProjectDeletePlanInput {
    pub(super) org_slug: String,
    pub(super) org_id: i64,
    pub(super) project_id: i64,
    pub(super) stable_id: String,
    pub(super) path: String,
    pub(super) expected_resource_version: i64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct WebhookCreatePlanInput {
    pub(super) request: pb::PlanCreateWebhookRequest,
    pub(super) org_id: i64,
    pub(super) owner_scope_key: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct WebhookDeletePlanInput {
    pub(super) webhook_id: i64,
    pub(super) org_id: i64,
    pub(super) owner_scope_key: String,
    pub(super) expected_resource_version: i64,
}

/// Immutable preconditions and desired state for registry-owned mirroring.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RegistryMirrorMutationPlanInput {
    pub(super) request: pb::PlanRegistryMirrorMutationRequest,
    pub(super) registry_db_id: i64,
    pub(super) baseline_resource_version: Option<i64>,
}

/// Immutable preconditions for deleting registry-owned mirroring.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RegistryMirrorDeletePlanInput {
    pub(super) request: pb::PlanDeleteTopologyResourceRequest,
    pub(super) registry_db_id: i64,
    pub(super) baseline_resource_version: i64,
}

/// Stored preconditions for making a surface explicitly read-only.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RemoveWriteAuthorityPlanInput {
    pub(super) registry_id: Option<i64>,
    pub(super) cache_id: Option<i64>,
    pub(super) authority_id: i64,
    pub(super) authority_incarnation_id: String,
    pub(super) authority_resource_version: i64,
    pub(super) observed_generation: i64,
    pub(super) observed_placement_name: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct BinaryCacheMutationPlanInput {
    pub(super) request: pb::PlanBinaryCacheMutationRequest,
    pub(super) org_id: i64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct BinaryCacheDeletePlanInput {
    pub(super) cache_id: i64,
    pub(super) stable_id: String,
    pub(super) expected_resource_version: i64,
}
