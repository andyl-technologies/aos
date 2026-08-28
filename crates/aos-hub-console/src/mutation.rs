//! Shared immutable plan/apply state for browser resource editors.
//!
//! Editors retain the exact server plan, confirmation hash, and idempotency
//! key as one value. Apply callbacks therefore cannot accidentally recompute a
//! plan or combine confirmation material from two requests.

#[cfg(target_arch = "wasm32")]
use std::sync::atomic::{AtomicU32, Ordering};

/// One exact reviewed mutation awaiting confirmation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PendingPlan {
    /// Immutable server-issued plan.
    pub(crate) plan: aos_proto_types::TopologyPlan,
    /// Idempotency key shared by the plan and apply request.
    pub(crate) idempotency_key: String,
}

/// Returns whether a tag ownership class accepts manual CAS mutation.
pub(crate) fn container_tag_is_manually_mutable(ownership_kind: &str) -> bool {
    ownership_kind == "manual"
}

/// Returns whether the live route capability allows manual tag mutation.
pub(crate) fn container_tag_controls_visible(allows: impl FnOnce(&str) -> bool) -> bool {
    allows("publish")
}

impl PendingPlan {
    /// Extracts a complete pending plan from an API response.
    pub(crate) fn from_response(
        response: aos_proto_types::TopologyPlanResponse,
        idempotency_key: String,
    ) -> Result<Self, String> {
        let plan = response
            .plan
            .ok_or_else(|| "the Hub omitted the reviewed plan".to_string())?;
        if plan.plan_id.is_empty() || plan.confirmation_hash.is_empty() {
            return Err("the Hub returned an incomplete reviewed plan".to_string());
        }
        Ok(Self {
            plan,
            idempotency_key,
        })
    }

    /// Builds the common topology apply envelope for this exact plan.
    pub(crate) fn topology_apply(&self) -> aos_proto_types::ApplyTopologyPlanRequest {
        aos_proto_types::ApplyTopologyPlanRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds an organization apply envelope for this exact plan.
    pub(crate) fn organization_apply(&self) -> aos_proto_types::ApplyOrganizationMutationRequest {
        aos_proto_types::ApplyOrganizationMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a project apply envelope for this exact plan.
    pub(crate) fn project_apply(&self) -> aos_proto_types::ApplyProjectMutationRequest {
        aos_proto_types::ApplyProjectMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a registry apply envelope for this exact plan.
    pub(crate) fn registry_apply(&self) -> aos_proto_types::ApplyRegistryMutationRequest {
        aos_proto_types::ApplyRegistryMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a binary-cache apply envelope for this exact plan.
    pub(crate) fn cache_apply(&self) -> aos_proto_types::ApplyBinaryCacheMutationRequest {
        aos_proto_types::ApplyBinaryCacheMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a cache policy/operation apply envelope for this exact plan.
    pub(crate) fn cache_plan_apply(&self) -> aos_proto_types::ApplyCachePlanRequest {
        aos_proto_types::ApplyCachePlanRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a container-administration apply envelope for this exact plan.
    pub(crate) fn container_apply(&self) -> aos_proto_types::ApplyContainerMutationRequest {
        aos_proto_types::ApplyContainerMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a topology-resource deletion envelope for this exact plan.
    pub(crate) fn delete_apply(&self) -> aos_proto_types::ApplyDeleteTopologyResourceRequest {
        aos_proto_types::ApplyDeleteTopologyResourceRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a storage-binding apply envelope for this exact plan.
    pub(crate) fn binding_apply(&self) -> aos_proto_types::ApplyBindingMutationRequest {
        aos_proto_types::ApplyBindingMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a storage-credential apply envelope for this exact plan.
    pub(crate) fn storage_credential_apply(
        &self,
    ) -> aos_proto_types::ApplyBindingCredentialRequest {
        aos_proto_types::ApplyBindingCredentialRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a consumer-scope grant apply envelope for this exact plan.
    pub(crate) fn consumer_grant_apply(&self) -> aos_proto_types::ApplyConsumerScopeGrantRequest {
        aos_proto_types::ApplyConsumerScopeGrantRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a topology-defaults apply envelope for this exact plan.
    pub(crate) fn topology_defaults_apply(
        &self,
    ) -> aos_proto_types::ApplySetTopologyDefaultsRequest {
        aos_proto_types::ApplySetTopologyDefaultsRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a domain-identity apply envelope for this exact plan.
    pub(crate) fn domain_apply(&self) -> aos_proto_types::ApplyDomainMutationRequest {
        aos_proto_types::ApplyDomainMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a domain-configuration apply envelope for this exact plan.
    pub(crate) fn domain_configuration_apply(
        &self,
    ) -> aos_proto_types::ApplyDomainConfigurationRequest {
        aos_proto_types::ApplyDomainConfigurationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a network-boundary identity apply envelope for this exact plan.
    pub(crate) fn network_policy_apply(
        &self,
    ) -> aos_proto_types::ApplyNetworkPolicyMutationRequest {
        aos_proto_types::ApplyNetworkPolicyMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a network-boundary revision apply envelope for this exact plan.
    pub(crate) fn network_policy_revision_apply(
        &self,
    ) -> aos_proto_types::ApplyNetworkPolicyRevisionRequest {
        aos_proto_types::ApplyNetworkPolicyRevisionRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a boundary lifecycle apply envelope for this exact plan.
    pub(crate) fn network_policy_lifecycle_apply(
        &self,
    ) -> aos_proto_types::ApplyNetworkPolicyLifecycleRequest {
        aos_proto_types::ApplyNetworkPolicyLifecycleRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a delivery-endpoint identity apply envelope for this exact plan.
    pub(crate) fn endpoint_apply(&self) -> aos_proto_types::ApplyEndpointMutationRequest {
        aos_proto_types::ApplyEndpointMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds an endpoint-generation apply envelope for this exact plan.
    pub(crate) fn endpoint_generation_apply(
        &self,
    ) -> aos_proto_types::ApplyEndpointGenerationRequest {
        aos_proto_types::ApplyEndpointGenerationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a storage-gateway mutation apply envelope for this exact plan.
    pub(crate) fn gateway_apply(&self) -> aos_proto_types::ApplyGatewayMutationRequest {
        aos_proto_types::ApplyGatewayMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a delivery-route mutation apply envelope for this exact plan.
    pub(crate) fn route_apply(&self) -> aos_proto_types::ApplyRouteMutationRequest {
        aos_proto_types::ApplyRouteMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a canonical-route apply envelope for this exact plan.
    pub(crate) fn route_advertisement_apply(
        &self,
    ) -> aos_proto_types::ApplyRouteAdvertisementRequest {
        aos_proto_types::ApplyRouteAdvertisementRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
static IDEMPOTENCY_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Generates a collision-resistant, non-secret browser idempotency key.
#[cfg(target_arch = "wasm32")]
pub(crate) fn idempotency_key(action: &str) -> String {
    let time = js_sys::Date::now().to_bits();
    let random = (js_sys::Math::random() * u64::MAX as f64) as u64;
    let sequence = IDEMPOTENCY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("web-{action}-{time:016x}-{random:016x}-{sequence:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_plan_rejects_missing_confirmation_material() {
        let response = aos_proto_types::TopologyPlanResponse {
            plan: Some(aos_proto_types::TopologyPlan {
                plan_id: "plan:one".to_string(),
                ..Default::default()
            }),
        };
        assert!(PendingPlan::from_response(response, "key".to_string()).is_err());
    }

    #[test]
    fn container_apply_preserves_the_reviewed_plan_and_idempotency_key() {
        let reviewed = PendingPlan::from_response(
            aos_proto_types::TopologyPlanResponse {
                plan: Some(aos_proto_types::TopologyPlan {
                    plan_id: "plan:container".to_string(),
                    confirmation_hash: "sha256:confirmation".to_string(),
                    ..Default::default()
                }),
            },
            "web-container-same-key".to_string(),
        )
        .expect("complete plan must be retained");

        let apply = reviewed.container_apply();
        assert_eq!(apply.plan_id, "plan:container");
        assert_eq!(apply.confirmation_hash, "sha256:confirmation");
        assert_eq!(apply.idempotency_key, "web-container-same-key");
    }

    #[test]
    fn signed_container_tags_never_enable_manual_controls() {
        assert!(container_tag_is_manually_mutable("manual"));
        assert!(!container_tag_is_manually_mutable("release"));
        assert!(!container_tag_is_manually_mutable("channel"));
    }

    #[test]
    fn admin_configure_only_does_not_expose_tag_mutation_controls() {
        let permissions = ["read", "registry.configure"];
        assert!(!container_tag_controls_visible(|required| {
            permissions.contains(&required)
        }));
    }

    #[test]
    fn maintainer_publish_exposes_tag_mutation_controls() {
        let permissions = ["read", "publish", "channel.advance", "keys.manage"];
        assert!(container_tag_controls_visible(|required| {
            permissions.contains(&required)
        }));
    }
}
