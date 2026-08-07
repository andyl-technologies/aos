//! Shared immutable plan/apply state for browser resource editors.
//!
//! Editors retain the exact server plan, confirmation hash, and idempotency
//! key as one value. Apply callbacks therefore cannot accidentally recompute a
//! plan or combine confirmation material from two requests.

use std::sync::atomic::{AtomicU32, Ordering};

/// One exact reviewed mutation awaiting confirmation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PendingPlan {
    /// Immutable server-issued plan.
    pub(crate) plan: aos_proto_types::TopologyPlan,
    /// Idempotency key shared by the plan and apply request.
    pub(crate) idempotency_key: String,
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

    /// Builds a topology-resource deletion envelope for this exact plan.
    pub(crate) fn delete_apply(&self) -> aos_proto_types::ApplyDeleteTopologyResourceRequest {
        aos_proto_types::ApplyDeleteTopologyResourceRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a storage-binding apply envelope for this exact plan.
    pub(crate) fn storage_binding_apply(
        &self,
    ) -> aos_proto_types::ApplyStorageBindingMutationRequest {
        aos_proto_types::ApplyStorageBindingMutationRequest {
            plan_id: self.plan.plan_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            confirmation_hash: self.plan.confirmation_hash.clone(),
        }
    }

    /// Builds a storage-credential apply envelope for this exact plan.
    pub(crate) fn storage_credential_apply(
        &self,
    ) -> aos_proto_types::ApplyStorageBindingCredentialRequest {
        aos_proto_types::ApplyStorageBindingCredentialRequest {
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
}

static IDEMPOTENCY_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Generates a collision-resistant, non-secret browser idempotency key.
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
}
