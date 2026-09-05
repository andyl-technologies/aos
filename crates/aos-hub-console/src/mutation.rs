//! Shared immutable plan/apply state for browser resource editors.
//!
//! Editors retain the exact server plan, confirmation hash, and idempotency
//! key as one value. Apply callbacks therefore cannot accidentally recompute a
//! plan or combine confirmation material from two requests.

#[cfg(target_arch = "wasm32")]
use std::{
    cell::RefCell,
    future::Future,
    sync::atomic::{AtomicU32, Ordering},
};

#[cfg(target_arch = "wasm32")]
use futures::future::{AbortHandle, Abortable};
#[cfg(target_arch = "wasm32")]
use leptos::prelude::*;

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, PartialEq)]
struct WorkflowTaskScope {
    handles: StoredValue<Vec<(u32, AbortHandle)>>,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static ACTIVE_WORKFLOW_TASK_SCOPE: RefCell<Option<WorkflowTaskScope>> = const {
        RefCell::new(None)
    };
}

#[cfg(target_arch = "wasm32")]
static WORKFLOW_TASK_SEQUENCE: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "wasm32")]
impl WorkflowTaskScope {
    fn new() -> Self {
        let handles = StoredValue::new(Vec::<(u32, AbortHandle)>::new());
        on_cleanup(move || {
            let _ = handles.try_update_value(|handles| {
                for (_, handle) in handles.drain(..) {
                    handle.abort();
                }
            });
        });
        Self { handles }
    }

    fn spawn(self, task: impl Future<Output = ()> + 'static) {
        let task_id = WORKFLOW_TASK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let (handle, registration) = AbortHandle::new_pair();
        if self
            .handles
            .try_update_value(|handles| handles.push((task_id, handle)))
            .is_none()
        {
            return;
        }

        leptos::task::spawn_local(async move {
            let _ = Abortable::new(task, registration).await;
            let _ = self.handles.try_update_value(|handles| {
                handles.retain(|(id, _)| *id != task_id);
            });
        });
    }
}

/// Installs the async task scope owned by one mounted resource workflow.
#[cfg(target_arch = "wasm32")]
pub(crate) fn install_workflow_task_scope() {
    let scope = WorkflowTaskScope::new();
    ACTIVE_WORKFLOW_TASK_SCOPE.with(|active| {
        *active.borrow_mut() = Some(scope);
    });
    on_cleanup(move || {
        ACTIVE_WORKFLOW_TASK_SCOPE.with(|active| {
            let mut active = active.borrow_mut();
            if *active == Some(scope) {
                *active = None;
            }
        });
    });
}

/// Spawns a task that is canceled when its resource workflow is unmounted.
#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn_workflow_task(task: impl Future<Output = ()> + 'static) {
    ACTIVE_WORKFLOW_TASK_SCOPE.with(|active| {
        if let Some(scope) = *active.borrow() {
            scope.spawn(task);
        }
    });
}

/// One exact reviewed mutation awaiting confirmation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PendingPlan {
    /// Immutable server-issued plan.
    pub(crate) plan: aos_proto_types::TopologyPlan,
    /// Idempotency key shared by the plan and apply request.
    pub(crate) idempotency_key: String,
}

/// Invalidates a reviewed plan whenever any signal observed by `observe` changes.
///
/// The returned epoch lets an asynchronous planning request discard a response
/// when the draft changed while the request was in flight.
#[cfg(target_arch = "wasm32")]
pub(crate) fn watch_draft(
    observe: impl Fn() + 'static,
    pending: RwSignal<Option<PendingPlan>>,
    error: RwSignal<Option<String>>,
) -> RwSignal<u64> {
    let epoch = RwSignal::new(0_u64);
    Effect::new(move |_| {
        observe();
        epoch.update(|value| *value = value.wrapping_add(1));
        pending.set(None);
        error.set(None);
    });
    epoch
}

/// Returns whether a tag ownership class accepts manual CAS mutation.
pub(crate) fn container_tag_is_manually_mutable(ownership_kind: &str) -> bool {
    ownership_kind == "manual"
}

/// Returns whether the live route capability allows manual tag mutation.
pub(crate) fn container_tag_controls_visible(allows: impl FnOnce(&str) -> bool) -> bool {
    allows("publish")
}

/// Returns the exact retention-policy resource version used by a GC plan.
pub(crate) fn effective_container_retention_version(value: &str) -> String {
    if value.is_empty() {
        "0".to_string()
    } else {
        value.to_string()
    }
}

/// Returns whether a reviewed GC plan can expose its destructive apply control.
pub(crate) fn container_gc_plan_is_applicable(
    response: &aos_proto_types::ContainerGcPlanResponse,
) -> bool {
    response.blockers.is_empty()
        && response
            .run
            .as_ref()
            .is_some_and(|run| run.state == "planned")
}

/// Extracts the positive optimistic-concurrency version frozen by a repair plan.
pub(crate) fn reviewed_plan_resource_version(
    response: &aos_proto_types::TopologyPlanResponse,
) -> Result<String, String> {
    response
        .plan
        .as_ref()
        .and_then(|plan| {
            plan.input_versions
                .iter()
                .find_map(|value| value.strip_prefix("resource_version="))
        })
        .filter(|value| value.parse::<u64>().is_ok_and(|version| version > 0))
        .map(str::to_string)
        .ok_or_else(|| "The repair plan omitted its positive resource-version CAS.".to_string())
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

    /// Builds a coordinated delivery-workflow apply envelope for this plan.
    pub(crate) fn delivery_workflow_apply(
        &self,
    ) -> aos_proto_types::ApplyDeliveryDestinationRequest {
        aos_proto_types::ApplyDeliveryDestinationRequest {
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

    #[test]
    fn default_retention_policy_binds_gc_to_version_zero() {
        assert_eq!(effective_container_retention_version(""), "0");
        assert_eq!(effective_container_retention_version("7"), "7");
    }

    #[test]
    fn blockers_and_non_planned_states_hide_apply_controls() {
        let planned = aos_proto_types::ContainerGcPlanResponse {
            run: Some(aos_proto_types::ContainerGcRun {
                state: "planned".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(container_gc_plan_is_applicable(&planned));

        let mut blocked = planned.clone();
        blocked.blockers.push(aos_proto_types::ContainerGcBlocker {
            kind: "stale_inventory".to_string(),
            detail: "placement inventory is stale".to_string(),
            ..Default::default()
        });
        assert!(!container_gc_plan_is_applicable(&blocked));

        let mut failed = planned;
        failed.run.as_mut().unwrap().state = "failed".to_string();
        assert!(!container_gc_plan_is_applicable(&failed));
    }

    #[test]
    fn untracked_repair_apply_requires_the_exact_positive_plan_version() {
        let response = aos_proto_types::TopologyPlanResponse {
            plan: Some(aos_proto_types::TopologyPlan {
                input_versions: vec!["resource_version=2".to_string()],
                ..Default::default()
            }),
        };
        assert_eq!(reviewed_plan_resource_version(&response).unwrap(), "2");

        for value in [
            "resource_version=0",
            "resource_version=-1",
            "mutation_epoch=2",
        ] {
            let response = aos_proto_types::TopologyPlanResponse {
                plan: Some(aos_proto_types::TopologyPlan {
                    input_versions: vec![value.to_string()],
                    ..Default::default()
                }),
            };
            assert!(reviewed_plan_resource_version(&response).is_err());
        }
    }
}
