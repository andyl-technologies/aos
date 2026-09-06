//! Executes reviewed plan/apply protocols and shared topology lifecycle mutations.

use crate::cli::{HubMutationArgs, HubOperationArgs, HubReviewedApplyArgs};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_generation_ref;
use crate::commands::hub::operation::print_or_wait_operation;
use crate::commands::hub::output::{print_hub_json, print_topology_message, topology_message_kind};
use crate::commands::hub::pins::read_pin_resolutions;
use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_remote::{HubClient, HubRpc, hub_types};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Builds the reviewed topology-plan application request.
pub(super) fn apply_topology_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyTopologyPlanRequest {
    hub_types::ApplyTopologyPlanRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

/// Builds the reviewed organization-plan application request.
pub(super) fn apply_organization_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyOrganizationMutationRequest {
    hub_types::ApplyOrganizationMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

/// Builds the reviewed registry-plan application request.
pub(super) fn apply_registry_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyRegistryMutationRequest {
    hub_types::ApplyRegistryMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

/// Builds the reviewed project-plan application request.
pub(super) fn apply_project_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyProjectMutationRequest {
    hub_types::ApplyProjectMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

/// Builds the reviewed webhook-plan application request.
pub(super) fn apply_webhook_plan(
    plan_id: &str,
    idempotency_key: &str,
    confirmation_hash: &str,
) -> hub_types::ApplyWebhookMutationRequest {
    hub_types::ApplyWebhookMutationRequest {
        plan_id: plan_id.into(),
        confirmation_hash: confirmation_hash.into(),
        idempotency_key: idempotency_key.into(),
    }
}

/// Calls and prints one read-only topology RPC.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands) async fn topology_read<Req, Resp>(
    printer: &Printer,
    client: &HubClient,
    method: impl HubRpc<Request = Req, Response = Resp>,
    request: &Req,
) -> Result<()>
where
    Req: Serialize,
    Resp: DeserializeOwned + Serialize,
{
    let response: Resp = client.call_topology(method, request).await?;
    print_topology_message(printer, &response)
}

/// Executes the shared plan/apply protocol for one topology mutation.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands) async fn topology_mutation<PlanReq, ApplyReq, Resp, BuildApply>(
    printer: &Printer,
    client: &HubClient,
    plan_method: impl HubRpc<Request = PlanReq, Response = hub_types::TopologyPlanResponse>,
    apply_method: impl HubRpc<Request = ApplyReq, Response = Resp> + Copy,
    plan_request: &PlanReq,
    mutation: &HubMutationArgs,
    build_apply: BuildApply,
) -> Result<()>
where
    PlanReq: Serialize + DeserializeOwned,
    ApplyReq: Serialize,
    Resp: DeserializeOwned + Serialize,
    BuildApply: Fn(&str, &str, &str) -> ApplyReq,
{
    let idempotency_key = if mutation.plan_id.is_some() {
        mutation
            .idempotency_key
            .clone()
            .context("--idempotency-key is required when applying a reviewed plan")?
    } else {
        mutation
            .idempotency_key
            .clone()
            .unwrap_or_else(|| format!("aos-cli-{:032x}", rand::random::<u128>()))
    };
    if let Some(plan_id) = mutation.plan_id.as_deref() {
        if !confirm_destructive(mutation.yes, "reviewed Hub plan application")? {
            printer.info("plan application cancelled");
            return Ok(());
        }
        let response: Resp = client
            .call_topology(
                apply_method,
                &build_apply(
                    plan_id,
                    &idempotency_key,
                    mutation.confirm_hash.as_deref().unwrap_or_default(),
                ),
            )
            .await?;
        if printer.mode() == OutputMode::Json {
            let value = serde_json::json!({
                "plan_id": plan_id,
                "applied": true,
                "result": serde_json::to_value(response)?,
            });
            print_hub_json(printer, &topology_message_kind::<Resp>(), value);
            return Ok(());
        }
        return print_topology_message(printer, &response);
    }

    let mut plan_value = serde_json::to_value(plan_request)?;
    let plan_object = plan_value
        .as_object_mut()
        .context("Hub plan request must serialize as an object")?;
    plan_object.insert(
        "idempotencyKey".to_string(),
        serde_json::Value::String(idempotency_key.clone()),
    );
    let plan_request: PlanReq = serde_json::from_value(plan_value)?;
    let planned: hub_types::TopologyPlanResponse =
        client.call_topology(plan_method, &plan_request).await?;
    let plan = planned
        .plan
        .as_ref()
        .context("the Hub returned a topology plan response without a plan")?;
    print_topology_message(printer, &planned)?;
    if !mutation.plan {
        printer.info(&format!(
            "review the plan, then apply it with --plan-id {} --confirm-hash {} --idempotency-key {}",
            plan.plan_id, plan.confirmation_hash, idempotency_key
        ));
    }
    Ok(())
}

/// Applies a reviewed topology plan and optionally waits for its operation.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn topology_operation_mutation<PlanReq>(
    printer: &Printer,
    client: &HubClient,
    plan_method: impl HubRpc<Request = PlanReq, Response = hub_types::TopologyPlanResponse>,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyTopologyPlanRequest,
        Response = hub_types::OperationResponse,
    > + Copy,
    plan_request: &PlanReq,
    mutation: &HubMutationArgs,
    operation: &HubOperationArgs,
) -> Result<()>
where
    PlanReq: Serialize + DeserializeOwned,
{
    let idempotency_key = if mutation.plan_id.is_some() {
        mutation
            .idempotency_key
            .clone()
            .context("--idempotency-key is required when applying a reviewed plan")?
    } else {
        mutation
            .idempotency_key
            .clone()
            .unwrap_or_else(new_idempotency_key)
    };
    if let Some(plan_id) = mutation.plan_id.as_deref() {
        if !confirm_destructive(mutation.yes, "reviewed Hub plan application")? {
            printer.info("plan application cancelled");
            return Ok(());
        }
        let response = client
            .call_topology(
                apply_method,
                &hub_types::ApplyTopologyPlanRequest {
                    plan_id: plan_id.into(),
                    confirmation_hash: mutation.confirm_hash.clone().unwrap_or_default(),
                    idempotency_key,
                },
            )
            .await?;
        return print_or_wait_operation(printer, client, &response, operation).await;
    }
    let mut plan_value = serde_json::to_value(plan_request)?;
    plan_value
        .as_object_mut()
        .context("Hub plan request must serialize as an object")?
        .insert(
            "idempotencyKey".to_string(),
            serde_json::Value::String(idempotency_key.clone()),
        );
    let plan_request: PlanReq = serde_json::from_value(plan_value)?;
    let planned: hub_types::TopologyPlanResponse =
        client.call_topology(plan_method, &plan_request).await?;
    let plan = planned
        .plan
        .as_ref()
        .context("the Hub returned a topology plan response without a plan")?;
    print_topology_message(printer, &planned)?;
    if !mutation.plan {
        printer.info(&format!(
            "review the plan, then apply it with --plan-id {} --confirm-hash {} --idempotency-key {}",
            plan.plan_id, plan.confirmation_hash, idempotency_key
        ));
    }
    Ok(())
}

/// Creates a fresh idempotency key for a hub mutation.
pub(in crate::commands) fn new_idempotency_key() -> String {
    format!("aos-cli-{:032x}", rand::random::<u128>())
}

/// Preserves an explicit identity or generates a typed stable identity.
pub(super) fn topology_stable_id(explicit: Option<&str>, kind: &str) -> String {
    explicit
        .map(str::to_string)
        .unwrap_or_else(|| format!("{kind}:{:032x}", rand::random::<u128>()))
}

/// Adapts one explicit retained-control plan subcommand to the shared RPC
/// executor without reintroducing the overloaded mutation flags in clap.
pub(super) fn retained_plan_mutation(
    idempotency_key: &str,
    if_version: Option<&str>,
) -> HubMutationArgs {
    HubMutationArgs {
        idempotency_key: Some(idempotency_key.to_string()),
        plan: true,
        if_version: if_version.map(str::to_string),
        ..HubMutationArgs::default()
    }
}

/// Adapts one sealed retained-control apply subcommand to the shared RPC
/// executor.
pub(super) fn retained_apply_mutation(apply: &HubReviewedApplyArgs) -> HubMutationArgs {
    HubMutationArgs {
        idempotency_key: Some(apply.idempotency_key.clone()),
        plan_id: Some(apply.plan_id.clone()),
        confirm_hash: Some(apply.confirm_hash.clone()),
        yes: apply.yes,
        ..HubMutationArgs::default()
    }
}

/// Requires the resource version needed to plan an existing-resource mutation.
///
/// # Errors
///
/// Returns an error if the required resource version is missing.
pub(super) fn required_plan_version<'a>(
    mutation: &'a HubMutationArgs,
    action: &str,
) -> Result<&'a str> {
    mutation
        .if_version
        .as_deref()
        .filter(|version| !version.is_empty())
        .with_context(|| format!("{action} requires --if-version when creating a plan"))
}

/// Requests confirmation unless the caller supplied the affirmative CLI flag.
///
/// # Errors
///
/// Returns an error if confirmation requires a terminal or terminal I/O fails.
pub(super) fn confirm_destructive(yes: bool, action: &str) -> Result<bool> {
    use std::io::{IsTerminal as _, Write as _};

    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("{action} requires confirmation on a terminal or --yes");
    }
    let mut stderr = std::io::stderr().lock();
    write!(stderr, "Confirm {action}? [y/N] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Plans or applies a change to a topology resource consumer scope.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn consumer_scope_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    resource_kind: &str,
    resource_id: &str,
    resource_generation: i64,
    consumer_scope: &str,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanConsumerScopeGrantRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyConsumerScopeGrantRequest,
        Response = hub_types::ConsumerScopeGrantResponse,
    > + Copy,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_mutation::<
        _,
        hub_types::ApplyConsumerScopeGrantRequest,
        hub_types::ConsumerScopeGrantResponse,
        _,
    >(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanConsumerScopeGrantRequest {
            resource_kind: resource_kind.into(),
            resource_stable_id: resource_id.into(),
            resource_generation,
            consumer_scope_key: consumer_scope.into(),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
            pin_resolutions: read_pin_resolutions(mutation)?,
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyConsumerScopeGrantRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

/// Plans or applies deletion of a versioned topology resource.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn delete_topology_resource(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    stable_id: &str,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanDeleteTopologyResourceRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyDeleteTopologyResourceRequest,
        Response = hub_types::DeleteTopologyResourceResponse,
    > + Copy,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_mutation::<
        _,
        hub_types::ApplyDeleteTopologyResourceRequest,
        hub_types::DeleteTopologyResourceResponse,
        _,
    >(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.into(),
            expected_resource_version: if mutation.plan_id.is_some() {
                None
            } else {
                Some(required_plan_version(mutation, "topology resource deletion")?.into())
            },
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| {
            hub_types::ApplyDeleteTopologyResourceRequest {
                plan_id: plan_id.into(),
                idempotency_key: idempotency_key.into(),
                confirmation_hash: confirmation_hash.into(),
            }
        },
    )
    .await
}

/// Plans or applies a boundary resource lifecycle transition.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn boundary_lifecycle_mutation(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    boundary_revision: &str,
    activation_mode: &str,
    default_for_new_plans: bool,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanNetworkPolicyLifecycleRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyNetworkPolicyLifecycleRequest,
        Response = hub_types::NetworkPolicyRevisionResponse,
    > + Copy,
) -> Result<()> {
    let (boundary_id, revision) =
        parse_generation_ref(boundary_revision, "network policy revision")?;
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_mutation::<
        _,
        hub_types::ApplyNetworkPolicyLifecycleRequest,
        hub_types::NetworkPolicyRevisionResponse,
        _,
    >(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanNetworkPolicyLifecycleRequest {
            boundary_id,
            revision,
            activation_mode: activation_mode.into(),
            default_for_new_plans,
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
            pin_resolutions: read_pin_resolutions(mutation)?,
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| {
            hub_types::ApplyNetworkPolicyLifecycleRequest {
                plan_id: plan_id.into(),
                idempotency_key: idempotency_key.into(),
                confirmation_hash: confirmation_hash.into(),
            }
        },
    )
    .await
}

/// Plans or applies a topology resource state transition.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn topology_state_mutation<Resp>(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    stable_id: &str,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanDeleteTopologyResourceRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<Request = hub_types::ApplyDeleteTopologyResourceRequest, Response = Resp>
    + Copy,
) -> Result<()>
where
    Resp: DeserializeOwned + Serialize,
{
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_mutation::<_, hub_types::ApplyDeleteTopologyResourceRequest, Resp, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanDeleteTopologyResourceRequest {
            stable_id: stable_id.into(),
            expected_resource_version: if mutation.plan_id.is_some() {
                None
            } else {
                Some(required_plan_version(mutation, "topology state mutation")?.into())
            },
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| {
            hub_types::ApplyDeleteTopologyResourceRequest {
                plan_id: plan_id.into(),
                idempotency_key: idempotency_key.into(),
                confirmation_hash: confirmation_hash.into(),
            }
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_stable_ids_preserve_overrides_and_generate_typed_ids() {
        assert_eq!(
            topology_stable_id(Some("endpoint:operator-chosen"), "delivery-endpoint"),
            "endpoint:operator-chosen"
        );

        let generated = topology_stable_id(None, "delivery-endpoint");
        let suffix = generated
            .strip_prefix("delivery-endpoint:")
            .expect("generated endpoint identity has its resource prefix");
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
