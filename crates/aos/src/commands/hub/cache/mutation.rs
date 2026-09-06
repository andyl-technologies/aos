//! Handles hub cache mutation commands and their domain-specific request validation.

use crate::cli::HubMutationArgs;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{confirm_destructive, topology_mutation, topology_read};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{HubRpc, hub_types};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Executes the reviewed plan/apply protocol for a cache mutation.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn cache_plan_mutation<PlanReq, Resp>(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    _cache_id: &str,
    plan_method: impl HubRpc<Request = PlanReq, Response = hub_types::TopologyPlanResponse>,
    apply_method: impl HubRpc<Request = hub_types::ApplyCachePlanRequest, Response = Resp> + Copy,
    request: &PlanReq,
    mutation: &HubMutationArgs,
) -> Result<()>
where
    PlanReq: Serialize + DeserializeOwned,
    Resp: DeserializeOwned + Serialize,
{
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_mutation::<_, hub_types::ApplyCachePlanRequest, Resp, _>(
        printer,
        &client,
        plan_method,
        apply_method,
        request,
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyCachePlanRequest {
            plan_id: plan_id.into(),
            confirmation_hash: confirmation_hash.into(),
            idempotency_key: idempotency_key.into(),
        },
    )
    .await
}

/// Applies a retained cache plan with its confirmation hash and idempotency key.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn apply_reviewed_cache_plan<Resp>(
    printer: &Printer,
    access: &crate::cli::HubAccessArgs,
    _cache_id: &str,
    plan_id: &str,
    confirmation_hash: &str,
    idempotency_key: &str,
    yes: bool,
    method: impl HubRpc<Request = hub_types::ApplyCachePlanRequest, Response = Resp>,
    action: &str,
) -> Result<()>
where
    Resp: DeserializeOwned + Serialize,
{
    if !confirm_destructive(yes, action)? {
        printer.info(&format!("{action} cancelled"));
        return Ok(());
    }
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    topology_read::<_, Resp>(
        printer,
        &client,
        method,
        &hub_types::ApplyCachePlanRequest {
            plan_id: plan_id.into(),
            confirmation_hash: confirmation_hash.into(),
            idempotency_key: idempotency_key.into(),
        },
    )
    .await
}
