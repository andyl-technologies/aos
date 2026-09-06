//! Handles hub access token commands and their domain-specific request validation.

use crate::cli::{
    HubAccessTokenCmd, HubAccessTokenIssueCmd, HubAccessTokenRetireCmd, HubReviewedApplyArgs,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub access token command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn access_token(printer: &Printer, command: &HubAccessTokenCmd) -> Result<()> {
    match command {
        HubAccessTokenCmd::List {
            access,
            scope,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListAccessTokensResponse>(
                printer,
                &client,
                HubTopologyMethod::ListAccessTokens,
                &hub_types::ListAccessTokensRequest {
                    scope: scope.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubAccessTokenCmd::Issue { command } => match command {
            HubAccessTokenIssueCmd::Plan {
                request,
                scope,
                owner,
                permissions,
                ttl_secs,
                comment,
                if_version,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, if_version.as_deref());
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::AccessTokenResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanIssueAccessToken,
                    HubTopologyMethod::IssueAccessToken,
                    &hub_types::PlanIssueAccessTokenRequest {
                        owner: owner.clone(),
                        scope: scope.clone(),
                        permissions: permissions.clone(),
                        ttl_secs: ttl_secs.unwrap_or_default(),
                        expected_resource_version: if_version.clone().unwrap_or_default(),
                        idempotency_key: request.idempotency_key.clone(),
                        comment: comment.clone().unwrap_or_default(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubAccessTokenIssueCmd::Apply(apply) => apply_access_token_issue(printer, apply).await,
        },
        HubAccessTokenCmd::Retire { command } => match command {
            HubAccessTokenRetireCmd::Plan {
                request,
                token_id,
                if_version,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::AccessTokenRetirementResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRetireAccessToken,
                    HubTopologyMethod::RetireAccessToken,
                    &hub_types::PlanRetireAccessTokenRequest {
                        token_id: token_id.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubAccessTokenRetireCmd::Apply(apply) => {
                apply_access_token_retirement(printer, apply).await
            }
        },
    }
}

async fn apply_access_token_issue(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::AccessTokenResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanIssueAccessToken,
        HubTopologyMethod::IssueAccessToken,
        &hub_types::PlanIssueAccessTokenRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_access_token_retirement(
    printer: &Printer,
    apply: &HubReviewedApplyArgs,
) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<
        _,
        hub_types::ApplyTopologyPlanRequest,
        hub_types::AccessTokenRetirementResponse,
        _,
    >(
        printer,
        &client,
        HubTopologyMethod::PlanRetireAccessToken,
        HubTopologyMethod::RetireAccessToken,
        &hub_types::PlanRetireAccessTokenRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}
