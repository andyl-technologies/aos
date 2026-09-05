//! Handles hub membership commands and their domain-specific request validation.

use crate::cli::{
    HubMembershipRemoveCmd, HubMembershipSetRoleCmd, HubOrgMemberCmd, HubReviewedApplyArgs,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub org member command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn org_member(printer: &Printer, command: &HubOrgMemberCmd) -> Result<()> {
    match command {
        HubOrgMemberCmd::Show {
            access,
            principal_kind,
            principal,
            scope,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::MembershipResponse>(
                printer,
                &client,
                HubTopologyMethod::GetMembership,
                &hub_types::GetMembershipRequest {
                    principal_kind: principal_kind.clone(),
                    principal_ref: principal.clone(),
                    scope: scope.clone(),
                },
            )
            .await
        }
        HubOrgMemberCmd::SetRole { command } => match command {
            HubMembershipSetRoleCmd::Plan {
                request,
                principal_kind,
                principal,
                scope,
                role,
                if_version,
            } => {
                plan_membership(
                    printer,
                    request,
                    principal_kind,
                    principal,
                    scope,
                    role,
                    if_version,
                )
                .await
            }
            HubMembershipSetRoleCmd::Apply(apply) => apply_membership(printer, apply).await,
        },
        HubOrgMemberCmd::Remove { command } => match command {
            HubMembershipRemoveCmd::Plan {
                request,
                principal_kind,
                principal,
                scope,
                if_version,
            } => {
                plan_membership(
                    printer,
                    request,
                    principal_kind,
                    principal,
                    scope,
                    "",
                    if_version,
                )
                .await
            }
            HubMembershipRemoveCmd::Apply(apply) => apply_membership(printer, apply).await,
        },
    }
}

async fn plan_membership(
    printer: &Printer,
    request: &crate::cli::HubReviewedPlanArgs,
    principal_kind: &str,
    principal: &str,
    scope: &str,
    role: &str,
    if_version: &str,
) -> Result<()> {
    let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
    let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::MembershipResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanSetMembership,
        HubTopologyMethod::SetMembership,
        &hub_types::PlanSetMembershipRequest {
            principal_kind: principal_kind.to_string(),
            principal_ref: principal.to_string(),
            scope: scope.to_string(),
            role: role.to_string(),
            expected_resource_version: if_version.to_string(),
            idempotency_key: request.idempotency_key.clone(),
        },
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_membership(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::MembershipResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanSetMembership,
        HubTopologyMethod::SetMembership,
        &hub_types::PlanSetMembershipRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}
