//! Handles hub organization domain commands and their domain-specific request validation.

use crate::cli::{
    HubOrganizationDomainClaimCmd, HubOrganizationDomainCmd, HubOrganizationDomainReleaseCmd,
    HubOrganizationDomainVerifyCmd,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub organization domain command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn organization_domain(
    printer: &Printer,
    command: &HubOrganizationDomainCmd,
) -> Result<()> {
    match command {
        HubOrganizationDomainCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::ListOrganizationDomains,
                &hub_types::ListOrganizationDomainsRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubOrganizationDomainCmd::Show {
            access,
            org,
            domain,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                HubTopologyMethod::GetOrganizationDomain,
                &hub_types::GetOrganizationDomainRequest {
                    org_slug: org.clone(),
                    domain: domain.clone(),
                },
            )
            .await
        }
        HubOrganizationDomainCmd::Claim { command } => match command {
            HubOrganizationDomainClaimCmd::Plan {
                request,
                org,
                domain,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanClaimOrganizationDomain,
                    HubTopologyMethod::ClaimOrganizationDomain,
                    &hub_types::PlanClaimOrganizationDomainRequest {
                        org_slug: org.clone(),
                        domain: domain.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubOrganizationDomainClaimCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::OrganizationDomainResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanClaimOrganizationDomain,
                    HubTopologyMethod::ClaimOrganizationDomain,
                    &hub_types::PlanClaimOrganizationDomainRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubOrganizationDomainCmd::Verify { command } => match command {
            HubOrganizationDomainVerifyCmd::Plan {
                request,
                org,
                domain,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanVerifyOrganizationDomain,
                    HubTopologyMethod::VerifyOrganizationDomain,
                    &hub_types::PlanVerifyOrganizationDomainRequest {
                        org_slug: org.clone(),
                        domain: domain.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubOrganizationDomainVerifyCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::OrganizationDomainResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanVerifyOrganizationDomain,
                    HubTopologyMethod::VerifyOrganizationDomain,
                    &hub_types::PlanVerifyOrganizationDomainRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
        HubOrganizationDomainCmd::Release { command } => match command {
            HubOrganizationDomainReleaseCmd::Plan {
                request,
                org,
                domain,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation = retained_plan_mutation(&request.idempotency_key, Some(if_version));
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReleaseOrganizationDomain,
                    HubTopologyMethod::ReleaseOrganizationDomain,
                    &hub_types::PlanReleaseOrganizationDomainRequest {
                        org_slug: org.clone(),
                        domain: domain.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubOrganizationDomainReleaseCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReleaseOrganizationDomain,
                    HubTopologyMethod::ReleaseOrganizationDomain,
                    &hub_types::PlanReleaseOrganizationDomainRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}
