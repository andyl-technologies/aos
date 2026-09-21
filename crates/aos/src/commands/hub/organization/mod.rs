//! Handles hub organization commands and their domain-specific request validation.

use crate::cli::HubOrgCmd;
use crate::commands::hub::audit::audit;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::instance::organization_topology_defaults;
use crate::commands::hub::mutation::apply_organization_plan;
use crate::commands::hub::mutation::{
    new_idempotency_key, required_plan_version, topology_mutation, topology_read,
};
use crate::commands::hub::organization::domain::organization_domain;
use crate::commands::hub::organization::identity_provider::identity_provider;
use crate::commands::hub::organization::invitation::invitation;
use crate::commands::hub::organization::membership::org_member;
use crate::commands::hub::organization::project::project;
use crate::commands::hub::organization::service_account::service_account;
use crate::commands::hub::webhook::webhook;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};

/// Resolves the explicit organization or the active profile organization scope.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn organization_scope_key(
    client: &HubClient,
    org: Option<&str>,
) -> Result<String> {
    let Some(slug) = org else {
        return Ok("instance".into());
    };
    let response: hub_types::OrganizationResponse = client
        .call_topology(
            HubTopologyMethod::GetOrganization,
            &hub_types::GetOrganizationRequest { slug: slug.into() },
        )
        .await
        .with_context(|| format!("resolving organization '{slug}'"))?;
    let organization = response
        .organization
        .with_context(|| format!("Hub returned no organization for '{slug}'"))?;
    anyhow::ensure!(
        !organization.stable_id.is_empty(),
        "Hub returned organization '{slug}' without a stable identity"
    );
    Ok(organization.stable_id)
}

/// Handles `aos hub org …`.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn org(printer: &Printer, command: &HubOrgCmd) -> Result<()> {
    match command {
        HubOrgCmd::List { access, pagination } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListOrganizationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListOrganizations,
                &hub_types::ListOrganizationsRequest {
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubOrgCmd::Show { access, org } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::OrganizationResponse>(
                printer,
                &client,
                HubTopologyMethod::GetOrganization,
                &hub_types::GetOrganizationRequest { slug: org.clone() },
            )
            .await
        }
        HubOrgCmd::Create {
            access,
            slug,
            display_name,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateOrganization,
                    HubTopologyMethod::CreateOrganization,
                    &hub_types::PlanCreateOrganizationRequest::default(),
                    mutation,
                    apply_organization_plan,
                )
                .await;
            }
            topology_mutation::<
                _,
                hub_types::ApplyOrganizationMutationRequest,
                hub_types::OrganizationResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateOrganization,
                HubTopologyMethod::CreateOrganization,
                &hub_types::PlanCreateOrganizationRequest {
                    slug: slug
                        .clone()
                        .context("org create requires --slug when creating a plan")?,
                    display_name: display_name
                        .clone()
                        .context("org create requires --display-name when creating a plan")?,
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_organization_plan,
            )
            .await
        }
        HubOrgCmd::Update {
            access,
            org,
            display_name,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanUpdateOrganization,
                    HubTopologyMethod::UpdateOrganization,
                    &hub_types::PlanUpdateOrganizationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyOrganizationMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let org = org
                .as_ref()
                .context("org update requires <org> when creating a plan")?;
            let display_name = display_name
                .as_ref()
                .context("org update requires --display-name when creating a plan")?;
            topology_mutation::<
                _,
                hub_types::ApplyOrganizationMutationRequest,
                hub_types::OrganizationResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanUpdateOrganization,
                HubTopologyMethod::UpdateOrganization,
                &hub_types::PlanUpdateOrganizationRequest {
                    slug: org.to_string(),
                    display_name: display_name.clone(),
                    expected_resource_version: required_plan_version(
                        mutation,
                        "organization update",
                    )?
                    .into(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyOrganizationMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubOrgCmd::Delete {
            access,
            org,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanDeleteOrganization,
                    HubTopologyMethod::DeleteOrganization,
                    &hub_types::PlanDeleteOrganizationRequest::default(),
                    mutation,
                    apply_organization_plan,
                )
                .await;
            }
            topology_mutation::<
                _,
                hub_types::ApplyOrganizationMutationRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteOrganization,
                HubTopologyMethod::DeleteOrganization,
                &hub_types::PlanDeleteOrganizationRequest {
                    slug: org
                        .clone()
                        .context("org delete requires <org> when creating a plan")?,
                    expected_resource_version: required_plan_version(
                        mutation,
                        "organization deletion",
                    )?
                    .into(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_organization_plan,
            )
            .await
        }
        HubOrgCmd::TopologyDefaults { command } => {
            organization_topology_defaults(printer, command).await
        }
        HubOrgCmd::Project { command } => project(printer, command).await,
        HubOrgCmd::Audit { command } => audit(printer, command).await,
        HubOrgCmd::Webhook { command } => webhook(printer, command).await,
        HubOrgCmd::Member { command } => org_member(printer, command).await,
        HubOrgCmd::ServiceAccount { command } => service_account(printer, command).await,
        HubOrgCmd::Invitation { command } => invitation(printer, command).await,
        HubOrgCmd::IdentityProvider { command } => identity_provider(printer, command).await,
        HubOrgCmd::Domain { command } => organization_domain(printer, command).await,
    }
}

mod domain;
mod identity_provider;
mod invitation;
mod membership;
pub(super) mod project;
mod service_account;
