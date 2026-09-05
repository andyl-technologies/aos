//! Handles hub instance commands and their domain-specific request validation.

use crate::cli::{
    HubInstanceCmd, HubInstanceSettingsMutationCmd, HubInstanceSettingsSectionCmd,
    HubInstanceTopologyDefaultsCmd, HubMutationArgs, HubOrgTopologyDefaultsCmd,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_generation_ref;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    new_idempotency_key, retained_apply_mutation, retained_plan_mutation, topology_mutation,
    topology_read,
};
use crate::commands::hub::output::print_topology_message;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubClient, HubRpc, hub_rpc as HubTopologyMethod, hub_types};

/// Handles `aos hub instance …` (get/set deployment-wide instance settings).
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn instance(printer: &Printer, command: &HubInstanceCmd) -> Result<()> {
    match command {
        HubInstanceCmd::Identity { command } => {
            instance_settings_section(printer, "identity", command).await
        }
        HubInstanceCmd::ResourceDefaults { command } => {
            instance_settings_section(printer, "resource-defaults", command).await
        }
        HubInstanceCmd::Branding { command } => {
            instance_settings_section(printer, "branding", command).await
        }
        HubInstanceCmd::TopologyDefaults { command } => {
            instance_topology_defaults(printer, command).await
        }
    }
}

/// Handles one topologically owned instance-settings section.
async fn instance_settings_section(
    printer: &Printer,
    section: &str,
    command: &HubInstanceSettingsSectionCmd,
) -> Result<()> {
    match command {
        HubInstanceSettingsSectionCmd::Show { access } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetInstanceSettingsResponse>(
                printer,
                &client,
                HubTopologyMethod::GetInstanceSettings,
                &hub_types::GetInstanceSettingsRequest {},
            )
            .await
        }
        HubInstanceSettingsSectionCmd::Update { command } => match command {
            HubInstanceSettingsMutationCmd::Plan {
                request,
                assignments,
                clear,
                if_version,
            } => {
                let mut values = std::collections::HashMap::new();
                for assignment in assignments {
                    let (key, value) = assignment
                        .split_once('=')
                        .context("instance assignments use KEY=VALUE")?;
                    require_instance_section_key(section, key)?;
                    values.insert(key.to_string(), value.to_string());
                }
                for key in clear {
                    require_instance_section_key(section, key)?;
                }
                if values.is_empty() && clear.is_empty() {
                    anyhow::bail!(
                        "instance {section} update plan requires KEY=VALUE or --clear KEY"
                    );
                }
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::GetInstanceSettingsResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetInstanceSettings,
                    HubTopologyMethod::SetInstanceSettings,
                    &hub_types::PlanSetInstanceSettingsRequest {
                        values,
                        clear: clear.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubInstanceSettingsMutationCmd::Apply(apply) => {
                let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
                let mutation = retained_apply_mutation(apply);
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::GetInstanceSettingsResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetInstanceSettings,
                    HubTopologyMethod::SetInstanceSettings,
                    &hub_types::PlanSetInstanceSettingsRequest::default(),
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
        },
    }
}

/// Rejects settings owned by a different instance section before planning.
fn require_instance_section_key(section: &str, key: &str) -> Result<()> {
    let valid = match section {
        "identity" => matches!(
            key,
            "signup_policy" | "signup_domains" | "password_login" | "session_lifetime_secs"
        ),
        "resource-defaults" => matches!(
            key,
            "caches_public" | "default_crawl_policy" | "max_upload_bytes"
        ),
        "branding" => matches!(
            key,
            "site_title" | "tagline" | "announcement" | "tos_url" | "privacy_url" | "support_url"
        ),
        _ => false,
    };
    anyhow::ensure!(valid, "setting '{key}' is not owned by instance {section}");
    Ok(())
}

fn set_generation_ref(
    value: Option<&String>,
    stable_id: &mut String,
    generation: &mut i64,
    kind: &str,
) -> Result<()> {
    if let Some(value) = value {
        if value.contains('@') {
            let (id, parsed_generation) = parse_generation_ref(value, kind)?;
            *stable_id = id;
            *generation = parsed_generation;
        } else {
            *stable_id = value.clone();
            *generation = 0;
        }
    }
    Ok(())
}

async fn apply_topology_defaults(
    printer: &Printer,
    client: &HubClient,
    mut defaults: hub_types::TopologyDefaults,
    binding: Option<&String>,
    domain: Option<&String>,
    endpoint: Option<&String>,
    gateway: Option<&String>,
    clear_binding: bool,
    clear_domain: bool,
    clear_endpoint: bool,
    clear_gateway: bool,
    mutation: &HubMutationArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanSetTopologyDefaultsRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplySetTopologyDefaultsRequest,
        Response = hub_types::TopologyDefaultsResponse,
    > + Copy,
) -> Result<()> {
    if let Some(value) = binding {
        defaults.binding_id = value.clone();
    }
    if let Some(value) = domain {
        defaults.domain_id = value.clone();
    }
    set_generation_ref(
        endpoint,
        &mut defaults.endpoint_id,
        &mut defaults.endpoint_generation,
        "endpoint",
    )?;
    set_generation_ref(
        gateway,
        &mut defaults.gateway_id,
        &mut defaults.gateway_generation,
        "gateway",
    )?;
    if clear_binding {
        defaults.binding_id.clear();
    }
    if clear_domain {
        defaults.domain_id.clear();
    }
    if clear_endpoint {
        defaults.endpoint_id.clear();
        defaults.endpoint_generation = 0;
    }
    if clear_gateway {
        defaults.gateway_id.clear();
        defaults.gateway_generation = 0;
    }
    topology_mutation::<
        _,
        hub_types::ApplySetTopologyDefaultsRequest,
        hub_types::TopologyDefaultsResponse,
        _,
    >(
        printer,
        client,
        plan_method,
        apply_method,
        &hub_types::PlanSetTopologyDefaultsRequest {
            defaults: Some(defaults),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplySetTopologyDefaultsRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

/// Plans or applies organization-wide topology defaults.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn organization_topology_defaults(
    printer: &Printer,
    command: &HubOrgTopologyDefaultsCmd,
) -> Result<()> {
    let (access, org) = match command {
        HubOrgTopologyDefaultsCmd::Show { access, org }
        | HubOrgTopologyDefaultsCmd::Set { access, org, .. }
        | HubOrgTopologyDefaultsCmd::Clear { access, org, .. } => (access, org),
    };
    let client = hub_client(&access.hub, access.token.as_deref())?;
    if let HubOrgTopologyDefaultsCmd::Set { mutation, .. }
    | HubOrgTopologyDefaultsCmd::Clear { mutation, .. } = command
    {
        if mutation.plan_id.is_some() {
            return apply_topology_defaults(
                printer,
                &client,
                hub_types::TopologyDefaults::default(),
                None,
                None,
                None,
                None,
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetOrganizationTopologyDefaults,
                HubTopologyMethod::SetOrganizationTopologyDefaults,
            )
            .await;
        }
    }
    let current: hub_types::TopologyDefaultsResponse = client
        .call_topology(
            HubTopologyMethod::GetOrganizationTopologyDefaults,
            &hub_types::GetOrganizationTopologyDefaultsRequest {
                org_slug: org.clone(),
            },
        )
        .await?;
    match command {
        HubOrgTopologyDefaultsCmd::Show { .. } => print_topology_message(printer, &current),
        HubOrgTopologyDefaultsCmd::Set {
            binding,
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if binding.is_none() && domain.is_none() && endpoint.is_none() && gateway.is_none() {
                anyhow::bail!("topology-defaults set requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                binding.as_ref(),
                domain.as_ref(),
                endpoint.as_ref(),
                gateway.as_ref(),
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetOrganizationTopologyDefaults,
                HubTopologyMethod::SetOrganizationTopologyDefaults,
            )
            .await
        }
        HubOrgTopologyDefaultsCmd::Clear {
            binding,
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if !*binding && !*domain && !*endpoint && !*gateway {
                anyhow::bail!("topology-defaults clear requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                None,
                None,
                None,
                None,
                *binding,
                *domain,
                *endpoint,
                *gateway,
                mutation,
                HubTopologyMethod::PlanSetOrganizationTopologyDefaults,
                HubTopologyMethod::SetOrganizationTopologyDefaults,
            )
            .await
        }
    }
}

async fn instance_topology_defaults(
    printer: &Printer,
    command: &HubInstanceTopologyDefaultsCmd,
) -> Result<()> {
    let access = match command {
        HubInstanceTopologyDefaultsCmd::Show { access }
        | HubInstanceTopologyDefaultsCmd::Set { access, .. }
        | HubInstanceTopologyDefaultsCmd::Clear { access, .. } => access,
    };
    let client = hub_client(&access.hub, access.token.as_deref())?;
    if let HubInstanceTopologyDefaultsCmd::Set { mutation, .. }
    | HubInstanceTopologyDefaultsCmd::Clear { mutation, .. } = command
    {
        if mutation.plan_id.is_some() {
            return apply_topology_defaults(
                printer,
                &client,
                hub_types::TopologyDefaults::default(),
                None,
                None,
                None,
                None,
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetInstanceTopologyDefaults,
                HubTopologyMethod::SetInstanceTopologyDefaults,
            )
            .await;
        }
    }
    let current: hub_types::TopologyDefaultsResponse = client
        .call_topology(
            HubTopologyMethod::GetInstanceTopologyDefaults,
            &hub_types::GetInstanceTopologyDefaultsRequest {},
        )
        .await?;
    match command {
        HubInstanceTopologyDefaultsCmd::Show { .. } => print_topology_message(printer, &current),
        HubInstanceTopologyDefaultsCmd::Set {
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if domain.is_none() && endpoint.is_none() && gateway.is_none() {
                anyhow::bail!("topology-defaults set requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                None,
                domain.as_ref(),
                endpoint.as_ref(),
                gateway.as_ref(),
                false,
                false,
                false,
                false,
                mutation,
                HubTopologyMethod::PlanSetInstanceTopologyDefaults,
                HubTopologyMethod::SetInstanceTopologyDefaults,
            )
            .await
        }
        HubInstanceTopologyDefaultsCmd::Clear {
            domain,
            endpoint,
            gateway,
            mutation,
            ..
        } => {
            if !*domain && !*endpoint && !*gateway {
                anyhow::bail!("topology-defaults clear requires at least one default");
            }
            apply_topology_defaults(
                printer,
                &client,
                current.defaults.unwrap_or_default(),
                None,
                None,
                None,
                None,
                false,
                *domain,
                *endpoint,
                *gateway,
                mutation,
                HubTopologyMethod::PlanSetInstanceTopologyDefaults,
                HubTopologyMethod::SetInstanceTopologyDefaults,
            )
            .await
        }
    }
}
