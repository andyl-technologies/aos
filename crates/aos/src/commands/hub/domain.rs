//! Handles hub domain commands and their domain-specific request validation.

use crate::cli::{HubDomainCertificateCmd, HubDomainCmd, HubDomainDnsCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{
    delete_topology_resource, new_idempotency_key, required_plan_version, topology_mutation,
    topology_operation_mutation, topology_read,
};
use crate::commands::hub::organization::organization_scope_key;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub domain command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn domain(printer: &Printer, command: &HubDomainCmd) -> Result<()> {
    match command {
        HubDomainCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListDomainsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListDomains,
                &hub_types::ListDomainsRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDomainCmd::Show { access, hostname } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::DomainResponse>(
                printer,
                &client,
                HubTopologyMethod::GetDomain,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: hostname.clone(),
                },
            )
            .await
        }
        HubDomainCmd::Status { access, hostname } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::DomainResponse>(
                printer,
                &client,
                HubTopologyMethod::GetDomain,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: hostname.clone(),
                },
            )
            .await
        }
        HubDomainCmd::Add {
            access,
            hostname,
            org,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_mutation::<
                _,
                hub_types::ApplyDomainMutationRequest,
                hub_types::DomainResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateDomain,
                HubTopologyMethod::CreateDomain,
                &hub_types::PlanDomainMutationRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    hostname: hostname.clone(),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyDomainMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubDomainCmd::Dns { command } => domain_dns(printer, command).await,
        HubDomainCmd::Certificate { command } => domain_certificate(printer, command).await,
        HubDomainCmd::Verify {
            access,
            hostname,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "domain verification")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanVerifyDomain,
                HubTopologyMethod::VerifyDomain,
                &hub_types::PlanVerifyDomainRequest {
                    stable_id: hostname.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
        HubDomainCmd::Remove {
            access,
            hostname,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                hostname,
                mutation,
                HubTopologyMethod::PlanDeleteDomain,
                HubTopologyMethod::DeleteDomain,
            )
            .await
        }
    }
}

async fn domain_stable_id(client: &HubClient, domain_ref: &str) -> Result<String> {
    let response: hub_types::DomainResponse = client
        .call_topology(
            HubTopologyMethod::GetDomain,
            &hub_types::GetTopologyResourceRequest {
                stable_id: domain_ref.into(),
            },
        )
        .await?;
    response
        .domain
        .map(|domain| domain.stable_id)
        .context("the Hub returned a domain response without a domain")
}

async fn domain_dns(printer: &Printer, command: &HubDomainDnsCmd) -> Result<()> {
    let HubDomainDnsCmd::Configure {
        access,
        hostname,
        mode,
        provider,
        zone_id,
        record_ttl,
        expected_target,
        mutation,
    } = command;
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let domain_id = domain_stable_id(&client, hostname).await?;
    let configuration = if mode == "external" {
        if provider.is_some() || zone_id.is_some() || record_ttl.is_some() {
            anyhow::bail!("external DNS rejects Hub-managed DNS options");
        }
        hub_types::dns_configuration::Configuration::External(hub_types::ExternalDnsConfiguration {
            expected_target: expected_target
                .clone()
                .context("--expected-target is required for external DNS")?,
        })
    } else {
        if expected_target.is_some() {
            anyhow::bail!("hub-managed DNS rejects --expected-target");
        }
        hub_types::dns_configuration::Configuration::HubManaged(
            hub_types::HubManagedDnsConfiguration {
                provider: provider
                    .clone()
                    .context("--provider is required for hub-managed DNS")?,
                zone_id: zone_id
                    .clone()
                    .context("--zone-id is required for hub-managed DNS")?,
                record_mode: "managed".into(),
                ttl_seconds: record_ttl.unwrap_or(300),
                ..Default::default()
            },
        )
    };
    topology_mutation::<_, hub_types::ApplyDomainConfigurationRequest, hub_types::DomainResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanConfigureDomainDns,
        HubTopologyMethod::ConfigureDomainDns,
        &hub_types::PlanDomainDnsRequest {
            stable_id: domain_id,
            configuration: Some(hub_types::DnsConfiguration {
                configuration: Some(configuration),
            }),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyDomainConfigurationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}

async fn domain_certificate(printer: &Printer, command: &HubDomainCertificateCmd) -> Result<()> {
    let HubDomainCertificateCmd::Configure {
        access,
        hostname,
        mode,
        certificate_ref,
        mutation,
    } = command;
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let domain_id = domain_stable_id(&client, hostname).await?;
    let configuration = if mode == "external" {
        hub_types::certificate_configuration::Configuration::External(
            hub_types::ExternalCertificateConfiguration {
                certificate_secret_ref: certificate_ref
                    .clone()
                    .context("--certificate-ref is required for external certificates")?,
            },
        )
    } else {
        if certificate_ref.is_some() {
            anyhow::bail!("hub-managed certificates reject --certificate-ref");
        }
        hub_types::certificate_configuration::Configuration::HubManaged(
            hub_types::HubManagedCertificateConfiguration::default(),
        )
    };
    topology_mutation::<_, hub_types::ApplyDomainConfigurationRequest, hub_types::DomainResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanConfigureDomainCertificate,
        HubTopologyMethod::ConfigureDomainCertificate,
        &hub_types::PlanDomainCertificateRequest {
            stable_id: domain_id,
            configuration: Some(hub_types::CertificateConfiguration {
                configuration: Some(configuration),
            }),
            expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
            idempotency_key: new_idempotency_key(),
        },
        mutation,
        |plan_id, idempotency_key, confirmation_hash| hub_types::ApplyDomainConfigurationRequest {
            plan_id: plan_id.into(),
            idempotency_key: idempotency_key.into(),
            confirmation_hash: confirmation_hash.into(),
        },
    )
    .await
}
