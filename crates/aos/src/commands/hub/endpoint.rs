//! Handles hub endpoint commands and their domain-specific request validation.

use crate::cli::HubEndpointCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{
    consumer_scope_mutation, delete_topology_resource, new_idempotency_key, topology_mutation,
    topology_read, topology_stable_id,
};
use crate::commands::hub::organization::organization_scope_key;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};
use serde::Serialize;

fn endpoint_ingress_kind(value: &str) -> Result<i32> {
    let kind = match value {
        "hub" => hub_types::EndpointIngressKind::Hub,
        "external" => hub_types::EndpointIngressKind::External,
        "layer7" => hub_types::EndpointIngressKind::Layer7,
        _ => anyhow::bail!("endpoint ingress must be hub, external, or layer7"),
    };
    Ok(kind as i32)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointProbeIdentity<'a> {
    provider: &'a str,
    signer_secret_ref: &'a str,
    public_key: &'a str,
}

fn endpoint_probe_configuration(
    provider: Option<&str>,
    signer_secret_ref: Option<&str>,
    public_key: Option<&str>,
) -> Result<Option<String>> {
    match (provider, signer_secret_ref, public_key) {
        (Some(provider), Some(signer_secret_ref), Some(public_key)) => {
            let provider = provider.replace('-', "_");
            Ok(Some(serde_json::to_string(&EndpointProbeIdentity {
                provider: &provider,
                signer_secret_ref,
                public_key,
            })?))
        }
        (None, None, None) => Ok(None),
        _ => anyhow::bail!(
            "--probe-provider, --probe-signer-secret-ref, and --probe-public-key must be supplied together"
        ),
    }
}

fn parse_delivery_origin(value: &str) -> Result<(String, hub_types::EndpointHost, u32)> {
    let url = reqwest::Url::parse(value).context("parsing endpoint URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("endpoint URLs require http or https");
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("endpoint URLs reject userinfo, query, and fragment components");
    }
    if url.path() != "/" && !url.path().is_empty() {
        anyhow::bail!("endpoint URLs contain only an origin; configure paths on routes");
    }
    let host_text = url.host_str().context("endpoint URL has no host")?;
    let ip_text = host_text
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host_text);
    let host = match ip_text.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            hub_types::endpoint_host::Host::Ipv4(address.octets().to_vec())
        }
        Ok(std::net::IpAddr::V6(address)) => {
            hub_types::endpoint_host::Host::Ipv6(address.octets().to_vec())
        }
        Err(_) => hub_types::endpoint_host::Host::DomainId(host_text.to_ascii_lowercase()),
    };
    let port = url
        .port_or_known_default()
        .context("endpoint URL scheme has no effective port")?;
    Ok((
        url.scheme().into(),
        hub_types::EndpointHost { host: Some(host) },
        u32::from(port),
    ))
}

/// Handles the hub endpoint command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn endpoint(printer: &Printer, command: &HubEndpointCmd) -> Result<()> {
    match command {
        HubEndpointCmd::List {
            access,
            org,
            include_granted,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListEndpointsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListEndpoints,
                &hub_types::ListTopologyResourcesRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                },
            )
            .await
        }
        HubEndpointCmd::Show { access, endpoint } | HubEndpointCmd::Status { access, endpoint } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::EndpointResponse>(
                printer,
                &client,
                HubTopologyMethod::GetEndpoint,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: endpoint.clone(),
                },
            )
            .await
        }
        HubEndpointCmd::Generations {
            access,
            endpoint,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListEndpointGenerationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListEndpointGenerations,
                &hub_types::ListEndpointGenerationsRequest {
                    endpoint_id: endpoint.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubEndpointCmd::Generation {
            access,
            endpoint,
            generation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::EndpointGenerationResponse>(
                printer,
                &client,
                HubTopologyMethod::GetEndpointGeneration,
                &hub_types::GetEndpointGenerationRequest {
                    endpoint_id: endpoint.clone(),
                    generation: *generation,
                },
            )
            .await
        }
        HubEndpointCmd::Add {
            access,
            origin,
            stable_id,
            org,
            acknowledge_cleartext,
            network_policy,
            ingress,
            listener_provider,
            listener_resource_id,
            tls_provider,
            certificate_ref,
            probe_provider,
            probe_signer_secret_ref,
            probe_public_key,
            mutation,
        } => {
            let (scheme, mut host, effective_port) = parse_delivery_origin(origin)?;
            if scheme == "http" && !acknowledge_cleartext {
                anyhow::bail!("http endpoints require --acknowledge-cleartext");
            }
            if scheme == "http" && (tls_provider.is_some() || certificate_ref.is_some()) {
                anyhow::bail!("http endpoints reject TLS options");
            }
            if scheme == "https" && tls_provider.is_none() {
                anyhow::bail!("https endpoints require --tls-provider");
            }
            if certificate_ref.is_some() && tls_provider.is_none() {
                anyhow::bail!("--certificate-ref requires --tls-provider");
            }
            if tls_provider.as_deref() == Some("external") && certificate_ref.is_none() {
                anyhow::bail!("external TLS requires --certificate-ref");
            }
            let tls = tls_provider
                .as_ref()
                .map(|provider| hub_types::TlsConfiguration {
                    provider: provider.clone(),
                    certificate_ref: certificate_ref.clone().unwrap_or_default(),
                    ..Default::default()
                });
            let probe_configuration_ref = endpoint_probe_configuration(
                Some(probe_provider),
                Some(probe_signer_secret_ref),
                Some(probe_public_key),
            )?
            .context("endpoint creation requires probe signing identity")?;
            let (boundary_id, boundary_revision) = network_policy
                .rsplit_once('@')
                .map(|(id, revision)| {
                    Ok::<_, anyhow::Error>((id.to_string(), revision.parse::<i64>()?))
                })
                .transpose()?
                .unwrap_or_else(|| (network_policy.clone(), 0));
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if let Some(hub_types::endpoint_host::Host::DomainId(hostname)) = host.host.as_mut() {
                let response: hub_types::DomainResponse = client
                    .call_topology(
                        HubTopologyMethod::GetDomain,
                        &hub_types::GetTopologyResourceRequest {
                            stable_id: hostname.clone(),
                        },
                    )
                    .await
                    .with_context(|| format!("resolving endpoint domain '{hostname}'"))?;
                *hostname = response
                    .domain
                    .context("the Hub returned no domain while resolving endpoint origin")?
                    .stable_id;
            }
            topology_mutation::<
                _,
                hub_types::ApplyEndpointMutationRequest,
                hub_types::EndpointResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateEndpoint,
                HubTopologyMethod::CreateEndpoint,
                &hub_types::PlanEndpointMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "delivery-endpoint"),
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    scheme,
                    host: Some(host),
                    effective_port,
                    network_policy_id: boundary_id,
                    revision: Some(hub_types::EndpointRevisionSpec {
                        boundary_revision,
                        ingress_kind: endpoint_ingress_kind(ingress)?,
                        listener_configuration_ref: format!(
                            "{listener_provider}:{listener_resource_id}"
                        ),
                        tls,
                        probe_configuration_ref,
                    }),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyEndpointMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubEndpointCmd::Stage {
            access,
            endpoint,
            ingress,
            boundary_revision,
            listener_provider,
            listener_resource_id,
            tls_provider,
            certificate_ref,
            probe_provider,
            probe_signer_secret_ref,
            probe_public_key,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanStageEndpointGeneration,
                    HubTopologyMethod::StageEndpointGeneration,
                    &hub_types::PlanStageEndpointGenerationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyEndpointGenerationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            if ingress.is_none()
                && boundary_revision.is_none()
                && listener_provider.is_none()
                && listener_resource_id.is_none()
                && tls_provider.is_none()
                && certificate_ref.is_none()
                && probe_provider.is_none()
                && probe_signer_secret_ref.is_none()
                && probe_public_key.is_none()
            {
                anyhow::bail!("endpoint stage requires at least one changed field");
            }
            let listener_configuration_ref = match (listener_provider, listener_resource_id) {
                (Some(provider), Some(resource)) => format!("{provider}:{resource}"),
                (Some(_), None) | (None, Some(_)) => anyhow::bail!(
                    "--listener-provider and --listener-resource-id must be supplied together"
                ),
                (None, None) => String::new(),
            };
            if certificate_ref.is_some() && tls_provider.is_none() {
                anyhow::bail!("--certificate-ref requires --tls-provider");
            }
            if tls_provider.as_deref() == Some("external") && certificate_ref.is_none() {
                anyhow::bail!("external TLS requires --certificate-ref");
            }
            let tls = tls_provider
                .as_ref()
                .map(|provider| hub_types::TlsConfiguration {
                    provider: provider.clone(),
                    certificate_ref: certificate_ref.clone().unwrap_or_default(),
                    ..Default::default()
                });
            let probe_configuration_ref = endpoint_probe_configuration(
                probe_provider.as_deref(),
                probe_signer_secret_ref.as_deref(),
                probe_public_key.as_deref(),
            )?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyEndpointGenerationRequest,
                hub_types::EndpointGenerationResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanStageEndpointGeneration,
                HubTopologyMethod::StageEndpointGeneration,
                &hub_types::PlanStageEndpointGenerationRequest {
                    endpoint_id: endpoint.clone(),
                    revision: Some(hub_types::EndpointRevisionSpec {
                        boundary_revision: boundary_revision
                            .map(|value| i64::try_from(value))
                            .transpose()?
                            .unwrap_or_default(),
                        ingress_kind: ingress
                            .as_deref()
                            .map(endpoint_ingress_kind)
                            .transpose()?
                            .unwrap_or_default(),
                        listener_configuration_ref,
                        tls,
                        probe_configuration_ref: probe_configuration_ref
                            .clone()
                            .unwrap_or_default(),
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: [
                        boundary_revision
                            .as_ref()
                            .map(|_| "revision.boundary_revision"),
                        ingress.as_ref().map(|_| "revision.ingress_kind"),
                        listener_provider
                            .as_ref()
                            .map(|_| "revision.listener_configuration_ref"),
                        tls_provider.as_ref().map(|_| "revision.tls"),
                        probe_configuration_ref
                            .as_ref()
                            .map(|_| "revision.probe_configuration_ref"),
                    ]
                    .into_iter()
                    .flatten()
                    .map(str::to_string)
                    .collect(),
                    carry_forward_consumer_scopes: Vec::new(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyEndpointGenerationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubEndpointCmd::Activate {
            access,
            endpoint,
            generation,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyEndpointGenerationRequest,
                hub_types::EndpointResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanActivateEndpointGeneration,
                HubTopologyMethod::ActivateEndpointGeneration,
                &hub_types::PlanActivateEndpointGenerationRequest {
                    endpoint_id: endpoint.clone(),
                    generation: *generation,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyEndpointGenerationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubEndpointCmd::Grant {
            access,
            endpoint,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "endpoint",
                endpoint,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanGrantEndpointScope,
                HubTopologyMethod::GrantEndpointScope,
            )
            .await
        }
        HubEndpointCmd::Revoke {
            access,
            endpoint,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "endpoint",
                endpoint,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanRevokeEndpointScope,
                HubTopologyMethod::RevokeEndpointScope,
            )
            .await
        }
        HubEndpointCmd::Remove {
            access,
            endpoint,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                endpoint,
                mutation,
                HubTopologyMethod::PlanDeleteEndpoint,
                HubTopologyMethod::DeleteEndpoint,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_probe_configuration_is_complete_and_canonical() {
        assert_eq!(
            endpoint_probe_configuration(
                Some("worker-secret"),
                Some("endpoint-v1"),
                Some("public-key"),
            )
            .unwrap()
            .as_deref(),
            Some(
                r#"{"provider":"worker_secret","signerSecretRef":"endpoint-v1","publicKey":"public-key"}"#
            )
        );
        assert!(endpoint_probe_configuration(Some("external"), None, None).is_err());
        assert_eq!(
            endpoint_probe_configuration(None, None, None).unwrap(),
            None
        );
    }

    #[test]
    fn endpoint_ingress_is_a_closed_wire_enum() {
        assert_eq!(
            endpoint_ingress_kind("hub").unwrap(),
            hub_types::EndpointIngressKind::Hub as i32
        );
        assert!(endpoint_ingress_kind("unknown").is_err());
    }

    #[test]
    fn endpoint_parser_rejects_non_origin_and_non_http_urls() {
        assert!(parse_delivery_origin("ftp://cache.example").is_err());
        assert!(parse_delivery_origin("https://cache.example/path").is_err());
        assert!(parse_delivery_origin("https://user@cache.example").is_err());
        assert!(parse_delivery_origin("https://cache.example").is_ok());
    }
}
