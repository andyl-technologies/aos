//! Handles hub binding commands and their domain-specific request validation.

use crate::cli::{
    HubBindingCmd, HubBindingCredentialCmd, HubBindingWriteRevisionCmd, HubMutationArgs,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::{
    consumer_scope_mutation, delete_topology_resource, new_idempotency_key, required_plan_version,
    topology_mutation, topology_operation_mutation, topology_read, topology_stable_id,
};
use crate::commands::hub::organization::organization_scope_key;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};

/// Parses a binding reference into organization and binding components.
///
/// # Errors
///
/// Returns an error if the binding reference is malformed.
pub(super) fn parse_binding_ref(value: &str) -> Result<hub_types::BindingRef> {
    let target = if value == "instance:default" {
        hub_types::binding_ref::Target::InstanceDefault(true)
    } else {
        let (org_slug, name) = value
            .split_once(':')
            .or_else(|| value.split_once('/'))
            .context("organization binding refs use <org>:<name>")?;
        hub_types::binding_ref::Target::Organization(hub_types::OrganizationBindingRef {
            org_slug: org_slug.into(),
            name: name.into(),
        })
    };
    Ok(hub_types::BindingRef {
        target: Some(target),
    })
}

fn binding_reference_requires_resolution(reference: &str) -> bool {
    !reference.starts_with("storage-binding:") && reference.contains([':', '/'])
}

async fn binding_grant_stable_id(
    client: &HubClient,
    reference: &str,
    mutation: &HubMutationArgs,
) -> Result<String> {
    if mutation.plan_id.is_some() || !binding_reference_requires_resolution(reference) {
        return Ok(reference.to_string());
    }
    let response: hub_types::GetBindingResponse = client
        .call_topology(
            HubTopologyMethod::GetBinding,
            &hub_types::GetBindingRequest {
                binding: Some(parse_binding_ref(reference)?),
            },
        )
        .await?;
    Ok(response
        .binding
        .context("Hub returned no binding for the canonical reference")?
        .stable_id)
}

fn parse_storage_endpoint(value: &str) -> Result<hub_types::StorageEndpoint> {
    let url = reqwest::Url::parse(value).context("parsing storage endpoint URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("object-storage endpoints require https");
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        anyhow::bail!("object-storage endpoint URLs contain only an https origin");
    }
    let host_text = url.host_str().context("storage endpoint URL has no host")?;
    let ip_text = host_text
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host_text);
    let host = match ip_text.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            hub_types::storage_endpoint::Host::Ipv4(address.octets().to_vec())
        }
        Ok(std::net::IpAddr::V6(address)) => {
            hub_types::storage_endpoint::Host::Ipv6(address.octets().to_vec())
        }
        Err(_) => hub_types::storage_endpoint::Host::DnsName(host_text.to_ascii_lowercase()),
    };
    let port = url
        .port_or_known_default()
        .context("storage endpoint URL scheme has no effective port")?;
    Ok(hub_types::StorageEndpoint {
        scheme: url.scheme().into(),
        host: Some(host),
        port: u32::from(port),
    })
}

/// Handles `aos hub storage-binding …`.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn binding(printer: &Printer, command: &HubBindingCmd) -> Result<()> {
    match command {
        HubBindingCmd::List {
            hub,
            token,
            org,
            include_granted,
            pagination,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            topology_read::<_, hub_types::ListBindingsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListBindings,
                &hub_types::ListBindingsRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                },
            )
            .await
        }
        HubBindingCmd::Show {
            access,
            binding_ref,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::GetBindingResponse>(
                printer,
                &client,
                HubTopologyMethod::GetBinding,
                &hub_types::GetBindingRequest {
                    binding: Some(parse_binding_ref(binding_ref)?),
                },
            )
            .await
        }
        HubBindingCmd::Create {
            hub,
            token,
            org,
            name,
            stable_id,
            kind,
            root,
            endpoint,
            region,
            access,
            bucket,
            prefix,
            bucket_binding,
            mutation,
        } => {
            let client = hub_client(hub, token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateBinding,
                    HubTopologyMethod::CreateBinding,
                    &hub_types::PlanBindingMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyBindingMutationRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            let kind = kind
                .as_deref()
                .context("storage-binding create requires --kind when creating a plan")?;
            match kind {
                "local-fs" => {
                    if root.is_none() {
                        anyhow::bail!("local-fs bindings require --root");
                    }
                    if bucket.is_some()
                        || prefix.is_some()
                        || endpoint.is_some()
                        || region.is_some()
                        || access.is_some()
                        || bucket_binding.is_some()
                    {
                        anyhow::bail!("local-fs bindings reject object-storage options");
                    }
                }
                "s3" | "r2" => {
                    if root.is_some() || bucket_binding.is_some() {
                        anyhow::bail!("s3/r2 bindings reject --root and --bucket-binding");
                    }
                    if bucket.is_none()
                        || endpoint.is_none()
                        || region.is_none()
                        || access.is_none()
                    {
                        anyhow::bail!(
                            "s3/r2 bindings require --bucket, --endpoint, --region, and --access"
                        );
                    }
                }
                "deployment-r2" => {
                    if bucket_binding.is_none() {
                        anyhow::bail!("deployment-r2 bindings require --bucket-binding");
                    }
                    if root.is_some()
                        || bucket.is_some()
                        || prefix.is_some()
                        || endpoint.is_some()
                        || region.is_some()
                        || access.is_some()
                    {
                        anyhow::bail!(
                            "deployment-r2 bindings reject filesystem and HTTP provider options"
                        );
                    }
                }
                _ => anyhow::bail!("unsupported binding kind '{kind}'"),
            }
            let parsed_endpoint = endpoint
                .as_deref()
                .map(parse_storage_endpoint)
                .transpose()?;
            let provider = match kind {
                "local-fs" => hub_types::binding_spec::Provider::LocalFilesystem(
                    hub_types::LocalFilesystemStorageProvider {
                        root_path: root.clone().unwrap_or_default(),
                    },
                ),
                "s3" => hub_types::binding_spec::Provider::S3(hub_types::S3StorageProvider {
                    bucket: bucket.clone().unwrap_or_default(),
                    prefix: prefix.clone().unwrap_or_default(),
                    endpoint: parsed_endpoint,
                    signing_region: region.clone().unwrap_or_default(),
                    access_mode: access.clone().unwrap_or_default(),
                }),
                "r2" => hub_types::binding_spec::Provider::R2(hub_types::R2StorageProvider {
                    bucket: bucket.clone().unwrap_or_default(),
                    prefix: prefix.clone().unwrap_or_default(),
                    endpoint: parsed_endpoint,
                    signing_region: region.clone().unwrap_or_default(),
                    access_mode: access.clone().unwrap_or_default(),
                }),
                "deployment-r2" => hub_types::binding_spec::Provider::DeploymentR2(
                    hub_types::DeploymentR2StorageProvider {
                        bucket_binding: bucket_binding.clone().unwrap_or_default(),
                    },
                ),
                other => anyhow::bail!("unsupported binding kind '{other}'"),
            };
            let spec = hub_types::BindingSpec {
                name: name.clone(),
                provider: Some(provider),
            };
            topology_mutation::<
                _,
                hub_types::ApplyBindingMutationRequest,
                hub_types::BindingResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateBinding,
                HubTopologyMethod::CreateBinding,
                &hub_types::PlanBindingMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "storage-binding"),
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    spec: Some(spec),
                    idempotency_key: new_idempotency_key(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyBindingMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubBindingCmd::Credential { command } => binding_credential(printer, command).await,
        HubBindingCmd::WriteRevision { command } => binding_write_revision(printer, command).await,
        HubBindingCmd::Grant {
            access,
            binding_ref,
            consumer_scope,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let binding_stable_id = binding_grant_stable_id(&client, binding_ref, mutation).await?;
            consumer_scope_mutation(
                printer,
                access,
                "binding",
                &binding_stable_id,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanGrantBindingScope,
                HubTopologyMethod::GrantBindingScope,
            )
            .await
        }
        HubBindingCmd::Revoke {
            access,
            binding_ref,
            consumer_scope,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let binding_stable_id = binding_grant_stable_id(&client, binding_ref, mutation).await?;
            consumer_scope_mutation(
                printer,
                access,
                "binding",
                &binding_stable_id,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanRevokeBindingScope,
                HubTopologyMethod::RevokeBindingScope,
            )
            .await
        }
        HubBindingCmd::Delete {
            access,
            binding_ref,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                binding_ref,
                mutation,
                HubTopologyMethod::PlanDeleteBinding,
                HubTopologyMethod::DeleteBinding,
            )
            .await
        }
    }
}

async fn binding_credential(printer: &Printer, command: &HubBindingCredentialCmd) -> Result<()> {
    match command {
        HubBindingCredentialCmd::Set {
            access,
            binding_ref,
            purpose,
            secret_version_ref,
            credential_fingerprint,
            mutation,
        }
        | HubBindingCredentialCmd::Rotate {
            access,
            binding_ref,
            purpose,
            secret_version_ref,
            credential_fingerprint,
            mutation,
            ..
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let expected_current_generation = match command {
                HubBindingCredentialCmd::Rotate {
                    from_generation, ..
                } => i64::try_from(*from_generation)?,
                _ => 0,
            };
            let rotate = matches!(command, HubBindingCredentialCmd::Rotate { .. });
            let request = hub_types::PlanBindingCredentialRequest {
                binding_id: binding_ref.clone(),
                purpose: purpose.clone(),
                secret_version_ref: secret_version_ref.clone(),
                expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                idempotency_key: new_idempotency_key(),
                expected_current_generation,
                credential_fingerprint: credential_fingerprint.clone(),
            };
            let build_apply = |plan_id: &str, idempotency_key: &str, confirmation_hash: &str| {
                hub_types::ApplyBindingCredentialRequest {
                    plan_id: plan_id.into(),
                    idempotency_key: idempotency_key.into(),
                    confirmation_hash: confirmation_hash.into(),
                }
            };
            if rotate {
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRotateBindingCredential,
                    HubTopologyMethod::RotateBindingCredential,
                    &request,
                    mutation,
                    build_apply,
                )
                .await
            } else {
                topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetBindingCredential,
                    HubTopologyMethod::SetBindingCredential,
                    &request,
                    mutation,
                    build_apply,
                )
                .await
            }
        }
        HubBindingCredentialCmd::Validate {
            access,
            binding_ref,
            purpose,
            mutation,
            operation,
        } => {
            if mutation.plan_id.is_none() {
                required_plan_version(mutation, "storage credential validation")?;
            }
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_operation_mutation(
                printer,
                &client,
                HubTopologyMethod::PlanValidateBindingCredential,
                HubTopologyMethod::ValidateBindingCredential,
                &hub_types::PlanValidateBindingCredentialRequest {
                    binding_id: binding_ref.clone(),
                    purpose: purpose.clone().unwrap_or_default(),
                    generation: 0,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                operation,
            )
            .await
        }
    }
}

async fn binding_write_revision(
    printer: &Printer,
    command: &HubBindingWriteRevisionCmd,
) -> Result<()> {
    match command {
        HubBindingWriteRevisionCmd::List {
            access,
            binding_ref,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListBindingWriteRevisionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListBindingWriteRevisions,
                &hub_types::ListBindingWriteRevisionsRequest {
                    binding: Some(parse_binding_ref(binding_ref)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubBindingWriteRevisionCmd::Show {
            access,
            binding_ref,
            revision,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::BindingWriteRevisionResponse>(
                printer,
                &client,
                HubTopologyMethod::GetBindingWriteRevision,
                &hub_types::GetBindingWriteRevisionRequest {
                    binding: Some(parse_binding_ref(binding_ref)?),
                    revision: i64::try_from(*revision)?,
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_binding_ids_do_not_require_human_reference_resolution() {
        assert!(!binding_reference_requires_resolution(
            "storage-binding:0123456789abcdef0123456789abcdef"
        ));
        assert!(binding_reference_requires_resolution("operations:archive"));
        assert!(binding_reference_requires_resolution("operations/archive"));
        assert!(!binding_reference_requires_resolution("operator-chosen"));
    }
}
