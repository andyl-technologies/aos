//! Handles hub access policy commands and their domain-specific request validation.

use crate::cli::HubAccessPolicyArgs;
use crate::commands::hub::input::{parse_generation_ref, sorted_unique};
use anyhow::{Context as _, Result};
use aos_remote::hub_types;

/// Builds an access policy while rejecting fields for incompatible policy kinds.
///
/// # Errors
///
/// Returns an error if the policy kind or its supplied fields are incompatible.
pub(super) fn build_access_policy(
    input: &HubAccessPolicyArgs,
    allow_hub_auth: bool,
) -> Result<Option<hub_types::DeliveryAccessPolicy>> {
    let Some(kind) = input.access.as_deref() else {
        let has_kind_fields = !input.hub_principals.is_empty()
            || !input.hub_client_classes.is_empty()
            || input.external_provider_kind.is_some()
            || input.external_provider_resource_id.is_some()
            || input.external_provider_revision.is_some()
            || !input.external_client_mechanisms.is_empty()
            || !input.external_client_classes.is_empty()
            || input.access_boundary.is_some();
        if has_kind_fields {
            anyhow::bail!("access-policy options require --access");
        }
        return Ok(None);
    };
    let has_hub_fields = !input.hub_principals.is_empty() || !input.hub_client_classes.is_empty();
    let has_external_fields = input.external_provider_kind.is_some()
        || input.external_provider_resource_id.is_some()
        || input.external_provider_revision.is_some()
        || !input.external_client_mechanisms.is_empty()
        || !input.external_client_classes.is_empty();
    let has_boundary_fields = input.access_boundary.is_some();
    let policy = match kind {
        "public" => {
            if has_hub_fields || has_external_fields || has_boundary_fields {
                anyhow::bail!("public access rejects kind-specific policy options");
            }
            hub_types::delivery_access_policy::Policy::Public(true)
        }
        "hub-auth" if allow_hub_auth => {
            if has_external_fields || has_boundary_fields {
                anyhow::bail!("hub-auth access rejects external-provider and boundary options");
            }
            hub_types::delivery_access_policy::Policy::HubAuth(hub_types::HubAuthPolicy {
                principals: sorted_unique(input.hub_principals.clone()),
                client_classes: sorted_unique(input.hub_client_classes.clone()),
                ..Default::default()
            })
        }
        "hub-auth" => anyhow::bail!("gateways do not support hub-auth access"),
        "external-provider" => {
            if has_hub_fields || has_boundary_fields {
                anyhow::bail!("external-provider access rejects Hub and boundary options");
            }
            if input.external_client_mechanisms.is_empty() {
                anyhow::bail!("external-provider access requires --external-client-mechanism");
            }
            let mut parsed_mechanisms = input
                .external_client_mechanisms
                .iter()
                .map(|value| {
                    let parsed = value
                        .split_once('=')
                        .map(|(kind, secret)| (kind.to_string(), secret.to_string()))
                        .context("--external-client-mechanism uses <mechanism>=<secret-ref>")?;
                    if !matches!(
                        parsed.0.as_str(),
                        "bearer-token" | "signed-cookie" | "signed-header" | "mtls"
                    ) {
                        anyhow::bail!("unsupported external client mechanism '{}'", parsed.0);
                    }
                    Ok(parsed)
                })
                .collect::<Result<Vec<_>>>()?;
            parsed_mechanisms.sort();
            parsed_mechanisms.dedup();
            hub_types::delivery_access_policy::Policy::ExternalProvider(
                hub_types::ExternalProviderPolicy {
                    provider_kind: input
                        .external_provider_kind
                        .clone()
                        .context("--external-provider-kind is required")?,
                    resource_id: input
                        .external_provider_resource_id
                        .clone()
                        .context("--external-provider-resource-id is required")?,
                    revision: input
                        .external_provider_revision
                        .clone()
                        .context("--external-provider-revision is required")?,
                    client_mechanisms: parsed_mechanisms
                        .into_iter()
                        .map(
                            |(kind, verification_secret_ref)| hub_types::ExternalClientMechanism {
                                kind,
                                verification_secret_ref,
                            },
                        )
                        .collect(),
                    client_classes: sorted_unique(input.external_client_classes.clone()),
                },
            )
        }
        "private-network" => {
            if has_hub_fields || has_external_fields {
                anyhow::bail!("private-network access rejects Hub and external-provider options");
            }
            let (boundary_id, boundary_revision) = parse_generation_ref(
                input
                    .access_boundary
                    .as_deref()
                    .context("--access-boundary is required")?,
                "access boundary",
            )?;
            hub_types::delivery_access_policy::Policy::PrivateNetwork(
                hub_types::PrivateNetworkPolicy {
                    boundary_id,
                    boundary_revision,
                },
            )
        }
        _ => anyhow::bail!("unsupported delivery access kind '{kind}'"),
    };
    Ok(Some(hub_types::DeliveryAccessPolicy {
        policy: Some(policy),
    }))
}

/// Reports whether any access-policy option was supplied.
pub(super) fn access_policy_args_present(input: &HubAccessPolicyArgs) -> bool {
    input.access.is_some()
        || !input.hub_principals.is_empty()
        || !input.hub_client_classes.is_empty()
        || input.external_provider_kind.is_some()
        || input.external_provider_resource_id.is_some()
        || input.external_provider_revision.is_some()
        || !input.external_client_mechanisms.is_empty()
        || !input.external_client_classes.is_empty()
        || input.access_boundary.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_policy_variants_reject_cross_kind_fields() {
        let input = HubAccessPolicyArgs {
            access: Some("public".into()),
            access_boundary: Some("corp@2".into()),
            ..Default::default()
        };
        assert!(build_access_policy(&input, true).is_err());
    }
}
