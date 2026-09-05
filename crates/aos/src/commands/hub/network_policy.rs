//! Handles hub network policy commands and their domain-specific request validation.

use crate::cli::{HubNetworkPolicyCmd, HubNetworkPolicyRevisionCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::{canonical_cidr, parse_generation_ref, sorted_unique};
use crate::commands::hub::mutation::{
    boundary_lifecycle_mutation, consumer_scope_mutation, delete_topology_resource,
    new_idempotency_key, topology_mutation, topology_read, topology_stable_id,
};
use crate::commands::hub::organization::organization_scope_key;
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

fn network_policy_revision_update_mask(
    protected_transport: bool,
    trusted_ingress: bool,
    source_allowlist_cidrs: bool,
    probe_location: bool,
) -> Vec<String> {
    [
        protected_transport.then_some("protected_transport_required"),
        trusted_ingress.then_some("trusted_ingress"),
        source_allowlist_cidrs.then_some("source_allowlist_cidrs"),
        probe_location.then_some("probe_location_configuration_ref"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_string)
    .collect()
}

fn canonical_network_policy_kind(kind: &str) -> &str {
    match kind {
        "source-allowlist" => "source_allowlist",
        "trusted-ingress" => "trusted_ingress",
        other => other,
    }
}

fn initial_network_policy_revision(
    protected_transport: &str,
    probe_location: &str,
) -> hub_types::NetworkPolicyRevisionSpec {
    hub_types::NetworkPolicyRevisionSpec {
        protected_transport_required: protected_transport == "required",
        trusted_ingress: Some(hub_types::TrustedIngressConfiguration {
            configuration: Some(
                hub_types::trusted_ingress_configuration::Configuration::None(true),
            ),
        }),
        probe_location_configuration_ref: probe_location.into(),
        ..Default::default()
    }
}

/// Handles the hub network policy command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn network_policy(printer: &Printer, command: &HubNetworkPolicyCmd) -> Result<()> {
    match command {
        HubNetworkPolicyCmd::List {
            access,
            org,
            include_granted,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListNetworkPoliciesResponse>(
                printer,
                &client,
                HubTopologyMethod::ListNetworkPolicies,
                &hub_types::ListTopologyResourcesRequest {
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    include_granted: *include_granted,
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Show { access, boundary }
        | HubNetworkPolicyCmd::Status { access, boundary } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::NetworkPolicyResponse>(
                printer,
                &client,
                HubTopologyMethod::GetNetworkPolicy,
                &hub_types::GetTopologyResourceRequest {
                    stable_id: boundary.clone(),
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Add {
            access,
            name,
            stable_id,
            kind,
            org,
            provider,
            provider_account,
            resource_id,
            allowlist_id,
            listener_id,
            protected_transport,
            probe_location,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            if mutation.plan_id.is_some() {
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanCreateNetworkPolicy,
                    HubTopologyMethod::CreateNetworkPolicy,
                    &hub_types::PlanNetworkPolicyMutationRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyNetworkPolicyMutationRequest {
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
                .context("network-boundary add requires --kind when creating a plan")?;
            let protected_transport = protected_transport.as_deref().context(
                "network-boundary add requires --protected-transport when creating a plan",
            )?;
            let probe_location = probe_location
                .as_deref()
                .context("network-boundary add requires --probe-location when creating a plan")?;
            match kind {
                "vpn" | "vpc" | "tunnel" if allowlist_id.is_some() || listener_id.is_some() => {
                    anyhow::bail!("provider network policies reject allowlist/listener options");
                }
                "source-allowlist"
                    if provider.is_some()
                        || provider_account.is_some()
                        || resource_id.is_some()
                        || listener_id.is_some() =>
                {
                    anyhow::bail!("source allowlists accept only --allowlist-id");
                }
                "trusted-ingress" if resource_id.is_some() || allowlist_id.is_some() => {
                    anyhow::bail!("trusted ingress rejects resource/allowlist options");
                }
                _ => {}
            }
            let identity = match kind {
                "vpn" => hub_types::network_policy_identity::Identity::Vpn(
                    hub_types::ProviderResourceIdentity {
                        provider: provider.clone().context("--provider is required for vpn")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for vpn")?,
                        resource_id: resource_id
                            .clone()
                            .context("--resource-id is required for vpn")?,
                    },
                ),
                "vpc" => hub_types::network_policy_identity::Identity::ProviderNetwork(
                    hub_types::ProviderNetworkIdentity {
                        provider: provider.clone().context("--provider is required for vpc")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for vpc")?,
                        resource_id: resource_id
                            .clone()
                            .context("--resource-id is required for vpc")?,
                        ..Default::default()
                    },
                ),
                "tunnel" => hub_types::network_policy_identity::Identity::Tunnel(
                    hub_types::ProviderResourceIdentity {
                        provider: provider
                            .clone()
                            .context("--provider is required for tunnel")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for tunnel")?,
                        resource_id: resource_id
                            .clone()
                            .context("--resource-id is required for tunnel")?,
                    },
                ),
                "source-allowlist" => {
                    hub_types::network_policy_identity::Identity::SourceAllowlistId(
                        allowlist_id
                            .clone()
                            .context("--allowlist-id is required for source-allowlist")?,
                    )
                }
                "trusted-ingress" => hub_types::network_policy_identity::Identity::TrustedIngress(
                    hub_types::ProviderNetworkIdentity {
                        provider: provider
                            .clone()
                            .context("--provider is required for trusted-ingress")?,
                        account_or_tenant: provider_account
                            .clone()
                            .context("--provider-account is required for trusted-ingress")?,
                        listener_id: listener_id
                            .clone()
                            .context("--listener-id is required for trusted-ingress")?,
                        ..Default::default()
                    },
                ),
                _ => anyhow::bail!("unsupported network policy kind '{kind}'"),
            };
            let canonical_kind = canonical_network_policy_kind(kind);
            topology_mutation::<
                _,
                hub_types::ApplyNetworkPolicyMutationRequest,
                hub_types::NetworkPolicyResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateNetworkPolicy,
                HubTopologyMethod::CreateNetworkPolicy,
                &hub_types::PlanNetworkPolicyMutationRequest {
                    stable_id: topology_stable_id(stable_id.as_deref(), "network-boundary"),
                    owner_scope_key: organization_scope_key(&client, org.as_deref()).await?,
                    name: name.clone(),
                    kind: canonical_kind.into(),
                    identity: Some(hub_types::NetworkPolicyIdentity {
                        identity: Some(identity),
                    }),
                    initial_revision: Some(initial_network_policy_revision(
                        protected_transport,
                        probe_location,
                    )),
                    idempotency_key: new_idempotency_key(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    ..Default::default()
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyNetworkPolicyMutationRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Revise {
            access,
            boundary,
            protected_transport,
            trusted_ingress,
            ca_secret_ref,
            client_sans,
            clear_client_sans,
            issuer,
            audience,
            verification_key_secret_ref,
            cidrs,
            clear_cidrs,
            probe_location,
            clear_probe_location,
            mutation,
        } => {
            if mutation.plan_id.is_some() {
                let client = hub_client(&access.hub, access.token.as_deref())?;
                return topology_mutation(
                    printer,
                    &client,
                    HubTopologyMethod::PlanReviseNetworkPolicy,
                    HubTopologyMethod::ReviseNetworkPolicy,
                    &hub_types::PlanNetworkPolicyRevisionRequest::default(),
                    mutation,
                    |plan_id, idempotency_key, confirmation_hash| {
                        hub_types::ApplyNetworkPolicyRevisionRequest {
                            plan_id: plan_id.into(),
                            idempotency_key: idempotency_key.into(),
                            confirmation_hash: confirmation_hash.into(),
                        }
                    },
                )
                .await;
            }
            if protected_transport.is_none()
                && trusted_ingress.is_none()
                && !clear_client_sans
                && cidrs.is_empty()
                && !clear_cidrs
                && probe_location.is_none()
                && !clear_probe_location
            {
                anyhow::bail!("network-boundary revise requires at least one changed field");
            }
            if (!client_sans.is_empty() || *clear_client_sans)
                && trusted_ingress.as_deref() != Some("mtls")
            {
                anyhow::bail!(
                    "--client-san and --clear-client-sans require --trusted-ingress mtls"
                );
            }
            let trusted_ingress = trusted_ingress
                .as_ref()
                .map(|kind| {
                    let configuration = match kind.as_str() {
                        "none" => {
                            if ca_secret_ref.is_some()
                                || !client_sans.is_empty()
                                || *clear_client_sans
                                || issuer.is_some()
                                || audience.is_some()
                                || verification_key_secret_ref.is_some()
                            {
                                anyhow::bail!("trusted ingress none rejects kind-specific fields");
                            }
                            hub_types::trusted_ingress_configuration::Configuration::None(true)
                        }
                        "mtls" => {
                            if issuer.is_some()
                                || audience.is_some()
                                || verification_key_secret_ref.is_some()
                            {
                                anyhow::bail!("mtls ingress rejects signed-assertion fields");
                            }
                            hub_types::trusted_ingress_configuration::Configuration::Mtls(
                                hub_types::MtlsTrustedIngress {
                                ca_secret_ref: ca_secret_ref
                                    .clone()
                                    .context("mtls ingress requires --ca-secret-ref")?,
                                client_sans: if *clear_client_sans {
                                    Vec::new()
                                } else {
                                    sorted_unique(client_sans.clone())
                                },
                                },
                            )
                        }
                        "signed-assertion" => {
                            if ca_secret_ref.is_some()
                                || !client_sans.is_empty()
                                || *clear_client_sans
                            {
                                anyhow::bail!("signed-assertion ingress rejects mTLS fields");
                            }
                            hub_types::trusted_ingress_configuration::Configuration::SignedAssertion(
                                hub_types::SignedAssertionTrustedIngress {
                                issuer: issuer.clone().context("signed-assertion ingress requires --issuer")?,
                                audience: audience.clone().context("signed-assertion ingress requires --audience")?,
                                verification_key_secret_ref: verification_key_secret_ref.clone().context(
                                    "signed-assertion ingress requires --verification-key-secret-ref",
                                )?,
                                },
                            )
                        }
                        _ => anyhow::bail!("unsupported trusted ingress kind '{kind}'"),
                    };
                    Ok::<_, anyhow::Error>(hub_types::TrustedIngressConfiguration {
                        configuration: Some(configuration),
                    })
                })
                .transpose()?;
            let updates_trusted_ingress = trusted_ingress.is_some();
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyNetworkPolicyRevisionRequest,
                hub_types::NetworkPolicyRevisionResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanReviseNetworkPolicy,
                HubTopologyMethod::ReviseNetworkPolicy,
                &hub_types::PlanNetworkPolicyRevisionRequest {
                    boundary_id: boundary.clone(),
                    spec: Some(hub_types::NetworkPolicyRevisionSpec {
                        protected_transport_required: protected_transport.as_deref()
                            == Some("required"),
                        trusted_ingress,
                        source_allowlist_cidrs: if *clear_cidrs {
                            Vec::new()
                        } else {
                            sorted_unique(
                                cidrs
                                    .iter()
                                    .map(|value| canonical_cidr(value))
                                    .collect::<Result<Vec<_>>>()?,
                            )
                        },
                        probe_location_configuration_ref: if *clear_probe_location {
                            String::new()
                        } else {
                            probe_location.clone().unwrap_or_default()
                        },
                    }),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                    update_mask: network_policy_revision_update_mask(
                        protected_transport.is_some(),
                        updates_trusted_ingress,
                        !cidrs.is_empty() || *clear_cidrs,
                        probe_location.is_some() || *clear_probe_location,
                    ),
                },
                mutation,
                |plan_id, idempotency_key, confirmation_hash| {
                    hub_types::ApplyNetworkPolicyRevisionRequest {
                        plan_id: plan_id.into(),
                        idempotency_key: idempotency_key.into(),
                        confirmation_hash: confirmation_hash.into(),
                    }
                },
            )
            .await
        }
        HubNetworkPolicyCmd::Grant {
            access,
            boundary,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "network_policy",
                boundary,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanGrantNetworkPolicyScope,
                HubTopologyMethod::GrantNetworkPolicyScope,
            )
            .await
        }
        HubNetworkPolicyCmd::Revoke {
            access,
            boundary,
            consumer_scope,
            mutation,
        } => {
            consumer_scope_mutation(
                printer,
                access,
                "network_policy",
                boundary,
                0,
                consumer_scope,
                mutation,
                HubTopologyMethod::PlanRevokeNetworkPolicyScope,
                HubTopologyMethod::RevokeNetworkPolicyScope,
            )
            .await
        }
        HubNetworkPolicyCmd::Revision { command } => {
            network_policy_revision(printer, command).await
        }
        HubNetworkPolicyCmd::Remove {
            access,
            boundary,
            mutation,
        } => {
            delete_topology_resource(
                printer,
                access,
                boundary,
                mutation,
                HubTopologyMethod::PlanDeleteNetworkPolicy,
                HubTopologyMethod::DeleteNetworkPolicy,
            )
            .await
        }
    }
}

async fn network_policy_revision(
    printer: &Printer,
    command: &HubNetworkPolicyRevisionCmd,
) -> Result<()> {
    match command {
        HubNetworkPolicyRevisionCmd::List {
            access,
            boundary,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListNetworkPolicyRevisionsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListNetworkPolicyRevisions,
                &hub_types::ListNetworkPolicyRevisionsRequest {
                    boundary_id: boundary.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubNetworkPolicyRevisionCmd::Show {
            access,
            boundary_revision,
        } => {
            let (boundary_id, revision) =
                parse_generation_ref(boundary_revision, "network policy revision")?;
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::NetworkPolicyRevisionResponse>(
                printer,
                &client,
                HubTopologyMethod::GetNetworkPolicyRevision,
                &hub_types::GetNetworkPolicyRevisionRequest {
                    boundary_id,
                    revision,
                },
            )
            .await
        }
        HubNetworkPolicyRevisionCmd::Activate {
            access,
            boundary_revision,
            mode,
            default_for_new_plans,
            mutation,
        } => {
            boundary_lifecycle_mutation(
                printer,
                access,
                boundary_revision,
                mode,
                default_for_new_plans == "yes",
                mutation,
                HubTopologyMethod::PlanActivateNetworkPolicyRevision,
                HubTopologyMethod::ActivateNetworkPolicyRevision,
            )
            .await
        }
        HubNetworkPolicyRevisionCmd::Retire {
            access,
            boundary_revision,
            mutation,
        } => {
            boundary_lifecycle_mutation(
                printer,
                access,
                boundary_revision,
                "",
                false,
                mutation,
                HubTopologyMethod::PlanRetireNetworkPolicyRevision,
                HubTopologyMethod::RetireNetworkPolicyRevision,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_policy_kinds_use_wire_spelling() {
        assert_eq!(
            canonical_network_policy_kind("source-allowlist"),
            "source_allowlist"
        );
        assert_eq!(
            canonical_network_policy_kind("trusted-ingress"),
            "trusted_ingress"
        );
        assert_eq!(canonical_network_policy_kind("vpc"), "vpc");
    }

    #[test]
    fn network_policies_start_with_an_explicit_untrusted_revision() {
        use hub_types::trusted_ingress_configuration::Configuration;

        let revision = initial_network_policy_revision("required", "edge-probe");
        assert!(revision.protected_transport_required);
        assert_eq!(revision.probe_location_configuration_ref, "edge-probe");
        assert!(matches!(
            revision
                .trusted_ingress
                .and_then(|trusted| trusted.configuration),
            Some(Configuration::None(true))
        ));
    }

    #[test]
    fn network_policy_revision_masks_use_service_field_names() {
        assert_eq!(
            network_policy_revision_update_mask(true, true, true, true),
            [
                "protected_transport_required",
                "trusted_ingress",
                "source_allowlist_cidrs",
                "probe_location_configuration_ref",
            ]
        );
        assert_eq!(
            network_policy_revision_update_mask(false, false, true, false),
            ["source_allowlist_cidrs"]
        );
    }
}
