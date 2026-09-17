//! Handles hub signing key commands and their domain-specific request validation.

use crate::cli::{
    HubReviewedApplyArgs, HubSigningKeyCmd, HubSigningKeyEnrollCmd, HubSigningKeyRetireCmd,
    HubSigningKeyRotateCmd, HubSigningKeyUsageCmd,
};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_topology_plan;
use crate::commands::hub::mutation::{
    retained_apply_mutation, retained_plan_mutation, topology_mutation, topology_read,
};
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{HubRpc, hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub signing key command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn signing_key(printer: &Printer, command: &HubSigningKeyCmd) -> Result<()> {
    match command {
        HubSigningKeyCmd::List {
            access,
            scope,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListSigningKeysResponse>(
                printer,
                &client,
                HubTopologyMethod::ListSigningKeys,
                &hub_types::ListSigningKeysRequest {
                    scope_key: scope.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubSigningKeyCmd::Show {
            access,
            scope,
            name,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::SigningKeyResponse>(
                printer,
                &client,
                HubTopologyMethod::GetSigningKey,
                &hub_types::GetSigningKeyRequest {
                    scope_key: scope.clone(),
                    name: name.clone(),
                },
            )
            .await
        }
        HubSigningKeyCmd::Enroll { command } => match command {
            HubSigningKeyEnrollCmd::Plan {
                request,
                scope,
                name,
                public_key_file,
                public_key_fingerprint,
                custody,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation = retained_plan_mutation(&request.idempotency_key, None);
                let public_key = read_signing_public_key(public_key_file)?;
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanEnrollSigningKey,
                    HubTopologyMethod::EnrollSigningKey,
                    &hub_types::PlanSigningKeyMutationRequest {
                        scope_key: scope.clone(),
                        name: name.clone(),
                        public_key,
                        public_key_fingerprint: public_key_fingerprint.clone(),
                        custody: custody.clone(),
                        expected_resource_version: String::new(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyEnrollCmd::Apply(apply) => {
                apply_signing_key_mutation(
                    printer,
                    apply,
                    HubTopologyMethod::PlanEnrollSigningKey,
                    HubTopologyMethod::EnrollSigningKey,
                )
                .await
            }
        },
        HubSigningKeyCmd::Rotate { command } => match command {
            HubSigningKeyRotateCmd::Plan {
                request,
                scope,
                name,
                public_key_file,
                public_key_fingerprint,
                custody,
                if_version,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                let public_key = read_signing_public_key(public_key_file)?;
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRotateSigningKey,
                    HubTopologyMethod::RotateSigningKey,
                    &hub_types::PlanSigningKeyMutationRequest {
                        scope_key: scope.clone(),
                        name: name.clone(),
                        public_key,
                        public_key_fingerprint: public_key_fingerprint.clone(),
                        custody: custody.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyRotateCmd::Apply(apply) => {
                apply_signing_key_mutation(
                    printer,
                    apply,
                    HubTopologyMethod::PlanRotateSigningKey,
                    HubTopologyMethod::RotateSigningKey,
                )
                .await
            }
        },
        HubSigningKeyCmd::Retire { command } => match command {
            HubSigningKeyRetireCmd::Plan {
                request,
                scope,
                name,
                if_version,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanRetireSigningKey,
                    HubTopologyMethod::RetireSigningKey,
                    &hub_types::PlanRetireSigningKeyRequest {
                        scope_key: scope.clone(),
                        name: name.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyRetireCmd::Apply(apply) => apply_retire_signing_key(printer, apply).await,
        },
        HubSigningKeyCmd::Usage { command } => match command {
            HubSigningKeyUsageCmd::Show {
                access,
                consumer,
                purpose,
            } => {
                let client = hub_client(&access.hub, access.token.as_deref()).await?;
                topology_read::<_, hub_types::SigningKeyUsageResponse>(
                    printer,
                    &client,
                    HubTopologyMethod::GetSigningKeyUsage,
                    &hub_types::GetSigningKeyUsageRequest {
                        consumer_stable_id: consumer.clone(),
                        purpose: signing_purpose(purpose)?.to_string(),
                    },
                )
                .await
            }
            HubSigningKeyUsageCmd::Plan {
                request,
                consumer,
                purpose,
                signing_key,
                generation,
                state,
                if_version,
            } => {
                let client =
                    hub_client(&request.access.hub, request.access.token.as_deref()).await?;
                let mutation =
                    retained_plan_mutation(&request.idempotency_key, Some(if_version.as_str()));
                topology_mutation::<
                    _,
                    hub_types::ApplyTopologyPlanRequest,
                    hub_types::SigningKeyUsageResponse,
                    _,
                >(
                    printer,
                    &client,
                    HubTopologyMethod::PlanSetSigningKeyUsage,
                    HubTopologyMethod::SetSigningKeyUsage,
                    &hub_types::PlanSigningKeyUsageRequest {
                        consumer_stable_id: consumer.clone(),
                        purpose: signing_purpose(purpose)?.to_string(),
                        signing_key_stable_id: signing_key.clone(),
                        signing_key_generation: generation.get(),
                        state: state.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    &mutation,
                    apply_topology_plan,
                )
                .await
            }
            HubSigningKeyUsageCmd::Apply(apply) => apply_signing_key_usage(printer, apply).await,
        },
    }
}

fn signing_purpose(value: &str) -> Result<&'static str> {
    match value {
        "registry-publication" => Ok("registry_publication"),
        "nar-info" => Ok("narinfo"),
        "channel-frontier" => Ok("channel_frontier"),
        other => anyhow::bail!("unsupported signing purpose '{other}'"),
    }
}

fn read_signing_public_key(path: &std::path::Path) -> Result<String> {
    let public_key = std::fs::read_to_string(path)
        .with_context(|| format!("reading signing public key from {}", path.display()))?;
    anyhow::ensure!(!public_key.is_empty(), "signing public-key file is empty");
    Ok(public_key)
}

async fn apply_signing_key_mutation(
    printer: &Printer,
    apply: &HubReviewedApplyArgs,
    plan_method: impl HubRpc<
        Request = hub_types::PlanSigningKeyMutationRequest,
        Response = hub_types::TopologyPlanResponse,
    >,
    apply_method: impl HubRpc<
        Request = hub_types::ApplyTopologyPlanRequest,
        Response = hub_types::SigningKeyResponse,
    > + Copy,
) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation(
        printer,
        &client,
        plan_method,
        apply_method,
        &hub_types::PlanSigningKeyMutationRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_retire_signing_key(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::SigningKeyResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanRetireSigningKey,
        HubTopologyMethod::RetireSigningKey,
        &hub_types::PlanRetireSigningKeyRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}

async fn apply_signing_key_usage(printer: &Printer, apply: &HubReviewedApplyArgs) -> Result<()> {
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref()).await?;
    let mutation = retained_apply_mutation(apply);
    topology_mutation::<_, hub_types::ApplyTopologyPlanRequest, hub_types::SigningKeyUsageResponse, _>(
        printer,
        &client,
        HubTopologyMethod::PlanSetSigningKeyUsage,
        HubTopologyMethod::SetSigningKeyUsage,
        &hub_types::PlanSigningKeyUsageRequest::default(),
        &mutation,
        apply_topology_plan,
    )
    .await
}
