//! Handles hub operation commands and their domain-specific request validation.

use crate::cli::{HubOperationArgs, HubOperationCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_duration_seconds;
use crate::commands::hub::mutation::{new_idempotency_key, topology_read};
use crate::commands::hub::output::print_topology_message;
use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};

/// Watches an operation until completion and reports its terminal status.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn watch_hub_operation(
    printer: &Printer,
    client: &HubClient,
    operation_id: &str,
    timeout: Option<&str>,
) -> Result<()> {
    let total_timeout = timeout
        .map(|value| parse_duration_seconds(value, "--timeout"))
        .transpose()?;
    let started = std::time::Instant::now();
    let mut after_resource_version = String::new();
    let mut last_response = None;
    loop {
        let remaining = total_timeout.map(|seconds| {
            seconds.saturating_sub(i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX))
        });
        if remaining == Some(0) {
            if let Some(response) = last_response {
                print_topology_message(printer, &response)?;
            }
            anyhow::bail!("timed out waiting for Hub operation '{operation_id}'");
        }
        let response: hub_types::WatchOperationResponse = client
            .call_topology(
                HubTopologyMethod::WatchOperation,
                &hub_types::WatchOperationRequest {
                    operation_id: operation_id.into(),
                    after_resource_version: after_resource_version.clone(),
                    timeout_seconds: remaining.unwrap_or(30).min(30),
                },
            )
            .await?;
        after_resource_version = response
            .operation
            .as_ref()
            .map(|operation| operation.resource_version.clone())
            .unwrap_or_default();
        if printer.mode() != OutputMode::Json {
            print_topology_message(printer, &response)?;
        }
        if response.terminal {
            if printer.mode() == OutputMode::Json {
                print_topology_message(printer, &response)?;
            }
            return terminal_operation_status(&response);
        }
        last_response = Some(response);
    }
}

fn terminal_operation_status(response: &hub_types::WatchOperationResponse) -> Result<()> {
    let detail = response
        .operation
        .as_ref()
        .context("the Hub returned a terminal watch response without operation detail")?;
    let operation = detail
        .operation
        .as_ref()
        .context("the Hub returned terminal operation detail without an operation")?;

    match operation.state.as_str() {
        "succeeded" => Ok(()),
        "failed" | "cancelled" => {
            let reason = if detail.error.is_empty() {
                "no error detail was provided"
            } else {
                detail.error.as_str()
            };
            anyhow::bail!(
                "Hub operation '{}' {}: {reason}",
                operation.operation_id,
                operation.state
            )
        }
        state => anyhow::bail!(
            "Hub operation '{}' was marked terminal in unexpected state '{state}'",
            operation.operation_id
        ),
    }
}

/// Prints an operation response or waits for completion according to CLI options.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn print_or_wait_operation(
    printer: &Printer,
    client: &HubClient,
    response: &hub_types::OperationResponse,
    options: &HubOperationArgs,
) -> Result<()> {
    if !options.wait {
        return print_topology_message(printer, response);
    }
    if printer.mode() != OutputMode::Json {
        print_topology_message(printer, response)?;
    }
    let operation_id = &response
        .operation
        .as_ref()
        .context("the Hub returned an operation response without an operation")?
        .operation_id;
    watch_hub_operation(printer, client, operation_id, options.timeout.as_deref()).await
}

/// Handles the hub operation command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn operation(printer: &Printer, command: &HubOperationCmd) -> Result<()> {
    match command {
        HubOperationCmd::Show {
            access,
            operation_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::OperationDetailResponse>(
                printer,
                &client,
                HubTopologyMethod::GetOperation,
                &hub_types::GetOperationRequest {
                    operation_id: operation_id.clone(),
                },
            )
            .await
        }
        HubOperationCmd::List {
            access,
            target,
            scope,
            state,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListOperationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListOperations,
                &hub_types::ListOperationsRequest {
                    target: target.as_deref().map(operation_list_target).transpose()?,
                    state: state.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                    authorization_scope_key: scope.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubOperationCmd::Watch {
            access,
            operation_id,
            timeout,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            watch_hub_operation(printer, &client, operation_id, timeout.as_deref()).await
        }
        HubOperationCmd::Cancel {
            access,
            operation_id,
            if_version,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::OperationDetailResponse>(
                printer,
                &client,
                HubTopologyMethod::CancelOperation,
                &hub_types::MutateOperationRequest {
                    operation_id: operation_id.clone(),
                    expected_resource_version: if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
            )
            .await
        }
        HubOperationCmd::Retry {
            access,
            operation_id,
            if_version,
            operation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            let response: hub_types::OperationDetailResponse = client
                .call_topology(
                    HubTopologyMethod::RetryOperation,
                    &hub_types::MutateOperationRequest {
                        operation_id: operation_id.clone(),
                        expected_resource_version: if_version.clone().unwrap_or_default(),
                        idempotency_key: new_idempotency_key(),
                    },
                )
                .await?;
            if !operation.wait {
                return print_topology_message(printer, &response);
            }
            if printer.mode() != OutputMode::Json {
                print_topology_message(printer, &response)?;
            }
            let operation_id = &response
                .operation
                .as_ref()
                .and_then(|detail| detail.operation.as_ref())
                .context("the Hub returned an operation detail without an operation")?
                .operation_id;
            watch_hub_operation(printer, &client, operation_id, operation.timeout.as_deref()).await
        }
    }
}

fn operation_list_target(value: &str) -> Result<hub_types::OperationResourceRef> {
    let (kind, stable_id) = value.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "operation target must be qualified as KIND:ID (for example registry:andyl/main)"
        )
    })?;
    if stable_id.is_empty() {
        anyhow::bail!("operation target id must not be empty");
    }
    let target = match kind {
        "registry" => hub_types::operation_resource_ref::Target::RegistryId(stable_id.into()),
        "cache" => hub_types::operation_resource_ref::Target::BinaryCacheId(stable_id.into()),
        "placement" => hub_types::operation_resource_ref::Target::PlacementId(stable_id.into()),
        "domain" => hub_types::operation_resource_ref::Target::DomainId(stable_id.into()),
        "boundary" => hub_types::operation_resource_ref::Target::NetworkPolicyId(stable_id.into()),
        "endpoint" => hub_types::operation_resource_ref::Target::EndpointId(stable_id.into()),
        "gateway" => hub_types::operation_resource_ref::Target::GatewayId(stable_id.into()),
        "route" => hub_types::operation_resource_ref::Target::RouteId(stable_id.into()),
        "policy" => hub_types::operation_resource_ref::Target::PlacementPolicyId(stable_id.into()),
        "retention" => {
            hub_types::operation_resource_ref::Target::RetentionSubscriptionId(stable_id.into())
        }
        "population" => {
            hub_types::operation_resource_ref::Target::PopulationTargetId(stable_id.into())
        }
        "gc-generation" => {
            hub_types::operation_resource_ref::Target::CacheGcGenerationId(stable_id.into())
        }
        "storage-binding" => hub_types::operation_resource_ref::Target::BindingId(stable_id.into()),
        _ => anyhow::bail!(
            "unknown operation target kind '{kind}'; expected registry, cache, placement, domain, boundary, endpoint, gateway, route, policy, retention, population, gc-generation, or storage-binding"
        ),
    };
    Ok(hub_types::OperationResourceRef {
        target: Some(target),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_operation_status_fails_closed() {
        let response = |state: &str, error: &str| hub_types::WatchOperationResponse {
            operation: Some(hub_types::OperationDetail {
                operation: Some(hub_types::OperationRef {
                    operation_id: "operation-1".into(),
                    state: state.into(),
                    ..Default::default()
                }),
                error: error.into(),
                ..Default::default()
            }),
            terminal: true,
        };

        assert!(terminal_operation_status(&response("succeeded", "")).is_ok());
        let failed = terminal_operation_status(&response("failed", "copy rejected"))
            .unwrap_err()
            .to_string();
        assert!(failed.contains("operation-1"));
        assert!(failed.contains("copy rejected"));
        assert!(terminal_operation_status(&response("cancelled", "")).is_err());
        assert!(terminal_operation_status(&response("running", "")).is_err());
    }
}
