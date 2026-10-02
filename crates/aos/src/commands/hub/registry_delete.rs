//! Plans and applies reviewed registry deletion and follows its operation.
//!
//! Planning prints the Hub's exact deletion readiness: the operator blockers
//! that refuse the apply, or the steps the deletion operation performs itself.
//! Applying starts one self-driving operation; `--wait` follows it through
//! long-polling watches until it is terminal. Machine output for a waited
//! deletion is one envelope whose `deletion` field is the parsed operation
//! detail, including the structured blocker breakdown:
//!
//! ```text
//! {"schema_version":"aos.hub.cli/v1","kind":"registry_deletion",
//!  "data":{"operation":{},"deletion":{"phase":"deleted","readiness":{
//!    "verdict":"automatic","blockers":{"repositories":"0"}}}}}
//! ```

use crate::cli::{HubAccessArgs, HubMutationArgs, HubOperationArgs};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::input::parse_duration_seconds;
use crate::commands::hub::mutation::{confirm_destructive, new_idempotency_key};
use crate::commands::hub::output::{print_hub_json, print_topology_message, snake_case_json};
use anyhow::{Context as _, Result};
use aos_core::output::{OutputMode, Printer};
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};

/// Longest single watch request; the Hub answers earlier on any change.
const WATCH_SECONDS: i64 = 30;

/// Handles `aos hub registry delete`.
///
/// # Errors
///
/// Returns an error if credential resolution or a Hub call fails, the apply
/// is refused, or a waited operation does not succeed.
pub(super) async fn delete_registry(
    printer: &Printer,
    access: &HubAccessArgs,
    registry: &str,
    mutation: &HubMutationArgs,
    operation: &HubOperationArgs,
) -> Result<()> {
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let Some(plan_id) = mutation.plan_id.as_deref() else {
        return plan_registry_deletion(printer, &client, registry, mutation).await;
    };

    let idempotency_key = mutation
        .idempotency_key
        .clone()
        .context("--idempotency-key is required when applying a reviewed plan")?;
    if !confirm_destructive(mutation.yes, "reviewed registry deletion")? {
        printer.info("registry deletion cancelled");
        return Ok(());
    }
    let response: hub_types::OperationResponse = client
        .call_topology(
            HubTopologyMethod::DeleteRegistry,
            &hub_types::ApplyDeleteTopologyResourceRequest {
                plan_id: plan_id.into(),
                idempotency_key,
                confirmation_hash: mutation.confirm_hash.clone().unwrap_or_default(),
            },
        )
        .await?;
    if !operation.wait {
        print_topology_message(printer, &response)?;
        if let Some(started) = response.operation.as_ref() {
            printer.info(&format!(
                "follow it with: aos hub operation watch {}",
                started.operation_id
            ));
        }
        return Ok(());
    }
    let operation_id = response
        .operation
        .as_ref()
        .context("the Hub returned a deletion response without an operation")?
        .operation_id
        .clone();
    wait_for_registry_deletion(printer, &client, &operation_id, operation.timeout.as_deref())
        .await
}

async fn plan_registry_deletion(
    printer: &Printer,
    client: &HubClient,
    registry: &str,
    mutation: &HubMutationArgs,
) -> Result<()> {
    let idempotency_key = mutation
        .idempotency_key
        .clone()
        .unwrap_or_else(new_idempotency_key);
    let planned: hub_types::RegistryDeletePlanResponse = client
        .call_topology(
            HubTopologyMethod::PlanDeleteRegistry,
            &hub_types::PlanDeleteTopologyResourceRequest {
                stable_id: registry.into(),
                expected_resource_version: mutation.if_version.clone(),
                idempotency_key: idempotency_key.clone(),
            },
        )
        .await?;
    let plan = planned
        .plan
        .as_ref()
        .context("the Hub returned a deletion plan response without a plan")?;
    print_topology_message(printer, &planned)?;
    if printer.mode() == OutputMode::Json {
        return Ok(());
    }

    if let Some(readiness) = planned.readiness.as_ref() {
        print_readiness(printer, readiness);
    }
    if !mutation.plan {
        printer.info(&format!(
            "review the plan, then apply it with --plan-id {} --confirm-hash {} \
             --idempotency-key {} --wait",
            plan.plan_id, plan.confirmation_hash, idempotency_key
        ));
    }
    Ok(())
}

/// Prints the readiness verdict and its reasons or automatic steps.
fn print_readiness(printer: &Printer, readiness: &hub_types::RegistryDeletionReadiness) {
    printer.info(&format!("deletion readiness: {}", readiness.verdict));
    for reason in &readiness.blocking_reasons {
        printer.warning(&format!("blocked: {reason}"));
    }
    for step in &readiness.automatic_steps {
        printer.info(&format!("the operation will {step}"));
    }
}

/// Follows a deletion operation until it is terminal.
async fn wait_for_registry_deletion(
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
    let mut last_progress = String::new();
    loop {
        let elapsed = i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX);
        let remaining = total_timeout.map(|seconds| seconds.saturating_sub(elapsed));
        if remaining == Some(0) {
            anyhow::bail!("timed out waiting for registry deletion operation '{operation_id}'");
        }

        // The watch long-polls on the Hub and returns as soon as the
        // operation's resource version changes, so no client sleep is needed.
        let response: hub_types::WatchOperationResponse = client
            .call_topology(
                HubTopologyMethod::WatchOperation,
                &hub_types::WatchOperationRequest {
                    operation_id: operation_id.into(),
                    after_resource_version: after_resource_version.clone(),
                    timeout_seconds: remaining.unwrap_or(WATCH_SECONDS).min(WATCH_SECONDS),
                },
            )
            .await?;
        let detail = response
            .operation
            .as_ref()
            .context("the Hub returned a watch response without operation detail")?;
        after_resource_version.clone_from(&detail.resource_version);
        let deletion = parse_deletion_detail(&detail.detail_json);

        let progress = format!(
            "{}: {}",
            deletion["phase"].as_str().unwrap_or("pending"),
            deletion["message"].as_str().unwrap_or_default()
        );
        if printer.mode() != OutputMode::Json && progress != last_progress {
            printer.info(&format!("registry deletion {progress}"));
            last_progress = progress;
        }
        if response.terminal {
            return finish_deletion(printer, detail, deletion);
        }
    }
}

/// Reports a terminal deletion operation and maps failure to an error.
fn finish_deletion(
    printer: &Printer,
    detail: &hub_types::OperationDetail,
    deletion: serde_json::Value,
) -> Result<()> {
    let state = detail
        .operation
        .as_ref()
        .map(|operation| operation.state.clone())
        .unwrap_or_default();
    let blocking_reasons = deletion["readiness"]["blockingReasons"]
        .as_array()
        .map(|reasons| {
            reasons
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let summary = snake_case_json(serde_json::json!({
        "operation": serde_json::to_value(detail)?,
        "deletion": deletion,
    }));
    if !print_hub_json(printer, "registry_deletion", summary) {
        for reason in &blocking_reasons {
            printer.warning(&format!("blocked: {reason}"));
        }
    }

    match state.as_str() {
        "succeeded" => {
            printer.success("registry deleted");
            Ok(())
        }
        "failed" | "cancelled" => {
            let reason = if detail.error.is_empty() {
                "no error detail was provided"
            } else {
                detail.error.as_str()
            };
            anyhow::bail!("registry deletion {state}: {reason}")
        }
        other => anyhow::bail!("registry deletion ended in unexpected state '{other}'"),
    }
}

/// Parses operation detail, keeping malformed detail visible as a string.
fn parse_deletion_detail(detail_json: &str) -> serde_json::Value {
    serde_json::from_str(detail_json)
        .unwrap_or_else(|_| serde_json::Value::String(detail_json.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_detail_parses_structured_readiness_and_keeps_malformed_text() {
        let parsed = parse_deletion_detail(
            r#"{"phase":"blocked","readiness":{"blockingReasons":["27 repositories"]}}"#,
        );
        assert_eq!(parsed["phase"], "blocked");
        assert_eq!(parsed["readiness"]["blockingReasons"][0], "27 repositories");

        assert_eq!(
            parse_deletion_detail("not json"),
            serde_json::Value::String("not json".to_string())
        );
    }
}
