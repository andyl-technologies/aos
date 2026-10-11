//! Explicit plan/apply commands for exact assessment configuration reviews.

use anyhow::{Context as _, Result, bail};
use aos_assessment_runtime::notifications::{SubscriptionV1, SubscriptionWriteV1};
use aos_assessment_runtime::schedules::{ScheduleV1, ScheduleWriteV1};
use aos_core::output::{OutputMode, Printer};
use aos_maintain::presentation::escape_terminal;
use aos_remote::{hub_rpc, hub_types};

use super::client::hub_client;
use crate::cli::HubAssessmentCmd;
use crate::commands::input::read_bounded_file;

/// Plans immutable configuration or applies an explicitly selected retained plan.
///
/// # Errors
/// Returns an error for invalid review input, unavailable authority, failed API
/// calls, absent confirmation commitments or incompatible admitted responses.
pub(super) async fn run(printer: &Printer, command: &HubAssessmentCmd) -> Result<()> {
    match command {
        HubAssessmentCmd::Schedule {
            access,
            registry,
            request,
            idempotency_key,
        }
        | HubAssessmentCmd::Subscription {
            access,
            registry,
            request,
            idempotency_key,
        } => {
            let bytes = read_bounded_file(request, 262_144, "assessment configuration review")?;
            let schedule = matches!(command, HubAssessmentCmd::Schedule { .. });
            let expected = if schedule {
                ScheduleWriteV1::from_slice(&bytes)?.expected_revision
            } else {
                SubscriptionWriteV1::from_slice(&bytes)?.expected_revision
            };
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let request = hub_types::PlanAssessmentReviewRequest {
                registry_slug: registry.clone(),
                document_json: bytes,
                expected_resource_version: expected.to_string(),
                idempotency_key: idempotency_key.clone(),
            };
            let response = if schedule {
                client
                    .call_topology(hub_rpc::PlanWriteAssessmentSchedule, &request)
                    .await?
            } else {
                client
                    .call_topology(hub_rpc::PlanWriteAssessmentSubscription, &request)
                    .await?
            };
            let plan = response
                .plan
                .context("assessment review response omitted its plan")?;
            if plan.plan_id.is_empty()
                || aos_contract::Sha256Digest::parse(&format!("sha256:{}", plan.confirmation_hash))
                    .is_err()
            {
                bail!("assessment review response lacks an exact confirmation commitment");
            }
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-configuration-plan", "data":plan}));
            } else {
                printer.info(&format!(
                    "Plan {} · expires {}",
                    escape_terminal(&plan.plan_id, 128),
                    plan.expires_at
                ));
                for effect in &plan.effects {
                    printer.info(&escape_terminal(effect, 262_144));
                }
                for warning in &plan.warnings {
                    printer.info(&escape_terminal(warning, 4096));
                }
                printer.info(&format!("Review these effects before using apply-{} with --plan-id {} --confirmation-hash {} and an explicit --idempotency-key.",
                    if schedule { "schedule" } else { "subscription" }, escape_terminal(&plan.plan_id, 128), plan.confirmation_hash));
            }
            Ok(())
        }
        HubAssessmentCmd::ApplySchedule {
            access,
            plan_id,
            idempotency_key,
            confirmation_hash,
        }
        | HubAssessmentCmd::ApplySubscription {
            access,
            plan_id,
            idempotency_key,
            confirmation_hash,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let request = hub_types::ApplyRegistryMutationRequest {
                plan_id: plan_id.clone(),
                idempotency_key: idempotency_key.clone(),
                confirmation_hash: confirmation_hash.clone(),
            };
            let schedule = matches!(command, HubAssessmentCmd::ApplySchedule { .. });
            let response = if schedule {
                client
                    .call_topology(hub_rpc::WriteAssessmentSchedule, &request)
                    .await?
            } else {
                client
                    .call_topology(hub_rpc::WriteAssessmentSubscription, &request)
                    .await?
            };
            let (kind, document, identity, revision) = if schedule {
                let value = ScheduleV1::from_slice(&response.document_json)?;
                (
                    "assessment-schedule",
                    serde_json::to_value(&value)?,
                    value.schedule_id,
                    value.revision,
                )
            } else {
                let value = SubscriptionV1::from_slice(&response.document_json)?;
                (
                    "assessment-subscription",
                    serde_json::to_value(&value)?,
                    value.subscription_id,
                    value.revision,
                )
            };
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":kind, "data":document}));
            } else {
                printer.info(&format!(
                    "Applied review {} · revision {}",
                    escape_terminal(&identity, 128),
                    revision
                ));
            }
            Ok(())
        }
        _ => bail!("unsupported assessment review command"),
    }
}
