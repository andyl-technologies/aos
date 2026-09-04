//! Executes coordinated delivery workflows through the typed public Hub API.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_remote::{hub_rpc, hub_types as pb};

use crate::cli::{HubDeliveryActivationCmd, HubDeliveryCmd, HubReviewedApplyArgs};

use super::{confirm_destructive, hub_client, surface_message, topology_read};

enum ReviewedStage {
    Setup,
    Activation,
}

/// Executes one delivery workflow command.
///
/// # Errors
/// Returns an error for invalid input, unavailable credentials, or a rejected Hub request.
pub(super) async fn run(printer: &Printer, command: &HubDeliveryCmd) -> Result<()> {
    match command {
        HubDeliveryCmd::Plan {
            request,
            intent_file,
        } => {
            let intent = read_intent(intent_file)?;
            let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                hub_rpc::PlanDeliveryDestination,
                &pb::PlanDeliveryDestinationRequest {
                    intent: Some(intent),
                    idempotency_key: request.idempotency_key.clone(),
                    expected_resource_version: String::new(),
                },
            )
            .await
        }
        HubDeliveryCmd::Apply(apply) => apply_reviewed(printer, apply, ReviewedStage::Setup).await,
        HubDeliveryCmd::Show { access, workflow } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                hub_rpc::GetDeliveryWorkflow,
                &pb::GetDeliveryWorkflowRequest {
                    workflow_id: workflow.clone(),
                },
            )
            .await
        }
        HubDeliveryCmd::List {
            access,
            surface,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                hub_rpc::ListDeliveryWorkflows,
                &pb::ListDeliveryWorkflowsRequest {
                    surface: Some(surface_message(surface)?),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubDeliveryCmd::Resume {
            request,
            workflow,
            if_version,
        } => {
            let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
            topology_read(
                printer,
                &client,
                hub_rpc::ResumeDeliveryDestination,
                &pb::ResumeDeliveryDestinationRequest {
                    workflow_id: workflow.clone(),
                    expected_resource_version: if_version.clone(),
                    idempotency_key: request.idempotency_key.clone(),
                },
            )
            .await
        }
        HubDeliveryCmd::Activate { command } => match command {
            HubDeliveryActivationCmd::Plan {
                request,
                workflow,
                if_version,
            } => {
                let client = hub_client(&request.access.hub, request.access.token.as_deref())?;
                topology_read(
                    printer,
                    &client,
                    hub_rpc::PlanActivateDeliveryDestination,
                    &pb::PlanActivateDeliveryDestinationRequest {
                        workflow_id: workflow.clone(),
                        expected_resource_version: if_version.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    },
                )
                .await
            }
            HubDeliveryActivationCmd::Apply(apply) => {
                apply_reviewed(printer, apply, ReviewedStage::Activation).await
            }
        },
    }
}

async fn apply_reviewed(
    printer: &Printer,
    apply: &HubReviewedApplyArgs,
    stage: ReviewedStage,
) -> Result<()> {
    if !confirm_destructive(apply.yes, "reviewed delivery plan application")? {
        printer.info("Cancelled.");
        return Ok(());
    }
    let client = hub_client(&apply.access.hub, apply.access.token.as_deref())?;
    let request = pb::ApplyDeliveryDestinationRequest {
        plan_id: apply.plan_id.clone(),
        confirmation_hash: apply.confirm_hash.clone(),
        idempotency_key: apply.idempotency_key.clone(),
    };
    match stage {
        ReviewedStage::Activation => {
            topology_read(
                printer,
                &client,
                hub_rpc::ActivateDeliveryDestination,
                &request,
            )
            .await
        }
        ReviewedStage::Setup => {
            topology_read(
                printer,
                &client,
                hub_rpc::ApplyDeliveryDestination,
                &request,
            )
            .await
        }
    }
}

fn read_intent(path: &Path) -> Result<pb::DeliveryDestinationIntent> {
    const MAX_BYTES: u64 = 1024 * 1024;
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening delivery intent {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "delivery intent exceeds 1 MiB"
    );
    serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding delivery intent {}", path.display()))
}
