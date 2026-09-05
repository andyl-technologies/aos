//! Handles hub webhook commands and their domain-specific request validation.

use crate::cli::HubWebhookCmd;
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::apply_webhook_plan;
use crate::commands::hub::mutation::{new_idempotency_key, topology_mutation, topology_read};
use anyhow::Result;
use aos_core::output::Printer;
use aos_remote::{hub_rpc as HubTopologyMethod, hub_types};

/// Handles the hub webhook command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(super) async fn webhook(printer: &Printer, command: &HubWebhookCmd) -> Result<()> {
    match command {
        HubWebhookCmd::List {
            access,
            org,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_read::<_, hub_types::ListWebhooksResponse>(
                printer,
                &client,
                HubTopologyMethod::ListWebhooks,
                &hub_types::ListWebhooksRequest {
                    org_slug: org.clone(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubWebhookCmd::Create {
            access,
            org,
            url,
            events,
            secret_version_ref,
            credential_fingerprint,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyWebhookMutationRequest,
                hub_types::CreateWebhookResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanCreateWebhook,
                HubTopologyMethod::CreateWebhook,
                &hub_types::PlanCreateWebhookRequest {
                    org_slug: org.clone(),
                    url: url.clone(),
                    events: events.clone(),
                    idempotency_key: new_idempotency_key(),
                    secret_version_ref: secret_version_ref.clone(),
                    credential_fingerprint: credential_fingerprint.clone(),
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                },
                mutation,
                apply_webhook_plan,
            )
            .await
        }
        HubWebhookCmd::Delete {
            access,
            id,
            mutation,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref())?;
            topology_mutation::<
                _,
                hub_types::ApplyWebhookMutationRequest,
                hub_types::DeleteTopologyResourceResponse,
                _,
            >(
                printer,
                &client,
                HubTopologyMethod::PlanDeleteWebhook,
                HubTopologyMethod::DeleteWebhook,
                &hub_types::PlanDeleteWebhookRequest {
                    id: *id,
                    expected_resource_version: mutation.if_version.clone().unwrap_or_default(),
                    idempotency_key: new_idempotency_key(),
                },
                mutation,
                apply_webhook_plan,
            )
            .await
        }
    }
}
