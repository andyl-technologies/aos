//! Canonical notification review controls over the public Hub API.

use anyhow::{Result, bail, ensure};
use aos_assessment_runtime::notifications::{
    DestinationReviewQueryV1, NotificationDeliveryPageV1, NotificationDeliveryQueryV1,
    NotificationDestinationV1, SubscriptionPageV1, SubscriptionQueryV1, SubscriptionV1,
    SubscriptionWriteV1,
};
use aos_core::output::{OutputMode, Printer};
use aos_maintain::presentation::escape_terminal;
use aos_remote::{hub_rpc, hub_types};

use super::client::hub_client;
use crate::cli::{HubAccessArgs, HubAssessmentCmd};
use crate::commands::input::read_bounded_file;

/// Executes closed notification reviews through the normal scoped Hub credentials.
///
/// # Errors
/// Returns an error for invalid requests, unavailable authority, failed RPCs or mismatched receipts.
pub(super) async fn run(printer: &Printer, command: &HubAssessmentCmd) -> Result<()> {
    match command {
        HubAssessmentCmd::Deliveries {
            access,
            registry,
            subscription_id,
            after_delivery,
            resource_scope,
            limit,
        } => {
            read_deliveries(
                printer,
                access,
                registry,
                NotificationDeliveryQueryV1 {
                    schema: "aos.assessment-notification-delivery-query/v1".into(),
                    resource_scope: resource_scope.clone(),
                    delivery_id: None,
                    subscription_id: subscription_id.clone(),
                    after_delivery: after_delivery.clone(),
                    limit: *limit,
                },
            )
            .await
        }
        HubAssessmentCmd::Delivery {
            access,
            registry,
            delivery_id,
            resource_scope,
        } => {
            read_deliveries(
                printer,
                access,
                registry,
                NotificationDeliveryQueryV1 {
                    schema: "aos.assessment-notification-delivery-query/v1".into(),
                    resource_scope: resource_scope.clone(),
                    delivery_id: Some(delivery_id.clone()),
                    subscription_id: None,
                    after_delivery: None,
                    limit: 1,
                },
            )
            .await
        }
        HubAssessmentCmd::Subscriptions {
            access,
            registry,
            subscription_id,
            after_subscription,
            resource_scope,
            limit,
        } => {
            let query = SubscriptionQueryV1 {
                schema: "aos.assessment-subscription-query/v1".into(),
                resource_scope: resource_scope.clone(),
                subscription_id: subscription_id.clone(),
                after_subscription: after_subscription.clone(),
                limit: *limit,
            };
            query.validate()?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response = client
                .call_topology(
                    hub_rpc::ListAssessmentSubscriptions,
                    &hub_types::AssessmentControlRequest {
                        registry_slug: registry.clone(),
                        document_json: serde_json::to_vec(&query)?,
                    },
                )
                .await?;
            let page = SubscriptionPageV1::from_slice(&response.document_json)?;
            ensure!(
                !resource_scope
                    .as_ref()
                    .is_some_and(|scope| scope != &page.resource_scope)
                    && page.subscriptions.len() <= *limit as usize
                    && !subscription_id
                        .as_ref()
                        .is_some_and(|identity| page.subscriptions.len() != 1
                            || page.subscriptions[0].subscription_id != *identity),
                "notification subscription page differs from the selected query"
            );
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-subscriptions", "data":page}));
            } else {
                for subscription in page.subscriptions {
                    render(printer, &subscription);
                }
            }
            Ok(())
        }
        HubAssessmentCmd::Subscription {
            access,
            registry,
            request,
        } => {
            let bytes = read_bounded_file(request, 262_144, "assessment notification review")?;
            let request = SubscriptionWriteV1::from_slice(&bytes)?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response = client
                .call_topology(
                    hub_rpc::WriteAssessmentSubscription,
                    &hub_types::AssessmentControlRequest {
                        registry_slug: registry.clone(),
                        document_json: bytes,
                    },
                )
                .await?;
            let subscription = SubscriptionV1::from_slice(&response.document_json)?;
            ensure!(
                subscription.resource_scope == request.resource_scope
                    && subscription.subscription_id == request.subscription_id
                    && subscription.enabled == request.enabled
                    && subscription.configuration == request.configuration,
                "notification receipt differs from the reviewed request"
            );
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-subscription", "data":subscription}));
            } else {
                render(printer, &subscription);
            }
            Ok(())
        }
        HubAssessmentCmd::NotificationDestination {
            access,
            registry,
            request,
        } => {
            let bytes = read_bounded_file(
                request,
                262_144,
                "assessment notification destination query",
            )?;
            let query = DestinationReviewQueryV1::from_slice(&bytes)?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let response = client
                .call_topology(
                    hub_rpc::ReviewAssessmentNotificationDestination,
                    &hub_types::AssessmentControlRequest {
                        registry_slug: registry.clone(),
                        document_json: bytes,
                    },
                )
                .await?;
            let destination = NotificationDestinationV1::from_slice(&response.document_json)?;
            ensure!(
                destination.resource_scope == query.resource_scope
                    && destination.destination_reference == query.destination_reference
                    && destination.expires_at == query.review_expires_at,
                "registered notification destination differs from the reviewed selection"
            );
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-notification-destination", "data":destination}));
            } else {
                printer.info(&format!(
                    "{} revision {}: {}\n  commitment {}\n  expires {}",
                    escape_terminal(&destination.destination_reference, 128),
                    destination.revision,
                    escape_terminal(&destination.url, 2048),
                    destination.digest()?,
                    destination.expires_at
                ));
            }
            Ok(())
        }
        _ => bail!("unsupported assessment notification command"),
    }
}

async fn read_deliveries(
    printer: &Printer,
    access: &HubAccessArgs,
    registry: &str,
    query: NotificationDeliveryQueryV1,
) -> Result<()> {
    query.validate()?;
    let client = hub_client(&access.hub, access.token.as_deref()).await?;
    let response = client
        .call_topology(
            hub_rpc::ListAssessmentNotificationDeliveries,
            &hub_types::AssessmentControlRequest {
                registry_slug: registry.to_owned(),
                document_json: serde_json::to_vec(&query)?,
            },
        )
        .await?;
    let page = NotificationDeliveryPageV1::from_slice(&response.document_json)?;
    ensure!(
        query
            .resource_scope
            .as_ref()
            .is_none_or(|scope| scope == &page.resource_scope)
            && query.subscription_id == page.subscription_id
            && page.deliveries.len() <= query.limit as usize
            && query
                .delivery_id
                .as_ref()
                .is_none_or(|identity| page.deliveries.len() == 1
                    && page.deliveries[0].delivery_id == *identity),
        "notification delivery page differs from the selected query"
    );
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({"schema_version":"aos.hub.cli/v1", "kind":"assessment-notification-deliveries", "data":page}));
    } else {
        printer.info(&format!("Delivery status observed at {}", page.as_of));
        for delivery in &page.deliveries {
            let state = serde_json::to_value(delivery.state)?;
            printer.info(&format!(
                "{}: {} (attempt {})\n  subscription {} revision {}, event {}\n  eligible {}{}",
                escape_terminal(&delivery.delivery_id, 128),
                state.as_str().unwrap_or("unknown"),
                delivery.attempt,
                escape_terminal(&delivery.subscription_id, 128),
                delivery.subscription_revision,
                delivery.event_sequence,
                delivery.not_before,
                delivery
                    .lease_expires_at
                    .as_ref()
                    .map(|time| format!(", lease expires {time}"))
                    .unwrap_or_default()
            ));
            if let Some(batch) = &delivery.batch_delivery_id {
                printer.info(&format!("  physical batch {}", escape_terminal(batch, 128)));
            }
            if let Some(failure) = delivery.last_error_code {
                let failure = serde_json::to_value(failure)?;
                printer.info(&format!("  {}", failure.as_str().unwrap_or("unknown")));
            }
        }
        if let Some(next) = &page.next_delivery {
            printer.info(&format!(
                "Continue with --resource-scope {} --after-delivery {}",
                escape_terminal(&page.resource_scope, 128),
                escape_terminal(next, 128)
            ));
        }
    }
    Ok(())
}

fn render(printer: &Printer, subscription: &SubscriptionV1) {
    printer.info(&format!(
        "{} revision {}: {}\n  destination {}\n  authority expires {}",
        escape_terminal(&subscription.subscription_id, 128),
        subscription.revision,
        if subscription.enabled {
            "enabled"
        } else {
            "disabled"
        },
        escape_terminal(&subscription.configuration.destination_reference, 128),
        subscription.authority_expires_at
    ));
}
