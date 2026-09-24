//! Checked resumable watch streaming over the registered public endpoint.

use anyhow::{Context as _, Result};
use aos_proto::aos::sandbox::v1::{EventKind, OperationServiceClient};
use aos_sandbox::cli_model::{
    DormantSandboxOutputV1, DormantSandboxRequestKindV1, DormantSandboxRequestV1,
    DormantWatchContinuationV1,
};
use aos_sandbox::client_state::{WatchApplyOutcomeV1, WatchResumePointV1};
use aos_sandbox::controller_query::{
    AuthenticatedWatchReadBatchV1, CheckedAuditWatchEventV1, CheckedObservationWatchInputV1,
    CheckedWatchEventV1, CheckedWatchRequestV1, ObservationWatchAdvanceV1,
    ObservationWatchContinuationV1, checked_watch_request_commitment_v1,
};
use aos_sandbox_core::CapabilityId;

use crate::cli::sandbox::SandboxArgs;

use super::{AuthorizedEndpoint, authenticated_query_binding};

/// Consumes one bounded public watch stream through checked event projections.
///
/// # Errors
///
/// Returns an error for protected transport failure, a rejected watch, an
/// invalid event, or output failure.
pub(in crate::commands::sandbox) async fn dispatch_watch(
    args: &SandboxArgs,
    request: &DormantSandboxRequestV1,
    output: DormantSandboxOutputV1,
    expected_capability_id: Option<CapabilityId>,
) -> Result<bool> {
    let DormantSandboxRequestKindV1::Events(message) = request.kind() else {
        return Ok(false);
    };
    if !args.public_api {
        return Ok(false);
    }
    let expected_capability_id = expected_capability_id
        .context("authenticated watch has no protected capability identity")?;
    let endpoint = AuthorizedEndpoint::connect(args, Some(expected_capability_id)).await?;
    let mut wire_request = message.clone();
    let retained = wire_request
        .resume_after
        .as_option()
        .map(|cursor| DormantWatchContinuationV1::decode(&cursor.opaque_cursor))
        .transpose()
        .context("watch cursor is not a bound CLI continuation")?;
    let resume = retained
        .as_ref()
        .map(|retained| {
            wire_request.resume_after = Some(aos_proto::aos::sandbox::v1::WatchCursor {
                opaque_cursor: retained.server_cursor().to_vec(),
                ..Default::default()
            })
            .into();
            WatchResumePointV1::from_cli_continuation(
                retained.binding(),
                retained.server_cursor().to_vec(),
                retained.sequence(),
            )
        })
        .transpose()
        .context("retained watch continuation is invalid")?;
    let mut stream =
        OperationServiceClient::new(endpoint.connection.clone(), endpoint.watch_config()?)
            .watch(wire_request.clone())
            .await
            .context("controller rejected operation watch")?;
    let binding = authenticated_query_binding(stream.headers())?;
    if retained
        .as_ref()
        .is_some_and(|retained| retained.binding() != binding)
    {
        anyhow::bail!("controller changed the authenticated watch binding");
    }
    let commitment = checked_watch_request_commitment_v1(&wire_request)
        .context("watch request is not canonical")?;
    let checked_request = CheckedWatchRequestV1::new(wire_request, binding, commitment, resume)
        .context("watch request continuation is invalid")?;
    let mut continuation = ObservationWatchContinuationV1::new(checked_request)
        .context("watch reducer could not be initialized")?;
    let maximum_events = request.client_state().maximum_events();
    for _ in 0..maximum_events {
        let Some(event) = stream
            .message()
            .await
            .context("controller watch stream failed")?
        else {
            require_complete_baseline(continuation.resume_point().is_some(), "stream end")?;
            return Ok(true);
        };
        let event = event.to_owned_message();
        let requested_resume = continuation.read_request().resume().cloned();
        let snapshot_complete =
            event.kind.as_known() == Some(EventKind::EVENT_KIND_SNAPSHOT_COMPLETE);
        let (input, public_event, audit_event) = if message.audit_only && !snapshot_complete {
            let checked = CheckedAuditWatchEventV1::from_response(binding, event)
                .context("controller returned an invalid audit watch event")?;
            (
                CheckedObservationWatchInputV1::AuditEvent(checked.clone()),
                None,
                Some(checked),
            )
        } else {
            let checked = CheckedWatchEventV1::from_response(binding, event)
                .context("controller returned an invalid watch event")?;
            (
                CheckedObservationWatchInputV1::PublicEvent(checked.clone()),
                Some(checked),
                None,
            )
        };
        let batch =
            AuthenticatedWatchReadBatchV1::new(binding, commitment, requested_resume, vec![input])
                .context("watch response batch is invalid")?;
        let advances = continuation
            .apply_authenticated_batch(batch)
            .context("watch reducer rejected the response")?;
        if advances.iter().any(|advance| {
            matches!(
                advance,
                ObservationWatchAdvanceV1::Public(WatchApplyOutcomeV1::Terminated(_))
            )
        }) {
            anyhow::bail!("watch stream requires resynchronization");
        }
        let should_render = advances.iter().any(|advance| {
            matches!(
                advance,
                ObservationWatchAdvanceV1::Public(WatchApplyOutcomeV1::BootstrapComplete(_))
                    | ObservationWatchAdvanceV1::Public(WatchApplyOutcomeV1::EventApplied(_))
                    | ObservationWatchAdvanceV1::AuditEventApplied(_)
            )
        });
        if should_render {
            match (public_event.as_ref(), audit_event.as_ref()) {
                (Some(event), None) => super::super::render_checked(output, event)?,
                (None, Some(event)) => super::super::render_checked(output, event)?,
                _ => anyhow::bail!("internal watch projection mismatch"),
            }
        }
    }

    require_complete_baseline(continuation.resume_point().is_some(), "event limit")?;
    Ok(true)
}

fn require_complete_baseline(complete: bool, boundary: &str) -> Result<()> {
    if !complete {
        anyhow::bail!("watch {boundary} reached before bootstrap completion");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_complete_baseline;

    #[test]
    fn watch_boundaries_reject_partial_bootstrap() {
        for boundary in ["stream end", "event limit"] {
            assert!(require_complete_baseline(false, boundary).is_err());
            assert!(require_complete_baseline(true, boundary).is_ok());
        }
    }
}
