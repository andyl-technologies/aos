//! Authenticated terminal sampling and cleanup for interactive artifact capture.

use super::*;

pub(super) async fn interactive_terminal_fingerprints(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged: &mut Vec<SessionCommandKind>,
    sampling_plan: Option<&RunInvocationPlan>,
) -> Result<Vec<crucible::FingerprintSample>, CliError> {
    let Some(plan) = sampling_plan else {
        return Ok(Vec::new());
    };

    // Sample a stable, still-owned boundary. Stop reaps the nodes and closes
    // their channels, so a subsequent query cannot supply terminal authority.
    acknowledge_stream_command(control, command_id, SessionCommandKind::Pause, acknowledged)
        .await?;
    let mut samples = Vec::new();
    query_execution_fingerprint(control, command_id, plan, acknowledged, &mut samples).await?;
    Ok(samples)
}

pub(super) async fn finish_interactive_capture<C: ControlClient + Sync>(
    client: &C,
    session: crucible_api::SessionRef,
    result: Result<Option<InteractiveTerminalEvidence>, CliError>,
) -> Result<Option<InteractiveTerminalEvidence>, CliError> {
    let error = match result {
        Ok(evidence) => return Ok(evidence),
        Err(error) => error,
    };

    // Sampling refusal must still retire the original authenticated owner.
    let cleanup = client
        .destroy_session(
            crucible_api::DestroySessionRequest::new(session).with_expected_epoch(session.epoch),
        )
        .await;
    match cleanup {
        Ok(_) => Err(error),
        Err(cleanup) => Err(backend_error(format!(
            "{error}; retire failed interactive capture: {cleanup}"
        ))),
    }
}
