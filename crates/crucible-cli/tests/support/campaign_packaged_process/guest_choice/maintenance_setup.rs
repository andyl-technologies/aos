//! Shared real guest-choice admission for retained storage-maintenance flights.

use super::*;

/// Selects the original fast recovery and retry-seven terminal execution.
///
/// # Errors
///
/// Returns the original public admission, observation or attempt-wait failure.
pub(super) fn select_running_maintenance_attempt(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    genesis: &str,
    fast_command: u8,
    terminal_command: u8,
) -> Result<(AttemptExecutionKey, String), Box<dyn Error>> {
    let (discovery, explanation) = wait_for_initial_discovery(fixture, service, genesis)?;
    diagnostics::report_maintenance_stage("initial-discovery-completed");
    let parent = json_string(&explanation["observation"], "child_artifact")?;
    let configuration = json_string(&explanation["observation"], "child")?;
    let recovery = wait_for_choice(fixture, "network.recovery-policy", &parent, &configuration)?;
    let mut known = attempt_states(fixture)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    known.insert(discovery);

    let fast = submit_choice(
        fixture,
        &recovery,
        &format!("discrete:{FAST_ALTERNATIVE}"),
        "next-choice",
        fast_command,
    )?;
    let fast_request = accepted_branch_request(&fast)?;
    let fast_attempt = wait_for_new_completed_attempt(fixture, service, &known, &fast_request)?;
    known.insert(fast_attempt);
    diagnostics::report_maintenance_stage("fast-recovery-attempt-completed");
    let fast_explanation = wait_for_attempt_observation(fixture, fast_attempt)?;
    let fast_parent = json_string(&fast_explanation["observation"], "child_artifact")?;
    let fast_configuration = json_string(&fast_explanation["observation"], "child")?;
    let retry = wait_for_choice(
        fixture,
        "network.retry-quanta",
        &fast_parent,
        &fast_configuration,
    )?;
    let terminal = submit_choice(fixture, &retry, "u64:7", "terminal", terminal_command)?;
    let terminal_request = accepted_branch_request(&terminal)?;
    let active = wait_for_new_running_attempt(fixture, service, &known, &terminal_request)?;
    diagnostics::report_maintenance_stage("selected-attempt-running");
    Ok((active, terminal_request))
}
