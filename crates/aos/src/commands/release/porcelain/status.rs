//! `aos release status`: the release's state and next step, read-only.
//!
//! ```text
//! State: finalized
//! staging/edge: complete
//! production/edge: pending
//! Next: qualify-run production/edge staging (collect) (aos release advance --to production/edge)
//! ```
//!
//! The next line comes from the same planner `advance` uses, evaluated for
//! the first planned destination that is not complete (staging destinations
//! first); it is either `Next: ...`, a `Waiting: ...` instruction, or
//! `Complete: ...` once every destination is complete.

use std::time::SystemTime;

use anyhow::Result;
use aos_core::output::Printer;
use aos_release::plan::{PlannedDestination, SurfaceRole};
use aos_release::state::ReleaseState;

use super::planner::{self, Next, Options};
use super::{Session, observe};
use crate::cli::ReleaseWorkArgs;

/// Prints the release state, each destination's state, and the next step.
///
/// # Errors
/// Returns an error for an unreadable configuration, work directory, or
/// journal, or journal state the planner cannot reconcile.
pub(super) fn run(args: &ReleaseWorkArgs, printer: &Printer) -> Result<()> {
    let session = Session::open(args.config.as_deref(), args.work.as_deref())?;
    let observation = observe::release(&session)?;
    let global = observation
        .release
        .global
        .unwrap_or(ReleaseState::Planned)
        .to_string();
    let destinations: Vec<(String, String)> = ordered(&session.plan.destinations)
        .into_iter()
        .map(|destination| {
            (
                destination.name.clone(),
                observation
                    .state_of(&destination.name)
                    .map_or_else(|| "pending".to_owned(), |state| state.to_string()),
            )
        })
        .collect();
    let next = next_line(&session, &observation)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.porcelain-status/v1",
        "release_id": session.plan.release_id,
        "state": global,
        "destinations": destinations.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
        "next": next,
    })) {
        return Ok(());
    }
    for line in render(&global, &destinations, &next) {
        println!("{line}");
    }
    Ok(())
}

/// Returns destinations with staging destinations first, otherwise in plan order.
pub(super) fn ordered(destinations: &[PlannedDestination]) -> Vec<&PlannedDestination> {
    let mut ordered: Vec<&PlannedDestination> = destinations.iter().collect();
    ordered.sort_by_key(|destination| destination.surface != SurfaceRole::Staging);
    ordered
}

/// Computes the final status line from the planner.
fn next_line(session: &Session, observation: &observe::Observation) -> Result<String> {
    let options = Options {
        accept_transaction: false,
        ring_limit: None,
        now: SystemTime::now(),
    };
    for destination in ordered(&session.plan.destinations) {
        let facts = observe::destination(session, observation, destination)?;
        match planner::next(&observation.release, &facts, &options)? {
            Next::Run(step) => {
                return Ok(format!(
                    "Next: {} (aos release advance --to {})",
                    step.describe(&destination.name),
                    destination.name
                ));
            }
            Next::Wait(instruction) => return Ok(format!("Waiting: {instruction}")),
            Next::Done(_) => {}
        }
    }
    Ok("Complete: every planned destination is complete".to_owned())
}

/// Renders the status lines.
pub(super) fn render(global: &str, destinations: &[(String, String)], next: &str) -> Vec<String> {
    let mut lines = vec![format!("State: {global}")];
    lines.extend(
        destinations
            .iter()
            .map(|(name, state)| format!("{name}: {state}")),
    );
    lines.push(next.to_owned());
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_prints_state_destinations_then_the_next_line() {
        let lines = render(
            "finalized",
            &[
                ("staging/edge".to_owned(), "complete".to_owned()),
                ("production/edge".to_owned(), "pending".to_owned()),
            ],
            "Waiting: record fresh fitness",
        );
        assert_eq!(
            lines,
            [
                "State: finalized",
                "staging/edge: complete",
                "production/edge: pending",
                "Waiting: record fresh fitness",
            ]
        );
    }
}
