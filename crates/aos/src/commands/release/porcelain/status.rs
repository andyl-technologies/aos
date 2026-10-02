//! `aos maintain release status`: the release's state and next step, read-only.
//!
//! ```text
//! State: finalized
//! staging/edge: complete
//! production/edge: pending
//! Next: qualify-run production/edge staging (collect) (aos maintain release advance --to production/edge)
//! ```
//!
//! The next line comes from the same planner `advance` uses, evaluated for
//! the first planned destination that is not complete (staging destinations
//! first); it is either `Next: ...`, a `Waiting: ...` instruction, or
//! `Complete: ...` once every destination is complete.

use std::collections::BTreeMap;
use std::time::SystemTime;

use anyhow::Result;
use aos_core::output::Printer;
use aos_registry_surface::staging::{StageRecord, StageState};
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
    let candidates: BTreeMap<String, Result<StageRecord, String>> =
        ordered(&session.plan.destinations)
            .into_iter()
            .filter(|destination| {
                observation.state_of(&destination.name).is_none()
                    && session.work.staged_upload(&destination.name).exists()
            })
            .map(|destination| {
                let inspected = inspect_candidate(&session, &observation, destination)
                    .map_err(|error| format!("{error:#}"));
                (destination.name.clone(), inspected)
            })
            .collect();
    let destinations: Vec<(String, String)> = ordered(&session.plan.destinations)
        .into_iter()
        .map(|destination| {
            let state = observation.state_of(&destination.name).map_or_else(
                || match candidates.get(&destination.name) {
                    Some(Ok(record)) => candidate_state(record),
                    Some(Err(_)) => "stale or corrupt candidate upload".to_owned(),
                    None => "pending".to_owned(),
                },
                |state| state.to_string(),
            );
            (destination.name.clone(), state)
        })
        .collect();
    let next = next_line(&session, &observation, &candidates)?;
    let candidate_diagnostics: BTreeMap<&str, &str> = candidates
        .iter()
        .filter_map(|(name, result)| {
            result
                .as_ref()
                .err()
                .map(|error| (name.as_str(), error.as_str()))
        })
        .collect();

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.porcelain-status/v1",
        "release_id": session.plan.release_id,
        "state": global,
        "destinations": destinations.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
        "next": next,
        "candidate_diagnostics": candidate_diagnostics,
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
fn next_line(
    session: &Session,
    observation: &observe::Observation,
    candidates: &BTreeMap<String, Result<StageRecord, String>>,
) -> Result<String> {
    let options = Options {
        accept_transaction: false,
        ring_limit: None,
        now: SystemTime::now(),
    };
    for destination in ordered(&session.plan.destinations) {
        let facts = observe::destination(session, observation, destination)?;
        match planner::next(&observation.release, &facts, &options)? {
            Next::Run(planner::Step::Publish) if candidates.contains_key(&destination.name) => {
                return Ok(candidate_next_action(
                    &destination.name,
                    session.work.root(),
                    &candidates[&destination.name],
                ));
            }
            Next::Run(step) => {
                return Ok(format!(
                    "Next: {} (aos maintain release advance --to {})",
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

/// Revalidates candidate bytes against the current signed bundle and composed metadata.
fn inspect_candidate(
    session: &Session,
    observation: &observe::Observation,
    destination: &PlannedDestination,
) -> Result<StageRecord> {
    let mut args = super::steps::publication_args(session, destination, observation, false, None)?;
    args.staged_upload = Some(session.work.staged_upload(&destination.name));
    super::super::publish::inspect_staged_upload(&args)
}

/// Offers publication only when exact local candidate evidence still verifies.
fn candidate_next_action(
    destination: &str,
    work: &std::path::Path,
    candidate: &Result<StageRecord, String>,
) -> String {
    match candidate {
        Ok(record) => {
            let action = if record.state == StageState::Ready {
                "publish uploaded candidate"
            } else {
                "resume exact candidate publication"
            };
            format!(
                "Next: {action} (aos maintain release publish --to {} --stage-revision {} --work {})",
                destination,
                record.revision.revision,
                work.display()
            )
        }
        Err(error) => format!(
            "Waiting: candidate upload for {} is stale or corrupt: {}; inspect the retained candidate and rerun aos maintain release advance --to {} --stop-after-upload",
            destination, error, destination
        ),
    }
}

fn candidate_state(record: &StageRecord) -> String {
    let state = match record.state {
        StageState::Ready => "uploaded (unreleased)",
        StageState::Releasing => "publication in progress",
        StageState::Released => "publication journal pending",
        StageState::Draft => "upload pending",
        StageState::Discarded => "discarded candidate",
    };
    format!("{state}, revision {}", record.revision.revision)
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
    fn interrupted_publication_resumes_the_selected_candidate_in_every_durable_phase() {
        use aos_registry_surface::staging::{STAGE_SCHEMA, StageRevision, inventory_digest};

        for (state, label, action) in [
            (
                StageState::Ready,
                "uploaded (unreleased)",
                "publish uploaded candidate",
            ),
            (
                StageState::Releasing,
                "publication in progress",
                "resume exact candidate publication",
            ),
            (
                StageState::Released,
                "publication journal pending",
                "resume exact candidate publication",
            ),
        ] {
            let record = StageRecord {
                revision: StageRevision {
                    schema: STAGE_SCHEMA.into(),
                    id: "candidate-1".into(),
                    registry: "example/main".into(),
                    revision: 3,
                    release_id: "1.0.0".into(),
                    source_branch: "dplecki/candidate".into(),
                    commit: "a".repeat(40),
                    inventory_digest: inventory_digest(&[]).expect("empty inventory digest"),
                    inventory: Vec::new(),
                    container: None,
                    publication: Vec::new(),
                    store_roots: Vec::new(),
                },
                state,
                released_version: (state == StageState::Released).then(|| "1.0.0".into()),
            };
            assert_eq!(candidate_state(&record), format!("{label}, revision 3"));

            let next = candidate_next_action(
                "staging/edge",
                std::path::Path::new("/work/release-1"),
                &Ok(record),
            );
            assert!(next.contains(action));
            assert!(next.contains("release publish --to staging/edge --stage-revision 3"));
            assert!(!next.contains("advance"));
        }
    }

    #[test]
    fn stale_candidate_requires_inspection_before_publication() {
        let candidate = Err("current composed metadata differs from revision 2".to_string());
        let next = candidate_next_action(
            "staging/edge",
            std::path::Path::new("/work/release-1"),
            &candidate,
        );
        assert!(next.starts_with("Waiting: "));
        assert!(next.contains("current composed metadata differs from revision 2"));
        assert!(next.contains("advance --to staging/edge --stop-after-upload"));
        assert!(!next.contains("release publish"));
    }

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
