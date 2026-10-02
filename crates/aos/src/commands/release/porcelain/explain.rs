//! `aos maintain release explain --to <destination>`: every obligation and its status.
//!
//! ```text
//! production/stable: profile soak (sha256:...)
//! claims qualified, soak 604800s, 4 ring(s)
//! change scope: image, container, and 3 package cell(s) affected
//! override: none
//! gates:
//!   [x] build build-integrity (blocking)
//!   [ ] staging staging-delivery (blocking)
//! reviews:
//!   [ ] staging: 0 of 1
//! fitness:
//!   [x] storage-restore: 3d 4h old, max 14d 0h; bindings match
//!   [!] key-rotation: 120d 0h old, max 90d 0h; bindings match
//!   [ ] hub-restore: no attestation
//! surface metadata:
//!   [ ] release record
//!   [ ] TUF metadata
//!   [ ] timestamp
//!   [ ] composed surface
//!   [ ] timestamp published
//! rings:
//!   [ ] ring 1: 4 partitions, observe 86400s: pending
//! completion approvals:
//!   [ ] 0 of 2
//! Next: qualify-run production/stable staging (collect)
//! ```
//!
//! `[x]` is satisfied, `[ ]` missing, `[!]` expired or no longer matching.
//! Nothing is written.

use std::time::{Duration, SystemTime};

use anyhow::Result;
use aos_core::output::Printer;
use aos_release::fitness::signer_roster_digest;
use aos_release::plan::{PlannedDestination, SurfaceRole};
use aos_release::qualification::{ClaimSelection, QualificationContract, QualificationPhase};
use aos_release::state::ReleaseState;

use super::fitness::{self, KindStatus, format_age};
use super::planner::{
    self, DestinationFacts, Next, Options, SurfaceMetadataFacts, TIMESTAMP_RENEWAL_MARGIN,
    format_time,
};
use super::workdir::Phase;
use super::{Session, observe};
use crate::cli::ReleaseExplainArgs;

/// Status marker of one obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mark {
    /// The obligation is met.
    Satisfied,
    /// The obligation is not met yet.
    Missing,
    /// Evidence exists but is too old or no longer matches.
    Expired,
}

impl Mark {
    const fn glyph(self) -> &'static str {
        match self {
            Self::Satisfied => "[x]",
            Self::Missing => "[ ]",
            Self::Expired => "[!]",
        }
    }
}

/// Everything `explain` prints for one destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Explanation {
    /// Destination name.
    pub(super) destination: String,
    /// Profile name and digest.
    pub(super) profile: (String, String),
    /// Claim selection, soak in force, and ring count line.
    pub(super) obligations: String,
    /// Change scope summary.
    pub(super) change_scope: String,
    /// Override in force, if any.
    pub(super) override_in_force: Option<String>,
    /// Gates as (mark, phase, policy id, blocking).
    pub(super) gates: Vec<(Mark, String, String, bool)>,
    /// Reviews per hold point as (mark, phase, present, required).
    pub(super) reviews: Vec<(Mark, String, u16, u16)>,
    /// Fitness kinds as (mark, detail).
    pub(super) fitness: Vec<(Mark, String)>,
    /// Surface metadata the publication carries as (mark, detail); empty when
    /// the destination reuses its surface's publication.
    pub(super) surface_metadata: Vec<(Mark, String)>,
    /// Rings as (mark, detail).
    pub(super) rings: Vec<(Mark, String)>,
    /// Completion approvals as (mark, present, required), for qualified profiles.
    pub(super) completion: Option<(Mark, u16, u16)>,
    /// The first unmet condition: the planner's next line.
    pub(super) next: String,
}

/// Prints the destination's obligations with their status.
///
/// # Errors
/// Returns an error for an unknown destination or unreadable release state.
pub(super) fn run(args: &ReleaseExplainArgs, printer: &Printer) -> Result<()> {
    let session = Session::open(args.config.as_deref(), args.work.as_deref())?;
    let destination = session.destination(&args.to)?;
    let observation = observe::release(&session)?;
    let facts = observe::destination(&session, &observation, destination)?;
    let now = SystemTime::now();
    let fitness = fitness_statuses(&session, destination, now)?;
    let next = match planner::next(
        &observation.release,
        &facts,
        &Options {
            accept_transaction: false,
            ring_limit: None,
            now,
        },
    )? {
        Next::Run(step) => format!("Next: {}", step.describe(&destination.name)),
        Next::Wait(instruction) => format!("Waiting: {instruction}"),
        Next::Done(message) => format!("Done: {message}"),
    };
    let explanation = explain(
        &session,
        &observation,
        destination,
        &facts,
        &fitness,
        next,
        now,
    )?;
    for line in render(&explanation) {
        printer.plain(&line);
    }
    Ok(())
}

/// Builds the explanation from observed facts.
fn explain(
    session: &Session,
    observation: &observe::Observation,
    destination: &PlannedDestination,
    facts: &DestinationFacts,
    fitness: &[KindStatus],
    next: String,
    now: SystemTime,
) -> Result<Explanation> {
    let plan = &session.plan;
    let contract = &plan.qualification;
    let profile = contract.profile(&destination.profile)?;
    let overridden = plan
        .profile_overrides
        .iter()
        .find(|reference| reference.destination == destination.name);
    let effective = if overridden.is_some() {
        " (override)"
    } else {
        ""
    };

    let finalized = matches!(observation.release.global, Some(ReleaseState::Finalized));
    let gates = destination
        .gates
        .iter()
        .map(|gate| {
            let phase = gate_phase(contract, &gate.policy_id);
            let mark = if phase_satisfied(phase, facts, finalized) {
                Mark::Satisfied
            } else {
                Mark::Missing
            };
            (
                mark,
                phase.map_or_else(
                    || "unknown".to_owned(),
                    |phase| format!("{phase:?}").to_lowercase(),
                ),
                gate.policy_id.clone(),
                gate.blocking,
            )
        })
        .collect();
    let reviews = facts
        .phases
        .iter()
        .filter(|(phase, phase_facts)| phase_facts.has_cases || **phase == Phase::Staging)
        .map(|(phase, phase_facts)| {
            let mark =
                if phase_facts.signed || phase_facts.accepted_reviews >= facts.review_threshold {
                    Mark::Satisfied
                } else {
                    Mark::Missing
                };
            (
                mark,
                phase.to_string(),
                phase_facts.accepted_reviews,
                facts.review_threshold,
            )
        })
        .collect();
    let fitness = fitness
        .iter()
        .filter(|status| profile.fitness.contains_key(&status.kind))
        .map(|status| fitness_line(status, &profile.name))
        .collect();
    let rings = ring_lines(destination, facts, now);
    let surface_metadata = facts
        .surface_metadata
        .as_ref()
        .map(|metadata| surface_metadata_lines(metadata, now))
        .unwrap_or_default();

    Ok(Explanation {
        destination: destination.name.clone(),
        profile: (profile.name.clone(), destination.profile_digest.to_string()),
        obligations: format!(
            "claims {}, soak {}s{effective}, {} ring(s){effective}, reviews {} per report",
            claim_label(profile.claims),
            destination.soak_seconds,
            destination.rings.len(),
            facts.review_threshold
        ),
        change_scope: plan.change_scope.as_ref().map_or_else(
            || "not recorded".to_owned(),
            |scope| {
                format!(
                    "image {}, container {}, {} package cell(s) affected ({})",
                    affected(scope.image_affecting),
                    affected(scope.container_affecting),
                    scope.changed_package_cells.len(),
                    scope.reason
                )
            },
        ),
        override_in_force: overridden.map(|reference| reference.override_digest.to_string()),
        gates,
        reviews,
        fitness,
        surface_metadata,
        rings,
        completion: facts.requires_completion.then(|| {
            let mark = if facts.state == Some(ReleaseState::Complete)
                || facts.completion_approvals >= facts.completion_threshold
            {
                Mark::Satisfied
            } else {
                Mark::Missing
            };
            (mark, facts.completion_approvals, facts.completion_threshold)
        }),
        next,
    })
}

/// Renders the explanation lines.
pub(super) fn render(explanation: &Explanation) -> Vec<String> {
    let mut lines = vec![
        format!(
            "{}: profile {} ({})",
            explanation.destination, explanation.profile.0, explanation.profile.1
        ),
        explanation.obligations.clone(),
        format!("change scope: {}", explanation.change_scope),
        format!(
            "override: {}",
            explanation.override_in_force.as_deref().unwrap_or("none")
        ),
        "gates:".to_owned(),
    ];
    for (mark, phase, policy, blocking) in &explanation.gates {
        lines.push(format!(
            "  {} {phase} {policy} ({})",
            mark.glyph(),
            if *blocking { "blocking" } else { "advisory" }
        ));
    }
    lines.push("reviews:".to_owned());
    if explanation.reviews.is_empty() {
        lines.push("  none required".to_owned());
    }
    for (mark, phase, present, required) in &explanation.reviews {
        lines.push(format!(
            "  {} {phase}: {present} of {required}",
            mark.glyph()
        ));
    }
    lines.push("fitness:".to_owned());
    if explanation.fitness.is_empty() {
        lines.push("  none required".to_owned());
    }
    for (mark, detail) in &explanation.fitness {
        lines.push(format!("  {} {detail}", mark.glyph()));
    }
    lines.push("surface metadata:".to_owned());
    if explanation.surface_metadata.is_empty() {
        lines
            .push("  none: the surface's first destination for this release carries it".to_owned());
    }
    for (mark, detail) in &explanation.surface_metadata {
        lines.push(format!("  {} {detail}", mark.glyph()));
    }
    lines.push("rings:".to_owned());
    for (mark, detail) in &explanation.rings {
        lines.push(format!("  {} {detail}", mark.glyph()));
    }
    if let Some((mark, present, required)) = explanation.completion {
        lines.push("completion approvals:".to_owned());
        lines.push(format!("  {} {present} of {required}", mark.glyph()));
    }
    lines.push(explanation.next.clone());
    lines
}

/// Returns the surface-metadata obligations of a destination that publishes first.
fn surface_metadata_lines(metadata: &SurfaceMetadataFacts, now: SystemTime) -> Vec<(Mark, String)> {
    let done = |satisfied: bool| {
        if satisfied {
            Mark::Satisfied
        } else {
            Mark::Missing
        }
    };
    let mut lines = Vec::new();
    if let Some(key) = &metadata.missing_config {
        lines.push((Mark::Missing, format!("configuration: {key} is missing")));
    }
    if metadata.record_required {
        lines.push((done(metadata.record), "release record".to_owned()));
    }
    lines.push((done(metadata.tuf), "TUF metadata".to_owned()));
    lines.push(match metadata.timestamp_expires {
        None => (Mark::Missing, "timestamp".to_owned()),
        Some(_) if metadata.timestamp_published => (Mark::Satisfied, "timestamp".to_owned()),
        Some(expires) => {
            let renew = now
                .checked_add(TIMESTAMP_RENEWAL_MARGIN)
                .is_none_or(|limit| expires <= limit);
            (
                if renew {
                    Mark::Expired
                } else {
                    Mark::Satisfied
                },
                format!(
                    "timestamp: expires {}{}",
                    format_time(expires),
                    if renew { ", will be signed again" } else { "" }
                ),
            )
        }
    });
    lines.push((done(metadata.composed), "composed surface".to_owned()));
    lines.push((
        done(metadata.timestamp_published),
        "timestamp published".to_owned(),
    ));
    lines
}

/// Returns the fitness status of every kind against the destination's live identities.
fn fitness_statuses(
    session: &Session,
    destination: &PlannedDestination,
    now: SystemTime,
) -> Result<Vec<KindStatus>> {
    let plan = &session.plan;
    let profile = plan.qualification.profile(&destination.profile)?;
    if profile.fitness.is_empty() {
        return Ok(Vec::new());
    }
    let live = fitness::live_bindings(
        &session.config,
        destination.surface,
        signer_roster_digest(plan)?,
    )?;
    let attestations = fitness::load_attestations(
        &session.config.fitness_root,
        &fitness::planned_evidence_keys(plan)?,
        &fitness::trusted_keys(&session.config)?,
    )?;
    plan.qualification
        .fitness
        .iter()
        .filter(|kind| profile.fitness.contains_key(&kind.kind))
        .map(|kind| {
            fitness::kind_status(
                &plan.qualification,
                std::slice::from_ref(destination),
                kind,
                &attestations,
                &live,
                now,
            )
        })
        .collect()
}

/// Renders one fitness kind for one profile.
fn fitness_line(status: &KindStatus, profile: &str) -> (Mark, String) {
    let max = status
        .demands
        .iter()
        .find(|(name, _, _)| name == profile)
        .map_or(0, |(_, max, _)| *max);
    let Some((_, age)) = &status.newest else {
        return (
            Mark::Missing,
            format!("{}: no attestation, max {}", status.kind, format_age(max)),
        );
    };
    let mismatched: Vec<&str> = status
        .bindings
        .iter()
        .filter(|(_, matches)| !*matches)
        .map(|(binding, _)| binding.as_str())
        .collect();
    let bindings = if mismatched.is_empty() {
        "bindings match".to_owned()
    } else {
        format!("{} differ", mismatched.join(", "))
    };
    let mark = if fitness::is_fresh(*age, max) && mismatched.is_empty() {
        Mark::Satisfied
    } else {
        Mark::Expired
    };
    (
        mark,
        format!(
            "{}: {} old, max {}; {bindings}",
            status.kind,
            format_age(*age),
            format_age(max)
        ),
    )
}

/// Renders each planned ring's partitions, window, and progress.
fn ring_lines(
    destination: &PlannedDestination,
    facts: &DestinationFacts,
    now: SystemTime,
) -> Vec<(Mark, String)> {
    destination
        .rings
        .iter()
        .enumerate()
        .map(|(index, ring)| {
            let number = index + 1;
            let head = format!(
                "ring {number}: {} partitions, observe {}s",
                ring.partitions, ring.observe_seconds
            );
            let advanced = facts
                .advanced
                .iter()
                .find(|done| usize::from(done.ring) == number);
            match advanced {
                None => (Mark::Missing, format!("{head}: pending")),
                Some(done) => {
                    let ready = done
                        .committed_at
                        .checked_add(Duration::from_secs(ring.observe_seconds));
                    let observation = match ready {
                        Some(ready) if ready > now => {
                            format!("observed until {}", format_time(ready))
                        }
                        _ => "observation elapsed".to_owned(),
                    };
                    (
                        Mark::Satisfied,
                        format!(
                            "{head}: advanced {}, {observation}",
                            format_time(done.committed_at)
                        ),
                    )
                }
            }
        })
        .collect()
}

/// Maps a gate policy id to the hold point of its requirement or claim.
fn gate_phase(contract: &QualificationContract, policy_id: &str) -> Option<QualificationPhase> {
    contract
        .requirements
        .iter()
        .find(|requirement| {
            contract
                .requirement_gate(requirement)
                .is_ok_and(|gate| gate.policy_id == policy_id)
        })
        .map(|requirement| requirement.phase)
        .or_else(|| {
            contract
                .claims
                .iter()
                .find(|claim| {
                    contract
                        .claim_gate(claim)
                        .is_ok_and(|gate| gate.policy_id == policy_id)
                })
                .map(|claim| claim.phase)
        })
}

/// Returns whether the evidence for a hold point has been admitted.
fn phase_satisfied(
    phase: Option<QualificationPhase>,
    facts: &DestinationFacts,
    finalized: bool,
) -> bool {
    let complete = facts.state == Some(ReleaseState::Complete);
    match phase {
        Some(QualificationPhase::Build) => finalized,
        Some(QualificationPhase::Staging) => match facts.surface {
            SurfaceRole::Production => facts
                .phases
                .get(&Phase::Staging)
                .is_some_and(|phase| phase.signed),
            SurfaceRole::Staging => facts.state.is_some(),
        },
        Some(QualificationPhase::Rollout) => {
            complete || facts.advanced.len() == facts.ring_observations.len()
        }
        Some(QualificationPhase::Complete) => {
            complete
                || facts
                    .phases
                    .get(&Phase::Complete)
                    .is_some_and(|phase| phase.signed)
        }
        None => false,
    }
}

fn claim_label(claims: ClaimSelection) -> &'static str {
    match claims {
        ClaimSelection::None => "none",
        ClaimSelection::Functional => "functional",
        ClaimSelection::Qualified => "qualified",
    }
}

const fn affected(value: bool) -> &'static str {
    if value { "affected" } else { "unaffected" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explanation_renders_every_obligation_with_markers() {
        let explanation = Explanation {
            destination: "production/stable".to_owned(),
            profile: ("soak".to_owned(), "sha256:abc".to_owned()),
            obligations: "claims qualified, soak 86400s (override), 2 ring(s) (override), reviews 1 per report".to_owned(),
            change_scope: "image affected, container affected, 0 package cell(s) affected (no predecessor)".to_owned(),
            override_in_force: Some("sha256:override".to_owned()),
            gates: vec![
                (Mark::Satisfied, "build".to_owned(), "build-integrity".to_owned(), true),
                (Mark::Missing, "complete".to_owned(), "rollout-observation".to_owned(), true),
            ],
            reviews: vec![(Mark::Missing, "staging".to_owned(), 0, 1)],
            fitness: vec![
                (Mark::Satisfied, "storage-restore: 3d 0h old, max 14d 0h; bindings match".to_owned()),
                (Mark::Expired, "key-rotation: 120d 0h old, max 90d 0h; bindings match".to_owned()),
                (Mark::Missing, "hub-restore: no attestation, max 90d 0h".to_owned()),
            ],
            surface_metadata: surface_metadata_lines(
                &SurfaceMetadataFacts {
                    record_required: true,
                    record: true,
                    ..SurfaceMetadataFacts::default()
                },
                SystemTime::UNIX_EPOCH,
            ),
            rings: vec![(Mark::Missing, "ring 1: 128 partitions, observe 3600s: pending".to_owned())],
            completion: Some((Mark::Missing, 0, 2)),
            next: "Waiting: 1 reviewer signature(s) needed".to_owned(),
        };
        let lines = render(&explanation);
        assert_eq!(lines[0], "production/stable: profile soak (sha256:abc)");
        assert!(lines.contains(&"override: sha256:override".to_owned()));
        assert!(lines.contains(&"  [x] build build-integrity (blocking)".to_owned()));
        assert!(lines.contains(&"  [ ] complete rollout-observation (blocking)".to_owned()));
        assert!(lines.contains(&"  [ ] staging: 0 of 1".to_owned()));
        assert!(
            lines.contains(
                &"  [!] key-rotation: 120d 0h old, max 90d 0h; bindings match".to_owned()
            )
        );
        assert!(lines.contains(&"  [ ] 0 of 2".to_owned()));
        assert!(lines.contains(&"  [x] release record".to_owned()));
        assert!(lines.contains(&"  [ ] TUF metadata".to_owned()));
        assert!(lines.contains(&"  [ ] timestamp published".to_owned()));
        assert_eq!(
            lines.last().map(String::as_str),
            Some("Waiting: 1 reviewer signature(s) needed")
        );
    }

    #[test]
    fn staging_explanations_have_no_reviews_or_fitness() {
        let explanation = Explanation {
            destination: "staging/edge".to_owned(),
            profile: ("build".to_owned(), "sha256:def".to_owned()),
            obligations: "claims none, soak 0s, 1 ring(s), reviews 0 per report".to_owned(),
            change_scope: "not recorded".to_owned(),
            override_in_force: None,
            gates: Vec::new(),
            reviews: Vec::new(),
            fitness: Vec::new(),
            surface_metadata: Vec::new(),
            rings: vec![(
                Mark::Satisfied,
                "ring 1: 256 partitions, observe 0s: advanced".to_owned(),
            )],
            completion: None,
            next: "Done: staging/edge is complete".to_owned(),
        };
        let lines = render(&explanation);
        assert!(lines.contains(&"override: none".to_owned()));
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.as_str() == "  none required")
                .count(),
            2
        );
        assert!(!lines.iter().any(|line| line == "completion approvals:"));
    }

    #[test]
    fn surface_metadata_marks_missing_configuration_and_expiring_timestamps() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let lines = surface_metadata_lines(
            &SurfaceMetadataFacts {
                tuf: true,
                timestamp_expires: Some(now + Duration::from_secs(600)),
                missing_config: Some("[tuf] (root)".to_owned()),
                ..SurfaceMetadataFacts::default()
            },
            now,
        );
        assert_eq!(
            lines[0],
            (
                Mark::Missing,
                "configuration: [tuf] (root) is missing".to_owned()
            )
        );
        assert!(lines.iter().any(
            |(mark, detail)| *mark == Mark::Expired && detail.ends_with("will be signed again")
        ));
        assert!(!lines.iter().any(|(_, detail)| detail == "release record"));
    }
}
