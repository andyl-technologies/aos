//! Pure next-step computation for `advance`, `status`, and `explain`.
//!
//! The planner never reads the filesystem or the network. [`ReleaseFacts`]
//! and [`DestinationFacts`] describe what the journal and the work directory
//! already hold; [`next`] returns the single next thing that must happen for
//! one destination: a leaf step to run, a human step to wait for, or the
//! destination's end state.
//!
//! The order is the release checklist's:
//!
//! ```text
//! build -> finalize-image (each planned Linux cell)
//!       -> prepare-registry -> [transaction review] -> finalize-registry
//!       -> finalize-cache -> assemble -> finalize -> verify
//! per destination:
//!   [after] -> [production: staging qualification: collect, review, admit]
//!   -> [fitness]
//!   -> [first destination on its surface: [production: record] -> tuf
//!       -> timestamp refresh -> compose-surface]
//!   -> publish -> [first destination on its surface: timestamp publish]
//!   -> per ring: [observation of the previous ring]
//!                -> [rollout qualification when the profile has rollout cases]
//!                -> channel advance
//!   -> [qualified claims: soak -> complete qualification -> approvals
//!       -> channel complete]
//! ```
//!
//! Profiles without `qualified` claims complete automatically inside the
//! final ring's channel advance, so their destinations end after the last
//! ring.
//!
//! The first destination published on a surface carries the surface's TUF
//! metadata for the release (and, on the production surface, the public
//! release record). `step publish` uploads the immutable part of the composed
//! surface; `step timestamp publish` then moves the surface's timestamp
//! pointer to the new snapshot by compare-and-swap, so readers never follow a
//! timestamp to metadata that is not yet served. A refreshed timestamp that
//! is expired or about to expire before it is published is retired and
//! signed again. A later destination on the same surface reuses the
//! publication and carries no metadata of its own.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use anyhow::{Result, bail};
use aos_release::plan::SurfaceRole;
use aos_release::platform::Platform;
use aos_release::state::ReleaseState;

use super::workdir::{Phase, destination_slug};

/// Remaining validity below which an unpublished refreshed timestamp is re-signed.
///
/// Composition and publication verify the timestamp's freshness; a pointer
/// that expires mid-publication would fail closed after the upload.
pub(super) const TIMESTAMP_RENEWAL_MARGIN: Duration = Duration::from_secs(60 * 60);

/// A leaf operation the driver runs next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Step {
    /// `step build`.
    Build,
    /// `step finalize-image` for one planned Linux cell.
    FinalizeImage {
        /// Planned system variant.
        system_variant: String,
        /// Linux platform.
        platform: Platform,
    },
    /// `step prepare-registry`.
    PrepareRegistry,
    /// Record the operator's acceptance of the reviewed transaction.
    AcceptTransaction,
    /// `step finalize-registry`.
    FinalizeRegistry,
    /// `step finalize-cache`.
    FinalizeCache,
    /// `step assemble`.
    Assemble,
    /// `step finalize`.
    Finalize,
    /// `step verify`, recorded in `verification.json`.
    Verify,
    /// Move a rejected report or stale admission aside so it can be recollected.
    Retire(Phase),
    /// `step qualify-run --prepare-only`.
    Collect(Phase),
    /// `step qualify-run --report-input` with the collected reviews.
    Admit(Phase),
    /// `step record` for the first production destination on its surface.
    Record,
    /// `step tuf` at the destination surface's next metadata versions.
    Tuf,
    /// `step timestamp refresh` naming the new snapshot.
    RefreshTimestamp,
    /// Move an expiring unpublished timestamp and its composed surface aside.
    RetireTimestamp,
    /// `step compose-surface` and the immutable overlay `step publish` uploads.
    ComposeSurface,
    /// `step publish`.
    Publish,
    /// `step timestamp publish` after the destination's publication.
    PublishTimestamp,
    /// `step channel advance --ring`.
    AdvanceRing(u16),
    /// `step channel complete`.
    Complete,
}

impl Step {
    /// Returns the step's name as used in progress lines and error prefixes.
    pub(super) fn describe(&self, destination: &str) -> String {
        match self {
            Self::Build => "build".to_owned(),
            Self::FinalizeImage {
                system_variant,
                platform,
            } => format!("finalize-image {system_variant} {platform}"),
            Self::PrepareRegistry => "prepare-registry".to_owned(),
            Self::AcceptTransaction => "accept registry transaction".to_owned(),
            Self::FinalizeRegistry => "finalize-registry".to_owned(),
            Self::FinalizeCache => "finalize-cache".to_owned(),
            Self::Assemble => "assemble".to_owned(),
            Self::Finalize => "finalize".to_owned(),
            Self::Verify => "verify".to_owned(),
            Self::Retire(phase) => {
                format!("retire rejected or stale {phase} qualification of {destination}")
            }
            Self::Collect(phase) => format!("qualify-run {destination} {phase} (collect)"),
            Self::Admit(phase) => format!("qualify-run {destination} {phase} (sign)"),
            Self::Record => format!("record {destination}"),
            Self::Tuf => format!("tuf {destination}"),
            Self::RefreshTimestamp => format!("timestamp refresh {destination}"),
            Self::RetireTimestamp => format!("retire expiring timestamp of {destination}"),
            Self::ComposeSurface => format!("compose-surface {destination}"),
            Self::Publish => format!("publish {destination}"),
            Self::PublishTimestamp => format!("timestamp publish {destination}"),
            Self::AdvanceRing(ring) => format!("channel advance {destination} ring {ring}"),
            Self::Complete => format!("channel complete {destination}"),
        }
    }
}

/// The planner's decision for one destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Next {
    /// Run this leaf step.
    Run(Step),
    /// A person must act first; the text is the single `Waiting:` instruction.
    Wait(String),
    /// Nothing remains for this invocation; the text states why.
    Done(String),
}

/// State of an output directory a leaf creates atomically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Output {
    /// Nothing exists yet.
    Absent,
    /// The complete output exists.
    Complete,
    /// A path exists without the complete output (a retained failed attempt).
    Incomplete,
}

/// One planned Linux image cell and its finalization output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ImageFact {
    /// Planned system variant.
    pub(super) system_variant: String,
    /// Linux platform.
    pub(super) platform: Platform,
    /// Finalization output state.
    pub(super) output: Output,
}

/// Release-wide facts gathered from the journal and the work directory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ReleaseFacts {
    /// Global journal state; `None` before the build journal exists.
    pub(super) global: Option<ReleaseState>,
    /// Planned Linux image cells.
    pub(super) images: Vec<ImageFact>,
    /// Whether the release must carry the signed OCI bundle.
    pub(super) container_required: bool,
    /// Whether `inputs/container/` exists.
    pub(super) container_input: bool,
    /// Whether `inputs/source-registry/` exists.
    pub(super) source_registry_input: bool,
    /// Whether the transaction and prepared registry exist.
    pub(super) registry_prepared: bool,
    /// Whether any planned destination's profile requires transaction review.
    pub(super) transaction_review_required: bool,
    /// Whether the operator's acceptance is recorded.
    pub(super) transaction_accepted: bool,
    /// Whether `registry/result.json` exists.
    pub(super) registry_finalized: bool,
    /// Whether the signed cache exists.
    pub(super) cache: bool,
    /// Whether `inputs/advisory-disposition.json` exists.
    pub(super) advisory_input: bool,
    /// Whether the assembled payload exists.
    pub(super) assembled: bool,
    /// Whether `verification.json` exists.
    pub(super) verified: bool,
}

/// Facts about one qualification hold point of a destination.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PhaseFacts {
    /// Whether the destination's profile selects any case at this phase.
    pub(super) has_cases: bool,
    /// Whether the collected report exists.
    pub(super) prepared: bool,
    /// Distinct accepting reviews of the collected report.
    pub(super) accepted_reviews: u16,
    /// Whether any review rejected the collected report.
    pub(super) rejected: bool,
    /// Whether the signed decision exists.
    pub(super) signed: bool,
    /// Whether the signed decision binds a journal the release has moved past.
    pub(super) stale: bool,
}

/// Progress of the surface metadata a destination's publication carries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct SurfaceMetadataFacts {
    /// Whether the publication carries the public release record.
    pub(super) record_required: bool,
    /// Whether the release record exists.
    pub(super) record: bool,
    /// Whether the immutable TUF metadata set exists.
    pub(super) tuf: bool,
    /// Expiry of the refreshed timestamp, once one exists.
    pub(super) timestamp_expires: Option<SystemTime>,
    /// Whether the composed surface and its publication overlay exist.
    pub(super) composed: bool,
    /// Whether the timestamp publication evidence exists.
    pub(super) timestamp_published: bool,
    /// Maintainer configuration key the TUF steps need but lack, if any.
    pub(super) missing_config: Option<String>,
}

/// One advanced ring and when its channel receipt was committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AdvancedRing {
    /// One-based ring number.
    pub(super) ring: u16,
    /// Channel receipt commit time.
    pub(super) committed_at: SystemTime,
}

/// Destination facts gathered from the plan, journal, and work directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DestinationFacts {
    /// Destination name, such as `production/stable`.
    pub(super) name: String,
    /// Surface role of the destination.
    pub(super) surface: SurfaceRole,
    /// Journal state; `None` while unpublished.
    pub(super) state: Option<ReleaseState>,
    /// Why the destination may not be published yet (`after`), if blocked.
    pub(super) after_blocker: Option<String>,
    /// Why required fitness is not satisfied, if it is not.
    pub(super) fitness_blocker: Option<String>,
    /// Surface metadata this destination publishes; `None` when it reuses a
    /// publication another destination placed on the same surface.
    pub(super) surface_metadata: Option<SurfaceMetadataFacts>,
    /// Distinct reviews each report of this destination requires.
    pub(super) review_threshold: u16,
    /// Hold points and their evidence.
    pub(super) phases: BTreeMap<Phase, PhaseFacts>,
    /// Observation window of each planned ring, in ring order.
    pub(super) ring_observations: Vec<u64>,
    /// Rings already advanced.
    pub(super) advanced: Vec<AdvancedRing>,
    /// When the destination was published.
    pub(super) published_at: Option<SystemTime>,
    /// Soak in force for the destination.
    pub(super) soak_seconds: u64,
    /// Whether completion needs a complete-phase decision and approvals.
    pub(super) requires_completion: bool,
    /// Release-evidence approvals completion requires.
    pub(super) completion_threshold: u16,
    /// Distinct completion approvals present.
    pub(super) completion_approvals: u16,
}

/// Operator options of one `advance` invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Options {
    /// `--accept-transaction`.
    pub(super) accept_transaction: bool,
    /// `--ring N`: stop after ring N.
    pub(super) ring_limit: Option<u16>,
    /// Decision time.
    pub(super) now: SystemTime,
}

/// Computes the next step toward `destination`.
///
/// # Errors
/// Returns an error for a failed journal, a retained incomplete output that
/// must be inspected before retrying, or journal state that contradicts the
/// plan (such as a rolling destination whose final ring should have
/// completed it).
pub(super) fn next(
    release: &ReleaseFacts,
    destination: &DestinationFacts,
    options: &Options,
) -> Result<Next> {
    if let Some(next) = next_release_step(release, options)? {
        return Ok(next);
    }
    next_destination_step(destination, options)
}

/// Returns the next release-wide step, or `None` once the bundle is verified.
pub(super) fn next_release_step(release: &ReleaseFacts, options: &Options) -> Result<Option<Next>> {
    let Some(global) = release.global else {
        return Ok(Some(Next::Run(Step::Build)));
    };
    match global {
        ReleaseState::Failed => bail!("the release journal records a terminal failure"),
        ReleaseState::Planned => bail!("the build journal has not recorded a completed build"),
        ReleaseState::Built => built_step(release, options).map(Some),
        _ if !release.verified => Ok(Some(Next::Run(Step::Verify))),
        _ => Ok(None),
    }
}

/// Orders the signing and assembly steps between `built` and `finalized`.
fn built_step(release: &ReleaseFacts, options: &Options) -> Result<Next> {
    for image in &release.images {
        match image.output {
            Output::Complete => {}
            Output::Absent => {
                return Ok(Next::Run(Step::FinalizeImage {
                    system_variant: image.system_variant.clone(),
                    platform: image.platform,
                }));
            }
            Output::Incomplete => bail!(
                "images/{}/{} holds a failed finalization attempt without finalized/; \
                 retain it elsewhere, remove it from the work directory, and rerun",
                image.platform,
                image.system_variant
            ),
        }
    }
    if release.container_required && !release.container_input {
        return Ok(Next::Wait(
            "place the externally signed OCI release bundle (container-release.json, \
             signature-input.json, layout/) at inputs/container/, then rerun advance"
                .to_owned(),
        ));
    }
    if !release.registry_prepared {
        if !release.source_registry_input {
            return Ok(Next::Wait(
                "place a clean authoring registry clone at the planned base commit at \
                 inputs/source-registry/, then rerun advance"
                    .to_owned(),
            ));
        }
        return Ok(Next::Run(Step::PrepareRegistry));
    }
    if !release.registry_finalized {
        if release.transaction_review_required && !release.transaction_accepted {
            if options.accept_transaction {
                return Ok(Next::Run(Step::AcceptTransaction));
            }
            return Ok(Next::Wait(
                "review registry/transaction.json with registry/prepared/, then rerun \
                 advance with --accept-transaction"
                    .to_owned(),
            ));
        }
        return Ok(Next::Run(Step::FinalizeRegistry));
    }
    if !release.cache {
        return Ok(Next::Run(Step::FinalizeCache));
    }
    if !release.advisory_input {
        return Ok(Next::Wait(
            "write the reviewed advisory disposition for build/evidence/sbom.spdx.json to \
             inputs/advisory-disposition.json, then rerun advance"
                .to_owned(),
        ));
    }
    if !release.assembled {
        return Ok(Next::Run(Step::Assemble));
    }
    Ok(Next::Run(Step::Finalize))
}

/// Orders one destination's publication, rollout, and completion.
fn next_destination_step(destination: &DestinationFacts, options: &Options) -> Result<Next> {
    let name = destination.name.as_str();
    match destination.state {
        Some(ReleaseState::Complete) => Ok(Next::Done(format!("{name} is complete"))),
        None => Ok(publication_step(destination, options)),
        Some(ReleaseState::Published | ReleaseState::Rolling) => {
            if let Some(next) = surface_metadata_step(destination, options, true) {
                return Ok(next);
            }
            if let Some(next) = rollout_step(destination, options)? {
                return Ok(next);
            }
            completion_step(destination, options)
        }
        Some(state) => bail!("destination {name} is in unexpected state {state}"),
    }
}

/// Steps before a destination's publication.
fn publication_step(destination: &DestinationFacts, options: &Options) -> Next {
    if let Some(blocker) = &destination.after_blocker {
        return Next::Wait(blocker.clone());
    }
    if destination.surface == SurfaceRole::Production {
        // Publication always admits a signed staging decision, even when the
        // profile selects no staging case.
        let mut staging = phase_facts(destination, Phase::Staging);
        staging.has_cases = true;
        if let Some(next) = phase_step(destination, Phase::Staging, staging) {
            return next;
        }
    }
    if let Some(blocker) = &destination.fitness_blocker {
        return Next::Wait(fitness_instruction(blocker));
    }
    // Short-lived timestamps are signed only once nothing else can hold the
    // publication back.
    if let Some(next) = surface_metadata_step(destination, options, false) {
        return next;
    }
    Next::Run(Step::Publish)
}

/// The next surface-metadata step, or `None` when nothing is pending.
///
/// Before publication (`published == false`) this prepares the record, TUF
/// metadata, timestamp, and composed surface; afterwards it publishes the
/// timestamp, renewing and recomposing it first if it expired meanwhile.
fn surface_metadata_step(
    destination: &DestinationFacts,
    options: &Options,
    published: bool,
) -> Option<Next> {
    let metadata = destination.surface_metadata.as_ref()?;
    if metadata.timestamp_published {
        return None;
    }
    if let Some(key) = &metadata.missing_config {
        return Some(Next::Wait(format!(
            "configure {key} in the maintainer configuration; {} publishes its surface's \
             TUF metadata",
            destination.name
        )));
    }
    if !published && metadata.record_required && !metadata.record {
        return Some(Next::Run(Step::Record));
    }
    if !metadata.tuf {
        return Some(Next::Run(Step::Tuf));
    }
    match metadata.timestamp_expires {
        None => return Some(Next::Run(Step::RefreshTimestamp)),
        Some(expires)
            if options
                .now
                .checked_add(TIMESTAMP_RENEWAL_MARGIN)
                .is_none_or(|limit| expires <= limit) =>
        {
            return Some(Next::Run(Step::RetireTimestamp));
        }
        Some(_) => {}
    }
    if !metadata.composed {
        return Some(Next::Run(Step::ComposeSurface));
    }
    published.then_some(Next::Run(Step::PublishTimestamp))
}

/// The next ring step, or `None` when every ring has advanced.
fn rollout_step(destination: &DestinationFacts, options: &Options) -> Result<Option<Next>> {
    let name = destination.name.as_str();
    for (index, _) in destination.ring_observations.iter().enumerate() {
        let ring = u16::try_from(index + 1)?;
        if destination.advanced.iter().any(|done| done.ring == ring) {
            continue;
        }
        if let Some(limit) = options.ring_limit
            && ring > limit
        {
            return Ok(Some(Next::Done(format!(
                "stopped after ring {limit} of {name}"
            ))));
        }
        if let Some(ready) = observation_ready_at(destination, ring)?
            && ready > options.now
        {
            return Ok(Some(Next::Wait(format!(
                "ring {} of {name} observation until {}",
                ring - 1,
                format_time(ready)
            ))));
        }
        let phase = Phase::Rollout(ring);
        if let Some(next) = phase_step(destination, phase, phase_facts(destination, phase)) {
            return Ok(Some(next));
        }
        if let Some(blocker) = &destination.fitness_blocker {
            return Ok(Some(Next::Wait(fitness_instruction(blocker))));
        }
        return Ok(Some(Next::Run(Step::AdvanceRing(ring))));
    }
    Ok(None)
}

/// Steps after the final ring of a destination that is not yet complete.
fn completion_step(destination: &DestinationFacts, options: &Options) -> Result<Next> {
    let name = destination.name.as_str();
    if !destination.requires_completion {
        bail!("{name} advanced its final ring without completing; inspect its journal");
    }
    if let Some(published) = destination.published_at {
        let ready = published
            .checked_add(Duration::from_secs(destination.soak_seconds))
            .ok_or_else(|| anyhow::anyhow!("soak of {name} overflowed"))?;
        if ready > options.now {
            return Ok(Next::Wait(format!(
                "soak of {name} until {}",
                format_time(ready)
            )));
        }
    }
    let phase = Phase::Complete;
    if let Some(next) = phase_step(destination, phase, phase_facts(destination, phase)) {
        return Ok(next);
    }
    if destination.completion_approvals < destination.completion_threshold {
        let missing = destination.completion_threshold - destination.completion_approvals;
        return Ok(Next::Wait(format!(
            "{missing} completion approval(s) needed for {name}: each release-evidence \
             reviewer runs aos release review"
        )));
    }
    Ok(Next::Run(Step::Complete))
}

/// The next step of one hold point, or `None` when it is signed or has no cases.
fn phase_step(destination: &DestinationFacts, phase: Phase, facts: PhaseFacts) -> Option<Next> {
    if !facts.has_cases {
        return None;
    }
    if facts.stale || (facts.rejected && !facts.signed) {
        return Some(Next::Run(Step::Retire(phase)));
    }
    if facts.signed {
        return None;
    }
    if !facts.prepared {
        return Some(Next::Run(Step::Collect(phase)));
    }
    if facts.accepted_reviews < destination.review_threshold {
        let missing = destination.review_threshold - facts.accepted_reviews;
        return Some(Next::Wait(format!(
            "{missing} reviewer signature(s) needed over qualification/{}/{}/prepared/\
             qualification-report.json: run aos release review",
            destination_slug(&destination.name),
            phase.directory_name()
        )));
    }
    Some(Next::Run(Step::Admit(phase)))
}

/// Returns the recorded facts of a phase, or empty facts.
fn phase_facts(destination: &DestinationFacts, phase: Phase) -> PhaseFacts {
    destination.phases.get(&phase).copied().unwrap_or_default()
}

/// Returns when ring `ring` may start: the previous ring's commit plus its window.
fn observation_ready_at(destination: &DestinationFacts, ring: u16) -> Result<Option<SystemTime>> {
    let Some(previous) = ring.checked_sub(1).filter(|previous| *previous > 0) else {
        return Ok(None);
    };
    let Some(done) = destination
        .advanced
        .iter()
        .find(|done| done.ring == previous)
    else {
        bail!(
            "ring {ring} of {} precedes ring {previous}",
            destination.name
        );
    };
    let window = destination
        .ring_observations
        .get(usize::from(previous) - 1)
        .copied()
        .unwrap_or_default();
    done.committed_at
        .checked_add(Duration::from_secs(window))
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("observation window overflowed"))
}

/// Renders the fitness instruction for a fitness failure.
fn fitness_instruction(blocker: &str) -> String {
    format!("record fresh fitness with aos release fitness run <kind> ({blocker})")
}

/// Formats a time as RFC 3339 UTC with second precision.
pub(super) fn format_time(time: SystemTime) -> String {
    humantime::format_rfc3339_seconds(time).to_string()
}

#[cfg(test)]
#[path = "planner_tests.rs"]
mod tests;
