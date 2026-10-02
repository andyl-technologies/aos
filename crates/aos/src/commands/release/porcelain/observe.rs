//! Planner facts gathered from the journal and the work directory.
//!
//! Observation is read-only and offline. Signed files the driver will later
//! hand to a leaf command (reviews, completion approvals, channel receipts)
//! are verified here against the configured keys, so the planner counts only
//! evidence the leaf would accept; the leaf verifies everything again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::plan::{PlannedDestination, SurfaceRole};
use aos_release::platform::MatrixCell;
use aos_release::qualification::{ClaimSelection, TargetKind};
use aos_release::qualification_admission::{
    QUALIFICATION_REVIEW, QualificationAdmission, QualificationReview,
};
use aos_release::receipt::{ChannelReceipt, CompletionReceipt, verify_signed_receipt_with_key};
use aos_release::registry::registry_policy;
use aos_release::signing::SignerRole;
use aos_release::state::ReleaseState;

use super::super::capture;
use super::super::journal::Journal;
use super::super::surface::{key_map, receipt_payload};
use super::Session;
use super::keys;
use super::planner::{AdvancedRing, DestinationFacts, ImageFact, Output, PhaseFacts, ReleaseFacts};
use super::workdir::{Phase, WorkDir};

/// Release-wide observations shared by every destination.
pub(super) struct Observation {
    /// Newest verified journal and its work path.
    pub(super) journal: Option<(PathBuf, Journal)>,
    /// Signed manifest envelope, once the bundle is finalized.
    pub(super) manifest: Option<ManifestEnvelopeV1>,
    /// Planner facts.
    pub(super) release: ReleaseFacts,
    /// Release-evidence keys trusted for reviews and approvals.
    pub(super) evidence_keys: BTreeMap<String, [u8; 32]>,
}

impl Observation {
    /// Returns the replayed state of a destination.
    pub(super) fn state_of(&self, destination: &str) -> Option<ReleaseState> {
        self.journal
            .as_ref()
            .and_then(|(_, journal)| journal.summary.state_of(destination))
    }

    /// Returns the newest journal, which every post-build step requires.
    ///
    /// # Errors
    /// Returns an error before the build journal exists.
    pub(super) fn require_journal(&self) -> Result<&(PathBuf, Journal)> {
        self.journal
            .as_ref()
            .context("the release has no journal yet; run aos maintain release advance")
    }
}

/// Observes the release-wide facts of a session.
///
/// # Errors
/// Returns an error for an invalid or diverging journal, an inconsistent
/// output, or unreadable configured keys.
pub(super) fn release(session: &Session) -> Result<Observation> {
    let work = &session.work;
    let plan = &session.plan;
    let journal = work.latest_journal(plan)?;
    let manifest = session.manifest()?;

    let mut images = Vec::new();
    for image in &plan.images {
        for cell in &image.platforms {
            if !matches!(cell.decision, MatrixCell::Artifact { .. }) {
                continue;
            }
            let path = work.image_work(cell.platform, &image.system_variant);
            let output = if path.join("finalized/finalized-image-set.json").is_file() {
                Output::Complete
            } else if path.exists() {
                Output::Incomplete
            } else {
                Output::Absent
            };
            images.push(ImageFact {
                system_variant: image.system_variant.clone(),
                platform: cell.platform,
                output,
            });
        }
    }

    let registry_prepared = work.transaction().is_file();
    if !registry_prepared && work.registry().exists() {
        bail!(
            "registry/prepared exists without registry/transaction.json; retain it elsewhere, \
             remove it from the work directory, and rerun"
        );
    }
    let contract = &plan.qualification;
    let release = ReleaseFacts {
        global: journal.as_ref().map(|(_, journal)| journal.summary.global),
        images,
        container_required: !plan.images.is_empty()
            && contract
                .targets
                .iter()
                .any(|target| target.kind == TargetKind::Container && target.required),
        container_input: work.container().is_dir(),
        source_registry_input: work.source_registry().is_dir(),
        registry_prepared,
        transaction_review_required: plan.destinations.iter().any(|destination| {
            contract
                .profile(&destination.profile)
                .is_ok_and(|profile| profile.review_registry_transaction)
        }),
        transaction_accepted: work.transaction_acceptance().is_file(),
        registry_finalized: work.registry_result().is_file(),
        cache: work.cache().is_dir(),
        advisory_input: work.advisory_disposition().is_file(),
        assembled: work
            .assembled()
            .join("release-manifest-payload.json")
            .is_file(),
        verified: work.verification().is_file(),
    };

    let mut specs = keys::trusted(&session.config)?;
    if let Ok(evidence) = keys::role_specs(&session.config, SignerRole::ReleaseEvidence) {
        specs.extend(evidence);
    }
    specs.sort();
    specs.dedup();
    Ok(Observation {
        journal,
        manifest,
        release,
        evidence_keys: key_map(&specs)?,
    })
}

/// Observes one destination's facts.
///
/// # Errors
/// Returns an error for an unknown profile, a journal that records a ring
/// whose receipt is missing, or unreadable evidence.
pub(super) fn destination(
    session: &Session,
    observation: &Observation,
    destination: &PlannedDestination,
) -> Result<DestinationFacts> {
    let plan = &session.plan;
    let work = &session.work;
    let name = destination.name.as_str();
    let profile = plan.qualification.profile(&destination.profile)?;
    let state = observation.state_of(name);
    let requires_completion = profile.claims == ClaimSelection::Qualified;

    let mut phases = BTreeMap::new();
    let mut hold_points = Vec::new();
    if destination.surface == SurfaceRole::Production {
        hold_points.push(Phase::Staging);
    }
    for ring in 1..=destination.rings.len() {
        hold_points.push(Phase::Rollout(u16::try_from(ring)?));
    }
    if requires_completion {
        hold_points.push(Phase::Complete);
    }
    let (advanced, published_at) = match &observation.journal {
        Some((_, journal)) => (
            advanced_rings(work, journal, name)?,
            published_at(journal, name)?,
        ),
        None => (Vec::new(), None),
    };
    let journal_digest = observation
        .journal
        .as_ref()
        .map(|(_, journal)| Sha256Digest::of_bytes(&journal.bytes));
    let plan_digest = Sha256Digest::of_bytes(&session.plan_bytes);
    for phase in hold_points {
        let has_cases = match &observation.manifest {
            Some(manifest) => !aos_release::qualification_evidence::cases(
                plan,
                &manifest.payload,
                Some(name),
                phase.qualification_phase(),
            )?
            .is_empty(),
            None => false,
        };
        let tally = tally_reviews(work, plan_digest, name, phase, &observation.evidence_keys)?;
        let signed_directory = work.phase(name, phase).join("signed");
        let signed = signed_directory.join("signed-qualification.json").is_file();
        // A rollout or completion admission binds the exact journal it was
        // signed over; once another step appends, it can no longer be used.
        let pending = match phase {
            Phase::Staging => false,
            Phase::Rollout(ring) => !advanced.iter().any(|done| done.ring == ring),
            Phase::Complete => state != Some(ReleaseState::Complete),
        };
        let stale = signed && pending && admission_journal(&signed_directory)? != journal_digest;
        phases.insert(
            phase,
            PhaseFacts {
                has_cases,
                prepared: tally.report_digest.is_some(),
                accepted_reviews: u16::try_from(tally.accepted.len())?,
                rejected: !tally.rejected.is_empty(),
                signed,
                stale,
            },
        );
    }

    let needs_gate = matches!(
        state,
        None | Some(ReleaseState::Published | ReleaseState::Rolling)
    );
    let completion_approvals = match (&observation.journal, state) {
        (Some((_, journal)), Some(ReleaseState::Rolling)) => {
            let head = journal
                .entries
                .last()
                .context("release journal is empty")?
                .digest()?;
            u16::try_from(tally_completions(work, name, head, &observation.evidence_keys)?.len())?
        }
        _ => 0,
    };

    Ok(DestinationFacts {
        name: name.to_owned(),
        surface: destination.surface,
        state,
        after_blocker: match state {
            None => after_blocker(session, observation, destination)?,
            Some(_) => None,
        },
        fitness_blocker: if needs_gate {
            fitness_blocker(session, destination)
        } else {
            None
        },
        surface_metadata: super::surface_metadata::facts(session, observation, destination)?,
        review_threshold: profile.review_threshold,
        phases,
        ring_observations: destination
            .rings
            .iter()
            .map(|ring| ring.observe_seconds)
            .collect(),
        advanced,
        published_at,
        soak_seconds: destination.soak_seconds,
        requires_completion,
        completion_threshold: evidence_threshold(session),
        completion_approvals,
    })
}

/// Reviews of one collected report.
#[derive(Debug, Default)]
pub(super) struct ReviewTally {
    /// Digest of the collected report, once one exists.
    pub(super) report_digest: Option<Sha256Digest>,
    /// Accepting reviewer key ids and their review files.
    pub(super) accepted: Vec<(String, PathBuf)>,
    /// Rejecting reviewer key ids.
    pub(super) rejected: Vec<String>,
}

/// Verifies and counts the reviews beside one collected report.
///
/// Only reviews signed by a trusted release-evidence key over this exact
/// plan and report count; other files are ignored here and would fail the
/// leaf's own verification.
///
/// # Errors
/// Returns an error for an unreadable report or review directory.
pub(super) fn tally_reviews(
    work: &WorkDir,
    plan_digest: Sha256Digest,
    destination: &str,
    phase: Phase,
    keys: &BTreeMap<String, [u8; 32]>,
) -> Result<ReviewTally> {
    let directory = work.phase(destination, phase);
    let report = directory.join("prepared/qualification-report.json");
    if !report.is_file() {
        return Ok(ReviewTally::default());
    }
    let report_digest = Sha256Digest::of_bytes(capture::control_file(
        &report,
        "prepared qualification report",
    )?);
    let mut tally = ReviewTally {
        report_digest: Some(report_digest),
        ..ReviewTally::default()
    };
    let mut seen = BTreeSet::new();
    for path in files_matching(&directory, "review-", ".json")? {
        let bytes = capture::control_file(&path, "qualification review")?;
        let Ok((key_id, review)) =
            verify_signed_receipt_with_key::<QualificationReview>(&bytes, keys)
        else {
            continue;
        };
        if review.schema_version != QUALIFICATION_REVIEW
            || review.authority_id != key_id
            || review.plan_digest != plan_digest
            || review.report_digest != report_digest
            || !seen.insert(key_id.clone())
        {
            continue;
        }
        if review.accepted {
            tally.accepted.push((key_id, path));
        } else {
            tally.rejected.push(key_id);
        }
    }
    Ok(tally)
}

/// Verifies the completion approvals of a destination for the current head.
///
/// # Errors
/// Returns an error for an unreadable approval directory.
pub(super) fn tally_completions(
    work: &WorkDir,
    destination: &str,
    head: Sha256Digest,
    keys: &BTreeMap<String, [u8; 32]>,
) -> Result<Vec<(String, PathBuf, CompletionReceipt)>> {
    let directory = work.channels(destination);
    let mut approvals = Vec::new();
    let mut seen = BTreeSet::new();
    for path in files_matching(&directory, "completion-", ".json")? {
        let bytes = capture::control_file(&path, "completion approval")?;
        let Ok((key_id, receipt)) =
            verify_signed_receipt_with_key::<CompletionReceipt>(&bytes, keys)
        else {
            continue;
        };
        if receipt.prior_journal_entry_digest == head && seen.insert(key_id.clone()) {
            approvals.push((key_id, path, receipt));
        }
    }
    Ok(approvals)
}

/// Returns the channel receipt of every advanced ring, in ring order.
///
/// # Errors
/// Returns an error when the journal records a ring whose receipt is absent
/// or unreadable.
pub(super) fn ring_receipts(
    work: &WorkDir,
    journal: &Journal,
    destination: &str,
) -> Result<Vec<(u16, PathBuf, ChannelReceipt)>> {
    let count = journal
        .entries
        .iter()
        .filter(|entry| {
            entry.new_state == ReleaseState::Rolling
                && entry.destination.as_deref() == Some(destination)
        })
        .count();
    (1..=count)
        .map(|ring| {
            let ring = u16::try_from(ring)?;
            let path = work.ring_receipt(destination, ring);
            let bytes = capture::control_file(&path, "channel receipt").with_context(|| {
                format!(
                    "the journal records ring {ring} of {destination} but its receipt is missing"
                )
            })?;
            let receipt: ChannelReceipt = receipt_payload(&bytes)?;
            if receipt.ring != ring {
                bail!("{} names ring {}", work.relative(&path), receipt.ring);
            }
            Ok((ring, path, receipt))
        })
        .collect()
}

/// Returns the journal digest a signed rollout or completion admission binds.
///
/// # Errors
/// Returns an error for an unreadable or malformed admission payload.
pub(super) fn admission_journal(signed: &Path) -> Result<Option<Sha256Digest>> {
    Ok(read_admission(signed)?.map(|admission| admission.journal_digest))
}

/// Reads the admission payload a signed rollout or completion decision carries.
///
/// # Errors
/// Returns an error for an unreadable or malformed payload.
pub(super) fn read_admission(signed: &Path) -> Result<Option<QualificationAdmission>> {
    let path = signed.join("qualification-receipt.json");
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = capture::control_file(&path, "qualification admission")?;
    Ok(Some(aos_release::canonical::from_slice(
        &bytes,
        "qualification admission",
    )?))
}

fn advanced_rings(
    work: &WorkDir,
    journal: &Journal,
    destination: &str,
) -> Result<Vec<AdvancedRing>> {
    ring_receipts(work, journal, destination)?
        .into_iter()
        .map(|(ring, _, receipt)| {
            Ok(AdvancedRing {
                ring,
                committed_at: parse_time(&receipt.committed_at)?,
            })
        })
        .collect()
}

fn published_at(journal: &Journal, destination: &str) -> Result<Option<SystemTime>> {
    journal
        .entries
        .iter()
        .find(|entry| {
            entry.new_state == ReleaseState::Published
                && entry.destination.as_deref() == Some(destination)
        })
        .map(|entry| parse_time(&entry.recorded_at))
        .transpose()
}

/// Returns the `after` instruction for an unpublished destination, if blocked.
fn after_blocker(
    session: &Session,
    observation: &Observation,
    destination: &PlannedDestination,
) -> Result<Option<String>> {
    let plan = &session.plan;
    let tier = registry_policy(&plan.registry)?.tier();
    let cell =
        plan.qualification
            .destination(tier, destination.surface, destination.channel_kind()?)?;
    let summary = observation
        .journal
        .as_ref()
        .map(|(_, journal)| &journal.summary);
    for role in &cell.after {
        if summary.is_some_and(|summary| summary.surface_holds_publication(*role)) {
            continue;
        }
        // Prefer the same channel on the prerequisite surface.
        let suggestion = plan
            .destinations
            .iter()
            .filter(|candidate| candidate.surface == *role)
            .min_by_key(|candidate| candidate.channel != destination.channel)
            .map_or_else(
                || format!("a {role} destination"),
                |candidate| format!("aos maintain release advance --to {}", candidate.name),
            );
        return Ok(Some(format!(
            "{} follows a {role} publication; publish it first with {suggestion}",
            destination.name
        )));
    }
    Ok(None)
}

/// Returns why the destination's demanded fitness is unmet, if it is.
fn fitness_blocker(session: &Session, destination: &PlannedDestination) -> Option<String> {
    let check = || -> Result<()> {
        let keys = super::super::verify::load_trusted_keys(&keys::trusted(&session.config)?)?;
        super::super::fitness_gate::require_fitness(
            &session.plan,
            destination,
            &crate::cli::ReleaseFitnessInputArgs::default(),
            Some(&session.config_path),
            &keys,
        )
    };
    check().err().map(|error| format!("{error:#}"))
}

/// Returns the planned release-evidence threshold.
fn evidence_threshold(session: &Session) -> u16 {
    session
        .plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .map_or(1, |requirement| requirement.threshold)
}

/// Lists `<directory>/<prefix>*<suffix>` regular files in name order.
///
/// # Errors
/// Returns an error for an unreadable directory other than a missing one.
pub(super) fn files_matching(directory: &Path, prefix: &str, suffix: &str) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", directory.display()));
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(suffix) && entry.file_type()?.is_file() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Parses an RFC 3339 time.
///
/// # Errors
/// Returns an error for a malformed time.
pub(super) fn parse_time(value: &str) -> Result<SystemTime> {
    humantime::parse_rfc3339(value).with_context(|| format!("parsing time {value}"))
}
