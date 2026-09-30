//! `aos release review`: sign the decision the release is waiting on.
//!
//! The pending decision is the first, in destination order (staging first)
//! and then hold-point order, of:
//!
//! - a collected qualification report that still needs reviews and that
//!   this reviewer has not reviewed: the command prints the plan and report
//!   digests and every case result, then writes
//!   `qualification/<slug>/<phase>/review-<key_id>.json` (an
//!   `aos.release.qualification-review/v1` envelope); `--reject --reason`
//!   signs `accepted: false` and stores the reason beside it as
//!   `review-<key_id>.reason.txt`;
//! - a completion decision of a `qualified` destination after its final
//!   ring (and complete-phase qualification): the command prints the rollout
//!   receipts and retention policy, then writes
//!   `channels/<slug>/completion-<key_id>.json`. Every approver signs the
//!   identical decision, so later approvers reuse the first approval's
//!   payload after checking it still describes the current rollout.
//!
//! Signatures come from the configured signer with the `[reviewer]` key.

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::QualificationReport;
use aos_release::plan::PlannedDestination;
use aos_release::qualification_admission::{QUALIFICATION_REVIEW, QualificationReview};
use aos_release::receipt::{COMPLETION_RECEIPT, CompletionReceipt};
use aos_release::signing::SignerRole;
use aos_release::state::ReleaseState;

use super::super::capture;
use super::evidence::{self, EvidenceScope};
use super::observe::{self, Observation};
use super::planner::DestinationFacts;
use super::workdir::{self, Phase};
use super::{Session, keys, status};
use crate::cli::ReleaseReviewArgs;

/// Public authority identity carried by completion decisions.
const COMPLETION_AUTHORITY: &str = "release-evidence";

/// The decision a reviewer can sign now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Pending {
    /// A collected report awaiting independent review.
    Report {
        /// Destination name.
        destination: String,
        /// Hold point.
        phase: Phase,
    },
    /// A completion decision awaiting approvals.
    Completion {
        /// Destination name.
        destination: String,
    },
}

/// Signs the pending decision with the configured reviewer key.
///
/// # Errors
/// Returns an error when nothing awaits this reviewer, the reviewer key is
/// not a configured release-evidence key, the signer fails, or the output
/// already exists.
pub(super) async fn run(args: &ReleaseReviewArgs, printer: &Printer) -> Result<()> {
    if args.reject
        && args
            .reason
            .as_deref()
            .is_none_or(|reason| reason.trim().is_empty())
    {
        bail!("--reject requires --reason TEXT");
    }
    let session = Session::open(args.config.as_deref(), args.work.as_deref())?;
    let observation = observe::release(&session)?;
    let key = evidence::reviewer_key(&session.config)?;
    let pending = find_pending(&session, &observation, &key.key_id)?
        .with_context(|| format!("nothing awaits review by {}", key.key_id))?;
    match pending {
        Pending::Report { destination, phase } => {
            review_report(&session, &destination, phase, args, printer).await
        }
        Pending::Completion { destination } => {
            if args.reject {
                bail!(
                    "completion decisions are approvals only; withhold approval and record the reason in the operator log"
                );
            }
            approve_completion(&session, &observation, &destination, printer).await
        }
    }
}

/// Finds the first decision `key_id` can sign.
fn find_pending(
    session: &Session,
    observation: &Observation,
    key_id: &str,
) -> Result<Option<Pending>> {
    let plan_digest = Sha256Digest::of_bytes(&session.plan_bytes);
    for destination in status::ordered(&session.plan.destinations) {
        let facts = observe::destination(session, observation, destination)?;
        for (phase, phase_facts) in &facts.phases {
            let collected = phase_facts.prepared && !phase_facts.signed && !phase_facts.rejected;
            if !collected || phase_facts.accepted_reviews >= facts.review_threshold {
                continue;
            }
            let tally = observe::tally_reviews(
                &session.work,
                plan_digest,
                &destination.name,
                *phase,
                &observation.evidence_keys,
            )?;
            if tally
                .accepted
                .iter()
                .all(|(reviewer, _)| reviewer != key_id)
            {
                return Ok(Some(Pending::Report {
                    destination: destination.name.clone(),
                    phase: *phase,
                }));
            }
        }
        if awaits_completion(&facts) && !approved_by(session, observation, destination, key_id)? {
            return Ok(Some(Pending::Completion {
                destination: destination.name.clone(),
            }));
        }
    }
    Ok(None)
}

/// Returns whether a destination's completion decision is collectable now.
pub(super) fn awaits_completion(facts: &DestinationFacts) -> bool {
    let rings_done = facts.advanced.len() == facts.ring_observations.len();
    let complete_phase_done = facts
        .phases
        .get(&Phase::Complete)
        .is_none_or(|phase| !phase.has_cases || (phase.signed && !phase.stale));
    facts.state == Some(ReleaseState::Rolling)
        && facts.requires_completion
        && rings_done
        && complete_phase_done
        && facts.completion_approvals < facts.completion_threshold
}

fn approved_by(
    session: &Session,
    observation: &Observation,
    destination: &PlannedDestination,
    key_id: &str,
) -> Result<bool> {
    let (_, journal) = observation.require_journal()?;
    let head = journal
        .entries
        .last()
        .context("release journal is empty")?
        .digest()?;
    Ok(observe::tally_completions(
        &session.work,
        &destination.name,
        head,
        &observation.evidence_keys,
    )?
    .iter()
    .any(|(reviewer, _, _)| reviewer == key_id))
}

/// Reviews one collected report.
async fn review_report(
    session: &Session,
    destination: &str,
    phase: Phase,
    args: &ReleaseReviewArgs,
    printer: &Printer,
) -> Result<()> {
    let config = &session.config;
    let key = evidence::reviewer_key(config)?;
    let directory = session.work.phase(destination, phase);
    let report_bytes = capture::control_file(
        &directory.join("prepared/qualification-report.json"),
        "prepared qualification report",
    )?;
    let report: QualificationReport = canonical::from_slice(&report_bytes, "qualification report")?;
    let plan_digest = Sha256Digest::of_bytes(&session.plan_bytes);
    let report_digest = Sha256Digest::of_bytes(&report_bytes);

    for line in report_summary(destination, phase, plan_digest, report_digest, &report) {
        printer.plain(&line);
    }

    let review = QualificationReview {
        schema_version: QUALIFICATION_REVIEW.to_owned(),
        plan_digest,
        report_digest,
        authority_id: key.key_id.clone(),
        accepted: !args.reject,
    };
    let provider_revision = keys::provider_revision(&session.plan, SignerRole::ReleaseEvidence)?;
    let signed = evidence::sign(
        config,
        &key,
        &EvidenceScope {
            registry: &session.plan.registry,
            release_id: &session.plan.release_id,
            plan_digest,
            manifest_digest: Some(report.manifest_digest),
            provider_revision: &provider_revision,
            approval_policy_digest: session.plan.restricted_operator_policy_digest,
            artifact_kind: "qualification-review",
        },
        &review,
    )
    .await?;
    let output = directory.join(format!("review-{}.json", key.key_id));
    if let Some(reason) = args.reason.as_deref().filter(|_| args.reject) {
        workdir::write_new_file(
            &directory.join(format!("review-{}.reason.txt", key.key_id)),
            format!("{}\n", reason.trim()).as_bytes(),
        )?;
    }
    workdir::write_new_file(&output, &signed)?;
    printer.success(&format!(
        "{} the {phase} report of {destination} as {}; wrote {}",
        if args.reject { "Rejected" } else { "Approved" },
        key.key_id,
        session.work.relative(&output)
    ));
    Ok(())
}

/// Renders the report facts a reviewer inspects before signing.
pub(super) fn report_summary(
    destination: &str,
    phase: Phase,
    plan_digest: Sha256Digest,
    report_digest: Sha256Digest,
    report: &QualificationReport,
) -> Vec<String> {
    let mut lines = vec![
        format!("Destination: {destination}"),
        format!("Phase: {phase}"),
        format!("Plan digest: {plan_digest}"),
        format!("Report digest: {report_digest}"),
        format!("Admitted at: {}", report.admitted_at),
        format!("Executor reports: {}", report.evidence.len()),
    ];
    if report.claims.is_empty() {
        lines.push("Cases: none selected at this hold point".to_owned());
    }
    for claim in &report.claims {
        lines.push(format!(
            "  {} {} required {:?} achieved {:?}: {:?}{}",
            claim.case_id,
            claim.claim_id,
            claim.required_assurance,
            claim.achieved_assurance,
            claim.disposition,
            if claim.blocks_release {
                " (blocking)"
            } else {
                ""
            }
        ));
    }
    lines
}

/// Signs the completion decision of a destination.
async fn approve_completion(
    session: &Session,
    observation: &Observation,
    destination: &str,
    printer: &Printer,
) -> Result<()> {
    let config = &session.config;
    let plan = &session.plan;
    let key = evidence::reviewer_key(config)?;
    let (_, journal) = observation.require_journal()?;
    let head = journal.entries.last().context("release journal is empty")?;
    let head_digest = head.digest()?;
    let manifest_digest = head
        .manifest_digest
        .context("the rolling journal binds no manifest")?;
    let publication = capture::control_file(
        &session.work.publication_receipt(destination),
        "publication receipt",
    )?;
    let mut rings: Vec<Sha256Digest> = observe::ring_receipts(&session.work, journal, destination)?
        .iter()
        .map(|(_, path, _)| {
            capture::control_file(path, "channel receipt").map(Sha256Digest::of_bytes)
        })
        .collect::<Result<_>>()?;
    rings.sort();
    rings.dedup();

    let expected = CompletionReceipt {
        schema_version: COMPLETION_RECEIPT.to_owned(),
        release_id: plan.release_id.clone(),
        plan_digest: Sha256Digest::of_bytes(&session.plan_bytes),
        manifest_digest,
        production_receipt_digest: Sha256Digest::of_bytes(&publication),
        channel_receipt_digests: rings,
        prior_journal_entry_digest: head_digest,
        retention_policy_id: plan.retention.policy_id.clone(),
        retention_policy_digest: plan.retention.policy_digest,
        corresponding_source_retained: true,
        operational_handoff_complete: true,
        authority_id: COMPLETION_AUTHORITY.to_owned(),
        completed_at: super::steps::now(),
    };
    // Approvers must sign identical bytes: reuse an existing decision when it
    // describes exactly this rollout.
    let existing = observe::tally_completions(
        &session.work,
        destination,
        head_digest,
        &observation.evidence_keys,
    )?;
    let decision = match existing.first() {
        Some((_, _, decision)) => {
            let mut comparable = decision.clone();
            comparable.completed_at.clone_from(&expected.completed_at);
            comparable.authority_id.clone_from(&expected.authority_id);
            if comparable != expected {
                bail!(
                    "existing completion approvals describe a different rollout; inspect channels/"
                );
            }
            decision.clone()
        }
        None => expected,
    };
    decision.validate()?;

    printer.plain(&format!("Destination: {destination}"));
    printer.plain(&format!(
        "Publication receipt: {}",
        decision.production_receipt_digest
    ));
    for digest in &decision.channel_receipt_digests {
        printer.plain(&format!("Channel receipt: {digest}"));
    }
    printer.plain(&format!(
        "Retention policy: {} {}",
        decision.retention_policy_id, decision.retention_policy_digest
    ));
    printer.plain("Approving affirms corresponding-source retention and operational handoff.");

    let provider_revision = keys::provider_revision(plan, SignerRole::ReleaseEvidence)?;
    let signed = evidence::sign(
        config,
        &key,
        &EvidenceScope {
            registry: &plan.registry,
            release_id: &plan.release_id,
            plan_digest: decision.plan_digest,
            manifest_digest: Some(decision.manifest_digest),
            provider_revision: &provider_revision,
            approval_policy_digest: plan.restricted_operator_policy_digest,
            artifact_kind: "completion-receipt",
        },
        &decision,
    )
    .await?;
    let output = session.work.completion_approval(destination, &key.key_id);
    workdir::write_new_file(&output, &signed)?;
    printer.success(&format!(
        "Approved completion of {destination} as {}; wrote {}",
        key.key_id,
        session.work.relative(&output)
    ));
    Ok(())
}
