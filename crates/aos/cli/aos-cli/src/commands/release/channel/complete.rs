//! `step channel complete`: close a `qualified` destination's rollout.
//!
//! The command performs no surface mutation. It verifies one channel receipt
//! per planned ring (all already in the rolling journal, generations
//! contiguous), the complete-phase qualification, and identical completion
//! decisions from exactly the release-evidence threshold, then rechecks the
//! anonymous publication receipt and every public partition.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::Printer;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::plan::ReleasePlan;
use aos_release_format::qualification::QualificationPhase;
use aos_release_format::receipt::{CompletionReceipt, verify_signed_receipt_with_key};
use aos_release_format::signing::SignerRole;
use aos_release_format::state::ReleaseState;

use super::super::access::{self, SignerNeed};
use super::super::journal::{self, Journal, Transition};
use super::super::qualification_transition::{AdmissionCheck, verify_admission};
use super::super::surface::{
    ChannelExpectation, SignedReceipt, key_map, verify_channel_receipt, verify_publication_receipt,
};
use super::super::verify::verified_bundle;
use super::{release_tag_object, requires_completion_approval, ring_count, validate_rollout};
use crate::cli::ReleaseChannelCompleteArgs;

/// Verifies completion evidence and appends the destination's `complete` entry.
pub(super) async fn run(args: &ReleaseChannelCompleteArgs, printer: &Printer) -> Result<()> {
    let bundle = verified_bundle(&args.bundle, &args.trusted_keys)?;
    let plan = &bundle.plan;
    let destination = plan.destination(&args.to)?;
    let manifest_digest = bundle.summary.manifest_digest;
    if !requires_completion_approval(plan, destination)? {
        bail!(
            "{} completes automatically after its final ring; no completion step applies",
            destination.name
        );
    }

    let journal = Journal::read(&args.journal, "release rollout journal")?;
    journal.require_release(plan, manifest_digest)?;
    if journal.summary.state_of(&destination.name) != Some(ReleaseState::Rolling) {
        bail!(
            "channel completion requires {} to be rolling",
            destination.name
        );
    }

    let publication = SignedReceipt::read(&args.publication_receipt, "publication receipt")?;
    let publication_view = verify_publication_receipt(
        plan,
        destination,
        &publication,
        &key_map(&args.receipt_keys)?,
    )?;
    if publication_view.bundle_digest != bundle.bundle_digest
        || !journal.contains_evidence(publication.digest)
    {
        bail!("publication receipt does not bind this release journal");
    }

    let channel_keys = key_map(if args.channel_receipt_keys.is_empty() {
        &args.receipt_keys
    } else {
        &args.channel_receipt_keys
    })?;
    let mut rings = Vec::with_capacity(args.channel_receipts.len());
    for path in &args.channel_receipts {
        let signed = SignedReceipt::read(path, "channel receipt")?;
        let view = verify_channel_receipt(plan, destination, None, &signed, &channel_keys)?;
        if view.manifest_digest != manifest_digest
            || view.publication_receipt_digest != publication.digest
            || !journal.contains_evidence(signed.digest)
        {
            bail!(
                "channel receipt {} is not bound into this rollout",
                path.display()
            );
        }
        rings.push((signed.digest, view));
    }
    let views: Vec<_> = rings.iter().map(|(_, view)| view.clone()).collect();
    validate_rollout(destination, &views, ring_count(destination)?)?;

    let qualification = verify_admission(AdmissionCheck {
        plan,
        manifest: &bundle.manifest.payload,
        destination,
        directory: args.qualification.as_deref(),
        key_specs: &args.qualification_keys,
        review_keys: &bundle.manifest_keys,
        phase: QualificationPhase::Complete,
        rollout: None,
        journal: &journal.bytes,
        publication_digest: publication.digest,
        manifest_digest,
    })?;

    let channel_digests: Vec<Sha256Digest> = rings
        .iter()
        .map(|(digest, _)| *digest)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let prior_entry = journal
        .entries
        .last()
        .context("release journal is empty")?
        .digest()?;
    let (completion, envelopes) = verify_completion(
        args,
        plan,
        manifest_digest,
        publication.digest,
        &channel_digests,
        prior_entry,
    )?;

    let client = access::connect(plan, destination.surface, None, None, SignerNeed::None).await?;
    client.verify_identity().await?;
    if client.published_receipt(bundle.bundle_digest).await? != publication {
        bail!("public publication receipt differs from the completion authority");
    }
    let tag_object = release_tag_object(&bundle, &args.bundle, client.surface().kind)?;
    for view in &views {
        client
            .read_back_channel(&ChannelExpectation {
                channel: &destination.channel,
                first_partition: view.first_partition,
                last_partition: view.last_partition,
                release_id: &plan.release_id,
                release_tag_object: tag_object.as_deref(),
            })
            .await?;
    }
    client.verify_identity().await?;

    let mut evidence: Vec<Sha256Digest> = envelopes.iter().map(Sha256Digest::of_bytes).collect();
    evidence.extend(qualification);
    let successor = journal::append(
        &journal.entries,
        Transition {
            new_state: ReleaseState::Complete,
            destination: Some(&destination.name),
            operation_ids: vec![format!("complete-{}", completion.authority_id)],
            evidence,
            recorded_at: completion.completed_at.clone(),
        },
    )?;

    let mut files: Vec<(String, &[u8])> = vec![
        ("publication-receipt.json".into(), &publication.bytes),
        ("release-journal.jsonl".into(), &successor),
    ];
    for (index, bytes) in envelopes.iter().enumerate() {
        files.push((format!("completion-receipts/{:04}.json", index + 1), bytes));
    }
    let ring_bytes = args
        .channel_receipts
        .iter()
        .map(|path| SignedReceipt::read(path, "channel receipt"))
        .collect::<Result<Vec<_>>>()?;
    for receipt in &ring_bytes {
        files.push((
            format!("channel-receipts/{}.json", receipt.digest.hex()),
            &receipt.bytes,
        ));
    }
    let named: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, bytes)| (name.as_str(), *bytes))
        .collect();
    journal::persist_tree(&args.output, &named, "completion")?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.channel-complete-result/v1",
        "destination": destination.name,
        "release_id": plan.release_id,
        "rings": views.len(),
        "completion_signatures": envelopes.len(),
        "completed_at": completion.completed_at,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Completed {} for {} after verifying {} rings",
        destination.name,
        plan.release_id,
        views.len()
    ));
    Ok(())
}

/// Verifies identical completion decisions from exactly the evidence threshold.
fn verify_completion(
    args: &ReleaseChannelCompleteArgs,
    plan: &ReleasePlan,
    manifest_digest: Sha256Digest,
    publication_digest: Sha256Digest,
    channel_digests: &[Sha256Digest],
    prior_entry: Sha256Digest,
) -> Result<(CompletionReceipt, Vec<Vec<u8>>)> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .context("release plan lacks the release-evidence signer policy")?;
    let keys = key_map(&args.completion_keys)?;
    if keys.len() != usize::from(requirement.threshold)
        || keys.keys().any(|key| !requirement.key_ids.contains(key))
    {
        bail!(
            "completion trust inputs must exactly satisfy the planned release-evidence threshold"
        );
    }
    let mut decision: Option<CompletionReceipt> = None;
    let mut signers = BTreeSet::new();
    let mut envelopes = Vec::with_capacity(args.completion_receipts.len());
    for path in &args.completion_receipts {
        let bytes = super::super::capture::control_file(path, "signed completion receipt")?;
        let (key_id, receipt): (String, CompletionReceipt) =
            verify_signed_receipt_with_key(&bytes, &keys)?;
        receipt.validate()?;
        if !signers.insert(key_id) {
            bail!("completion evidence repeats a signing key");
        }
        if decision.as_ref().is_some_and(|prior| prior != &receipt) {
            bail!("completion authorities signed different decisions");
        }
        decision = Some(receipt);
        envelopes.push(bytes);
    }
    if signers.len() != usize::from(requirement.threshold) {
        bail!("completion evidence does not satisfy the planned threshold");
    }
    let decision = decision.context("completion evidence is empty")?;
    let plan_digest = Sha256Digest::of_bytes(aos_release_format::canonical::to_vec(plan)?);
    if decision.release_id != plan.release_id
        || decision.plan_digest != plan_digest
        || decision.manifest_digest != manifest_digest
        || decision.production_receipt_digest != publication_digest
        || decision.channel_receipt_digests != channel_digests
        || decision.prior_journal_entry_digest != prior_entry
        || decision.retention_policy_id != plan.retention.policy_id
        || decision.retention_policy_digest != plan.retention.policy_digest
    {
        bail!("completion decision differs from the frozen release and rollout");
    }
    Ok((decision, envelopes))
}
