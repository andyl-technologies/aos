//! `step channel advance`: one compare-and-swap rollout ring.

use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::Printer;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::plan::PlannedDestination;
use aos_release_format::qualification::QualificationPhase;
use aos_release_format::qualification_admission::QualificationRolloutIntent;
use aos_release_format::receipt::ChannelReceipt;
use aos_release_format::state::ReleaseState;

use super::super::access::{self, SignerNeed};
use super::super::journal::{self, Journal, Transition};
use super::super::qualification_transition::{AdmissionCheck, verify_admission};
use super::super::surface::{
    ChannelAdvance, ChannelExpectation, SignedReceipt, key_map, verify_channel_receipt,
    verify_publication_receipt,
};
use super::super::verify::verified_bundle;
use super::{release_tag_object, requires_completion_approval, ring_count};
use crate::cli::ReleaseChannelAdvanceArgs;

/// Advances one planned ring and appends its journal entries.
pub(super) async fn run(args: &ReleaseChannelAdvanceArgs, printer: &Printer) -> Result<()> {
    let bundle = verified_bundle(&args.bundle, &args.trusted_keys)?;
    let plan = &bundle.plan;
    let destination = plan.destination(&args.to)?;
    let manifest_digest = bundle.summary.manifest_digest;
    let (first_partition, last_partition) = destination.ring_range(args.ring)?;

    let journal = Journal::read(&args.journal, "release rollout journal")?;
    journal.require_release(plan, manifest_digest)?;
    journal.summary.require_rolling_allowed(&destination.name)?;
    require_next_ring(&journal, destination, args.ring)?;

    let publication = SignedReceipt::read(&args.publication_receipt, "publication receipt")?;
    let publication_view = verify_publication_receipt(
        plan,
        destination,
        &publication,
        &key_map(&args.receipt_keys)?,
    )?;
    if publication_view.bundle_digest != bundle.bundle_digest
        || publication_view.manifest_digest != manifest_digest
        || !journal.contains_evidence(publication.digest)
    {
        bail!("publication receipt does not bind this release journal");
    }
    let channel_keys = key_map(if args.channel_receipt_keys.is_empty() {
        &args.receipt_keys
    } else {
        &args.channel_receipt_keys
    })?;
    let earlier = args
        .channel_receipts
        .iter()
        .map(|path| {
            let receipt = SignedReceipt::read(path, "earlier channel receipt")?;
            if !journal.contains_evidence(receipt.digest) {
                bail!("channel receipt {} is not in this journal", path.display());
            }
            let view = verify_channel_receipt(plan, destination, None, &receipt, &channel_keys)?;
            Ok((receipt.digest, view))
        })
        .collect::<Result<Vec<_>>>()?;
    let earlier_digests: Vec<Sha256Digest> = earlier.iter().map(|(digest, _)| *digest).collect();
    let earlier: Vec<ChannelReceipt> = earlier.into_iter().map(|(_, view)| view).collect();
    require_observation_elapsed(destination, args.ring, &earlier)?;
    super::super::fitness_gate::require_fitness(
        plan,
        destination,
        &args.fitness,
        args.config.as_deref(),
        &bundle.manifest_keys,
    )?;

    let client = access::connect(
        plan,
        destination.surface,
        args.token.as_deref(),
        args.config.as_deref(),
        SignerNeed::Channels,
    )
    .await?;
    client.verify_identity().await?;
    if client.published_receipt(bundle.bundle_digest).await? != publication {
        bail!("public publication receipt differs from the rollout authority");
    }
    let prior_generation = match args.prior_generation {
        Some(generation) => generation,
        None => {
            client
                .current_generation(&destination.channel, &earlier)
                .await?
        }
    };

    let intent = QualificationRolloutIntent::for_ring(destination, args.ring, prior_generation)?;
    let qualification = verify_admission(AdmissionCheck {
        plan,
        manifest: &bundle.manifest.payload,
        destination,
        directory: args.qualification.as_deref(),
        key_specs: &args.qualification_keys,
        review_keys: &bundle.manifest_keys,
        phase: QualificationPhase::Rollout,
        rollout: Some(&intent),
        journal: &journal.bytes,
        publication_digest: publication.digest,
        manifest_digest,
    })?;

    let tag_object = release_tag_object(&bundle, &args.bundle, client.surface().kind)?;
    let signed = client
        .advance_ring(&ChannelAdvance {
            plan,
            destination,
            ring: args.ring,
            first_partition,
            last_partition,
            prior_generation,
            manifest_digest,
            publication_receipt: &publication,
            release_tag_object: tag_object.as_deref(),
        })
        .await?;
    let receipt =
        verify_channel_receipt(plan, destination, Some(args.ring), &signed, &channel_keys)?;
    if receipt.prior_generation != prior_generation
        || receipt.manifest_digest != manifest_digest
        || receipt.publication_receipt_digest != publication.digest
    {
        bail!("channel receipt does not bind the exact planned operation");
    }
    client.verify_identity().await?;
    client
        .read_back_channel(&ChannelExpectation {
            channel: &destination.channel,
            first_partition,
            last_partition,
            release_id: &plan.release_id,
            release_tag_object: tag_object.as_deref(),
        })
        .await?;

    let successor = successor_journal(
        &journal,
        destination,
        &receipt,
        signed.digest,
        qualification,
        &earlier_digests,
        args.ring == ring_count(destination)? && !requires_completion_approval(plan, destination)?,
    )?;
    journal::persist_tree(
        &args.output,
        &[
            ("channel-receipt.json", &signed.bytes),
            ("release-journal.jsonl", &successor),
        ],
        "channel",
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.channel-advance-result/v1",
        "destination": destination.name,
        "release_id": plan.release_id,
        "ring": receipt.ring,
        "first_partition": receipt.first_partition,
        "last_partition": receipt.last_partition,
        "new_generation": receipt.new_generation,
        "receipt_digest": signed.digest,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Advanced {} ring {} (partitions {}..={}) to {} at generation {}",
        destination.name,
        receipt.ring,
        receipt.first_partition,
        receipt.last_partition,
        plan.release_id,
        receipt.new_generation
    ));
    Ok(())
}

/// Requires `ring` to be the next unadvanced ring of the destination.
fn require_next_ring(journal: &Journal, destination: &PlannedDestination, ring: u16) -> Result<()> {
    let advanced = journal
        .entries
        .iter()
        .filter(|entry| {
            entry.new_state == ReleaseState::Rolling
                && entry.destination.as_deref() == Some(destination.name.as_str())
        })
        .count();
    if usize::from(ring) != advanced + 1 {
        bail!(
            "{} has advanced {advanced} ring(s); ring {ring} is not next",
            destination.name
        );
    }
    Ok(())
}

/// Requires the previous ring's observation window to have elapsed.
fn require_observation_elapsed(
    destination: &PlannedDestination,
    ring: u16,
    earlier: &[ChannelReceipt],
) -> Result<()> {
    let Some(previous) = ring.checked_sub(1).filter(|previous| *previous > 0) else {
        return Ok(());
    };
    let receipt = earlier
        .iter()
        .find(|receipt| receipt.ring == previous)
        .with_context(|| format!("ring {ring} requires the channel receipt of ring {previous}"))?;
    let window = destination
        .rings
        .get(usize::from(previous) - 1)
        .context("previous ring is outside the plan")?
        .observe_seconds;
    let committed = humantime::parse_rfc3339(&receipt.committed_at)?;
    let ready = committed
        .checked_add(Duration::from_secs(window))
        .context("observation window overflowed")?;
    if SystemTime::now() < ready {
        bail!(
            "ring {previous} of {} must be observed for {window} seconds before ring {ring}",
            destination.name
        );
    }
    Ok(())
}

/// Appends the rolling entry, and the automatic completion after a final ring.
fn successor_journal(
    journal: &Journal,
    destination: &PlannedDestination,
    receipt: &ChannelReceipt,
    receipt_digest: Sha256Digest,
    qualification: Option<Sha256Digest>,
    earlier: &[Sha256Digest],
    completes: bool,
) -> Result<Vec<u8>> {
    let mut evidence = vec![receipt_digest];
    evidence.extend(qualification);
    let rolling = journal::append(
        &journal.entries,
        Transition {
            new_state: ReleaseState::Rolling,
            destination: Some(&destination.name),
            operation_ids: vec![format!(
                "{}-generation-{}",
                receipt.channel, receipt.new_generation
            )],
            evidence,
            recorded_at: receipt.committed_at.clone(),
        },
    )?;
    if !completes {
        return Ok(rolling);
    }
    if usize::from(receipt.ring) != earlier.len() + 1 {
        bail!("automatic completion requires the channel receipt of every earlier ring");
    }
    let entries = aos_release_format::state::parse_journal(&rolling)?;
    // Profiles without qualified claims close on the final ring's public
    // read-back; the completion names every ring receipt it relied on.
    let mut rings = earlier.to_vec();
    rings.push(receipt_digest);
    journal::append(
        &entries,
        Transition {
            new_state: ReleaseState::Complete,
            destination: Some(&destination.name),
            operation_ids: vec![format!("complete-{}", destination.name.replace('/', "-"))],
            evidence: rings,
            recorded_at: receipt.committed_at.clone(),
        },
    )
}

#[cfg(test)]
mod tests {
    use aos_release_format::plan::{RolloutRing, SurfaceKind, SurfaceRole};
    use aos_release_format::receipt::CHANNEL_RECEIPT;

    use super::*;

    fn destination() -> PlannedDestination {
        PlannedDestination {
            name: "production/stable".into(),
            surface: SurfaceRole::Production,
            channel: "stable".into(),
            profile: "soak".into(),
            profile_digest: Sha256Digest::of_bytes("profile"),
            soak_seconds: 604_800,
            gates: Vec::new(),
            rings: vec![
                RolloutRing {
                    partitions: 4,
                    observe_seconds: 86_400,
                },
                RolloutRing {
                    partitions: 256,
                    observe_seconds: 0,
                },
            ],
        }
    }

    fn ring_one(committed_at: String) -> ChannelReceipt {
        ChannelReceipt {
            schema_version: CHANNEL_RECEIPT.into(),
            destination: "production/stable".into(),
            channel: "stable".into(),
            ring: 1,
            first_partition: 0,
            last_partition: 3,
            prior_generation: 1,
            new_generation: 2,
            manifest_digest: Sha256Digest::of_bytes("manifest"),
            publication_receipt_digest: Sha256Digest::of_bytes("publication"),
            surface_kind: SurfaceKind::Static,
            surface_identity: "cdn-1".into(),
            committed_at,
        }
    }

    #[test]
    fn later_rings_wait_for_the_previous_observation_window() {
        let destination = destination();
        assert!(require_observation_elapsed(&destination, 1, &[]).is_ok());
        assert!(require_observation_elapsed(&destination, 2, &[]).is_err());

        let recent = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
        assert!(require_observation_elapsed(&destination, 2, &[ring_one(recent)]).is_err());
        let old = "2026-01-01T00:00:00Z".to_owned();
        assert!(require_observation_elapsed(&destination, 2, &[ring_one(old)]).is_ok());
    }
}
