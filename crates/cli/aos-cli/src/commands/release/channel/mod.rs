//! `aos maintain release step channel`: ring-by-ring rollout of one destination.
//!
//! `advance` moves one planned ring of the destination's channel with a
//! compare-and-swap on the surface (Hub transaction or static generation
//! record) and appends a `rolling` entry. Rings are numbered from 1, advance
//! in order exactly once, and a ring may start only after the previous ring's
//! `observe_seconds` elapsed since its channel receipt.
//!
//! A destination whose profile selects `qualified` claims closes with
//! `complete`, which checks the complete-phase qualification and the
//! release-evidence completion approvals. Every other destination (staging
//! destinations, `smoke`, `functional`) records `complete` automatically
//! right after its final ring is read back.

mod advance;
mod complete;

use anyhow::{Context as _, Result, bail};
use aos_cli_ui::output::Printer;
use aos_registry_authoring::registry::release::FinalizedRegistryRelease;
use aos_release_format::canonical;
use aos_release_format::plan::{PlannedDestination, ReleasePlan, SurfaceKind};
use aos_release_format::qualification::ClaimSelection;
use aos_release_format::receipt::ChannelReceipt;

use super::capture;
use super::verify::VerifiedBundle;
use crate::cli::ReleaseChannelCommand;

/// Artifact id of the registry finalization result inside a bundle.
const REGISTRY_FINALIZATION_ID: &str = "provenance/registry-finalization";

/// Runs one channel operation.
pub(super) async fn run(command: &ReleaseChannelCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseChannelCommand::Advance(args) => advance::run(args, printer).await,
        ReleaseChannelCommand::Complete(args) => complete::run(args, printer).await,
    }
}

/// Returns whether a destination needs explicit completion approvals.
fn requires_completion_approval(
    plan: &ReleasePlan,
    destination: &PlannedDestination,
) -> Result<bool> {
    Ok(plan.qualification.profile(&destination.profile)?.claims == ClaimSelection::Qualified)
}

/// Returns the number of planned rings of a destination.
fn ring_count(destination: &PlannedDestination) -> Result<u16> {
    u16::try_from(destination.rings.len()).context("destination has too many rollout rings")
}

/// Reads the registry release tag object that static partitions select.
///
/// Hub surfaces project their own partitions and need no tag object.
fn release_tag_object(
    bundle: &VerifiedBundle,
    bundle_path: &std::path::Path,
    surface_kind: SurfaceKind,
) -> Result<Option<String>> {
    if surface_kind == SurfaceKind::Hub {
        return Ok(None);
    }
    let artifact = bundle
        .manifest
        .payload
        .artifacts
        .iter()
        .find(|artifact| artifact.id == REGISTRY_FINALIZATION_ID)
        .context("bundle lacks its registry finalization result")?;
    let bytes = capture::control_file(
        &bundle_path.join(artifact.path.as_str()),
        "registry finalization result",
    )?;
    if aos_release_format::Sha256Digest::of_bytes(&bytes) != artifact.sha256 {
        bail!("registry finalization result differs from its manifest record");
    }
    let result: FinalizedRegistryRelease =
        canonical::from_slice(&bytes, "registry finalization result")?;
    if result.registry != bundle.plan.registry || result.release != bundle.plan.version {
        bail!("registry finalization result names a different release");
    }
    Ok(Some(result.tag_object))
}

/// Requires receipts to cover rings `1..=count` once each with contiguous generations.
fn validate_rollout(
    destination: &PlannedDestination,
    receipts: &[ChannelReceipt],
    count: u16,
) -> Result<()> {
    let mut ordered: Vec<_> = receipts.iter().collect();
    ordered.sort_by_key(|receipt| receipt.ring);
    let rings: Vec<u16> = ordered.iter().map(|receipt| receipt.ring).collect();
    if rings != (1..=count).collect::<Vec<_>>() {
        bail!(
            "{} rollout requires one channel receipt for each of rings 1..={count}",
            destination.name
        );
    }
    if ordered
        .windows(2)
        .any(|pair| pair[1].prior_generation != pair[0].new_generation)
    {
        bail!(
            "{} channel receipt generations are not contiguous",
            destination.name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_release_format::digest::Sha256Digest;
    use aos_release_format::plan::{RolloutRing, SurfaceRole};
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
                    partitions: 32,
                    observe_seconds: 60,
                },
                RolloutRing {
                    partitions: 256,
                    observe_seconds: 0,
                },
            ],
        }
    }

    fn receipt(ring: u16, prior: u64) -> ChannelReceipt {
        let (first, last) = destination()
            .ring_range(ring)
            .unwrap_or_else(|error| panic!("{error}"));
        ChannelReceipt {
            schema_version: CHANNEL_RECEIPT.into(),
            destination: "production/stable".into(),
            channel: "stable".into(),
            ring,
            first_partition: first,
            last_partition: last,
            prior_generation: prior,
            new_generation: prior + 1,
            manifest_digest: Sha256Digest::of_bytes("manifest"),
            publication_receipt_digest: Sha256Digest::of_bytes("publication"),
            surface_kind: SurfaceKind::Static,
            surface_identity: "cdn-1".into(),
            committed_at: "2026-09-03T00:00:00Z".into(),
        }
    }

    #[test]
    fn rollout_requires_every_ring_and_contiguous_generations() {
        let destination = destination();
        assert!(validate_rollout(&destination, &[receipt(1, 7), receipt(2, 8)], 2).is_ok());
        assert!(validate_rollout(&destination, &[receipt(1, 7), receipt(2, 9)], 2).is_err());
        assert!(validate_rollout(&destination, &[receipt(1, 7)], 2).is_err());
        assert!(
            validate_rollout(
                &destination,
                &[receipt(1, 7), receipt(1, 8), receipt(2, 9)],
                2
            )
            .is_err()
        );
    }
}
