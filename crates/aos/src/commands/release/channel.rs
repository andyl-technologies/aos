//! Planned compare-and-swap production channel rollout.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{
    ChannelReceiptV1, HubEnvironment, PublicationReceiptV1, verify_signed_receipt_with_key,
};
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
use aos_remote::hub::{HubClient, hub_rpc};

use crate::cli::{ReleaseChannelAdvanceArgs, ReleaseChannelCommand};

use super::{capture, hub_transition, verify};

const PRODUCTION_HUB: &str = "https://aos.andyl.org";

pub(super) async fn run(command: &ReleaseChannelCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseChannelCommand::Advance(args) => advance(args, printer).await,
    }
}

async fn advance(args: &ReleaseChannelAdvanceArgs, printer: &Printer) -> Result<()> {
    let captured = capture::bundle(&args.bundle)?;
    let manifest_keys = verify::load_trusted_keys(&args.trusted_keys)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &manifest_keys,
    )?;
    let plan: aos_release::plan::ReleasePlanV1 =
        canonical::from_slice(&captured.plan_bytes, "release plan")?;
    let bundle_digest =
        aos_release::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;
    if !plan.intended_channels.iter().any(|intent| {
        intent.channel == args.channel
            && intent.first_partition == args.first_partition
            && intent.last_partition == args.last_partition
    }) {
        bail!("channel operation is not an exact intent in the frozen release plan");
    }

    let journal_bytes = capture::control_file(&args.journal, "release rollout journal")?;
    let journal = parse_journal(&journal_bytes)?;
    let prior_state = aos_release::verify::verify_journal(&journal)?;
    if !matches!(prior_state, ReleaseState::Promoted | ReleaseState::Rolling) {
        bail!("channel advance requires a promoted or rolling journal");
    }
    let latest = journal.last().context("release journal is empty")?;
    if latest.plan_digest != summary.plan_digest
        || latest.manifest_digest != Some(summary.manifest_digest)
    {
        bail!("release journal does not bind the exact rollout bundle");
    }

    let production_bytes =
        capture::control_file(&args.production_receipt, "signed production receipt")?;
    let production_digest = Sha256Digest::of_bytes(&production_bytes);
    let production_keys = key_map(&args.production_receipt_keys)?;
    let (_, production): (String, PublicationReceiptV1) =
        verify_signed_receipt_with_key(&production_bytes, &production_keys)?;
    production.validate()?;
    if production.environment != HubEnvironment::Production
        || production.deployment_id != plan.production_deployment_id
        || production.registry != plan.registry
        || production.release_id != summary.release_id
        || production.manifest_digest != summary.manifest_digest
        || production.bundle_digest != bundle_digest
    {
        bail!("production receipt does not bind the exact rollout release");
    }
    if !journal
        .iter()
        .any(|entry| entry.evidence.contains(&production_digest))
    {
        bail!("release journal does not contain the production receipt");
    }

    let public_client = hub_transition::public_client()?;
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;
    let public_hub = HubClient::connect_anonymous(PRODUCTION_HUB)?;
    let public_receipt = public_hub
        .call_topology(
            hub_rpc::GetReleaseReceipt,
            &aos_proto_types::GetReleaseReceiptRequest {
                bundle_digest: bundle_digest.to_string(),
                environment: "production".into(),
            },
        )
        .await?;
    if public_receipt.receipt_digest != production_digest.to_string()
        || public_receipt.signed_receipt_json.as_bytes() != production_bytes
    {
        bail!("public production receipt differs from the rollout authority");
    }

    let token = args
        .token
        .as_deref()
        .context("channel advance requires a production access token")?;
    let hub = HubClient::connect_with_token(PRODUCTION_HUB, token)?;
    let signed = hub
        .call_topology(
            hub_rpc::AdvanceReleaseChannel,
            &aos_proto_types::AdvanceReleaseChannelRequest {
                registry: plan.registry.clone(),
                channel: args.channel.clone(),
                prior_generation: i64::try_from(args.prior_generation)?,
                first_partition: i64::from(args.first_partition),
                last_partition: i64::from(args.last_partition),
                manifest_digest: summary.manifest_digest.to_string(),
                production_receipt_digest: production_digest.to_string(),
            },
        )
        .await?;
    let channel_bytes = signed.signed_receipt_json.into_bytes();
    let channel_digest = Sha256Digest::of_bytes(&channel_bytes);
    if channel_digest.to_string() != signed.receipt_digest {
        bail!("channel receipt digest does not match its signed bytes");
    }
    let channel_keys = key_map(&args.channel_receipt_keys)?;
    let (_, receipt): (String, ChannelReceiptV1) =
        verify_signed_receipt_with_key(&channel_bytes, &channel_keys)?;
    receipt.validate()?;
    if receipt.channel != args.channel
        || receipt.first_partition != args.first_partition
        || receipt.last_partition != args.last_partition
        || receipt.prior_generation != args.prior_generation
        || receipt.manifest_digest != summary.manifest_digest
        || receipt.production_receipt_digest != production_digest
    {
        bail!("channel receipt does not bind the exact planned operation");
    }
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;
    verify_public_channel(
        &public_hub,
        &plan.registry,
        &args.channel,
        args.first_partition,
        args.last_partition,
        &summary.release_id,
    )
    .await?;

    let rollout_journal = append_rolling_journal(&journal, prior_state, &receipt, channel_digest)?;
    persist(
        &args.output,
        &production_bytes,
        &channel_bytes,
        &rollout_journal,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.channel-advance-result/v1",
        "release_id": summary.release_id,
        "channel": receipt.channel,
        "first_partition": receipt.first_partition,
        "last_partition": receipt.last_partition,
        "new_generation": receipt.new_generation,
        "receipt_digest": channel_digest,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Advanced {} partitions {}..={} to {} at generation {}",
        receipt.channel,
        receipt.first_partition,
        receipt.last_partition,
        summary.release_id,
        receipt.new_generation
    ));
    Ok(())
}

async fn verify_public_channel(
    hub: &HubClient,
    registry: &str,
    channel: &str,
    first: u16,
    last: u16,
    release: &str,
) -> Result<()> {
    let response = hub
        .call_topology(
            hub_rpc::GetChannel,
            &aos_proto_types::GetChannelRequest {
                slug: registry.into(),
                name: channel.into(),
            },
        )
        .await?;
    let found = response
        .channel
        .context("public channel response is empty")?;
    if found.name != channel || found.frontier != release {
        bail!("public channel frontier differs from the signed operation");
    }
    let partitions = found
        .partitions
        .into_iter()
        .map(|partition| (partition.bucket, partition.release))
        .collect::<BTreeMap<_, _>>();
    for bucket in first..=last {
        if partitions.get(&u32::from(bucket)).map(String::as_str) != Some(release) {
            bail!("public channel partition {bucket} differs from the signed operation");
        }
    }
    Ok(())
}

fn key_map(specifications: &[String]) -> Result<BTreeMap<String, [u8; 32]>> {
    Ok(verify::load_trusted_keys(specifications)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect())
}

fn append_rolling_journal(
    journal: &[JournalEntryV1],
    prior_state: ReleaseState,
    receipt: &ChannelReceiptV1,
    receipt_digest: Sha256Digest,
) -> Result<Vec<u8>> {
    let previous = journal.last().context("release journal is empty")?;
    let operation_id = format!("{}-generation-{}", receipt.channel, receipt.new_generation);
    if journal
        .iter()
        .flat_map(|entry| entry.operation_ids.iter())
        .any(|existing| existing == &operation_id)
    {
        bail!("release journal already contains this channel generation");
    }
    let entry = JournalEntryV1 {
        schema_version: aos_release::RELEASE_JOURNAL_ENTRY_V1.to_owned(),
        sequence: previous
            .sequence
            .checked_add(1)
            .context("journal sequence overflowed")?,
        previous_entry_digest: Some(Sha256Digest::of_canonical(
            "aos.release.journal-entry/v1",
            previous,
        )?),
        plan_digest: previous.plan_digest,
        manifest_digest: previous.manifest_digest,
        prior_state: Some(prior_state),
        new_state: ReleaseState::Rolling,
        operation_ids: vec![operation_id],
        evidence: vec![receipt_digest],
        recorded_at: receipt.committed_at.clone(),
    };
    let mut complete = journal.to_vec();
    complete.push(entry);
    aos_release::verify::verify_journal(&complete)?;
    let mut bytes = Vec::new();
    for entry in complete {
        bytes.extend(canonical::to_vec(&entry)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn persist(output: &Path, production: &[u8], channel: &[u8], journal: &[u8]) -> Result<()> {
    if output.exists() {
        bail!("channel output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-channel-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    for (name, bytes) in [
        ("production-receipt.json", production),
        ("channel-receipt.json", channel),
        ("release-journal.jsonl", journal),
    ] {
        let mut file = File::create(root.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    File::open(&root)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &root,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_output_never_replaces_existing_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("channel");
        persist(&output, b"production", b"channel", b"journal")?;
        assert!(persist(&output, b"other", b"other", b"other").is_err());
        assert_eq!(fs::read(output.join("channel-receipt.json"))?, b"channel");
        Ok(())
    }
}
