//! Planned compare-and-swap production channel rollout.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{
    ChannelReceiptV1, CompletionReceiptV1, HubEnvironment, PublicationReceiptV1,
    verify_signed_receipt_with_key,
};
use aos_release::signing::SignerRole;
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
use aos_remote::hub::{HubClient, hub_rpc};

use crate::cli::{ReleaseChannelAdvanceArgs, ReleaseChannelCommand, ReleaseChannelCompleteArgs};

use super::{capture, hub_transition, verify};

const PRODUCTION_HUB: &str = "https://aos.andyl.org";

pub(super) async fn run(command: &ReleaseChannelCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseChannelCommand::Advance(args) => advance(args, printer).await,
        ReleaseChannelCommand::Complete(args) => complete(args, printer).await,
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
    plan.require_publishable_qualification()?;
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

    let manifest: aos_release::manifest::ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;
    let qualification_digest = super::qualification_transition::verify_admission(
        &plan,
        &manifest.payload,
        args.qualification.as_deref(),
        &args.qualification_keys,
        &manifest_keys,
        aos_release::qualification::QualificationPhase::Rollout,
        Some(
            &aos_release::qualification_admission::QualificationRolloutIntent {
                channel: args.channel.clone(),
                prior_generation: args.prior_generation,
                first_partition: args.first_partition,
                last_partition: args.last_partition,
            },
        ),
        &journal_bytes,
        production_digest,
        summary.manifest_digest,
    )?;

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
    let rollout_journal = bind_qualification(rollout_journal, qualification_digest)?;
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

async fn complete(args: &ReleaseChannelCompleteArgs, printer: &Printer) -> Result<()> {
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
    plan.require_publishable_qualification()?;
    let bundle_digest =
        aos_release::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;

    let journal_bytes = capture::control_file(&args.journal, "release rollout journal")?;
    let journal = parse_journal(&journal_bytes)?;
    if aos_release::verify::verify_journal(&journal)? != ReleaseState::Rolling {
        bail!("channel completion requires a rolling journal");
    }
    let latest = journal.last().context("release journal is empty")?;
    if latest.plan_digest != summary.plan_digest
        || latest.manifest_digest != Some(summary.manifest_digest)
    {
        bail!("release journal does not bind the exact completion bundle");
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
        || !journal
            .iter()
            .any(|entry| entry.evidence.contains(&production_digest))
    {
        bail!("production receipt does not bind the exact completion release");
    }

    let manifest: aos_release::manifest::ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;
    let qualification_digest = super::qualification_transition::verify_admission(
        &plan,
        &manifest.payload,
        args.qualification.as_deref(),
        &args.qualification_keys,
        &manifest_keys,
        aos_release::qualification::QualificationPhase::Complete,
        None,
        &journal_bytes,
        production_digest,
        summary.manifest_digest,
    )?;

    let channel_keys = key_map(&args.channel_receipt_keys)?;
    let mut channel_receipts = Vec::with_capacity(args.channel_receipts.len());
    for path in &args.channel_receipts {
        let bytes = capture::control_file(path, "signed channel receipt")?;
        let digest = Sha256Digest::of_bytes(&bytes);
        let (_, receipt): (String, ChannelReceiptV1) =
            verify_signed_receipt_with_key(&bytes, &channel_keys)?;
        receipt.validate()?;
        if receipt.manifest_digest != summary.manifest_digest
            || receipt.production_receipt_digest != production_digest
            || !journal.iter().any(|entry| entry.evidence.contains(&digest))
        {
            bail!("channel receipt is not bound into this release journal");
        }
        channel_receipts.push((digest, receipt, bytes));
    }
    validate_complete_rollout(&plan.intended_channels, &channel_receipts)?;

    let completion_requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .context("release plan lacks the release-evidence signer policy")?;
    let completion_keys = key_map(&args.completion_keys)?;
    if completion_keys.len() != usize::from(completion_requirement.threshold)
        || completion_keys
            .keys()
            .any(|key| !completion_requirement.key_ids.contains(key))
    {
        bail!(
            "completion trust inputs must exactly satisfy the planned release-evidence threshold"
        );
    }
    let expected_channel_digests = channel_receipts
        .iter()
        .map(|(digest, _, _)| *digest)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let prior_journal_entry_digest = Sha256Digest::of_canonical(
        "aos.release.journal-entry/v1",
        journal.last().context("release journal is empty")?,
    )?;
    let mut completion_payload: Option<CompletionReceiptV1> = None;
    let mut completion_signers = BTreeSet::new();
    let mut completion_envelopes = Vec::with_capacity(args.completion_receipts.len());
    for path in &args.completion_receipts {
        let bytes = capture::control_file(path, "signed completion receipt")?;
        let (key_id, receipt): (String, CompletionReceiptV1) =
            verify_signed_receipt_with_key(&bytes, &completion_keys)?;
        receipt.validate()?;
        if !completion_signers.insert(key_id) {
            bail!("completion evidence repeats a signing key");
        }
        if completion_payload
            .as_ref()
            .is_some_and(|prior| prior != &receipt)
        {
            bail!("completion authorities signed different decisions");
        }
        completion_payload = Some(receipt);
        completion_envelopes.push(bytes);
    }
    if completion_signers.len() != usize::from(completion_requirement.threshold) {
        bail!("completion evidence does not satisfy the planned threshold");
    }
    let completion = completion_payload.context("completion evidence is empty")?;
    if completion.release_id != summary.release_id
        || completion.plan_digest != summary.plan_digest
        || completion.manifest_digest != summary.manifest_digest
        || completion.production_receipt_digest != production_digest
        || completion.channel_receipt_digests != expected_channel_digests
        || completion.prior_journal_entry_digest != prior_journal_entry_digest
        || completion.retention_policy_id != plan.retention.policy_id
        || completion.retention_policy_digest != plan.retention.policy_digest
    {
        bail!("completion decision differs from the frozen release and rollout");
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
        bail!("public production receipt differs from completion authority");
    }
    for (_, receipt, _) in &channel_receipts {
        verify_public_channel(
            &public_hub,
            &plan.registry,
            &receipt.channel,
            receipt.first_partition,
            receipt.last_partition,
            &summary.release_id,
        )
        .await?;
    }
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;

    let complete_journal = append_complete_journal(&journal, &completion, &completion_envelopes)?;
    let complete_journal = bind_qualification(complete_journal, qualification_digest)?;
    persist_completion(
        &args.output,
        &production_bytes,
        &channel_receipts,
        &completion_envelopes,
        &complete_journal,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.channel-complete-result/v1",
        "release_id": summary.release_id,
        "channel_operations": channel_receipts.len(),
        "completion_signatures": completion_envelopes.len(),
        "completed_at": completion.completed_at,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Completed release {} after verifying {} planned channel operations",
        summary.release_id,
        channel_receipts.len()
    ));
    Ok(())
}

fn validate_complete_rollout(
    intended_channels: &[aos_release::plan::ChannelIntent],
    receipts: &[(Sha256Digest, ChannelReceiptV1, Vec<u8>)],
) -> Result<()> {
    if receipts.len() != intended_channels.len() {
        bail!("channel completion requires exactly one receipt per planned range");
    }
    let intended = intended_channels
        .iter()
        .map(|intent| {
            (
                &intent.channel,
                intent.first_partition,
                intent.last_partition,
            )
        })
        .collect::<BTreeSet<_>>();
    let found = receipts
        .iter()
        .map(|(_, receipt, _)| {
            (
                &receipt.channel,
                receipt.first_partition,
                receipt.last_partition,
            )
        })
        .collect::<BTreeSet<_>>();
    if found.len() != receipts.len() || found != intended {
        bail!("channel receipts do not exactly cover the frozen rollout intents");
    }
    let mut by_channel: BTreeMap<&str, Vec<&ChannelReceiptV1>> = BTreeMap::new();
    for (_, receipt, _) in receipts {
        by_channel
            .entry(&receipt.channel)
            .or_default()
            .push(receipt);
    }
    for operations in by_channel.values_mut() {
        operations.sort_by_key(|receipt| receipt.new_generation);
        if operations.windows(2).any(|pair| {
            pair[1].prior_generation != pair[0].new_generation
                || pair[1].new_generation != pair[0].new_generation.saturating_add(1)
        }) {
            bail!("channel receipt generations are not contiguous");
        }
    }
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

fn append_complete_journal(
    journal: &[JournalEntryV1],
    receipt: &CompletionReceiptV1,
    envelopes: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let previous = journal.last().context("release journal is empty")?;
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
        prior_state: Some(ReleaseState::Rolling),
        new_state: ReleaseState::Complete,
        operation_ids: vec![format!("complete-{}", receipt.authority_id)],
        evidence: envelopes
            .iter()
            .map(Sha256Digest::of_bytes)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        recorded_at: receipt.completed_at.clone(),
    };
    if entry.evidence.len() != envelopes.len() {
        bail!("completion evidence contains duplicate envelopes");
    }
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

fn persist_completion(
    output: &Path,
    production: &[u8],
    channels: &[(Sha256Digest, ChannelReceiptV1, Vec<u8>)],
    completion: &[Vec<u8>],
    journal: &[u8],
) -> Result<()> {
    if output.exists() {
        bail!("completion output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-complete-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    fs::create_dir(root.join("channel-receipts"))?;
    fs::create_dir(root.join("completion-receipts"))?;
    write_file(&root.join("production-receipt.json"), production)?;
    write_file(&root.join("release-journal.jsonl"), journal)?;
    for (digest, _, bytes) in channels {
        write_file(
            &root
                .join("channel-receipts")
                .join(format!("{}.json", digest.hex())),
            bytes,
        )?;
    }
    for (index, bytes) in completion.iter().enumerate() {
        write_file(
            &root
                .join("completion-receipts")
                .join(format!("{:04}.json", index + 1)),
            bytes,
        )?;
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

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
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

    fn channel_receipt(
        channel: &str,
        first: u16,
        last: u16,
        prior: u64,
    ) -> (Sha256Digest, ChannelReceiptV1, Vec<u8>) {
        let receipt = ChannelReceiptV1 {
            schema_version: "aos.release.channel-receipt/v1".into(),
            channel: channel.into(),
            first_partition: first,
            last_partition: last,
            prior_generation: prior,
            new_generation: prior + 1,
            manifest_digest: Sha256Digest::of_bytes("manifest"),
            production_receipt_digest: Sha256Digest::of_bytes("production"),
            committed_at: "2026-09-03T00:00:00Z".into(),
        };
        let bytes = canonical::to_vec(&receipt).unwrap();
        (Sha256Digest::of_bytes(&bytes), receipt, bytes)
    }

    #[test]
    fn completion_requires_exact_intents_and_contiguous_generations() {
        let intended = vec![
            aos_release::plan::ChannelIntent {
                channel: "edge".into(),
                first_partition: 0,
                last_partition: 31,
            },
            aos_release::plan::ChannelIntent {
                channel: "edge".into(),
                first_partition: 32,
                last_partition: 255,
            },
        ];
        let valid = vec![
            channel_receipt("edge", 0, 31, 7),
            channel_receipt("edge", 32, 255, 8),
        ];
        assert!(validate_complete_rollout(&intended, &valid).is_ok());

        let skipped = vec![
            channel_receipt("edge", 0, 31, 7),
            channel_receipt("edge", 32, 255, 9),
        ];
        assert!(validate_complete_rollout(&intended, &skipped).is_err());

        let partial = vec![channel_receipt("edge", 0, 31, 7)];
        assert!(validate_complete_rollout(&intended, &partial).is_err());
    }

    #[test]
    fn channel_output_never_replaces_existing_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("channel");
        persist(&output, b"production", b"channel", b"journal")?;
        assert!(persist(&output, b"other", b"other", b"other").is_err());
        assert_eq!(fs::read(output.join("channel-receipt.json"))?, b"channel");
        Ok(())
    }

    #[test]
    fn completion_output_never_replaces_existing_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("complete");
        let channels = vec![channel_receipt("edge", 0, 255, 1)];
        persist_completion(
            &output,
            b"production",
            &channels,
            &[b"completion".to_vec()],
            b"journal",
        )?;
        assert!(
            persist_completion(&output, b"other", &channels, &[b"other".to_vec()], b"other",)
                .is_err()
        );
        assert_eq!(
            fs::read(output.join("production-receipt.json"))?,
            b"production"
        );
        Ok(())
    }
}

/// Adds admission evidence before the successor journal is persisted.
fn bind_qualification(bytes: Vec<u8>, digest: Option<Sha256Digest>) -> Result<Vec<u8>> {
    let Some(digest) = digest else {
        return Ok(bytes);
    };
    let mut journal = parse_journal(&bytes)?;
    let last = journal.last_mut().context("empty successor journal")?;
    last.evidence.push(digest);
    last.evidence.sort();
    last.evidence.dedup();
    aos_release::verify::verify_journal(&journal)?;
    let mut result = Vec::new();
    for entry in journal {
        result.extend(canonical::to_vec(&entry)?);
        result.push(b'\n');
    }
    Ok(result)
}
