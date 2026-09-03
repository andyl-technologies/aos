//! Admission of independently signed staging qualification evidence.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{
    HubEnvironment, PublicationReceiptV1, QualificationReceiptV1, verify_signed_receipt_with_key,
};
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
use aos_remote::hub::{HubClient, hub_rpc};

use crate::cli::ReleaseQualifyArgs;

use super::{capture, verify};

const STAGING_HUB: &str = "https://aos.staging.andyl.org";

pub(super) async fn run(args: &ReleaseQualifyArgs, printer: &Printer) -> Result<()> {
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

    let journal_bytes = capture::control_file(&args.journal, "staged release journal")?;
    let journal = parse_journal(&journal_bytes)?;
    require_staged_journal(&journal, summary.plan_digest, summary.manifest_digest)?;

    let staging_bytes = capture::control_file(&args.staging_receipt, "signed staging receipt")?;
    let staging_digest = Sha256Digest::of_bytes(&staging_bytes);
    let staging_keys = key_map(&args.hub_receipt_keys)?;
    let (_, staging): (String, PublicationReceiptV1) =
        verify_signed_receipt_with_key(&staging_bytes, &staging_keys)?;
    staging.validate()?;
    if staging.environment != HubEnvironment::Staging
        || staging.deployment_id != plan.staging_deployment_id
        || staging.registry != plan.registry
        || staging.release_id != summary.release_id
        || staging.manifest_digest != summary.manifest_digest
        || staging.bundle_digest != bundle_digest
        || staging.staging_receipt_digest.is_some()
    {
        bail!("staging receipt does not bind the exact qualified release");
    }
    if !journal
        .last()
        .is_some_and(|entry| entry.evidence.contains(&staging_digest))
    {
        bail!("staged journal does not contain the exact staging receipt");
    }

    let qualification_bytes =
        capture::control_file(&args.signed_qualification, "signed qualification receipt")?;
    let qualification_digest = Sha256Digest::of_bytes(&qualification_bytes);
    let qualification_keys = key_map(&args.qualification_keys)?;
    let (qualification_key_id, qualification): (String, QualificationReceiptV1) =
        verify_signed_receipt_with_key(&qualification_bytes, &qualification_keys)?;
    qualification.validate()?;
    if qualification_key_id != qualification.authority_id
        || qualification.staging_receipt_digest != staging_digest
        || qualification.manifest_digest != summary.manifest_digest
        || !plan.gates.iter().any(|gate| {
            gate.policy_id == qualification.policy_id
                && gate.policy_digest == qualification.policy_digest
        })
    {
        bail!("qualification receipt does not match the release plan and staging receipt");
    }
    let qualification_payload = canonical::to_vec(&qualification)?;

    let token = args
        .token
        .as_deref()
        .context("qualification admission requires a staging access token")?;
    let hub = HubClient::connect_with_token(STAGING_HUB, token)?;
    let admitted = hub
        .call_topology(
            hub_rpc::RecordReleaseQualification,
            &aos_proto_types::RecordReleaseQualificationRequest {
                registry: plan.registry,
                bundle_digest: bundle_digest.to_string(),
                staging_receipt_digest: staging_digest.to_string(),
                qualification_digest: qualification_digest.to_string(),
                signed_qualification_json: String::from_utf8(qualification_bytes.clone())
                    .context("signed qualification receipt is not UTF-8")?,
                qualification_receipt_json: String::from_utf8(qualification_payload.clone())
                    .context("qualification receipt is not UTF-8")?,
            },
        )
        .await?;
    if admitted.bundle_digest != bundle_digest.to_string()
        || admitted.staging_receipt_digest != staging_digest.to_string()
        || admitted.qualification_digest != qualification_digest.to_string()
    {
        bail!("staging Hub returned a mismatched qualification admission");
    }

    let qualified_journal = append_qualified_journal(
        &journal,
        &qualification,
        staging_digest,
        qualification_digest,
    )?;
    persist(
        &args.output,
        &staging_bytes,
        &qualification_bytes,
        &qualification_payload,
        &qualified_journal,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.qualify-result/v1",
        "release_id": summary.release_id,
        "staging_receipt_digest": staging_digest,
        "qualification_digest": qualification_digest,
        "authority_id": qualification.authority_id,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Admitted signed qualification {} for release {}",
        qualification_digest, summary.release_id
    ));
    Ok(())
}

fn key_map(specifications: &[String]) -> Result<BTreeMap<String, [u8; 32]>> {
    Ok(verify::load_trusted_keys(specifications)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect())
}

fn require_staged_journal(
    journal: &[JournalEntryV1],
    plan_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
) -> Result<()> {
    if aos_release::verify::verify_journal(journal)? != ReleaseState::Staged {
        bail!("qualification requires a journal in the staged state");
    }
    let latest = journal.last().context("release journal is empty")?;
    if latest.plan_digest != plan_digest || latest.manifest_digest != Some(manifest_digest) {
        bail!("staged journal does not bind the exact release bundle");
    }
    Ok(())
}

fn append_qualified_journal(
    journal: &[JournalEntryV1],
    receipt: &QualificationReceiptV1,
    staging_digest: Sha256Digest,
    qualification_digest: Sha256Digest,
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
        prior_state: Some(ReleaseState::Staged),
        new_state: ReleaseState::Qualified,
        operation_ids: vec![receipt.nonce.clone()],
        evidence: vec![staging_digest, qualification_digest],
        recorded_at: receipt.qualified_at.clone(),
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

fn persist(
    output: &Path,
    staging: &[u8],
    signed_qualification: &[u8],
    qualification: &[u8],
    journal: &[u8],
) -> Result<()> {
    if output.exists() {
        bail!("qualification output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-qualify-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    for (name, bytes) in [
        ("staging-receipt.json", staging),
        ("qualification-receipt.json", qualification),
        ("signed-qualification.json", signed_qualification),
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
    fn qualification_output_never_replaces_existing_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("qualified");
        persist(&output, b"stage", b"signed", b"payload", b"journal")?;
        assert!(persist(&output, b"other", b"other", b"other", b"other").is_err());
        assert_eq!(
            fs::read(output.join("signed-qualification.json"))?,
            b"signed"
        );
        Ok(())
    }
}
