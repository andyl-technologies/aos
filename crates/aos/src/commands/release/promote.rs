//! Exact-evidence import into the isolated production Hub.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::evidence::QualificationReportV1;
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::receipt::{
    HubEnvironment, PublicationReceiptV1, QualificationReceiptV1, verify_signed_receipt_with_key,
};
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
use aos_release::tuf::TufRole;
use aos_remote::hub::{HubClient, hub_rpc};

use crate::cli::{HubAccessArgs, ReleasePromoteArgs};

use super::{capture, hub_transition, stage, verify};

const PRODUCTION_HUB: &str = "https://aos.andyl.org";

pub(super) async fn run(args: &ReleasePromoteArgs, printer: &Printer) -> Result<()> {
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
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;
    let bundle_digest =
        aos_release::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;

    let journal_bytes = capture::control_file(&args.journal, "qualified release journal")?;
    let journal = parse_journal(&journal_bytes)?;
    require_qualified_journal(&journal, summary.plan_digest, summary.manifest_digest)?;

    let staging_bytes = capture::control_file(&args.staging_receipt, "signed staging receipt")?;
    let staging_digest = Sha256Digest::of_bytes(&staging_bytes);
    let staging_keys = key_map(&args.staging_receipt_keys)?;
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
        bail!("staging receipt does not bind the exact promoted release");
    }

    let qualification_payload =
        capture::control_file(&args.qualification_receipt, "qualification receipt")?;
    canonical::require_canonical(&qualification_payload, "qualification receipt")?;
    let qualification: QualificationReceiptV1 =
        canonical::from_slice(&qualification_payload, "qualification receipt")?;
    let qualification_bytes =
        capture::control_file(&args.signed_qualification, "signed qualification receipt")?;
    let qualification_digest = Sha256Digest::of_bytes(&qualification_bytes);
    let qualification_keys = key_map(&args.qualification_keys)?;
    let (qualification_key_id, signed_qualification): (String, QualificationReceiptV1) =
        verify_signed_receipt_with_key(&qualification_bytes, &qualification_keys)?;
    qualification.validate()?;
    let report_bytes = capture::control_file(&args.qualification_report, "qualification report")?;
    let report: QualificationReportV1 =
        canonical::from_slice(&report_bytes, "qualification report")?;
    if canonical::to_vec(&report)? != report_bytes {
        bail!("qualification report is not canonical JSON");
    }
    report.validate(
        &plan,
        &manifest.payload,
        staging_digest,
        summary.manifest_digest,
    )?;
    if qualification != signed_qualification
        || qualification_key_id != qualification.authority_id
        || qualification.staging_receipt_digest != staging_digest
        || qualification.manifest_digest != summary.manifest_digest
        || qualification.policy_id != "full-release-qualification"
        || qualification.policy_digest != plan.public_evidence_policy_digest
        || qualification.report_digest != Sha256Digest::of_bytes(&report_bytes)
    {
        bail!("qualification evidence does not bind the exact promoted release");
    }
    let latest = journal.last().context("release journal is empty")?;
    if !latest.evidence.contains(&staging_digest)
        || !latest.evidence.contains(&qualification_digest)
    {
        bail!("qualified journal does not contain the exact predecessor evidence");
    }

    let public_client = hub_transition::public_client()?;
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;
    let access = HubAccessArgs {
        hub: Some(PRODUCTION_HUB.to_owned()),
        token: args.token.clone(),
    };
    let manifest_public_path = format!(
        "releases/{}/{}/release-manifest.json",
        TufRole::for_release(plan.release_class).as_str(),
        plan.version
    );
    let publication_surface = stage::publication_surface(
        &args.bundle,
        &captured.files,
        &manifest_public_path,
        &captured.manifest_bytes,
    )?;
    let publication = crate::commands::hub::upload_registry_publication(
        &access,
        &plan.registry,
        None,
        &publication_surface.path().join("surface"),
        printer,
    )
    .await?;
    if publication.state != "ready" || publication.completed_at <= 0 {
        bail!("production Hub did not return a completed ready publication");
    }
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;
    hub_transition::read_back_publication(
        &public_client,
        PRODUCTION_HUB,
        &plan.registry,
        &publication,
    )
    .await?;
    if publication.parent_publication_id.is_empty() {
        bail!("production release publication has no compare-and-swap base publication");
    }
    if publication.default_commit != plan.registry_base_commit {
        bail!("production release publication does not preserve the approved registry base");
    }

    let token = args
        .token
        .as_deref()
        .context("production promotion requires an access token")?;
    let hub = HubClient::connect_with_token(PRODUCTION_HUB, token)?;
    hub.call_topology(
        hub_rpc::BeginReleasePublication,
        &aos_proto_types::BeginReleasePublicationRequest {
            registry: plan.registry.clone(),
            bundle_digest: bundle_digest.to_string(),
            release_id: summary.release_id.clone(),
            manifest_digest: summary.manifest_digest.to_string(),
            registry_base_commit: plan.registry_base_commit.clone(),
            staging_deployment_id: plan.staging_deployment_id.clone(),
            production_deployment_id: plan.production_deployment_id.clone(),
            backing_publication_id: publication.publication_id.clone(),
        },
    )
    .await?;
    let signed = hub
        .call_topology(
            hub_rpc::PromoteReleasePublication,
            &aos_proto_types::PromoteReleasePublicationRequest {
                registry: plan.registry.clone(),
                bundle_digest: bundle_digest.to_string(),
                publication_id: publication.publication_id.clone(),
                expected_deployment_id: plan.production_deployment_id.clone(),
                staging_receipt_digest: staging_digest.to_string(),
                qualification_digest: qualification_digest.to_string(),
                signed_staging_receipt_json: String::from_utf8(staging_bytes.clone())
                    .context("signed staging receipt is not UTF-8")?,
                qualification_receipt_json: String::from_utf8(qualification_payload.clone())
                    .context("qualification receipt is not UTF-8")?,
                signed_qualification_json: String::from_utf8(qualification_bytes.clone())
                    .context("signed qualification receipt is not UTF-8")?,
            },
        )
        .await?;
    let production_bytes = signed.signed_receipt_json.into_bytes();
    let production_digest = Sha256Digest::of_bytes(&production_bytes);
    if production_digest.to_string() != signed.receipt_digest {
        bail!("production Hub receipt digest does not match its signed bytes");
    }
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
        || production.operation_id != publication.publication_id
        || production.staging_receipt_digest != Some(staging_digest)
    {
        bail!("production receipt does not bind the exact promoted release");
    }
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
        bail!("anonymous production receipt read-back differs from the committed receipt");
    }

    let promoted_journal = append_promoted_journal(&journal, &production, production_digest)?;
    persist(
        &args.output,
        &staging_bytes,
        &qualification_payload,
        &qualification_bytes,
        &report_bytes,
        &production_bytes,
        &promoted_journal,
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.promote-result/v1",
        "release_id": summary.release_id,
        "bundle_digest": bundle_digest,
        "production_receipt_digest": production_digest,
        "publication_id": production.operation_id,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Promoted and publicly verified release {} as production publication {}",
        summary.release_id, production.operation_id
    ));
    Ok(())
}

fn key_map(specifications: &[String]) -> Result<BTreeMap<String, [u8; 32]>> {
    Ok(verify::load_trusted_keys(specifications)?
        .into_iter()
        .map(|key| (key.key_id, key.public_key))
        .collect())
}

fn require_qualified_journal(
    journal: &[JournalEntryV1],
    plan_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
) -> Result<()> {
    if aos_release::verify::verify_journal(journal)? != ReleaseState::Qualified {
        bail!("promotion requires a journal in the qualified state");
    }
    let latest = journal.last().context("release journal is empty")?;
    if latest.plan_digest != plan_digest || latest.manifest_digest != Some(manifest_digest) {
        bail!("qualified journal does not bind the exact release bundle");
    }
    Ok(())
}

fn append_promoted_journal(
    journal: &[JournalEntryV1],
    receipt: &PublicationReceiptV1,
    receipt_digest: Sha256Digest,
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
        prior_state: Some(ReleaseState::Qualified),
        new_state: ReleaseState::Promoted,
        operation_ids: vec![receipt.operation_id.clone()],
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

fn persist(
    output: &Path,
    staging: &[u8],
    qualification: &[u8],
    signed_qualification: &[u8],
    report: &[u8],
    production: &[u8],
    journal: &[u8],
) -> Result<()> {
    if output.exists() {
        bail!("promotion output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-promote-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    for (name, bytes) in [
        ("staging-receipt.json", staging),
        ("qualification-receipt.json", qualification),
        ("signed-qualification.json", signed_qualification),
        ("qualification-report.json", report),
        ("production-receipt.json", production),
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
    fn promotion_output_never_replaces_existing_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("promoted");
        persist(
            &output,
            b"stage",
            b"qualification",
            b"signed",
            b"report",
            b"production",
            b"journal",
        )?;
        assert!(
            persist(
                &output, b"other", b"other", b"other", b"other", b"other", b"other"
            )
            .is_err()
        );
        assert_eq!(
            fs::read(output.join("production-receipt.json"))?,
            b"production"
        );
        Ok(())
    }
}
