//! Exact-byte publication to the canonical isolated staging Hub.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{PublicationReceiptV1, verify_signed_receipt};
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
use aos_remote::hub::HubClient;
use aos_remote::hub::hub_rpc;
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};

use crate::cli::{HubAccessArgs, ReleaseStageArgs};

use super::{capture, verify};

const STAGING_HUB: &str = "https://aos.staging.andyl.org";
const DEPLOYMENT_ID_PATH: &str = "/.well-known/aos-deployment";
const MAX_DEPLOYMENT_ID_BYTES: usize = 1024;

/// Verifies, uploads, publicly reads back, and receipts one staging bundle.
pub(super) async fn run(args: &ReleaseStageArgs, printer: &Printer) -> Result<()> {
    let captured = capture::bundle(&args.bundle)?;
    let trusted_keys = verify::load_trusted_keys(&args.trusted_keys)?;
    let summary = aos_release::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &trusted_keys,
    )?;
    let plan: aos_release::plan::ReleasePlanV1 =
        canonical::from_slice(&captured.plan_bytes, "release plan")?;
    let journal_bytes = capture::control_file(&args.journal, "release journal")?;
    let journal = parse_journal(&journal_bytes)?;
    require_finalized_journal(&journal, summary.plan_digest, summary.manifest_digest)?;

    let public_client = public_client()?;
    verify_deployment(&public_client, &plan.staging_deployment_id).await?;
    let access = HubAccessArgs {
        hub: Some(STAGING_HUB.to_owned()),
        token: args.token.clone(),
    };
    let publication = crate::commands::hub::upload_registry_publication(
        &access,
        &plan.registry,
        None,
        &args.bundle,
        printer,
    )
    .await?;
    if publication.state != "ready" || publication.completed_at <= 0 {
        bail!("staging Hub did not return a completed ready publication");
    }
    verify_deployment(&public_client, &plan.staging_deployment_id).await?;
    read_back_publication(&public_client, &plan.registry, &publication).await?;
    let bundle_digest =
        aos_release::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;
    let backing_publication_id = publication.parent_publication_id.as_str();
    if backing_publication_id.is_empty() {
        bail!("staging release publication has no compare-and-swap base publication");
    }
    let token = args
        .token
        .as_deref()
        .context("staging requires an access token")?;
    let hub = HubClient::connect_with_token(STAGING_HUB, token)?;
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
            backing_publication_id: backing_publication_id.to_owned(),
        },
    )
    .await?;
    let signed = hub
        .call_topology(
            hub_rpc::CommitReleasePublication,
            &aos_proto_types::CommitReleasePublicationRequest {
                registry: plan.registry.clone(),
                bundle_digest: bundle_digest.to_string(),
                environment: "staging".into(),
                publication_id: publication.publication_id.clone(),
                expected_deployment_id: plan.staging_deployment_id.clone(),
                staging_receipt_digest: String::new(),
            },
        )
        .await?;
    let receipt_bytes = signed.signed_receipt_json.into_bytes();
    if Sha256Digest::of_bytes(&receipt_bytes).to_string() != signed.receipt_digest {
        bail!("staging Hub receipt digest does not match its signed bytes");
    }
    let receipt_keys = trusted_keys
        .iter()
        .map(|key| (key.key_id.clone(), key.public_key))
        .collect::<BTreeMap<_, _>>();
    let receipt: PublicationReceiptV1 = verify_signed_receipt(&receipt_bytes, &receipt_keys)?;
    receipt.validate()?;
    if receipt.deployment_id != plan.staging_deployment_id
        || receipt.registry != plan.registry
        || receipt.release_id != summary.release_id
        || receipt.manifest_digest != summary.manifest_digest
        || receipt.bundle_digest != bundle_digest
        || receipt.operation_id != publication.publication_id
    {
        bail!("staging Hub receipt does not bind the exact release publication");
    }
    let staged_journal =
        append_staged_journal(&journal, &receipt, Sha256Digest::of_bytes(&receipt_bytes))?;
    persist_stage_tree(&args.output, &receipt_bytes, &staged_journal)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.stage-result/v1",
        "release_id": receipt.release_id,
        "manifest_digest": receipt.manifest_digest,
        "bundle_digest": receipt.bundle_digest,
        "publication_id": receipt.operation_id,
        "deployment_id": receipt.deployment_id,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Staged and publicly verified release {} as publication {}",
        receipt.release_id, receipt.operation_id
    ));
    Ok(())
}

fn public_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
        .context("building staging public read-back client")
}

async fn verify_deployment(client: &reqwest::Client, expected: &str) -> Result<()> {
    let url = format!("{STAGING_HUB}{DEPLOYMENT_ID_PATH}");
    let response = client.get(&url).send().await?.error_for_status()?;
    let header = response
        .headers()
        .get("x-aos-deployment-id")
        .context("staging deployment response lacks its identity header")?
        .to_str()
        .context("staging deployment identity header is not ASCII")?
        .to_owned();
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_DEPLOYMENT_ID_BYTES {
        bail!("staging deployment identity response is oversized");
    }
    let body = std::str::from_utf8(&bytes)
        .context("staging deployment identity is not UTF-8")?
        .trim();
    if header != expected || body != expected {
        bail!("staging Hub deployment identity does not match the release plan");
    }
    Ok(())
}

async fn read_back_publication(
    client: &reqwest::Client,
    registry: &str,
    publication: &aos_remote::hub_types::RegistryPublication,
) -> Result<()> {
    let base = url::Url::parse(&format!("{STAGING_HUB}/{registry}/"))?;
    for object in &publication.objects {
        if !object.verified || object.byte_size < 0 {
            bail!("staging publication contains an unverified object");
        }
        aos_release::artifact::BundlePath::parse(&object.path)
            .context("staging Hub returned an invalid publication path")?;
        let url = base.join(&object.path)?;
        if !url.as_str().starts_with(base.as_str()) {
            bail!("staging Hub returned a path outside the registry surface");
        }
        let response = client.get(url).send().await?.error_for_status()?;
        let mut stream = response.bytes_stream();
        let mut digest = Sha256::new();
        let mut size = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size = size
                .checked_add(u64::try_from(chunk.len())?)
                .context("public read-back size overflowed")?;
            if size > u64::try_from(object.byte_size)? {
                bail!("public read-back object is larger than its declaration");
            }
            digest.update(&chunk);
        }
        let found = format!("{:x}", digest.finalize());
        if size != u64::try_from(object.byte_size)? || found != object.sha256 {
            bail!("public read-back differs for {}", object.path);
        }
    }
    Ok(())
}

fn require_finalized_journal(
    journal: &[JournalEntryV1],
    plan_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
) -> Result<()> {
    if aos_release::verify::verify_journal(journal)? != ReleaseState::Finalized {
        bail!("staging requires a journal in the finalized state");
    }
    let latest = journal.last().context("release journal is empty")?;
    if latest.plan_digest != plan_digest || latest.manifest_digest != Some(manifest_digest) {
        bail!("finalized journal does not bind the exact release bundle");
    }
    Ok(())
}

fn append_staged_journal(
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
        prior_state: Some(ReleaseState::Finalized),
        new_state: ReleaseState::Staged,
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

fn persist_stage_tree(output: &Path, receipt: &[u8], journal: &[u8]) -> Result<()> {
    if output.exists() {
        bail!(
            "staging evidence output already exists: {}",
            output.display()
        );
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-stage-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    write_synced(&root.join("staging-receipt.json"), receipt)?;
    write_synced(&root.join("release-journal.jsonl"), journal)?;
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

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_entry(state: ReleaseState, manifest: Option<Sha256Digest>) -> JournalEntryV1 {
        JournalEntryV1 {
            schema_version: aos_release::RELEASE_JOURNAL_ENTRY_V1.to_owned(),
            sequence: 1,
            previous_entry_digest: None,
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: manifest,
            prior_state: None,
            new_state: state,
            operation_ids: Vec::new(),
            evidence: Vec::new(),
            recorded_at: "2026-09-03T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn staging_rejects_a_nonfinalized_journal() {
        let entry = journal_entry(ReleaseState::Planned, None);
        assert!(
            require_finalized_journal(
                &[entry],
                Sha256Digest::of_bytes("plan"),
                Sha256Digest::of_bytes("manifest")
            )
            .is_err()
        );
    }

    #[test]
    fn stage_output_never_replaces_existing_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("staged");
        persist_stage_tree(&output, b"receipt", b"journal")?;
        assert!(persist_stage_tree(&output, b"other", b"other").is_err());
        assert_eq!(fs::read(output.join("staging-receipt.json"))?, b"receipt");
        Ok(())
    }
}
