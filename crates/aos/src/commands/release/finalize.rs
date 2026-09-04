//! Atomic release-bundle closure and threshold manifest signing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::manifest::{
    MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1, ManifestSignature, ReleaseManifestV1,
};
use aos_release::plan::ReleasePlanV1;
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignerRole, SigningContext, SigningOperation, SigningRequestV1,
    TrustedEd25519Key,
};
use aos_release::state::{JournalEntryV1, ReleaseState, parse_journal};
use aos_release::verify::CapturedFile;

use crate::cli::ReleaseFinalizeArgs;

use super::capture;
use super::signer::ExternalSigner;
use super::verify;

/// Closes a payload tree, signs its manifest threshold, and advances Built to Finalized.
pub(super) async fn run(
    args: &ReleaseFinalizeArgs,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    require_utc(&args.recorded_at)?;
    if args.output.exists() {
        bail!(
            "release finalization output already exists: {}",
            args.output.display()
        );
    }

    let plan_bytes = read_canonical(&args.plan, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    let manifest_bytes = read_canonical(&args.manifest_payload, "manifest payload")?;
    let manifest: ReleaseManifestV1 = canonical::from_slice(&manifest_bytes, "manifest payload")?;
    manifest.validate(&plan)?;
    if manifest.plan_digest != plan_digest {
        bail!("manifest payload does not bind the exact release plan bytes");
    }

    let journal_bytes = capture::control_file(&args.journal, "release journal")?;
    let mut journal = parse_journal(&journal_bytes)?;
    if aos_release::verify::verify_journal(&journal)? != ReleaseState::Built
        || journal.last().map(|entry| entry.plan_digest) != Some(plan_digest)
    {
        bail!("release finalization requires the matching Built-state journal");
    }

    let trusted_keys = verify::load_trusted_keys(&args.signing_keys)?;
    let identities = parse_identities(&args.verification_identities)?;
    let requirement = release_requirement(&plan, &trusted_keys, &identities)?;
    let external = ExternalSigner::new(
        args.signer_executable.clone(),
        Duration::from_secs(args.signer_timeout_seconds),
    )?;

    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-finalize-")
        .tempdir_in(parent)?;
    let sealed = temporary.path().join("sealed");
    fs::create_dir(&sealed)?;
    let bundle = sealed.join("bundle");
    let mut captured = capture::copy_payload_tree(&args.payload, &bundle)?;
    write_new(&bundle.join("release-plan.json"), &plan_bytes)?;
    captured.push(CapturedFile {
        path: aos_release::artifact::BundlePath::parse("release-plan.json")?,
        size_bytes: u64::try_from(plan_bytes.len())?,
        sha256: plan_digest,
    });
    require_manifest_closure(&manifest, &captured)?;

    let payload_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &manifest)?;
    let mut signatures = Vec::with_capacity(trusted_keys.len());
    let mut nonces = BTreeSet::new();
    for key in &trusted_keys {
        let nonce = fresh_nonce(&mut nonces)?;
        let request = SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_string(),
            request_id: format!("manifest-{}", &nonce[..24]),
            nonce,
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest,
            manifest_digest: Some(payload_digest),
            role: SignerRole::ReleaseEvidence,
            key_id: key.key_id.clone(),
            provider_revision: requirement.provider_revision.clone(),
            algorithm: aos_release::signing::SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Payload {
                artifact_kind: "release-manifest".to_string(),
            },
            payload_digest,
            approval_policy_digest: plan.restricted_operator_policy_digest,
        };
        let response = external
            .sign_ed25519(
                &request,
                &manifest_bytes,
                key,
                identities
                    .get(&key.key_id)
                    .context("manifest signer lacks its pinned provider identity")?,
            )
            .await?;
        signatures.push(ManifestSignature { request, response });
    }
    let envelope = ManifestEnvelopeV1 {
        schema_version: MANIFEST_ENVELOPE_V1.to_string(),
        payload: manifest,
        payload_digest,
        signatures,
    };
    let envelope_bytes = canonical::to_vec(&envelope)?;
    write_new(&bundle.join("release-manifest.json"), &envelope_bytes)?;

    let captured_bundle = capture::bundle(&bundle)?;
    aos_release::verify::verify_release(
        &captured_bundle.plan_bytes,
        &captured_bundle.manifest_bytes,
        &captured_bundle.files,
        &trusted_keys,
    )?;
    append_finalized_journal(
        &mut journal,
        plan_digest,
        payload_digest,
        &args.recorded_at,
        &envelope,
    )?;
    let finalized_journal = encode_journal(&journal)?;
    write_new(&sealed.join("release-journal.jsonl"), &finalized_journal)?;

    File::open(&bundle)?.sync_all()?;
    File::open(&sealed)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &sealed,
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.finalization-result/v1",
        "release_id": plan.release_id,
        "manifest_digest": payload_digest,
        "bundle": args.output.join("bundle"),
        "journal": args.output.join("release-journal.jsonl"),
        "signatures": trusted_keys.len(),
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Finalized release {} with {} manifest signatures at {}",
        plan.release_id,
        trusted_keys.len(),
        args.output.display()
    ));
    Ok(())
}

fn read_canonical(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = capture::control_file(path, label)?;
    canonical::require_canonical(&bytes, label)?;
    Ok(bytes)
}

fn require_manifest_closure(manifest: &ReleaseManifestV1, files: &[CapturedFile]) -> Result<()> {
    let captured = files
        .iter()
        .map(|file| (file.path.as_str(), (file.size_bytes, file.sha256)))
        .collect::<BTreeMap<_, _>>();
    if captured.len() != files.len() || manifest.artifacts.len() != captured.len() {
        bail!("manifest artifact count differs from the captured payload closure");
    }
    for artifact in &manifest.artifacts {
        let Some((size, digest)) = captured.get(artifact.path.as_str()) else {
            bail!(
                "manifest artifact {} is absent from the payload tree",
                artifact.id
            );
        };
        if artifact.size_bytes != *size || artifact.sha256 != *digest {
            bail!(
                "manifest artifact {} differs from captured payload bytes",
                artifact.id
            );
        }
    }
    Ok(())
}

fn parse_identities(values: &[String]) -> Result<BTreeMap<String, String>> {
    let mut identities = BTreeMap::new();
    for value in values {
        let (key_id, identity) = value
            .split_once('=')
            .context("verification identity must use KEY_ID=IDENTITY")?;
        if key_id.is_empty()
            || identity.is_empty()
            || identities
                .insert(key_id.to_string(), identity.to_string())
                .is_some()
        {
            bail!("verification identities require unique nonempty key ids and identities");
        }
    }
    Ok(identities)
}

fn release_requirement<'a>(
    plan: &'a ReleasePlanV1,
    keys: &[TrustedEd25519Key],
    identities: &BTreeMap<String, String>,
) -> Result<&'a aos_release::signing::SignerRequirement> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .context("release plan lacks the release-evidence signer policy")?;
    if keys.len() != usize::from(requirement.threshold)
        || identities.len() != keys.len()
        || keys.iter().any(|key| {
            !requirement.key_ids.contains(&key.key_id) || !identities.contains_key(&key.key_id)
        })
    {
        bail!("manifest signers do not exactly satisfy the release-evidence threshold");
    }
    Ok(requirement)
}

fn fresh_nonce(seen: &mut BTreeSet<String>) -> Result<String> {
    for _ in 0..8 {
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        if seen.insert(nonce.clone()) {
            return Ok(nonce);
        }
    }
    bail!("could not allocate a unique manifest signer nonce")
}

fn append_finalized_journal(
    journal: &mut Vec<JournalEntryV1>,
    plan_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    recorded_at: &str,
    envelope: &ManifestEnvelopeV1,
) -> Result<()> {
    let previous = journal.last().context("release journal is empty")?;
    let previous_digest = Sha256Digest::of_canonical("aos.release.journal-entry/v1", previous)?;
    let entry = JournalEntryV1 {
        schema_version: aos_release::RELEASE_JOURNAL_ENTRY_V1.to_string(),
        sequence: u64::try_from(journal.len())?
            .checked_add(1)
            .context("journal sequence overflow")?,
        previous_entry_digest: Some(previous_digest),
        plan_digest,
        manifest_digest: Some(manifest_digest),
        prior_state: Some(ReleaseState::Built),
        new_state: ReleaseState::Finalized,
        operation_ids: envelope
            .signatures
            .iter()
            .map(|signature| signature.response.provider_operation_id.clone())
            .collect(),
        evidence: envelope
            .signatures
            .iter()
            .map(|signature| {
                Sha256Digest::of_canonical("aos.release.signature-response/v1", &signature.response)
            })
            .collect::<Result<Vec<_>>>()?,
        recorded_at: recorded_at.to_string(),
    };
    entry.validate()?;
    journal.push(entry);
    aos_release::verify::verify_journal(journal)?;
    Ok(())
}

fn encode_journal(entries: &[JournalEntryV1]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(canonical::to_vec(entry)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_utc(value: &str) -> Result<()> {
    if !value.ends_with('Z') {
        bail!("release finalization time must be RFC 3339 UTC");
    }
    humantime::parse_rfc3339(value).context("parsing release finalization time")?;
    Ok(())
}
