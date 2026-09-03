//! Restricted renewal of TUF timestamp metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignerRole, SigningContext, SigningOperation,
    SigningRequestV1, TrustedEd25519Key,
};
use aos_release::tuf::{
    RootMetadataV1, SnapshotMetadataV1, TufEnvelopeV1, TufRole, TufRootTrust, TufSignatureV1,
    metadata_signing_digest, timestamp_metadata, verify_prior_timestamp_for_refresh,
    verify_root_envelope, verify_snapshot_envelope, verify_timestamp,
};
use base64::Engine as _;

use crate::cli::{ReleaseTimestampCommand, ReleaseTimestampRefreshArgs};

use super::capture;
use super::signer::ExternalSigner;
use super::verify;

pub(super) async fn run(command: &ReleaseTimestampCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseTimestampCommand::Refresh(args) => refresh(args, printer).await,
    }
}

async fn refresh(args: &ReleaseTimestampRefreshArgs, printer: &Printer) -> Result<()> {
    let plan_bytes = capture::control_file(&args.plan, "release plan")?;
    canonical::require_canonical(&plan_bytes, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);

    let root: TufEnvelopeV1<RootMetadataV1> = read_canonical(&args.root, "TUF root")?;
    let snapshot: TufEnvelopeV1<SnapshotMetadataV1> =
        read_canonical(&args.snapshot, "TUF snapshot")?;
    let bootstrap_keys = verify::load_trusted_keys(&args.trusted_root_keys)?;
    let _ = parse_utc(&args.issued_at, "timestamp issuance")?;
    let now = SystemTime::now();
    verify_root_envelope(
        &root,
        &TufRootTrust {
            keys: &bootstrap_keys,
            threshold: args.trusted_root_threshold,
        },
        None,
        now,
    )?;
    verify_snapshot_envelope(&snapshot, &root.signed, now)?;

    let previous = args
        .previous_timestamp
        .as_ref()
        .map(|path| read_canonical(path, "prior TUF timestamp"))
        .transpose()?;
    let previous_version = if let Some(previous) = &previous {
        verify_prior_timestamp_for_refresh(previous, &root.signed, &snapshot)?;
        if args.version != previous.signed.version.saturating_add(1) {
            bail!("timestamp refresh version must increase by exactly one");
        }
        Some(previous.signed.version)
    } else {
        if args.version != 1 {
            bail!("first timestamp version must be one");
        }
        None
    };

    let signed = timestamp_metadata(
        args.version,
        args.issued_at.clone(),
        args.expires.clone(),
        &snapshot,
    )?;
    let signing_keys = timestamp_signing_keys(&root.signed, &plan, &args.signing_keys)?;
    let signer = ExternalSigner::new(
        args.signer_executable.clone(),
        Duration::from_secs(args.signer_timeout_seconds),
    )?;
    let payload = canonical::to_vec(&signed)?;
    let payload_digest = metadata_signing_digest(TufRole::Timestamp, &signed)?;
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::TufTimestamp)
        .context("release plan lacks the timestamp signer policy")?;
    let mut signatures = Vec::with_capacity(signing_keys.len());
    let mut nonces = BTreeSet::new();
    for (key, identity) in signing_keys {
        let nonce = fresh_nonce(&mut nonces)?;
        let request = SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_owned(),
            request_id: format!("timestamp-{}", &nonce[..20]),
            nonce,
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest,
            manifest_digest: None,
            role: SignerRole::TufTimestamp,
            key_id: key.key_id.clone(),
            provider_revision: requirement.provider_revision.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Tuf {
                metadata_role: "timestamp".to_owned(),
                metadata_version: args.version,
            },
            payload_digest,
            approval_policy_digest: plan.restricted_operator_policy_digest,
        };
        let response = signer
            .sign_ed25519(&request, &payload, &key, &identity)
            .await?;
        signatures.push(TufSignatureV1 { request, response });
    }
    let envelope = TufEnvelopeV1 { signed, signatures };
    verify_timestamp(&envelope, &root.signed, &snapshot, previous_version, now)?;
    write_new(&args.output, &canonical::to_vec(&envelope)?)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.timestamp-refresh-result/v1",
        "version": envelope.signed.version,
        "snapshot_version": snapshot.signed.version,
        "signature_count": envelope.signatures.len(),
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Signed timestamp {} for snapshot {} at {}",
        envelope.signed.version,
        snapshot.signed.version,
        args.output.display()
    ));
    Ok(())
}

fn timestamp_signing_keys(
    root: &RootMetadataV1,
    plan: &ReleasePlanV1,
    specifications: &[String],
) -> Result<Vec<(TrustedEd25519Key, String)>> {
    let policy = root
        .roles
        .iter()
        .find(|policy| policy.role == TufRole::Timestamp)
        .context("TUF root lacks the timestamp role")?;
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::TufTimestamp)
        .context("release plan lacks the timestamp signer policy")?;
    let mut root_ids = policy.key_ids.clone();
    let mut plan_ids = requirement.key_ids.clone();
    root_ids.sort();
    plan_ids.sort();
    if root_ids != plan_ids || policy.threshold != requirement.threshold {
        bail!("release plan and TUF root timestamp policies differ");
    }
    if specifications.len() != usize::from(policy.threshold) {
        bail!("timestamp signing requires exactly its threshold of key specifications");
    }

    let paths = parse_key_paths(specifications)?;
    let mut keys = Vec::with_capacity(paths.len());
    for (key_id, path) in paths {
        if !policy.key_ids.contains(&key_id) {
            bail!("timestamp signing key is outside the root role policy");
        }
        let declared = root
            .keys
            .iter()
            .find(|key| key.key_id == key_id)
            .context("timestamp role references an absent root key")?;
        let declared_bytes = base64::engine::general_purpose::STANDARD
            .decode(&declared.public_key_base64)
            .context("decoding root timestamp public key")?;
        let trusted = TrustedEd25519Key::from_encoded(
            key_id,
            &capture::control_file(&path, "timestamp public key")?,
        )?;
        if trusted.public_key.as_slice() != declared_bytes {
            bail!("timestamp public key differs from trusted root metadata");
        }
        keys.push((trusted, declared.verification_identity.clone()));
    }
    Ok(keys)
}

fn parse_key_paths(values: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut paths = BTreeMap::new();
    for value in values {
        let (key_id, path) = value
            .split_once('=')
            .context("key specification must use KEY_ID=PATH")?;
        if key_id.is_empty()
            || path.is_empty()
            || paths
                .insert(key_id.to_owned(), PathBuf::from(path))
                .is_some()
        {
            bail!("key specifications must contain unique nonempty key ids and paths");
        }
    }
    Ok(paths)
}

fn fresh_nonce(seen: &mut BTreeSet<String>) -> Result<String> {
    for _ in 0..8 {
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        if seen.insert(nonce.clone()) {
            return Ok(nonce);
        }
    }
    bail!("could not allocate a unique timestamp signer nonce")
}

fn read_canonical<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let bytes = capture::control_file(path, label)?;
    canonical::require_canonical(&bytes, label)?;
    canonical::from_slice(&bytes, label)
}

fn parse_utc(value: &str, label: &str) -> Result<std::time::SystemTime> {
    if !value.ends_with('Z') {
        bail!("{label} must be RFC 3339 UTC");
    }
    humantime::parse_rfc3339(value).with_context(|| format!("parsing {label}"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_paths_reject_duplicates() {
        assert!(parse_key_paths(&["key-1=/a".to_owned(), "key-1=/b".to_owned()]).is_err());
    }
}
