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

use aos_remote::hub::{HubClient, hub_rpc};

use crate::cli::{
    HubAccessArgs, ReleaseTimestampCommand, ReleaseTimestampPublishArgs,
    ReleaseTimestampRefreshArgs,
};

use super::capture;
use super::hub_transition;
use super::signer::ExternalSigner;
use super::verify;

pub(super) async fn run(command: &ReleaseTimestampCommand, printer: &Printer) -> Result<()> {
    match command {
        ReleaseTimestampCommand::Refresh(args) => refresh(args, printer).await,
        ReleaseTimestampCommand::Publish(args) => publish(args, printer).await,
    }
}

const PRODUCTION_HUB: &str = "https://aos.andyl.org";

async fn publish(args: &ReleaseTimestampPublishArgs, printer: &Printer) -> Result<()> {
    let plan: ReleasePlanV1 = read_canonical(&args.plan, "release plan")?;
    plan.require_publishable_qualification()?;
    let root: TufEnvelopeV1<RootMetadataV1> = read_canonical(&args.root, "TUF root")?;
    let snapshot: TufEnvelopeV1<SnapshotMetadataV1> =
        read_canonical(&args.snapshot, "TUF snapshot")?;
    let timestamp: TufEnvelopeV1<aos_release::tuf::TimestampMetadataV1> =
        read_canonical(&args.timestamp, "TUF timestamp")?;
    let bootstrap_keys = verify::load_trusted_keys(&args.trusted_root_keys)?;
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
    if root.signed.registry != plan.registry {
        bail!("TUF root registry differs from the release plan");
    }
    verify_snapshot_envelope(&snapshot, &root.signed, now)?;
    verify_timestamp(
        &timestamp,
        &root.signed,
        &snapshot,
        (args.previous_version > 0).then_some(args.previous_version),
        now,
    )?;
    let expected_version = args
        .previous_version
        .checked_add(1)
        .context("timestamp publication version overflowed")?;
    if timestamp.signed.version != expected_version {
        bail!("timestamp publication version must increase by exactly one");
    }

    let timestamp_bytes = canonical::to_vec(&timestamp)?;
    let snapshot_bytes = canonical::to_vec(&snapshot)?;
    let timestamp_digest = Sha256Digest::of_bytes(&timestamp_bytes);
    let snapshot_digest = Sha256Digest::of_bytes(&snapshot_bytes);
    let timestamp_path = "tuf/timestamp.json";
    let snapshot_path = format!("tuf/{}.snapshot.json", snapshot.signed.version);
    require_surface_bytes(&args.registry_surface, timestamp_path, &timestamp_bytes)?;
    require_surface_bytes(&args.registry_surface, &snapshot_path, &snapshot_bytes)?;

    let public_client = hub_transition::public_client()?;
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;
    let access = HubAccessArgs {
        hub: Some(PRODUCTION_HUB.into()),
        token: args.token.clone(),
    };
    let publication = crate::commands::hub::prepare_registry_publication(
        &access,
        &plan.registry,
        None,
        &args.registry_surface,
        printer,
    )
    .await?;
    if !matches!(publication.state.as_str(), "preparing" | "writing_pointers") {
        bail!("production Hub did not retain the timestamp publication for atomic commit");
    }
    require_publication_object(
        &publication,
        timestamp_path,
        "mutable_pointer",
        timestamp_digest,
        timestamp_bytes.len(),
    )?;
    require_publication_object(
        &publication,
        &snapshot_path,
        "immutable",
        snapshot_digest,
        snapshot_bytes.len(),
    )?;
    let token = args
        .token
        .as_deref()
        .context("timestamp publication requires a production access token")?;
    let hub = HubClient::connect_with_token(PRODUCTION_HUB, token)?;
    let state = hub
        .call_topology(
            hub_rpc::PublishReleaseTimestamp,
            &aos_proto_types::PublishReleaseTimestampRequest {
                registry: plan.registry.clone(),
                snapshot_digest: snapshot_digest.to_string(),
                snapshot_version: i64::try_from(snapshot.signed.version)?,
                timestamp_version: i64::try_from(timestamp.signed.version)?,
                timestamp_digest: timestamp_digest.to_string(),
                publication_id: publication.publication_id.clone(),
                timestamp_path: timestamp_path.into(),
                snapshot_path: snapshot_path.clone(),
            },
        )
        .await?;
    if state.snapshot_digest != snapshot_digest.to_string()
        || state.snapshot_version != i64::try_from(snapshot.signed.version)?
        || state.timestamp_version != i64::try_from(timestamp.signed.version)?
        || state.timestamp_digest != timestamp_digest.to_string()
    {
        bail!("Hub timestamp state differs from the exact signed metadata");
    }
    let publication = hub
        .call_topology(
            hub_rpc::GetRegistryPublication,
            &aos_proto_types::GetRegistryPublicationRequest {
                publication_id: publication.publication_id.clone(),
            },
        )
        .await?;
    if publication.state != "ready" || publication.completed_at <= 0 {
        bail!("production Hub did not atomically commit the timestamp publication");
    }
    hub_transition::read_back_publication(
        &public_client,
        PRODUCTION_HUB,
        &plan.registry,
        &publication,
    )
    .await?;
    hub_transition::verify_deployment(
        &public_client,
        PRODUCTION_HUB,
        &plan.production_deployment_id,
    )
    .await?;
    persist_publication(args, &timestamp_bytes, &state, &publication.publication_id)?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.timestamp-publish-result/v1",
        "timestamp_version": timestamp.signed.version,
        "timestamp_digest": timestamp_digest,
        "snapshot_version": snapshot.signed.version,
        "snapshot_digest": snapshot_digest,
        "publication_id": publication.publication_id,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Published and publicly verified timestamp {} as {}",
        timestamp.signed.version, publication.publication_id
    ));
    Ok(())
}

fn require_surface_bytes(root: &Path, relative: &str, expected: &[u8]) -> Result<()> {
    let path = root.join(relative);
    let bytes = capture::control_file(&path, "timestamp registry surface object")?;
    if bytes != expected {
        bail!("registry surface object {relative} differs from the verified metadata");
    }
    Ok(())
}

fn require_publication_object(
    publication: &aos_remote::hub_types::RegistryPublication,
    path: &str,
    kind: &str,
    digest: Sha256Digest,
    size: usize,
) -> Result<()> {
    let object = publication
        .objects
        .iter()
        .find(|object| object.path == path)
        .with_context(|| format!("Hub publication lacks {path}"))?;
    if !object.verified
        || object.kind != kind
        || object.sha256 != digest.hex()
        || object.byte_size != i64::try_from(size)?
    {
        bail!("Hub publication object {path} differs from signed metadata");
    }
    Ok(())
}

fn persist_publication(
    args: &ReleaseTimestampPublishArgs,
    timestamp: &[u8],
    state: &aos_proto_types::ReleaseTimestampState,
    publication_id: &str,
) -> Result<()> {
    if args.output.exists() {
        bail!(
            "timestamp publication output already exists: {}",
            args.output.display()
        );
    }
    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-timestamp-publish-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    write_new(&root.join("timestamp.json"), timestamp)?;
    let evidence = canonical::to_vec(&serde_json::json!({
        "schema_version": "aos.release.timestamp-publication-evidence/v1",
        "publication_id": publication_id,
        "snapshot_digest": state.snapshot_digest,
        "snapshot_version": state.snapshot_version,
        "timestamp_digest": state.timestamp_digest,
        "timestamp_version": state.timestamp_version,
    }))?;
    write_new(&root.join("publication-evidence.json"), &evidence)?;
    File::open(&root)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &root,
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(())
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
    if root.signed.registry != plan.registry {
        bail!("TUF root registry differs from the release plan");
    }
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
        &plan.registry,
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

    #[test]
    fn timestamp_publication_requires_exact_declared_object() {
        let bytes = b"timestamp";
        let digest = Sha256Digest::of_bytes(bytes);
        let publication = aos_remote::hub_types::RegistryPublication {
            objects: vec![aos_remote::hub_types::RegistryPublicationObject {
                path: "tuf/timestamp.json".into(),
                kind: "mutable_pointer".into(),
                sha256: digest.hex(),
                byte_size: i64::try_from(bytes.len()).unwrap(),
                verified: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            require_publication_object(
                &publication,
                "tuf/timestamp.json",
                "mutable_pointer",
                digest,
                bytes.len(),
            )
            .is_ok()
        );
        assert!(
            require_publication_object(
                &publication,
                "tuf/timestamp.json",
                "immutable",
                digest,
                bytes.len(),
            )
            .is_err()
        );
    }
}
