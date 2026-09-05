//! Immutable role-separated TUF repository metadata construction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::manifest::ManifestEnvelopeV1;
use aos_release::plan::ReleasePlanV1;
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignerRequirement, SigningContext, SigningOperation, SigningRequestV1,
    TrustedEd25519Key,
};
use aos_release::tuf::{
    ImmutableTufSetV1, RootMetadataV1, TufEnvelopeV1, TufReleaseExpectation, TufReleaseTargetV1,
    TufRole, TufRolePolicyV1, TufRootTrust, TufSignatureV1, TufTargetFileV1,
    canonical_targets_metadata, delegated_release_metadata, immutable_snapshot_metadata,
    metadata_signing_digest, verify_immutable_set, verify_root_envelope,
};
use base64::Engine as _;
use serde::Serialize;

use crate::cli::ReleaseTufArgs;

use super::capture;
use super::signer::ExternalSigner;
use super::verify;

/// Constructs and verifies one immutable metadata set around a finalized bundle.
pub(super) async fn run(args: &ReleaseTufArgs, printer: &aos_core::output::Printer) -> Result<()> {
    if args.output.exists() {
        bail!(
            "TUF metadata output already exists: {}",
            args.output.display()
        );
    }
    let now = parse_utc(&args.now, "TUF verification time")?;
    let plan_bytes = read_canonical(&args.plan, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);

    let captured_bundle = capture::bundle(&args.bundle)?;
    if captured_bundle.plan_bytes != plan_bytes {
        bail!("TUF bundle carries different release plan bytes");
    }
    let manifest_keys = verify::load_trusted_keys(&args.manifest_keys)?;
    let summary = aos_release::verify::verify_release(
        &captured_bundle.plan_bytes,
        &captured_bundle.manifest_bytes,
        &captured_bundle.files,
        &manifest_keys,
    )?;
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured_bundle.manifest_bytes, "release manifest")?;
    // The record is optional metadata beside the manifest; when supplied it
    // must already describe this exact manifest so the delegated role never
    // authorizes a record for a different release.
    let release_record = args
        .release_record
        .as_deref()
        .map(|path| -> Result<(Vec<u8>, String)> {
            let bytes = capture::control_file(path, "release record")?;
            canonical::require_canonical(&bytes, "release record")?;
            let record: aos_release::record::ReleaseRecordV1 =
                canonical::from_slice(&bytes, "release record")?;
            record.validate()?;
            if record.manifest_digest != summary.manifest_digest
                || record.release_id != plan.release_id
                || record.version != plan.version
            {
                bail!("release record does not describe the authorized manifest");
            }
            Ok((
                bytes,
                aos_release::record::record_path(plan.release_class, &plan.version),
            ))
        })
        .transpose()?;

    let root_bytes = read_canonical(&args.root, "TUF root")?;
    let root: TufEnvelopeV1<RootMetadataV1> = canonical::from_slice(&root_bytes, "TUF root")?;
    let previous_root = args
        .previous_root
        .as_ref()
        .map(|path| read_tuf_root(path, "previous TUF root"))
        .transpose()?;
    let trusted_root_keys = verify::load_trusted_keys(&args.trusted_root_keys)?;
    let root_trust = TufRootTrust {
        keys: &trusted_root_keys,
        threshold: args.trusted_root_threshold,
    };
    verify_root_envelope(&root, &root_trust, previous_root.as_ref(), now)?;
    if root.signed.registry != plan.registry {
        bail!("TUF root registry differs from the release plan");
    }
    require_policy_match(&root.signed, &plan, TufRole::Root)?;
    require_policy_match(&root.signed, &plan, TufRole::Timestamp)?;

    let targets_keys = role_keys(&root.signed, &plan, TufRole::Targets, &args.targets_keys)?;
    let delegated_role = TufRole::for_release(plan.release_class);
    let delegated_keys = role_keys(&root.signed, &plan, delegated_role, &args.delegated_keys)?;
    let snapshot_keys = role_keys(&root.signed, &plan, TufRole::Snapshot, &args.snapshot_keys)?;
    let external = ExternalSigner::new(
        args.signer_executable.clone(),
        Duration::from_secs(args.signer_timeout_seconds),
    )?;
    let mut nonces = BTreeSet::new();

    let targets = sign_metadata(
        canonical_targets_metadata(
            &plan.registry,
            args.targets_version,
            args.targets_expires.clone(),
        )?,
        TufRole::Targets,
        &targets_keys,
        &plan,
        plan_digest,
        manifest.payload_digest,
        &external,
        &mut nonces,
    )
    .await?;
    let manifest_envelope_digest = Sha256Digest::of_bytes(&captured_bundle.manifest_bytes);
    let delegated = sign_metadata(
        delegated_release_metadata(
            &plan.registry,
            args.delegated_version,
            args.delegated_expires.clone(),
            TufReleaseTargetV1 {
                path: format!(
                    "releases/{}/{}/release-manifest.json",
                    delegated_role.as_str(),
                    plan.version
                ),
                release_id: plan.release_id.clone(),
                release_class: plan.release_class,
                manifest_digest: manifest_envelope_digest,
                length: u64::try_from(captured_bundle.manifest_bytes.len())?,
                record: release_record
                    .as_ref()
                    .map(|(bytes, path)| TufTargetFileV1 {
                        path: path.clone(),
                        digest: Sha256Digest::of_bytes(bytes),
                        length: bytes.len() as u64,
                    }),
            },
        )?,
        delegated_role,
        &delegated_keys,
        &plan,
        plan_digest,
        manifest.payload_digest,
        &external,
        &mut nonces,
    )
    .await?;
    let snapshot_unsigned = immutable_snapshot_metadata(
        &plan.registry,
        args.snapshot_version,
        args.snapshot_expires.clone(),
        &root,
        &targets,
        &delegated,
    )?;
    let snapshot = sign_metadata(
        snapshot_unsigned,
        TufRole::Snapshot,
        &snapshot_keys,
        &plan,
        plan_digest,
        manifest.payload_digest,
        &external,
        &mut nonces,
    )
    .await?;
    let set = ImmutableTufSetV1 {
        root: root.clone(),
        targets,
        delegated,
        snapshot,
    };
    verify_immutable_set(
        &set,
        &root_trust,
        previous_root.as_ref(),
        now,
        &TufReleaseExpectation {
            registry: &plan.registry,
            release_id: &plan.release_id,
            release_class: plan.release_class,
            manifest_digest: manifest_envelope_digest,
        },
    )?;

    persist_set(&args.output, &root_bytes, &set)?;
    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.tuf-result/v1",
        "release_id": summary.release_id,
        "manifest_envelope_digest": manifest_envelope_digest,
        "root_version": set.root.signed.version,
        "targets_version": set.targets.signed.version,
        "delegated_role": set.delegated.signed.role,
        "delegated_version": set.delegated.signed.version,
        "snapshot_version": set.snapshot.signed.version,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Authorized release {} in {} TUF metadata at {}",
        plan.release_id,
        delegated_role.as_str(),
        args.output.display()
    ));
    Ok(())
}

async fn sign_metadata<T: Serialize + Clone>(
    signed: T,
    role: TufRole,
    keys: &[(TrustedEd25519Key, String, String)],
    plan: &ReleasePlanV1,
    plan_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    external: &ExternalSigner,
    nonces: &mut BTreeSet<String>,
) -> Result<TufEnvelopeV1<T>> {
    let payload = canonical::to_vec(&signed)?;
    let payload_digest = metadata_signing_digest(role, &signed)?;
    let mut signatures = Vec::with_capacity(keys.len());
    for (key, identity, provider_revision) in keys {
        let nonce = fresh_nonce(nonces)?;
        let request = SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_string(),
            request_id: format!("tuf-{}-{}", role.as_str(), &nonce[..20]),
            nonce,
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest,
            manifest_digest: Some(manifest_digest),
            role: role.signer_role(),
            key_id: key.key_id.clone(),
            provider_revision: provider_revision.clone(),
            algorithm: aos_release::signing::SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Tuf {
                metadata_role: role.as_str().to_string(),
                metadata_version: metadata_version(&signed)?,
            },
            payload_digest,
            approval_policy_digest: plan.restricted_operator_policy_digest,
        };
        let response = external
            .sign_ed25519(&request, &payload, key, identity)
            .await?;
        signatures.push(TufSignatureV1 { request, response });
    }
    Ok(TufEnvelopeV1 { signed, signatures })
}

fn metadata_version<T: Serialize>(metadata: &T) -> Result<u64> {
    let value = serde_json::to_value(metadata)?;
    value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .context("TUF metadata has no integer version")
}

fn role_keys(
    root: &RootMetadataV1,
    plan: &ReleasePlanV1,
    role: TufRole,
    specifications: &[String],
) -> Result<Vec<(TrustedEd25519Key, String, String)>> {
    let policy = root_policy(root, role)?;
    let requirement = plan_requirement(plan, role)?;
    let mut root_ids = policy.key_ids.clone();
    let mut plan_ids = requirement.key_ids.clone();
    root_ids.sort();
    plan_ids.sort();
    if root_ids != plan_ids || policy.threshold != requirement.threshold {
        bail!(
            "release plan and TUF root {} policies differ",
            role.as_str()
        );
    }
    if specifications.len() != usize::from(policy.threshold) {
        bail!(
            "TUF {} signing requires exactly its threshold",
            role.as_str()
        );
    }
    let paths = parse_key_paths(specifications)?;
    let mut keys = Vec::with_capacity(paths.len());
    for (key_id, path) in paths {
        if !policy.key_ids.contains(&key_id) {
            bail!(
                "TUF {} signing key is outside its role policy",
                role.as_str()
            );
        }
        let declared = root
            .keys
            .iter()
            .find(|key| key.key_id == key_id)
            .context("TUF role references an absent root key")?;
        let declared_bytes =
            base64::engine::general_purpose::STANDARD.decode(&declared.public_key_base64)?;
        let trusted = TrustedEd25519Key::from_encoded(
            key_id,
            &capture::control_file(&path, "TUF role public key")?,
        )?;
        if trusted.public_key.as_slice() != declared_bytes {
            bail!("TUF role public key differs from trusted root metadata");
        }
        keys.push((
            trusted,
            declared.verification_identity.clone(),
            requirement.provider_revision.clone(),
        ));
    }
    Ok(keys)
}

fn require_policy_match(root: &RootMetadataV1, plan: &ReleasePlanV1, role: TufRole) -> Result<()> {
    let policy = root_policy(root, role)?;
    let requirement = plan_requirement(plan, role)?;
    let mut root_ids = policy.key_ids.clone();
    let mut plan_ids = requirement.key_ids.clone();
    root_ids.sort();
    plan_ids.sort();
    if root_ids != plan_ids || policy.threshold != requirement.threshold {
        bail!(
            "release plan and TUF root {} policies differ",
            role.as_str()
        );
    }
    Ok(())
}

fn root_policy(root: &RootMetadataV1, role: TufRole) -> Result<&TufRolePolicyV1> {
    root.roles
        .iter()
        .find(|policy| policy.role == role)
        .with_context(|| format!("TUF root lacks {} policy", role.as_str()))
}

fn plan_requirement(plan: &ReleasePlanV1, role: TufRole) -> Result<&SignerRequirement> {
    plan.signers
        .iter()
        .find(|requirement| requirement.role == role.signer_role())
        .with_context(|| format!("release plan lacks {} signer policy", role.as_str()))
}

fn parse_key_paths(values: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut paths = BTreeMap::new();
    for value in values {
        let (key_id, path) = value
            .split_once('=')
            .context("TUF key specification must use KEY_ID=PATH")?;
        if key_id.is_empty()
            || path.is_empty()
            || paths
                .insert(key_id.to_string(), PathBuf::from(path))
                .is_some()
        {
            bail!("TUF key specifications require unique nonempty ids and paths");
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
    bail!("could not allocate a unique TUF signer nonce")
}

fn persist_set(output: &Path, root_bytes: &[u8], set: &ImmutableTufSetV1) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-tuf-")
        .tempdir_in(parent)?;
    let sealed = temporary.path().join("metadata");
    fs::create_dir(&sealed)?;
    write_new(
        &sealed.join(format!("{}.root.json", set.root.signed.version)),
        root_bytes,
    )?;
    write_new(
        &sealed.join(format!("{}.targets.json", set.targets.signed.version)),
        &canonical::to_vec(&set.targets)?,
    )?;
    write_new(
        &sealed.join(format!(
            "{}.{}.json",
            set.delegated.signed.version,
            set.delegated.signed.role.as_str()
        )),
        &canonical::to_vec(&set.delegated)?,
    )?;
    write_new(
        &sealed.join(format!("{}.snapshot.json", set.snapshot.signed.version)),
        &canonical::to_vec(&set.snapshot)?,
    )?;
    File::open(&sealed)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &sealed,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_canonical(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = capture::control_file(path, label)?;
    canonical::require_canonical(&bytes, label)?;
    Ok(bytes)
}

fn read_tuf_root(path: &Path, label: &str) -> Result<TufEnvelopeV1<RootMetadataV1>> {
    canonical::from_slice(&read_canonical(path, label)?, label)
}

fn parse_utc(value: &str, label: &str) -> Result<std::time::SystemTime> {
    if !value.ends_with('Z') {
        bail!("{label} must be RFC 3339 UTC");
    }
    humantime::parse_rfc3339(value).with_context(|| format!("parsing {label}"))
}
