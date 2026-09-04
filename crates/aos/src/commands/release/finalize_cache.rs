//! Static Nix cache generation with externally backed narinfo signatures.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_core::nar::cache::NarInfoSigner;
use aos_core::nar::info;
use aos_package::registry::nixcache::generate_static_cache;
use aos_package::registry::release::{RegistryReleaseEntry, verify_release_entries};
use aos_release::build::BuildReportV1;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlanV1;
use aos_release::signing::{
    SIGNING_REQUEST_DOMAIN, SignatureAlgorithm, SignerRole, SigningContext, SigningOperation,
    SigningRequestV1, TrustedEd25519Key,
};
use base64::Engine as _;

use crate::cli::ReleaseFinalizeCacheArgs;

use super::capture;
use super::signer::ExternalSigner;

/// Generates every closure NAR and signs every narinfo through the cache role.
pub(super) async fn run(
    args: &ReleaseFinalizeCacheArgs,
    printer: &aos_core::output::Printer,
) -> Result<()> {
    if args.output.exists() {
        bail!(
            "static cache output already exists: {}",
            args.output.display()
        );
    }
    let plan_bytes = read_canonical(&args.plan, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    let report_bytes = read_canonical(&args.build_report, "build report")?;
    let report: BuildReportV1 = canonical::from_slice(&report_bytes, "build report")?;
    report.validate(&plan, plan_digest)?;
    let entries = report
        .outputs
        .iter()
        .map(|output| RegistryReleaseEntry {
            id: output.id.clone(),
            name: output.package.clone(),
            version: output.version.clone(),
            platform: output.platform.to_string(),
            store_path: output.store_path.clone(),
        })
        .collect::<Vec<_>>();
    verify_release_entries(&args.registry, &entries)?;

    let (key_id, key_path) = parse_key_spec(&args.cache_key)?;
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::Cache)
        .context("release plan lacks cache signer policy")?;
    if requirement.threshold != 1 || requirement.key_ids.as_slice() != [key_id.as_str()] {
        bail!("Nix narinfo format requires the plan's one exact cache signer key");
    }
    let trusted_key = load_cache_public_key(&key_id, &key_path)?;
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
        .prefix(".aos-release-cache-")
        .tempdir_in(parent)?;
    let cache = temporary.path().join("cache");
    let report = generate_static_cache(
        &args.registry,
        &cache,
        None,
        args.priority,
        args.jobs,
        None,
        true,
        printer,
    )
    .await?;
    let operation_ids = sign_narinfos(
        &cache,
        &plan,
        plan_digest,
        &trusted_key,
        &args.verification_identity,
        &requirement.provider_revision,
        &external,
    )
    .await?;
    if operation_ids.len() != report.narinfos {
        bail!("cache signer count differs from generated narinfo count");
    }
    File::open(&cache)?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &cache,
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.cache-finalization-result/v1",
        "release_id": plan.release_id,
        "paths": report.paths,
        "narinfos": report.narinfos,
        "nars": report.nars,
        "signing_operations": operation_ids,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Generated and externally signed {} narinfos at {}",
        report.narinfos,
        args.output.display()
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sign_narinfos(
    cache: &Path,
    plan: &ReleasePlanV1,
    plan_digest: Sha256Digest,
    key: &TrustedEd25519Key,
    verification_identity: &str,
    provider_revision: &str,
    external: &ExternalSigner,
) -> Result<Vec<String>> {
    let mut paths = fs::read_dir(cache)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("narinfo"));
    paths.sort();
    let mut nonces = BTreeSet::new();
    let mut operations = Vec::with_capacity(paths.len());
    for path in paths {
        let body = capture::control_file(&path, "unsigned narinfo")?;
        let text = std::str::from_utf8(&body).context("narinfo is not UTF-8")?;
        let parsed = info::parse(text)?;
        if !parsed.signatures.is_empty() {
            bail!("generated narinfo unexpectedly contains a signature");
        }
        let store_dir = Path::new(&parsed.store_path)
            .parent()
            .and_then(Path::to_str)
            .context("narinfo StorePath has no UTF-8 store directory")?;
        let references = parsed
            .references
            .iter()
            .map(|reference| format!("{store_dir}/{}", info::basename(reference)))
            .collect::<Vec<_>>();
        let fingerprint = NarInfoSigner::fingerprint(
            &parsed.store_path,
            &parsed.nar_hash,
            i64::try_from(parsed.nar_size)?,
            &references,
        );
        let nonce = fresh_nonce(&mut nonces)?;
        let request = SigningRequestV1 {
            schema_version: SIGNING_REQUEST_DOMAIN.to_string(),
            request_id: format!("narinfo-{}", &nonce[..24]),
            nonce,
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest,
            manifest_digest: None,
            role: SignerRole::Cache,
            key_id: key.key_id.clone(),
            provider_revision: provider_revision.to_string(),
            algorithm: SignatureAlgorithm::Ed25519Payload,
            operation: SigningOperation::SignPayload,
            context: SigningContext::Payload {
                artifact_kind: "narinfo-fingerprint".to_string(),
            },
            payload_digest: Sha256Digest::of_bytes(fingerprint.as_bytes()),
            approval_policy_digest: plan.restricted_operator_policy_digest,
        };
        let response = external
            .sign_ed25519_payload(&request, fingerprint.as_bytes(), key, verification_identity)
            .await?;
        let signature =
            base64::engine::general_purpose::STANDARD.decode(&response.signature_base64)?;
        if signature.len() != 64 {
            bail!("cache provider returned a non-Ed25519 signature length");
        }
        let mut signed = body;
        if !signed.ends_with(b"\n") {
            signed.push(b'\n');
        }
        signed.extend_from_slice(
            format!("Sig: {}:{}\n", key.key_id, response.signature_base64).as_bytes(),
        );
        fs::write(&path, signed)?;
        operations.push(response.provider_operation_id);
    }
    Ok(operations)
}

fn parse_key_spec(value: &str) -> Result<(String, PathBuf)> {
    let (key_id, path) = value
        .split_once('=')
        .context("cache key must use KEY_ID=PATH")?;
    if key_id.is_empty() || path.is_empty() {
        bail!("cache key must use nonempty KEY_ID=PATH");
    }
    Ok((key_id.to_string(), PathBuf::from(path)))
}

fn load_cache_public_key(key_id: &str, path: &Path) -> Result<TrustedEd25519Key> {
    let bytes = capture::control_file(path, "cache public key")?;
    let text = std::str::from_utf8(&bytes)
        .context("cache public key is neither a Nix key line nor supported raw encoding")?
        .trim();
    if let Some((name, encoded)) = text.split_once(':') {
        if name != key_id || encoded.contains(':') {
            bail!("Nix cache public key name must exactly equal its plan key id");
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("decoding Nix cache public key")?;
        return TrustedEd25519Key::from_encoded(key_id, &decoded);
    }
    TrustedEd25519Key::from_encoded(key_id, &bytes)
}

fn fresh_nonce(seen: &mut BTreeSet<String>) -> Result<String> {
    for _ in 0..8 {
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        if seen.insert(nonce.clone()) {
            return Ok(nonce);
        }
    }
    bail!("could not allocate a unique narinfo signer nonce")
}

fn read_canonical(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = capture::control_file(path, label)?;
    canonical::require_canonical(&bytes, label)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_public_key_name_is_bound_to_plan_key_id() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let public = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32])
            .verifying_key()
            .to_bytes();
        let encoded = base64::engine::general_purpose::STANDARD.encode(public);
        let path = temporary.path().join("cache.pub");
        fs::write(&path, format!("cache-1:{encoded}\n"))?;

        assert_eq!(load_cache_public_key("cache-1", &path)?.public_key, public);
        assert!(load_cache_public_key("cache-2", &path).is_err());
        Ok(())
    }
}
