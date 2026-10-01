//! Protected hybrid secret delivery and unchanged-version acceptance activation.
//!
//! Operator provisioning credentials are consumed only by the existing Wrangler
//! launcher. Runtime credentials come from owner-private files, travel on stdin
//! to Worker secret delivery, and are never rendered into configuration or logs.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use zeroize::Zeroizing;

use crate::cloudflare::{Assets, DeployMode, HybridDeployConfig};

/// Owner-private files supplying explicit hybrid Worker secret rotations.
///
/// Omitted values preserve existing Worker secrets. Initial installation requires
/// all selected bindings and never prints or invents provider credentials.
#[derive(Clone, Debug, Default)]
pub struct HybridDeploySecretFiles {
    /// Existing Native-matched `HUB_HYBRID_INGRESS_KEY` material.
    pub hybrid_ingress_key_file: Option<PathBuf>,
    /// Existing Native-matched `HUB_STORAGE_WORK_KEY` material.
    pub storage_work_key_file: Option<PathBuf>,
    /// Separate Native-matched physical guard authentication key.
    pub direct_upload_guard_key_file: Option<PathBuf>,
    /// Separate direct upload durable journal authentication key.
    pub direct_upload_journal_key_file: Option<PathBuf>,
    /// Persistent scoped R2 S3 access key identifier, delivered as a Worker secret.
    pub direct_upload_access_key_id_file: Option<PathBuf>,
    /// Matching persistent scoped R2 S3 secret key material.
    pub direct_upload_secret_access_key_file: Option<PathBuf>,
    /// Separate opt-in hosted SDK measurement control key.
    pub direct_upload_conformance_key_file: Option<PathBuf>,
}

struct ProtectedSecrets {
    entries: Vec<(&'static str, Zeroizing<String>)>,
}

impl ProtectedSecrets {
    fn read(files: &HybridDeploySecretFiles, cfg: &HybridDeployConfig) -> Result<Self> {
        ensure!(
            files.direct_upload_access_key_id_file.is_some()
                == files.direct_upload_secret_access_key_file.is_some(),
            "direct R2 access and secret key files must be supplied together"
        );
        ensure!(
            files.direct_upload_access_key_id_file.is_none() || cfg.direct_upload.is_some(),
            "direct R2 credential files require a managed profile"
        );
        ensure!(
            files.direct_upload_conformance_key_file.is_none()
                || cfg.direct_upload_conformance
                || cfg.direct_upload_qualification.is_some(),
            "measurement control key requires explicit SDK or isolated qualification enablement"
        );

        let selections = [
            (
                "HUB_HYBRID_INGRESS_KEY",
                files.hybrid_ingress_key_file.as_deref(),
            ),
            (
                "HUB_STORAGE_WORK_KEY",
                files.storage_work_key_file.as_deref(),
            ),
            (
                "HUB_DIRECT_UPLOAD_GUARD_KEY",
                files.direct_upload_guard_key_file.as_deref(),
            ),
            (
                "HUB_DIRECT_UPLOAD_JOURNAL_KEY",
                files.direct_upload_journal_key_file.as_deref(),
            ),
            (
                "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID",
                files.direct_upload_access_key_id_file.as_deref(),
            ),
            (
                "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY",
                files.direct_upload_secret_access_key_file.as_deref(),
            ),
            (
                "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
                files.direct_upload_conformance_key_file.as_deref(),
            ),
        ];
        let mut entries = Vec::new();
        for (name, path) in selections {
            let Some(path) = path else {
                continue;
            };
            let value = read_protected_text(path)?;
            if !name.starts_with("HUB_DIRECT_UPLOAD_R2_") {
                StorageWorkKey::new(value.as_bytes())
                    .map_err(|_| anyhow::anyhow!("protected Worker control key is too short"))?;
            }
            let maximum = if name == "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID" {
                255
            } else {
                4096
            };
            ensure!(
                !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control),
                "protected Worker secret has invalid text or length"
            );
            entries.push((name, value));
        }
        let controls: Vec<_> = entries
            .iter()
            .filter(|(name, _)| !name.starts_with("HUB_DIRECT_UPLOAD_R2_"))
            .collect();
        for (index, (_, value)) in controls.iter().enumerate() {
            ensure!(
                controls[index + 1..]
                    .iter()
                    .all(|(_, other)| value.as_str() != other.as_str()),
                "hybrid Worker control keys must have separate material"
            );
        }
        if cfg.mirror_trust.is_some() {
            // Native deliberately uses this independently supplied guard role
            // for both purpose-separated lookup protocols. Never alias the
            // storage-work producer key or bypass the existing separation check.
            if let Some((_, guard)) = entries
                .iter()
                .find(|(name, _)| *name == "HUB_DIRECT_UPLOAD_GUARD_KEY")
            {
                entries.push(("HUB_MIRROR_GUARD_KEY", guard.clone()));
            }
        }
        Ok(Self { entries })
    }

    fn require_bindings(&self, cfg: &HybridDeployConfig, existing: &[String]) -> Result<()> {
        let mut required = vec!["HUB_HYBRID_INGRESS_KEY", "HUB_STORAGE_WORK_KEY"];
        if cfg.direct_upload.is_some() || cfg.direct_upload_clock.is_some() {
            required.extend([
                "HUB_DIRECT_UPLOAD_GUARD_KEY",
                "HUB_DIRECT_UPLOAD_JOURNAL_KEY",
            ]);
        }
        if cfg.direct_upload.is_some() {
            required.extend([
                "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID",
                "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY",
            ]);
        }
        if cfg.mirror_trust.is_some() {
            required.push("HUB_MIRROR_GUARD_KEY");
        }
        if cfg.direct_upload_conformance || cfg.direct_upload_qualification.is_some() {
            required.push("HUB_DIRECT_UPLOAD_CONFORMANCE_KEY");
        }
        for name in required {
            ensure!(
                self.entries.iter().any(|(supplied, _)| *supplied == name)
                    || existing.iter().any(|present| present == name),
                "hybrid Worker requires protected secret {name}"
            );
        }
        Ok(())
    }
}

fn read_protected_text(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(path, 8192)
        .map_err(|_| anyhow::anyhow!("protected Worker secret file custody or read failed"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("protected Worker secret file is not UTF-8"))?;
    // Native consumes these files as exact key bytes. Silent newline trimming
    // would change the Worker key and break the paired transport authentication.
    ensure!(
        !text.is_empty() && text.trim() == text && !text.chars().any(char::is_control),
        "protected Worker secret file must contain exact printable key bytes"
    );
    Ok(Zeroizing::new(text.to_owned()))
}

/// Provisions selected ordinary resources and deploys a hybrid Worker safely.
///
/// Updates preserve every omitted existing secret. Direct upload production
/// dispatch remains unavailable until independently signed acceptance is uploaded
/// for the final unchanged hosted version by [`activate_hybrid_direct_upload`].
///
/// # Errors
/// Returns an error for invalid configuration, insecure secret custody, missing
/// selected secrets, resource provisioning, staging or protected secret delivery.
pub async fn deploy_hybrid(
    assets: &Assets,
    cfg: &HybridDeployConfig,
    files: &HybridDeploySecretFiles,
    mode: DeployMode,
) -> Result<()> {
    let source = crate::cloudflare::render_hybrid_wrangler_toml(cfg)?;
    let secrets = ProtectedSecrets::read(files, cfg)?;
    if mode == DeployMode::Install {
        secrets.require_bindings(cfg, &[])?;
    }
    let work = tempfile::Builder::new()
        .prefix("aos-hub-hybrid-deploy")
        .tempdir()
        .context("creating hybrid deployment staging directory")?;
    let config = stage(assets, &source, work.path(), cfg.serve_assets).await?;

    let existing = if mode == DeployMode::Update {
        let listed = crate::cloudflare::run_wrangler(
            assets,
            &crate::cloudflare::secret_list_args(&config),
            None,
            None,
        )
        .await?;
        crate::cloudflare::parse_secret_names(&listed)?
    } else {
        Vec::new()
    };
    secrets.require_bindings(cfg, &existing)?;

    crate::cloudflare::run_wrangler_tolerant(
        assets,
        &crate::cloudflare::r2_create_args(&cfg.bucket),
        "hybrid R2 bucket create",
    )
    .await;
    let lifecycle = crate::cloudflare::run_wrangler(
        assets,
        &crate::cloudflare::r2_multipart_lifecycle_list_args(&cfg.bucket),
        None,
        None,
    )
    .await?;
    if !crate::cloudflare::r2_lifecycle_has_bounded_multipart_abort(&lifecycle, 7) {
        let rule = format!("aos-abandoned-multipart-{}", uuid::Uuid::new_v4().simple());
        crate::cloudflare::run_wrangler(
            assets,
            &crate::cloudflare::r2_multipart_lifecycle_add_args(&cfg.bucket, &rule),
            None,
            None,
        )
        .await?;
    }
    if let Some(queues) = &cfg.direct_upload_queues {
        for queue in [&queues.bulk, &queues.metadata] {
            crate::cloudflare::run_wrangler_tolerant(
                assets,
                &crate::cloudflare::queue_create_args(queue),
                "direct verification queue create",
            )
            .await;
        }
    }
    if mode == DeployMode::Install {
        crate::cloudflare::run_wrangler(
            assets,
            &crate::cloudflare::deploy_args(&config),
            None,
            Some(work.path()),
        )
        .await?;
    }
    for (name, value) in &secrets.entries {
        // Provider tools may echo rejected input in diagnostics. Discard all
        // captured output on this protected path, including nested error text.
        crate::cloudflare::run_wrangler(
            assets,
            &crate::cloudflare::secret_put_args(name, &config),
            Some(value.as_str()),
            None,
        )
        .await
        .map_err(|_| anyhow::anyhow!("applying protected Worker secret {name} failed"))?;
    }
    crate::cloudflare::run_wrangler(
        assets,
        &crate::cloudflare::deploy_args(&config),
        None,
        Some(work.path()),
    )
    .await?;
    Ok(())
}

async fn stage(
    assets: &Assets,
    source: &str,
    directory: &Path,
    serve_assets: bool,
) -> Result<PathBuf> {
    for name in ["shim.mjs", "index.wasm"] {
        tokio::fs::copy(assets.dist_dir.join(name), directory.join(name))
            .await
            .with_context(|| format!("staging hybrid {name}"))?;
    }
    if serve_assets {
        let assets_source = assets
            .assets_dir
            .as_deref()
            .context("hybrid assets requested but the prebuilt bundle has no assets")?;
        crate::cloudflare::copy_dir_all(assets_source, &directory.join("assets")).await?;
    }
    let config = directory.join("wrangler.toml");
    tokio::fs::write(&config, source)
        .await
        .context("writing hybrid deployment configuration")?;
    Ok(config)
}

/// Captures actual protected public deployment facts before independent review.
///
/// This read-only discovery grants no acceptance. External selectors come from
/// independently selected operator policy and are bounded by the shared protocol.
///
/// # Errors
/// Returns an error for invalid configuration or selectors, insecure guard key
/// custody, stale or forged replies, changed audience, transport or oversized data.
pub async fn inspect_hybrid_direct_upload(
    cfg: &HybridDeployConfig,
    guard_key_file: &Path,
    external_selectors: Vec<DirectExternalProfileSelector>,
) -> Result<DirectWorkerDeploymentIdentity> {
    crate::cloudflare::render_hybrid_wrangler_toml(cfg)?;
    let protected = read_protected_text(guard_key_file)?;
    let guard = StorageWorkKey::new(protected.as_bytes())
        .map_err(|_| anyhow::anyhow!("protected deployment guard key is too short"))?;
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let challenge = DirectWorkerDeploymentChallenge {
        version: 1,
        nonce: crate::cloudflare::generate_hex_secret(32),
        expires_at: WireInteger::new(
            now.checked_add(30)
                .context("deployment discovery clock overflow")?,
        ),
        external_selectors,
    };
    let request = sign_direct_worker_deployment_request(&guard, &challenge)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(25))
        .build()?;
    let response = client
        .post(format!(
            "{}{}",
            cfg.external_url.trim_end_matches('/'),
            DIRECT_WORKER_DEPLOYMENT_PATH
        ))
        .header(DIRECT_WORKER_DEPLOYMENT_SIGNATURE_HEADER, request.signature)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(request.body)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("protected deployment discovery transport failed"))?;
    ensure!(
        response.status().is_success(),
        "protected deployment discovery refused"
    );
    let signature = response
        .headers()
        .get(DIRECT_WORKER_DEPLOYMENT_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .context("protected deployment discovery signature absent")?
        .to_owned();
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("protected deployment discovery body failed"))?
    {
        ensure!(
            body.len()
                .checked_add(chunk.len())
                .is_some_and(|size| size <= MAX_DIRECT_CAPABILITY_BYTES),
            "protected deployment discovery exceeds limit"
        );
        body.extend_from_slice(&chunk);
    }
    let latest = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let reply =
        verify_direct_worker_deployment_reply(&guard, &signature, &body, &challenge, latest)?;
    ensure!(
        reply.identity.deployment_id == cfg.deployment_id
            && reply.identity.public_origin == cfg.external_url,
        "protected deployment discovery audience differs"
    );
    Ok(reply.identity)
}

/// Reads closed bounded operator selectors for protected deployment discovery.
///
/// # Errors
/// Returns an error for malformed, oversized or invalid selector files.
pub fn read_hybrid_direct_upload_selectors(
    path: &Path,
) -> Result<Vec<DirectExternalProfileSelector>> {
    let selectors: Vec<DirectExternalProfileSelector> =
        super::read_config_file_with_limit(path, 64 * 1024)?;
    ensure!(
        selectors.len() <= MAX_DIRECT_PLACEMENTS,
        "direct discovery selector count exceeds limit"
    );
    for selector in &selectors {
        selector.validate()?;
    }
    Ok(selectors)
}

/// Authenticates current deployed bindings and publishes their signed acceptance.
///
/// This changes only the version-specific KV record and never deploys a Worker
/// version or mints a reviewer signature. The operator's existing persistent
/// provider credential supplies KV write authority through Wrangler.
///
/// # Errors
/// Returns an error for missing trust/acceptance, invalid independent evidence,
/// protected key custody, current deployment mismatch, transport or KV write.
pub async fn activate_hybrid_direct_upload(
    assets: &Assets,
    cfg: &HybridDeployConfig,
    guard_key_file: &Path,
) -> Result<()> {
    crate::cloudflare::render_hybrid_wrangler_toml(cfg)?;
    let acceptance = cfg
        .direct_upload_acceptance
        .as_ref()
        .context("activation requires an independently signed Worker acceptance file")?;
    acceptance.validate(cfg)?;
    let trust = cfg
        .direct_upload_trust
        .as_ref()
        .context("activation requires independently installed reviewer trust")?;
    let selectors = acceptance
        .artifact
        .evidence
        .external_profiles
        .iter()
        .map(|item| item.profile.selector.clone())
        .collect();
    let identity = inspect_hybrid_direct_upload(cfg, guard_key_file, selectors).await?;
    acceptance
        .artifact
        .verify_deployment_identity(&identity, &trust.public_key)?;
    acceptance.validate(cfg)?;
    let key = direct_worker_acceptance_key(
        &cfg.deployment_id,
        &identity.source_digest,
        &identity.script_version,
    )?;
    let bytes = encode_direct_control(&acceptance.artifact)?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "direct acceptance exceeds registry limit"
    );
    let work = tempfile::Builder::new()
        .prefix("aos-hub-direct-acceptance")
        .tempdir()?;
    let path = work.path().join("accepted.json");
    tokio::fs::write(&path, bytes).await?;
    let args = vec![
        "kv".into(),
        "key".into(),
        "put".into(),
        key,
        "--namespace-id".into(),
        trust.namespace_id.clone(),
        "--path".into(),
        path.to_string_lossy().into_owned(),
        "--remote".into(),
    ];
    crate::cloudflare::run_wrangler(assets, &args, None, None).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
