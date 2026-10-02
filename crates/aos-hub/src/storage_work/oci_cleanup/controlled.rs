//! Actual pair input for the ignored Managed terminal-cleanup runtime helper.
//!
//! This helper selects an existing terminal SQL chunk and independently current
//! Delete capability. It creates no upload, chunk, provider bytes or capability.
//! The caller retains real transport/SDK observations and owns cold restart and
//! normal SQL recovery; an unknown exchange is never reported as positive.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::backend::{Backend as _, SqlxBackend};
use aos_hub_core::db::Database;
use aos_hub_core::mirror_guard::MirrorGuardIssuer;
use aos_hub_core::oci_cleanup::ManagedOciCleanupOriginal;
use aos_hub_core::oci_sdk_emulation::OciSdkEmulationProfile;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum Phase {
    Observe,
    DispatchUnknown,
    ReplayPositive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    version: u32,
    phase: Phase,
    database_url_file: PathBuf,
    work_key_file: PathBuf,
    guard_key_file: PathBuf,
    tls_root_file: PathBuf,
    output_file: PathBuf,
    placement_prefix: String,
    upload_id: String,
    ordinal: u32,
    expected_original_sha256: Option<String>,
    profile: OciSdkEmulationProfile,
}

async fn existing_database(url: &str) -> Result<Database> {
    let backend = if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        #[cfg(feature = "postgres")]
        {
            SqlxBackend::connect_postgres(url).await?
        }
        #[cfg(not(feature = "postgres"))]
        {
            anyhow::bail!("controlled pair PostgreSQL support is not compiled in");
        }
    } else {
        ensure!(
            !url.contains("://") || url.starts_with("sqlite://") || url.starts_with("file://"),
            "controlled pair database scheme differs"
        );
        let path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("file://"))
            .unwrap_or(url);
        SqlxBackend::connect_sqlite_read_only(path).await?
    };
    let versions = backend
        .query("SELECT version FROM schema_version", &[])
        .await?;
    let identities = backend
        .query("SELECT identity FROM hub_schema_identity", &[])
        .await?;
    ensure!(
        versions.len() == 1
            && versions[0].get::<i64>(0)? == aos_hub_core::db::MIGRATIONS.len() as i64
            && identities.len() == 1
            && identities[0].get::<String>(0)? == aos_hub_core::db::SCHEMA_IDENTITY,
        "controlled pair existing schema differs"
    );
    let db = Database::attach(Box::new(backend));
    db.validate_binding_identity_reservations().await?;
    Ok(db)
}

#[tokio::test]
#[ignore = "requires a real fresh Managed pair, terminal SQL chunk and current Delete probe"]
async fn actual_managed_terminal_cleanup_pair() -> Result<()> {
    let input_path = PathBuf::from(
        std::env::var_os("AOS_MANAGED_CLEANUP_CONTROLLED_INPUT")
            .context("owner-private controlled pair input is required")?,
    );
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(&input_path, 64 * 1024)?;
    let input: Input = serde_json::from_slice(&bytes)?;
    ensure!(
        input.version == 1,
        "controlled cleanup input version differs"
    );
    input.profile.validate()?;
    let protected_profile_digest =
        aos_hub_core::oci_cleanup::managed_cleanup_fixture_profile_digest(&input.profile)?;
    let url_bytes =
        crate::auth::seal::read_secret_file_zeroizing_capped(&input.database_url_file, 8192)?;
    let url = std::str::from_utf8(&url_bytes)?.trim();
    let db = Arc::new(existing_database(url).await?);
    let mut candidates = db.oci_upload_cleanup_candidates(1000).await?;
    candidates.retain(|candidate| candidate.upload.id == input.upload_id);
    ensure!(
        candidates.len() == 1,
        "actual terminal cleanup upload is absent or ambiguous"
    );
    let candidate = candidates
        .pop()
        .context("actual terminal upload disappeared")?;
    let chunk = candidate
        .chunks
        .iter()
        .find(|chunk| chunk.ordinal == input.ordinal)
        .context("actual terminal chunk is absent")?;
    let claim = db
        .claim_terminal_oci_chunk_cleanup(&candidate, chunk)
        .await?;
    let placement = db
        .surface_placement(
            claim
                .upload()
                .staging_placement_id
                .context("actual staging placement absent")?,
        )
        .await?
        .context("actual staging placement disappeared")?;
    let binding = db
        .binding(placement.binding_id)
        .await?
        .context("actual binding disappeared")?;
    let revision = claim
        .upload()
        .staging_binding_write_revision
        .context("actual write revision absent")?;
    let capability = db
        .oci_conditional_delete_capability(binding.id, revision)
        .await?
        .context("actual independently probed Delete capability absent")?;
    let writer = db
        .binding_write_state(binding.id)
        .await?
        .context("actual current binding writer disappeared")?;
    ensure!(
        placement.prefix == input.placement_prefix
            && Some(placement.resource_version)
                == claim.upload().staging_placement_resource_version
            && writer.current_write_revision == Some(revision)
            && binding.kind == "deployment_r2"
            && binding.is_instance_default
            && capability.state == "valid"
            && capability.binding_resource_version == binding.resource_version
            && capability.delete_credential_purpose.is_none()
            && capability.delete_credential_generation.is_none(),
        "actual Managed terminal chunk or current credential-free Delete capability differs"
    );
    let original = ManagedOciCleanupOriginal::from_claim(
        &claim,
        placement.prefix.clone(),
        binding.resource_version,
        capability.capability_fingerprint,
        capability.resource_version,
    )?;
    let original_bytes = serde_json::to_vec(&original)?;
    let original_sha256 = format!("{:x}", Sha256::digest(&original_bytes));
    let original_fingerprint = original.fingerprint()?;
    if !matches!(input.phase, Phase::Observe) {
        ensure!(
            input.expected_original_sha256.as_deref() == Some(original_sha256.as_str()),
            "controlled cleanup dispatch differs from the independently retained SQL original"
        );
    }

    let result = if matches!(input.phase, Phase::Observe) {
        "observed_sql_only"
    } else {
        let work_key = crate::auth::seal::read_secret_file_zeroizing(&input.work_key_file)?;
        let guard_key = crate::auth::seal::read_secret_file_zeroizing(&input.guard_key_file)?;
        let root =
            crate::auth::seal::read_secret_file_zeroizing_capped(&input.tls_root_file, 64 * 1024)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .add_root_certificate(reqwest::Certificate::from_pem(&root)?)
            .build()?;
        let issuer = MirrorGuardIssuer {
            source_digest: input.profile.worker_source_digest.clone(),
            script_version: input.profile.worker_script_version.clone(),
        };
        let work = super::super::RemoteStorageWorkClient::new(
            &input.profile.public_origin,
            input.profile.deployment_id.clone(),
            &work_key,
        )?
        .with_mirror_guard_key(&guard_key)?
        .with_controlled_http(http)
        .with_controlled_managed_cleanup(input.profile, issuer, input.placement_prefix)?;
        let writes = super::super::HybridSurfaceWrites::new(db.clone(), Arc::new(work));
        let attempted = writes.cleanup_managed_oci_chunk(&claim).await;
        match input.phase {
            Phase::DispatchUnknown => {
                ensure!(
                    attempted.is_err(),
                    "lost-response attempt unexpectedly returned a positive reply"
                );
                "exchange_unknown"
            }
            Phase::ReplayPositive => {
                ensure!(
                    attempted?,
                    "actual cleanup selected no supported physical implementation"
                );
                "authenticated_positive_reply"
            }
            Phase::Observe => unreachable!("observation branch performs no exchange"),
        }
    };
    claim.check_current(&db).await?;
    let parent = input
        .output_file
        .parent()
        .context("controlled receipt parent absent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.uid() == fs::metadata("/proc/self")?.uid(),
        "controlled receipt directory is not owner-private"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&input.output_file)?;
    serde_json::to_writer(
        &mut output,
        &json!({
            "version": 1,
            "outcome": result,
            "inputSha256": format!("{:x}", Sha256::digest(bytes.as_slice())),
            "originalSha256": original_sha256,
            "originalFingerprint": original_fingerprint,
            "protectedProfileDigest": protected_profile_digest,
            "original": original,
            "sqlClaimUnchangedAfterAttempt": true,
            "providerSdkCalls": null,
            "sqlCleanupSettled": false,
        }),
    )?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(())
}
