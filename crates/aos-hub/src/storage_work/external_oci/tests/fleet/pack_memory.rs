//! Fixture-only current Native consumers over existing SQL and accepted profiles.
//!
//! This child is attached to the existing private Fleet helper only in the
//! separately identified auxiliary test ELF. It creates no registry, original,
//! profile, credential or object. Publisher bytes never enter this process.

use super::*;

#[path = "../../../../logging.rs"]
mod logging;
use aos_hub_core::{
    direct_upload::{DirectManagedR2Profile, DirectPrivateStagePolicyRef},
    mirror_guard::MirrorGuardIssuer,
    mirror_inspection::{MirrorPackRange, MirrorPackSelection},
    mirror_batch::MirrorBatchItem,
    mirror_work::MirrorStep,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    version: u8,
    helper_input_file: PathBuf,
    helper_input_sha256: String,
    output_file: PathBuf,
    cutoff_unix_seconds: i64,
    phase: Phase,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Pack { registry_id: i64, index_path: String, oid: String },
    Metadata {
        original_file: PathBuf,
        managed_profile_file: PathBuf,
        policy_file: PathBuf,
        candidate_key_file: PathBuf,
        issuer: MirrorGuardIssuer,
    },
}

#[tokio::test]
#[ignore = "requires selected current SQL, Worker, profiles and owned fixture source"]
async fn actual_pack_memory_native_consumer() -> Result<()> {
    logging::init();
    let selected = PathBuf::from(std::env::var_os("AOS_PACK_MEMORY_SELECTION")
        .context("private selected input absent")?);
    let raw = private_bytes(&selected, MAX_INPUT_BYTES)?;
    let selection: Selection = serde_json::from_slice(&raw)?;
    let now = aos_hub_core::clock::now_unix_secs();
    ensure!(selection.version == 1 && selection.cutoff_unix_seconds > now
        && selection.cutoff_unix_seconds - now <= 25,
        "original measurement cutoff absent or expired");
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(u64::try_from(selection.cutoff_unix_seconds - now)?);
    let helper_raw = private_bytes(&selection.helper_input_file, MAX_INPUT_BYTES)?;
    ensure!(hex::encode(Sha256::digest(&helper_raw)) == selection.helper_input_sha256,
        "selected helper input changed");
    let input: Input = serde_json::from_slice(&helper_raw)?;
    input.validate()?;
    let (actual_executable, _) = executable_identity()?;
    ensure!(actual_executable == input.expected_executable_sha256,
        "selected auxiliary ELF differs");
    let db = existing_database(private_text(&input.files.database_url_file, 8192)?.as_str()).await?;
    let work_key = private_bytes(&input.files.work_key_file, 8192)?;
    let ca = reqwest::Certificate::from_pem(&private_bytes(&input.files.tls_root_file, MAX_INPUT_BYTES)?)?;
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30)).add_root_certificate(ca).build()?;
    let direct = direct_selection(&input, &work_key)?;
    let work = install_direct_profiles(RemoteStorageWorkClient::new(&input.public_origin,
        &input.deployment_id, &work_key)?.with_controlled_http(http), direct.as_ref());

    let action = async {
        match selection.phase {
            Phase::Pack { registry_id, index_path, oid } => {
                let work = install_mirror_functional(work, &input)?;
                let registry = db.registry_by_id(registry_id).await?
                    .context("actual pack registry absent")?;
                let placement = db.reconciled_surface_writer(
                    aos_hub_core::db::SurfaceTarget::Registry(registry.id)).await?;
                let binding = db.binding(placement.binding_id).await?
                    .context("actual pack binding absent")?;
                if !binding.is_instance_default {
                    work.ensure_remote_binding_snapshot(&db, &binding).await?;
                }
                // The existing consumer signs its actual current SQL selection,
                // validates the whole returned projection and repeats SQL checks.
                let projection = work.inspect_mirror_pack(&db, &registry, &index_path,
                    vec![MirrorPackSelection { oid, range: Some(MirrorPackRange {
                        start: 0, end: 32 }) }]).await?;
                Ok::<_, anyhow::Error>(json!({"kind":"pack", "projection":projection,
                    "consumer":"RemoteStorageWorkClient::inspect_mirror_pack"}))
            }
            Phase::Metadata { original_file, managed_profile_file, policy_file,
                candidate_key_file, issuer } => {
                let item: MirrorBatchItem = serde_json::from_slice(
                    &private_bytes(&original_file, MAX_INPUT_BYTES)?)?;
                ensure!(matches!(item.step, MirrorStep::UploadParts {
                    first_part: 1, maximum_parts: 1 })
                    && item.original.external_destination.is_none()
                    && item.original.verification.size() > 0
                    && item.original.verification.size() <= 256 * 1024
                    && !matches!(&item.original.verification,
                        aos_hub_core::mirror_work::MirrorVerification::Nar { compression, .. }
                        if compression == "zstd"),
                    "metadata must be an existing bounded non-zstd Managed original");
                let profile: DirectManagedR2Profile = serde_json::from_slice(
                    &private_bytes(&managed_profile_file, MAX_INPUT_BYTES)?)?;
                let policy: DirectPrivateStagePolicyRef = serde_json::from_slice(
                    &private_bytes(&policy_file, MAX_INPUT_BYTES)?)?;
                let work = work.with_controlled_mirror(&profile, &policy, issuer,
                    &private_bytes(&candidate_key_file, 8192)?)?;
                // The wrapper delegates unchanged real preflight, transport and
                // transactional returned-progress persistence, without admission.
                let progress = crate::mirror::hybrid::pack_memory_metadata_phase(
                    &db, &work, item).await?;
                Ok(json!({"kind":"metadata", "progress":progress,
                    "consumer":"mirror::hybrid::batch::run"}))
            }
        }
    };
    let result = tokio::time::timeout_at(deadline, action).await
        .context("original Native measurement cutoff reached")??;
    ensure!(aos_hub_core::clock::now_unix_secs() < selection.cutoff_unix_seconds,
        "original cutoff reached before retention");
    ensure!(raw.as_slice() == private_bytes(&selected, MAX_INPUT_BYTES)?.as_slice(),
        "measurement selection changed");
    write_private(&selection.output_file, &json!({
        "version":1, "selectionSha256":hex::encode(Sha256::digest(&raw)),
        "helperInputSha256":selection.helper_input_sha256,
        "nativeExecutableSha256":actual_executable, "result":result,
        "replyMacAuthentication":null, "nativeBulkBytes":null,
        "providerDrain":null, "wholeIsolateBytes":null}))?;
    Ok(())
}
