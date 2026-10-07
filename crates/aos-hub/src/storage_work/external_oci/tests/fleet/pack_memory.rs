//! Fixture-only current Native consumers over existing SQL and accepted profiles.
//!
//! This child is attached to the existing private Fleet helper only in the
//! separately identified auxiliary test ELF. Its preparation phase admits two
//! real metadata originals through the ordinary SQL controller. Its material
//! selector only derives a raw candidate projection, never runtime acceptance.
//! Publisher bytes never enter this process.

use super::*;

#[path = "../../../../logging.rs"]
mod logging;
use aos_hub_core::{
    direct_upload::{DirectManagedR2Profile, DirectPrivateStagePolicyRef},
    mirror_batch::MirrorBatchItem,
    mirror_guard::MirrorGuardIssuer,
    mirror_inspection::{MirrorPackRange, MirrorPackSelection},
    mirror_batch::MirrorBatchItem,
    mirror_work::MirrorStep,
};

#[path = "pack_memory/material.rs"]
mod material;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateSelection {
    configuration_file: PathBuf,
    configuration_custody: material::ConfigCustody,
    public_configuration_file: PathBuf,
    public_configuration_digest: String,
    managed_profile_file: PathBuf,
    policy_file: PathBuf,
    candidate_key_file: PathBuf,
    issuer: MirrorGuardIssuer,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MetadataObject {
    registry_id: i64,
    path: String,
    verification: aos_hub_core::mirror_work::MirrorVerification,
}

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
    PrepareMetadata { material: CandidateSelection, objects: [MetadataObject; 2] },
    Metadata {
        original_file: PathBuf,
        managed_profile_file: PathBuf,
        policy_file: PathBuf,
        candidate_key_file: PathBuf,
        issuer: MirrorGuardIssuer,
        configuration_file: PathBuf,
        configuration_custody: material::ConfigCustody,
        public_configuration_file: PathBuf,
        public_configuration_digest: String,
        candidate_buffers_output_file: PathBuf,
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
        input.deployment_id.clone(), &work_key)?.with_controlled_http(http), direct.as_ref());

    let action = async {
        match selection.phase {
            Phase::PrepareMetadata { material, objects } => {
                let work = material::checked_work(work, &input,
                    &material.configuration_file, &material.configuration_custody,
                    &material.public_configuration_file, &material.public_configuration_digest,
                    &material.managed_profile_file, &material.policy_file,
                    &material.candidate_key_file, material.issuer)?;
                let objects = objects.map(|object| (object.registry_id, object.path, object.verification));
                let items = crate::mirror::hybrid::pack_memory_prepare_metadata(&db, &work, objects).await?;
                let digests = items.iter().map(|item|
                    aos_hub_core::mirror_work::digest(&item.original)).collect::<Result<Vec<_>>>()?;
                Ok(json!({"kind":"prepare_metadata", "items":items, "originalDigests":digests,
                    "publicConfigurationDigest":material.public_configuration_digest,
                    "runtimeAcceptance":null,
                    "consumer":"mirror::hybrid::admit_object+batch::run(Status,Begin)"}))
            }
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
                candidate_key_file, issuer, configuration_file, configuration_custody,
                public_configuration_file, public_configuration_digest,
                candidate_buffers_output_file } => {
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
                let work = material::checked_work(work, &input, &configuration_file,
                    &configuration_custody, &public_configuration_file, &public_configuration_digest,
                    &managed_profile_file, &policy_file,
                    &candidate_key_file, issuer)?;
                let capture = crate::storage_work::mirror_candidate::buffer_capture::Capture::new(item.clone())?;
                let work = work.with_candidate_buffer_capture(capture.clone())?;
                // The wrapper delegates unchanged real preflight, transport and
                // transactional returned-progress persistence, without admission.
                let progress = crate::mirror::hybrid::pack_memory_metadata_phase(
                    &db, &work, item).await?;
                ensure!(aos_hub_core::clock::now_unix_secs() < selection.cutoff_unix_seconds,
                    "original cutoff reached before header retention");
                write_private(&candidate_buffers_output_file, &json!({
                    "version":1, "selectionSha256":hex::encode(Sha256::digest(&raw)),
                    "nativeExecutableSha256":actual_executable,
                    "candidateObservation":capture.finish()?}))?;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterialSelection {
    version: u8,
    configuration_file: PathBuf,
    configuration_custody: material::ConfigCustody,
    expected_executable_sha256: String,
    expected_worker_source_digest: String,
    expected_worker_script_version: String,
    output_file: PathBuf,
    cutoff_unix_seconds: i64,
}

#[tokio::test]
#[ignore = "requires actual private initial candidate config and selected current test ELF"]
async fn actual_pack_memory_candidate_material() -> Result<()> {
    let path = PathBuf::from(std::env::var_os("AOS_PACK_MEMORY_SELECTION")
        .context("private material selection absent")?);
    let raw = private_bytes(&path, MAX_INPUT_BYTES)?;
    let selection: MaterialSelection = serde_json::from_slice(&raw)?;
    let now = aos_hub_core::clock::now_unix_secs();
    ensure!(selection.version == 1 && selection.cutoff_unix_seconds > now
        && selection.cutoff_unix_seconds - now <= 25,
        "original material cutoff absent or expired");
    let (executable_sha256, _) = executable_identity()?;
    ensure!(executable_sha256 == selection.expected_executable_sha256,
        "actual material executable differs");
    let configuration = material::read_configuration(&selection.configuration_file, &selection.configuration_custody)?;
    let (actual, binding_projection, public_projection) = material::derive_seed(&configuration)?;
    ensure!(actual.issuer.source_digest == selection.expected_worker_source_digest
        && actual.issuer.script_version == selection.expected_worker_script_version,
        "initial candidate configuration differs from selected Worker artifact");
    let profile_digest = aos_hub_core::mirror_acceptance::mirror_candidate_profile_digest(
        &actual.profile, &actual.policy)?;
    ensure!(private_bytes(&path, MAX_INPUT_BYTES)? == raw
        && aos_hub_core::clock::now_unix_secs() < selection.cutoff_unix_seconds,
        "selected material or cutoff changed before retention");
    material::read_configuration(&selection.configuration_file, &selection.configuration_custody)?;
    write_private(&selection.output_file, &json!({"version":1,
        "selectionSha256":hex::encode(Sha256::digest(&raw)),
        "configurationCustody":selection.configuration_custody,
        "publicConfigurationDigest":aos_hub_core::mirror_work::digest(&public_projection)?,
        "publicConfiguration":public_projection,
        "nativeExecutableSha256":executable_sha256,
        "bindingProjection":binding_projection,
        "material":{"profile":actual.profile,"policy":actual.policy,"issuer":actual.issuer,
            "profileDigest":profile_digest},
        "runtimeAcceptance":null, "providerObservation":null}))?;
    Ok(())
}
