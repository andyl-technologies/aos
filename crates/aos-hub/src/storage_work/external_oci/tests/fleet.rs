//! Confined External OCI origin over existing Fleet SQL and business handlers.
//!
//! The ignored helper loads existing private configuration and authenticates the
//! reserved controlled candidate. It serves the real Hybrid router; it does not
//! create SQL authority, credentials, probe outcomes, routes or provider objects.
//! The caller owns normal setup and publication, independent transport capture,
//! process supervision and readback. The ordinary Hosted constructor is unused.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::future::IntoFuture as _;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::backend::{Backend as _, SqlxBackend};
use aos_hub_core::db::Database;
use aos_hub_core::storage_authority::external_object::oci::{
    candidate::{ExternalOciCandidate, MAX_OCI_CANDIDATE_BYTES},
    qualification::ExternalOciProfile,
};
use aos_hub_core::storage_work::{StorageBindingSnapshot, StorageWorkKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::super::{ExternalOciRuntime, RemoteStorageWorkClient};

#[path = "fleet/background.rs"]
mod background;

const MAX_INPUT_BYTES: u64 = 64 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const FIXTURE_ROOT: &str = "/var/lib/hybrid-native/external-oci";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReleaseFiles {
    publication_key_id: String,
    publication_seed_file: PathBuf,
    channel_key_id: String,
    channel_seed_file: PathBuf,
    publication_keys_file: PathBuf,
    qualification_keys_file: PathBuf,
}

// This optional role selects only an independently measured Direct artifact.
// It cannot be supplied by the OCI candidate, Copy/List contracts or issuer keys.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DirectFiles {
    acceptance_file: PathBuf,
    review_keys_file: PathBuf,
    guard_key_file: PathBuf,
}

// A functional document is separate from both the Direct prerequisite and the
// OCI candidate. Its reviewer and read-only guard role are owner-selected.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MirrorFunctionalFiles {
    artifact_file: PathBuf,
    reviewer_public_key_file: PathBuf,
    guard_key_file: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Files {
    #[serde(default)]
    direct: Option<DirectFiles>,
    #[serde(default)]
    mirror_functional: Option<MirrorFunctionalFiles>,
    database_url_file: PathBuf,
    jwt_secret_file: PathBuf,
    seal_key_file: PathBuf,
    route_keys_file: PathBuf,
    secret_version_manifest_file: PathBuf,
    domain_probe_signer_manifest_file: PathBuf,
    tls_root_file: PathBuf,
    work_key_file: PathBuf,
    ingress_key_file: PathBuf,
    guard_key_file: PathBuf,
    candidate_key_file: PathBuf,
    candidate_file: PathBuf,
    candidate_signature_file: PathBuf,
    profile_file: PathBuf,
    release: ReleaseFiles,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    version: u8,
    run_id: String,
    listen: SocketAddr,
    public_origin: String,
    control_origin: String,
    deployment_id: String,
    worker_source_digest: String,
    worker_script_version: String,
    clock_uncertainty_seconds: i64,
    placement_id: i64,
    placement_prefix: String,
    expected_executable_sha256: String,
    readiness_file: PathBuf,
    terminal_file: PathBuf,
    shutdown_file: PathBuf,
    files: Files,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Shutdown {
    version: u8,
    input_sha256: String,
    candidate_sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stop {
    OwnerShutdown,
    OriginalExpired,
}

fn hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Input {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && hex_digest(&self.run_id, 32),
            "External OCI helper run differs"
        );
        ensure!(
            self.listen == SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4676)
                && self.public_origin == "https://localhost:4673"
                && self.control_origin == "https://localhost:4674",
            "External OCI helper requires its distinct reserved logical pair"
        );
        ensure!(
            !self.deployment_id.is_empty()
                && self.deployment_id.len() <= 256
                && hex_digest(&self.worker_source_digest, 64)
                && self.worker_script_version
                    == aos_hub_core::direct_upload::direct_worker_emulated_script_id(
                        &self.worker_source_digest
                    )?
                && (1..30).contains(&self.clock_uncertainty_seconds)
                && self.placement_id > 0
                && self.placement_prefix
                    == format!(
                        ".aos-direct-qualification/external-oci/{}/registry",
                        self.run_id
                    )
                && hex_digest(&self.expected_executable_sha256, 64),
            "External OCI helper source, placement or clock differs"
        );
        let root = Path::new(FIXTURE_ROOT).join(&self.run_id);
        ensure!(
            [
                &self.readiness_file,
                &self.terminal_file,
                &self.shutdown_file
            ]
            .iter()
            .all(|path| path.parent() == Some(root.as_path()))
                && self.readiness_file != self.terminal_file
                && self.readiness_file != self.shutdown_file
                && self.terminal_file != self.shutdown_file,
            "External OCI helper lifecycle files leave their private run root"
        );
        Ok(())
    }
}

fn private_bytes(path: &Path, maximum: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    crate::auth::seal::read_secret_file_zeroizing_capped(path, maximum)
}

fn private_text(path: &Path, maximum: u64) -> Result<zeroize::Zeroizing<String>> {
    let raw = private_bytes(path, maximum)?;
    Ok(zeroize::Zeroizing::new(
        std::str::from_utf8(&raw)?.trim().to_owned(),
    ))
}

fn write_private(path: &Path, value: &serde_json::Value) -> Result<()> {
    let parent = fs::symlink_metadata(path.parent().context("private receipt parent absent")?)?;
    ensure!(
        parent.is_dir()
            && !parent.file_type().is_symlink()
            && parent.permissions().mode() & 0o077 == 0
            && parent.uid() == fs::metadata("/proc/self")?.uid(),
        "External OCI receipt parent is not owner-private"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn executable_identity() -> Result<(String, u64)> {
    let path = std::env::current_exe()?;
    let mut file = fs::File::open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() > 0 && before.len() <= MAX_EXECUTABLE_BYTES,
        "External OCI helper executable exceeds its selected bound"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("executable byte count overflow")?;
        ensure!(
            bytes <= MAX_EXECUTABLE_BYTES,
            "helper executable grew past its bound"
        );
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    ensure!(
        bytes == before.len()
            && before.len() == after.len()
            && before.ino() == after.ino()
            && before.dev() == after.dev()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime_nsec() == after.ctime_nsec()
            && before.mtime() == after.mtime()
            && before.ctime() == after.ctime(),
        "External OCI helper executable changed while hashing"
    );
    Ok((hex::encode(hash.finalize()), bytes))
}

fn process_start_ticks() -> Result<u64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let fields = stat
        .rsplit_once(')')
        .context("process stat command absent")?
        .1;
    fields
        .split_whitespace()
        .nth(19)
        .context("process start tick absent")?
        .parse()
        .context("invalid process start tick")
}

async fn existing_database(url: &str) -> Result<Database> {
    ensure!(
        url.starts_with("postgres://") || url.starts_with("postgresql://"),
        "External OCI helper requires the existing dedicated PostgreSQL instance"
    );
    #[cfg(feature = "postgres")]
    let backend = SqlxBackend::connect_postgres(url).await?;
    #[cfg(not(feature = "postgres"))]
    {
        anyhow::bail!("External OCI helper requires compiled PostgreSQL support");
    }
    #[cfg(feature = "postgres")]
    {
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
            "External OCI existing schema differs"
        );
        let db = Database::attach(Box::new(backend));
        db.validate_binding_identity_reservations().await?;
        Ok(db)
    }
}

async fn selected_profile(
    db: &Database,
    input: &Input,
    profile: &ExternalOciProfile,
    latest: i64,
) -> Result<()> {
    let placement = db
        .surface_placement(input.placement_id)
        .await?
        .context("selected existing placement absent")?;
    ensure!(
        placement.prefix == input.placement_prefix
            && placement.registry_id.is_some()
            && placement.effective_read_enabled
            && placement.effective_write_enabled,
        "External OCI selected placement differs"
    );
    let binding = db
        .binding(placement.binding_id)
        .await?
        .context("selected existing binding absent")?;
    ensure!(
        !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2"),
        "External OCI helper cannot select Managed storage"
    );
    let credentials = db.list_current_binding_credentials(binding.id).await?;
    let snapshot = StorageBindingSnapshot::from_binding(
        input.deployment_id.clone(),
        &binding,
        &credentials,
        latest,
        latest
            .checked_add(30)
            .context("binding observation cutoff overflow")?,
    )?;
    profile.validate_snapshot(&snapshot, latest)?;
    Ok(())
}

// The normal production loader verifies the reviewer and all current measured
// facts. Parsing the already authenticated record below only correlates the
// selected source and audience; it grants no additional acceptance.
struct DirectSelection {
    factory: Arc<dyn crate::direct_upload::DirectUploadTransportFactory>,
    profiles: crate::direct_upload::authority::NativeDirectUploadAcceptances,
}

fn install_direct_profiles(
    work: RemoteStorageWorkClient,
    direct: Option<&DirectSelection>,
) -> RemoteStorageWorkClient {
    match direct {
        Some(direct) => work.with_mirror_profiles(direct.profiles.clone()),
        None => work,
    }
}

fn install_mirror_functional(work: RemoteStorageWorkClient, input: &Input) -> Result<RemoteStorageWorkClient> {
    use aos_hub_core::mirror_acceptance::external_controlled::{
        ControlledExternalMirrorArtifact, CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES,
    };

    let Some(files) = &input.files.mirror_functional else { return Ok(work); };
    let direct = input.files.direct.as_ref().context("functional Mirror requires real Direct files")?;
    let raw = private_bytes(&files.artifact_file, CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES as u64)?;
    let artifact: ControlledExternalMirrorArtifact = serde_json::from_slice(&raw)?;
    let reviewer = private_text(&files.reviewer_public_key_file, 4096)?;
    let prerequisite_reviewers: BTreeMap<String, String> = serde_json::from_slice(
        &private_bytes(&direct.review_keys_file, MAX_INPUT_BYTES)?)?;
    for key in prerequisite_reviewers.values() {
        aos_hub_core::mirror_acceptance::external_controlled::require_distinct_external_mirror_reviewer(
            reviewer.as_str(), key)?;
    }
    ensure!(artifact.installation.native_executable_sha256 == input.expected_executable_sha256
        && artifact.upstream_base == format!("https://aos.andyl.org:4778/fleet-mirror/{}", input.run_id)
        && artifact.placement_prefix == format!(".aos-mirror-qualification/{}/final", input.run_id),
        "functional Mirror selected another helper or reserved fixture source");
    let guard = private_bytes(&files.guard_key_file, 8192)?;
    let physical = private_bytes(&input.files.guard_key_file, 8192)?;
    let readback_role = StorageWorkKey::new(guard.as_slice())?;
    let physical_role = StorageWorkKey::new(physical.as_slice())?;
    let separation = b"aos.hub.external-mirror-readback-role-separation.v1";
    ensure!(readback_role.sign_body(separation)? != physical_role.sign_body(separation)?,
        "functional Mirror guard cannot borrow physical producer authority");
    ensure!(raw.as_slice() == private_bytes(&files.artifact_file, CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES as u64)?.as_slice(),
        "functional Mirror artifact changed during selection");
    work.with_controlled_external_mirror(artifact, reviewer.as_str(), guard.as_slice())
}

fn direct_selection(input: &Input, work_key: &[u8]) -> Result<Option<DirectSelection>> {
    use crate::direct_upload::authority::{
        NativeDirectUploadAcceptances, NativeDirectUploadRuntime,
    };

    let Some(files) = &input.files.direct else {
        return Ok(None);
    };
    let original = private_bytes(&files.acceptance_file, MAX_INPUT_BYTES)?;
    let acceptances =
        NativeDirectUploadAcceptances::from_files(&files.acceptance_file, &files.review_keys_file)?;
    let artifact: aos_hub_core::direct_upload::DirectWorkerQualificationArtifact =
        serde_json::from_slice(&original)?;
    ensure!(
        artifact.deployment_id == input.deployment_id
            && artifact.public_origin == input.public_origin
            && artifact.source_digest == input.worker_source_digest
            && artifact.script_version == input.worker_script_version
            && *private_bytes(&files.acceptance_file, MAX_INPUT_BYTES)? == *original,
        "Direct acceptance differs from this helper's exact selected Worker"
    );
    let guard_key = private_bytes(&files.guard_key_file, 8192)?;
    // This constructor keeps the production role separation, clock policy and
    // current acceptance checks. TLS uses the existing configured CA bundle.
    let runtime = NativeDirectUploadRuntime::new(
        &input.public_origin,
        &input.deployment_id,
        work_key,
        &guard_key,
        acceptances.clone(),
    )?;
    Ok(Some(DirectSelection {
        factory: Arc::new(runtime),
        profiles: acceptances,
    }))
}

async fn app_state(db: Arc<Database>, input: &Input) -> Result<crate::server::AppState> {
    let files = &input.files;
    let mut state = crate::server::AppState::new(db.clone(), input.public_origin.clone()).await;
    state.deployment_id = Some(input.deployment_id.clone());
    state.leases = Arc::new(aos_hub_core::lease::DatabasePublishLease::new(db.clone()));

    let jwt = private_bytes(&files.jwt_secret_file, 8192)?;
    ensure!(jwt.len() >= 32, "existing JWT secret is too short");
    state.auth = Arc::new(crate::auth::extract::AuthState {
        db: db.clone(),
        jwt_keys: crate::auth::jwt::JwtKeys::from_secret(&jwt),
        access_token_ttl: state.auth.access_token_ttl,
        ratelimit: state.ratelimit.clone(),
        trusted_proxy: false,
    });
    let seal = private_bytes(&files.seal_key_file, 8192)?;
    let key = zeroize::Zeroizing::new(aos_hub_core::auth::seal::parse_key(&seal)?);
    state.sealer = Arc::new(aos_hub_core::auth::seal::AesGcmSealer::new(&key)?);
    state.secret_versions =
        crate::coreports::load_secret_version_manifest(&files.secret_version_manifest_file)?;

    let keys = private_text(&files.route_keys_file, MAX_INPUT_BYTES)?;
    let keyring =
        Arc::new(aos_hub_core::service::ConfiguredRouteReservationKeyring::from_json(&keys)?);
    keyring.validate_referenced_versions(&db).await?;
    state.route_reservation_keyring = Some(keyring);
    let manifest = private_text(&files.domain_probe_signer_manifest_file, MAX_INPUT_BYTES)?;
    state.domain_probe_terminator = Some(Arc::new(
        aos_hub_core::topology_probe::ManifestDomainProbeTerminatorProvider::from_json(
            &manifest,
            "native_file",
        )?,
    ));

    let release = &files.release;
    let publication_seed = private_text(&release.publication_seed_file, 4096)?;
    let channel_seed = private_text(&release.channel_seed_file, 4096)?;
    let publication_keys: BTreeMap<String, String> = serde_json::from_slice(&private_bytes(
        &release.publication_keys_file,
        MAX_INPUT_BYTES,
    )?)?;
    let qualification_keys: BTreeMap<String, String> = serde_json::from_slice(&private_bytes(
        &release.qualification_keys_file,
        MAX_INPUT_BYTES,
    )?)?;
    state.release_evidence = Some(Arc::new(
        aos_hub_core::release_evidence::Ed25519ReleaseEvidenceAuthority::from_base64(
            input.deployment_id.clone(),
            release.publication_key_id.clone(),
            &publication_seed,
            release.channel_key_id.clone(),
            &channel_seed,
            publication_keys,
            qualification_keys,
        )?,
    ));
    Ok(state)
}

async fn wait_for_stop(
    input: &Input,
    input_sha: &str,
    candidate_sha: &str,
    original_deadline: Instant,
    expires_at: i64,
) -> Result<Stop> {
    let mut interval = tokio::time::interval(Duration::from_millis(50));
    loop {
        interval.tick().await;
        let latest = aos_hub_core::clock::now_unix_secs()
            .checked_add(input.clock_uncertainty_seconds)
            .context("External OCI clock overflow")?;
        if Instant::now() >= original_deadline || latest >= expires_at {
            return Ok(Stop::OriginalExpired);
        }
        match fs::symlink_metadata(&input.shutdown_file) {
            Ok(_) => {
                let stop: Shutdown =
                    serde_json::from_slice(&private_bytes(&input.shutdown_file, 4096)?)?;
                ensure!(
                    stop.version == 1
                        && stop.input_sha256 == input_sha
                        && stop.candidate_sha256 == candidate_sha,
                    "External OCI shutdown names another original"
                );
                return Ok(Stop::OwnerShutdown);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
}

async fn serve_window(
    server: impl std::future::Future<Output = std::io::Result<()>>,
    input: &Input,
    input_sha: &str,
    candidate_sha: &str,
    deadline: Instant,
    expires_at: i64,
    controllers: &mut background::Controllers,
) -> Result<Stop> {
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            result?;
            anyhow::bail!("External OCI server ended before its owner window");
        }
        reason = wait_for_stop(input, input_sha, candidate_sha, deadline, expires_at) => reason,
        result = controllers.next_exit() => {
            result?;
            Ok(Stop::OriginalExpired)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the actual confined External OCI Fleet pair and existing SQL authority"]
async fn actual_external_oci_fleet_origin() -> Result<()> {
    let path = PathBuf::from(
        std::env::var_os("AOS_EXTERNAL_OCI_FLEET_INPUT")
            .context("private External OCI helper input required")?,
    );
    let bytes = private_bytes(&path, MAX_INPUT_BYTES)?;
    let input: Input = serde_json::from_slice(&bytes)?;
    input.validate()?;
    let input_sha = hex::encode(Sha256::digest(&bytes));
    let (executable_sha, executable_bytes) = executable_identity()?;
    ensure!(
        executable_sha == input.expected_executable_sha256,
        "selected External OCI test ELF differs"
    );

    let work_key = private_bytes(&input.files.work_key_file, 8192)?;
    let guard_bytes = private_bytes(&input.files.guard_key_file, 8192)?;
    let guard_key = StorageWorkKey::new(guard_bytes.as_slice())?;
    let candidate_key =
        StorageWorkKey::new(private_bytes(&input.files.candidate_key_file, 8192)?.as_slice())?;
    let work_role = StorageWorkKey::new(work_key.as_slice())?;
    let role_domain = b"aos.oci.fixture.role-separation";
    ensure!(
        candidate_key.sign_body(role_domain)? != guard_key.sign_body(role_domain)?
            && candidate_key.sign_body(role_domain)? != work_role.sign_body(role_domain)?,
        "External OCI candidate role overlaps a production role"
    );
    let raw_candidate = private_bytes(&input.files.candidate_file, MAX_OCI_CANDIDATE_BYTES as u64)?;
    let signature = private_text(&input.files.candidate_signature_file, 4096)?;
    let candidate = ExternalOciCandidate::authenticate(&candidate_key, &signature, &raw_candidate)?;
    let profile: ExternalOciProfile =
        serde_json::from_slice(&private_bytes(&input.files.profile_file, MAX_INPUT_BYTES)?)?;
    let now = aos_hub_core::clock::now_unix_secs();
    let latest = now
        .checked_add(input.clock_uncertainty_seconds)
        .context("External OCI clock overflow")?;
    candidate.validate(
        &input.deployment_id,
        &input.worker_source_digest,
        &input.worker_script_version,
        &profile,
        &input.placement_prefix,
        latest,
    )?;
    let remaining = u64::try_from(
        candidate
            .expires_at
            .checked_sub(latest)
            .context("candidate time overflow")?,
    )?;
    let original_deadline = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .context("monotonic helper deadline overflow")?;
    let candidate_sha = hex::encode(Sha256::digest(&raw_candidate));
    let expires_at = candidate.expires_at;

    let database_url = private_text(&input.files.database_url_file, 8192)?;
    let db = Arc::new(existing_database(&database_url).await?);
    selected_profile(&db, &input, &profile, latest).await?;
    let root = private_bytes(&input.files.tls_root_file, MAX_INPUT_BYTES)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .add_root_certificate(reqwest::Certificate::from_pem(&root)?)
        .build()?;
    let runtime = ExternalOciRuntime::controlled(
        candidate,
        profile,
        input.clock_uncertainty_seconds,
        guard_bytes.as_slice(),
        now,
    )?;
    let direct = direct_selection(&input, &work_key)?;
    let work =
        RemoteStorageWorkClient::new(&input.public_origin, input.deployment_id.clone(), &work_key)?
            .with_controlled_http(http)
            .with_external_oci_runtime(runtime)?;
    let work = install_direct_profiles(work, direct.as_ref());
    let work = Arc::new(install_mirror_functional(work, &input)?);
    let ingress = private_bytes(&input.files.ingress_key_file, 8192)?;
    let ingress = Arc::new(aos_hub_core::hybrid_ingress::HybridIngressKey::new(
        &ingress,
    )?);
    let state = Arc::new(app_state(Arc::clone(&db), &input).await?);
    let router = crate::server::router_with_hybrid_ingress_and_direct(
        state,
        ingress,
        input.deployment_id.clone(),
        Arc::clone(&work),
        direct.map(|selection| selection.factory),
    )
    .await;
    let latest = aos_hub_core::clock::now_unix_secs()
        .checked_add(input.clock_uncertainty_seconds)
        .context("External OCI clock overflow")?;
    ensure!(
        latest < expires_at && Instant::now() < original_deadline,
        "External OCI original expired during startup"
    );
    ensure!(
        !input.shutdown_file.try_exists()?,
        "External OCI shutdown already exists"
    );
    let listener = tokio::net::TcpListener::bind(input.listen).await?;

    // This process has one exact ignored selector. Existing production events
    // remain observational; the caller retains full stdout/stderr and joins its
    // own proxy and SQL windows. This logger supplies no completeness verdict.
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(std::io::stderr)
            .finish(),
    )?;
    let start_ticks = process_start_ticks()?;
    let mut controllers = background::Controllers::start(
        db,
        work,
        &input.run_id,
        original_deadline,
        expires_at,
        input.clock_uncertainty_seconds,
    )?;
    let identity = json!({"pid":std::process::id(), "startTicks":start_ticks,
        "executableSha256":executable_sha, "executableBytes":executable_bytes,
        "inputSha256":input_sha, "candidateSha256":candidate_sha,
        "selectedWorkerSourceDigest":input.worker_source_digest, "selectedWorkerScriptVersion":input.worker_script_version,
        "placementId":input.placement_id, "placementPrefix":input.placement_prefix,
        "publicOrigin":input.public_origin, "controlOrigin":input.control_origin,
        "expiresAt":expires_at, "clockUncertaintySeconds":input.clock_uncertainty_seconds});
    let readiness = write_private(
        &input.readiness_file,
        &json!({"version":1,"scope":"controlled_external_oci_native_origin",
        "identity":identity, "listen":input.listen, "observedAt":aos_hub_core::clock::now_unix_secs(),
        "backgroundControllers":controllers.selection(),
        "nativeBulkBytes":null,"providerSdkCalls":null}),
    );

    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .into_future();
    let outcome = match readiness {
        Ok(()) => {
            serve_window(
                server,
                &input,
                &input_sha,
                &candidate_sha,
                original_deadline,
                expires_at,
                &mut controllers,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let joined = controllers.stop().await;
    let reason = match outcome {
        Ok(reason) => {
            joined?;
            reason
        }
        Err(error) => {
            if let Err(join_error) = joined {
                tracing::warn!(error = %format!("{join_error:#}"), "External helper controller shutdown failed");
            }
            return Err(error);
        }
    };
    // Dropping the server is not proof that provider promises drained. The
    // supervisor observes actual process exit; pending effects stay unknown.
    write_private(
        &input.terminal_file,
        &json!({"version":1,"scope":"controlled_external_oci_native_origin",
        "identity":identity,"stopReason":reason,"observedAt":aos_hub_core::clock::now_unix_secs(),
        "nativeBulkBytes":null,"providerSdkCalls":null,"providerEffectsSettled":null}),
    )?;
    Ok(())
}

fn test_input() -> Input {
    let run = "1".repeat(32);
    let file = PathBuf::from("/private/existing-file");
    let source = "2".repeat(64);
    Input {
        version: 1,
        run_id: run.clone(),
        listen: "127.0.0.1:4676".parse().unwrap(),
        public_origin: "https://localhost:4673".into(),
        control_origin: "https://localhost:4674".into(),
        deployment_id: "controlled-existing-fleet".into(),
        worker_source_digest: source.clone(),
        worker_script_version: aos_hub_core::direct_upload::direct_worker_emulated_script_id(
            &source,
        )
        .unwrap(),
        clock_uncertainty_seconds: 2,
        placement_id: 1,
        placement_prefix: format!(".aos-direct-qualification/external-oci/{run}/registry"),
        expected_executable_sha256: "3".repeat(64),
        readiness_file: Path::new(FIXTURE_ROOT).join(&run).join("ready.json"),
        terminal_file: Path::new(FIXTURE_ROOT).join(&run).join("terminal.json"),
        shutdown_file: Path::new(FIXTURE_ROOT).join(&run).join("shutdown.json"),
        files: Files {
            direct: None,
            mirror_functional: None,
            database_url_file: file.clone(),
            jwt_secret_file: file.clone(),
            seal_key_file: file.clone(),
            route_keys_file: file.clone(),
            secret_version_manifest_file: file.clone(),
            domain_probe_signer_manifest_file: file.clone(),
            tls_root_file: file.clone(),
            work_key_file: file.clone(),
            ingress_key_file: file.clone(),
            guard_key_file: file.clone(),
            candidate_key_file: file.clone(),
            candidate_file: file.clone(),
            candidate_signature_file: file.clone(),
            profile_file: file.clone(),
            release: ReleaseFiles {
                publication_key_id: "existing-release-role".into(),
                publication_seed_file: file.clone(),
                channel_key_id: "existing-channel-role".into(),
                channel_seed_file: file.clone(),
                publication_keys_file: file.clone(),
                qualification_keys_file: file,
            },
        },
    }
}

#[test]
fn confined_selection_rejects_other_origin_source_prefix_and_output() {
    let input = test_input();
    input.validate().unwrap();

    for changed in [
        Input {
            listen: "0.0.0.0:4676".parse().unwrap(),
            ..input.clone()
        },
        Input {
            public_origin: "https://localhost:4643".into(),
            ..input.clone()
        },
        Input {
            worker_source_digest: "4".repeat(64),
            ..input.clone()
        },
        Input {
            placement_prefix: "production/containers".into(),
            ..input.clone()
        },
        Input {
            readiness_file: PathBuf::from("/tmp/ready.json"),
            ..input.clone()
        },
        Input {
            terminal_file: input.readiness_file.clone(),
            ..input.clone()
        },
        Input {
            clock_uncertainty_seconds: 30,
            ..input.clone()
        },
        Input {
            clock_uncertainty_seconds: 0,
            ..input
        },
    ] {
        assert!(changed.validate().is_err());
    }
}

#[test]
fn private_receipts_are_exclusive_and_never_seed_numeric_zero() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("ready.json");
    let record = json!({"nativeBulkBytes":null,"providerSdkCalls":null});
    write_private(&path, &record).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap(),
        record
    );
    assert!(write_private(&path, &json!({"nativeBulkBytes":0})).is_err());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap(),
        record
    );
}

#[tokio::test]
async fn original_expiry_drops_the_pending_origin_without_owner_renewal() {
    struct PendingOrigin(Arc<std::sync::atomic::AtomicBool>);
    impl std::future::Future for PendingOrigin {
        type Output = std::io::Result<()>;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingOrigin {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let input = test_input();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let work = Arc::new(
        RemoteStorageWorkClient::new(&input.public_origin, input.deployment_id.clone(), &[11; 32])
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_millis(20);
    let expires_at = aos_hub_core::clock::now_unix_secs() + 600;
    let mut controllers = background::Controllers::start(
        db,
        work,
        &input.run_id,
        deadline,
        expires_at,
        input.clock_uncertainty_seconds,
    )
    .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        serve_window(
            PendingOrigin(dropped.clone()),
            &input,
            "input",
            "candidate",
            deadline,
            expires_at,
            &mut controllers,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, Stop::OriginalExpired);
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    controllers.stop().await.unwrap();
}

#[tokio::test]
async fn owner_shutdown_cannot_name_another_input_or_candidate() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut input = test_input();
    input.shutdown_file = root.path().join("shutdown.json");
    write_private(
        &input.shutdown_file,
        &json!({"version":1,"inputSha256":"another","candidateSha256":"candidate"}),
    )
    .unwrap();
    assert!(wait_for_stop(
        &input,
        "input",
        "candidate",
        Instant::now() + Duration::from_secs(1),
        aos_hub_core::clock::now_unix_secs() + 600
    )
    .await
    .is_err());
}

#[tokio::test]
async fn unsigned_business_request_is_rejected_before_body_consumption() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let state = Arc::new(crate::server::AppState::new(db, "https://localhost:4673".into()).await);
    let work = Arc::new(
        RemoteStorageWorkClient::new(
            "https://localhost:4673",
            "controlled-existing-fleet".into(),
            b"fixture-work-role-at-least-thirty-two-bytes",
        )
        .unwrap(),
    );
    let key = Arc::new(
        aos_hub_core::hybrid_ingress::HybridIngressKey::new(
            b"fixture-ingress-role-at-least-thirty-two-bytes",
        )
        .unwrap(),
    );
    let router = crate::server::router_with_hybrid_ingress(
        state,
        key,
        "controlled-existing-fleet".into(),
        work,
    )
    .await;
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let stream = futures_util::stream::poll_fn(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(
            axum::body::Bytes::from_static(b"unadmitted-body"),
        )))
    });
    let request = axum::http::Request::builder()
        .method("PUT")
        .uri("/v2/aos/manifests/latest")
        .body(axum::body::Body::from_stream(stream))
        .unwrap();
    let reply = router.oneshot(request).await.unwrap();
    assert_eq!(reply.status(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[test]
fn optional_direct_role_requires_the_closed_complete_private_triplet() {
    let fields = json!({
        "acceptanceFile": "/private/direct/acceptance.json",
        "reviewKeysFile": "/private/direct/reviewers.json",
        "guardKeyFile": "/private/direct/guard.key"
    });
    serde_json::from_value::<DirectFiles>(fields.clone()).unwrap();
    for name in ["acceptanceFile", "reviewKeysFile", "guardKeyFile"] {
        let mut missing = fields.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<DirectFiles>(missing).is_err());
    }
    let mut widened = fields;
    widened["copyContract"] = json!({});
    assert!(serde_json::from_value::<DirectFiles>(widened).is_err());
}

#[test]
fn omitted_direct_role_does_not_load_files_or_grant_a_factory() {
    // The predecessor has no Direct role; its deliberately absent private paths
    // must remain unused when the optional triplet is omitted.
    assert!(direct_selection(&test_input(), b"unused")
        .unwrap()
        .is_none());
    let work =
        RemoteStorageWorkClient::new("https://localhost:4673", "deployment-1".into(), &[11; 32])
            .unwrap();
    assert!(install_direct_profiles(work, None)
        .mirror_profiles
        .is_none());
}

#[tokio::test]
async fn genuine_direct_selection_installs_the_same_verified_profiles_on_work() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db
        .create_org("direct-profile", "Direct profile")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let binding = db
        .create_topology_binding(
            Some(org),
            "binding",
            &owner.stable_id,
            "Binding",
            "s3",
            None,
            Some("qualified-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("test-region"),
            Some("private"),
        )
        .await
        .unwrap();
    let binding = db.binding(binding).await.unwrap().unwrap();
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap();
    let origin = "https://localhost:4673";
    let (profiles, expected) = crate::direct_upload::authority::external_acceptance_fixture(
        origin,
        now,
        now + 600,
        &binding,
    );
    let runtime = crate::direct_upload::authority::NativeDirectUploadRuntime::new(
        origin,
        "deployment-1",
        &[11; 32],
        &[12; 32],
        profiles.clone(),
    )
    .unwrap();
    let selection = DirectSelection {
        factory: Arc::new(runtime),
        profiles,
    };
    let work = RemoteStorageWorkClient::new(origin, "deployment-1".into(), &[11; 32]).unwrap();
    let work = install_direct_profiles(work, Some(&selection));

    assert_eq!(
        work.mirror_profiles
            .as_ref()
            .unwrap()
            .profiles("deployment-1", origin, now)
            .unwrap(),
        vec![expected]
    );
    assert!(work
        .mirror_profiles
        .as_ref()
        .unwrap()
        .profiles("deployment-1", "https://localhost:4674", now)
        .is_err());
    let mut controllers = background::Controllers::start(
        Arc::new(db),
        Arc::new(work),
        &"1".repeat(32),
        Instant::now() + Duration::from_secs(30),
        i64::try_from(now + 600).unwrap(),
        2,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(controllers.selection()).unwrap(),
        json!({
            "placementScan":{"intervalSeconds":2,"maximumPlacements":5},
            "ociInventory":{
                "collectorId":format!("external-oci-inventory-{}", "1".repeat(32)),
                "idempotencyPrefix":format!("external-oci-inventory-{}", "1".repeat(32)),
                "maximumPlacements":100,"dispatchBudget":"native"
            },
            "mirrorSync":{"intervalSeconds":60,"mode":"full"}
        })
    );
    tokio::task::yield_now().await;
    controllers.stop().await.unwrap();
}

#[test]
fn direct_factory_refuses_an_oci_candidate_instead_of_measured_acceptance() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let artifact = root.path().join("oci-candidate.json");
    let reviewers = root.path().join("reviewers.json");
    let guard = root.path().join("guard.key");
    write_private(
        &artifact,
        &json!({"version":1,"profile_digest":"0".repeat(64)}),
    )
    .unwrap();
    write_private(&reviewers, &json!({})).unwrap();
    let mut input = test_input();
    input.files.direct = Some(DirectFiles {
        acceptance_file: artifact,
        review_keys_file: reviewers,
        guard_key_file: guard,
    });
    // The unchanged production loader refuses before the absent guard is read,
    // a business router is constructed, or any provider exchange can begin.
    assert!(direct_selection(&input, b"unused").is_err());
}

#[test]
fn optional_mirror_functional_role_is_closed_and_needs_the_real_prerequisite() {
    let files = json!({
        "artifactFile": "/private/mirror/artifact.json",
        "reviewerPublicKeyFile": "/private/mirror/reviewer.pub",
        "guardKeyFile": "/private/mirror/guard.key"
    });
    serde_json::from_value::<MirrorFunctionalFiles>(files.clone()).unwrap();
    for name in ["artifactFile", "reviewerPublicKeyFile", "guardKeyFile"] {
        let mut missing = files.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<MirrorFunctionalFiles>(missing).is_err());
    }
    let mut widened = files.clone();
    widened["accepted"] = json!(true);
    assert!(serde_json::from_value::<MirrorFunctionalFiles>(widened).is_err());

    let mut input = test_input();
    let work = RemoteStorageWorkClient::new("https://localhost:4673", "deployment-1".into(), &[11; 32]).unwrap();
    let work = install_mirror_functional(work, &input).unwrap();
    assert!(work.controlled_external_mirror.is_none());
    input.files.mirror_functional = Some(serde_json::from_value(files).unwrap());
    assert!(install_mirror_functional(work, &input).is_err());
}
