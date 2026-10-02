//! Authenticates and stages an immutable image without changing boot selection.
//!
//! The signed registry supplies exact NAR and delivery identities. The running
//! image selects the physical staging executable; its receipt is admitted into
//! the retained image index only after the candidate metadata agrees.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::adapter::{CancellationToken, RuntimeControl};
use aos_core::output::Printer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::ApmConfig;
use crate::download::{
    DownloadRequest, default_engine, download_nars, fetch_narinfo_closure, resolve_mirror_chain,
    split_mirror_chain,
};
use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::ResolvedClosure;
use crate::types::{BootProviderState, ImageDelivery, ImageGeneration, ModuleLibraryIdentity};

use super::{
    IMAGE_PROFILE_DIR, IMAGE_STATE_FILE, load_image_generation_state_pub, read_toplevel_meta,
    running_image_generation, sync_directory, write_atomic_durable,
};

const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Serialize)]
struct StageRequest<'a> {
    schema: &'static str,
    action: &'static str,
    generation: u32,
    source: &'a Path,
    metadata: &'a Path,
    artifacts: &'a Path,
    delivery: &'a ImageDelivery,
    candidate: &'a ImageGeneration,
    running: &'a ImageGeneration,
    retained_generations: &'a [ImageGeneration],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagePreflight {
    schema: String,
    generation: u32,
    retirement_required: bool,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageIntent {
    schema: String,
    generation: u32,
    toplevel: String,
    source_sha256: String,
    stage_executable: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageReceipt {
    schema: String,
    generation: u32,
    toplevel: String,
    boot_artifact_contract: String,
    boot_provider_state: BootProviderState,
}

/// Authenticates, physically stages, and durably indexes a candidate image.
///
/// Boot selection and rollout admission remain separate operations. An
/// outstanding rollout or selection rejects staging before any slot write.
///
/// # Errors
///
/// Returns an error for unsigned release graphs, content drift, incompatible
/// state formats, busy image state, physical staging failure, or an invalid
/// receipt, cancellation at the staging boundary, or a physical helper budget
/// exhaustion. A failed index write leaves physical bytes unselected.
/// Immutable imports finish before cooperative cancellation is honored;
/// physical helpers are cancelled as a process group and fully reaped.
pub(crate) async fn stage_candidate(
    config: &ApmConfig,
    registries: &RegistrySet,
    closure: &ResolvedClosure,
    created_at: &str,
    qualified: bool,
    cancellation: &CancellationToken,
    printer: &Printer,
) -> Result<ImageGeneration> {
    ensure!(!cancellation.is_cancelled(), "image preparation cancelled");
    let package = &closure.root;
    ensure!(package.sysroot, "candidate package is not a sysroot");
    let raw = package
        .images
        .iter()
        .find(|image| image.format == "raw")
        .context("candidate package has no authenticated raw delivery")?;
    raw.delivery
        .validate("raw", &package.version, &package.platform)?;
    ensure!(
        raw.delivery.is_store_backed(),
        "image staging requires a signed store-backed delivery"
    );
    let registry = registries
        .get_registry(&closure.registry_name)
        .context("candidate registry is unavailable")?;
    ensure!(
        registry.release_trust().is_some() && registry.store_map().is_present(),
        "image staging requires an authenticated release graph"
    );
    let registry_config = config
        .registries
        .iter()
        .find(|(entry, _)| entry.name == closure.registry_name)
        .map(|(entry, _)| entry)
        .context("candidate registry has no configured mirror")?;
    let mirror = resolve_mirror_chain(&config.scope.registries_path(), registry_config);

    import_toplevel(config, registries, closure, &mirror, printer).await?;
    import_exact(
        config,
        registries,
        &closure.registry_name,
        &mirror,
        &raw.store_path,
        &raw.nar_hash,
        raw.nar_size,
        printer,
    )
    .await?;
    let document = &raw.delivery.artifact_contract.document;
    import_exact(
        config,
        registries,
        &closure.registry_name,
        &mirror,
        &document.store_path,
        &document.nar_hash,
        document.nar_size,
        printer,
    )
    .await?;
    let artifacts = raw
        .delivery
        .artifact_contract
        .artifacts
        .as_ref()
        .context("candidate delivery has no retained artifact set")?;
    import_exact(
        config,
        registries,
        &closure.registry_name,
        &mirror,
        &artifacts.store_path,
        &artifacts.nar_hash,
        artifacts.nar_size,
        printer,
    )
    .await?;
    // Imports finish before cancellation is honored: their shared downloader
    // owns spawned transfers and store children. Dropping that outer future
    // would detach them. No physical write occurs past this checkpoint.
    ensure!(
        !cancellation.is_cancelled(),
        "image preparation cancelled after immutable imports"
    );
    let source = exact_file(&raw.store_path, &raw.delivery.filename)?;
    verify_file(&source, raw.delivery.byte_size, &raw.delivery.sha256)?;
    let metadata = exact_file(&document.store_path, &document.filename)?;
    verify_file(&metadata, document.byte_size, &document.sha256)?;

    let profile = Path::new(IMAGE_PROFILE_DIR);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(profile.join("candidate-stage.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("another candidate staging operation is active")?;
    let running = running_image_generation()?;
    let mut state = load_image_generation_state_pub(profile)?;
    ensure_staging_available(&state)?;
    let number = state
        .generations
        .iter()
        .map(|image| image.number)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .context("image generation number overflow")?;
    let mut candidate = candidate_identity(package, &closure.registry_name, number, created_at)?;
    ensure!(
        candidate.state_version == running.state_version && !candidate.state_version.is_empty(),
        "candidate and running image have incompatible state formats"
    );
    ensure!(
        candidate.toplevel != running.toplevel,
        "candidate is already the running image"
    );
    let mut validation = state.clone();
    validation.generations.push(candidate.clone());
    validation.validate()?;
    let (library_hash, library_size) =
        crate::store::verification::dump_store_path_identity(&candidate.module_library.store_path)?;
    ensure!(
        library_hash.hex() == crate::verify::sha256_digest_hex(&candidate.module_library.nar_hash)?
            && library_size == candidate.module_library.nar_size,
        "candidate realized native module library differs from its immutable NAR identity"
    );
    if qualified {
        let contract: serde_json::Value = serde_json::from_slice(&std::fs::read(
            Path::new(&candidate.boot_artifact_contract).join("contract.json"),
        )?)?;
        ensure!(
            contract
                .get("health-executable")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|path| !path.is_empty()),
            "qualified reboot requires explicit candidate site health before staging"
        );
    }
    let executable = read_toplevel_meta(Path::new(&running.toplevel), "image-stage-executable")?;
    validate_executable(&executable)?;
    let intent_path = profile.join("candidate-stage.json");
    let intent = StageIntent {
        schema: "aos.image-candidate-stage-intent".into(),
        generation: number,
        toplevel: candidate.toplevel.clone(),
        source_sha256: raw.delivery.sha256.clone(),
        stage_executable: executable.clone(),
    };
    match std::fs::read(&intent_path) {
        Ok(bytes) => {
            let pending: StageIntent = serde_json::from_slice(&bytes)?;
            if let Some(committed) = recover_committed(&state, &candidate, &pending, &intent)? {
                super::remove_file_durable(&intent_path)?;
                return Ok(committed);
            }
            ensure!(
                pending == intent,
                "an interrupted staging intent names another image; reconcile it before staging"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(indexed) = reusable_candidate(&state, &candidate)? {
                return Ok(indexed);
            }
        }
        Err(error) => return Err(error.into()),
    }
    let preflight: StagePreflight = run_stage(
        &executable,
        &StageRequest {
            schema: "aos.image-candidate-stage",
            action: "preflight",
            generation: number,
            source: &source,
            metadata: &metadata,
            artifacts: Path::new(&artifacts.store_path),
            delivery: &raw.delivery,
            candidate: &candidate,
            running: &running,
            retained_generations: &state.generations,
        },
        cancellation,
    )?;
    ensure!(
        preflight.schema == "aos.image-candidate-stage-preflight" && preflight.generation == number,
        "staging preflight names another candidate"
    );
    if preflight.retirement_required {
        // The admitted retirement handler takes the same lock. Revalidate all
        // staging authority after it returns, before publishing a write intent.
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::Unlock)?;
        ensure!(
            super::image_rollout::retire_expired_image_lease(config, printer)?,
            "occupied inactive slot has no authenticated lease eligible for retirement"
        );
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .context("another image operation started during admitted retirement")?;
        let refreshed = load_image_generation_state_pub(profile)?;
        validate_refreshed_authority(&running, &state, &refreshed, number)?;
        let actual_running = running_image_generation()?;
        ensure!(
            native_image_identity(&actual_running)? == native_image_identity(&running)?
                && actual_running.number == running.number,
            "running immutable image changed during retirement"
        );
        state = refreshed;
    }
    match std::fs::read(&intent_path) {
        Ok(bytes) => ensure!(
            serde_json::from_slice::<StageIntent>(&bytes)? == intent,
            "another candidate acquired staging authority during retirement"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic_durable(&intent_path, &serde_json::to_vec(&intent)?)?
        }
        Err(error) => return Err(error.into()),
    }
    let request = StageRequest {
        schema: "aos.image-candidate-stage",
        action: "stage",
        generation: number,
        source: &source,
        metadata: &metadata,
        artifacts: Path::new(&artifacts.store_path),
        delivery: &raw.delivery,
        candidate: &candidate,
        running: &running,
        retained_generations: &state.generations,
    };
    let receipt = run_stage(&executable, &request, cancellation)?;
    candidate = admit_receipt(profile, &mut state, candidate, receipt)?;
    super::remove_file_durable(&intent_path)?;
    Ok(candidate)
}

fn validate_refreshed_authority(
    running: &ImageGeneration,
    original: &crate::types::ImageGenerationState,
    refreshed: &crate::types::ImageGenerationState,
    number: u32,
) -> Result<()> {
    let actual = refreshed
        .running_generation()
        .context("retirement lost the running image")?;
    ensure!(
        refreshed.running == original.running
            && actual.number == running.number
            && serde_json::to_value(actual)? == serde_json::to_value(running)?
            && refreshed.pending.is_none()
            && refreshed.active_rollout.is_none(),
        "image selection or running authority changed during retirement"
    );
    ensure!(
        refreshed
            .generations
            .iter()
            .map(|image| image.number)
            .max()
            .and_then(|number| number.checked_add(1))
            == Some(number),
        "another candidate was indexed during retirement"
    );
    Ok(())
}

fn recover_committed(
    state: &crate::types::ImageGenerationState,
    candidate: &ImageGeneration,
    pending: &StageIntent,
    expected: &StageIntent,
) -> Result<Option<ImageGeneration>> {
    ensure!(
        pending.schema == expected.schema
            && pending.toplevel == expected.toplevel
            && pending.source_sha256 == expected.source_sha256
            && pending.stage_executable == expected.stage_executable,
        "interrupted stage names another authenticated candidate or executor"
    );
    let Some(committed) = state
        .generations
        .iter()
        .find(|image| image.number == pending.generation)
    else {
        return Ok(None);
    };
    ensure!(
        native_image_identity(committed)? == native_image_identity(candidate)?,
        "committed stage metadata differs from authenticated candidate"
    );
    Ok(Some(committed.clone()))
}

fn native_image_identity(image: &ImageGeneration) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(image)?;
    let object = value
        .as_object_mut()
        .context("image identity is not an object")?;
    for field in ["number", "created_at", "boot_provider_state"] {
        object.remove(field);
    }
    Ok(value)
}

fn reusable_candidate(
    state: &crate::types::ImageGenerationState,
    candidate: &ImageGeneration,
) -> Result<Option<ImageGeneration>> {
    let mut matching = Vec::new();
    for indexed in &state.generations {
        if indexed.number != state.running && indexed.toplevel == candidate.toplevel {
            ensure!(
                native_image_identity(indexed)? == native_image_identity(candidate)?,
                "indexed candidate metadata differs from its authenticated package"
            );
            matching.push(indexed.clone());
        }
    }
    ensure!(
        matching.len() <= 1,
        "candidate has ambiguous retained generation identities"
    );
    // The selected rollout handler authenticates its own physical receipt and
    // retirement status; the frontend does not interpret provider evidence.
    Ok(matching.pop())
}

fn admit_receipt(
    profile: &Path,
    state: &mut crate::types::ImageGenerationState,
    mut candidate: ImageGeneration,
    receipt: StageReceipt,
) -> Result<ImageGeneration> {
    ensure!(
        receipt.schema == "aos.image-candidate-staged"
            && receipt.generation == candidate.number
            && receipt.toplevel == candidate.toplevel
            && receipt.boot_artifact_contract == candidate.boot_artifact_contract,
        "physical staging receipt names another candidate"
    );
    candidate.boot_provider_state = receipt.boot_provider_state;
    let mut prepared = state.clone();
    prepared.generations.push(candidate.clone());
    prepared.validate()?;
    let roots = profile.join(format!("image-gen-{}", candidate.number));
    crate::store::create_image_gc_roots(&roots, &candidate)?;
    sync_directory(profile)?;
    write_atomic_durable(
        &profile.join(IMAGE_STATE_FILE),
        &serde_json::to_vec_pretty(&prepared)?,
    )?;
    *state = prepared;
    Ok(candidate)
}

fn candidate_identity(
    package: &crate::types::PackageMeta,
    registry: &str,
    number: u32,
    created_at: &str,
) -> Result<ImageGeneration> {
    let root = Path::new(&package.store_path);
    let meta = |name| read_toplevel_meta(root, name);
    ensure!(
        meta("package-name")? == package.name && meta("version")? == package.version,
        "candidate immutable package identity disagrees with signed catalog"
    );
    let library: ModuleLibraryIdentity = serde_json::from_str(&meta("module-library.json")?)?;
    Ok(ImageGeneration {
        number,
        boot_artifact_contract: meta("boot-artifact-contract")?,
        boot_provider_state: BootProviderState {
            schema: "aos.image-candidate/unselected".into(),
            evidence: serde_json::json!({}),
        },
        toplevel: package.store_path.clone(),
        package_name: package.name.clone(),
        version: package.version.clone(),
        state_version: meta("state-version")?,
        native_executor_ref: meta("native-executor-ref")?,
        registry: registry.into(),
        kernel_path: None,
        module_library: library,
        evaluation_descriptor: meta("evaluation-descriptor")?,
        created_at: created_at.into(),
    })
}

async fn import_toplevel(
    config: &ApmConfig,
    registries: &RegistrySet,
    closure: &ResolvedClosure,
    mirror: &[String],
    printer: &Printer,
) -> Result<()> {
    let roots = [(
        closure.registry_name.as_str(),
        store_path_hash(&closure.root.store_path),
    )];
    let trust = registries.trust_context_for_roots(&roots);
    trust.enforce_totality()?;
    let requests = [request(&closure.root.store_path, mirror)];
    let resolved = fetch_narinfo_closure(
        Arc::new(default_engine()),
        &requests,
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    let results = download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    crate::verify::verify_downloads(&results, &trust, printer)?;
    let root = results
        .iter()
        .find(|result| result.store_path == closure.root.store_path)
        .context("candidate toplevel download is missing")?;
    crate::verify::verify_nar_identity_with_compression(
        &root.local_path,
        &closure.root.nar_hash,
        closure.root.nar_size,
        &root.compression,
    )?;
    for result in results {
        crate::store::import_nar_with_compression(
            &result.local_path,
            &result.store_path,
            &result.references,
            result.deriver.as_deref(),
            &result.compression,
        )
        .await?;
    }
    Ok(())
}

async fn import_exact(
    config: &ApmConfig,
    registries: &RegistrySet,
    registry_name: &str,
    mirror: &[String],
    store_path: &str,
    nar_hash: &str,
    nar_size: u64,
    printer: &Printer,
) -> Result<()> {
    let roots = [(registry_name, store_path_hash(store_path))];
    let trust = registries.trust_context_for_roots(&roots);
    trust.enforce_totality()?;
    let resolved = fetch_narinfo_closure(
        Arc::new(default_engine()),
        &[request(store_path, mirror)],
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    let results = download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    for result in &results {
        ensure!(
            result.store_path == store_path || trust.enforced(store_path_hash(&result.store_path)),
            "image artifact dependency is absent from its authenticated release graph"
        );
    }
    crate::verify::verify_downloads(&results, &trust, printer)?;
    let root_index = results
        .iter()
        .position(|result| result.store_path == store_path)
        .context("image artifact root download is missing")?;
    let result = &results[root_index];
    crate::verify::verify_download_hash(&result.local_path, &result.download_hash)?;
    crate::verify::verify_nar_identity_with_compression(
        &result.local_path,
        nar_hash,
        nar_size,
        &result.compression,
    )?;
    for result in results {
        crate::store::import_nar_with_compression(
            &result.local_path,
            &result.store_path,
            &result.references,
            result.deriver.as_deref(),
            &result.compression,
        )
        .await?;
    }
    Ok(())
}

fn request(store_path: &str, mirror: &[String]) -> DownloadRequest {
    let (mirror_url, fallback_mirrors) = split_mirror_chain(mirror);
    DownloadRequest {
        store_path: store_path.into(),
        mirror_url,
        fallback_mirrors,
    }
}

fn exact_file(store_path: &str, filename: &str) -> Result<PathBuf> {
    ensure!(
        Path::new(filename).components().count() == 1 && !matches!(filename, "." | ".."),
        "image artifact filename is not a leaf"
    );
    let root = Path::new(store_path);
    if root.is_file() {
        return Ok(root.into());
    }
    let named = root.join(filename);
    if named.is_file() {
        return Ok(named);
    }
    // Delivery names are download names; an independently signed single-file
    // NAR may preserve the finalizer's original filename instead.
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "image artifact output is not a single regular file"
        );
        files.push(entry.path());
    }
    ensure!(
        files.len() == 1,
        "image artifact output is missing or ambiguous"
    );
    files.pop().context("image artifact output is empty")
}

fn verify_file(path: &Path, size: u64, digest: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() == size,
        "image artifact length differs from signed identity"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    ensure!(
        hex::encode(hash.finalize()) == digest,
        "image artifact differs from signed digest"
    );
    Ok(())
}

fn validate_executable(value: &str) -> Result<()> {
    let path = Path::new(value);
    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(path)?;
    ensure!(
        !suffix.as_os_str().is_empty()
            && root.join(suffix) == path
            && !value.contains("//")
            && !value.split('/').any(|part| matches!(part, "." | "..")),
        "image staging executable is not a canonical retained store member"
    );
    Ok(())
}

/// Rejects staging while any native image transition still owns the pair.
///
/// # Errors
/// Returns an error for a pending selection or an active rollout.
pub(super) fn ensure_staging_available(state: &crate::types::ImageGenerationState) -> Result<()> {
    ensure!(
        state.pending.is_none() && state.active_rollout.is_none(),
        "cannot overwrite a slot while an image transition is pending"
    );
    Ok(())
}

struct StageControl<'a>(&'a CancellationToken);

impl RuntimeControl for StageControl<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
    fn elapsed_millis(&self) -> u64 {
        0
    }
    fn attempt_remaining_millis(&self) -> u64 {
        60 * 60 * 1000
    }
    fn recovery_remaining_millis(&self) -> u64 {
        60 * 60 * 1000
    }
}

fn run_stage<T: serde::de::DeserializeOwned>(
    executable: &str,
    request: &StageRequest<'_>,
    cancellation: &CancellationToken,
) -> Result<T> {
    let output = crate::deployment::process::run_bounded_with_input_limit(
        &mut Command::new(executable),
        Some(&serde_json::to_vec(request)?),
        1024 * 1024,
        MAX_RECEIPT_BYTES as usize,
        &StageControl(cancellation),
        &[],
    )
    .context("running cancellable physical image preparation")?;
    ensure!(
        output.status.success(),
        "physical image staging failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).context("decoding physical staging receipt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ImageGenerationState;

    fn image(number: u32) -> ImageGeneration {
        let root = format!("/nix/store/{}-image-{number}", "0".repeat(32));
        ImageGeneration {
            number,
            boot_artifact_contract: format!("/nix/store/{}-boot-contract", "1".repeat(32)),
            boot_provider_state: BootProviderState {
                schema: "aos.test/boot-generation".into(),
                evidence: serde_json::json!({"slot":if number == 1 {"A"} else {"B"}}),
            },
            toplevel: root.clone(),
            package_name: "server".into(),
            version: number.to_string(),
            state_version: "state-format".into(),
            native_executor_ref: format!("/nix/store/{}-executor", "2".repeat(32)),
            registry: "release".into(),
            kernel_path: None,
            module_library: ModuleLibraryIdentity {
                store_path: format!("/nix/store/{}-library", "3".repeat(32)),
                nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                nar_size: 1,
            },
            evaluation_descriptor: format!("{root}/evaluation.json"),
            created_at: "2026-09-29T00:00:00Z".into(),
        }
    }

    fn state() -> ImageGenerationState {
        let running = image(1);
        ImageGenerationState {
            schema: "aos.image-generation-state/v1".into(),
            running: 1,
            pending: None,
            boot_provider_state: running.boot_provider_state.clone(),
            active_rollout: None,
            last_rollout: None,
            generations: vec![running],
        }
    }

    fn receipt(candidate: &ImageGeneration) -> StageReceipt {
        StageReceipt {
            schema: "aos.image-candidate-staged".into(),
            generation: candidate.number,
            toplevel: candidate.toplevel.clone(),
            boot_artifact_contract: candidate.boot_artifact_contract.clone(),
            boot_provider_state: candidate.boot_provider_state.clone(),
        }
    }

    #[test]
    fn preparation_busy_guard_rejects_pending_and_active_transitions() {
        let mut images = state();
        ensure_staging_available(&images).unwrap();
        images.generations.push(image(2));
        images.pending = Some(2);
        assert!(ensure_staging_available(&images).is_err());
        images.pending = None;
        images.active_rollout = Some(crate::types::ImageRollout {
            schema: "aos.image-rollout/v1".into(),
            candidate: 2,
            prior: 1,
            state_version: "state-format".into(),
            status: crate::types::ImageRolloutStatus::Staged,
        });
        assert!(ensure_staging_available(&images).is_err());
    }

    #[test]
    fn cancellation_prevents_starting_a_physical_preparation_child() {
        let token = CancellationToken::default();
        token.cancel();
        let error = crate::deployment::process::run_bounded(
            &mut Command::new("/nonexistent-cancelled-stage-program"),
            None,
            1024,
            &StageControl(&token),
            &[],
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn authenticated_receipt_indexes_candidate_without_selecting_it() {
        let profile = tempfile::tempdir().unwrap();
        let mut initial = state();
        let candidate = image(2);
        admit_receipt(
            profile.path(),
            &mut initial,
            candidate.clone(),
            receipt(&candidate),
        )
        .unwrap();

        let retained = load_image_generation_state_pub(profile.path()).unwrap();
        assert_eq!(retained.running, 1);
        assert!(retained.pending.is_none());
        assert!(retained.active_rollout.is_none());
        assert_eq!(retained.generations.len(), 2);
        assert_eq!(retained.generations[1].toplevel, candidate.toplevel);
        assert_eq!(
            std::fs::read_link(profile.path().join("image-gen-2/toplevel")).unwrap(),
            Path::new(&candidate.toplevel)
        );
    }

    #[test]
    fn foreign_receipt_cannot_publish_roots_or_mutate_index() {
        let profile = tempfile::tempdir().unwrap();
        let mut initial = state();
        let candidate = image(2);
        let mut foreign = receipt(&candidate);
        foreign.generation = 3;

        assert!(admit_receipt(profile.path(), &mut initial, candidate, foreign).is_err());
        assert_eq!(initial.generations.len(), 1);
        assert!(!profile.path().join(IMAGE_STATE_FILE).exists());
        assert!(!profile.path().join("image-gen-2").exists());
    }

    #[test]
    fn committed_staging_recovers_after_index_write_before_intent_cleanup() {
        let mut indexed = state();
        let committed = image(2);
        indexed.generations.push(committed.clone());
        let mut retry = committed.clone();
        retry.number = 3;
        retry.created_at = "2026-09-30T00:00:00Z".into();
        let pending = StageIntent {
            schema: "aos.image-candidate-stage-intent".into(),
            generation: 2,
            toplevel: committed.toplevel.clone(),
            source_sha256: "0".repeat(64),
            stage_executable: format!("/nix/store/{}-stage/bin/stage", "4".repeat(32)),
        };
        let expected = StageIntent {
            generation: 3,
            ..StageIntent {
                schema: pending.schema.clone(),
                generation: pending.generation,
                toplevel: pending.toplevel.clone(),
                source_sha256: pending.source_sha256.clone(),
                stage_executable: pending.stage_executable.clone(),
            }
        };

        let recovered = recover_committed(&indexed, &retry, &pending, &expected)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.number, 2);
        assert_eq!(indexed.generations.len(), 2);
        retry.native_executor_ref = format!("/nix/store/{}-changed-executor", "5".repeat(32));
        assert!(recover_committed(&indexed, &retry, &pending, &expected).is_err());
    }

    #[test]
    fn completed_stage_can_resume_selection_without_claiming_its_slot_again() {
        let mut indexed = state();
        let committed = image(2);
        indexed.generations.push(committed.clone());
        let mut retry = committed;
        retry.number = 3;
        let recovered = reusable_candidate(&indexed, &retry).unwrap().unwrap();
        assert_eq!(recovered.number, 2);
        assert_eq!(indexed.generations.len(), 2);
        retry.state_version = "another-format".into();
        assert!(reusable_candidate(&indexed, &retry).is_err());
    }

    #[test]
    fn retirement_revalidation_fences_concurrent_selection_and_staging() {
        let mut original = state();
        original.generations.push(image(2));
        original.running = 2;
        let running = original.generations[1].clone();
        original.boot_provider_state = running.boot_provider_state.clone();
        original.validate().unwrap();
        let mut retired = original.clone();
        retired.generations[0].boot_provider_state.evidence["retired"] = serde_json::json!(true);

        validate_refreshed_authority(&running, &original, &retired, 3).unwrap();

        let mut selected = retired.clone();
        selected.running = 1;
        assert!(validate_refreshed_authority(&running, &original, &selected, 3).is_err());

        let mut pending = retired.clone();
        pending.pending = Some(1);
        assert!(validate_refreshed_authority(&running, &original, &pending, 3).is_err());

        let mut indexed = retired.clone();
        indexed.generations.push(image(3));
        assert!(validate_refreshed_authority(&running, &original, &indexed, 3).is_err());

        retired.generations[1].native_executor_ref =
            format!("/nix/store/{}-foreign-executor", "5".repeat(32));
        assert!(validate_refreshed_authority(&running, &original, &retired, 3).is_err());
    }

    #[test]
    fn delivery_bytes_must_match_both_signed_length_and_digest() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("delivery");
        std::fs::write(&file, b"authenticated bytes").unwrap();
        let digest = hex::encode(Sha256::digest(b"authenticated bytes"));
        verify_file(&file, 19, &digest).unwrap();
        assert!(verify_file(&file, 18, &digest).is_err());
        assert!(verify_file(&file, 19, &hex::encode(Sha256::digest(b"other bytes"))).is_err());
    }
}
