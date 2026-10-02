//! Systemd and ESP implementations of provider-neutral image rollout platform effects.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const BOOT_ROOT: &str = "/boot";
const RETENTION_ROOT: &str = "EFI/.aos-rollout-retention";
const BOOT_ARTIFACT_CONTRACT: &str = "contract.json";
const MAX_BOOT_ARTIFACT_CONTRACT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootPlatformRole {
    ArtifactStorage,
    Selection,
    Success,
    HealthObservation,
    HostRestart,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ImageIdentity {
    toplevel: String,
    boot_artifact_contract: String,
    executor: String,
    state_format: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RolloutRequest {
    predecessor: ImageIdentity,
    candidate: ImageIdentity,
    retention_expires_at_millis: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct BootArtifactContract {
    schema: String,
    health_executable: Option<PathBuf>,
    #[serde(default)]
    health_arguments: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionRequest {
    rollout: RolloutRequest,
    entry: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImageState {
    generations: Vec<ImageGeneration>,
    running: u32,
    #[serde(default)]
    pending: Option<u32>,
    #[serde(default)]
    active_rollout: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ImageGeneration {
    number: u32,
    toplevel: String,
    native_executor_ref: String,
    state_version: String,
    boot_artifact_contract: String,
    boot_provider_state: ProviderStateEnvelope,
}

#[derive(Debug, Deserialize)]
struct ProviderStateEnvelope {
    schema: String,
    evidence: SystemdBootGenerationEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SystemdBootGenerationEvidence {
    installed_entry: String,
    #[serde(default, rename = "uki-source-path")]
    uki_source_path: Option<String>,
    #[serde(default)]
    uki_sha256: Option<String>,
    #[serde(default)]
    uki_byte_size: Option<u64>,
    #[serde(default)]
    retired: bool,
    #[serde(default, rename = "slot")]
    _slot: Option<String>,
    #[serde(default, rename = "recovery")]
    _recovery: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct BootPlatformTools {
    bootctl: PathBuf,
    bless_boot: PathBuf,
    mount: PathBuf,
    systemctl: PathBuf,
}

impl BootPlatformTools {
    pub(crate) fn from_launcher_arguments(arguments: &mut Vec<OsString>) -> Result<Option<Self>> {
        if arguments
            .get(1)
            .is_none_or(|argument| argument != "--bootctl")
        {
            return Ok(None);
        }
        ensure!(
            arguments.len() >= 9,
            "systemd launcher omitted its exact boot tool paths"
        );
        for (index, expected) in ["--bootctl", "--bless-boot", "--mount", "--systemctl"]
            .into_iter()
            .enumerate()
        {
            ensure!(
                arguments
                    .get(1 + index * 2)
                    .is_some_and(|value| value == expected),
                "systemd launcher tool arguments are not canonical"
            );
        }
        let tools = Self {
            bootctl: PathBuf::from(&arguments[2]),
            bless_boot: PathBuf::from(&arguments[4]),
            mount: PathBuf::from(&arguments[6]),
            systemctl: PathBuf::from(&arguments[8]),
        };
        tools.validate()?;
        arguments.drain(1..9);
        Ok(Some(tools))
    }

    fn validate(&self) -> Result<()> {
        validate_store_executable(&self.bootctl, "bootctl")?;
        validate_store_executable(&self.bless_boot, "systemd-bless-boot")?;
        validate_store_executable(&self.mount, "mount")?;
        validate_store_executable(&self.systemctl, "systemctl")?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct StorageObservation<'a> {
    schema: &'a str,
    state: &'static str,
    #[serde(rename = "payload-digest")]
    payload_digest: Option<Sha256Digest>,
}

#[derive(Debug, Serialize)]
struct SelectionObservation<'a> {
    schema: &'a str,
    state: &'static str,
    entry: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuccessObservation<'a> {
    schema: &'a str,
    state: &'static str,
    entry: Option<String>,
}

#[derive(Debug, Serialize)]
struct RestartObservation<'a> {
    schema: &'a str,
    state: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthObservation<'a> {
    schema: &'a str,
    healthy: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetentionManifest {
    schema: String,
    candidate: String,
    candidate_entry: String,
    candidate_sha256: Sha256Digest,
    predecessor: String,
    predecessor_entry: String,
    predecessor_sha256: Sha256Digest,
}

/// Executes one directly selected OS boot operation using retained tools.
///
/// # Errors
/// Returns an error for malformed bounded input, unretained tools, inconsistent
/// physical boot evidence, or a failed platform mutation.
pub(crate) fn run_from_process() -> Result<()> {
    let mut arguments = std::env::args_os().collect::<Vec<_>>();
    let tools = BootPlatformTools::from_launcher_arguments(&mut arguments)?
        .context("boot platform launcher omitted retained tools")?;
    ensure!(
        arguments.len() == 2,
        "boot platform requires exactly one operation"
    );
    let operation = arguments[1].to_str().context("operation is not UTF-8")?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "boot platform input exceeds its bound"
    );
    let request: SelectionRequest = serde_json::from_slice(&bytes)?;
    validate_rollout(&request.rollout)?;
    let (role, method) = match operation {
        "retain" => (BootPlatformRole::ArtifactStorage, "retain"),
        "release" => (BootPlatformRole::ArtifactStorage, "release"),
        "observe-storage" => (BootPlatformRole::ArtifactStorage, "observe"),
        "select" => (BootPlatformRole::Selection, "select"),
        "observe-selection" => (BootPlatformRole::Selection, "observe"),
        "mark" => (BootPlatformRole::Success, "mark"),
        "observe-success" => (BootPlatformRole::Success, "observe"),
        "observe-release" => {
            let retired = physical_release_observed(&request.rollout)?;
            serde_json::to_writer(
                std::io::stdout().lock(),
                &serde_json::json!({"retired": retired}),
            )?;
            return Ok(());
        }
        "health" => (BootPlatformRole::HealthObservation, "observe"),
        "restart" => (BootPlatformRole::HostRestart, "request"),
        "validate-selection" => {
            installed_entry(&request.rollout.candidate)?;
            installed_entry(&request.rollout.predecessor)?;
            serde_json::to_writer(std::io::stdout().lock(), &serde_json::json!({"valid":true}))?;
            return Ok(());
        }
        "validate" => {
            let (root, contract) = boot_artifact_contract(&request.rollout.candidate)?;
            contract_health_executable(&root, &contract)?;
            installed_entry(&request.rollout.candidate)?;
            installed_entry(&request.rollout.predecessor)?;
            serde_json::to_writer(std::io::stdout().lock(), &serde_json::json!({"valid":true}))?;
            return Ok(());
        }
        "select-fallback" => {
            let entry = stable_entry(&installed_entry(&request.rollout.predecessor)?)?;
            with_writable_boot(&tools, || {
                run(
                    &tools.bootctl,
                    &["set-preferred", &entry],
                    "selecting retained fallback",
                )
            })?;
            let result = selection_observation(
                "aos.systemd.boot-operation/v1",
                &request.rollout,
                Some(&entry),
            )?;
            serde_json::to_writer(std::io::stdout().lock(), &result)?;
            return Ok(());
        }
        "observe-boot-failure" => {
            let exhausted = exhausted_candidate_boot(&request.rollout)?;
            serde_json::to_writer(
                std::io::stdout().lock(),
                &serde_json::json!({"exhausted":exhausted}),
            )?;
            return Ok(());
        }
        "resolve" => {
            let entry = resolve_candidate_entry(&request.rollout)?;
            serde_json::to_writer(
                std::io::stdout().lock(),
                &serde_json::json!({"entry": entry}),
            )?;
            return Ok(());
        }
        _ => bail!("unsupported boot platform operation"),
    };
    let result = apply(
        role,
        "aos.systemd.boot-operation/v1",
        method,
        &request.rollout,
        request.entry.as_deref(),
        &tools,
    )?;
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    Ok(())
}

fn value<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(Into::into)
}

fn apply(
    role: BootPlatformRole,
    observation_schema: &str,
    method: &str,
    rollout: &RolloutRequest,
    entry: Option<&str>,
    tools: &BootPlatformTools,
) -> Result<serde_json::Value> {
    match (role, method) {
        (BootPlatformRole::ArtifactStorage, "retain") => {
            with_writable_boot(tools, || retain_payloads(rollout))?;
            storage_observation(observation_schema, rollout)
        }
        (BootPlatformRole::ArtifactStorage, "release") => {
            ensure!(
                now_millis()? >= rollout.retention_expires_at_millis,
                "boot payload retention lease has not expired"
            );
            with_writable_boot(tools, || release_payloads(rollout))?;
            storage_observation(observation_schema, rollout)
        }
        (BootPlatformRole::ArtifactStorage, "observe") => {
            storage_observation(observation_schema, rollout)
        }
        (BootPlatformRole::Selection, "resolve" | "observe") => {
            selection_observation(observation_schema, rollout, entry)
        }
        (BootPlatformRole::Selection, "select") => {
            let entry = entry.context("boot selection has no resolved entry")?;
            ensure!(
                entry == resolve_candidate_entry(rollout)?,
                "resolved boot entry changed before selection"
            );
            with_writable_boot(tools, || {
                promote_candidate(
                    &rollout.candidate,
                    selected_entry()?.as_deref() != Some(entry),
                )?;
                run(
                    &tools.bootctl,
                    &["set-oneshot", ""],
                    "clearing obsolete one-shot selection",
                )?;
                run(
                    &tools.bootctl,
                    &["set-preferred", entry],
                    "selecting the next boot entry",
                )
            })?;
            selection_observation(observation_schema, rollout, Some(entry))
        }
        (BootPlatformRole::Selection, "clear") => {
            let entry = entry.context("boot selection clear has no exact entry")?;
            let current = selected_entry()?;
            ensure!(
                current.as_deref() != Some(entry),
                "refusing to clear the active default without a replacement"
            );
            selection_observation(observation_schema, rollout, None)
        }
        (BootPlatformRole::Success, "mark") => {
            let stable = running_entry(rollout)?;
            with_writable_boot(tools, || {
                run(
                    &tools.bless_boot,
                    &["--path", BOOT_ROOT, "good"],
                    "marking the running boot successful",
                )?;
                run(
                    &tools.bootctl,
                    &["set-default", &stable],
                    "publishing the stable boot default",
                )
            })?;
            success_observation(observation_schema, rollout)
        }
        (BootPlatformRole::Success, "observe") => success_observation(observation_schema, rollout),
        (BootPlatformRole::HealthObservation, "observe") => {
            health_observation(observation_schema, rollout)
        }
        (BootPlatformRole::HostRestart, "request") => {
            run(
                &tools.systemctl,
                &["--no-block", "reboot"],
                "requesting a host restart",
            )?;
            value(&RestartObservation {
                schema: observation_schema,
                state: "accepted",
            })
        }
        (BootPlatformRole::HostRestart, "observe") => value(&RestartObservation {
            schema: observation_schema,
            state: "unknown",
        }),
        _ => bail!("unsupported boot platform method"),
    }
}

fn storage_observation(
    observation_schema: &str,
    rollout: &RolloutRequest,
) -> Result<serde_json::Value> {
    let manifest = retention_directory(rollout)?.join("manifest.json");
    match fs::read(&manifest) {
        Ok(bytes) => {
            let retained: RetentionManifest = serde_json::from_slice(&bytes)
                .with_context(|| format!("decoding {}", manifest.display()))?;
            validate_retention(rollout, &manifest, &retained)?;
            value(&StorageObservation {
                schema: observation_schema,
                state: "retained",
                payload_digest: Some(Sha256Digest::of_bytes(&bytes)),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => value(&StorageObservation {
            schema: observation_schema,
            state: "absent",
            payload_digest: None,
        }),
        Err(error) => Err(error).with_context(|| format!("reading {}", manifest.display())),
    }
}

fn selection_observation(
    observation_schema: &str,
    rollout: &RolloutRequest,
    expected: Option<&str>,
) -> Result<serde_json::Value> {
    let selected = selected_entry()?;
    let candidate = resolve_candidate_entry(rollout)?;
    let requested = expected.unwrap_or(&candidate);
    value(&SelectionObservation {
        schema: observation_schema,
        state: if selected.as_deref() == Some(requested) {
            "selected"
        } else {
            "unselected"
        },
        entry: selected,
    })
}

fn success_observation(
    observation_schema: &str,
    rollout: &RolloutRequest,
) -> Result<serde_json::Value> {
    let running = running_entry(rollout)?;
    let selected = selected_entry()?;
    value(&SuccessObservation {
        schema: observation_schema,
        state: if selected.as_deref() == Some(running.as_str()) {
            "marked"
        } else {
            "unmarked"
        },
        entry: Some(running),
    })
}

fn health_observation(
    observation_schema: &str,
    rollout: &RolloutRequest,
) -> Result<serde_json::Value> {
    let (root, contract) = boot_artifact_contract(&rollout.candidate)?;
    let executable = contract_health_executable(&root, &contract)?;
    ensure!(
        contract.health_arguments.len() <= 256
            && contract
                .health_arguments
                .iter()
                .all(|argument| argument.len() <= 16 * 1024 && !argument.contains('\0')),
        "health arguments exceed their bound"
    );
    let mut child = Command::new(executable)
        .env_clear()
        .args(&contract.health_arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("observing candidate image health")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            bail!("image health program exceeded its 30-second bound");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let healthy = health_from_exit_code(status.code())?;

    value(&HealthObservation {
        schema: observation_schema,
        healthy,
    })
}

fn health_from_exit_code(code: Option<i32>) -> Result<bool> {
    match code {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(code) => bail!("image health executable returned indeterminate status {code}"),
        None => bail!("image health executable terminated without an exit status"),
    }
}

fn immutable_store_root(path: &Path, label: &str) -> Result<PathBuf> {
    ensure!(
        path.is_absolute()
            && path.starts_with("/nix/store")
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "{label} is not a normalized immutable store path"
    );
    ensure!(
        path.strip_prefix("/nix/store")?.components().count() == 1,
        "{label} does not name an immutable artifact root"
    );
    let canonical = fs::canonicalize(path).with_context(|| format!("resolving {label}"))?;
    ensure!(
        canonical == path,
        "{label} is not its canonical artifact root"
    );
    Ok(canonical)
}

fn boot_artifact_contract(identity: &ImageIdentity) -> Result<(PathBuf, BootArtifactContract)> {
    let root = immutable_store_root(
        Path::new(&identity.boot_artifact_contract),
        "boot artifact contract",
    )?;
    let path = root.join(BOOT_ARTIFACT_CONTRACT);
    let metadata =
        fs::symlink_metadata(&path).with_context(|| format!("inspecting {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "boot artifact contract document is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_BOOT_ARTIFACT_CONTRACT_BYTES,
        "boot artifact contract document exceeds its size bound"
    );
    let contract: BootArtifactContract = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("decoding {}", path.display()))?;
    ensure!(
        contract.schema == "aos.systemd.boot-artifact-contract/v1",
        "unsupported systemd boot artifact contract"
    );
    Ok((root, contract))
}

fn contract_health_executable(root: &Path, contract: &BootArtifactContract) -> Result<PathBuf> {
    let selected = contract
        .health_executable
        .as_ref()
        .context("qualified rollout has no explicit site health program")?;
    let metadata = fs::symlink_metadata(selected).context("inspecting image health executable")?;
    ensure!(
        metadata.file_type().is_file(),
        "image health executable is not a regular file"
    );
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "image health executable is not executable"
    );
    let executable = validate_store_executable(selected, "image health executable")?;
    ensure!(
        executable.starts_with(root),
        "image health executable is outside its authenticated contract"
    );
    Ok(executable)
}

fn validate_rollout(request: &RolloutRequest) -> Result<()> {
    ensure!(
        !request.candidate.state_format.is_empty()
            && request.candidate.state_format == request.predecessor.state_format,
        "rollout images have incompatible state formats"
    );
    Ok(())
}

fn image_state() -> Result<ImageState> {
    let path = Path::new(IMAGE_PROFILE).join("state.json");
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("reading {}", path.display()))?)
        .context("decoding image generation state")
}

fn generation_for<'a>(
    state: &'a ImageState,
    identity: &ImageIdentity,
) -> Result<&'a ImageGeneration> {
    let matches = state
        .generations
        .iter()
        .filter(|generation| {
            generation.boot_artifact_contract == identity.boot_artifact_contract
                && generation.toplevel == identity.toplevel
                && generation.native_executor_ref == identity.executor
                && generation.state_version == identity.state_format
        })
        .collect::<Vec<_>>();
    let [generation] = matches.as_slice() else {
        bail!("rollout image has no unique physical boot entry");
    };
    Ok(generation)
}

fn installed_entry(identity: &ImageIdentity) -> Result<String> {
    let state = image_state()?;
    let generation = generation_for(&state, identity)?;
    ensure!(
        generation.boot_provider_state.schema == "aos.systemd.boot-generation-state/v1",
        "unsupported selected boot generation state"
    );
    let evidence = &generation.boot_provider_state.evidence;
    ensure!(!evidence.retired, "boot generation is physically retired");
    let recorded = safe_entry_path(&evidence.installed_entry)?;
    if let Some(source) = &evidence.uki_source_path {
        let source = safe_source_path(source)?;
        if source.starts_with("EFI/.aos-candidates") {
            checked_staged_bytes(evidence, &Path::new(BOOT_ROOT).join(source))?;
            return recorded
                .file_name()
                .and_then(|name| name.to_str())
                .map(ToOwned::to_owned)
                .context("invalid intended entry");
        }
    }
    let exact = Path::new(BOOT_ROOT).join(&recorded);
    if exact.is_file() {
        return recorded
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToOwned::to_owned)
            .context("installed boot entry name is not UTF-8");
    }

    let filename = recorded
        .file_name()
        .and_then(|name| name.to_str())
        .context("boot entry has no UTF-8 filename")?;
    let stable = stable_entry(filename)?;
    let stable_stem = stable
        .strip_suffix(".efi")
        .context("stable boot entry has no suffix")?;
    let mut matches = fs::read_dir(Path::new(BOOT_ROOT).join("EFI/Linux"))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| {
            name == &stable
                || (name.starts_with(&format!("{stable_stem}+")) && name.ends_with(".efi"))
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "installed boot entry is missing or ambiguous"
    );
    Ok(matches.remove(0))
}

fn resolve_candidate_entry(rollout: &RolloutRequest) -> Result<String> {
    stable_entry(&installed_entry(&rollout.candidate)?)
}

// A counted filename alone does not authorize fallback: bind the exact bytes,
// firmware preference, actually booted entry, immutable root, and physical slot.
fn exhausted_candidate_boot(rollout: &RolloutRequest) -> Result<bool> {
    let state = image_state()?;
    let predecessor = generation_for(&state, &rollout.predecessor)?;
    let candidate = generation_for(&state, &rollout.candidate)?;
    if state.running != predecessor.number {
        return Ok(false);
    }
    let expected = stable_entry(&installed_entry(&rollout.candidate)?)?;
    if firmware_entry("LoaderEntryPreferred")?.as_deref() != Some(&expected) {
        return Ok(false);
    }
    let stem = expected
        .strip_suffix(".efi")
        .context("candidate entry has no suffix")?;
    let directory = Path::new(BOOT_ROOT).join("EFI/Linux");
    let mut entries = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("boot filename is not UTF-8"))?;
        if name.ends_with(".efi") && (name == expected || name.starts_with(&format!("{stem}+"))) {
            ensure!(
                stable_entry(&name)? == expected,
                "counted candidate filename changed"
            );
            entries.push(name);
        }
    }
    ensure!(
        entries.len() == 1,
        "candidate counted entry is absent or ambiguous"
    );
    if !exhausted_entry(&entries[0])? {
        return Ok(false);
    }
    let running_entry = stable_entry(&installed_entry(&rollout.predecessor)?)?;
    ensure!(
        firmware_entry("LoaderEntrySelected")?.as_deref() == Some(&running_entry),
        "exhausted candidate did not boot the retained predecessor"
    );
    ensure!(
        fs::read_link("/run/current-system")? == Path::new(&rollout.predecessor.toplevel),
        "running immutable root differs from retained predecessor"
    );
    let active = aos_boot_identity::parse_normal(&fs::read_to_string("/proc/cmdline")?)?;
    let slot = match active.slot {
        aos_boot_identity::BootSlot::A => "A",
        aos_boot_identity::BootSlot::B => "B",
    };
    ensure!(
        predecessor.boot_provider_state.evidence._slot.as_deref() == Some(slot)
            && candidate
                .boot_provider_state
                .evidence
                ._slot
                .as_deref()
                .is_some_and(|candidate_slot| candidate_slot != slot),
        "exhausted boot slot differs from retained physical pair"
    );
    let retained: RetentionManifest = serde_json::from_slice(&fs::read(
        retention_directory(rollout)?.join("manifest.json"),
    )?)?;
    validate_retention(
        rollout,
        &retention_directory(rollout)?.join("manifest.json"),
        &retained,
    )?;
    for (path, digest) in [
        (directory.join(&entries[0]), retained.candidate_sha256),
        (
            directory.join(installed_entry(&rollout.predecessor)?),
            retained.predecessor_sha256,
        ),
    ] {
        ensure!(
            fs::symlink_metadata(&path)?.is_file()
                && Sha256Digest::of_bytes(&fs::read(&path)?) == digest,
            "exhausted boot payload differs from authenticated retention"
        );
    }
    Ok(true)
}

fn exhausted_entry(entry: &str) -> Result<bool> {
    stable_entry(entry)?;
    let stem = entry
        .strip_suffix(".efi")
        .context("boot entry has no suffix")?;
    let Some((_, count)) = stem.rsplit_once('+') else {
        return Ok(false);
    };
    let Some((left, done)) = count.split_once('-') else {
        return Ok(false);
    };
    let left: u32 = left.parse().context("boot tries exceed their bound")?;
    let done: u32 = done
        .parse()
        .context("completed boot tries exceed their bound")?;
    Ok(left == 0 && done > 0)
}

fn running_entry(rollout: &RolloutRequest) -> Result<String> {
    let state = image_state()?;
    let running = state
        .generations
        .iter()
        .filter(|generation| generation.number == state.running)
        .collect::<Vec<_>>();
    let [running] = running.as_slice() else {
        bail!("running image generation is absent or ambiguous");
    };
    let identity = if generation_for(&state, &rollout.candidate)?.number == running.number {
        &rollout.candidate
    } else if generation_for(&state, &rollout.predecessor)?.number == running.number {
        &rollout.predecessor
    } else {
        bail!("running image is outside the checked rollout pair");
    };
    stable_entry(&installed_entry(identity)?)
}

fn safe_entry_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    let [
        Component::Normal(efi),
        Component::Normal(linux),
        Component::Normal(file),
    ] = components.as_slice()
    else {
        bail!("boot entry path is outside EFI/Linux");
    };
    ensure!(
        *efi == "EFI" && *linux == "Linux",
        "boot entry path is outside EFI/Linux"
    );
    ensure!(
        file.to_str().is_some_and(|name| name.ends_with(".efi")),
        "boot entry filename is invalid"
    );
    Ok(path.to_path_buf())
}

fn stable_entry(entry: &str) -> Result<String> {
    ensure!(
        matches!(
            Path::new(entry).components().collect::<Vec<_>>().as_slice(),
            [Component::Normal(_)]
        ),
        "boot entry name is not a single path component"
    );
    let stem = entry
        .strip_suffix(".efi")
        .context("boot entry has no .efi suffix")?;
    let stable = match stem.rsplit_once('+') {
        Some((base, tries))
            if !base.is_empty()
                && !tries.is_empty()
                && tries.split('-').count() <= 2
                && tries.split('-').all(|part| {
                    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                }) =>
        {
            base
        }
        Some(_) => bail!("boot entry has an invalid terminal boot count"),
        None => stem,
    };
    Ok(format!("{stable}.efi"))
}

fn retention_directory(rollout: &RolloutRequest) -> Result<PathBuf> {
    let digest = Sha256Digest::of_canonical("aos.boot.artifact-storage-request/v1", rollout)?;
    Ok(Path::new(BOOT_ROOT)
        .join(RETENTION_ROOT)
        .join(digest.to_string().replace(':', "-")))
}

fn retain_payloads(rollout: &RolloutRequest) -> Result<()> {
    let directory = retention_directory(rollout)?;
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let predecessor_entry = installed_entry(&rollout.predecessor)?;
    let candidate_entry = installed_entry(&rollout.candidate)?;
    let predecessor_digest = copy_identity_payload(
        &rollout.predecessor,
        &predecessor_entry,
        &directory.join("predecessor.efi"),
    )?;
    let candidate_digest = copy_identity_payload(
        &rollout.candidate,
        &candidate_entry,
        &directory.join("candidate.efi"),
    )?;
    let manifest = RetentionManifest {
        schema: "aos.boot.artifact-storage-manifest/v1".to_string(),
        candidate: rollout.candidate.boot_artifact_contract.clone(),
        candidate_entry,
        candidate_sha256: candidate_digest,
        predecessor: rollout.predecessor.boot_artifact_contract.clone(),
        predecessor_entry,
        predecessor_sha256: predecessor_digest,
    };
    write_atomic(
        &directory.join("manifest.json"),
        &aos_contract::canonical::to_vec(&manifest)?,
    )
}

fn safe_source_path(value: &str) -> Result<PathBuf> {
    if let Ok(path) = safe_entry_path(value) {
        return Ok(path);
    }
    let parts = value.split('/').collect::<Vec<_>>();
    ensure!(
        parts.len() == 4
            && parts[0] == "EFI"
            && parts[1] == ".aos-candidates"
            && parts[3] == "candidate.efi",
        "invalid staged UKI source"
    );
    let generation: u32 = parts[2].parse()?;
    ensure!(
        generation > 0 && generation.to_string() == parts[2],
        "invalid staged generation"
    );
    Ok(PathBuf::from(value))
}

fn checked_staged_bytes(
    evidence: &SystemdBootGenerationEvidence,
    source: &Path,
) -> Result<Vec<u8>> {
    ensure!(
        fs::symlink_metadata(source)?.is_file(),
        "staged UKI is not regular"
    );
    let size = evidence.uki_byte_size.context("staged UKI size missing")?;
    ensure!(
        size > 0 && size <= 512 * 1024 * 1024,
        "staged UKI exceeds its byte bound"
    );
    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(source)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut source_file)
        .take(size + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == evidence.uki_byte_size.context("staged UKI size missing")?,
        "staged UKI size changed"
    );
    let digest = evidence
        .uki_sha256
        .as_deref()
        .context("staged UKI digest missing")?;
    ensure!(
        Sha256Digest::of_bytes(&bytes).to_string()
            == if digest.starts_with("sha256:") {
                digest.to_owned()
            } else {
                format!("sha256:{digest}")
            },
        "staged UKI digest changed"
    );
    Ok(bytes)
}

fn promote_candidate(identity: &ImageIdentity, reset_count: bool) -> Result<()> {
    let state = image_state()?;
    let evidence = &generation_for(&state, identity)?
        .boot_provider_state
        .evidence;
    let Some(source) = &evidence.uki_source_path else {
        return Ok(());
    };
    let source = safe_source_path(source)?;
    if !source.starts_with("EFI/.aos-candidates") {
        return Ok(());
    }
    let bytes = checked_staged_bytes(evidence, &Path::new(BOOT_ROOT).join(&source))?;
    let destination = Path::new(BOOT_ROOT).join(safe_entry_path(&evidence.installed_entry)?);
    if !prepare_counted_payload(
        destination
            .parent()
            .context("candidate destination has no parent")?,
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .context("candidate name is not UTF-8")?,
        &bytes,
        reset_count,
    )? {
        return Ok(());
    }
    for suffix in [".measurement", ".measurement.sig"] {
        let sidecar = PathBuf::from(format!(
            "{}{suffix}",
            Path::new(BOOT_ROOT).join(&source).display()
        ));
        ensure!(
            fs::symlink_metadata(&sidecar)?.is_file(),
            "staged measurement sidecar is not regular"
        );
        write_atomic(
            &PathBuf::from(format!("{}{suffix}", destination.display())),
            &fs::read(sidecar)?,
        )?;
    }
    write_atomic(&destination, &bytes)
}

// Replaying the same preferred selection preserves systemd's consumed tries.
// A newly admitted selection from another preferred entry may reset only the
// exact authenticated payload, after removing its old counted variant.
fn prepare_counted_payload(
    directory: &Path,
    intended: &str,
    bytes: &[u8],
    reset: bool,
) -> Result<bool> {
    let stable = stable_entry(intended)?;
    let stem = stable.strip_suffix(".efi").context("entry has no suffix")?;
    let mut matches = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("entry name is not UTF-8"))?;
        if name.ends_with(".efi") && (name == stable || name.starts_with(&format!("{stem}+"))) {
            ensure!(
                stable_entry(&name)? == stable,
                "counted entry name is malformed"
            );
            ensure!(
                entry.file_type()?.is_file() && fs::read(entry.path())? == bytes,
                "existing counted payload differs from authenticated candidate"
            );
            matches.push(entry.path());
        }
    }
    ensure!(
        matches.len() <= 1,
        "candidate has ambiguous counted entries"
    );
    if !reset && !matches.is_empty() {
        return Ok(false);
    }
    for path in matches {
        remove_regular_payload(&path)?;
        for suffix in [".measurement", ".measurement.sig"] {
            remove_regular_payload(&PathBuf::from(format!("{}{suffix}", path.display())))?;
        }
    }
    Ok(true)
}

fn copy_identity_payload(
    identity: &ImageIdentity,
    entry: &str,
    destination: &Path,
) -> Result<Sha256Digest> {
    let state = image_state()?;
    let evidence = &generation_for(&state, identity)?
        .boot_provider_state
        .evidence;
    if let Some(source) = &evidence.uki_source_path {
        let source = safe_source_path(source)?;
        if source.starts_with("EFI/.aos-candidates") {
            let bytes = checked_staged_bytes(evidence, &Path::new(BOOT_ROOT).join(source))?;
            let digest = Sha256Digest::of_bytes(&bytes);
            if destination.exists() {
                ensure!(
                    fs::read(destination)? == bytes,
                    "retained staged UKI changed"
                );
            } else {
                write_atomic(destination, &bytes)?;
            }
            return Ok(digest);
        }
    }
    copy_payload(entry, destination)
}

fn copy_payload(entry: &str, destination: &Path) -> Result<Sha256Digest> {
    let source = Path::new(BOOT_ROOT).join("EFI/Linux").join(entry);
    let bytes = fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
    let digest = Sha256Digest::of_bytes(&bytes);
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "retained boot payload is not a regular file"
            );
            ensure!(
                Sha256Digest::of_bytes(&fs::read(destination)?) == digest,
                "retained boot payload differs from the installed entry"
            );
            return Ok(digest);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", destination.display()));
        }
    }
    write_atomic(destination, &bytes)?;
    Ok(digest)
}

fn release_payloads(rollout: &RolloutRequest) -> Result<()> {
    let directory = retention_directory(rollout)?;
    let mut retained = None;
    if directory.exists() {
        let bytes = fs::read(directory.join("manifest.json"))?;
        let manifest: RetentionManifest = serde_json::from_slice(&bytes)?;
        validate_retention(rollout, &directory.join("manifest.json"), &manifest)?;
        retained = Some(manifest);
    }
    if let Some(retained) = retained.as_ref() {
        remove_inactive_payload(rollout, retained)?;
    } else {
        ensure!(
            physical_release_observed(rollout)?,
            "missing retention manifest does not prove physical release"
        );
    }
    match fs::remove_dir_all(&directory) {
        Ok(()) => sync_parent(&directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", directory.display())),
    }
}

// A missing private manifest alone cannot authorize discarding a physical
// lease. Its exact inactive generation must already record completed retirement,
// with both normal/counting and hidden payload namespaces durably empty.
fn physical_release_observed(rollout: &RolloutRequest) -> Result<bool> {
    let state = image_state()?;
    if now_millis()? < rollout.retention_expires_at_millis {
        return Ok(false);
    }
    let candidate = generation_for(&state, &rollout.candidate)?;
    let predecessor = generation_for(&state, &rollout.predecessor)?;
    let inactive = if state.running == candidate.number {
        predecessor
    } else if state.running == predecessor.number {
        candidate
    } else {
        bail!("running image is outside the checked release pair");
    };
    if !inactive.boot_provider_state.evidence.retired
        || state.pending == Some(inactive.number)
        || state.active_rollout.is_some()
    {
        return Ok(false);
    }
    match fs::symlink_metadata(retention_directory(rollout)?) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    retired_payload_is_absent(Path::new(BOOT_ROOT), inactive)
}

fn retired_payload_is_absent(boot_root: &Path, inactive: &ImageGeneration) -> Result<bool> {
    let evidence = &inactive.boot_provider_state.evidence;
    let entry = safe_entry_path(&evidence.installed_entry)?;
    let filename = entry
        .file_name()
        .and_then(|name| name.to_str())
        .context("retired generation entry is not UTF-8")?;
    let stable = stable_entry(filename)?;
    let stem = stable.strip_suffix(".efi").context("entry has no suffix")?;
    for member in fs::read_dir(boot_root.join("EFI/Linux"))? {
        let member = member?;
        let name = member.file_name();
        let name = name.to_str().context("boot payload name is not UTF-8")?;
        let payload = name
            .strip_suffix(".measurement.sig")
            .or_else(|| name.strip_suffix(".measurement"))
            .unwrap_or(name);
        if payload == stable
            || (payload.starts_with(&format!("{stem}+")) && payload.ends_with(".efi"))
        {
            stable_entry(payload)?;
            return Ok(false);
        }
    }
    if let Some(source) = &evidence.uki_source_path {
        let source = boot_root.join(safe_source_path(source)?);
        for suffix in ["", ".measurement", ".measurement.sig"] {
            match fs::symlink_metadata(PathBuf::from(format!("{}{suffix}", source.display()))) {
                Ok(_) => return Ok(false),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(true)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("boot platform path has no parent")?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .context("boot platform path is not UTF-8")?
    ));
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(&temporary)?,
        Ok(_) => bail!("boot platform temporary path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", temporary.display()));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_parent(path)
}

fn validate_retention(
    rollout: &RolloutRequest,
    manifest_path: &Path,
    retained: &RetentionManifest,
) -> Result<()> {
    let directory = manifest_path
        .parent()
        .context("retention manifest has no parent")?;
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.file_type().is_dir(),
        "boot payload retention path is not a directory"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "boot payload retention directory is not private"
    );
    ensure!(
        retained.schema == "aos.boot.artifact-storage-manifest/v1",
        "unsupported boot payload retention manifest"
    );
    ensure!(
        retained.candidate == rollout.candidate.boot_artifact_contract,
        "retained candidate differs from the checked rollout"
    );
    ensure!(
        retained.predecessor == rollout.predecessor.boot_artifact_contract,
        "retained predecessor differs from the checked rollout"
    );
    for (name, expected) in [
        ("candidate.efi", retained.candidate_sha256),
        ("predecessor.efi", retained.predecessor_sha256),
    ] {
        let path = directory.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file(),
            "retained boot payload is not a regular file"
        );
        ensure!(
            Sha256Digest::of_bytes(&fs::read(&path)?) == expected,
            "retained boot payload digest differs from its manifest"
        );
    }
    Ok(())
}

fn remove_inactive_payload(rollout: &RolloutRequest, retained: &RetentionManifest) -> Result<()> {
    let lock = rustix::fs::open(
        Path::new(IMAGE_PROFILE).join("candidate-stage.lock"),
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("another physical image mutation is active")?;
    let state = image_state()?;
    let candidate = generation_for(&state, &rollout.candidate)?;
    let predecessor = generation_for(&state, &rollout.predecessor)?;
    let (inactive, entry) = if state.running == candidate.number {
        (predecessor, &retained.predecessor_entry)
    } else if state.running == predecessor.number {
        (candidate, &retained.candidate_entry)
    } else {
        bail!("running image is outside the checked rollout pair");
    };
    let state_path = Path::new(IMAGE_PROFILE).join("state.json");
    let mut document: serde_json::Value = serde_json::from_slice(&fs::read(&state_path)?)?;
    ensure!(
        document.get("pending").and_then(serde_json::Value::as_u64)
            != Some(u64::from(inactive.number)),
        "cannot retire a pending boot candidate"
    );
    ensure!(
        document
            .get("active_rollout")
            .is_none_or(serde_json::Value::is_null),
        "cannot retire an active rollout participant"
    );
    let stable = stable_entry(entry)?;
    let stem = stable
        .strip_suffix(".efi")
        .context("invalid inactive entry")?;
    for member in fs::read_dir(Path::new(BOOT_ROOT).join("EFI/Linux"))? {
        let member = member?;
        let Some(name) = member.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let payload = name
            .strip_suffix(".measurement.sig")
            .or_else(|| name.strip_suffix(".measurement"))
            .unwrap_or(&name);
        if payload == stable
            || (payload.starts_with(&format!("{stem}+")) && payload.ends_with(".efi"))
        {
            stable_entry(payload)?;
            remove_regular_payload(&member.path())?;
        }
    }
    if let Some(source) = &inactive.boot_provider_state.evidence.uki_source_path {
        let source = safe_source_path(source)?;
        if source.starts_with("EFI/.aos-candidates") {
            let path = Path::new(BOOT_ROOT).join(source);
            for suffix in ["", ".measurement", ".measurement.sig"] {
                remove_regular_payload(&PathBuf::from(format!("{}{suffix}", path.display())))?;
            }
            if let Some(parent) = path.parent() {
                match fs::remove_dir(parent) {
                    Ok(()) => sync_parent(parent)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    // Publish retirement only after inactive physical bytes are durably absent.
    // The historical native sources remain available for profile provenance.
    let generations = document
        .get_mut("generations")
        .and_then(serde_json::Value::as_array_mut)
        .context("image state omits generation index")?;
    let generation = generations
        .iter_mut()
        .find(|generation| {
            generation.get("number").and_then(serde_json::Value::as_u64)
                == Some(u64::from(inactive.number))
        })
        .context("inactive generation disappeared")?;
    let evidence = generation
        .pointer_mut("/boot_provider_state/evidence")
        .and_then(serde_json::Value::as_object_mut)
        .context("inactive generation omits evidence")?;
    evidence.insert("retired".into(), serde_json::Value::Bool(true));
    write_atomic(&state_path, &serde_json::to_vec(&document)?)
}

fn remove_regular_payload(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(metadata.is_file(), "inactive boot payload is not regular");
            fs::remove_file(path)?;
            sync_parent(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn now_millis() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("system time exceeds the rollout clock range")
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("boot platform path has no parent")?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn selected_entry() -> Result<Option<String>> {
    // bootctl stores the preferred/default selection in firmware, overriding
    // loader.conf. Preferred honors boot counts, preserving exhausted-entry fallback.
    for name in [
        "LoaderEntryOneShot",
        "LoaderEntryPreferred",
        "LoaderEntryDefault",
    ] {
        let path = Path::new("/sys/firmware/efi/efivars")
            .join(format!("{name}-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"));
        match fs::read(&path) {
            Ok(bytes) => return Ok(Some(parse_efi_entry(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("reading selected boot entry EFI variable"),
        }
    }
    Ok(None)
}

fn firmware_entry(name: &str) -> Result<Option<String>> {
    let path = Path::new("/sys/firmware/efi/efivars")
        .join(format!("{name}-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"));
    match fs::read(path) {
        Ok(bytes) => parse_efi_entry(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("reading actual boot entry EFI variable"),
    }
}

fn parse_efi_entry(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() >= 6 && bytes.len() <= 4096 && bytes.len() % 2 == 0,
        "boot entry EFI variable has an invalid length"
    );
    let words = bytes[4..]
        .chunks_exact(2)
        .map(|part| u16::from_le_bytes([part[0], part[1]]))
        .collect::<Vec<_>>();
    ensure!(
        words.last() == Some(&0) && !words[..words.len() - 1].contains(&0),
        "boot entry EFI variable is not one terminated string"
    );
    let entry = String::from_utf16(&words[..words.len() - 1])?;
    ensure!(
        !entry.is_empty()
            && matches!(
                Path::new(&entry)
                    .components()
                    .collect::<Vec<_>>()
                    .as_slice(),
                [Component::Normal(_)]
            ),
        "EFI selected entry is malformed"
    );
    // systemd may expose a type-2 ID with or without its filename suffix.
    stable_entry(&if entry.ends_with(".efi") {
        entry
    } else {
        format!("{entry}.efi")
    })
}

fn with_writable_boot<T>(
    tools: &BootPlatformTools,
    effect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    run(
        &tools.mount,
        &["-o", "remount,rw", BOOT_ROOT],
        "remounting boot storage writable",
    )?;
    let result = effect();
    let read_only = run(
        &tools.mount,
        &["-o", "remount,ro", BOOT_ROOT],
        "remounting boot storage read-only",
    );
    match (result, read_only) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(effect), Err(remount)) => {
            Err(effect.context(format!("also failed to restore boot storage: {remount:#}")))
        }
    }
}

fn run(executable: &Path, arguments: &[&str], action: &str) -> Result<()> {
    let status = Command::new(executable)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .args(arguments)
        .status()
        .with_context(|| action.to_string())?;
    ensure!(status.success(), "{action} failed with {status}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_selection_parser_rejects_ambiguous_strings() {
        let mut bytes = vec![7, 0, 0, 0];
        bytes.extend(
            "candidate-gen12+2-1.efi"
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes),
        );
        assert_eq!(parse_efi_entry(&bytes).unwrap(), "candidate-gen12.efi");
        bytes.extend([0, 0]);
        assert!(parse_efi_entry(&bytes).is_err());
        assert!(parse_efi_entry(&[7, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn staged_source_is_confined_and_bound_to_exact_bytes() {
        assert!(safe_source_path("EFI/.aos-candidates/12/candidate.efi").is_ok());
        for path in [
            "EFI/.aos-candidates/0/candidate.efi",
            "EFI/.aos-candidates/01/candidate.efi",
            "EFI/.aos-candidates/12/other.efi",
            "EFI/.aos-candidates/../candidate.efi",
        ] {
            assert!(safe_source_path(path).is_err());
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.efi");
        fs::write(&path, b"authenticated UKI").unwrap();
        let evidence = SystemdBootGenerationEvidence {
            installed_entry: "EFI/Linux/candidate-gen12+3.efi".into(),
            uki_source_path: Some("EFI/.aos-candidates/12/candidate.efi".into()),
            uki_sha256: Some(Sha256Digest::of_bytes(b"authenticated UKI").to_string()),
            uki_byte_size: Some(17),
            retired: false,
            _slot: Some("A".into()),
            _recovery: None,
        };
        assert_eq!(
            checked_staged_bytes(&evidence, &path).unwrap(),
            b"authenticated UKI"
        );
        fs::write(&path, b"substituted bytes").unwrap();
        assert!(checked_staged_bytes(&evidence, &path).is_err());
    }

    #[test]
    fn selection_replay_preserves_counts_and_new_selection_resets_only_owned_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let consumed = directory.path().join("candidate+0-3.efi");
        fs::write(&consumed, b"signed candidate").unwrap();
        assert!(
            !prepare_counted_payload(
                directory.path(),
                "candidate+3.efi",
                b"signed candidate",
                false
            )
            .unwrap()
        );
        assert!(consumed.exists());
        assert!(
            prepare_counted_payload(
                directory.path(),
                "candidate+3.efi",
                b"other candidate",
                true
            )
            .is_err()
        );
        assert!(consumed.exists());
        assert!(
            prepare_counted_payload(
                directory.path(),
                "candidate+3.efi",
                b"signed candidate",
                true
            )
            .unwrap()
        );
        assert!(!consumed.exists());
    }

    #[test]
    fn exhaustion_requires_zero_remaining_and_actual_completed_tries() {
        assert!(exhausted_entry("candidate+0-3.efi").unwrap());
        for name in [
            "candidate+3.efi",
            "candidate+1-2.efi",
            "candidate+0-0.efi",
            "candidate.efi",
            "candidate+0.efi",
        ] {
            assert!(!exhausted_entry(name).unwrap(), "{name}");
        }
        for name in [
            "candidate+0-3-1.efi",
            "candidate+0-.efi",
            "candidate+0-9999999999999.efi",
        ] {
            assert!(exhausted_entry(name).is_err(), "{name}");
        }
    }

    #[test]
    fn counted_entry_names_preserve_systemd_retry_progress() {
        assert_eq!(
            stable_entry("candidate-gen12+2-1.efi").unwrap(),
            "candidate-gen12.efi"
        );
        for name in ["candidate+.efi", "candidate+2-.efi", "candidate+2-1-1.efi"] {
            assert!(stable_entry(name).is_err());
        }
    }

    #[test]
    fn stable_entry_removes_only_a_terminal_boot_count() {
        assert_eq!(
            stable_entry("aos-generation+3.efi").unwrap(),
            "aos-generation.efi"
        );
        assert_eq!(
            stable_entry("aos-generation.efi").unwrap(),
            "aos-generation.efi"
        );
        assert!(stable_entry("aos-generation+bad.efi").is_err());
    }

    #[test]
    fn entry_paths_are_confined_to_the_boot_payload_directory() {
        assert_eq!(
            safe_entry_path("EFI/Linux/aos.efi").unwrap(),
            PathBuf::from("EFI/Linux/aos.efi")
        );
        assert!(safe_entry_path("../EFI/Linux/aos.efi").is_err());
        assert!(safe_entry_path("loader/aos.conf").is_err());
    }

    #[test]
    fn health_exit_codes_are_fail_closed() {
        assert!(health_from_exit_code(Some(0)).unwrap());
        assert!(!health_from_exit_code(Some(1)).unwrap());
        assert!(health_from_exit_code(Some(2)).is_err());
        assert!(health_from_exit_code(None).is_err());
    }
    #[test]
    fn completed_release_requires_all_owned_payload_variants_and_sidecars_absent() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path();
        let installed = boot.join("EFI/Linux");
        let hidden = boot.join("EFI/.aos-candidates/2");
        fs::create_dir_all(&installed).unwrap();
        fs::create_dir_all(&hidden).unwrap();
        let generation: ImageGeneration = serde_json::from_value(serde_json::json!({
            "number":2, "toplevel":"/nix/store/image", "native_executor_ref":"/nix/store/executor",
            "state_version":"1", "boot_artifact_contract":"/nix/store/contract",
            "boot_provider_state": {"schema":"aos.systemd.boot-generation-state/v1",
                "evidence":{"installed-entry":"EFI/Linux/gen2+3.efi", "uki-source-path":"EFI/.aos-candidates/2/candidate.efi", "retired":true}}
        })).unwrap();
        fs::write(installed.join("foreign.efi"), b"foreign payload").unwrap();
        assert!(retired_payload_is_absent(boot, &generation).unwrap());

        let counted = installed.join("gen2+0-3.efi");
        fs::write(&counted, b"owned payload").unwrap();
        assert!(!retired_payload_is_absent(boot, &generation).unwrap());
        fs::remove_file(&counted).unwrap();
        let sidecar = installed.join("gen2+0-3.efi.measurement.sig");
        fs::write(&sidecar, b"owned measurement").unwrap();
        assert!(!retired_payload_is_absent(boot, &generation).unwrap());
        fs::remove_file(&sidecar).unwrap();
        let hidden_sidecar = hidden.join("candidate.efi.measurement");
        fs::write(&hidden_sidecar, b"staged measurement").unwrap();
        assert!(!retired_payload_is_absent(boot, &generation).unwrap());
        fs::remove_file(&hidden_sidecar).unwrap();

        assert!(retired_payload_is_absent(boot, &generation).unwrap());
        assert_eq!(
            fs::read(installed.join("foreign.efi")).unwrap(),
            b"foreign payload"
        );
    }
}

fn validate_store_executable(path: &Path, label: &str) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "{label} path is not absolute");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "{label} path is not normalized"
    );

    let store = Path::new("/nix/store");
    let relative = path
        .strip_prefix(store)
        .with_context(|| format!("{label} is outside the immutable store"))?;
    let package = relative
        .components()
        .next()
        .and_then(|component| match component {
            Component::Normal(package) => Some(package),
            _ => None,
        })
        .with_context(|| format!("{label} store path has no package identity"))?;
    ensure!(
        relative.components().count() > 1,
        "{label} does not name a file inside its package"
    );

    let package_root = fs::canonicalize(store.join(package))
        .with_context(|| format!("resolving {label} package root"))?;
    let executable = fs::canonicalize(path).with_context(|| format!("resolving {label}"))?;
    ensure!(
        executable.starts_with(package_root),
        "{label} escapes its selected package"
    );
    let metadata = fs::metadata(&executable).with_context(|| format!("inspecting {label}"))?;
    ensure!(metadata.is_file(), "{label} is not a regular file");
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "{label} is not executable"
    );

    Ok(executable)
}
