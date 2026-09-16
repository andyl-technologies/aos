//! Systemd and ESP implementations of provider-neutral image rollout platform effects.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use serde::{Deserialize, Serialize};

use crate::executable::validate_store_executable;
use crate::{decode_value, target_context, value};

const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const BOOT_ROOT: &str = "/boot";
const RETENTION_ROOT: &str = "EFI/.aos-rollout-retention";

const CONTEXT_SCHEMA: &str = "aos.systemd.image-rollout-platform-context/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootPlatformRole {
    ArtifactStorage,
    Selection,
    Success,
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
#[serde(deny_unknown_fields)]
struct SelectionRequest {
    rollout: RolloutRequest,
    entry: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartRequest {
    reason: RestartReason,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RestartReason {
    ActivateImage,
    RestoreImage,
}

#[derive(Debug, Deserialize)]
struct ImageState {
    generations: Vec<ImageGeneration>,
    running: u32,
}

#[derive(Debug, Deserialize)]
struct ImageGeneration {
    number: u32,
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
}

#[derive(Debug, Deserialize, Serialize)]
struct ProviderContext {
    schema: String,
    role: String,
    tools: BootPlatformTools,
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

pub(crate) fn admit(
    role: BootPlatformRole,
    request: AdmissionRequest,
    tools: Option<&BootPlatformTools>,
) -> Result<AdmissionResult> {
    ensure!(
        request.schema == ADMISSION_REQUEST_SCHEMA,
        "unsupported admission request schema"
    );
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    require_method(role, &request.method, &request.semantics)?;
    let observation_schema = request
        .contract
        .observation_discriminator()
        .context("selected boot-platform method has no exact observation discriminator")?;

    let rollout: RolloutRequest = decode_value(&request.resource_spec.value)?;
    validate_rollout(&rollout)?;
    let tools = tools
        .context("selected systemd launcher omitted the boot tool context")?
        .clone();
    let observation = observe_role(role, observation_schema, &rollout, None)?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .context("boot platform purpose set is not canonical")?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Unknown,
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context: value(&ProviderContext {
            schema: CONTEXT_SCHEMA.to_string(),
            role: role_name(role).to_string(),
            tools,
        })?,
        supported_purposes,
    })
}

pub(crate) fn invoke(role: BootPlatformRole, invocation: Invocation) -> Result<InvocationResult> {
    ensure!(
        invocation.schema == INVOCATION_SCHEMA && invocation.request.schema == REQUEST_SCHEMA,
        "unsupported invocation schema"
    );
    ensure!(
        invocation.method_is_bound(),
        "invocation method is not bound to its recovery contract"
    );
    ensure!(
        resource_set_digest(&invocation.request.resources)?
            == invocation.request.native_context_digest,
        "invocation resource-set digest does not match"
    );
    validate_resource_contexts(&invocation.request.resources)?;
    require_method(role, &invocation.method, &invocation.semantics)?;
    require_method(
        role,
        &invocation.request.method,
        &invocation.request.semantics,
    )?;
    let observation_schema = invocation
        .contract
        .observation_discriminator()
        .context("selected boot-platform method has no exact observation discriminator")?;

    let target = target_context(&invocation)?;
    let bound = validate_resource_context(target)?;
    let rollout: RolloutRequest = decode_value(&bound.resource_spec.value)?;
    validate_rollout(&rollout)?;
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    ensure!(
        provider.schema == CONTEXT_SCHEMA && provider.role == role_name(role),
        "boot platform context differs from the selected role"
    );
    provider.tools.validate()?;

    let method = invocation.method.method.as_str();
    let selected_entry = validate_inputs(role, method, &rollout, &invocation.request.inputs)?;
    let observation = match invocation.purpose {
        InvocationPurpose::Effect => apply(
            role,
            observation_schema,
            method,
            &rollout,
            selected_entry.as_deref(),
            &provider.tools,
        )?,
        InvocationPurpose::Reconcile => observe_role(
            role,
            observation_schema,
            &rollout,
            selected_entry.as_deref(),
        )?,
        _ => bail!("boot platform role does not advertise this invocation purpose"),
    };
    let mut outputs = BTreeMap::from([(LocalKey::new("observation")?, observation.clone())]);
    if role == BootPlatformRole::Selection && method == "resolve" {
        outputs.insert(
            LocalKey::new("entry")?,
            AbilityValue::new(serde_json::Value::String(resolve_candidate_entry(
                &rollout,
            )?))
            .map_err(anyhow::Error::msg)?,
        );
    }

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: InvocationDisposition::Completed,
        evidence: observation,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn validate_inputs(
    role: BootPlatformRole,
    method: &str,
    rollout: &RolloutRequest,
    inputs: &AbilityValue,
) -> Result<Option<String>> {
    match role {
        BootPlatformRole::ArtifactStorage | BootPlatformRole::Success => {
            let requested: RolloutRequest = decode_value(inputs)?;
            ensure!(
                &requested == rollout,
                "boot platform inputs differ from the checked rollout"
            );
            Ok(None)
        }
        BootPlatformRole::Selection => {
            let requested: SelectionRequest = decode_value(inputs)?;
            ensure!(
                requested.rollout == *rollout,
                "boot selection inputs differ from the checked rollout"
            );
            if method == "select" {
                ensure!(
                    requested.entry.is_some(),
                    "boot selection requires a resolved entry"
                );
            }
            Ok(requested.entry)
        }
        BootPlatformRole::HostRestart => {
            let request: RestartRequest = decode_value(inputs)?;
            match request.reason {
                RestartReason::ActivateImage | RestartReason::RestoreImage => {}
            }
            Ok(None)
        }
    }
}

fn apply(
    role: BootPlatformRole,
    observation_schema: &str,
    method: &str,
    rollout: &RolloutRequest,
    entry: Option<&str>,
    tools: &BootPlatformTools,
) -> Result<AbilityValue> {
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
                run(
                    &tools.bootctl,
                    &["set-default", entry],
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

fn observe_role(
    role: BootPlatformRole,
    observation_schema: &str,
    rollout: &RolloutRequest,
    entry: Option<&str>,
) -> Result<AbilityValue> {
    match role {
        BootPlatformRole::ArtifactStorage => storage_observation(observation_schema, rollout),
        BootPlatformRole::Selection => selection_observation(observation_schema, rollout, entry),
        BootPlatformRole::Success => success_observation(observation_schema, rollout),
        BootPlatformRole::HostRestart => value(&RestartObservation {
            schema: observation_schema,
            state: "not-requested",
        }),
    }
}

fn storage_observation(observation_schema: &str, rollout: &RolloutRequest) -> Result<AbilityValue> {
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
) -> Result<AbilityValue> {
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

fn success_observation(observation_schema: &str, rollout: &RolloutRequest) -> Result<AbilityValue> {
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

fn validate_rollout(request: &RolloutRequest) -> Result<()> {
    ensure!(
        !request.candidate.state_format.is_empty()
            && request.candidate.state_format == request.predecessor.state_format,
        "rollout images have incompatible state formats"
    );
    Ok(())
}

fn require_method(
    role: BootPlatformRole,
    method: &MethodReference,
    semantics: &MethodSemantics,
) -> Result<()> {
    let access = match (role, method.method.as_str()) {
        (BootPlatformRole::ArtifactStorage, "observe")
        | (BootPlatformRole::Selection, "resolve" | "observe")
        | (BootPlatformRole::Success, "observe")
        | (BootPlatformRole::HostRestart, "observe") => AccessMode::Read,
        (BootPlatformRole::ArtifactStorage, "retain" | "release")
        | (BootPlatformRole::Selection, "select" | "clear")
        | (BootPlatformRole::Success, "mark")
        | (BootPlatformRole::HostRestart, "request") => AccessMode::ExclusiveWrite,
        _ => bail!("handler invocation selects an unsupported boot platform method"),
    };
    ensure!(
        *semantics == MethodSemantics::ordinary(access),
        "boot platform method carries mismatched semantics"
    );
    Ok(())
}

const fn role_name(role: BootPlatformRole) -> &'static str {
    match role {
        BootPlatformRole::ArtifactStorage => "artifact-storage",
        BootPlatformRole::Selection => "selection",
        BootPlatformRole::Success => "success",
        BootPlatformRole::HostRestart => "host-restart",
    }
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
        .filter(|generation| generation.boot_artifact_contract == identity.boot_artifact_contract)
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
    let recorded = safe_entry_path(&generation.boot_provider_state.evidence.installed_entry)?;
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
            if !base.is_empty() && tries.bytes().all(|byte| byte.is_ascii_digit()) =>
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
    let predecessor_digest = copy_payload(&predecessor_entry, &directory.join("predecessor.efi"))?;
    let candidate_digest = copy_payload(&candidate_entry, &directory.join("candidate.efi"))?;
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
    }
    match fs::remove_dir_all(&directory) {
        Ok(()) => sync_parent(&directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", directory.display())),
    }
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
    let state = image_state()?;
    let candidate = generation_for(&state, &rollout.candidate)?;
    let predecessor = generation_for(&state, &rollout.predecessor)?;
    let entry = if state.running == candidate.number {
        &retained.predecessor_entry
    } else if state.running == predecessor.number {
        &retained.candidate_entry
    } else {
        bail!("running image is outside the checked rollout pair");
    };
    stable_entry(entry)?;
    let path = Path::new(BOOT_ROOT).join("EFI/Linux").join(entry);
    match fs::remove_file(&path) {
        Ok(()) => sync_parent(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
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
    let path = Path::new(BOOT_ROOT).join("loader/loader.conf");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let defaults = text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("default ")
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
        })
        .collect::<Vec<_>>();
    ensure!(
        defaults.len() <= 1,
        "boot loader configuration has ambiguous defaults"
    );
    Ok(defaults.first().map(|entry| (*entry).to_string()))
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
}
