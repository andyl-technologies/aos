//! Package-owned boot finalization for qualified A/B image rollouts.
//!
//! The boot service invokes this module after configuration activation. It
//! authenticates the configuration and rollout evidence, commits the firmware
//! default, synchronizes the ESP replicas, and only then publishes terminal
//! image state. The failure entry point preserves the pre-ability fallback for
//! image transitions that do not carry a checked native ability plan.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{LocalKey, TransactionId};
use aos_ability_runtime::execution::TerminalResult;
use aos_ability_runtime::journal::JournalLimits;
use sha2::{Digest as _, Sha256};

use super::{NativeAbRolloutBackend, authenticate_single_image_rollout_fragment};
use crate::attestation::{EVAL_MODE_PURE, GEN_ATTESTATION_SCHEMA, GenAttestation};
use crate::config_eval::RetainedAbilityDiagnosticSource;
use crate::config_eval::activation::{load_config_manifest, read_stored_activation_record};
use crate::types::{ImageGenerationState, ImageRolloutStatus};

const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const SYSTEM_PROFILE: &str = "/var/lib/profiles/system";
const BOOT_ROOT: &str = "/boot";
const IMAGE_STATE_FILE: &str = "state.json";
const TRANSITION_INTENT_FILE: &str = ".transition-intent.json";
const REEVALUATION_MARKER: &str = "/run/aos/image-reeval-required";

#[derive(Clone, Debug, Eq, PartialEq)]
enum BootCommand {
    Commit { require_attestation_quote: bool },
    Fallback,
    MeasurementIndex { pcr_public_key: PathBuf },
}

#[derive(Clone, Debug)]
struct BootCommitPaths {
    image_profile: PathBuf,
    system_profile: PathBuf,
    boot_root: PathBuf,
    reevaluation_marker: PathBuf,
}

impl Default for BootCommitPaths {
    fn default() -> Self {
        Self {
            image_profile: PathBuf::from(IMAGE_PROFILE),
            system_profile: PathBuf::from(SYSTEM_PROFILE),
            boot_root: PathBuf::from(BOOT_ROOT),
            reevaluation_marker: PathBuf::from(REEVALUATION_MARKER),
        }
    }
}

/// Runs the package-owned boot-finalization command from process arguments.
///
/// # Errors
///
/// Returns an error when arguments are invalid or boot finalization cannot be
/// authenticated and committed.
pub fn run_from_process() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&arguments)? {
        BootCommand::Commit {
            require_attestation_quote,
        } => commit(&BootCommitPaths::default(), require_attestation_quote),
        BootCommand::Fallback => fallback(&BootCommitPaths::default()),
        BootCommand::MeasurementIndex { pcr_public_key } => {
            import_measurement(&BootCommitPaths::default(), &pcr_public_key)
        }
    }
}

fn parse_command(arguments: &[String]) -> Result<BootCommand> {
    match arguments {
        [command] if command == "commit" => Ok(BootCommand::Commit {
            require_attestation_quote: false,
        }),
        [command, flag] if command == "commit" && flag == "--require-attestation-quote" => {
            Ok(BootCommand::Commit {
                require_attestation_quote: true,
            })
        }
        [command] if command == "fallback" => Ok(BootCommand::Fallback),
        [command, flag, pcr_public_key]
            if command == "measurement-index" && flag == "--pcr-public-key" =>
        {
            let pcr_public_key = PathBuf::from(pcr_public_key);
            ensure!(
                pcr_public_key.is_absolute(),
                "PCR public key path must be absolute"
            );
            Ok(BootCommand::MeasurementIndex { pcr_public_key })
        }
        _ => bail!(
            "usage: aos-image-rollout-boot <commit [--require-attestation-quote] | fallback | measurement-index --pcr-public-key PATH>"
        ),
    }
}

/// Verifies the exact successful provider transaction before boot commit.
///
/// # Errors
///
/// Returns an error when retained transaction evidence is invalid, incomplete,
/// unsuccessful, or does not authorize the running image.
pub(crate) fn verify_rollout_boot_commit(
    generation: u32,
    transaction: &TransactionId,
    running: u32,
) -> Result<()> {
    verify_rollout_transaction(
        generation,
        transaction,
        running,
        &BootCommitPaths::default(),
    )
}

fn import_measurement(paths: &BootCommitPaths, pcr_public_key: &Path) -> Result<()> {
    let layout = crate::sysroot::ImageSlotLayout::from_running_toplevel()?;
    crate::sysroot::validate_boot_esp_mount(
        &paths.boot_root,
        Path::new("/proc/self/mountinfo"),
        &layout.esp_devices,
        true,
    )?;

    let state_path = paths.image_profile.join(IMAGE_STATE_FILE);
    let mut images = read_json::<ImageGenerationState>(&state_path)?;
    let matching = images
        .generations
        .iter()
        .filter(|generation| generation.number == images.running)
        .collect::<Vec<_>>();
    let [running] = matching.as_slice() else {
        bail!("running image generation is absent or ambiguous");
    };
    if running.registry != "seed" {
        ensure!(
            running
                .expected_pcr11
                .as_deref()
                .is_some_and(|digest| !digest.is_empty()),
            "registry image has no authenticated PCR 11 expectation"
        );
        return Ok(());
    }

    let recorded_relative = safe_uki_path(&running.uki_path)?;
    let recorded_uki = paths.boot_root.join(&recorded_relative);
    let live_uki = resolve_unique_live_uki(&paths.boot_root, &recorded_relative)?;
    let measurement = PathBuf::from(format!("{}.measurement", recorded_uki.display()));
    let signature = PathBuf::from(format!("{}.sig", measurement.display()));
    for required in [
        live_uki.as_path(),
        measurement.as_path(),
        signature.as_path(),
        pcr_public_key,
    ] {
        ensure!(
            required.is_file(),
            "required file is missing: {}",
            required.display()
        );
    }

    run(
        Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(pcr_public_key)
            .arg("-signature")
            .arg(&signature)
            .arg(&measurement),
        "verifying signed UKI measurement metadata",
    )?;
    let metadata = std::fs::read_to_string(&measurement)
        .with_context(|| format!("reading {}", measurement.display()))?;
    let parsed = parse_measurement(&metadata)?;
    ensure!(
        sha256_file(&live_uki)? == parsed.uki_sha256,
        "measurement metadata belongs to a different UKI"
    );

    if let Some(recorded) = running.expected_pcr11.as_deref() {
        ensure!(
            recorded == parsed.expected_pcr11,
            "catalog and signed UKI PCR 11 disagree"
        );
        return Ok(());
    }
    images
        .generations
        .iter_mut()
        .find(|generation| generation.number == images.running)
        .context("running image generation disappeared")?
        .expected_pcr11 = Some(parsed.expected_pcr11);
    crate::sysroot::write_atomic_durable(&state_path, &serde_json::to_vec_pretty(&images)?)
}

struct UkiMeasurement {
    uki_sha256: String,
    expected_pcr11: String,
}

fn parse_measurement(document: &str) -> Result<UkiMeasurement> {
    let lines = document.lines().collect::<Vec<_>>();
    let [schema, uki, expected] = lines.as_slice() else {
        bail!("measurement metadata must contain exactly three lines");
    };
    ensure!(
        *schema == "aos.uki-measurement/v1",
        "unsupported measurement schema"
    );
    let uki_sha256 = uki
        .strip_prefix("uki_sha256=")
        .context("measurement metadata has no UKI digest")?;
    let expected_pcr11 = expected
        .strip_prefix("expected_pcr11=sha256:")
        .context("measurement metadata has no PCR 11 digest")?;
    ensure!(
        is_lower_hex_digest(uki_sha256),
        "UKI digest is not canonical SHA-256"
    );
    ensure!(
        is_lower_hex_digest(expected_pcr11),
        "PCR 11 digest is not canonical SHA-256"
    );
    Ok(UkiMeasurement {
        uki_sha256: uki_sha256.to_string(),
        expected_pcr11: format!("sha256:{expected_pcr11}"),
    })
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_uki_path(recorded: &str) -> Result<PathBuf> {
    let path = Path::new(recorded);
    let components = path.components().collect::<Vec<_>>();
    let [
        Component::Normal(efi),
        Component::Normal(linux),
        Component::Normal(file),
    ] = components.as_slice()
    else {
        bail!("unsafe recorded UKI path {recorded:?}");
    };
    ensure!(
        *efi == "EFI" && *linux == "Linux",
        "UKI is outside EFI/Linux"
    );
    let file = file.to_str().context("UKI filename is not UTF-8")?;
    ensure!(
        file.ends_with(".efi") && file.len() > 4,
        "invalid UKI filename"
    );
    Ok(path.to_path_buf())
}

fn resolve_unique_live_uki(boot_root: &Path, recorded: &Path) -> Result<PathBuf> {
    let exact = boot_root.join(recorded);
    if exact.is_file() {
        return Ok(exact);
    }
    let filename = recorded
        .file_name()
        .and_then(|name| name.to_str())
        .context("recorded UKI has no UTF-8 filename")?;
    let stem = filename
        .strip_suffix(".efi")
        .context("recorded UKI has no .efi suffix")?;
    if let Some((base, remaining_tries)) = stem.rsplit_once('+') {
        ensure!(
            !base.is_empty()
                && !remaining_tries.is_empty()
                && remaining_tries.bytes().all(|byte| byte.is_ascii_digit()),
            "recorded UKI has an invalid terminal boot count"
        );
    }
    let stable = crate::sysroot::stable_uki_entry_id(filename)?;
    let stable_stem = stable
        .strip_suffix(".efi")
        .context("stable UKI has no .efi suffix")?;
    let directory = boot_root.join("EFI/Linux");
    let mut matching = std::fs::read_dir(&directory)
        .with_context(|| format!("reading {}", directory.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            (name == stable
                || (name.starts_with(&format!("{stable_stem}+")) && name.ends_with(".efi")))
            .then(|| entry.path())
        })
        .collect::<Vec<_>>();
    ensure!(matching.len() == 1, "live UKI is missing or ambiguous");
    Ok(matching.remove(0))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn commit(paths: &BootCommitPaths, require_attestation_quote: bool) -> Result<()> {
    let state_path = paths.image_profile.join(IMAGE_STATE_FILE);
    let mut images = read_json::<ImageGenerationState>(&state_path)?;
    let rollout = validate_boot_rollout(&images)?;
    let qualified = rollout.is_some();

    let configs = crate::sysroot::load_generation_state_pub(&paths.system_profile)?;
    let generation = configs
        .generations
        .iter()
        .filter(|generation| generation.number == configs.current)
        .collect::<Vec<_>>();
    let [generation] = generation.as_slice() else {
        bail!("running configuration generation is absent or ambiguous");
    };
    let generation_root = paths
        .system_profile
        .join(format!("gen-{}", generation.number));
    let manifest_path = generation_root.join("manifest.json");
    ensure!(
        manifest_path
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0),
        "running configuration generation has no committed manifest"
    );

    let activation_path = generation_root.join("activation.json");
    let activation = read_stored_activation_record(&activation_path, true)?
        .context("running configuration generation has no activation proof")?;
    validate_activation_proof(
        &activation,
        generation.number,
        &generation.manifest_hash,
        qualified,
    )?;

    let manifest = load_config_manifest(&manifest_path)?;
    if qualified && manifest.inputs.ability_activation.is_some() {
        let transaction = activation
            .native_ability_transaction
            .as_deref()
            .context("native ability health evidence is missing")?;
        let transaction = TransactionId(
            LocalKey::new(transaction.to_string())
                .context("decoding rollout transaction identity")?,
        );
        verify_rollout_transaction(generation.number, &transaction, images.running, paths)?;
    }

    let attestation_path = generation_root.join("gen-attestation.json");
    let attestation = read_json::<GenAttestation>(&attestation_path)?;
    ensure!(
        attestation.schema == GEN_ATTESTATION_SCHEMA
            && attestation.generation_id == generation.manifest_hash
            && attestation.manifest_hash == generation.manifest_hash
            && attestation.eval_mode == EVAL_MODE_PURE,
        "generation attestation is incomplete"
    );
    if require_attestation_quote {
        let running = images
            .running_generation()
            .context("image state has no running generation")?;
        crate::verify_local_boot_commit(
            &attestation_path,
            &generation_root.join("gen-attestation-quote"),
            running.expected_pcr11.as_deref(),
        )?;
    }

    ensure!(
        generation.image_gen_parent == images.running,
        "configuration has not rebound to running image {}",
        images.running
    );
    commit_firmware(paths, &images)?;
    crate::sysroot::replicate_boot_partitions(
        &crate::sysroot::ImageSlotLayout::from_running_toplevel()?,
    )?;

    finalize_state(&mut images, qualified)?;
    crate::sysroot::write_atomic_durable(&state_path, &serde_json::to_vec_pretty(&images)?)?;
    crate::sysroot::remove_file_durable(&paths.image_profile.join(TRANSITION_INTENT_FILE))?;
    crate::sysroot::remove_file_durable(&paths.reevaluation_marker)?;
    Ok(())
}

fn fallback(paths: &BootCommitPaths) -> Result<()> {
    let state_path = paths.image_profile.join(IMAGE_STATE_FILE);
    let metadata = match state_path.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("reading image generation state metadata"),
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return Ok(());
    }

    let mut images = read_json::<ImageGenerationState>(&state_path)?;
    if images.active_rollout.is_none() {
        return Ok(());
    }

    let configs = crate::sysroot::load_generation_state_pub(&paths.system_profile)?;
    let manifest_path = paths
        .system_profile
        .join(format!("gen-{}", configs.current))
        .join("manifest.json");
    if manifest_path.is_file()
        && load_config_manifest(&manifest_path)?
            .inputs
            .ability_activation
            .is_some()
    {
        return Ok(());
    }

    let rollout =
        validate_boot_rollout(&images)?.context("image rollout fallback has no active rollout")?;
    ensure!(
        images.running == rollout.candidate
            && matches!(
                rollout.status,
                ImageRolloutStatus::CandidateBooted | ImageRolloutStatus::HealthFailed
            ),
        "refusing an invalid rollout fallback"
    );
    images
        .active_rollout
        .as_mut()
        .context("active rollout disappeared")?
        .status = ImageRolloutStatus::HealthFailed;
    crate::sysroot::write_atomic_durable(&state_path, &serde_json::to_vec_pretty(&images)?)?;
    run(
        Command::new("systemctl").args(["--no-block", "reboot"]),
        "requesting rollout fallback",
    )
}

fn validate_boot_rollout(
    images: &ImageGenerationState,
) -> Result<Option<&crate::types::ImageRollout>> {
    let Some(rollout) = images.active_rollout.as_ref() else {
        return Ok(None);
    };
    ensure!(
        rollout.schema == "aos.image-rollout/v1"
            && rollout.candidate != rollout.prior
            && images.pending == Some(rollout.candidate)
            && !rollout.state_version.is_empty()
            && matches!(
                rollout.status,
                ImageRolloutStatus::Staged
                    | ImageRolloutStatus::CandidateBooted
                    | ImageRolloutStatus::HealthFailed
            ),
        "qualified rollout record is invalid"
    );
    for (role, number) in [("candidate", rollout.candidate), ("prior", rollout.prior)] {
        let matching = images
            .generations
            .iter()
            .filter(|generation| {
                generation.number == number && generation.state_version == rollout.state_version
            })
            .count();
        ensure!(
            matching == 1,
            "qualified rollout {role} identity is absent, ambiguous, or changed"
        );
    }
    if images.running == rollout.candidate {
        ensure!(
            rollout.status == ImageRolloutStatus::CandidateBooted,
            "rollout candidate is not health-eligible"
        );
    } else if images.running == rollout.prior {
        ensure!(
            rollout.status == ImageRolloutStatus::HealthFailed,
            "rollout fallback lacks failure evidence"
        );
    } else {
        bail!("running image is outside the qualified rollout pair");
    }
    Ok(Some(rollout))
}

fn validate_activation_proof(
    activation: &crate::config_eval::activation::StoredActivationRecord,
    generation: u32,
    manifest_hash: &str,
    qualified: bool,
) -> Result<()> {
    let healthy = if qualified {
        activation.status == "complete" && activation.activation_exit == 0
    } else {
        matches!(activation.status.as_str(), "complete" | "degraded")
            && matches!(activation.activation_exit, 0 | 5 | 6)
    };
    ensure!(
        activation.schema == "aos.config-activation/v1"
            && activation.generation == generation
            && activation.generation_id == manifest_hash
            && healthy,
        "configuration activation proof is incomplete"
    );
    Ok(())
}

fn verify_rollout_transaction(
    generation: u32,
    transaction: &TransactionId,
    running: u32,
    paths: &BootCommitPaths,
) -> Result<()> {
    let generation = paths.system_profile.join(format!("gen-{generation}"));
    let source = RetainedAbilityDiagnosticSource::load(
        generation,
        transaction,
        crate::config_eval::supported_native_ability_features()?,
    )
    .context("authenticating retained rollout transaction")?;
    let request = authenticate_single_image_rollout_fragment(source.plan())
        .context("authenticating the retained rollout fragment")?;
    ensure!(
        source.terminal_result(JournalLimits::default())? == Some(TerminalResult::Succeeded),
        "native rollout transaction did not settle successfully"
    );
    NativeAbRolloutBackend::new(&paths.image_profile, &paths.boot_root)
        .verify_boot_commit(&request, running)
        .context("verifying provider-owned rollout health evidence")
}

fn commit_firmware(paths: &BootCommitPaths, images: &ImageGenerationState) -> Result<()> {
    let running = images
        .running_generation()
        .context("image state has no running generation")?;
    let recorded = crate::sysroot::validate_staged_uki_path(&running.uki_path)?;
    let stable = crate::sysroot::stable_uki_entry_id(&recorded)?;
    let installed =
        crate::sysroot::resolve_installed_uki_entry(&paths.boot_root, &running.uki_path)?;

    crate::sysroot::with_writable_boot(|| {
        if images.pending == Some(images.running)
            && crate::sysroot::entry_remaining_tries(&installed).is_some()
        {
            run(
                Command::new("systemd-bless-boot").args(["--path", BOOT_ROOT, "good"]),
                "blessing the running image",
            )?;
        }
        run(
            Command::new("bootctl").args(["set-default", &stable]),
            "selecting the running image as firmware default",
        )
    })
}

fn finalize_state(images: &mut ImageGenerationState, qualified: bool) -> Result<()> {
    images.default = images.running;
    images.pending = None;
    images.recovery_pending = None;
    if let Some(recovery) = images
        .running_generation()
        .and_then(|generation| generation.recovery.as_ref())
    {
        images.recovery_known_good = Some(recovery.copy);
    }
    if qualified {
        let mut rollout = images
            .active_rollout
            .take()
            .context("qualified rollout disappeared before state finalization")?;
        rollout.status = if images.running == rollout.candidate {
            ImageRolloutStatus::Succeeded
        } else {
            ImageRolloutStatus::HealthFailed
        };
        images.last_rollout = Some(rollout);
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))
}

fn run(command: &mut Command, action: &str) -> Result<()> {
    let status = command.status().with_context(|| action.to_string())?;
    ensure!(status.success(), "{action} failed with {status}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ImageGeneration, ImageRollout, ImageSlot};

    #[test]
    fn finalization_publishes_distinct_rollout_outcomes() {
        let mut candidate = state(2, ImageRolloutStatus::CandidateBooted);
        finalize_state(&mut candidate, true).unwrap();
        assert_eq!(candidate.default, 2);
        assert_eq!(candidate.pending, None);
        assert_eq!(
            candidate
                .last_rollout
                .as_ref()
                .map(|rollout| rollout.status),
            Some(ImageRolloutStatus::Succeeded)
        );

        let mut fallback = state(1, ImageRolloutStatus::HealthFailed);
        finalize_state(&mut fallback, true).unwrap();
        assert_eq!(
            fallback.last_rollout.as_ref().map(|rollout| rollout.status),
            Some(ImageRolloutStatus::HealthFailed)
        );
    }

    #[test]
    fn rollout_validation_rejects_ambiguous_identity() {
        let mut images = state(2, ImageRolloutStatus::CandidateBooted);
        images.generations.push(images.generations[1].clone());
        assert!(validate_boot_rollout(&images).is_err());
    }

    #[test]
    fn measurement_metadata_is_strict_and_canonical() {
        let parsed = parse_measurement(&format!(
            "aos.uki-measurement/v1\nuki_sha256={}\nexpected_pcr11=sha256:{}\n",
            "a".repeat(64),
            "b".repeat(64)
        ))
        .unwrap();
        assert_eq!(parsed.uki_sha256, "a".repeat(64));
        assert_eq!(parsed.expected_pcr11, format!("sha256:{}", "b".repeat(64)));

        assert!(parse_measurement("aos.uki-measurement/v1\nuki_sha256=AA\n").is_err());
        assert!(safe_uki_path("EFI/Linux/aos-generation+3.efi").is_ok());
        assert!(safe_uki_path("../EFI/Linux/aos-generation+3.efi").is_err());
    }

    #[test]
    fn measurement_command_requires_an_explicit_absolute_key() {
        let command = parse_command(&[
            "measurement-index".to_string(),
            "--pcr-public-key".to_string(),
            "/nix/store/pcr-key/pcr.pem".to_string(),
        ])
        .unwrap();
        assert_eq!(
            command,
            BootCommand::MeasurementIndex {
                pcr_public_key: PathBuf::from("/nix/store/pcr-key/pcr.pem")
            }
        );
        assert!(parse_command(&["measurement-index".to_string()]).is_err());
        assert!(
            parse_command(&[
                "measurement-index".to_string(),
                "--pcr-public-key".to_string(),
                "relative.pem".to_string(),
            ])
            .is_err()
        );
    }

    fn state(running: u32, status: ImageRolloutStatus) -> ImageGenerationState {
        let generation = |number, slot| ImageGeneration {
            number,
            version: format!("test-{number}"),
            slot,
            toplevel: format!("/nix/store/{number:032}-system"),
            uki_path: format!("EFI/Linux/aos-generation-{number:010}+3.efi"),
            uki_source_path: None,
            package_name: "aos".to_string(),
            registry: "test".to_string(),
            kernel_path: None,
            state_version: "7".to_string(),
            native_executor_ref: format!("/nix/store/{number:032}-executor"),
            evaluator_ref: format!("/nix/store/{number:032}-evaluator"),
            module_abi: 1,
            base_lib_abi_hash: format!("sha256:{}", "0".repeat(64)),
            root_verity_roothash: None,
            expected_pcr11: None,
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        ImageGenerationState {
            running,
            default: 1,
            pending: Some(2),
            recovery_known_good: None,
            recovery_pending: None,
            active_rollout: Some(ImageRollout {
                schema: "aos.image-rollout/v1".to_string(),
                candidate: 2,
                prior: 1,
                state_version: "7".to_string(),
                status,
            }),
            last_rollout: None,
            generations: vec![generation(1, ImageSlot::A), generation(2, ImageSlot::B)],
        }
    }
}
