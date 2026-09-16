//! Package-owned boot finalization for qualified A/B image rollouts.
//!
//! The boot service invokes this module after configuration activation. It
//! authenticates the configuration and rollout evidence before publishing
//! terminal image state. Boot selection, boot success, and restart effects are
//! performed only by the checked rollout platform abilities.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{LocalKey, TransactionId};
use aos_ability_runtime::execution::TerminalResult;
use aos_ability_runtime::journal::JournalLimits;

use super::{NativeAbRolloutBackend, authenticate_single_image_rollout_fragment};
use crate::attestation::{EVAL_MODE_PURE, GEN_ATTESTATION_SCHEMA, GenAttestation};
use crate::config_eval::RetainedAbilityDiagnosticSource;
use crate::config_eval::activation::{load_config_manifest, read_stored_activation_record};
use crate::types::{ImageGenerationState, ImageRolloutStatus};

const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const SYSTEM_PROFILE: &str = "/var/lib/profiles/system";
const IMAGE_STATE_FILE: &str = "state.json";
const TRANSITION_INTENT_FILE: &str = ".transition-intent.json";
const REEVALUATION_MARKER: &str = "/run/aos/image-reeval-required";

#[derive(Clone, Debug, Eq, PartialEq)]
enum BootCommand {
    Commit { require_attestation_quote: bool },
}

#[derive(Clone, Debug)]
struct BootCommitPaths {
    image_profile: PathBuf,
    system_profile: PathBuf,
    reevaluation_marker: PathBuf,
}

impl Default for BootCommitPaths {
    fn default() -> Self {
        Self {
            image_profile: PathBuf::from(IMAGE_PROFILE),
            system_profile: PathBuf::from(SYSTEM_PROFILE),
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
        _ => bail!("usage: aos-image-rollout-boot commit [--require-attestation-quote]"),
    }
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
    finalize_state(&mut images, qualified)?;
    crate::sysroot::write_atomic_durable(&state_path, &serde_json::to_vec_pretty(&images)?)?;
    crate::sysroot::remove_file_durable(&paths.image_profile.join(TRANSITION_INTENT_FILE))?;
    crate::sysroot::remove_file_durable(&paths.reevaluation_marker)?;
    Ok(())
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
    NativeAbRolloutBackend::new(&paths.image_profile)
        .verify_boot_commit(&request, running)
        .context("verifying provider-owned rollout health evidence")
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
