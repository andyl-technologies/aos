//! Package-owned boot finalization for qualified image rollouts.
//!
//! The boot service invokes this module after configuration activation. It
//! authenticates the configuration and rollout evidence before publishing
//! terminal image state. Boot selection, boot success, and restart effects are
//! performed only by the checked rollout platform abilities.

use std::path::{Path, PathBuf};

use super::{ImageRolloutRequest, NativeImageRolloutBackend};
use crate::attestation::native::MeasuredImageEvidence;
use crate::types::{ImageGenerationState, ImageRolloutStatus};
use anyhow::{Context as _, Result, bail, ensure};

const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const SYSTEM_PROFILE: &str = "/var/lib/profiles/system";
const IMAGE_STATE_FILE: &str = "state.json";
const TRANSITION_INTENT_FILE: &str = ".transition-intent.json";
const REEVALUATION_MARKER: &str = "/run/aos/image-reeval-required";

#[derive(Clone, Debug, Eq, PartialEq)]
enum BootCommand {
    Commit {
        require_attestation_quote: bool,
        image_evidence: Option<(PathBuf, PathBuf)>,
    },
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
            image_evidence,
        } => commit(
            &BootCommitPaths::default(),
            require_attestation_quote,
            image_evidence,
        ),
    }
}

fn parse_command(arguments: &[String]) -> Result<BootCommand> {
    ensure!(
        arguments
            .first()
            .is_some_and(|argument| argument == "commit"),
        "expected image boot commit"
    );
    let mut require_attestation_quote = false;
    let mut executable = None;
    let mut key = None;
    let mut remaining = arguments[1..].iter();
    while let Some(argument) = remaining.next() {
        match argument.as_str() {
            "--require-attestation-quote" if !require_attestation_quote => {
                require_attestation_quote = true
            }
            "--image-evidence-executable" if executable.is_none() => {
                executable = Some(PathBuf::from(
                    remaining.next().context("evidence executable is missing")?,
                ));
            }
            "--pcr-public-key" if key.is_none() => {
                key = Some(PathBuf::from(
                    remaining.next().context("PCR public key is missing")?,
                ));
            }
            _ => bail!("unknown or duplicate image boot commit argument"),
        }
    }
    let image_evidence = match (executable, key) {
        (Some(executable), Some(key)) => Some((executable, key)),
        (None, None) => None,
        _ => bail!("signed image evidence requires both executable and pinned public key"),
    };
    ensure!(
        !require_attestation_quote || image_evidence.is_some(),
        "required quote has no selected signed-image evidence verifier"
    );
    Ok(BootCommand::Commit {
        require_attestation_quote,
        image_evidence,
    })
}

fn commit(
    paths: &BootCommitPaths,
    require_attestation_quote: bool,
    image_evidence: Option<(PathBuf, PathBuf)>,
) -> Result<()> {
    let state_path = paths.image_profile.join(IMAGE_STATE_FILE);
    let mut images = read_json::<ImageGenerationState>(&state_path)?;
    images
        .validate()
        .context("validating image generation state before boot commit")?;
    let rollout = validate_boot_rollout(&images)?;
    let qualified = rollout.is_some();

    let authenticated = crate::sysroot::running_image_generation()?;
    let recorded = images
        .generations
        .iter()
        .find(|image| image.number == images.running)
        .context("running image generation is absent")?;
    ensure!(
        authenticated.toplevel == recorded.toplevel
            && authenticated.boot_artifact_contract == recorded.boot_artifact_contract,
        "running image differs from authenticated immutable boot identity"
    );
    let profile = crate::profile::Profile::open_at(
        paths.system_profile.clone(),
        crate::types::ProfileScope::System,
    )?;
    let generation = profile
        .current_generation()?
        .context("native profile has no current generation")?;
    let committed =
        crate::profile::deployment::committed_generation(&paths.system_profile, generation.number)?;
    if qualified {
        verify_rollout_transaction(&committed, images.running, paths)?;
    }
    // Physical expectations are supplied by the signed boot backend. An absent
    // pin remains unavailable; live PCR values never manufacture expectations.
    let image = match image_evidence {
        Some((executable, key)) => {
            for path in [&executable, &key] {
                crate::deployment::nix::store_root_and_suffix(path)?;
                ensure!(
                    std::fs::canonicalize(path)? == *path
                        && std::fs::symlink_metadata(path)?.is_file(),
                    "signed image verifier inputs are not canonical immutable files"
                );
            }
            use std::io::Read as _;
            let mut child = std::process::Command::new(executable)
                .env_clear()
                .arg("--pcr-public-key")
                .arg(key)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()?;
            let mut bytes = Vec::new();
            child
                .stdout
                .take()
                .context("image verifier output is absent")?
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                child.wait()?.success() && bytes.len() <= 64 * 1024,
                "signed image evidence verification failed"
            );
            let evidence: MeasuredImageEvidence = serde_json::from_slice(&bytes)?;
            ensure!(
                evidence.toplevel == authenticated.toplevel
                    && evidence.boot_artifact_contract == authenticated.boot_artifact_contract,
                "signed image evidence differs from authenticated boot identity"
            );
            evidence
        }
        None => MeasuredImageEvidence {
            toplevel: authenticated.toplevel,
            boot_artifact_contract: authenticated.boot_artifact_contract,
            expected_pcr11: None,
            root_verity_roothash: None,
            root_verity_uuid: None,
        },
    };
    crate::attestation::native::persist(
        &paths.system_profile,
        generation.number,
        image,
        require_attestation_quote,
        true,
    )?;
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
                    | ImageRolloutStatus::BootFailed
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
            matches!(
                rollout.status,
                ImageRolloutStatus::HealthFailed | ImageRolloutStatus::BootFailed
            ),
            "rollout fallback lacks failure evidence"
        );
    } else {
        bail!("running image is outside the qualified rollout pair");
    }
    Ok(Some(rollout))
}

fn verify_rollout_transaction(
    committed: &crate::deployment::transaction::Generation,
    running: u32,
    paths: &BootCommitPaths,
) -> Result<()> {
    // This binding is written by the OS aggregate, not discovered by searching
    // graph operation names. The selected result must be in this exact commit.
    let binding: serde_json::Value =
        read_json(&paths.image_profile.join("active-native-rollout.json"))?;
    let effect = binding
        .get("effect")
        .and_then(serde_json::Value::as_str)
        .context("native rollout binding omits effect identity")?;
    let request: ImageRolloutRequest = serde_json::from_value(
        binding
            .get("input")
            .and_then(|input| input.get("rollout"))
            .cloned()
            .context("native rollout binding omits rollout identity")?,
    )?;
    let checked = committed
        .outputs
        .get(effect)
        .context("committed native deployment has no selected rollout result")?;
    ensure!(
        checked.get("rollout") == Some(&serde_json::to_value(&request)?),
        "checked rollout result differs from OS binding"
    );
    let backend = NativeImageRolloutBackend::new(&paths.image_profile);
    ensure!(
        checked
            .get("retentionDirectory")
            .and_then(serde_json::Value::as_str)
            == backend.execution_directory(&request)?.to_str(),
        "checked rollout receipt directory differs from OS authority"
    );
    backend
        .verify_boot_commit(&request, running)
        .context("verifying native rollout health evidence")
}

fn finalize_state(images: &mut ImageGenerationState, qualified: bool) -> Result<()> {
    images.pending = None;
    if qualified {
        let mut rollout = images
            .active_rollout
            .take()
            .context("qualified rollout disappeared before state finalization")?;
        rollout.status = if images.running == rollout.candidate {
            ImageRolloutStatus::Succeeded
        } else {
            rollout.status
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
    use crate::types::{ImageGeneration, ImageRollout};

    #[test]
    fn boot_counter_failure_preserves_its_distinct_terminal_reason() {
        let mut images = state(1, ImageRolloutStatus::BootFailed);
        validate_boot_rollout(&images).unwrap();
        finalize_state(&mut images, true).unwrap();
        assert!(images.active_rollout.is_none());
        assert!(images.pending.is_none());
        assert_eq!(
            images.last_rollout.unwrap().status,
            ImageRolloutStatus::BootFailed
        );
    }

    #[test]
    fn finalization_publishes_distinct_rollout_outcomes() {
        let mut candidate = state(2, ImageRolloutStatus::CandidateBooted);
        finalize_state(&mut candidate, true).unwrap();
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
        let generation = |number| ImageGeneration {
            number,
            version: format!("test-{number}"),
            boot_artifact_contract: format!("/nix/store/{number:032}-boot-contract"),
            boot_provider_state: crate::types::BootProviderState {
                schema: "aos.test.boot-generation-state/v1".into(),
                evidence: serde_json::json!({"installed-entry": format!("installed-entry-{number}")}),
            },
            toplevel: format!("/nix/store/{number:032}-system"),
            package_name: "aos".to_string(),
            registry: "test".to_string(),
            kernel_path: None,
            state_version: "7".to_string(),
            native_executor_ref: format!("/nix/store/{number:032}-executor"),
            module_library: crate::types::ModuleLibraryIdentity {
                store_path: "/nix/store/11111111111111111111111111111111-module-library".into(),
                nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                nar_size: 1,
            },
            evaluation_descriptor:
                "/nix/store/22222222222222222222222222222222-evaluation/evaluation.json".into(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        ImageGenerationState {
            schema: "aos.image-generation-state/v1".into(),
            running,
            pending: Some(2),
            boot_provider_state: crate::types::BootProviderState {
                schema: "aos.test.boot-state/v1".into(),
                evidence: serde_json::json!({}),
            },
            active_rollout: Some(ImageRollout {
                schema: "aos.image-rollout/v1".to_string(),
                candidate: 2,
                prior: 1,
                state_version: "7".to_string(),
                status,
            }),
            last_rollout: None,
            generations: vec![generation(1), generation(2)],
        }
    }
}
