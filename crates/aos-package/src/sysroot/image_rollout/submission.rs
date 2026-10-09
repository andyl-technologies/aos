//! Admitted operator-source submission for native image selection and rollout.
//!
//! These entry points append ordinary package configuration to the retained
//! native profile descriptor. They never submit a caller-authored effect graph.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_core::output::Printer;
use serde_json::Value;

use super::{ImageRolloutRequest, RolloutImageIdentity, is_qualified_image_rollout};
use crate::config::ApmConfig;
use crate::deployment::evaluation::Evaluation;
use crate::profile::{Generation, Profile};
use crate::sysroot::{SystemTransitionMode, running_image_generation};
use crate::types::{ImageGeneration, ProfileScope};

pub(super) fn evaluation(config: &ApmConfig) -> Result<(Evaluation, PathBuf)> {
    ensure!(
        config.scope == ProfileScope::System,
        "image selection requires the system profile"
    );
    let profile = Profile::open_readonly(config.scope);
    let number = crate::profile::deployment::current_committed_generation(&profile.path)?
        .context("image selection requires a committed native system profile")?;
    let generation = Generation {
        number,
        path: profile.path.join(format!("gen-{number}")),
    };
    let desired = crate::install::native::probe_rollback(&profile, &generation)?;
    let nix_store = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    let (descriptor, input) = crate::native_deployment::read_retained_evaluation_in(
        &generation.path.join("evaluation.json"),
        &desired,
        &nix_store,
        &CancellationToken::default(),
    )?;
    let mut configuration = input.configuration;
    configuration.extend(input.runtime_configuration);
    let declarations = crate::native_deployment::retained_declarations(
        &input.package_envelopes,
        input.os_release.as_ref(),
        &nix_store,
    )?;
    Ok((
        Evaluation {
            os_release: input.os_release.clone(),
            os_requirements: declarations.os_requirements,
            package_releases: declarations.package_releases,
            nix_store,
            library: input.library,
            scope: input.scope,
            packages: input.packages,
            module_requirements: input
                .resolution_lock
                .as_ref()
                .map_or_else(Vec::new, |lock| lock.module_requirements()),
            configuration,
            retained_inputs: desired.inputs().iter().map(PathBuf::from).collect(),
            evaluation_input: Some(descriptor),
        },
        profile.path,
    ))
}

pub(super) fn project(evaluation: &Evaluation, key: &str, staging: &Path) -> Result<Value> {
    evaluation.project(
        &["aos".into(), "imageRollout".into(), key.into()],
        staging,
        60_000,
        &CancellationToken::default(),
    )
}

/// Checks selected native policy before downloading or physically staging an image.
///
/// # Errors
/// Returns an error for unavailable authenticated native inputs or missing
/// explicitly configured platform, drain, and drain observation programs.
pub(crate) fn preflight_image_selection(
    config: &ApmConfig,
    mode: SystemTransitionMode,
    drain: bool,
) -> Result<()> {
    let (evaluation, _) = evaluation(config)?;
    let staging = tempfile::tempdir()?;
    ensure!(
        project(&evaluation, "platformExecutable", staging.path())?
            .as_str()
            .is_some(),
        "native image selection platform is not configured"
    );
    if is_qualified_image_rollout(mode, drain) {
        for key in ["drain", "drainObservation"] {
            ensure!(
                !project(&evaluation, key, staging.path())?.is_null(),
                "qualified image rollout requires explicit {key} configuration"
            );
        }
    }
    Ok(())
}

fn identity(image: &ImageGeneration) -> RolloutImageIdentity {
    RolloutImageIdentity {
        toplevel: image.toplevel.clone(),
        boot_artifact_contract: image.boot_artifact_contract.clone(),
        executor: image.native_executor_ref.clone(),
        state_format: image.state_version.clone(),
    }
}

/// Appends admitted native selection policy and commits through ProfileDeployment.
///
/// # Errors
/// Returns an error for changed image authority, missing native policy,
/// rejected source admission, uncertain drain, or unsuccessful selection.
pub(crate) fn submit_image_selection(
    config: &ApmConfig,
    candidate: &ImageGeneration,
    mode: SystemTransitionMode,
    drain: bool,
    printer: &Printer,
) -> Result<()> {
    preflight_image_selection(config, mode, drain)?;
    let running = running_image_generation()?;
    let qualified = is_qualified_image_rollout(mode, drain);
    ensure!(
        qualified || candidate.native_executor_ref == running.native_executor_ref,
        "native executor replacement requires a drained reboot"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let deadline = u64::try_from(now)?
        .checked_add(super::MAX_RETENTION_MILLIS)
        .context("image retention deadline overflow")?;
    let request = ImageRolloutRequest {
        predecessor: identity(&running),
        candidate: identity(candidate),
        retention_expires_at_millis: deadline,
    };
    let source = tempfile::tempdir()?;
    let staging = tempfile::tempdir()?;
    let json = serde_json::to_string(&serde_json::json!({"rollout":request,"qualified":qualified,
        "restart":matches!(mode, SystemTransitionMode::Reboot)}))?;
    fs::write(
        source.path().join("image-selection.nix"),
        format!(
            "{{ ... }}: {{ aos.imageRollout.requests = [ (builtins.fromJSON {}) ]; }}\n",
            crate::deployment::nix::nix_string(&json)
        ),
    )?;
    let snapshot = crate::runtime_modules::snapshot(source.path(), staging.path(), true)?;
    let (mut evaluated, _) = evaluation(config)?;
    evaluated
        .configuration
        .extend(snapshot.entrypoints.iter().cloned());
    let effect = project(&evaluated, "selectedEffect", staging.path())?
        .as_str()
        .context("native image request did not select an effect")?
        .to_owned();
    match crate::install::native::append_runtime_snapshot(config, &snapshot, printer) {
        Ok(_) => Ok(()),
        Err(error) if qualified => {
            // A reboot may intentionally leave the aggregate transaction pending.
            // Only the exact admitted effect with a completed restart receipt is accepted.
            let receipt: Value =
                match fs::read("/var/lib/profiles/image/active-native-rollout.json") {
                    Ok(bytes) if bytes.len() <= 64 * 1024 => serde_json::from_slice(&bytes)?,
                    _ => return Err(error),
                };
            if receipt.get("effect").and_then(Value::as_str) == Some(&effect)
                && receipt
                    .pointer("/phases/candidate-restart")
                    .and_then(Value::as_bool)
                    == Some(true)
                && receipt.pointer("/input/rollout") == Some(&serde_json::to_value(request)?)
            {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}
