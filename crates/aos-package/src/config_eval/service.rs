//! Boot-time configuration evaluation service orchestration.
//!
//! This module turns the previously shell-authored service flow into one
//! compiled entry point. It selects retained image-transition inputs or the
//! current authenticated host input, reconstructs the exact runtime module
//! set from the active manifest, and invokes the same configuration evaluator
//! used by explicit package operations.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::materialize::ConfigManifest;
use super::{EvalCommand, current_config_generation_number, run_eval_command};

const IMAGE_REEVALUATION_MARKER: &str = "/run/aos/image-reeval-required";
const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const SYSTEM_PROFILE: &str = "/var/lib/profiles/system";
const SYSTEM_STATE: &str = "/var/lib/profiles/system/state.json";
const ACTIVE_MANIFEST: &str = "/var/lib/profiles/system/current/manifest.json";
const RUNNING_OS_RELEASE: &str = "/aos-toplevel/os-release";
const RUNTIME_GRAPH: &str = "/run/aos/graph.json";

/// Supplies the image-owned and operator-configurable paths for boot evaluation.
#[derive(Debug, Clone)]
pub struct ServiceCommand {
    /// Exact host module path released by initrd metadata authorization.
    pub host_nix: PathBuf,
    /// Image-owned base module library.
    pub base_lib: PathBuf,
    /// Fallback module ABI when the running image omits it.
    pub module_abi: u32,
    /// Optional desired package selection file.
    pub desired: PathBuf,
    /// Destination for the converged manifest.
    pub out: PathBuf,
    /// Private evaluator scratch directory.
    pub eval_root: PathBuf,
    /// Durable provisioning evidence and last-known-good input directory.
    pub provisioning_state: PathBuf,
    /// Immutable image version recorded with provisioning evidence.
    pub image_version: String,
    /// Verbosity forwarded to the evaluator.
    pub verbose: u8,
}

/// Runs one boot-time configuration evaluation.
///
/// # Errors
///
/// Returns an error when retained image-transition inputs cannot be replayed,
/// metadata authorization evidence does not bind the current host module, the
/// active runtime module set is malformed, or configuration evaluation fails.
pub fn run(command: &ServiceCommand) -> Result<()> {
    create_runtime_directories(command)?;
    remove_stale_output(&command.out)?;
    remove_stale_output(Path::new(RUNTIME_GRAPH))?;
    prepare_provisioning_input(command)?;
    crate::sysroot::reconcile_image_boot_for_config_evaluation(
        Path::new(IMAGE_PROFILE),
        Path::new(SYSTEM_PROFILE),
        Path::new(IMAGE_REEVALUATION_MARKER),
    )?;

    if retained_reevaluation_is_required() {
        let result = crate::sysroot::reeval_active_config_for_boot(
            Path::new(SYSTEM_PROFILE),
            command.eval_root.clone(),
            command.out.clone(),
            command.verbose,
        );
        cache_accepted_input(command, result)?;
        return Ok(());
    }

    let (host_nix, image_default_host) = stage_host_module(command)?;
    let module_abi =
        running_module_abi(Path::new(RUNNING_OS_RELEASE))?.unwrap_or(command.module_abi);
    let (runtime_modules, runtime_module_root, expected_current_generation) =
        active_runtime_modules(Path::new(ACTIVE_MANIFEST), Path::new(SYSTEM_STATE))?;
    let desired = command.desired.is_file().then(|| command.desired.clone());

    let result = run_eval_command(&EvalCommand {
        host_nix,
        runtime_modules,
        runtime_module_root,
        expected_current_generation,
        base_lib: command.base_lib.clone(),
        facts_json: Some(PathBuf::from(super::stock::DEFAULT_FACTS_PATH)),
        desired,
        module_abi,
        out: command.out.clone(),
        eval_root: command.eval_root.clone(),
        verbose: command.verbose,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: None,
        require_signed_host_nix: false,
        image_default_host,
        registry_snapshot: None,
    });
    cache_accepted_input(command, result)
}

fn prepare_provisioning_input(command: &ServiceCommand) -> Result<()> {
    let stash = Path::new(crate::metadata::stash::DEFAULT_STASH_DIR);
    if !command.host_nix.is_file() {
        crate::metadata::state::restore_runtime_input(stash, &command.provisioning_state)
            .context("restoring the last authenticated host input")?;
    }
    verify_missing_host_is_image_authored(command)
}

fn verify_missing_host_is_image_authored(command: &ServiceCommand) -> Result<()> {
    if command.host_nix.is_file() || !Path::new(SYSTEM_STATE).is_file() {
        return Ok(());
    }
    let state: crate::types::ConfigGenerationState = serde_json::from_slice(
        &fs::read(SYSTEM_STATE).with_context(|| format!("reading {SYSTEM_STATE}"))?,
    )
    .with_context(|| format!("parsing {SYSTEM_STATE}"))?;
    if state.current == 0 && state.generations.is_empty() {
        return Ok(());
    }

    let manifest_path = Path::new(SYSTEM_PROFILE)
        .join(format!("gen-{}", state.current))
        .join("manifest.json");
    let manifest: ConfigManifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parsing {}", manifest_path.display()))?;
    manifest.validate()?;
    if matches!(
        manifest.inputs.host_nix.trust_mode.as_str(),
        "image" | "image-default"
    ) {
        Ok(())
    } else {
        bail!(
            "operator-backed host input is unavailable for configuration generation {}",
            state.current
        )
    }
}

fn cache_accepted_input(command: &ServiceCommand, result: Result<()>) -> Result<()> {
    result?;
    if command.out.is_file() && command.host_nix.is_file() {
        crate::metadata::state::cache_runtime_input(
            Path::new(crate::metadata::stash::DEFAULT_STASH_DIR),
            &command.provisioning_state,
        )
        .context("caching the accepted host input")?;
    }
    Ok(())
}

fn remove_stale_output(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn create_runtime_directories(command: &ServiceCommand) -> Result<()> {
    fs::create_dir_all(&command.eval_root)
        .with_context(|| format!("creating {}", command.eval_root.display()))?;
    if let Some(parent) = command.out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}

fn retained_reevaluation_is_required() -> bool {
    if !Path::new(IMAGE_REEVALUATION_MARKER).is_file() {
        return false;
    }

    let Ok(bytes) = fs::read(SYSTEM_STATE) else {
        return false;
    };
    let Ok(state) = serde_json::from_slice::<crate::types::ConfigGenerationState>(&bytes) else {
        return false;
    };

    state.current > 0
        && state
            .generations
            .iter()
            .any(|generation| generation.number == state.current)
}

fn stage_host_module(command: &ServiceCommand) -> Result<(PathBuf, bool)> {
    let staged = command.eval_root.join("host.nix");
    if command.host_nix.is_file() {
        crate::metadata::verify_binding_main(Path::new(crate::metadata::stash::DEFAULT_STASH_DIR))?;
        fs::copy(&command.host_nix, &staged).with_context(|| {
            format!(
                "copying authenticated host module {} to {}",
                command.host_nix.display(),
                staged.display()
            )
        })?;
        return Ok((staged, false));
    }

    fs::write(&staged, b"{}\n")
        .with_context(|| format!("writing image-default host module {}", staged.display()))?;
    Ok((staged, true))
}

fn running_module_abi(path: &Path) -> Result<Option<u32>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix("AOS_MODULE_ABI="))
        .map(|value| value.trim_matches('"'))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        bail!(
            "{} contains multiple AOS_MODULE_ABI assignments",
            path.display()
        );
    }
    let value = values[0]
        .parse::<u32>()
        .with_context(|| format!("parsing AOS_MODULE_ABI in {}", path.display()))?;
    Ok(Some(value))
}

fn active_runtime_modules(
    manifest_path: &Path,
    state_path: &Path,
) -> Result<(Vec<PathBuf>, Option<PathBuf>, Option<u32>)> {
    let bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), None, None));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", manifest_path.display()));
        }
    };
    let manifest = match serde_json::from_slice::<ConfigManifest>(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return Ok((Vec::new(), None, None)),
    };
    let Some(runtime) = manifest.inputs.runtime_modules else {
        return Ok((Vec::new(), None, None));
    };
    runtime.validate()?;

    let root = PathBuf::from(&runtime.store_path);
    let modules = runtime
        .entrypoints
        .iter()
        .map(|entry| root.join(entry))
        .collect();
    let generation = current_config_generation_number(state_path)?;

    Ok((modules, Some(root), Some(generation)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_module_abi_requires_one_unsigned_integer() {
        let root =
            std::env::temp_dir().join(format!("aos-config-eval-service-{}", std::process::id()));
        fs::create_dir_all(&root).expect("create temporary directory");
        let release = root.join("os-release");

        fs::write(&release, "NAME=AOS\nAOS_MODULE_ABI=7\n").expect("write release");
        assert_eq!(running_module_abi(&release).expect("module ABI"), Some(7));

        fs::write(&release, "AOS_MODULE_ABI=7\nAOS_MODULE_ABI=8\n")
            .expect("write duplicate release");
        assert!(running_module_abi(&release).is_err());

        fs::remove_dir_all(root).expect("remove temporary directory");
    }
}
