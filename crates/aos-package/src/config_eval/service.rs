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
    /// Selected immutable view of the running image's package store.
    pub store_view: super::store_view::StoreViewLocator,
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
    crate::sysroot::reconcile_image_boot_for_config_evaluation(
        Path::new(IMAGE_PROFILE),
        Path::new(SYSTEM_PROFILE),
        Path::new(IMAGE_REEVALUATION_MARKER),
    )?;

    if retained_reevaluation_is_required() {
        let result = crate::sysroot::reeval_active_config_for_boot_in_store_view(
            Path::new(SYSTEM_PROFILE),
            &command.store_view,
            command.eval_root.clone(),
            command.out.clone(),
            command.verbose,
        );
        result?;
        return Ok(());
    }

    let (host_nix, image_default_host, facts_json, retained_host_inputs) =
        retained_configuration_inputs(command, Path::new(ACTIVE_MANIFEST))?;
    let module_abi =
        running_module_abi(Path::new(RUNNING_OS_RELEASE))?.unwrap_or(command.module_abi);
    let (runtime_modules, runtime_module_root, expected_current_generation) =
        active_runtime_modules(
            Path::new(ACTIVE_MANIFEST),
            Path::new(SYSTEM_STATE),
            &command.store_view,
        )?;
    let desired = command.desired.is_file().then(|| command.desired.clone());

    let result = run_eval_command(&EvalCommand {
        store_view: command.store_view.clone(),
        host_nix,
        runtime_modules,
        runtime_module_root,
        expected_current_generation,
        base_lib: command.base_lib.clone(),
        facts_json,
        desired,
        module_abi,
        out: command.out.clone(),
        eval_root: command.eval_root.clone(),
        verbose: command.verbose,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs,
        require_signed_host_nix: false,
        image_default_host,
        registry_snapshot: None,
    });
    result
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

fn retained_configuration_inputs(
    command: &ServiceCommand,
    active_manifest: &Path,
) -> Result<(
    PathBuf,
    bool,
    Option<PathBuf>,
    Option<super::RetainedHostInputs>,
)> {
    let staged = command.eval_root.join("host.nix");
    if active_manifest.is_file() {
        let manifest: ConfigManifest = serde_json::from_slice(
            &fs::read(active_manifest)
                .with_context(|| format!("reading {}", active_manifest.display()))?,
        )
        .with_context(|| format!("parsing {}", active_manifest.display()))?;
        manifest.validate()?;

        let host_nix = command
            .store_view
            .read_path(Path::new(&manifest.inputs.host_nix.store_path))?;
        if !host_nix.is_file() {
            bail!("retained host input is unavailable: {}", host_nix.display());
        }
        let facts_json = command
            .store_view
            .read_path(Path::new(&manifest.inputs.instance_facts.store_path))?;
        if !facts_json.is_file() {
            bail!(
                "retained instance facts are unavailable: {}",
                facts_json.display()
            );
        }
        let image_default = matches!(
            manifest.inputs.host_nix.trust_mode.as_str(),
            "image" | "image-default"
        );
        let retained = super::RetainedHostInputs {
            host_nix: manifest.inputs.host_nix,
            instance_facts: manifest.inputs.instance_facts,
        };
        return Ok((host_nix, image_default, Some(facts_json), Some(retained)));
    }

    fs::write(&staged, b"{}\n")
        .with_context(|| format!("writing image-default host module {}", staged.display()))?;
    Ok((staged, true, None, None))
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
    store_view: &super::store_view::StoreViewLocator,
) -> Result<(Vec<super::EvaluatorInput>, Option<PathBuf>, Option<u32>)> {
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

    let identity_root = PathBuf::from(&runtime.store_path);
    let read_root = store_view.read_path(&identity_root)?;
    let modules = runtime
        .entrypoints
        .iter()
        .map(|entry| {
            let read_path = read_root.join(entry);
            anyhow::ensure!(
                read_path.is_file(),
                "retained runtime module entrypoint is unavailable: {}",
                read_path.display()
            );
            Ok(super::EvaluatorInput {
                identity: identity_root.join(entry),
                read_path,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let generation = current_config_generation_number(state_path)?;

    Ok((modules, Some(identity_root), Some(generation)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_command(
        store_view: super::super::store_view::StoreViewLocator,
        eval_root: PathBuf,
    ) -> ServiceCommand {
        ServiceCommand {
            store_view,
            base_lib: "/nix/store/base-lib".into(),
            module_abi: 1,
            desired: eval_root.join("desired.toml"),
            out: eval_root.join("manifest-out.json"),
            eval_root,
            verbose: 0,
        }
    }

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

    #[test]
    fn retained_inputs_use_selected_store_read_view() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let read_root = temporary.path().join("read-store");
        let canonical_host = PathBuf::from("/nix/store/gggggggggggggggggggggggggggggggg-host.nix");
        let canonical_facts =
            PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-facts.json");
        let readable_host = read_root.join(canonical_host.file_name().expect("host object name"));
        let readable_facts =
            read_root.join(canonical_facts.file_name().expect("facts object name"));
        fs::create_dir_all(&read_root).expect("create selected read view");
        fs::write(&readable_host, "{}\n").expect("write readable host input");
        fs::write(&readable_facts, "{}\n").expect("write readable facts input");

        let store_view = super::super::store_view::StoreViewLocator::new(
            "/nix/store".into(),
            read_root,
            "/nix/store/static-contract/contract.json".into(),
        )
        .expect("selected store view");
        let mut manifest: ConfigManifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/config_manifest/manifest.json"
        ))
        .expect("fixture manifest");
        manifest.inputs.store_view = store_view.clone();
        manifest.inputs.host_nix.store_path = canonical_host.to_string_lossy().into_owned();
        manifest.inputs.instance_facts.store_path = canonical_facts.to_string_lossy().into_owned();
        let manifest_path = temporary.path().join("active-manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialize manifest"),
        )
        .expect("write active manifest");

        let command = service_command(store_view, temporary.path().join("eval"));
        let (host, image_default, facts, retained) =
            retained_configuration_inputs(&command, &manifest_path).expect("retained inputs");

        assert_eq!(host, readable_host);
        assert_eq!(facts.as_deref(), Some(readable_facts.as_path()));
        assert!(!image_default);
        let retained = retained.expect("retained identities");
        assert_eq!(
            retained.host_nix.store_path,
            canonical_host.to_string_lossy()
        );
        assert_eq!(
            retained.instance_facts.store_path,
            canonical_facts.to_string_lossy()
        );
    }
}
