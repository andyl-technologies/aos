//! Imports bounded authorized policy and observational facts as immutable sources.
//!
//! Host policy keeps the recursive `source/host.nix` layout used by restricted
//! native module evaluation. Facts are imported as a fixed flat source file.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_ability_runtime::adapter::{CancellationToken, RuntimeControl};
use aos_contract::Sha256Digest;

use crate::store::temp_roots::{TemporaryRoots, fixed_path};

struct ImportControl<'a> {
    cancellation: &'a CancellationToken,
    timeout_ms: u64,
}

impl RuntimeControl for ImportControl<'_> {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.timeout_ms
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.timeout_ms
    }
}

/// Imports a regular bounded source file using the retained store executable.
///
/// # Errors
/// Returns an error for invalid input files, an unpinned executable, cancellation,
/// exhausted time/output budgets, failed store import, or a malformed result.
pub(crate) fn add_fixed_input_to_store(
    path: &Path,
    timeout_ms: u64,
    cancellation: &CancellationToken,
    temporary_roots: &mut TemporaryRoots,
) -> Result<PathBuf> {
    validate_source(path)?;
    import(path, false, timeout_ms, cancellation, temporary_roots)
}

/// Imports authorized policy beneath an immutable recursive source root.
///
/// # Errors
/// Returns an error for invalid or oversized source bytes, scratch I/O failure,
/// cancellation, store import failure, or an invalid returned store root.
pub(super) fn add_fixed_eval_host_source(
    path: &Path,
    eval_root: &Path,
    timeout_ms: u64,
    cancellation: &CancellationToken,
    temporary_roots: &mut TemporaryRoots,
) -> Result<PathBuf> {
    validate_source(path)?;
    let source = eval_root.join("host-input/source");
    fs::create_dir_all(&source).context("creating authorized host source directory")?;
    let payload = fs::read_to_string(path).context("reading authorized host policy")?;
    materialize_authorized_host_source(&payload, &source)?;
    Ok(import(&source, true, timeout_ms, cancellation, temporary_roots)?.join("host.nix"))
}

/// Materializes exact authorized operator bytes beneath a fresh source root.
///
/// Configuration bundles retain their original document and every validated
/// source file beside the generated entrypoint wrapper. Literal Nix inputs
/// remain a single entrypoint file.
///
/// # Errors
/// Returns an error for an invalid bundle, a preexisting source tree, or I/O.
pub(crate) fn materialize_authorized_host_source(payload: &str, root: &Path) -> Result<()> {
    if let Some(bundle) = aos_metadata::bundle::parse(payload.as_bytes())? {
        bundle.materialize(&root.join(aos_metadata::bundle::SOURCE_DIR))?;
        bundle.verify_tree(&root.join(aos_metadata::bundle::SOURCE_DIR))?;
        fs::write(root.join(aos_metadata::bundle::BUNDLE_FILE), payload)?;
        fs::write(
            root.join("host.nix"),
            bundle.host_module(payload.as_bytes()),
        )?;
    } else {
        fs::write(root.join("host.nix"), payload)?;
    }
    Ok(())
}

fn validate_source(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspecting native evaluator source")?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
        "native evaluator source must be a bounded regular file"
    );
    Ok(())
}

fn import(
    path: &Path,
    recursive: bool,
    timeout_ms: u64,
    cancellation: &CancellationToken,
    temporary_roots: &mut TemporaryRoots,
) -> Result<PathBuf> {
    let executable = store_executable()?;
    let mut command = configured_store_command(&executable)?;
    let environment = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect::<Vec<_>>();
    let digest = if recursive {
        let mut command = configured_store_command(&executable)?;
        command.arg("--dump").arg(path);
        let output = crate::deployment::process::run_bounded(
            &mut command,
            None,
            usize::try_from(ABILITY_LIMITS_V1.max_document_bytes)?
                .checked_add(4096)
                .context("source NAR limit overflow")?,
            &ImportControl {
                cancellation,
                timeout_ms,
            },
            &environment,
        )?;
        ensure!(
            output.status.success(),
            "hashing authorized source NAR failed"
        );
        Sha256Digest::of_bytes(&output.stdout)
    } else {
        Sha256Digest::of_bytes(fs::read(path)?)
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("authorized source name is not UTF-8")?;
    let expected = fixed_path(&executable, digest, name, recursive, cancellation)?;
    temporary_roots.retain(
        [expected
            .to_str()
            .context("source root is not UTF-8")?
            .to_owned()],
        cancellation,
    )?;
    command.arg("--add-fixed");
    if recursive {
        command.arg("--recursive");
    }
    command.arg("sha256").arg(path);
    let output = crate::deployment::process::run_bounded(
        &mut command,
        None,
        64 * 1024,
        &ImportControl {
            cancellation,
            timeout_ms,
        },
        &environment,
    )
    .context("importing retained native evaluator source")?;
    ensure!(
        output.status.success(),
        "native evaluator source import failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let imported = PathBuf::from(std::str::from_utf8(&output.stdout)?.trim());
    ensure!(
        imported == expected,
        "native source import changed its pre-rooted identity"
    );
    let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&imported)?;
    ensure!(
        suffix.as_os_str().is_empty() && root == imported,
        "native source import returned a noncanonical root"
    );
    Ok(imported)
}

/// Selects the same pinned store executable for import and temporary root leases.
///
/// # Errors
/// Returns an error when the source-built wrapper omitted its tool identity or
/// supplied an executable outside the normalized immutable store namespace.
pub(super) fn store_executable() -> Result<PathBuf> {
    let executable = PathBuf::from(
        std::env::var_os("AOS_NIX_STORE")
            .context("native evaluator has no retained store executable")?,
    );
    ensure!(
        executable.is_absolute()
            && executable.starts_with("/nix/store")
            && !executable
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir)),
        "native evaluator store executable is not a normalized immutable path"
    );
    Ok(executable)
}

fn configured_store_command(executable: &Path) -> Result<Command> {
    let mut command = Command::new(executable);
    aos_core::nix::configure_aos_nix_store(&mut command)?;
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_literal_remains_exact() {
        let directory = tempfile::tempdir().unwrap();
        let payload = "{ aos.host.hostname = \"operator\"; }\n";

        materialize_authorized_host_source(payload, directory.path()).unwrap();

        assert_eq!(
            fs::read_to_string(directory.path().join("host.nix")).unwrap(),
            payload
        );
        assert!(
            !directory
                .path()
                .join(aos_metadata::bundle::SOURCE_DIR)
                .exists()
        );
    }

    #[test]
    fn authorized_bundle_retains_complete_source_and_exact_payload() {
        let directory = tempfile::tempdir().unwrap();
        let payload = r#"{"schema":"aos.config-bundle/v1","entrypoint":"host.nix","files":{"host.nix":"aW1wb3J0IC4vbG9jYWwubml4Cg==","local.nix":"e30K"}}"#;

        materialize_authorized_host_source(payload, directory.path()).unwrap();

        let bundle = aos_metadata::bundle::parse(payload.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::read_to_string(directory.path().join("host.nix")).unwrap(),
            bundle.host_module(payload.as_bytes())
        );
        assert_eq!(
            fs::read_to_string(directory.path().join(aos_metadata::bundle::BUNDLE_FILE)).unwrap(),
            payload
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("source/local.nix")).unwrap(),
            "{}\n"
        );
        bundle
            .verify_tree(&directory.path().join("source"))
            .unwrap();
    }

    #[test]
    fn invalid_bundle_never_materializes_a_host_wrapper() {
        let directory = tempfile::tempdir().unwrap();
        let payload = r#"{"schema":"aos.config-bundle/v1","entrypoint":"host.nix","files":{"../host.nix":"e30K"}}"#;

        assert!(materialize_authorized_host_source(payload, directory.path()).is_err());
        assert!(!directory.path().join("host.nix").exists());
    }
}
