//! Acquisition and retention of immutable deployment evaluation descriptors.
//!
//! Portable descriptor validation belongs to `aos-deployment-format`. This
//! module owns bounded store reads and fixed-output imports, keeping imported
//! inputs rooted until callers publish their durable generation.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_activation::adapter::CancellationToken;
use aos_core::Sha256Digest;
use aos_deployment_format::input::EvaluationInput;
use aos_module_format::graph::GRAPH_LIMITS;

use crate::document::{read_descriptor_in, read_immutable_document_in};

/// Reads one bounded native descriptor from an immutable source.
///
/// # Errors
/// Returns an error for non-store sources, malformed or oversized documents,
/// an unsupported schema, or invalid library/source locators and scope.
pub fn read_evaluation_input(path: &Path) -> Result<EvaluationInput> {
    let executable = packaged_path("AOS_NIX_STORE")?;
    read_evaluation_input_in(path, &executable, &CancellationToken::default())
}

/// Reads a native descriptor through an explicitly selected store executable.
///
/// Canonical store identities are resolved by Nix, including isolated local
/// stores. A retained profile symlink is resolved only to obtain its identity.
///
/// # Errors
/// Returns an error for invalid locators, inaccessible or oversized documents,
/// malformed descriptors, store failure, timeout, or cancellation.
pub fn read_evaluation_input_in(
    path: &Path,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<EvaluationInput> {
    let (_, bytes) = read_descriptor_in(path, nix_store, cancellation)?;
    EvaluationInput::decode(&bytes)
}

/// Imports a caller-assembled descriptor into the configured AOS store.
///
/// Callers must already authenticate the represented sources and record the
/// resulting descriptor's NAR identity before dispatching package effects.
///
/// # Errors
/// Returns an error for invalid serialization, failed store import, output
/// limits, timeout or cancellation, or changed imported document bytes.
pub fn import_evaluation_input(
    input: &EvaluationInput,
    nix_store: &Path,
    staging: &Path,
    cancellation: &CancellationToken,
) -> Result<ImportedEvaluationInput> {
    let mut temporary_roots =
        crate::store::temp_roots::TemporaryRoots::open(nix_store, cancellation)?;
    let path = import_evaluation_input_retained(
        input,
        nix_store,
        staging,
        cancellation,
        &mut temporary_roots,
    )?;
    Ok(ImportedEvaluationInput {
        path,
        _temporary_roots: temporary_roots,
    })
}

/// Imports a descriptor while adding its expected identity to caller-owned roots.
///
/// # Errors
/// Returns an error for malformed imports, changed bytes, cancellation, or store failures.
pub fn import_evaluation_input_retained(
    input: &EvaluationInput,
    nix_store: &Path,
    staging: &Path,
    cancellation: &CancellationToken,
    temporary_roots: &mut crate::store::temp_roots::TemporaryRoots,
) -> Result<PathBuf> {
    let temporary = tempfile::tempdir_in(staging)?;
    let path = temporary.path().join("evaluation-input.json");
    let bytes = serde_json::to_vec(input)?;
    ensure!(
        bytes.len() <= GRAPH_LIMITS.max_bytes,
        "evaluation input exceeds its byte bound"
    );
    fs::write(&path, &bytes)?;
    let expected = crate::store::temp_roots::fixed_path(
        nix_store,
        Sha256Digest::of_bytes(&bytes),
        "evaluation-input.json",
        false,
        cancellation,
    )?;
    temporary_roots.retain(
        [expected
            .to_str()
            .context("descriptor path is not UTF-8")?
            .to_owned()],
        cancellation,
    )?;
    let mut command = crate::store::verification::live_store_command(Some(nix_store))?;
    command.args(["--add-fixed", "sha256"]).arg(&path);
    let environment = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect::<Vec<_>>();
    let output = crate::process::run_bounded(
        &mut command,
        None,
        64 * 1024,
        &ImportControl(cancellation),
        &environment,
    )?;
    ensure!(
        output.status.success(),
        "native evaluation input import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let imported = PathBuf::from(std::str::from_utf8(&output.stdout)?.trim());
    let (root, suffix) = crate::nix::store_root_and_suffix(&imported)?;
    ensure!(
        suffix.as_os_str().is_empty() && root == imported,
        "store import returned a noncanonical descriptor root"
    );
    ensure!(
        imported == expected
            && read_immutable_document_in(&imported, nix_store, cancellation)? == bytes,
        "imported evaluation input changed"
    );
    Ok(imported)
}
/// Keeps an imported evaluation descriptor rooted until its caller publishes it.
pub struct ImportedEvaluationInput {
    /// Immutable descriptor locator in the configured store.
    pub path: PathBuf,
    _temporary_roots: crate::store::temp_roots::TemporaryRoots,
}

/// Supplies the fixed import deadline and caller cancellation to bounded subprocesses.
pub struct ImportControl<'a>(
    /// Supplies the caller's cancellation signal.
    pub &'a CancellationToken,
);

impl aos_activation::adapter::RuntimeControl for ImportControl<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
    fn elapsed_millis(&self) -> u64 {
        0
    }
    fn attempt_remaining_millis(&self) -> u64 {
        60_000
    }
    fn recovery_remaining_millis(&self) -> u64 {
        60_000
    }
}

/// Resolves one explicitly supplied immutable packaged runtime input.
///
/// # Errors
/// Returns an error when the input variable is absent or is not an absolute path.
pub fn packaged_path(variable: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(variable)
            .with_context(|| format!("packaged native runtime omitted {variable}"))?,
    );
    ensure!(
        path.is_absolute(),
        "{variable} must identify an absolute packaged input"
    );
    Ok(path)
}
