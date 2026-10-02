//! Pure native source replay for the public ability CLI.
//!
//! The shared evaluator checks immutable input integrity and retains its store
//! roots during replay. Authentication of the descriptor and its proofs remains
//! the caller's responsibility. This command never activates the returned graph.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aos_package::AbilityCancellationGuard;

use crate::cli::AbilityEvaluateArgs;

/// Replays immutable native sources and writes canonical transaction JSON.
///
/// # Errors
/// Returns an error if the store executable is unconfigured, immutable inputs
/// fail integrity validation, evaluation times out or is cancelled, staging
/// cannot be created, the canonical transaction is not valid UTF-8, or stdout
/// cannot be written.
pub(super) fn run(arguments: &AbilityEvaluateArgs) -> Result<()> {
    let nix_store = arguments
        .nix_store
        .clone()
        .or_else(|| std::env::var_os("AOS_NIX_STORE").map(PathBuf::from))
        .context("native source replay requires --nix-store or AOS_NIX_STORE")?;
    let cancellation = AbilityCancellationGuard::install()?;
    let staging = tempfile::Builder::new()
        .prefix("aos-native-evaluate-")
        .tempdir()
        .context("creating private native evaluation staging")?;

    let deployment = aos_package::native_deployment::evaluate_input(
        &arguments.input,
        staging.path(),
        &nix_store,
        arguments.timeout_ms,
        cancellation.token(),
    )?;
    let bytes = deployment.canonical_bytes()?;
    let document = std::str::from_utf8(&bytes).context("encoding canonical native transaction")?;
    io::stdout()
        .lock()
        .write_all(document.as_bytes())
        .context("writing canonical native transaction")?;
    Ok(())
}
