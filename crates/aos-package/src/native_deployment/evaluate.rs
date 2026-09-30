//! Effect-free replay of an immutable native source descriptor.
//!
//! Replay preserves explicit source roles and roots while the evaluator runs.
//! Integrity checks do not grant publication, image, or operator authority;
//! callers authenticate those inputs before using the returned desired state.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;

use super::EvaluationInput;
use crate::deployment::evaluation::Evaluation;
use crate::deployment::model::Deployment;
use crate::deployment::nix::store_root_and_suffix;
use crate::store::temp_roots::TemporaryRoots;
use crate::store::verification::dump_store_path_identity_in;

/// Replays one immutable source descriptor without building or applying effects.
///
/// The descriptor and its sources remain temporarily rooted during evaluation.
/// The library's actual NAR must match its declared identity. Other source NARs
/// are locked by the restricted evaluator. The caller remains responsible for
/// authenticating the descriptor, package catalog, and source authority.
///
/// The result is desired state only: no generation, effect journal, persistent
/// deployment root, or profile publication is created. The temporary roots end
/// when this call returns; execution callers must retain their own inputs.
///
/// # Errors
/// Returns an error for invalid immutable paths or descriptors, unavailable
/// artifacts, a changed library NAR, failed temporary retention, cancellation,
/// or an invalid graph or evaluation exceeding `timeout_ms`.
pub fn evaluate_input(
    input: &Path,
    staging: &Path,
    nix_store: &Path,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> Result<Deployment> {
    ensure!(timeout_ms > 0, "evaluation timeout must be positive");
    let descriptor_root = root_string(input)?;
    let mut retained = TemporaryRoots::open(nix_store, cancellation)?;
    retained.retain([descriptor_root], cancellation)?;

    let descriptor = EvaluationInput::read_in(input, nix_store, cancellation)?;
    retained.retain(source_roots(&descriptor)?, cancellation)?;
    let library_root = root_string(&descriptor.library)?;
    let (actual, _) = dump_store_path_identity_in(&library_root, Some(nix_store))?;
    ensure!(
        actual == descriptor.library_nar_hash,
        "evaluation library differs from its descriptor NAR identity"
    );

    let configuration = descriptor
        .configuration
        .into_iter()
        .chain(descriptor.runtime_configuration)
        .collect();
    let evaluation = Evaluation {
        library: descriptor.library,
        scope: descriptor.scope,
        packages: descriptor.packages,
        configuration,
        retained_inputs: descriptor.supplemental_inputs,
        evaluation_input: Some(input.to_path_buf()),
    };
    evaluation.evaluate(staging, timeout_ms, cancellation)
}

fn root_string(path: &Path) -> Result<String> {
    let (root, _) = store_root_and_suffix(path)?;
    Ok(root
        .to_str()
        .context("source root is not UTF-8")?
        .to_owned())
}

fn source_roots(descriptor: &EvaluationInput) -> Result<BTreeSet<String>> {
    let source_paths = std::iter::once(descriptor.library.clone())
        .chain(descriptor.configuration.iter().cloned())
        .chain(descriptor.runtime_configuration.iter().cloned())
        .chain(descriptor.supplemental_inputs.iter().cloned())
        .chain(
            descriptor
                .packages
                .modules
                .iter()
                .map(|module| PathBuf::from(&module.config_root)),
        )
        .chain(
            descriptor
                .packages
                .artifacts
                .iter()
                .map(|artifact| PathBuf::from(&artifact.path)),
        );
    source_paths.map(|path| root_string(&path)).collect()
}
