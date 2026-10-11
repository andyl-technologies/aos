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

mod validation;

/// Contains declarations derived from original retained envelopes.
pub(crate) struct RetainedDeclarations {
    /// Preserves host requirements from packages without module records.
    pub(crate) os_requirements: Vec<aos_doc_model::runtime::OsRequirement>,
    /// Preserves selected release coordinates and original recipe policy.
    pub(crate) package_releases: Vec<aos_doc_model::runtime::PackageIdentity>,
}

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
/// changed envelope declarations or locked choices, incompatible OS releases,
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
    let declarations = validation::validate(&descriptor, nix_store, cancellation)?;
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
        os_release: descriptor.os_release.clone(),
        os_requirements: declarations.os_requirements,
        package_releases: declarations.package_releases,
        module_requirements: descriptor
            .resolution_lock
            .as_ref()
            .map_or_else(Vec::new, |lock| lock.module_requirements()),
        nix_store: nix_store.to_path_buf(),
        library: descriptor.library,
        scope: descriptor.scope,
        packages: descriptor.packages,
        configuration,
        retained_inputs: descriptor
            .supplemental_inputs
            .into_iter()
            .chain(descriptor.module_envelopes.into_values())
            .chain(descriptor.package_envelopes.into_values())
            .chain(
                descriptor
                    .resolution_lock
                    .into_iter()
                    .flat_map(|lock| lock.requesters.into_values()),
            )
            .collect(),
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
        .chain(descriptor.module_envelopes.values().cloned())
        .chain(descriptor.package_envelopes.values().cloned())
        .chain(
            descriptor
                .resolution_lock
                .iter()
                .flat_map(|lock| lock.requesters.values().cloned()),
        )
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

/// Validates immutable envelope requirements before projecting configuration.
///
/// # Errors
/// Returns an error for changed retained envelopes, unsatisfied dependencies or
/// host constraints, missing sources, or cancellation.
pub(crate) fn os_requirements(
    descriptor: &EvaluationInput,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<Vec<aos_doc_model::runtime::OsRequirement>> {
    Ok(validation::validate(descriptor, nix_store, cancellation)?.os_requirements)
}

/// Validates and projects original retained package declarations.
///
/// # Errors
/// Returns an error for changed envelopes, incompatible choices or OS releases,
/// unavailable sources, or cancellation.
pub(crate) fn validated_declarations(
    descriptor: &EvaluationInput,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<RetainedDeclarations> {
    validation::validate(descriptor, nix_store, cancellation)
}

/// Projects OS constraints and selected releases from retained payload envelopes.
///
/// # Errors
/// Returns an error for inaccessible or malformed envelope companions, changed
/// payload identities, or constraints incompatible with the retained host.
pub(crate) fn retained_declarations(
    envelopes: &std::collections::BTreeMap<String, PathBuf>,
    release: Option<&aos_doc_model::runtime::OsRelease>,
    nix_store: &Path,
) -> Result<RetainedDeclarations> {
    let mut requirements = Vec::new();
    let mut package_releases = Vec::new();
    for (artifact, root) in envelopes {
        let bytes = super::read_regular_store_document_in(
            &root.join("deployment.json"),
            nix_store,
            &CancellationToken::default(),
        )?;
        let envelope = crate::deployment::model::Envelope::decode(&bytes)?;
        ensure!(
            envelope.package.canonical_catalog().path == *artifact,
            "retained declaration envelope has a changed payload identity"
        );
        crate::native_registry::solver::check_os_requirement(&envelope, release)?;
        package_releases.push(aos_doc_model::runtime::PackageIdentity {
            name: envelope.package.name.clone(),
            version: envelope.package.version.clone(),
            version_requirement: envelope.version_requirement.clone(),
        });
        if envelope.module.is_none() {
            if let Some(os_version) = envelope.os_version {
                requirements.push(aos_doc_model::runtime::OsRequirement {
                    owner: envelope.package.name,
                    os_version,
                });
            }
        }
    }
    Ok(RetainedDeclarations {
        os_requirements: requirements,
        package_releases,
    })
}

/// Checks retained package choices against a mutation's current target snapshot.
///
/// The original descriptor and its historical release remain unchanged.
///
/// # Errors
/// Returns an error for changed retained envelopes, unavailable sources,
/// dependency mismatches, incompatible current host requirements, or cancellation.
pub(crate) fn validate_target_os(
    descriptor: &EvaluationInput,
    release: Option<aos_doc_model::runtime::OsRelease>,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    validation::validate_for_release(descriptor, release, nix_store, cancellation)?;
    Ok(())
}
