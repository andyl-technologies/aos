//! Checks offline replay against original retained package envelopes.
//!
//! Envelope companions retain authored dependencies and OS constraints. Their
//! selected-store bytes validate exact choices without registry discovery. Authenticating the descriptor and those roots remains the caller's
//! responsibility; these checks establish consistency, not new authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;

use crate::deployment::model::Envelope;
use crate::native_deployment::{EvaluationInput, read_regular_store_document_in};
use crate::native_registry::{same_package_context, solver};

/// Validates retained declarations before importing any configuration modules.
///
/// Every selected payload retains its original envelope, including moduleless
/// packages with exact dependencies. Their OS constraints are checked against
/// the fixed host release before any configuration module is imported.
///
/// # Errors
/// Returns an error for unavailable or malformed companions, changed module or
/// requester identities, incomplete exact dependencies, incompatible lock
/// choices, conflicting package contexts, incompatible OS releases, or cancellation.
pub(super) fn validate(
    descriptor: &EvaluationInput,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<super::RetainedDeclarations> {
    validate_with(descriptor, |path| {
        read_regular_store_document_in(path, nix_store, cancellation)
    })
}

/// Checks original envelope choices against an explicitly selected target.
///
/// # Errors
/// Returns an error for unavailable or inconsistent retained envelopes,
/// incompatible target constraints, dependency mismatches, or cancellation.
pub(super) fn validate_for_release(
    descriptor: &EvaluationInput,
    release: Option<aos_doc_model::runtime::OsRelease>,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<super::RetainedDeclarations> {
    validate_with_release(descriptor, release, |path| {
        read_regular_store_document_in(path, nix_store, cancellation)
    })
}

fn validate_with_release(
    descriptor: &EvaluationInput,
    release: Option<aos_doc_model::runtime::OsRelease>,
    read: impl FnMut(&Path) -> Result<Vec<u8>>,
) -> Result<super::RetainedDeclarations> {
    let mut target = descriptor.clone();
    target.os_release = release;
    validate_with(&target, read)
}

fn validate_with(
    descriptor: &EvaluationInput,
    mut read: impl FnMut(&Path) -> Result<Vec<u8>>,
) -> Result<super::RetainedDeclarations> {
    let payloads: BTreeSet<_> = descriptor
        .packages
        .artifacts
        .iter()
        .map(|artifact| artifact.canonical_catalog().path)
        .collect();
    ensure!(
        payloads == descriptor.package_envelopes.keys().cloned().collect(),
        "replay payload catalog differs from retained envelope catalog"
    );
    let names: BTreeSet<_> = descriptor
        .packages
        .modules
        .iter()
        .map(|module| &module.name)
        .collect();
    ensure!(
        names.len() == descriptor.packages.modules.len()
            && names == descriptor.module_envelopes.keys().collect(),
        "replay module companion catalog differs from its selected modules"
    );
    if let Some(lock) = &descriptor.resolution_lock {
        lock.check()?;
    }

    let mut envelopes = BTreeMap::new();
    for module in &descriptor.packages.modules {
        let root = descriptor
            .module_envelopes
            .get(&module.name)
            .context("replay module lacks its original envelope")?;
        let envelope = Envelope::decode(&read(&root.join("deployment.json"))?)?;
        ensure!(
            envelope.system == descriptor.packages.system
                && envelope.module_record().as_ref() == Some(module),
            "replay module envelope differs from its retained module catalog"
        );
        insert(&mut envelopes, envelope)?;
    }

    for (artifact, root) in &descriptor.package_envelopes {
        let envelope = Envelope::decode(&read(&root.join("deployment.json"))?)?;
        ensure!(
            envelope.system == descriptor.packages.system
                && envelope.package.canonical_catalog().path == *artifact
                && descriptor.packages.artifacts.iter().any(|selected| {
                    selected.canonical_catalog() == envelope.package.canonical_catalog()
                }),
            "replay payload envelope differs from its selected package catalog"
        );
        insert(&mut envelopes, envelope)?;
    }
    if let Some(lock) = &descriptor.resolution_lock {
        for (artifact, root) in &lock.requesters {
            let envelope = Envelope::decode(&read(&root.join("deployment.json"))?)?;
            ensure!(
                envelope.system == descriptor.packages.system
                    && envelope.package.canonical_catalog().path == *artifact,
                "replay lock requester differs from its original package identity"
            );
            let selected = match envelope.module_record() {
                Some(module) => descriptor.packages.modules.contains(&module),
                None => descriptor.packages.artifacts.iter().any(|artifact| {
                    artifact.canonical_catalog() == envelope.package.canonical_catalog()
                }),
            };
            ensure!(
                selected,
                "replay lock requester is absent from the selected package catalog"
            );
            solver::check_os_requirement(&envelope, descriptor.os_release.as_ref())?;
            insert(&mut envelopes, envelope)?;
        }
        lock.validate(&envelopes.values().cloned().collect::<Vec<_>>())?;
    } else {
        for envelope in envelopes.values() {
            for dependency in &envelope.module_dependencies {
                ensure!(
                    !dependency.is_ranged(),
                    "replay ranged dependency has no retained resolution lock"
                );
                let selected = envelopes
                    .get(&dependency.seed().name)
                    .context("replay exact module dependency is absent")?;
                ensure!(
                    solver::matches_requirement(dependency, selected)?,
                    "replay exact module dependency differs from its retained source"
                );
            }
        }
    }
    let mut os_requirements = Vec::new();
    for envelope in envelopes.values() {
        solver::check_os_requirement(envelope, descriptor.os_release.as_ref())?;
        if envelope.module.is_none() {
            if let Some(os_version) = &envelope.os_version {
                os_requirements.push(aos_doc_model::runtime::OsRequirement {
                    owner: envelope.package.name.clone(),
                    os_version: os_version.clone(),
                });
            }
        }
    }
    let package_releases = envelopes
        .values()
        .map(|envelope| aos_doc_model::runtime::PackageIdentity {
            name: envelope.package.name.clone(),
            version: envelope.package.version.clone(),
            version_requirement: envelope.version_requirement.clone(),
        })
        .collect();
    Ok(super::RetainedDeclarations {
        os_requirements,
        package_releases,
    })
}

fn insert(envelopes: &mut BTreeMap<String, Envelope>, mut envelope: Envelope) -> Result<()> {
    envelope.package = envelope.package.canonical_catalog();
    if let Some(previous) = envelopes.get(&envelope.package.name) {
        ensure!(
            same_package_context(previous, &envelope),
            "replay retains conflicting contexts for one package"
        );
    } else {
        envelopes.insert(envelope.package.name.clone(), envelope);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
