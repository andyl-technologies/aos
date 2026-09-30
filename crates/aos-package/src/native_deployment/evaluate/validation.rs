//! Checks offline replay against original retained package envelopes.
//!
//! Envelope companions retain authored dependencies and independently versioned
//! exports. Their selected-store bytes validate an exact lock without registry
//! discovery. Authenticating the descriptor and those roots remains the caller's
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
/// Ranged moduleless requesters are opened through the lock's exact companion
/// bindings. An exact-only descriptor needs no compatibility decision for its
/// moduleless payload roots; its retained modules still receive full dependency
/// and export checks.
///
/// # Errors
/// Returns an error for unavailable or malformed companions, changed module or
/// requester identities, incomplete exact dependencies, incompatible lock
/// choices, conflicting package contexts or exports, or cancellation.
pub(super) fn validate(
    descriptor: &EvaluationInput,
    nix_store: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    validate_with(descriptor, |path| {
        read_regular_store_document_in(path, nix_store, cancellation)
    })
}

fn validate_with(
    descriptor: &EvaluationInput,
    mut read: impl FnMut(&Path) -> Result<Vec<u8>>,
) -> Result<()> {
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
            insert(&mut envelopes, envelope)?;
        }
        lock.validate(&envelopes.into_values().collect::<Vec<_>>())?;
    } else {
        solver::check_exports(envelopes.values())?;
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
    Ok(())
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
