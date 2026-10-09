//! Prepares scoped interface upgrades from original admitted profile envelopes.
//!
//! Payload selection stays fixed; only explicitly eligible module dependency
//! choices are rediscovered. Semantically identical choices publish no generation.

use std::collections::{BTreeSet, HashSet};

use anyhow::{Context, Result, ensure};

use super::{Prepared, discover_modules, packaged_path, prepare};
use aos_registry_client::config::ApmConfig;
use aos_deployment_format::input::EvaluationInput;
use crate::profile::Profile;
use aos_registry_client::registry::RegistrySet;
use aos_deployment_format::inventory::{InstalledPackageRecord};
use crate::types::{PackageMeta};

/// Discovers trusted release alternatives for selected retained interface owners.
///
/// # Errors
/// Returns an error for invalid original admission or companion identity,
/// untrusted or malformed release metadata, failed transport, or cancellation.
pub(crate) async fn realize_module_upgrades(
    config: &ApmConfig,
    profile: &Profile,
    registries: &RegistrySet,
    installed: &[InstalledPackageRecord],
    refresh_names: &BTreeSet<String>,
    printer: &aos_cli_ui::output::Printer,
    download_only: bool,
    temporary_roots: &mut Option<aos_deployment::store::temp_roots::TemporaryRoots>,
) -> Result<Vec<(String, PackageMeta)>> {
    if refresh_names.is_empty() {
        return Ok(Vec::new());
    }
    let retained = super::discovery::RetainedDiscovery::read(profile)?
        .context("module upgrade requires a committed native profile")?;
    if !has_refreshable_ranges(retained.descriptor.resolution_lock.as_ref(), refresh_names) {
        return Ok(Vec::new());
    }
    let super::discovery::RetainedContext {
        mut originals,
        artifacts: retained_artifacts,
    } = retained.authenticate(registries, installed)?;
    let mut eligible = refresh_names.clone();
    loop {
        let previous = eligible.len();
        for envelope in &originals {
            if eligible.contains(&envelope.package.name) {
                eligible.extend(
                    envelope
                        .module_dependencies
                        .iter()
                        .map(|dependency| dependency.seed().name.clone()),
                );
            }
        }
        if eligible.len() == previous {
            break;
        }
    }
    originals.retain(|envelope| eligible.contains(&envelope.package.name));
    discover_modules(
        config,
        registries,
        &[],
        &originals,
        &retained_artifacts,
        printer,
        download_only,
        temporary_roots,
    )
    .await
}

/// Prepares an interface-only upgrade while preserving every selected payload.
///
/// Preparation may import authenticated companion sources and evaluate desired
/// state, but it dispatches no effects and publishes no profile generation.
///
/// # Errors
/// Returns an error for invalid retained authority, incompatible dependency
/// requirements, failed evaluation, or an attempt to select another payload.
pub(crate) async fn prepare_module_upgrade(
    config: &ApmConfig,
    profile: &Profile,
    registries: &RegistrySet,
    installed: &[InstalledPackageRecord],
    refresh_names: &BTreeSet<String>,
    printer: &aos_cli_ui::output::Printer,
) -> Result<Option<Prepared>> {
    if refresh_names.is_empty() {
        return Ok(None);
    }
    let executable = packaged_path("AOS_NIX_STORE")?;
    let generation = profile
        .current_generation()?
        .context("module upgrade requires a committed profile")?;
    let previous =
        crate::profile::deployment::committed_generation(&profile.path, generation.number)?;
    let (_, descriptor) = crate::native_deployment::read_retained_evaluation_in(
        &generation.path.join("evaluation.json"),
        &previous.deployment,
        &executable,
        &Default::default(),
    )?;
    if !has_refreshable_ranges(descriptor.resolution_lock.as_ref(), refresh_names) {
        return Ok(None);
    }
    let mut temporary_roots = None;
    let candidates = realize_module_upgrades(
        config,
        profile,
        registries,
        installed,
        refresh_names,
        printer,
        false,
        &mut temporary_roots,
    )
    .await?;
    let prepared = prepare(
        config,
        profile,
        registries,
        installed,
        &[],
        &candidates,
        &HashSet::new(),
        Some(refresh_names),
    )?;
    let next = aos_deployment::input::read_evaluation_input_in(
        &prepared.evaluation_input,
        &prepared.executable,
        &Default::default(),
    )?;
    if !module_selection_changed(
        &descriptor.packages,
        &descriptor.resolution_lock,
        &next.packages,
        &next.resolution_lock,
    )? {
        return Ok(None);
    }
    ensure!(
        prepared.additional.is_empty(),
        "interface-only upgrade attempted to install an extra payload"
    );
    Ok(Some(prepared))
}

pub(super) fn has_refreshable_ranges(
    lock: Option<&aos_deployment_format::resolution_lock::ResolutionLock>,
    refresh_names: &BTreeSet<String>,
) -> bool {
    let Some(lock) = lock else {
        return false;
    };
    let mut reachable = refresh_names.clone();
    loop {
        let previous = reachable.len();
        for edge in &lock.edges {
            if reachable.contains(&edge.requester.name) {
                reachable.insert(edge.selected.name.clone());
            }
        }
        if previous == reachable.len() {
            break;
        }
    }
    lock.edges
        .iter()
        .any(|edge| reachable.contains(&edge.requester.name) && edge.requirement.is_ranged())
}

pub(super) fn module_selection_changed(
    previous: &aos_deployment_format::model::ResolvedPackages,
    previous_lock: &Option<aos_deployment_format::resolution_lock::ResolutionLock>,
    next: &aos_deployment_format::model::ResolvedPackages,
    next_lock: &Option<aos_deployment_format::resolution_lock::ResolutionLock>,
) -> Result<bool> {
    Ok(previous != next || !same_lock(previous_lock, next_lock)?)
}

fn same_lock(
    previous: &Option<aos_deployment_format::resolution_lock::ResolutionLock>,
    next: &Option<aos_deployment_format::resolution_lock::ResolutionLock>,
) -> Result<bool> {
    fn canonical(lock: &Option<aos_deployment_format::resolution_lock::ResolutionLock>) -> Result<Vec<u8>> {
        let mut lock = lock.clone();
        if let Some(lock) = &mut lock {
            let mut edges = lock
                .edges
                .iter()
                .map(|edge| Ok((serde_json::to_vec(edge)?, edge.clone())))
                .collect::<Result<Vec<_>>>()?;
            edges.sort_by(|left, right| left.0.cmp(&right.0));
            lock.edges = edges.into_iter().map(|(_, edge)| edge).collect();
        }
        Ok(serde_json::to_vec(&lock)?)
    }
    Ok(canonical(previous)? == canonical(next)?)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::has_refreshable_ranges;
    use aos_deployment_format::model::{Artifact, ModuleDependency, ModuleSource};
    use aos_deployment_format::resolution_lock::LockedEdge;
use aos_deployment_format::resolution_lock::ResolutionLock;

    #[test]
    fn exact_only_or_unreachable_ranges_skip_upgrade_evaluation() {
        let requested = BTreeSet::from(["application".to_owned()]);
        assert!(!has_refreshable_ranges(None, &requested));
        let source = ModuleSource {
            name: "interface".into(),
            version: "1.0.0".into(),
            source: format!("/nix/store/{}-interface-source", "b".repeat(32)),
            entrypoint: "module.nix".into(),
        };
        let path = format!("/nix/store/{}-other", "a".repeat(32));
        let mut lock = ResolutionLock {
            schema: "aos.package.resolution-lock".into(),
            requesters: BTreeMap::new(),
            edges: vec![LockedEdge {
                requester: Artifact {
                    name: "other".into(),
                    version: "1".into(),
                    path: path.clone(),
                    outputs: BTreeMap::from([("out".into(), path)]),
                    main_program: None,
                },
                requirement: ModuleDependency::Ranged {
                    package: source.clone(),
                    package_version: "^1".into(),
                },
                selected: source.clone(),
            }],
        };
        assert!(!has_refreshable_ranges(Some(&lock), &requested));
        lock.edges[0].requester.name = "application".into();
        assert!(has_refreshable_ranges(Some(&lock), &requested));
        lock.edges[0].requirement = ModuleDependency::Exact(source);
        assert!(!has_refreshable_ranges(Some(&lock), &requested));
    }
}
