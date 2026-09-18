//! Maps native package artifacts and selector bindings to registry entries.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_package::registry::release::RegistryReleaseEntry;
use aos_release::build::{BuildOutputEvidence, BuildSourceEvidence};
use aos_release::plan::PackagePlan;
use aos_release::platform::MatrixCell;

/// Maps a validated plan and build report to exact catalog entries.
///
/// Derivation-backed artifacts take their realized paths from build evidence.
/// Content-addressed selector inputs, such as package modules, take their paths
/// from the frozen plan and must also appear in retained source evidence.
///
/// # Errors
///
/// Returns an error when build evidence omits a planned artifact, a selector
/// names an unpublished package, or a content-addressed selector was not
/// retained by the build report.
pub(super) fn from_build(
    packages: &[PackagePlan],
    outputs: &[BuildOutputEvidence],
    sources: &[BuildSourceEvidence],
) -> Result<Vec<RegistryReleaseEntry>> {
    let built = outputs
        .iter()
        .map(|output| (output.id.as_str(), output))
        .collect::<BTreeMap<_, _>>();
    let retained_sources = sources
        .iter()
        .map(|source| source.store_path.as_str())
        .collect::<BTreeSet<_>>();
    let package_index = packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();

    let mut entries = BTreeMap::new();
    for package in packages {
        let Some(publication) = package.publication.as_ref() else {
            continue;
        };
        for cell in &package.platforms {
            let MatrixCell::Artifact { artifact: set } = &cell.decision else {
                continue;
            };
            for artifact in &set.artifacts {
                let output = built.get(artifact.id.as_str()).with_context(|| {
                    format!("build report lacks planned artifact {}", artifact.id)
                })?;
                let logical_output = logical_output(&artifact.id)?;
                entries.insert(
                    artifact.id.clone(),
                    RegistryReleaseEntry {
                        id: artifact.id.clone(),
                        name: package.name.clone(),
                        version: publication.version.clone(),
                        platform: cell.platform.to_string(),
                        output: logical_output.to_owned(),
                        store_path: output.store_path.clone(),
                    },
                );
            }

            let Some(contract) = &set.package_contract else {
                continue;
            };
            for selector in &contract.selectors {
                let selected_name = if selector.package == "self" {
                    package.name.as_str()
                } else {
                    selector.package.as_str()
                };
                let selected_package = package_index.get(selected_name).with_context(|| {
                    format!("package contract selects unpublished package {selected_name}")
                })?;
                let selected_publication = selected_package.publication.as_ref().with_context(|| {
                    format!("package contract selects package {selected_name} without publication metadata")
                })?;
                let id = format!(
                    "package/{}/{}/{}",
                    selected_name, cell.platform, selector.output
                );
                if let Some(existing) = entries.get(&id) {
                    if existing.store_path != selector.store_path {
                        bail!("package contract selector differs from planned artifact {id}");
                    }
                    continue;
                }
                if !retained_sources.contains(selector.store_path.as_str()) {
                    bail!("content-addressed package selector {id} lacks retained source evidence");
                }
                entries.insert(
                    id.clone(),
                    RegistryReleaseEntry {
                        id,
                        name: selected_name.to_owned(),
                        version: selected_publication.version.clone(),
                        platform: cell.platform.to_string(),
                        output: selector.output.clone(),
                        store_path: selector.store_path.clone(),
                    },
                );
            }
        }
    }

    Ok(entries.into_values().collect())
}

fn logical_output(id: &str) -> Result<&str> {
    id.rsplit('/')
        .next()
        .filter(|output| !output.is_empty())
        .context("planned package artifact id has no logical output")
}
