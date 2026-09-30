//! Maps frozen native package artifacts and retained source roots to registry entries.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_package::registry::release::RegistryReleaseEntry;
use aos_release::build::{BuildOutputEvidence, BuildSourceEvidence};
use aos_release::plan::PackagePlan;
use aos_release::platform::MatrixCell;

/// Maps a validated plan and build report to exact catalog entries.
///
/// Every entry uses its realized build path. Native module source roots remain
/// independently retained in build evidence and referenced by deployment artifacts.
///
/// # Errors
/// Returns an error when an artifact or one of its frozen source roots is
/// absent from the exact build report.
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
                for source in &artifact.source_store_paths {
                    if !retained_sources.contains(source.as_str()) {
                        bail!(
                            "native artifact {} lacks retained source evidence {source}",
                            artifact.id
                        );
                    }
                }
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
