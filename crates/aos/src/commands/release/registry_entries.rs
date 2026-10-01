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
        let Some(_) = package.publication.as_ref() else {
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
                        version: output.version.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use aos_release::build::ReproducibilityResult;
    use aos_release::inventory::PackagePublicationMetadata;
    use aos_release::plan::{PlannedArtifact, PlannedArtifactSet, PlatformCell};
    use aos_release::platform::Platform;

    #[test]
    fn registry_entries_preserve_target_versions_and_require_retained_sources() -> Result<()> {
        let source = BuildSourceEvidence {
            store_path: "/nix/store/11111111111111111111111111111111-source".into(),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 1,
        };
        let output = BuildOutputEvidence {
            id: "package/example/x86_64-linux/out".into(),
            package: "example".into(),
            version: "2.0.0".into(),
            license_expression: "Apache-2.0".into(),
            source_store_paths: vec![source.store_path.clone()],
            platform: Platform::X86_64Linux,
            derivation: "/nix/store/00000000000000000000000000000000-example.drv".into(),
            output: "out".into(),
            store_path: "/nix/store/00000000000000000000000000000000-example".into(),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 1,
            closure_size: 1,
            references: vec![],
            reproducibility: ReproducibilityResult::Reproduced,
        };
        let package = PackagePlan {
            name: "example".into(),
            publication: Some(PackagePublicationMetadata {
                version: "1.0.0".into(),
                description: "Native package fixture".into(),
                homepage: None,
                license_expression: "Apache-2.0".into(),
                maintainers: vec!["AOS test".into()],
            }),
            platform_versions: BTreeMap::from([(Platform::X86_64Linux, "2.0.0".into())]),
            platforms: vec![PlatformCell {
                platform: Platform::X86_64Linux,
                decision: MatrixCell::Artifact {
                    artifact: PlannedArtifactSet {
                        artifacts: vec![PlannedArtifact {
                            id: output.id.clone(),
                            derivation: Some(output.derivation.clone()),
                            output: Some(output.output.clone()),
                            store_path: Some(output.store_path.clone()),
                            source_store_paths: output.source_store_paths.clone(),
                        }],
                    },
                },
            }],
        };
        let packages = [package];
        let outputs = [output];

        let entries = from_build(&packages, &outputs, &[source])?;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version, "2.0.0");
        assert_eq!(entries[0].output, "out");
        assert_eq!(entries[0].store_path, outputs[0].store_path);
        assert!(from_build(&packages, &outputs, &[]).is_err());
        Ok(())
    }
}
