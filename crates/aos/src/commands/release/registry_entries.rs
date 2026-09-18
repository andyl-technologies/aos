//! Maps built package outputs and configuration companions to registry entries.
//!
//! Configuration inputs remain separate Nix artifacts in the build report.
//! Registry authoring attaches their authenticated interfaces to the runtime
//! entry instead of publishing them as interchangeable package outputs.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use aos_package::registry::release::{RegistryReleaseConfiguration, RegistryReleaseEntry};
use aos_release::build::BuildOutputEvidence;
use aos_release::plan::PackagePlan;
use aos_release::platform::MatrixCell;

/// Maps a previously validated plan and build report to exact catalog entries.
///
/// # Errors
///
/// Returns an error when a runtime output or configuration companion from the
/// planned package cells is absent from the build evidence.
pub(super) fn from_build(
    packages: &[PackagePlan],
    outputs: &[BuildOutputEvidence],
) -> Result<Vec<RegistryReleaseEntry>> {
    let built = outputs
        .iter()
        .map(|output| (output.id.as_str(), output))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::new();
    for package in packages {
        for cell in &package.platforms {
            let MatrixCell::Artifact { artifact: set } = &cell.decision else {
                continue;
            };
            let configuration = set
                .configuration
                .as_ref()
                .map(|binding| {
                    let module = built
                        .get(binding.module_artifact.as_str())
                        .context("build report lacks the planned configuration module")?;
                    let base = built
                        .get(binding.evaluation_base_artifact.as_str())
                        .context("build report lacks the planned configuration evaluation base")?;
                    Ok::<_, anyhow::Error>(RegistryReleaseConfiguration {
                        module_store_path: module.store_path.clone(),
                        evaluation_base_store_path: base.store_path.clone(),
                        dependency_outputs: binding.dependency_outputs.clone(),
                    })
                })
                .transpose()?;

            for artifact in &set.artifacts {
                if set
                    .configuration
                    .as_ref()
                    .is_some_and(|binding| binding.is_companion(&artifact.id))
                {
                    continue;
                }
                let output = built
                    .get(artifact.id.as_str())
                    .context("build report lacks a planned runtime output")?;
                entries.push(RegistryReleaseEntry {
                    id: output.id.clone(),
                    name: output.package.clone(),
                    version: output.version.clone(),
                    platform: output.platform.to_string(),
                    output: output.output.clone(),
                    store_path: output.store_path.clone(),
                    configuration: (output.output == "out")
                        .then(|| configuration.clone())
                        .flatten(),
                });
            }
        }
    }
    entries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_release::build::ReproducibilityResult;
    use aos_release::inventory::PackagePublicationMetadata;
    use aos_release::plan::{
        PackageConfigurationBinding, PlannedArtifact, PlannedArtifactSet, PlatformCell,
    };
    use aos_release::platform::Platform;

    fn fixture() -> (Vec<PackagePlan>, Vec<BuildOutputEvidence>) {
        let outputs = [
            ("out", "out"),
            ("dev", "dev"),
            ("config", "config"),
            ("configuration-base", "out"),
        ]
        .into_iter()
        .map(|(logical, output)| BuildOutputEvidence {
            id: format!("package/example/x86_64-linux/{logical}"),
            package: "example".into(),
            version: "1.0.0".into(),
            license_expression: "Apache-2.0".into(),
            source_store_paths: vec!["/nix/store/11111111111111111111111111111111-source".into()],
            platform: Platform::X86_64Linux,
            derivation: format!("/nix/store/00000000000000000000000000000000-{logical}.drv"),
            output: output.into(),
            store_path: format!("/nix/store/00000000000000000000000000000000-{logical}"),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 1,
            closure_size: 1,
            references: vec![],
            reproducibility: ReproducibilityResult::Reproduced,
        })
        .collect::<Vec<_>>();
        let package = PackagePlan {
            name: "example".into(),
            publication: Some(PackagePublicationMetadata {
                version: "1.0.0".into(),
                description: "Configuration fixture".into(),
                homepage: None,
                license_expression: "Apache-2.0".into(),
                maintainers: vec!["AOS test".into()],
            }),
            platforms: vec![PlatformCell {
                platform: Platform::X86_64Linux,
                decision: MatrixCell::Artifact {
                    artifact: PlannedArtifactSet {
                        artifacts: outputs
                            .iter()
                            .map(|output| PlannedArtifact {
                                id: output.id.clone(),
                                derivation: Some(output.derivation.clone()),
                                output: Some(output.output.clone()),
                                store_path: Some(output.store_path.clone()),
                                source_store_paths: output.source_store_paths.clone(),
                            })
                            .collect(),
                        configuration: Some(PackageConfigurationBinding {
                            module_artifact: outputs[2].id.clone(),
                            evaluation_base_artifact: outputs[3].id.clone(),
                            dependency_outputs: BTreeMap::from([(
                                "dependency".into(),
                                outputs[1].store_path.clone(),
                            )]),
                        }),
                    },
                },
            }],
        };
        (vec![package], outputs)
    }

    #[test]
    fn companions_attach_to_runtime_without_becoming_named_outputs() -> Result<()> {
        let (packages, outputs) = fixture();
        let entries = from_build(&packages, &outputs)?;

        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.output.as_str())
                .collect::<Vec<_>>(),
            ["dev", "out"]
        );
        assert!(entries[0].configuration.is_none());
        let configuration = entries[1].configuration.as_ref().unwrap();
        assert_eq!(entries[1].store_path, outputs[0].store_path);
        assert_eq!(configuration.module_store_path, outputs[2].store_path);
        assert_eq!(
            configuration.evaluation_base_store_path,
            outputs[3].store_path
        );
        assert_eq!(
            configuration.dependency_outputs["dependency"],
            outputs[1].store_path
        );
        Ok(())
    }

    #[test]
    fn missing_companions_cannot_be_replaced_by_the_runtime_output() {
        let (packages, outputs) = fixture();
        for missing in [2, 3] {
            let mut changed = outputs.clone();
            changed.remove(missing);
            assert!(from_build(&packages, &changed).is_err());
        }
    }
}
