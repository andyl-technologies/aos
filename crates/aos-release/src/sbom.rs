//! Deterministic SPDX 2.3 inventory derived from build evidence.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::build::BuildReportV1;

/// SPDX document generated for one release build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxDocument {
    /// SPDX specification version.
    pub spdx_version: String,
    /// SPDX data license.
    pub data_license: String,
    /// Document SPDX identifier.
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Human-readable document name.
    pub name: String,
    /// Globally unique immutable document namespace.
    pub document_namespace: String,
    /// Deterministic creation metadata.
    pub creation_info: SpdxCreationInfo,
    /// One package for every planned Nix output.
    pub packages: Vec<SpdxPackage>,
    /// Direct dependencies between planned outputs.
    pub relationships: Vec<SpdxRelationship>,
}

/// SPDX creation metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxCreationInfo {
    /// RFC 3339 UTC creation time.
    pub created: String,
    /// Public tool and organization identities.
    pub creators: Vec<String>,
}

/// Minimal complete SPDX package record for a Nix output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxPackage {
    /// Stable SPDX package id.
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Planned artifact id.
    pub name: String,
    /// Exact Nix store path.
    pub package_file_name: String,
    /// Public package version.
    pub version_info: String,
    /// No network location is inferred from build output.
    pub download_location: String,
    /// Package files are represented by their NAR identity, not expanded.
    pub files_analyzed: bool,
    /// License conclusion inherited from reviewed Nix distribution metadata.
    pub license_concluded: String,
    /// Declared license inherited from reviewed Nix distribution metadata.
    pub license_declared: String,
    /// Copyright evidence is not inferred.
    pub copyright_text: String,
    /// Nix-specific immutable external references.
    pub external_refs: Vec<SpdxExternalRef>,
}

/// SPDX external reference carrying a Nix NAR identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxExternalRef {
    /// SPDX reference category.
    pub reference_category: String,
    /// AOS-defined Nix reference type.
    pub reference_type: String,
    /// Exact reference locator.
    pub reference_locator: String,
}

/// SPDX package dependency relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxRelationship {
    /// Depending package SPDX id.
    pub spdx_element_id: String,
    /// SPDX relationship kind.
    pub relationship_type: String,
    /// Referenced package SPDX id.
    pub related_spdx_element: String,
}

impl SpdxDocument {
    /// Generates a deterministic SPDX document from a validated build report.
    #[must_use]
    pub fn from_build(report: &BuildReportV1) -> Self {
        let ids: BTreeMap<_, _> = report
            .outputs
            .iter()
            .map(|output| (output.store_path.as_str(), spdx_id(&output.id)))
            .collect();
        let source_ids: BTreeMap<_, _> = report
            .sources
            .iter()
            .map(|source| {
                (
                    source.store_path.as_str(),
                    spdx_id(&format!("source/{}", source.store_path)),
                )
            })
            .collect();
        let mut packages = report
            .outputs
            .iter()
            .map(|output| SpdxPackage {
                spdx_id: spdx_id(&output.id),
                name: output.package.clone(),
                package_file_name: output.store_path.clone(),
                version_info: output.version.clone(),
                download_location: "NOASSERTION".to_string(),
                files_analyzed: false,
                license_concluded: output.license_expression.clone(),
                license_declared: output.license_expression.clone(),
                copyright_text: "NOASSERTION".to_string(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "OTHER".to_string(),
                    reference_type: "aos-nix-nar-hash".to_string(),
                    reference_locator: output.nar_hash.clone(),
                }],
            })
            .collect::<Vec<_>>();
        packages.extend(report.sources.iter().map(|source| {
            SpdxPackage {
                spdx_id: source_ids[&source.store_path.as_str()].clone(),
                name: source
                    .store_path
                    .rsplit_once('-')
                    .map_or_else(|| source.store_path.clone(), |(_, name)| name.to_owned()),
                package_file_name: source.store_path.clone(),
                version_info: "source".to_owned(),
                download_location: "NOASSERTION".to_owned(),
                files_analyzed: false,
                license_concluded: "NOASSERTION".to_owned(),
                license_declared: "NOASSERTION".to_owned(),
                copyright_text: "NOASSERTION".to_owned(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "OTHER".to_owned(),
                    reference_type: "aos-nix-nar-hash".to_owned(),
                    reference_locator: source.nar_hash.clone(),
                }],
            }
        }));
        let mut relationships = report
            .outputs
            .iter()
            .flat_map(|output| {
                let source = spdx_id(&output.id);
                let ids = &ids;
                let dependency_source = source.clone();
                let dependencies = output.references.iter().filter_map(move |reference| {
                    ids.get(reference.as_str()).map(|target| SpdxRelationship {
                        spdx_element_id: dependency_source.clone(),
                        relationship_type: "DEPENDS_ON".to_string(),
                        related_spdx_element: target.clone(),
                    })
                });
                let generated_from = output.source_store_paths.iter().filter_map({
                    let source = source.clone();
                    let source_ids = &source_ids;
                    move |source_path| {
                        source_ids
                            .get(source_path.as_str())
                            .map(|target| SpdxRelationship {
                                spdx_element_id: source.clone(),
                                relationship_type: "GENERATED_FROM".to_owned(),
                                related_spdx_element: target.clone(),
                            })
                    }
                });
                dependencies.chain(generated_from)
            })
            .collect::<Vec<_>>();
        relationships.sort_by(|left, right| {
            left.spdx_element_id
                .cmp(&right.spdx_element_id)
                .then_with(|| left.related_spdx_element.cmp(&right.related_spdx_element))
        });

        Self {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: format!("AOS release {}", report.plan_digest.hex()),
            document_namespace: format!(
                "https://aos.andyl.org/spdx/releases/{}",
                report.plan_digest.hex()
            ),
            creation_info: SpdxCreationInfo {
                created: report.completed_at.clone(),
                creators: vec![
                    "Organization: Andyl, Inc.".to_string(),
                    "Tool: aos".to_string(),
                ],
            },
            packages,
            relationships,
        }
    }

    /// Validates structural SPDX invariants needed by the release gate.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong SPDX constants, empty creation data,
    /// duplicate package ids, or dangling dependency relationships.
    pub fn validate(&self) -> Result<()> {
        if self.spdx_version != "SPDX-2.3"
            || self.data_license != "CC0-1.0"
            || self.spdx_id != "SPDXRef-DOCUMENT"
            || self.creation_info.created.is_empty()
            || self.creation_info.creators.is_empty()
        {
            bail!("invalid SPDX document identity");
        }
        let ids = self
            .packages
            .iter()
            .map(|package| package.spdx_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if ids.len() != self.packages.len()
            || self.relationships.iter().any(|relationship| {
                !ids.contains(relationship.spdx_element_id.as_str())
                    || !ids.contains(relationship.related_spdx_element.as_str())
            })
        {
            bail!("SPDX document contains duplicate or dangling package identities");
        }
        Ok(())
    }
}

fn spdx_id(id: &str) -> String {
    let digest = crate::digest::Sha256Digest::of_bytes(id);
    format!("SPDXRef-AOS-{}", &digest.hex()[..24])
}

#[cfg(test)]
mod tests {
    use crate::build::{
        BUILD_REPORT_V1, BuildOutputEvidence, BuildSourceEvidence, ReproducibilityResult,
    };
    use crate::digest::Sha256Digest;
    use crate::platform::Platform;

    use super::*;

    #[test]
    fn sbom_is_deterministic_and_links_planned_dependencies() {
        let dependency = "/nix/store/00000000000000000000000000000000-dependency";
        let source = "/nix/store/33333333333333333333333333333333-example-source";
        let report = BuildReportV1 {
            schema_version: BUILD_REPORT_V1.to_string(),
            plan_digest: Sha256Digest::of_bytes("plan"),
            source_commit: "0".repeat(40),
            outputs: vec![
                output("package/dependency/x86_64-linux/out", dependency, vec![]),
                {
                    let mut output = output(
                        "package/example/x86_64-linux/out",
                        "/nix/store/11111111111111111111111111111111-example",
                        vec![dependency.to_string()],
                    );
                    output.source_store_paths = vec![source.to_owned()];
                    output
                },
            ],
            sources: vec![BuildSourceEvidence {
                store_path: source.to_owned(),
                nar_hash: format!("sha256:{}", "b".repeat(64)),
                nar_size: 1,
            }],
            completed_at: "2026-09-03T00:00:00Z".to_string(),
        };

        let first = SpdxDocument::from_build(&report);
        let second = SpdxDocument::from_build(&report);
        assert_eq!(first, second);
        assert_eq!(first.relationships.len(), 2);
        assert!(first.validate().is_ok());
    }

    fn output(id: &str, store_path: &str, references: Vec<String>) -> BuildOutputEvidence {
        BuildOutputEvidence {
            id: id.to_string(),
            package: "example".to_owned(),
            version: "1.0.0".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            source_store_paths: vec![],
            platform: Platform::X86_64Linux,
            derivation: "/nix/store/22222222222222222222222222222222-example.drv".to_string(),
            output: "out".to_string(),
            store_path: store_path.to_string(),
            nar_hash: format!("sha256:{}", "a".repeat(64)),
            nar_size: 1,
            closure_size: 1,
            references,
            reproducibility: ReproducibilityResult::Reproduced,
        }
    }
}
