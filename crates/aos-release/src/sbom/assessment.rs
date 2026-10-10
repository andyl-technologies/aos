//! Frozen upstream component identities and declared containment in release SPDX.
//!
//! Recipe declarations preserve their exact identity and coverage basis. They
//! never imply that binary contents or transitive dependencies were analyzed.

use anyhow::{Context as _, Result, bail};
use aos_assessment::security::SecurityIdentity;

use super::{SpdxDocument, SpdxExternalRef, SpdxPackage, SpdxRelationship, spdx_id};
use crate::build::BuildReportV1;
use crate::digest::Sha256Digest;
use crate::plan::ReleasePlan;
use crate::platform::MatrixCell;

impl SpdxDocument {
    /// Enriches validated build evidence with the exact frozen package scan policy.
    ///
    /// Declared component containment remains distinct from observed binary
    /// composition. External references retain explicit security identities,
    /// raw upstream version, declaration digest and dependency coverage.
    /// Legacy plans without scan declarations produce the original document.
    ///
    /// # Errors
    /// Returns an error for invalid plan/build binding, missing primary output,
    /// malformed frozen ownership, conflicting identities or invalid SPDX.
    pub fn from_plan_and_build(plan: &ReleasePlan, report: &BuildReportV1) -> Result<Self> {
        plan.validate()?;
        let plan_digest = Sha256Digest::of_bytes(&crate::canonical::to_vec(plan)?);
        report.validate(plan, plan_digest)?;
        let mut document = Self::from_build(report);
        if plan
            .packages
            .iter()
            .all(|package| package.scan_declarations.is_empty())
        {
            return Ok(document);
        }
        for package in &plan.packages {
            for (platform, declaration) in &package.scan_declarations {
                let set = package
                    .platforms
                    .iter()
                    .find(|cell| cell.platform == *platform)
                    .context("frozen component declaration lacks its target cell")?;
                let MatrixCell::Artifact { artifact: set } = &set.decision else {
                    bail!("frozen components target a nonpublishable cell");
                };
                let primary = set
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.id.rsplit('/').next() == Some("out"))
                    .context("frozen components lack the primary artifact")?;
                let output = report
                    .outputs
                    .iter()
                    .find(|output| output.id == primary.id)
                    .context("build report lacks the frozen primary artifact")?;
                let parent_id = spdx_id(&output.id);
                let parent = document
                    .packages
                    .iter_mut()
                    .find(|record| record.spdx_id == parent_id)
                    .context("SPDX document lacks the primary artifact")?;
                parent.external_refs.push(reference(
                    "aos-scan-declaration",
                    &declaration.digest()?.to_string(),
                ));
                let owner = declaration.owner_definition()?;
                for component in &owner.components {
                    let component_id = spdx_id(&format!(
                        "assessment/{}/{}",
                        primary.id, component.component_id
                    ));
                    let mut refs = vec![
                        reference("aos-scan-definition", &owner.digest()?.to_string()),
                        reference("aos-upstream-id", &component.current.upstream_id),
                        reference(
                            "aos-dependency-coverage",
                            &String::from_utf8(aos_contract::canonical::to_vec(
                                &component.security.dependency_coverage,
                            )?)?,
                        ),
                    ];
                    for identity in &component.security.identities {
                        match identity {
                            SecurityIdentity::Purl { value } => refs.push(SpdxExternalRef {
                                reference_category: "PACKAGE-MANAGER".into(),
                                reference_type: "purl".into(),
                                reference_locator: value.clone(),
                            }),
                            _ => refs.push(reference(
                                "aos-security-identity",
                                &String::from_utf8(aos_contract::canonical::to_vec(identity)?)?,
                            )),
                        }
                    }
                    document.packages.push(SpdxPackage {
                        spdx_id: component_id.clone(),
                        name: format!("{}/{}", owner.family, component.component_id),
                        package_file_name: output.store_path.clone(),
                        version_info: component.current.comparison_version.clone(),
                        download_location: "NOASSERTION".into(),
                        files_analyzed: false,
                        license_concluded: "NOASSERTION".into(),
                        license_declared: "NOASSERTION".into(),
                        copyright_text: "NOASSERTION".into(),
                        external_refs: refs,
                    });
                    document.relationships.push(SpdxRelationship {
                        spdx_element_id: parent_id.clone(),
                        relationship_type: "CONTAINS".into(),
                        related_spdx_element: component_id,
                    });
                }
            }
        }
        document
            .packages
            .sort_by(|left, right| left.spdx_id.cmp(&right.spdx_id));
        document.relationships.sort_by(|left, right| {
            (
                &left.spdx_element_id,
                &left.relationship_type,
                &left.related_spdx_element,
            )
                .cmp(&(
                    &right.spdx_element_id,
                    &right.relationship_type,
                    &right.related_spdx_element,
                ))
        });
        document.validate()?;
        Ok(document)
    }
}

fn reference(kind: &str, value: &str) -> SpdxExternalRef {
    SpdxExternalRef {
        reference_category: "OTHER".into(),
        reference_type: kind.into(),
        reference_locator: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{
        BUILD_REPORT_V1, BuildOutputEvidence, ReproducibilityResult, planned_nix_outputs,
    };
    use crate::platform::Platform;
    use aos_assessment::metadata::PackageScanPublicationV1;
    use serde_json::json;

    fn fixture() -> Result<(ReleasePlan, BuildReportV1)> {
        let (mut plan, _) = crate::verify::tests::qualification_fixture()?;
        for cell in &mut plan.packages[0].platforms {
            let MatrixCell::Artifact { artifact: set } = &mut cell.decision else {
                continue;
            };
            let artifact = &mut set.artifacts[0];
            artifact.id.push_str("/out");
            artifact.derivation =
                Some("/nix/store/00000000000000000000000000000000-example.drv".into());
            artifact.output = Some("out".into());
            artifact.store_path = Some(format!(
                "/nix/store/00000000000000000000000000000000-example-{}",
                cell.platform
            ));
        }
        let outputs = planned_nix_outputs(&plan)?
            .into_iter()
            .map(|(id, planned)| BuildOutputEvidence {
                id: id.into(),
                package: planned.package.into(),
                version: planned.version.into(),
                license_expression: planned.license_expression.into(),
                source_store_paths: planned.source_store_paths.to_vec(),
                platform: planned.platform,
                derivation: planned.derivation.into(),
                output: planned.output.into(),
                store_path: planned.store_path.into(),
                nar_hash: format!("sha256:{}", "a".repeat(64)),
                nar_size: 1,
                closure_size: 1,
                references: vec![],
                reproducibility: ReproducibilityResult::Reproduced,
            })
            .collect();
        let report = BuildReportV1 {
            schema_version: BUILD_REPORT_V1.into(),
            plan_digest: Sha256Digest::of_bytes(&crate::canonical::to_vec(&plan)?),
            source_commit: plan.source.commit.clone(),
            outputs,
            sources: vec![],
            completed_at: "2026-10-09T00:00:00Z".into(),
        };
        Ok((plan, report))
    }

    fn declaration() -> Result<PackageScanPublicationV1> {
        PackageScanPublicationV1::from_slice(&serde_json::to_vec(&json!({
            "schema":"aos.package-scan-publication/v1", "packageName":"example", "version":"1.0.0",
            "platform":"x86_64-linux", "memberId":"example", "definitions":[{
                "schema":"aos.package-scan-definition/v1", "unitId":"example-1", "family":"example", "stream":"1",
                "members":["example"], "classification":"manual", "lifecycle":"supported", "metadataOrigins":["published-source"],
                "reason":"Reviewed source declaration", "versionProjection":{"kind":"component-field", "component":"main", "field":"comparisonVersion"},
                "components":[{"componentId":"main", "current":{"upstreamId":"release-v1.0.0", "comparisonVersion":"1.0.0"},
                    "discovery":{"advisors":[]}, "releasePolicy":{"strategy":"channel", "versionScheme":"provider", "minimumAgeDays":0},
                    "security":{"identities":[{"kind":"ecosystem", "ecosystem":"crates.io", "name":"upstream-example"}],
                        "advisorySources":[{"provider":"osv"}], "versionScheme":"semver", "dependencyCoverage":{"state":"unknown", "basis":"Declared recipe components"}}}]
            }]
        }))?)
    }

    #[test]
    fn frozen_component_spdx_preserves_exact_identity_and_unknown_binary_coverage() -> Result<()> {
        let (mut plan, mut report) = fixture()?;
        let legacy = SpdxDocument::from_build(&report);
        assert_eq!(SpdxDocument::from_plan_and_build(&plan, &report)?, legacy);
        let declaration = declaration()?;
        plan.packages[0]
            .scan_declarations
            .insert(Platform::X86_64Linux, declaration.clone());
        plan.validate()?;
        // The frozen plan changed, so previously produced build evidence is refused.
        assert!(SpdxDocument::from_plan_and_build(&plan, &report).is_err());
        report.plan_digest = Sha256Digest::of_bytes(&crate::canonical::to_vec(&plan)?);
        let document = SpdxDocument::from_plan_and_build(&plan, &report)?;
        assert_eq!(document.packages.len(), legacy.packages.len() + 1);
        let component = document
            .packages
            .iter()
            .find(|record| record.name == "example/main")
            .context("upstream component")?;
        assert!(!component.files_analyzed);
        assert_eq!(component.version_info, "1.0.0");
        assert!(
            component
                .external_refs
                .iter()
                .any(|reference| reference.reference_type == "aos-upstream-id"
                    && reference.reference_locator == "release-v1.0.0")
        );
        assert!(component.external_refs.iter().any(|reference| {
            reference.reference_type == "aos-dependency-coverage"
                && reference
                    .reference_locator
                    .contains("\"state\":\"unknown\"")
        }));
        assert!(
            component
                .external_refs
                .iter()
                .any(
                    |reference| reference.reference_type == "aos-security-identity"
                        && reference.reference_locator.contains("upstream-example")
                )
        );
        assert!(
            document
                .relationships
                .iter()
                .any(|relationship| relationship.relationship_type == "CONTAINS"
                    && relationship.related_spdx_element == component.spdx_id)
        );
        assert_eq!(SpdxDocument::from_plan_and_build(&plan, &report)?, document);

        for field in ["package", "version", "platform"] {
            let mut changed = declaration.clone();
            match field {
                "package" => changed.package_name = "unrelated".into(),
                "version" => changed.version = "9.0.0".into(),
                _ => changed.platform = "aarch64-linux".into(),
            }
            plan.packages[0]
                .scan_declarations
                .insert(Platform::X86_64Linux, changed);
            assert!(plan.validate().is_err());
        }
        Ok(())
    }
}
