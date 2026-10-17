//! Authenticated package scan metadata authoring before publication signing.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_assessment::metadata::{PackageAssessmentInventoryV1, PackageScanPublicationV1};
use aos_core::nix::NixRunner;

/// Evaluates scan declarations for the exact publication target.
pub(super) fn evaluate_inventory(platform: &str) -> Result<PackageAssessmentInventoryV1> {
    let value =
        NixRunner::new(0, true)?.eval_json_for_target("assessmentInventory", Some(platform))?;
    PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?)
        .context("decoding evaluated package assessment metadata")
}

/// Adds a closed declaration to its existing exact package platform entry.
///
/// The caller holds the publication lock and signs the resulting catalog as
/// part of its ordinary atomic transaction. Other retained versions survive.
pub(super) fn record(existing: &str, declaration: &PackageScanPublicationV1) -> Result<String> {
    let encoded = declaration.to_json()?;
    let mut document: toml::Value = toml::from_str(existing)?;
    if document
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        != Some(&declaration.package_name)
    {
        bail!("package scan declaration differs from authored package name");
    }
    let entry = document
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .and_then(|versions| {
            versions.iter_mut().find(|version| {
                version.get("version").and_then(toml::Value::as_str) == Some(&declaration.version)
            })
        })
        .and_then(|version| version.get_mut("platforms"))
        .and_then(toml::Value::as_table_mut)
        .and_then(|platforms| platforms.get_mut(&declaration.platform))
        .and_then(toml::Value::as_table_mut)
        .context("package scan declaration lacks its exact authored platform")?;
    if let Some(previous) = entry.get("scan").and_then(toml::Value::as_str) {
        let previous = PackageScanPublicationV1::from_slice(previous.as_bytes())?;
        if previous != *declaration {
            bail!("published package scan declaration is already bound to different metadata");
        }
    }
    entry.insert("scan".into(), toml::Value::String(encoded));
    let result = toml::to_string_pretty(&document)?;
    aos_registry_surface::manifest::parse_package_file(&result)?;
    Ok(result)
}

/// Writes evaluated scan policy inside the catalog that will be signed.
pub(super) fn publish(
    directory: &Path,
    inventory: &PackageAssessmentInventoryV1,
    name: &str,
    version: &str,
    platform: &str,
) -> Result<()> {
    let declaration = inventory.publication(
        aos_assessment::identity::MemberId::parse(name)?,
        name.to_owned(),
        version.to_owned(),
        platform.to_owned(),
    )?;
    publish_declaration(directory, &declaration)
}

/// Writes a declaration already frozen by an authenticated release plan.
pub(crate) fn publish_declaration(
    directory: &Path,
    declaration: &PackageScanPublicationV1,
) -> Result<()> {
    declaration.validate()?;
    let name = &declaration.package_name;
    crate::types::validate_package_name(name)?;
    let path = directory
        .join("packages")
        .join(aos_registry_surface::manifest::package_name_bucket(name))
        .join(format!("{name}.toml"));
    let existing = fs::read_to_string(&path)?;
    let content = record(&existing, declaration)?;
    fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn declaration() -> Result<PackageScanPublicationV1> {
        PackageScanPublicationV1::from_slice(&serde_json::to_vec(&json!({
            "schema":"aos.package-scan-publication/v1", "packageName":"example",
            "version":"1.2.0", "platform":"x86_64-linux", "memberId":"example",
            "definitions":[{
                "schema":"aos.package-scan-definition/v1", "unitId":"example-1",
                "family":"example", "stream":"1", "members":["example"],
                "classification":"manual", "lifecycle":"supported", "metadataOrigins":["published-source"],
                "reason":"Explicit manual upstream policy",
                "versionProjection":{"kind":"component-field", "component":"main", "field":"comparisonVersion"},
                "components":[{
                    "componentId":"main", "current":{"upstreamId":"v1.2.0", "comparisonVersion":"1.2.0"},
                    "discovery":{"advisors":[]},
                    "releasePolicy":{"strategy":"channel", "versionScheme":"provider", "minimumAgeDays":0},
                    "security":{"identities":[{"kind":"unmapped", "reason":"no-reviewed-product-mapping", "explanation":"Publisher declares no automatic advisory identity."}], "advisorySources":[], "versionScheme":"unsupported",
                        "dependencyCoverage":{"state":"unknown", "basis":"Recipe declarations only"}}
                }]
            }]
        }))?)
    }

    fn catalog() -> String {
        r#"[package]
name = "example"
description = "Publication fixture"
license = "MIT"
maintainer = "AOS test"

[[versions]]
version = "1.1.0"
[versions.platforms.x86_64-linux]
store_path = "/nix/store/00000000000000000000000000000000-example-old"
closure_size = 1
source_drv = ""
source_nar_hash = ""

[[versions]]
version = "1.2.0"
[versions.platforms.x86_64-linux]
store_path = "/nix/store/11111111111111111111111111111111-example"
closure_size = 1
source_drv = ""
source_nar_hash = ""
[versions.platforms.aarch64-linux]
store_path = "/nix/store/22222222222222222222222222222222-example"
closure_size = 1
source_drv = ""
source_nar_hash = ""
"#
        .into()
    }

    #[test]
    fn authored_scan_retains_versions_and_platforms_and_refuses_rebinding() -> Result<()> {
        let declaration = declaration()?;
        let authored = record(&catalog(), &declaration)?;
        let parsed = aos_registry_surface::manifest::parse_package_file(&authored)?;
        assert_eq!(parsed.versions.len(), 2);
        assert!(parsed.versions[0].platforms["x86_64-linux"].scan.is_none());
        assert!(parsed.versions[1].platforms["aarch64-linux"].scan.is_none());
        let platform = &parsed.versions[1].platforms["x86_64-linux"];
        assert_eq!(
            platform.scan_declaration("example", "1.2.0", "x86_64-linux")?,
            Some(declaration.clone())
        );
        assert!(
            platform
                .scan_declaration("different", "1.2.0", "x86_64-linux")
                .is_err()
        );
        assert!(
            platform
                .scan_declaration("example", "1.1.0", "x86_64-linux")
                .is_err()
        );
        assert!(
            platform
                .scan_declaration("example", "1.2.0", "aarch64-linux")
                .is_err()
        );
        assert_eq!(record(&authored, &declaration)?, authored);

        let mut changed = declaration.clone();
        changed.definitions[0].reason = Some("Different published policy".into());
        assert!(record(&authored, &changed).is_err());
        changed = declaration.clone();
        changed.package_name = "absent".into();
        assert!(record(&authored, &changed).is_err());
        changed = declaration;
        changed.version = "absent".into();
        assert!(record(&authored, &changed).is_err());
        Ok(())
    }

    #[test]
    fn package_parser_rejects_scan_policy_replayed_to_another_version() -> Result<()> {
        let authored = record(&catalog(), &declaration()?)?;
        let replayed = authored.replace("version = \"1.2.0\"", "version = \"9.0.0\"");
        assert!(aos_registry_surface::manifest::parse_package_file(&replayed).is_err());
        Ok(())
    }

    #[test]
    fn primary_output_republication_cannot_erase_a_bound_scan_policy() -> Result<()> {
        let declaration = declaration()?;
        let authored = record(&catalog(), &declaration)?;
        let info = crate::registry_ops::store_paths::StorePathInfo {
            path: "/nix/store/11111111111111111111111111111111-example".into(),
            nar_hash: format!("sha256:{}", "0".repeat(64)),
            nar_size: 1,
            references: vec![],
            closure_size: 1,
        };
        let republished = super::super::metadata::build_package_toml(
            &authored,
            "example",
            "1.2.0",
            "x86_64-linux",
            &info,
            Some("Publication fixture"),
            None,
            Some("MIT"),
            Some("AOS test"),
            false,
            None,
            &[],
            None,
        )?;
        let parsed = aos_registry_surface::manifest::parse_package_file(&republished)?;
        assert_eq!(
            parsed.versions[1].platforms["x86_64-linux"].scan_declaration(
                "example",
                "1.2.0",
                "x86_64-linux"
            )?,
            Some(declaration.clone())
        );

        let mut changed = declaration;
        changed.definitions[0].reason = Some("Changed policy after publication".into());
        assert!(record(&republished, &changed).is_err());
        Ok(())
    }
}
