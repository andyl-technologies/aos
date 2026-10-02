//! Output-specific native envelope measurements and signed publication evidence.
//!
//! Every selectable payload receives its own root digest, native companion
//! commitment, DSSE statement, and entry in the existing provenance hash chain.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_registry_surface::manifest::parse_package_file;

use super::attestation::package_nar_root_digest;
use super::provenance::{
    PublishProvenanceArtifact, append_package_provenance_transparency_log, publish_provenance_ref,
    publish_provenance_statement, validate_external_provenance_signer,
};
use super::store_paths::{first_letter, introspect_store_path};
use crate::provenance::{ProvenanceSigner, sign_statement_dsse_jsonl_external};
use crate::types::{AttestationMeta, NativeArtifactMeta};

/// Updates exact output facts without copying another output's authority.
///
/// # Errors
/// Rejects missing or repeated coordinates, invalid native locators, malformed
/// metadata tables, and serialization failures.
pub(super) fn record_output_facts(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    output: &str,
    deployment: Option<&NativeArtifactMeta>,
    attestation: Option<&AttestationMeta>,
) -> Result<String> {
    let mut document: toml::Value = toml::from_str(existing)?;
    ensure!(
        document
            .get("package")
            .and_then(|value| value.get("name"))
            .and_then(toml::Value::as_str)
            == Some(name),
        "output evidence package mismatch"
    );
    let versions = document
        .get_mut("versions")
        .and_then(toml::Value::as_array_mut)
        .context("package lacks versions")?;
    let matches = versions
        .iter()
        .filter(|entry| entry.get("version").and_then(toml::Value::as_str) == Some(version))
        .count();
    ensure!(
        matches == 1,
        "output evidence requires one exact package version"
    );
    let entry = versions
        .iter_mut()
        .find(|entry| entry.get("version").and_then(toml::Value::as_str) == Some(version))
        .context("package version absent")?
        .get_mut("platforms")
        .and_then(|platforms| platforms.get_mut(platform))
        .context("package platform absent")?;
    let selected = if output == "out" {
        &mut *entry
    } else {
        entry
            .get_mut("named_outputs")
            .and_then(|outputs| outputs.get_mut(output))
            .context("named output absent")?
    };
    let table = selected
        .as_table_mut()
        .context("output metadata is not a table")?;
    if let Some(deployment) = deployment {
        deployment.validate()?;
        table.insert("deployment".into(), toml::Value::try_from(deployment)?);
    }
    if let Some(attestation) = attestation {
        if output == "out" {
            let facts = toml::Value::try_from(attestation)?;
            for field in [
                "root_digest",
                "root_hash",
                "root_hash_sig",
                "provenance",
                "measurement",
            ] {
                table.remove(field);
                if let Some(value) = facts.get(field) {
                    table.insert(field.into(), value.clone());
                }
            }
        } else {
            table.insert("attestation".into(), toml::Value::try_from(attestation)?);
        }
    }
    if attestation.is_some() {
        // Readers must reject unsupported evidence before selecting any output.
        super::metadata::record_feature_gate(
            entry
                .as_table_mut()
                .context("platform metadata is not a table")?,
            crate::types::FEATURE_ATTESTATION_V1,
        )?;
    }
    Ok(toml::to_string_pretty(&document)?)
}

/// Signs an output's exact native binding and appends its audit evidence.
///
/// # Errors
/// Rejects missing native companions, unavailable NARs, untrusted signers,
/// conflicting output identities, and failed statement or catalog writes.
pub(crate) async fn publish_output_evidence(
    directory: &Path,
    registry: &str,
    name: &str,
    version: &str,
    platform: &str,
    output: &str,
    signer: &mut dyn ProvenanceSigner,
) -> Result<()> {
    validate_external_provenance_signer(directory, signer)?;
    let catalog_path = directory
        .join("packages")
        .join(first_letter(name))
        .join(format!("{name}.toml"));
    let content = fs::read_to_string(&catalog_path)?;
    let package = parse_package_file(&content)?;
    let entry = package
        .versions
        .iter()
        .find(|entry| entry.version == version)
        .and_then(|version| version.platforms.get(platform))
        .context("publication coordinate absent")?;
    let (payload, deployment) = if output == "out" {
        (&entry.store_path, entry.deployment.as_ref())
    } else {
        let selected = entry
            .named_outputs
            .get(output)
            .context("named output absent")?;
        (&selected.store_path, selected.deployment.as_ref())
    };
    let deployment = deployment.context("selectable output lacks its own native envelope")?;
    let (actual, bytes) = super::native_artifacts::inspect_native_artifact(
        &deployment.store_path,
        "deployment.json",
    )?;
    ensure!(
        &actual == deployment,
        "output envelope NAR identity differs from catalog commitment"
    );
    let envelope = crate::deployment::model::Envelope::decode(&bytes)?;
    ensure!(
        envelope.package.path == *payload
            && envelope.package.name == name
            && envelope.package.version == version
            && envelope.system == platform,
        "output envelope identity differs from signed publication"
    );
    let binding = crate::package_attestation::native_package_binding_digest(
        deployment,
        entry.module_documentation.as_ref(),
        entry.qualification.as_ref(),
    )?;
    let info = introspect_store_path(payload)?;
    let source = introspect_store_path(&entry.source_drv)?;
    ensure!(
        aos_registry_surface::store::canonical_digest_hex(&source.nar_hash)?
            == aos_registry_surface::store::canonical_digest_hex(&entry.source_nar_hash)?,
        "publication source NAR differs from catalog commitment"
    );
    let root_digest = package_nar_root_digest(&info.nar_hash)?;
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        &binding,
    );
    let provenance = publish_provenance_ref(name, platform, &measurement)?;
    let attestation = AttestationMeta {
        root_digest: Some(root_digest),
        measurement: Some(measurement),
        provenance: Some(provenance.clone()),
        ..AttestationMeta::default()
    };
    let statement = publish_provenance_statement(
        registry,
        name,
        version,
        platform,
        &info,
        Some(&source),
        &binding,
        &attestation,
        signer.key_id(),
    )?;
    let jsonl = sign_statement_dsse_jsonl_external(&statement, signer).await?;
    let artifact = PublishProvenanceArtifact {
        path: provenance.clone(),
        jsonl,
        attestation: attestation.clone(),
    };
    let statement_path = directory.join(&provenance);
    fs::create_dir_all(
        statement_path
            .parent()
            .context("provenance path lacks parent")?,
    )?;
    fs::write(&statement_path, &artifact.jsonl)?;
    append_package_provenance_transparency_log(
        directory,
        name,
        version,
        platform,
        &info,
        Some(&source),
        &artifact,
        &statement_path,
    )?;
    fs::write(
        catalog_path,
        record_output_facts(
            &content,
            name,
            version,
            platform,
            output,
            None,
            Some(&attestation),
        )?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> &'static str {
        r#"
[package]
name = "example"
description = "Selected-output evidence fixture"
license = "Apache-2.0"
maintainer = "Example Maintainer"
[[versions]]
version = "1"
[versions.platforms.x86_64-linux]
store_path = "/nix/store/11111111111111111111111111111111-example"
closure_size = 1
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:primary"
measurement = "sha256:primary-measurement"
[versions.platforms.x86_64-linux.named_outputs.tools]
store_path = "/nix/store/22222222222222222222222222222222-example-tools"
"#
    }

    #[test]
    fn output_evidence_declares_features_required_by_strict_catalog_readers() {
        let deployment = NativeArtifactMeta {
            store_path: "/nix/store/33333333333333333333333333333333-envelope".into(),
            nar_hash: format!("sha256:{}", "a".repeat(64)),
            nar_size: 512,
            references: vec![],
            document_sha256: format!("sha256:{}", "b".repeat(64)),
            document_size: 256,
        };
        let attestation = AttestationMeta {
            root_digest: Some(format!("sha256:{}", "c".repeat(64))),
            measurement: Some(format!("sha256:{}", "d".repeat(64))),
            provenance: Some("provenance/e/example/x86_64-linux/output.intoto.jsonl".into()),
            ..AttestationMeta::default()
        };
        let clean = catalog()
            .replace("root_digest = \"sha256:primary\"\n", "")
            .replace("measurement = \"sha256:primary-measurement\"\n", "");
        let native = super::super::metadata::record_native_artifacts(
            &clean,
            "example",
            "1",
            "x86_64-linux",
            &deployment,
            None,
            None,
            None,
            None,
            &[],
        )
        .unwrap();

        for output in ["out", "tools"] {
            let encoded = record_output_facts(
                &native,
                "example",
                "1",
                "x86_64-linux",
                output,
                Some(&deployment),
                Some(&attestation),
            )
            .unwrap();
            let meta = crate::registry::parse::parse_package_toml(&encoded, "x86_64-linux")
                .unwrap()
                .unwrap();
            crate::types::validate_supported_package_meta(&meta).unwrap();
            let expected = vec![
                crate::types::FEATURE_ATTESTATION_V1.to_string(),
                crate::types::FEATURE_NATIVE_PACKAGE_MODULES_V1.to_string(),
            ];
            assert_eq!(meta.requires_features, expected);
            let parsed = parse_package_file(&encoded).unwrap();
            let platform = &parsed.versions[0].platforms["x86_64-linux"];
            assert_eq!(platform.requires_features, expected);
            assert_eq!(platform.references.requires_features(), expected);
            assert_eq!(platform.deployment.as_ref(), Some(&deployment));
        }
    }

    #[test]
    fn named_output_evidence_preserves_the_primary_and_its_own_envelope() {
        let deployment = NativeArtifactMeta {
            store_path: "/nix/store/33333333333333333333333333333333-tools-envelope".into(),
            nar_hash: format!("sha256:{}", "a".repeat(64)),
            nar_size: 512,
            references: vec![],
            document_sha256: format!("sha256:{}", "b".repeat(64)),
            document_size: 256,
        };
        let attestation = AttestationMeta {
            root_digest: Some("sha256:tools".into()),
            measurement: Some("sha256:tools-measurement".into()),
            provenance: Some("provenance/e/example/x86_64-linux/tools.intoto.jsonl".into()),
            ..AttestationMeta::default()
        };

        let primary = super::super::metadata::record_native_artifacts(
            catalog(),
            "example",
            "1",
            "x86_64-linux",
            &deployment,
            None,
            None,
            None,
            None,
            &[],
        )
        .unwrap();
        let encoded = record_output_facts(
            &primary,
            "example",
            "1",
            "x86_64-linux",
            "tools",
            Some(&deployment),
            Some(&attestation),
        )
        .unwrap();
        let parsed = parse_package_file(&encoded).unwrap();
        let platform = &parsed.versions[0].platforms["x86_64-linux"];
        let tools = &platform.named_outputs["tools"];

        assert_eq!(platform.root_digest.as_deref(), Some("sha256:primary"));
        assert_eq!(tools.deployment.as_ref(), Some(&deployment));
        assert_eq!(tools.attestation, attestation);
        assert_eq!(platform.deployment.as_ref(), Some(&deployment));
        assert!(
            record_output_facts(
                &encoded,
                "other",
                "1",
                "x86_64-linux",
                "tools",
                None,
                Some(&attestation)
            )
            .is_err()
        );
        assert!(
            record_output_facts(
                &encoded,
                "example",
                "1",
                "x86_64-linux",
                "missing",
                None,
                Some(&attestation)
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires the explicitly source-built selected-output fixture and primary companion"]
    async fn source_built_named_outputs_receive_distinct_signed_evidence() {
        use super::super::metadata::{build_package_toml, record_named_output};
        use super::super::native_artifacts::publish_native_documents;
        use super::super::test_support::{init_test_transparency_repo, test_provenance_signer};
        use crate::registry_ops::git::git;

        let fixture =
            std::env::var("AOS_TEST_SELECTED_OUTPUT_FIXTURE").expect("built fixture root");
        let primary = std::env::var("AOS_TEST_SELECTED_OUTPUT_PRIMARY_ENVELOPE")
            .expect("built primary companion");
        let fixture: serde_json::Value =
            serde_json::from_slice(&fs::read(Path::new(&fixture).join("fixture.json")).unwrap())
                .unwrap();
        let qualification = fixture
            .get("qualificationArtifact")
            .and_then(serde_json::Value::as_str);
        let available: crate::deployment::model::Artifact =
            serde_json::from_value(fixture["available"].clone()).unwrap();
        let tools_envelope = Path::new(fixture["envelope"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_str()
            .unwrap();
        let documentation = Path::new(fixture["documentation"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_str()
            .unwrap();
        let info = introspect_store_path(&available.path).unwrap();
        let source = super::super::store_paths::introspect_deriver(&available.path)
            .unwrap()
            .unwrap();
        let directory = tempfile::TempDir::new().unwrap();
        init_test_transparency_repo(directory.path());
        git(directory.path(), &["add", "registry.toml", "keys.toml"]).unwrap();
        git(
            directory.path(),
            &["commit", "-m", "Initialize publication fixture"],
        )
        .unwrap();
        let catalog_path = directory.path().join("packages/s/selected-handler.toml");
        fs::create_dir_all(catalog_path.parent().unwrap()).unwrap();
        let mut catalog = build_package_toml(
            "",
            &available.name,
            &available.version,
            "x86_64-linux",
            &info,
            Some("Selected output integration fixture"),
            None,
            Some("Apache-2.0"),
            Some("Example Maintainer"),
            false,
            None,
            &[],
            Some(&source),
        )
        .unwrap();
        for (output, path) in &available.outputs {
            if output != "out" {
                catalog = record_named_output(
                    &catalog,
                    &available.name,
                    &available.version,
                    "x86_64-linux",
                    output,
                    path,
                )
                .unwrap();
            }
        }
        fs::write(&catalog_path, catalog).unwrap();
        let printer = aos_core::output::Printer::new(0, true, false);
        for envelope in [primary.as_str(), tools_envelope] {
            publish_native_documents(
                directory.path(),
                &available.name,
                &available.version,
                "x86_64-linux",
                &available.outputs,
                envelope,
                Some(documentation),
                qualification,
                &printer,
            )
            .unwrap();
        }
        let mut signer = test_provenance_signer();
        for output in ["out", "tools"] {
            publish_output_evidence(
                directory.path(),
                "test",
                &available.name,
                &available.version,
                "x86_64-linux",
                output,
                &mut signer.signer,
            )
            .await
            .unwrap();
        }

        let parsed = parse_package_file(&fs::read_to_string(&catalog_path).unwrap()).unwrap();
        let platform = &parsed.versions[0].platforms["x86_64-linux"];
        let tools = &platform.named_outputs["tools"];
        assert_ne!(platform.root_digest, tools.attestation.root_digest);
        assert_ne!(platform.measurement, tools.attestation.measurement);
        assert_ne!(platform.provenance, tools.attestation.provenance);
        assert_ne!(platform.deployment, tools.deployment);
        let (_, trusted) =
            super::super::provenance::package_provenance_trusted_keys(directory.path()).unwrap();
        for (path, evidence, envelope) in [
            (
                &platform.store_path,
                platform.attestation(),
                platform.deployment.as_ref().unwrap(),
            ),
            (
                &tools.store_path,
                tools.attestation.clone(),
                tools.deployment.as_ref().unwrap(),
            ),
        ] {
            let jsonl =
                fs::read_to_string(directory.path().join(evidence.provenance.as_ref().unwrap()))
                    .unwrap();
            let (statement, key) =
                crate::provenance::verify_statement_dsse_jsonl(&jsonl, &trusted).unwrap();
            assert_eq!(key, "builder");
            assert_eq!(statement["subject"][0]["name"], *path);
            assert_eq!(
                statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"],
                format!("nix:{}", source.path)
            );
            let binding = crate::package_attestation::native_package_binding_digest(
                envelope,
                platform.module_documentation.as_ref(),
                platform.qualification.as_ref(),
            )
            .unwrap();
            assert_eq!(
                statement["subject"][1]["digest"]["sha256"],
                binding.trim_start_matches("sha256:")
            );
        }
        git(
            directory.path(),
            &["add", "packages", "store", "provenance", "transparency"],
        )
        .unwrap();
        super::super::provenance::staged::validate_staged_package_provenance_transparency_log(
            directory.path(),
        )
        .unwrap();

        let original = fs::read_to_string(&catalog_path).unwrap();
        let mut document: toml::Value = toml::from_str(&original).unwrap();
        document["versions"][0]["platforms"]["x86_64-linux"]["named_outputs"]["tools"]["attestation"] =
            toml::Value::try_from(platform.attestation()).unwrap();
        fs::write(&catalog_path, toml::to_string_pretty(&document).unwrap()).unwrap();
        git(directory.path(), &["add", "packages"]).unwrap();
        assert!(
            super::super::provenance::staged::validate_staged_package_provenance_transparency_log(
                directory.path()
            )
            .is_err()
        );

        fs::write(&catalog_path, &original).unwrap();
        git(directory.path(), &["add", "packages"]).unwrap();
        git(
            directory.path(),
            &["commit", "-m", "Publish exact output evidence"],
        )
        .unwrap();
        let mut document: toml::Value = toml::from_str(&original).unwrap();
        document["versions"][0]["platforms"]["x86_64-linux"]["named_outputs"]["tools"]
            .as_table_mut()
            .unwrap()
            .remove("attestation");
        fs::write(&catalog_path, toml::to_string_pretty(&document).unwrap()).unwrap();
        git(directory.path(), &["add", "packages"]).unwrap();
        assert!(
            super::super::provenance::staged::validate_staged_package_provenance_transparency_log(
                directory.path()
            )
            .is_err()
        );
    }
}
