//! Package sidecar projection, exact owners and legacy wire compatibility.

use anyhow::{Context as _, Result};
use aos_assessment::metadata::{
    PACKAGE_ASSESSMENT_INVENTORY_V1, PACKAGE_ASSESSMENT_METADATA_V1, PackageAssessmentInventoryV1,
};
use serde_json::json;

fn metadata() -> serde_json::Value {
    json!({
        "schema":PACKAGE_ASSESSMENT_INVENTORY_V1,
        "maintenanceInventory":{"schema":aos_assessment::MAINTENANCE_INVENTORY_V1,"units":[{
            "unitId":"example-1", "family":"example", "stream":"1", "classification":"manual",
            "package":{"currentVersion":"1.2.0", "versionProjection":{"kind":"component-field","component":"main","field":"comparisonVersion"}},
            "components":{"main":{"current":{"upstreamId":"v1.2.0","comparisonVersion":"1.2.0"},
                "primary":null, "advisors":[], "sources":{},
                "releasePolicy":{"strategy":"channel","versionScheme":"provider","seriesMajor":null,"allowPrerelease":false,"minimumAgeDays":0}}},
            "owner":"pkgs/fixtures/example.nix", "members":["example"], "platforms":["x86_64-linux"],
            "policy":{"lifecycle":"supported","riskFloor":"high","repairScope":[]}, "reason":"Reviewed manual source fixture"
        }]},
        "securityDeclarations":[{"schema":PACKAGE_ASSESSMENT_METADATA_V1,"unitId":"example-1","components":{"main":{
            "identities":[{"kind":"ecosystem","ecosystem":"crates.io","name":"example"}], "advisorySources":[{"provider":"osv"}],
            "versionScheme":"semver", "dependencyCoverage":{"state":"unknown","basis":"Source declaration only"}
        }}}]
    })
}

#[test]
fn source_sidecars_preserve_legacy_nulls_and_project_exact_security_definitions() -> Result<()> {
    let value = metadata();
    let inventory = PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?)?;
    let definitions = inventory.definitions()?;
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        definitions[0].components[0].security,
        inventory.security_declarations[0]
            .components
            .values()
            .next()
            .context("fixture security")?
            .clone()
    );
    assert_eq!(
        definitions[0].metadata_origins,
        ["pkgs/fixtures/example.nix"]
    );
    definitions[0].digest()?;
    Ok(())
}

#[test]
fn unknown_security_fields_optional_nulls_and_wrong_unit_scopes_are_rejected() -> Result<()> {
    let mut value = metadata();
    value["securityDeclarations"][0]["components"]["main"]["script"] = json!("untrusted code");
    assert!(PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = metadata();
    value["securityDeclarations"][0]["components"]["main"]["advisorySources"][0]["project"] =
        serde_json::Value::Null;
    assert!(PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = metadata();
    value["securityDeclarations"][0]["unitId"] = json!("unrelated-1");
    assert!(PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn alias_projection_binds_exact_owner_definition_and_declared_member() -> Result<()> {
    let mut value = metadata();
    value["maintenanceInventory"]["units"].as_array_mut().context("fixture units")?.push(json!({
        "unitId":"example-alias", "family":"example", "stream":"alias", "classification":"alias", "components":{},
        "owner":"pkgs/fixtures/example-alias.nix", "members":["example-alias"], "platforms":["x86_64-linux"],
        "policy":{"lifecycle":"supported","riskFloor":"high","repairScope":[]}, "ownerUnit":"example-1", "ownerMember":"example"
    }));
    value["securityDeclarations"]
        .as_array_mut()
        .context("fixture sidecars")?
        .push(json!({
            "schema":PACKAGE_ASSESSMENT_METADATA_V1,"unitId":"example-alias","components":{}
        }));
    let inventory = PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?)?;
    let definitions = inventory.definitions()?;
    let owner = definitions[1]
        .owner_ref
        .as_ref()
        .context("alias owner binding")?;
    assert_eq!(owner.definition_digest, definitions[0].digest()?);
    assert_eq!(owner.member_id.as_str(), "example");
    let bindings: Vec<aos_assessment::metadata::SourcePackageBindingV1> =
        serde_json::from_value(json!([
            {"member":"example", "version":"1.2.0", "platform":"x86_64-linux"},
            {"member":"example-alias", "version":"9.4.0", "platform":"x86_64-linux"}
        ]))?;
    let source = aos_contract::Sha256Digest::of_bytes("exact source content");
    let scan = inventory.source_inventory(&bindings, "publisher/fixtures", source)?;
    let alias = scan
        .subjects
        .iter()
        .find(|subject| subject.package_coordinate.ends_with("/example-alias"))
        .context("source alias")?;
    let owner_subject = scan
        .subjects
        .iter()
        .find(|subject| subject.package_coordinate.ends_with("/example"))
        .context("source owner")?;
    assert_eq!(alias.version, "9.4.0");
    assert_eq!(owner_subject.version, "1.2.0");
    assert_eq!(
        alias.member_refs,
        std::slice::from_ref(&owner_subject.subject_ref)
    );
    assert_eq!(scan.components.len(), 1);
    assert_eq!(scan.components[0].subject_ref, owner_subject.subject_ref);
    let data = aos_assessment::input::EvaluationData {
        inventory: scan.clone(),
        definitions,
        upstream: vec![],
        advisory_snapshot: None,
        advisories: vec![],
        dispositions: vec![],
        history: vec![],
        policy: serde_json::from_value(
            json!({"schema":aos_assessment::input::ASSESSMENT_POLICY_V1,
            "upstreamMaxAgeSeconds":86400,"advisoryMaxAgeSeconds":86400,"requiredAdvisorySources":[],"requireDependencyCoverage":true}),
        )?,
    };
    let graph = aos_assessment::evaluator::ScopeGraph::new(&data)?;
    assert_eq!(
        graph.components(&alias.subject_ref)?,
        graph.components(&owner_subject.subject_ref)?
    );
    assert_eq!(
        scan.coverage.state,
        aos_assessment::security::CoverageState::Unknown
    );
    assert!(
        scan.subjects
            .iter()
            .all(|subject| subject.artifact_digest.is_none()
                && subject.source_content_digest == Some(source))
    );
    value["maintenanceInventory"]["units"][1]["ownerMember"] = json!("unowned-member");
    assert!(
        PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?)
            .and_then(|inventory| inventory.definitions())
            .is_err()
    );
    Ok(())
}

#[test]
fn source_inventory_requires_exact_evaluated_versions_and_all_declared_members() -> Result<()> {
    let inventory = PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&metadata())?)?;
    let source = aos_contract::Sha256Digest::of_bytes("exact source content");
    let binding: aos_assessment::metadata::SourcePackageBindingV1 = serde_json::from_value(
        json!({"member":"example", "version":"7.8.9", "platform":"x86_64-linux"}),
    )?;
    let scan =
        inventory.source_inventory(std::slice::from_ref(&binding), "publisher/fixtures", source)?;
    assert_eq!(scan.subjects[0].version, "7.8.9");
    assert!(
        inventory
            .source_inventory(&[], "publisher/fixtures", source)
            .is_err()
    );
    assert!(
        inventory
            .source_inventory(&[binding.clone(), binding], "publisher/fixtures", source)
            .is_err()
    );
    assert!(
        inventory
            .source_inventory(&[], "publisher/fixtures/", source)
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "Requires an evaluated Nix export in AOS_ASSESSMENT_METADATA_FIXTURE"]
fn actual_package_set_export_projects_every_declared_unit() -> Result<()> {
    let path = std::env::var("AOS_ASSESSMENT_METADATA_FIXTURE")
        .context("missing evaluated package metadata fixture")?;
    let bytes = std::fs::read(path)?;
    let inventory = PackageAssessmentInventoryV1::from_slice(&bytes)?;
    let definitions = inventory.definitions()?;
    assert_eq!(
        definitions.len(),
        inventory.maintenance_inventory.units.len()
    );
    assert!(definitions.len() > 100);
    for definition in &definitions {
        definition.digest()?;
    }
    if let Ok(path) = std::env::var("AOS_ASSESSMENT_SOURCE_BINDINGS_FIXTURE") {
        let bindings: Vec<aos_assessment::metadata::SourcePackageBindingV1> =
            serde_json::from_slice(&std::fs::read(path)?)?;
        let scan = inventory.source_inventory(
            &bindings,
            "publisher/actual-package-set",
            aos_contract::Sha256Digest::of_bytes("fixture-admitted-source-tree"),
        )?;
        assert_eq!(scan.subjects.len(), bindings.len());
        assert!(scan.subjects.len() > 100);
        let data = aos_assessment::input::EvaluationData {
            inventory: scan,
            definitions,
            upstream: vec![],
            advisories: vec![],
            dispositions: vec![],
            history: vec![],
            advisory_snapshot: Some(aos_assessment::advisory::AdvisorySnapshotV1 {
                schema: aos_assessment::advisory::ADVISORY_SNAPSHOT_V1.into(),
                sources: vec![],
                exploit_catalog: None,
            }),
            policy: serde_json::from_value(
                json!({"schema":aos_assessment::input::ASSESSMENT_POLICY_V1,
                "upstreamMaxAgeSeconds":86400, "advisoryMaxAgeSeconds":86400, "requiredAdvisorySources":[], "requireDependencyCoverage":true}),
            )?,
        };
        let input = data.freeze(
            vec![
                aos_assessment::input::Profile::Updates,
                aos_assessment::input::Profile::Vulnerabilities,
            ],
            aos_assessment::time::Timestamp::parse("2026-10-09T12:00:00Z")?,
        )?;
        let result = aos_assessment::evaluator::evaluate(&input, &data)?;
        assert_eq!(result.subject_results.len(), bindings.len());
        result.digest()?;
    }
    Ok(())
}
