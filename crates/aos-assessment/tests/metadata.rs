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
    value["maintenanceInventory"]["units"][1]["ownerMember"] = json!("unowned-member");
    assert!(
        PackageAssessmentInventoryV1::from_slice(&serde_json::to_vec(&value)?)
            .and_then(|inventory| inventory.definitions())
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
    for definition in definitions {
        definition.digest()?;
    }
    Ok(())
}
