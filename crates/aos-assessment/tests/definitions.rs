//! Hostile metadata and identity checks for the portable package contract.

use anyhow::{Context as _, Result};
use aos_assessment::definition::{PACKAGE_SCAN_DEFINITION_V1, PackageScanDefinitionV1};
use aos_assessment::security::SecurityIdentity;
use serde_json::json;

fn definition() -> serde_json::Value {
    json!({
        "schema": PACKAGE_SCAN_DEFINITION_V1,
        "unitId": "example-1", "family": "example", "stream": "1",
        "classification": "manual", "lifecycle": "supported",
        "reason": "Human-reviewed upstream identity",
        "metadataOrigins": ["fixture-publication"],
        "versionProjection": {"kind":"component-field", "component":"main", "field":"comparisonVersion"},
        "components": [{
            "componentId": "main",
            "current": {"upstreamId":"v1.0.0", "comparisonVersion":"1.0.0"},
            "discovery": {"advisors":[]},
            "releasePolicy": {"strategy":"latest-in-series", "versionScheme":"semver", "seriesMajor":1, "allowPrerelease":false, "minimumAgeDays":3},
            "security": {
                "identities":[{"kind":"ecosystem", "ecosystem":"crates.io", "name":"example"}],
                "advisorySources":[{"provider":"osv"}],
                "versionScheme":"semver",
                "dependencyCoverage":{"state":"unknown", "basis":"Source declaration only"}
            }
        }]
    })
}

#[test]
fn canonical_definitions_bind_security_policy_and_reject_extensions() -> Result<()> {
    let mut value = definition();
    let first = PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?)?;
    let digest = first.digest()?;

    value["components"][0]["security"]["dependencyCoverage"]["state"] = json!("partial");
    let second = PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?)?;
    assert_ne!(second.digest()?, digest);

    value["credentials"] = json!("forbidden");
    assert!(PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?).is_err());

    value = definition();
    value["ownerRef"] = serde_json::Value::Null;
    assert!(PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn automatic_manual_frozen_and_local_roles_cannot_change_authority_implicitly() -> Result<()> {
    let mut value = definition();
    value["classification"] = json!("automatic");
    assert!(PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?).is_err());

    value["classification"] = json!("frozen");
    assert!(PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["reviewAfter"] = json!("2026-10-12T00:00:00Z");
    PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?)?;

    value["classification"] = json!("local");
    assert!(PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["components"] = json!([]);
    value
        .as_object_mut()
        .context("expected fixture object")?
        .remove("versionProjection");
    PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?)?;
    Ok(())
}

#[test]
fn identity_declarations_reject_credentials_wildcards_and_noncanonical_purls() -> Result<()> {
    let identities = [
        json!({"kind":"git", "repository":"https://token@example.invalid/project", "commit":"a".repeat(40)}),
        json!({"kind":"git", "repository":"https://example.invalid/project", "commit":"main"}),
        json!({"kind":"cpe", "part":"a", "vendor":"*", "product":"example"}),
        json!({"kind":"purl", "value":"https://example.invalid/project"}),
    ];
    for value in identities {
        let identity: SecurityIdentity = serde_json::from_value(value)?;
        assert!(identity.validate().is_err());
    }
    Ok(())
}

#[test]
fn explicit_generic_purls_remain_generic_and_unmapped_is_valid() -> Result<()> {
    for value in [
        json!({"kind":"purl", "value":"pkg:generic/example@1.0"}),
        json!({"kind":"unmapped", "reason":"identity-unmapped", "explanation":"Needs product mapping"}),
    ] {
        let identity: SecurityIdentity = serde_json::from_value(value.clone())?;
        identity.validate()?;
        assert_eq!(serde_json::to_value(identity)?, value);
    }
    Ok(())
}

#[test]
fn declaration_sets_are_rejected_instead_of_silently_resorted() -> Result<()> {
    let mut value = definition();
    let identity = value["components"][0]["security"]["identities"][0].clone();
    value["components"][0]["security"]["identities"] = json!([identity.clone(), identity]);
    assert!(PackageScanDefinitionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
