//! Artifact/source binding and graph qualification for portable inventories.

use anyhow::{Context as _, Result};
use aos_assessment::scan_inventory::{SCAN_INVENTORY_V1, ScanInventoryV1};
use aos_contract::Sha256Digest;
use serde_json::json;

fn inventory() -> serde_json::Value {
    let source = Sha256Digest::of_bytes(b"exact source tree").to_string();
    let definition = Sha256Digest::of_bytes(b"definition fixture").to_string();
    json!({
        "schema": SCAN_INVENTORY_V1,
        "subjects": [{
            "subjectRef":"subject", "packageCoordinate":"fixture/example", "version":"1.0.0",
            "platform":"x86_64-linux", "output":"source", "kind":"source",
            "sourceContentDigest":source,
            "scanDefinitionDigest":definition,
            "componentInventoryDigest":Sha256Digest::of_bytes(b"component evidence").to_string()
        }],
        "components": [{
            "componentRef":"component", "componentId":"main", "subjectRef":"subject",
            "current":{"upstreamId":"v1.0.0", "comparisonVersion":"1.0.0"},
            "sourceContentDigest":source, "scanDefinitionDigest":definition,
            "security": {
                "identities":[{"kind":"unmapped", "reason":"identity-unmapped", "explanation":"Needs mapping"}],
                "advisorySources":[], "versionScheme":"unsupported",
                "dependencyCoverage":{"state":"unknown", "basis":"Source declaration only"}
            }
        }],
        "relationships":[{"fromRef":"subject", "kind":"contains", "toRef":"component"}],
        "coverage":{"state":"partial", "basis":"No observed build inclusion"}
    })
}

#[test]
fn portable_inventory_binds_bytes_and_rejects_ambient_database_fields() -> Result<()> {
    let mut value = inventory();
    let first = ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?)?;

    value["components"][0]["patchSetDigest"] =
        json!(Sha256Digest::of_bytes(b"backport").to_string());
    let second = ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?)?;
    assert_ne!(first.digest()?, second.digest()?);

    value["databaseId"] = json!(12);
    assert!(ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn dangling_edges_and_wrong_source_bindings_fail_admission() -> Result<()> {
    let mut value = inventory();
    value["relationships"][0]["toRef"] = json!("absent");
    assert!(ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());

    value = inventory();
    value["components"][0]["sourceContentDigest"] =
        json!(Sha256Digest::of_bytes(b"different tree").to_string());
    assert!(ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());

    value = inventory();
    value["subjects"][0]["kind"] = json!("package-artifact");
    assert!(ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn dependency_cycles_are_preserved_but_aggregate_cycles_are_rejected() -> Result<()> {
    let mut value = inventory();
    let mut second = value["components"][0].clone();
    second["componentRef"] = json!("component-2");
    value["components"]
        .as_array_mut()
        .context("expected fixture array")?
        .push(second);
    value["relationships"] = json!([
        {"fromRef":"component", "kind":"runtime-depends-on", "toRef":"component-2"},
        {"fromRef":"component-2", "kind":"runtime-depends-on", "toRef":"component"},
        {"fromRef":"subject", "kind":"contains", "toRef":"component"}
    ]);
    ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?)?;

    let mut second_subject = value["subjects"][0].clone();
    second_subject["subjectRef"] = json!("subject-2");
    second_subject["memberRefs"] = json!(["subject"]);
    value["subjects"][0]["memberRefs"] = json!(["subject-2"]);
    value["subjects"]
        .as_array_mut()
        .context("expected fixture array")?
        .push(second_subject);
    assert!(ScanInventoryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
