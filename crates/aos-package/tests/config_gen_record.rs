//! Acceptance tests for complete configuration-generation records.

use serde_json::json;

#[test]
fn config_generation_record_keeps_all_replay_identities() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/config_manifest/manifest.json"))
            .expect("parse manifest fixture");
    let modules = &fixture["inputs"]["package_modules"]["modules"];
    assert_eq!(modules.as_array().map(Vec::len), Some(1));
    assert_eq!(modules[0]["package"], json!("example"));
    assert_eq!(
        modules[0]["store_path"],
        json!("/nix/store/dddddddddddddddddddddddddddddddd-example-config")
    );
    assert_eq!(
        modules[0]["nar_hash"],
        json!("sha256:0000000000000000000000000000000000000000000000000000")
    );
    assert!(
        fixture["inputs"]["host_nix"]["store_path"]
            .as_str()
            .is_some_and(|path| path.starts_with("/nix/store/"))
    );
    assert!(
        fixture["inputs"]["instance_facts"]["store_path"]
            .as_str()
            .is_some_and(|path| path.starts_with("/nix/store/"))
    );
}
