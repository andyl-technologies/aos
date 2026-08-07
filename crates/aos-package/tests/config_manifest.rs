//! Cross-language conformance tests for `aos.config-manifest/v1`.

use aos_package::config_eval::materialize::ConfigManifest;
use aos_package::graph_compile::reproject::hash_cjson;

const FIXTURE: &str = include_str!("fixtures/config_manifest/manifest.json");

#[test]
fn shared_fixture_is_strict_valid_and_byte_stable() {
    let manifest: ConfigManifest = serde_json::from_str(FIXTURE.trim_end()).unwrap();
    manifest.validate().unwrap();
    let first = serde_json::to_vec(&manifest).unwrap();
    let reparsed: ConfigManifest = serde_json::from_slice(&first).unwrap();
    let second = serde_json::to_vec(&reparsed).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_value(manifest).unwrap(),
        serde_json::from_str::<serde_json::Value>(FIXTURE).unwrap()
    );
}

#[test]
fn shared_fixture_rejects_unknown_top_level_fields() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    value["unexpected"] = serde_json::json!(true);
    let error = serde_json::from_value::<ConfigManifest>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field"), "{error}");
}

#[test]
fn shared_fixture_inputs_are_exactly_the_five_declared_inputs() {
    let value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let mut keys: Vec<&str> = value["inputs"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "base_lib",
            "config_modules",
            "evaluator",
            "host_nix",
            "instance_facts"
        ]
    );
}

#[test]
fn image_runtime_output_may_retain_base_ownership() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let output = value["packageOutputs"]["example"]["store_path"]
        .as_str()
        .unwrap()
        .to_string();
    value["packageOutputs"]["example"]["origin"] = serde_json::json!("image");
    value["ownership"]["storePaths"][&output] = serde_json::json!("@base");

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    manifest
        .validate()
        .expect("an image-authenticated output may remain owned by the immutable base");
}

#[test]
fn registry_runtime_output_may_not_claim_base_ownership() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let output = value["packageOutputs"]["example"]["store_path"]
        .as_str()
        .unwrap()
        .to_string();
    value["ownership"]["storePaths"][&output] = serde_json::json!("@base");

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("a registry output cannot assume immutable base ownership");
    assert!(
        error
            .to_string()
            .contains("store_path is not owned by that package"),
        "{error}"
    );
}

#[test]
fn computed_unpinned_store_path_in_emitted_text_is_rejected() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let store_path = [
        "/nix",
        "store",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-untrusted",
        "bin",
        "payload",
    ]
    .join("/");
    value["etc"]["computed.conf"]["kind"] = serde_json::json!("text");
    value["etc"]["computed.conf"]["mode"] = serde_json::json!("0644");
    value["etc"]["computed.conf"]["text"] = serde_json::json!(store_path);
    value["ownership"]["etc"]["computed.conf"] = serde_json::json!("@base");

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("unpinned computed store path");
    assert!(
        error.to_string().contains("emits unpinned store path"),
        "{error}"
    );
}

#[test]
fn emitted_store_path_requires_an_ownership_record() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let store_path = ["/nix", "store", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-owned"].join("/");
    value["etc"]["computed.conf"] = serde_json::json!({
        "kind": "text",
        "mode": "0644",
        "text": store_path.clone(),
    });
    value["ownership"]["etc"]["computed.conf"] = serde_json::json!("@base");
    value["storePaths"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(store_path));
    value["storePaths"]
        .as_array_mut()
        .unwrap()
        .sort_by(|left, right| left.as_str().cmp(&right.as_str()));

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("emitted store path without owner");
    assert!(error.to_string().contains("without an owner"), "{error}");
}

#[test]
fn package_artifact_cannot_emit_another_packages_pinned_path() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let other = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other";
    value["etc"]["example.conf"]["text"] = serde_json::json!(other);
    value["storePaths"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!(other));
    value["storePaths"]
        .as_array_mut()
        .unwrap()
        .sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    value["ownership"]["storePaths"][other] = serde_json::json!("other");

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("cross-package computed store path");
    assert!(
        error.to_string().contains(
            "owner \"example\" emits store path \"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other\" owned by \"other\""
        ),
        "{error}"
    );
}

#[test]
fn package_artifact_can_emit_transitive_dependency_path() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let middle = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-middle";
    let other = "/nix/store/cccccccccccccccccccccccccccccccc-other";
    value["packages"] = serde_json::json!(["example", "middle", "other"]);
    value["storePaths"] = serde_json::json!([
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example",
        middle,
        other,
        "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-bash",
    ]);
    value["ownership"]["storePaths"][middle] = serde_json::json!("middle");
    value["ownership"]["storePaths"][other] = serde_json::json!("other");
    value["packageOutputs"]["middle"] = runtime_pin("middle", 'b');
    value["packageOutputs"]["other"] = runtime_pin("other", 'c');
    value["graph"]["edges"] = serde_json::json!({
        "example": ["middle"],
        "middle": ["other"],
        "other": [],
    });
    value["etc"]["example.conf"]["text"] = serde_json::json!(other);

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    manifest
        .validate()
        .expect("authenticated transitive dependency path");
}

#[test]
fn json_object_keys_are_scanned_for_store_paths() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let unpinned = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-untrusted";
    value["config"]["example"] = serde_json::json!({unpinned: true});

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("unpinned store path in object key");
    assert!(
        error.to_string().contains("emits unpinned store path"),
        "{error}"
    );
}

#[test]
fn malformed_store_path_prefix_in_emitted_data_is_rejected() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    value["config"]["example"] = serde_json::json!({"path": "/nix/store/not-a-root"});

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("malformed store-path prefix");
    assert!(
        error.to_string().contains("malformed Nix store-path"),
        "{error}"
    );
}

fn runtime_pin(package: &str, hash_byte: char) -> serde_json::Value {
    let hash: String = std::iter::repeat(hash_byte).take(32).collect();
    let store_path = format!("/nix/store/{hash}-{package}");
    serde_json::json!({
        "version": "1",
        "platform": "fixture",
        "registry": "fixture",
        "store_path": store_path,
        "closure": [{
            "store_path_hash": hash,
            "store_path": store_path,
            "realisations": [{
                "nar_hash": "sha256:fixture",
                "nar_size": 1,
            }],
        }],
    })
}

fn migrated_fixture() -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let signed_config = serde_json::json!({
        "artifacts": [{
            "name": "env",
            "path": "/etc/aos/packages/example/config.env",
            "format": "env",
            "required": ["TOKEN"],
            "optional": [],
            "units": ["example.service"],
            "reload": "reload"
        }],
        "credentials": []
    });
    value["packageOutputs"]["example"]["config_projection"] = serde_json::json!({
        "config_output": "/nix/store/dddddddddddddddddddddddddddddddd-example-config",
        "config_nar_hash": "sha256:0000000000000000000000000000000000000000000000000000",
        "config": signed_config.clone()
    });
    value["config"] = serde_json::json!({"example": {"env": {"TOKEN": "secret"}}});
    value["configProjections"] = serde_json::json!({
        "example": {
            "schema": "aos.package-config-projection/v1",
            "schema_hash": hash_cjson(&signed_config),
            "artifacts": [{
                "path": "/etc/aos/packages/example/config.env",
                "text": "TOKEN=secret\n",
                "mode": "0644",
                "sha256": "sha256:218c0671c80bca81e845740de6692b7288c0f9ba7cdacf6a32febcb65302971c"
            }],
            "units": {"example.service": "reload"}
        }
    });
    value
}

#[test]
fn migrated_projection_binds_exact_bytes_schema_and_actions() {
    let manifest: ConfigManifest = serde_json::from_value(migrated_fixture()).unwrap();
    manifest.validate().unwrap();
}

#[test]
fn migrated_projection_fails_closed_when_missing_or_tampered() {
    for mutation in ["missing", "bytes", "desired", "action", "schema"] {
        let mut value = migrated_fixture();
        match mutation {
            "missing" => value.as_object_mut().unwrap().remove("configProjections"),
            "bytes" => {
                value["configProjections"]["example"]["artifacts"][0]["text"] =
                    serde_json::json!("TOKEN=tampered\n");
                None
            }
            "desired" => {
                value["config"]["example"]["env"]["TOKEN"] = serde_json::json!("tampered");
                None
            }
            "action" => {
                value["configProjections"]["example"]["units"]["example.service"] =
                    serde_json::json!("restart");
                None
            }
            "schema" => {
                value["configProjections"]["example"]["schema_hash"] =
                    serde_json::json!(format!("sha256:{}", "0".repeat(64)));
                None
            }
            _ => unreachable!(),
        };
        let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
        assert!(
            manifest.validate().is_err(),
            "{mutation} projection mutation was accepted"
        );
    }
}

#[test]
fn legacy_config_schema_is_manifest_pinned_and_exclusive() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let signed_config = serde_json::json!({
        "artifacts": [{
            "name": "env",
            "path": "/etc/aos/packages/example/config.env",
            "format": "env",
            "required": [],
            "optional": ["TOKEN"],
            "units": ["example.service"],
            "reload": "reload"
        }],
        "credentials": []
    });
    value["packageOutputs"]["example"]["legacy_config"] = signed_config;
    value["config"] = serde_json::json!({"example": {"env": {"TOKEN": "pinned"}}});

    let manifest: ConfigManifest = serde_json::from_value(value.clone()).unwrap();
    manifest.validate().unwrap();
    assert_eq!(
        serde_json::to_value(&manifest).unwrap()["packageOutputs"]["example"]["legacy_config"]["artifacts"]
            [0]["optional"],
        serde_json::json!(["TOKEN"])
    );

    let migrated = migrated_fixture();
    value["packageOutputs"]["example"]["config_projection"] =
        migrated["packageOutputs"]["example"]["config_projection"].clone();
    value["configProjections"] = migrated["configProjections"].clone();
    value["config"] = migrated["config"].clone();
    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("legacy and migrated schemas must be mutually exclusive");
    assert!(
        error.to_string().contains("both migrated and legacy"),
        "{error}"
    );
}

#[test]
fn package_state_cannot_name_an_absent_owner() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    value["config"] = serde_json::json!({"absent": {}});
    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("package-owned config must have a package pin");
    assert!(error.to_string().contains("absent package"), "{error}");
}

#[test]
fn noncanonical_store_path_cannot_be_pinned() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    value["storePaths"] = serde_json::json!(["/nix/store/short-fake"]);
    value["ownership"]["storePaths"] = serde_json::json!({"/nix/store/short-fake": "@base"});
    value["packageOutputs"]["example"]["store_path"] = serde_json::json!("/nix/store/short-fake");

    let manifest: ConfigManifest = serde_json::from_value(value).unwrap();
    let error = manifest
        .validate()
        .expect_err("noncanonical pinned store path");
    assert!(
        error.to_string().contains("invalid Nix store hash"),
        "{error}"
    );
}
