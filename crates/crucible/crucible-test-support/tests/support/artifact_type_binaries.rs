//! Validates ordinary binary exclusions and the gated gateway test-oracle input.

use super::*;

pub(super) fn gateway_test_oracle_failures(
    manifest: &Value,
    layout: &PackageLayout,
) -> Vec<String> {
    let mut failures = Vec::new();
    let bins = manifest.get("bin").and_then(Value::as_array);
    let only_bin = bins
        .filter(|bins| bins.len() == 1)
        .and_then(|bins| bins.first());
    let feature = vec![Value::String("qemu-test-oracle".to_owned())];
    let valid_target = only_bin.is_some_and(|bin| {
        bin.get("name").and_then(Value::as_str) == Some("crucible-qemu-test-oracle")
            && bin.get("path").and_then(Value::as_str) == Some("src/bin/qemu_test_oracle.rs")
            && bin.get("required-features").and_then(Value::as_array) == Some(&feature)
            && bin.get("test").and_then(Value::as_bool) == Some(false)
            && bin.get("bench").and_then(Value::as_bool) == Some(false)
    });
    let default_features = manifest
        .get("features")
        .and_then(|features| features.get("default"))
        .and_then(Value::as_array);
    let autobins = manifest
        .get("package")
        .and_then(|package| package.get("autobins"))
        .and_then(Value::as_bool);

    // This is a test input, not another installed control-server command.
    // Reject default activation, implicit commands, and additional targets.
    if !valid_target || autobins != Some(false) || !default_features.is_some_and(Vec::is_empty) {
        failures.push(
            "crucible-control-server: must declare only the disabled-by-default qemu-test-oracle binary with autobins = false, test = false, and bench = false".to_owned(),
        );
    }
    if layout.has_main_rs || !layout.has_src_bin_dir {
        failures.push(
            "crucible-control-server: test oracle must remain under src/bin without src/main.rs"
                .to_owned(),
        );
    }
    failures
}

pub(super) fn forbid_binary_targets(
    package: &str,
    manifest: &Value,
    layout: &PackageLayout,
    failures: &mut Vec<String>,
) {
    let bins = bin_targets(manifest);
    if !bins.is_empty() {
        failures.push(format!(
            "{}: library/plugin package must not declare [[bin]] targets",
            package
        ));
    }
    if layout.has_main_rs {
        failures.push(format!(
            "{}: library/plugin package must not have an implicit binary target at src/main.rs",
            package
        ));
    }
    if layout.has_src_bin_dir {
        failures.push(format!(
            "{}: library/plugin package must not have implicit binary targets under src/bin",
            package
        ));
    }
}

#[test]
fn gateway_test_oracle_requires_a_closed_opt_in_artifact_surface() -> Result<(), Box<dyn Error>> {
    let manifest: Value = r#"
        [package]
        name = "crucible-control-server"
        autobins = false
        [features]
        default = []
        qemu-test-oracle = []
        [[bin]]
        name = "crucible-qemu-test-oracle"
        path = "src/bin/qemu_test_oracle.rs"
        required-features = ["qemu-test-oracle"]
        test = false
        bench = false
    "#
    .parse()?;
    let spec = ArtifactSpec {
        package: "crucible-control-server",
        expected: ExpectedArtifact::Library,
    };
    let layout = PackageLayout {
        has_src_bin_dir: true,
        ..PackageLayout::library()
    };
    assert!(artifact_type_failures(&spec, &manifest, &layout).is_empty());

    for field in ["name", "path", "required-features", "test", "bench"] {
        let mut changed = manifest.clone();
        changed["bin"][0]
            .as_table_mut()
            .ok_or("oracle binary is not a table")?
            .remove(field);
        assert!(
            !artifact_type_failures(&spec, &changed, &layout).is_empty(),
            "{field}"
        );
    }
    let mut implicit = manifest.clone();
    implicit["package"]["autobins"] = Value::Boolean(true);
    assert!(!artifact_type_failures(&spec, &implicit, &layout).is_empty());

    let mut default_enabled = manifest.clone();
    default_enabled["features"]["default"] =
        Value::Array(vec![Value::String("qemu-test-oracle".to_owned())]);
    assert!(!artifact_type_failures(&spec, &default_enabled, &layout).is_empty());

    let mut extra = manifest.clone();
    extra["bin"]
        .as_array_mut()
        .ok_or("oracle binaries are not an array")?
        .push(manifest["bin"][0].clone());
    assert!(!artifact_type_failures(&spec, &extra, &layout).is_empty());
    Ok(())
}
