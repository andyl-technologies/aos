//! Explicit shipped library, plugin, CLI and private measurement targets.

use super::{ArtifactSpec, ExpectedArtifact};

pub(super) const ARTIFACT_SPECS: &[ArtifactSpec] = &[
    ArtifactSpec {
        package: "crucible-sim",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-assert",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-cas",
        expected: ExpectedArtifact::FleetStoreBinary,
    },
    ArtifactSpec {
        package: "crucible-sqlite-heap",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-linux-resource",
        expected: ExpectedArtifact::PrivateMeasurementLibrary {
            name: "crucible-measurement-init",
            path: "src/bin/measurement_init.rs",
        },
    },
    ArtifactSpec {
        package: "crucible-s3-store",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-campaign",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-shmem",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-protocol",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-ram",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-device",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-qemu",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-qemu-plugin",
        expected: ExpectedArtifact::CdylibPlugin,
    },
    ArtifactSpec {
        package: "crucible-guest",
        expected: ExpectedArtifact::GuestEmitter,
    },
    ArtifactSpec {
        package: "crucible",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-session",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-api",
        expected: ExpectedArtifact::Library,
    },
    ArtifactSpec {
        package: "crucible-daemon",
        expected: ExpectedArtifact::PrivateMeasurementLibrary {
            name: "crucible-measurement-actor",
            path: "src/bin/measurement_actor.rs",
        },
    },
    ArtifactSpec {
        package: "crucible-debug-gateway",
        expected: ExpectedArtifact::DebugGatewayBinary,
    },
    ArtifactSpec {
        package: "crucible-cli",
        expected: ExpectedArtifact::CliBinary,
    },
    ArtifactSpec {
        package: "crucible-harness",
        expected: ExpectedArtifact::Library,
    },
];

/// Checks the real directory because Cargo can also discover implicit binaries.
pub(super) fn private_binary_source_failures(
    spec: &ArtifactSpec,
    package_dir: &std::path::Path,
) -> Result<Vec<String>, std::io::Error> {
    let ExpectedArtifact::PrivateMeasurementLibrary { path, .. } = spec.expected else {
        return Ok(Vec::new());
    };
    let expected = package_dir.join(path);
    let mut entries = std::fs::read_dir(package_dir.join("src/bin"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    let mut expected_sources = vec![expected];
    if spec.package == "crucible-linux-resource" {
        expected_sources.push(package_dir.join("src/bin/allocation_roster_controls.rs"));
    } else if spec.package == "crucible-daemon" {
        expected_sources.push(package_dir.join("src/bin/measurement_workflow.rs"));
    }
    expected_sources.sort();
    if entries == expected_sources && expected_sources.iter().all(|path| path.is_file()) {
        Ok(Vec::new())
    } else {
        Ok(vec![format!(
            "{}: private measurement package has unreviewed implicit binary sources: {entries:?}",
            spec.package,
        )])
    }
}

#[test]
fn private_measurement_binary_requires_exact_name_path_and_feature() {
    let spec = ArtifactSpec {
        package: "crucible-linux-resource",
        expected: ExpectedArtifact::PrivateMeasurementLibrary {
            name: "crucible-measurement-init",
            path: "src/bin/measurement_init.rs",
        },
    };
    let layout = super::PackageLayout::fleet_store();
    let valid: toml::Value = r#"
        [package]
        name = "crucible-linux-resource"
        [features]
        private-measurement-domain = []
        [[bin]]
        name = "crucible-measurement-init"
        path = "src/bin/measurement_init.rs"
        required-features = ["private-measurement-domain"]
        [[bin]]
        name = "crucible-allocation-roster-controls"
        path = "src/bin/allocation_roster_controls.rs"
        required-features = ["test-support"]
    "#
    .parse()
    .expect("fixture TOML is valid");
    assert!(super::artifact_type_failures(&spec, &valid, &layout).is_empty());
    for field in ["name", "path", "required-features"] {
        let mut invalid = valid.clone();
        invalid["bin"][0]
            .as_table_mut()
            .expect("fixture bin is a table")
            .remove(field);
        assert!(!super::artifact_type_failures(&spec, &invalid, &layout).is_empty());
    }
    let mut extra = valid.clone();
    extra["bin"]
        .as_array_mut()
        .expect("fixture bins are an array")
        .push(valid["bin"][0].clone());
    assert!(!super::artifact_type_failures(&spec, &extra, &layout).is_empty());
    let mut default = valid;
    default["features"]
        .as_table_mut()
        .expect("fixture features are a table")
        .insert(
            "default".to_owned(),
            toml::Value::Array(vec![toml::Value::String(
                "private-measurement-domain".to_owned(),
            )]),
        );
    assert!(!super::artifact_type_failures(&spec, &default, &layout).is_empty());
}

/// Requires the exact standalone fixture target without enabling it by default.
pub(super) fn allocation_control_target_failures(manifest: &toml::Value) -> Vec<String> {
    let mut failures = Vec::new();
    let target = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .and_then(|targets| targets.get(1));
    let valid = target.is_some_and(|target| {
        target.get("name").and_then(toml::Value::as_str)
            == Some("crucible-allocation-roster-controls")
            && target.get("path").and_then(toml::Value::as_str)
                == Some("src/bin/allocation_roster_controls.rs")
            && target
                .get("required-features")
                .and_then(toml::Value::as_array)
                .is_some_and(|features| {
                    features.len() == 1 && features[0].as_str() == Some("test-support")
                })
    });
    if !valid {
        failures.push(
            "allocation controls must have the exact name, path and test-support feature"
                .to_owned(),
        );
    }
    if manifest
        .get("features")
        .and_then(|features| features.get("default"))
        .and_then(toml::Value::as_array)
        .is_some_and(|features| {
            features
                .iter()
                .any(|feature| feature.as_str() == Some("test-support"))
        })
    {
        failures.push("allocation controls must not be enabled by default".to_owned());
    }
    failures
}

#[test]
fn allocation_control_target_rejects_missing_extra_or_default_targets() {
    let spec = ArtifactSpec {
        package: "crucible-linux-resource",
        expected: ExpectedArtifact::PrivateMeasurementLibrary {
            name: "crucible-measurement-init",
            path: "src/bin/measurement_init.rs",
        },
    };
    let layout = super::PackageLayout::fleet_store();
    let valid: toml::Value = r#"
        [package]
        name = "crucible-linux-resource"
        [features]
        private-measurement-domain = []
        test-support = []
        [[bin]]
        name = "crucible-measurement-init"
        path = "src/bin/measurement_init.rs"
        required-features = ["private-measurement-domain"]
        [[bin]]
        name = "crucible-allocation-roster-controls"
        path = "src/bin/allocation_roster_controls.rs"
        required-features = ["test-support"]
    "#
    .parse()
    .expect("fixture TOML is valid");
    assert!(super::artifact_type_failures(&spec, &valid, &layout).is_empty());

    for field in ["name", "path", "required-features"] {
        let mut invalid = valid.clone();
        invalid["bin"][1]
            .as_table_mut()
            .expect("fixture target is a table")
            .remove(field);
        assert!(!super::artifact_type_failures(&spec, &invalid, &layout).is_empty());
    }
    let mut extra = valid.clone();
    extra["bin"]
        .as_array_mut()
        .expect("fixture targets are an array")
        .push(valid["bin"][1].clone());
    assert!(!super::artifact_type_failures(&spec, &extra, &layout).is_empty());

    let mut missing = valid.clone();
    missing["bin"]
        .as_array_mut()
        .expect("fixture targets are an array")
        .remove(1);
    assert!(!super::artifact_type_failures(&spec, &missing, &layout).is_empty());

    let mut default = valid;
    default["features"]
        .as_table_mut()
        .expect("fixture features are a table")
        .insert(
            "default".to_owned(),
            toml::Value::Array(vec![toml::Value::String("test-support".to_owned())]),
        );
    assert!(!super::artifact_type_failures(&spec, &default, &layout).is_empty());
}

#[test]
fn qemu_library_rejects_retired_standalone_measurement_parent() {
    let spec = ArtifactSpec {
        package: "crucible-qemu",
        expected: ExpectedArtifact::Library,
    };
    let valid: toml::Value = r#"
        [package]
        name = "crucible-qemu"
    "#
    .parse()
    .expect("fixture TOML is valid");
    assert!(
        super::artifact_type_failures(&spec, &valid, &super::PackageLayout::library()).is_empty()
    );

    let retired: toml::Value = r#"
        [package]
        name = "crucible-qemu"
        [features]
        private-measurement-domain = []
        [[bin]]
        name = "crucible-measurement-parent"
        path = "src/bin/measurement_parent.rs"
        required-features = ["private-measurement-domain"]
    "#
    .parse()
    .expect("fixture TOML is valid");
    assert!(
        !super::artifact_type_failures(&spec, &retired, &super::PackageLayout::fleet_store())
            .is_empty()
    );

    let implicit = super::PackageLayout {
        has_lib_rs: true,
        has_main_rs: false,
        has_src_bin_dir: true,
    };
    assert!(!super::artifact_type_failures(&spec, &valid, &implicit).is_empty());
}

/// Requires the immutable builder's exact author target, separately from the actor.
pub(super) fn workflow_author_target_failures(manifest: &toml::Value) -> Vec<String> {
    let target = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .and_then(|targets| targets.get(1));
    let valid = target.is_some_and(|target| {
        target.get("name").and_then(toml::Value::as_str) == Some("crucible-measurement-workflow")
            && target.get("path").and_then(toml::Value::as_str)
                == Some("src/bin/measurement_workflow.rs")
            && target
                .get("required-features")
                .and_then(toml::Value::as_array)
                .is_some_and(|features| {
                    features.len() == 1
                        && features[0].as_str() == Some("private-measurement-domain")
                })
    });
    if valid {
        Vec::new()
    } else {
        vec!["crucible-daemon: build-time workflow author must have its exact name, path and nondefault private feature".to_owned()]
    }
}

#[test]
fn workflow_author_is_exact_and_separate_from_runtime_actor() {
    let spec = ArtifactSpec {
        package: "crucible-daemon",
        expected: ExpectedArtifact::PrivateMeasurementLibrary {
            name: "crucible-measurement-actor",
            path: "src/bin/measurement_actor.rs",
        },
    };
    let valid: toml::Value = r#"
        [package]
        name = "crucible-daemon"
        [features]
        private-measurement-domain = []
        [[bin]]
        name = "crucible-measurement-actor"
        path = "src/bin/measurement_actor.rs"
        required-features = ["private-measurement-domain"]
        [[bin]]
        name = "crucible-measurement-workflow"
        path = "src/bin/measurement_workflow.rs"
        required-features = ["private-measurement-domain"]
    "#
    .parse()
    .expect("fixture TOML is valid");
    let layout = super::PackageLayout::fleet_store();
    assert!(super::artifact_type_failures(&spec, &valid, &layout).is_empty());

    for field in ["name", "path", "required-features"] {
        let mut missing = valid.clone();
        missing["bin"][1]
            .as_table_mut()
            .expect("fixture target is a table")
            .remove(field);
        assert!(!super::artifact_type_failures(&spec, &missing, &layout).is_empty());
    }

    for (field, value) in [
        ("name", "crucible-measurement-parent"),
        ("path", "src/bin/measurement_parent.rs"),
    ] {
        let mut wrong = valid.clone();
        wrong["bin"][1][field] = toml::Value::String(value.to_owned());
        assert!(!super::artifact_type_failures(&spec, &wrong, &layout).is_empty());
    }

    let mut wrong_feature = valid.clone();
    wrong_feature["bin"][1]["required-features"] =
        toml::Value::Array(vec![toml::Value::String("test-support".to_owned())]);
    assert!(!super::artifact_type_failures(&spec, &wrong_feature, &layout).is_empty());

    let mut extra = valid.clone();
    extra["bin"]
        .as_array_mut()
        .expect("fixture targets are an array")
        .push(valid["bin"][1].clone());
    assert!(!super::artifact_type_failures(&spec, &extra, &layout).is_empty());

    let mut missing_author = valid.clone();
    missing_author["bin"]
        .as_array_mut()
        .expect("fixture targets are an array")
        .pop();
    assert!(!super::artifact_type_failures(&spec, &missing_author, &layout).is_empty());

    let mut default = valid;
    default["features"]
        .as_table_mut()
        .expect("fixture features are a table")
        .insert(
            "default".to_owned(),
            toml::Value::Array(vec![toml::Value::String(
                "private-measurement-domain".to_owned(),
            )]),
        );
    assert!(!super::artifact_type_failures(&spec, &default, &layout).is_empty());
}
