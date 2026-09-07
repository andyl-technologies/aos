//! Checks the Crucible crate artifact-type contract.
//!
//! RFC-0010 file 27 fixes the Rust artifact surface before later phases add
//! implementation detail: only the QEMU plugin builds a `cdylib`, the CLI
//! builds the public `crucible` binary, `crucible-debug-gateway` builds the
//! GPL-side gateway process, `crucible-guest` builds its optional in-guest
//! emitter binary, `crucible-cas` builds the fleet-store binary, and every
//! other Crucible package remains a library crate.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use toml::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedArtifact {
    CdylibPlugin,
    CliBinary,
    DebugGatewayBinary,
    FleetStoreBinary,
    GuestEmitter,
    Library,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArtifactSpec {
    package: &'static str,
    expected: ExpectedArtifact,
}

const ARTIFACT_SPECS: &[ArtifactSpec] = &[
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
        package: "crucible-linux-resource",
        expected: ExpectedArtifact::Library,
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
        expected: ExpectedArtifact::Library,
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

#[test]
fn crucible_packages_expose_declared_artifact_types() -> Result<(), Box<dyn Error>> {
    let crates_dir = workspace_crates_dir()?;
    let mut failures = Vec::new();

    assert_expected_crucible_package_set(&crates_dir, &mut failures)?;

    for spec in ARTIFACT_SPECS {
        let package_dir = crates_dir.join(spec.package);
        let manifest_path = package_dir.join("Cargo.toml");
        let manifest: Value = fs::read_to_string(&manifest_path)?.parse()?;
        let layout = PackageLayout::from_package_dir(&package_dir);

        failures.extend(artifact_type_failures(spec, &manifest, &layout));
    }

    assert!(
        failures.is_empty(),
        "Crucible crate artifact-type lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn artifact_type_rules_reject_extra_or_missing_outputs() -> Result<(), Box<dyn Error>> {
    let plugin_without_cdylib: Value = r#"
        [package]
        name = "crucible-qemu-plugin"
        version = "0.1.0"
        edition = "2024"

        [lib]
        crate-type = ["rlib"]
    "#
    .parse()?;
    let library_with_cdylib: Value = r#"
        [package]
        name = "crucible-session"
        version = "0.1.0"
        edition = "2024"

        [lib]
        crate-type = ["rlib", "cdylib"]
    "#
    .parse()?;
    let cli_with_extra_bin: Value = r#"
        [package]
        name = "crucible-cli"
        version = "0.1.0"
        edition = "2024"

        [[bin]]
        name = "crucible"
        path = "src/main.rs"

        [[bin]]
        name = "crucible-debug"
        path = "src/bin/debug.rs"
    "#
    .parse()?;
    let guest_with_extra_bin: Value = r#"
        [package]
        name = "crucible-guest"
        version = "0.1.0"
        edition = "2024"

        [[bin]]
        name = "crucible-guest"
        path = "src/main.rs"

        [[bin]]
        name = "crucible-guest-debug"
        path = "src/bin/debug.rs"
    "#
    .parse()?;
    let library_manifest: Value = r#"
        [package]
        name = "crucible-api"
        version = "0.1.0"
        edition = "2024"
    "#
    .parse()?;

    let plugin_findings = artifact_type_failures(
        &ArtifactSpec {
            package: "crucible-qemu-plugin",
            expected: ExpectedArtifact::CdylibPlugin,
        },
        &plugin_without_cdylib,
        &PackageLayout::library(),
    );
    assert!(
        contains_finding(&plugin_findings, "must declare exactly [\"cdylib\"]"),
        "plugin without exact cdylib should be rejected: {plugin_findings:?}"
    );

    let library_findings = artifact_type_failures(
        &ArtifactSpec {
            package: "crucible-session",
            expected: ExpectedArtifact::Library,
        },
        &library_with_cdylib,
        &PackageLayout::library(),
    );
    assert!(
        contains_finding(&library_findings, "forbidden crate-type"),
        "non-plugin cdylib should be rejected: {library_findings:?}"
    );

    let cli_findings = artifact_type_failures(
        &ArtifactSpec {
            package: "crucible-cli",
            expected: ExpectedArtifact::CliBinary,
        },
        &cli_with_extra_bin,
        &PackageLayout::cli(),
    );
    assert!(
        contains_finding(&cli_findings, "exactly one [[bin]]"),
        "extra CLI binary target should be rejected: {cli_findings:?}"
    );

    let guest_findings = artifact_type_failures(
        &ArtifactSpec {
            package: "crucible-guest",
            expected: ExpectedArtifact::GuestEmitter,
        },
        &guest_with_extra_bin,
        &PackageLayout::guest_emitter(),
    );
    assert!(
        contains_finding(&guest_findings, "exactly one [[bin]]"),
        "extra guest emitter binary target should be rejected: {guest_findings:?}"
    );

    let cas_with_extra_bin: Value = r#"
        [package]
        name = "crucible-cas"
        version = "0.1.0"
        edition = "2024"

        [[bin]]
        name = "crucible-fleet-store"
        path = "src/bin/crucible-fleet-store.rs"

        [[bin]]
        name = "crucible-fleet-store-debug"
        path = "src/bin/debug.rs"
    "#
    .parse()?;
    let cas_findings = artifact_type_failures(
        &ArtifactSpec {
            package: "crucible-cas",
            expected: ExpectedArtifact::FleetStoreBinary,
        },
        &cas_with_extra_bin,
        &PackageLayout::fleet_store(),
    );
    assert!(
        contains_finding(&cas_findings, "exactly one [[bin]]"),
        "extra fleet-store binary target should be rejected: {cas_findings:?}"
    );

    let implicit_bin_findings = artifact_type_failures(
        &ArtifactSpec {
            package: "crucible-api",
            expected: ExpectedArtifact::Library,
        },
        &library_manifest,
        &PackageLayout {
            has_lib_rs: true,
            has_main_rs: true,
            has_src_bin_dir: false,
        },
    );
    assert!(
        contains_finding(&implicit_bin_findings, "implicit binary target"),
        "library src/main.rs should be rejected: {implicit_bin_findings:?}"
    );

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PackageLayout {
    has_lib_rs: bool,
    has_main_rs: bool,
    has_src_bin_dir: bool,
}

impl PackageLayout {
    fn from_package_dir(package_dir: &Path) -> Self {
        let src_dir = package_dir.join("src");
        Self {
            has_lib_rs: src_dir.join("lib.rs").is_file(),
            has_main_rs: src_dir.join("main.rs").is_file(),
            has_src_bin_dir: src_dir.join("bin").is_dir(),
        }
    }

    fn library() -> Self {
        Self {
            has_lib_rs: true,
            has_main_rs: false,
            has_src_bin_dir: false,
        }
    }

    fn cli() -> Self {
        Self {
            has_lib_rs: false,
            has_main_rs: true,
            has_src_bin_dir: false,
        }
    }

    fn guest_emitter() -> Self {
        Self {
            has_lib_rs: true,
            has_main_rs: true,
            has_src_bin_dir: false,
        }
    }

    fn fleet_store() -> Self {
        Self {
            has_lib_rs: true,
            has_main_rs: false,
            has_src_bin_dir: true,
        }
    }
}

fn artifact_type_failures(
    spec: &ArtifactSpec,
    manifest: &Value,
    layout: &PackageLayout,
) -> Vec<String> {
    let mut failures = Vec::new();
    let package = manifest_package_name(manifest).unwrap_or("<missing package.name>");

    if package != spec.package {
        failures.push(format!(
            "{}: manifest package.name must be `{}`",
            spec.package, spec.package
        ));
    }

    match spec.expected {
        ExpectedArtifact::CdylibPlugin => {
            let crate_types = lib_crate_types(manifest);
            if crate_types != ["cdylib"] {
                failures.push(format!(
                    "{}: plugin must declare exactly [\"cdylib\"] in [lib].crate-type, found {:?}",
                    spec.package, crate_types
                ));
            }
            if !declares_or_implies_lib_target(manifest, layout) {
                failures.push(format!(
                    "{}: plugin must expose a library target",
                    spec.package
                ));
            }
            forbid_binary_targets(spec.package, manifest, layout, &mut failures);
        }
        ExpectedArtifact::CliBinary => {
            let bins = bin_targets(manifest);
            if bins.len() != 1 {
                failures.push(format!(
                    "{}: CLI must declare exactly one [[bin]] target, found {}",
                    spec.package,
                    bins.len()
                ));
            } else {
                let bin = &bins[0];
                if bin.name.as_deref() != Some("crucible") {
                    failures.push(format!(
                        "{}: CLI [[bin]] name must be `crucible`, found {:?}",
                        spec.package, bin.name
                    ));
                }
                if bin.path.as_deref() != Some("src/main.rs") {
                    failures.push(format!(
                        "{}: CLI [[bin]] path must be `src/main.rs`, found {:?}",
                        spec.package, bin.path
                    ));
                }
            }
            if !layout.has_main_rs {
                failures.push(format!(
                    "{}: CLI target must have src/main.rs",
                    spec.package
                ));
            }
            if declares_or_implies_lib_target(manifest, layout) {
                failures.push(format!(
                    "{}: CLI must not expose a library target",
                    spec.package
                ));
            }
            if layout.has_src_bin_dir {
                failures.push(format!(
                    "{}: CLI must not add extra implicit binary targets under src/bin",
                    spec.package
                ));
            }
        }
        ExpectedArtifact::DebugGatewayBinary => {
            if !declares_or_implies_lib_target(manifest, layout) {
                failures.push(format!(
                    "{}: debug gateway must expose its gateway library target",
                    spec.package
                ));
            }
            for crate_type in lib_crate_types(manifest) {
                if !matches!(crate_type.as_str(), "lib" | "rlib") {
                    failures.push(format!(
                        "{}: forbidden crate-type `{}` for debug gateway library target",
                        spec.package, crate_type
                    ));
                }
            }
            let bins = bin_targets(manifest);
            if bins.len() != 1 {
                failures.push(format!(
                    "{}: debug gateway must declare exactly one [[bin]] target, found {}",
                    spec.package,
                    bins.len()
                ));
            } else {
                let bin = &bins[0];
                if bin.name.as_deref() != Some("crucible-debug-gateway") {
                    failures.push(format!(
                        "{}: debug gateway [[bin]] name must be `crucible-debug-gateway`, found {:?}",
                        spec.package, bin.name
                    ));
                }
                if bin.path.as_deref() != Some("src/main.rs") {
                    failures.push(format!(
                        "{}: debug gateway [[bin]] path must be `src/main.rs`, found {:?}",
                        spec.package, bin.path
                    ));
                }
            }
            if !layout.has_main_rs {
                failures.push(format!(
                    "{}: debug gateway target must have src/main.rs",
                    spec.package
                ));
            }
            if layout.has_src_bin_dir {
                failures.push(format!(
                    "{}: debug gateway must not add extra implicit binary targets under src/bin",
                    spec.package
                ));
            }
        }
        ExpectedArtifact::FleetStoreBinary => {
            if !declares_or_implies_lib_target(manifest, layout) {
                failures.push(format!(
                    "{}: fleet-store package must expose a library target",
                    spec.package
                ));
            }
            for crate_type in lib_crate_types(manifest) {
                if !matches!(crate_type.as_str(), "lib" | "rlib") {
                    failures.push(format!(
                        "{}: forbidden crate-type `{}` for fleet-store library target",
                        spec.package, crate_type
                    ));
                }
            }

            let bins = bin_targets(manifest);
            if bins.len() != 1 {
                failures.push(format!(
                    "{}: fleet-store package must declare exactly one [[bin]] target, found {}",
                    spec.package,
                    bins.len()
                ));
            } else {
                let bin = &bins[0];
                if bin.name.as_deref() != Some("crucible-fleet-store") {
                    failures.push(format!(
                        "{}: fleet-store [[bin]] name must be `crucible-fleet-store`, found {:?}",
                        spec.package, bin.name
                    ));
                }
                if bin.path.as_deref() != Some("src/bin/crucible-fleet-store.rs") {
                    failures.push(format!(
                        "{}: fleet-store [[bin]] path must be `src/bin/crucible-fleet-store.rs`, found {:?}",
                        spec.package, bin.path
                    ));
                }
            }
            if layout.has_main_rs {
                failures.push(format!(
                    "{}: fleet-store package must not have an implicit binary target at src/main.rs",
                    spec.package
                ));
            }
            if !layout.has_src_bin_dir {
                failures.push(format!(
                    "{}: fleet-store package must keep its binary under src/bin",
                    spec.package
                ));
            }
        }
        ExpectedArtifact::GuestEmitter => {
            if !declares_or_implies_lib_target(manifest, layout) {
                failures.push(format!(
                    "{}: guest emitter must expose a library target",
                    spec.package
                ));
            }
            for crate_type in lib_crate_types(manifest) {
                if !matches!(crate_type.as_str(), "lib" | "rlib") {
                    failures.push(format!(
                        "{}: forbidden crate-type `{}` for guest emitter library target",
                        spec.package, crate_type
                    ));
                }
            }

            let bins = bin_targets(manifest);
            if bins.len() != 1 {
                failures.push(format!(
                    "{}: guest emitter must declare exactly one [[bin]] target, found {}",
                    spec.package,
                    bins.len()
                ));
            } else {
                let bin = &bins[0];
                if bin.name.as_deref() != Some("crucible-guest") {
                    failures.push(format!(
                        "{}: guest emitter [[bin]] name must be `crucible-guest`, found {:?}",
                        spec.package, bin.name
                    ));
                }
                if bin.path.as_deref() != Some("src/main.rs") {
                    failures.push(format!(
                        "{}: guest emitter [[bin]] path must be `src/main.rs`, found {:?}",
                        spec.package, bin.path
                    ));
                }
            }
            if !layout.has_main_rs {
                failures.push(format!(
                    "{}: guest emitter target must have src/main.rs",
                    spec.package
                ));
            }
            if layout.has_src_bin_dir {
                failures.push(format!(
                    "{}: guest emitter must not add extra implicit binary targets under src/bin",
                    spec.package
                ));
            }
        }
        ExpectedArtifact::Library => {
            if !declares_or_implies_lib_target(manifest, layout) {
                failures.push(format!(
                    "{}: package must expose a library target",
                    spec.package
                ));
            }
            for crate_type in lib_crate_types(manifest) {
                if !matches!(crate_type.as_str(), "lib" | "rlib") {
                    failures.push(format!(
                        "{}: forbidden crate-type `{}` for library package",
                        spec.package, crate_type
                    ));
                }
            }
            forbid_binary_targets(spec.package, manifest, layout, &mut failures);
        }
    }

    failures
}

fn manifest_package_name(manifest: &Value) -> Option<&str> {
    manifest
        .get("package")
        .and_then(Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(Value::as_str)
}

fn declares_or_implies_lib_target(manifest: &Value, layout: &PackageLayout) -> bool {
    manifest.get("lib").is_some() || layout.has_lib_rs
}

fn lib_crate_types(manifest: &Value) -> Vec<String> {
    manifest
        .get("lib")
        .and_then(Value::as_table)
        .and_then(|lib| lib.get("crate-type"))
        .and_then(Value::as_array)
        .map(|crate_types| {
            crate_types
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BinTarget {
    name: Option<String>,
    path: Option<String>,
}

fn bin_targets(manifest: &Value) -> Vec<BinTarget> {
    manifest
        .get("bin")
        .and_then(Value::as_array)
        .map(|bins| {
            bins.iter()
                .filter_map(Value::as_table)
                .map(|bin| BinTarget {
                    name: bin.get("name").and_then(Value::as_str).map(str::to_owned),
                    path: bin.get("path").and_then(Value::as_str).map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn forbid_binary_targets(
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

fn contains_finding(findings: &[String], needle: &str) -> bool {
    findings.iter().any(|finding| finding.contains(needle))
}

fn workspace_crates_dir() -> Result<PathBuf, io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("crucible-harness manifest is not inside crates/"))
}

fn assert_expected_crucible_package_set(
    crates_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let mut expected: Vec<String> = ARTIFACT_SPECS
        .iter()
        .map(|spec| spec.package.to_string())
        .collect();
    expected.sort();

    let mut found = Vec::new();
    for entry in fs::read_dir(crates_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("Cargo.toml").is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("crucible") {
            found.push(name);
        }
    }
    found.sort();

    if found != expected {
        failures.push(format!(
            "crucible package set mismatch: expected [{}], found [{}]",
            expected.join(", "),
            found.join(", ")
        ));
    }

    Ok(())
}
