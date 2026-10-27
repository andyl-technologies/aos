//! Checks product artifact roles directly from declared Bazel Rust targets.
//!
//! Feature variants share a logical artifact only when kind, crate name, and
//! source root agree. Explicit example binaries keep their declared roots;
//! they do not become installed product commands through name-based guesses.

use super::architecture::{Architecture, CompilationTarget};
use super::{ARTIFACT_SPECS, ArtifactSpec, ExpectedArtifact, PackageLayout};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

/// Checks each Crucible package's declared products and source layout.
///
/// # Errors
///
/// Returns an error for absent package ownership or artifact metadata.
pub(super) fn artifact_failures(
    graph: &Architecture,
    source_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let expected = ARTIFACT_SPECS
        .iter()
        .map(|spec| spec.package)
        .collect::<BTreeSet<_>>();
    let found = graph
        .package_names()
        .filter(|name| name.starts_with("crucible"))
        .collect::<BTreeSet<_>>();
    let mut failures = Vec::new();
    if found != expected {
        failures.push(format!(
            "crucible package set mismatch: expected {expected:?}, found {found:?}"
        ));
    }

    for spec in ARTIFACT_SPECS {
        let directory = source_root.join(graph.package_directory(spec.package)?);
        let layout = PackageLayout::from_package_dir(&directory);
        let targets = graph.compilation_targets(spec.package)?.collect::<Vec<_>>();
        failures.extend(surface_failures(spec, &targets, &layout));
        for (_, target) in targets {
            for root in &target.crate_roots {
                if !directory.join(root).is_file() {
                    failures.push(format!(
                        "{}: missing declared artifact root {root}",
                        spec.package
                    ));
                }
            }
        }
    }
    Ok(failures)
}

fn surface_failures(
    spec: &ArtifactSpec,
    targets: &[(&str, &CompilationTarget)],
    layout: &PackageLayout,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut products = BTreeSet::new();
    let mut production = BTreeSet::new();
    let mut oracles = Vec::new();
    for (label, target) in targets {
        for root in &target.crate_roots {
            if target.kind == "rust_binary" && root.starts_with("examples/") {
                continue;
            }
            if target.test_only
                && target.kind == "rust_library"
                && spec.package != "crucible-test-support"
            {
                continue;
            }
            if spec.package == "crucible-control-server" && target.kind == "rust_binary" {
                oracles.push((*label, target, root));
                continue;
            }
            let artifact = (
                target.kind.as_str(),
                root.as_str(),
                target.crate_name.as_str(),
            );
            products.insert(artifact);
            if !target.test_only || spec.package == "crucible-test-support" {
                production.insert(artifact);
            }
        }
    }

    let library = spec.package.replace('-', "_");
    let mut expected = BTreeSet::new();
    if spec.expected != ExpectedArtifact::CliBinary {
        let kind = if spec.expected == ExpectedArtifact::CdylibPlugin {
            "rust_shared_library"
        } else {
            "rust_library"
        };
        expected.insert((kind, "src/lib.rs", library.as_str()));
    }
    match spec.expected {
        ExpectedArtifact::CliBinary => {
            expected.insert(("rust_binary", "src/main.rs", "crucible"));
        }
        ExpectedArtifact::DebugGatewayBinary => {
            expected.insert(("rust_binary", "src/main.rs", "crucible_debug_gateway"));
        }
        ExpectedArtifact::GuestEmitter => {
            expected.insert(("rust_binary", "src/main.rs", "crucible_guest"));
        }
        ExpectedArtifact::FleetStoreBinary => {
            expected.insert((
                "rust_binary",
                "src/bin/crucible-fleet-store.rs",
                "crucible_fleet_store",
            ));
        }
        ExpectedArtifact::Library | ExpectedArtifact::CdylibPlugin => {}
    }
    if products != expected || production != expected {
        failures.push(format!(
            "{}: declared Bazel artifact surface must be {expected:?}, found {products:?} with production roots {production:?}",
            spec.package
        ));
    }

    let requires_main = matches!(
        spec.expected,
        ExpectedArtifact::CliBinary
            | ExpectedArtifact::DebugGatewayBinary
            | ExpectedArtifact::GuestEmitter
    );
    let requires_bin_directory = spec.expected == ExpectedArtifact::FleetStoreBinary
        || spec.package == "crucible-control-server";
    if layout.has_main_rs != requires_main
        || layout.has_src_bin_dir != requires_bin_directory
        || layout.has_lib_rs != (spec.expected != ExpectedArtifact::CliBinary)
    {
        failures.push(format!(
            "{}: source layout differs from its declared artifact roles",
            spec.package
        ));
    }
    if spec.package == "crucible-control-server" {
        let valid = oracles.len() == 1
            && oracles.iter().all(|(label, target, root)| {
                *label == "//crates/crucible/crucible-control-server:crucible-qemu-test-oracle"
                    && root.as_str() == "src/bin/qemu_test_oracle.rs"
                    && target.crate_name == "crucible_qemu_test_oracle"
                    && target.test_only
                    && target.tags.contains("manual")
                    && target.features.contains("qemu-test-oracle")
            });
        if !valid {
            failures.push("crucible-control-server: must declare only the manual test-only qemu-test-oracle binary with its opt-in feature".to_owned());
        }
    }
    failures
}

#[test]
fn bazel_artifact_roles_reject_extra_missing_and_wrong_kind_products() {
    let spec = ArtifactSpec {
        package: "crucible-session",
        expected: ExpectedArtifact::Library,
    };
    let mut library = CompilationTarget {
        package: spec.package.to_owned(),
        kind: "rust_library".to_owned(),
        crate_name: "crucible_session".to_owned(),
        crate_roots: BTreeSet::from(["src/lib.rs".to_owned()]),
        features: BTreeSet::new(),
        tags: BTreeSet::new(),
        test_only: false,
    };
    let label = "//crates/crucible/crucible-session:lib";
    assert!(surface_failures(&spec, &[(label, &library)], &PackageLayout::library()).is_empty());
    assert!(!surface_failures(&spec, &[], &PackageLayout::library()).is_empty());

    for kind in [
        "rust_shared_library",
        "rust_static_library",
        "rust_binary",
        "rust_proc_macro",
    ] {
        library.kind = kind.to_owned();
        assert!(
            !surface_failures(&spec, &[(label, &library)], &PackageLayout::library()).is_empty(),
            "{kind}"
        );
    }
    library.kind = "rust_library".to_owned();
    library.test_only = true;
    assert!(!surface_failures(&spec, &[(label, &library)], &PackageLayout::library()).is_empty());

    let production = CompilationTarget {
        test_only: false,
        ..library
    };
    for root in ["src/lib.rs", "examples/hidden.rs"] {
        let hidden_shared_library = CompilationTarget {
            kind: "rust_shared_library".to_owned(),
            crate_roots: BTreeSet::from([root.to_owned()]),
            test_only: true,
            package: spec.package.to_owned(),
            crate_name: "hidden".to_owned(),
            features: BTreeSet::new(),
            tags: BTreeSet::new(),
        };
        assert!(
            !surface_failures(
                &spec,
                &[
                    (label, &production),
                    (
                        "//crates/crucible/crucible-session:hidden",
                        &hidden_shared_library
                    )
                ],
                &PackageLayout::library(),
            )
            .is_empty(),
            "{root}"
        );
    }
}

#[test]
fn bazel_oracle_requires_manual_test_only_feature_gating() {
    let spec = ArtifactSpec {
        package: "crucible-control-server",
        expected: ExpectedArtifact::Library,
    };
    let library = CompilationTarget {
        package: spec.package.to_owned(),
        kind: "rust_library".to_owned(),
        crate_name: "crucible_control_server".to_owned(),
        crate_roots: BTreeSet::from(["src/lib.rs".to_owned()]),
        features: BTreeSet::new(),
        tags: BTreeSet::new(),
        test_only: false,
    };
    let mut oracle = CompilationTarget {
        package: spec.package.to_owned(),
        kind: "rust_binary".to_owned(),
        crate_name: "crucible_qemu_test_oracle".to_owned(),
        crate_roots: BTreeSet::from(["src/bin/qemu_test_oracle.rs".to_owned()]),
        features: BTreeSet::from(["qemu-test-oracle".to_owned()]),
        tags: BTreeSet::from(["manual".to_owned()]),
        test_only: true,
    };
    let label = "//crates/crucible/crucible-control-server:crucible-qemu-test-oracle";
    let layout = PackageLayout {
        has_src_bin_dir: true,
        ..PackageLayout::library()
    };
    let check = |oracle: &CompilationTarget| {
        surface_failures(
            &spec,
            &[
                ("//crates/crucible/crucible-control-server:lib", &library),
                (label, oracle),
            ],
            &layout,
        )
    };
    assert!(check(&oracle).is_empty());
    oracle.tags.clear();
    assert!(!check(&oracle).is_empty());
    oracle.tags.insert("manual".to_owned());
    oracle.test_only = false;
    assert!(!check(&oracle).is_empty());
    oracle.test_only = true;
    oracle.features.clear();
    assert!(!check(&oracle).is_empty());
}
