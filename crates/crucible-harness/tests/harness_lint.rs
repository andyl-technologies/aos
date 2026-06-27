//! Runs the reduction-path static determinism lint.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::spec_index::crate_spec_index;
use toml::Value;

#[path = "support/harness_lint/allow.rs"]
mod allow;
#[path = "support/harness_lint/clippy.rs"]
mod clippy;
#[path = "support/harness_lint/common.rs"]
mod common;
#[path = "support/harness_lint/confinement.rs"]
mod confinement;
#[path = "support/harness_lint/error_logging.rs"]
mod error_logging;
#[path = "support/harness_lint/lex.rs"]
mod lex;
#[path = "support/harness_lint/scan.rs"]
mod scan;

use allow::*;
use clippy::*;
use common::*;
use confinement::*;
use error_logging::*;
use lex::*;
use scan::*;

#[test]
fn reduction_path_sources_have_no_banned_nondeterminism() -> Result<(), Box<dyn Error>> {
    let mut findings = Vec::new();
    for package in REDUCTION_PATH_PACKAGES {
        let src_dir = workspace_root().join(package).join("src");
        for source in rust_sources(&src_dir)? {
            let content = fs::read_to_string(&source)?;
            findings.extend(scan_content(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn host_boundary_nondeterminism_is_confined_from_state() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let workspace_manifest: Value = fs::read_to_string(root.join("Cargo.toml"))?.parse()?;
    let workspace_dependencies = workspace_dependency_table(&workspace_manifest);
    let findings = workspace_confinement_findings(&root, &workspace_dependencies)?;

    assert!(
        findings.is_empty(),
        "host-boundary nondeterminism confinement findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn production_sources_follow_error_and_logging_conventions() -> Result<(), Box<dyn Error>> {
    let mut findings = Vec::new();
    let root = workspace_root();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        let manifest = fs::read_to_string(package_dir.join("Cargo.toml"))?;
        let is_library = spec.package != BINARY_BOUNDARY_PACKAGE;
        let mut has_typed_error =
            !is_library || manifest_declares_dependency(&manifest, "thiserror");

        findings.extend(manifest_error_dependency_failures(
            spec.package,
            &manifest,
            is_library,
        ));

        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            has_typed_error |= source_declares_typed_error(&content);
            findings.extend(error_logging_failures(
                &source,
                &content,
                is_binary_boundary_source(spec.package, &package_dir, &source),
            ));
        }

        if !has_typed_error {
            findings.push(missing_typed_error_finding(spec.package));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint error/logging findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn clippy_tier_is_checked_in_and_wired() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let repo = repo_root();
    let workspace_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let clippy_config = fs::read_to_string(root.join("clippy.toml"))?;
    let crucible_package = fs::read_to_string(repo.join("pkgs/tools/crucible/crucible.nix"))?;
    let mut package_manifests = Vec::new();

    for spec in crate_spec_index() {
        let manifest = fs::read_to_string(root.join(spec.package).join("Cargo.toml"))?;
        package_manifests.push((spec.package, manifest));
    }

    let findings = clippy_tier_failures(
        &workspace_manifest,
        &clippy_config,
        &package_manifests,
        &crucible_package,
    );

    assert!(
        findings.is_empty(),
        "gate:harness-lint clippy tier findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn custom_static_analysis_tier_runs_over_crucible_sources() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut findings = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            findings.extend(custom_static_analysis_failures(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint custom static-analysis findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn allow_annotations_are_checked_for_all_crucible_targets() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut findings = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        for source in rust_sources(&package_dir)? {
            let content = fs::read_to_string(&source)?;
            findings.extend(allow_annotation_failures(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint allow-annotation findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn harness_lint_rejects_banned_code_patterns() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                let _ = std::time::SystemTime::now();
                let _ = rand::thread_rng();
                let _ = std::collections::HashMap::<u8, u8>::new();
                let _ = std::collections::hash_map::DefaultHasher::new();
                tokio::select! { _ = async {} => {} }
            }
        "#,
    );

    assert_contains(&findings, "host wall-clock");
    assert_contains(&findings, "thread/global RNG");
    assert_contains(&findings, "unordered map/set");
    assert_contains(&findings, "default/random hasher");
    assert_contains(&findings, "nondeterministic select");
}

#[test]
fn harness_lint_rejects_host_boundary_state_leaks() -> Result<(), Box<dyn Error>> {
    let failures = confinement_regression_failures()?;
    assert!(
        failures.is_empty(),
        "harness-lint confinement regression failures:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn harness_lint_rejects_spaced_paths_and_grouped_imports() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::hash_map::{DefaultHasher, RandomState};
            use std::collections::{HashMap, HashSet};
            use std::time::{Instant, SystemTime};

            fn bad() {
                let _ = HashMap :: <u8, u8> :: new();
                let _ = HashSet :: <u8> :: new();
                let _ = DefaultHasher :: new();
                let _ = RandomState :: new();
                let _ = SystemTime :: now();
                let _ = Instant :: now();
                rand :: thread_rng();
                rand :: rng();
                tokio::select ! { _ = async {} => {} }
            }
        "#,
    );

    assert_contains(&findings, "host wall-clock");
    assert_contains(&findings, "host monotonic time");
    assert_contains(&findings, "thread/global RNG");
    assert_contains(&findings, "unordered map/set");
    assert_contains(&findings, "default/random hasher");
    assert_contains(&findings, "nondeterministic select");
}

#[test]
fn harness_lint_ignores_comments_and_strings() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r##"
            //! std::time::SystemTime::now()
            // rand::thread_rng()
            /*
              std::collections::HashMap::<u8, u8>::new()
            */
            /*
              /*
                rand::thread_rng()
              */
            */
            const TEXT: &str = "tokio::select!";
            const RAW: &str = r#"SystemTime::now and thread_rng()"#;
            const LIFE: &'static str = "lifetimes are not char literals";
        "##,
    );

    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn harness_lint_rejects_error_and_logging_drift() {
    let library_findings = error_logging_failures(
        Path::new("crucible-sim/src/lib.rs"),
        r#"
            pub fn bad() -> Result<(), Box<dyn Error>> {
                let value = maybe().unwrap();
                let other = maybe().expect /* comment */ ("value exists");
                println!("library diagnostic");
                eprintln!("library diagnostic");
                print!("library diagnostic");
                anyhow::bail!("erased error");
            }
        "#,
        false,
    );

    assert_contains(&library_findings, "panic shortcut");
    assert_contains(&library_findings, "direct stdout/stderr diagnostic");
    assert_contains(&library_findings, "erased error");

    let binary_findings = error_logging_failures(
        Path::new("crucible-cli/src/main.rs"),
        r#"
            fn main() -> anyhow::Result<()> {
                println!("cli output is allowed");
                Ok(())
            }
        "#,
        true,
    );

    assert!(binary_findings.is_empty(), "{binary_findings:?}");

    let cli_module_findings = error_logging_failures(
        Path::new("crucible-cli/src/command.rs"),
        r#"
            pub fn command() -> anyhow::Result<()> {
                println!("command module output crosses the binary boundary");
                Ok(())
            }
        "#,
        false,
    );

    assert_contains(&cli_module_findings, "direct stdout/stderr diagnostic");
    assert_contains(&cli_module_findings, "erased error");
}

#[test]
fn harness_lint_rejects_erased_error_dependencies_in_libraries() {
    let findings = manifest_error_dependency_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
            thiserror = { workspace = true }
            anyhow = { workspace = true }
        "#,
        true,
    );

    assert_contains(&findings, "erased error dependency");

    let cli_findings = manifest_error_dependency_failures(
        "crucible-cli",
        r#"
            [package]
            name = "crucible-cli"

            [dependencies]
            anyhow = { workspace = true }
        "#,
        false,
    );

    assert!(cli_findings.is_empty(), "{cli_findings:?}");
}

#[test]
fn harness_lint_rejects_missing_typed_error_signal_in_libraries() {
    let findings = typed_error_policy_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
        "#,
        &[],
        true,
    );

    assert_contains(&findings, "missing typed error");

    let thiserror_findings = typed_error_policy_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
            thiserror = { workspace = true }
        "#,
        &[],
        true,
    );

    assert!(thiserror_findings.is_empty(), "{thiserror_findings:?}");

    let hand_rolled_findings = typed_error_policy_failures(
        "crucible-harness",
        r#"
            [package]
            name = "crucible-harness"

            [dependencies]
        "#,
        &[r#"
            use std::error::Error;

            pub struct HarnessError;

            impl Error for HarnessError {}
        "#],
        true,
    );

    assert!(hand_rolled_findings.is_empty(), "{hand_rolled_findings:?}");

    let cli_findings = typed_error_policy_failures(
        "crucible-cli",
        r#"
            [package]
            name = "crucible-cli"

            [dependencies]
            anyhow = { workspace = true }
        "#,
        &[],
        false,
    );

    assert!(cli_findings.is_empty(), "{cli_findings:?}");
}

#[test]
fn harness_lint_rejects_clippy_tier_drift() {
    let package_manifests = [(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"
        "#
        .to_owned(),
    )];
    let findings = clippy_tier_failures(
        r#"
            [workspace.lints.clippy]
            all = "warn"
            disallowed_methods = "deny"
        "#,
        r#"
            disallowed-methods = []
            disallowed-types = []
        "#,
        &package_manifests,
        "",
    );

    assert_contains(&findings, "workspace clippy deny");
    assert_contains(&findings, "disallowed method");
    assert_contains(&findings, "disallowed type");
    assert_contains(&findings, "workspace lint inheritance");
    assert_contains(&findings, "clippy gate wiring");
}

#[test]
fn harness_lint_rejects_custom_static_analysis_drift() {
    let findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::HashMap;

            fn bad() {
                let map: HashMap<u8, u8> = HashMap::new();
                for item in map.iter() {
                    consume(item);
                }
                let _ = std::collections::hash_map::DefaultHasher::new();
                let _ = map.keys();
                let _ = map.values_mut();
                let _ = map.into_values();
                tokio::select! { _ = async {} => {} }
                unsafe {
                    core::ptr::read_volatile(core::ptr::null::<u8>());
                }
            }
        "#,
    );

    assert_contains(&findings, "unordered hash-container iteration");
    assert_contains(&findings, "default/random hasher");
    assert_contains(&findings, "unordered select");
    assert_contains(&findings, "bare unsafe block");

    let stale_safety_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                // SAFETY: stale comment is separated from the unsafe block.

                unsafe {}
                // SAFETY: this applies only to the next unsafe block.
                unsafe {}
                unsafe {}
            }
        "#,
    );

    assert!(
        stale_safety_findings.len() >= 2,
        "expected stale and missing SAFETY comments to be rejected, got {stale_safety_findings:?}"
    );

    let allowed_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::BTreeMap;

            fn allowed() {
                let map: BTreeMap<u8, u8> = BTreeMap::new();
                for item in map.iter() {
                    consume(item);
                }
                tokio::select! {
                    biased;
                    _ = async {} => {}
                }
                // SAFETY: synthetic volatile read is isolated to test the marker.
                unsafe {
                    core::ptr::read_volatile(core::ptr::null::<u8>());
                }
            }
        "#,
    );

    assert!(
        allowed_findings.is_empty(),
        "expected deterministic custom tier sample to pass, got {allowed_findings:?}"
    );
}
