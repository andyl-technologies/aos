//! Workspace-wide unsafe-placement policy tests.
//!
//! The flat-value campaign sanctions four hand-written unsafe zones. Every
//! other crate root must forbid unsafe Rust, except `aos-proto`, whose private
//! Buffa-generated module has one token-counted scoped exception.

use std::{fs, path::Path};

const SANCTIONED_UNSAFE_CRATES: &[&str] = &[
    "ratchet-cache",
    "ratchet-jit",
    "ratchet-runtime-ffi",
    "ratchet-value",
];
const GENERATED_UNSAFE_EXCEPTION_CRATE: &str = "aos-proto";
const FORBID_UNSAFE: &str = "#![forbid(unsafe_code)]";
const DENY_UNSAFE: &str = "#![deny(unsafe_code)]";
const DENY_UNSAFE_OPERATIONS: &str = "#![deny(unsafe_op_in_unsafe_fn)]";
const ALLOW_UNSAFE: &str = "#[allow(unsafe_code)]";

#[test]
fn workspace_crate_roots_enforce_the_unsafe_zone_set() {
    let crates_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ratchet-core lives below the workspace crates directory");
    let mut observed_sanctioned = Vec::new();
    let mut observed_crates = Vec::new();

    for entry in fs::read_dir(crates_root).expect("workspace crates directory is readable") {
        let path = entry.expect("workspace crate entry is readable").path();
        if !path.join("Cargo.toml").is_file() {
            continue;
        }
        let Some(crate_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(crate_root) = crate_root(&path) else {
            continue;
        };
        let source = fs::read_to_string(&crate_root).expect("workspace crate root is readable");
        observed_crates.push(crate_name.to_owned());

        if SANCTIONED_UNSAFE_CRATES.contains(&crate_name) {
            assert!(
                source.contains(DENY_UNSAFE_OPERATIONS),
                "{crate_name} must deny unsafe operations inside unsafe functions"
            );
            assert!(
                !source.contains(FORBID_UNSAFE),
                "{crate_name} is sanctioned and must retain its audited unsafe boundary"
            );
            observed_sanctioned.push(crate_name.to_owned());
        } else if crate_name == GENERATED_UNSAFE_EXCEPTION_CRATE {
            assert!(
                source.contains(DENY_UNSAFE),
                "{crate_name} must deny unsafe code outside generated output"
            );
            assert_eq!(
                source.matches(ALLOW_UNSAFE).count(),
                1,
                "{crate_name} must have exactly one generated-code exception"
            );
            assert!(
                source.contains("pub mod safety;"),
                "{crate_name} must expose its generated unsafe manifest"
            );
        } else {
            assert!(
                source.contains(FORBID_UNSAFE),
                "{crate_name} must forbid unsafe code"
            );
        }
    }

    observed_sanctioned.sort();
    let mut expected_sanctioned: Vec<_> = SANCTIONED_UNSAFE_CRATES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    expected_sanctioned.sort();
    assert_eq!(
        observed_sanctioned, expected_sanctioned,
        "workspace sanctioned unsafe-zone set changed"
    );

    observed_crates.sort();
    assert!(
        observed_crates.contains(&String::from("aos"))
            && observed_crates.contains(&String::from("ratchet-oracle")),
        "workspace crate discovery missed required safe roots"
    );
}

fn crate_root(crate_dir: &Path) -> Option<std::path::PathBuf> {
    let library = crate_dir.join("src/lib.rs");
    if library.is_file() {
        return Some(library);
    }
    let binary = crate_dir.join("src/main.rs");
    binary.is_file().then_some(binary)
}
