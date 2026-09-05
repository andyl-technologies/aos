//! Tests for package documentation derivation, runtime surface descriptions, and publication.

use super::{documented_option_declarations, exposed_unit_description};
use crate::registry_ops::attestation::documentation_nar_identity;
use crate::registry_ops::test_support::documentation_declaration;
use aos_doc_model::Visibility;
use std::fs;
use tempfile::TempDir;

#[test]
fn package_documentation_excludes_internal_module_plumbing() {
    let declarations = [
        documentation_declaration("nginx.enable", Visibility::Public),
        documentation_declaration("nginx._aosExposeConfigProjection", Visibility::Internal),
    ];

    let paths = documented_option_declarations(&declarations)
        .map(|declaration| declaration.path_str.as_str())
        .collect::<Vec<_>>();

    assert_eq!(paths, ["nginx.enable"]);
}

#[test]
fn package_documentation_preserves_the_nar_byte_identity() {
    let expected = format!("sha256:{}", "0".repeat(64));
    assert_eq!(documentation_nar_identity(&expected).unwrap(), expected);

    let sri = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(documentation_nar_identity(sri).unwrap(), expected);

    let nix_base32 = format!("sha256:{}", "0".repeat(52));
    assert_eq!(documentation_nar_identity(&nix_base32).unwrap(), expected);
}

#[test]
fn package_documentation_extracts_exposed_unit_descriptions() {
    let expose = TempDir::new().unwrap();
    fs::create_dir(expose.path().join("units")).unwrap();
    fs::write(
        expose.path().join("units/example.service"),
        "[Unit]\nDescription=Example workload service\n\n[Service]\nExecStart=/bin/true\n",
    )
    .unwrap();

    assert_eq!(
        exposed_unit_description(expose.path().to_str().unwrap(), "example.service").unwrap(),
        "Example workload service"
    );
}

#[cfg(unix)]
#[test]
fn package_documentation_accepts_only_store_owned_unit_symlinks() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    let store = root.path().join("nix/store");
    let expose = store.join("00000000000000000000000000000000-expose");
    let unit_output = store.join("11111111111111111111111111111111-unit");
    fs::create_dir_all(expose.join("units")).unwrap();
    fs::create_dir_all(&unit_output).unwrap();
    let unit = unit_output.join("example.service");
    fs::write(&unit, "[Unit]\nDescription=Store-owned unit\n").unwrap();
    symlink(&unit, expose.join("units/example.service")).unwrap();

    assert_eq!(
        exposed_unit_description(expose.to_str().unwrap(), "example.service").unwrap(),
        "Store-owned unit"
    );

    fs::remove_file(expose.join("units/example.service")).unwrap();
    symlink("/etc/passwd", expose.join("units/example.service")).unwrap();
    assert!(
        exposed_unit_description(expose.to_str().unwrap(), "example.service")
            .unwrap_err()
            .to_string()
            .contains("same unit from one direct store object")
    );
}

#[test]
fn package_documentation_rejects_undocumented_or_oversized_units() {
    let expose = TempDir::new().unwrap();
    fs::create_dir(expose.path().join("units")).unwrap();
    fs::write(
        expose.path().join("units/missing.service"),
        "[Unit]\nAfter=network.target\n",
    )
    .unwrap();
    assert!(
        exposed_unit_description(expose.path().to_str().unwrap(), "missing.service")
            .unwrap_err()
            .to_string()
            .contains("has no non-empty [Unit] Description")
    );

    fs::write(
        expose.path().join("units/large.service"),
        vec![b'x'; 1024 * 1024 + 1],
    )
    .unwrap();
    assert!(
        exposed_unit_description(expose.path().to_str().unwrap(), "large.service")
            .unwrap_err()
            .to_string()
            .contains("exceeds 1048576 bytes")
    );
}
