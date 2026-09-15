//! Tests for package documentation derivation, runtime surface descriptions, and publication.

use super::documented_option_declarations;
use crate::registry_ops::attestation::documentation_nar_identity;
use crate::registry_ops::test_support::documentation_declaration;
use aos_doc_model::Visibility;

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
