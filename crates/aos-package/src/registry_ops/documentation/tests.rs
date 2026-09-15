//! Tests for package documentation identity and publication.

use crate::registry_ops::attestation::documentation_nar_identity;

#[test]
fn package_documentation_preserves_the_nar_byte_identity() {
    let expected = format!("sha256:{}", "0".repeat(64));
    assert_eq!(documentation_nar_identity(&expected).unwrap(), expected);

    let sri = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(documentation_nar_identity(sri).unwrap(), expected);

    let nix_base32 = format!("sha256:{}", "0".repeat(52));
    assert_eq!(documentation_nar_identity(&nix_base32).unwrap(), expected);
}
