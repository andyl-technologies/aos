//! Guards the intentionally narrow and production-inert public surface.

const CRATE_MANIFEST: &str = include_str!("../Cargo.toml");
const ENDPOINT_SOURCE: &str = include_str!("../src/endpoint.rs");
const LIBRARY_SOURCE: &str = include_str!("../src/lib.rs");

#[test]
fn dependency_boundary_has_no_forbidden_convenience_layer() {
    for forbidden in [
        "\nrand =",
        "\nrand_core =",
        "\ngetrandom =",
        "\nserde =",
        "buffa",
        "journal",
        "aos-sandbox-protocol",
    ] {
        assert!(
            !CRATE_MANIFEST.contains(forbidden),
            "forbidden dependency marker: {forbidden}"
        );
    }
}

#[test]
fn endpoint_surface_exposes_no_signer_or_scalar_escape_hatch() {
    for forbidden in [
        "pub fn sign",
        "pub fn signing_key",
        "pub fn seed",
        "pub fn descriptor",
        "pub fn from_bytes",
        "pub fn as_bytes",
        "pub fn verification_context",
        "pub fn session_binding",
        "pub fn with_rng",
        "pub fn with_uid",
    ] {
        assert!(
            !ENDPOINT_SOURCE.contains(forbidden),
            "forbidden public API marker: {forbidden}"
        );
    }

    assert!(!LIBRARY_SOURCE.contains("pub mod self_execution"));
    assert!(!LIBRARY_SOURCE.contains("pub use self_execution"));
}

#[test]
fn production_brokers_do_not_depend_on_the_inert_crate() {
    for manifest in [
        include_str!("../../aos-sandbox/Cargo.toml"),
        include_str!("../../aos-sandbox-host/Cargo.toml"),
        include_str!("../../aos-sandbox-storage/Cargo.toml"),
        include_str!("../../aos-sandbox-mount/Cargo.toml"),
        include_str!("../../aos-sandbox-network/Cargo.toml"),
        include_str!("../../aos-sandbox-protocol/Cargo.toml"),
    ] {
        assert!(!manifest.contains("aos-sandbox-broker-session-security"));
    }
}
