//! Guards the intentionally narrow and production-inert public surface.

const CRATE_MANIFEST: &str = include_str!("../Cargo.toml");
const ENDPOINT_SOURCE: &str = include_str!("../src/endpoint.rs");
const HANDSHAKE_SOURCE: &str = include_str!("../src/handshake.rs");
const TRAFFIC_PROOF_SOURCE: &str = include_str!("../src/handshake/traffic.rs");
const LIBRARY_SOURCE: &str = include_str!("../src/lib.rs");
const PROTOCOL_AUTHENTICATED_SESSION_SOURCE: &str =
    include_str!("../../aos-sandbox-protocol/src/authenticated_session.rs");
const PROTOCOL_LIBRARY_SOURCE: &str = include_str!("../../aos-sandbox-protocol/src/lib.rs");
const NETWORK_SERVICE_SOURCE: &str = include_str!("../../aos-sandbox-network/src/service.rs");

#[test]
fn dependency_boundary_uses_only_explicit_wire_and_kernel_layers() {
    for forbidden in [
        "\nrand =",
        "\nrand_core =",
        "\ngetrandom =",
        "\nserde =",
        "journal",
    ] {
        assert!(
            !CRATE_MANIFEST.contains(forbidden),
            "forbidden dependency marker: {forbidden}"
        );
    }

    // The complete method adapters own canonical protobuf traffic directly;
    // keep that wire dependency explicit instead of adding a generic codec.
    assert_eq!(CRATE_MANIFEST.matches("aos-proto.workspace").count(), 1);
    assert_eq!(CRATE_MANIFEST.matches("buffa.workspace").count(), 1);
    assert_eq!(CRATE_MANIFEST.matches("aos-sandbox-protocol").count(), 1);
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
    assert!(!LIBRARY_SOURCE.contains("pub mod handshake"));
    assert!(!LIBRARY_SOURCE.contains("pub use handshake"));

    for forbidden in [
        "pub struct",
        "pub enum",
        "pub trait",
        "pub fn",
        "AsRawFd",
        "IntoRawFd",
        "FromRawFd",
    ] {
        assert!(
            !HANDSHAKE_SOURCE.contains(forbidden),
            "private handshake escape marker: {forbidden}"
        );
        assert!(
            !TRAFFIC_PROOF_SOURCE.contains(forbidden),
            "private traffic-proof escape marker: {forbidden}"
        );
    }
}

#[test]
fn production_brokers_do_not_depend_on_the_inert_crate() {
    for manifest in [
        include_str!("../../aos-sandbox/Cargo.toml"),
        include_str!("../../aos-sandbox-broker/Cargo.toml"),
        include_str!("../../aos-sandbox-host/Cargo.toml"),
        include_str!("../../aos-sandbox-storage/Cargo.toml"),
        include_str!("../../aos-sandbox-mount/Cargo.toml"),
        include_str!("../../aos-sandbox-network/Cargo.toml"),
        include_str!("../../aos-sandbox-protocol/Cargo.toml"),
    ] {
        assert!(!manifest.contains("aos-sandbox-broker-session-security"));
    }
}

#[test]
fn expiry_retention_seam_is_narrow_and_absent_from_the_dormant_service() {
    const RESULT_NAME: &str = "SealedInitialNetworkInventoryTrafficProofAdmissionV1";
    const METHOD_NAME: &str = "admit_initial_network_inventory_traffic_proof_request";

    assert_eq!(
        PROTOCOL_AUTHENTICATED_SESSION_SOURCE
            .matches(&format!("pub enum {RESULT_NAME}"))
            .count(),
        1
    );
    assert_eq!(
        PROTOCOL_AUTHENTICATED_SESSION_SOURCE
            .matches(&format!("pub fn {METHOD_NAME}"))
            .count(),
        1
    );
    assert!(!PROTOCOL_LIBRARY_SOURCE.contains(RESULT_NAME));

    let result_surface = PROTOCOL_AUTHENTICATED_SESSION_SOURCE
        .split(&format!("pub enum {RESULT_NAME}"))
        .nth(1)
        .and_then(|suffix| {
            suffix
                .split("/// Selects one closed terminal result")
                .next()
        })
        .unwrap_or_else(|| panic!("sealed result source boundary disappeared"));
    for forbidden in ["SigningKey", "VerificationContext", "Socket", "Descriptor"] {
        assert!(
            !result_surface.contains(forbidden),
            "sealed result exposed {forbidden} authority"
        );
    }

    assert!(
        NETWORK_SERVICE_SOURCE.contains(".admit_network_inventory_request("),
        "dormant Network seam stopped using the fail-closed public admission"
    );
    assert!(!NETWORK_SERVICE_SOURCE.contains(METHOD_NAME));
}
