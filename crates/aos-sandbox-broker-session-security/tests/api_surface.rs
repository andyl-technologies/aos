//! Guards sealed transport custody below concrete application assembly.

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
fn dependency_boundary_keeps_crypto_and_application_ownership_explicit() {
    for forbidden in ["\nrand =", "\nrand_core =", "\ngetrandom =", "journal"] {
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
fn executable_and_http_registration_ownership_is_outside_security() {
    let controller = include_str!("../src/controller_service.rs");
    assert!(!CRATE_MANIFEST.contains("[[bin]]"));
    assert!(!CRATE_MANIFEST.contains("aos-sandbox-services"));
    assert!(!controller.contains("axum::serve("));
    assert!(!controller.contains("::register("));
}

#[test]
fn host_scheduling_stays_above_fixed_session_admission() {
    let activation = include_str!("../src/production_activation.rs");
    let host = include_str!("../src/production_activation/host.rs");
    let service = include_str!("../src/production_service.rs");

    for source in [LIBRARY_SOURCE, activation, host, service] {
        assert!(!source.contains("ProductionHostBrokerServiceV1"));
        assert!(!source.contains("into_host_service"));
        assert!(!source.contains("serve_production_host_request"));
    }

    for forbidden in [
        "pub fn as_fd",
        "pub fn descriptor",
        "pub fn sign",
        "pub fn from_bytes",
        "pub fn verification_context",
        "DormantRuntimeExecutionOwnerV1",
        "select_ready_role",
    ] {
        assert!(
            !host.contains(forbidden),
            "fixed Host port exposed {forbidden}"
        );
    }

    assert!(activation.contains("#[cfg(any(test, feature = \"kernel-tests\"))]"));
    assert!(activation.contains("pub fn adopt_host_listeners("));
    assert!(host.contains("open_fixed_protected(fixed.endpoint)"));
    assert!(host.contains("verify_storage_connection_peer(socket.peer())?"));
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
fn effect_owners_do_not_depend_on_session_or_application_assembly() {
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
        assert!(!manifest.contains("aos-sandbox-services"));
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
