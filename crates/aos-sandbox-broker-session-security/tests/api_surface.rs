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
    for forbidden in ["\nrand =", "\nrand_core =", "\ngetrandom ="] {
        assert!(
            !CRATE_MANIFEST.contains(forbidden),
            "forbidden dependency marker: {forbidden}"
        );
    }

    // The native floor shares checked preparation geometry with the mechanics
    // crate; keep that existing edge explicit without admitting application owners.
    assert_eq!(
        CRATE_MANIFEST
            .matches("aos-sandbox-journal.workspace = true")
            .count(),
        1
    );

    // The complete method adapters own canonical protobuf traffic directly;
    // keep that wire dependency explicit instead of adding a generic codec.
    assert_eq!(CRATE_MANIFEST.matches("aos-proto.workspace").count(), 1);
    assert_eq!(CRATE_MANIFEST.matches("buffa.workspace").count(), 1);
    assert_eq!(CRATE_MANIFEST.matches("aos-sandbox-protocol").count(), 1);
}

#[test]
fn executable_and_http_registration_ownership_is_outside_security() {
    let controller_sources = [
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service.rs"),
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service/effects/mod.rs"),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/effects/admission.rs"
        ),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/effects/execution.rs"
        ),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/effects/lifecycle.rs"
        ),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/effects/snapshot_coordination.rs"
        ),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/effects/execution/tests.rs"
        ),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/effects/lifecycle/tests.rs"
        ),
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service/worker.rs"),
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service/worker/tests.rs"),
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service/activation.rs"),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/activation/configuration.rs"
        ),
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service/commands.rs"),
        include_str!("../../aos-sandbox-controller-runtime/src/controller_service/public_rpc.rs"),
        include_str!(
            "../../aos-sandbox-controller-runtime/src/controller_service/public_rpc/tests.rs"
        ),
    ];
    assert!(!CRATE_MANIFEST.contains("[[bin]]"));
    assert!(!CRATE_MANIFEST.contains("aos-sandbox-services"));
    for controller in controller_sources {
        assert!(!controller.contains("axum::serve("));
        assert!(!controller.contains("::register("));
    }
}

#[test]
fn host_scheduling_stays_above_fixed_session_admission() {
    let activation = include_str!("../src/production_activation.rs");
    let host = include_str!("../src/production_activation/host.rs");
    let service = [
        include_str!("../src/production_service.rs"),
        include_str!("../src/production_service/mount.rs"),
        include_str!("../src/production_service/nix_generation.rs"),
        include_str!("../src/production_service/storage_output.rs"),
    ]
    .concat();

    for source in [LIBRARY_SOURCE, activation, host, service.as_str()] {
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
    // The module stays private. Only these finite, opaque receiving/session
    // ports are reexported; an additional signer or raw transport still fails.
    let exports = LIBRARY_SOURCE.split("pub use handshake")
        .skip(1)
        .map(|suffix| format!("pub use handshake{};", suffix.split(';').next().unwrap()))
        .map(|export| export.chars().filter(|character| !character.is_whitespace()).collect::<String>())
        .collect::<Vec<_>>();
    assert_eq!(exports, [
        "pubusehandshake::output_registration_continuation::{ExecutionAvailabilitySessionIoOriginalV2,ExecutionAvailabilityClientSessionBorrowV2,HostExecutionNoApplySessionIoOriginalV2,HostExecutionNoApplyClientSessionBorrowV2,};",
        "pubusehandshake::output_registration_continuation::{FixedServiceRequestOriginalV4,FixedServiceRequestClosedV4};",
        "pubusehandshake::output_registration_continuation::{FixedServiceResponseOriginalV4,FixedServiceResponseClosedV4,FixedServiceResponseProgressV4};",
        "pubusehandshake::{FixedServiceSessionOpenOriginalV4,FixedServiceSessionBorrowV4,FixedServiceSessionClosedV4};",
        "pubusehandshake::{StartResourceSessionOpenOriginalV4,StartResourceSessionClosedV4,StartResourceSessionBorrowV4};",
    ]);

    for forbidden in ["AsRawFd", "IntoRawFd", "FromRawFd"] {
        assert!(!HANDSHAKE_SOURCE.contains(forbidden));
    }

    assert!(HANDSHAKE_SOURCE.contains("self.owner.arm_execution_client_socket_post_v1("));
    assert!(HANDSHAKE_SOURCE.contains("self.owner.finish_execution_client_socket_post_v1("));
    assert_eq!(HANDSHAKE_SOURCE.matches("self.socket.as_fd().ok()").count(), 3);

    let post = include_str!("../src/recovery/journal/client_session_continuation.rs");
    let socket_post = post.split("impl ProtectedBrokerSessionOwnerV1 {\n    /// Arms the same native post")
        .nth(1).unwrap();
    assert!(socket_post.contains("socket: Option<std::os::fd::BorrowedFd<'_>>"));
    assert!(socket_post.contains("let socket = socket.map(|socket| socket.as_raw_fd()).unwrap_or(-1);"));
    assert!(socket_post.contains("self.finish_execution_client_post_v1(transcript, peer, socket, original)"));

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

// This source guard deliberately audits declarations even when their feature
// is not selected. Named sealed ports replace the old blanket private-module
// rule; raw traffic proof and private module registration remain closed.
fn public_declaration_names(source: &str) -> Vec<&str> {
    let mut names = source
        .lines()
        .filter_map(|line| {
            let public = line.trim_start().strip_prefix("pub ")?;
            let declaration = public
                .strip_prefix("const ")
                .or_else(|| public.strip_prefix("async "))
                .unwrap_or(public);
            let named = ["fn ", "struct ", "enum ", "trait "]
                .into_iter()
                .find_map(|kind| declaration.strip_prefix(kind))?;
            Some(
                named
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .next()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

#[test]
fn controller_composition_has_an_exact_closed_declaration_surface() {
    assert_eq!(
        public_declaration_names(HANDSHAKE_SOURCE),
        [
            "DormantBrokerSessionHandshakeErrorV1",
            "OnlineTransportFailureV1",
            "OriginalBrokerColdDeadlineV1",
            "OutputCurrentnessBoundaryV1",
            "RetainedStorageColdOpenV1",
            "RetainedStorageHandshakeSendFailureV1",
            "RetainedStoragePreparationHandshakeFailureV1",
            "check",
            "controller",
            "git_coverage",
            "is_failed",
            "output_failure",
            "postcheck_failure",
            "protected_boottime_nanoseconds",
            "value",
        ],
        "handshake.rs public composition surface changed"
    );

    let dormant_sources = [
        include_str!("../src/dormant_handshake.rs"),
        include_str!("../src/dormant_handshake/host_catalog_publication.rs"),
        include_str!("../src/dormant_handshake/host_scope_terminal.rs"),
    ]
    .concat();
    assert_eq!(
        public_declaration_names(&dormant_sources),
        [
            "DormantAuthenticatedBrokerSessionV1",
            "DormantBrokerDescriptorCommitRecoveryV1",
            "DormantBrokerDescriptorCommitResultV1",
            "DormantBrokerDescriptorExecutionFailureV1",
            "DormantBrokerDescriptorInFlightReplayV1",
            "DormantBrokerDescriptorOutcomeUnknownV1",
            "DormantBrokerDescriptorRequestPreparationV1",
            "DormantBrokerDescriptorRequestReceiveProgressV1",
            "DormantBrokerDescriptorRequestSendProgressV1",
            "DormantBrokerDescriptorRequestSendRecoveryV1",
            "DormantBrokerDescriptorResponseProgressV1",
            "DormantBrokerDescriptorSendProgressV1",
            "DormantBrokerDescriptorSendRecoveryV1",
            "DormantBrokerDescriptorTerminalReplayRecoveryProgressV1",
            "DormantBrokerDescriptorTerminalReplaySendProgressV1",
            "DormantBrokerDescriptorTerminalReplayV1",
            "DormantBrokerEndpointHandshakeProgressV1",
            "DormantBrokerEndpointHandshakeV1",
            "DormantBrokerExecutionErrorV1",
            "DormantBrokerExecutionFailureV1",
            "DormantBrokerFailureV1",
            "DormantBrokerOutcomeUnknownV1",
            "DormantBrokerOutcomeVerificationV1",
            "DormantBrokerPublicationExecutionFailureV1",
            "DormantBrokerRequestCoordinatesV1",
            "DormantBrokerRequestPreparationV1",
            "DormantBrokerRequestReceiveProgressV1",
            "DormantBrokerRequestSendProgressV1",
            "DormantBrokerResponseProgressV1",
            "DormantBrokerResponseSendProgressV1",
            "DormantBrokerSessionHandshakeErrorV1",
            "DormantBrokerTerminalReplaySendProgressV1",
            "DormantBrokerTerminalReplayV1",
            "DormantCommittedBrokerDescriptorResponseV1",
            "DormantControllerClientHandshakeProgressV1",
            "DormantControllerClientHandshakeV1",
            "DormantControllerInitialSessionCompletedBorrowV1",
            "DormantControllerInitialSessionOpenV1",
            "DormantHostCatalogPublicationRecoveryProgressV1",
            "DormantHostCatalogPublicationRetryV1",
            "DormantHostCatalogPublicationUnknownV1",
            "DormantHostConsumerCgroupResponseProgressV1",
            "DormantHostMountScopeIdentityResponseProgressV1",
            "DormantHostScopeTerminalFinalizationV1",
            "DormantMountSourceBrokerRecoveryProgressV1",
            "DormantMountSourceBrokerRecoveryV1",
            "DormantOutstandingBrokerRequestV1",
            "DormantPreparedBrokerDescriptorRequestV1",
            "DormantPreparedBrokerRequestV1",
            "DormantReadyBrokerDescriptorTerminalReplayV1",
            "DormantReceivedBrokerDescriptorRequestV1",
            "DormantReceivedBrokerRequestV1",
            "DormantUnconfirmedBrokerDescriptorRequestV1",
            "DormantUnconfirmedBrokerRequestV1",
            "DormantUnconfirmedReceivedBrokerRequestV1",
            "ExecutionPublicationReceiveCustodyV1",
            "ProtectedStorageSessionBindingV1",
            "advance",
            "advance",
            "archive_original_storage_inventory",
            "archive_verified_atomic_storage_history",
            "arm_execution_client_post_v1",
            "as_fd",
            "as_fd",
            "as_fd",
            "audience",
            "authorization_artifacts",
            "authorization_artifacts",
            "authorization_artifacts",
            "begin_broker_handshake",
            "begin_client_handshake",
            "begin_production_broker_handshake",
            "begin_production_client_handshake",
            "body",
            "bookend_output_terminal_witnesses",
            "borrow_active_execution_no_apply_client_once_v2",
            "borrow_completed_session_v1",
            "borrow_execution_availability_client_once_v2",
            "capture_failed_create_originals_v3",
            "capture_preparation_request_v3",
            "check_production_deadline",
            "client_confirm_storage_inventory_abandonment",
            "client_storage_inventory_abandonment_committed",
            "commit_authenticated_error_response",
            "commit_authenticated_publication_error_response",
            "commit_broker_outcome",
            "compare_atomic_snapshot_predecessor_v3",
            "compare_original_capture_candidate_outcome",
            "compare_original_storage_output_outcome_v1",
            "complete_production_broker_handshake",
            "complete_production_client_handshake",
            "connect_git_coverage_mount_session_v1",
            "connect_output_client_session",
            "connect_production_client_session",
            "connect_retained_git_coverage_storage_session_v1",
            "connect_retained_nix_generation_storage_session",
            "connect_retained_output_storage_session",
            "connect_retained_storage_preparation_session_v1",
            "current_storage_session_binding",
            "deadline_boottime_nanoseconds",
            "deadline_boottime_nanoseconds",
            "deadline_boottime_nanoseconds",
            "deadline_boottime_nanoseconds",
            "decode_error",
            "delete_mount_reap_shape_v4",
            "delete_network_apply_shape_v4",
            "delete_storage_apply_shape_v3",
            "delete_storage_preparation_shape_v3",
            "digest",
            "encode_original_create_storage_ready_bundle_once",
            "error",
            "error",
            "error",
            "error",
            "exchange_original_create_storage_outcome_once",
            "execute_host_accepted_execution_and_commit_v2",
            "execute_host_apply_and_commit",
            "execute_host_apply_and_commit_retaining_v2",
            "execute_host_argument_and_commit_v2",
            "execute_host_catalog_publication_and_commit",
            "execute_host_execution_and_commit",
            "execute_host_observation_and_commit",
            "execute_host_resident_query_and_commit_v3",
            "execute_host_scope_and_commit",
            "execute_mount_apply_and_commit",
            "execute_mount_catalog_preparation_and_commit",
            "execute_mount_destination_slot_and_commit",
            "execute_mount_inventory_and_commit",
            "execute_mount_source_inventory_and_commit",
            "execute_mount_source_operation_and_commit",
            "execute_network_inventory_and_commit",
            "execute_original_host_catalog_publication_and_commit_v2",
            "execute_storage_apply_and_commit",
            "execute_storage_inventory_and_commit",
            "execute_storage_inventory_recovery_and_commit",
            "execute_storage_operation_and_commit",
            "execution_output_demand_v1",
            "failure",
            "finish_execution_client_post_v1",
            "finish_original_create_storage_signing_once",
            "fresh_storage_inventory_coordinates",
            "has_selected_capture_candidate_profile",
            "historical_checkpoint_digest",
            "historical_host_terminal_no_apply_archive",
            "host_execution_argument_demand_v1",
            "host_execution_authorize_observe_demand_v2",
            "host_execution_history_data_v1",
            "host_stop_demand_v4",
            "host_stop_dispatch_request_data_v1",
            "host_stop_inventory_demand_v5",
            "host_stop_request_bound_data_v4",
            "into_before_effect_request",
            "into_descriptor_free_request",
            "into_error",
            "into_parts",
            "is_original_storage_preparation_profile_v1",
            "maximum_response_bytes",
            "method",
            "method",
            "mount_request_coordinates",
            "native_error",
            "new",
            "nix_generation_request_id",
            "open_git_coverage_once_v1",
            "open_once",
            "operator_repair_inventory_history",
            "original_create_storage_inventory_failure",
            "original_create_storage_inventory_failure_with_ready",
            "original_create_storage_ready_bundle_failure",
            "original_create_storage_ready_bundle_failure_with_ready",
            "original_create_storage_use_failure_with_ready",
            "original_storage_inventory_coordinates",
            "output_client_flight_failure",
            "output_client_flight_postcheck_debt",
            "output_preparation_failure",
            "output_preparation_postcheck_debt",
            "output_registration_transport",
            "output_terminal_witness_debt",
            "output_terminal_witness_failure",
            "park_capture_candidate_client_coordinates",
            "park_output_client_coordinates",
            "park_output_client_request",
            "prepare_authenticated_authority_effect",
            "prepare_authenticated_authority_effect_checked",
            "prepare_authenticated_descriptor_request",
            "prepare_authenticated_destination_slot_effect",
            "prepare_authenticated_host_effect_query",
            "prepare_authenticated_mount_apply",
            "prepare_authenticated_mount_catalog_query",
            "prepare_authenticated_mount_source_effect",
            "prepare_authenticated_request",
            "prepare_authenticated_request_checked",
            "prepare_authenticated_request_checked_fallible",
            "prepare_host_execution_argument_accept_v2",
            "prepare_host_stop_inventory_retaining_v5",
            "prepare_host_stop_retaining_v5",
            "prepare_nix_generation_request",
            "prepare_original_create_storage_inventory_once",
            "prepare_original_create_storage_request_once",
            "prepare_original_create_storage_signing_once",
            "prepare_storage_capture_query_v2",
            "prepare_storage_capture_reserve_ongoing_v3",
            "prior_verified_atomic_storage_history",
            "protocol_version",
            "raw_error",
            "receive_authenticated_consumer_cgroup_response",
            "receive_authenticated_host_request",
            "receive_authenticated_mount_scope_identity_response",
            "receive_authenticated_request",
            "receive_authenticated_response",
            "receive_authenticated_scope_response",
            "receive_execution_publication_response",
            "receive_original_create_storage_inventory_once",
            "receive_original_create_storage_request_once",
            "receive_original_output_client_terminal",
            "receiving_shape_v1",
            "recheck_original_capture_candidate_client",
            "record_original_create_storage_outcome_once",
            "record_original_create_storage_signed_once",
            "recover_broker_outcome_commit",
            "recover_descriptor_response_commit",
            "recover_host_catalog_publication",
            "recover_host_scope_terminal_finalization",
            "recover_initialization",
            "recover_prepared_descriptor_initialization",
            "recover_prepared_descriptor_successor",
            "recover_prepared_initialization",
            "recover_prepared_successor",
            "recover_received_descriptor_initialization",
            "recover_received_descriptor_successor",
            "recover_received_initialization",
            "recover_received_successor",
            "recover_request_commit",
            "recover_terminal_authority_effect",
            "reopen_host_scope_terminal_replay",
            "request_header",
            "request_id",
            "request_id",
            "require_current_node",
            "require_negotiated_client_method",
            "require_recovered_ordinary_context_v2",
            "require_recovered_ordinary_context_with_node_v2",
            "reserve_original_create_storage_use_once",
            "resume_mount_source_operation_and_commit",
            "retain_authenticated_peer_pidfd",
            "retain_execution_outcome_current",
            "retain_execution_outcome_current_with_post_v1",
            "retain_mount_source_operation_recovery",
            "retire_atomic_storage_archive",
            "retry_absent_host_catalog_publication",
            "retry_authenticated_descriptor_request",
            "retry_authenticated_descriptor_response",
            "retry_observed_host_scope_and_commit",
            "retry_observed_success_and_commit",
            "revalidate_broker_outcome",
            "send_authenticated_descriptor_request",
            "send_authenticated_descriptor_response",
            "send_authenticated_descriptor_terminal_replay",
            "send_authenticated_request",
            "send_authenticated_response",
            "send_authenticated_terminal_replay",
            "send_execution_publication_request",
            "send_original_create_storage_inventory_once",
            "send_original_create_storage_request_once",
            "send_original_output_client_request",
            "serve_operator_repair_unresolved_rejection",
            "sign_original_create_storage_plan_once",
            "signed_request",
            "storage_capture_history_data_v2",
            "take_completed",
            "verify_original_storage_inventory_terminal",
            "wait_for_handshake_readiness",
            "wait_original_create_storage_inventory_once",
            "wait_original_create_storage_request_once",
            "wants_write",
            "wants_write",
        ],
        "dormant_handshake.rs public composition surface changed"
    );

    assert_eq!(
        public_declaration_names(include_str!("../src/dormant_handshake/git_coverage.rs")),
        [
            "capture_git_coverage_checkpoint_v1",
            "compare_git_coverage_outcome_v1",
            "execute_mount_git_coverage_and_commit_v1",
            "execute_storage_git_coverage_and_commit_v1",
            "prepare_git_coverage_request_v1",
        ],
        "dormant_handshake/git_coverage.rs public composition surface changed"
    );

    let journal = include_str!("../src/recovery/journal.rs");
    let committed = journal
        .split("impl ProtectedBrokerOutcomeCommittedAdvancementV1 {")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert_eq!(
        public_declaration_names(committed),
        [
            "capture_candidate_client_originals",
            "output_registration_originals_v1",
            "storage_inventory_client_originals_v1",
            "storage_prepare_client_originals_v1",
        ],
        "committed outcome projections changed"
    );

    assert_eq!(
        public_declaration_names(include_str!("../src/production_startup.rs")),
        [
            "ControllerLaunchImageBindingErrorV1",
            "ControllerLaunchImageCaptureFailureV1",
            "ControllerLaunchImageCaptureV1",
            "Pid1LaunchImageV1",
            "ProductionStorageResourceRecipientStartupErrorV1",
            "ProductionStorageStartupV1",
            "bind_controller_profile_original_v1",
            "capture",
            "capture_delivery_once",
            "capture_original_worker_startup",
            "capture_resource_recipient_startup",
            "into_parts",
            "new",
        ],
        "production_startup.rs public composition surface changed"
    );

    assert_eq!(
        public_declaration_names(include_str!(
            "../src/handshake/output_registration_continuation.rs"
        )),
        [
            "HeldOutputPreparationV1",
            "OriginalOutputClientFlightV1",
            "OriginalStoragePreparationClientFlightV1",
            "OutputPreparationClosedV1",
            "OutputPreparationCustodyV1",
            "StoragePreparationClientProgressV1",
            "client_receiving_demand_v1",
            "committed",
            "committed",
            "coordinates",
            "empty",
            "empty",
            "empty",
            "finish_turn",
            "has_postcheck_debt",
            "has_postcheck_debt",
            "original_head",
            "receive",
            "record",
            "request",
            "request",
            "send",
        ],
        "handshake/output_registration_continuation.rs public composition surface changed"
    );

    // The Create flight exposes only inert custody and compiled byte geometry.
    // Its signing, native IO and completion methods remain crate-private.
    let create_flight = include_str!(
        "../src/handshake/output_registration_continuation/storage_create.rs"
    );
    assert_eq!(
        public_declaration_names(create_flight),
        [
            "OriginalStorageCreatePreparationFlightV1",
            "empty",
            "original_create_storage_use_security_shape_v1",
        ],
        "Create Storage flight public composition surface changed"
    );
    let create_fields = create_flight
        .split("pub struct OriginalStorageCreatePreparationFlightV1 {")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert!(!create_fields.contains("pub "));

    assert_eq!(
        public_declaration_names(include_str!("../src/controller_composition/lifecycle.rs")),
        [
            "complete_controller_atomic_storage_adjacent",
            "complete_controller_historical_atomic_storage_adjacent",
            "complete_controller_historical_atomic_storage_status",
            "complete_controller_host_effect",
            "complete_controller_host_inventory_bootstrap",
            "complete_controller_host_inventory_successor",
            "complete_controller_mount_inventory_bootstrap",
            "complete_controller_mount_inventory_successor",
            "complete_controller_network_inventory_bootstrap",
            "complete_controller_network_inventory_successor",
            "complete_controller_storage_effect_readback",
            "complete_controller_storage_inventory_bootstrap",
            "complete_controller_storage_inventory_successor",
            "complete_host_stop_inventory_retaining_v5",
        ],
        "controller_composition/lifecycle.rs public composition surface changed"
    );

    assert_eq!(
        public_declaration_names(include_str!("../src/controller_composition/online.rs")),
        [
            "ControllerOnlineNixEndpointCustodyV1",
            "ControllerOnlineNixHandshakeProgressV1",
            "ControllerOnlineNixHandshakeV1",
            "ControllerOnlineNixHelloV1",
            "ControllerOnlineNixNativeRequestCustodyV1",
            "ControllerOnlineNixOutcomeOpeningV1",
            "ControllerOnlineNixPreparedRequestV1",
            "ControllerOnlineNixProvisionV1",
            "ControllerOnlineNixSessionV1",
            "ControllerOnlineNixVerifiedHandshakeV1",
            "acquire",
            "admit",
            "advance_online_nix_terminal",
            "advance_retaining_storage",
            "as_fd",
            "as_fd",
            "begin",
            "client_request_coordinates",
            "commit_broker_outcome",
            "decode_online_request_into",
            "existing_outputs",
            "finish_controller_online",
            "finish_online_native_step",
            "into_gate",
            "new_controller",
            "node",
            "open_outcome",
            "prepare_query_path_info",
            "prepare_realize",
            "prepare_resolve",
            "receive_online_record_into",
            "request",
            "require_online_request",
            "require_online_transport",
            "resolve",
            "retain_controller_online",
            "retain_online_admission",
            "retain_online_request_commit_into",
            "send_canonical_request",
            "wants_write",
        ],
        "controller_composition/online.rs public composition surface changed"
    );

    assert_eq!(
        public_declaration_names(include_str!("../src/controller_composition/history.rs")),
        [
            "ArchivedStorageInventoryHeadDataV1",
            "HistoricalAtomicStorageHistoryDataV1",
            "HistoricalAtomicStorageHistoryV1",
            "into_data",
            "view",
        ],
        "controller_composition/history.rs public composition surface changed"
    );
}

#[test]
fn controller_composition_exports_only_named_sealed_owners_and_data() {
    let composition = include_str!("../src/controller_composition.rs");
    let exports = composition
        .split("pub use ")
        .skip(1)
        .map(|suffix| format!("pub use {}", suffix.split(';').next().unwrap()))
        .map(|export| {
            export
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                + ";"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        exports,
        [
            "pubusehistory::{ArchivedStorageInventoryHeadDataV1,HistoricalAtomicStorageHistoryDataV1,HistoricalAtomicStorageHistoryV1,};",
            "pubuseonline::{ControllerOnlineNixEndpointCustodyV1,ControllerOnlineNixHandshakeErrorV1,ControllerOnlineNixHandshakeProgressV1,ControllerOnlineNixHandshakeV1,ControllerOnlineNixHelloV1,ControllerOnlineNixNativeRequestCustodyV1,ControllerOnlineNixOutcomeOpeningV1,ControllerOnlineNixPreparedRequestV1,ControllerOnlineNixProvisionV1,ControllerOnlineNixSessionV1,ControllerOnlineNixVerifiedHandshakeV1,OnlineTransportFailureV1,};",
            "pubusecrate::dormant_handshake::{ExecutionPublicationReceiveCustodyV1,ProtectedStorageSessionBindingV1,OriginalStorageClientSessionTransitionV1,OriginalStorageClientTransitionClosedV1,OriginalDeleteInventoryClientV1,OperatorRecoverStorageInventoryOriginalV1,OperatorReconciliationSessionOpenV2,OperatorReconciliationInventoryOriginalV2,ControllerCatalogMaintenanceInventoryOriginalV2,ControllerCatalogMaintenanceCycleOriginalV2,ControllerCatalogMaintenanceColdCompletedV2,ControllerCatalogMaintenanceColdReceiptV2,ControllerCatalogMaintenanceRefreshCompletedV2,ControllerCatalogMaintenanceRefreshReceiptV2,check_production_deadline,wait_for_handshake_readiness,};",
            "pubusecrate::handshake::{OriginalBrokerColdDeadlineV1,OutputCurrentnessBoundaryV1,RetainedStorageColdOpenV1,RetainedStorageHandshakeSendFailureV1,protected_boottime_nanoseconds,};",
            "pubusecrate::handshake::output_registration_continuation::{HeldOutputPreparationV1,OriginalOutputClientFlightV1,OriginalStorageInventoryClientFlightV1,DeleteInventoryModelV1,DeleteInventoryAnswerOriginalsV1,DeleteInventoryNegotiatedPreimagesV2,OriginalStorageCreatePreparationFlightV1,CreateStorageCompletedPreparationDataV1,original_create_storage_use_security_shape_v1,CreateStorageReadyBundleClosedV1,OriginalStorageReadyBundleFlightV1,OriginalStoragePreparationClientFlightV1,OutputPreparationClosedV1,DeleteNetworkApplySessionIoOriginalV4,delete_network_apply_security_shape_v4,delete_network_apply_response_maximum_v4,DeleteMountReapSessionIoOriginalV4,delete_mount_reap_security_shape_v4,delete_mount_reap_response_maximum_v4,DeleteStorageApplySessionIoOriginalV3,delete_storage_apply_security_shape_v3,delete_storage_apply_response_maximum_v3,DeleteStoragePreparationSessionIoOriginalV3,delete_storage_preparation_security_shape_v3,delete_storage_preparation_response_maximum_v3,OutputPreparationCustodyV1,StoragePreparationClientProgressV1,ControllerCatalogMaintenanceSessionIoOriginalV2,StorageProvisioningSessionIoOriginalV1,StartHostCatalogSessionIoOriginalV2,StartHostCatalogQualifiedSessionBorrowV2,StartResourceProvisioningSessionIoOriginalV4,StartResourceCompletedModelsOriginalV2,StartResourceSessionCompletionDataV2,};",
            "pubuseaos_sandbox_broker::ownership_clock::{CLOCK_PROVENANCE,sample_ownership_clock};",
            "pubusecrate::production_startup::{ControllerLaunchImageCaptureV1,ControllerLaunchImageBindingErrorV1,ControllerLaunchImageCaptureFailureV1,Pid1LaunchImageV1,};",
            "pubusecrate::recovery::{ArchivedStorageInventoryHeadV1,AuthenticatedOriginalHostArgumentArchiveV1,AuthenticatedOriginalHostNoApplyJoinV1,RetainedFailedCreateOriginalsDataV3,};",
            "pubusecrate::tpm_nv_custody::FloorErrorV1;",
        ]
    );

    for source in [
        include_str!("../src/controller_composition/online.rs"),
        include_str!("../src/controller_composition/history.rs"),
    ] {
        for forbidden in [
            "pub fn signing_key",
            "pub fn sign",
            "pub fn verification_context",
            "pub fn prepare_client_request",
            "pub fn send_online_packet",
            "pub fn load(",
            "pub fn into_session",
            "pub fn into_inner",
        ] {
            assert!(
                !source.contains(forbidden),
                "composition escape: {forbidden}"
            );
        }
    }

    let history = include_str!("../src/controller_composition/history.rs");
    assert!(history.contains(
        "pub struct HistoricalAtomicStorageHistoryV1(pub(crate) HistoricalAtomicStorageHistoryDataV1);"
    ));

    let online = include_str!("../src/controller_composition/online.rs");
    for declaration in [
        "pub struct ControllerOnlineNixEndpointCustodyV1(",
        "pub struct ControllerOnlineNixHelloV1(",
        "pub struct ControllerOnlineNixProvisionV1(",
        "pub struct ControllerOnlineNixHandshakeV1(",
        "pub struct ControllerOnlineNixVerifiedHandshakeV1(",
        "pub struct ControllerOnlineNixSessionV1(",
        "pub struct ControllerOnlineNixPreparedRequestV1(",
        "pub struct ControllerOnlineNixNativeRequestCustodyV1(",
        "pub struct ControllerOnlineNixOutcomeOpeningV1(",
    ] {
        let fields = online
            .split(declaration)
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert!(
            !fields.contains("pub "),
            "opaque custody exposed construction: {declaration}"
        );
    }
    assert!(HANDSHAKE_SOURCE.contains("pub(super) fn prepare_client_request("));
    assert!(HANDSHAKE_SOURCE.contains("pub(crate) fn send_online_packet("));
    let dormant = [
        include_str!("../src/dormant_handshake.rs"),
        include_str!("../src/dormant_handshake/host_catalog_publication.rs"),
        include_str!("../src/dormant_handshake/host_scope_terminal.rs"),
    ]
    .concat();
    assert!(!dormant.contains("pub fn sign_lifecycle_bootstrap_attestation"));
    let startup = include_str!("../src/production_startup.rs");
    // The retired raw-profile setter remains forbidden. Its named successor
    // accepts only the genuine opaque completed-admission owner.
    assert!(!startup.contains("pub fn bind_controller_profile("));
    assert!(startup.contains(
        "pub fn bind_controller_profile_original_v1(\n        &mut self,\n        profile: ControllerSharedStartupProfileV1,"
    ));
    assert!(!startup.contains("pub fn profile_path"));
}

#[test]
fn controller_runtime_is_an_upper_owner_without_a_security_reverse_edge() {
    let runtime = include_str!("../../aos-sandbox-controller-runtime/Cargo.toml");
    let services = include_str!("../../aos-sandbox-services/Cargo.toml");
    assert!(runtime.contains("aos-sandbox-broker-session-security.workspace = true"));
    assert!(!runtime.contains("aos-sandbox-services"));
    assert!(!runtime.contains("[[bin]]"));
    assert!(!CRATE_MANIFEST.contains("aos-sandbox-controller-runtime"));
    assert!(!LIBRARY_SOURCE.contains("mod controller_service"));
    assert!(!LIBRARY_SOURCE.contains("pub use controller_service"));
    assert!(services.contains("dep:aos-sandbox-controller-runtime"));
    let controller = include_str!("../../aos-sandbox-services/src/controller.rs");
    assert!(controller.contains("aos_sandbox_controller_runtime::controller_service"));
    assert!(!controller.contains("aos_sandbox_broker_session_security::controller_service"));
}

#[test]
fn controller_startup_orchestration_stays_above_security() {
    let lower = include_str!("../src/production_startup.rs");
    let exports = include_str!("../src/controller_composition.rs");

    for upper in ["ControllerStartupContinuationV1", "CapturedControllerStartupV1",
        "ControllerStartupCaptureAttemptV1", "ControllerResourceBankOpeningV1",
        "ControllerNixStartRecipeSelectorV2"]
    {
        assert!(!lower.contains(upper), "upper startup body remains: {upper}");
        assert!(!exports.contains(upper), "upper startup export remains: {upper}");
    }
    assert!(!lower.contains("profile: Option<Arc<ProductionControllerNormalRootProfileV1>>"));
}


#[test]
fn provisioning_composition_requires_opaque_native_loans_and_private_flights() {
    let source = include_str!(
        "../src/handshake/output_registration_continuation/storage_provisioning.rs"
    );
    assert_eq!(
        public_declaration_names(source),
        [
            "StartResourceProvisioningSessionIoOriginalV4",
            "StartResourceSessionCompletionDataV2",
            "StorageProvisioningSessionIoOriginalV1",
            "apply_once_v1",
            "borrow_source_workspace_original_v1",
            "completed_apply_outcome_v1",
            "completed_exchange_data_v2",
            "completed_host_inventory_model_v2",
            "completed_inventory_model_v4",
            "completed_inventory_outcome_v4",
            "completed_mount_inventory_model_v2",
            "completed_mount_namespace_result_v2",
            "completed_prepare_outcome_v4",
            "completed_prepare_result_v4",
            "failure",
            "failure",
            "has_selected_original_failure_v1",
            "has_selected_original_failure_v4",
            "host_launch_v2",
            "inventory_once_v1",
            "inventory_once_v4",
            "mount_namespace_v2",
            "new",
            "new",
            "prepare_once_v4",
            "retained_post_receiving_demand_v1",
            "retained_post_receiving_demand_v4",
        ],
        "provisioning IO exposes only the installed finite Controller ports"
    );

    let fields = source
        .split("pub struct StorageProvisioningSessionIoOriginalV1 {")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert!(!fields.contains("pub "));
    assert!(source.contains(
        "Self::new_kind_v4(ProvisioningKindV4::Storage)"
    ));

    let compact = source.split_whitespace().collect::<String>();
    for signature in [
        "pubfnapply_once_v1(&mutself,session:&mutcrate::DormantAuthenticatedBrokerSessionV1,original:&mutCreateProvisioningStorageIoLoanV1<'_>,prepared:&PreparedAuthorityEffectV1,)->Result<(),OutputPreparationClosedV1>",
        "pubfninventory_once_v1(&mutself,session:&mutcrate::DormantAuthenticatedBrokerSessionV1,original:&mutCreateProvisioningStorageIoLoanV1<'_>,prepared:&PreparedAuthorityEffectV1,)->Result<(),OutputPreparationClosedV1>",
        "pubfnborrow_source_workspace_original_v1<'models>(&'modelsself,session:&'modelscrate::DormantAuthenticatedBrokerSessionV1,context:&mutaos_sandbox::CreateProvisioningSourceWorkspaceContextV1<'_>,)->Result<aos_sandbox::StorageProvisioningWorkspaceOriginalV1<'models>,ResourceReservationErrorV1>",
        "pubfncompleted_apply_outcome_v1(&self)->Option<&AuthenticatedBrokerMethodOutcomeV1>",
        "pubfnretained_post_receiving_demand_v1()->Option<aos_sandbox_core::ResourceVector>",
    ] {
        assert!(compact.contains(signature), "changed closed provisioning signature: {signature}");
    }

    for forbidden in [
        "pub fn from_",
        "pub fn into_",
        "pub fn sign",
        "pub fn descriptor",
        "pub fn as_fd",
        "pub fn verification_context",
        "pub fn require_complete",
        "pub fn debit",
    ] {
        assert!(!source.contains(forbidden), "provisioning escape: {forbidden}");
    }
    assert!(!LIBRARY_SOURCE.contains("StorageProvisioningSessionIoOriginalV1"));
    assert!(!LIBRARY_SOURCE.contains("StorageProvisioningSessionIoClosedV1"));
}

#[test]
fn negotiated_delete_and_capture_history_are_borrowed_data_without_factories() {
    let inventory = include_str!(
        "../src/handshake/output_registration_continuation/delete_inventory.rs"
    );
    let preimages = inventory
        .split("pub struct DeleteInventoryNegotiatedPreimagesV2<'answer> {")
        .nth(1)
        .unwrap();
    let fields = preimages.split("\n}").next().unwrap();
    assert!(!fields.contains("pub "));
    assert_eq!(
        public_declaration_names(preimages),
        [
            "checkpoint_v2",
            "context_v2",
            "encoded_history_v2",
            "fixed_location_v2",
            "history_v2",
            "transcript_v2",
        ],
        "negotiated preimages expose no constructor, adopter or mutable view"
    );

    let compact = inventory.split_whitespace().collect::<String>();
    for signature in [
        "pubfnnegotiated_preimages_v2(&self)->Option<DeleteInventoryNegotiatedPreimagesV2<'_>>",
        "pubfnencoded_history_v2(&self)->&[u8]",
        "pubfncheckpoint_v2(&self)->&HistoricalSessionCheckpointV1",
        "pubfnhistory_v2(&self)->&aos_sandbox_broker_session_protocol::BrokerSessionDurableHistoryV1",
        "pubfncontext_v2(&self)->&aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1",
        "pubfntranscript_v2(&self)->&VerifiedBrokerSessionTranscriptV1",
        "pubconstfnfixed_location_v2(&self)->(&'staticstr,&'staticstr)",
    ] {
        assert!(compact.contains(signature), "changed borrowed preimage signature: {signature}");
    }

    let dormant = include_str!("../src/dormant_handshake.rs")
        .split_whitespace()
        .collect::<String>();
    assert!(dormant.contains(
        "pubfnstorage_capture_history_data_v2(&self)->Result<&[u8],BrokerSessionSecurityError>{self.0.storage_capture_history_data_v2()}"
    ));
}

#[test]
fn completed_start_models_have_only_borrowed_post_disposal_ports() {
    let source = include_str!(
        "../src/handshake/output_registration_continuation/storage_provisioning/completed_models.rs"
    );
    assert_eq!(public_declaration_names(source), [
        "StartResourceCompletedModelsOriginalV2",
        "completed_models_v2",
        "mount_v2",
        "network_v2",
        "resident_memory_bytes_data_v2",
        "storage_v2",
    ]);
    for forbidden in ["pub fn new", "pub fn from_", "pub fn into_", "pub fn sign",
        "pub fn debit", "pub fn as_fd", "pub fn verification_context"] {
        assert!(!source.contains(forbidden), "completed-model escape: {forbidden}");
    }
    let fields = source.split("pub struct StartResourceCompletedModelsOriginalV2 {")
        .nth(1).unwrap().split("\n}").next().unwrap();
    assert!(!fields.contains("pub "));
}
