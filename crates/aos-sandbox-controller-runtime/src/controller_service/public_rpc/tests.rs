//! Public RPC boundary regression fixtures.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use super::*;
use buffa::Message as _;

#[tokio::test]
async fn first_capability_bootstrap_requires_registered_public_peer() {
    let (commands, receiver) = mpsc::sync_channel(1);
    let diagnostic = CapabilityService {
        capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
        commands: commands.clone(),
        endpoint: ControllerEndpoint::RootDiagnostic,
    };
    let context = RequestContext::new(Default::default());
    let error = diagnostic
        .bootstrap_public_capability(&context, &[1; 16])
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let public = CapabilityService {
        endpoint: ControllerEndpoint::RegisteredPublic,
        ..diagnostic
    };
    let error = public
        .bootstrap_public_capability(&context, &[1; 16])
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unauthenticated);
    assert!(receiver.try_recv().is_err());
}

#[test]
fn readiness_changes_only_after_a_confirmed_catalog() {
    let mut state = CapabilityState::starting([7; 16]);
    let starting = state.response().unwrap();
    let starting = starting.capabilities.as_option().unwrap();
    assert!(starting.capabilities.is_empty());
    assert_eq!(starting.capability_generation, 1);
    let starting_version = starting.resource_version.clone();

    state.record_success(9, ObjectDigest::from_bytes([8; 32]));
    let ready = state.response().unwrap();
    let ready = ready.capabilities.as_option().unwrap();
    assert!(ready.capabilities.is_empty());
    assert_eq!(ready.capability_generation, 2);
    assert_ne!(ready.resource_version, starting_version);
}

#[test]
fn unregistered_semantic_capabilities_are_not_advertised() {
    let mut state = CapabilityState::starting([7; 16]);
    state.record_success(1, ObjectDigest::from_bytes([8; 32]));
    let response = state.response().unwrap();
    let capabilities = response.capabilities.as_option().unwrap();
    let mutation = mutation_unavailable();

    assert!(capabilities.capabilities.is_empty());
    assert_eq!(mutation.code, ErrorCode::Unimplemented);
    assert_eq!(mutation.message.as_deref(), Some(UNAVAILABLE_REASON));
}

#[test]
fn root_diagnostic_response_discloses_no_catalog_or_resource_detail() {
    let mut state = CapabilityState::starting([7; 16]);
    state.record_success(9, ObjectDigest::from_bytes([8; 32]));
    let response = state.response().unwrap();
    let capabilities = response.capabilities.as_option().unwrap();

    assert_eq!(capabilities.node_id, [7; 16]);
    assert_eq!(capabilities.resource_version.len(), 32);
    assert_eq!(capabilities.capability_generation, 2);
    assert!(capabilities.capabilities.is_empty());
    assert!(capabilities.observed_at.as_option().is_some());
}

#[tokio::test]
async fn canonical_discovery_service_exposes_only_checked_diagnostics() {
    use aos_proto::aos::sandbox::v1::{
        GetNodeCapabilitiesRequest, GetPublicFeatureRegistryRequest,
    };
    use buffa::{Message, view::HasMessageView};
    use connectrpc::CodecFormat;

    let mut state = CapabilityState::starting([7; 16]);
    state.record_success(9, ObjectDigest::from_bytes([8; 32]));
    let (commands, _command_receiver) = mpsc::sync_channel(1);
    let service = CapabilityService {
        capabilities: Arc::new(Mutex::new(state)),
        commands,
        endpoint: ControllerEndpoint::RootDiagnostic,
    };

    let registry_body: axum::body::Bytes = GetPublicFeatureRegistryRequest::default()
        .encode_to_vec()
        .into();
    let registry_view = GetPublicFeatureRegistryRequest::decode_view(&registry_body).unwrap();
    let registry_response = DiscoveryService::get_public_feature_registry(
        &service,
        RequestContext::new(Default::default()),
        ServiceRequest::from_parts(&registry_view, &registry_body),
    )
    .await
    .unwrap();
    let registry_response = GetPublicFeatureRegistryResponse::decode_from_slice(
        registry_response
            .body
            .encode(CodecFormat::Proto)
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let expected_registry = aos_sandbox_protocol::public_api::public_feature_registry_v1();
    assert_eq!(
        registry_response.registry.as_option(),
        Some(&expected_registry)
    );

    let capabilities_body: axum::body::Bytes = GetNodeCapabilitiesRequest {
        node_id: vec![7; 16],
        ..Default::default()
    }
    .encode_to_vec()
    .into();
    let capabilities_view = GetNodeCapabilitiesRequest::decode_view(&capabilities_body).unwrap();
    let capabilities_response = DiscoveryService::get_node_capabilities(
        &service,
        RequestContext::new(Default::default()),
        ServiceRequest::from_parts(&capabilities_view, &capabilities_body),
    )
    .await
    .unwrap();
    let capabilities_response = GetNodeCapabilitiesResponse::decode_from_slice(
        capabilities_response
            .body
            .encode(CodecFormat::Proto)
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let capabilities = capabilities_response.capabilities.as_option().unwrap();
    assert_eq!(capabilities.node_id, [7; 16]);
    assert!(capabilities.capabilities.is_empty());
}

#[tokio::test]
async fn operation_lookup_crosses_the_bounded_worker_channel() {
    let (commands, receiver) = mpsc::sync_channel(1);
    let service = CapabilityService {
        capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
        commands,
        endpoint: ControllerEndpoint::RootDiagnostic,
    };
    let operation_id = [0x42; 16];
    let worker = std::thread::spawn(move || {
        let (operation_id, expires_at, reply) = match receiver.recv().unwrap() {
            ControllerCommand::GetOperation {
                operation_id,
                expires_at,
                reply,
            } => (operation_id, expires_at, reply),
            ControllerCommand::GetAuthorizedOperation { .. } => {
                panic!("root diagnostics must not enter public authorization")
            }
            ControllerCommand::AuthorizePublicRead { .. } => {
                panic!("root diagnostics must not enter public read authorization")
            }
            ControllerCommand::ReadPublicProjection { .. } => {
                panic!("root diagnostics must not enter public projection reads")
            }
            ControllerCommand::InspectGitRead { .. } => {
                panic!("root diagnostics must not enter delegated Git reads")
            }
            ControllerCommand::BootstrapPublicCapability { .. }
            | ControllerCommand::PlanPublicPolicy { .. }
            | ControllerCommand::AdmitPublicOperatorRecovery { .. }
            | ControllerCommand::AdmitPublicMutation { .. }
            | ControllerCommand::AdmitPublicAttach { .. }
            | ControllerCommand::ResolvePublicCapabilityTarget { .. } => {
                panic!("root diagnostics must not enter public mutation services")
            }
        };
        assert_eq!(operation_id.as_bytes(), &[0x42; 16]);
        assert!(expires_at > Instant::now());
        reply
            .send(Ok(Some(Operation {
                operation_id: operation_id.into_bytes().to_vec(),
                ..Default::default()
            })))
            .unwrap();
    });

    let response = service
        .operation(&RequestContext::default(), &operation_id, &[])
        .await
        .unwrap();
    assert_eq!(
        response.operation.as_option().unwrap().operation_id,
        operation_id
    );
    worker.join().unwrap();
}

#[tokio::test]
async fn operation_lookup_rejects_invalid_identity_and_channel_saturation() {
    let (commands, receiver) = mpsc::sync_channel(1);
    let service = CapabilityService {
        capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
        commands: commands.clone(),
        endpoint: ControllerEndpoint::RootDiagnostic,
    };

    let invalid = service
        .operation(&RequestContext::default(), &[1; 15], &[])
        .await
        .unwrap_err();
    assert_eq!(invalid.code, ErrorCode::InvalidArgument);
    let zero = service
        .operation(&RequestContext::default(), &[0; 16], &[])
        .await
        .unwrap_err();
    assert_eq!(zero.code, ErrorCode::InvalidArgument);

    let (reply, _response) = tokio::sync::oneshot::channel();
    commands
        .try_send(ControllerCommand::GetOperation {
            operation_id: OperationId::from_bytes([0x43; 16]),
            expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
            reply,
        })
        .unwrap();
    let saturated = service
        .operation(&RequestContext::default(), &[0x44; 16], &[])
        .await
        .unwrap_err();
    assert_eq!(saturated.code, ErrorCode::ResourceExhausted);

    drop(receiver);
}

#[test]
fn public_capability_header_requires_one_canonical_nonzero_identity() {
    let missing = public_capability_id(&RequestContext::default()).unwrap_err();
    assert_eq!(missing.code, ErrorCode::Unauthenticated);

    for invalid in [
        "NOT-A-UUID",
        "00112233-4455-6677-8899-AABBCCDDEEFF",
        "00000000-0000-0000-0000-000000000000",
    ] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(PUBLIC_CAPABILITY_HEADER, invalid.parse().unwrap());
        let error = public_capability_id(&RequestContext::new(headers)).unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthenticated);
    }

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        PUBLIC_CAPABILITY_HEADER,
        "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap(),
    );
    let capability_id = public_capability_id(&RequestContext::new(headers)).unwrap();
    assert_eq!(
        capability_id.to_string(),
        "00112233-4455-6677-8899-aabbccddeeff"
    );

    let mut duplicate_headers = axum::http::HeaderMap::new();
    duplicate_headers.append(
        PUBLIC_CAPABILITY_HEADER,
        "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap(),
    );
    duplicate_headers.append(
        PUBLIC_CAPABILITY_HEADER,
        "11112233-4455-6677-8899-aabbccddeeff".parse().unwrap(),
    );
    let duplicate = public_capability_id(&RequestContext::new(duplicate_headers)).unwrap_err();
    assert_eq!(duplicate.code, ErrorCode::Unauthenticated);
}

#[test]
fn public_handle_header_requires_one_canonical_nonzero_secret() {
    let missing = public_capability_handle(&RequestContext::default()).unwrap_err();
    assert_eq!(missing.code, ErrorCode::Unauthenticated);

    for invalid in [
        "00".repeat(32),
        "ab".repeat(31),
        "AB".repeat(32),
        "gg".repeat(32),
    ] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(PUBLIC_CAPABILITY_HANDLE_HEADER, invalid.parse().unwrap());
        let error = public_capability_handle(&RequestContext::new(headers)).unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthenticated);
    }

    let encoded = "ab".repeat(32);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(PUBLIC_CAPABILITY_HANDLE_HEADER, encoded.parse().unwrap());
    assert_eq!(
        public_capability_handle(&RequestContext::new(headers)).unwrap(),
        [0xab; 32]
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.append(PUBLIC_CAPABILITY_HANDLE_HEADER, encoded.parse().unwrap());
    headers.append(
        PUBLIC_CAPABILITY_HANDLE_HEADER,
        "cd".repeat(32).parse().unwrap(),
    );
    let duplicate = public_capability_handle(&RequestContext::new(headers)).unwrap_err();
    assert_eq!(duplicate.code, ErrorCode::Unauthenticated);
}

#[tokio::test]
async fn public_operation_lookup_never_falls_back_to_root_diagnostics() {
    let (commands, _receiver) = mpsc::sync_channel(1);
    let service = CapabilityService {
        capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
        commands,
        endpoint: ControllerEndpoint::RegisteredPublic,
    };

    let error = service
        .operation(&RequestContext::default(), &[0x42; 16], &[0x0a, 0x10])
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unauthenticated);
}

#[test]
fn retryable_inventory_loss_closes_observation_status() {
    let mut state = CapabilityState::starting([7; 16]);
    state.record_success(1, ObjectDigest::from_bytes([8; 32]));
    state.record_retryable_failure("Storage inventory is unavailable".to_owned());
    let response = state.response().unwrap();
    let capabilities = response.capabilities.as_option().unwrap();

    assert!(capabilities.capabilities.is_empty());
    assert_eq!(capabilities.capability_generation, 3);
}

#[test]
fn worker_failure_projection_preserves_each_error_code_and_message() {
    let cases = [
        (
            ControllerCommandFailure::DeadlineExceeded,
            ErrorCode::DeadlineExceeded,
            "expired",
        ),
        (
            ControllerCommandFailure::InvalidRequest,
            ErrorCode::InvalidArgument,
            "invalid",
        ),
        (
            ControllerCommandFailure::Rejected,
            ErrorCode::PermissionDenied,
            "rejected",
        ),
        (
            ControllerCommandFailure::ControllerUnavailable,
            ErrorCode::Unavailable,
            "unavailable",
        ),
    ];

    for (failure, code, message) in cases {
        let error = public_controller_command_error(
            failure,
            "expired",
            "invalid",
            "rejected",
            "unavailable",
        );

        assert_eq!(error.code, code);
        assert_eq!(error.message.as_deref(), Some(message));
    }
}
