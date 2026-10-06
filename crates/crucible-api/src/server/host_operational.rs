//! Bounded transport-authenticated host operational RPC handling.
//!
//! Principal identity is taken only from the mutual-TLS connection extension.
//! Executor authorization runs independently of guest debugger capabilities.
//! Blocking durable history and native-control work never holds the lifecycle
//! mutex or a guest quantum's actor mailbox.

use super::*;
use crate::host_operational::{HOST_OPERATIONAL_MAX_BYTES, HostOperationalError, codec};
use axum::Extension;

const MAX_HOST_CONTROL_IN_FLIGHT: usize = 16;
static HOST_CONTROL_ADMISSION: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

pub(super) async fn handle<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    identity: Option<Extension<DebugTransportIdentity>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let Some(Extension(identity)) = identity else {
        return error_response(HostOperationalError::PrincipalDenied);
    };
    if request.version() != Version::HTTP_2 {
        return http2_response(StatusCode::BAD_REQUEST, "Crucible RPC requires HTTP/2");
    }
    if request
        .headers()
        .get("x-crucible-rpc-build")
        .and_then(|value| value.to_str().ok())
        != Some(RPC_PROTOCOL_BUILD)
    {
        return error_response(HostOperationalError::InvalidMessage {
            message: String::from("host operational RPC build mismatch"),
        });
    }
    let body = match axum::body::to_bytes(request.into_body(), HOST_OPERATIONAL_MAX_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return http2_response(StatusCode::PAYLOAD_TOO_LARGE, "host operational size limit");
        }
    };
    let request = match codec::decode_request(&body) {
        Ok(request) => request,
        Err(error) => return error_response(error),
    };
    if state.mode.is_read_only() && request.is_mutating() {
        return read_only_rejection_response("host-operational");
    }
    let control = state.host_operational_control.clone();
    let Some(control) = control else {
        return error_response(HostOperationalError::Unavailable);
    };
    let admission = HOST_CONTROL_ADMISSION
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_HOST_CONTROL_IN_FLIGHT)));
    let permit = match Arc::clone(admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return error_response(HostOperationalError::Unavailable),
    };
    let principal = identity.certificate_sha256().to_owned();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        control.execute(&principal, request)
    })
    .await
    {
        Ok(Ok(response)) => match codec::encode_response(&response) {
            Ok(bytes) => http2_response(StatusCode::OK, bytes),
            Err(error) => error_response(error),
        },
        Ok(Err(error)) => error_response(error),
        Err(_) => error_response(HostOperationalError::Unavailable),
    }
}

fn error_response(error: HostOperationalError) -> Response {
    let (status, code, kind) = match &error {
        HostOperationalError::PrincipalDenied => (
            StatusCode::FORBIDDEN,
            RpcStatusCode::Unsupported,
            "host-principal-denied",
        ),
        HostOperationalError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            RpcStatusCode::Internal,
            "host-owner-unavailable",
        ),
        HostOperationalError::IdempotencyConflict => (
            StatusCode::CONFLICT,
            RpcStatusCode::InvalidArgument,
            "host-idempotency-conflict",
        ),
        HostOperationalError::InvalidMessage { .. } => (
            StatusCode::BAD_REQUEST,
            RpcStatusCode::InvalidArgument,
            "host-invalid-message",
        ),
    };
    typed_rpc_status_response(status, code, kind, &error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_operational::{
        HostOperationalControl, HostOperationalRequest, HostOperationalResponse,
        HostRamCapabilities, HostRamTarget,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Probe {
        principal: String,
        calls: AtomicU64,
    }

    impl HostOperationalControl for Probe {
        fn execute(
            &self,
            principal: &str,
            request: HostOperationalRequest,
        ) -> Result<HostOperationalResponse, HostOperationalError> {
            if principal != self.principal {
                return Err(HostOperationalError::PrincipalDenied);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let crate::host_operational::HostOperationalTarget::Ram(target) = request.target()
            else {
                return Err(HostOperationalError::Unavailable);
            };
            Ok(HostOperationalResponse::Capabilities {
                target,
                capabilities: HostRamCapabilities {
                    logical_ram_bytes: 4096,
                    compulsory_resident_bytes: 4096,
                    minimum_execution_peak_bytes: 4096,
                    maximum_paging_io_slots: 1,
                    dynamic_residency: false,
                    disk_oriented: false,
                    resident_required: false,
                },
                qualification: crate::host_operational::HostRamQualification::default(),
            })
        }
    }

    fn target() -> HostRamTarget {
        HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 4,
            arena_generation: 5,
            retained_template: false,
        }
    }

    fn request(bytes: Vec<u8>) -> Request<Body> {
        Request::builder()
            .version(Version::HTTP_2)
            .header("x-crucible-rpc-build", RPC_PROTOCOL_BUILD)
            .body(Body::from(bytes))
            .unwrap()
    }

    async fn state(probe: Arc<Probe>, mode: LifecycleServerMode) -> super::super::tests::TestState {
        let mut state = super::super::tests::test_state(mode);
        state.host_operational_control = Some(probe);
        state
    }

    #[tokio::test]
    async fn operational_transport_rejects_unauthenticated_requests_before_controller_call() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes =
            codec::encode_request(&HostOperationalRequest::Capabilities { target: target() })
                .unwrap();

        let response = handle(State(state), None, request(bytes)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authenticated_transport_dispatches_exact_target_through_executor_authority() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes =
            codec::encode_request(&HostOperationalRequest::Capabilities { target: target() })
                .unwrap();

        let response = handle(State(state), Some(Extension(identity)), request(bytes)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), HOST_OPERATIONAL_MAX_BYTES)
            .await
            .unwrap();
        assert!(matches!(codec::decode_response(&bytes).unwrap(),
            HostOperationalResponse::Capabilities { target: observed, .. } if observed == target()));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn host_status_dispatch_does_not_wait_for_modeled_lifecycle_lock() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes =
            codec::encode_request(&HostOperationalRequest::Capabilities { target: target() })
                .unwrap();
        let held_lifecycle = state.control_plane.lock().await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle(
                State(state.clone()),
                Some(Extension(identity)),
                request(bytes),
            ),
        )
        .await
        .expect("host authority must remain responsive while lifecycle is held");

        drop(held_lifecycle);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn malformed_and_read_only_mutations_never_reach_controller() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_only()).await;
        let mutation = HostOperationalRequest::AmendOuterCap {
            target: crate::host_operational::HostOuterCapTarget {
                daemon_epoch: [1; 32],
                owner: crate::host_operational::HostOuterCapOwner::Execution([2; 32]),
                owner_generation: 4,
                cap_id: [7; 32],
            },
            expected_cap_revision: 7,
            idempotency_key: [8; 32],
            allowance: Some(std::time::Duration::from_secs(60)),
        };
        let bytes = codec::encode_request(&mutation).unwrap();

        let response = handle(
            State(state.clone()),
            Some(Extension(identity.clone())),
            request(bytes),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = handle(
            State(state),
            Some(Extension(identity)),
            request(vec![0; HOST_OPERATIONAL_MAX_BYTES + 1]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn host_protocol_predecessor_is_rejected_before_live_dispatch() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes =
            codec::encode_request(&HostOperationalRequest::Capabilities { target: target() })
                .unwrap();
        let mut request = request(bytes);
        request.headers_mut().insert(
            "x-crucible-rpc-build",
            axum::http::HeaderValue::from_static("crucible-rpc-abi-v8"),
        );

        let response = handle(State(state), Some(Extension(identity)), request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }
}
