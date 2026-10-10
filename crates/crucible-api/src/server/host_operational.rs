//! Bounded transport-authenticated host operational RPC handling.
//!
//! Principal identity is taken only from the mutual-TLS connection extension.
//! Executor authorization runs independently of guest debugger capabilities.
//! Blocking durable history and native-control work never holds the lifecycle
//! mutex or a guest quantum's actor mailbox.

use super::*;
use crate::host_operational::{HOST_OPERATIONAL_MAX_BYTES, HostOperationalError, codec};
use axum::Extension;
use futures_util::StreamExt;

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
    let Some(control) = state.host_operational_control.clone() else {
        return error_response(HostOperationalError::Unavailable);
    };
    let admission = HOST_CONTROL_ADMISSION
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_HOST_CONTROL_IN_FLIGHT)));
    let permit = match Arc::clone(admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return error_response(HostOperationalError::Unavailable),
    };
    let operation = match control.begin_request(identity.certificate_sha256()) {
        Ok(operation) => operation,
        Err(error) => return error_response(error),
    };
    let budget = match control
        .metadata_budget(identity.certificate_sha256())
        .and_then(|budget| {
            budget
                .child()
                .map_err(|source| HostOperationalError::Admission { source })
        }) {
        Ok(budget) => budget,
        Err(error) => return error_response(error),
    };
    let mut body = {
        let _scope = budget.enter();
        if let Err(source) = crucible::owned_decode::charge_array::<u8>(HOST_OPERATIONAL_MAX_BYTES)
        {
            return error_response(HostOperationalError::Admission { source });
        }
        let mut bytes = Vec::new();
        if let Err(source) = bytes.try_reserve_exact(HOST_OPERATIONAL_MAX_BYTES) {
            return error_response(HostOperationalError::Admission {
                source: crucible::owned_decode::DecodeAdmissionError::new(source),
            });
        }
        bytes
    };
    let mut chunks = request.into_body().into_data_stream();
    loop {
        let slice = match operation.wait_slice() {
            Ok(slice) => slice,
            Err(source) => {
                return error_response(HostOperationalError::OriginalBoundary { source });
            }
        };
        let chunk = match tokio::time::timeout(slice, chunks.next()).await {
            Ok(chunk) => chunk,
            Err(_) => continue,
        };
        if let Err(source) = operation.wait_slice() {
            return error_response(HostOperationalError::OriginalBoundary { source });
        }
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => return error_response(HostOperationalError::Unavailable),
        };
        if chunk.len() > HOST_OPERATIONAL_MAX_BYTES.saturating_sub(body.len()) {
            return http2_response(StatusCode::PAYLOAD_TOO_LARGE, "host operational size limit");
        }
        body.extend_from_slice(&chunk);
    }
    let request = {
        let _scope = budget.enter();
        match codec::decode_request(&body) {
            Ok(request) => request,
            Err(error) => return error_response(error),
        }
    };
    // The body allocation closes while its original metadata account is still here.
    drop(chunks);
    drop(body);
    if state.mode.is_read_only() && request.is_mutating() {
        return read_only_rejection_response("host-operational");
    }
    let principal = {
        let _scope = budget.enter();
        match crucible::owned_decode::display_string(identity.certificate_sha256()) {
            Ok(principal) => principal,
            Err(source) => return error_response(HostOperationalError::Admission { source }),
        }
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _scope = budget.enter();
        let (request, _request_custody) = request.into_parts();
        if let Err(source) = operation.wait_slice() {
            return Err(HostOperationalError::OriginalBoundary { source });
        }
        let result = control.execute(&principal, request);
        let after = operation.wait_slice();
        match (result, after) {
            (Err(first), _) => Err(first),
            (Ok(response), Ok(_)) => {
                operation
                    .complete()
                    .map_err(|source| HostOperationalError::OriginalBoundary { source })?;
                Ok(response)
            }
            (Ok(_), Err(source)) => Err(HostOperationalError::OriginalBoundary { source }),
        }
    })
    .await
    {
        Ok(Ok(response)) => match codec::encode_owned_response(&response) {
            Ok(bytes) => match bytes.into_wire_bytes() {
                Ok(bytes) => http2_response(StatusCode::OK, bytes),
                Err(source) => error_response(HostOperationalError::Admission { source }),
            },
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
        HostOperationalError::Unavailable
        | HostOperationalError::Admission { .. }
        | HostOperationalError::OriginalBoundary { .. } => (
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
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::host_operational::{
        HostOperationalControl, HostOperationalRequest, HostOperationalResponse,
        HostRamCapabilities, HostRamTarget,
    };
    use crucible_linux_resource::host_supervision::{
        HostOperationBudget, HostOperationBudgets, HostOperationClass,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Probe {
        principal: String,
        calls: AtomicU64,
        body_closed: Option<Arc<std::sync::atomic::AtomicBool>>,
        supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
    }

    impl HostOperationalControl for Probe {
        fn begin_request(
            &self,
            principal: &str,
        ) -> Result<
            crucible_linux_resource::host_supervision::HostOperationGuard,
            HostOperationalError,
        > {
            if principal != self.principal {
                return Err(HostOperationalError::PrincipalDenied);
            }
            self.supervisor
                .begin(HostOperationClass::Setup)
                .map_err(|source| HostOperationalError::OriginalBoundary { source })
        }

        fn metadata_budget(
            &self,
            principal: &str,
        ) -> Result<crucible::owned_decode::DecodeBudget, HostOperationalError> {
            if principal != self.principal {
                return Err(HostOperationalError::PrincipalDenied);
            }
            crate::admitted_output::tests::fixture_budget()
                .map_err(|source| HostOperationalError::Admission { source })
        }

        fn execute(
            &self,
            principal: &str,
            request: HostOperationalRequest,
        ) -> Result<crate::AdmittedOutput<HostOperationalResponse>, HostOperationalError> {
            let _scope = crucible::test_support::fixture_decode_scope(32 * 1024 * 1024)
                .map_err(|source| HostOperationalError::Admission { source })?;
            if principal != self.principal {
                return Err(HostOperationalError::PrincipalDenied);
            }
            if let Some(closed) = &self.body_closed {
                assert!(
                    closed.load(Ordering::Acquire),
                    "body owner must close before dispatch"
                );
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let crate::host_operational::HostOperationalTarget::Ram(target) = request.target()
            else {
                return Err(HostOperationalError::Unavailable);
            };
            HostOperationalResponse::admit(|| {
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
            })
        }
    }

    fn fixture_supervisor(
        total: std::time::Duration,
    ) -> crucible_linux_resource::host_supervision::HostOperationSupervisor {
        let budgets = HostOperationBudgets {
            classes: [HostOperationBudget::finite(total);
                crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
        };
        crucible_linux_resource::host_supervision::HostOperationSupervisor::new(budgets, None)
            .unwrap()
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

    fn request(bytes: impl Into<bytes::Bytes>) -> Request<Body> {
        Request::builder()
            .version(Version::HTTP_2)
            .header("x-crucible-rpc-build", RPC_PROTOCOL_BUILD)
            .body(Body::from(bytes.into()))
            .unwrap()
    }

    fn encode_request(request: &HostOperationalRequest) -> bytes::Bytes {
        let budget = crate::admitted_output::tests::fixture_budget().unwrap();
        let _scope = budget.enter();
        codec::encode_request(request)
            .unwrap()
            .into_wire_bytes()
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
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes = encode_request(&HostOperationalRequest::Capabilities { target: target() });

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
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes = encode_request(&HostOperationalRequest::Capabilities { target: target() });

        let response = handle(State(state), Some(Extension(identity)), request(bytes)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), HOST_OPERATIONAL_MAX_BYTES)
            .await
            .unwrap();
        let _scope = crucible::test_support::fixture_decode_scope(32 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("finite response decoding fixture: {error}"));
        let decoded = codec::decode_response(&bytes).unwrap();
        assert!(matches!(decoded.value(),
            HostOperationalResponse::Capabilities { target: observed, .. } if *observed == target()));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn host_status_dispatch_does_not_wait_for_modeled_lifecycle_lock() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes = encode_request(&HostOperationalRequest::Capabilities { target: target() });
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
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
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
        let bytes = encode_request(&mutation);

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
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let bytes = encode_request(&HostOperationalRequest::Capabilities { target: target() });
        let mut request = request(bytes);
        request.headers_mut().insert(
            "x-crucible-rpc-build",
            axum::http::HeaderValue::from_static("crucible-rpc-abi-v8"),
        );

        let response = handle(State(state), Some(Extension(identity)), request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authenticated_pending_body_expires_without_live_dispatch() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_millis(30)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let mut pending = request(bytes::Bytes::new());
        *pending.body_mut() = Body::from_stream(futures_util::stream::pending::<
            Result<bytes::Bytes, std::io::Error>,
        >());

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle(State(state), Some(Extension(identity)), pending),
        )
        .await
        .expect("actual declared body operation must expire");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn same_service_cancellation_interrupts_an_authenticated_pending_body() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let observed = Arc::clone(&entered);
        let body = futures_util::stream::poll_fn(move |_| {
            observed.notify_one();
            std::task::Poll::Pending::<Option<Result<bytes::Bytes, std::io::Error>>>
        });
        let mut pending = request(bytes::Bytes::new());
        *pending.body_mut() = Body::from_stream(body);
        let running = tokio::spawn(handle(State(state), Some(Extension(identity)), pending));
        entered.notified().await;

        probe.supervisor.cancel().unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), running)
            .await
            .expect("same original cancellation must stop body waiting")
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn arriving_body_chunks_do_not_renew_the_declared_operation() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
            body_closed: None,
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let delivered = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&delivered);
        let supervisor = probe.supervisor.clone();
        let chunks = futures_util::stream::unfold(0, move |next| {
            let observed = Arc::clone(&observed);
            let supervisor = supervisor.clone();
            async move {
                if next == 0 {
                    let (revision, mut budgets) = supervisor.budgets().unwrap();
                    budgets.classes[HostOperationClass::Setup as usize] =
                        HostOperationBudget::finite(std::time::Duration::from_millis(50));
                    supervisor.update_budgets(revision, budgets).unwrap();
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                }
                observed.fetch_add(1, Ordering::SeqCst);
                Some((
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")),
                    next + 1,
                ))
            }
        });
        let mut incoming = request(bytes::Bytes::new());
        *incoming.body_mut() = Body::from_stream(chunks);

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle(State(state), Some(Extension(identity)), incoming),
        )
        .await
        .expect("partial delivery must not renew the original operation");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(delivered.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    struct DroppingBody {
        bytes: Option<bytes::Bytes>,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl futures_util::Stream for DroppingBody {
        type Item = Result<bytes::Bytes, std::io::Error>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.bytes.take().map(Ok))
        }
    }

    impl Drop for DroppingBody {
        fn drop(&mut self) {
            self.closed.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn completed_body_owner_closes_before_blocking_dispatch() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = Arc::new(Probe {
            principal: identity.certificate_sha256().into(),
            calls: AtomicU64::new(0),
            body_closed: Some(Arc::clone(&closed)),
            supervisor: fixture_supervisor(std::time::Duration::from_secs(5)),
        });
        let state = state(Arc::clone(&probe), LifecycleServerMode::read_write()).await;
        let wire = encode_request(&HostOperationalRequest::Capabilities { target: target() });
        let mut incoming = request(bytes::Bytes::new());
        *incoming.body_mut() = Body::from_stream(DroppingBody {
            bytes: Some(wire),
            closed,
        });

        let response = handle(State(state), Some(Extension(identity)), incoming).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }
}
