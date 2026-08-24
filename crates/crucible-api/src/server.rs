//! HTTP/2 daemon transport for the lifecycle and streaming control API.
//!
//! The server owns only transport concerns. It accepts the same canonical text
//! RPC ABI that [`crate::RpcControlClient`] emits, dispatches into a
//! [`LifecycleControlPlane`], and serializes lifecycle, `Control`, `Watch`, and
//! unary `Send` responses without taking ownership of scheduler semantics.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode, Version};
use axum::response::Response;
use axum::routing::post;
use bytes::Bytes;
use crucible::{
    Checkpoint, ContentHash, EventLevel, GdbListen, NodeId, QuantumLoop, ScenarioDef,
    ScenarioDefForm, Schedule, Seed,
};
use crucible_protocol::guest_introspection::GuestIntrospectionRecord;
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, BreakpointSpec, DebugCapability, DebugClientId,
    DebugControllerLease, DebugRole, EngineState, LifecycleStateKind, LiveStateKind, Outcome,
    OutcomeKind, PauseReason, QueryKind, QueryResult, SessionCommand, SessionCommandKind, StepMode,
};
use futures_util::stream;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, OwnedMutexGuard, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::debug_holders::{
    DebugControllerHolderId, DebugControllerHolderRegistry, DebugHolderRelease,
};
use crate::debug_relay::{DEBUG_RELAY_CHUNK_MAX_BYTES, DebugRelayId, DebugRelayRegistry};
use crate::event_log_stream::EventLogCursor;
use crate::lifecycle::{
    CreateSessionRequest, CreateSessionResponse, DestroySessionRequest, DestroySessionResponse,
    GetReproductionRequest, GetReproductionResponse, LifecycleApiError, LifecycleControlPlane,
    ListScenariosResponse, ListSessionsResponse, ReproductionCommandRecord,
    ReproductionCommandResult, ResumeSessionRequest, ResumeSessionResponse, SessionId, SessionRef,
};
use crate::open_set::{
    OpenSetAttributeValue, OpenSetEventSource, open_set_command_kind,
    session_command_for_open_set_command_kind,
};
use crate::rpc_abi::{
    ProtocolVersion, RPC_PROTOCOL_BUILD, RpcStatusCode, encode_rpc_hello_response,
    rpc_status_code_wire_name,
};
use crate::session_mapping::API_COMMAND_MAPPINGS;
use crate::streaming::{
    AttachRequest, Attached, CommandResultStatus, ControlStream, SendRequest, SendResponse,
    StateUpdate, StreamingApiError, StreamingEventFrame, StreamingFrame, StreamingStateUpdateFrame,
    WatchStream,
};
use crate::transport_security::DebugTransportIdentity;
use crate::{ControlClientError, DebugAuthorizationPolicy, HelloRequest};

type SharedLifecycleControlPlane<L, F> = Arc<Mutex<LifecycleControlPlane<L, F>>>;

/// Runtime policy for the HTTP/2 lifecycle server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LifecycleServerMode {
    read_only: bool,
}

impl LifecycleServerMode {
    /// Builds the default read-write server mode.
    #[must_use]
    pub const fn read_write() -> Self {
        Self { read_only: false }
    }

    /// Builds a mode that rejects state-mutating lifecycle and control calls.
    #[must_use]
    pub const fn read_only() -> Self {
        Self { read_only: true }
    }

    /// Returns whether the server rejects state-mutating calls.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        self.read_only
    }
}

struct Http2LifecycleState<L, F> {
    control_plane: SharedLifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
    shutdown: watch::Receiver<bool>,
    debug_authorization: DebugAuthorizationPolicy,
    debug_holders: Arc<Mutex<DebugControllerHolderRegistry>>,
    debug_relays: Arc<Mutex<DebugRelayRegistry>>,
}

impl<L, F> Clone for Http2LifecycleState<L, F> {
    fn clone(&self) -> Self {
        Self {
            control_plane: Arc::clone(&self.control_plane),
            mode: self.mode,
            shutdown: self.shutdown.clone(),
            debug_authorization: self.debug_authorization.clone(),
            debug_holders: Arc::clone(&self.debug_holders),
            debug_relays: Arc::clone(&self.debug_relays),
        }
    }
}

async fn debug_operation_guard<L, F>(
    state: &Http2LifecycleState<L, F>,
    session: SessionRef,
) -> OwnedMutexGuard<()>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>,
{
    let gate = match state
        .control_plane
        .lock()
        .await
        .debug_operation_gate(session)
    {
        Ok(gate) => gate,
        Err(_) => Arc::new(Mutex::new(())),
    };
    gate.lock_owned().await
}

/// Runs an authorized actor operation while retaining its session gate after caller cancellation.
async fn complete_debug_operation<T>(
    guard: OwnedMutexGuard<()>,
    operation: impl Future<Output = T> + Send + 'static,
) -> Result<T, LifecycleApiError>
where
    T: Send + 'static,
{
    tokio::spawn(async move {
        let _guard = guard;
        operation.await
    })
    .await
    .map_err(|error| LifecycleApiError::ActorFailed {
        message: format!("debug operation task failed: {error}"),
    })
}

/// Serves a [`LifecycleControlPlane`] over the Crucible HTTP/2 RPC transport.
///
/// The function binds no sockets itself; callers supply an already-bound
/// listener so command-line and test harness code can decide whether to use a
/// stable or ephemeral address.
///
/// # Errors
///
/// Returns the underlying `axum` server I/O error if the listener fails while
/// serving requests.
pub async fn serve_lifecycle_http2<L, F>(
    listener: TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
) -> Result<(), std::io::Error>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    serve_lifecycle_http2_with_mode(listener, control_plane, LifecycleServerMode::read_write())
        .await
}

/// Serves a [`LifecycleControlPlane`] over HTTP/2 with an explicit server mode.
///
/// Use [`LifecycleServerMode::read_only`] when the daemon should accept only
/// observation calls and reject lifecycle or session-control mutations.
///
/// # Errors
///
/// Returns the underlying `axum` server I/O error if the listener fails while
/// serving requests.
pub async fn serve_lifecycle_http2_with_mode<L, F>(
    listener: TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
) -> Result<(), std::io::Error>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    serve_lifecycle_http2_with_mode_until_shutdown(
        listener,
        control_plane,
        mode,
        std::future::pending(),
    )
    .await
}

/// Serves a [`LifecycleControlPlane`] over HTTP/2 until a shutdown future resolves.
///
/// This variant is used by process-level hosts that need clean signal-driven
/// termination while preserving the same router and transport behavior as
/// [`serve_lifecycle_http2_with_mode`].
///
/// # Errors
///
/// Returns the underlying `axum` server I/O error if the listener fails while
/// serving requests.
pub async fn serve_lifecycle_http2_with_mode_until_shutdown<L, F, S>(
    listener: TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
    shutdown: S,
) -> Result<(), std::io::Error>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = ()> + Send + 'static,
{
    serve_lifecycle_http2_with_debug_policy_until_shutdown(
        listener,
        control_plane,
        mode,
        DebugAuthorizationPolicy::deny_all(),
        shutdown,
    )
    .await
}

/// Serves cleartext HTTP/2 with an explicit debugger authorization policy.
///
/// This function does not authenticate its transport. It is intended only for
/// an explicitly trusted listener whose role is represented by
/// `debug_authorization`.
///
/// # Errors
///
/// Returns the underlying server I/O error if the listener fails while serving
/// requests.
pub async fn serve_lifecycle_http2_with_debug_policy_until_shutdown<L, F, S>(
    listener: TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
    debug_authorization: DebugAuthorizationPolicy,
    shutdown: S,
) -> Result<(), std::io::Error>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = ()> + Send + 'static,
{
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let app = lifecycle_router(Http2LifecycleState {
        control_plane: Arc::new(Mutex::new(control_plane)),
        mode,
        shutdown: shutdown_receiver.clone(),
        debug_authorization,
        debug_holders: Arc::new(Mutex::new(DebugControllerHolderRegistry::default())),
        debug_relays: Arc::new(Mutex::new(DebugRelayRegistry::default())),
    });
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            let _ = shutdown_sender.send(true);
        })
        .await
}

/// Serves the lifecycle API over HTTP/2 with mandatory mutual TLS.
///
/// The caller supplies an acceptor configured to validate client certificates.
/// Each connection receives a [`DebugTransportIdentity`] request extension
/// derived from its authenticated leaf certificate for debugger authorization.
/// TLS handshake failures affect only the rejected connection.
///
/// # Errors
///
/// Returns an I/O error when the listening socket cannot accept connections.
pub async fn serve_lifecycle_http2_mtls_with_mode_until_shutdown<L, F, S>(
    listener: TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
    tls_acceptor: TlsAcceptor,
    debug_authorization: DebugAuthorizationPolicy,
    shutdown: S,
) -> Result<(), std::io::Error>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = ()> + Send + 'static,
{
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let app = lifecycle_router(Http2LifecycleState {
        control_plane: Arc::new(Mutex::new(control_plane)),
        mode,
        shutdown: shutdown_receiver.clone(),
        debug_authorization,
        debug_holders: Arc::new(Mutex::new(DebugControllerHolderRegistry::default())),
        debug_relays: Arc::new(Mutex::new(DebugRelayRegistry::default())),
    });
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            result = listener.accept() => {
                let (stream, _peer) = result?;
                let acceptor = tls_acceptor.clone();
                let app = app.clone();
                let connection_shutdown = shutdown_receiver.clone();
                connections.spawn(async move {
                    serve_authenticated_connection(stream, acceptor, app, connection_shutdown).await;
                });
            }
            () = &mut shutdown => {
                let _ = shutdown_sender.send(true);
                break;
            }
        }
    }

    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_authenticated_connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) {
    let Ok(tls_stream) = acceptor.accept(stream).await else {
        return;
    };
    let Some(certificate) = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
    else {
        return;
    };
    let identity = DebugTransportIdentity::from_leaf_certificate(certificate.as_ref());
    let authenticated_app = app.layer(Extension(identity));
    let service = TowerToHyperService::new(authenticated_app);
    let io = TokioIo::new(tls_stream);
    let builder = auto::Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        biased;
        _result = &mut connection => {}
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
    }
}

fn lifecycle_router<L, F>(state: Http2LifecycleState<L, F>) -> Router
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    Router::new()
        .route("/crucible.rpc/hello", post(handle_rpc_hello::<L, F>))
        .route(
            "/crucible.rpc/list-scenarios",
            post(handle_list_scenarios::<L, F>),
        )
        .route(
            "/crucible.rpc/create-session",
            post(handle_create_session::<L, F>),
        )
        .route(
            "/crucible.rpc/resume-session",
            post(handle_resume_session::<L, F>),
        )
        .route(
            "/crucible.rpc/list-sessions",
            post(handle_list_sessions::<L, F>),
        )
        .route(
            "/crucible.rpc/destroy-session",
            post(handle_destroy_session::<L, F>),
        )
        .route(
            "/crucible.rpc/get-reproduction",
            post(handle_get_reproduction::<L, F>),
        )
        .route(
            "/crucible.rpc/control/attach",
            post(handle_control_attach::<L, F>),
        )
        .route(
            "/crucible.rpc/control/send",
            post(handle_control_send::<L, F>),
        )
        .route("/crucible.rpc/watch", post(handle_watch_attach::<L, F>))
        .route("/crucible.rpc/send", post(handle_send_command::<L, F>))
        .route(
            "/crucible.rpc/debug/controller/acquire",
            post(handle_debug_controller_acquire::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/controller/release",
            post(handle_debug_controller_release::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/attach",
            post(handle_debug_attach::<L, F>),
        )
        .route("/crucible.rpc/debug/goto", post(handle_debug_goto::<L, F>))
        .route(
            "/crucible.rpc/debug/reverse-step",
            post(handle_debug_reverse_step::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/reverse-continue",
            post(handle_debug_reverse_continue::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/relay/open",
            post(handle_debug_relay_open::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/relay/write",
            post(handle_debug_relay_write::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/relay/read",
            post(handle_debug_relay_read::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/relay/close",
            post(handle_debug_relay_close::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/guest/exchange",
            post(handle_debug_guest_exchange::<L, F>),
        )
        .route(
            "/crucible.rpc/debug/guest/fork",
            post(handle_debug_guest_fork::<L, F>),
        )
        .with_state(state)
}

async fn handle_debug_guest_fork<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-guest-fork");
    }
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, node) = match parse_debug_guest_fork_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let operation_guard = debug_operation_guard(&state, session).await;
    let lease = DebugControllerLease {
        client: client.clone(),
        generation,
    };
    if let Err(response) = authorize_debug_holder(&state, session, &lease, holder).await {
        return response;
    }
    let dispatch = {
        let control_plane = state.control_plane.lock().await;
        for capability in [
            DebugCapability::Control,
            DebugCapability::Mutate,
            DebugCapability::Shell,
        ] {
            if let Err(error) = control_plane
                .authorize_debug_controller_operation(session, &lease, &role, capability)
            {
                return lifecycle_error_response(error);
            }
        }
        match control_plane.guest_introspection_dispatch(session) {
            Ok(dispatch) => dispatch,
            Err(error) => return lifecycle_error_response(error),
        }
    };
    let result =
        match complete_debug_operation(operation_guard, async move { dispatch.fork(node).await })
            .await
        {
            Ok(result) => result,
            Err(error) => return lifecycle_error_response(error),
        };
    match result {
        Ok(report) => match (
            report.guest_introspection_features,
            report.guest_introspection_activation_failure,
        ) {
            (Some(features), None) => http2_response(
                StatusCode::OK,
                format!(
                    "crucible.rpc/debug-guest-fork-response\nbranch={}\nstatus=ready\nfailure=\nargv-exec={}\npty={}\nresize={}\nssh-bridge={}\nmax-channels={}\n",
                    hex_encode(&report.branch.id.bytes),
                    features.argv_exec(),
                    features.pty(),
                    features.resize(),
                    features.ssh_bridge(),
                    features.max_channels(),
                ),
            ),
            (None, Some(failure)) => http2_response(
                StatusCode::OK,
                format!(
                    "crucible.rpc/debug-guest-fork-response\nbranch={}\nstatus=failed\nfailure={}\nargv-exec=false\npty=false\nresize=false\nssh-bridge=false\nmax-channels=0\n",
                    hex_encode(&report.branch.id.bytes),
                    hex_encode(failure.as_bytes()),
                ),
            ),
            _ => lifecycle_error_response(LifecycleApiError::ActorFailed {
                message: String::from("debug guest fork returned inconsistent activation state"),
            }),
        },
        Err(error) => lifecycle_error_response(error),
    }
}

async fn handle_debug_guest_exchange<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-guest-exchange");
    }
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, node, channel_id, record) =
        match parse_debug_guest_exchange_request(&body) {
            Ok(request) => request,
            Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
        };
    let operation_guard = debug_operation_guard(&state, session).await;
    let lease = DebugControllerLease {
        client: client.clone(),
        generation,
    };
    if let Err(response) = authorize_debug_holder(&state, session, &lease, holder).await {
        return response;
    }
    let dispatch = {
        let control_plane = state.control_plane.lock().await;
        if let Err(error) = control_plane.authorize_debug_controller_operation(
            session,
            &lease,
            &role,
            DebugCapability::Shell,
        ) {
            return lifecycle_error_response(error);
        }
        match control_plane.guest_introspection_dispatch(session) {
            Ok(dispatch) => dispatch,
            Err(error) => return lifecycle_error_response(error),
        }
    };
    let response = match complete_debug_operation(operation_guard, async move {
        dispatch.exchange(node, channel_id, record).await
    })
    .await
    {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    let mut output = String::from("crucible.rpc/debug-guest-exchange-response\n");
    match response {
        Some(record) => match record.encode() {
            Ok(bytes) => push_wire_line(&mut output, "record", &hex_encode(&bytes)),
            Err(error) => {
                return http2_response(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
            }
        },
        None => push_wire_line(&mut output, "record", ""),
    }
    http2_response(StatusCode::OK, output)
}

async fn handle_debug_controller_acquire<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-controller-acquire");
    }
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, holder) = match parse_debug_controller_acquire_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let stale = state.debug_relays.lock().await.remove_stale(session);
    for (lease, holder) in stale {
        if let Err(response) = release_debug_holder(&state, session, &lease, holder).await {
            return response;
        }
    }
    let mut control_plane = state.control_plane.lock().await;
    let mut holders = state.debug_holders.lock().await;
    if let Err(error) = holders.preflight_register(session, holder) {
        return http2_response(StatusCode::CONFLICT, error.to_string());
    }
    let controller_preexisted = holders.has_active_session(session);
    let lease = match control_plane.acquire_debug_controller(session, client, &role) {
        Ok(lease) => lease,
        Err(error) => return lifecycle_error_response(error),
    };
    if let Err(error) = holders.register(session, lease.clone(), holder) {
        if !controller_preexisted {
            let _ = control_plane.release_debug_controller(session, &lease);
        }
        return http2_response(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
    }
    let mut output = String::from("crucible.rpc/debug-controller-acquire-response\n");
    push_wire_line(
        &mut output,
        "client",
        &hex_encode(lease.client.as_str().as_bytes()),
    );
    push_wire_line(&mut output, "generation", &lease.generation.to_string());
    http2_response(StatusCode::OK, output)
}

async fn handle_debug_attach<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-attach");
    }
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, node) = match parse_debug_attach_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let operation_guard = debug_operation_guard(&state, session).await;
    let lease = DebugControllerLease { client, generation };
    if let Err(response) = authorize_debug_holder(&state, session, &lease, holder).await {
        return response;
    }
    let operation_state = state.clone();
    let response = complete_debug_operation(operation_guard, async move {
        let control_plane = operation_state.control_plane.lock().await;
        if let Err(error) = control_plane.authorize_debug_controller_operation(
            session,
            &lease,
            &role,
            DebugCapability::Control,
        ) {
            return lifecycle_error_response(error);
        }
        if let Err(error) = control_plane.authorize_debug_controller_operation(
            session,
            &lease,
            &role,
            DebugCapability::Observe,
        ) {
            return lifecycle_error_response(error);
        }
        match control_plane.debug_operator_target(session).await {
            Ok((active_node, _endpoint)) if active_node == node => {}
            Ok((active_node, _endpoint)) => {
                return typed_rpc_status_response(
                    StatusCode::BAD_REQUEST,
                    RpcStatusCode::InvalidArgument,
                    "debug-node-conflict",
                    &format!(
                        "debugger is already attached to node `{}`; requested `{}`",
                        active_node.name, node.name
                    ),
                );
            }
            Err(LifecycleApiError::DebugEndpointUnavailable) => {
                let listen = match GdbListen::new("127.0.0.1:0") {
                    Ok(listen) => listen,
                    Err(error) => {
                        return typed_rpc_status_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            RpcStatusCode::Internal,
                            "internal",
                            &error.to_string(),
                        );
                    }
                };
                match control_plane.attach_debugger(session, node, listen).await {
                    Ok(_report) => {}
                    Err(error) => return lifecycle_error_response(error),
                }
            }
            Err(error) => return lifecycle_error_response(error),
        }
        http2_response(StatusCode::OK, "crucible.rpc/debug-attach-response\n")
    })
    .await;
    match response {
        Ok(response) => response,
        Err(error) => lifecycle_error_response(error),
    }
}

async fn handle_debug_controller_release<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-controller-release");
    }
    let (client, _role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder) = match parse_debug_controller_release_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let lease = DebugControllerLease { client, generation };
    let stale = state.debug_relays.lock().await.remove_stale(session);
    for (stale_lease, stale_holder) in stale {
        if let Err(response) =
            release_debug_holder(&state, session, &stale_lease, stale_holder).await
        {
            return response;
        }
    }
    if state
        .debug_relays
        .lock()
        .await
        .has_holder(session, &lease, holder)
    {
        return http2_response(
            StatusCode::CONFLICT,
            "debug controller holder is retained by a live relay; close the relay first",
        );
    }
    if let Err(response) = release_debug_holder(&state, session, &lease, holder).await {
        return response;
    }
    http2_response(
        StatusCode::OK,
        "crucible.rpc/debug-controller-release-response\n",
    )
}

async fn handle_debug_relay_open<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-relay-open");
    }
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder) = match parse_debug_relay_open_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let lease = DebugControllerLease { client, generation };
    if let Err(error) = state
        .debug_holders
        .lock()
        .await
        .authorize(session, &lease, holder)
    {
        return http2_response(StatusCode::FORBIDDEN, error.to_string());
    }
    let endpoint = {
        let control_plane = state.control_plane.lock().await;
        if let Err(error) = control_plane.authorize_debug_controller_operation(
            session,
            &lease,
            &role,
            DebugCapability::Control,
        ) {
            return lifecycle_error_response(error);
        }
        if let Err(error) = control_plane.authorize_debug_controller_operation(
            session,
            &lease,
            &role,
            DebugCapability::Observe,
        ) {
            return lifecycle_error_response(error);
        }
        match control_plane.debug_operator_target(session).await {
            Ok((_node, endpoint)) => endpoint,
            Err(error) => return lifecycle_error_response(error),
        }
    };
    let existing = {
        let mut relays = state.debug_relays.lock().await;
        relays.existing(session, &lease, holder)
    };
    let id = if let Some(id) = existing {
        id
    } else {
        let stream = match DebugRelayRegistry::connect(endpoint.as_str()).await {
            Ok(stream) => stream,
            Err(error) => return debug_relay_error_response(error),
        };
        match state
            .debug_relays
            .lock()
            .await
            .register(stream, session, lease, holder)
        {
            Ok(id) => id,
            Err(error) => return debug_relay_error_response(error),
        }
    };
    let mut output = String::from("crucible.rpc/debug-relay-open-response\n");
    push_wire_line(&mut output, "relay-id", &id.0.to_string());
    http2_response(StatusCode::OK, output)
}

async fn handle_debug_relay_write<L, F>(
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
    if state.mode.is_read_only() {
        return read_only_rejection_response("debug-relay-write");
    }
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, id, bytes) = match parse_debug_relay_write_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(response) = authorize_relay_role(&role) {
        return *response;
    }
    if let Err(error) = state
        .debug_relays
        .lock()
        .await
        .touch(id, session, &client, generation, holder)
    {
        return debug_relay_error_response(error);
    }
    let _operation_guard = debug_operation_guard(&state, session).await;
    let stream_result = {
        let mut relays = state.debug_relays.lock().await;
        relays.stream(id, session, &client, generation, holder)
    };
    let stream = match stream_result {
        Ok(stream) => stream,
        Err(error) => return debug_relay_error_response(error),
    };
    let written = match DebugRelayRegistry::write_stream(stream, &bytes).await {
        Ok(written) => written,
        Err(error) => {
            close_failed_relay(&state, session, &client, generation, holder, id).await;
            return debug_relay_error_response(error);
        }
    };
    let mut output = String::from("crucible.rpc/debug-relay-write-response\n");
    push_wire_line(&mut output, "written", &written.to_string());
    http2_response(StatusCode::OK, output)
}

async fn handle_debug_relay_read<L, F>(
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
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, id, maximum) = match parse_debug_relay_read_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(response) = authorize_relay_role(&role) {
        return *response;
    }
    if let Err(error) = state
        .debug_relays
        .lock()
        .await
        .touch(id, session, &client, generation, holder)
    {
        return debug_relay_error_response(error);
    }
    let _operation_guard = debug_operation_guard(&state, session).await;
    let chunk_result = {
        let mut relays = state.debug_relays.lock().await;
        relays.read(id, session, &client, generation, holder, maximum)
    };
    let chunk = match chunk_result {
        Ok(chunk) => chunk,
        Err(error) => return debug_relay_error_response(error),
    };
    if chunk.eof {
        close_failed_relay(&state, session, &client, generation, holder, id).await;
    }
    let mut output = String::from("crucible.rpc/debug-relay-read-response\n");
    push_wire_line(&mut output, "eof", if chunk.eof { "true" } else { "false" });
    push_wire_line(&mut output, "data", &hex_encode(&chunk.bytes));
    http2_response(StatusCode::OK, output)
}

async fn handle_debug_relay_close<L, F>(
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
    let (client, role) = match debug_principal(&state.debug_authorization, identity.as_ref()) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let body = match read_debug_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, id) = match parse_debug_relay_close_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(response) = authorize_relay_role(&role) {
        return *response;
    }
    let _operation_guard = debug_operation_guard(&state, session).await;
    let close_result = {
        let mut relays = state.debug_relays.lock().await;
        relays.close(id, session, &client, generation, holder)
    };
    let closed = match close_result {
        Ok(closed) => closed,
        Err(error) => return debug_relay_error_response(error),
    };
    if let Err(response) = release_debug_holder(&state, session, &closed.lease, closed.holder).await
    {
        return response;
    }
    http2_response(StatusCode::OK, "crucible.rpc/debug-relay-close-response\n")
}

fn authorize_relay_role(role: &DebugRole) -> Result<(), Box<Response>> {
    if role.allows(DebugCapability::Control) && role.allows(DebugCapability::Observe) {
        return Ok(());
    }
    Err(Box::new(http2_response(
        StatusCode::FORBIDDEN,
        "debug relay requires observe and control capabilities",
    )))
}

async fn release_debug_holder<L, F>(
    state: &Http2LifecycleState<L, F>,
    session: SessionRef,
    lease: &DebugControllerLease,
    holder: DebugControllerHolderId,
) -> Result<(), Response>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let mut control_plane = state.control_plane.lock().await;
    let mut holders = state.debug_holders.lock().await;
    let release = holders
        .release(session, lease, holder)
        .map_err(|error| http2_response(StatusCode::FORBIDDEN, error.to_string()))?;
    if release != DebugHolderRelease::Final {
        return Ok(());
    }
    if let Err(error) = control_plane.release_debug_controller(session, lease) {
        holders.restore(session, lease.clone(), holder);
        return Err(lifecycle_error_response(error));
    }
    Ok(())
}

async fn authorize_debug_holder<L, F>(
    state: &Http2LifecycleState<L, F>,
    session: SessionRef,
    lease: &DebugControllerLease,
    holder: DebugControllerHolderId,
) -> Result<(), Response>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    state
        .debug_holders
        .lock()
        .await
        .authorize(session, lease, holder)
        .map_err(|error| http2_response(StatusCode::FORBIDDEN, error.to_string()))
}

async fn close_failed_relay<L, F>(
    state: &Http2LifecycleState<L, F>,
    session: SessionRef,
    client: &DebugClientId,
    generation: u64,
    holder: DebugControllerHolderId,
    id: DebugRelayId,
) where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let closed = state
        .debug_relays
        .lock()
        .await
        .close(id, session, client, generation, holder);
    if let Ok(closed) = closed {
        let _ = release_debug_holder(state, session, &closed.lease, closed.holder).await;
    }
}

fn debug_principal(
    authorization: &DebugAuthorizationPolicy,
    identity: Option<&Extension<DebugTransportIdentity>>,
) -> Result<(DebugClientId, DebugRole), Box<Response>> {
    let transport_identity = identity.map(|Extension(identity)| identity);
    let role = authorization
        .role_for(transport_identity)
        .map_err(|error| Box::new(http2_response(StatusCode::FORBIDDEN, error.to_string())))?
        .clone();
    let name = transport_identity.map_or_else(
        || String::from("trusted-unauthenticated"),
        |identity| format!("x509-sha256:{}", identity.certificate_sha256()),
    );
    let client = DebugClientId::new(name)
        .map_err(|error| Box::new(http2_response(StatusCode::FORBIDDEN, error.to_string())))?;
    Ok((client, role))
}

async fn handle_rpc_hello<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let hello = match parse_hello_request(&body) {
        Ok(hello) => hello,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let response = match state.control_plane.lock().await.hello(hello) {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(
        StatusCode::OK,
        encode_rpc_hello_response(
            &response.server_name,
            response.version,
            response.payload_kinds,
        ),
    )
}

async fn handle_list_scenarios<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if body.as_slice() != b"crucible.rpc/list-scenarios-request\n" {
        return http2_response(StatusCode::BAD_REQUEST, "unexpected list scenarios request");
    }
    let response = state.control_plane.lock().await.list_scenarios();
    http2_response(StatusCode::OK, encode_list_scenarios_response(&response))
}

async fn handle_create_session<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if state.mode.is_read_only() {
        return read_only_rejection_response("create-session");
    }
    let create = match parse_create_session_request(&body) {
        Ok(create) => create,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let response = match state
        .control_plane
        .lock()
        .await
        .create_session(create)
        .await
    {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(StatusCode::OK, encode_create_session_response(&response))
}

async fn handle_resume_session<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if state.mode.is_read_only() {
        return read_only_rejection_response("resume-session");
    }
    let resume = match parse_resume_session_request(&body) {
        Ok(resume) => resume,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let response = match state
        .control_plane
        .lock()
        .await
        .resume_session(resume)
        .await
    {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(StatusCode::OK, encode_resume_session_response(&response))
}

async fn handle_list_sessions<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if body.as_slice() != b"crucible.rpc/list-sessions-request\n" {
        return http2_response(StatusCode::BAD_REQUEST, "unexpected list sessions request");
    }
    let response = state.control_plane.lock().await.list_sessions();
    http2_response(StatusCode::OK, encode_list_sessions_response(&response))
}

async fn handle_destroy_session<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if state.mode.is_read_only() {
        return read_only_rejection_response("destroy-session");
    }
    let destroy = match parse_destroy_session_request(&body) {
        Ok(destroy) => destroy,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let response = match state
        .control_plane
        .lock()
        .await
        .destroy_session(destroy)
        .await
    {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    let _closed = state
        .debug_relays
        .lock()
        .await
        .close_for_session(response.session);
    state
        .debug_holders
        .lock()
        .await
        .remove_session(response.session);
    http2_response(StatusCode::OK, encode_destroy_session_response(&response))
}

async fn handle_get_reproduction<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let get_reproduction = match parse_get_reproduction_request(&body) {
        Ok(get_reproduction) => get_reproduction,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let response = match state
        .control_plane
        .lock()
        .await
        .get_reproduction(get_reproduction)
    {
        Ok(response) => response,
        Err(error) => return lifecycle_error_response(error),
    };
    http2_response(StatusCode::OK, encode_get_reproduction_response(&response))
}

async fn handle_control_attach<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let attach = match parse_attach_request(&body) {
        Ok(attach) => attach,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    if state.mode.is_read_only() {
        return read_only_rejection_response("control-attach");
    }
    let streaming = match state
        .control_plane
        .lock()
        .await
        .streaming_session(attach.session)
    {
        Ok(streaming) => streaming,
        Err(error) => return streaming_error_response(error),
    };
    let control = match streaming.control(attach) {
        Ok(control) => control,
        Err(error) => return streaming_error_response(error),
    };
    http2_stream_response(control_event_body(control, state.shutdown.clone()))
}

async fn handle_control_send<L, F>(
    state: State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    handle_streaming_send(state, request).await
}

async fn handle_watch_attach<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let attach = match parse_attach_request(&body) {
        Ok(attach) => attach,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let streaming = match state
        .control_plane
        .lock()
        .await
        .streaming_session(attach.session)
    {
        Ok(streaming) => streaming,
        Err(error) => return streaming_error_response(error),
    };
    let watch = match streaming.watch(attach) {
        Ok(watch) => watch,
        Err(error) => return streaming_error_response(error),
    };
    http2_stream_response(watch_event_body(watch, state.shutdown.clone()))
}

async fn handle_send_command<L, F>(
    state: State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    handle_streaming_send(state, request).await
}

async fn handle_streaming_send<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match read_rpc_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let send = match parse_send_request(&body) {
        Ok(send) => send,
        Err(error) => return send_parse_error_response(&error),
    };
    if state.mode.is_read_only() && !send.command.is_read_only() {
        return read_only_rejection_response("send");
    }
    let response = match state
        .control_plane
        .lock()
        .await
        .send_streaming_command(send)
        .await
    {
        Ok(response) => response,
        Err(ControlClientError::Lifecycle { source }) => return lifecycle_error_response(source),
        Err(ControlClientError::Streaming { source }) => return streaming_error_response(source),
        Err(error) => {
            return typed_rpc_status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                RpcStatusCode::Internal,
                "internal",
                &error.to_string(),
            );
        }
    };
    http2_response(StatusCode::OK, encode_send_response(&response))
}

async fn read_rpc_body(request: Request<Body>) -> Result<Vec<u8>, Response> {
    if request.version() != Version::HTTP_2 {
        return Err(http2_response(
            StatusCode::BAD_REQUEST,
            "Crucible RPC requires HTTP/2",
        ));
    }
    axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map(|body| body.to_vec())
        .map_err(|error| http2_response(StatusCode::BAD_REQUEST, error.to_string()))
}

async fn read_debug_rpc_body(request: Request<Body>) -> Result<Vec<u8>, Response> {
    const DEBUG_RPC_BODY_MAX_BYTES: usize = DEBUG_RELAY_CHUNK_MAX_BYTES * 2 + 1024;

    if request.version() != Version::HTTP_2 {
        return Err(http2_response(
            StatusCode::BAD_REQUEST,
            "Crucible RPC requires HTTP/2",
        ));
    }
    axum::body::to_bytes(request.into_body(), DEBUG_RPC_BODY_MAX_BYTES)
        .await
        .map(|body| body.to_vec())
        .map_err(|error| {
            typed_rpc_status_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                RpcStatusCode::InvalidArgument,
                "debug-request-too-large",
                &error.to_string(),
            )
        })
}

fn parse_hello_request(body: &[u8]) -> Result<HelloRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/hello-request")?;
    let version = parse_version_line(lines.next(), "version=")?;
    let client_name = parse_wire_line(lines.next(), "client=")?.to_owned();
    reject_extra_line(lines.next())?;
    Ok(HelloRequest::new(client_name, version))
}

fn parse_create_session_request(body: &[u8]) -> Result<CreateSessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/create-session-request")?;
    match parse_wire_line(lines.next(), "source=")? {
        "scenario-ref" => {
            let name = parse_wire_line(lines.next(), "name=")?.to_owned();
            let seed = parse_seed_line(lines.next(), "seed=")?;
            let start_paused = parse_bool_line(lines.next(), "start-paused=")?;
            reject_extra_line(lines.next())?;
            Ok(CreateSessionRequest::scenario_ref(name, seed).with_start_paused(start_paused))
        }
        "inline" => {
            let id = parse_content_hash_line(lines.next(), "scenario-id=")?;
            let scenario_seed = parse_seed_line(lines.next(), "scenario-seed=")?;
            let app_random_draw_cap = parse_u64_line(lines.next(), "app-random-draw-cap=")?;
            let next = lines.next();
            let (scenario_form, seed_line) = if let Some(line) = next {
                if line.starts_with("scenario-payload=") {
                    let scenario = parse_scenario_form_line(Some(line), "scenario-payload=")?;
                    let scenario_def = scenario.scenario_def();
                    if scenario_def.id() != id {
                        return Err(format!(
                            "scenario payload id {} did not match request scenario id {}",
                            scenario_def.id().to_hex(),
                            id.to_hex()
                        ));
                    }
                    if scenario.seed() != scenario_seed {
                        return Err(format!(
                            "scenario payload seed {} did not match request scenario seed {}",
                            scenario.seed().to_hex(),
                            scenario_seed.to_hex()
                        ));
                    }
                    if scenario.app_random_draw_cap() != app_random_draw_cap {
                        return Err(format!(
                            "scenario payload app-random draw cap {} did not match request cap {}",
                            scenario.app_random_draw_cap(),
                            app_random_draw_cap
                        ));
                    }
                    (Some(scenario), lines.next())
                } else {
                    (None, Some(line))
                }
            } else {
                (None, None)
            };
            let seed = parse_seed_line(seed_line, "seed=")?;
            let start_paused = parse_bool_line(lines.next(), "start-paused=")?;
            reject_extra_line(lines.next())?;
            let scenario = ScenarioDef::from_content_hash_seed_and_app_random_draw_cap(
                id,
                scenario_seed,
                app_random_draw_cap,
            );
            let request = if let Some(scenario_form) = scenario_form {
                CreateSessionRequest::inline_form(scenario_form, seed)
            } else {
                CreateSessionRequest::inline(scenario, seed)
            };
            Ok(request.with_start_paused(start_paused))
        }
        source => Err(format!("unexpected create-session source `{source}`")),
    }
}

fn parse_resume_session_request(body: &[u8]) -> Result<ResumeSessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/resume-session-request")?;
    let id = parse_content_hash_line(lines.next(), "scenario-id=")?;
    let scenario_seed = parse_seed_line(lines.next(), "scenario-seed=")?;
    let app_random_draw_cap = parse_u64_line(lines.next(), "app-random-draw-cap=")?;
    let scenario = parse_scenario_form_line(lines.next(), "scenario-payload=")?;
    let scenario_def = scenario.scenario_def();
    if scenario_def.id() != id {
        return Err(format!(
            "scenario payload id {} did not match request scenario id {}",
            scenario_def.id().to_hex(),
            id.to_hex()
        ));
    }
    if scenario.seed() != scenario_seed {
        return Err(format!(
            "scenario payload seed {} did not match request scenario seed {}",
            scenario.seed().to_hex(),
            scenario_seed.to_hex()
        ));
    }
    if scenario.app_random_draw_cap() != app_random_draw_cap {
        return Err(format!(
            "scenario payload app-random draw cap {} did not match request cap {}",
            scenario.app_random_draw_cap(),
            app_random_draw_cap
        ));
    }
    let seed = parse_seed_line(lines.next(), "seed=")?;
    let schedule = parse_schedule_line(lines.next(), "schedule=")?;
    let checkpoint = parse_checkpoint_line(lines.next(), "checkpoint=")?;
    reject_extra_line(lines.next())?;
    Ok(ResumeSessionRequest::new(
        scenario, schedule, checkpoint, seed,
    ))
}

fn parse_destroy_session_request(body: &[u8]) -> Result<DestroySessionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/destroy-session-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    reject_extra_line(lines.next())?;
    let mut request = DestroySessionRequest::new(session);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn parse_get_reproduction_request(body: &[u8]) -> Result<GetReproductionRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/get-reproduction-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    reject_extra_line(lines.next())?;
    let mut request = GetReproductionRequest::new(session);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn parse_attach_request(body: &[u8]) -> Result<AttachRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/attach-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    let from = EventLogCursor::new(parse_u64_line(lines.next(), "from-seq=")?);
    let client_name = parse_wire_line(lines.next(), "client-name=")?.to_owned();
    reject_extra_line(lines.next())?;
    let mut request = AttachRequest::new(session)
        .with_cursor(from)
        .with_client_name(client_name);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn parse_send_request(body: &[u8]) -> Result<SendRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/send-request")?;
    let session = parse_session_ref(&mut lines)?;
    let expected_epoch = parse_optional_epoch_line(lines.next(), "expected-epoch=")?;
    let command_id = parse_u64_line(lines.next(), "command-id=")?;
    let command_line = lines.next();
    let mut query_line = None;
    let mut savepoint_label_line = None;
    let mut step_duration_line = None;
    let mut breakpoint_predicate_line = None;
    let mut breakpoint_disposition_line = None;
    let mut breakpoint_policy_line = None;
    for line in lines {
        if line.starts_with("query=") {
            set_unique_payload_line(&mut query_line, line, "query")?;
        } else if line.starts_with("savepoint-label=") {
            set_unique_payload_line(&mut savepoint_label_line, line, "savepoint label")?;
        } else if line.starts_with("step-duration-nanos=") {
            set_unique_payload_line(&mut step_duration_line, line, "step duration")?;
        } else if line.starts_with("breakpoint-predicate=") {
            set_unique_payload_line(&mut breakpoint_predicate_line, line, "breakpoint predicate")?;
        } else if line.starts_with("breakpoint-disposition=") {
            set_unique_payload_line(
                &mut breakpoint_disposition_line,
                line,
                "breakpoint disposition",
            )?;
        } else if line.starts_with("breakpoint-policy=") {
            set_unique_payload_line(&mut breakpoint_policy_line, line, "breakpoint policy")?;
        } else {
            return Err(format!("unexpected trailing RPC request field `{line}`"));
        }
    }
    let command = parse_session_command(
        command_line,
        "command=",
        query_line,
        savepoint_label_line,
        step_duration_line,
        breakpoint_predicate_line,
        breakpoint_disposition_line,
        breakpoint_policy_line,
    )?;
    let mut request = SendRequest::new(session, command_id, command);
    if let Some(expected_epoch) = expected_epoch {
        request = request.with_expected_epoch(expected_epoch);
    }
    Ok(request)
}

fn set_unique_payload_line<'a>(
    slot: &mut Option<&'a str>,
    line: &'a str,
    label: &'static str,
) -> Result<(), String> {
    if slot.replace(line).is_some() {
        return Err(format!("duplicate {label} payload"));
    }
    Ok(())
}

fn parse_session_ref<'a, I>(lines: &mut I) -> Result<SessionRef, String>
where
    I: Iterator<Item = &'a str>,
{
    let id = parse_u64_line(lines.next(), "session-id=")?;
    let epoch = parse_u64_line(lines.next(), "epoch=")?;
    let seed = parse_seed_line(lines.next(), "seed=")?;
    Ok(SessionRef::new(SessionId::new(id), epoch, seed))
}

fn parse_version_line(line: Option<&str>, prefix: &'static str) -> Result<ProtocolVersion, String> {
    let value = parse_wire_line(line, prefix)?;
    let Some((semver, build)) = value.split_once('+') else {
        return Err(format!("version `{value}` is missing build metadata"));
    };
    if build != RPC_PROTOCOL_BUILD {
        return Err(format!("unsupported RPC build `{build}`"));
    }
    let mut fields = semver.split('.');
    let major = parse_u16_field(fields.next(), "version major")?;
    let minor = parse_u16_field(fields.next(), "version minor")?;
    let patch = parse_u16_field(fields.next(), "version patch")?;
    if fields.next().is_some() {
        return Err(format!("version `{value}` has too many fields"));
    }
    Ok(ProtocolVersion {
        major,
        minor,
        patch,
        build: RPC_PROTOCOL_BUILD,
    })
}

fn parse_u16_field(value: Option<&str>, label: &'static str) -> Result<u16, String> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    value
        .parse::<u16>()
        .map_err(|error| format!("invalid {label} `{value}`: {error}"))
}

fn parse_u64_line(line: Option<&str>, prefix: &'static str) -> Result<u64, String> {
    let value = parse_wire_line(line, prefix)?;
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid integer `{value}` for `{prefix}`: {error}"))
}

fn parse_optional_epoch_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<Option<u64>, String> {
    let value = parse_wire_line(line, prefix)?;
    if value == "none" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|error| format!("invalid integer `{value}` for `{prefix}`: {error}"))
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn parse_session_command(
    line: Option<&str>,
    prefix: &'static str,
    query_line: Option<&str>,
    savepoint_label_line: Option<&str>,
    step_duration_line: Option<&str>,
    breakpoint_predicate_line: Option<&str>,
    breakpoint_disposition_line: Option<&str>,
    breakpoint_policy_line: Option<&str>,
) -> Result<SessionCommand, String> {
    let command_kind_wire = parse_wire_line(line, prefix)?;
    let command_kind = session_command_for_open_set_command_kind(command_kind_wire)
        .ok_or_else(|| format!("unknown command `{command_kind_wire}`"))?;
    if command_kind == SessionCommandKind::Query {
        if savepoint_label_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a savepoint label"
            ));
        }
        if step_duration_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a step duration"
            ));
        }
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        let query_line = query_line
            .ok_or_else(|| format!("command `{command_kind_wire}` requires a query payload"))?;
        return Ok(SessionCommand::Query {
            kind: parse_query_kind_line(Some(query_line))?,
            reply: crucible_session::CommandReply::discard(),
        });
    } else if command_kind == SessionCommandKind::CreateSavepoint {
        if query_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a query payload"
            ));
        }
        if step_duration_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a step duration"
            ));
        }
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        let label = match savepoint_label_line {
            Some(line) => parse_hex_string_field(
                Some(parse_wire_line(Some(line), "savepoint-label=")?),
                "savepoint label",
            )?,
            None => String::from("lifecycle-model"),
        };
        return Ok(SessionCommand::CreateSavepoint {
            label,
            reply: crucible_session::CommandReply::discard(),
        });
    } else if command_kind == SessionCommandKind::StepDuration {
        if query_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a query payload"
            ));
        }
        if savepoint_label_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a savepoint label"
            ));
        }
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        let nanos = match step_duration_line {
            Some(line) => parse_u64_line(Some(line), "step-duration-nanos=")?,
            None => crucible_session::StepMode::DEFAULT_DURATION.nanos,
        };
        return Ok(SessionCommand::Step {
            mode: crucible_session::StepMode::Duration(crucible::SimDuration { nanos }),
        });
    } else if command_kind == SessionCommandKind::SetBreakpoint {
        if query_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a query payload"
            ));
        }
        if savepoint_label_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a savepoint label"
            ));
        }
        if step_duration_line.is_some() {
            return Err(format!(
                "command `{command_kind_wire}` does not accept a step duration"
            ));
        }
        let spec = parse_breakpoint_spec_lines(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
        return Ok(SessionCommand::SetBreakpoint {
            spec,
            reply: crucible_session::CommandReply::discard(),
        });
    } else if query_line.is_some() {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a query payload"
        ));
    } else if savepoint_label_line.is_some() {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a savepoint label"
        ));
    } else if step_duration_line.is_some() {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a step duration"
        ));
    } else {
        reject_breakpoint_payload_fields(
            command_kind_wire,
            breakpoint_predicate_line,
            breakpoint_disposition_line,
            breakpoint_policy_line,
        )?;
    }
    command_kind
        .representative_command()
        .ok_or_else(|| format!("command `{command_kind_wire}` has no representative payload"))
}

fn reject_breakpoint_payload_fields(
    command_kind_wire: &str,
    breakpoint_predicate_line: Option<&str>,
    breakpoint_disposition_line: Option<&str>,
    breakpoint_policy_line: Option<&str>,
) -> Result<(), String> {
    if breakpoint_predicate_line.is_some()
        || breakpoint_disposition_line.is_some()
        || breakpoint_policy_line.is_some()
    {
        return Err(format!(
            "command `{command_kind_wire}` does not accept a breakpoint payload"
        ));
    }
    Ok(())
}

fn parse_breakpoint_spec_lines(
    command_kind_wire: &str,
    predicate_line: Option<&str>,
    disposition_line: Option<&str>,
    policy_line: Option<&str>,
) -> Result<BreakpointSpec, String> {
    let predicate_line = predicate_line
        .ok_or_else(|| format!("command `{command_kind_wire}` requires a breakpoint predicate"))?;
    let disposition_line = disposition_line.ok_or_else(|| {
        format!("command `{command_kind_wire}` requires a breakpoint disposition")
    })?;
    let policy_line = policy_line
        .ok_or_else(|| format!("command `{command_kind_wire}` requires a breakpoint policy"))?;
    let predicate = parse_breakpoint_predicate_line(Some(predicate_line))?;
    let disposition = parse_breakpoint_disposition_line(Some(disposition_line))?;
    let policy = parse_breakpoint_policy_line(Some(policy_line))?;
    Ok(BreakpointSpec {
        predicate,
        disposition,
        policy,
    })
}

fn parse_breakpoint_predicate_line(line: Option<&str>) -> Result<crucible::Predicate, String> {
    let value = parse_wire_line(line, "breakpoint-predicate=")?;
    let bytes = parse_hex_bytes(value)?;
    crucible::Predicate::from_compact_binary(&bytes)
        .map_err(|error| format!("invalid breakpoint predicate: {error}"))
}

fn parse_breakpoint_disposition_line(line: Option<&str>) -> Result<BreakpointDisposition, String> {
    let value = parse_wire_line(line, "breakpoint-disposition=")?;
    if value == "suspend" {
        return Ok(BreakpointDisposition::Suspend);
    }
    if value == "trace" {
        return Ok(BreakpointDisposition::Trace);
    }
    let Some(action) = value.strip_prefix("action:") else {
        return Err(format!("invalid breakpoint disposition `{value}`"));
    };
    let bytes = parse_hex_bytes(action)?;
    let action = crucible::Action::from_compact_binary(&bytes)
        .map_err(|error| format!("invalid breakpoint action disposition: {error}"))?;
    Ok(BreakpointDisposition::Action(action))
}

fn parse_breakpoint_policy_line(line: Option<&str>) -> Result<BreakpointPolicy, String> {
    match parse_wire_line(line, "breakpoint-policy=")? {
        "one-shot" => Ok(BreakpointPolicy::OneShot),
        "repeatable" => Ok(BreakpointPolicy::Repeatable),
        value => Err(format!("invalid breakpoint policy `{value}`")),
    }
}

fn reject_extra_query_field(field: Option<&str>) -> Result<(), String> {
    if field.is_some() {
        return Err(String::from("unexpected extra query fields"));
    }
    Ok(())
}

fn parse_seed_line(line: Option<&str>, prefix: &'static str) -> Result<Seed, String> {
    let value = parse_wire_line(line, prefix)?;
    Ok(Seed::from_bytes(parse_hex_32(value, "seed")?))
}

fn parse_content_hash_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<ContentHash, String> {
    let value = parse_wire_line(line, prefix)?;
    Ok(ContentHash {
        bytes: parse_hex_32(value, "content hash")?,
    })
}

fn parse_schedule_line(line: Option<&str>, prefix: &'static str) -> Result<Schedule, String> {
    let value = parse_wire_line(line, prefix)?;
    let bytes = parse_hex_bytes(value)?;
    Schedule::from_compact_binary(&bytes).map_err(|error| format!("invalid schedule: {error}"))
}

fn parse_scenario_form_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<ScenarioDefForm, String> {
    let value = parse_wire_line(line, prefix)?;
    let bytes = parse_hex_bytes(value)?;
    ScenarioDefForm::from_compact_binary(&bytes)
        .map_err(|error| format!("invalid scenario form: {error}"))
}

fn parse_checkpoint_line(line: Option<&str>, prefix: &'static str) -> Result<Checkpoint, String> {
    let value = parse_wire_line(line, prefix)?;
    let bytes = parse_hex_bytes(value)?;
    Checkpoint::from_compact_binary(&bytes).map_err(|error| format!("invalid checkpoint: {error}"))
}

fn parse_hex_string_field(value: Option<&str>, label: &'static str) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    String::from_utf8(parse_hex_bytes(value)?)
        .map_err(|error| format!("invalid UTF-8 {label}: {error}"))
}

fn parse_hex_32(value: &str, label: &'static str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} hex has length {}", value.len()));
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index.saturating_mul(2);
        let pair = &value[start..start.saturating_add(2)];
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|error| format!("invalid {label} hex `{pair}`: {error}"))?;
    }
    Ok(bytes)
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", value.len()));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let pair = &value[index..index + 2];
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|error| format!("invalid hex byte `{pair}`: {error}"))?,
        );
    }
    Ok(bytes)
}

fn parse_bool_line(line: Option<&str>, prefix: &'static str) -> Result<bool, String> {
    match parse_wire_line(line, prefix)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(format!("invalid bool `{value}` for `{prefix}`")),
    }
}

fn expect_wire_header(line: Option<&str>, expected: &'static str) -> Result<(), String> {
    match line {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("unexpected RPC message header `{actual}`")),
        None => Err(String::from("empty RPC request")),
    }
}

fn parse_wire_line<'a>(line: Option<&'a str>, prefix: &'static str) -> Result<&'a str, String> {
    let line = line.ok_or_else(|| format!("missing `{prefix}` line"))?;
    line.strip_prefix(prefix)
        .ok_or_else(|| format!("expected `{prefix}` line, got `{line}`"))
}

fn reject_extra_line(line: Option<&str>) -> Result<(), String> {
    if let Some(line) = line {
        return Err(format!("unexpected trailing RPC request field `{line}`"));
    }
    Ok(())
}

fn encode_list_scenarios_response(response: &ListScenariosResponse) -> String {
    let mut output = String::from("crucible.rpc/list-scenarios-response\n");
    for scenario in &response.scenarios {
        output.push_str("scenario=");
        output.push_str(&scenario.name);
        output.push('|');
        output.push_str(&scenario.description);
        output.push('|');
        output.push_str(&scenario.source_id);
        output.push('\n');
    }
    output
}

fn encode_create_session_response(response: &CreateSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/create-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    output
}

fn encode_resume_session_response(response: &ResumeSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/resume-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    push_wire_line(&mut output, "checkpoint", &response.checkpoint.to_hex());
    push_wire_line(
        &mut output,
        "configuration",
        &response.configuration.to_hex(),
    );
    output
}

fn encode_list_sessions_response(response: &ListSessionsResponse) -> String {
    let mut output = String::from("crucible.rpc/list-sessions-response\n");
    for session in &response.sessions {
        output.push_str("session=");
        output.push_str(&session.session.id.value.to_string());
        output.push('|');
        output.push_str(&session.session.epoch.to_string());
        output.push('|');
        output.push_str(&session.session.seed.to_hex());
        output.push('|');
        output.push_str(state_wire_name(session.state));
        output.push('|');
        output.push_str(&session.event_log_len.to_string());
        output.push('|');
        output.push_str(&session.frontier.ticks.to_string());
        output.push('|');
        output.push_str(&session.quanta_stepped.to_string());
        output.push('|');
        output.push_str(outcome_wire_name(session.outcome));
        output.push('|');
        output.push_str(&content_hash_option_wire(session.terminal_savepoint));
        output.push('\n');
    }
    output
}

fn encode_destroy_session_response(response: &DestroySessionResponse) -> String {
    let mut output = String::from("crucible.rpc/destroy-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(
        &mut output,
        "already-absent",
        if response.already_absent {
            "true"
        } else {
            "false"
        },
    );
    push_wire_line(
        &mut output,
        "stopped",
        if response.stopped { "true" } else { "false" },
    );
    output
}

fn encode_get_reproduction_response(response: &GetReproductionResponse) -> String {
    let mut output = String::from("crucible.rpc/get-reproduction-response\n");
    push_session_ref(&mut output, response.session);
    for command in &response.commands {
        push_wire_line(&mut output, "command", &reproduction_record_wire(command));
    }
    output
}

fn encode_attached_response(attached: &Attached) -> String {
    let mut output = String::from("crucible.rpc/attached-response\n");
    push_session_ref(&mut output, attached.session);
    push_wire_line(
        &mut output,
        "event-log-len",
        &attached.event_log_len.to_string(),
    );
    push_wire_line(&mut output, "state", state_wire_name(attached.state));
    push_wire_line(
        &mut output,
        "version",
        &format!(
            "{}.{}.{}+{}",
            attached.version.major,
            attached.version.minor,
            attached.version.patch,
            attached.version.build
        ),
    );
    let commands = attached
        .capabilities
        .commands
        .iter()
        .map(|capability| {
            open_set_command_kind(capability.command_kind)
                .unwrap_or_else(|| format!("crucible.cmd.{}", capability.command_name))
        })
        .collect::<Vec<_>>()
        .join(",");
    push_wire_line(&mut output, "commands", &commands);
    push_wire_line(&mut output, "snapshot", &snapshot_wire(attached));
    let reproduction = attached
        .snapshot
        .as_ref()
        .map(|snapshot| reproduction_records_wire(&snapshot.reproduction))
        .unwrap_or_else(|| String::from("none"));
    push_wire_line(&mut output, "reproduction", &reproduction);
    output
}

fn encode_send_response(response: &SendResponse) -> String {
    let mut output = String::from("crucible.rpc/send-response\n");
    push_wire_line(
        &mut output,
        "command-id",
        &response.result.command_id.to_string(),
    );
    push_wire_line(
        &mut output,
        "command",
        &command_name(response.result.command_kind),
    );
    push_wire_line(
        &mut output,
        "status",
        &command_status_wire(response.result.status),
    );
    match response.state_update {
        Some(update) => push_wire_line(&mut output, "state-update", &state_update_wire(update)),
        None => push_wire_line(&mut output, "state-update", "none"),
    }
    push_wire_line(
        &mut output,
        "query-result",
        &query_result_wire(response.query_result.as_ref()),
    );
    push_wire_line(
        &mut output,
        "breakpoint-id",
        &breakpoint_id_wire(response.breakpoint_id),
    );
    push_wire_line(
        &mut output,
        "savepoint-info",
        &savepoint_info_wire(response.savepoint_info.as_ref()),
    );
    output
}

fn breakpoint_firings_wire(firings: &[crucible_session::BreakpointFiring]) -> String {
    let mut output = format!("breakpoint-firings|{}", firings.len());
    for firing in firings {
        output.push('|');
        output.push_str(&firing.sequence.to_string());
        output.push('|');
        output.push_str(&firing.id.to_string());
        output.push('|');
        output.push_str(&firing.frontier.ticks.to_string());
        output.push('|');
        output.push_str(&firing.quanta.to_string());
        output.push('|');
        output.push_str(&hex_encode(&firing.predicate.to_compact_binary()));
        output.push('|');
        output.push_str(&breakpoint_disposition_wire(&firing.disposition));
        output.push('|');
        output.push_str(&firing.scheduler_controls.len().to_string());
        for control in &firing.scheduler_controls {
            output.push('|');
            output.push_str(&hex_encode(&control.to_compact_binary()));
        }
    }
    output
}

fn breakpoint_disposition_wire(disposition: &BreakpointDisposition) -> String {
    match disposition {
        BreakpointDisposition::Suspend => String::from("suspend"),
        BreakpointDisposition::Trace => String::from("trace"),
        BreakpointDisposition::Action(action) => {
            format!("action:{}", hex_encode(&action.to_compact_binary()))
        }
    }
}

fn breakpoint_id_wire(id: Option<crucible_session::BreakpointId>) -> String {
    id.map(|id| id.to_string())
        .unwrap_or_else(|| String::from("none"))
}

fn savepoint_info_wire(info: Option<&crucible_session::SavepointInfo>) -> String {
    match info {
        Some(info) => format!(
            "savepoint|{}|{}|{}",
            hex_encode(info.label.as_bytes()),
            info.configuration.to_hex(),
            hex_encode(&info.checkpoint.to_compact_binary())
        ),
        None => String::from("none"),
    }
}

fn snapshot_engine_state_wire(state: &EngineState) -> String {
    match state {
        EngineState::Loaded => String::from("loaded"),
        EngineState::Running => String::from("running"),
        EngineState::Paused { reason } => format!("paused:{}", pause_reason_wire(reason)),
        EngineState::Stopped { outcome } => format!("stopped:{}", snapshot_outcome_wire(outcome)),
    }
}

fn pause_reason_wire(reason: &PauseReason) -> String {
    match reason {
        PauseReason::Instantiated => String::from("instantiated"),
        PauseReason::UserRequested => String::from("user-requested"),
        PauseReason::Breakpoint { id } => format!("breakpoint:{id}"),
        PauseReason::StepComplete { mode } => format!("step:{}", step_mode_wire(*mode)),
    }
}

fn step_mode_wire(mode: StepMode) -> String {
    match mode {
        StepMode::Quantum => String::from("quantum"),
        StepMode::Event => String::from("event"),
        StepMode::Assertion => String::from("assertion"),
        StepMode::Timer => String::from("timer"),
        StepMode::Duration(duration) => format!("duration:{}", duration.nanos),
    }
}

fn snapshot_outcome_wire(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Passed => String::from("passed"),
        Outcome::Failed { violations } => {
            let violations = violations
                .iter()
                .map(|violation| hex_encode(violation.as_bytes()))
                .collect::<Vec<_>>()
                .join(",");
            format!("failed:{violations}")
        }
        Outcome::Timeout => String::from("timeout"),
        Outcome::Crashed { detail } => format!("crashed:{}", hex_encode(detail.as_bytes())),
        Outcome::Stopped => String::from("stopped"),
    }
}

fn control_event_body(
    control: ControlStream,
    shutdown: watch::Receiver<bool>,
) -> impl futures_util::Stream<Item = Result<Bytes, Infallible>> {
    let attached = framed_rpc_message(encode_attached_response(control.attached()));
    stream::unfold(
        (control, shutdown, Some(attached)),
        |(mut control, mut shutdown, pending)| async move {
            if let Some(message) = pending {
                return Some((Ok(message), (control, shutdown, None)));
            }
            if *shutdown.borrow() {
                return None;
            }
            // crucible-lint: allow unordered-select -- stream delivery may race with shutdown without affecting engine state.
            let frame = tokio::select! {
                frame = control.recv_frame() => match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => return None,
                },
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return None;
                    }
                    return None;
                }
            };
            Some((
                Ok(framed_rpc_message(encode_streaming_frame(&frame))),
                (control, shutdown, None),
            ))
        },
    )
}

fn watch_event_body(
    watch: WatchStream,
    shutdown: watch::Receiver<bool>,
) -> impl futures_util::Stream<Item = Result<Bytes, Infallible>> {
    let attached = framed_rpc_message(encode_attached_response(watch.attached()));
    stream::unfold(
        (watch, shutdown, Some(attached)),
        |(mut watch, mut shutdown, pending)| async move {
            if let Some(message) = pending {
                return Some((Ok(message), (watch, shutdown, None)));
            }
            if *shutdown.borrow() {
                return None;
            }
            // crucible-lint: allow unordered-select -- watch delivery may race with shutdown without affecting engine state.
            let frame = tokio::select! {
                frame = watch.recv_frame() => match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => return None,
                },
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return None;
                    }
                    return None;
                }
            };
            Some((
                Ok(framed_rpc_message(encode_streaming_frame(&frame))),
                (watch, shutdown, None),
            ))
        },
    )
}

fn encode_streaming_frame(frame: &StreamingFrame) -> String {
    match frame {
        StreamingFrame::Event(frame) => encode_streaming_event_frame(frame),
        StreamingFrame::StateUpdate(frame) => encode_streaming_state_update_frame(*frame),
    }
}

fn encode_streaming_event_frame(frame: &StreamingEventFrame) -> String {
    let mut output = String::from("crucible.rpc/event-frame\n");
    push_wire_line(&mut output, "generation", &frame.generation.to_string());
    push_wire_line(
        &mut output,
        "cursor",
        &frame.cursor.next_sequence.to_string(),
    );
    push_wire_line(
        &mut output,
        "next-cursor",
        &frame.next_cursor.next_sequence.to_string(),
    );
    push_wire_line(&mut output, "sequence", &frame.event.sequence.to_string());
    push_wire_line(
        &mut output,
        "virtual-time-ticks",
        &frame.event.at.virtual_time_ticks.to_string(),
    );
    push_wire_line(
        &mut output,
        "icount-retired",
        &frame.event.at.icount_retired.to_string(),
    );
    push_wire_line(
        &mut output,
        "icount-node",
        &optional_string_wire(frame.event.at.icount_node.as_deref()),
    );
    push_wire_line(
        &mut output,
        "source",
        &event_source_wire(&frame.event.source),
    );
    push_wire_line(&mut output, "level", event_level_wire(frame.event.level));
    push_wire_line(
        &mut output,
        "observational",
        if frame.event.observational {
            "true"
        } else {
            "false"
        },
    );
    push_wire_line(&mut output, "kind", &frame.event.payload.kind);
    for (name, value) in &frame.event.payload.attributes {
        push_wire_line(
            &mut output,
            "attribute",
            &format!("{}|{}", hex_encode(name.as_bytes()), attribute_wire(value)),
        );
    }
    output
}

fn encode_streaming_state_update_frame(frame: StreamingStateUpdateFrame) -> String {
    let mut output = String::from("crucible.rpc/state-update-frame\n");
    push_wire_line(&mut output, "sequence", &frame.sequence.to_string());
    push_wire_line(
        &mut output,
        "state-update",
        &state_update_wire(frame.update),
    );
    output
}

fn lifecycle_error_response(error: LifecycleApiError) -> Response {
    match error {
        LifecycleApiError::EpochMismatch {
            session_id,
            expected,
            actual,
        } => lifecycle_epoch_mismatch_response(session_id, expected, actual),
        LifecycleApiError::ScenarioNotFound { name } => {
            let mut output = String::from("crucible.rpc/error\n");
            push_wire_line(&mut output, "status", "not-found");
            push_wire_line(&mut output, "reason", "scenario-not-found");
            push_wire_line(&mut output, "name", &hex_encode(name.as_bytes()));
            http2_response(StatusCode::NOT_FOUND, output)
        }
        LifecycleApiError::SessionNotFound { session } => {
            lifecycle_session_not_found_response(session)
        }
        LifecycleApiError::SessionLimitReached { .. } => typed_rpc_status_response(
            StatusCode::TOO_MANY_REQUESTS,
            RpcStatusCode::InvalidState,
            "session-limit",
            &error.to_string(),
        ),
        LifecycleApiError::ScenarioSeedMismatch { .. }
        | LifecycleApiError::InlineScenarioIdentityMismatch { .. }
        | LifecycleApiError::ResumeCheckpoint { .. } => typed_rpc_status_response(
            StatusCode::BAD_REQUEST,
            RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        LifecycleApiError::DebugAccess { .. } | LifecycleApiError::DebugEndpointUnavailable => {
            typed_rpc_status_response(
                StatusCode::FORBIDDEN,
                RpcStatusCode::InvalidState,
                "debug-access-denied",
                &error.to_string(),
            )
        }
        LifecycleApiError::SessionCommandRejected { .. } => typed_rpc_status_response(
            StatusCode::CONFLICT,
            RpcStatusCode::InvalidState,
            "session-command-rejected",
            &error.to_string(),
        ),
        LifecycleApiError::RpcAbi { .. }
        | LifecycleApiError::GenesisGraph { .. }
        | LifecycleApiError::LoopFactory { .. }
        | LifecycleApiError::AttemptOperational { .. }
        | LifecycleApiError::CommandChannelClosed { .. }
        | LifecycleApiError::StateDidNotAdvance { .. }
        | LifecycleApiError::ActorJoin { .. }
        | LifecycleApiError::ActorFailed { .. } => typed_rpc_status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

fn debug_relay_error_response(error: crate::DebugRelayError) -> Response {
    let status = match &error {
        crate::DebugRelayError::NotFound => StatusCode::NOT_FOUND,
        crate::DebugRelayError::StaleOrForeignLease => StatusCode::FORBIDDEN,
        crate::DebugRelayError::InvalidGatewayEndpoint
        | crate::DebugRelayError::GatewayEndpointNotLoopback
        | crate::DebugRelayError::ChunkTooLarge { .. }
        | crate::DebugRelayError::InvalidReadMaximum { .. } => StatusCode::BAD_REQUEST,
        crate::DebugRelayError::CapacityExhausted => StatusCode::TOO_MANY_REQUESTS,
        crate::DebugRelayError::Busy => StatusCode::CONFLICT,
        crate::DebugRelayError::Connect { .. }
        | crate::DebugRelayError::ConnectTimeout
        | crate::DebugRelayError::IdentifierExhausted
        | crate::DebugRelayError::Io { .. }
        | crate::DebugRelayError::IoTimeout => StatusCode::BAD_GATEWAY,
    };
    http2_response(status, error.to_string())
}

fn streaming_error_response(error: StreamingApiError) -> Response {
    match error {
        StreamingApiError::EpochMismatch { expected, actual } => {
            streaming_epoch_mismatch_response(expected, actual)
        }
        StreamingApiError::SessionNotFound { session } => {
            streaming_session_not_found_response(session)
        }
        StreamingApiError::SessionMismatch { .. } => typed_rpc_status_response(
            StatusCode::BAD_REQUEST,
            RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        StreamingApiError::CommandChannelClosed { .. }
        | StreamingApiError::StateDidNotAdvance { .. }
        | StreamingApiError::EventStreamLagged { .. }
        | StreamingApiError::StateUpdateStreamLagged { .. } => typed_rpc_status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

fn lifecycle_epoch_mismatch_response(
    session_id: SessionId,
    expected: u64,
    actual: u64,
) -> Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "epoch-mismatch");
    push_wire_line(&mut output, "session-id", &session_id.value.to_string());
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(StatusCode::PRECONDITION_FAILED, output)
}

fn lifecycle_session_not_found_response(session: SessionRef) -> Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "lifecycle-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(StatusCode::NOT_FOUND, output)
}

fn streaming_session_not_found_response(session: SessionRef) -> Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "streaming-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(StatusCode::NOT_FOUND, output)
}

fn streaming_epoch_mismatch_response(expected: u64, actual: u64) -> Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "streaming-epoch-mismatch");
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(StatusCode::PRECONDITION_FAILED, output)
}

fn send_parse_error_response(error: &str) -> Response {
    let (status, reason) = if error.starts_with("unknown command")
        || error.contains("has no representative payload")
    {
        (RpcStatusCode::Unsupported, "unsupported")
    } else {
        (RpcStatusCode::InvalidArgument, "invalid-argument")
    };
    typed_rpc_status_response(StatusCode::BAD_REQUEST, status, reason, error)
}

fn read_only_rejection_response(operation: &str) -> Response {
    let message = format!("read-only daemon rejects state-mutating API call `{operation}`");
    typed_rpc_status_response(
        StatusCode::FORBIDDEN,
        RpcStatusCode::Unsupported,
        "read-only",
        &message,
    )
}

fn typed_rpc_status_response(
    http_status: StatusCode,
    status: RpcStatusCode,
    reason: &'static str,
    message: &str,
) -> Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", rpc_status_code_wire_name(status));
    push_wire_line(&mut output, "reason", reason);
    push_wire_line(&mut output, "message", &hex_encode(message.as_bytes()));
    http2_response(http_status, output)
}

fn http2_stream_response(
    body: impl futures_util::Stream<Item = Result<Bytes, Infallible>> + Send + 'static,
) -> Response {
    http2_response(StatusCode::OK, Body::from_stream(body))
}

fn http2_response(status: StatusCode, body: impl Into<Body>) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    response
}

fn framed_rpc_message(message: String) -> Bytes {
    let mut message = message;
    message.push('\n');
    Bytes::from(message)
}

fn snapshot_wire(attached: &Attached) -> String {
    let Some(snapshot) = &attached.snapshot else {
        return String::from("none");
    };
    let last = snapshot
        .last_sequence
        .map(|sequence| sequence.to_string())
        .unwrap_or_else(|| String::from("none"));
    format!(
        "{}|{}|{}|{}|{}",
        snapshot.through.next_sequence,
        snapshot.event_count,
        snapshot.causal_event_count,
        snapshot.observational_event_count,
        last,
    )
}

fn reproduction_records_wire(commands: &[ReproductionCommandRecord]) -> String {
    if commands.is_empty() {
        return String::from("none");
    }
    commands
        .iter()
        .map(reproduction_record_wire)
        .collect::<Vec<_>>()
        .join(";")
}

fn reproduction_record_wire(command: &ReproductionCommandRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        command.sequence,
        command_name(command.payload.command),
        command.virtual_time.ticks,
        command.quanta,
        command.at_sequence,
        match command.result {
            ReproductionCommandResult::Accepted => "accepted",
        },
        command.observational_order,
        command.payload.scheduler_batch,
        scheduler_control_wire(command.payload.scheduler_control.as_ref()),
        command_payload_material_wire(&command.payload.command_payload),
    )
}

fn command_payload_material_wire(material: &str) -> String {
    hex_encode(material.as_bytes())
}

fn scheduler_control_wire(control: Option<&String>) -> String {
    control
        .map(|material| hex_encode(material.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

fn command_status_wire(status: CommandResultStatus) -> String {
    match status {
        CommandResultStatus::Accepted => String::from("accepted"),
        CommandResultStatus::Rejected { reason } => {
            format!(
                "rejected:{}",
                rpc_status_code_wire_name(reason.rpc_status())
            )
        }
    }
}

fn state_update_wire(update: StateUpdate) -> String {
    format!(
        "{}|{}|{}|{}",
        update.session.id.value,
        update.session.epoch,
        update.session.seed.to_hex(),
        state_wire_name(update.state),
    )
}

fn optional_string_wire(value: Option<&str>) -> String {
    value
        .map(|value| hex_encode(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

fn event_source_wire(source: &OpenSetEventSource) -> String {
    match source {
        OpenSetEventSource::Scenario { event } => {
            format!("scenario|{}", hex_encode(event.as_bytes()))
        }
        OpenSetEventSource::Engine => String::from("engine"),
        OpenSetEventSource::Node { node } => format!("node|{}", hex_encode(node.as_bytes())),
        OpenSetEventSource::Guest { node } => format!("guest|{}", hex_encode(node.as_bytes())),
        OpenSetEventSource::Command { command_id } => format!("command|{command_id}"),
    }
}

fn event_level_wire(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests;

mod query_wire;

#[path = "server/debug_reposition.rs"]
mod debug_reposition;
mod debug_wire;

use debug_reposition::*;
use debug_wire::*;
use query_wire::*;
