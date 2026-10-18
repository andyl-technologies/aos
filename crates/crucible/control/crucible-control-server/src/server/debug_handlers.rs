//! HTTP/2 debugger authorization, relay, and guest-control handlers.

use super::*;

pub(super) async fn handle_debug_guest_fork<L, F>(
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
        Err(response) => return *response,
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
        return *response;
    }
    let dispatch = {
        let control_plane = state.control_plane.lock().await;
        if let Err(error) = control_plane.authorize_debug_branch_fork(session, &lease, &role) {
            return lifecycle_error_response(error);
        }
        match control_plane.debug_branch_fork_dispatch(session) {
            Ok(dispatch) => dispatch,
            Err(error) => return lifecycle_error_response(error),
        }
    };
    let operation_state = state.clone();
    let result = match complete_debug_operation(operation_guard, async move {
        let report = dispatch.fork(node).await?;
        operation_state
            .control_plane
            .lock()
            .await
            .commit_writable_debug_branch(session, &report)?;
        Ok(report)
    })
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

pub(super) async fn handle_debug_guest_exchange<L, F>(
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
        Err(response) => return *response,
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
        return *response;
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

pub(super) async fn handle_debug_controller_acquire<L, F>(
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
        Err(response) => return *response,
    };
    let (session, holder) = match parse_debug_controller_acquire_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let stale = state.debug_relays.lock().await.remove_stale(session);
    for (lease, holder) in stale {
        if let Err(response) = release_debug_holder(&state, session, &lease, holder).await {
            return *response;
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

pub(super) async fn handle_debug_attach<L, F>(
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
        Err(response) => return *response,
    };
    let (session, generation, holder, node) = match parse_debug_attach_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let operation_guard = debug_operation_guard(&state, session).await;
    let lease = DebugControllerLease { client, generation };
    if let Err(response) = authorize_debug_holder(&state, session, &lease, holder).await {
        return *response;
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

pub(super) async fn handle_debug_controller_release<L, F>(
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
        Err(response) => return *response,
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
            return *response;
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
        return *response;
    }
    http2_response(
        StatusCode::OK,
        "crucible.rpc/debug-controller-release-response\n",
    )
}

pub(super) async fn handle_debug_relay_open<L, F>(
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
        Err(response) => return *response,
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
    let (endpoint, relay_access) = {
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
        let relay_access = match control_plane.debug_relay_access(session) {
            Ok(access) => access,
            Err(error) => return lifecycle_error_response(error),
        };
        match control_plane.debug_operator_target(session).await {
            Ok((_node, endpoint)) => (endpoint, relay_access),
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
            .register(stream, session, lease, holder, relay_access)
        {
            Ok(id) => id,
            Err(error) => return debug_relay_error_response(error),
        }
    };
    let mut output = String::from("crucible.rpc/debug-relay-open-response\n");
    push_wire_line(&mut output, "relay-id", &id.0.to_string());
    http2_response(StatusCode::OK, output)
}

pub(super) async fn handle_debug_relay_write<L, F>(
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
        Err(response) => return *response,
    };
    let (session, generation, holder, id, bytes) = match parse_debug_relay_write_request(&body) {
        Ok(request) => request,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    if let Err(response) = authorize_relay_role(&role) {
        return *response;
    }
    let _operation_guard = debug_operation_guard(&state, session).await;
    let prepared_write = {
        let mut relays = state.debug_relays.lock().await;
        relays.prepare_write(id, session, &client, generation, holder, &bytes)
    };
    let (stream, forwarded) = match prepared_write {
        Ok(prepared) => prepared,
        Err(error) => {
            close_failed_relay(&state, session, &client, generation, holder, id).await;
            return debug_relay_error_response(error);
        }
    };
    if !forwarded.is_empty()
        && let Err(error) = DebugRelayRegistry::write_stream(stream, &forwarded).await
    {
        close_failed_relay(&state, session, &client, generation, holder, id).await;
        return debug_relay_error_response(error);
    }
    let mut output = String::from("crucible.rpc/debug-relay-write-response\n");
    push_wire_line(&mut output, "written", &bytes.len().to_string());
    http2_response(StatusCode::OK, output)
}

pub(super) async fn handle_debug_relay_read<L, F>(
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
        Err(response) => return *response,
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

pub(super) async fn handle_debug_relay_close<L, F>(
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
        Err(response) => return *response,
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
        return *response;
    }
    http2_response(StatusCode::OK, "crucible.rpc/debug-relay-close-response\n")
}

pub(super) fn authorize_relay_role(role: &DebugRole) -> Result<(), Box<Response>> {
    if role.allows(DebugCapability::Control) && role.allows(DebugCapability::Observe) {
        return Ok(());
    }
    Err(Box::new(http2_response(
        StatusCode::FORBIDDEN,
        "debug relay requires observe and control capabilities",
    )))
}

pub(super) async fn release_debug_holder<L, F>(
    state: &Http2LifecycleState<L, F>,
    session: SessionRef,
    lease: &DebugControllerLease,
    holder: DebugControllerHolderId,
) -> Result<(), Box<Response>>
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
        .map_err(|error| Box::new(http2_response(StatusCode::FORBIDDEN, error.to_string())))?;
    if release != DebugHolderRelease::Final {
        return Ok(());
    }
    if let Err(error) = control_plane.release_debug_controller(session, lease) {
        holders.restore(session, lease.clone(), holder);
        return Err(Box::new(lifecycle_error_response(error)));
    }
    Ok(())
}

pub(super) async fn authorize_debug_holder<L, F>(
    state: &Http2LifecycleState<L, F>,
    session: SessionRef,
    lease: &DebugControllerLease,
    holder: DebugControllerHolderId,
) -> Result<(), Box<Response>>
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
        .map_err(|error| Box::new(http2_response(StatusCode::FORBIDDEN, error.to_string())))
}

pub(super) async fn close_failed_relay<L, F>(
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

pub(super) fn debug_principal(
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
