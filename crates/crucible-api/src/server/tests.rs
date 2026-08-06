//! Regression tests for the HTTP/2 lifecycle server.
//!
//! These tests exercise request parsing, authorization, lifecycle limits,
//! and typed transport responses through the private server surface.

use std::error::Error;

use axum::body::to_bytes;
use axum::extract::State;
use axum::http::Version;

use crate::lifecycle::QuiescentLifecycleLoop;

use super::*;

const TEST_SEED: &str = "000000000000000000000000000000000000000000000000000000000000004d";

type TestState = Http2LifecycleState<
    QuiescentLifecycleLoop,
    crate::lifecycle::LifecycleLoopFactory<QuiescentLifecycleLoop>,
>;

fn quiescent_loop(_: &ScenarioDef, _: Seed) -> QuiescentLifecycleLoop {
    QuiescentLifecycleLoop::new()
}

fn open_shutdown_receiver() -> watch::Receiver<bool> {
    let (_sender, receiver) = watch::channel(false);
    receiver
}

fn test_state(mode: LifecycleServerMode) -> TestState {
    Http2LifecycleState {
        control_plane: Arc::new(Mutex::new(LifecycleControlPlane::new(
            "server-test",
            Vec::new(),
            quiescent_loop as fn(&ScenarioDef, Seed) -> QuiescentLifecycleLoop,
        ))),
        mode,
        shutdown: open_shutdown_receiver(),
        debug_authorization: DebugAuthorizationPolicy::deny_all(),
        debug_relays: Arc::new(Mutex::new(DebugRelayRegistry::default())),
    }
}

fn test_state_with_max_sessions(mode: LifecycleServerMode, max_sessions: usize) -> TestState {
    Http2LifecycleState {
        control_plane: Arc::new(Mutex::new(
            LifecycleControlPlane::new(
                "server-test",
                Vec::new(),
                quiescent_loop as fn(&ScenarioDef, Seed) -> QuiescentLifecycleLoop,
            )
            .with_max_sessions(max_sessions),
        )),
        mode,
        shutdown: open_shutdown_receiver(),
        debug_authorization: DebugAuthorizationPolicy::deny_all(),
        debug_relays: Arc::new(Mutex::new(DebugRelayRegistry::default())),
    }
}

fn rpc_request(body: impl Into<String>) -> Request<Body> {
    Request::builder()
        .version(Version::HTTP_2)
        .body(Body::from(body.into()))
        .expect("test request must be well-formed")
}

async fn response_text(response: Response) -> Result<String, Box<dyn Error>> {
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

fn create_session_request() -> String {
    format!(
        "crucible.rpc/create-session-request\nsource=scenario-ref\nname=missing\nseed={TEST_SEED}\nstart-paused=false\n"
    )
}

fn destroy_session_request() -> String {
    format!(
        "crucible.rpc/destroy-session-request\nsession-id=42\nepoch=7\nseed={TEST_SEED}\nexpected-epoch=none\n"
    )
}

fn attach_request() -> String {
    format!(
        "crucible.rpc/attach-request\nsession-id=42\nepoch=7\nseed={TEST_SEED}\nexpected-epoch=none\nfrom-seq=0\nclient-name=read-only-test\n"
    )
}

#[test]
fn debug_guest_wire_parsers_preserve_node_and_bounded_record() {
    let record = GuestIntrospectionRecord::new(
        9,
        crucible_protocol::guest_introspection::GuestIntrospectionMessage::Close,
    )
    .expect("guest record fixture must be valid");
    let encoded = hex_encode(&record.encode().expect("guest record fixture must encode"));
    let request = format!(
        "crucible.rpc/debug-guest-exchange-request\nsession-id=7\nepoch=12\nseed={TEST_SEED}\ngeneration=3\nnode={}\nchannel-id=9\nrecord={encoded}\n",
        hex_encode(b"node-a")
    );
    let (_session, generation, node, channel_id, parsed) =
        parse_debug_guest_exchange_request(request.as_bytes())
            .expect("guest exchange request must parse");
    assert_eq!(generation, 3);
    assert_eq!(node.name, "node-a");
    assert_eq!(channel_id, 9);
    assert_eq!(parsed, Some(record));

    let fork = format!(
        "crucible.rpc/debug-guest-fork-request\nsession-id=7\nepoch=12\nseed={TEST_SEED}\ngeneration=3\nnode={}\n",
        hex_encode(b"node-a")
    );
    let (_session, generation, node) =
        parse_debug_guest_fork_request(fork.as_bytes()).expect("guest fork request must parse");
    assert_eq!(generation, 3);
    assert_eq!(node.name, "node-a");
}

#[tokio::test]
async fn debugger_session_rejection_is_a_typed_conflict_not_internal_error() {
    let response = lifecycle_error_response(LifecycleApiError::SessionCommandRejected {
        message: String::from("non-canonical debug branch required"),
    });
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = response_text(response)
        .await
        .expect("typed conflict response must decode");
    assert!(body.contains("status=invalid-state"));
    assert!(body.contains("reason=session-command-rejected"));
}

fn send_request(command: &str, query: Option<&str>) -> String {
    let mut body = format!(
        "crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed={TEST_SEED}\nexpected-epoch=none\ncommand-id=9001\ncommand={command}\n"
    );
    if let Some(query) = query {
        body.push_str("query=");
        body.push_str(query);
        body.push('\n');
    }
    body
}

#[tokio::test]
async fn server_read_only_mode_rejects_session_creation() -> Result<(), Box<dyn Error>> {
    let response = handle_create_session(
        State(test_state(LifecycleServerMode::read_only())),
        rpc_request(create_session_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await?;
    assert!(body.contains("status=unsupported"));
    assert!(body.contains("reason=read-only"));

    Ok(())
}

#[tokio::test]
async fn server_read_only_mode_rejects_debug_controller_before_authorization()
-> Result<(), Box<dyn Error>> {
    let response = handle_debug_controller_acquire(
        State(test_state(LifecycleServerMode::read_only())),
        None,
        rpc_request(format!(
            "crucible.rpc/debug-controller-acquire-request\nsession-id=42\nepoch=7\nseed={TEST_SEED}\n"
        )),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await?;
    assert!(body.contains("reason=read-only"));

    Ok(())
}

#[tokio::test]
async fn server_read_only_mode_rejects_session_destruction() -> Result<(), Box<dyn Error>> {
    let response = handle_destroy_session(
        State(test_state(LifecycleServerMode::read_only())),
        rpc_request(destroy_session_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await?;
    assert!(body.contains("status=unsupported"));
    assert!(body.contains("reason=read-only"));

    Ok(())
}

#[tokio::test]
async fn server_read_only_mode_rejects_control_attach() -> Result<(), Box<dyn Error>> {
    let response = handle_control_attach(
        State(test_state(LifecycleServerMode::read_only())),
        rpc_request(attach_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await?;
    assert!(body.contains("status=unsupported"));
    assert!(body.contains("reason=read-only"));

    Ok(())
}

#[tokio::test]
async fn server_read_only_mode_allows_watch_attach() -> Result<(), Box<dyn Error>> {
    let response = handle_watch_attach(
        State(test_state(LifecycleServerMode::read_only())),
        rpc_request(attach_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_text(response).await?;
    assert!(body.contains("status=not-found"));

    Ok(())
}

#[tokio::test]
async fn server_read_only_mode_rejects_mutating_send_but_allows_query() -> Result<(), Box<dyn Error>>
{
    let mutating = handle_streaming_send(
        State(test_state(LifecycleServerMode::read_only())),
        rpc_request(send_request("crucible.cmd.continue", None)),
    )
    .await;

    assert_eq!(mutating.status(), StatusCode::FORBIDDEN);
    let body = response_text(mutating).await?;
    assert!(body.contains("reason=read-only"));

    let query = handle_streaming_send(
        State(test_state(LifecycleServerMode::read_only())),
        rpc_request(send_request("crucible.cmd.query", Some("state"))),
    )
    .await;

    assert_eq!(query.status(), StatusCode::NOT_FOUND);
    let body = response_text(query).await?;
    assert!(body.contains("status=not-found"));

    Ok(())
}

#[tokio::test]
async fn server_read_write_mode_keeps_default_mutating_routes() -> Result<(), Box<dyn Error>> {
    let response = handle_create_session(
        State(test_state(LifecycleServerMode::read_write())),
        rpc_request(create_session_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_text(response).await?;
    assert!(body.contains("status=not-found"));

    Ok(())
}

#[tokio::test]
async fn server_create_session_limit_maps_to_typed_rpc_error() -> Result<(), Box<dyn Error>> {
    let response = handle_create_session(
        State(test_state_with_max_sessions(
            LifecycleServerMode::read_write(),
            0,
        )),
        rpc_request(create_session_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = response_text(response).await?;
    assert!(body.contains("status=invalid-state"));
    assert!(body.contains("reason=session-limit"));

    Ok(())
}
