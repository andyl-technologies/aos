//! Regression tests for the HTTP/2 lifecycle server.
//!
//! These tests exercise request parsing, authorization, lifecycle limits,
//! and typed transport responses through the private server surface.

use std::error::Error;

use axum::body::to_bytes;
use axum::extract::State;
use axum::http::Version;
use bytes::Bytes;
use futures_util::stream;

use crate::lifecycle::QuiescentLifecycleLoop;
use crucible::{
    CheckpointKind, Configuration, Decision, DeliveryOrderDecision, Schedule, VirtualTime,
};
use std::collections::BTreeMap;

use super::*;

const TEST_SEED: &str = "000000000000000000000000000000000000000000000000000000000000004d";
const TEST_HOLDER: &str = "00000000-0000-0000-0000-000000000009";

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
        debug_holders: Arc::new(Mutex::new(DebugControllerHolderRegistry::default())),
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
        debug_holders: Arc::new(Mutex::new(DebugControllerHolderRegistry::default())),
        debug_relays: Arc::new(Mutex::new(DebugRelayRegistry::default())),
    }
}

fn rpc_request(body: impl Into<String>) -> Request<Body> {
    Request::builder()
        .version(Version::HTTP_2)
        .body(Body::from(body.into()))
        .expect("test request must be well-formed")
}

#[tokio::test(flavor = "current_thread")]
async fn resume_body_rejects_declared_oversize_before_collection() {
    let request = Request::builder()
        .version(Version::HTTP_2)
        .header(
            CONTENT_LENGTH,
            RESUME_SESSION_RPC_BODY_MAX_BYTES.saturating_add(1),
        )
        .body(Body::empty())
        .expect("oversize request fixture must be well-formed");

    let response = read_resume_session_rpc_body(request)
        .await
        .expect_err("oversize resume body must reject before collection");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response_text(response)
            .await
            .expect("oversize response should be text")
            .contains("resume-session-request-too-large")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resume_body_rejects_oversize_chunked_stream_during_collection() {
    let body = Body::from_stream(stream::iter([
        Ok::<_, std::convert::Infallible>(Bytes::from_static(b"1234")),
        Ok(Bytes::from_static(b"56789")),
    ]));
    let request = Request::builder()
        .version(Version::HTTP_2)
        .body(body)
        .expect("chunked oversize request fixture must be well-formed");

    let response = read_bounded_resume_session_rpc_body(request, 8)
        .await
        .expect_err("chunked resume body must stop at the collection bound");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response_text(response)
            .await
            .expect("oversize response should be text")
            .contains("resume-session-request-too-large")
    );
}

async fn wait_until_control_lock_is_held(state: &TestState) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state.control_plane.try_lock().is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler must reach the control-plane lock");
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

fn resume_request_with_closure() -> (ResumeSessionRequest, String) {
    let scenario = crucible::happy_path_scenario()
        .expect("resume parser scenario should build")
        .scenario;
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: schedule.clone(),
    };
    let parent = Configuration::genesis(configuration.def.clone());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        Some(&parent),
        VirtualTime { ticks: 1 },
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("resume parser checkpoint should build");
    let replay_closure = ResumeReplayClosure::new(
        &scenario,
        &schedule,
        &checkpoint,
        7,
        b"production-parser-replay-closure".to_vec(),
    )
    .expect("bounded replay closure should build");
    let request = ResumeSessionRequest::new(
        scenario.clone(),
        schedule.clone(),
        checkpoint.clone(),
        scenario.seed(),
    )
    .with_replay_closure(replay_closure.clone());
    let mut wire = String::from("crucible.rpc/resume-session-request\n");
    push_wire_line(&mut wire, "scenario-id", &scenario.id().to_hex());
    push_wire_line(&mut wire, "scenario-seed", &scenario.seed().to_hex());
    push_wire_line(
        &mut wire,
        "app-random-draw-cap",
        &scenario.app_random_draw_cap().to_string(),
    );
    push_wire_line(
        &mut wire,
        "scenario-payload",
        &hex_encode(&scenario.to_compact_binary()),
    );
    push_wire_line(&mut wire, "seed", &scenario.seed().to_hex());
    push_wire_line(
        &mut wire,
        "schedule",
        &hex_encode(&schedule.to_compact_binary()),
    );
    push_wire_line(
        &mut wire,
        "checkpoint",
        &hex_encode(&checkpoint.to_compact_binary()),
    );
    push_wire_line(
        &mut wire,
        "campaign-replay-closure-version",
        &replay_closure.schema_version().to_string(),
    );
    push_wire_line(
        &mut wire,
        "campaign-replay-closure-identity",
        &replay_closure.identity().to_hex(),
    );
    push_wire_line(
        &mut wire,
        "campaign-replay-closure-size",
        &replay_closure.payload_len().to_string(),
    );
    push_wire_line(
        &mut wire,
        "campaign-replay-closure-payload",
        &hex_encode(replay_closure.payload()),
    );
    (request, wire)
}

#[test]
fn production_resume_parser_authenticates_complete_closure_envelope() {
    let (request, wire) = resume_request_with_closure();
    assert_eq!(
        parse_resume_session_request(wire.as_bytes()).expect("canonical envelope should parse"),
        request,
    );

    let closure = request
        .replay_closure
        .as_ref()
        .expect("fixture should carry replay closure");
    let wrong_size = wire.replace(
        &format!("campaign-replay-closure-size={}\n", closure.payload_len()),
        &format!(
            "campaign-replay-closure-size={}\n",
            closure.payload_len().saturating_add(1)
        ),
    );
    assert!(parse_resume_session_request(wrong_size.as_bytes()).is_err());

    let wrong_identity = wire.replace(
        &closure.identity().to_hex(),
        &ContentHash::default().to_hex(),
    );
    assert!(parse_resume_session_request(wrong_identity.as_bytes()).is_err());

    let extra_field = format!("{wire}unexpected=field\n");
    assert!(parse_resume_session_request(extra_field.as_bytes()).is_err());

    let partial = wire.lines().take(9).collect::<Vec<_>>().join("\n") + "\n";
    assert!(parse_resume_session_request(partial.as_bytes()).is_err());

    let oversize = wire
        .replace(
            &format!("campaign-replay-closure-size={}\n", closure.payload_len()),
            &format!(
                "campaign-replay-closure-size={}\n",
                RESUME_REPLAY_CLOSURE_MAX_BYTES.saturating_add(1)
            ),
        )
        .replace(
            &format!(
                "campaign-replay-closure-payload={}\n",
                hex_encode(closure.payload())
            ),
            "campaign-replay-closure-payload=\n",
        );
    assert!(
        parse_resume_session_request(oversize.as_bytes())
            .expect_err("declared oversize closure must reject")
            .contains("maximum")
    );
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
        "crucible.rpc/debug-guest-exchange-request\nsession-id=7\nepoch=12\nseed={TEST_SEED}\ngeneration=3\nholder={TEST_HOLDER}\nnode={}\nchannel-id=9\nrecord={encoded}\n",
        hex_encode(b"node-a")
    );
    let (_session, generation, _holder, node, channel_id, parsed) =
        parse_debug_guest_exchange_request(request.as_bytes())
            .expect("guest exchange request must parse");
    assert_eq!(generation, 3);
    assert_eq!(node.name, "node-a");
    assert_eq!(channel_id, 9);
    assert_eq!(parsed, Some(record));

    let fork = format!(
        "crucible.rpc/debug-guest-fork-request\nsession-id=7\nepoch=12\nseed={TEST_SEED}\ngeneration=3\nholder={TEST_HOLDER}\nnode={}\n",
        hex_encode(b"node-a")
    );
    let (_session, generation, _holder, node) =
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
async fn debugger_reposition_requires_writable_authenticated_service() -> Result<(), Box<dyn Error>>
{
    let request = format!(
        "crucible.rpc/debug-goto-request\nsession-id=42\nepoch=7\nseed={TEST_SEED}\ngeneration=1\nholder={TEST_HOLDER}\ncoordinate=virtual-time:9\n"
    );
    let read_only = handle_debug_goto(
        State(test_state(LifecycleServerMode::read_only())),
        None,
        rpc_request(request.clone()),
    )
    .await;
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);
    assert!(response_text(read_only).await?.contains("reason=read-only"));

    let denied = handle_debug_goto(
        State(test_state(LifecycleServerMode::read_write())),
        None,
        rpc_request(request),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(response_text(denied).await?.contains("debug"));
    Ok(())
}

#[tokio::test]
async fn debugger_operation_gate_blocks_controller_handoff_until_dispatch_finishes() {
    let state = test_state(LifecycleServerMode::read_write());
    let scenario = crucible::happy_path_scenario()
        .expect("operation-gate scenario must build")
        .scenario;
    let session = state
        .control_plane
        .lock()
        .await
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await
        .expect("operation-gate session must start")
        .session;
    let active = debug_operation_guard(&state, session).await;
    let waiting_state = state.clone();
    let waiting = tokio::spawn(async move { debug_operation_guard(&waiting_state, session).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), async {
            while !waiting.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err(),
        "controller handoff must wait while reposition dispatch owns the gate"
    );
    drop(active);
    let completed = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
        .await
        .expect("controller handoff must resume when dispatch finishes")
        .expect("operation gate task must not fail");
    drop(completed);
    state
        .control_plane
        .lock()
        .await
        .destroy_session(DestroySessionRequest::new(session))
        .await
        .expect("operation-gate session must stop");
}

#[tokio::test]
async fn controller_release_cannot_bypass_a_live_relay_holder() -> Result<(), Box<dyn Error>> {
    let mut state = test_state(LifecycleServerMode::read_write());
    let controller_role = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
    state
        .debug_authorization
        .grant_trusted_unauthenticated_role(controller_role.clone());
    let scenario = crucible::happy_path_scenario()?.scenario;
    let session = state
        .control_plane
        .lock()
        .await
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await?
        .session;
    let controller_client = DebugClientId::new("trusted-unauthenticated")?;
    let lease = state.control_plane.lock().await.acquire_debug_controller(
        session,
        controller_client,
        &controller_role,
    )?;
    let holder = uuid::Uuid::from_u128(91);
    state
        .debug_holders
        .lock()
        .await
        .register(session, lease.clone(), holder)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let stream = DebugRelayRegistry::connect(&listener.local_addr()?.to_string()).await?;
    state
        .debug_relays
        .lock()
        .await
        .register(stream, session, lease.clone(), holder)?;
    let request = format!(
        "crucible.rpc/debug-controller-release-request\nsession-id={}\nepoch={}\nseed={}\ngeneration={}\nholder={}\n",
        session.id.value,
        session.epoch,
        session.seed.to_hex(),
        lease.generation,
        holder,
    );

    let response =
        handle_debug_controller_release(State(state.clone()), None, rpc_request(request)).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response_text(response).await?.contains("live relay"));
    state
        .debug_holders
        .lock()
        .await
        .authorize(session, &lease, holder)?;
    let other = DebugClientId::new("other-controller")?;
    assert!(
        state
            .control_plane
            .lock()
            .await
            .acquire_debug_controller(session, other, &controller_role)
            .is_err(),
        "a second principal must remain excluded while the relay is live"
    );
    drop(listener);
    Ok(())
}

#[tokio::test]
async fn rejected_reacquisition_preserves_existing_controller() -> Result<(), Box<dyn Error>> {
    let mut state = test_state(LifecycleServerMode::read_write());
    let controller_role = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
    state
        .debug_authorization
        .grant_trusted_unauthenticated_role(controller_role.clone());
    let scenario = crucible::happy_path_scenario()?.scenario;
    let session = state
        .control_plane
        .lock()
        .await
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await?
        .session;
    let controller_client = DebugClientId::new("trusted-unauthenticated")?;
    let lease = state.control_plane.lock().await.acquire_debug_controller(
        session,
        controller_client,
        &controller_role,
    )?;
    let active_holder = uuid::Uuid::from_u128(101);
    let released_holder = uuid::Uuid::from_u128(102);
    {
        let mut holders = state.debug_holders.lock().await;
        holders.register(session, lease.clone(), active_holder)?;
        holders.register(session, lease.clone(), released_holder)?;
        assert_eq!(
            holders.release(session, &lease, released_holder)?,
            DebugHolderRelease::Retained
        );
    }
    let request = format!(
        "crucible.rpc/debug-controller-acquire-request\nsession-id={}\nepoch={}\nseed={}\nholder={}\n",
        session.id.value,
        session.epoch,
        session.seed.to_hex(),
        released_holder,
    );

    let response =
        handle_debug_controller_acquire(State(state.clone()), None, rpc_request(request)).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    state
        .debug_holders
        .lock()
        .await
        .authorize(session, &lease, active_holder)?;
    let other = DebugClientId::new("other-controller")?;
    assert!(
        state
            .control_plane
            .lock()
            .await
            .acquire_debug_controller(session, other, &controller_role)
            .is_err(),
        "a rejected released-holder reacquisition must not release the existing controller"
    );
    Ok(())
}

#[tokio::test]
async fn nonexistent_debug_sessions_do_not_retain_operation_gates() {
    let state = test_state(LifecycleServerMode::read_write());
    let missing = SessionRef::new(SessionId::new(42), 7, Seed::from_u64(77));
    let first = debug_operation_guard(&state, missing).await;
    let waiting_state = state.clone();
    let second = tokio::spawn(async move { debug_operation_guard(&waiting_state, missing).await });
    let independent = tokio::time::timeout(std::time::Duration::from_secs(1), second)
        .await
        .expect("a nonexistent session must not retain a shared operation gate")
        .expect("nonexistent operation-gate task must not fail");
    drop(independent);
    drop(first);
}

#[path = "tests/controller_cancellation.rs"]
mod controller_cancellation;

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
