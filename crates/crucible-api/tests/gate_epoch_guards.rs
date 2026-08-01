//! API-side checks for epoch-guarded session identity.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{QuantumLoop, QuantumOutcome, QuantumRequest, SchedulerError, Seed};
use crucible_api::{
    AttachRequest, CreateSessionRequest, DestroySessionRequest, EventLogCursor,
    LIFECYCLE_SESSION_MAILBOX_CAPACITY, LifecycleApiError, LifecycleControlPlane,
    LifecycleLoopFactory, ScenarioCatalogEntry, SendRequest, SessionId, StreamingApiError,
};
use crucible_session::{LiveStateKind, SessionCommand};

#[tokio::test(flavor = "current_thread")]
async fn epoch_guards_fast_fail_without_state_or_event_log_mutation() {
    let mut control_plane = lifecycle_control_plane();
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-epoch-guard-scenario",
            Seed::from_u64(801),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));
    let session = created.session;
    let stale_epoch = session.epoch.saturating_add(1);
    let streaming = control_plane
        .streaming_session(session)
        .unwrap_or_else(|error| panic!("streaming session should exist: {error}"));
    let before_cursor = streaming.event_log().current_cursor();
    assert_eq!(before_cursor, EventLogCursor::default());

    let attach_error =
        match streaming.watch(AttachRequest::new(session).with_expected_epoch(stale_epoch)) {
            Ok(_) => panic!("Watch attach should reject stale expected_epoch"),
            Err(error) => error,
        };
    assert_eq!(
        attach_error,
        StreamingApiError::EpochMismatch {
            expected: stale_epoch,
            actual: session.epoch,
        },
    );

    let command_error = streaming
        .send(
            SendRequest::new(session, 1, SessionCommand::Continue).with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("Send should reject stale expected_epoch before dispatch");
    assert_eq!(
        command_error,
        StreamingApiError::EpochMismatch {
            expected: stale_epoch,
            actual: session.epoch,
        },
    );

    let destroy_error = control_plane
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(stale_epoch))
        .await
        .expect_err("DestroySession should reject stale expected_epoch");
    assert_eq!(
        destroy_error,
        LifecycleApiError::EpochMismatch {
            session_id: session.id,
            expected: session.epoch,
            actual: stale_epoch,
        },
    );

    let sessions = control_plane.list_sessions();
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Paused);
    assert_eq!(streaming.event_log().current_cursor(), before_cursor);

    let destroyed = control_plane
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("matching expected_epoch should destroy: {error}"));
    assert!(destroyed.stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn stale_session_ref_epoch_detects_recycled_identity_before_dispatch() {
    let mut control_plane = lifecycle_control_plane();
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-epoch-guard-scenario",
            Seed::from_u64(802),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));
    let mut stale_ref = created.session;
    stale_ref.epoch = stale_ref.epoch.saturating_add(1);

    let streaming_error = match control_plane.streaming_session(stale_ref) {
        Ok(_) => panic!("stale SessionRef should not produce a streaming handle"),
        Err(error) => error,
    };
    assert_eq!(
        streaming_error,
        StreamingApiError::EpochMismatch {
            expected: stale_ref.epoch,
            actual: created.session.epoch,
        },
    );

    let destroy_error = control_plane
        .destroy_session(DestroySessionRequest::new(stale_ref))
        .await
        .expect_err("stale SessionRef should not destroy the live actor");
    assert_eq!(
        destroy_error,
        LifecycleApiError::EpochMismatch {
            session_id: created.session.id,
            expected: created.session.epoch,
            actual: stale_ref.epoch,
        },
    );
    assert_eq!(control_plane.session_count(), 1);

    let destroyed = control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
    assert!(destroyed.stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn session_epoch_is_server_monotonic_and_closed_protocol_identity() {
    let mut control_plane = lifecycle_control_plane();
    let first = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-epoch-guard-scenario",
            Seed::from_u64(803),
        ))
        .await
        .unwrap_or_else(|error| panic!("first create should start actor: {error}"));
    control_plane
        .destroy_session(DestroySessionRequest::new(first.session))
        .await
        .unwrap_or_else(|error| panic!("first destroy should stop actor: {error}"));

    let second = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-epoch-guard-scenario",
            Seed::from_u64(804),
        ))
        .await
        .unwrap_or_else(|error| panic!("second create should start actor: {error}"));
    assert!(second.session.epoch > first.session.epoch);
    assert_eq!(first.session.id, SessionId::new(1));
    assert_eq!(second.session.id, SessionId::new(2));

    let streaming = control_plane
        .streaming_session(second.session)
        .unwrap_or_else(|error| panic!("streaming session should exist: {error}"));
    let attached = streaming
        .watch(AttachRequest::new(second.session))
        .unwrap_or_else(|error| panic!("attach should report session identity: {error}"));
    assert_eq!(attached.attached().session.epoch, second.session.epoch);
    assert_eq!(attached.attached().state, LiveStateKind::Paused);
    assert_eq!(
        streaming.event_log().current_cursor(),
        EventLogCursor::default()
    );

    control_plane
        .destroy_session(DestroySessionRequest::new(second.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

fn lifecycle_control_plane() -> LifecycleControlPlane<NoopLoop, LifecycleLoopFactory<NoopLoop>> {
    LifecycleControlPlane::new(
        "crucible-epoch-guard-test-server",
        vec![catalog_entry()],
        |_scenario, _seed| NoopLoop,
    )
    .with_mailbox_capacity(LIFECYCLE_SESSION_MAILBOX_CAPACITY)
}

fn catalog_entry() -> ScenarioCatalogEntry {
    ScenarioCatalogEntry::from_canonical_material(
        "api-epoch-guard-scenario",
        "Epoch guard API scenario",
        "test://api-epoch-guard-scenario",
        "crucible.api.gate-epoch-guards.scenario",
        "scenario=api-epoch-guards",
    )
}

struct NoopLoop;

impl QuantumLoop for NoopLoop {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        panic!("epoch guard gate keeps sessions paused before any quantum")
    }
}
