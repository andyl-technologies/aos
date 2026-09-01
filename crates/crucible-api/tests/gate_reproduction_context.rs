//! API-side checks for the reproduction-context command stream.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{QuantumLoop, QuantumOutcome, QuantumRequest, SchedulerError, Seed, VirtualTime};
use crucible_api::{
    AttachRequest, CommandResultStatus, CreateSessionRequest, DestroySessionRequest,
    GetReproductionRequest, LifecycleApiError, LifecycleControlPlane, LifecycleLoopFactory,
    ReproductionCommandRecord, ReproductionCommandResult, ScenarioCatalogEntry, SendRequest,
    SessionRef,
};
use crucible_session::{LiveStateKind, SessionCommand, SessionCommandKind};

#[tokio::test(flavor = "current_thread")]
async fn reproduction_context_is_read_only_and_visible_on_attach_snapshot() {
    let mut control_plane = lifecycle_control_plane();
    let created = control_plane
        .create_session(
            CreateSessionRequest::scenario_ref(
                "api-reproduction-context-scenario",
                Seed::from_u64(901),
            )
            .with_start_paused(false),
        )
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));
    let session = created.session;
    assert_eq!(created.state, LiveStateKind::Running);

    let before_streaming = control_plane
        .streaming_session(session)
        .unwrap_or_else(|error| panic!("streaming session should exist: {error}"));
    let before_cursor = before_streaming.event_log().current_cursor();
    let paused = control_plane
        .send_streaming_command(SendRequest::new(session, 1, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("Pause should dispatch: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused),
    );

    let after_pause_streaming = control_plane
        .streaming_session(session)
        .unwrap_or_else(|error| panic!("streaming session should still exist: {error}"));
    let after_pause_cursor = after_pause_streaming.event_log().current_cursor();
    let reproduction = control_plane
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(session.epoch))
        .unwrap_or_else(|error| panic!("GetReproduction should read context: {error}"));
    assert_eq!(reproduction.session, session);
    assert_eq!(reproduction.commands.len(), 1);
    assert_pause_record(&reproduction.commands[0], before_cursor.next_sequence);
    assert_eq!(
        after_pause_streaming.event_log().current_cursor(),
        after_pause_cursor,
        "GetReproduction must not append or truncate the event-log stream",
    );

    let second_read = control_plane
        .get_reproduction(GetReproductionRequest::new(session))
        .unwrap_or_else(|error| panic!("second GetReproduction should be read-only: {error}"));
    assert_eq!(second_read.commands, reproduction.commands);

    let attached = control_plane
        .streaming_session(session)
        .unwrap_or_else(|error| panic!("streaming session should still exist: {error}"))
        .watch(AttachRequest::new(session))
        .unwrap_or_else(|error| panic!("Watch attach should succeed: {error}"))
        .attached()
        .clone();
    let snapshot = attached
        .snapshot
        .as_ref()
        .expect("attach should include a snapshot");
    assert_eq!(snapshot.reproduction, reproduction.commands);
    assert_eq!(snapshot.through, after_pause_cursor);
    assert_eq!(snapshot.event_count, after_pause_cursor.next_sequence);

    let stale_epoch = session.epoch.saturating_add(1);
    let stale_error = control_plane
        .get_reproduction(GetReproductionRequest::new(session).with_expected_epoch(stale_epoch))
        .expect_err("stale expected_epoch should reject before actor dispatch");
    assert_eq!(
        stale_error,
        LifecycleApiError::EpochMismatch {
            session_id: session.id,
            expected: session.epoch,
            actual: stale_epoch,
        },
    );
    assert_eq!(
        control_plane
            .streaming_session(session)
            .unwrap_or_else(|error| panic!("streaming session should still exist: {error}"))
            .event_log()
            .current_cursor(),
        after_pause_cursor,
    );

    control_plane
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(session.epoch))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn interactive_and_scripted_same_schedule_reproduce_equivalently() {
    let interactive = drive_pause_with_control(Seed::from_u64(902)).await;
    let scripted = drive_pause_with_send(Seed::from_u64(902)).await;
    assert_eq!(interactive, scripted);

    let record = interactive
        .first()
        .expect("pause schedule should record one command");
    assert_eq!(record.payload.command, SessionCommandKind::Pause);
    assert!(
        record
            .payload
            .command_payload
            .contains("payload=command-kind")
    );
    assert!(record.payload.command_payload.contains("command=Pause"));
    assert_eq!(record.payload.scheduler_control, None);
    assert_eq!(record.virtual_time, VirtualTime::default());
    assert_eq!(record.quanta, 0);
    assert_eq!(record.at_sequence, 0);
    assert_eq!(record.result, ReproductionCommandResult::Accepted);
    assert_eq!(record.observational_order, record.sequence);
}

async fn drive_pause_with_control(seed: Seed) -> Vec<ReproductionCommandRecord> {
    let mut control_plane = lifecycle_control_plane();
    let session = create_running_session(&mut control_plane, seed).await;
    let control = control_plane
        .streaming_session(session)
        .unwrap_or_else(|error| panic!("streaming session should exist: {error}"))
        .control(AttachRequest::new(session))
        .unwrap_or_else(|error| panic!("Control attach should succeed: {error}"));
    let paused = control
        .send_command(1, SessionCommand::Pause)
        .await
        .unwrap_or_else(|error| panic!("Control Pause should dispatch: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);
    let commands = wait_for_reproduction_len(&control_plane, session, 1).await;
    control_plane
        .destroy_session(DestroySessionRequest::new(session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
    commands
}

async fn drive_pause_with_send(seed: Seed) -> Vec<ReproductionCommandRecord> {
    let mut control_plane = lifecycle_control_plane();
    let session = create_running_session(&mut control_plane, seed).await;
    let paused = control_plane
        .send_streaming_command(SendRequest::new(session, 1, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("Send Pause should dispatch: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);
    let commands = wait_for_reproduction_len(&control_plane, session, 1).await;
    control_plane
        .destroy_session(DestroySessionRequest::new(session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
    commands
}

async fn create_running_session(
    control_plane: &mut LifecycleControlPlane<BoundaryLoop, LifecycleLoopFactory<BoundaryLoop>>,
    seed: Seed,
) -> SessionRef {
    let created = control_plane
        .create_session(
            CreateSessionRequest::scenario_ref("api-reproduction-context-scenario", seed)
                .with_start_paused(false),
        )
        .await
        .unwrap_or_else(|error| panic!("create running session should start actor: {error}"));
    assert_eq!(created.state, LiveStateKind::Running);
    created.session
}

async fn wait_for_reproduction_len(
    control_plane: &LifecycleControlPlane<BoundaryLoop, LifecycleLoopFactory<BoundaryLoop>>,
    session: SessionRef,
    expected_len: usize,
) -> Vec<ReproductionCommandRecord> {
    for _ in 0..128 {
        let response = control_plane
            .get_reproduction(GetReproductionRequest::new(session))
            .unwrap_or_else(|error| panic!("GetReproduction should read context: {error}"));
        if response.commands.len() == expected_len {
            return response.commands;
        }
        tokio::task::yield_now().await;
    }
    panic!("reproduction context did not reach {expected_len} command records")
}

fn assert_pause_record(record: &ReproductionCommandRecord, at_sequence: u64) {
    assert_eq!(record.sequence, 1);
    assert_eq!(record.payload.command, SessionCommandKind::Pause);
    assert!(
        record
            .payload
            .command_payload
            .contains("payload=command-kind")
    );
    assert!(record.payload.command_payload.contains("command=Pause"));
    assert_eq!(record.payload.scheduler_batch, 0);
    assert!(record.payload.scheduler_control.is_none());
    assert_eq!(record.at_sequence, at_sequence);
    assert_eq!(record.result, ReproductionCommandResult::Accepted);
    assert_eq!(record.observational_order, record.sequence);
}

fn lifecycle_control_plane()
-> LifecycleControlPlane<BoundaryLoop, LifecycleLoopFactory<BoundaryLoop>> {
    LifecycleControlPlane::new(
        "crucible-reproduction-context-test-server",
        vec![ScenarioCatalogEntry::from_canonical_material(
            "api-reproduction-context-scenario",
            "Reproduction context API scenario",
            "test://api-reproduction-context-scenario",
            "crucible.api.gate-reproduction-context.scenario",
            "scenario=api-reproduction-context",
        )],
        |_scenario, _seed| BoundaryLoop { quanta: 0 },
    )
}

struct BoundaryLoop {
    quanta: u64,
}

impl QuantumLoop for BoundaryLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.quanta = self.quanta.saturating_add(1);
        Ok(QuantumOutcome {
            configuration: request.configuration,
            frontier: VirtualTime { ticks: self.quanta },
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: Vec::new(),
            event_log_entries: Vec::new(),
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::default(),
            scheduler_quiescence: None,
        })
    }
}
