//! Transport-equivalence control-client contract tests.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn control_client_trait_is_transport_agnostic_over_in_process_and_rpc() {
    let (in_process, _actor) = in_process_client_fixture();
    let rpc_server = spawn_http2_hello_server().await;
    let rpc = RpcControlClient::new(RpcEndpoint::http2(rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("HTTP/2 RPC client should build: {error}"));

    assert_control_client_trait(&in_process);
    assert_control_client_trait(&rpc);
    assert_eq!(in_process.transport(), ControlTransportKind::InProcess);
    assert_eq!(rpc.transport(), ControlTransportKind::Http2Rpc);
    assert_eq!(rpc.endpoint().protocol(), RpcTransportProtocol::Http2);
    let shared_model = assert_shared_wire_model(&in_process, &rpc)
        .unwrap_or_else(|error| panic!("client transports should share one wire model: {error}"));
    assert_eq!(shared_model, ControlWireModel::current());

    let request = HelloRequest::new("api-control-client-test", RPC_PROTOCOL_VERSION);
    assert_eq!(
        shared_model.encode_hello_request(&request),
        encode_rpc_hello_request("api-control-client-test", RPC_PROTOCOL_VERSION)
    );
    let in_process_hello = in_process
        .hello(request.clone())
        .await
        .unwrap_or_else(|error| panic!("in-process hello should negotiate: {error}"));
    let rpc_hello = rpc
        .hello(request)
        .await
        .unwrap_or_else(|error| panic!("RPC hello should negotiate: {error}"));

    assert_eq!(in_process_hello.version, RPC_PROTOCOL_VERSION);
    assert_eq!(rpc_hello.version, RPC_PROTOCOL_VERSION);
    assert_eq!(in_process_hello.payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
    assert_eq!(rpc_hello.payload_kinds, RPC_OPEN_SET_PAYLOAD_KINDS);
    assert_eq!(
        shared_model.encode_hello_response(&rpc_hello),
        encode_rpc_hello_response(
            &rpc_hello.server_name,
            RPC_PROTOCOL_VERSION,
            RPC_OPEN_SET_PAYLOAD_KINDS,
        )
    );
    let scenarios = rpc
        .list_scenarios()
        .await
        .unwrap_or_else(|error| panic!("RPC list scenarios should decode: {error}"));
    assert_eq!(scenarios.scenarios.len(), 1);
    assert_eq!(scenarios.scenarios[0].name, "api-control-client-scenario");
    assert_command_rejection_taxonomy_is_closed();

    let missing_scenario_error = rpc
        .create_session(CreateSessionRequest::scenario_ref(
            "missing-api-control-client-scenario",
            Seed::from_u64(77),
        ))
        .await
        .expect_err("RPC unknown scenario should decode as typed NOT_FOUND");
    assert_eq!(
        missing_scenario_error,
        ControlClientError::Lifecycle {
            source: LifecycleApiError::ScenarioNotFound {
                name: String::from("missing-api-control-client-scenario"),
            },
        },
    );

    let created = rpc
        .create_session(
            CreateSessionRequest::scenario_ref("api-control-client-scenario", Seed::from_u64(77))
                .with_start_paused(false),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC create session should decode: {error}"));
    assert_eq!(created.state, LiveStateKind::Running);
    assert_eq!(created.session.id.value, 1);
    assert_eq!(created.session.epoch, 1);
    assert_eq!(created.session.seed, Seed::from_u64(77));
    assert_raw_send_error(
        rpc_server.endpoint(),
        raw_send_body(created.session, 901, "crucible.cmd.no-such-command"),
        "unsupported",
        "unsupported",
    )
    .await;
    assert_raw_send_error(
        rpc_server.endpoint(),
        String::from(
            "crucible.rpc/send-request\nsession-id=not-an-integer\nepoch=1\nseed=00\nexpected-epoch=none\ncommand-id=902\ncommand=crucible.cmd.continue\n",
        ),
        "invalid-argument",
        "invalid-argument",
    )
    .await;

    let sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list sessions should decode: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Running);

    let pre_attach_paused = rpc
        .send_command(SendRequest::new(
            created.session,
            100,
            SessionCommand::Pause,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC pre-attach Pause should decode: {error}"));
    assert_eq!(
        pre_attach_paused.result.status,
        CommandResultStatus::Accepted
    );
    assert_eq!(
        pre_attach_paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused),
    );
    let paused_sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC paused list sessions should decode: {error}"));
    assert_eq!(paused_sessions.sessions[0].state, LiveStateKind::Paused);
    let control_replay_start = paused_sessions.sessions[0].event_log_len;
    let reproduction = rpc
        .get_reproduction(
            GetReproductionRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC GetReproduction should decode: {error}"));
    assert_eq!(reproduction.session, created.session);
    assert_eq!(reproduction.commands.len(), 1);
    assert_reproduction_pause_record(&reproduction.commands[0], control_replay_start);
    rpc_server
        .append_session_events(created.session, &event_pair(control_replay_start, 301))
        .await;

    let mut control = rpc
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_cursor(EventLogCursor::new(control_replay_start)),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC Control attach should decode: {error}"));
    let control_attached = control.attached().clone();
    assert_eq!(control_attached.session, created.session);
    assert_eq!(control_attached.state, LiveStateKind::Paused);
    assert_eq!(
        control_attached.event_log_len,
        control_replay_start.saturating_add(2),
    );
    assert_eq!(
        control_attached
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.event_count),
        Some(control_replay_start.saturating_add(2)),
    );
    assert_eq!(
        control_attached
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.reproduction.clone()),
        Some(reproduction.commands.clone()),
    );
    assert_eq!(
        control_attached.capabilities.commands.len(),
        SessionCommandKind::ALL.len(),
    );
    let control_replay = recv_rpc_control_event(&mut control).await;
    assert_eq!(
        control_replay.cursor,
        EventLogCursor::new(control_replay_start)
    );
    assert_eq!(control_replay.event.payload.kind, "crucible.event.rng_draw",);
    assert!(!control_replay.event.observational);
    let control_replay_observational = recv_rpc_control_event(&mut control).await;
    assert_eq!(
        control_replay_observational.cursor,
        EventLogCursor::new(control_replay_start.saturating_add(1)),
    );
    assert!(control_replay_observational.event.observational);
    let control_live_start = control_attached.event_log_len;
    rpc_server
        .append_session_events(created.session, &event_pair(control_live_start, 302))
        .await;
    let control_live = recv_rpc_control_event(&mut control).await;
    assert_eq!(control_live.cursor, EventLogCursor::new(control_live_start));
    assert_eq!(control_live.event.sequence, control_live_start);

    let control_continued = rpc
        .control_send(SendRequest::new(
            created.session,
            101,
            SessionCommand::Continue,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Control send should decode: {error}"));
    assert_eq!(control_continued.result.command_id, 101);
    assert_eq!(
        control_continued.result.status,
        CommandResultStatus::Accepted
    );
    assert_eq!(
        control_continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );
    let control_running_update = recv_rpc_control_state_update(&mut control).await;
    assert_eq!(control_running_update.update.session, created.session);
    assert_eq!(control_running_update.update.state, LiveStateKind::Running);

    let control_paused = rpc
        .control_send(SendRequest::new(
            created.session,
            102,
            SessionCommand::Pause,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Control Pause should decode: {error}"));
    assert_eq!(control_paused.result.command_id, 102);
    assert_eq!(control_paused.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        control_paused.state_update.map(|update| update.state),
        Some(LiveStateKind::Paused),
    );
    let control_paused_update = recv_rpc_control_state_update(&mut control).await;
    assert_eq!(control_paused_update.update.session, created.session);
    assert_eq!(control_paused_update.update.state, LiveStateKind::Paused);
    assert!(
        control_paused_update.sequence > control_running_update.sequence,
        "Control state updates should be monotone",
    );

    let watch_replay_start = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list before Watch attach should decode: {error}"))
        .sessions[0]
        .event_log_len;
    let mut watch = rpc
        .watch_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_cursor(EventLogCursor::new(watch_replay_start)),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC Watch attach should decode: {error}"));
    let watch_attached = watch.attached().clone();
    assert_eq!(watch_attached.session, created.session);
    assert_eq!(watch_attached.state, LiveStateKind::Paused);
    assert_eq!(watch_attached.capabilities, control_attached.capabilities);
    assert_eq!(watch_attached.event_log_len, watch_replay_start);
    let quiet_watch = tokio::time::timeout(Duration::from_millis(10), watch.recv_event()).await;
    assert!(
        quiet_watch.is_err(),
        "Watch cursor at tail should not replay"
    );
    rpc_server
        .append_session_events(created.session, &event_pair(watch_replay_start, 303))
        .await;
    let watch_live = recv_rpc_watch_event(&mut watch).await;
    assert_eq!(watch_live.cursor, EventLogCursor::new(watch_replay_start));
    assert_eq!(watch_live.event.payload.kind, "crucible.event.rng_draw");
    let watch_burst_start = watch_replay_start.saturating_add(2);
    rpc_server
        .append_session_events(created.session, &event_burst(watch_burst_start, 304, 10))
        .await;

    let send_continued = rpc
        .send_command(SendRequest::new(
            created.session,
            103,
            SessionCommand::Continue,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send should decode: {error}"));
    assert_eq!(send_continued.result.command_id, 103);
    assert_eq!(send_continued.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        send_continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );
    let watch_running_update = recv_rpc_watch_state_update(&mut watch).await;
    assert_eq!(watch_running_update.update.session, created.session);
    assert_eq!(watch_running_update.update.state, LiveStateKind::Running);

    let rejected_start = rpc
        .send_command(SendRequest::new(
            created.session,
            104,
            SessionCommand::Start,
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send rejection should decode: {error}"));
    assert_eq!(
        rejected_start.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::InvalidState,
        },
    );
    assert!(rejected_start.state_update.is_none());

    let rejected_remove = rpc
        .send_command(SendRequest::new(
            created.session,
            105,
            SessionCommandKind::RemoveBreakpoint
                .representative_command()
                .unwrap_or_else(|| panic!("RemoveBreakpoint has a representative payload")),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC Send RemoveBreakpoint should decode: {error}"));
    assert_eq!(
        rejected_remove.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::NotFound,
        },
    );
    assert!(rejected_remove.state_update.is_none());
    assert_raw_send_rejection(
        rpc_server.endpoint(),
        raw_send_body(created.session, 106, "crucible.cmd.remove-breakpoint"),
        "crucible.cmd.remove-breakpoint",
        "not-found",
    )
    .await;

    let stream_stopped = rpc
        .send_command(SendRequest::new(created.session, 107, SessionCommand::Stop))
        .await
        .unwrap_or_else(|error| panic!("RPC Send Stop should decode: {error}"));
    assert_eq!(stream_stopped.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        stream_stopped.state_update.map(|update| update.state),
        Some(LiveStateKind::Stopped),
    );
    let destroyed = rpc
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("RPC destroy after streaming Stop should decode: {error}"));
    assert_eq!(destroyed.session, created.session);
    assert!(!destroyed.stopped);
    assert!(destroyed.already_absent);

    let missing_reproduction_error = rpc
        .get_reproduction(GetReproductionRequest::new(created.session))
        .await
        .expect_err("RPC GetReproduction on absent session should decode as typed NOT_FOUND");
    assert_eq!(
        missing_reproduction_error,
        ControlClientError::Lifecycle {
            source: LifecycleApiError::SessionNotFound {
                session: created.session,
            },
        },
    );
    let missing_watch_error = match rpc.watch_attach(AttachRequest::new(created.session)).await {
        Ok(_) => panic!("RPC Watch on absent session should reject"),
        Err(error) => error,
    };
    assert_eq!(
        missing_watch_error,
        ControlClientError::Streaming {
            source: StreamingApiError::SessionNotFound {
                session: created.session,
            },
        },
    );

    let inline_scenario = generated_scenario(78);
    let inline_created = rpc
        .create_session(CreateSessionRequest::inline(
            inline_scenario.clone(),
            inline_scenario.seed(),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC inline create session should decode: {error}"));
    assert_eq!(inline_created.state, LiveStateKind::Paused);
    assert_eq!(inline_created.session.id.value, 2);
    assert_eq!(inline_created.session.epoch, 2);
    assert_eq!(inline_created.session.seed, inline_scenario.seed());

    let inline_sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC inline list sessions should decode: {error}"));
    assert_eq!(inline_sessions.sessions.len(), 1);
    assert_eq!(inline_sessions.sessions[0].session, inline_created.session);
    assert_eq!(inline_sessions.sessions[0].state, LiveStateKind::Paused);

    let mut resume_request = resume_session_request(79);
    let replay_closure = ResumeReplayClosure::new(
        &resume_request.scenario,
        &resume_request.schedule,
        &resume_request.checkpoint,
        7,
        b"rpc-replay-closure".to_vec(),
    )
    .expect("bounded RPC replay closure should build");
    resume_request = resume_request.with_replay_closure(replay_closure);
    let expected_resume_checkpoint = resume_request.checkpoint.id;
    let expected_resume_scenario = resume_request.scenario.scenario_def();
    let expected_resume_configuration = Configuration {
        def: expected_resume_scenario,
        schedule: resume_request.schedule.clone(),
    }
    .id();
    let resumed = rpc
        .resume_session(resume_request)
        .await
        .unwrap_or_else(|error| panic!("RPC resume session should decode: {error}"));
    assert_eq!(resumed.state, LiveStateKind::Paused);
    assert_eq!(resumed.checkpoint, expected_resume_checkpoint);
    assert_eq!(resumed.configuration, expected_resume_configuration);
    assert_eq!(resumed.session.id.value, 3);
    assert_eq!(resumed.session.epoch, 3);
    assert_eq!(resumed.session.seed, Seed::from_u64(79));
    let resume_sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC resume list sessions should decode: {error}"));
    assert!(
        resume_sessions
            .sessions
            .iter()
            .any(|summary| summary.session == resumed.session
                && summary.state == LiveStateKind::Paused
                && summary.frontier == VirtualTime { ticks: 1 })
    );
    let resumed_destroyed = rpc
        .destroy_session(
            DestroySessionRequest::new(resumed.session).with_expected_epoch(resumed.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC resumed destroy session should decode: {error}"));
    assert!(resumed_destroyed.stopped);

    let stale_epoch = inline_created.session.epoch.saturating_add(1);
    let stale_watch_error = match rpc
        .watch_attach(AttachRequest::new(inline_created.session).with_expected_epoch(stale_epoch))
        .await
    {
        Ok(_) => panic!("RPC Watch attach stale epoch should be typed"),
        Err(error) => error,
    };
    assert_eq!(
        stale_watch_error,
        crucible_api::ControlClientError::Streaming {
            source: StreamingApiError::EpochMismatch {
                expected: stale_epoch,
                actual: inline_created.session.epoch,
            },
        },
    );

    let stale_send_error = rpc
        .send_command(
            SendRequest::new(inline_created.session, 200, SessionCommand::Continue)
                .with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("RPC Send stale epoch should be typed");
    assert_eq!(
        stale_send_error,
        crucible_api::ControlClientError::Streaming {
            source: StreamingApiError::EpochMismatch {
                expected: stale_epoch,
                actual: inline_created.session.epoch,
            },
        },
    );

    let stale_destroy_error = rpc
        .destroy_session(
            DestroySessionRequest::new(inline_created.session).with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("RPC DestroySession stale epoch should be typed");
    assert_eq!(
        stale_destroy_error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::EpochMismatch {
                session_id: inline_created.session.id,
                expected: inline_created.session.epoch,
                actual: stale_epoch,
            },
        },
    );

    let stale_reproduction_error = rpc
        .get_reproduction(
            GetReproductionRequest::new(inline_created.session).with_expected_epoch(stale_epoch),
        )
        .await
        .expect_err("RPC GetReproduction stale epoch should be typed");
    assert_eq!(
        stale_reproduction_error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::EpochMismatch {
                session_id: inline_created.session.id,
                expected: inline_created.session.epoch,
                actual: stale_epoch,
            },
        },
    );

    let inline_destroyed = rpc
        .destroy_session(
            DestroySessionRequest::new(inline_created.session)
                .with_expected_epoch(inline_created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("RPC inline destroy session should decode: {error}"));
    assert_eq!(inline_destroyed.session, inline_created.session);
    assert!(inline_destroyed.stopped);
    assert!(!inline_destroyed.already_absent);

    let mismatch_error = rpc
        .create_session(CreateSessionRequest::inline(
            generated_scenario(108),
            Seed::from_u64(109),
        ))
        .await
        .expect_err("RPC inline seed mismatch should reject");
    assert!(matches!(
        mismatch_error,
        ControlClientError::RpcStatus {
            status: RpcStatusCode::InvalidArgument,
            ref message,
        } if message.contains("scenario seed mismatch")
    ));
    let sessions_after_rejected_inline = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("RPC list after rejected inline should decode: {error}"));
    assert!(sessions_after_rejected_inline.sessions.is_empty());

    assert!(rpc_server.saw_http2_request().await);
    assert_eq!(
        in_process.live_snapshot().read().event_log_len,
        in_process.event_log().current_cursor().next_sequence
    );
}
