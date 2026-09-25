//! Transport-neutral control-client contract tests.

use super::*;

#[path = "contract_tests/transport.rs"]
mod transport;

#[tokio::test(flavor = "current_thread")]
async fn in_process_lifecycle_control_stream_stop_cleans_registry() {
    let client = InProcessLifecycleClient::new(lifecycle_control_plane());
    let created = client
        .create_session(
            CreateSessionRequest::scenario_ref(
                "api-control-client-scenario",
                Seed::from_u64(30_516),
            )
            .with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("in-process CreateSession should succeed: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let control = client
        .control_attach(
            AttachRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("in-process Control attach should succeed: {error}"));
    let stepped = control
        .send_command(30_515, SessionCommand::step(StepMode::Quantum))
        .await
        .unwrap_or_else(|error| panic!("in-process Control Step should succeed: {error}"));
    assert_eq!(stepped.result.status, CommandResultStatus::Accepted);
    let before_stop = control
        .send_command(30_516, SessionCommand::query_snapshot())
        .await
        .unwrap_or_else(|error| panic!("pre-Stop snapshot should succeed: {error}"));
    let Some(QueryResult::Snapshot(before_stop)) = before_stop.query_result else {
        panic!("pre-Stop query should return a snapshot");
    };
    assert!(before_stop.quanta > 0);
    let stopped = control
        .send_command(30_517, SessionCommand::Stop)
        .await
        .unwrap_or_else(|error| panic!("in-process Control Stop should clean up: {error}"));
    assert_eq!(stopped.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        stopped.state_update.map(|update| update.state),
        Some(LiveStateKind::Stopped),
    );
    let Some(QueryResult::Snapshot(snapshot)) = stopped.query_result else {
        panic!("accepted lifecycle Stop should return its terminal snapshot");
    };
    assert!(matches!(
        snapshot.state,
        EngineState::Stopped {
            outcome: crucible_session::Outcome::Stopped
        }
    ));
    assert_eq!(snapshot.configuration, before_stop.configuration);
    assert_eq!(snapshot.frontier, before_stop.frontier);
    assert_eq!(snapshot.quanta, before_stop.quanta);
    assert_eq!(snapshot.event_log_len, before_stop.event_log_len);
    let checkpoint = snapshot
        .terminal_savepoint
        .as_ref()
        .unwrap_or_else(|| panic!("operator Stop should materialize a terminal savepoint"));
    assert_eq!(checkpoint.id, snapshot.configuration.id());
    assert_eq!(checkpoint.configuration, snapshot.configuration.id());
    assert_eq!(checkpoint.virtual_time, snapshot.frontier);

    let sessions = client.list_sessions().await.unwrap_or_else(|error| {
        panic!("in-process list after Control Stop should succeed: {error}")
    });
    assert!(
        sessions.sessions.is_empty(),
        "accepted in-process Control Stop should remove session: {:?}",
        sessions.sessions
    );
    let destroyed = client
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| {
            panic!("idempotent destroy after Control Stop should succeed: {error}")
        });
    assert_eq!(destroyed.session, created.session);
    assert!(destroyed.already_absent);
    assert!(!destroyed.stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_lifecycle_stop_has_no_snapshot_and_keeps_registry_entry() {
    let client = InProcessLifecycleClient::new(lifecycle_control_plane());
    let created = client
        .create_session(
            CreateSessionRequest::scenario_ref(
                "api-control-client-scenario",
                Seed::from_u64(30_518),
            )
            .with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("in-process CreateSession should succeed: {error}"));
    let control = client
        .control_attach(AttachRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("in-process Control attach should succeed: {error}"));
    let exhausted = control
        .send_command(30_519, SessionCommand::ExhaustBudget)
        .await
        .unwrap_or_else(|error| panic!("ExhaustBudget should terminalize the session: {error}"));
    assert_eq!(exhausted.result.status, CommandResultStatus::Accepted);

    let rejected = control
        .send_command(30_520, SessionCommand::Stop)
        .await
        .unwrap_or_else(|error| panic!("rejected Stop should remain a response: {error}"));
    assert_eq!(
        rejected.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::InvalidState,
        }
    );
    assert!(rejected.query_result.is_none());
    let sessions = client
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("list after rejected Stop should succeed: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);

    let destroyed = client
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("terminal session cleanup should succeed: {error}"));
    assert_eq!(destroyed.session, created.session);
}

#[tokio::test(flavor = "current_thread")]
async fn production_http2_lifecycle_server_hosts_rpc_control_surface() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 listener should bind: {error}"));
    let addr = listener.local_addr().unwrap_or_else(|error| {
        panic!("production HTTP/2 listener should report address: {error}")
    });
    let control_plane = LifecycleControlPlane::new(
        "production-http2-lifecycle-server",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let server = tokio::spawn(async move { serve_lifecycle_http2(listener, control_plane).await });

    let rpc = RpcControlClient::new(RpcEndpoint::http2(format!("http://{addr}")))
        .unwrap_or_else(|error| panic!("production HTTP/2 RPC client should build: {error}"));
    let hello = rpc
        .hello(HelloRequest::new(
            "production-http2-lifecycle-client",
            RPC_PROTOCOL_VERSION,
        ))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 hello should decode: {error}"));
    assert_eq!(hello.server_name, "production-http2-lifecycle-server");

    let scenario = generated_scenario(91);
    let created = rpc
        .create_session(
            CreateSessionRequest::inline(scenario.clone(), scenario.seed()).with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 create should decode: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let control = rpc
        .control_attach(
            AttachRequest::new(created.session).with_expected_epoch(created.session.epoch),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 control attach should decode: {error}"));
    assert_eq!(control.attached().session, created.session);
    let query = control
        .send_command(1, query_state_command())
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 control send should decode: {error}"));
    assert_eq!(query.result.status, CommandResultStatus::Accepted);
    assert_raw_send_accepted(
        &format!("http://{addr}"),
        format!(
            "{}query=snapshot\n",
            raw_send_body(created.session, 2, "crucible.cmd.query")
        ),
        "crucible.cmd.query",
    )
    .await;
    assert_raw_send_accepted(
        &format!("http://{addr}"),
        format!(
            "{}query=breakpoint-firings\n",
            raw_send_body(created.session, 3, "crucible.cmd.query")
        ),
        "crucible.cmd.query",
    )
    .await;

    let sessions = rpc
        .list_sessions()
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 list sessions should decode: {error}"));
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].session, created.session);
    assert_eq!(sessions.sessions[0].state, LiveStateKind::Paused);

    let destroyed = rpc
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 destroy should decode: {error}"));
    assert!(destroyed.stopped);
    server.abort();
    match server.await {
        Err(error) if error.is_cancelled() => {}
        other => panic!("production HTTP/2 server task should abort cleanly: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_http2_lifecycle_server_admits_concurrent_watch_and_query_clients() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 listener should bind: {error}"));
    let addr = listener.local_addr().unwrap_or_else(|error| {
        panic!("production HTTP/2 listener should report address: {error}")
    });
    let control_plane = LifecycleControlPlane::new(
        "production-http2-multi-client-server",
        Vec::new(),
        test_loop_factory as fn(&ScenarioDef, Seed) -> ServerQuantumLoop,
    );
    let server = tokio::spawn(async move { serve_lifecycle_http2(listener, control_plane).await });

    let endpoint = RpcEndpoint::http2(format!("http://{addr}"));
    let rpc = RpcControlClient::new(endpoint)
        .unwrap_or_else(|error| panic!("production HTTP/2 RPC client should build: {error}"));
    let scenario = generated_scenario(92);
    let created = rpc
        .create_session(
            CreateSessionRequest::inline(scenario.clone(), scenario.seed()).with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 create should decode: {error}"));
    assert_eq!(created.state, LiveStateKind::Paused);

    let control = rpc
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("production-http2-control-client"),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 control attach should decode: {error}"));
    assert_eq!(control.attached().session, created.session);

    let watch_a_client = rpc.clone();
    let watch_b_client = rpc.clone();
    let query_client = rpc.clone();
    let watch_a = watch_a_client.watch_attach(
        AttachRequest::new(created.session)
            .with_expected_epoch(created.session.epoch)
            .with_client_name("production-http2-watch-a"),
    );
    let watch_b = watch_b_client.watch_attach(
        AttachRequest::new(created.session)
            .with_expected_epoch(created.session.epoch)
            .with_client_name("production-http2-watch-b"),
    );
    let paused_query =
        query_client.send_command(SendRequest::new(created.session, 1, query_state_command()));
    let (watch_a, watch_b, paused_query) = tokio::join!(watch_a, watch_b, paused_query);
    let mut watch_a =
        watch_a.unwrap_or_else(|error| panic!("first concurrent Watch should attach: {error}"));
    let mut watch_b =
        watch_b.unwrap_or_else(|error| panic!("second concurrent Watch should attach: {error}"));
    let paused_query =
        paused_query.unwrap_or_else(|error| panic!("concurrent Query should decode: {error}"));
    assert_eq!(paused_query.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        paused_query.query_result,
        Some(QueryResult::State(LifecycleStateKind::Paused)),
    );

    for attached in [watch_a.attached(), watch_b.attached()] {
        assert_eq!(attached.session, created.session);
        assert_eq!(attached.state, LiveStateKind::Paused);
        assert!(attached.snapshot.is_some());
    }

    let continued = control
        .send_command(2, SessionCommand::Continue)
        .await
        .unwrap_or_else(|error| panic!("Control Continue should decode: {error}"));
    assert_eq!(continued.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        continued.state_update.map(|update| update.state),
        Some(LiveStateKind::Running),
    );

    let running_query_client = rpc.clone();
    let watch_a_running = recv_watch_state_update(&mut watch_a, LiveStateKind::Running);
    let watch_b_running = recv_watch_state_update(&mut watch_b, LiveStateKind::Running);
    let running_query = running_query_client.send_command(SendRequest::new(
        created.session,
        3,
        query_state_command(),
    ));
    let (watch_a_state, watch_b_state, running_query) =
        tokio::join!(watch_a_running, watch_b_running, running_query);
    assert_eq!(watch_a_state, LiveStateKind::Running);
    assert_eq!(watch_b_state, LiveStateKind::Running);
    let running_query =
        running_query.unwrap_or_else(|error| panic!("running Query should decode: {error}"));
    assert_eq!(running_query.result.status, CommandResultStatus::Accepted);
    assert_eq!(
        running_query.query_result,
        Some(QueryResult::State(LifecycleStateKind::Running)),
    );

    let stopped = control
        .send_command(4, SessionCommand::Stop)
        .await
        .unwrap_or_else(|error| panic!("Control Stop should decode: {error}"));
    assert_eq!(stopped.result.status, CommandResultStatus::Accepted);
    let Some(QueryResult::Snapshot(snapshot)) = stopped.query_result else {
        panic!("HTTP/2 Stop should round-trip the terminal snapshot");
    };
    assert!(matches!(snapshot.state, EngineState::Stopped { .. }));
    assert_eq!(snapshot.configuration.def, scenario.scenario_def());
    let checkpoint = snapshot
        .terminal_savepoint
        .as_ref()
        .unwrap_or_else(|| panic!("HTTP/2 terminal snapshot should carry its savepoint"));
    assert_eq!(checkpoint.id, snapshot.configuration.id());
    assert_eq!(checkpoint.virtual_time, snapshot.frontier);
    assert!(snapshot.quanta > 0);
    assert_eq!(snapshot.frontier.ticks, snapshot.quanta);
    assert_eq!(snapshot.event_log_len, 0);
    let destroyed = rpc
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 destroy should decode: {error}"));
    assert_eq!(destroyed.session, created.session);
    server.abort();
    match server.await {
        Err(error) if error.is_cancelled() => {}
        other => panic!("production HTTP/2 server task should abort cleanly: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_http2_lifecycle_server_shutdown_completes_with_active_watch_stream() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 listener should bind: {error}"));
    let addr = listener.local_addr().unwrap_or_else(|error| {
        panic!("production HTTP/2 listener should report address: {error}")
    });
    let control_plane = LifecycleControlPlane::new(
        "production-http2-active-watch-shutdown-server",
        Vec::new(),
        test_loop_factory as fn(&ScenarioDef, Seed) -> ServerQuantumLoop,
    );
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        serve_lifecycle_http2_with_mode_until_shutdown(
            listener,
            control_plane,
            LifecycleServerMode::read_write(),
            async move {
                let _ = shutdown_receiver.await;
            },
        )
        .await
    });

    let rpc = RpcControlClient::new(RpcEndpoint::http2(format!("http://{addr}")))
        .unwrap_or_else(|error| panic!("production HTTP/2 RPC client should build: {error}"));
    let scenario = generated_scenario(93);
    let created = rpc
        .create_session(
            CreateSessionRequest::inline(scenario.clone(), scenario.seed()).with_start_paused(true),
        )
        .await
        .unwrap_or_else(|error| panic!("production HTTP/2 create should decode: {error}"));
    let mut watch = rpc
        .watch_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("production-http2-active-watch"),
        )
        .await
        .unwrap_or_else(|error| panic!("active Watch should attach before shutdown: {error}"));
    assert_eq!(watch.attached().session, created.session);

    shutdown_sender
        .send(())
        .unwrap_or_else(|_| panic!("shutdown receiver should still be active"));
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap_or_else(|_| panic!("server should finish after shutdown with active Watch"))
        .unwrap_or_else(|error| panic!("server task should join after shutdown: {error}"))
        .unwrap_or_else(|error| panic!("server should not fail during shutdown: {error}"));
    let stream_end = tokio::time::timeout(Duration::from_millis(100), watch.recv_state_update())
        .await
        .unwrap_or_else(|_| panic!("Watch stream should close after server shutdown"))
        .unwrap_or_else(|error| panic!("Watch stream should close cleanly: {error}"));
    assert!(stream_end.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_rejections_use_closed_status_taxonomy_without_closing_stream() {
    let (streaming, actor, session) =
        streaming_session_fixture(ServerQuantumLoop { quanta: 0 }, 90);
    let actor_task = tokio::spawn(actor.run());

    let started = streaming
        .send(SendRequest::new(session, 1, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("initial Start should be accepted: {error}"));
    assert_eq!(started.result.status, CommandResultStatus::Accepted);

    assert_rejected_send(
        &streaming,
        session,
        2,
        SessionCommand::Start,
        CommandRejectionKind::InvalidState,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 3).await;

    let reproduction_before_missing_remove = streaming.reproduction_log().snapshot();
    let event_tail_before_missing_remove = streaming.event_log().current_cursor();
    assert_rejected_send(
        &streaming,
        session,
        4,
        SessionCommand::RemoveBreakpoint {
            id: 404,
            reply: CommandReply::discard(),
        },
        CommandRejectionKind::NotFound,
    )
    .await;
    assert_eq!(
        streaming.reproduction_log().snapshot(),
        reproduction_before_missing_remove,
        "running missing-breakpoint rejection must not record reproduction control",
    );
    assert_eq!(
        streaming.event_log().current_cursor(),
        event_tail_before_missing_remove,
        "running missing-breakpoint rejection must not append event-log control",
    );
    assert_accepted_query_after_rejection(&streaming, session, 5).await;

    let paused = streaming
        .send(SendRequest::new(session, 6, SessionCommand::Pause))
        .await
        .unwrap_or_else(|error| panic!("Pause after rejected Start should be accepted: {error}"));
    assert_eq!(paused.result.status, CommandResultStatus::Accepted);

    assert_rejected_send(
        &streaming,
        session,
        7,
        SessionCommand::RemoveBreakpoint {
            id: 404,
            reply: CommandReply::discard(),
        },
        CommandRejectionKind::NotFound,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 8).await;

    let missing_checkpoint = ContentHash::from_bytes(b"missing-api-command-status-checkpoint");
    assert_rejected_send(
        &streaming,
        session,
        9,
        SessionCommand::Fork {
            from: CheckpointRef::Checkpoint(missing_checkpoint),
            reply: CommandReply::discard(),
        },
        CommandRejectionKind::NotFound,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 10).await;

    assert_rejected_send(
        &streaming,
        session,
        11,
        attach_gdb_command("taxonomy-unsupported"),
        CommandRejectionKind::Unsupported,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 12).await;

    stop_streaming_actor(streaming, session, 13, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_maps_backend_rejections_to_invalid_argument() {
    let (streaming, actor, session) = streaming_session_fixture(RejectingGdbLoop { quanta: 0 }, 91);
    let actor_task = tokio::spawn(actor.run());
    start_and_pause_streaming_actor(&streaming, session).await;

    assert_rejected_send(
        &streaming,
        session,
        3,
        attach_gdb_command("taxonomy-invalid-argument"),
        CommandRejectionKind::InvalidArgument,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 4).await;

    stop_streaming_actor(streaming, session, 5, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_maps_internal_command_failures_without_closing_stream() {
    let (streaming, actor, session) = streaming_session_fixture(InternalGdbLoop { quanta: 0 }, 92);
    let actor_task = tokio::spawn(actor.run());
    start_and_pause_streaming_actor(&streaming, session).await;

    assert_rejected_send(
        &streaming,
        session,
        3,
        attach_gdb_command("taxonomy-internal"),
        CommandRejectionKind::Internal,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 4).await;

    stop_streaming_actor(streaming, session, 5, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_send_observes_payload_free_actor_failures() {
    let (streaming, actor, session) = streaming_session_fixture(
        RejectingOnceShutdownLoop {
            quanta: 0,
            shutdown_rejections: 1,
        },
        93,
    );
    let actor_task = tokio::spawn(actor.run());
    start_and_pause_streaming_actor(&streaming, session).await;

    assert_rejected_send(
        &streaming,
        session,
        3,
        SessionCommand::Stop,
        CommandRejectionKind::InvalidArgument,
    )
    .await;
    assert_accepted_query_after_rejection(&streaming, session, 4).await;

    stop_streaming_actor(streaming, session, 5, actor_task).await;
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_send_decodes_all_rejection_statuses_and_golden_error_bytes() {
    let session = SessionRef::new(SessionId::new(77), 3, Seed::from_u64(7700));
    for reason in [
        CommandRejectionKind::InvalidState,
        CommandRejectionKind::NotFound,
        CommandRejectionKind::InvalidArgument,
        CommandRejectionKind::Unsupported,
        CommandRejectionKind::Internal,
    ] {
        let server = spawn_scripted_send_server(vec![
            scripted_send_response(
                axum::http::StatusCode::OK,
                send_response_body(
                    1,
                    SessionCommandKind::Start,
                    CommandResultStatus::Rejected { reason },
                ),
            ),
            scripted_send_response(
                axum::http::StatusCode::OK,
                send_response_body(2, SessionCommandKind::Query, CommandResultStatus::Accepted),
            ),
        ])
        .await;
        let client = RpcControlClient::new(RpcEndpoint::http2(server.endpoint()))
            .unwrap_or_else(|error| panic!("scripted RPC client should build: {error}"));
        let rejected = client
            .send_command(SendRequest::new(session, 1, SessionCommand::Start))
            .await
            .unwrap_or_else(|error| panic!("scripted rejected send should decode: {error}"));
        assert_eq!(
            rejected.result.status,
            CommandResultStatus::Rejected { reason },
        );
        let accepted = client
            .send_command(SendRequest::new(session, 2, query_state_command()))
            .await
            .unwrap_or_else(|error| panic!("scripted send after rejection should decode: {error}"));
        assert_eq!(accepted.result.status, CommandResultStatus::Accepted);
    }

    let golden_rejection = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        String::from_utf8(golden_vector_bytes("send-response-rejected-not-found").to_vec())
            .unwrap_or_else(|error| panic!("golden send response should be UTF-8: {error}")),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(golden_rejection.endpoint()))
        .unwrap_or_else(|error| panic!("golden rejection RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(session, 9002, SessionCommand::Start))
        .await
        .unwrap_or_else(|error| panic!("golden rejected send should decode: {error}"));
    assert_eq!(
        decoded.result.status,
        CommandResultStatus::Rejected {
            reason: CommandRejectionKind::NotFound,
        },
    );

    let query_result_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        String::from(
            "crucible.rpc/send-response\ncommand-id=12\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=state|paused\n",
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(query_result_server.endpoint()))
        .unwrap_or_else(|error| panic!("query-result RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(session, 12, query_state_command()))
        .await
        .unwrap_or_else(|error| panic!("query-result send should decode: {error}"));
    assert_eq!(
        decoded.query_result,
        Some(QueryResult::State(LifecycleStateKind::Paused)),
    );

    let scenario = generated_scenario(9013);
    let config = Configuration::genesis(scenario.scenario_def());
    let snapshot_result_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        format!(
            "crucible.rpc/send-response\ncommand-id=13\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=snapshot|paused:user-requested|0|0|0|{}|{}|{}|{}|none\n",
            scenario.id().to_hex(),
            scenario.seed().to_hex(),
            scenario.app_random_draw_cap(),
            hex_encode(&config.schedule.to_compact_binary()),
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(snapshot_result_server.endpoint()))
        .unwrap_or_else(|error| panic!("snapshot result RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(
            session,
            13,
            SessionCommand::query_snapshot(),
        ))
        .await
        .unwrap_or_else(|error| panic!("snapshot query-result send should decode: {error}"));
    let Some(QueryResult::Snapshot(snapshot)) = decoded.query_result else {
        panic!("snapshot query should decode to an engine snapshot");
    };
    assert_eq!(
        snapshot.state,
        EngineState::Paused {
            reason: crucible_session::PauseReason::UserRequested,
        }
    );
    assert_eq!(snapshot.frontier, VirtualTime { ticks: 0 });
    assert_eq!(snapshot.event_log_len, 0);
    assert_eq!(snapshot.quanta, 0);
    assert_eq!(snapshot.configuration.def.id(), scenario.id());
    assert_eq!(snapshot.configuration.def.seed(), scenario.seed());
    assert_eq!(
        snapshot.configuration.def.app_random_draw_cap(),
        scenario.app_random_draw_cap(),
    );
    assert_eq!(snapshot.configuration.schedule, config.schedule);
    assert!(snapshot.terminal_savepoint.is_none());

    let firing_predicate =
        crucible::Predicate::guest_marker(crucible::MarkerId::from_name("rpc-save-marker"));
    let action_disposition = crucible::Action::pass();
    let scheduler_control = ControlOperationKind::Pause;
    let breakpoint_result_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        format!(
            "crucible.rpc/send-response\ncommand-id=14\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=breakpoint-firings|2|7|11|2|3|{}|suspend|0|8|12|4|5|{}|action:{}|1|{}\nbreakpoint-id=none\nsavepoint-info=none\n",
            hex_encode(&firing_predicate.to_compact_binary()),
            hex_encode(&firing_predicate.to_compact_binary()),
            hex_encode(&action_disposition.to_compact_binary()),
            hex_encode(&scheduler_control.to_compact_binary()),
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(breakpoint_result_server.endpoint()))
        .unwrap_or_else(|error| panic!("breakpoint result RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(
            session,
            14,
            SessionCommand::query_breakpoint_firings(),
        ))
        .await
        .unwrap_or_else(|error| panic!("breakpoint query-result send should decode: {error}"));
    let Some(QueryResult::BreakpointFirings(firings)) = decoded.query_result else {
        panic!("breakpoint query should decode firing records");
    };
    assert_eq!(firings.len(), 2);
    assert_eq!(firings[0].sequence, 7);
    assert_eq!(firings[0].id, 11);
    assert_eq!(firings[0].frontier, VirtualTime { ticks: 2 });
    assert_eq!(firings[0].quanta, 3);
    assert_eq!(firings[0].predicate, firing_predicate);
    assert_eq!(firings[0].disposition, BreakpointDisposition::Suspend);
    assert!(firings[0].scheduler_controls.is_empty());
    assert_eq!(firings[1].sequence, 8);
    assert_eq!(firings[1].id, 12);
    assert_eq!(
        firings[1].disposition,
        BreakpointDisposition::Action(action_disposition),
    );
    assert_eq!(firings[1].scheduler_controls, vec![scheduler_control]);

    let excessive_firing_count_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        format!(
            "crucible.rpc/send-response\ncommand-id=16\ncommand=crucible.cmd.query\nstatus=accepted\nstate-update=none\nquery-result=breakpoint-firings|{}\nbreakpoint-id=none\nsavepoint-info=none\n",
            usize::MAX,
        ),
    )])
    .await;
    let client =
        RpcControlClient::new(RpcEndpoint::http2(excessive_firing_count_server.endpoint()))
            .unwrap_or_else(|error| {
                panic!("excessive firing count RPC client should build: {error}")
            });
    let error = client
        .send_command(SendRequest::new(
            session,
            16,
            SessionCommand::query_breakpoint_firings(),
        ))
        .await
        .expect_err("excessive breakpoint firing count should reject without panicking");
    assert!(
        format!("{error:?}").contains("breakpoint firing count is too large"),
        "unexpected excessive count error: {error:?}"
    );

    let breakpoint_id_server = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::OK,
        String::from(
            "crucible.rpc/send-response\ncommand-id=17\ncommand=crucible.cmd.set-breakpoint\nstatus=accepted\nstate-update=none\nquery-result=none\nbreakpoint-id=44\nsavepoint-info=none\n",
        ),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(breakpoint_id_server.endpoint()))
        .unwrap_or_else(|error| panic!("breakpoint id RPC client should build: {error}"));
    let decoded = client
        .send_command(SendRequest::new(
            session,
            17,
            SessionCommand::SetBreakpoint {
                spec: crucible_session::BreakpointSpec::suspend_once(
                    crucible::Predicate::quiescent(),
                ),
                reply: CommandReply::discard(),
            },
        ))
        .await
        .unwrap_or_else(|error| panic!("breakpoint id send should decode: {error}"));
    assert_eq!(decoded.breakpoint_id, Some(44));

    let golden_error = spawn_scripted_send_server(vec![scripted_send_response(
        axum::http::StatusCode::PRECONDITION_FAILED,
        String::from_utf8(golden_vector_bytes("rpc-error-invalid-state").to_vec())
            .unwrap_or_else(|error| panic!("golden error response should be UTF-8: {error}")),
    )])
    .await;
    let client = RpcControlClient::new(RpcEndpoint::http2(golden_error.endpoint()))
        .unwrap_or_else(|error| panic!("golden error RPC client should build: {error}"));
    let error = client
        .send_command(SendRequest::new(session, 8, SessionCommand::Start))
        .await
        .expect_err("golden invalid-state RPC error should decode");
    assert_eq!(
        error,
        ControlClientError::Streaming {
            source: StreamingApiError::EpochMismatch {
                expected: 8,
                actual: 7,
            },
        },
    );
}

#[test]
fn rpc_wire_contract_snapshots_cover_lifecycle_and_streaming_message_variants() {
    let session = SessionRef::new(SessionId::new(42), 7, Seed::from_u64(42));
    let seed_hex = session.seed.to_hex();
    let reproduction = ReproductionCommandRecord {
        sequence: 1,
        payload: ReproductionCommandPayload {
            command: SessionCommandKind::Pause,
            command_payload: String::from("payload=command-kind\ncommand=Pause\n"),
            scheduler_batch: 0,
            scheduler_control: None,
        },
        virtual_time: VirtualTime { ticks: 5 },
        quanta: 4,
        at_sequence: 3,
        result: ReproductionCommandResult::Accepted,
        observational_order: 1,
    };

    let hello = String::from_utf8(encode_rpc_hello_request(
        "contract-client",
        RPC_PROTOCOL_VERSION,
    ))
    .unwrap_or_else(|error| panic!("hello request should be UTF-8: {error}"));
    assert_rpc_snapshot(
        "hello-request",
        &hello,
        "crucible.rpc/hello-request\nversion=8.0.0+crucible-rpc-abi-v8\nclient=contract-client\n",
    );
    assert_rpc_snapshot(
        "list-scenarios-request",
        "crucible.rpc/list-scenarios-request\n",
        "crucible.rpc/list-scenarios-request\n",
    );

    let create_ref = format!(
        "crucible.rpc/create-session-request\nsource=scenario-ref\nname=contract-scenario\nseed={seed_hex}\nstart-paused=false\n"
    );
    assert_eq!(
        parse_create_session_request(create_ref.as_bytes())
            .unwrap_or_else(|error| panic!("scenario-ref request should parse: {error}")),
        CreateSessionRequest::scenario_ref("contract-scenario", session.seed)
            .with_start_paused(false),
    );
    assert_rpc_snapshot("create-session-ref-request", &create_ref, &create_ref);

    let inline_form = resume_session_request(80).scenario;
    let inline_form_scenario = inline_form.scenario_def();
    let create_inline_form = format!(
        "crucible.rpc/create-session-request\nsource=inline\nscenario-id={}\nscenario-seed={}\napp-random-draw-cap={}\nscenario-payload={}\nseed={seed_hex}\nstart-paused=true\n",
        inline_form_scenario.id().to_hex(),
        inline_form.seed().to_hex(),
        inline_form.app_random_draw_cap(),
        hex_encode(&inline_form.to_compact_binary()),
    );
    assert!(
        create_inline_form.contains("\nscenario-payload="),
        "form-bearing inline create-session must transfer source payload"
    );
    assert_eq!(
        parse_create_session_request(create_inline_form.as_bytes())
            .unwrap_or_else(|error| panic!("inline form request should parse: {error}")),
        CreateSessionRequest::inline(inline_form.clone(), session.seed),
    );
    assert_rpc_snapshot(
        "create-session-inline-request",
        &create_inline_form,
        &create_inline_form,
    );
    let missing_inline_payload = format!(
        "crucible.rpc/create-session-request\nsource=inline\nscenario-id={}\nscenario-seed={}\napp-random-draw-cap={}\nseed={seed_hex}\nstart-paused=true\n",
        inline_form_scenario.id().to_hex(),
        inline_form_scenario.seed().to_hex(),
        inline_form_scenario.app_random_draw_cap(),
    );
    assert!(
        parse_create_session_request(missing_inline_payload.as_bytes()).is_err(),
        "inline create-session must reject a missing scenario payload"
    );

    let resume_request = resume_session_request(78);
    let resume_prefix = format!(
        "crucible.rpc/resume-session-request\nscenario-id={}\nscenario-seed={}\napp-random-draw-cap={}\nscenario-payload={}\nseed={}\nschedule={}\ncheckpoint={}\n",
        resume_request.scenario.id().to_hex(),
        resume_request.scenario.seed().to_hex(),
        resume_request.scenario.app_random_draw_cap(),
        hex_encode(&resume_request.scenario.to_compact_binary()),
        resume_request.seed.to_hex(),
        hex_encode(&resume_request.schedule.to_compact_binary()),
        hex_encode(&resume_request.checkpoint.to_compact_binary()),
    );
    assert!(
        parse_resume_session_request(resume_prefix.as_bytes()).is_err(),
        "source-free resume requests must fail closed"
    );
    let observation_source = &resume_request.observation_source;
    let observation_wire = format!(
        "campaign-observation-source-version={}\ncampaign-observation-source-identity={}\ncampaign-observation-source-proof-size={}\ncampaign-observation-source-proof={}\ncampaign-observation-source-evidence-size={}\ncampaign-observation-source-evidence={}\n",
        observation_source.schema_version(),
        observation_source.identity().to_hex(),
        observation_source.proof().len(),
        hex_encode(observation_source.proof()),
        observation_source.evidence().len(),
        hex_encode(observation_source.evidence()),
    );
    let resume_wire = format!("{resume_prefix}{observation_wire}");
    assert_eq!(
        parse_resume_session_request(resume_wire.as_bytes())
            .unwrap_or_else(|error| panic!("resume request should parse: {error}")),
        resume_request,
    );
    assert_rpc_snapshot("resume-session-request", &resume_wire, &resume_wire);

    let replay_payload = b"snapshot-replay-closure".to_vec();
    let replay_closure = ResumeReplayClosure::new(
        &resume_request.scenario,
        &resume_request.schedule,
        &resume_request.checkpoint,
        7,
        replay_payload.clone(),
    )
    .expect("bounded snapshot replay closure should build");
    let resume_with_closure = resume_request
        .clone()
        .with_replay_closure(replay_closure.clone());
    let resume_closure_wire = format!(
        "{resume_prefix}campaign-replay-closure-version={}\ncampaign-replay-closure-identity={}\ncampaign-replay-closure-size={}\ncampaign-replay-closure-payload={}\n{observation_wire}",
        replay_closure.schema_version(),
        replay_closure.identity().to_hex(),
        replay_closure.payload_len(),
        hex_encode(&replay_payload),
    );
    assert_eq!(
        parse_resume_session_request(resume_closure_wire.as_bytes())
            .unwrap_or_else(|error| panic!("resume closure request should parse: {error}")),
        resume_with_closure,
    );
    assert_rpc_snapshot(
        "resume-session-replay-closure-request",
        &resume_closure_wire,
        &resume_closure_wire,
    );
    let wrong_size = resume_closure_wire.replace(
        &format!(
            "campaign-replay-closure-size={}\n",
            replay_closure.payload_len()
        ),
        &format!(
            "campaign-replay-closure-size={}\n",
            replay_closure.payload_len().saturating_add(1)
        ),
    );
    assert!(parse_resume_session_request(wrong_size.as_bytes()).is_err());
    let wrong_identity = resume_closure_wire.replace(
        &replay_closure.identity().to_hex(),
        &ContentHash::default().to_hex(),
    );
    assert!(parse_resume_session_request(wrong_identity.as_bytes()).is_err());
    let extra_field = format!("{resume_closure_wire}unexpected=field\n");
    assert!(parse_resume_session_request(extra_field.as_bytes()).is_err());

    assert_eq!(
        parse_resume_session_request(resume_closure_wire.as_bytes())
            .unwrap_or_else(|error| panic!("resume observation request should parse: {error}")),
        resume_with_closure,
    );
    assert_rpc_snapshot(
        "resume-session-observation-source-request",
        &resume_closure_wire,
        &resume_closure_wire,
    );
    let wrong_observation_size = resume_closure_wire.replace(
        &format!(
            "campaign-observation-source-proof-size={}\n",
            observation_source.proof().len()
        ),
        &format!(
            "campaign-observation-source-proof-size={}\n",
            observation_source.proof().len().saturating_add(1)
        ),
    );
    assert!(parse_resume_session_request(wrong_observation_size.as_bytes()).is_err());
    let wrong_observation_identity = resume_closure_wire.replace(
        &observation_source.identity().to_hex(),
        &ContentHash::default().to_hex(),
    );
    assert!(parse_resume_session_request(wrong_observation_identity.as_bytes()).is_err());

    assert_rpc_snapshot(
        "list-sessions-request",
        "crucible.rpc/list-sessions-request\n",
        "crucible.rpc/list-sessions-request\n",
    );
    let destroy = format!(
        "crucible.rpc/destroy-session-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\n"
    );
    assert_eq!(
        parse_destroy_session_request(destroy.as_bytes())
            .unwrap_or_else(|error| panic!("destroy request should parse: {error}")),
        DestroySessionRequest::new(session).with_expected_epoch(7),
    );
    assert_rpc_snapshot("destroy-session-request", &destroy, &destroy);

    let get_reproduction = format!(
        "crucible.rpc/get-reproduction-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\n"
    );
    assert_eq!(
        parse_get_reproduction_request(get_reproduction.as_bytes())
            .unwrap_or_else(|error| panic!("get-reproduction request should parse: {error}")),
        GetReproductionRequest::new(session).with_expected_epoch(7),
    );
    assert_rpc_snapshot(
        "get-reproduction-request",
        &get_reproduction,
        &get_reproduction,
    );

    let attach = format!(
        "crucible.rpc/attach-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\nfrom-seq=3\nclient-name=contract-watch\n"
    );
    assert_eq!(
        parse_attach_request(attach.as_bytes())
            .unwrap_or_else(|error| panic!("attach request should parse: {error}")),
        AttachRequest::new(session)
            .with_expected_epoch(7)
            .with_cursor(EventLogCursor::new(3))
            .with_client_name("contract-watch"),
    );
    assert_rpc_snapshot("attach-request", &attach, &attach);

    let send = format!(
        "crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\ncommand-id=99\ncommand=crucible.cmd.pause\n"
    );
    assert_eq!(
        parse_send_request(send.as_bytes())
            .unwrap_or_else(|error| panic!("send request should parse: {error}")),
        SendRequest::new(session, 99, SessionCommand::Pause).with_expected_epoch(7),
    );
    assert_rpc_snapshot("send-request", &send, &send);

    let savepoint_request = format!(
        "crucible.rpc/send-request\nsession-id=42\nepoch=7\nseed={seed_hex}\nexpected-epoch=7\ncommand-id=100\ncommand=crucible.cmd.create-savepoint\nsavepoint-label=636f6e74726163742d73617665\n"
    );
    let parsed_savepoint = parse_send_request(savepoint_request.as_bytes())
        .unwrap_or_else(|error| panic!("savepoint send request should parse: {error}"));
    assert_eq!(
        parsed_savepoint,
        SendRequest::new(
            session,
            100,
            SessionCommand::CreateSavepoint {
                label: String::from("contract-save"),
                reply: CommandReply::discard(),
            },
        )
        .with_expected_epoch(7),
    );
    assert_rpc_snapshot(
        "send-request-savepoint",
        &savepoint_request,
        &savepoint_request,
    );

    let hello_response = String::from_utf8(encode_rpc_hello_response(
        "contract-server",
        RPC_PROTOCOL_VERSION,
        RPC_OPEN_SET_PAYLOAD_KINDS,
    ))
    .unwrap_or_else(|error| panic!("hello response should be UTF-8: {error}"));
    assert_rpc_snapshot(
        "hello-response",
        &hello_response,
        "crucible.rpc/hello-response\nversion=8.0.0+crucible-rpc-abi-v8\nserver=contract-server\npayload-kinds=crucible.cmd.*,crucible.bp.*,crucible.event.*\n",
    );
    assert_rpc_snapshot(
        "list-scenarios-response",
        &encode_list_scenarios_response(&ListScenariosResponse {
            scenarios: vec![ScenarioSummary {
                name: String::from("contract-scenario"),
                description: String::from("Contract scenario"),
                source_id: String::from("test://contract"),
            }],
        }),
        "crucible.rpc/list-scenarios-response\nscenario=contract-scenario|Contract scenario|test://contract\n",
    );
    assert_rpc_snapshot(
        "create-session-response",
        &encode_create_session_response(&CreateSessionResponse {
            session,
            state: LiveStateKind::Paused,
        }),
        &format!(
            "crucible.rpc/create-session-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nstate=paused\n"
        ),
    );
    let resume_checkpoint = ContentHash { bytes: [0x33; 32] };
    let resume_configuration = ContentHash { bytes: [0x44; 32] };
    assert_rpc_snapshot(
        "resume-session-response",
        &encode_resume_session_response(&ResumeSessionResponse {
            session,
            state: LiveStateKind::Paused,
            checkpoint: resume_checkpoint,
            configuration: resume_configuration,
        }),
        &format!(
            "crucible.rpc/resume-session-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nstate=paused\ncheckpoint={}\nconfiguration={}\n",
            resume_checkpoint.to_hex(),
            resume_configuration.to_hex(),
        ),
    );
    assert_rpc_snapshot(
        "list-sessions-response",
        &encode_list_sessions_response(&ListSessionsResponse {
            sessions: vec![SessionSummary {
                session,
                state: LiveStateKind::Running,
                outcome: None,
                terminal_savepoint: None,
                frontier: VirtualTime { ticks: 8 },
                event_log_len: 12,
                quanta_stepped: 4,
            }],
        }),
        &format!(
            "crucible.rpc/list-sessions-response\nsession=42|7|{seed_hex}|running|12|8|4|none|none\n"
        ),
    );
    assert_rpc_snapshot(
        "destroy-session-response",
        &encode_destroy_session_response(&DestroySessionResponse {
            session,
            already_absent: false,
            stopped: true,
        }),
        &format!(
            "crucible.rpc/destroy-session-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nalready-absent=false\nstopped=true\n"
        ),
    );
    assert_rpc_snapshot(
        "get-reproduction-response",
        &encode_get_reproduction_response(&GetReproductionResponse {
            session,
            commands: vec![reproduction.clone()],
        }),
        &format!(
            "crucible.rpc/get-reproduction-response\nsession-id=42\nepoch=7\nseed={seed_hex}\ncommand=1|crucible.cmd.pause|5|4|3|accepted|1|0|none|7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\n"
        ),
    );
    assert_rpc_snapshot(
        "attached-response",
        &encode_attached_response(&Attached {
            session,
            event_log_len: 9,
            state: LiveStateKind::Paused,
            version: RPC_PROTOCOL_VERSION,
            capabilities: StreamingCapabilitySet {
                commands: Vec::new(),
                snapshot_on_attach: true,
            },
            snapshot: Some(AttachSnapshot {
                through: EventLogCursor::new(9),
                event_count: 2,
                causal_event_count: 1,
                observational_event_count: 1,
                last_sequence: Some(8),
                reproduction: vec![reproduction],
            }),
        }),
        &format!(
            "crucible.rpc/attached-response\nsession-id=42\nepoch=7\nseed={seed_hex}\nevent-log-len=9\nstate=paused\nversion=8.0.0+crucible-rpc-abi-v8\ncommands=\nsnapshot=9|2|1|1|8\nreproduction=1|crucible.cmd.pause|5|4|3|accepted|1|0|none|7061796c6f61643d636f6d6d616e642d6b696e640a636f6d6d616e643d50617573650a\n"
        ),
    );
    assert_rpc_snapshot(
        "send-response-accepted",
        &encode_send_response(&SendResponse {
            result: CommandResult {
                command_id: 99,
                command_kind: SessionCommandKind::Pause,
                status: CommandResultStatus::Accepted,
            },
            state_update: Some(StateUpdate {
                session,
                state: LiveStateKind::Paused,
            }),
            query_result: None,
            breakpoint_id: None,
            savepoint_info: None,
        }),
        &format!(
            "crucible.rpc/send-response\ncommand-id=99\ncommand=crucible.cmd.pause\nstatus=accepted\nstate-update=42|7|{seed_hex}|paused\nquery-result=none\nbreakpoint-id=none\nsavepoint-info=none\n"
        ),
    );
    assert_rpc_snapshot(
        "send-response-rejected",
        &encode_send_response(&SendResponse {
            result: CommandResult {
                command_id: 100,
                command_kind: SessionCommandKind::RemoveBreakpoint,
                status: CommandResultStatus::Rejected {
                    reason: CommandRejectionKind::NotFound,
                },
            },
            state_update: None,
            query_result: None,
            breakpoint_id: None,
            savepoint_info: None,
        }),
        "crucible.rpc/send-response\ncommand-id=100\ncommand=crucible.cmd.remove-breakpoint\nstatus=rejected:not-found\nstate-update=none\nquery-result=none\nbreakpoint-id=none\nsavepoint-info=none\n",
    );

    let mut attributes = BTreeMap::new();
    attributes.insert(String::from("ok"), OpenSetAttributeValue::Bool(true));
    assert_rpc_snapshot(
        "event-frame",
        &encode_streaming_frame(&StreamingFrame::Event(StreamingEventFrame {
            generation: 2,
            cursor: EventLogCursor::new(3),
            next_cursor: EventLogCursor::new(4),
            event: OpenSetEventEnvelope {
                sequence: 3,
                at: OpenSetEventTime {
                    virtual_time_ticks: 5,
                    stamp_tick: 355,
                    stamp_retired: Some(6),
                    stamp_node: Some(String::from("node-a")),
                },
                source: OpenSetEventSource::Command { command_id: 99 },
                level: EventLevel::Info,
                observational: false,
                payload: OpenSetPayload::new("crucible.event.contract", attributes),
            },
        })),
        "crucible.rpc/event-frame\ngeneration=2\ncursor=3\nnext-cursor=4\nsequence=3\nvirtual-time-ticks=5\nstamp-tick=355\nstamp-retired=6\nstamp-node=6e6f64652d61\nsource=command|99\nlevel=info\nobservational=false\nkind=crucible.event.contract\nattribute=6f6b|bool|true\n",
    );
    assert_rpc_snapshot(
        "state-update-frame",
        &encode_streaming_frame(&StreamingFrame::StateUpdate(StreamingStateUpdateFrame {
            sequence: 11,
            update: StateUpdate {
                session,
                state: LiveStateKind::Running,
            },
        })),
        &format!(
            "crucible.rpc/state-update-frame\nsequence=11\nstate-update=42|7|{seed_hex}|running\n"
        ),
    );
    assert_rpc_snapshot(
        "rpc-error",
        "crucible.rpc/error\nstatus=invalid-state\nreason=streaming-epoch-mismatch\nexpected=8\nactual=7\n",
        "crucible.rpc/error\nstatus=invalid-state\nreason=streaming-epoch-mismatch\nexpected=8\nactual=7\n",
    );
}

#[path = "contract_tests/transport_conformance.rs"]
mod transport_conformance;
