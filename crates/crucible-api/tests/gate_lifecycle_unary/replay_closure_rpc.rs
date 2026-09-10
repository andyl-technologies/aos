//! Production HTTP/2 transport coverage for typed replay-closure resume.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn http2_resume_round_trips_authenticated_typed_closure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("replay-closure test listener should bind");
    let address = listener
        .local_addr()
        .expect("replay-closure test listener should have an address");
    let control_plane = LifecycleControlPlane::new(
        "crucible-replay-closure-http2-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| NoopLoop,
    )
    .with_resume_replay_closure_validator(|scenario, configuration, checkpoint, closure| {
        if scenario.scenario_def() == configuration.def
            && checkpoint.configuration == configuration.id()
            && closure.schema_version() == 7
            && closure.payload() == b"http2-replay-closure"
        {
            Ok(())
        } else {
            Err(ResumeReplayClosureValidationError::new(
                "HTTP/2 replay closure did not authenticate",
            ))
        }
    });
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_lifecycle_http2_with_debug_policy_until_shutdown(
        listener,
        control_plane,
        LifecycleServerMode::read_write(),
        DebugAuthorizationPolicy::deny_all(),
        async move {
            let _ = shutdown_receiver.await;
        },
    ));
    let client = RpcControlClient::new(RpcEndpoint::http2(format!("http://{address}")))
        .expect("replay-closure RPC client should build");
    let mut request = selected_resume_request(134);
    let replay_closure = ResumeReplayClosure::new(
        &request.scenario,
        &request.schedule,
        &request.checkpoint,
        7,
        b"http2-replay-closure".to_vec(),
    )
    .expect("bounded HTTP/2 replay closure should build");
    request = request.with_replay_closure(replay_closure);

    let resumed = client
        .resume_session(request)
        .await
        .expect("production HTTP/2 server should accept typed replay closure");

    assert_eq!(resumed.state, LiveStateKind::Paused);
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("HTTP/2 resumed session should retain destroy control");

    let missing = client
        .resume_session(selected_resume_request(135))
        .await
        .expect_err("HTTP/2 typed resume without closure must reject");
    assert!(matches!(
        missing,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::ResumeReplayClosure { .. }
        }
    ));

    let _ = shutdown_sender.send(());
    server
        .await
        .expect("replay-closure server task should join")
        .expect("replay-closure server should shut down cleanly");
}
