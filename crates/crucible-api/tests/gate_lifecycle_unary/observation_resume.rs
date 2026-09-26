//! Observation-backed resume preparation and admission tests.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn observation_resume_requires_factory_before_session_allocation() {
    let ordinary_allocations = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ordinary_allocations);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-resume-missing-factory-test",
        Vec::new(),
        move |_scenario: &ScenarioDef, _seed| {
            counted.fetch_add(1, Ordering::SeqCst);
            QuiescentLifecycleLoop::new()
        },
    );
    let mut request = resume_request(142);
    request.replay_closure = None;

    let client = InProcessLifecycleClient::new(control_plane);
    let error = client
        .resume_session(request)
        .await
        .expect_err("observation resume without a campaign factory must reject");

    assert!(matches!(
        error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::ResumeObservationSource { .. }
        }
    ));
    assert_eq!(ordinary_allocations.load(Ordering::SeqCst), 0);
    assert_eq!(client.session_count().await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn observation_resume_factory_finishes_before_session_publication() {
    let ordinary_allocations = Arc::new(AtomicUsize::new(0));
    let counted_ordinary = Arc::clone(&ordinary_allocations);
    let authenticated = Arc::new(AtomicUsize::new(0));
    let counted_authenticated = Arc::clone(&authenticated);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-resume-factory-test",
        Vec::new(),
        move |_scenario: &ScenarioDef, _seed| {
            counted_ordinary.fetch_add(1, Ordering::SeqCst);
            QuiescentLifecycleLoop::new()
        },
    )
    .with_resume_observation_loop_factory(move |request, configuration, _context| {
        assert_eq!(request.observation_source.proof(), b"proof");
        assert_eq!(configuration.id(), request.checkpoint.configuration);
        counted_authenticated.fetch_add(1, Ordering::SeqCst);
        Ok(QuiescentLifecycleLoop::new())
    });
    let request = resume_request(143);

    let client = InProcessLifecycleClient::new(control_plane);
    let resumed = client
        .resume_session(request)
        .await
        .expect("campaign factory should authorize ordinary session publication");

    assert_eq!(authenticated.load(Ordering::SeqCst), 1);
    assert_eq!(ordinary_allocations.load(Ordering::SeqCst), 0);
    assert_eq!(client.session_count().await, 1);
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("destroy resumed session");
}

#[tokio::test(flavor = "current_thread")]
async fn failed_observation_preparation_releases_its_in_flight_permit() {
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&factory_calls);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-failed-permit-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        let call = counted.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            Err(LifecycleApiError::ResumeObservationSource {
                message: String::from("injected source authentication failure"),
            })
        } else {
            Ok(QuiescentLifecycleLoop::new())
        }
    })
    .with_resume_observation_preparation_capacity(1);
    let client = InProcessLifecycleClient::new(control_plane);

    client
        .resume_session(observation_resume_request(148))
        .await
        .expect_err("first preparation should fail");
    let resumed = client
        .resume_session(observation_resume_request(149))
        .await
        .expect("failed preparation must release its permit");

    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(client.session_count().await, 1);
    client
        .destroy_session(DestroySessionRequest::new(resumed.session))
        .await
        .expect("destroy resumed session");
}

#[tokio::test(flavor = "current_thread")]
async fn http_observation_preparation_releases_registry_lock_and_bounds_in_flight_work() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("observation concurrency listener");
    let address = listener.local_addr().expect("observation listener address");
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let counted_calls = Arc::clone(&factory_calls);
    let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
    let release_receiver = Arc::new(Mutex::new(release_receiver));
    let factory_release = Arc::clone(&release_receiver);
    let control_plane = LifecycleControlPlane::new(
        "crucible-observation-concurrency-test",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_resume_observation_loop_factory(move |_request, _configuration, _context| {
        counted_calls.fetch_add(1, Ordering::SeqCst);
        started_sender
            .send(())
            .map_err(|error| LifecycleApiError::ResumeObservationSource {
                message: format!("signal blocked test factory: {error}"),
            })?;
        factory_release
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv()
            .map_err(|error| LifecycleApiError::ResumeObservationSource {
                message: format!("release blocked test factory: {error}"),
            })?;
        Ok(QuiescentLifecycleLoop::new())
    })
    .with_resume_observation_preparation_capacity(1)
    .with_max_sessions(2);
    let server = tokio::spawn(async move { serve_lifecycle_http2(listener, control_plane).await });
    let endpoint = format!("http://{address}");
    let rpc = RpcControlClient::new(RpcEndpoint::http2(endpoint.clone()))
        .expect("observation concurrency client");

    let first_request = observation_resume_request(145);
    let first_endpoint = endpoint.clone();
    let first_resume = tokio::spawn(async move {
        RpcControlClient::new(RpcEndpoint::http2(first_endpoint))
            .expect("first observation client")
            .resume_session(first_request)
            .await
    });
    tokio::task::spawn_blocking(move || {
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("observation factory should start")
    })
    .await
    .expect("factory-start waiter");

    let sessions = tokio::time::timeout(std::time::Duration::from_secs(1), rpc.list_sessions())
        .await
        .expect("list sessions must not wait for observation replay")
        .expect("list sessions during observation replay");
    assert!(sessions.sessions.is_empty());
    let second_error = rpc
        .resume_session(observation_resume_request(146))
        .await
        .expect_err("preparation capacity must reject a concurrent source replay");
    assert!(matches!(
        second_error,
        crucible_api::ControlClientError::Lifecycle {
            source: LifecycleApiError::ResumeObservationSource { .. }
        }
    ));
    assert_eq!(factory_calls.load(Ordering::SeqCst), 1);

    release_sender
        .send(())
        .expect("release first observation replay");
    first_resume
        .await
        .expect("first observation resume task")
        .expect("first observation resume");
    let sessions = rpc.list_sessions().await.expect("list resumed session");
    assert_eq!(sessions.sessions.len(), 1);

    server.abort();
    let _ = server.await;
}

fn observation_resume_request(seed: u64) -> ResumeSessionRequest {
    resume_request(seed)
}
