//! Frame forwarding and gap-detectable window lifecycle regression tests.

use super::*;
use axum::http::{HeaderMap, StatusCode};
use futures_util::stream;
use http_body_util::{BodyExt as _, StreamBody};
use tower::ServiceExt as _;

fn window() -> Arc<Window> {
    Window::new(
        Policy {
            version: 1,
            window_id: "a".repeat(32),
            start_unix_millis: "1".into(),
            end_unix_millis: "2".into(),
        },
        Instant::now(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap()
}

fn member(window: &Arc<Window>) -> Arc<Mutex<Member>> {
    Arc::new(Mutex::new(Member {
        window: Arc::clone(window),
        ordinal: window.admit().unwrap(),
        method: "POST".into(),
        path_sha256: hex::encode(Sha256::digest(b"/synthetic")),
        query_class: None,
        request_id: None,
        transport_call_id: None,
        status: Some(200),
        returned: true,
        typed_evidence: None,
        sql_projection: None,
        publication_summary: None,
        request: ObservedFrames::default(),
        reply: ObservedFrames::default(),
    }))
}

#[test]
fn returned_error_phase_child_matches_actual_frames_without_success_evidence() {
    // The bridge fixture's summary is explicitly synthetic. Core's separate
    // operation tests validate actual summaries against their typed original.
    let selected_window = window();
    let selected = member(&selected_window);
    let request = b"{\"publicationId\":\"synthetic-publication\"}";
    let error = b"unclassified returned error";
    {
        let mut selected = selected.lock().unwrap();
        selected.status = Some(412);
        selected.path_sha256 = hex::encode(Sha256::digest(
            b"/aos.hub.v1.PublishService/CommitRegistryPublication",
        ));
        selected.request.observe(request);
        selected.request.eof = true;
        selected.reply.observe(error);
        selected.reply.eof = true;
        selected.publication_summary = Some(serde_json::from_value(serde_json::json!({
            "version":1, "producerSha256":"a".repeat(64), "publicationId":"synthetic-publication",
            "request":aos_hub_core::application_body_observation::image(request),
            "sourceBeforeUnixNanos":"100", "sourceAfterUnixNanos":"200",
            "sourceElapsedNanos":"100", "terminalOutcome":"returned_error", "phases":[],
        })).unwrap());
    }
    drop(selected);
    let raw = selected_window.raw_records.lock().unwrap();
    let child = raw
        .iter()
        .find(|raw| {
            serde_json::from_str::<serde_json::Value>(raw).unwrap()["event"] == "publication_phases"
        })
        .unwrap();
    let receipt: serde_json::Value = raw
        .iter()
        .find_map(|raw| {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            (value["event"] == "member").then_some(value)
        })
        .unwrap();
    let decoded: serde_json::Value = serde_json::from_str(child).unwrap();
    assert_eq!(
        receipt["publicationPhases"]["sha256"],
        aos_hub_core::application_body_observation::image(child.as_bytes()).sha256
    );
    assert_eq!(
        receipt["publicationPhases"]["byteSize"],
        child.len().to_string()
    );
    for field in [
        "admissionOrdinal",
        "status",
        "handlerReturned",
        "requestConsumed",
        "replyOffered",
    ] {
        assert_eq!(decoded[field], receipt[field]);
    }
    assert_eq!(decoded["status"], 412);
    assert!(receipt["typedEvidence"].is_null());
    assert!(receipt.get("sqlProjection").is_none());
    assert!(decoded.get("sqlReaderAuthority").is_none());
    assert!(decoded.get("objectPayloadBytes").is_none());
}

#[tokio::test]
async fn forwards_data_trailers_and_closes_only_after_both_body_owners() {
    let window = window();
    let member = member(&window);
    let mut trailers = HeaderMap::new();
    trailers.insert("x-end", "yes".parse().unwrap());
    let frames: Vec<Result<Frame<Bytes>, std::io::Error>> = vec![
        Ok(Frame::data(Bytes::from_static(b"first"))),
        Ok(Frame::data(Bytes::from_static(b"second"))),
        Ok(Frame::trailers(trailers.clone())),
    ];
    let request = tap(
        Body::new(StreamBody::new(stream::iter(frames))),
        &member,
        false,
    );
    let reply = tap(Body::empty(), &member, true);
    window.close();
    assert!(!window.counters.lock().unwrap().summary_emitted);

    let collected = request.collect().await.unwrap();
    assert_eq!(collected.trailers(), Some(&trailers));
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"firstsecond"));
    drop(reply);
    assert!(!window.counters.lock().unwrap().summary_emitted);
    drop(member);

    let records = window.records.lock().unwrap();
    assert_eq!(
        records
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["begin", "member", "end"]
    );
    assert_eq!(records[1]["requestConsumed"]["exposedBytes"], "11");
    assert_eq!(
        records[1]["requestConsumed"]["exposedSha256"],
        hex::encode(Sha256::digest(b"firstsecond"))
    );
    assert_eq!(records[2]["pending"], "0");
    assert_eq!(records[1]["requestTrailers"], true);
    assert_eq!(records[1]["replyTrailers"], false);
    assert_eq!(records[2]["incomplete"], "1");
}

#[tokio::test]
async fn unread_and_failed_prefixes_remain_incomplete() {
    let window = window();
    let unread = member(&window);
    drop(tap(Body::from("unread body"), &unread, false));
    drop(tap(Body::empty(), &unread, true));
    drop(unread);
    let failed = member(&window);
    let frames = vec![
        Ok(Frame::data(Bytes::from_static(b"prefix"))),
        Err(std::io::Error::other("actual stream failure")),
    ];
    assert!(tap(
        Body::new(StreamBody::new(stream::iter(frames))),
        &failed,
        false
    )
    .collect()
    .await
    .is_err());
    drop(tap(Body::empty(), &failed, true));
    drop(failed);
    window.close();

    let records = window.records.lock().unwrap();
    assert_eq!(records[1]["requestConsumed"]["eof"], false);
    assert_eq!(records[1]["requestConsumed"]["exposedBytes"], "0");
    assert_eq!(records[2]["requestConsumed"]["failed"], true);
    assert_eq!(records[2]["requestConsumed"]["exposedBytes"], "6");
    assert_eq!(records[3]["incomplete"], "2");
}

#[tokio::test]
async fn all_routes_include_early_refusals_and_response_offering() {
    let window = window();
    let app = Router::new()
        .route(
            "/early",
            axum::routing::post(|| async { StatusCode::UNAUTHORIZED }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "source-fixed error") })
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&window),
            observe,
        ));
    let request = Request::builder()
        .method("POST")
        .uri("/early")
        .body(Body::from("not consumed by this handler"))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    response.into_body().collect().await.unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "source-fixed error"
    );
    window.close();

    let records = window.records.lock().unwrap();
    assert_eq!(records[1]["status"], 401);
    assert_eq!(records[1]["requestConsumed"]["eof"], false);
    assert_eq!(records[2]["status"], 404);
    assert_eq!(records[2]["replyOffered"]["exposedBytes"], "18");
    assert!(records[2]["typedEvidence"].is_null());
    assert_eq!(records[3]["started"], "2");
}

#[test]
fn chain_binds_exact_member_order_and_dropped_handler_is_not_complete() {
    let window = window();
    let first = member(&window);
    let second = member(&window);
    first.lock().unwrap().returned = false;
    drop(second);
    drop(first);
    window.close();

    let records = window.records.lock().unwrap();
    let raw_records = window.raw_records.lock().unwrap();
    let mut previous = [0_u8; 32];
    for (index, record) in records[1..3].iter().enumerate() {
        assert_eq!(record["previousChainSha256"], hex::encode(previous));
        assert_eq!(record["completionOrdinal"], (index + 1).to_string());
        let raw = raw_records[index + 1].as_bytes();
        let mut hash = Sha256::new();
        hash.update(previous);
        hash.update((raw.len() as u64).to_be_bytes());
        hash.update(raw);
        previous = hash.finalize().into();
    }
    assert_eq!(records[3]["chainSha256"], hex::encode(previous));
    let raw = raw_records[2].as_bytes();
    let mut omitted = Sha256::new();
    omitted.update([0_u8; 32]);
    omitted.update((raw.len() as u64).to_be_bytes());
    omitted.update(raw);
    assert_ne!(hex::encode(omitted.finalize()), records[3]["chainSha256"]);
    assert_eq!(records[1]["admissionOrdinal"], "2");
    assert_eq!(records[2]["admissionOrdinal"], "1");
    assert_eq!(records[3]["incomplete"], "2");
}

#[test]
fn cutoff_and_capacity_do_not_admit_invisible_complete_members() {
    let full = window();
    full.counters.lock().unwrap().pending = MAX_PENDING;
    assert!(full.admit().is_none());
    assert!(full.counters.lock().unwrap().overflow);
    let closed = window();
    closed.close();
    assert!(closed.admit().is_none());
    assert!(closed.counters.lock().unwrap().summary_emitted);
    assert!(selected_window(r#"{"version":1,"windowId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","startUnixMillis":"1","endUnixMillis":"2"}"#).is_err());
    assert!(selected_window(r#"{"version":1,"windowId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","startUnixMillis":"01","endUnixMillis":"2","extra":true}"#).is_err());
}

#[tokio::test]
async fn source_extension_joins_actual_frames_and_trailers_prevent_typed_coverage() {
    let captured_window = window();
    let app = Router::new()
        .route(
            "/_assets/style.css",
            axum::routing::get(aos_hub_core::web::assets::stylesheet),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&captured_window),
            observe,
        ));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/_assets/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    captured_window.close();
    let records = captured_window.records.lock().unwrap();
    assert_eq!(
        records[1]["typedEvidence"]["constructor"],
        "embedded_static_asset"
    );
    assert_eq!(
        records[1]["typedEvidence"]["reply"]["sha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(records[1]["replyTrailers"], false);
    drop(records);

    // Export actual producer bytes only for a selected private reader fixture.
    // This synthetic window is not a deployed runtime observation.
    #[cfg(unix)]
    if let Some(path) = std::env::var_os("AOS_NATIVE_INVENTORY_TEST_OUTPUT") {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let raw = captured_window.raw_records.lock().unwrap().join("\n") + "\n";
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        output.write_all(raw.as_bytes()).unwrap();
    }

    let member_window = window();
    let member = member(&member_window);
    {
        let mut state = member.lock().unwrap();
        state.reply.observe(b"actual");
        state.reply.eof = true;
        state.typed_evidence = Some(aos_hub_core::application_body_observation::BodyEvidence {
            constructor: "synthetic_source_constructor",
            constructor_source_sha256: "a".repeat(64),
            request: None,
            reply: aos_hub_core::application_body_observation::image(b"actual"),
            required_projection: "unresolved",
        });
        assert!(matched_evidence(&state).is_some());
        state.reply.trailers = true;
        assert!(matched_evidence(&state).is_none());
        state.reply.trailers = false;
        state.reply.observe(b"changed");
        assert!(matched_evidence(&state).is_none());
    }
}

#[tokio::test]
async fn query_presence_observes_actual_uri_without_changing_forwarded_frames() {
    let window = window();
    let app = Router::new()
        .route(
            "/selected",
            axum::routing::get(|request: Request| async move {
                let body = axum::body::to_bytes(request.into_body(), 128)
                    .await
                    .unwrap();
                (StatusCode::OK, body)
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&window),
            observe,
        ));

    for path in ["/selected", "/selected?", "/selected?key=synthetic"] {
        let request = Request::builder()
            .uri(path)
            .body(Body::from("forwarded"))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "forwarded");
    }
    window.close();

    let records = window.records.lock().unwrap();
    let members: Vec<_> = records
        .iter()
        .filter(|row| row["event"] == "member")
        .collect();
    assert_eq!(members.len(), 3);
    for (row, query) in members.into_iter().zip(["absent", "present", "present"]) {
        assert_eq!(row["queryClass"], query);
        assert_eq!(row["pathSha256"], hex::encode(Sha256::digest(b"/selected")));
        assert_eq!(row["requestConsumed"]["exposedBytes"], "9");
        assert_eq!(row["replyOffered"]["exposedBytes"], "9");
        assert_eq!(row["requestConsumed"]["eof"], true);
        assert_eq!(row["replyOffered"]["eof"], true);
    }
    assert_eq!(records.last().unwrap()["started"], "3");
    assert_eq!(records.last().unwrap()["incomplete"], "0");
}

#[test]
fn absent_legacy_query_field_remains_omitted_without_claiming_absence() {
    let window = window();
    let owner = member(&window);
    drop(owner);
    window.close();

    let records = window.records.lock().unwrap();
    let row = records.iter().find(|row| row["event"] == "member").unwrap();
    assert!(row.get("queryClass").is_none());
}
