//! Actual frame forwarding, unread refusals, partial bodies and cancellation.

use super::*;
use futures_util::stream;
use http_body_util::{BodyExt as _, StreamBody};

fn observation() -> IngressObservation {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-aos-fleet-request-id",
        "0123456789abcdef0123456789abcdef".parse().unwrap(),
    );
    IngressObservation::new(&headers, "PATCH", "/v2/aos/blobs/uploads/id")
}

#[tokio::test]
async fn request_limit_failure_retains_the_actual_exposed_frame() {
    let observation = observation();
    let state = Arc::clone(&observation.0);
    let body = observation.request_body(Body::from("actual oversize data"));

    assert!(axum::body::to_bytes(body, 2).await.is_err());

    let state = state.lock().unwrap();
    // A frame exposed before a limit error can exceed that limit; neither the
    // configured cap nor the error response substitutes for actual consumption.
    assert_eq!(state.request.bytes, "actual oversize data".len() as u64);
    assert_eq!(
        state.request.receipt().exposed_sha256,
        hex::encode(Sha256::digest(b"actual oversize data"))
    );
    assert!(!state.body_authenticated);
}

#[tokio::test]
async fn response_preserves_data_trailers_and_actual_eof() {
    let observation = observation();
    let state = Arc::clone(&observation.0);
    let mut trailers = HeaderMap::new();
    trailers.insert("x-final", "retained".parse().unwrap());
    let frames: Vec<Result<Frame<Bytes>, std::io::Error>> = vec![
        Ok(Frame::data(Bytes::from_static(b"actual"))),
        Ok(Frame::trailers(trailers.clone())),
    ];
    let response = observation.response(
        Response::new(Body::new(StreamBody::new(stream::iter(frames)))),
        "handler_completed",
    );

    let collected = response.into_body().collect().await.unwrap();

    assert_eq!(collected.trailers(), Some(&trailers));
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"actual"));
    let state = state.lock().unwrap();
    assert_eq!(state.reply.bytes, 6);
    assert!(state.reply.eof);
    assert!(!state.reply.failed);
    assert!(state.emitted);
}

#[tokio::test]
async fn dropped_partial_reply_does_not_claim_eof_or_full_response() {
    let observation = observation();
    let state = Arc::clone(&observation.0);
    let frames: Vec<Result<Frame<Bytes>, std::io::Error>> = vec![
        Ok(Frame::data(Bytes::from_static(b"first"))),
        Ok(Frame::data(Bytes::from_static(b"unread"))),
    ];
    let mut body = observation
        .response(
            Response::new(Body::new(StreamBody::new(stream::iter(frames)))),
            "handler_completed",
        )
        .into_body();

    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        Bytes::from_static(b"first")
    );
    drop(body);

    let state = state.lock().unwrap();
    assert_eq!(state.reply.bytes, 5);
    assert!(!state.reply.eof);
    assert_eq!(
        state.reply.receipt().exposed_sha256,
        hex::encode(Sha256::digest(b"first"))
    );
    assert!(state.emitted);
}

#[tokio::test]
async fn failed_request_stream_retains_prefix_without_authentication() {
    let observation = observation();
    let state = Arc::clone(&observation.0);
    let frames = vec![
        Ok(Frame::data(Bytes::from_static(b"prefix"))),
        Err(std::io::Error::other("actual source failed")),
    ];
    let body = observation.request_body(Body::new(StreamBody::new(stream::iter(frames))));

    assert!(body.collect().await.is_err());

    let state = state.lock().unwrap();
    assert_eq!(state.request.bytes, 6);
    assert!(state.request.failed);
    assert!(!state.body_authenticated);
}

#[test]
fn pre_body_refusal_does_not_claim_request_eof_or_actor_acceptance() {
    let observation = observation();
    let state = Arc::clone(&observation.0);

    drop(observation.response(Response::new(Body::empty()), "envelope_refused"));

    let state = state.lock().unwrap();
    assert_eq!(state.request.bytes, 0);
    assert!(!state.request.eof);
    assert!(state.reply.eof);
    assert!(!state.envelope_authenticated);
    assert!(state.checks.is_none());
}

#[test]
fn empty_request_and_reply_report_inner_eof_without_polling() {
    let retained = Arc::new(Mutex::new(Vec::new()));
    let writer = CapturedReceipt(Arc::clone(&retained));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _scope = tracing::dispatcher::set_default(&dispatch);
    let observation = observation();
    let request = observation.request_body(Body::empty());
    let response = observation.response(Response::new(Body::empty()), "handler_completed");

    assert!(request.is_end_stream());
    assert!(response.body().is_end_stream());
    drop(response);

    // Retaining the unpolled request prevents its destructor from supplying
    // the initial EOF fact after the reply has already emitted this receipt.
    let raw = retained.lock().unwrap().clone();
    let text = std::str::from_utf8(&raw).unwrap();
    let (_, encoded) = text
        .split_once("native_ingress_application_body_observation ")
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(encoded.trim()).unwrap();
    for partition in ["requestConsumed", "replyOffered"] {
        assert_eq!(value[partition]["exposedBytes"], "0");
        assert_eq!(
            value[partition]["exposedSha256"],
            hex::encode(Sha256::digest(b""))
        );
        assert_eq!(value[partition]["eof"], true);
        assert_eq!(value[partition]["failed"], false);
    }
    assert_eq!(value["bodyAuthenticated"], false);
    drop(request);
}

#[derive(Clone)]
struct CapturedReceipt(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedReceipt {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn cancellation_emits_when_the_unread_request_body_is_dropped_last() {
    let retained = Arc::new(Mutex::new(Vec::new()));
    let writer = CapturedReceipt(Arc::clone(&retained));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let _scope = tracing::dispatcher::set_default(&dispatch);
    let observation = observation();
    let body = observation.request_body(Body::from("unread body"));

    drop(observation);
    assert!(retained.lock().unwrap().is_empty());
    drop(body);

    let raw = retained.lock().unwrap().clone();
    let text = std::str::from_utf8(&raw).unwrap();
    let (_, encoded) = text
        .split_once("native_ingress_application_body_observation ")
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(encoded.trim()).unwrap();
    assert_eq!(value["stage"], "cancelled");
    assert!(value["checkedContexts"].is_null());
    assert_eq!(value["requestConsumed"]["exposedBytes"], "0");
    assert_eq!(value["requestConsumed"]["eof"], false);
    assert_eq!(value["replyOffered"]["eof"], false);
}
