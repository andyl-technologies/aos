//! Streaming resume parser tests: chunk independence, bounds checked before
//! bytes are read, and refusal kinds.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use futures_util::FutureExt;
use futures_util::stream::{self, Stream, StreamExt};

use super::*;
use crate::server::tests::resume_request_with_closure;

/// Error a fixture stream yields where the parser must already have stopped.
const UNREAD_TAIL: &str = "parser read past its refusal point";

fn parse_chunks(
    chunks: Vec<Result<Bytes, String>>,
    limits: ResumeWireLimits,
) -> Result<ResumeSessionRequest, ResumeWireError> {
    read_resume_session_request(stream::iter(chunks), limits)
        .now_or_never()
        .expect("in-memory chunks never pend")
}

fn split_into(wire: &[u8], size: usize) -> Vec<Result<Bytes, String>> {
    wire.chunks(size)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect()
}

/// Ends the body with a transport error right after `prefix`.
fn prefix_then_unread_tail(prefix: &str) -> Vec<Result<Bytes, String>> {
    vec![
        Ok(Bytes::copy_from_slice(prefix.as_bytes())),
        Err(String::from(UNREAD_TAIL)),
    ]
}

/// Returns the wire text before the first line starting with `field=`.
fn wire_before(wire: &str, field: &str) -> String {
    let marker = format!("\n{field}=");
    let end = wire.find(&marker).expect("fixture carries the field") + 1;
    wire[..end].to_owned()
}

#[test]
fn any_chunking_parses_to_the_same_request() {
    let (request, wire) = resume_request_with_closure();

    for size in [1, 2, 3, 7, 64, 4096, wire.len()] {
        let parsed = parse_chunks(
            split_into(wire.as_bytes(), size),
            ResumeWireLimits::default(),
        )
        .expect("canonical envelope parses at any chunking");
        assert_eq!(parsed, request, "chunk size {size}");
    }
}

#[test]
fn empty_transport_chunks_are_skipped() {
    let (request, wire) = resume_request_with_closure();
    let mut chunks = Vec::new();
    for chunk in split_into(wire.as_bytes(), 5) {
        chunks.push(Ok(Bytes::new()));
        chunks.push(chunk);
    }

    let parsed = parse_chunks(chunks, ResumeWireLimits::default()).expect("parses");
    assert_eq!(parsed, request);
}

#[test]
fn model_fields_share_one_hex_budget() {
    let (_, wire) = resume_request_with_closure();
    let limits = ResumeWireLimits {
        model_envelope_hex_digits: 16,
    };

    let error = parse_chunks(split_into(wire.as_bytes(), 64), limits)
        .expect_err("a model field over the budget must reject");
    assert!(matches!(error, ResumeWireError::TooLarge(_)), "{error}");
    assert!(error.to_string().contains("bounded wire envelope"));
}

#[test]
fn a_declared_oversize_closure_frame_is_refused_before_its_hex_is_read() {
    let (_, wire) = resume_request_with_closure();
    let mut prefix = wire_before(&wire, "campaign-replay-closure-frame-size");
    prefix.push_str(&format!(
        "campaign-replay-closure-frame-size={}\n",
        RESUME_REPLAY_CLOSURE_FRAME_MAX_BYTES + 1
    ));

    let error = parse_chunks(
        prefix_then_unread_tail(&prefix),
        ResumeWireLimits::default(),
    )
    .expect_err("oversize frame must reject");
    let message = error.to_string();
    assert!(message.contains("maximum"), "{message}");
    assert!(!message.contains(UNREAD_TAIL), "{message}");
}

#[test]
fn a_declared_oversize_observation_total_is_refused_before_the_evidence_is_read() {
    let (request, wire) = resume_request_with_closure();
    let proof_len = request.observation_source.proof().len();
    let mut prefix = wire_before(&wire, "campaign-observation-source-evidence-size");
    prefix.push_str(&format!(
        "campaign-observation-source-evidence-size={}\n",
        RESUME_OBSERVATION_SOURCE_MAX_BYTES - proof_len + 1
    ));

    let error = parse_chunks(
        prefix_then_unread_tail(&prefix),
        ResumeWireLimits::default(),
    )
    .expect_err("oversize observation source must reject");
    let message = error.to_string();
    assert!(message.contains("maximum"), "{message}");
    assert!(!message.contains(UNREAD_TAIL), "{message}");
}

#[test]
fn a_sized_payload_longer_than_declared_is_refused_at_the_excess() {
    let (_, wire) = resume_request_with_closure();
    let prefix = wire_before(&wire, "campaign-observation-source-proof");
    let mut body = prefix.clone();
    body.push_str("campaign-observation-source-proof=");
    body.push_str(&"ab".repeat(4096));

    let error = parse_chunks(
        vec![Ok(Bytes::from(body)), Err(String::from(UNREAD_TAIL))],
        ResumeWireLimits::default(),
    )
    .expect_err("an overlong proof must reject");
    let message = error.to_string();
    assert!(message.contains("more than"), "{message}");
    assert!(!message.contains(UNREAD_TAIL), "{message}");
}

#[test]
fn a_text_line_over_its_bound_is_too_large() {
    let body = format!(
        "crucible.rpc/resume-session-request\nscenario-id={}\n",
        "0".repeat(RESUME_WIRE_TEXT_LINE_MAX_BYTES)
    );

    let error = parse_chunks(
        split_into(body.as_bytes(), 100),
        ResumeWireLimits::default(),
    )
    .expect_err("an overlong text line must reject");
    assert!(matches!(error, ResumeWireError::TooLarge(_)), "{error}");
}

#[test]
fn truncation_and_transport_errors_are_malformed() {
    let (_, wire) = resume_request_with_closure();

    // Cut inside the checkpoint hex, on an odd digit.
    let checkpoint = wire
        .find("\ncheckpoint=")
        .expect("fixture has a checkpoint")
        + 13;
    let error = parse_chunks(
        split_into(&wire.as_bytes()[..checkpoint + 1], 8),
        ResumeWireLimits::default(),
    )
    .expect_err("a truncated body must reject");
    assert!(matches!(error, ResumeWireError::Malformed(_)), "{error}");

    let error = parse_chunks(
        vec![
            Ok(Bytes::from_static(b"crucible.rpc/resume-session-request\n")),
            Err(String::from("connection reset")),
        ],
        ResumeWireLimits::default(),
    )
    .expect_err("a transport error must reject");
    assert!(error.to_string().contains("connection reset"), "{error}");
}

#[test]
fn trailing_bytes_after_the_evidence_are_refused() {
    let (_, wire) = resume_request_with_closure();

    let error = parse_chunks(
        split_into(format!("{wire}\n").as_bytes(), 32),
        ResumeWireLimits::default(),
    )
    .expect_err("an extra line must reject");
    assert!(error.to_string().contains("unexpected trailing"), "{error}");
}

#[tokio::test(flavor = "current_thread")]
async fn the_handler_streams_the_body_and_refuses_read_only_mode_first() {
    let state = crate::server::tests::test_state(crate::server::LifecycleServerMode::read_only());
    // A body that fails as soon as it is polled proves the mode check runs
    // before any byte is read.
    let body = axum::body::Body::from_stream(failing_stream());
    let request = axum::http::Request::builder()
        .version(axum::http::Version::HTTP_2)
        .body(body)
        .expect("request fixture must build");

    let response = super::super::handle_resume_session(axum::extract::State(state), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

fn failing_stream() -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send {
    stream::once(async { Err(std::io::Error::other(UNREAD_TAIL)) }).boxed()
}
