//! Bounded read-only observations of native service consumers.
//!
//! The resource-map contract authorizes one numeric loopback HTTP target. The
//! observer sends a fixed request and accepts only exact instance and resource
//! revision headers from the actual process answering that socket.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Error, Result, ensure};
use aos_ability_model::{InstanceId, RevisionId};
use aos_contract::Sha256Digest;

use super::native_resource_map::NativeHttpConsumerObservation;

const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_REQUEST_BYTES: usize = 2 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const INSTANCE_HEADER: &str = "x-aos-consumer-instance";
const CONTROLLER_REVISION_HEADER: &str = "x-aos-consumer-controller-revision";
const CONTENT_REVISION_HEADER: &str = "x-aos-consumer-content-revision";

/// Classifies whether a consumer observation disproved convergence or could
/// not determine it.
#[derive(Debug)]
pub(super) enum NativeConsumerObservationError {
    /// The contract is invalid or the consumer returned definitive nonmatching evidence.
    Rejected(Error),
    /// Transport failure prevented an authoritative observation.
    Unavailable(Error),
}

impl NativeConsumerObservationError {
    /// Returns whether the consumer supplied definitive nonmatching evidence.
    pub(super) const fn is_rejection(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

impl std::fmt::Display for NativeConsumerObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(error) | Self::Unavailable(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for NativeConsumerObservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(error) | Self::Unavailable(error) => Some(error.root_cause()),
        }
    }
}

/// Carries exact revision evidence reported by the expected live consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NativeConsumerClassification {
    /// Identifies the service-controller revision reported by the process.
    pub(super) controller_revision: RevisionId,
    /// Identifies the content revision reported by the process.
    pub(super) content_revision: RevisionId,
}

/// Observes the exact process answering an authenticated loopback HTTP target.
///
/// # Errors
///
/// Returns an error when the target is not a numeric loopback socket, the
/// bounded connection or read fails, the response is malformed, or its exact
/// instance and revision evidence differs from the resource-map contract.
#[cfg(test)]
pub(super) fn observe_native_http_consumer(
    observation: &NativeHttpConsumerObservation,
) -> Result<(), NativeConsumerObservationError> {
    observe_native_http_consumer_with_control(
        observation,
        OBSERVATION_TIMEOUT.as_millis() as u64,
        &|| false,
    )
}

/// Classifies the exact revisions reported by the expected live consumer.
///
/// Unlike convergence verification, this accepts nonmatching revisions so a
/// trusted controller can construct a new repair graph. A different instance,
/// malformed response, or unavailable transport still fails closed.
///
/// # Errors
///
/// Returns a rejected error for invalid or foreign response evidence and an
/// unavailable error when the bounded transport cannot establish a result.
pub(super) fn classify_native_http_consumer(
    observation: &NativeHttpConsumerObservation,
) -> Result<NativeConsumerClassification, NativeConsumerObservationError> {
    classify_native_http_consumer_with_control(
        observation,
        OBSERVATION_TIMEOUT.as_millis() as u64,
        &|| false,
    )
}

/// Observes a consumer within the caller's remaining method budget.
///
/// The live budget is capped by the observer's own maximum and I/O polls are
/// short enough to notice cancellation without waiting for that whole cap.
///
/// # Errors
///
/// Returns a rejected error for an invalid contract or definitive response
/// mismatch, and an unavailable error when cancellation, budget, or transport
/// prevents an authoritative result.
pub(super) fn observe_native_http_consumer_with_control(
    observation: &NativeHttpConsumerObservation,
    remaining_millis: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), NativeConsumerObservationError> {
    let (endpoint, request) =
        prepare_request(observation).map_err(NativeConsumerObservationError::Rejected)?;

    ensure_available(!cancelled(), "native consumer observation was cancelled")?;
    let budget = OBSERVATION_TIMEOUT.min(Duration::from_millis(remaining_millis));
    ensure_available(
        !budget.is_zero(),
        "native consumer observation has no remaining method budget",
    )?;

    let deadline = Instant::now()
        .checked_add(budget)
        .context("native consumer observation deadline overflowed")
        .map_err(NativeConsumerObservationError::Unavailable)?;
    let mut stream = TcpStream::connect_timeout(&endpoint, budget.min(CANCELLATION_POLL_INTERVAL))
        .context("connecting to native consumer observation endpoint")
        .map_err(NativeConsumerObservationError::Unavailable)?;
    ensure_available(!cancelled(), "native consumer observation was cancelled")?;
    set_remaining_timeout(&stream, deadline, true)
        .map_err(NativeConsumerObservationError::Unavailable)?;
    stream
        .write_all(request.as_bytes())
        .context("writing native consumer observation request")
        .map_err(NativeConsumerObservationError::Unavailable)?;
    ensure_available(!cancelled(), "native consumer observation was cancelled")?;

    let response = read_response_headers(&mut stream, deadline, cancelled)
        .map_err(NativeConsumerObservationError::Unavailable)?;
    verify_response_headers(&response, observation)
        .map_err(NativeConsumerObservationError::Rejected)
}

fn classify_native_http_consumer_with_control(
    observation: &NativeHttpConsumerObservation,
    remaining_millis: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<NativeConsumerClassification, NativeConsumerObservationError> {
    let (endpoint, request) =
        prepare_request(observation).map_err(NativeConsumerObservationError::Rejected)?;
    ensure_available(!cancelled(), "native consumer observation was cancelled")?;
    let budget = OBSERVATION_TIMEOUT.min(Duration::from_millis(remaining_millis));
    ensure_available(
        !budget.is_zero(),
        "native consumer observation has no remaining method budget",
    )?;

    let deadline = Instant::now()
        .checked_add(budget)
        .context("native consumer observation deadline overflowed")
        .map_err(NativeConsumerObservationError::Unavailable)?;
    let mut stream = TcpStream::connect_timeout(&endpoint, budget.min(CANCELLATION_POLL_INTERVAL))
        .context("connecting to native consumer observation endpoint")
        .map_err(NativeConsumerObservationError::Unavailable)?;
    ensure_available(!cancelled(), "native consumer observation was cancelled")?;
    set_remaining_timeout(&stream, deadline, true)
        .map_err(NativeConsumerObservationError::Unavailable)?;
    stream
        .write_all(request.as_bytes())
        .context("writing native consumer observation request")
        .map_err(NativeConsumerObservationError::Unavailable)?;
    ensure_available(!cancelled(), "native consumer observation was cancelled")?;
    let response = read_response_headers(&mut stream, deadline, cancelled)
        .map_err(NativeConsumerObservationError::Unavailable)?;
    classify_response_headers(&response, observation)
        .map_err(NativeConsumerObservationError::Rejected)
}

fn ensure_available(condition: bool, message: &str) -> Result<(), NativeConsumerObservationError> {
    if condition {
        Ok(())
    } else {
        Err(NativeConsumerObservationError::Unavailable(
            anyhow::anyhow!("{message}"),
        ))
    }
}

fn prepare_request(observation: &NativeHttpConsumerObservation) -> Result<(SocketAddr, String)> {
    ensure!(
        observation.schema == NativeHttpConsumerObservation::SCHEMA,
        "unsupported native HTTP consumer-observation schema"
    );
    let endpoint: SocketAddr = observation
        .endpoint
        .parse()
        .context("native consumer observation endpoint is not numeric")?;
    ensure!(
        endpoint.ip().is_loopback() && endpoint.port() != 0,
        "native consumer observation endpoint is not a nonzero loopback socket"
    );

    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        observation.path, observation.authority
    );
    ensure!(
        request.len() <= MAX_REQUEST_BYTES,
        "native consumer observation request exceeds its bound"
    );

    Ok((endpoint, request))
}

fn read_response_headers(
    stream: &mut TcpStream,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>> {
    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        ensure!(!cancelled(), "native consumer observation was cancelled");
        set_remaining_timeout(stream, deadline, false)?;
        let count = match stream.read(&mut chunk) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => {
                return Err(error).context("reading native consumer observation response");
            }
        };
        ensure!(
            count != 0,
            "native consumer response ended before its headers"
        );
        response.extend_from_slice(&chunk[..count]);
        ensure!(
            response.len() <= MAX_RESPONSE_HEADER_BYTES,
            "native consumer response headers exceed their bound"
        );
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
    }
}

fn set_remaining_timeout(stream: &TcpStream, deadline: Instant, write: bool) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("native consumer observation exceeded its deadline")?;
    let timeout = remaining.min(CANCELLATION_POLL_INTERVAL);
    if write {
        stream
            .set_write_timeout(Some(timeout))
            .context("bounding native consumer observation write")
    } else {
        stream
            .set_read_timeout(Some(timeout))
            .context("bounding native consumer observation read")
    }
}

fn verify_response_headers(
    response: &[u8],
    observation: &NativeHttpConsumerObservation,
) -> Result<()> {
    let classified = classify_response_headers(response, observation)?;
    ensure!(
        classified.controller_revision == observation.expected_controller_revision,
        "native consumer response reports another controller revision"
    );
    ensure!(
        classified.content_revision == observation.expected_content_revision,
        "native consumer response reports another content revision"
    );
    Ok(())
}

fn classify_response_headers(
    response: &[u8],
    observation: &NativeHttpConsumerObservation,
) -> Result<NativeConsumerClassification> {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("native consumer response has no complete header block")?;
    let headers = std::str::from_utf8(&response[..end])
        .context("native consumer response headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .context("native consumer response has no status line")?;
    let mut status_fields = status.split_ascii_whitespace();
    let version = status_fields
        .next()
        .context("native consumer response has no HTTP version")?;
    let code = status_fields
        .next()
        .context("native consumer response has no status code")?;
    ensure!(
        matches!(version, "HTTP/1.0" | "HTTP/1.1") && code == "204",
        "native consumer observation returned an unexpected HTTP status"
    );

    let mut instance = None;
    let mut controller_revision = None;
    let mut content_revision = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("native consumer response contains a malformed header")?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case(INSTANCE_HEADER) {
            ensure!(
                instance.replace(value).is_none(),
                "native consumer response repeats its instance evidence"
            );
        } else if name.eq_ignore_ascii_case(CONTROLLER_REVISION_HEADER) {
            ensure!(
                controller_revision.replace(value).is_none(),
                "native consumer response repeats its controller revision evidence"
            );
        } else if name.eq_ignore_ascii_case(CONTENT_REVISION_HEADER) {
            ensure!(
                content_revision.replace(value).is_none(),
                "native consumer response repeats its content revision evidence"
            );
        }
    }

    let instance: InstanceId = serde_json::from_str(
        instance.context("native consumer response omitted its instance evidence")?,
    )
    .context("native consumer response has invalid instance evidence")?;
    ensure!(
        instance == observation.expected_instance,
        "native consumer response came from another checked instance"
    );
    let controller_revision = RevisionId(
        Sha256Digest::parse(
            controller_revision
                .context("native consumer response omitted its controller revision evidence")?,
        )
        .context("native consumer response has invalid controller revision evidence")?,
    );
    let content_revision = RevisionId(
        Sha256Digest::parse(
            content_revision
                .context("native consumer response omitted its content revision evidence")?,
        )
        .context("native consumer response has invalid content revision evidence")?,
    );
    Ok(NativeConsumerClassification {
        controller_revision,
        content_revision,
    })
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use aos_ability_model::{EnvironmentId, ExecutionStage, LocalKey, RevisionId};
    use aos_contract::Sha256Digest;

    use super::*;

    #[test]
    fn exact_instance_and_revision_are_required() {
        let expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        let expected_instance = serde_json::to_string(&expected.expected_instance).unwrap();
        let correct_controller = expected.expected_controller_revision.0.to_string();
        let correct_content = expected.expected_content_revision.0.to_string();
        let current = response(&expected_instance, &correct_controller, &correct_content);
        verify_response_headers(current.as_bytes(), &expected).unwrap();

        let old_content = RevisionId(Sha256Digest::of_bytes("old")).0.to_string();
        let error = verify_response_headers(
            response(&expected_instance, &correct_controller, &old_content).as_bytes(),
            &expected,
        )
        .unwrap_err();
        assert!(error.to_string().contains("another content revision"));

        let wrong_instance = serde_json::to_string(&instance("wrong")).unwrap();
        let error = verify_response_headers(
            response(&wrong_instance, &correct_controller, &correct_content).as_bytes(),
            &expected,
        )
        .unwrap_err();
        assert!(error.to_string().contains("another checked instance"));
    }

    #[test]
    fn observer_reads_the_authorized_loopback_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        expected.endpoint = listener.local_addr().unwrap().to_string();
        let instance = serde_json::to_string(&expected.expected_instance).unwrap();
        let controller = expected.expected_controller_revision.0.to_string();
        let content = expected.expected_content_revision.0.to_string();
        let response = response(&instance, &controller, &content);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; MAX_REQUEST_BYTES];
            let count = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..count]).unwrap();
            assert!(request.starts_with("GET /__aos/consumer HTTP/1.0\r\n"));
            assert!(request.contains("\r\nHost: aos-consumer.invalid\r\n"));
            stream.write_all(response.as_bytes()).unwrap();
        });

        observe_native_http_consumer(&expected).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn ambiguous_headers_fail_closed() {
        let expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        let instance = serde_json::to_string(&expected.expected_instance).unwrap();
        let controller = expected.expected_controller_revision.0.to_string();
        let content = expected.expected_content_revision.0.to_string();
        let duplicate = format!(
            "HTTP/1.0 204 No Content\r\nX-AOS-Consumer-Instance: {instance}\r\nX-AOS-Consumer-Instance: {instance}\r\nX-AOS-Consumer-Controller-Revision: {controller}\r\nX-AOS-Consumer-Content-Revision: {content}\r\n\r\n"
        );
        assert!(verify_response_headers(duplicate.as_bytes(), &expected).is_err());
    }

    #[test]
    fn answered_revision_mismatch_is_definitive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        expected.endpoint = listener.local_addr().unwrap().to_string();
        let instance = serde_json::to_string(&expected.expected_instance).unwrap();
        let controller = expected.expected_controller_revision.0.to_string();
        let old_content = RevisionId(Sha256Digest::of_bytes("old")).0.to_string();
        let response = response(&instance, &controller, &old_content);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; MAX_REQUEST_BYTES];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });

        let error = observe_native_http_consumer(&expected).unwrap_err();
        assert!(error.is_rejection());
        server.join().unwrap();
    }

    #[test]
    fn classifier_retains_mismatched_revision_evidence_from_the_expected_instance() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        expected.endpoint = listener.local_addr().unwrap().to_string();
        let instance = serde_json::to_string(&expected.expected_instance).unwrap();
        let controller = expected.expected_controller_revision.0.to_string();
        let old_content = RevisionId(Sha256Digest::of_bytes("old"));
        let response = response(&instance, &controller, &old_content.0.to_string());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; MAX_REQUEST_BYTES];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });

        let classified = classify_native_http_consumer(&expected).unwrap();
        assert_eq!(
            classified.controller_revision,
            expected.expected_controller_revision
        );
        assert_eq!(classified.content_revision, old_content);
        server.join().unwrap();
    }

    #[test]
    fn unavailable_endpoint_remains_indeterminate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        drop(listener);
        let mut expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        expected.endpoint = endpoint.to_string();

        let error = observe_native_http_consumer(&expected).unwrap_err();
        assert!(!error.is_rejection());
    }

    #[test]
    fn live_budget_and_cancellation_stop_before_network_io() {
        let expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));

        let exhausted =
            observe_native_http_consumer_with_control(&expected, 0, &|| false).unwrap_err();
        assert!(!exhausted.is_rejection());

        let cancelled =
            observe_native_http_consumer_with_control(&expected, 2_000, &|| true).unwrap_err();
        assert!(!cancelled.is_rejection());
        assert!(cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn cancellation_interrupts_a_stalled_consumer_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        expected.endpoint = listener.local_addr().unwrap().to_string();
        let cancelled = Arc::new(AtomicBool::new(false));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; MAX_REQUEST_BYTES];
            let _ = stream.read(&mut request).unwrap();
            thread::sleep(Duration::from_millis(250));
        });
        let cancellation = Arc::clone(&cancelled);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(75));
            cancellation.store(true, Ordering::SeqCst);
        });

        let started = Instant::now();
        let error = observe_native_http_consumer_with_control(&expected, 1_000, &|| {
            cancelled.load(Ordering::SeqCst)
        })
        .unwrap_err();
        let elapsed = started.elapsed();

        assert!(!error.is_rejection());
        assert!(error.to_string().contains("cancelled"));
        assert!(elapsed < Duration::from_millis(500));
        canceller.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn method_budget_bounds_a_stalled_consumer_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut expected = observation("expected", RevisionId(Sha256Digest::of_bytes("current")));
        expected.endpoint = listener.local_addr().unwrap().to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; MAX_REQUEST_BYTES];
            let _ = stream.read(&mut request).unwrap();
            thread::sleep(Duration::from_millis(250));
        });

        let started = Instant::now();
        let error =
            observe_native_http_consumer_with_control(&expected, 75, &|| false).unwrap_err();
        let elapsed = started.elapsed();

        assert!(!error.is_rejection());
        assert!(error.to_string().contains("exceeded its deadline"));
        assert!(elapsed < Duration::from_millis(500));
        server.join().unwrap();
    }

    fn response(instance: &str, controller: &str, content: &str) -> String {
        format!(
            "HTTP/1.0 204 No Content\r\nX-AOS-Consumer-Instance: {instance}\r\nX-AOS-Consumer-Controller-Revision: {controller}\r\nX-AOS-Consumer-Content-Revision: {content}\r\n\r\n"
        )
    }

    fn observation(key: &str, expected_revision: RevisionId) -> NativeHttpConsumerObservation {
        NativeHttpConsumerObservation {
            schema: NativeHttpConsumerObservation::SCHEMA.to_string(),
            endpoint: "127.0.0.1:18081".to_string(),
            authority: "aos-consumer.invalid".to_string(),
            path: "/__aos/consumer".to_string(),
            expected_instance: instance(key),
            expected_controller_revision: expected_revision,
            content_resource: aos_ability_model::ResourceId {
                provider: instance(key),
                key: LocalKey::new("content").unwrap(),
            },
            expected_content_revision: RevisionId(Sha256Digest::of_bytes("content")),
        }
    }

    fn instance(key: &str) -> InstanceId {
        InstanceId {
            environment: EnvironmentId {
                authority: LocalKey::new("test").unwrap(),
                key: LocalKey::new("host").unwrap(),
                stage: ExecutionStage::Host,
            },
            key: LocalKey::new(key).unwrap(),
        }
    }
}
