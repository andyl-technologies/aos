//! Classification and real-loopback controls for the optional fixture observer.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{Method, StatusCode};

use super::{GROUPS, Observer, ROW_BYTES, ROW_LIMIT, classify};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Unavailable;

impl Write for Unavailable {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn paths() -> [&'static str; 10] {
    [
        "BeginRegistryPublicationManifest",
        "AppendRegistryPublicationManifest",
        "SealRegistryPublicationManifest",
        "UploadObject/fixture-private-id/1",
        "BeginRegistryPublicationMultipartUpload",
        "UploadPart/fixture-private-id/1",
        "CompleteRegistryPublicationMultipartUpload",
        "CommitRegistryPublication",
        "GetRegistryPublication",
        "ListRegistryPublications",
    ]
}

#[test]
fn exact_publication_routes_and_row_budget() {
    let capture = Capture::default();
    let observer = Observer::new(Box::new(capture.clone()));
    assert!(observer.begin_request(&Method::POST, "/foreign").is_none());

    for ordinal in 1..=2 {
        assert_eq!(observer.begin_scope(), Some(ordinal));
        for (group, suffix) in paths().into_iter().enumerate() {
            let method = if matches!(group, 3 | 5) {
                Method::PUT
            } else {
                Method::POST
            };
            let path = format!("/aos.hub.v1.PublishService/{suffix}");
            assert_eq!(classify(&method, &path), Some(group));

            for _ in 0..3 {
                let request = observer.begin_request(&method, &path).unwrap();
                observer.finish_request(request, StatusCode::FORBIDDEN);
            }
        }
        observer.finish_scope(ordinal);
    }
    assert!(observer.begin_scope().is_none());

    let bytes = capture.0.lock().unwrap();
    let output = std::str::from_utf8(&bytes).unwrap();
    for ordinal in 1..=2 {
        let rows = output
            .lines()
            .filter(|line| line.contains(&format!("ordinal={ordinal} ")))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), ROW_LIMIT);
        assert!(rows.iter().all(|row| row.len() < ROW_BYTES));
        for group in GROUPS {
            let summary = rows
                .iter()
                .find(|row| row.contains(&format!("phase={group} edge=summary ")))
                .unwrap();
            assert!(summary.contains("started=3 returned=3 in_flight=0 success=0 failure=3"));
        }
    }
    assert!(!output.contains("fixture-private-id"));

    for path in [
        "/aos.hub.v1.PublishService/CommitRegistryPublication/extra",
        "/aos.hub.v1.PublishService/UploadObject//1",
        "/aos.hub.v1.PublishService/UploadObject/id/0",
        "/aos.hub.v1.PublishService/UploadObject/id/1/extra",
        "/aos.hub.v1.PublishService/UploadPart/id/4294967296",
        "/aos.hub.v1.ContainerService/CommitRegistryPublication",
    ] {
        assert!(classify(&Method::POST, path).is_none());
        assert!(classify(&Method::PUT, path).is_none());
    }
}

#[tokio::test]
async fn original_loopback_middleware_preserves_refusal_with_observer_controls() {
    let capture = Capture::default();
    let enabled = Arc::new(Observer::new(Box::new(capture.clone())));
    let unavailable = Arc::new(Observer::new(Box::new(Unavailable)));

    for observer in [
        None,
        Some(Arc::clone(&enabled)),
        Some(Arc::clone(&unavailable)),
    ] {
        let observations = Arc::new(Mutex::new(Vec::new()));
        let state = crate::ObserverState {
            db: Arc::new(crate::Database::open_in_memory().await.unwrap()),
            registry_id: 0,
            observations: Arc::clone(&observations),
            publication_timing: observer.clone(),
        };
        let app = Router::new()
            .route(
                "/aos.hub.v1.PublishService/CommitRegistryPublication",
                axum::routing::post(|| async { (StatusCode::FORBIDDEN, "fixture refusal") }),
            )
            .route(
                "/aos.hub.v1.ContainerService/FixtureControl",
                axum::routing::post(|| async { StatusCode::GONE }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                crate::observe_control,
            ));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let scope = observer.as_ref().and_then(|value| value.begin_scope());

        let response = reqwest::Client::new()
            .post(format!(
                "http://{address}/aos.hub.v1.PublishService/CommitRegistryPublication"
            ))
            .timeout(std::time::Duration::from_secs(5))
            .body("fixture-private-body")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.text().await.unwrap(), "fixture refusal");
        if let (Some(value), Some(scope)) = (&observer, scope) {
            value.finish_scope(scope);
        }
        let control = reqwest::Client::new()
            .post(format!(
                "http://{address}/aos.hub.v1.ContainerService/FixtureControl"
            ))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .unwrap();
        assert_eq!(control.status(), StatusCode::GONE);
        assert_eq!(
            *observations.lock().unwrap(),
            vec![crate::ControlObservation {
                method: "FixtureControl".to_string(),
                status: StatusCode::GONE,
                tag_digest: None,
            }],
        );
        if observer.is_none() {
            assert!(capture.0.lock().unwrap().is_empty());
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    let bytes = capture.0.lock().unwrap();
    let output = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(output.lines().count(), 5);
    assert!(output.contains(
        "phase=commit edge=summary started=1 returned=1 in_flight=0 success=0 failure=1"
    ));
    assert!(!output.contains("fixture-private-body"));
    assert!(
        unavailable
            .dropped
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
}
