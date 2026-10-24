//! Exercises capability authentication over actual native Distribution sockets.
//!
//! Fixture handlers establish dispatch and credential preservation only; they
//! deliberately provide no repository authorization or durable backend result.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction intentionally panics."
)]

use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use terrane_format::auth::{self, Authority, Grant, IssuerKey, PrincipalKind, Token, Verb, Verbs};
use terrane_sdk::{store::Clock, wire::authentication::CapabilityAuthentication};

use super::{Running, Services, TestResult, frame, request, transport};

#[derive(Clone)]
struct LiveClock(Arc<AtomicU64>);

impl Clock for LiveClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
    }

    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
}

fn key() -> IssuerKey {
    IssuerKey {
        issuer: "distribution-tests".into(),
        key_id: "active".into(),
        public_key: auth::public_key_from_secret(&[11; 32]),
        retirement: None,
    }
}

fn credential() -> Vec<u8> {
    Token::issue(
        Authority {
            issuer: "distribution-tests".into(),
            key_id: "active".into(),
            subject: "build-job".into(),
            kind: PrincipalKind::Workload,
            groups: vec![],
            not_after: 200,
            not_before: Some(50),
            token_id: [9; 16],
            grants: vec![
                Grant::new(
                    "refs/heads/main".into(),
                    Verbs::new(Verb::Read as u8).unwrap(),
                )
                .unwrap(),
            ],
            workload: Some("job/123".into()),
        },
        &[11; 32],
        auth::public_key_from_secret(&[12; 32]),
    )
    .unwrap()
    .encode()
}

fn bearer(bytes: &[u8]) -> String {
    format!("Bearer {}", URL_SAFE_NO_PAD.encode(bytes))
}

async fn start(
    services: Arc<Services>,
    clock: LiveClock,
    anonymous: bool,
    keys: Vec<IssuerKey>,
) -> Result<Running, super::TestError> {
    let authentication =
        CapabilityAuthentication::new(clock, keys, NonZeroUsize::new(2048).unwrap(), anonymous);
    Ok(Running::start(
        transport(services, None)
            .await?
            .with_authentication(authentication),
    ))
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

#[tokio::test]
async fn refuses_missing_malformed_duplicate_and_tampered_credentials_before_decode() -> TestResult
{
    let services = Arc::new(Services::default());
    let clock = LiveClock(Arc::new(AtomicU64::new(100)));
    let running = start(services.clone(), clock, false, vec![key()]).await?;
    let url = format!("http://{}/terrane.v1.ContentService/Has", running.address);
    let valid = bearer(&credential());
    let mut tampered = credential();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let cases = vec![
        vec![],
        vec!["Basic abc".into()],
        vec!["Bearer".into()],
        vec!["Bearer ".into()],
        vec!["Bearer abc=".into()],
        vec![format!("Bearer {}", "A".repeat(2048))],
        vec![valid.clone(), valid],
        vec![bearer(&tampered)],
    ];

    for headers in cases {
        let mut request = client()
            .post(&url)
            .header("content-type", "application/json")
            .body("{invalid JSON");
        for header in headers {
            request = request.header("authorization", header);
        }
        let response = request.send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let error: serde_json::Value = response.json().await?;
        assert_eq!(error["code"], "unauthenticated");
        assert!(!error["details"].as_array().unwrap().is_empty());
    }

    assert_eq!(services.calls.load(Ordering::SeqCst), 0);
    assert!(services.tokens.lock().unwrap().is_empty());
    running.stop().await
}

#[tokio::test]
async fn preserves_exact_verified_token_and_rechecks_live_expiry_and_key_retirement() -> TestResult
{
    for retirement in [None, Some(150)] {
        let services = Arc::new(Services::default());
        let clock = LiveClock(Arc::new(AtomicU64::new(100)));
        let mut trusted = key();
        trusted.retirement = retirement;
        let running = start(services.clone(), clock.clone(), false, vec![trusted]).await?;
        let url = format!("http://{}/terrane.v1.ContentService/Has", running.address);
        let token = credential();
        let mut accepted_calls = 0;

        for time in [100, 149, 150, 151, 49, 200, 201, 100] {
            clock.0.store(time, Ordering::SeqCst);
            let accepted =
                (50..=200).contains(&time) && retirement.is_none_or(|retirement| time < retirement);
            let response = client()
                .post(&url)
                .header("authorization", bearer(&token))
                .json(&request())
                .send()
                .await?;
            assert_eq!(
                response.status().is_success(),
                accepted,
                "time {time}, retirement {retirement:?}"
            );
            if accepted {
                accepted_calls += 1;
            } else {
                assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            }
        }

        assert_eq!(services.calls.load(Ordering::SeqCst), accepted_calls);
        assert_eq!(
            *services.tokens.lock().unwrap(),
            vec![token; accepted_calls]
        );
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn authenticates_server_and_client_streams_without_dispatching_invalid_calls() -> TestResult {
    let services = Arc::new(Services::default());
    let running = start(
        services.clone(),
        LiveClock(Arc::new(AtomicU64::new(100))),
        false,
        vec![key()],
    )
    .await?;

    for method in ["GetRange", "PutPack"] {
        let response = client()
            .post(format!(
                "http://{}/terrane.v1.ContentService/{method}",
                running.address
            ))
            .header("content-type", "application/connect+proto")
            .header("connect-protocol-version", "1")
            .body(frame(&[]))
            .send()
            .await?;
        let bytes = response.bytes().await?;
        assert!(
            bytes
                .windows(b"unauthenticated".len())
                .any(|window| window == b"unauthenticated"),
            "{method}: {bytes:?}"
        );
    }

    assert_eq!(services.calls.load(Ordering::SeqCst), 0);
    assert!(!services.dropped_stream.load(Ordering::SeqCst));

    for method in ["GetRange", "PutPack"] {
        let response = client()
            .post(format!(
                "http://{}/terrane.v1.ContentService/{method}",
                running.address
            ))
            .header("authorization", bearer(&credential()))
            .header("content-type", "application/connect+proto")
            .header("connect-protocol-version", "1")
            .body(frame(&[]))
            .send()
            .await?;
        let bytes = response.bytes().await?;
        assert!(
            !bytes
                .windows(b"unauthenticated".len())
                .any(|window| window == b"unauthenticated"),
            "{method}: {bytes:?}"
        );
        if method == "GetRange" {
            assert!(
                bytes
                    .windows(b"first frame".len())
                    .any(|window| window == b"first frame")
            );
        }
    }

    assert_eq!(services.calls.load(Ordering::SeqCst), 2);
    assert!(services.dropped_stream.load(Ordering::SeqCst));
    running.stop().await
}

#[tokio::test]
async fn anonymous_capabilities_is_explicit_and_never_hides_invalid_credentials() -> TestResult {
    for anonymous in [false, true] {
        let services = Arc::new(Services::default());
        let running = start(
            services,
            LiveClock(Arc::new(AtomicU64::new(100))),
            anonymous,
            vec![key()],
        )
        .await?;
        for (method, header, expected) in [
            (
                "Capabilities",
                None,
                if anonymous {
                    reqwest::StatusCode::NOT_IMPLEMENTED
                } else {
                    reqwest::StatusCode::UNAUTHORIZED
                },
            ),
            (
                "Capabilities",
                Some("Bearer invalid"),
                reqwest::StatusCode::UNAUTHORIZED,
            ),
            ("Residency", None, reqwest::StatusCode::UNAUTHORIZED),
        ] {
            let mut request = client()
                .post(format!(
                    "http://{}/terrane.v1.TierService/{method}",
                    running.address
                ))
                .json(&serde_json::json!({}));
            if let Some(header) = header {
                request = request.header("authorization", header);
            }
            assert_eq!(request.send().await?.status(), expected);
        }
        running.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn preserves_attenuation_and_refuses_a_token_from_an_unconfigured_issuer() -> TestResult {
    let token = Token::decode(&credential())
        .unwrap()
        .attenuate(
            auth::Attenuation {
                not_after: Some(120),
                ..Default::default()
            },
            &[12; 32],
            auth::public_key_from_secret(&[13; 32]),
        )
        .unwrap()
        .encode();

    for trusted in [true, false] {
        let services = Arc::new(Services::default());
        let clock = LiveClock(Arc::new(AtomicU64::new(100)));
        let running = start(
            services.clone(),
            clock.clone(),
            false,
            if trusted { vec![key()] } else { vec![] },
        )
        .await?;
        let url = format!("http://{}/terrane.v1.ContentService/Has", running.address);
        for time in [100, 121] {
            clock.0.store(time, Ordering::SeqCst);
            let response = client()
                .post(&url)
                .header("authorization", bearer(&token))
                .json(&request())
                .send()
                .await?;
            assert_eq!(response.status().is_success(), trusted && time == 100);
            if !trusted || time == 121 {
                assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            }
        }
        assert_eq!(
            *services.tokens.lock().unwrap(),
            if trusted { vec![token.clone()] } else { vec![] }
        );
        running.stop().await?;
    }
    Ok(())
}
