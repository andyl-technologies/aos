//! Actual loopback HTTP and retained SQLite control/issuance regressions.
//!
//! Fixed clocks and qualification digests are test fixtures; NativeClock cases
//! sample actual UTC. These tests prove real local HTTP/persistence paths, not
//! hosted TLS, physical-volume novelty, qualified clock uncertainty, capacity
//! or provider dispatch.

use std::sync::atomic::{AtomicI64, Ordering};

use crate::authority_journal::tests::{
    clock, cohort, integer, next_publication, profile, publication, Fixture,
};
use aos_hub_core::storage_authority::{
    control::StorageAuthorityDeniedTransition,
    lease::{
        control::{sign_issuer_request, verify_issuer_reply},
        LeaseClock,
    },
    StorageAuthorityAdmissionState, StorageAuthorityRemoteWatermark,
};

use super::*;

mod clock_recovery;
mod native_clock;

struct FixedClock(AtomicI64);

impl ClockSource for FixedClock {
    fn observe(&self) -> Result<LeaseClock> {
        Ok(clock(self.0.load(Ordering::SeqCst)))
    }
}

struct HttpFixture {
    file: Fixture,
    server: AuthorityServer,
    clock: Arc<FixedClock>,
    address: String,
    task: tokio::task::JoinHandle<()>,
}

impl HttpFixture {
    async fn new() -> Self {
        let file = Fixture::new();
        let journal = file.initialize();
        Self::from_file(file, journal, 100).await
    }

    async fn from_file(file: Fixture, journal: AuthorityJournal, now: i64) -> Self {
        let clock = Arc::new(FixedClock(AtomicI64::new(now)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = test_server(
            &file,
            journal,
            clock.clone(),
            listener.local_addr().unwrap(),
        );
        let router = server.router();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            file,
            server,
            clock,
            address,
            task,
        }
    }

    async fn restart(&mut self) {
        self.task.abort();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.address = format!("http://{}", listener.local_addr().unwrap());
        self.server = test_server(
            &self.file,
            self.file.reopen().unwrap(),
            self.clock.clone(),
            listener.local_addr().unwrap(),
        );
        let router = self.server.router();
        self.task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
    }

    fn request(&self, operation: IssuerOperation, nonce: char) -> IssuerRequest {
        IssuerRequest {
            protocol_version: 1,
            installation: self.file.marker.clone(),
            nonce: nonce.to_string().repeat(64),
            issued_at: integer(100),
            expires_at: integer(130),
            operation,
        }
    }

    async fn send(&self, request: &IssuerRequest, role: &str) -> reqwest::Response {
        let bytes = serde_json::to_vec(request).unwrap();
        self.send_bytes(bytes, role).await
    }

    async fn send_bytes(&self, bytes: Vec<u8>, role: &str) -> reqwest::Response {
        let key = if role == "publisher" {
            &self.server.inner.publisher_key
        } else {
            &self.server.inner.renewal_key
        };
        let signature = sign_issuer_request(key, &bytes).unwrap();
        reqwest::Client::new()
            .post(format!("{}{}", self.address, ISSUER_CONTROL_PATH))
            .header(ISSUER_SIGNATURE_HEADER, signature)
            .body(bytes)
            .send()
            .await
            .unwrap()
    }

    async fn verified(&self, request: &IssuerRequest, role: &str) -> IssuerReply {
        let response = self.send(request, role).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let bytes = response.bytes().await.unwrap();
        verify_issuer_reply(&self.server.inner.verifier, request, &bytes).unwrap()
    }
}

fn test_server(
    file: &Fixture,
    journal: AuthorityJournal,
    clock: Arc<dyn ClockSource>,
    listen: std::net::SocketAddr,
) -> AuthorityServer {
    let signing_key_id = "fixture-authority-signing-v1".to_owned();
    let seed = [13; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    AuthorityServer {
        inner: Arc::new(Inner {
            journal,
            installation: file.marker.clone(),
            publisher_key: StorageWorkKey::new([11; 32]).unwrap(),
            renewal_key: StorageWorkKey::new([12; 32]).unwrap(),
            signer: EpochLeaseSigningKey::from_bytes(signing_key_id.clone(), &seed).unwrap(),
            verifier: EpochLeaseVerifier::from_bytes(signing_key_id.clone(), &public).unwrap(),
            signing_key_id,
            issuance_enabled: true,
            clock,
            gate: Mutex::new(()),
            listen,
            tls: None,
        }),
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn current_and_issue_use_actual_http_compact_signed_head_and_durable_sequence() {
    let fixture = HttpFixture::new().await;
    for role in ["publisher", "renewal"] {
        let request = fixture.request(IssuerOperation::Current, '1');
        let reply = fixture.verified(&request, role).await;
        assert!(reply.lease.is_none());
        assert!(reply.applied.is_none());
        let encoded = serde_json::to_string(&reply.current).unwrap();
        assert!(!encoded.contains("secret_version_ref"));
        assert!(!encoded.contains("publication\""));
    }

    let request = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
        '2',
    );
    let first = fixture.verified(&request, "renewal").await;
    let second = fixture.verified(&request, "renewal").await;
    assert!(first.lease.is_some() && second.lease.is_some());
    assert_eq!(first.current.journal.last_sequence.get(), 1);
    assert_eq!(second.current.journal.last_sequence.get(), 2);
    let retained = fixture.file.reopen().unwrap().load().unwrap();
    assert_eq!(retained.journal.last_sequence.get(), 2);
    assert_eq!(retained.journal.largest_issued_expiry.get(), 120);
}

#[tokio::test]
async fn roles_and_bad_auth_are_rejected_before_any_journal_effect() {
    let fixture = HttpFixture::new().await;
    let before = fixture.file.reopen().unwrap().load().unwrap();
    let issue = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
        '3',
    );
    assert_eq!(
        fixture.send(&issue, "publisher").await.status(),
        StatusCode::FORBIDDEN
    );
    let publish = fixture.request(
        IssuerOperation::Publish(next_publication(
            &publication(),
            StorageAuthorityAdmissionState::Blocked,
        )),
        '4',
    );
    assert_eq!(
        fixture.send(&publish, "renewal").await.status(),
        StatusCode::FORBIDDEN
    );
    let bytes = serde_json::to_vec(&issue).unwrap();
    let response = reqwest::Client::new()
        .post(format!("{}{}", fixture.address, ISSUER_CONTROL_PATH))
        .header(ISSUER_SIGNATURE_HEADER, "f".repeat(64))
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(fixture.file.reopen().unwrap().load().unwrap(), before);
}

#[tokio::test]
async fn original_publish_intent_and_install_kind_survive_restart_and_fresh_nonce_replay() {
    let mut fixture = HttpFixture::new().await;
    let initial = fixture.request(IssuerOperation::Install(publication()), '5');
    let installed = fixture.verified(&initial, "publisher").await;
    assert_eq!(installed.applied.unwrap().generation.get(), 1);
    let changed_kind = fixture.request(IssuerOperation::Publish(publication()), '6');
    assert_eq!(
        fixture.send(&changed_kind, "publisher").await.status(),
        StatusCode::CONFLICT
    );

    let denied = next_publication(&publication(), StorageAuthorityAdmissionState::Blocked);
    let request = fixture.request(IssuerOperation::Publish(denied.clone()), '7');
    let applied = fixture
        .verified(&request, "publisher")
        .await
        .applied
        .unwrap();
    // Discarding the response does not undo its transaction. Open independent
    // actual connections to simulate process state loss; no cache is retained.
    let reopened = fixture.file.reopen().unwrap();
    assert_eq!(
        reopened
            .receipt_for_operation(request.operation.clone())
            .unwrap(),
        Some(applied.clone())
    );
    fixture.restart().await;
    let mut replay = request;
    replay.nonce = "8".repeat(64);
    assert_eq!(
        fixture.verified(&replay, "publisher").await.applied,
        Some(applied)
    );
    let changed_kind = fixture.request(
        IssuerOperation::Deny(StorageAuthorityDeniedTransition {
            publication: denied,
            expected_remote: None,
        }),
        '9',
    );
    assert_eq!(
        fixture.send(&changed_kind, "publisher").await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn denial_gap_retains_original_remote_cas_and_prevents_any_further_issue() {
    let fixture = HttpFixture::new().await;
    let issue = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
        'a',
    );
    fixture.verified(&issue, "renewal").await;
    let mut denied = next_publication(&publication(), StorageAuthorityAdmissionState::Blocked);
    denied.generation = 5;
    denied.admission.expected_generation = 4;
    denied.admission.expected_digest = Some("9".repeat(64));
    use sha2::Digest as _;
    denied.digest = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&denied.admission).unwrap(),
    ));
    let denial = StorageAuthorityDeniedTransition {
        publication: denied,
        expected_remote: Some(StorageAuthorityRemoteWatermark {
            authority_id: fixture.file.marker.authority.authority_id.clone(),
            guard_namespace_id: fixture.file.marker.authority.guard_namespace_id.clone(),
            generation: 1,
            digest: publication().digest,
        }),
    };
    let request = fixture.request(IssuerOperation::Deny(denial.clone()), 'b');
    let receipt = fixture
        .verified(&request, "publisher")
        .await
        .applied
        .unwrap();
    assert_eq!(receipt.generation.get(), 5);
    assert_eq!(
        fixture
            .file
            .reopen()
            .unwrap()
            .load()
            .unwrap()
            .journal
            .largest_issued_expiry
            .get(),
        120
    );
    let mut exact_replay = request;
    exact_replay.nonce = "c".repeat(64);
    assert_eq!(
        fixture.verified(&exact_replay, "publisher").await.applied,
        Some(receipt)
    );
    let mut changed = denial;
    changed.expected_remote = None;
    let changed = fixture.request(IssuerOperation::Deny(changed), 'd');
    assert_eq!(
        fixture.send(&changed, "publisher").await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture.send(&issue, "renewal").await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn authenticated_malformed_unknown_duplicate_and_oversized_http_bodies_fail_without_writes() {
    let fixture = HttpFixture::new().await;
    let before = fixture.file.reopen().unwrap().load().unwrap();
    for body in [
        b"{bad".to_vec(),
        b"{\"protocol_version\":1,\"protocol_version\":1}".to_vec(),
        b"{\"unknown\":1}".to_vec(),
    ] {
        assert_eq!(
            fixture.send_bytes(body, "publisher").await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let response = reqwest::Client::new()
        .post(format!("{}{}", fixture.address, ISSUER_CONTROL_PATH))
        .header(ISSUER_SIGNATURE_HEADER, "0".repeat(64))
        .body(vec![b'x'; MAX_ISSUER_CONTROL_BYTES + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(fixture.file.reopen().unwrap().load().unwrap(), before);
}

#[tokio::test]
async fn expired_request_and_changed_installation_cannot_mutate_retained_state() {
    let fixture = HttpFixture::new().await;
    let before = fixture.file.reopen().unwrap().load().unwrap();
    let mut expired = fixture.request(IssuerOperation::Current, 'e');
    expired.expires_at = integer(100);
    assert_eq!(
        fixture.send(&expired, "publisher").await.status(),
        StatusCode::CONFLICT
    );
    let mut changed = fixture.request(IssuerOperation::Current, 'f');
    changed.installation.runtime_identity = "other-runtime".into();
    assert_eq!(
        fixture.send(&changed, "publisher").await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.file.reopen().unwrap().load().unwrap(), before);
}

#[tokio::test]
async fn lost_http_reply_retains_sequence_and_expiry_after_actual_server_restart() {
    use tokio::io::AsyncWriteExt as _;

    let mut fixture = HttpFixture::new().await;
    let request = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
        '1',
    );
    let bytes = serde_json::to_vec(&request).unwrap();
    let signature = sign_issuer_request(&fixture.server.inner.renewal_key, &bytes).unwrap();
    let host = fixture.address.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
    let header = format!("POST {ISSUER_CONTROL_PATH} HTTP/1.1\r\nHost: {host}\r\n{ISSUER_SIGNATURE_HEADER}: {signature}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    // Observe actual committed state without ever reading the HTTP response.
    // The caller receives no token acknowledgment, yet issuance history remains.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let journal = fixture.server.inner.journal.clone();
            let retained = tokio::task::spawn_blocking(move || journal.load())
                .await
                .unwrap()
                .unwrap();
            if retained.journal.last_sequence.get() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(stream);
    fixture.restart().await;
    let retained = fixture.file.reopen().unwrap().load().unwrap();
    assert_eq!(retained.journal.last_sequence.get(), 1);
    assert_eq!(retained.journal.largest_issued_expiry.get(), 120);
    assert_eq!(
        fixture
            .verified(&request, "renewal")
            .await
            .current
            .journal
            .last_sequence
            .get(),
        2
    );
}

#[tokio::test]
async fn cancellation_while_waiting_for_live_gate_creates_no_lease_and_rechecks_deadline() {
    let fixture = HttpFixture::new().await;
    let guard = fixture.server.inner.gate.lock().await;
    let request = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
        '2',
    );
    let server = fixture.server.clone();
    let pending = tokio::spawn(async move { server.execute(&request).await });
    tokio::task::yield_now().await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    drop(guard);
    assert_eq!(
        fixture
            .file
            .reopen()
            .unwrap()
            .load()
            .unwrap()
            .journal
            .last_sequence
            .get(),
        0
    );

    // The gate may have delayed a valid request past its bounded window.
    fixture.clock.0.store(130, Ordering::SeqCst);
    let request = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(150),
        },
        '3',
    );
    assert_eq!(
        fixture.send(&request, "renewal").await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .file
            .reopen()
            .unwrap()
            .load()
            .unwrap()
            .journal
            .last_sequence
            .get(),
        0
    );
}

#[tokio::test]
async fn default_disabled_issuance_and_serving_missing_or_changed_files_fail_closed() {
    let fixture = Fixture::new();
    let secrets = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(secrets.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = secrets.path().join("publisher");
    let renewal = secrets.path().join("renewal");
    let seed = secrets.path().join("signer");
    for (path, bytes) in [
        (&publisher, [11; 32]),
        (&renewal, [12; 32]),
        (&seed, [13; 32]),
    ] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let configuration = AuthorityConfiguration {
        format_version: 1,
        listen: "127.0.0.1:0".parse().unwrap(),
        journal_file: fixture.path.clone(),
        installation: fixture.marker.clone(),
        hub_root: fixture.boundary.hub_root.clone(),
        hub_sqlite_file: None,
        policy: aos_hub_core::storage_authority::lease::BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        clock_uncertainty: integer(0),
        clock_commit_latency: integer(1),
        clock_recovery: None,
        issuance_enabled: false,
        publisher_key_file: publisher,
        renewal_key_file: renewal,
        signing_seed_file: seed,
        signing_key_id: "fixture-authority-signing-v1".into(),
        tls: None,
    };
    assert!(AuthorityServer::open(&configuration).is_err());
    assert!(!fixture.path.exists());
    fixture.initialize();
    let server = AuthorityServer::open(&configuration).unwrap();
    assert!(!server.inner.issuance_enabled);
    let mut json = serde_json::to_value(&configuration).unwrap();
    json.as_object_mut().unwrap().remove("issuance_enabled");
    let without_opt_in: AuthorityConfiguration = serde_json::from_value(json).unwrap();
    assert!(!without_opt_in.issuance_enabled);
    let mut changed = configuration.clone();
    changed.installation.issuer_resource_id = "changed-resource".into();
    assert!(AuthorityServer::open(&changed).is_err());
    std::fs::remove_file(&fixture.path).unwrap();
    assert!(AuthorityServer::open(&configuration).is_err());
    assert!(!fixture.path.exists());
}

#[test]
fn native_clock_retains_unresolved_session_and_refuses_automatic_restart() {
    let fixture = Fixture::new();
    let journal = fixture.initialize();
    let clock = NativeClock::new(journal.clone(), 0, 1, 100).unwrap();
    let first = clock.observe().unwrap();
    let second = clock.observe().unwrap();
    assert!(second.observed_at >= first.observed_at);
    assert_eq!(second.uncertainty, 2);
    // A successful observation does not clear the permanent session marker.
    drop(clock);
    assert!(NativeClock::new(fixture.reopen().unwrap(), 0, 1, 100).is_err());
    assert!(journal.load().is_ok());
}

#[test]
fn failed_native_observation_leaves_session_unresolved_before_restart() {
    let fixture = Fixture::new();
    let journal = fixture.initialize();
    let clock = NativeClock::new(journal.clone(), 0, 1, i64::MAX).unwrap();
    assert!(clock.observe().is_err());
    drop(clock);
    assert!(NativeClock::new(fixture.reopen().unwrap(), 0, 1, 100).is_err());
    assert!(journal.load().is_ok());
}

#[tokio::test]
async fn concurrent_http_renewals_have_unique_actual_commits_and_each_reply_matches_its_token() {
    let fixture = HttpFixture::new().await;
    let mut tasks = Vec::new();
    for digit in ['1', '2', '3', '4', '5', '6', '7', '8'] {
        let request = fixture.request(
            IssuerOperation::Issue {
                cohort: cohort(&publication()),
                requested_not_after: integer(120),
            },
            digit,
        );
        let address = fixture.address.clone();
        let bytes = serde_json::to_vec(&request).unwrap();
        let signature = sign_issuer_request(&fixture.server.inner.renewal_key, &bytes).unwrap();
        let public = ed25519_dalek::SigningKey::from_bytes(&[13; 32])
            .verifying_key()
            .to_bytes();
        tasks.push(tokio::spawn(async move {
            let response = reqwest::Client::new()
                .post(format!("{address}{ISSUER_CONTROL_PATH}"))
                .header(ISSUER_SIGNATURE_HEADER, signature)
                .body(bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response.bytes().await.unwrap();
            let verifier =
                EpochLeaseVerifier::from_bytes("fixture-authority-signing-v1".into(), &public)
                    .unwrap();
            verify_issuer_reply(&verifier, &request, &bytes)
                .unwrap()
                .current
                .journal
                .last_sequence
                .get()
        }));
    }
    let mut sequences = Vec::new();
    for task in tasks {
        sequences.push(task.await.unwrap());
    }
    sequences.sort_unstable();
    assert_eq!(sequences, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        fixture
            .file
            .reopen()
            .unwrap()
            .load()
            .unwrap()
            .journal
            .last_sequence
            .get(),
        8
    );
}

#[test]
fn different_auth_encodings_cannot_reuse_role_entropy_or_issuer_seed() {
    use base64::Engine as _;
    let seed = std::array::from_fn::<_, 32, _>(|index| (index * 37 + 251) as u8);
    let mut representations = vec![hex::encode(seed), hex::encode_upper(seed)];
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        representations.push(engine.encode(seed));
    }
    for encoded in representations {
        assert!(reuses_seed(encoded.as_bytes(), &seed));
        assert!(same_auth_material(&seed, encoded.as_bytes()));
    }
    assert!(!same_auth_material(&[11; 32], &[12; 32]));
    assert!(!reuses_seed(&[11; 32], &seed));
    assert!(!reuses_seed(&[b'a'; 129], &seed));
}

#[tokio::test]
async fn incomplete_real_http_body_cancellation_never_dispatches_issuance() {
    use tokio::io::AsyncWriteExt as _;

    let fixture = HttpFixture::new().await;
    let before = fixture.file.reopen().unwrap().load().unwrap();
    let request = fixture.request(
        IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
        '3',
    );
    let bytes = serde_json::to_vec(&request).unwrap();
    let signature = sign_issuer_request(&fixture.server.inner.renewal_key, &bytes).unwrap();
    let host = fixture.address.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
    let header = format!("POST {ISSUER_CONTROL_PATH} HTTP/1.1\r\nHost: {host}\r\n{ISSUER_SIGNATURE_HEADER}: {signature}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(&bytes[..bytes.len() / 2]).await.unwrap();
    stream.shutdown().await.unwrap();
    drop(stream);
    // A subsequent valid request proves the listener remains live after the
    // incomplete connection, while the independent real file stays unchanged.
    let current = fixture.request(IssuerOperation::Current, '4');
    fixture.verified(&current, "publisher").await;
    assert_eq!(fixture.file.reopen().unwrap().load().unwrap(), before);
}

#[tokio::test]
async fn final_time_after_reply_signing_refuses_expired_token_and_preserves_committed_history() {
    struct FinalClock(std::sync::atomic::AtomicUsize);
    impl ClockSource for FinalClock {
        fn observe(&self) -> Result<LeaseClock> {
            let invocation = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(clock(if invocation < 3 { 100 } else { 119 }))
        }
    }
    let file = Fixture::new();
    let journal = file.initialize();
    let clock = Arc::new(FinalClock(std::sync::atomic::AtomicUsize::new(0)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let server = test_server(
        &file,
        journal,
        clock.clone(),
        listener.local_addr().unwrap(),
    );
    let router = server.router();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let request = IssuerRequest {
        protocol_version: 1,
        installation: file.marker.clone(),
        nonce: "a".repeat(64),
        issued_at: integer(100),
        expires_at: integer(130),
        operation: IssuerOperation::Issue {
            cohort: cohort(&publication()),
            requested_not_after: integer(120),
        },
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let signature = sign_issuer_request(&server.inner.renewal_key, &bytes).unwrap();
    let response = reqwest::Client::new()
        .post(format!("{address}{ISSUER_CONTROL_PATH}"))
        .header(ISSUER_SIGNATURE_HEADER, signature)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.text().await.unwrap(), "issuer request refused");
    assert_eq!(clock.0.load(Ordering::SeqCst), 4);
    let retained = file.reopen().unwrap().load().unwrap();
    assert_eq!(retained.journal.last_sequence.get(), 1);
    assert_eq!(retained.journal.largest_issued_expiry.get(), 120);
    task.abort();
}
