//! Verifies recorded GCE-shaped identities with real RSA signatures and job policy.
//!
//! The checked-in RSA key is public test material, never production authority.

#![cfg(all(feature = "tokio", unix))]
#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

use std::{
    collections::VecDeque,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use terrane_format::auth::{
    self, Grant, IssuerKey, Locality, PrincipalKind, Request, Token, Verb, Verbs,
};
use terrane_sdk::{
    store::{
        Clock, HttpClient, HttpError, HttpRequest, HttpResponse, TokioLocalFs,
        http_stream::{
            HttpBodyStream, HttpStreamError, HttpStreamLimits, StreamingHttpClient,
            StreamingHttpRequest, StreamingHttpResponse,
        },
    },
    workload::{
        IssuerPolicy, StaticKeyIssuer, WorkloadClaims,
        gcp::{GOOGLE_JWKS_URL, GcpInstanceIssuer, InstanceAssignment, InstanceError},
    },
};

const RSA_PEM: &str = include_str!("workload_fixtures/instance-test-key.pem");
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "terrane-gcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("issuer.seed");
        fs::write(&path, [23; 32]).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        Self(directory)
    }

    fn static_issuer(&self) -> StaticKeyIssuer {
        let path = self.0.join("issuer.seed");
        StaticKeyIssuer::open(
            &path,
            fs::metadata(&path).unwrap().uid(),
            IssuerPolicy::new(public_key(), 60, 5).unwrap(),
        )
        .unwrap()
    }

    fn issuer(&self, timeout: Duration) -> GcpInstanceIssuer {
        GcpInstanceIssuer::new(
            self.static_issuer(),
            "https://warehouse.test/identity".into(),
            vec![assignment()],
            timeout,
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn public_key() -> IssuerKey {
    IssuerKey {
        issuer: "warehouse".into(),
        key_id: "primary".into(),
        public_key: auth::public_key_from_secret(&[23; 32]),
        retirement: None,
    }
}

fn assignment() -> InstanceAssignment {
    InstanceAssignment {
        project_id: "project-a".into(),
        project_number: 42,
        zone: "region-a1".into(),
        instance_id: "789".into(),
        creation_timestamp: 70,
        service_account_subject: "123456".into(),
        job: WorkloadClaims {
            subject: "ci-job".into(),
            workload: "job-123".into(),
            groups: vec!["builders".into()],
            grants: vec![Grant::new("refs/heads/jobs/123".into(), Verbs::new(7).unwrap()).unwrap()],
            expected_end: 120,
            not_after: None,
        },
    }
}

fn payload() -> Value {
    json!({"iss":"https://accounts.google.com", "aud":"https://warehouse.test/identity",
        "sub":"123456", "azp":"123456", "iat":90, "exp":119,
        "groups":["admins"], "grants":["admin"],
        "google":{"compute_engine":{"project_id":"project-a", "project_number":42,
            "zone":"region-a1", "instance_id":"789", "instance_name":"reusable-name",
            "instance_creation_timestamp":70}}})
}

fn signed(payload: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(
        &header,
        payload,
        &EncodingKey::from_rsa_pem(RSA_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn jwks() -> Value {
    serde_json::from_str(include_str!("workload_fixtures/instance-jwks.json")).unwrap()
}

struct Times {
    seconds: Vec<u64>,
    reads: AtomicUsize,
}

impl Times {
    fn new(seconds: &[u64]) -> Self {
        Self {
            seconds: seconds.to_vec(),
            reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl Clock for Times {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(
                self.seconds[self
                    .reads
                    .fetch_add(1, Ordering::SeqCst)
                    .min(self.seconds.len() - 1)],
            )
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
}

struct Body {
    chunks: VecDeque<Vec<u8>>,
    pending: bool,
    failed: bool,
    dropped: Arc<AtomicBool>,
}

impl Drop for Body {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl HttpBodyStream for Body {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        if let Some(chunk) = self.chunks.pop_front() {
            return Ok(Some(chunk));
        }
        if self.failed {
            return Err(HttpStreamError::Terminated);
        }
        if self.pending {
            std::future::pending::<()>().await;
        }
        Ok(None)
    }
}

struct Http {
    bytes: Vec<u8>,
    status: u16,
    pending: bool,
    failed: bool,
    calls: AtomicUsize,
    dropped: Arc<AtomicBool>,
}

impl Http {
    fn new(keys: Value) -> Self {
        Self {
            bytes: serde_json::to_vec(&keys).unwrap(),
            status: 200,
            pending: false,
            failed: false,
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for Http {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, HttpError> {
        panic!("identity exchange must use the bounded streaming interface")
    }
}

#[async_trait::async_trait]
impl StreamingHttpClient for Http {
    async fn send_stream(
        &self,
        mut request: StreamingHttpRequest,
        _: HttpStreamLimits,
        response_limits: HttpStreamLimits,
    ) -> Result<StreamingHttpResponse, HttpStreamError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, GOOGLE_JWKS_URL);
        assert_eq!(
            request.headers,
            [("accept".into(), b"application/json".to_vec())]
        );
        assert!(request.body.next().await.unwrap().is_none());
        assert_eq!(response_limits.body_bytes(), 65536);
        Ok(StreamingHttpResponse {
            status: self.status,
            headers: vec![],
            body: Box::new(Body {
                chunks: self.bytes.chunks(512).map(|chunk| chunk.to_vec()).collect(),
                pending: self.pending,
                failed: self.failed,
                dropped: self.dropped.clone(),
            }),
        })
    }
}

#[tokio::test]
async fn signed_full_identity_mints_only_the_assigned_instance_and_job() {
    let fixture = Fixture::new();
    let http = Http::new(jwks());
    let credential = fixture
        .issuer(Duration::from_secs(2))
        .exchange(
            &TokioLocalFs,
            &Times::new(&[100]),
            &http,
            &signed(&payload(), "google-fixture"),
            "job-123",
        )
        .await
        .unwrap();
    let token = Token::decode(credential.token()).unwrap();
    let verified = token.verify(&[public_key()], 100).unwrap();
    let authority = verified.authority();
    assert_eq!(authority.kind, PrincipalKind::Workload);
    assert_eq!(authority.subject, "ci-job");
    assert_eq!(authority.groups, ["builders"]);
    assert_eq!(authority.grants, assignment().job.grants);
    assert_eq!(authority.not_after, 118);
    assert_eq!(
        serde_json::from_str::<Value>(authority.workload.as_ref().unwrap()).unwrap(),
        json!(["gce", "project-a", 42, "region-a1", "789", 70, "job-123"])
    );
    assert_eq!(
        token.signing_public_key(),
        auth::public_key_from_secret(credential.signing_secret())
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn signed_ci_identity_cannot_mint_baseline_or_other_change_writes() {
    let fixture = Fixture::new();
    let mut assigned = assignment();
    assigned.job = WorkloadClaims::ci_change(
        "ci-job".into(),
        "job-123".into(),
        std::num::NonZeroU64::new(123).unwrap(),
        120,
    )
    .unwrap();
    let issuer = GcpInstanceIssuer::new(
        fixture.static_issuer(),
        "https://warehouse.test/identity".into(),
        vec![assigned],
        Duration::from_secs(2),
    )
    .unwrap();
    let credential = issuer
        .exchange(
            &TokioLocalFs,
            &Times::new(&[100]),
            &Http::new(jwks()),
            &signed(&payload(), "google-fixture"),
            "job-123",
        )
        .await
        .unwrap();
    let token = Token::decode(credential.token()).unwrap();
    let verified = token.verify(&[public_key()], 100).unwrap();
    let authority = verified.authority();

    assert!(authority.groups.is_empty());
    assert_eq!(authority.grants.len(), 2);
    assert_eq!(authority.grants[0].pattern(), "refs/heads/ci/master");
    assert_eq!(authority.grants[0].verbs().bits(), 2);
    assert_eq!(authority.grants[1].pattern(), "refs/heads/ci/pr/123");
    assert_eq!(authority.grants[1].verbs().bits(), 4);
    assert_eq!(authority.not_after, 118);

    for (reference, verb, permitted) in [
        ("refs/heads/ci/master", Verb::Fork, true),
        ("refs/heads/ci/master", Verb::Commit, false),
        ("refs/heads/ci/pr/123", Verb::Commit, true),
        ("refs/heads/ci/pr/123", Verb::Read, true),
        ("refs/heads/ci/pr/124", Verb::Commit, false),
        ("refs/heads/ci/pr/124", Verb::Read, false),
        ("refs/heads/ci/pr/123", Verb::Admin, false),
    ] {
        assert_eq!(
            verified
                .authorize(&Request {
                    reference: reference.as_bytes(),
                    verb,
                    roots: &[],
                    now: 100,
                    surface: "sdk",
                    locality: &Locality::default(),
                    epochs: &[],
                })
                .is_ok(),
            permitted,
            "{verb:?} on {reference}"
        );
    }
}

#[tokio::test]
async fn changed_signatures_unknown_keys_and_unsupported_headers_are_denied() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(Duration::from_secs(2));
    let valid = signed(&payload(), "google-fixture");
    let mut segments: Vec<_> = valid.split('.').map(str::to_owned).collect();
    let mut altered = payload();
    altered["iat"] = json!(91);
    segments[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered).unwrap());
    let http = Http::new(jwks());
    assert!(matches!(
        issuer
            .exchange(
                &TokioLocalFs,
                &Times::new(&[100]),
                &http,
                &segments.join("."),
                "job-123"
            )
            .await,
        Err(InstanceError::Unauthorized)
    ));
    assert!(matches!(
        issuer
            .exchange(
                &TokioLocalFs,
                &Times::new(&[100]),
                &http,
                &signed(&payload(), "unknown"),
                "job-123"
            )
            .await,
        Err(InstanceError::Unauthorized)
    ));
    for header in [
        json!({"alg":"HS256","kid":"google-fixture"}),
        json!({"alg":"RS256","kid":"google-fixture","jku":"https://attacker.test/keys"}),
        json!({"alg":"RS256","kid":"google-fixture","crit":["extension"]}),
        json!({"alg":"RS256","kid":"google-fixture","typ":"other"}),
    ] {
        let http = Http::new(jwks());
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            segments[1],
            segments[2]
        );
        assert!(matches!(
            issuer
                .exchange(&TokioLocalFs, &Times::new(&[100]), &http, &token, "job-123")
                .await,
            Err(InstanceError::Unauthorized)
        ));
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn signed_claims_cannot_select_another_project_instance_account_or_job() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(Duration::from_secs(2));
    for (pointer, value) in [
        ("/iss", json!("https://other.test")),
        ("/aud", json!("other")),
        ("/sub", json!("999")),
        ("/azp", json!("999")),
        ("/google/compute_engine/project_id", json!("other")),
        ("/google/compute_engine/project_number", json!(43)),
        ("/google/compute_engine/zone", json!("other")),
        ("/google/compute_engine/instance_id", json!("790")),
        (
            "/google/compute_engine/instance_creation_timestamp",
            json!(71),
        ),
        ("/google", Value::Null),
    ] {
        let mut claims = payload();
        *claims.pointer_mut(pointer).unwrap() = value;
        assert!(matches!(
            issuer
                .exchange(
                    &TokioLocalFs,
                    &Times::new(&[100]),
                    &Http::new(jwks()),
                    &signed(&claims, "google-fixture"),
                    "job-123"
                )
                .await,
            Err(InstanceError::Unauthorized)
        ));
    }
    let http = Http::new(jwks());
    assert!(matches!(
        issuer
            .exchange(
                &TokioLocalFs,
                &Times::new(&[100]),
                &http,
                &signed(&payload(), "google-fixture"),
                "unassigned-job"
            )
            .await,
        Err(InstanceError::Unauthorized)
    ));
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signed_identity_times_are_checked_with_the_injected_clock() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(Duration::from_secs(2));
    for (field, value) in [
        ("iat", json!(101)),
        ("exp", json!(100)),
        ("exp", json!(99)),
        ("exp", json!(3691)),
        ("nbf", json!(101)),
    ] {
        let mut claims = payload();
        claims[field] = value;
        assert!(matches!(
            issuer
                .exchange(
                    &TokioLocalFs,
                    &Times::new(&[100]),
                    &Http::new(jwks()),
                    &signed(&claims, "google-fixture"),
                    "job-123"
                )
                .await,
            Err(InstanceError::Unauthorized)
        ));
    }
    for times in [&[100, 99][..], &[100, 119], &[100, 100, 99, 99, 99]] {
        assert!(matches!(
            issuer
                .exchange(
                    &TokioLocalFs,
                    &Times::new(times),
                    &Http::new(jwks()),
                    &signed(&payload(), "google-fixture"),
                    "job-123"
                )
                .await,
            Err(InstanceError::Unauthorized)
        ));
    }
}

#[tokio::test]
async fn unavailable_ambiguous_and_excessive_key_responses_never_mint() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(Duration::from_secs(2));
    let mut duplicate = jwks();
    let key = duplicate["keys"][0].clone();
    duplicate["keys"].as_array_mut().unwrap().push(key);
    let mut wrong_algorithm = jwks();
    wrong_algorithm["keys"][0]["alg"] = json!("HS256");
    let mut wrong_use = jwks();
    wrong_use["keys"][0]["use"] = json!("enc");
    for keys in [
        json!({"keys":[]}),
        duplicate,
        wrong_algorithm,
        wrong_use,
        json!({"keys":[{}]}),
    ] {
        assert!(matches!(
            issuer
                .exchange(
                    &TokioLocalFs,
                    &Times::new(&[100]),
                    &Http::new(keys),
                    &signed(&payload(), "google-fixture"),
                    "job-123"
                )
                .await,
            Err(InstanceError::Unavailable)
        ));
    }
    for mode in 0..3 {
        let mut http = Http::new(jwks());
        match mode {
            0 => http.status = 503,
            1 => http.failed = true,
            _ => http.bytes = vec![b' '; 65537],
        }
        assert!(matches!(
            issuer
                .exchange(
                    &TokioLocalFs,
                    &Times::new(&[100]),
                    &http,
                    &signed(&payload(), "google-fixture"),
                    "job-123"
                )
                .await,
            Err(InstanceError::Unavailable)
        ));
    }
}

#[tokio::test]
async fn complete_exchange_deadline_drops_a_pending_key_stream() {
    let fixture = Fixture::new();
    let issuer = fixture.issuer(Duration::from_millis(50));
    let mut http = Http::new(jwks());
    http.pending = true;
    let outcome = issuer
        .exchange(
            &TokioLocalFs,
            &Times::new(&[100]),
            &http,
            &signed(&payload(), "google-fixture"),
            "job-123",
        )
        .await;
    assert!(matches!(outcome, Err(InstanceError::Deadline)));
    assert!(http.dropped.load(Ordering::SeqCst));
}

#[test]
fn duplicate_assignments_and_invalid_trusted_configuration_are_rejected() {
    let fixture = Fixture::new();
    for (audience, assignments, deadline) in [
        ("", vec![assignment()], Duration::from_secs(1)),
        ("a", vec![], Duration::from_secs(1)),
        (
            "a",
            vec![assignment(), assignment()],
            Duration::from_secs(1),
        ),
        ("a", vec![assignment()], Duration::ZERO),
        ("a", vec![assignment()], Duration::from_secs(31)),
    ] {
        assert!(matches!(
            GcpInstanceIssuer::new(
                fixture.static_issuer(),
                audience.into(),
                assignments,
                deadline
            ),
            Err(InstanceError::Configuration)
        ));
    }
    for mutation in 0..4 {
        let mut entry = assignment();
        match mutation {
            0 => entry.instance_id = "name".into(),
            1 => entry.service_account_subject.clear(),
            2 => entry.job.workload.clear(),
            _ => entry.job.grants.clear(),
        }
        assert!(matches!(
            GcpInstanceIssuer::new(
                fixture.static_issuer(),
                "a".into(),
                vec![entry],
                Duration::from_secs(1)
            ),
            Err(InstanceError::Configuration)
        ));
    }
}
