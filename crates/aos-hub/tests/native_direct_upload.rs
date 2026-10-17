//! Native public upload protocol against a local TLS S3-compatible provider.
//!
//! Provider tests need the debug-only local-remote opt-in. Run them in the
//! source-built development shell with the flag scoped to the test subprocess:
//!
//! ```text
//! env AOS_HUB_ALLOW_LOCAL_REMOTES=1 nix develop -c cargo test \
//!   --manifest-path crates/Cargo.toml -p aos-hub --test native_direct_upload \
//!   -- --include-ignored
//! ```
//!
//! Tests never mutate the process environment or weaken the production URL guard.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{ensure, Result};

use aos_hub_core::{
    auth::jwt::JwtKeys,
    db::Database,
    db::{NewBindingWriteRevision, NewSurfacePlacementSpec, SurfaceTarget},
    direct_upload::*,
    domain::{Permission, Principal},
    secret_version::{ResolvedSecretVersion, SecretVersionResolver},
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, Method, Request, StatusCode},
    response::{IntoResponse as _, Response},
    routing::any,
    Router,
};
use base64::Engine as _;
use md5::Digest as _;
use sha2::{Digest as _, Sha256};

use tokio::sync::Mutex;
use tower::ServiceExt as _;

const SECRET: &str = "fixture-access:fixture-secret:test-region";

struct FixtureSecrets;

#[async_trait::async_trait]
impl SecretVersionResolver for FixtureSecrets {
    async fn resolve(&self, reference: &str) -> Result<ResolvedSecretVersion> {
        ensure!(
            reference.starts_with("secret://native-fixture/"),
            "unknown fixture secret"
        );
        Ok(ResolvedSecretVersion::from_bytes(
            SECRET.as_bytes().to_vec(),
        ))
    }
}

#[derive(Default)]
struct StoreData {
    next_id: usize,
    uploads: BTreeMap<String, (String, BTreeMap<u32, Vec<u8>>)>,
    objects: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct Store {
    data: Mutex<StoreData>,
    active_parts: AtomicUsize,
    peak_parts: AtomicUsize,
    uploaded_bytes: AtomicUsize,
    read_delay_ms: AtomicUsize,
}

fn tag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
}

async fn storage(State(store): State<Arc<Store>>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().trim_start_matches('/').to_owned();
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    assert!(query.contains_key("X-Amz-Signature"));
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), MIN_DIRECT_PART_BYTES as usize + 1024)
        .await
        .unwrap();
    if method == Method::PUT
        && query.contains_key("partNumber")
        && !headers.contains_key("x-amz-copy-source")
    {
        let active = store.active_parts.fetch_add(1, Ordering::SeqCst) + 1;
        store.peak_parts.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        store.active_parts.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(
            headers
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            body.len().to_string()
        );
        assert!(query["X-Amz-SignedHeaders"]
            .split(';')
            .any(|name| name == "content-length"));
        assert!(query["X-Amz-SignedHeaders"]
            .split(';')
            .any(|name| name == "content-md5"));
        let md5 = base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&body));
        assert_eq!(headers.get("content-md5").unwrap().to_str().unwrap(), md5);
        store.uploaded_bytes.fetch_add(body.len(), Ordering::SeqCst);
    }
    if method == Method::GET {
        tokio::time::sleep(std::time::Duration::from_millis(
            store.read_delay_ms.load(Ordering::SeqCst) as u64,
        ))
        .await;
    }
    let mut data = store.data.lock().await;
    if method == Method::POST && query.contains_key("uploads") {
        data.next_id += 1;
        let id = format!("upload-{}", data.next_id);
        data.uploads
            .insert(id.clone(), (path.clone(), BTreeMap::new()));
        let (bucket, key) = path.split_once('/').unwrap();
        return format!("<InitiateMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>").into_response();
    }
    if method == Method::PUT && query.contains_key("partNumber") {
        let number: u32 = query["partNumber"].parse().unwrap();
        let bytes = if let Some(source) = headers.get("x-amz-copy-source") {
            let source = source.to_str().unwrap().trim_start_matches('/');
            let source = url::form_urlencoded::parse(format!("source={source}").as_bytes())
                .next()
                .unwrap()
                .1
                .into_owned();
            let range = headers
                .get("x-amz-copy-source-range")
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("bytes=")
                .unwrap();
            let (first, last) = range.split_once('-').unwrap();
            data.objects[&source][first.parse::<usize>().unwrap()..=last.parse::<usize>().unwrap()]
                .to_vec()
        } else {
            body.to_vec()
        };
        let etag = tag(&bytes);
        let upload = data.uploads.get_mut(&query["uploadId"]).unwrap();
        assert_eq!(upload.0, path);
        upload.1.insert(number, bytes);
        if headers.contains_key("x-amz-copy-source") {
            return format!("<CopyPartResult><ETag>{etag}</ETag></CopyPartResult>").into_response();
        }
        return ([(header::ETAG, etag)], Bytes::new()).into_response();
    }
    if method == Method::POST && query.contains_key("uploadId") {
        let upload = data.uploads.remove(&query["uploadId"]).unwrap();
        assert_eq!(upload.0, path);
        let bytes: Vec<u8> = upload.1.into_values().flatten().collect();
        let etag = tag(&bytes);
        data.objects.insert(path.clone(), bytes);
        let (bucket, key) = path.split_once('/').unwrap();
        return format!("<CompleteMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{key}</Key><ETag>{etag}</ETag></CompleteMultipartUploadResult>").into_response();
    }
    if method == Method::DELETE {
        if let Some(upload) = query.get("uploadId") {
            data.uploads.remove(upload);
        } else {
            let Some(bytes) = data.objects.get(&path) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            assert_eq!(
                headers.get(header::IF_MATCH).unwrap().to_str().unwrap(),
                tag(bytes)
            );
            data.objects.remove(&path);
        }
        return StatusCode::NO_CONTENT.into_response();
    }
    if method == Method::PUT {
        assert!(body.is_empty());
        if let Some(expected) = headers.get(header::IF_NONE_MATCH) {
            assert_eq!(expected, "*");
            if data.objects.contains_key(&path) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        } else {
            let expected = headers
                .get(header::IF_MATCH)
                .expect("empty PUT must be conditional");
            let Some(existing) = data.objects.get(&path) else {
                return StatusCode::PRECONDITION_FAILED.into_response();
            };
            if expected.to_str().unwrap() != tag(existing) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
        data.objects.insert(path, Vec::new());
        return ([(header::ETAG, tag(&[]))], Bytes::new()).into_response();
    }
    if method == Method::GET || method == Method::HEAD {
        let Some(bytes) = data.objects.get(&path) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let etag = tag(bytes);
        if let Some(expected) = headers.get(header::IF_MATCH) {
            if expected.to_str().unwrap() != etag {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
        return (
            [
                (header::ETAG, etag),
                (header::CONTENT_LENGTH, bytes.len().to_string()),
            ],
            if method == Method::GET {
                Bytes::copy_from_slice(bytes)
            } else {
                Bytes::new()
            },
        )
            .into_response();
    }
    StatusCode::NOT_IMPLEMENTED.into_response()
}

struct Fixture {
    jwt: JwtKeys,
    app: Router,
    db: Arc<Database>,
    token: String,
    cache_id: String,
    http: reqwest::Client,
    store: Arc<Store>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture() -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let files = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let tls = aos_hub::native_tls::NativeTlsListener::new(
        listener,
        &files.join("hub-hybrid-fleet-s3.crt"),
        &files.join("hub-hybrid-fleet-s3.key"),
        "s3.fleet.test".into(),
    )
    .unwrap();
    let store = Arc::new(Store::default());
    let app = Router::new()
        .fallback(any(storage))
        .with_state(Arc::clone(&store));
    let server = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    let ca = reqwest::Certificate::from_pem(
        &std::fs::read(files.join("hub-hybrid-fleet-s3-ca.crt")).unwrap(),
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(ca)
        .resolve("s3.fleet.test", address)
        .build()
        .unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db
        .create_org("native-direct", "Native direct")
        .await
        .unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "storage",
            &org.stable_id,
            "Storage",
            "s3",
            None,
            Some("bucket"),
            Some("managed"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(i64::from(address.port())),
            Some("test-region"),
            Some("private"),
        )
        .await
        .unwrap();
    for purpose in ["read", "write", "presign"] {
        let credential = db
            .set_binding_credential_revision(
                binding_id,
                purpose,
                &format!("secret://native-fixture/{purpose}/v1"),
                0,
                &hex::encode(Sha256::digest(SECRET.as_bytes())),
                "test",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            binding_id,
            purpose,
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
    }
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: 1,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "native-fixture-revision".into(),
            capability_fingerprint: "native-fixture-capability".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let binding_state = db.binding_write_state(binding_id).await.unwrap().unwrap();
    db.set_current_binding_write_revision(
        binding_id,
        revision.revision,
        binding_state.resource_version,
    )
    .await
    .unwrap();
    let cache = db
        .create_binary_cache(
            Some(org_id),
            "native-cache",
            "Native cache",
            "private",
            0,
            "none",
            false,
        )
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::BinaryCache(cache),
            name: "primary".into(),
            binding_id,
            prefix: "cache".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    db.observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision.revision)
        .await
        .unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::BinaryCache(cache),
        "native-writer",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision.revision,
    )
    .await
    .unwrap();
    let user = db
        .create_user("native-direct@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, &org.stable_id, "owner")
        .await
        .unwrap();
    let (_, secret) = db
        .create_token(
            Principal::user(user),
            &org.stable_id,
            &[Permission::RegistryConfigure],
            None,
            None,
        )
        .await
        .unwrap();
    let jwt = JwtKeys::random();
    let token = jwt
        .mint(&db.validate_token(&secret).await.unwrap().unwrap(), 900)
        .unwrap();
    let app = native_app(
        Arc::clone(&db),
        jwt.clone(),
        http.clone(),
        Some("native-fixture".into()),
    )
    .await;
    Fixture {
        jwt,
        app,
        db: Arc::clone(&db),
        token,
        cache_id: db
            .binary_cache_by_id(cache)
            .await
            .unwrap()
            .unwrap()
            .stable_id,
        http,
        store,
        server,
    }
}

async fn native_app(
    db: Arc<Database>,
    jwt: JwtKeys,
    http: reqwest::Client,
    deployment: Option<String>,
) -> Router {
    let mut state =
        aos_hub::server::AppState::new(Arc::clone(&db), "http://native.example.test".into()).await;
    state.auth = Arc::new(aos_hub::auth::extract::AuthState {
        db,
        jwt_keys: jwt,
        access_token_ttl: 900,
        ratelimit: Arc::clone(&state.ratelimit),
        trusted_proxy: false,
    });
    state.deployment_id = deployment;
    state.secret_versions = Arc::new(FixtureSecrets);
    state.http = http;
    aos_hub::server::router(Arc::new(state)).await
}

async fn call_unchecked<T: serde::Serialize>(
    fixture: &Fixture,
    method: &str,
    body: &T,
) -> DirectUploadResponse {
    let encoded = encode_direct_control(body).unwrap();
    assert!(encoded.len() < MAX_DIRECT_CONTROL_BYTES);
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/aos.hub.v1.DirectUploadService/{method}"))
        .header(header::HOST, "native.example.test")
        .header(header::AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from(encoded))
        .unwrap();
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), MAX_DIRECT_CONTROL_BYTES)
        .await
        .unwrap();
    let reply: DirectUploadResponse = decode_direct_control(&body).unwrap();
    reply
}

async fn call<T: serde::Serialize>(
    fixture: &Fixture,
    method: &str,
    body: &T,
) -> DirectUploadResponse {
    let reply = call_unchecked(fixture, method, body).await;
    assert!(
        reply.errors.is_empty(),
        "control errors: {:?}",
        reply.errors
    );
    reply
}

async fn upload(
    fixture: &Fixture,
    ordinal: u8,
    bytes: Vec<u8>,
    corrupt_hash: bool,
) -> DirectSessionStatus {
    let path = format!("nar/object-{ordinal}.nar");
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: hex::encode([ordinal; 32]),
        target: DirectUploadTarget::CacheObject {
            cache_id: fixture.cache_id.clone(),
            path,
        },
        expected_sha256: if corrupt_hash {
            "0".repeat(64)
        } else {
            hex::encode(Sha256::digest(&bytes))
        },
        byte_size: WireInteger::new(bytes.len() as u64),
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let begin = call(
        fixture,
        "BeginBatch",
        &DirectBeginBatch {
            operation_id: "a".repeat(64),
            items: vec![intent.clone()],
        },
    )
    .await;
    let status = &begin.sessions[0];
    let parts: Vec<_> = bytes
        .chunks(MIN_DIRECT_PART_BYTES as usize)
        .enumerate()
        .map(|(index, data)| DirectPart {
            part_number: index as u32 + 1,
            offset: WireInteger::new(index as u64 * MIN_DIRECT_PART_BYTES),
            byte_size: WireInteger::new(data.len() as u64),
            sha256: hex::encode(Sha256::digest(data)),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Md5,
                value: base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(data)),
            },
        })
        .collect();
    let grants = call(
        fixture,
        "GrantPartsBatch",
        &DirectBatch {
            operation_id: "b".repeat(64),
            items: parts
                .iter()
                .map(|part| DirectGrantPartRequest {
                    session: status.session.clone(),
                    placement: status.placements[0].clone(),
                    operation_id: hex::encode([part.part_number as u8; 32]),
                    part: part.clone(),
                })
                .collect(),
        },
    )
    .await;
    let upload_bytes = &bytes;
    let reports =
        futures_util::future::join_all(grants.grants.into_iter().map(|grant| async move {
            let url = url::Url::parse(&grant.url).unwrap();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("s3.fleet.test"));
            assert!(grant
                .required_headers
                .iter()
                .all(|header| !matches!(header.name.as_str(), "authorization" | "cookie")));
            let start = grant.part.offset.get() as usize;
            let end = start + grant.part.byte_size.get() as usize;
            let mut request = fixture.http.put(&grant.url);
            for header in &grant.required_headers {
                request = request.header(&header.name, &header.value);
            }
            let response = request
                .body(upload_bytes[start..end].to_vec())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            DirectPartReport {
                session: status.session.clone(),
                placement: grant.placement,
                operation_id: grant.grant_id.clone(),
                grant_id: grant.grant_id,
                grant_revision: grant.grant_revision,
                observed: DirectManifestPart {
                    part: grant.part,
                    etag: response
                        .headers()
                        .get(header::ETAG)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .into(),
                },
            }
        }))
        .await;
    let manifest: Vec<_> = reports
        .iter()
        .map(|report| report.observed.clone())
        .collect();
    call(
        fixture,
        "ReportPartsBatch",
        &DirectBatch {
            operation_id: "c".repeat(64),
            items: reports,
        },
    )
    .await;
    let complete = DirectCompleteRequest {
        session: status.session.clone(),
        operation_id: "d".repeat(64),
        expected_resource_version: status.resource_version,
        manifests: vec![DirectManifestCommitment {
            placement: status.placements[0].clone(),
            manifest_digest: canonical_manifest_digest(&intent, &status.placements[0], &manifest)
                .unwrap(),
            part_count: parts.len() as u32,
        }],
    };
    let started = tokio::time::Instant::now();
    call(
        fixture,
        "CompleteBatch",
        &DirectBatch {
            operation_id: "e".repeat(64),
            items: vec![complete],
        },
    )
    .await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "Complete blocked on provider verification"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let response = call_unchecked(
            fixture,
            "StatusBatch",
            &DirectBatch {
                operation_id: "f".repeat(64),
                items: vec![DirectStatusQuery {
                    session: status.session.clone(),
                    after: None,
                    maximum_parts: 1,
                }],
            },
        )
        .await;
        if corrupt_hash && !response.errors.is_empty() {
            assert!(response
                .errors
                .iter()
                .all(|error| error.code == DirectItemErrorCode::Invalid));
            return status.clone();
        }
        assert!(
            response.errors.is_empty(),
            "unexpected status refusal: {:?}",
            response.errors
        );
        let current = response.sessions[0].clone();
        if current.state == DirectSessionState::Committed
            && staging_cleaned(fixture, &current.session.session_id).await
        {
            return current;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "upload did not finish: {:?}",
            current.state
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn staging_cleaned(fixture: &Fixture, session_id: &str) -> bool {
    let prefix = format!(".aos-direct-upload/native/{session_id}/");
    fixture
        .store
        .data
        .lock()
        .await
        .objects
        .keys()
        .all(|path| !path.contains(&prefix))
}

#[tokio::test]
#[ignore = "requires debug-only local-remote opt-in for the TLS S3 fixture"]
async fn native_only_parallel_signed_multipart_uploads_commit_without_workers() {
    let fixture = fixture().await;
    fixture.store.read_delay_ms.store(1500, Ordering::SeqCst);
    let bytes = vec![7_u8; MIN_DIRECT_PART_BYTES as usize + 17];
    let (first, second) = tokio::join!(
        upload(&fixture, 1, bytes.clone(), false),
        upload(&fixture, 2, bytes.clone(), false)
    );
    assert_eq!(first.state, DirectSessionState::Committed);
    assert_eq!(second.state, DirectSessionState::Committed);
    assert!(fixture.store.peak_parts.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        fixture.store.uploaded_bytes.load(Ordering::SeqCst),
        bytes.len() * 2
    );
    let stored = fixture.store.data.lock().await;
    assert_eq!(
        stored.objects["bucket/managed/cache/nar/object-1.nar"],
        bytes
    );
    assert_eq!(
        stored.objects["bucket/managed/cache/nar/object-2.nar"],
        bytes
    );
    assert!(stored
        .objects
        .keys()
        .all(|path| !path.contains(".aos-direct-upload/native/")));
    drop(stored);
    let cache = fixture
        .db
        .binary_cache_by_stable_id(&fixture.cache_id)
        .await
        .unwrap()
        .unwrap();
    let usage = fixture.db.org_usage(cache.org_id.unwrap()).await.unwrap();
    assert_eq!(usage.used_bytes, bytes.len() as i64 * 2);
    assert_eq!(usage.object_count, 2);
    for session in [first.session, second.session] {
        let record = fixture
            .db
            .native_direct_upload("native-fixture", &session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, "committed");
        assert_eq!(
            record.verified_sha256.as_deref(),
            Some(record.source_sha256.as_str())
        );
        assert!(!record.state_json.contains("X-Amz-Signature"));
        assert!(!record.state_json.contains(SECRET));
        assert_eq!(
            fixture
                .db
                .cache_write_ticket(&session.session_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "completed"
        );
    }
}

#[tokio::test]
#[ignore = "requires debug-only local-remote opt-in for the TLS S3 fixture"]
async fn native_only_wrong_full_hash_never_promotes_or_completes_ticket() {
    let fixture = fixture().await;
    let status = upload(&fixture, 3, vec![9_u8; 31], true).await;
    assert_ne!(status.state, DirectSessionState::Committed);
    assert!(!fixture
        .store
        .data
        .lock()
        .await
        .objects
        .contains_key("bucket/managed/cache/nar/object-3.nar"));
    let ticket = fixture
        .db
        .cache_write_ticket(&status.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.state, "observing");
    let record = fixture
        .db
        .native_direct_upload("native-fixture", &status.session.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(record.verified_sha256.is_none());
    let state: serde_json::Value = serde_json::from_str(&record.state_json).unwrap();
    assert_eq!(state["integrity_failed"], true);
    let cache = fixture
        .db
        .binary_cache_by_stable_id(&fixture.cache_id)
        .await
        .unwrap()
        .unwrap();
    let usage = fixture.db.org_usage(cache.org_id.unwrap()).await.unwrap();
    assert_eq!(usage.used_bytes, 0);
    assert_eq!(usage.object_count, 0);
}

#[tokio::test]
async fn native_public_uploads_require_user_auth_and_reject_bulk_and_private_envelopes() {
    let fixture = fixture().await;
    let path = "/aos.hub.v1.DirectUploadService/BeginBatch";
    let unauthenticated = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, "native.example.test")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        fixture
            .app
            .clone()
            .oneshot(unauthenticated)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let private = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, "native.example.test")
        .header(header::AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from(
            r#"{"context":{},"request":{"kind":"begin_batch","request":{}}}"#,
        ))
        .unwrap();
    assert_eq!(
        fixture.app.clone().oneshot(private).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let bulk = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, "native.example.test")
        .header(header::AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from(vec![0_u8; MAX_DIRECT_CONTROL_BYTES + 1]))
        .unwrap();
    assert_eq!(
        fixture.app.clone().oneshot(bulk).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(fixture.store.data.lock().await.uploads.is_empty());
}

#[tokio::test]
async fn native_without_deployment_advertises_legacy_after_current_permission_check() {
    let fixture = fixture().await;
    let app = native_app(
        Arc::clone(&fixture.db),
        fixture.jwt.clone(),
        fixture.http.clone(),
        None,
    )
    .await;
    let query = DirectGetCapabilities {
        target: DirectCapabilitiesTarget::Cache {
            cache_id: fixture.cache_id.clone(),
        },
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri("/aos.hub.v1.DirectUploadService/GetCapabilities")
        .header(header::HOST, "native.example.test")
        .header(header::AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from(encode_direct_control(&query).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), MAX_DIRECT_CONTROL_BYTES)
        .await
        .unwrap();
    let capability: DirectUploadCapabilities = decode_direct_control(&bytes).unwrap();
    assert_eq!(
        capability.transfer_mode,
        DirectAdvertisedTransferMode::Legacy
    );
    assert!(capability.profiles.is_empty());
    assert!(fixture.store.data.lock().await.uploads.is_empty());
}

#[tokio::test]
#[ignore = "requires debug-only local-remote opt-in for the TLS S3 fixture"]
async fn restarted_native_upload_keeps_unresolved_provider_dispatch_blocked() {
    let fixture = fixture().await;
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "9".repeat(64),
        target: DirectUploadTarget::CacheObject {
            cache_id: fixture.cache_id.clone(),
            path: "nar/interrupted.nar".into(),
        },
        expected_sha256: hex::encode(Sha256::digest(b"pending")),
        byte_size: WireInteger::new(7),
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let begun = call(
        &fixture,
        "BeginBatch",
        &DirectBeginBatch {
            operation_id: "8".repeat(64),
            items: vec![intent],
        },
    )
    .await;
    let original = &begun.sessions[0];
    let mut record = fixture
        .db
        .native_direct_upload("native-fixture", &original.session.session_id)
        .await
        .unwrap()
        .unwrap();
    let mut state: serde_json::Value = serde_json::from_str(&record.state_json).unwrap();
    state["pending"] = "previous-process:complete-stage-0".into();
    let revision = record.resource_version;
    record.resource_version += 1;
    record.state_json = serde_json::to_string(&state).unwrap();
    fixture
        .db
        .replace_native_direct_upload(&record, revision, Vec::new())
        .await
        .unwrap();
    let uploads_before = fixture.store.data.lock().await.next_id;

    let status = call(
        &fixture,
        "StatusBatch",
        &DirectBatch {
            operation_id: "7".repeat(64),
            items: vec![DirectStatusQuery {
                session: original.session.clone(),
                after: None,
                maximum_parts: 1,
            }],
        },
    )
    .await;

    assert_eq!(status.sessions[0].state, DirectSessionState::BlockedUnknown);
    assert_eq!(fixture.store.data.lock().await.next_id, uploads_before);
    assert_eq!(fixture.store.uploaded_bytes.load(Ordering::SeqCst), 0);
    let retained = fixture
        .db
        .native_direct_upload("native-fixture", &original.session.session_id)
        .await
        .unwrap()
        .unwrap();
    let state: serde_json::Value = serde_json::from_str(&retained.state_json).unwrap();
    assert_eq!(
        state["pending"].as_str(),
        Some("previous-process:complete-stage-0")
    );
}

async fn empty_upload(fixture: &Fixture, operation: u8) -> DirectSessionStatus {
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: hex::encode([operation; 32]),
        target: DirectUploadTarget::CacheObject {
            cache_id: fixture.cache_id.clone(),
            path: "nar/empty.nar".into(),
        },
        expected_sha256: hex::encode(Sha256::digest([])),
        byte_size: WireInteger::new(0),
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let begun = call(
        fixture,
        "BeginBatch",
        &DirectBeginBatch {
            operation_id: "1".repeat(64),
            items: vec![intent.clone()],
        },
    )
    .await;
    let original = &begun.sessions[0];
    let complete = DirectCompleteRequest {
        session: original.session.clone(),
        operation_id: "2".repeat(64),
        expected_resource_version: original.resource_version,
        manifests: vec![DirectManifestCommitment {
            placement: original.placements[0].clone(),
            part_count: 0,
            manifest_digest: canonical_manifest_digest(&intent, &original.placements[0], &[])
                .unwrap(),
        }],
    };
    call(
        fixture,
        "CompleteBatch",
        &DirectBatch {
            operation_id: "3".repeat(64),
            items: vec![complete],
        },
    )
    .await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let result = call(
            fixture,
            "StatusBatch",
            &DirectBatch {
                operation_id: "4".repeat(64),
                items: vec![DirectStatusQuery {
                    session: original.session.clone(),
                    after: None,
                    maximum_parts: 1,
                }],
            },
        )
        .await;
        if result.sessions[0].state == DirectSessionState::Committed
            && staging_cleaned(fixture, &original.session.session_id).await
        {
            return result.sessions[0].clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "empty upload did not commit"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test]
#[ignore = "requires debug-only local-remote opt-in for the TLS S3 fixture"]
async fn native_empty_upload_creates_and_replaces_without_multipart_or_duplicate_accounting() {
    let fixture = fixture().await;
    let first = empty_upload(&fixture, 41).await;
    let second = empty_upload(&fixture, 42).await;

    assert_eq!(first.state, DirectSessionState::Committed);
    assert_eq!(second.state, DirectSessionState::Committed);
    let stored = fixture.store.data.lock().await;
    assert_eq!(
        stored.next_id, 0,
        "empty objects must not create multipart uploads"
    );
    assert!(stored.objects["bucket/managed/cache/nar/empty.nar"].is_empty());
    assert!(stored
        .objects
        .keys()
        .all(|path| !path.contains(".aos-direct-upload/native/")));
    drop(stored);
    let cache = fixture
        .db
        .binary_cache_by_stable_id(&fixture.cache_id)
        .await
        .unwrap()
        .unwrap();
    let usage = fixture.db.org_usage(cache.org_id.unwrap()).await.unwrap();
    assert_eq!(usage.used_bytes, 0);
    assert_eq!(usage.object_count, 1);
    for session in [first.session, second.session] {
        let record = fixture
            .db
            .native_direct_upload("native-fixture", &session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.verified_sha256,
            Some(hex::encode(Sha256::digest([])))
        );
        assert_eq!(record.verified_size, Some(0));
    }
}
