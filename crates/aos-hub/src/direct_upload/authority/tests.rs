//! Production Native admission over real SQL and independently signed TLS discovery.

use std::sync::atomic::{AtomicUsize, Ordering};

use aos_hub_core::storage_work::{STORAGE_CAPABILITIES_PATH, STORAGE_WORK_SIGNATURE_HEADER};
use aos_hub_core::{
    db::NewSurfacePlacementSpec,
    domain::{Permission, Principal},
};
use axum::{body::Bytes, http::HeaderMap, routing::post, Router};

use super::*;
use sha2::Digest as _;

#[path = "oci_projection_tests.rs"]
mod oci_projection_tests;

#[path = "empty_tests.rs"]
mod empty_tests;

#[path = "recovery_tests.rs"]
mod recovery_tests;

fn context(origin: &str, nonce: u8) -> DirectRequestContext {
    let now = current_time().unwrap();
    DirectRequestContext {
        deployment_id: "deployment-1".into(),
        executor_public_origin: origin.into(),
        public_authority: url::Url::parse(origin).unwrap().host_str().unwrap().into(),
        foreground: DirectForegroundBudget {
            invocation_id: hex::encode([nonce; 32]),
            issued_at: WireInteger::new(now),
            expires_at: WireInteger::new(now + 30),
        },
        request_nonce: hex::encode([nonce; 32]),
        request_body_sha256: "f".repeat(64),
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/BeginBatch".into(),
        issued_at: WireInteger::new(now),
        expires_at: WireInteger::new(now + 30),
    }
}

async fn rpc(db: Arc<Database>, http: reqwest::Client) -> Arc<RpcService> {
    let surface = Arc::new(crate::coreports::HubSurfaceProvider::new(
        db.clone(),
        http.clone(),
        None,
    ));
    Arc::new(RpcService::new(
        db.clone(),
        JwtKeys::random(),
        "https://localhost".into(),
        Arc::new(crate::ratelimit::RateLimiter::new()),
        surface,
        Arc::new(crate::coreports::HubSurfaceWriteProvider::new(
            db.clone(),
            http,
        )),
        Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        Arc::new(crate::coreports::HubReindexer::new(db.clone(), None)),
        Arc::new(aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(db)),
        None,
    ))
}

#[tokio::test]
async fn sixty_four_real_admissions_share_one_signed_discovery_and_new_invocation_refetches() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("https://localhost:{}", address.port());
    let now = current_time().unwrap();
    let (acceptances, profile) = acceptance::tests::managed_fixture(&origin, now, now + 600);
    let DirectProtectedProfile::Managed {
        profile: managed,
        private_stage_policy,
        runtime_qualification,
    } = profile
    else {
        panic!("managed test projection required");
    };
    let storage_key = StorageWorkKey::new(&[11; 32]).unwrap();
    let guard_key = StorageWorkKey::new(&[12; 32]).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint_calls = calls.clone();
    let endpoint_key = storage_key.clone();
    let endpoint_origin = origin.clone();
    let app = Router::new().route(
        STORAGE_CAPABILITIES_PATH,
        post(move |headers: HeaderMap, body: Bytes| {
            let key = endpoint_key.clone();
            let origin = endpoint_origin.clone();
            let calls = endpoint_calls.clone();
            let managed = managed.clone();
            let policy = private_stage_policy.clone();
            let runtime = runtime_qualification.clone();
            async move {
                let request = verify_direct_storage_capabilities_request(
                    &key,
                    headers
                        .get(STORAGE_WORK_SIGNATURE_HEADER)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    &body,
                    "deployment-1",
                    &origin,
                    current_time().unwrap(),
                )
                .unwrap();
                calls.fetch_add(1, Ordering::SeqCst);
                let reply = sign_direct_storage_capabilities_reply(
                    &key,
                    &DirectStorageCapabilitiesReply {
                        request,
                        capabilities: DirectStorageCapabilities {
                            version: 2,
                            capability: DIRECT_UPLOAD_CAPABILITY.into(),
                            profile: Some(managed),
                            private_stage_policy: Some(policy),
                            runtime_qualification: Some(runtime),
                            external_profiles: Vec::new(),
                        },
                    },
                )
                .unwrap();
                (
                    [(STORAGE_WORK_SIGNATURE_HEADER, reply.signature)],
                    reply.body,
                )
            }
        }),
    );
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let tls = crate::native_tls::NativeTlsListener::new(
        listener,
        &fixture.join("hub-hybrid-fleet-server.crt"),
        &fixture.join("hub-hybrid-fleet-server.key"),
        "localhost".into(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    let ca = reqwest::Certificate::from_pem(
        &std::fs::read(fixture.join("hub-hybrid-fleet-ca.crt")).unwrap(),
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("hub-private-objects"))
        .await
        .unwrap();
    let user = db
        .create_user("batch-profile@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (_, token_secret) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::RegistryConfigure],
            None,
            None,
        )
        .await
        .unwrap();
    let keys = JwtKeys::random();
    let claims = keys
        .verify(
            &keys
                .mint(
                    &db.validate_token(&token_secret).await.unwrap().unwrap(),
                    900,
                )
                .unwrap(),
        )
        .unwrap();
    let mut intents = Vec::new();
    for index in 0..65 {
        let cache = db
            .create_binary_cache(
                None,
                &format!("batch-{index}"),
                "Batch",
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
                binding_id: binding.id,
                prefix: format!("cache-{index}"),
                kind: "complete".into(),
                desired_state: "active".into(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        db.observe_surface_placement(placement.id, "ready", "complete", 1)
            .await
            .unwrap();
        db.bind_surface_placement_write_capability(placement.id, 1)
            .await
            .unwrap();
        db.create_surface_write_authority(
            SurfaceTarget::BinaryCache(cache),
            &format!("authority-{index}"),
            placement.id,
            placement.resource_version,
            placement.write_spec_version,
            1,
        )
        .await
        .unwrap();
        let cache = db.binary_cache_by_id(cache).await.unwrap().unwrap();
        intents.push(DirectUploadIntent {
            version: 1,
            client_operation_id: format!("{index:064x}"),
            target: DirectUploadTarget::CacheObject {
                cache_id: cache.stable_id,
                path: "nar/source.nar".into(),
            },
            expected_sha256: "a".repeat(64),
            byte_size: WireInteger::new(1),
            part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        });
    }
    let authority = NativeDirectUploadAuthority {
        db: db.clone(),
        rpc: rpc(db.clone(), http.clone()).await,
        origin: origin.clone(),
        deployment: "deployment-1".into(),
        storage_key,
        guard_key,
        acceptances: Arc::new(acceptances),
        http,
        clock_uncertainty_seconds: 1,
        discovery: Arc::new(tokio::sync::OnceCell::new()),
        lookup_slots: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let service = DirectUploadService::new(db.clone(), Arc::new(authority.clone()));
    let first = DirectLogicalRequestEnvelope {
        context: context(&origin, 1),
        request: DirectUploadLogicalRequest::Admission {
            intents: intents[..64].to_vec(),
        },
    };
    let started = std::time::Instant::now();
    let reply = service
        .dispatch(&claims, &first, current_time().unwrap() as i64)
        .await
        .unwrap();
    assert!(
        reply.errors.is_empty(),
        "unexpected admission errors: {:?}",
        reply.errors
    );
    assert_eq!(reply.admissions.len(), 64);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    eprintln!(
        "64 production Native admissions: {:?}, signed profile requests: 1",
        started.elapsed()
    );

    let second = DirectLogicalRequestEnvelope {
        context: context(&origin, 2),
        request: DirectUploadLogicalRequest::Admission {
            intents: vec![intents[64].clone()],
        },
    };
    let reply = service
        .dispatch(&claims, &second, current_time().unwrap() as i64)
        .await
        .unwrap();
    assert!(reply.errors.is_empty());
    assert_eq!(reply.admissions.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let scoped = authority.clone();
    scoped
        .current_profiles(&first.context, current_time().unwrap() as i64)
        .await
        .unwrap();
    let mut changed_context = first.context.clone();
    changed_context.request_nonce = "ab".repeat(32);
    assert!(scoped
        .current_profiles(&changed_context, current_time().unwrap() as i64)
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let (expired, _) = acceptance::tests::managed_fixture(
        &origin,
        current_time().unwrap() - 2,
        current_time().unwrap(),
    );
    let mut expired_authority = authority;
    expired_authority.acceptances = Arc::new(expired);
    assert!(expired_authority
        .current_profiles(&context(&origin, 3), current_time().unwrap() as i64)
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let mut empty = intents[0].clone();
    if let DirectUploadTarget::CacheObject { path, .. } = &mut empty.target {
        *path = "nar/empty.nar".into();
    }
    empty.client_operation_id = "fc".repeat(32);
    empty.byte_size = WireInteger::new(0);
    empty.expected_sha256 = hex::encode(sha2::Sha256::digest([]));
    let empty_reply = service
        .dispatch(
            &claims,
            &DirectLogicalRequestEnvelope {
                context: context(&origin, 4),
                request: DirectUploadLogicalRequest::Admission {
                    intents: vec![empty],
                },
            },
            current_time().unwrap() as i64,
        )
        .await
        .unwrap();
    assert!(empty_reply.errors.is_empty());
    assert_eq!(empty_reply.admissions.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let cache = match &intents[0].target {
        DirectUploadTarget::CacheObject { cache_id, .. } => cache_id.clone(),
        _ => panic!("cache fixture required"),
    };
    let caps = service
        .get_capabilities(
            &claims,
            &DirectCapabilitiesTarget::Cache { cache_id: cache },
            "deployment-1",
            current_time().unwrap() as i64,
        )
        .await
        .unwrap();
    assert_eq!(caps.minimum_object_bytes.get(), 0);
    server.abort();
}
