//! Qualified external empty refusal before Native target or quota reservation.

use super::*;

#[tokio::test]
async fn external_capability_minimum_refuses_empty_before_any_retained_sql_plan() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("external-empty", "External").await.unwrap();
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "external-binding",
            &owner.stable_id,
            "External",
            "s3",
            None,
            Some("qualified-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
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
                &format!("secret://fixture/{purpose}/v1"),
                0,
                &"4".repeat(64),
                "system:test",
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
        .create_binding_write_revision(&aos_hub_core::db::NewBindingWriteRevision {
            binding_id,
            write_credential_generation: 1,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "revision-1".into(),
            capability_fingerprint: "capability-1".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let state = db.binding_write_state(binding_id).await.unwrap().unwrap();
    db.set_current_binding_write_revision(binding_id, revision.revision, state.resource_version)
        .await
        .unwrap();
    let cache = db
        .create_binary_cache(
            Some(org_id),
            "external-empty",
            "External",
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
            prefix: "managed/binding/cache".into(),
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
        "external-writer",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision.revision,
    )
    .await
    .unwrap();
    let user = db
        .create_user("external-empty@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, &owner.stable_id, "owner")
        .await
        .unwrap();
    let (_, secret) = db
        .create_token(
            Principal::user(user),
            &owner.stable_id,
            &[Permission::RegistryConfigure],
            None,
            None,
        )
        .await
        .unwrap();
    let jwt = JwtKeys::random();
    let claims = jwt
        .verify(
            &jwt.mint(&db.validate_token(&secret).await.unwrap().unwrap(), 900)
                .unwrap(),
        )
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let now = current_time().unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let (acceptances, profile) =
        acceptance::tests::external_fixture(&origin, now, now + 600, &binding);
    let DirectProtectedProfile::External {
        profile,
        runtime_qualification,
    } = profile
    else {
        panic!("external fixture required");
    };
    let storage_key = StorageWorkKey::new(&[21; 32]).unwrap();
    let endpoint_key = storage_key.clone();
    let endpoint_origin = origin.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint_calls = calls.clone();
    let app = Router::new().route(
        STORAGE_CAPABILITIES_PATH,
        post(move |headers: HeaderMap, body: Bytes| {
            let key = endpoint_key.clone();
            let origin = endpoint_origin.clone();
            let profile = profile.clone();
            let runtime = runtime_qualification.clone();
            let calls = endpoint_calls.clone();
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
                assert!(!request.managed);
                assert_eq!(request.external_selectors, vec![profile.selector.clone()]);
                calls.fetch_add(1, Ordering::SeqCst);
                let signed = sign_direct_storage_capabilities_reply(
                    &key,
                    &DirectStorageCapabilitiesReply {
                        request,
                        capabilities: DirectStorageCapabilities {
                            version: 2,
                            capability: DIRECT_UPLOAD_CAPABILITY.into(),
                            profile: None,
                            private_stage_policy: None,
                            runtime_qualification: None,
                            external_profiles: vec![DirectProtectedExternalProfile::new(
                                profile, runtime,
                            )
                            .unwrap()],
                        },
                    },
                )
                .unwrap();
                (
                    [(STORAGE_WORK_SIGNATURE_HEADER, signed.signature)],
                    signed.body,
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
        .build()
        .unwrap();
    let authority = NativeDirectUploadAuthority {
        db: db.clone(),
        rpc: rpc(db.clone(), http.clone()).await,
        origin: origin.clone(),
        deployment: "deployment-1".into(),
        storage_key,
        guard_key: StorageWorkKey::new(&[22; 32]).unwrap(),
        acceptances: Arc::new(acceptances),
        http,
        clock_uncertainty_seconds: 2,
        discovery: Arc::new(tokio::sync::OnceCell::new()),
        lookup_slots: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let service = DirectUploadService::new(db.clone(), Arc::new(authority));
    let cache = db.binary_cache_by_id(cache).await.unwrap().unwrap();
    let caps = service
        .get_capabilities(
            &claims,
            &DirectCapabilitiesTarget::Cache {
                cache_id: cache.stable_id.clone(),
            },
            "deployment-1",
            now as i64,
        )
        .await
        .unwrap();
    assert_eq!(caps.minimum_object_bytes.get(), 1);
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "ed".repeat(32),
        target: DirectUploadTarget::CacheObject {
            cache_id: cache.stable_id,
            path: "nar/empty.nar".into(),
        },
        expected_sha256: hex::encode(sha2::Sha256::digest([])),
        byte_size: WireInteger::new(0),
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let reply = service
        .dispatch(
            &claims,
            &DirectLogicalRequestEnvelope {
                context: context(&origin, 5),
                request: DirectUploadLogicalRequest::Admission {
                    intents: vec![intent.clone()],
                },
            },
            now as i64,
        )
        .await
        .unwrap();
    assert!(reply.admissions.is_empty());
    assert_eq!(reply.errors.len(), 1);
    assert_eq!(reply.errors[0].code, DirectItemErrorCode::Unsupported);
    let session = deterministic_business_operation_id(
        "deployment-1",
        &caps.principal_id,
        &intent.client_operation_id,
    )
    .unwrap();
    assert!(db
        .direct_upload_session("deployment-1", &session)
        .await
        .unwrap()
        .is_none());
    assert!(db.cache_write_ticket(&session).await.unwrap().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
}
