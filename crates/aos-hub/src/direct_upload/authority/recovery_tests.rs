//! Cold expired qualification recovery through actual Native SQL and signed TLS guards.
//!
//! The independent controlled guard oracle proves consumer behavior and cannot
//! qualify provider execution. Every production logical phase uses the real service.

use super::*;
use axum::http::StatusCode;
use std::sync::atomic::AtomicBool;

fn authorize(
    complete: &DirectCompleteRequest,
    step: DirectCompleteStep,
) -> DirectUploadLogicalRequest {
    DirectUploadLogicalRequest::Authorize {
        action: DirectLogicalAction::Complete,
        complete_step: Some(step),
        stage_evidence: Vec::new(),
        retained_stage_digests: Vec::new(),
        baseline_evidence: Vec::new(),
        baseline_witnesses: Vec::new(),
        baseline_witness_refs: Vec::new(),
        settled_placements: Vec::new(),
        sessions: vec![DirectSessionAuthorization {
            session: complete.session.clone(),
            expected_resource_version: Some(complete.expected_resource_version),
            operation_id: complete.operation_id.clone(),
            complete_intent: Some(complete.clone()),
        }],
    }
}

async fn dispatch(
    service: &DirectUploadService,
    claims: &Claims,
    origin: &str,
    mut request: DirectUploadLogicalRequest,
    nonce: u8,
) -> DirectUploadLogicalReply {
    let mut context = context(origin, nonce);
    if let DirectUploadLogicalRequest::Authorize {
        baseline_evidence,
        baseline_witness_refs,
        ..
    } = &mut request
    {
        // The controlled guard returns a fresh observation for this invocation;
        // only the first baseline/reservation is immutable across retries.
        for (baseline, witness) in baseline_evidence.iter().zip(baseline_witness_refs) {
            witness.issued_at = context.issued_at;
            witness.expires_at = WireInteger::new(
                context
                    .expires_at
                    .get()
                    .min(baseline.binding.admission_expires_at.get()),
            );
            witness.observation_operation_id = hex::encode([nonce; 32]);
        }
    }
    if !matches!(request, DirectUploadLogicalRequest::Admission { .. }) {
        context.public_path = "/aos.hub.v1.DirectUploadService/CompleteBatch".into();
    }
    service
        .dispatch(
            claims,
            &DirectLogicalRequestEnvelope { context, request },
            current_time().unwrap() as i64,
        )
        .await
        .unwrap()
}

async fn refuses_unknown_legacy_before_admission(
    db: &Database,
    authority: &NativeDirectUploadAuthority,
    service: &DirectUploadService,
    claims: &Claims,
    origin: &str,
    binding_id: i64,
    discovery_calls: &AtomicUsize,
) {
    use aos_hub_core::db::{
        NewRegistryPublication, RegistryPublicationManifestObject, SetSurfaceObject,
    };
    let registry = db
        .register_registry("legacy-direct", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "legacy-primary".into(),
            binding_id,
            prefix: "legacy-direct".into(),
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
        SurfaceTarget::Registry(registry),
        "legacy-direct-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        1,
    )
    .await
    .unwrap();
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry),
            object_key: "objects/legacy".into(),
            content_hash: Some("7".repeat(64)),
            size: Some(1),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    let publication = "legacy-direct-publication";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication.into(),
        registry_id: registry,
        generation: "legacy-generation".into(),
        manifest_digest: "8".repeat(64),
        refs_digest: "9".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    let now = current_time().unwrap() as i64;
    db.begin_registry_publication_manifest_session(
        publication,
        registry,
        &"8".repeat(64),
        1,
        "legacy-lease",
        now,
    )
    .await
    .unwrap();
    db.append_registry_publication_manifest_chunk(
        publication,
        "legacy-lease",
        0,
        &"a".repeat(64),
        &[RegistryPublicationManifestObject {
            object_key: "objects/legacy".into(),
            expected_hash: "7".repeat(64),
            expected_size: 1,
            object_kind: "immutable".into(),
        }],
        now,
    )
    .await
    .unwrap();
    db.seal_registry_publication_manifest_session(
        publication,
        "legacy-lease",
        &[placement.id],
        now,
    )
    .await
    .unwrap();
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "6".repeat(64),
        target: DirectUploadTarget::PublicationObject {
            publication_id: publication.into(),
            surface_object_id: WireInteger::new(object.id as u64),
            path: "objects/legacy".into(),
        },
        expected_sha256: "7".repeat(64),
        byte_size: WireInteger::new(1),
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let actor = authority.current_actor(claims).await.unwrap();
    // The public target, current owner/actor and complete writer are otherwise
    // eligible. A manifest conflict cannot synthesize a new accounting origin.
    authority
        .resolve_target(claims, &actor, &intent, false, now)
        .await
        .unwrap();
    let before = discovery_calls.load(Ordering::SeqCst);
    let original = deterministic_business_operation_id(
        "deployment-1",
        &actor.principal_id("deployment-1").unwrap(),
        &intent.client_operation_id,
    )
    .unwrap();
    let refused = dispatch(
        service,
        claims,
        origin,
        DirectUploadLogicalRequest::Admission {
            intents: vec![intent],
        },
        25,
    )
    .await;
    assert!(!refused.errors.is_empty());
    assert_eq!(discovery_calls.load(Ordering::SeqCst), before);
    assert!(db
        .direct_upload_session("deployment-1", &original)
        .await
        .unwrap()
        .is_none());
    assert!(db.surface_object_usage(object.id).await.unwrap().is_none());
}

#[tokio::test]
async fn cold_expired_native_requires_fresh_positive_guards_and_refuses_new_effects() {
    recovery_contract(None).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn cold_expired_native_postgres_blocks_past_deadline_without_ack_and_replays_exact_original()
{
    let Ok(url) = std::env::var("AOS_HUB_DIRECT_RECOVERY_TEST_PG_URL") else {
        return;
    };
    recovery_contract(Some(url)).await;
}

async fn open_recovery_database(
    path: &std::path::Path,
    postgres_url: Option<&str>,
) -> Arc<Database> {
    #[cfg(feature = "postgres")]
    if let Some(url) = postgres_url {
        return Arc::new(
            Database::with_backend(Box::new(
                aos_hub_core::backend::SqlxBackend::connect_postgres(url)
                    .await
                    .unwrap(),
            ))
            .await
            .unwrap(),
        );
    }
    let _ = postgres_url;
    Arc::new(Database::open(path).await.unwrap())
}

async fn recovery_contract(postgres_url: Option<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let now = current_time().unwrap();
    let (accepted, profile) = acceptance::tests::managed_fixture(&origin, now, now + 600);
    let DirectProtectedProfile::Managed {
        profile: managed,
        private_stage_policy,
        runtime_qualification,
    } = profile
    else {
        panic!("managed fixture required")
    };
    // The protected guard observes the same reviewed conservative clock as
    // Native. Raw UTC can precede the qualified challenge issuance by this bound.
    let guard_clock_uncertainty = managed.clock_uncertainty_seconds.get();
    let storage_key = StorageWorkKey::new(&[11; 32]).unwrap();
    let guard_key = StorageWorkKey::new(&[12; 32]).unwrap();
    let positive = Arc::new(AtomicBool::new(true));
    let stage_calls = Arc::new(AtomicUsize::new(0));
    let final_calls = Arc::new(AtomicUsize::new(0));
    let discovery_calls = Arc::new(AtomicUsize::new(0));
    let discover_key = storage_key.clone();
    let discover_origin = origin.clone();
    let discover_calls = discovery_calls.clone();
    let stage_key = guard_key.clone();
    let stage_positive = positive.clone();
    let observed_stage = stage_calls.clone();
    let final_key = guard_key.clone();
    let final_positive = Arc::new(AtomicBool::new(true));
    let final_availability = final_positive.clone();
    let observed_final = final_calls.clone();
    let app = Router::new()
        .route(
            STORAGE_CAPABILITIES_PATH,
            post(move |headers: HeaderMap, body: Bytes| {
                let key = discover_key.clone();
                let origin = discover_origin.clone();
                let profile = managed.clone();
                let policy = private_stage_policy.clone();
                let runtime = runtime_qualification.clone();
                let calls = discover_calls.clone();
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
                    let signed = sign_direct_storage_capabilities_reply(
                        &key,
                        &DirectStorageCapabilitiesReply {
                            request,
                            capabilities: DirectStorageCapabilities {
                                version: 2,
                                capability: DIRECT_UPLOAD_CAPABILITY.into(),
                                profile: Some(profile),
                                private_stage_policy: Some(policy),
                                runtime_qualification: Some(runtime),
                                external_profiles: Vec::new(),
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
        )
        .route(
            DIRECT_AUTHORITY_LOOKUP_PATH,
            post(move |headers: HeaderMap, body: Bytes| {
                let key = stage_key.clone();
                let positive = stage_positive.clone();
                let calls = observed_stage.clone();
                async move {
                    let request = verify_direct_authority_lookup(
                        &key,
                        headers
                            .get(DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER)
                            .unwrap()
                            .to_str()
                            .unwrap(),
                        &body,
                        "deployment-1",
                        current_time().unwrap() + guard_clock_uncertainty,
                    )
                    .unwrap();
                    if matches!(
                        request.operation,
                        DirectAuthorityLookupOperation::Stage { .. }
                    ) {
                        calls.fetch_add(1, Ordering::SeqCst);
                    }
                    if !positive.load(Ordering::SeqCst) {
                        return (
                            StatusCode::CONFLICT,
                            [(DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER, String::new())],
                            Vec::new(),
                        );
                    }
                    let signed = sign_direct_authority_lookup_reply(
                        &key,
                        &DirectAuthorityLookupReply { request },
                    )
                    .unwrap();
                    (
                        StatusCode::OK,
                        [(DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER, signed.signature)],
                        signed.body,
                    )
                }
            }),
        )
        .route(
            DIRECT_FINAL_GUARD_PATH,
            post(move |headers: HeaderMap, body: Bytes| {
                let key = final_key.clone();
                let positive = final_positive.clone();
                let calls = observed_final.clone();
                async move {
                    let request = verify_direct_final_guard_lookup(
                        &key,
                        headers
                            .get(DIRECT_FINAL_GUARD_SIGNATURE_HEADER)
                            .unwrap()
                            .to_str()
                            .unwrap(),
                        &body,
                        "deployment-1",
                        current_time().unwrap() + guard_clock_uncertainty,
                    )
                    .unwrap();
                    calls.fetch_add(1, Ordering::SeqCst);
                    if !positive.load(Ordering::SeqCst) {
                        return (
                            StatusCode::CONFLICT,
                            [(DIRECT_FINAL_GUARD_SIGNATURE_HEADER, String::new())],
                            Vec::new(),
                        );
                    }
                    let signed = sign_direct_final_guard_reply(
                        &key,
                        &DirectFinalGuardReply {
                            record: request.expected.clone(),
                            request,
                        },
                    )
                    .unwrap();
                    (
                        StatusCode::OK,
                        [(DIRECT_FINAL_GUARD_SIGNATURE_HEADER, signed.signature)],
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
    let server = tokio::spawn(async move { axum::serve(tls, app).await.unwrap() });
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
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cold-recovery.sqlite");
    let db = open_recovery_database(&path, postgres_url.as_deref()).await;
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("hub-private-objects"))
        .await
        .unwrap();
    let user = db
        .create_user("cold-recovery@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (_, token) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::RegistryConfigure, Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let jwt = JwtKeys::random();
    let claims = jwt
        .verify(
            &jwt.mint(&db.validate_token(&token).await.unwrap().unwrap(), 900)
                .unwrap(),
        )
        .unwrap();
    let cache_id = db
        .create_binary_cache(None, "cold-recovery", "Cold", "private", 0, "none", false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::BinaryCache(cache_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "cold-recovery".into(),
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
        SurfaceTarget::BinaryCache(cache_id),
        "cold-recovery-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        1,
    )
    .await
    .unwrap();
    let cache = db.binary_cache_by_id(cache_id).await.unwrap().unwrap();
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "a".repeat(64),
        target: DirectUploadTarget::CacheObject {
            cache_id: cache.stable_id,
            path: "nar/source.nar".into(),
        },
        expected_sha256: "b".repeat(64),
        byte_size: WireInteger::new(1),
        part_size: WireInteger::new(MIN_DIRECT_PART_BYTES),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let authority = NativeDirectUploadAuthority {
        db: db.clone(),
        rpc: rpc(db.clone(), http.clone()).await,
        origin: origin.clone(),
        deployment: "deployment-1".into(),
        storage_key,
        guard_key,
        acceptances: Arc::new(accepted),
        http: http.clone(),
        clock_uncertainty_seconds: guard_clock_uncertainty,
        discovery: Arc::new(tokio::sync::OnceCell::new()),
        lookup_slots: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let service = DirectUploadService::new(db.clone(), Arc::new(authority.clone()));
    let begin = dispatch(
        &service,
        &claims,
        &origin,
        DirectUploadLogicalRequest::Admission {
            intents: vec![intent.clone()],
        },
        10,
    )
    .await;
    assert!(begin.errors.is_empty(), "{:?}", begin.errors);
    refuses_unknown_legacy_before_admission(
        &db,
        &authority,
        &service,
        &claims,
        &origin,
        binding.id,
        &discovery_calls,
    )
    .await;
    let admission = begin.admissions[0].clone();
    let session = DirectSessionRef {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
    };
    let complete = DirectCompleteRequest {
        session: session.clone(),
        operation_id: "c".repeat(64),
        expected_resource_version: WireInteger::new(1),
        manifests: vec![DirectManifestCommitment {
            placement: admission.placements[0].public_ref("deployment-1").unwrap(),
            manifest_digest: "d".repeat(64),
            part_count: 1,
        }],
    };
    let freeze = dispatch(
        &service,
        &claims,
        &origin,
        authorize(&complete, DirectCompleteStep::Freeze),
        11,
    )
    .await;
    assert!(freeze.errors.is_empty(), "{:?}", freeze.errors);
    let incarnation = |version: &str| DirectObjectIncarnation::ProviderVersion {
        version: version.into(),
    };
    let stage = DirectVerifiedStageEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: intent.expected_sha256.clone(),
        byte_size: intent.byte_size,
        projection: None,
        placements: vec![DirectStagePlacementEvidence {
            placement: complete.manifests[0].placement.clone(),
            manifest: complete.manifests[0].clone(),
            verification_operation_id: "e".repeat(64),
            staging_incarnation: incarnation("source-version"),
        }],
    };
    let mut baseline_request = authorize(&complete, DirectCompleteStep::Baseline);
    if let DirectUploadLogicalRequest::Authorize { stage_evidence, .. } = &mut baseline_request {
        stage_evidence.push(stage.clone());
    }
    let reply = dispatch(&service, &claims, &origin, baseline_request, 12).await;
    assert!(reply.errors.is_empty(), "{:?}", reply.errors);
    let selected = &admission.placements[0];
    let promotion = direct_destination_promotion_operation_id(
        &session,
        selected.placement_id,
        &complete.operation_id,
    )
    .unwrap();
    let baseline_binding = DirectDestinationBaselineBinding {
        deployment_id: "deployment-1".into(),
        session: session.clone(),
        admission_expires_at: admission.expires_at,
        complete_operation_id: complete.operation_id.clone(),
        complete_intent_digest: complete.fingerprint().unwrap(),
        placement: complete.manifests[0].placement.clone(),
        protected_profile_digest: selected.protected_profile_digest.clone(),
        final_key_digest: direct_destination_key_digest(&selected.final_key).unwrap(),
        scope: DirectDestinationReservationScope::Managed {
            bucket_namespace: match &selected.physical {
                DirectPhysicalContext::DeploymentR2 {
                    bucket_namespace, ..
                } => bucket_namespace.clone(),
                _ => panic!("managed fixture required"),
            },
        },
        reservation_operation_id: promotion.clone(),
        reservation_nonce: "f".repeat(64),
        reservation_revision: WireInteger::new(1),
    };
    let baseline = DirectDestinationBaselineEvidence {
        binding: baseline_binding.clone(),
        observation_operation_id: "1".repeat(64),
        issued_at: WireInteger::new(now),
        expires_at: WireInteger::new(now + 30),
        state: DirectDestinationBaselineState::Missing {},
    };
    let witness = DirectDestinationBaselineWitness {
        binding: baseline_binding.clone(),
        baseline_digest: baseline.fingerprint().unwrap(),
        observation_operation_id: "2".repeat(64),
        issued_at: WireInteger::new(now),
        expires_at: WireInteger::new(now + 30),
    };
    let mut promote = authorize(&complete, DirectCompleteStep::Promote);
    if let DirectUploadLogicalRequest::Authorize {
        retained_stage_digests,
        baseline_evidence,
        baseline_witness_refs,
        ..
    } = &mut promote
    {
        retained_stage_digests.push(DirectRetainedStageDigest::from_evidence(&stage).unwrap());
        baseline_evidence.push(baseline);
        baseline_witness_refs.push(DirectBaselineWitnessRef::from_witness(&witness).unwrap());
    }
    let reply = dispatch(&service, &claims, &origin, promote.clone(), 13).await;
    assert!(reply.errors.is_empty(), "{:?}", reply.errors);
    drop(service);
    drop(authority);
    drop(db);

    let db = open_recovery_database(&path, postgres_url.as_deref()).await;
    let expired = acceptance::tests::managed_expired_fixture(&origin, current_time().unwrap());
    NativeDirectUploadRuntime::new_for_positive_recovery(
        &origin,
        "deployment-1",
        &[11; 32],
        &[12; 32],
        expired.clone(),
    )
    .unwrap();
    let cold = NativeDirectUploadAuthority {
        db: db.clone(),
        rpc: rpc(db.clone(), http.clone()).await,
        origin: origin.clone(),
        deployment: "deployment-1".into(),
        storage_key: StorageWorkKey::new(&[11; 32]).unwrap(),
        guard_key: StorageWorkKey::new(&[12; 32]).unwrap(),
        acceptances: Arc::new(expired),
        http,
        clock_uncertainty_seconds: guard_clock_uncertainty,
        discovery: Arc::new(tokio::sync::OnceCell::new()),
        lookup_slots: Arc::new(tokio::sync::Semaphore::new(8)),
    };
    let service = Arc::new(DirectUploadService::new(db.clone(), Arc::new(cold)));
    let discovery_before = discovery_calls.load(Ordering::SeqCst);
    let mut expired_context = context(&origin, 23);
    expired_context.public_path = "/aos.hub.v1.DirectUploadService/CompleteBatch".into();
    expired_context.expires_at = expired_context.issued_at;
    expired_context.foreground.expires_at = expired_context.issued_at;
    let before_expired = db
        .direct_upload_session("deployment-1", &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(service
        .dispatch(
            &claims,
            &DirectLogicalRequestEnvelope {
                context: expired_context,
                request: authorize(&complete, DirectCompleteStep::Freeze),
            },
            current_time().unwrap() as i64
        )
        .await
        .is_err());
    let after_expired = db
        .direct_upload_session("deployment-1", &admission.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        before_expired.resource_version,
        after_expired.resource_version
    );
    assert_eq!(before_expired.state, after_expired.state);
    let denied = dispatch(
        &service,
        &claims,
        &origin,
        DirectUploadLogicalRequest::Admission {
            intents: vec![intent],
        },
        14,
    )
    .await;
    assert!(!denied.errors.is_empty());
    assert!(!dispatch(&service, &claims, &origin, promote, 15)
        .await
        .errors
        .is_empty());
    positive.store(false, Ordering::SeqCst);
    assert!(!dispatch(
        &service,
        &claims,
        &origin,
        authorize(&complete, DirectCompleteStep::Freeze),
        16
    )
    .await
    .errors
    .is_empty());
    positive.store(true, Ordering::SeqCst);
    assert!(dispatch(
        &service,
        &claims,
        &origin,
        authorize(&complete, DirectCompleteStep::Freeze),
        17
    )
    .await
    .errors
    .is_empty());
    let evidence = DirectCompletionEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: 1,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        projection: None,
        placements: vec![DirectPlacementEvidence {
            placement_id: selected.placement_id,
            placement_resource_version: selected.placement_resource_version,
            write_spec_version: selected.write_spec_version,
            binding_id: selected.binding_id,
            binding_resource_version: selected.binding_resource_version,
            binding_write_revision: selected.binding_write_revision,
            manifest: complete.manifests[0].clone(),
            promotion_operation_id: promotion,
            staging_incarnation: incarnation("source-version"),
            final_incarnation: incarnation("final-version"),
            final_etag: "\"final\"".into(),
        }],
    };
    let guard = DirectFinalGuardRecord {
        version: 1,
        reservation: baseline_binding,
        selected: DirectSelectedCompleteCommitment {
            version: 1,
            session: session.clone(),
            operation_id: complete.operation_id.clone(),
            expected_resource_version: complete.expected_resource_version,
            complete_intent_digest: complete.fingerprint().unwrap(),
            manifest: complete.manifests[0].clone(),
            protected_profile_digest: selected.protected_profile_digest.clone(),
        },
        sha256: evidence.sha256.clone(),
        byte_size: evidence.byte_size,
        source_incarnation: incarnation("source-version"),
        final_incarnation: incarnation("final-version"),
        final_etag: "\"final\"".into(),
    };
    let commit = DirectUploadLogicalRequest::Commit {
        evidence: vec![evidence],
        final_guards: Vec::new(),
        final_guard_refs: vec![DirectFinalGuardRef::from_record(&guard).unwrap()],
    };
    final_availability.store(false, Ordering::SeqCst);
    assert!(!dispatch(&service, &claims, &origin, commit.clone(), 18)
        .await
        .errors
        .is_empty());
    final_availability.store(true, Ordering::SeqCst);
    let other = db
        .create_user("recovery-other-owner@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", other, "instance", "owner")
        .await
        .unwrap();
    db.revoke_membership("user", user, "instance")
        .await
        .unwrap();
    let mut revoked_context = context(&origin, 21);
    revoked_context.public_path = "/aos.hub.v1.DirectUploadService/CompleteBatch".into();
    let revoked = service
        .dispatch(
            &claims,
            &DirectLogicalRequestEnvelope {
                context: revoked_context,
                request: commit.clone(),
            },
            current_time().unwrap() as i64,
        )
        .await;
    assert!(revoked.is_err() || revoked.is_ok_and(|reply| !reply.errors.is_empty()));
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    #[cfg(feature = "postgres")]
    if let Some(url) = &postgres_url {
        let pool = sqlx::PgPool::connect(url).await.unwrap();
        let mut holder = pool.begin().await.unwrap();
        let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *holder)
            .await
            .unwrap();
        sqlx::query("UPDATE bindings SET updated_at = updated_at WHERE id = $1")
            .bind(binding.id)
            .execute(&mut *holder)
            .await
            .unwrap();
        let work = service.clone();
        // Mint and verify a genuine shorter JWT for the same current actor. The
        // original control request remains valid for thirty seconds, so only the
        // authenticated claims boundary cancels this blocked SQL transaction.
        let actor = jwt
            .verify(
                &jwt.mint(&db.validate_token(&token).await.unwrap().unwrap(), 2)
                    .unwrap(),
            )
            .unwrap();
        assert!(actor.exp < context(&origin, 22).expires_at.get() as i64);
        let destination = origin.clone();
        let original_commit = commit.clone();
        let pending = tokio::spawn(async move {
            dispatch(&work, &actor, &destination, original_commit, 22).await
        });
        let blocked_pid = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let pid: Option<i32> = sqlx::query_scalar(
                    "SELECT pid FROM pg_stat_activity WHERE datname = current_database()
                       AND wait_event_type = 'Lock' AND $1 = ANY(pg_blocking_pids(pid)) LIMIT 1",
                )
                .bind(holder_pid)
                .fetch_optional(&pool)
                .await
                .unwrap();
                if let Some(pid) = pid {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("actual Direct transaction never waited on held authority row");
        eprintln!(
            "Direct final deadline: holder PID {holder_pid}, blocked backend PID {blocked_pid}"
        );
        let refused = tokio::time::timeout(std::time::Duration::from_secs(4), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !refused.errors.is_empty(),
            "expired SQL authority must not acknowledge success"
        );
        holder.commit().await.unwrap();
        let observed = db
            .direct_upload_session("deployment-1", &admission.session_id)
            .await
            .unwrap()
            .unwrap();
        // Cancellation can race a SQL commit. Both retained states require the
        // same exact original retry; a timeout itself proves neither outcome.
        assert!(matches!(
            observed.state,
            DirectSessionState::StagedVerified | DirectSessionState::Committed
        ));
    }
    let completed = dispatch(&service, &claims, &origin, commit.clone(), 19).await;
    assert!(completed.errors.is_empty(), "{:?}", completed.errors);
    assert_eq!(
        db.direct_upload_session("deployment-1", &admission.session_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        DirectSessionState::Committed
    );
    let calls = (
        stage_calls.load(Ordering::SeqCst),
        final_calls.load(Ordering::SeqCst),
    );
    positive.store(false, Ordering::SeqCst);
    assert!(dispatch(&service, &claims, &origin, commit, 20)
        .await
        .errors
        .is_empty());
    assert_eq!(
        (
            stage_calls.load(Ordering::SeqCst),
            final_calls.load(Ordering::SeqCst)
        ),
        calls
    );
    assert_eq!(discovery_calls.load(Ordering::SeqCst), discovery_before);
    server.abort();
}
