//! Real queued Delete credential validation and conditional-delete capability.
//!
//! A separate bootstrap Worker validates the unknown credential before its
//! cohort is admitted. Business cleanup consumes the resulting SQL capability;
//! no fixture initializes a valid Delete observation or borrows GC authority.

use super::*;
use crate::storage_work::{
    HybridStorageCredentialProbeProvider, HybridSurfaceProvider, HybridSurfaceWrites,
};
use aos_hub_core::{
    conditional_delete_probe::ConditionalDeleteProbeController,
    surface_write::SurfaceWriteProvider as _,
    topology_probe::{DomainProbeController, DomainTlsProbeVerifier},
};

pub(super) async fn validate_credential(db: Arc<Database>, binding_id: i64, root: &Path) {
    let root = root.join("credential-bootstrap");
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let credential = db
        .current_binding_credential(binding_id, "delete")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.validation_state, "unknown");
    let (rpc, operator) = configuration::operator(db.clone()).await;
    let plan = rpc
        .plan_validate_binding_credential(
            Some(&operator),
            aos_proto_types::hub_v1::PlanValidateBindingCredentialRequest {
                binding_id: binding.stable_id.clone(),
                purpose: "delete".into(),
                generation: credential.generation,
                expected_resource_version: credential.head_resource_version.to_string(),
                idempotency_key: "oci-bootstrap-delete-plan".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let operation = rpc
        .validate_binding_credential(
            Some(&operator),
            aos_proto_types::hub_v1::ApplyTopologyPlanRequest {
                plan_id: plan.plan_id,
                confirmation_hash: plan.confirmation_hash,
                idempotency_key: "oci-bootstrap-delete-apply".into(),
            },
        )
        .await
        .unwrap()
        .operation
        .unwrap();
    let queued = db
        .topology_operation(&operation.operation_id)
        .await
        .unwrap()
        .unwrap();
    let detail: Value = serde_json::from_str(&queued.detail_json).unwrap();
    let clock = aos_hub_core::direct_upload::DirectClockPolicy {
        version: 1,
        mode: aos_hub_core::direct_upload::DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: aos_hub_core::direct_upload::WireInteger::new(2),
    };
    private(
        &root.join("setup.json"),
        &serde_json::to_vec(&json!({
            "bootstrapOnly":true, "issuer":"127.0.0.1:1", "native":"127.0.0.1:1",
            "application":configuration::APPLICATION,"guard":configuration::GUARD,
            "renewal":configuration::RENEWAL,"ingress":INGRESS,
            "physicalPrefix":format!("managed/binding/{PREFIX}"),
            "sourceKey":format!("managed/binding/{PREFIX}/fixture-unused-source"),
            "guardClockPolicy":clock,"guardClockQualification":clock.commitment().unwrap(),
        }))
        .unwrap(),
    );
    let log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("fixture.log"))
        .unwrap();
    let script = PathBuf::from(std::env::var_os("AOS_OCI_FIXTURE_SCRIPT").unwrap());
    let mut process = Process(
        Command::new(std::env::var("AOS_OCI_NODE").unwrap())
            .arg(script)
            .arg(&root)
            .arg(std::env::var("AOS_OCI_DIST").unwrap())
            .arg(std::env::var("AOS_OCI_WORKERD").unwrap())
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures"))
            .stdin(Stdio::piped())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        while !root.join("ready.json").exists() {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "bootstrap fixture exited; inspect its retained log"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root.join("ready.json")).unwrap()).unwrap();
    let ca = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hub-hybrid-fleet-s3-ca.crt"),
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30))
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .resolve(
            "s3.fleet.test",
            ready["relayAddress"].as_str().unwrap().parse().unwrap(),
        )
        .build()
        .unwrap();
    let mut client = RemoteStorageWorkClient::new(
        ready["workerOrigin"].as_str().unwrap(),
        "fixture-deployment".into(),
        configuration::APPLICATION.as_bytes(),
    )
    .unwrap();
    client.http = http.clone();
    client.semantic_observation_http = http.clone();
    let client = Arc::new(client);
    let now = aos_hub_core::clock::now_unix_secs();
    let stage = aos_hub_core::storage_work::binding_custody::StorageCredentialCustodyProbe {
        version: 1,
        nonce: uuid::Uuid::new_v4().simple().to_string().repeat(2),
        issued_at: now,
        expires_at: now + 30,
        operation_id: queued.operation_id.clone(),
        probe_token: detail["probeToken"].as_str().unwrap().into(),
        head_resource_version: credential.head_resource_version,
        snapshot: StorageBindingSnapshot::for_credential_probe(
            "fixture-deployment".into(),
            &binding,
            &credential,
            now,
        )
        .unwrap(),
    };
    client
        .stage_credential_custody(stage, &Resolver, now + 3600)
        .await
        .unwrap();
    let controller = DomainProbeController::new(
        db.clone(),
        Arc::new(crate::coreports::HubHttpClient::new(http.clone())),
        DomainTlsProbeVerifier::new(),
        "https://dns.fixture.test/resolve",
        "oci-delete-bootstrap",
    )
    .unwrap()
    .with_storage_credential_probe(Arc::new(HybridStorageCredentialProbeProvider::new(
        client,
        db.clone(),
    )));
    assert_eq!(controller.run_due(1).await.unwrap(), 1);
    let validated = db
        .current_binding_credential(binding_id, "delete")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(validated.validation_state, "valid");
    assert_eq!(
        validated.head_resource_version,
        credential.head_resource_version + 1
    );
    assert_eq!(
        db.topology_operation(&queued.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "succeeded"
    );
    let current_binding = db.binding(binding_id).await.unwrap().unwrap();
    assert_eq!(
        StorageBindingSnapshot::for_credential_probe(
            "fixture-deployment".into(),
            &current_binding,
            &credential,
            now
        )
        .unwrap(),
        StorageBindingSnapshot::for_credential_probe(
            "fixture-deployment".into(),
            &binding,
            &credential,
            now
        )
        .unwrap()
    );
    let observed = inspect(&http, ready["administrativeOrigin"].as_str().unwrap()).await;
    assert_eq!(observed["credentialProbes"], 1);
    assert_eq!(observed["creates"], 0);
    assert_eq!(observed["parts"], 0);
    private(&root.join("credential-validation.json"),&serde_json::to_vec_pretty(&json!({
        "operationId":queued.operation_id,"operationState":"succeeded",
        "credential":{"purpose":validated.purpose,"generation":validated.generation,
            "headResourceVersion":validated.head_resource_version,"validationState":validated.validation_state,
            "fingerprint":validated.credential_fingerprint,"validatedAt":validated.validated_at},
        "provider":observed,
        "scope":"Actual queued Native controller and Worker-held credential probe; no conditional-delete capability inferred."
    })).unwrap());
    drop(process);
}

pub(super) async fn qualify_capability(
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    placement: &aos_hub_core::db::SurfacePlacementRecord,
    root: &Path,
) {
    let state = db
        .binding_write_state(placement.binding_id)
        .await
        .unwrap()
        .unwrap();
    let revision = state.current_write_revision.unwrap();
    assert!(
        db.oci_conditional_delete_capability(placement.binding_id, revision)
            .await
            .unwrap()
            .is_none()
    );
    let controller = ConditionalDeleteProbeController::new(
        db.clone(),
        Arc::new(HybridSurfaceProvider::new(db.clone(), work.clone())),
        Arc::new(HybridSurfaceWrites::new(db.clone(), work)),
    );
    assert_eq!(
        controller
            .run_due(aos_hub_core::clock::now_unix_secs(), 1)
            .await
            .unwrap(),
        1
    );
    let capability = db
        .oci_conditional_delete_capability(placement.binding_id, revision)
        .await
        .unwrap()
        .unwrap();
    let binding = db.binding(placement.binding_id).await.unwrap().unwrap();
    let credential = db
        .current_binding_credential(binding.id, "delete")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(capability.state, "valid");
    assert_eq!(
        capability.binding_resource_version,
        binding.resource_version
    );
    assert_eq!(
        capability.delete_credential_purpose.as_deref(),
        Some("delete")
    );
    assert_eq!(
        capability.delete_credential_generation,
        Some(credential.generation)
    );
    private(
        &root.join("delete-capability.json"),
        &serde_json::to_vec_pretty(&json!({
            "bindingId":capability.binding_id,"bindingWriteRevision":capability.binding_write_revision,
            "bindingResourceVersion":capability.binding_resource_version,
            "deleteCredentialPurpose":capability.delete_credential_purpose,
            "deleteCredentialGeneration":capability.delete_credential_generation,
            "capabilityFingerprint":capability.capability_fingerprint,"state":capability.state,
            "resourceVersion":capability.resource_version,"observedAt":capability.observed_at,
        })).unwrap(),
    );
}

pub(super) async fn settle_terminal_chunks(
    db: &Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    http: &reqwest::Client,
    administrative: &str,
    root: &Path,
) {
    let candidates = db.oci_upload_cleanup_candidates(100).await.unwrap();
    assert!(
        !candidates.is_empty(),
        "lost positive cleanup reply must leave real SQL pending"
    );
    let before = inspect(http, administrative).await;
    assert_eq!(before["lostCleanupReplies"], 1);
    let writes = HybridSurfaceWrites::new(db.clone(), work);
    for candidate in &candidates {
        for chunk in &candidate.chunks {
            let claim = db
                .claim_terminal_oci_chunk_cleanup(candidate, chunk)
                .await
                .unwrap();
            assert!(writes.cleanup_oci_upload_chunk(&claim).await.unwrap());
            claim.check_current(db).await.unwrap();
        }
    }
    let after = inspect(http, administrative).await;
    assert_eq!(
        after["conditionalDeleteRequests"], before["conditionalDeleteRequests"],
        "cold positive receipt replay dispatched another Delete"
    );
    assert_eq!(
        after["signatures"], before["signatures"],
        "cold positive receipt replay dispatched HEAD or issuer-authorized provider I/O"
    );
    let summary = aos_hub_core::oci::recover_expired_oci_work(
        db,
        &writes,
        aos_hub_core::clock::now_unix_secs(),
        100,
    )
    .await
    .unwrap();
    assert!(summary.cleaned_uploads > 0);
    assert!(
        db.oci_upload_cleanup_candidates(100)
            .await
            .unwrap()
            .is_empty()
    );
    for candidate in &candidates {
        assert_eq!(
            db.oci_upload_chunks(&candidate.upload.id).await.unwrap(),
            candidate.chunks,
            "immutable chunk input history was removed by cleanup"
        );
        let upload = db
            .oci_upload(
                &candidate.upload.id,
                &candidate.upload.writer_id,
                &candidate.upload.token_id,
                aos_hub_core::clock::now_unix_secs(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(upload.cleanup_state, "complete");
        assert_eq!(upload.staging_placement_id, None);
    }
    private(&root.join("terminal-cleanup.json"), &serde_json::to_vec_pretty(&json!({
        "cleanedUploads":summary.cleaned_uploads,"retainedChunkHistory":true,
        "lostPositiveReply":1,"coldReplayProviderDispatchDelta":0,
        "before":before,"after":inspect(http,administrative).await,
        "scope":"Actual versioned TLS S3 fixture and independently probed Delete capability; no Garage, Hosted or Managed SDK qualification."
    })).unwrap());
}

/// Keeps an actual dispatched-but-unacknowledged DELETE unknown across retries.
pub(super) async fn unknown_acknowledgement(
    db: &Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    http: &reqwest::Client,
    origin: &str,
    authorization: &str,
    administrative: &str,
    root: &Path,
) {
    http.post(format!("{administrative}/fixture/lose-delete-reply"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let body = b"a distinct terminal unknown cleanup original";
    let (_, final_url) =
        super::upload(http, origin, authorization, body, true, administrative).await;
    let upload_id = final_url
        .rsplit_once("/blobs/uploads/")
        .unwrap()
        .1
        .split('?')
        .next()
        .unwrap();
    let candidates = db.oci_upload_cleanup_candidates(100).await.unwrap();
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.upload.id == upload_id)
        .unwrap();
    assert_eq!(candidate.upload.state, "complete");
    assert_eq!(candidate.upload.cleanup_state, "pending");
    assert_eq!(candidate.chunks.len(), 1);
    let claim = db
        .claim_terminal_oci_chunk_cleanup(candidate, &candidate.chunks[0])
        .await
        .unwrap();
    let before = inspect(http, administrative).await;
    assert_eq!(before["lostDeleteReplies"], 1);
    let writes = HybridSurfaceWrites::new(db.clone(), work);
    for _ in 0..2 {
        assert!(
            writes.cleanup_oci_upload_chunk(&claim).await.is_err(),
            "unknown DELETE must not be settled by later absence"
        );
        claim.check_current(db).await.unwrap();
    }
    let after = inspect(http, administrative).await;
    for field in [
        "signatures",
        "conditionalDeleteRequests",
        "deletedVersions",
        "conditionalReads",
    ] {
        assert_eq!(
            after[field], before[field],
            "unknown cleanup retry redispatched provider work: {field}"
        );
    }
    private(&root.join("unknown-terminal-cleanup.json"),&serde_json::to_vec_pretty(&json!({
        "uploadId":upload_id,"cleanupState":"pending","lostProviderAcknowledgement":1,
        "retries":2,"providerDispatchDelta":0,"retainedOriginal":{"uploadId":candidate.upload.id,
            "resourceVersion":candidate.upload.resource_version,
            "placementId":candidate.upload.staging_placement_id,
            "bindingId":candidate.upload.staging_binding_id,
            "bindingWriteRevision":candidate.upload.staging_binding_write_revision,
            "ordinal":candidate.chunks[0].ordinal,"bytes":candidate.chunks[0].byte_size,
            "digest":candidate.chunks[0].digest.to_string(),
            "stagingKeySha256":hex::encode(Sha256::digest(candidate.chunks[0].staging_object_key.as_bytes()))},
        "before":before,"after":after,
        "scope":"Actual provider DELETE applied without an acknowledgement; persistent guard remains unknown and SQL stays pending."
    })).unwrap());
}
