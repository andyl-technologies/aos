//! Actual public registration controls with a separately authenticated Worker stub.
//!
//! SQL validation is performed only by the real controller. The TLS producer
//! supplies controlled replies; these tests do not qualify a physical provider.

use serde_json::{json, Value};
use tower::ServiceExt as _;

use super::credential_custody::{custody_client, CustodyFault};
use super::*;

pub(super) struct ResolverSpy {
    pub(super) calls: AtomicUsize,
    pub(super) forbid: bool,
}

#[async_trait::async_trait]
impl SecretVersionResolver for ResolverSpy {
    async fn resolve(&self, _reference: &str) -> Result<ResolvedSecretVersion> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.forbid {
            anyhow::bail!("Native must not resolve provider material in configured Hybrid");
        }
        Ok(ResolvedSecretVersion::from_bytes(MATERIAL.to_vec()))
    }
}

pub(super) struct Api {
    app: Router,
    auth: String,
    ingress: Option<Arc<aos_hub_core::hybrid_ingress::HybridIngressKey>>,
    sequence: AtomicUsize,
}

impl Api {
    pub(super) async fn new(
        fixture: &Fixture,
        resolver: Arc<ResolverSpy>,
        work: Option<Arc<RemoteStorageWorkClient>>,
    ) -> Self {
        let mut state =
            aos_hub::server::AppState::new(fixture.db.clone(), "https://localhost".into()).await;
        Arc::get_mut(&mut state.auth).unwrap().jwt_keys = fixture.rpc.jwt_keys.clone();
        state.secret_versions = resolver;
        state.deployment_id = Some("qualification-deployment".into());
        let ingress = work.as_ref().map(|_| {
            Arc::new(aos_hub_core::hybrid_ingress::HybridIngressKey::new([9; 32]).unwrap())
        });
        let app = match work {
            Some(work) => {
                aos_hub::server::router_with_hybrid_ingress(
                    Arc::new(state),
                    ingress.clone().unwrap(),
                    "qualification-deployment".into(),
                    work,
                )
                .await
            }
            None => {
                let listener = aos_hub_core::connect::DeliveryTransportEvidence::from_verified_url(
                    &url::Url::parse("https://localhost").unwrap(),
                    "hub",
                )
                .unwrap();
                aos_hub::server::router_with_transport(Arc::new(state), Some(listener)).await
            }
        };
        Self {
            app,
            auth: fixture.auth.clone(),
            ingress,
            sequence: AtomicUsize::new(0),
        }
    }

    pub(super) async fn request(
        &self,
        service: &str,
        method: &str,
        value: Value,
    ) -> (axum::http::StatusCode, Value) {
        use aos_hub_core::hybrid_ingress::{HybridIngressAssertion, HYBRID_INGRESS_HEADER};

        let path = format!("/aos.hub.v1.{service}/{method}");
        let body = serde_json::to_vec(&value).unwrap();
        let mut request = axum::http::Request::builder()
            .uri(&path)
            .method("POST")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("connect-protocol-version", "1")
            .header("authorization", &self.auth);
        if let Some(key) = &self.ingress {
            let now = aos_hub_core::clock::now_unix_secs();
            let assertion = HybridIngressAssertion {
                version: 1,
                deployment_id: "qualification-deployment".into(),
                issued_at: now,
                expires_at: now + 30,
                request_id: format!(
                    "registration-{}",
                    self.sequence.fetch_add(1, Ordering::SeqCst)
                ),
                scheme: "https".into(),
                authority: "localhost".into(),
                method: "POST".into(),
                path_and_query: path,
                body_sha256: hex::encode(Sha256::digest(&body)),
                upload_phase: None,
                client_ip: "192.0.2.7".into(),
            };
            request = request.header(HYBRID_INGRESS_HEADER, key.sign(&assertion).unwrap());
        }
        let reply = self
            .app
            .clone()
            .oneshot(request.body(axum::body::Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = reply.status();
        let body = axum::body::to_bytes(reply.into_body(), 262144)
            .await
            .unwrap();
        let value = serde_json::from_slice(&body).unwrap_or_else(|error| {
            panic!("{service}/{method}: HTTP {status} has invalid JSON: {error}")
        });
        (status, value)
    }

    pub(super) async fn call(&self, service: &str, method: &str, value: Value) -> Value {
        let (status, reply) = self.request(service, method, value).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "{service}/{method}: {reply}"
        );
        reply
    }

    pub(super) async fn reviewed(
        &self,
        service: &str,
        plan: &str,
        apply: &str,
        value: Value,
        label: &str,
    ) -> Value {
        let mut value = value;
        value["idempotencyKey"] = json!(format!("{label}-plan"));
        let planned = self.call(service, plan, value).await;
        self.call(
            service,
            apply,
            json!({
                "planId": planned["plan"]["planId"],
                "confirmationHash": planned["plan"]["confirmationHash"],
                "idempotencyKey": format!("{label}-apply"),
            }),
        )
        .await
    }
}

pub(super) async fn create_target(api: &Api, fixture: &mut Fixture) -> Value {
    let org = api.reviewed("OrganizationService", "PlanCreateOrganization", "CreateOrganization",
        json!({"slug":"api-registration", "displayName":"API registration", "expectedResourceVersion":""}),
        "api-organization").await;
    let binding = api.reviewed("BindingService", "PlanCreateBinding", "CreateBinding", json!({
        "stableId":"api-registration-binding", "ownerScopeKey":org["organization"]["ownerScopeKey"],
        "expectedResourceVersion":"", "spec":{"name":"api-registration", "s3":{
            "bucket":"fixture-bucket", "prefix":"managed/api/.aos-direct-qualification/probe",
            "endpoint":{"scheme":"https", "dnsName":"s3.fleet.test", "port":443},
            "signingRegion":"fixture-region", "accessMode":"private"
        }}
    }), "api-binding").await["binding"].clone();
    fixture.binding_id = fixture
        .db
        .binding_by_stable_id(binding["stableId"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap()
        .id;
    binding
}

pub(super) fn credential_request(binding: &Value, purpose: &str, generation: i64) -> Value {
    json!({
        "bindingId": binding["stableId"], "purpose":purpose,
        "secretVersionRef":format!("secret://api-registration/{purpose}/v{}", generation + 1),
        "credentialFingerprint":hex::encode(Sha256::digest(MATERIAL)),
        "expectedResourceVersion":binding["resourceVersion"], "expectedCurrentGeneration":generation,
    })
}

#[tokio::test]
async fn hybrid_public_controls_register_stage_validate_retry_adopt_and_rotate_without_native_material(
) {
    use aos_hub::storage_work::HybridStorageCredentialProbeProvider;
    use aos_hub_core::topology_probe::{DomainProbeController, DomainTlsProbeVerifier};

    let _gate = TLS_TEST_GATE.lock().await;
    let mut fixture = fixture().await;
    let spy = Arc::new(ResolverSpy {
        calls: AtomicUsize::new(0),
        forbid: true,
    });
    let (client, origin, _, server) = custody_client(&fixture, CustodyFault::None).await;
    let api = Api::new(&fixture, spy.clone(), Some(client.clone())).await;
    let binding = create_target(&api, &mut fixture).await;
    let controller = DomainProbeController::new(
        fixture.db.clone(),
        Arc::new(aos_hub::coreports::HubHttpClient::new(
            reqwest::Client::new(),
        )),
        DomainTlsProbeVerifier::new(),
        "https://dns.example.test/resolve",
        "registration-controller",
    )
    .unwrap()
    .with_storage_credential_probe(Arc::new(HybridStorageCredentialProbeProvider::new(
        client.clone(),
        fixture.db.clone(),
    )));

    for purpose in ["read", "presign", "write"] {
        let credential = api
            .reviewed(
                "BindingService",
                "PlanSetBindingCredential",
                "SetBindingCredential",
                credential_request(&binding, purpose, 0),
                &format!("set-{purpose}"),
            )
            .await["credential"]
            .clone();
        assert_eq!(credential["validationState"], "unknown");
        let current_binding = fixture
            .db
            .binding(fixture.binding_id)
            .await
            .unwrap()
            .unwrap();
        assert!(client
            .ensure_remote_binding_snapshot(&fixture.db, &current_binding)
            .await
            .is_err());
        let operation = api.reviewed("BindingService", "PlanValidateBindingCredential", "ValidateBindingCredential",
            json!({"bindingId":binding["stableId"], "purpose":purpose, "generation":credential["generation"],
                "expectedResourceVersion":credential["resourceVersion"]}),
            &format!("validate-{purpose}")).await["operation"]["operationId"].as_str().unwrap().to_owned();

        let failed = if purpose == "read" {
            assert_eq!(controller.run_due(1).await.unwrap(), 1);
            let failed = api
                .call(
                    "OperationService",
                    "GetOperation",
                    json!({"operationId":operation}),
                )
                .await;
            assert_eq!(failed["operation"]["operation"]["state"], "failed");
            Some(failed)
        } else {
            None
        };
        stage_queued_credential(&fixture.db, &client, &operation, &MaterialResolver, 86400)
            .await
            .unwrap();
        if let Some(failed) = failed {
            let (status, _) = api.request("OperationService", "RetryOperation", json!({
                "operationId":operation, "expectedResourceVersion":"0", "idempotencyKey":"stale-retry"
            })).await;
            assert!(!status.is_success());
            api.call("OperationService", "RetryOperation", json!({
                "operationId":operation, "expectedResourceVersion":failed["operation"]["resourceVersion"],
                "idempotencyKey":"original-retry"
            })).await;
        }
        assert_eq!(controller.run_due(1).await.unwrap(), 1);
        let result = api
            .call(
                "OperationService",
                "GetOperation",
                json!({"operationId":operation}),
            )
            .await;
        assert_eq!(result["operation"]["operation"]["state"], "succeeded");
        let head = fixture
            .db
            .current_binding_credential(fixture.binding_id, purpose)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.validation_state, "valid");
        assert!(head.validated_at.is_some());
    }
    assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    let writes = api.call("BindingService", "ListBindingWriteRevisions", json!({
        "binding":{"organization":{"orgSlug":"api-registration", "name":"api-registration"}}, "pageSize":100
    })).await;
    assert_eq!(writes["revisions"].as_array().unwrap().len(), 1);
    assert_eq!(writes["revisions"][0]["validationState"], "valid");
    assert_eq!(writes["revisions"][0]["writesSupported"], true);
    let selected = fixture
        .db
        .binding_write_state(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.current_write_revision, Some(1));

    let cold =
        RemoteStorageWorkClient::new(&origin, "qualification-deployment".into(), KEY).unwrap();
    let current = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    assert!(cold.acknowledged_binding_snapshot(current.id).is_err());
    cold.ensure_remote_binding_snapshot(&fixture.db, &current)
        .await
        .unwrap();
    let original = cold.acknowledged_binding_snapshot(current.id).unwrap();
    assert_eq!(original.credentials.len(), 3);
    let rotated = api
        .reviewed(
            "BindingService",
            "PlanRotateBindingCredential",
            "RotateBindingCredential",
            credential_request(&binding, "read", 1),
            "rotate-read",
        )
        .await;
    assert_eq!(rotated["credential"]["validationState"], "unknown");
    assert!(cold
        .ensure_remote_binding_snapshot(&fixture.db, &current)
        .await
        .is_err());
    assert!(cold.acknowledged_binding_snapshot(current.id).is_err());
    assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn native_public_registration_still_resolves_and_checks_provider_bytes() {
    let mut fixture = fixture().await;
    let spy = Arc::new(ResolverSpy {
        calls: AtomicUsize::new(0),
        forbid: false,
    });
    let api = Api::new(&fixture, spy.clone(), None).await;
    let binding = create_target(&api, &mut fixture).await;
    let mut invalid = credential_request(&binding, "read", 0);
    invalid["credentialFingerprint"] = json!("f".repeat(64));
    invalid["idempotencyKey"] = json!("invalid-fingerprint");
    let (status, _) = api
        .request("BindingService", "PlanSetBindingCredential", invalid)
        .await;
    assert!(!status.is_success());
    assert_eq!(spy.calls.load(Ordering::SeqCst), 1);
    assert!(fixture
        .db
        .current_binding_credential(fixture.binding_id, "read")
        .await
        .unwrap()
        .is_none());
    let result = api
        .reviewed(
            "BindingService",
            "PlanSetBindingCredential",
            "SetBindingCredential",
            credential_request(&binding, "read", 0),
            "native-register",
        )
        .await;
    assert_eq!(result["credential"]["validationState"], "unknown");
    assert_eq!(spy.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn public_credential_apply_rejects_replaced_binding_identity_after_planning() {
    let _gate = TLS_TEST_GATE.lock().await;
    let mut fixture = fixture().await;
    let spy = Arc::new(ResolverSpy {
        calls: AtomicUsize::new(0),
        forbid: true,
    });
    let (client, _, _, server) = custody_client(&fixture, CustodyFault::None).await;
    let api = Api::new(&fixture, spy.clone(), Some(client)).await;
    let binding = create_target(&api, &mut fixture).await;
    let mut request = credential_request(&binding, "read", 0);
    request["idempotencyKey"] = json!("binding-race-plan");
    let planned = api
        .call("BindingService", "PlanSetBindingCredential", request)
        .await;
    api.reviewed(
        "BindingService",
        "PlanDeleteBinding",
        "DeleteBinding",
        json!({
            "stableId":binding["stableId"], "expectedResourceVersion":binding["resourceVersion"],
        }),
        "replace-binding-delete",
    )
    .await;
    let mut intermediate_spec = binding["spec"].clone();
    intermediate_spec["name"] = json!("intermediate-registration");
    api.reviewed(
        "BindingService",
        "PlanCreateBinding",
        "CreateBinding",
        json!({
            "stableId":"intermediate-registration-binding", "ownerScopeKey":binding["ownerScopeKey"],
            "expectedResourceVersion":"", "spec":intermediate_spec,
        }),
        "intermediate-binding-create",
    )
    .await;
    let replacement = api
        .reviewed(
            "BindingService",
            "PlanCreateBinding",
            "CreateBinding",
            json!({
                "stableId":"replacement-registration-binding", "ownerScopeKey":binding["ownerScopeKey"],
                "expectedResourceVersion":"", "spec":binding["spec"],
            }),
            "replace-binding-create",
        )
        .await;
    let replaced = fixture
        .db
        .binding_by_stable_id(replacement["binding"]["stableId"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(replaced.id, fixture.binding_id);
    fixture.binding_id = replaced.id;
    let (status, _) = api.request("BindingService", "SetBindingCredential", json!({
        "planId":planned["plan"]["planId"], "confirmationHash":planned["plan"]["confirmationHash"],
        "idempotencyKey":"binding-race-apply"
    })).await;
    assert!(!status.is_success());
    assert!(fixture
        .db
        .current_binding_credential(fixture.binding_id, "read")
        .await
        .unwrap()
        .is_none());
    assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}
