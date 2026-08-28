//! Native Connect-JSON coverage for OCI container administration.

use std::net::SocketAddr;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use aos_proto_types as pb;
use reqwest::StatusCode;

const TEST_JWT_SECRET: &[u8] = b"native-container-admin-test-secret";

struct RunningHub {
    _server: tokio::task::JoinHandle<()>,
    db: Arc<Database>,
    keys: JwtKeys,
    org_id: i64,
    registry: String,
    registry_id: i64,
    origin: String,
}

impl Drop for RunningHub {
    fn drop(&mut self) {
        self._server.abort();
    }
}

impl RunningHub {
    async fn bearer(&self, email: &str, token_id: &str) -> String {
        self.bearer_with_permissions(
            email,
            token_id,
            self.registry_id,
            vec![
                Permission::Read,
                Permission::Publish,
                Permission::RegistryConfigure,
            ],
        )
        .await
    }

    async fn bearer_with_permissions(
        &self,
        email: &str,
        token_id: &str,
        registry_id: i64,
        permissions: Vec<Permission>,
    ) -> String {
        let user_id = self.db.create_user(email, Some(email)).await.unwrap();
        let org = self.db.org_by_id(self.org_id).await.unwrap().unwrap();
        self.db
            .grant_membership("user", user_id, &org.stable_id, "owner")
            .await
            .unwrap();
        let scope = self
            .db
            .registry_authorization_scope(registry_id)
            .await
            .unwrap();
        self.keys
            .mint(
                &TokenAuth {
                    token_id: token_id.to_string(),
                    owner: Principal::user(user_id),
                    scope: Scope::parse(&scope),
                    permissions,
                },
                900,
            )
            .unwrap()
    }

    async fn response<Req>(
        &self,
        method: &str,
        bearer: Option<&str>,
        request: &Req,
    ) -> reqwest::Response
    where
        Req: serde::Serialize + ?Sized,
    {
        let request = reqwest::Client::new()
            .post(format!(
                "{}{}/{}",
                self.origin, "aos.hub.v1.ContainerService", method
            ))
            .header("connect-protocol-version", "1")
            .json(request);
        let request = if let Some(bearer) = bearer {
            request.bearer_auth(bearer)
        } else {
            request
        };
        request.send().await.unwrap()
    }

    async fn call<Req, Resp>(&self, method: &str, bearer: &str, request: &Req) -> Resp
    where
        Req: serde::Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let response = reqwest::Client::new()
            .post(format!(
                "{}{}/{}",
                self.origin, "aos.hub.v1.ContainerService", method
            ))
            .bearer_auth(bearer)
            .header("connect-protocol-version", "1")
            .json(request)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.bytes().await.unwrap();
        assert!(
            status.is_success(),
            "{method} returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
        serde_json::from_slice(&body).unwrap()
    }
}

#[tokio::test]
async fn publication_inventory_requires_publish_permission_even_for_public_registries() {
    let hub = spawn_hub().await;
    let public_registry_id = hub
        .db
        .create_managed_registry(hub.org_id, "", "public", "public", &[], false)
        .await
        .unwrap();
    let public_registry = hub
        .db
        .registry_by_id(public_registry_id)
        .await
        .unwrap()
        .unwrap();
    let publisher = hub
        .bearer_with_permissions(
            "publisher@example.test",
            "publisher-token",
            public_registry_id,
            vec![Permission::Read, Permission::Publish],
        )
        .await;
    let private_reader = hub
        .bearer_with_permissions(
            "reader@example.test",
            "reader-token",
            hub.registry_id,
            vec![Permission::Read],
        )
        .await;

    let public_list = pb::ListContainerPublicationsRequest {
        registry: public_registry.slug.clone(),
        ..Default::default()
    };
    assert_eq!(
        hub.response("ListContainerPublications", None, &public_list)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let listed: pb::ListContainerPublicationsResponse = hub
        .call("ListContainerPublications", &publisher, &public_list)
        .await;
    assert!(listed.publications.is_empty());

    let private_list = pb::ListContainerPublicationsRequest {
        registry: hub.registry.clone(),
        ..Default::default()
    };
    assert_eq!(
        hub.response(
            "ListContainerPublications",
            Some(&private_reader),
            &private_list,
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );

    let public_get = pb::GetContainerPublicationRequest {
        publication_id: "missing-publication".to_string(),
        registry: public_registry.slug,
    };
    assert_eq!(
        hub.response("GetContainerPublication", None, &public_get)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hub.response("GetContainerPublication", Some(&publisher), &public_get,)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let private_get = pb::GetContainerPublicationRequest {
        publication_id: "missing-publication".to_string(),
        registry: hub.registry.clone(),
    };
    assert_eq!(
        hub.response(
            "GetContainerPublication",
            Some(&private_reader),
            &private_get,
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
}

async fn spawn_hub() -> RunningHub {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db
        .create_org("container-admin", "Container Admin")
        .await
        .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let keys = JwtKeys::from_secret(TEST_JWT_SECRET);
    let ratelimit = Arc::new(aos_hub::ratelimit::RateLimiter::new());
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: keys.clone(),
        access_token_ttl: 900,
        ratelimit: Arc::clone(&ratelimit),
        trusted_proxy: false,
    });
    let state = Arc::new(AppState {
        db: Arc::clone(&db),
        external_url: origin.trim_end_matches('/').to_string(),
        auth,
        leases: Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        ratelimit,
        trusted_proxy: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
    });
    let app = router(state).await;
    let server = tokio::spawn(async move {
        let result = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
        assert!(
            result.is_ok(),
            "native container-admin server failed: {result:?}"
        );
    });

    RunningHub {
        _server: server,
        db,
        keys,
        org_id,
        registry: registry.slug,
        registry_id,
        origin,
    }
}

#[tokio::test]
async fn reviewed_container_administration_is_private_actor_bound_and_idempotent() {
    let hub = spawn_hub().await;
    let owner = hub.bearer("owner@example.test", "owner-token").await;
    let other = hub.bearer("other@example.test", "other-token").await;

    let unauthenticated = reqwest::Client::new()
        .post(format!(
            "{}aos.hub.v1.ContainerService/ListContainerRepositories",
            hub.origin
        ))
        .header("connect-protocol-version", "1")
        .json(&pb::ListContainerRepositoriesRequest {
            registry: hub.registry.clone(),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let planned: pb::TopologyPlanResponse = hub
        .call(
            "PlanCreateContainerRepository",
            &owner,
            &pb::PlanCreateContainerRepositoryRequest {
                registry: hub.registry.clone(),
                repository: "base/runtime".to_string(),
                description: "Base runtime".to_string(),
                expected_resource_version: String::new(),
                idempotency_key: "plan-create-base".to_string(),
            },
        )
        .await;
    let plan = planned.plan.unwrap();
    assert!(plan.expires_at > 0);
    assert!(!plan.confirmation_hash.is_empty());

    let cross_actor = reqwest::Client::new()
        .post(format!(
            "{}aos.hub.v1.ContainerService/CreateContainerRepository",
            hub.origin
        ))
        .bearer_auth(&other)
        .header("connect-protocol-version", "1")
        .json(&pb::ApplyContainerMutationRequest {
            plan_id: plan.plan_id.clone(),
            idempotency_key: "apply-create-base".to_string(),
            confirmation_hash: plan.confirmation_hash.clone(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_actor.status(), StatusCode::NOT_FOUND);

    let apply = pb::ApplyContainerMutationRequest {
        plan_id: plan.plan_id,
        idempotency_key: "apply-create-base".to_string(),
        confirmation_hash: plan.confirmation_hash,
    };
    let created: pb::ContainerRepositoryResponse =
        hub.call("CreateContainerRepository", &owner, &apply).await;
    let created = created.repository.unwrap();
    assert_eq!(created.repository, "base/runtime");
    assert_eq!(created.description, "Base runtime");
    assert!(created.distribution_reference.is_empty());
    let created_version = created.resource_version.clone();
    let replayed: pb::ContainerRepositoryResponse =
        hub.call("CreateContainerRepository", &owner, &apply).await;
    assert_eq!(replayed.repository, Some(created.clone()));

    let listed: pb::ListContainerRepositoriesResponse = hub
        .call(
            "ListContainerRepositories",
            &owner,
            &pb::ListContainerRepositoriesRequest {
                registry: hub.registry.clone(),
                repository_prefix: "base/".to_string(),
                lifecycle_state: "active".to_string(),
                page_size: 10,
                page_token: String::new(),
            },
        )
        .await;
    assert_eq!(listed.repositories, vec![created]);
    assert!(!listed.mutation_epoch.is_empty());

    let defaults: pb::ContainerRetentionPolicyResponse = hub
        .call(
            "GetContainerRetentionPolicy",
            &owner,
            &pb::GetContainerRetentionPolicyRequest {
                registry: hub.registry.clone(),
            },
        )
        .await;
    let defaults = defaults.policy.unwrap();
    assert!(defaults.untagged_grace_period_secs > 0);
    assert!(defaults.deleted_tag_history_period_secs > 0);
    assert!(defaults.retain_referrers);
    assert!(defaults.resource_version.is_empty());

    let retention_plan: pb::TopologyPlanResponse = hub
        .call(
            "PlanSetContainerRetentionPolicy",
            &owner,
            &pb::PlanSetContainerRetentionPolicyRequest {
                registry: hub.registry.clone(),
                policy: Some(pb::ContainerRetentionPolicy {
                    registry: hub.registry.clone(),
                    untagged_grace_period_secs: 86_400,
                    deleted_tag_history_period_secs: 604_800,
                    recent_manual_tag_revisions: 4,
                    retain_referrers: true,
                    resource_version: String::new(),
                    updated_at: 0,
                }),
                expected_resource_version: String::new(),
                idempotency_key: "plan-retention".to_string(),
            },
        )
        .await;
    let retention_plan = retention_plan.plan.unwrap();
    let retained: pb::ContainerRetentionPolicyResponse = hub
        .call(
            "SetContainerRetentionPolicy",
            &owner,
            &pb::ApplyContainerMutationRequest {
                plan_id: retention_plan.plan_id,
                idempotency_key: "apply-retention".to_string(),
                confirmation_hash: retention_plan.confirmation_hash,
            },
        )
        .await;
    let policy = retained.policy.unwrap();
    assert_eq!(policy.recent_manual_tag_revisions, 4);
    assert_eq!(policy.deleted_tag_history_period_secs, 604_800);

    let gc_plan = pb::PlanRunContainerGcRequest {
        registry: hub.registry.clone(),
        expected_resource_version: policy.resource_version,
        idempotency_key: "plan-gc".to_string(),
    };
    let gc_apply = pb::ApplyContainerMutationRequest {
        plan_id: "missing-gc-plan".to_string(),
        idempotency_key: "apply-gc".to_string(),
        confirmation_hash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    };
    let gc_get = pb::GetContainerGcRunRequest {
        registry: hub.registry.clone(),
        run_id: "missing-gc-run".to_string(),
    };
    let gc_list = pb::ListContainerGcRunsRequest {
        registry: hub.registry.clone(),
        ..Default::default()
    };

    for (method, status) in [
        (
            "PlanRunContainerGc",
            hub.response("PlanRunContainerGc", None, &gc_plan)
                .await
                .status(),
        ),
        (
            "RunContainerGc",
            hub.response("RunContainerGc", None, &gc_apply)
                .await
                .status(),
        ),
        (
            "GetContainerGcRun",
            hub.response("GetContainerGcRun", None, &gc_get)
                .await
                .status(),
        ),
        (
            "ListContainerGcRuns",
            hub.response("ListContainerGcRuns", None, &gc_list)
                .await
                .status(),
        ),
    ] {
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method}");
    }

    let mut unavailable = Vec::new();
    unavailable.push(
        hub.response("PlanRunContainerGc", Some(&owner), &gc_plan)
            .await,
    );
    unavailable.push(
        hub.response("RunContainerGc", Some(&owner), &gc_apply)
            .await,
    );
    unavailable.push(
        hub.response("GetContainerGcRun", Some(&owner), &gc_get)
            .await,
    );
    unavailable.push(
        hub.response("ListContainerGcRuns", Some(&owner), &gc_list)
            .await,
    );
    for response in unavailable {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let envelope: serde_json::Value = response.json().await.unwrap();
        assert_eq!(envelope["code"], "unavailable");
    }

    let deletion_plan: pb::TopologyPlanResponse = hub
        .call(
            "PlanDeleteContainerRepository",
            &owner,
            &pb::PlanDeleteContainerRepositoryRequest {
                registry: hub.registry.clone(),
                repository: "base/runtime".to_string(),
                expected_resource_version: created_version.clone(),
                idempotency_key: "plan-delete-base".to_string(),
            },
        )
        .await;
    let deletion_plan = deletion_plan.plan.unwrap();
    let deleted: pb::ContainerDeletionResponse = hub
        .call(
            "DeleteContainerRepository",
            &owner,
            &pb::ApplyContainerMutationRequest {
                plan_id: deletion_plan.plan_id,
                idempotency_key: "apply-delete-base".to_string(),
                confirmation_hash: deletion_plan.confirmation_hash,
            },
        )
        .await;
    assert!(deleted.deleted);
    assert_eq!(
        deleted.resource_version.parse::<i64>().unwrap(),
        created_version.parse::<i64>().unwrap() + 1
    );
}
