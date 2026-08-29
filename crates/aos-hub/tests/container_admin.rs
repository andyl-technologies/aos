//! Native Connect-JSON coverage for OCI container administration.

use std::net::SocketAddr;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{
    Database, OciRegistryPurgeFenceAction, PlanOciGc, PlanOciRegistryPurgeFence, TokenAuth,
};
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

    async fn seed_gc_plan(&self, bearer: &str, idempotency_key: &str) -> String {
        let actor_id = self.keys.verify(bearer).unwrap().sub;
        self.db
            .plan_oci_gc(&PlanOciGc {
                registry_id: self.registry_id,
                actor_id,
                idempotency_key: idempotency_key.to_string(),
                expected_resource_version: 0,
                now: aos_hub_core::clock::now_unix_secs(),
            })
            .await
            .unwrap()
            .id
    }

    async fn seed_purge_fence_plan(
        &self,
        bearer: &str,
        idempotency_key: &str,
    ) -> (String, String, String) {
        let actor_id = self.keys.verify(bearer).unwrap().sub;
        let registry = self
            .db
            .registry_by_id(self.registry_id)
            .await
            .unwrap()
            .unwrap();
        let plan = self
            .db
            .plan_oci_registry_purge_fence(&PlanOciRegistryPurgeFence {
                registry_id: self.registry_id,
                action: OciRegistryPurgeFenceAction::Begin,
                actor_id,
                idempotency_key: idempotency_key.to_string(),
                expected_resource_version: registry.resource_version,
                now: aos_hub_core::clock::now_unix_secs(),
            })
            .await
            .unwrap();
        (
            plan.id,
            plan.resource_version.to_string(),
            plan.confirmation_hash.to_string(),
        )
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
    spawn_hub_with_rollout(aos_hub_core::container_rollout::ContainerRollout::all_enabled()).await
}

async fn spawn_hub_with_rollout(
    container_rollout: aos_hub_core::container_rollout::ContainerRollout,
) -> RunningHub {
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
        container_rollout,
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
async fn direct_connect_requests_cannot_bypass_container_rollout_gates() {
    let hub =
        spawn_hub_with_rollout(aos_hub_core::container_rollout::ContainerRollout::default()).await;
    let owner = hub
        .bearer("rollout-owner@example.test", "rollout-owner")
        .await;

    let read = hub
        .response(
            "ListContainerRepositories",
            Some(&owner),
            &pb::ListContainerRepositoriesRequest {
                registry: hub.registry.clone(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(read.status(), StatusCode::OK);

    let administration = hub
        .response(
            "PlanCreateContainerRepository",
            Some(&owner),
            &pb::PlanCreateContainerRepositoryRequest {
                registry: hub.registry.clone(),
                repository: "disabled/admin".to_string(),
                idempotency_key: "disabled-admin-plan".to_string(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(administration.status(), StatusCode::SERVICE_UNAVAILABLE);

    let publication = hub
        .response(
            "BeginContainerPublication",
            Some(&owner),
            &pb::BeginContainerPublicationRequest {
                registry: hub.registry.clone(),
                repository: "aos".to_string(),
                idempotency_key: "disabled-publication".to_string(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(publication.status(), StatusCode::SERVICE_UNAVAILABLE);

    let garbage_collection = hub
        .response(
            "PlanRunContainerGc",
            Some(&owner),
            &pb::PlanRunContainerGcRequest {
                registry: hub.registry.clone(),
                expected_resource_version: "0".to_string(),
                idempotency_key: "disabled-gc".to_string(),
            },
        )
        .await;
    assert_eq!(garbage_collection.status(), StatusCode::SERVICE_UNAVAILABLE);

    for (method, status) in [
        (
            "GetContainerGcRun",
            hub.response(
                "GetContainerGcRun",
                Some(&owner),
                &pb::GetContainerGcRunRequest {
                    registry: hub.registry.clone(),
                    run_id: "gc-run".to_string(),
                },
            )
            .await
            .status(),
        ),
        (
            "ListContainerGcRuns",
            hub.response(
                "ListContainerGcRuns",
                Some(&owner),
                &pb::ListContainerGcRunsRequest {
                    registry: hub.registry.clone(),
                    ..Default::default()
                },
            )
            .await
            .status(),
        ),
        (
            "ListContainerGcCandidates",
            hub.response(
                "ListContainerGcCandidates",
                Some(&owner),
                &pb::ListContainerGcCandidatesRequest {
                    registry: hub.registry.clone(),
                    run_id: "gc-run".to_string(),
                    ..Default::default()
                },
            )
            .await
            .status(),
        ),
        (
            "ListContainerGcBlockers",
            hub.response(
                "ListContainerGcBlockers",
                Some(&owner),
                &pb::ListContainerGcBlockersRequest {
                    registry: hub.registry.clone(),
                    run_id: "gc-run".to_string(),
                },
            )
            .await
            .status(),
        ),
        (
            "ListContainerGcPlacementActions",
            hub.response(
                "ListContainerGcPlacementActions",
                Some(&owner),
                &pb::ListContainerGcPlacementActionsRequest {
                    registry: hub.registry.clone(),
                    run_id: "gc-run".to_string(),
                    ..Default::default()
                },
            )
            .await
            .status(),
        ),
        (
            "ListContainerUntrackedInventory",
            hub.response(
                "ListContainerUntrackedInventory",
                Some(&owner),
                &pb::ListContainerUntrackedInventoryRequest {
                    registry: hub.registry.clone(),
                    ..Default::default()
                },
            )
            .await
            .status(),
        ),
    ] {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method}");
    }

    let gc_requeue = hub
        .response(
            "RequeueContainerGcPlacementAction",
            Some(&owner),
            &pb::RequeueContainerGcPlacementActionRequest {
                registry: hub.registry.clone(),
                run_id: "gc-run".to_string(),
                action_id: "gc-action".to_string(),
                expected_resource_version: "1".to_string(),
                idempotency_key: "disabled-gc-requeue".to_string(),
            },
        )
        .await;
    assert_eq!(gc_requeue.status(), StatusCode::SERVICE_UNAVAILABLE);

    let repair_plan = hub
        .response(
            "PlanRepairContainerUntrackedObject",
            Some(&owner),
            &pb::PlanRepairContainerUntrackedObjectRequest {
                registry: hub.registry.clone(),
                placement_id: 1,
                inventory_generation_id: "inventory".to_string(),
                object_key: "oci/blobs/sha256/missing".to_string(),
                expected_resource_version: "0".to_string(),
                idempotency_key: "disabled-untracked-repair".to_string(),
            },
        )
        .await;
    assert_eq!(repair_plan.status(), StatusCode::SERVICE_UNAVAILABLE);

    let repair_apply = hub
        .response(
            "RepairContainerUntrackedObject",
            Some(&owner),
            &pb::RepairContainerUntrackedObjectRequest {
                plan_id: "missing-repair".to_string(),
                idempotency_key: "disabled-untracked-apply".to_string(),
                confirmation_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                expected_resource_version: "1".to_string(),
            },
        )
        .await;
    assert_eq!(repair_apply.status(), StatusCode::NOT_FOUND);

    let repair_status = hub
        .response(
            "GetContainerUntrackedRepair",
            Some(&owner),
            &pb::GetContainerUntrackedRepairRequest {
                plan_id: "missing-repair".to_string(),
            },
        )
        .await;
    assert_eq!(repair_status.status(), StatusCode::NOT_FOUND);

    let purge_plan = hub
        .response(
            "PlanContainerRegistryPurgeFence",
            Some(&owner),
            &pb::PlanContainerRegistryPurgeFenceRequest {
                registry: hub.registry.clone(),
                action: pb::ContainerRegistryPurgeFenceAction::Begin as i32,
                expected_resource_version: "1".to_string(),
                idempotency_key: "disabled-purge-fence".to_string(),
            },
        )
        .await;
    assert_eq!(purge_plan.status(), StatusCode::SERVICE_UNAVAILABLE);
    for (method, status) in [
        (
            "ApplyContainerRegistryPurgeFence",
            hub.response(
                "ApplyContainerRegistryPurgeFence",
                Some(&owner),
                &pb::ApplyContainerRegistryPurgeFenceRequest {
                    plan_id: "missing-purge-fence".to_string(),
                    idempotency_key: "disabled-purge-fence-apply".to_string(),
                    confirmation_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    expected_resource_version: "1".to_string(),
                },
            )
            .await
            .status(),
        ),
        (
            "GetContainerRegistryPurgeFence",
            hub.response(
                "GetContainerRegistryPurgeFence",
                Some(&owner),
                &pb::GetContainerRegistryPurgeFenceRequest {
                    plan_id: "missing-purge-fence".to_string(),
                },
            )
            .await
            .status(),
        ),
    ] {
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
    }
}

#[tokio::test]
async fn gc_apply_masks_actor_and_registry_authorization_before_disabled_rollout() {
    let hub =
        spawn_hub_with_rollout(aos_hub_core::container_rollout::ContainerRollout::default()).await;
    let owner = hub.bearer("gc-owner@example.test", "gc-owner-token").await;
    let other = hub.bearer("gc-other@example.test", "gc-other-token").await;
    let reader = hub
        .bearer_with_permissions(
            "gc-reader@example.test",
            "gc-reader-token",
            hub.registry_id,
            vec![Permission::Read],
        )
        .await;
    let owner_plan = hub.seed_gc_plan(&owner, "disabled-owner-plan").await;
    let reader_plan = hub.seed_gc_plan(&reader, "disabled-reader-plan").await;
    let apply = |plan_id: String| pb::ApplyContainerMutationRequest {
        plan_id,
        idempotency_key: "disabled-apply".to_string(),
        confirmation_hash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    };

    assert_eq!(
        hub.response("RunContainerGc", None, &apply(owner_plan.clone()))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let missing = hub
        .response(
            "RunContainerGc",
            Some(&owner),
            &apply("missing-gc-plan".to_string()),
        )
        .await;
    let missing_status = missing.status();
    let missing_body = missing.bytes().await.unwrap();
    let wrong_actor = hub
        .response("RunContainerGc", Some(&other), &apply(owner_plan.clone()))
        .await;
    let wrong_actor_status = wrong_actor.status();
    let wrong_actor_body = wrong_actor.bytes().await.unwrap();
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(wrong_actor_status, missing_status);
    assert_eq!(wrong_actor_body, missing_body);

    assert_eq!(
        hub.response("RunContainerGc", Some(&reader), &apply(reader_plan))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        hub.response("RunContainerGc", Some(&owner), &apply(owner_plan))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn purge_fence_apply_masks_actor_and_registry_authorization_before_disabled_rollout() {
    let hub =
        spawn_hub_with_rollout(aos_hub_core::container_rollout::ContainerRollout::default()).await;
    let owner = hub
        .bearer("purge-owner@example.test", "purge-owner-token")
        .await;
    let other = hub
        .bearer("purge-other@example.test", "purge-other-token")
        .await;
    let reader = hub
        .bearer_with_permissions(
            "purge-reader@example.test",
            "purge-reader-token",
            hub.registry_id,
            vec![Permission::Read],
        )
        .await;
    let owner_plan = hub
        .seed_purge_fence_plan(&owner, "disabled-owner-purge-fence")
        .await;
    let reader_plan = hub
        .seed_purge_fence_plan(&reader, "disabled-reader-purge-fence")
        .await;
    let apply = |plan: &(String, String, String)| pb::ApplyContainerRegistryPurgeFenceRequest {
        plan_id: plan.0.clone(),
        idempotency_key: "disabled-purge-fence-apply".to_string(),
        confirmation_hash: plan.2.clone(),
        expected_resource_version: plan.1.clone(),
    };

    assert_eq!(
        hub.response(
            "ApplyContainerRegistryPurgeFence",
            None,
            &apply(&owner_plan)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let missing = hub
        .response(
            "ApplyContainerRegistryPurgeFence",
            Some(&owner),
            &pb::ApplyContainerRegistryPurgeFenceRequest {
                plan_id: "missing-purge-fence-plan".to_string(),
                ..apply(&owner_plan)
            },
        )
        .await;
    let wrong_actor = hub
        .response(
            "ApplyContainerRegistryPurgeFence",
            Some(&other),
            &apply(&owner_plan),
        )
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(wrong_actor.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        missing.bytes().await.unwrap(),
        wrong_actor.bytes().await.unwrap()
    );
    assert_eq!(
        hub.response(
            "ApplyContainerRegistryPurgeFence",
            Some(&reader),
            &apply(&reader_plan),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        hub.response(
            "ApplyContainerRegistryPurgeFence",
            Some(&owner),
            &apply(&owner_plan),
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn enabled_gc_plan_replay_returns_the_same_actor_bound_review() {
    let hub = spawn_hub().await;
    let owner = hub
        .bearer("gc-replay@example.test", "gc-replay-token")
        .await;
    let request = pb::PlanRunContainerGcRequest {
        registry: hub.registry.clone(),
        expected_resource_version: "0".to_string(),
        idempotency_key: "same-enabled-gc-plan".to_string(),
    };

    let first: pb::ContainerGcPlanResponse = hub.call("PlanRunContainerGc", &owner, &request).await;
    let replay: pb::ContainerGcPlanResponse =
        hub.call("PlanRunContainerGc", &owner, &request).await;
    assert_eq!(replay, first);
    assert!(!first.plan.unwrap().plan_id.is_empty());
}

#[tokio::test]
async fn enabled_purge_fence_plan_apply_status_and_replay_preserve_exact_identity() {
    let hub = spawn_hub().await;
    let owner = hub
        .bearer("purge-replay@example.test", "purge-replay-token")
        .await;
    let other = hub
        .bearer(
            "purge-replay-other@example.test",
            "purge-replay-other-token",
        )
        .await;
    let registry = hub
        .db
        .registry_by_id(hub.registry_id)
        .await
        .unwrap()
        .unwrap();
    let request = pb::PlanContainerRegistryPurgeFenceRequest {
        registry: hub.registry.clone(),
        action: pb::ContainerRegistryPurgeFenceAction::Begin as i32,
        expected_resource_version: registry.resource_version.to_string(),
        idempotency_key: "same-enabled-purge-fence-plan".to_string(),
    };
    let first: pb::TopologyPlanResponse = hub
        .call("PlanContainerRegistryPurgeFence", &owner, &request)
        .await;
    let replay: pb::TopologyPlanResponse = hub
        .call("PlanContainerRegistryPurgeFence", &owner, &request)
        .await;
    assert_eq!(replay, first);
    let plan = first.plan.unwrap();
    let expected_resource_version = plan
        .input_versions
        .iter()
        .find_map(|value| value.strip_prefix("resource_version="))
        .unwrap()
        .to_string();
    let apply = pb::ApplyContainerRegistryPurgeFenceRequest {
        plan_id: plan.plan_id.clone(),
        idempotency_key: "same-enabled-purge-fence-apply".to_string(),
        confirmation_hash: plan.confirmation_hash,
        expected_resource_version,
    };
    let applied: pb::ContainerRegistryPurgeFenceResponse = hub
        .call("ApplyContainerRegistryPurgeFence", &owner, &apply)
        .await;
    let replayed: pb::ContainerRegistryPurgeFenceResponse = hub
        .call("ApplyContainerRegistryPurgeFence", &owner, &apply)
        .await;
    assert_eq!(replayed, applied);
    let fence = applied.fence.as_ref().unwrap();
    assert_eq!(fence.plan_id, plan.plan_id);
    assert_eq!(fence.plan_state, "applied");
    assert_eq!(fence.fence_state, "collecting");
    assert!(!fence.fence_resource_version.is_empty());
    assert!(fence.post_fence_inventory_ready);

    let get = pb::GetContainerRegistryPurgeFenceRequest {
        plan_id: plan.plan_id,
    };
    let status: pb::ContainerRegistryPurgeFenceResponse = hub
        .call("GetContainerRegistryPurgeFence", &owner, &get)
        .await;
    assert_eq!(status, applied);
    assert_eq!(
        hub.response("GetContainerRegistryPurgeFence", Some(&other), &get)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn untracked_inventory_requires_registry_configuration_before_provider_lookup() {
    let hub = spawn_hub().await;
    let owner = hub
        .bearer("untracked-owner@example.test", "untracked-owner")
        .await;
    let reader = hub
        .bearer_with_permissions(
            "untracked-reader@example.test",
            "untracked-reader",
            hub.registry_id,
            vec![Permission::Read],
        )
        .await;
    let list = pb::ListContainerUntrackedInventoryRequest {
        registry: hub.registry.clone(),
        page_size: 10,
        page_token: String::new(),
    };

    assert_eq!(
        hub.response("ListContainerUntrackedInventory", Some(&reader), &list)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let listed: pb::ListContainerUntrackedInventoryResponse = hub
        .call("ListContainerUntrackedInventory", &owner, &list)
        .await;
    assert!(listed.objects.is_empty());
    assert_eq!(listed.inventory_epoch, "0");

    let plan = pb::PlanRepairContainerUntrackedObjectRequest {
        registry: hub.registry.clone(),
        placement_id: 1,
        inventory_generation_id: "inventory".to_string(),
        object_key: "oci/blobs/sha256/missing".to_string(),
        expected_resource_version: listed.inventory_epoch,
        idempotency_key: "missing-untracked".to_string(),
    };
    assert_eq!(
        hub.response("PlanRepairContainerUntrackedObject", Some(&reader), &plan,)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = hub
        .response("PlanRepairContainerUntrackedObject", Some(&owner), &plan)
        .await;
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["code"], "failed_precondition");
    assert_eq!(
        error["message"],
        "untracked provider evidence is no longer repairable"
    );
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
        expected_resource_version: policy.resource_version.clone(),
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
    let gc_candidates = pb::ListContainerGcCandidatesRequest {
        registry: hub.registry.clone(),
        run_id: "missing-gc-run".to_string(),
        ..Default::default()
    };
    let gc_blockers = pb::ListContainerGcBlockersRequest {
        registry: hub.registry.clone(),
        run_id: "missing-gc-run".to_string(),
    };
    let gc_actions = pb::ListContainerGcPlacementActionsRequest {
        registry: hub.registry.clone(),
        run_id: "missing-gc-run".to_string(),
        ..Default::default()
    };
    let gc_requeue = pb::RequeueContainerGcPlacementActionRequest {
        registry: hub.registry.clone(),
        run_id: "missing-gc-run".to_string(),
        action_id: "missing-gc-action".to_string(),
        expected_resource_version: "1".to_string(),
        idempotency_key: "requeue-gc".to_string(),
    };
    let untracked_list = pb::ListContainerUntrackedInventoryRequest {
        registry: hub.registry.clone(),
        ..Default::default()
    };
    let untracked_plan = pb::PlanRepairContainerUntrackedObjectRequest {
        registry: hub.registry.clone(),
        placement_id: 1,
        inventory_generation_id: "inventory".to_string(),
        object_key: "oci/blobs/sha256/missing".to_string(),
        expected_resource_version: "0".to_string(),
        idempotency_key: "plan-untracked".to_string(),
    };
    let untracked_apply = pb::RepairContainerUntrackedObjectRequest {
        plan_id: "missing-untracked-plan".to_string(),
        idempotency_key: "apply-untracked".to_string(),
        confirmation_hash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        expected_resource_version: "1".to_string(),
    };
    let untracked_status = pb::GetContainerUntrackedRepairRequest {
        plan_id: "missing-untracked-plan".to_string(),
    };
    let purge_plan = pb::PlanContainerRegistryPurgeFenceRequest {
        registry: hub.registry.clone(),
        action: pb::ContainerRegistryPurgeFenceAction::Begin as i32,
        expected_resource_version: "1".to_string(),
        idempotency_key: "plan-purge-fence".to_string(),
    };
    let purge_apply = pb::ApplyContainerRegistryPurgeFenceRequest {
        plan_id: "missing-purge-fence-plan".to_string(),
        idempotency_key: "apply-purge-fence".to_string(),
        confirmation_hash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        expected_resource_version: "1".to_string(),
    };
    let purge_status = pb::GetContainerRegistryPurgeFenceRequest {
        plan_id: "missing-purge-fence-plan".to_string(),
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
        (
            "ListContainerGcCandidates",
            hub.response("ListContainerGcCandidates", None, &gc_candidates)
                .await
                .status(),
        ),
        (
            "ListContainerGcBlockers",
            hub.response("ListContainerGcBlockers", None, &gc_blockers)
                .await
                .status(),
        ),
        (
            "ListContainerGcPlacementActions",
            hub.response("ListContainerGcPlacementActions", None, &gc_actions)
                .await
                .status(),
        ),
        (
            "RequeueContainerGcPlacementAction",
            hub.response("RequeueContainerGcPlacementAction", None, &gc_requeue)
                .await
                .status(),
        ),
        (
            "ListContainerUntrackedInventory",
            hub.response("ListContainerUntrackedInventory", None, &untracked_list)
                .await
                .status(),
        ),
        (
            "PlanRepairContainerUntrackedObject",
            hub.response("PlanRepairContainerUntrackedObject", None, &untracked_plan)
                .await
                .status(),
        ),
        (
            "RepairContainerUntrackedObject",
            hub.response("RepairContainerUntrackedObject", None, &untracked_apply)
                .await
                .status(),
        ),
        (
            "GetContainerUntrackedRepair",
            hub.response("GetContainerUntrackedRepair", None, &untracked_status)
                .await
                .status(),
        ),
        (
            "PlanContainerRegistryPurgeFence",
            hub.response("PlanContainerRegistryPurgeFence", None, &purge_plan)
                .await
                .status(),
        ),
        (
            "ApplyContainerRegistryPurgeFence",
            hub.response("ApplyContainerRegistryPurgeFence", None, &purge_apply)
                .await
                .status(),
        ),
        (
            "GetContainerRegistryPurgeFence",
            hub.response("GetContainerRegistryPurgeFence", None, &purge_status)
                .await
                .status(),
        ),
    ] {
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method}");
    }

    let planned_gc: pb::ContainerGcPlanResponse =
        hub.call("PlanRunContainerGc", &owner, &gc_plan).await;
    let gc_run = planned_gc.run.as_ref().unwrap();
    let gc_topology = planned_gc.plan.as_ref().unwrap();
    assert_eq!(gc_topology.plan_id, gc_run.run_id);
    assert_eq!(gc_topology.confirmation_hash, gc_run.confirmation_hash);
    assert!(!gc_run.plan_digest.is_empty());
    assert_eq!(gc_run.policy_resource_version, policy.resource_version);

    let cross_actor_gc_apply = hub
        .response(
            "RunContainerGc",
            Some(&other),
            &pb::ApplyContainerMutationRequest {
                plan_id: gc_run.run_id.clone(),
                idempotency_key: "cross-actor-gc".to_string(),
                confirmation_hash: gc_run.confirmation_hash.clone(),
            },
        )
        .await;
    assert_eq!(cross_actor_gc_apply.status(), StatusCode::NOT_FOUND);

    let missing_gc_apply = hub
        .response("RunContainerGc", Some(&owner), &gc_apply)
        .await;
    assert_eq!(missing_gc_apply.status(), StatusCode::NOT_FOUND);
    let missing_gc_get = hub
        .response("GetContainerGcRun", Some(&owner), &gc_get)
        .await;
    assert_eq!(missing_gc_get.status(), StatusCode::NOT_FOUND);
    let missing_gc_requeue = hub
        .response(
            "RequeueContainerGcPlacementAction",
            Some(&owner),
            &gc_requeue,
        )
        .await;
    assert_eq!(missing_gc_requeue.status(), StatusCode::NOT_FOUND);

    let fetched_gc: pb::ContainerGcRunResponse = hub
        .call(
            "GetContainerGcRun",
            &owner,
            &pb::GetContainerGcRunRequest {
                registry: hub.registry.clone(),
                run_id: gc_run.run_id.clone(),
            },
        )
        .await;
    assert_eq!(fetched_gc.run.as_ref(), planned_gc.run.as_ref());
    assert_eq!(&fetched_gc.blockers, &planned_gc.blockers);

    let listed_gc: pb::ListContainerGcRunsResponse =
        hub.call("ListContainerGcRuns", &owner, &gc_list).await;
    assert!(listed_gc
        .runs
        .iter()
        .any(|listed| listed.run_id == gc_run.run_id));
    assert!(!listed_gc.mutation_epoch.is_empty());

    let candidates: pb::ListContainerGcCandidatesResponse = hub
        .call(
            "ListContainerGcCandidates",
            &owner,
            &pb::ListContainerGcCandidatesRequest {
                registry: hub.registry.clone(),
                run_id: gc_run.run_id.clone(),
                page_size: 10,
                page_token: String::new(),
            },
        )
        .await;
    assert_eq!(candidates.mutation_epoch, gc_run.mutation_epoch);
    let blockers: pb::ListContainerGcBlockersResponse = hub
        .call(
            "ListContainerGcBlockers",
            &owner,
            &pb::ListContainerGcBlockersRequest {
                registry: hub.registry.clone(),
                run_id: gc_run.run_id.clone(),
            },
        )
        .await;
    assert_eq!(&blockers.blockers, &planned_gc.blockers);
    let actions: pb::ListContainerGcPlacementActionsResponse = hub
        .call(
            "ListContainerGcPlacementActions",
            &owner,
            &pb::ListContainerGcPlacementActionsRequest {
                registry: hub.registry.clone(),
                run_id: gc_run.run_id.clone(),
                page_size: 10,
                ..Default::default()
            },
        )
        .await;
    assert_eq!(actions.mutation_epoch, gc_run.mutation_epoch);

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
