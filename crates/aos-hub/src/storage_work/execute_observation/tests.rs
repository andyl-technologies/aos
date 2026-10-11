//! Actual loopback reply consumption and existing current-state fences.

use std::sync::{Arc, Mutex};

use aos_hub_core::db::{
    Database, NewSurfacePlacementSpec, SurfaceTarget, UpdateSurfacePlacementSpec,
};
use aos_hub_core::storage_work::{
    STORAGE_WORK_SIGNATURE_HEADER, StorageWorkKey, StorageWorkOperation, StorageWorkOutcome,
    StorageWorkResult,
};
use axum::{body::Bytes, http::HeaderMap};
use serde_json::Value;
use tracing::{
    Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber as _,
};
use tracing_subscriber::{Layer, layer::SubscriberExt as _};

use super::*;
use crate::storage_work::{HybridSurfaceFetch, telemetry};

const WORK_KEY: &[u8] = b"hybrid-storage-test-key-with-thirty-two-bytes";

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<String>>>);

impl<S: Subscriber> Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message(Option<String>);
        impl Visit for Message {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut message = Message(None);
        event.record(&mut message);
        if let Some(message) = message.0 {
            self.0.lock().unwrap().push(message);
        }
    }
}

impl Events {
    fn rows(&self, marker: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|message| {
                message
                    .strip_prefix(&format!("{marker} "))
                    .map(|body| serde_json::from_str(body).unwrap())
            })
            .collect()
    }
}

fn plan() -> StorageWorkPlan {
    let now = aos_hub_core::clock::now_unix_secs();
    StorageWorkPlan {
        version: 1,
        plan_id: "1".repeat(32),
        deployment_id: "exchange-deployment".into(),
        issued_at: now,
        expires_at: now + 30,
        placement_id: 1,
        placement_resource_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: vec![],
        placement_prefix: "registry".into(),
        operation: StorageWorkOperation::Head {
            path: "object".into(),
        },
    }
}

fn absent(plan: &StorageWorkPlan) -> StorageWorkResult {
    StorageWorkResult {
        versioned_sources: Vec::new(),
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes: 0,
        outcome: StorageWorkOutcome::NotFound,
    }
}

#[tokio::test]
async fn retries_have_distinct_actual_header_ids_and_unread_status_bodies() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let retained = calls.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let retained = retained.clone();
            async move {
                let plan = StorageWorkKey::new(WORK_KEY)
                    .unwrap()
                    .verify_plan(
                        headers[STORAGE_WORK_SIGNATURE_HEADER].to_str().unwrap(),
                        &body,
                        "exchange-deployment",
                        aos_hub_core::clock::now_unix_secs(),
                    )
                    .unwrap();
                let count = {
                    let mut calls = retained.lock().unwrap();
                    calls.push((
                        headers[telemetry::STORAGE_CALL_ID_HEADER]
                            .to_str()
                            .unwrap()
                            .to_owned(),
                        body.to_vec(),
                    ));
                    calls.len()
                };
                if count == 1 {
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        b"storage work failed".to_vec(),
                    )
                } else {
                    (
                        axum::http::StatusCode::OK,
                        serde_json::to_vec(&absent(&plan)).unwrap(),
                    )
                }
            }
        }),
    );
    let (client, server) = telemetry::tests::serve(app).await;
    let events = Events::default();
    let request = plan();
    client
        .execute(&request)
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await
        .unwrap();
    server.abort();

    let rows = events.rows("storage_work_attempt_observed");
    assert_eq!(rows.len(), 2);
    let calls = calls.lock().unwrap();
    assert_ne!(calls[0].0, calls[1].0);
    for (row, (id, body)) in rows.iter().zip(calls.iter()) {
        assert_eq!(row["transportCallId"], *id);
        assert_eq!(
            row["offeredRequestSha256"],
            hex::encode(Sha256::digest(body))
        );
        assert_eq!(row["offeredRequestBytes"], body.len().to_string());
        assert_eq!(row["endpointScheme"], "http");
        assert!(row["replyMacAuthentication"].is_null());
    }
    assert_eq!(rows[0]["outcome"], "http_status_retry");
    assert_eq!(rows[0]["exposedReplyBytes"], "0");
    assert_eq!(rows[0]["unreadResponse"], true);
    assert_eq!(rows[0]["replyEof"], false);
    assert_eq!(rows[1]["outcome"], "typed_result_checked");
    assert_eq!(rows[1]["replyEof"], true);
    assert!(events.rows("storage_work_final_sql_checked").is_empty());
}

#[tokio::test]
async fn fully_consumed_malformed_reply_is_not_typed_acceptance() {
    let private = "private response contents";
    let app = axum::Router::new().route("/", axum::routing::post(move || async move { private }));
    let (client, server) = telemetry::tests::serve(app).await;
    let events = Events::default();
    assert!(
        client
            .execute(&plan())
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await
            .is_err()
    );
    server.abort();

    let rows = events.rows("storage_work_attempt_observed");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["outcome"], "malformed_result");
    assert_eq!(rows[0]["exposedReplyBytes"], private.len().to_string());
    assert_eq!(
        rows[0]["exposedReplySha256"],
        hex::encode(Sha256::digest(private))
    );
    assert_eq!(rows[0]["replyEof"], true);
    assert!(
        !events
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|message| message.contains(private))
    );
    assert!(events.rows("storage_work_final_sql_checked").is_empty());
}

#[tokio::test]
async fn an_actual_failed_reply_stream_keeps_its_exposed_prefix() {
    use futures_util::StreamExt as _;
    let prefix = b"actual partial reply";
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move || async move {
            let first = futures_util::stream::once(async {
                Ok::<_, std::io::Error>(Bytes::from_static(prefix))
            });
            let failed = futures_util::stream::once(async {
                // Separates the actual HTTP data frame from the later failed frame.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                Err::<Bytes, _>(std::io::Error::other("controlled reply stream failure"))
            });
            axum::body::Body::from_stream(first.chain(failed))
        }),
    );
    let (client, server) = telemetry::tests::serve(app).await;
    let events = Events::default();
    assert!(
        client
            .execute(&plan())
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await
            .is_err()
    );
    server.abort();

    let rows = events.rows("storage_work_attempt_observed");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["outcome"], "response_read_failed");
    assert_eq!(
        rows[0]["exposedReplySha256"],
        hex::encode(Sha256::digest(prefix))
    );
    assert_eq!(rows[0]["exposedReplyBytes"], prefix.len().to_string());
    assert_eq!(rows[0]["replyEof"], false);
    assert_eq!(rows[0]["unreadResponse"], false);
    assert!(events.rows("storage_work_final_sql_checked").is_empty());
}

#[test]
fn cancelled_owner_preserves_only_observed_bytes_and_never_checks_an_unread_reply() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        let plan = plan();
        let body = serde_json::to_vec(&plan).unwrap();
        let mut owner =
            AttemptObservation::new(&plan, "invocation", 1, &body, "https://worker.example");
        owner.offer(body.len());
        owner.response(200);
        assert!(owner.checked().is_none());
        owner.exposed(b"prefix");
    });

    let row = events.rows("storage_work_attempt_observed").remove(0);
    assert_eq!(row["outcome"], "cancelled");
    assert_eq!(row["exposedReplyBytes"], "6");
    assert_eq!(
        row["exposedReplySha256"],
        hex::encode(Sha256::digest(b"prefix"))
    );
    assert_eq!(row["replyEof"], false);
}

async fn current_surface(change: bool) -> (HybridSurfaceFetch, tokio::task::JoinHandle<()>) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("observed-owner", "Observed owner")
        .await
        .unwrap();
    let registry = db
        .register_registry("observed-registry", &[], false)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("observed-bucket"))
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "observed".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let retained = db.clone();
    let placement_id = placement.id;
    let version = placement.resource_version;
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |body: Bytes| {
            let db = retained.clone();
            async move {
                let plan: StorageWorkPlan = serde_json::from_slice(&body).unwrap();
                if change {
                    db.update_surface_placement(
                        placement_id,
                        &UpdateSurfacePlacementSpec {
                            expected_version: version,
                            desired_state: "active".into(),
                            desired_read_enabled: true,
                            read_order: 1,
                        },
                    )
                    .await
                    .unwrap();
                }
                axum::Json(absent(&plan))
            }
        }),
    );
    let (client, server) = telemetry::tests::serve(app).await;
    (
        HybridSurfaceFetch {
            db,
            placement,
            binding,
            work: Arc::new(client),
        },
        server,
    )
}

#[tokio::test]
async fn final_context_follows_real_current_sql_checks_and_refuses_changed_placement() {
    for change in [false, true] {
        let (surface, server) = current_surface(change).await;
        let plan = surface
            .work
            .plan_for_placement(
                &surface.placement,
                &surface.binding,
                StorageWorkOperation::Head {
                    path: "object".into(),
                },
                aos_hub_core::clock::now_unix_secs(),
            )
            .unwrap();
        let events = Events::default();
        let result = surface
            .execute(&plan)
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await;
        server.abort();

        assert_eq!(result.is_err(), change);
        assert_eq!(
            events.rows("storage_work_attempt_observed")[0]["outcome"],
            "typed_result_checked"
        );
        let contexts = events.rows("storage_work_final_sql_checked");
        assert_eq!(contexts.len(), usize::from(!change));
        if let Some(context) = contexts.first() {
            assert_eq!(context["contextKind"], "surface_fetch_current_sql");
            assert_eq!(context["commitments"].as_object().unwrap().len(), 2);
            assert_eq!(context["attempt"]["planId"], plan.plan_id);
        }
    }
}
