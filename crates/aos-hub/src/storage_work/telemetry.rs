//! Accounting for offered plans and observed response bodies, including cancellation.
//!
//! Request bodies offered to the HTTP client are not proof of delivery. Response
//! bytes count only chunks exposed by the client, excluding transport framing,
//! unread error bodies, and any internal prefetch. Provider telemetry supplies
//! wire usage; this event preserves the application-side evidence on every exit.

use std::time::Instant;

use aos_hub_core::storage_work::StorageWorkPlan;

/// Retains counters until the exchange completes or its future is dropped.
pub(super) struct ExchangeTelemetry<'a> {
    plan_id: &'a str,
    operation: &'a str,
    dispatcher: tracing::Dispatch,
    span: tracing::Span,
    started: Instant,
    attempts: usize,
    offered_plan_bytes: u64,
    observed_body_bytes: u64,
    discarded_status_responses: usize,
    outcome: &'static str,
}

impl<'a> ExchangeTelemetry<'a> {
    pub(super) fn new(plan: &'a StorageWorkPlan) -> Self {
        Self::control(&plan.plan_id, plan.operation.kind())
    }

    /// Records the same byte contract for a separate closed control exchange.
    pub(super) fn control(plan_id: &'a str, operation: &'a str) -> Self {
        Self {
            plan_id,
            operation,
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::current(),
            started: Instant::now(),
            attempts: 0,
            offered_plan_bytes: 0,
            observed_body_bytes: 0,
            discarded_status_responses: 0,
            outcome: "cancelled",
        }
    }

    pub(super) fn offer_plan(&mut self, length: usize) {
        self.attempts += 1;
        self.offered_plan_bytes = self.offered_plan_bytes.saturating_add(length as u64);
    }

    pub(super) fn observe_body(&mut self, length: usize) {
        self.observed_body_bytes = self.observed_body_bytes.saturating_add(length as u64);
    }

    pub(super) fn discard_status_response(&mut self) {
        self.discarded_status_responses += 1;
    }

    pub(super) fn finish(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for ExchangeTelemetry<'_> {
    fn drop(&mut self) {
        // A cancelled future may be dropped outside its subscriber wrapper.
        // Retain the original dispatcher and task context for this final event.
        let _subscriber = tracing::dispatcher::set_default(&self.dispatcher);
        let _span = self.span.enter();
        tracing::info!(
            plan_id = %self.plan_id,
            operation = self.operation,
            exchange_attempts = self.attempts,
            offered_plan_bytes = self.offered_plan_bytes,
            observed_body_bytes = self.observed_body_bytes,
            discarded_status_responses = self.discarded_status_responses,
            outcome = self.outcome,
            exchange_elapsed_ms = self.started.elapsed().as_millis() as u64,
            "hybrid storage exchange accounting"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome, StorageWorkResult};
    use tracing::field::{Field, Visit};
    use tracing::instrument::WithSubscriber as _;
    use tracing::Subscriber;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer;

    use super::StorageWorkPlan;
    use crate::storage_work::RemoteStorageWorkClient;

    type Fields = BTreeMap<String, String>;

    #[derive(Clone, Default)]
    struct RecordedEvents(Arc<Mutex<Vec<Fields>>>);

    impl<S: Subscriber> Layer<S> for RecordedEvents {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = RecordedFields::default();
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
    }

    impl RecordedEvents {
        fn exchange(&self) -> Fields {
            let events = self.0.lock().unwrap();
            let exchanges: Vec<_> = events
                .iter()
                .filter(|fields| {
                    fields
                        .get("message")
                        .is_some_and(|message| message == "hybrid storage exchange accounting")
                })
                .collect();
            assert_eq!(exchanges.len(), 1, "{events:?}");
            exchanges[0].clone()
        }
    }

    #[derive(Default)]
    struct RecordedFields(Fields);

    impl Visit for RecordedFields {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
    }

    fn plan() -> StorageWorkPlan {
        let now = aos_hub_core::clock::now_unix_secs();
        StorageWorkPlan {
            version: 1,
            plan_id: "11111111111111111111111111111111".into(),
            deployment_id: "exchange-deployment".into(),
            issued_at: now,
            expires_at: now + 30,
            placement_id: 1,
            placement_resource_version: 1,
            binding_id: 1,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: "registry".into(),
            operation: StorageWorkOperation::Head {
                path: "object".into(),
            },
        }
    }

    async fn serve(app: axum::Router) -> (RemoteStorageWorkClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut client = RemoteStorageWorkClient::new(
            "https://worker.example",
            "exchange-deployment".into(),
            b"hybrid-storage-test-key-with-thirty-two-bytes",
        )
        .unwrap();
        client.endpoint = format!("http://{address}/");
        (client, server)
    }

    #[tokio::test]
    async fn retry_accounting_separates_offered_plans_from_observed_bodies() {
        let plan = plan();
        let result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: 1,
            placement_resource_version: 1,
            binding_id: 1,
            binding_resource_version: 1,
            source_bytes: 0,
            outcome: StorageWorkOutcome::NotFound,
        };
        let response = serde_json::to_vec(&result).unwrap();
        let expected_response_bytes = response.len();
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let attempts = Arc::clone(&attempts);
                let response = response.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            b"unread error body".to_vec(),
                        )
                    } else {
                        (axum::http::StatusCode::OK, response)
                    }
                }
            }),
        );
        let (client, server) = serve(app).await;
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());

        client
            .execute(&plan)
            .with_subscriber(subscriber)
            .await
            .unwrap();
        server.abort();

        let event = recorded.exchange();
        assert_eq!(event["outcome"], "success");
        assert_eq!(event["exchange_attempts"], "2");
        assert_eq!(
            event["offered_plan_bytes"],
            (2 * serde_json::to_vec(&plan).unwrap().len()).to_string()
        );
        assert_eq!(
            event["observed_body_bytes"],
            expected_response_bytes.to_string()
        );
        assert_eq!(event["discarded_status_responses"], "1");
    }

    #[tokio::test]
    async fn malformed_response_bytes_remain_accounted_without_logging_the_body() {
        let private_body = "private object contents must stay out of logs";
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || async move { private_body }),
        );
        let (client, server) = serve(app).await;
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());

        assert!(client
            .execute(&plan())
            .with_subscriber(subscriber)
            .await
            .is_err());
        server.abort();

        let event = recorded.exchange();
        assert_eq!(event["outcome"], "malformed_result");
        assert_eq!(event["observed_body_bytes"], private_body.len().to_string());
        assert!(!format!("{:?}", recorded.0.lock().unwrap()).contains(private_body));
    }

    #[tokio::test]
    async fn cancelled_caller_records_the_plan_already_offered() {
        let (started, received) = tokio::sync::oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started)));
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let started = Arc::clone(&started);
                async move {
                    started.lock().unwrap().take().unwrap().send(()).unwrap();
                    std::future::pending::<&'static str>().await
                }
            }),
        );
        let (client, server) = serve(app).await;
        let plan = plan();
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());
        let mut request = Box::pin(client.execute(&plan).with_subscriber(subscriber));

        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = &mut request => panic!("request completed before cancellation: {result:?}"),
                result = received => result.unwrap(),
            }
        }).await.unwrap();
        drop(request);
        server.abort();

        let event = recorded.exchange();
        assert_eq!(event["outcome"], "cancelled");
        assert_eq!(event["exchange_attempts"], "1");
        assert_eq!(
            event["offered_plan_bytes"],
            serde_json::to_vec(&plan).unwrap().len().to_string()
        );
        assert_eq!(event["observed_body_bytes"], "0");
    }
}
