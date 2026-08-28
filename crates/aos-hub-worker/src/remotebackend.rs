//! Seal-gated remote database backend for background Worker isolates.
//!
//! Queue consumers run provider and network I/O outside the global database
//! Durable Object. They still reuse the shared [`Database`](aos_hub_core::db::Database)
//! by sending each short SQL operation to `HubDb`; checked batches cross as one
//! request and remain one SQLite transaction. No public request can reach this
//! bridge because both the Worker route and Durable Object endpoint require the
//! deployment seal.

use std::cell::Cell;
use std::rc::Rc;

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use wasm_bindgen::JsValue;
use worker::{Env, Method, Request, RequestInit};

use aos_hub_core::backend::{Backend, CheckedStatement, Statement};
use aos_hub_core::dialect::Dialect;
use aos_hub_core::value::{Row, Value};

use crate::handlers::bindings::HUB_DB;
use crate::remoteprotocol::{RemoteSqlRequest, RemoteSqlResponse, RemoteStatement};

const HUB_SEAL_KEY: &str = "HUB_SEAL_KEY";

/// Internal path serving the remote SQL protocol.
pub(crate) const REMOTE_SQL_PATH: &str = "/_internal/sql";

/// Per-activation counters for SQL operations crossing into `HubDb`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RemoteSqlMetricsSnapshot {
    /// Internal SQL requests issued.
    pub(crate) calls: u64,
    /// Aggregate internal SQL request latency in milliseconds.
    pub(crate) duration_ms: u64,
    /// Rows returned by query operations.
    pub(crate) rows_read: u64,
}

impl RemoteSqlMetricsSnapshot {
    /// Returns the counter delta since `before`.
    #[must_use]
    pub(crate) fn since(self, before: Self) -> Self {
        Self {
            calls: self.calls.saturating_sub(before.calls),
            duration_ms: self.duration_ms.saturating_sub(before.duration_ms),
            rows_read: self.rows_read.saturating_sub(before.rows_read),
        }
    }
}

/// Shared metrics recorder cloned with a [`RemoteHubBackend`].
#[derive(Clone, Default)]
pub(crate) struct RemoteSqlMetrics(Rc<Cell<RemoteSqlMetricsSnapshot>>);

impl RemoteSqlMetrics {
    /// Returns the current cumulative snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> RemoteSqlMetricsSnapshot {
        self.0.get()
    }

    fn record(&self, duration_ms: u64, rows_read: usize) {
        let current = self.0.get();
        self.0.set(RemoteSqlMetricsSnapshot {
            calls: current.calls.saturating_add(1),
            duration_ms: current.duration_ms.saturating_add(duration_ms),
            rows_read: current
                .rows_read
                .saturating_add(u64::try_from(rows_read).unwrap_or(u64::MAX)),
        });
    }
}

/// Shared-database backend used outside the Durable Object isolate.
#[derive(Clone)]
pub(crate) struct RemoteHubBackend {
    env: Env,
    metrics: RemoteSqlMetrics,
}

impl RemoteHubBackend {
    /// Builds a backend from the queue handler's Worker environment.
    #[must_use]
    pub(crate) fn new(env: &Env) -> Self {
        Self {
            env: env.clone(),
            metrics: RemoteSqlMetrics::default(),
        }
    }

    /// Builds a backend that reports into the supplied activation recorder.
    #[must_use]
    pub(crate) fn with_metrics(env: &Env, metrics: RemoteSqlMetrics) -> Self {
        Self {
            env: env.clone(),
            metrics,
        }
    }

    async fn call(&self, operation: &RemoteSqlRequest) -> Result<RemoteSqlResponse> {
        let seal = self
            .env
            .secret(HUB_SEAL_KEY)
            .map_err(|error| anyhow!("remote SQL seal: {error}"))?
            .to_string();
        let database_instance = self
            .env
            .var("HUB_DATABASE_INSTANCE")
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "hub".to_string());
        let stub = self
            .env
            .durable_object(HUB_DB)
            .map_err(|error| anyhow!("remote SQL binding: {error}"))?
            .id_from_name(&database_instance)
            .and_then(|id| id.get_stub_with_location_hint("wnam"))
            .map_err(|error| anyhow!("remote SQL stub: {error}"))?;
        let headers = worker::Headers::new();
        headers
            .set("x-hub-seal", &seal)
            .map_err(|error| anyhow!("remote SQL seal header: {error}"))?;
        headers
            .set("content-type", "application/json")
            .map_err(|error| anyhow!("remote SQL content type: {error}"))?;
        let body = serde_json::to_string(operation).context("serializing remote SQL operation")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(JsValue::from_str(&body)));
        let request = Request::new_with_init(&format!("https://hub{REMOTE_SQL_PATH}"), &init)
            .map_err(|error| anyhow!("building remote SQL request: {error}"))?;
        let started_at = worker::Date::now().as_millis();
        let mut response = stub
            .fetch_with_request(request)
            .await
            .map_err(|error| anyhow!("remote SQL fetch: {error}"))?;
        if response.status_code() != 200 {
            let detail = response.text().await.unwrap_or_default();
            bail!("remote SQL returned {}: {detail}", response.status_code());
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| anyhow!("reading remote SQL response: {error}"))?;
        let decoded: RemoteSqlResponse =
            serde_json::from_slice(&body).context("decoding remote SQL response JSON")?;
        self.metrics.record(
            worker::Date::now().as_millis().saturating_sub(started_at),
            decoded.rows.as_ref().map_or(0, Vec::len),
        );
        Ok(decoded)
    }
}

#[async_trait(?Send)]
impl Backend for RemoteHubBackend {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        self.call(&RemoteSqlRequest::Execute {
            sql: sql.to_string(),
            params: params.to_vec(),
        })
        .await?
        .count
        .ok_or_else(|| anyhow!("remote execute omitted its row count"))
    }

    async fn execute_discarding_count(&self, sql: &str, params: &[Value]) -> Result<()> {
        self.call(&RemoteSqlRequest::ExecuteDiscardingCount {
            sql: sql.to_string(),
            params: params.to_vec(),
        })
        .await?;
        Ok(())
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        self.call(&RemoteSqlRequest::ExecuteInsert {
            sql: sql.to_string(),
            params: params.to_vec(),
        })
        .await?
        .inserted_id
        .ok_or_else(|| anyhow!("remote insert omitted its generated id"))
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        self.call(&RemoteSqlRequest::Query {
            sql: sql.to_string(),
            params: params.to_vec(),
        })
        .await?
        .rows
        .ok_or_else(|| anyhow!("remote query omitted its rows"))
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        self.call(&RemoteSqlRequest::ExecuteBatch {
            sql: sql.to_string(),
        })
        .await?;
        Ok(())
    }

    async fn batch(&self, statements: &[Statement]) -> Result<()> {
        let statements = statements
            .iter()
            .map(|statement| RemoteStatement {
                sql: statement.sql.clone(),
                params: statement.params.clone(),
                expected_rows: None,
            })
            .collect();
        self.call(&RemoteSqlRequest::Batch { statements }).await?;
        Ok(())
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        let statements = statements
            .iter()
            .map(|statement| RemoteStatement {
                sql: statement.statement.sql.clone(),
                params: statement.statement.params.clone(),
                expected_rows: statement.expected_rows,
            })
            .collect();
        self.call(&RemoteSqlRequest::Batch { statements }).await?;
        Ok(())
    }
}

/// Executes one decoded internal SQL operation on the colocated backend.
///
/// # Errors
///
/// Returns an error if SQL execution fails or a checked batch assertion does
/// not hold.
pub(crate) async fn execute_remote_sql(
    backend: &crate::sqldobackend::SqlDoBackend,
    operation: RemoteSqlRequest,
) -> Result<RemoteSqlResponse> {
    match operation {
        RemoteSqlRequest::Execute { sql, params } => Ok(RemoteSqlResponse {
            count: Some(backend.execute(&sql, &params).await?),
            ..RemoteSqlResponse::default()
        }),
        RemoteSqlRequest::ExecuteDiscardingCount { sql, params } => {
            backend.execute_discarding_count(&sql, &params).await?;
            Ok(RemoteSqlResponse::default())
        }
        RemoteSqlRequest::ExecuteInsert { sql, params } => Ok(RemoteSqlResponse {
            inserted_id: Some(backend.execute_insert(&sql, &params).await?),
            ..RemoteSqlResponse::default()
        }),
        RemoteSqlRequest::Query { sql, params } => Ok(RemoteSqlResponse {
            rows: Some(backend.query(&sql, &params).await?),
            ..RemoteSqlResponse::default()
        }),
        RemoteSqlRequest::ExecuteBatch { sql } => {
            backend.execute_batch(&sql).await?;
            Ok(RemoteSqlResponse::default())
        }
        RemoteSqlRequest::Batch { statements } => {
            let checked = statements
                .into_iter()
                .map(|statement| CheckedStatement {
                    statement: Statement {
                        sql: statement.sql,
                        params: statement.params,
                    },
                    expected_rows: statement.expected_rows,
                })
                .collect::<Vec<_>>();
            backend.checked_batch(&checked).await?;
            Ok(RemoteSqlResponse::default())
        }
    }
}
