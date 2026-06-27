//! [`TenantDb`]: a per-tenant Durable Object owning colocated SQLite, and its
//! [`TenantDbRouter`] client (wasm32-only) — RFC-0004 ch.14 Phase E (E2/E3).
//!
//! Phase E shards the relational **system of record** per tenant: one Durable
//! Object per org/registry holds that tenant's SQLite, run in the same thread as
//! the handler ([`SqlDoBackend`](crate::sqldobackend::SqlDoBackend) over
//! `state.storage().sql()`). That gives microsecond-local reads, full SQL, and
//! strict serializability — the colocation D1 cannot — while the
//! [`id_from_name`](worker::ObjectNamespace::id_from_name) routing makes each
//! tenant's DB a distinct, addressable object.
//!
//! - [`TenantDb`] — the DO. On first use it applies the shared
//!   [`MIGRATIONS`](aos_hub_core::db::MIGRATIONS) to its fresh SQLite (tracked by
//!   SQLite's `PRAGMA user_version`), so the *exact* hub schema runs inside the
//!   tenant DO. Its `fetch` decodes a [`SqlCommand`] and runs it against a
//!   [`Database`](aos_hub_core::db::Database) over the local engine.
//! - [`TenantDbRouter`] — the client: resolves a tenant to its DO stub and
//!   forwards a [`SqlCommand`], returning the rows. This is the E3 routing
//!   primitive the request path would drive (the full request-path migration is
//!   the remaining structural step; the runtime is exercised under a deploy).
//!
//! ```text
//! request --(tenant slug)--> TenantDbRouter --(SqlCommand JSON)--> TenantDb DO
//!                                                                  └ local SQLite
//! ```

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Method, ObjectNamespace, Request, RequestInit, Response,
    State,
};

use aos_hub_core::db::MIGRATIONS;
use aos_hub_core::value::Value;

use crate::sqldobackend::SqlDoBackend;

/// The Durable Object binding name for per-tenant SQLite (must match
/// `wrangler.toml` `[[durable_objects.bindings]]` and a `new_sqlite_classes`
/// migration, since `TenantDb` uses SQLite storage).
const TENANT_DB_BINDING: &str = "TENANT_DB";

/// A SQL operation sent from [`TenantDbRouter`] to a [`TenantDb`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SqlCommand {
    /// A `SELECT` (or `… RETURNING`): returns rows.
    Query {
        /// The source (sqlite-dialect) SQL.
        sql: String,
        /// Positional parameters (JSON-encoded [`Value`]s).
        params: Vec<JsonValue>,
    },
    /// A non-`SELECT`: returns the affected row count.
    Execute { sql: String, params: Vec<JsonValue> },
}

/// A JSON-friendly mirror of a bound [`Value`] (the wire form of a parameter and
/// of a result cell), so commands and rows cross the DO boundary as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "t", content = "v")]
pub enum JsonValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Bytes(Vec<u8>),
}

impl From<&Value> for JsonValue {
    fn from(value: &Value) -> JsonValue {
        match value {
            Value::Null => JsonValue::Null,
            Value::Int(n) => JsonValue::Int(*n),
            Value::Real(f) => JsonValue::Real(*f),
            Value::Text(s) => JsonValue::Text(s.clone()),
            Value::Bytes(b) => JsonValue::Bytes(b.clone()),
        }
    }
}

impl From<&JsonValue> for Value {
    fn from(value: &JsonValue) -> Value {
        match value {
            JsonValue::Null => Value::Null,
            JsonValue::Int(n) => Value::Int(*n),
            JsonValue::Real(f) => Value::Real(*f),
            JsonValue::Text(s) => Value::Text(s.clone()),
            JsonValue::Bytes(b) => Value::Bytes(b.clone()),
        }
    }
}

/// The reply to a [`SqlCommand`]: rows for a query, or a count for an execute.
#[derive(Debug, Serialize, Deserialize)]
pub struct SqlReply {
    /// The result rows (each a list of cells), for a `Query`; empty for an
    /// `Execute`.
    pub rows: Vec<Vec<JsonValue>>,
    /// The affected row count, for an `Execute`; `0` for a `Query`.
    pub affected: u64,
}

/// Applies the shared `MIGRATIONS` to a fresh tenant SQLite once, tracked by
/// `PRAGMA user_version`.
///
/// A new DO's SQLite starts at `user_version = 0`; this applies every migration
/// in order and stamps the count, so a recycled DO re-opening the same storage
/// skips already-applied migrations. Idempotent across DO restarts.
///
/// Durable Object SQLite **forbids `PRAGMA`** (`SQLITE_AUTH`), so the applied
/// count is tracked in a one-row `_do_migrations` table rather than
/// `PRAGMA user_version`.
pub(crate) async fn ensure_migrated(backend: &SqlDoBackend) -> anyhow::Result<()> {
    use aos_hub_core::backend::Backend as _;
    use aos_hub_core::value::Value;
    // The version-tracking table (one row, id = 0). Plain DDL — authorized in DO
    // SQLite (only PRAGMA/ATTACH/etc. are not).
    backend
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS _do_migrations (\
               id INTEGER PRIMARY KEY CHECK (id = 0), \
               applied INTEGER NOT NULL)",
        )
        .await?;
    let applied = backend
        .query("SELECT applied FROM _do_migrations WHERE id = 0", &[])
        .await?
        .first()
        .and_then(|row| row.get::<i64>(0).ok())
        .unwrap_or(0)
        .max(0) as usize;
    if applied >= MIGRATIONS.len() {
        return Ok(());
    }
    for migration in &MIGRATIONS[applied..] {
        backend.execute_batch(migration).await?;
    }
    backend
        .execute(
            "INSERT INTO _do_migrations (id, applied) VALUES (0, ?1) \
             ON CONFLICT(id) DO UPDATE SET applied = ?1",
            &[Value::Int(MIGRATIONS.len() as i64)],
        )
        .await?;
    Ok(())
}

/// The per-tenant SQLite Durable Object.
#[durable_object]
pub struct TenantDb {
    state: State,
}

impl DurableObject for TenantDb {
    fn new(state: State, _env: Env) -> Self {
        TenantDb { state }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        use aos_hub_core::backend::Backend as _;
        let command: SqlCommand = req.json().await?;
        let backend = SqlDoBackend::new(self.state.storage().sql());
        if let Err(err) = ensure_migrated(&backend).await {
            return Response::error(format!("tenant migrate: {err:#}"), 500);
        }
        let reply = match command {
            SqlCommand::Query { sql, params } => {
                let bound: Vec<Value> = params.iter().map(Value::from).collect();
                match backend.query(&sql, &bound).await {
                    Ok(rows) => SqlReply {
                        rows: rows
                            .into_iter()
                            .map(|row| {
                                (0..row.len())
                                    .filter_map(|i| row.value(i))
                                    .map(JsonValue::from)
                                    .collect()
                            })
                            .collect(),
                        affected: 0,
                    },
                    Err(err) => return Response::error(format!("tenant query: {err:#}"), 500),
                }
            }
            SqlCommand::Execute { sql, params } => {
                let bound: Vec<Value> = params.iter().map(Value::from).collect();
                match backend.execute(&sql, &bound).await {
                    Ok(affected) => SqlReply {
                        rows: Vec::new(),
                        affected,
                    },
                    Err(err) => return Response::error(format!("tenant execute: {err:#}"), 500),
                }
            }
        };
        Response::from_json(&reply)
    }
}

/// A client that routes a tenant's SQL operations to its [`TenantDb`] DO.
///
/// One DO per tenant key (`id_from_name(tenant)`), so each tenant's database is a
/// distinct, serialized, colocated object. The request path resolves the tenant
/// from the request slug and drives this; that wiring is the remaining E3
/// structural step.
pub struct TenantDbRouter {
    namespace: ObjectNamespace,
}

impl TenantDbRouter {
    /// Builds the router from the Worker environment's tenant-DB binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the `TENANT_DB` Durable Object binding is missing.
    pub fn from_env(env: &Env) -> worker::Result<TenantDbRouter> {
        Ok(TenantDbRouter {
            namespace: env.durable_object(TENANT_DB_BINDING)?,
        })
    }

    /// Runs a [`SqlCommand`] against `tenant`'s database, returning its reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant DO cannot be reached or the command fails.
    pub async fn run(&self, tenant: &str, command: &SqlCommand) -> anyhow::Result<SqlReply> {
        let stub = self
            .namespace
            .id_from_name(tenant)
            .and_then(|id| id.get_stub())
            .map_err(|err| anyhow::anyhow!("tenant stub: {err}"))?;
        let body = serde_json::to_string(command)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(JsValue::from_str(&body)));
        let req = Request::new_with_init("https://tenant-db/", &init)
            .map_err(|err| anyhow::anyhow!("tenant request: {err}"))?;
        let mut resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|err| anyhow::anyhow!("tenant fetch: {err}"))?;
        resp.json::<SqlReply>()
            .await
            .map_err(|err| anyhow::anyhow!("tenant reply: {err}"))
    }

    /// Convenience: run a `SELECT` against `tenant`, binding `params`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant DO cannot be reached or the query fails.
    pub async fn query(
        &self,
        tenant: &str,
        sql: &str,
        params: &[Value],
    ) -> anyhow::Result<SqlReply> {
        self.run(
            tenant,
            &SqlCommand::Query {
                sql: sql.to_string(),
                params: params.iter().map(JsonValue::from).collect(),
            },
        )
        .await
    }
}
