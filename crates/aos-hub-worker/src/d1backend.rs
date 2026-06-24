//! [`D1Backend`]: the Cloudflare D1 implementation of the shared
//! [`Backend`](aos_hub_core::backend::Backend) trait (wasm32-only).
//!
//! D1 is sqlite (RFC-0004: "D1 is the sqlite backend — same dialect, different
//! driver"), so this drives the *exact* `core::Database` read/write logic the
//! native hub runs, over `worker::D1DatabaseSession` prepared statements instead
//! of the native `sqlx` pool. The Worker opens one session per request
//! ([`open_session`]) and constructs
//! `Database::attach(Box::new(D1Backend::new(session)))`; from there every query
//! method, the migrations, and the auth/config/webhook logic are the same
//! compiled code as the native binary.
//!
//! # Read replication
//!
//! Each statement runs through a [`D1DatabaseSession`] rather than the raw
//! [`D1Database`], so D1 serves reads from the nearest up-to-date read replica
//! and routes writes to the primary, while the session's monotonic bookmark
//! gives sequential consistency. The entry point seeds the session from a
//! per-client bookmark cookie (read-your-writes) and threads the resulting
//! bookmark back; see the `fetch` handler at the crate root.
//!
//! # Marshalling
//!
//! Parameters cross as [`Value`] → [`JsValue`] ([`to_js`]); result rows come
//! back **positionally** via D1's `raw::<serde_json::Value>()` (a `Vec<Vec<_>>`
//! of column values per row) and are mapped column-by-column into a
//! [`Row`] ([`from_json`]). D1 reports `meta.changes`/`meta.last_row_id` for the
//! write paths, and its atomic `batch()` backs [`Backend::batch`] — exactly the
//! self-contained statement-list seam `core` was designed around (no
//! interactive transactions).

use std::rc::Rc;

use async_trait::async_trait;
use wasm_bindgen::{JsCast, JsValue};
use worker::{D1Database, D1DatabaseSession};

use aos_hub_core::backend::{prepare, split_statements, Backend, Statement};
use aos_hub_core::dialect::Dialect;
use aos_hub_core::value::{Row, Value};

/// A [`Backend`] over a Cloudflare D1 **session** (RFC-0004 read replication).
///
/// Every statement runs through a [`D1DatabaseSession`] rather than the raw
/// [`D1Database`], so reads are routed to the nearest up-to-date read replica
/// and writes to the primary, with the session's monotonic bookmark giving
/// sequential consistency. One session is shared (`Rc`) by all the D1 backends a
/// single request builds (the read path, the rate limiter, the publish lease),
/// so the whole request reads against one consistency floor; the entry point
/// threads that floor across requests via a bookmark cookie (see
/// [`open_session`] and the `fetch` handler). A non-request context (the Cron
/// indexer) opens its own [`open_session`] with a `first-primary` seed.
pub struct D1Backend {
    session: Rc<D1DatabaseSession>,
}

impl D1Backend {
    /// Wraps a shared D1 [`D1DatabaseSession`] as a [`Backend`].
    #[must_use]
    pub fn new(session: Rc<D1DatabaseSession>) -> D1Backend {
        D1Backend { session }
    }
}

/// Opens a D1 read-replication session over a bound database, seeded by a
/// bookmark or a session constraint.
///
/// `seed` is either a prior session bookmark (the freshness floor for
/// read-your-writes) or one of the constraint strings D1 accepts —
/// `"first-unconstrained"` (the first read may be served by any replica) or
/// `"first-primary"` (the first query routes to the primary, for write-bearing
/// requests and the Cron indexer). The returned session is wrapped in an [`Rc`]
/// so all of a request's backends can share one consistency floor on the
/// single-threaded isolate.
///
/// # Errors
///
/// Returns an error if the D1 binding rejects the session seed.
pub fn open_session(db: &D1Database, seed: &str) -> anyhow::Result<Rc<D1DatabaseSession>> {
    db.with_session(Some(seed))
        .map(Rc::new)
        .map_err(|err| anyhow::anyhow!("D1 session ({seed}): {err}"))
}

/// Maps a worker/D1 error into an `anyhow::Error` for the [`Backend`] contract.
fn d1_err(err: worker::Error) -> anyhow::Error {
    anyhow::anyhow!("D1: {err}")
}

/// Returns a genuine JavaScript `null` for binding a SQL `NULL` to D1.
///
/// The static `wasm_bindgen::JsValue::NULL` is a well-known heap *sentinel*, and
/// under this Worker's build pipeline (`wasm-bindgen --target bundler`, the
/// custom wasm-instantiation glue, then an `esbuild` bundle) that sentinel does
/// not resolve to a real JS `null` at runtime: it reaches D1 as a plain object,
/// which D1 rejects with `D1_TYPE_ERROR: Type 'object' not supported`. (Reads are
/// unaffected — a `NULL` column comes back as a real engine `null`, which
/// [`js_to_value`] maps correctly.) Parsing the literal `"null"` produces a real
/// engine `null` on the JS heap, independent of the sentinel table, so D1 binds
/// it as SQL `NULL`. `JSON.parse("null")` cannot fail; the fallback is defensive.
fn js_null() -> JsValue {
    js_sys::JSON::parse("null").unwrap_or(JsValue::NULL)
}

/// Converts a bound [`Value`] into the `JsValue` D1 binds.
///
/// Integers cross as JS numbers (f64): every hub id/count is well under 2^53, so
/// this is lossless. Blobs cross as a `Uint8Array`. `NULL` uses [`js_null`]
/// rather than the `JsValue::NULL` sentinel (see that function).
fn to_js(value: &Value) -> JsValue {
    match value {
        Value::Null => js_null(),
        Value::Int(n) => JsValue::from_f64(*n as f64),
        Value::Real(f) => JsValue::from_f64(*f),
        Value::Text(s) => JsValue::from_str(s),
        Value::Bytes(b) => js_sys::Uint8Array::from(b.as_slice()).into(),
    }
}

/// Converts one D1 column, as a raw [`JsValue`], into a [`Value`].
///
/// Reading cells straight off the JS row array (rather than through
/// `serde_wasm_bindgen` into `serde_json::Value`) is deliberate: a NULL column
/// arrives as JS `null`, which `serde_wasm_bindgen` refuses to coerce into
/// `serde_json::Value` ("invalid type: null, expected any valid JSON value"),
/// and the hub's full-column SELECTs read many nullable columns. The mapping
/// mirrors sqlite affinities D1 surfaces: `null`→Null, number→Int when it has
/// no fractional part (sqlite INTEGER; ids/counts are well under 2^53) else
/// Real, string→Text, `Uint8Array`→Bytes (BLOB). A boolean (not produced by
/// sqlite, but tolerated) maps to the `0`/`1` integer the schema stores.
fn js_to_value(value: &JsValue) -> Value {
    if value.is_null() || value.is_undefined() {
        Value::Null
    } else if let Some(b) = value.as_bool() {
        Value::Int(i64::from(b))
    } else if let Some(f) = value.as_f64() {
        if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
            Value::Int(f as i64)
        } else {
            Value::Real(f)
        }
    } else if let Some(s) = value.as_string() {
        Value::Text(s)
    } else if let Ok(bytes) = value.clone().dyn_into::<js_sys::Uint8Array>() {
        Value::Bytes(bytes.to_vec())
    } else {
        // No other sqlite/D1 column shape is expected; treat as NULL rather
        // than fail the whole row.
        Value::Null
    }
}

/// Names the JS type D1 sees for a bound value, for bind-error diagnostics.
///
/// D1 accepts `null`, numbers, strings, booleans, and `ArrayBuffer` blobs; it
/// rejects any other object with `D1_TYPE_ERROR: Type 'object' not supported`.
/// Surfacing the per-parameter type turns that opaque error into an actionable
/// one (which column, what shape).
fn js_type_name(value: &JsValue) -> &'static str {
    if value.is_null() {
        "null"
    } else if value.is_undefined() {
        "undefined"
    } else if value.as_f64().is_some() {
        "number"
    } else if value.as_string().is_some() {
        "string"
    } else if value.dyn_ref::<js_sys::Uint8Array>().is_some() {
        "uint8array"
    } else if value.is_object() {
        "object"
    } else {
        "other"
    }
}

/// Prepares + binds a single source statement for D1 (sqlite dialect).
///
/// # Errors
///
/// Returns an error if dialect translation fails or D1 rejects a bound value.
/// A bind failure is annotated with the translated SQL and each parameter's JS
/// type (see [`js_type_name`]) so the otherwise-opaque `D1_TYPE_ERROR` points at
/// the offending column.
fn bind_stmt(
    session: &D1DatabaseSession,
    sql: &str,
    params: &[Value],
) -> anyhow::Result<worker::D1PreparedStatement> {
    let (translated, ordered) = prepare(Dialect::Sqlite, sql, params)?;
    let js: Vec<JsValue> = ordered.iter().map(to_js).collect();
    session.prepare(&translated).bind(&js).map_err(|err| {
        let types: Vec<&str> = js.iter().map(js_type_name).collect();
        anyhow::anyhow!(
            "D1 bind failed: {err} | sql: {translated} | param_types: [{}]",
            types.join(", ")
        )
    })
}

#[async_trait(?Send)]
impl Backend for D1Backend {
    fn dialect(&self) -> Dialect {
        // D1 is sqlite: the source dialect, no translation beyond placeholders.
        Dialect::Sqlite
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> anyhow::Result<u64> {
        let stmt = bind_stmt(&self.session, sql, params)?;
        let result = stmt.run().await.map_err(d1_err)?;
        let changes = result
            .meta()
            .map_err(d1_err)?
            .and_then(|m| m.changes)
            .unwrap_or(0);
        Ok(changes as u64)
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> anyhow::Result<i64> {
        let stmt = bind_stmt(&self.session, sql, params)?;
        let result = stmt.run().await.map_err(d1_err)?;
        result
            .meta()
            .map_err(d1_err)?
            .and_then(|m| m.last_row_id)
            .ok_or_else(|| anyhow::anyhow!("D1 INSERT returned no last_row_id"))
    }

    async fn query(&self, sql: &str, params: &[Value]) -> anyhow::Result<Vec<Row>> {
        let stmt = bind_stmt(&self.session, sql, params)?;
        // `raw_js_value` returns each row as a JS array of positional column
        // values (column order matches the SELECT list). We walk the cells
        // directly as `JsValue`s rather than via `raw::<Vec<serde_json::Value>>`,
        // because serde-wasm-bindgen rejects a JS `null` column ("invalid type:
        // null, expected any valid JSON value") and the hub's full-column
        // SELECTs read many nullable columns (org_id, storage_binding_id,
        // indexed_at, …). See [`js_to_value`].
        let rows = stmt.raw_js_value().await.map_err(d1_err)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let cols = js_sys::Array::from(&row);
                Row::new(cols.iter().map(|c| js_to_value(&c)).collect())
            })
            .collect())
    }

    async fn execute_batch(&self, sql: &str) -> anyhow::Result<()> {
        // A migration script is multiple `;`-separated DDL statements with no
        // bound parameters; run each translated statement in turn.
        for statement in split_statements(sql) {
            let (translated, _) = prepare(Dialect::Sqlite, &statement, &[])?;
            self.session.prepare(&translated).run().await.map_err(d1_err)?;
        }
        Ok(())
    }

    async fn batch(&self, stmts: &[Statement]) -> anyhow::Result<()> {
        // D1's `batch` runs a fixed statement list as one atomic unit — the
        // exact primitive `core`'s batch seam targets (no interactive tx).
        let mut prepared = Vec::with_capacity(stmts.len());
        for statement in stmts {
            prepared.push(bind_stmt(&self.session, &statement.sql, &statement.params)?);
        }
        self.session.batch(prepared).await.map_err(d1_err)?;
        Ok(())
    }
}
